import argparse
import base64
import binascii
import errno
import fnmatch
import hashlib
import http.client
import json
import os
import queue
import select
import signal
import socket
import sys
import threading
import time
import tomllib
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import FrameType
from typing import Any, Protocol
from urllib.parse import urlsplit

VERSION = "0.2.0"
MIB = 1024 * 1024
MODES = ("web", "background")
LABEL_PREFIX = "idlenap."


def page_size() -> int:
    if hasattr(os, "sysconf"):
        try:
            return os.sysconf("SC_PAGE_SIZE")
        except (ValueError, OSError):
            pass
    return 4096


def parse_duration(value: Any) -> int:
    if isinstance(value, bool):
        raise TypeError(f"invalid duration: {value!r}")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"invalid duration: {value!r}")
        return value
    if not isinstance(value, str):
        raise TypeError(f"invalid duration: {value!r}")
    text = value.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text and text[-1] in units:
        number, unit = text[:-1], units[text[-1]]
    else:
        number, unit = text, 1
    try:
        seconds = float(number) * unit
    except ValueError:
        raise ValueError(f"invalid duration: {value!r}") from None
    if seconds < 0:
        raise ValueError(f"invalid duration: {value!r}")
    return int(seconds)


@dataclass
class Rule:
    match: str
    mode: str = "web"
    idle_seconds: int = 600
    watch: str | None = None
    activity_bytes: int | None = None


@dataclass
class Config:
    interval: int = 30
    apply: bool = False
    docker_socket: str = "/var/run/docker.sock"
    state_file: str = "/var/lib/idlenap/state.json"
    events_file: str = "/var/lib/idlenap/events.jsonl"
    proc_root: str = field(default_factory=lambda: os.environ.get("IDLENAP_PROC_ROOT", "/proc"))
    cgroup_root: str = field(default_factory=lambda: os.environ.get("IDLENAP_CGROUP_ROOT", "/sys/fs/cgroup"))
    activity_bytes: int = 8192
    activity_cpu_usec: int = 100_000
    topup_mb: int = 64
    min_reclaim_mb: int = 8
    min_swap_free_mb: int = 512
    max_pressure: float = 10.0
    swappiness: int | None = None
    background_min_interval: int = 300
    background_max_interval: int = 7200
    healthcheck_min_timeout: float = 3.0
    reclaim_timeout: float = 5.0
    restore_swap: bool = False
    exclude: list[str] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)


DURATION_KEYS = {"interval", "background_min_interval", "background_max_interval"}
INT_KEYS = {"activity_bytes", "activity_cpu_usec", "topup_mb", "min_reclaim_mb", "min_swap_free_mb"}
FLOAT_KEYS = {"max_pressure", "healthcheck_min_timeout", "reclaim_timeout"}
STR_KEYS = {"docker_socket", "state_file", "events_file", "proc_root", "cgroup_root"}


class ConfigError(Exception):
    pass


def parse_rule(raw: Any, where: str) -> Rule:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: must be a table")
    unknown = set(raw) - {"match", "mode", "idle", "watch", "activity_bytes"}
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")
    match = raw.get("match")
    if not isinstance(match, str) or not match:
        raise ConfigError(f"{where}: 'match' is required")
    mode = raw.get("mode", "web")
    if mode not in MODES:
        raise ConfigError(f"{where}: mode must be one of {MODES}")
    try:
        idle = parse_duration(raw.get("idle", "10m"))
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"{where}: {exc}") from None
    watch = raw.get("watch")
    if watch is not None and (not isinstance(watch, str) or not watch):
        raise ConfigError(f"{where}: 'watch' must be a container name")
    activity = raw.get("activity_bytes")
    if activity is not None and (not isinstance(activity, int) or isinstance(activity, bool) or activity < 0):
        raise ConfigError(f"{where}: 'activity_bytes' must be a non-negative integer")
    return Rule(match=match, mode=mode, idle_seconds=idle, watch=watch, activity_bytes=activity)


def config_from_dict(data: dict[str, Any]) -> Config:
    cfg = Config()
    known = {f.name for f in fields(Config)} - {"rules"} | {"target"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown keys {sorted(unknown)}")
    for key, value in data.items():
        if key == "target":
            if not isinstance(value, list):
                raise ConfigError("'target' must be an array of tables ([[target]])")
            cfg.rules = [parse_rule(item, f"target[{i}]") for i, item in enumerate(value)]
        elif key == "exclude":
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ConfigError("'exclude' must be a list of strings")
            cfg.exclude = list(value)
        elif key in ("apply", "restore_swap"):
            if not isinstance(value, bool):
                raise ConfigError(f"'{key}' must be true or false")
            setattr(cfg, key, value)
        elif key == "swappiness":
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 200:
                raise ConfigError("'swappiness' must be an integer between 0 and 200")
            cfg.swappiness = value
        elif key in DURATION_KEYS:
            try:
                setattr(cfg, key, parse_duration(value))
            except (ValueError, TypeError) as exc:
                raise ConfigError(f"{key}: {exc}") from None
        elif key in INT_KEYS:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ConfigError(f"'{key}' must be a non-negative integer")
            setattr(cfg, key, value)
        elif key in FLOAT_KEYS:
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                raise ConfigError(f"'{key}' must be a non-negative number")
            setattr(cfg, key, float(value))
        elif key in STR_KEYS:
            if not isinstance(value, str) or not value:
                raise ConfigError(f"'{key}' must be a non-empty string")
            setattr(cfg, key, value)
    if cfg.interval < 1:
        raise ConfigError("'interval' must be at least 1 second")
    if cfg.background_min_interval > cfg.background_max_interval:
        raise ConfigError("'background_min_interval' must not exceed 'background_max_interval'")
    return cfg


def load_config(path: str | None) -> Config:
    if path is None:
        return Config()
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    return config_from_dict(data)


def label_flag(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in ("true", "1", "yes", "on"):
        return True
    if lowered in ("false", "0", "no", "off"):
        return False
    return None


def resolve_rule(cfg: Config, name: str, labels: dict[str, str]) -> Rule | None:
    enabled = label_flag(labels.get(LABEL_PREFIX + "enable"))
    if enabled is False:
        return None
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in cfg.exclude):
        return None
    if enabled is True:
        mode = labels.get(LABEL_PREFIX + "mode", "web")
        if mode not in MODES:
            return None
        try:
            idle = parse_duration(labels.get(LABEL_PREFIX + "idle", "10m"))
        except ValueError:
            return None
        return Rule(match=name, mode=mode, idle_seconds=idle, watch=labels.get(LABEL_PREFIX + "watch") or None)
    for rule in cfg.rules:
        if fnmatch.fnmatchcase(name, rule.match):
            return rule
    return None


@dataclass
class Memory:
    current: int
    swap: int
    anon: int
    file: int
    refault_anon: int
    swap_max: int | None = None


def reclaimable(mem: Memory) -> int:
    anon = mem.anon
    if mem.swap_max is not None:
        anon = min(anon, max(0, mem.swap_max - mem.swap))
    return anon + mem.file


class Host:
    def __init__(self, proc_root: str = "/proc", cgroup_root: str = "/sys/fs/cgroup") -> None:
        self.proc = Path(proc_root)
        self.cgroup_root = Path(cgroup_root)
        self.found: dict[str, Path] = {}

    def cgroup_v2(self) -> bool:
        return (self.cgroup_root / "cgroup.controllers").exists()

    def pid_alive(self, pid: int) -> bool:
        return pid > 0 and (self.proc / str(pid)).exists()

    def cgroup_dir(self, pid: int) -> Path | None:
        try:
            text = (self.proc / str(pid) / "cgroup").read_text()
        except OSError:
            return None
        for line in text.splitlines():
            if line.startswith("0::"):
                path = line[3:].strip()
                if not path.startswith("/.."):
                    return self.cgroup_root / path.lstrip("/")
                while path.startswith("/.."):
                    path = path[3:]
                return self.find_cgroup(path.strip("/"))
        return None

    def relative_cgroup(self, cgroup: Path) -> str:
        try:
            return cgroup.relative_to(self.cgroup_root).as_posix()
        except ValueError:
            return ""

    def find_cgroup(self, suffix: str, max_depth: int = 6) -> Path | None:
        if not suffix:
            return None
        cached = self.found.get(suffix)
        if cached is not None and cached.exists():
            return cached
        root_depth = len(self.cgroup_root.parts)
        for dirpath, dirnames, _ in os.walk(self.cgroup_root):
            current = Path(dirpath)
            if current.as_posix().endswith("/" + suffix):
                self.found[suffix] = current
                return current
            if len(current.parts) - root_depth >= max_depth:
                dirnames.clear()
        return None

    def net_bytes(self, pid: int) -> int | None:
        try:
            lines = (self.proc / str(pid) / "net" / "dev").read_text().splitlines()
        except OSError:
            return None
        total = 0
        for line in lines[2:]:
            if ":" not in line:
                continue
            iface, data = line.split(":", 1)
            if iface.strip() == "lo":
                continue
            parts = data.split()
            if len(parts) < 9:
                continue
            total += int(parts[0]) + int(parts[8])
        return total

    def memory(self, cgroup: Path) -> Memory | None:
        try:
            current = int((cgroup / "memory.current").read_text())
            stat = parse_kv((cgroup / "memory.stat").read_text())
        except (OSError, ValueError):
            return None
        try:
            swap = int((cgroup / "memory.swap.current").read_text())
        except (OSError, ValueError):
            swap = 0
        try:
            raw = (cgroup / "memory.swap.max").read_text().strip()
            swap_max = None if raw == "max" else int(raw)
        except (OSError, ValueError):
            swap_max = None
        return Memory(
            current=current,
            swap=swap,
            anon=stat.get("anon", 0),
            file=stat.get("file", 0),
            refault_anon=stat.get("workingset_refault_anon", 0),
            swap_max=swap_max,
        )

    def cpu_usec(self, cgroup: Path) -> int | None:
        try:
            return parse_kv((cgroup / "cpu.stat").read_text()).get("usage_usec")
        except (OSError, ValueError):
            return None

    def memory_max(self, cgroup: Path) -> str | None:
        try:
            raw = (cgroup / "memory.max").read_text().strip()
        except OSError:
            return None
        return raw if raw == "max" or raw.isdigit() else None

    def reclaim_supported(self, cgroup: Path) -> bool:
        return (cgroup / "memory.reclaim").exists()

    def meminfo(self) -> dict[str, int]:
        try:
            lines = (self.proc / "meminfo").read_text().splitlines()
        except OSError:
            return {}
        info: dict[str, int] = {}
        for line in lines:
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                factor = 1024 if len(parts) > 1 and parts[1] == "kB" else 1
                info[key.strip()] = int(parts[0]) * factor
        return info

    def pressure_full_avg10(self) -> float | None:
        try:
            lines = (self.proc / "pressure" / "memory").read_text().splitlines()
        except OSError:
            return None
        for line in lines:
            if line.startswith("full "):
                for part in line.split()[1:]:
                    key, _, value = part.partition("=")
                    if key == "avg10":
                        try:
                            return float(value)
                        except ValueError:
                            return None
        return None


def parse_kv(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                continue
    return result


def os_write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


class ReclaimTimeout(Exception):
    pass


def raise_timeout(_signum: int, _frame: FrameType | None) -> None:
    raise ReclaimTimeout


def call_with_deadline(seconds: float, action: Callable[[], None]) -> None:
    if sys.platform == "win32":
        action()
        return
    if seconds <= 0 or threading.current_thread() is not threading.main_thread():
        action()
        return
    previous = signal.signal(signal.SIGALRM, raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        action()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL if previous is None else previous)


class Reclaimer:
    def __init__(
        self,
        swappiness: int | None,
        writer: Callable[[Path, bytes], None] = os_write,
        timeout: float = 5.0,
    ) -> None:
        self.swappiness = swappiness
        self.writer = writer
        self.timeout = timeout
        self.swappiness_rejected = False

    def request(self, cgroup: Path, amount: int) -> str:
        argument = str(amount)
        if self.swappiness is not None:
            argument += f" swappiness={self.swappiness}"
        try:
            call_with_deadline(self.timeout, lambda: self.writer(cgroup / "memory.reclaim", argument.encode()))
        except ReclaimTimeout:
            return "timeout"
        except OSError as exc:
            if exc.errno == errno.EAGAIN:
                return "partial"
            if exc.errno == errno.EINVAL and self.swappiness is not None:
                self.swappiness = None
                self.swappiness_rejected = True
                return self.request(cgroup, amount)
            return "error:" + errno.errorcode.get(exc.errno or 0, str(exc.errno))
        return "ok"

    def set_swap_max(self, cgroup: Path, value: str) -> str:
        try:
            self.writer(cgroup / "memory.swap.max", value.encode())
        except OSError as exc:
            return "error:" + errno.errorcode.get(exc.errno or 0, str(exc.errno))
        return "ok"


@dataclass
class ContainerInfo:
    id: str
    name: str
    labels: dict[str, str]
    pid: int
    host_network: bool
    healthcheck_timeout: float | None
    project: str | None = None
    published: bool = False


def front_door(target: ContainerInfo, rule: Rule | None, infos: list[ContainerInfo]) -> ContainerInfo:
    if rule is not None and rule.watch:
        for item in infos:
            if item.name == rule.watch:
                return item
        return target
    if target.published or target.project is None:
        return target
    doors = [item for item in infos if item.project == target.project and item.published and item.id != target.id]
    if len(doors) == 1 and not doors[0].host_network:
        return doors[0]
    return target


class DockerError(Exception):
    pass


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        if sys.platform == "win32":
            raise OSError(errno.EAFNOSUPPORT, "the Docker Engine API over a Unix socket needs Linux")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class Docker:
    def __init__(self, socket_path: str, timeout: float = 10.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout
        self.cache: dict[str, ContainerInfo] = {}

    def get(self, path: str) -> Any:
        conn = UnixHTTPConnection(self.socket_path, self.timeout)
        try:
            conn.request("GET", path, headers={"Host": "docker"})
            response = conn.getresponse()
            body = response.read()
        except OSError as exc:
            raise DockerError(f"{self.socket_path}: {exc}") from None
        finally:
            conn.close()
        if response.status != 200:
            raise DockerError(f"GET {path}: HTTP {response.status}")
        return json.loads(body)

    def version(self) -> dict[str, Any]:
        return self.get("/version")

    def inspect(self, container_id: str, name: str, labels: dict[str, str]) -> ContainerInfo:
        data = self.get(f"/containers/{container_id}/json")
        state = data.get("State") or {}
        host_config = data.get("HostConfig") or {}
        healthcheck = (data.get("Config") or {}).get("Healthcheck") or {}
        timeout_ns = healthcheck.get("Timeout") or 0
        has_check = bool(healthcheck.get("Test")) and healthcheck.get("Test") != ["NONE"]
        return ContainerInfo(
            id=container_id,
            name=name,
            labels=labels,
            pid=int(state.get("Pid") or 0),
            host_network=host_config.get("NetworkMode") == "host",
            healthcheck_timeout=(timeout_ns / 1e9 if timeout_ns else 30.0) if has_check else None,
        )

    def running(self, alive: Callable[[int], bool]) -> list[ContainerInfo]:
        listing = self.get("/containers/json")
        result: list[ContainerInfo] = []
        seen: set[str] = set()
        for item in listing:
            container_id = item["Id"]
            seen.add(container_id)
            names = item.get("Names") or [container_id[:12]]
            name = names[0].lstrip("/")
            labels = item.get("Labels") or {}
            info = self.cache.get(container_id)
            if info is None or not alive(info.pid):
                try:
                    info = self.inspect(container_id, name, labels)
                except DockerError:
                    continue
                self.cache[container_id] = info
            info.project = labels.get("com.docker.compose.project")
            info.published = any(port.get("PublicPort") for port in item.get("Ports") or [])
            result.append(info)
        for stale in set(self.cache) - seen:
            del self.cache[stale]
        return result


@dataclass
class Stats:
    mode: str | None = None
    ticks: int = 0
    quiet_ticks: int = 0
    asleep_ticks: int = 0
    longest_quiet: float = 0.0
    saved_sum: int = 0
    bound_sum: int = 0
    reclaims: int = 0
    freed_total: int = 0
    wakes: int = 0
    peak_quiet_bytes: int = 0
    watch: str | None = None
    asleep: bool = False
    quiet_for: float = 0.0
    current: int = 0
    swap: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    cgroup: str = ""
    idle_s: int = 0


@dataclass
class Track:
    info: ContainerInfo
    cgroup: Path
    rule: Rule | None
    last_active: float
    next_step: float
    watch: ContainerInfo | None = None
    last_net: int | None = None
    net_pid: int = 0
    last_cpu: int | None = None
    delta: int | None = None
    active: bool = False
    asleep: bool = False
    pre_reclaim: int = 0
    post_reclaim: int = 0
    step_interval: int = 0
    step_refault: int = 0
    step_freed: int = 0
    last_skip: str | None = None
    mem: Memory | None = None


Emit = Callable[[str, dict[str, Any]], None]


class ContainerSource(Protocol):
    def running(self, alive: Callable[[int], bool]) -> list[ContainerInfo]: ...


def event_record(event: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **data}


def emit_json(event: str, data: dict[str, Any]) -> None:
    print(json.dumps(event_record(event, data), ensure_ascii=False), flush=True)


def rotated(path: Path) -> Path:
    return path.with_name(path.name + ".1")


class EventLog:
    def __init__(self, path: str, max_bytes: int = 256 * 1024) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.broken = False

    def write(self, record: dict[str, Any]) -> None:
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                size = self.path.stat().st_size
            except FileNotFoundError:
                size = 0
            if size and size + len(line) > self.max_bytes:
                os.replace(self.path, rotated(self.path))
            with open(self.path, "ab") as fh:
                fh.write(line)
        except OSError as exc:
            if not self.broken:
                self.broken = True
                emit_json("warn", {"message": "cannot write events file", "path": str(self.path), "error": str(exc)})

    def emit(self, event: str, data: dict[str, Any]) -> None:
        record = event_record(event, data)
        print(json.dumps(record, ensure_ascii=False), flush=True)
        self.write(record)


def mb(value: int) -> float:
    return round(value / MIB, 1)


class Daemon:
    def __init__(
        self,
        cfg: Config,
        docker: ContainerSource,
        host: Host,
        reclaimer: Reclaimer,
        emit: Emit = emit_json,
    ) -> None:
        self.cfg = cfg
        self.docker = docker
        self.host = host
        self.reclaimer = reclaimer
        self.emit = emit
        self.tracks: dict[str, Track] = {}
        self.stats: dict[str, Stats] = {}
        self.page = page_size()
        self.warned: set[str] = set()

    def load_state(self) -> None:
        try:
            data = json.loads(Path(self.cfg.state_file).read_text())
        except (OSError, ValueError):
            return
        known = {f.name for f in fields(Stats)}
        for name, raw in (data.get("containers") or {}).items():
            if isinstance(raw, dict):
                self.stats[name] = Stats(**{k: v for k, v in raw.items() if k in known})
        for st in self.stats.values():
            st.asleep = False

    def save_state(self, now: float) -> None:
        path = Path(self.cfg.state_file)
        payload = {
            "version": VERSION,
            "updated": now,
            "apply": self.cfg.apply,
            "interval": self.cfg.interval,
            "containers": {name: asdict(st) for name, st in sorted(self.stats.items())},
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(json.dumps(payload, indent=1))
            os.replace(tmp, path)
        except OSError as exc:
            self.warn_once("state", "cannot write state file", path=str(path), error=str(exc))

    def warn_once(self, key: str, message: str, **data: Any) -> None:
        if key in self.warned:
            return
        self.warned.add(key)
        self.emit("warn", {"message": message, **data})

    def tick(self, now: float) -> None:
        try:
            infos = self.docker.running(self.host.pid_alive)
        except (DockerError, ValueError) as exc:
            self.emit("error", {"message": "docker unavailable", "error": str(exc)})
            return
        pressure = self.host.pressure_full_avg10()
        meminfo = self.host.meminfo()
        seen: set[str] = set()
        for info in infos:
            seen.add(info.id)
            track = self.tracks.get(info.id)
            if track is None or track.info.pid != info.pid:
                track = self.discover(info, now)
                if track is None:
                    continue
            self.follow(track, infos)
            self.observe(track, now)
            if track.mem is None:
                continue
            if track.rule is not None:
                self.restore_swap(track, meminfo)
                if track.rule.mode == "web":
                    self.decide_web(track, now, pressure, meminfo)
                else:
                    self.decide_background(track, now, pressure, meminfo)
            self.account(track, now)
        for gone in set(self.tracks) - seen:
            track = self.tracks.pop(gone)
            self.stats[track.info.name].asleep = False
        self.save_state(now)

    def discover(self, info: ContainerInfo, now: float) -> Track | None:
        cgroup = self.host.cgroup_dir(info.pid)
        if cgroup is None:
            return None
        rule = resolve_rule(self.cfg, info.name, info.labels)
        track = Track(
            info=info,
            cgroup=cgroup,
            rule=rule,
            last_active=now,
            next_step=now + self.cfg.background_min_interval,
            step_interval=self.cfg.background_min_interval,
        )
        self.tracks[info.id] = track
        st = self.stats.setdefault(info.name, Stats(first_seen=now))
        st.mode = rule.mode if rule else None
        st.cgroup = self.host.relative_cgroup(cgroup)
        st.idle_s = rule.idle_seconds if rule is not None and rule.mode == "web" else 0
        if rule is not None:
            self.emit(
                "target",
                {"container": info.name, "mode": rule.mode, "idle_s": rule.idle_seconds, "rule": rule.match},
            )
            timeout = info.healthcheck_timeout
            if timeout is not None and timeout < self.cfg.healthcheck_min_timeout:
                self.warn_once(
                    "hc:" + info.name,
                    "healthcheck timeout is short; the first check after a reclaim may fail",
                    container=info.name,
                    timeout_s=timeout,
                )
        return track

    def follow(self, track: Track, infos: list[ContainerInfo]) -> None:
        if track.rule is None or track.rule.mode != "web":
            track.watch = track.info
            return
        door = front_door(track.info, track.rule, infos)
        previous = track.watch
        track.watch = door
        st = self.stats[track.info.name]
        st.watch = door.name if door.id != track.info.id else None
        if previous is None or previous.id != door.id:
            if door.id != track.info.id:
                self.emit("watch", {"container": track.info.name, "front_door": door.name})
            elif track.rule.watch:
                self.warn_once(
                    "watch:" + track.info.name,
                    "watch container not found; using the target's own traffic",
                    container=track.info.name,
                    watch=track.rule.watch,
                )

    def observe(self, track: Track, now: float) -> None:
        track.mem = self.host.memory(track.cgroup)
        if track.mem is None:
            return
        source = track.watch or track.info
        if source.host_network:
            sample = self.host.cpu_usec(track.cgroup)
            previous, track.last_cpu = track.last_cpu, sample
            threshold = self.cfg.activity_cpu_usec
            track.delta = None
        else:
            sample = self.host.net_bytes(source.pid)
            previous = track.last_net if track.net_pid == source.pid else None
            track.last_net, track.net_pid = sample, source.pid
            threshold = self.cfg.activity_bytes
            if track.rule is not None and track.rule.activity_bytes is not None:
                threshold = track.rule.activity_bytes
            track.delta = sample - previous if sample is not None and previous is not None else None
        if sample is None or previous is None:
            active = False
        elif sample < previous:
            active = True
        else:
            active = sample - previous > threshold
        track.active = active
        if active:
            track.last_active = now

    def restore_swap(self, track: Track, meminfo: dict[str, int]) -> None:
        mem = track.mem
        if not self.cfg.restore_swap or not self.cfg.apply or mem is None or mem.swap_max != 0:
            return
        if meminfo.get("SwapTotal", 0) == 0:
            return
        name = track.info.name
        limit = self.host.memory_max(track.cgroup)
        if limit is None:
            return
        outcome = self.reclaimer.set_swap_max(track.cgroup, limit)
        if outcome != "ok":
            self.warn_once("swap-error:" + name, "cannot set memory.swap.max", container=name, error=outcome)
            return
        track.mem = self.host.memory(track.cgroup) or mem
        detail: dict[str, Any] = {"swap_max": "max"} if limit == "max" else {"swap_max_mb": mb(int(limit))}
        self.emit("swap", {"container": name, **detail})

    def estimate(self, track: Track, mem: Memory) -> int:
        if self.cfg.restore_swap and not self.cfg.apply and mem.swap_max == 0:
            limit = self.host.memory_max(track.cgroup)
            mem = replace(mem, swap_max=int(limit) if limit is not None and limit != "max" else None)
        return reclaimable(mem)

    def account(self, track: Track, now: float) -> None:
        mem = track.mem
        if mem is None:
            return
        st = self.stats[track.info.name]
        st.ticks += 1
        st.last_seen = now
        st.current = mem.current
        st.swap = mem.swap
        st.quiet_for = now - track.last_active
        st.longest_quiet = max(st.longest_quiet, st.quiet_for)
        if not track.active:
            st.quiet_ticks += 1
            if track.delta is not None:
                st.peak_quiet_bytes = max(st.peak_quiet_bytes, track.delta)
        st.asleep = track.asleep
        if track.asleep:
            st.asleep_ticks += 1
            if self.cfg.apply:
                st.saved_sum += max(0, track.pre_reclaim - mem.current)
            elif track.rule is not None and track.rule.mode == "background":
                st.bound_sum += self.estimate(track, mem)
            else:
                st.saved_sum += self.estimate(track, mem)

    def decide_web(self, track: Track, now: float, pressure: float | None, meminfo: dict[str, int]) -> None:
        mem = track.mem
        rule = track.rule
        if mem is None or rule is None:
            return
        if track.active:
            if track.asleep:
                track.asleep = False
                self.stats[track.info.name].wakes += 1
                self.emit("wake", {"container": track.info.name, "ram_mb": mb(mem.current), "swap_mb": mb(mem.swap)})
            return
        quiet_for = now - track.last_active
        if not track.asleep:
            if quiet_for >= rule.idle_seconds:
                self.reclaim(track, "idle", pressure, meminfo, quiet_s=int(quiet_for))
        elif mem.current - track.post_reclaim >= self.cfg.topup_mb * MIB:
            self.reclaim(track, "topup", pressure, meminfo, quiet_s=int(quiet_for))

    def decide_background(self, track: Track, now: float, pressure: float | None, meminfo: dict[str, int]) -> None:
        mem = track.mem
        if mem is None or now < track.next_step:
            return
        if track.step_freed > 0:
            refault_bytes = max(0, mem.refault_anon - track.step_refault) * self.page
            ratio = refault_bytes / track.step_freed
            if ratio > 0.5:
                track.step_interval = min(track.step_interval * 2, self.cfg.background_max_interval)
            elif ratio < 0.1:
                track.step_interval = max(track.step_interval // 2, self.cfg.background_min_interval)
        self.reclaim(track, "background", pressure, meminfo, next_s=track.step_interval)
        after = self.host.memory(track.cgroup) if self.cfg.apply else None
        track.step_refault = (after or mem).refault_anon
        track.next_step = now + track.step_interval

    def guard(self, track: Track, pressure: float | None, meminfo: dict[str, int]) -> str | None:
        mem = track.mem
        if mem is None:
            return "no-memory-data"
        if pressure is not None and pressure > self.cfg.max_pressure:
            return f"memory pressure {pressure:.1f} > {self.cfg.max_pressure:.1f}"
        swap_free = meminfo.get("SwapFree")
        if swap_free is None or meminfo.get("SwapTotal", 0) == 0:
            return "no swap"
        if swap_free - mem.anon < self.cfg.min_swap_free_mb * MIB:
            return f"swap free {mb(swap_free)} MB is too low"
        if not self.host.reclaim_supported(track.cgroup):
            return "memory.reclaim not available (kernel 5.19+ required)"
        return None

    def reclaim(self, track: Track, reason: str, pressure: float | None, meminfo: dict[str, int], **extra: Any) -> None:
        mem = track.mem
        if mem is None:
            return
        name = track.info.name
        st = self.stats[name]
        base = {"container": name, "reason": reason, "mode": track.rule.mode if track.rule else None, **extra}
        target = self.estimate(track, mem)
        if mem.swap_max == 0 and (self.cfg.apply or not self.cfg.restore_swap):
            self.warn_once(
                f"swap-max:{name}",
                "memory.swap.max is 0, only page cache can be reclaimed",
                container=name,
            )
        if mem.current < self.cfg.min_reclaim_mb * MIB or target < self.cfg.min_reclaim_mb * MIB:
            track.asleep = True
            track.pre_reclaim = mem.current
            track.post_reclaim = mem.current
            track.step_freed = 0
            return
        if not self.cfg.apply:
            track.asleep = True
            track.pre_reclaim = mem.current
            track.post_reclaim = mem.current
            track.step_freed = target
            st.reclaims += 1
            self.emit("reclaim", {**base, "dry_run": True, "ram_mb": mb(mem.current), "estimate_mb": mb(target)})
            return
        blocked = self.guard(track, pressure, meminfo)
        if blocked is not None:
            if blocked != track.last_skip:
                self.emit("skip", {**base, "why": blocked})
            track.last_skip = blocked
            return
        started = time.monotonic()
        outcome = self.reclaimer.request(track.cgroup, target)
        elapsed = int((time.monotonic() - started) * 1000)
        if self.reclaimer.swappiness_rejected:
            self.warn_once("swappiness", "kernel rejected swappiness= for memory.reclaim; using the system default")
        if outcome.startswith("error"):
            if outcome != track.last_skip:
                self.emit("error", {**base, "message": "memory.reclaim write failed", "error": outcome, "ms": elapsed})
            track.last_skip = outcome
            return
        track.last_skip = None
        after = self.host.memory(track.cgroup) or mem
        track.mem = after
        freed = max(0, mem.current - after.current)
        track.asleep = True
        track.pre_reclaim = mem.current
        track.post_reclaim = after.current
        track.step_freed = freed
        st.reclaims += 1
        st.freed_total += freed
        self.emit(
            "reclaim",
            {
                **base,
                "dry_run": False,
                "before_mb": mb(mem.current),
                "after_mb": mb(after.current),
                "freed_mb": mb(freed),
                "swap_mb": mb(after.swap),
                "ms": elapsed,
                "result": outcome,
            },
        )


def build_daemon(cfg: Config, emit: Emit = emit_json) -> Daemon:
    return Daemon(
        cfg,
        Docker(cfg.docker_socket),
        Host(cfg.proc_root, cfg.cgroup_root),
        Reclaimer(cfg.swappiness, timeout=cfg.reclaim_timeout),
        emit,
    )


def command_run(cfg: Config, once: bool) -> int:
    host = Host(cfg.proc_root, cfg.cgroup_root)
    if not host.cgroup_v2():
        print("idlenap: cgroup v2 is required", file=sys.stderr)
        return 1
    if cfg.apply and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("idlenap: --apply needs root to write memory.reclaim", file=sys.stderr)
        return 1
    daemon = build_daemon(cfg, EventLog(cfg.events_file).emit)
    daemon.load_state()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    daemon.emit(
        "start",
        {
            "version": VERSION,
            "apply": cfg.apply,
            "restore_swap": cfg.restore_swap,
            "interval_s": cfg.interval,
            "rules": len(cfg.rules),
            "exclude": cfg.exclude,
        },
    )
    while not stop.is_set():
        started = time.monotonic()
        daemon.tick(time.time())
        if once:
            break
        stop.wait(max(0.0, cfg.interval - (time.monotonic() - started)))
    daemon.emit("stop", {})
    return 0


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds >= 86400:
        return f"{seconds // 86400}d{seconds % 86400 // 3600}h"
    if seconds >= 3600:
        return f"{seconds // 3600}h{seconds % 3600 // 60}m"
    if seconds >= 60:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def command_status(cfg: Config, show_all: bool) -> int:
    try:
        data = json.loads(Path(cfg.state_file).read_text())
    except OSError:
        print(f"idlenap: no state file at {cfg.state_file}; is the daemon running?", file=sys.stderr)
        return 1
    except ValueError:
        print(f"idlenap: state file {cfg.state_file} is not valid JSON", file=sys.stderr)
        return 1
    containers: dict[str, dict[str, Any]] = data.get("containers") or {}
    updated = float(data.get("updated") or 0)
    rows = []
    total_saved = 0.0
    total_bound = 0.0
    for name, st in containers.items():
        if not show_all and not st.get("mode"):
            continue
        if updated - float(st.get("last_seen") or 0) > 3 * float(data.get("interval") or 30):
            state = "gone"
        elif not st.get("mode"):
            state = "-"
        else:
            state = "asleep" if st.get("asleep") else "awake"
        ticks = int(st.get("ticks") or 0)
        avg_saved = (int(st.get("saved_sum") or 0) / ticks / MIB) if ticks else 0.0
        avg_bound = (int(st.get("bound_sum") or 0) / ticks / MIB) if ticks else 0.0
        if state != "gone":
            total_saved += avg_saved
            total_bound += avg_bound
        quiet = 100.0 * int(st.get("quiet_ticks") or 0) / ticks if ticks else 0.0
        rows.append(
            (
                avg_saved,
                [
                    name,
                    st.get("mode") or "-",
                    state,
                    f"{quiet:.0f}%",
                    fmt_duration(float(st.get("longest_quiet") or 0)),
                    f"{mb(int(st.get('current') or 0)):.0f}",
                    f"{mb(int(st.get('swap') or 0)):.0f}",
                    f"<={avg_bound:.0f}" if avg_bound else f"{avg_saved:.0f}",
                    str(st.get("wakes") or 0),
                    f"{int(st.get('peak_quiet_bytes') or 0) / 1024:.1f}",
                    st.get("watch") or "-",
                ],
            )
        )
    rows.sort(key=lambda item: (-item[0], item[1][0]))
    header = ["CONTAINER", "MODE", "STATE", "QUIET", "LONGEST", "RAM_MB", "SWAP_MB", "SAVED_MB", "WAKES", "NOISE_KB", "WATCH"]
    table = [header] + [row for _, row in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(header))]
    for row in table:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    mode = "applied" if data.get("apply") else "dry-run estimate"
    age = time.time() - updated
    print(f"\naverage RAM saved: {total_saved:.0f} MB ({mode}); state updated {fmt_duration(age)} ago")
    if total_bound:
        print(f"background targets: at most {total_bound:.0f} MB more (upper bound, real value depends on refaults)")
    return 0


def command_check(cfg: Config) -> int:
    host = Host(cfg.proc_root, cfg.cgroup_root)
    problems = 0

    def line(ok: bool, text: str) -> None:
        nonlocal problems
        if not ok:
            problems += 1
        print(("ok   " if ok else "FAIL ") + text)

    line(host.cgroup_v2(), "cgroup v2 mounted at " + cfg.cgroup_root)
    info = host.meminfo()
    swap_total = info.get("SwapTotal", 0)
    line(swap_total > 0, f"swap: {mb(swap_total):.0f} MB total, {mb(info.get('SwapFree', 0)):.0f} MB free")
    pressure = host.pressure_full_avg10()
    print(("ok   " if pressure is not None else "info ") + f"memory pressure (PSI full avg10): {pressure}")
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    print(("ok   " if is_root else "info ") + ("running as root" if is_root else "not root: dry-run only"))
    docker = Docker(cfg.docker_socket)
    try:
        version = docker.version()
        line(True, f"docker API at {cfg.docker_socket}: {version.get('Version')} (API {version.get('ApiVersion')})")
        containers = docker.running(host.pid_alive)
    except DockerError as exc:
        line(False, f"docker API at {cfg.docker_socket}: {exc}")
        return 1
    rules = {item.id: resolve_rule(cfg, item.name, item.labels) for item in containers}
    probe = [item for item in containers if rules[item.id]] or containers
    for item in probe:
        cgroup = host.cgroup_dir(item.pid)
        if cgroup is not None and host.memory(cgroup) is not None:
            line(host.reclaim_supported(cgroup), f"memory.reclaim available (kernel 5.19+), checked on {item.name}")
            break
    print()
    for item in sorted(containers, key=lambda c: c.name):
        rule = rules[item.id]
        if rule is None:
            target = "-"
        elif rule.mode == "web":
            target = f"web idle={fmt_duration(rule.idle_seconds)} ({rule.match})"
        else:
            target = f"background ({rule.match})"
        notes = ""
        if rule and rule.mode == "web":
            door = front_door(item, rule, containers)
            if door.id != item.id:
                notes += f"  [watch {door.name}]"
        timeout = item.healthcheck_timeout
        if rule and timeout is not None and timeout < cfg.healthcheck_min_timeout:
            notes += f"  [healthcheck timeout {timeout:g}s]"
        if rule:
            cgroup = host.cgroup_dir(item.pid)
            mem = host.memory(cgroup) if cgroup is not None else None
            if mem is not None and mem.swap_max == 0 and cgroup is not None:
                if cfg.restore_swap:
                    notes += f"  [memory.swap.max=0: restore_swap sets it to {host.memory_max(cgroup)}]"
                else:
                    notes += "  [memory.swap.max=0: only page cache can be reclaimed]"
        print(f"  {item.name:<40} {target}{notes}")
    return 1 if problems else 0


PANEL_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="data:,">
<title>idlenap</title>
<style>
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink-2:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--series:#2a78d6;--wash:rgba(42,120,214,.12);--track:#cde2fb;--good:#0ca30c;--good-text:#006300;--warning:#fab219;--critical:#d03b3b;--flash:rgba(42,120,214,.10)}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink-2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--series:#3987e5;--wash:rgba(57,135,229,.16);--track:#184f95;--good-text:#0ca30c;--flash:rgba(57,135,229,.18)}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1120px;margin:0 auto;padding:20px 16px 48px}
header{display:flex;align-items:center;justify-content:space-between;gap:10px 16px;flex-wrap:wrap;margin-bottom:20px}
.brand{display:flex;align-items:center;gap:10px}
.brand h1{font-size:18px;font-weight:650;margin:0;letter-spacing:-.01em}
.chip{font-size:12px;color:var(--ink-2);border:1px solid var(--border);border-radius:999px;padding:1px 8px}
.ver,.updated{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.right{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.conn,.stale{display:inline-flex;align-items:center;gap:7px;color:var(--ink-2);font-size:13px}
.conn .dot,.stale i,.sev{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none}
.conn[data-state=live] .dot{background:var(--good)}
.conn[data-state=retry] .dot,.stale i,.sev[data-level=warn]{background:var(--warning)}
.sev[data-level=error]{background:var(--critical)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:28px}
.tile,.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;min-width:0}
.label{color:var(--ink-2);font-size:13px}
.value{font-size:26px;font-weight:600;letter-spacing:-.02em;margin:2px 0 8px;font-variant-numeric:tabular-nums}
.sub{color:var(--muted);font-size:12px;margin-top:6px;font-variant-numeric:tabular-nums}
.meter{height:8px;border-radius:999px;background:var(--track);overflow:hidden}
.meter>span{display:block;height:100%;width:0;border-radius:999px;background:var(--series);transition:width .4s ease}
section{margin-bottom:28px}
h2{font-size:14px;font-weight:600;margin:0 0 10px;color:var(--ink-2)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,320px),1fr));gap:12px}
.card-head{display:flex;justify-content:space-between;align-items:center;gap:8px}
.name{font-weight:600;font-size:15px;overflow-wrap:anywhere}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--ink-2);white-space:nowrap}
.badge i{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.badge[data-state=asleep]{color:var(--good-text)}
.badge[data-state=asleep] i{background:var(--good)}
.badge[data-state=awake] i{background:var(--series)}
.figs{display:flex;gap:24px;margin:10px 0 4px;font-variant-numeric:tabular-nums}
.fig .v{font-size:22px;font-weight:600;letter-spacing:-.02em}
.fig .k{font-size:12px;color:var(--ink-2)}
.chart{position:relative;height:72px;margin:8px 0 2px;touch-action:none}
.chart svg{display:block;width:100%;height:100%;overflow:visible}
.chart .line{fill:none;stroke:var(--series);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.chart .area{fill:var(--wash)}
.chart .base{stroke:var(--axis);stroke-width:1}
.chart .cross{stroke:var(--muted);stroke-width:1}
.chart .pt{fill:var(--series);stroke:var(--surface);stroke-width:2}
.tip{position:absolute;top:-4px;transform:translate(-50%,-100%);background:var(--ink);color:var(--page);font-size:12px;padding:5px 8px;border-radius:6px;white-space:nowrap;pointer-events:none;font-variant-numeric:tabular-nums;z-index:2}
.tip b{font-weight:600}
.caption{font-size:12px;color:var(--muted);margin-bottom:10px;font-variant-numeric:tabular-nums}
.progress{display:flex;align-items:center;gap:10px;font-size:12px;color:var(--ink-2);font-variant-numeric:tabular-nums;min-height:18px}
.progress .meter{flex:1;height:6px}
.stats{display:flex;flex-wrap:wrap;gap:4px 14px;margin-top:10px;font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.empty{color:var(--muted);margin:6px 0}
.table-wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:10px}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--grid);vertical-align:top}
th{font-weight:500;color:var(--ink-2);font-size:12px}
tbody tr:last-child td{border-bottom:0}
td.time{color:var(--muted);white-space:nowrap;width:1%}
td.who{white-space:nowrap}
td.what{white-space:nowrap}
td.what .sev{margin-right:7px}
td.detail{color:var(--ink-2);overflow-wrap:anywhere;min-width:160px}
tr.new td{animation:flash 2.4s ease-out}
@keyframes flash{from{background:var(--flash)}to{background:transparent}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<div class="wrap">
<header>
<div class="brand"><h1>idlenap</h1><span class="chip" id="mode">connecting</span><span class="ver" id="version"></span></div>
<div class="right">
<span class="stale" id="stale" hidden><i></i>Daemon is not updating</span>
<span class="updated" id="updated"></span>
<div class="conn" id="conn" data-state="connecting" role="status" aria-live="polite"><span class="dot"></span><span id="conn-text">Connecting</span></div>
</div>
</header>
<section class="kpis" aria-label="Host">
<div class="tile"><div class="label">Memory in use</div><div class="value" id="k-mem">–</div><div class="meter"><span id="m-mem"></span></div><div class="sub" id="k-mem-sub"></div></div>
<div class="tile"><div class="label">Swap in use</div><div class="value" id="k-swap">–</div><div class="meter"><span id="m-swap"></span></div><div class="sub" id="k-swap-sub"></div></div>
<div class="tile"><div class="label">Memory pressure</div><div class="value" id="k-psi">–</div><div class="sub">Share of the last 10 s in which every task waited for memory</div></div>
<div class="tile"><div class="label">Saved on average</div><div class="value" id="k-saved">–</div><div class="sub" id="k-saved-sub"></div></div>
</section>
<section aria-labelledby="h-containers">
<h2 id="h-containers">Containers</h2>
<div class="cards" id="cards"></div>
<p class="empty" id="empty">No targets yet. Containers show up here once idlenap picks them up.</p>
</section>
<section aria-labelledby="h-events">
<h2 id="h-events">Events</h2>
<div class="table-wrap"><table><thead><tr><th>Time</th><th>Container</th><th>Event</th><th>Detail</th></tr></thead><tbody id="events"></tbody></table></div>
<p class="empty" id="no-events" hidden>No events yet.</p>
</section>
</div>
<script src="/app.js"></script>
</body>
</html>
"""

PANEL_JS = """"use strict";
const $ = (id) => document.getElementById(id);
const MAX_EVENTS = 200;
const model = { state: null, host: null, history: {}, events: [], keep: 300, sampleS: 2, skew: 0 };
const cards = new Map();
let retry = 0;

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function svgEl(tag, attrs) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

function fmtMB(v) {
  if (v === null || v === undefined || Number.isNaN(v)) return "–";
  if (v >= 1024) return (v / 1024).toFixed(1) + " GB";
  if (v >= 100) return Math.round(v) + " MB";
  return v.toFixed(1) + " MB";
}

function fmtDur(s) {
  s = Math.max(0, Math.floor(s));
  if (s >= 86400) return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
  if (s >= 3600) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  if (s >= 60) return Math.floor(s / 60) + "m" + (s % 60 ? " " + (s % 60) + "s" : "");
  return s + "s";
}

function clock(t) {
  return new Date(t * 1000).toLocaleTimeString([], { hour12: false });
}

function serverNow() {
  return Date.now() / 1000 + model.skew;
}

function pct(part, whole) {
  return whole > 0 ? Math.min(100, Math.max(0, (part / whole) * 100)).toFixed(1) + "%" : "0%";
}

function setConn(state, text) {
  $("conn").dataset.state = state;
  $("conn-text").textContent = text;
}

function connect() {
  setConn("connecting", "Connecting");
  const scheme = location.protocol === "https:" ? "wss://" : "ws://";
  const ws = new WebSocket(scheme + location.host + "/ws");
  ws.onopen = () => {
    retry = 0;
    setConn("live", "Live");
  };
  ws.onmessage = (msg) => {
    try {
      handle(JSON.parse(msg.data));
    } catch (err) {
      console.error(err);
    }
  };
  ws.onclose = () => {
    const delay = [1000, 2000, 5000, 10000][Math.min(retry, 3)];
    retry += 1;
    setConn("retry", "Reconnecting");
    setTimeout(connect, delay);
  };
}

function handle(msg) {
  if (typeof msg.now === "number") model.skew = msg.now - Date.now() / 1000;
  if (msg.type === "hello") {
    model.keep = msg.keep;
    model.sampleS = msg.sample_s;
    model.host = msg.host;
    model.history = msg.history || {};
    model.events = (msg.events || []).slice(-MAX_EVENTS).reverse();
    $("version").textContent = "v" + msg.version;
    setState(msg.state);
    renderEvents();
  } else if (msg.type === "state") {
    setState(msg.state);
  } else if (msg.type === "sample") {
    model.host = msg.host;
    for (const [name, value] of Object.entries(msg.ram)) {
      const list = model.history[name] || (model.history[name] = []);
      list.push([msg.t, value[0], value[1]]);
      if (list.length > model.keep) list.splice(0, list.length - model.keep);
    }
    renderHost();
    for (const card of cards.values()) updateCard(card);
  } else if (msg.type === "events") {
    for (const ev of msg.items) addEvent(ev);
  }
}

function setState(state) {
  model.state = state;
  $("mode").textContent = state.apply ? "applying" : "dry run";
  const rows = state.containers;
  const seen = new Set();
  const box = $("cards");
  for (const row of rows) {
    seen.add(row.name);
    let card = cards.get(row.name);
    if (!card) {
      card = buildCard(row.name);
      cards.set(row.name, card);
    }
    card.row = row;
    box.appendChild(card.root);
    updateCard(card);
  }
  for (const [name, card] of cards) {
    if (!seen.has(name)) {
      card.root.remove();
      cards.delete(name);
    }
  }
  $("empty").hidden = rows.length > 0;
  renderHost();
  tick();
}

function renderHost() {
  const h = model.host;
  if (!h) return;
  const used = h.mem_total_mb - h.mem_available_mb;
  $("k-mem").textContent = fmtMB(used);
  $("m-mem").style.width = pct(used, h.mem_total_mb);
  $("k-mem-sub").textContent = fmtMB(h.mem_available_mb) + " available of " + fmtMB(h.mem_total_mb);
  const swapUsed = h.swap_total_mb - h.swap_free_mb;
  $("k-swap").textContent = h.swap_total_mb ? fmtMB(swapUsed) : "off";
  $("m-swap").style.width = pct(swapUsed, h.swap_total_mb);
  $("k-swap-sub").textContent = h.swap_total_mb ? "of " + fmtMB(h.swap_total_mb) : "No swap on this host";
  $("k-psi").textContent = h.pressure === null || h.pressure === undefined ? "–" : h.pressure.toFixed(2) + "%";
  const rows = model.state ? model.state.containers.filter((r) => !r.gone) : [];
  $("k-saved").textContent = fmtMB(rows.reduce((sum, r) => sum + r.saved_mb, 0));
  $("k-saved-sub").textContent = rows.filter((r) => r.asleep).length + " of " + rows.length + " asleep now";
}

function buildCard(name) {
  const root = el("article", "card");
  const head = el("div", "card-head");
  const badge = el("span", "badge");
  badge.append(el("i"), el("span"));
  head.append(el("div", "name", name), badge);
  const figs = el("div", "figs");
  const ram = el("div", "v", "–");
  const swap = el("div", "v", "–");
  const ramFig = el("div", "fig");
  ramFig.append(ram, el("div", "k", "RAM"));
  const swapFig = el("div", "fig");
  swapFig.append(swap, el("div", "k", "Swap"));
  figs.append(ramFig, swapFig);
  const chart = el("div", "chart");
  const svg = svgEl("svg", { role: "img" });
  const area = svgEl("path", { class: "area" });
  const base = svgEl("line", { class: "base" });
  const line = svgEl("path", { class: "line" });
  const cross = svgEl("line", { class: "cross", visibility: "hidden" });
  const point = svgEl("circle", { class: "pt", r: "4", visibility: "hidden" });
  svg.append(area, base, line, cross, point);
  const tip = el("div", "tip");
  tip.hidden = true;
  chart.append(svg, tip);
  const caption = el("div", "caption");
  const progress = el("div", "progress");
  const progressText = el("span");
  const meter = el("div", "meter");
  const fill = el("span");
  meter.append(fill);
  progress.append(progressText, meter);
  const stats = el("div", "stats");
  root.append(head, figs, chart, caption, progress, stats);
  const card = { name, root, badge, ram, swap, svg, area, base, line, cross, point, tip, caption, progressText, meter, fill, stats, row: null, geom: null, hoverX: null };
  svg.addEventListener("pointermove", (e) => {
    const box = svg.getBoundingClientRect();
    card.hoverX = e.clientX - box.left;
    placeHover(card);
  });
  svg.addEventListener("pointerleave", () => {
    card.hoverX = null;
    card.cross.setAttribute("visibility", "hidden");
    card.point.setAttribute("visibility", "hidden");
    card.tip.hidden = true;
  });
  return card;
}

function updateCard(card) {
  const row = card.row;
  if (!row) return;
  const points = model.history[card.name] || [];
  const last = points.length ? points[points.length - 1] : null;
  card.ram.textContent = fmtMB(last ? last[1] : row.ram_mb);
  card.swap.textContent = fmtMB(last ? last[2] : row.swap_mb);
  const state = row.gone ? "gone" : row.asleep ? "asleep" : "awake";
  card.badge.dataset.state = state;
  card.badge.lastChild.textContent = state === "gone" ? "Not running" : state === "asleep" ? "Asleep" : "Awake";
  drawChart(card, points);
  const facts = ["Quiet " + row.quiet_pct + "% of the time", "Saved " + fmtMB(row.saved_mb) + " on average", row.reclaims + " sleeps", row.wakes + " wakes"];
  if (row.watch) facts.push("Traffic from " + row.watch);
  card.stats.replaceChildren(...facts.map((text) => el("span", null, text)));
  updateProgress(card);
}

function quietNow(row) {
  if (!model.state || row.gone) return row.quiet_for;
  return row.quiet_for + Math.max(0, serverNow() - model.state.updated);
}

function updateProgress(card) {
  const row = card.row;
  if (!row) return;
  if (row.gone) {
    card.progressText.textContent = "Not running";
    card.meter.hidden = true;
    return;
  }
  if (row.mode !== "web" || !row.idle_s) {
    card.progressText.textContent = "Background: memory is reclaimed on a timer";
    card.meter.hidden = true;
    return;
  }
  const quiet = quietNow(row);
  if (row.asleep) {
    card.progressText.textContent = "Asleep, quiet for " + fmtDur(quiet);
    card.meter.hidden = true;
    return;
  }
  card.meter.hidden = false;
  card.progressText.textContent = "Quiet " + fmtDur(Math.min(quiet, row.idle_s)) + " of " + fmtDur(row.idle_s);
  card.fill.style.width = pct(quiet, row.idle_s);
}

function drawChart(card, points) {
  const w = card.svg.clientWidth || 300;
  const h = card.svg.clientHeight || 72;
  card.svg.setAttribute("viewBox", "0 0 " + w + " " + h);
  const span = model.keep * model.sampleS;
  const end = points.length ? points[points.length - 1][0] : serverNow();
  const start = end - span;
  const peak = points.reduce((m, p) => Math.max(m, p[1]), 0);
  const top = Math.max(8, peak) * 1.15;
  const x = (t) => Math.max(0, ((t - start) / span) * w);
  const y = (v) => h - 1 - (v / top) * (h - 6);
  card.base.setAttribute("x1", "0");
  card.base.setAttribute("x2", String(w));
  card.base.setAttribute("y1", String(h - 0.5));
  card.base.setAttribute("y2", String(h - 0.5));
  const visible = points.filter((p) => p[0] >= start);
  if (visible.length < 2) {
    card.line.setAttribute("d", "");
    card.area.setAttribute("d", "");
  } else {
    let d = "";
    visible.forEach((p, i) => {
      d += (i ? "L" : "M") + x(p[0]).toFixed(1) + " " + y(p[1]).toFixed(1);
    });
    card.line.setAttribute("d", d);
    const first = x(visible[0][0]).toFixed(1);
    const lastX = x(visible[visible.length - 1][0]).toFixed(1);
    card.area.setAttribute("d", d + "L" + lastX + " " + (h - 1) + "L" + first + " " + (h - 1) + "Z");
  }
  card.geom = { points: visible, x, y, w, h };
  const now = visible.length ? visible[visible.length - 1][1] : null;
  card.caption.textContent = "RAM, last " + fmtDur(span) + " · peak " + fmtMB(peak);
  card.svg.setAttribute("aria-label", card.name + " RAM over the last " + fmtDur(span) + ": now " + fmtMB(now) + ", peak " + fmtMB(peak));
  if (card.hoverX !== null) placeHover(card);
}

function placeHover(card) {
  const g = card.geom;
  if (!g || !g.points.length || card.hoverX === null) return;
  let best = g.points[0];
  let dist = Infinity;
  for (const p of g.points) {
    const d = Math.abs(g.x(p[0]) - card.hoverX);
    if (d < dist) {
      dist = d;
      best = p;
    }
  }
  const cx = g.x(best[0]);
  const cy = g.y(best[1]);
  card.cross.setAttribute("x1", String(cx));
  card.cross.setAttribute("x2", String(cx));
  card.cross.setAttribute("y1", "0");
  card.cross.setAttribute("y2", String(g.h));
  card.cross.setAttribute("visibility", "visible");
  card.point.setAttribute("cx", String(cx));
  card.point.setAttribute("cy", String(cy));
  card.point.setAttribute("visibility", "visible");
  card.tip.replaceChildren(el("b", null, fmtMB(best[1])), document.createTextNode(" RAM · " + fmtMB(best[2]) + " swap · " + clock(best[0])));
  card.tip.hidden = false;
  const half = card.tip.offsetWidth / 2;
  card.tip.style.left = Math.min(Math.max(cx, half), g.w - half) + "px";
}

function describe(ev) {
  switch (ev.event) {
    case "reclaim":
      if (ev.dry_run) return ["Would sleep", "about " + fmtMB(ev.estimate_mb) + " reclaimable (dry run)"];
      return ["Put to sleep", fmtMB(ev.before_mb) + " → " + fmtMB(ev.after_mb) + " · " + ev.ms + " ms" + (ev.reason && ev.reason !== "idle" ? " · " + ev.reason : "")];
    case "wake":
      return ["Woke up", "RAM " + fmtMB(ev.ram_mb) + " · swap " + fmtMB(ev.swap_mb)];
    case "swap":
      return ["Swap limit set", ev.swap_max === "max" ? "no limit" : fmtMB(ev.swap_max_mb)];
    case "skip":
      return ["Skipped", ev.why || ""];
    case "warn":
      return ["Warning", ev.message || "", "warn"];
    case "error":
      return ["Error", (ev.message || "") + (ev.error ? " · " + ev.error : ""), "error"];
    case "start":
      return ["Daemon started", (ev.apply ? "applying" : "dry run") + " · " + ev.rules + " rules"];
    case "stop":
      return ["Daemon stopped", ""];
    case "target":
      return ["Tracking", ev.mode + (ev.mode === "web" ? " · sleeps after " + fmtDur(ev.idle_s) + " quiet" : "")];
    case "watch":
      return ["Watching", "traffic from " + ev.front_door];
    default:
      return [String(ev.event), ""];
  }
}

function eventRow(ev, fresh) {
  const [what, detail, level] = describe(ev);
  const tr = el("tr", fresh ? "new" : null);
  const cell = el("td", "what");
  if (level) {
    const icon = el("i", "sev");
    icon.dataset.level = level;
    cell.append(icon);
  }
  cell.append(document.createTextNode(what));
  tr.append(el("td", "time", typeof ev.t === "number" ? clock(ev.t) : String(ev.ts || "")), el("td", "who", ev.container || "–"), cell, el("td", "detail", detail));
  return tr;
}

function renderEvents() {
  $("events").replaceChildren(...model.events.map((ev) => eventRow(ev, false)));
  $("no-events").hidden = model.events.length > 0;
}

function addEvent(ev) {
  model.events.unshift(ev);
  if (model.events.length > MAX_EVENTS) model.events.length = MAX_EVENTS;
  const body = $("events");
  body.prepend(eventRow(ev, true));
  while (body.children.length > MAX_EVENTS) body.lastChild.remove();
  $("no-events").hidden = true;
}

function tick() {
  const state = model.state;
  if (!state || !state.updated) {
    $("updated").textContent = "";
    $("stale").hidden = true;
    return;
  }
  const age = serverNow() - state.updated;
  $("updated").textContent = "updated " + fmtDur(age) + " ago";
  $("stale").hidden = age < 3 * state.interval;
  for (const card of cards.values()) updateProgress(card);
}

setInterval(tick, 1000);
window.addEventListener("resize", () => {
  for (const card of cards.values()) drawChart(card, model.history[card.name] || []);
});
connect();
"""

PANEL_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self' ws: wss:; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_TEXT = 0x1
WS_CLOSE = 0x8
WS_PING = 0x9
WS_PONG = 0xA


class WSClosed(Exception):
    pass


class WSError(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def ws_accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_key_valid(key: str) -> bool:
    try:
        return len(base64.b64decode(key, validate=True)) == 16
    except (binascii.Error, ValueError):
        return False


def ws_mask(payload: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def ws_frame(opcode: int, payload: bytes, mask: bytes | None = None) -> bytes:
    size = len(payload)
    flag = 0x80 if mask else 0
    if size < 126:
        head = bytes([0x80 | opcode, flag | size])
    elif size < 65536:
        head = bytes([0x80 | opcode, flag | 126]) + size.to_bytes(2, "big")
    else:
        head = bytes([0x80 | opcode, flag | 127]) + size.to_bytes(8, "big")
    if not mask:
        return head + payload
    return head + mask + ws_mask(payload, mask)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise WSClosed
        data += chunk
    return bytes(data)


def ws_read(sock: socket.socket, limit: int, masked: bool = True) -> tuple[int, bytes]:
    first, second = recv_exact(sock, 2)
    size = second & 0x7F
    if size == 126:
        size = int.from_bytes(recv_exact(sock, 2), "big")
    elif size == 127:
        size = int.from_bytes(recv_exact(sock, 8), "big")
    if bool(second & 0x80) != masked:
        raise WSError(1002)
    if size > limit:
        raise WSError(1009)
    mask = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, size)
    return first & 0x0F, ws_mask(payload, mask) if mask else payload


def origin_allowed(origin: str | None, host: str | None) -> bool:
    if origin is None:
        return True
    return bool(host) and urlsplit(origin).netloc.lower() == (host or "").lower()


def parse_event(line: bytes) -> dict[str, Any] | None:
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if not isinstance(record, dict) or "event" not in record:
        return None
    try:
        record["t"] = datetime.strptime(str(record.get("ts")), "%Y-%m-%dT%H:%M:%S%z").timestamp()
    except ValueError:
        record["t"] = None
    return record


class EventFollower:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.inode: int | None = None
        self.offset = 0

    def backlog(self, limit: int) -> list[dict[str, Any]]:
        lines: list[bytes] = []
        try:
            lines += rotated(self.path).read_bytes().splitlines()
        except OSError:
            pass
        try:
            with open(self.path, "rb") as fh:
                data = fh.read()
                self.inode = os.fstat(fh.fileno()).st_ino
        except OSError:
            data = b""
            self.inode = None
        cut = data.rfind(b"\n") + 1
        self.offset = cut
        lines += data[:cut].splitlines()
        records = (parse_event(line) for line in lines[-limit:] if line.strip())
        return [record for record in records if record is not None]

    def read_from(self, path: Path, offset: int, whole: bool) -> tuple[list[bytes], int]:
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read()
        cut = len(data) if whole else data.rfind(b"\n") + 1
        return data[:cut].splitlines(), offset + cut

    def poll(self) -> list[dict[str, Any]]:
        try:
            st = self.path.stat()
        except OSError:
            return []
        lines: list[bytes] = []
        if self.inode is not None and st.st_ino != self.inode:
            try:
                old = rotated(self.path)
                if old.stat().st_ino == self.inode:
                    lines += self.read_from(old, self.offset, whole=True)[0]
            except OSError:
                pass
            self.offset = 0
        elif st.st_size < self.offset:
            self.offset = 0
        self.inode = st.st_ino
        if st.st_size > self.offset:
            try:
                fresh, self.offset = self.read_from(self.path, self.offset, whole=False)
                lines += fresh
            except OSError:
                pass
        records = (parse_event(line) for line in lines if line.strip())
        return [record for record in records if record is not None]


def panel_state(data: dict[str, Any]) -> dict[str, Any]:
    updated = float(data.get("updated") or 0)
    interval = float(data.get("interval") or 30)
    rows: list[dict[str, Any]] = []
    for name, st in sorted((data.get("containers") or {}).items()):
        if not isinstance(st, dict) or not st.get("mode"):
            continue
        ticks = int(st.get("ticks") or 0)
        gone = updated - float(st.get("last_seen") or 0) > 3 * interval
        rows.append(
            {
                "name": name,
                "mode": st.get("mode"),
                "asleep": bool(st.get("asleep")) and not gone,
                "gone": gone,
                "quiet_for": float(st.get("quiet_for") or 0),
                "idle_s": int(st.get("idle_s") or 0),
                "quiet_pct": round(100 * int(st.get("quiet_ticks") or 0) / ticks) if ticks else 0,
                "saved_mb": round(int(st.get("saved_sum") or 0) / ticks / MIB, 1) if ticks else 0.0,
                "reclaims": int(st.get("reclaims") or 0),
                "wakes": int(st.get("wakes") or 0),
                "watch": st.get("watch"),
                "ram_mb": mb(int(st.get("current") or 0)),
                "swap_mb": mb(int(st.get("swap") or 0)),
            }
        )
    return {"updated": updated, "interval": interval, "apply": bool(data.get("apply")), "containers": rows}


def encode_message(message: dict[str, Any]) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode()


class Client:
    def __init__(self, depth: int = 256) -> None:
        self.outbox: queue.Queue[bytes] = queue.Queue(maxsize=depth)
        self.dropped = threading.Event()

    def push(self, payload: bytes) -> None:
        try:
            self.outbox.put_nowait(payload)
        except queue.Full:
            self.dropped.set()


class Hub:
    def __init__(
        self,
        cfg: Config,
        host: Host,
        sample_every: float = 2.0,
        keep: int = 300,
        max_clients: int = 32,
    ) -> None:
        self.cfg = cfg
        self.host = host
        self.sample_every = sample_every
        self.keep = keep
        self.max_clients = max_clients
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.clients: set[Client] = set()
        self.follower = EventFollower(Path(cfg.events_file))
        self.events: deque[dict[str, Any]] = deque(maxlen=200)
        self.history: dict[str, deque[list[float]]] = {}
        self.cgroups: dict[str, str] = {}
        self.view: dict[str, Any] = panel_state({})
        self.host_view: dict[str, Any] = {}
        self.state_stamp: tuple[int, int] | None = None
        self.next_sample = 0.0

    def prime(self, now: float) -> None:
        with self.lock:
            self.events.extend(self.follower.backlog(200))
            self.refresh_state()
            self.sample(now)
            self.next_sample = now + self.sample_every

    def refresh_state(self) -> bool:
        path = Path(self.cfg.state_file)
        try:
            st = path.stat()
            stamp = (st.st_mtime_ns, st.st_size)
            if stamp == self.state_stamp:
                return False
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return False
        if not isinstance(data, dict):
            return False
        self.state_stamp = stamp
        self.view = panel_state(data)
        raw = data.get("containers") or {}
        cgroups: dict[str, str] = {}
        for row in self.view["containers"]:
            entry = raw.get(row["name"])
            rel = str(entry.get("cgroup") or "") if isinstance(entry, dict) else ""
            if not row["gone"] and rel and ".." not in Path(rel).parts:
                cgroups[row["name"]] = rel
        self.cgroups = cgroups
        return True

    def sample(self, now: float) -> dict[str, Any]:
        info = self.host.meminfo()
        self.host_view = {
            "mem_total_mb": mb(info.get("MemTotal", 0)),
            "mem_available_mb": mb(info.get("MemAvailable", 0)),
            "swap_total_mb": mb(info.get("SwapTotal", 0)),
            "swap_free_mb": mb(info.get("SwapFree", 0)),
            "pressure": self.host.pressure_full_avg10(),
        }
        ram: dict[str, list[float]] = {}
        for name, rel in self.cgroups.items():
            mem = self.host.memory(self.host.cgroup_root / rel)
            if mem is None:
                continue
            point = [round(now, 1), mb(mem.current), mb(mem.swap)]
            self.history.setdefault(name, deque(maxlen=self.keep)).append(point)
            ram[name] = point[1:]
        for name in set(self.history) - set(self.cgroups):
            del self.history[name]
        return {"type": "sample", "now": now, "t": round(now, 1), "host": self.host_view, "ram": ram}

    def hello(self, now: float) -> dict[str, Any]:
        return {
            "type": "hello",
            "now": now,
            "version": VERSION,
            "sample_s": self.sample_every,
            "keep": self.keep,
            "state": self.view,
            "host": self.host_view,
            "history": {name: list(points) for name, points in self.history.items()},
            "events": list(self.events),
        }

    def attach(self, client: Client) -> bool:
        with self.lock:
            if len(self.clients) >= self.max_clients:
                return False
            client.push(encode_message(self.hello(time.time())))
            self.clients.add(client)
            return True

    def detach(self, client: Client) -> None:
        with self.lock:
            self.clients.discard(client)

    def broadcast(self, message: dict[str, Any]) -> None:
        payload = encode_message(message)
        for client in list(self.clients):
            client.push(payload)

    def step(self, now: float) -> None:
        with self.lock:
            fresh = self.follower.poll()
            if fresh:
                self.events.extend(fresh)
                self.broadcast({"type": "events", "now": now, "items": fresh})
            if self.refresh_state():
                self.broadcast({"type": "state", "now": now, "state": self.view})
            if now >= self.next_sample:
                self.next_sample = now + self.sample_every
                self.broadcast(self.sample(now))

    def run(self, poll: float = 0.25) -> None:
        while not self.stop.is_set():
            self.step(time.time())
            self.stop.wait(poll)


def serve_client(sock: socket.socket, client: Client, stop: threading.Event) -> None:
    sock.settimeout(10)
    try:
        while not stop.is_set() and not client.dropped.is_set():
            while True:
                try:
                    payload = client.outbox.get_nowait()
                except queue.Empty:
                    break
                sock.sendall(ws_frame(WS_TEXT, payload))
            readable, _, _ = select.select([sock], [], [], 0.2)
            if not readable:
                continue
            opcode, data = ws_read(sock, 4096)
            if opcode == WS_CLOSE:
                sock.sendall(ws_frame(WS_CLOSE, data[:2]))
                return
            if opcode == WS_PING:
                sock.sendall(ws_frame(WS_PONG, data[:125]))
        code = 1008 if client.dropped.is_set() else 1001
        sock.sendall(ws_frame(WS_CLOSE, code.to_bytes(2, "big")))
    except WSError as exc:
        try:
            sock.sendall(ws_frame(WS_CLOSE, exc.code.to_bytes(2, "big")))
        except OSError:
            pass
    except (WSClosed, OSError):
        return


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "idlenap"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    rbufsize = 0
    timeout = 30

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def do_GET(self) -> None:
        server = self.server
        if not isinstance(server, PanelServer):
            return
        path = urlsplit(self.path).path
        if path == "/":
            self.reply(200, "text/html; charset=utf-8", PANEL_HTML.encode())
        elif path == "/app.js":
            self.reply(200, "text/javascript; charset=utf-8", PANEL_JS.encode())
        elif path == "/ws":
            self.upgrade(server.hub)
        else:
            self.reply(404, "text/plain; charset=utf-8", b"not found\n")

    def reply(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", PANEL_CSP)
        self.end_headers()
        self.wfile.write(body)

    def upgrade(self, hub: Hub) -> None:
        key = self.headers.get("Sec-WebSocket-Key", "")
        if (
            self.headers.get("Upgrade", "").lower() != "websocket"
            or "upgrade" not in self.headers.get("Connection", "").lower()
            or self.headers.get("Sec-WebSocket-Version") != "13"
            or not ws_key_valid(key)
        ):
            self.reply(400, "text/plain; charset=utf-8", b"websocket upgrade required\n")
            return
        if not origin_allowed(self.headers.get("Origin"), self.headers.get("Host")):
            self.reply(403, "text/plain; charset=utf-8", b"origin not allowed\n")
            return
        client = Client()
        if not hub.attach(client):
            self.reply(503, "text/plain; charset=utf-8", b"too many clients\n")
            return
        self.close_connection = True
        try:
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", ws_accept(key))
            self.end_headers()
            serve_client(self.connection, client, hub.stop)
        finally:
            hub.detach(client)


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], hub: Hub) -> None:
        super().__init__(address, PanelHandler)
        self.hub = hub


def parse_listen(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or int(port) > 65535:
        raise ValueError(f"invalid listen address {value!r}, expected HOST:PORT")
    return host or "0.0.0.0", int(port)


def command_panel(cfg: Config, listen: str) -> int:
    try:
        address = parse_listen(listen)
    except ValueError as exc:
        print(f"idlenap: {exc}", file=sys.stderr)
        return 2
    hub = Hub(cfg, Host(cfg.proc_root, cfg.cgroup_root))
    hub.prime(time.time())
    try:
        server = PanelServer(address, hub)
    except OSError as exc:
        print(f"idlenap: cannot listen on {listen}: {exc.strerror}", file=sys.stderr)
        return 1
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    threading.Thread(target=hub.run, daemon=True).start()
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True).start()
    emit_json("panel", {"version": VERSION, "listen": f"{address[0]}:{server.server_port}"})
    while not stop.wait(1.0):
        pass
    hub.stop.set()
    server.shutdown()
    server.server_close()
    emit_json("stop", {})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="idlenap", description="Swap out the memory of idle containers.")
    parser.add_argument("--version", action="version", version=f"idlenap {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "status", "check", "panel"):
        command = sub.add_parser(name)
        command.add_argument("-c", "--config", help="path to config.toml")
        if name == "run":
            command.add_argument("--apply", action="store_true", help="really write memory.reclaim")
            command.add_argument("--once", action="store_true", help="run a single tick and exit")
        if name == "status":
            command.add_argument("-a", "--all", action="store_true", help="include containers that are not targets")
        if name == "panel":
            command.add_argument("--listen", default="127.0.0.1:9180", help="HOST:PORT for the web panel")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config or os.environ.get("IDLENAP_CONFIG") or None)
    except ConfigError as exc:
        print(f"idlenap: config: {exc}", file=sys.stderr)
        return 2
    if args.command == "run":
        if args.apply:
            cfg.apply = True
        return command_run(cfg, args.once)
    if args.command == "status":
        return command_status(cfg, args.all)
    if args.command == "panel":
        return command_panel(cfg, args.listen)
    return command_check(cfg)


if __name__ == "__main__":
    sys.exit(main())
