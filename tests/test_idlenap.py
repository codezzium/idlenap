import base64
import contextlib
import errno
import http.client
import io
import json
import signal
import socket
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import idlenap
from idlenap import (
    MIB,
    WS_CLOSE,
    WS_TEXT,
    Config,
    ConfigError,
    ContainerInfo,
    Daemon,
    EventFollower,
    EventLog,
    Host,
    Hub,
    PanelServer,
    Reclaimer,
    Rule,
    WSError,
    config_from_dict,
    origin_allowed,
    panel_state,
    parse_listen,
    rotated,
    ws_accept,
    ws_frame,
    ws_key_valid,
    ws_read,
)

NET_HEADER = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
)


class FakeTree:
    def __init__(self, root: Path) -> None:
        self.proc = root / "proc"
        self.cgroup = root / "cgroup"
        self.proc.mkdir(parents=True)
        self.cgroup.mkdir(parents=True)
        (self.cgroup / "cgroup.controllers").write_text("cpu memory\n")
        self.meminfo(swap_total=4096 * MIB, swap_free=4000 * MIB)

    def cg(self, rel: str) -> Path:
        return self.cgroup / rel

    def add(self, pid: int, rel: str, reclaim: bool = True) -> None:
        piddir = self.proc / str(pid)
        (piddir / "net").mkdir(parents=True)
        (piddir / "cgroup").write_text(f"0::/{rel}\n")
        self.cg(rel).mkdir(parents=True)
        if reclaim:
            (self.cg(rel) / "memory.reclaim").write_text("")
        self.net(pid, 0, 0)
        self.mem(rel, current=200 * MIB, anon=180 * MIB, file=10 * MIB)
        self.cpu(rel, 0)

    def net(self, pid: int, rx: int, tx: int) -> None:
        body = NET_HEADER
        body += "    lo: 999999 10 0 0 0 0 0 0 999999 10 0 0 0 0 0 0\n"
        body += f"  eth0: {rx} 10 0 0 0 0 0 0 {tx} 10 0 0 0 0 0 0\n"
        (self.proc / str(pid) / "net" / "dev").write_text(body)

    def mem(self, rel: str, current: int, anon: int, file: int, swap: int = 0, refault: int = 0) -> None:
        cg = self.cg(rel)
        (cg / "memory.current").write_text(f"{current}\n")
        (cg / "memory.swap.current").write_text(f"{swap}\n")
        (cg / "memory.stat").write_text(f"anon {anon}\nfile {file}\nworkingset_refault_anon {refault}\n")

    def cpu(self, rel: str, usec: int) -> None:
        (self.cg(rel) / "cpu.stat").write_text(f"usage_usec {usec}\nuser_usec 0\n")

    def meminfo(self, swap_total: int, swap_free: int) -> None:
        (self.proc / "meminfo").write_text(
            f"MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\nSwapTotal: {swap_total // 1024} kB\nSwapFree: {swap_free // 1024} kB\n"
        )

    def pressure(self, full_avg10: float) -> None:
        (self.proc / "pressure").mkdir(exist_ok=True)
        (self.proc / "pressure" / "memory").write_text(
            f"some avg10=0.00 avg60=0.00 avg300=0.00 total=1\nfull avg10={full_avg10:.2f} avg60=0.00 avg300=0.00 total=1\n"
        )


class FakeDocker:
    def __init__(self, infos: list[ContainerInfo]) -> None:
        self.infos = infos

    def running(self, alive: Callable[[int], bool]) -> list[ContainerInfo]:
        return list(self.infos)


def info(
    name: str,
    pid: int,
    labels: dict[str, str] | None = None,
    host_network: bool = False,
    hc: float | None = 10.0,
    project: str | None = None,
    published: bool = False,
) -> ContainerInfo:
    return ContainerInfo(
        id=name + "-id",
        name=name,
        labels=labels or {},
        pid=pid,
        host_network=host_network,
        healthcheck_timeout=hc,
        project=project,
        published=published,
    )


class Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event: str, data: dict[str, Any]) -> None:
        self.events.append((event, data))

    def named(self, event: str) -> list[dict[str, Any]]:
        return [data for name, data in self.events if name == event]


class FreeingWriter:
    def __init__(self, tree: FakeTree, rel: str, left: int = 3 * MIB) -> None:
        self.tree = tree
        self.rel = rel
        self.left = left
        self.calls: list[bytes] = []
        self.swap_writes: list[bytes] = []

    def __call__(self, path: Path, data: bytes) -> None:
        if path.name == "memory.swap.max":
            self.swap_writes.append(data)
            path.write_text(data.decode() + "\n")
            return
        self.calls.append(data)
        self.tree.mem(self.rel, current=self.left, anon=0, file=0, swap=190 * MIB)


class DurationTests(unittest.TestCase):
    def test_parse(self) -> None:
        self.assertEqual(idlenap.parse_duration("10m"), 600)
        self.assertEqual(idlenap.parse_duration(30), 30)
        self.assertEqual(idlenap.parse_duration("1.5h"), 5400)
        self.assertEqual(idlenap.parse_duration("45"), 45)
        self.assertEqual(idlenap.parse_duration("2d"), 172800)

    def test_invalid(self) -> None:
        for value in ("x", "-5m", -1, "m"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                idlenap.parse_duration(value)
        for value in (True, None, 1.5):
            with self.subTest(value=value), self.assertRaises(TypeError):
                idlenap.parse_duration(value)


class ConfigTests(unittest.TestCase):
    def test_full(self) -> None:
        cfg = idlenap.config_from_dict(
            {
                "interval": "1m",
                "apply": True,
                "swappiness": 200,
                "max_pressure": 5,
                "restore_swap": True,
                "exclude": ["shared-*"],
                "target": [{"match": "*-web", "idle": "15m"}, {"match": "*-worker", "mode": "background"}],
            }
        )
        self.assertEqual(cfg.interval, 60)
        self.assertTrue(cfg.apply)
        self.assertTrue(cfg.restore_swap)
        self.assertEqual(cfg.swappiness, 200)
        self.assertEqual(cfg.max_pressure, 5.0)
        self.assertEqual(cfg.rules, [Rule("*-web", "web", 900), Rule("*-worker", "background", 600)])

    def test_errors(self) -> None:
        bad: list[dict[str, Any]] = [
            {"intervall": 30},
            {"target": [{"match": "*", "mode": "sleep"}]},
            {"target": [{"mode": "web"}]},
            {"target": [{"match": "*", "idle": "soon"}]},
            {"target": [{"match": "*", "extra": 1}]},
            {"swappiness": 300},
            {"apply": "yes"},
            {"restore_swap": 1},
            {"exclude": "shared-*"},
            {"interval": 0},
            {"background_min_interval": "2h", "background_max_interval": "1h"},
        ]
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ConfigError):
                idlenap.config_from_dict(data)

    def test_rule_watch_and_threshold(self) -> None:
        cfg = idlenap.config_from_dict({"target": [{"match": "api", "watch": "api-proxy", "activity_bytes": 500}]})
        self.assertEqual(cfg.rules[0].watch, "api-proxy")
        self.assertEqual(cfg.rules[0].activity_bytes, 500)
        for bad in ({"match": "api", "watch": ""}, {"match": "api", "activity_bytes": -1}):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                idlenap.config_from_dict({"target": [bad]})

    def test_load_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('exclude = ["db"]\n\n[[target]]\nmatch = "app"\nidle = "5m"\n')
            cfg = idlenap.load_config(str(path))
            self.assertEqual(cfg.exclude, ["db"])
            self.assertEqual(cfg.rules[0].idle_seconds, 300)
            with self.assertRaises(ConfigError):
                idlenap.load_config(str(Path(tmp) / "missing.toml"))

    def test_example_config_is_valid(self) -> None:
        example = Path(__file__).resolve().parent.parent / "config.example.toml"
        cfg = idlenap.load_config(str(example))
        self.assertFalse(cfg.apply)
        self.assertTrue(cfg.rules)


class RuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = Config(exclude=["shared-*"], rules=[Rule("*-web", "web", 600), Rule("*", "background", 600)])

    def test_config_rules_in_order(self) -> None:
        rule = idlenap.resolve_rule(self.cfg, "shop-web", {})
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual(rule.mode, "web")
        rule = idlenap.resolve_rule(self.cfg, "shop-worker", {})
        assert rule is not None
        self.assertEqual(rule.mode, "background")

    def test_exclude_wins_over_rules_and_labels(self) -> None:
        self.assertIsNone(idlenap.resolve_rule(self.cfg, "shared-db", {}))
        self.assertIsNone(idlenap.resolve_rule(self.cfg, "shared-db", {"idlenap.enable": "true"}))

    def test_labels(self) -> None:
        self.assertIsNone(idlenap.resolve_rule(self.cfg, "shop-web", {"idlenap.enable": "false"}))
        rule = idlenap.resolve_rule(Config(), "api", {"idlenap.enable": "true", "idlenap.idle": "2m"})
        self.assertEqual(rule, Rule("api", "web", 120))
        self.assertIsNone(idlenap.resolve_rule(Config(), "api", {"idlenap.enable": "true", "idlenap.mode": "nap"}))
        self.assertIsNone(idlenap.resolve_rule(Config(), "api", {}))


class HostTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tree = FakeTree(Path(self.tmp.name))
        self.host = Host(str(self.tree.proc), str(self.tree.cgroup))
        self.tree.add(42, "system.slice/docker-abc.scope")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_readers(self) -> None:
        self.tree.net(42, 1000, 500)
        self.assertEqual(self.host.net_bytes(42), 1500)
        self.assertEqual(self.host.cgroup_dir(42), self.tree.cg("system.slice/docker-abc.scope"))
        mem = self.host.memory(self.tree.cg("system.slice/docker-abc.scope"))
        assert mem is not None
        self.assertEqual((mem.current, mem.anon, mem.file), (200 * MIB, 180 * MIB, 10 * MIB))
        self.assertEqual(self.host.meminfo()["SwapFree"], 4000 * MIB)
        self.assertTrue(self.host.cgroup_v2())
        self.assertTrue(self.host.pid_alive(42))
        self.assertFalse(self.host.pid_alive(43))
        self.assertIsNone(self.host.net_bytes(43))
        self.assertIsNone(self.host.pressure_full_avg10())
        self.tree.pressure(12.5)
        self.assertEqual(self.host.pressure_full_avg10(), 12.5)

    def test_swap_max_limits_what_is_reclaimable(self) -> None:
        cg = self.tree.cg("system.slice/docker-abc.scope")

        def read() -> idlenap.Memory:
            mem = self.host.memory(cg)
            assert mem is not None
            return mem

        self.assertIsNone(read().swap_max)
        self.assertEqual(idlenap.reclaimable(read()), 190 * MIB)
        (cg / "memory.swap.max").write_text("max\n")
        self.assertIsNone(read().swap_max)
        (cg / "memory.swap.max").write_text("0\n")
        self.assertEqual(read().swap_max, 0)
        self.assertEqual(idlenap.reclaimable(read()), 10 * MIB)
        (cg / "memory.swap.max").write_text(f"{50 * MIB}\n")
        self.assertEqual(idlenap.reclaimable(read()), 60 * MIB)


    def test_cgroup_path_from_inside_a_cgroup_namespace(self) -> None:
        self.tree.add(77, "system.slice/kiri.service/kiri/demo123")
        (self.tree.proc / "77" / "cgroup").write_text("0::/../demo123\n")
        self.assertEqual(self.host.cgroup_dir(77), self.tree.cg("system.slice/kiri.service/kiri/demo123"))
        (self.tree.proc / "77" / "cgroup").write_text("0::/../../system.slice/missing\n")
        self.assertIsNone(self.host.cgroup_dir(77))


class ReclaimerTests(unittest.TestCase):
    def test_outcomes(self) -> None:
        calls: list[bytes] = []

        def raising(code: int | None) -> Callable[[Path, bytes], None]:
            def writer(path: Path, data: bytes) -> None:
                calls.append(data)
                if code is not None:
                    raise OSError(code, "x")

            return writer

        self.assertEqual(Reclaimer(None, raising(None)).request(Path("/cg"), 100), "ok")
        self.assertEqual(Reclaimer(None, raising(errno.EAGAIN)).request(Path("/cg"), 100), "partial")
        self.assertEqual(Reclaimer(None, raising(errno.EINVAL)).request(Path("/cg"), 100), "error:EINVAL")

    def test_swappiness_fallback(self) -> None:
        calls: list[bytes] = []

        def writer(path: Path, data: bytes) -> None:
            calls.append(data)
            if b"swappiness" in data:
                raise OSError(errno.EINVAL, "invalid")

        reclaimer = Reclaimer(200, writer)
        self.assertEqual(reclaimer.request(Path("/cg"), 100), "ok")
        self.assertEqual(calls, [b"100 swappiness=200", b"100"])
        self.assertTrue(reclaimer.swappiness_rejected)
        self.assertIsNone(reclaimer.swappiness)

    @unittest.skipIf(sys.platform == "win32", "SIGALRM is not available on Windows")
    def test_timeout_interrupts_a_stuck_write(self) -> None:
        if sys.platform == "win32":
            return
        before = signal.getsignal(signal.SIGALRM)

        def stuck(path: Path, data: bytes) -> None:
            time.sleep(5)

        started = time.monotonic()
        self.assertEqual(Reclaimer(None, stuck, timeout=0.2).request(Path("/cg"), 100), "timeout")
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(signal.getsignal(signal.SIGALRM), before)


class DaemonTests(unittest.TestCase):
    rel = "system.slice/docker-web.scope"

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.tree = FakeTree(root)
        self.tree.add(100, self.rel)
        self.events = Recorder()
        self.writer = FreeingWriter(self.tree, self.rel)
        self.cfg = Config(
            interval=30,
            state_file=str(root / "state" / "state.json"),
            proc_root=str(self.tree.proc),
            cgroup_root=str(self.tree.cgroup),
            rules=[Rule("shop-web", "web", 60)],
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def daemon(self, containers: list[ContainerInfo] | None = None) -> Daemon:
        return Daemon(
            self.cfg,
            FakeDocker(containers or [info("shop-web", 100)]),
            Host(self.cfg.proc_root, self.cfg.cgroup_root),
            Reclaimer(None, self.writer),
            self.events,
        )

    def test_dry_run_sleeps_and_wakes_without_writing(self) -> None:
        daemon = self.daemon()
        daemon.tick(1000)
        daemon.tick(1030)
        self.assertEqual(self.events.named("reclaim"), [])
        daemon.tick(1060)
        reclaims = self.events.named("reclaim")
        self.assertEqual(len(reclaims), 1)
        self.assertTrue(reclaims[0]["dry_run"])
        self.assertEqual(reclaims[0]["estimate_mb"], 190.0)
        self.assertEqual(self.writer.calls, [])
        self.tree.net(100, 50_000, 80_000)
        daemon.tick(1090)
        self.assertEqual(len(self.events.named("wake")), 1)
        st = daemon.stats["shop-web"]
        self.assertEqual((st.reclaims, st.wakes, st.asleep_ticks), (1, 1, 1))
        self.assertEqual(st.saved_sum, 190 * MIB)

    def test_small_traffic_is_ignored(self) -> None:
        daemon = self.daemon()
        daemon.tick(1000)
        self.tree.net(100, 1000, 500)
        daemon.tick(1030)
        daemon.tick(1060)
        self.assertEqual(len(self.events.named("reclaim")), 1)

    def test_apply_reclaims_and_tops_up_only_on_real_growth(self) -> None:
        self.cfg.apply = True
        daemon = self.daemon()
        daemon.tick(1000)
        daemon.tick(1060)
        reclaims = self.events.named("reclaim")
        self.assertEqual(len(reclaims), 1)
        self.assertEqual(reclaims[0]["freed_mb"], 197.0)
        self.assertEqual(reclaims[0]["result"], "ok")
        self.assertEqual(self.writer.calls, [str(190 * MIB).encode()])
        st = daemon.stats["shop-web"]
        self.assertEqual((st.current, st.saved_sum), (3 * MIB, 197 * MIB))
        self.tree.mem(self.rel, current=23 * MIB, anon=20 * MIB, file=0, swap=170 * MIB)
        daemon.tick(1090)
        self.assertEqual(len(self.events.named("reclaim")), 1)
        self.tree.mem(self.rel, current=80 * MIB, anon=75 * MIB, file=0, swap=120 * MIB)
        daemon.tick(1120)
        reclaims = self.events.named("reclaim")
        self.assertEqual(len(reclaims), 2)
        self.assertEqual(reclaims[1]["reason"], "topup")

    def test_swap_max_zero_reclaims_page_cache_only(self) -> None:
        self.cfg.apply = True
        (self.tree.cg(self.rel) / "memory.swap.max").write_text("0\n")
        daemon = self.daemon()
        daemon.tick(1000)
        daemon.tick(1060)
        self.assertEqual(self.writer.calls, [str(10 * MIB).encode()])
        warns = [w for w in self.events.named("warn") if "memory.swap.max" in w["message"]]
        self.assertEqual(len(warns), 1)
        self.assertEqual(warns[0]["container"], "shop-web")

    def test_restore_swap_sets_swap_like_docker_and_reclaims(self) -> None:
        self.cfg.apply = True
        self.cfg.restore_swap = True
        cg = self.tree.cg(self.rel)
        (cg / "memory.swap.max").write_text("0\n")
        (cg / "memory.max").write_text(f"{256 * MIB}\n")
        daemon = self.daemon()
        daemon.tick(1000)
        self.assertEqual(self.writer.swap_writes, [str(256 * MIB).encode()])
        self.assertEqual(self.events.named("swap"), [{"container": "shop-web", "swap_max_mb": 256.0}])
        daemon.tick(1030)
        self.assertEqual(len(self.writer.swap_writes), 1)
        daemon.tick(1060)
        self.assertEqual(self.writer.calls, [str(190 * MIB).encode()])
        self.assertEqual([w for w in self.events.named("warn") if "memory.swap.max" in w["message"]], [])
        (cg / "memory.swap.max").write_text("0\n")
        daemon.tick(1090)
        self.assertEqual(len(self.writer.swap_writes), 2)

    def test_restore_swap_without_memory_limit_uses_max(self) -> None:
        self.cfg.apply = True
        self.cfg.restore_swap = True
        cg = self.tree.cg(self.rel)
        (cg / "memory.swap.max").write_text("0\n")
        (cg / "memory.max").write_text("max\n")
        self.daemon().tick(1000)
        self.assertEqual(self.writer.swap_writes, [b"max"])
        self.assertEqual(self.events.named("swap"), [{"container": "shop-web", "swap_max": "max"}])

    def test_restore_swap_in_dry_run_only_estimates(self) -> None:
        self.cfg.restore_swap = True
        cg = self.tree.cg(self.rel)
        (cg / "memory.swap.max").write_text("0\n")
        (cg / "memory.max").write_text(f"{256 * MIB}\n")
        daemon = self.daemon()
        daemon.tick(1000)
        daemon.tick(1060)
        self.assertEqual(self.writer.swap_writes, [])
        self.assertEqual(self.writer.calls, [])
        self.assertEqual(self.events.named("reclaim")[0]["estimate_mb"], 190.0)
        self.assertEqual(self.events.named("warn"), [])

    def test_restore_swap_leaves_non_targets_alone(self) -> None:
        self.cfg.apply = True
        self.cfg.restore_swap = True
        self.tree.add(200, "system.slice/docker-db.scope")
        db = self.tree.cg("system.slice/docker-db.scope")
        (db / "memory.swap.max").write_text("0\n")
        (db / "memory.max").write_text(f"{512 * MIB}\n")
        self.daemon([info("shop-web", 100), info("shared-db", 200)]).tick(1000)
        self.assertEqual(self.writer.swap_writes, [])
        self.assertEqual((db / "memory.swap.max").read_text(), "0\n")

    def test_nothing_reclaimable_writes_nothing(self) -> None:
        self.cfg.apply = True
        self.tree.mem(self.rel, current=200 * MIB, anon=195 * MIB, file=2 * MIB)
        (self.tree.cg(self.rel) / "memory.swap.max").write_text("0\n")
        daemon = self.daemon()
        daemon.tick(1000)
        daemon.tick(1060)
        self.assertEqual(self.writer.calls, [])

    def test_guards_block_apply(self) -> None:
        self.cfg.apply = True
        self.tree.meminfo(swap_total=0, swap_free=0)
        daemon = self.daemon()
        daemon.tick(1000)
        daemon.tick(1060)
        self.assertEqual(self.writer.calls, [])
        self.assertEqual(self.events.named("skip")[0]["why"], "no swap")
        self.tree.meminfo(swap_total=4096 * MIB, swap_free=4000 * MIB)
        self.tree.pressure(50.0)
        daemon.tick(1090)
        self.assertIn("memory pressure", self.events.named("skip")[1]["why"])
        self.tree.pressure(0.0)
        (self.tree.cg(self.rel) / "memory.reclaim").unlink()
        daemon.tick(1120)
        self.assertIn("memory.reclaim", self.events.named("skip")[2]["why"])

    def test_non_targets_are_observed_but_never_reclaimed(self) -> None:
        self.tree.add(200, "system.slice/docker-db.scope")
        daemon = self.daemon([info("shop-web", 100), info("shared-db", 200)])
        for t in range(1000, 1300, 30):
            daemon.tick(t)
        names = {data["container"] for data in self.events.named("reclaim")}
        self.assertEqual(names, {"shop-web"})
        self.assertEqual(daemon.stats["shared-db"].quiet_ticks, 10)
        self.assertIsNone(daemon.stats["shared-db"].mode)

    def test_host_network_uses_cpu(self) -> None:
        daemon = self.daemon([info("shop-web", 100, host_network=True)])
        daemon.tick(1000)
        self.tree.cpu(self.rel, 5_000_000)
        daemon.tick(1030)
        self.tree.cpu(self.rel, 5_050_000)
        daemon.tick(1060)
        self.assertEqual(self.events.named("reclaim"), [])
        daemon.tick(1090)
        self.assertEqual(len(self.events.named("reclaim")), 1)

    def test_counter_reset_counts_as_activity(self) -> None:
        self.tree.net(100, 900_000, 900_000)
        daemon = self.daemon()
        daemon.tick(1000)
        self.tree.net(100, 10, 10)
        daemon.tick(1030)
        daemon.tick(1060)
        self.assertEqual(self.events.named("reclaim"), [])

    def test_background_backs_off_when_pages_come_back(self) -> None:
        self.cfg.apply = True
        self.cfg.rules = [Rule("shop-web", "background", 600)]
        self.cfg.background_min_interval = 300
        self.cfg.background_max_interval = 2400
        daemon = self.daemon()
        daemon.tick(1000)
        daemon.tick(1300)
        self.assertEqual(len(self.events.named("reclaim")), 1)
        page = daemon.page
        self.tree.mem(self.rel, current=150 * MIB, anon=140 * MIB, file=0, swap=50 * MIB, refault=150 * MIB // page)
        daemon.tick(1600)
        reclaims = self.events.named("reclaim")
        self.assertEqual(len(reclaims), 2)
        self.assertEqual(reclaims[1]["next_s"], 600)
        track = daemon.tracks["shop-web-id"]
        self.assertEqual(track.next_step, 2200)

    def test_front_door_traffic_decides_and_backend_noise_is_ignored(self) -> None:
        self.tree.add(300, "system.slice/docker-nginx.scope")
        containers = [
            info("shop-web", 100, project="shop"),
            info("shop-nginx", 300, project="shop", published=True),
        ]
        daemon = self.daemon(containers)
        daemon.tick(1000)
        self.assertEqual(self.events.named("watch"), [{"container": "shop-web", "front_door": "shop-nginx"}])
        self.tree.net(100, 40_000, 40_000)
        daemon.tick(1030)
        daemon.tick(1060)
        self.assertEqual(len(self.events.named("reclaim")), 1)
        self.tree.net(300, 30_000, 60_000)
        daemon.tick(1090)
        self.assertEqual(len(self.events.named("wake")), 1)
        self.assertEqual(daemon.stats["shop-web"].watch, "shop-nginx")

    def test_explicit_watch_and_rule_threshold(self) -> None:
        self.tree.add(300, "system.slice/docker-proxy.scope")
        self.cfg.rules = [Rule("shop-web", "web", 60, watch="edge", activity_bytes=100)]
        daemon = self.daemon([info("shop-web", 100), info("edge", 300)])
        daemon.tick(1000)
        self.tree.net(300, 150, 0)
        daemon.tick(1030)
        daemon.tick(1060)
        self.assertEqual(self.events.named("reclaim"), [])
        daemon.tick(1090)
        self.assertEqual(len(self.events.named("reclaim")), 1)

    def test_missing_watch_falls_back_with_warning(self) -> None:
        self.cfg.rules = [Rule("shop-web", "web", 60, watch="nope")]
        daemon = self.daemon()
        daemon.tick(1000)
        self.assertEqual(self.events.named("warn")[0]["watch"], "nope")

    def test_peak_quiet_bytes_shows_noise_floor(self) -> None:
        daemon = self.daemon()
        daemon.tick(1000)
        self.tree.net(100, 1500, 1500)
        daemon.tick(1030)
        self.tree.net(100, 2000, 2000)
        daemon.tick(1060)
        self.assertEqual(daemon.stats["shop-web"].peak_quiet_bytes, 3000)

    def test_dry_run_background_is_only_an_upper_bound(self) -> None:
        self.cfg.rules = [Rule("shop-web", "background", 600)]
        self.cfg.background_min_interval = 300
        daemon = self.daemon()
        for t in range(1000, 1700, 30):
            daemon.tick(t)
        st = daemon.stats["shop-web"]
        self.assertEqual(st.saved_sum, 0)
        self.assertGreater(st.bound_sum, 0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            idlenap.command_status(self.cfg, False)
        self.assertIn("average RAM saved: 0 MB", out.getvalue())
        self.assertIn("upper bound", out.getvalue())

    def test_write_error_does_not_mark_asleep(self) -> None:
        self.cfg.apply = True

        def denied(path: Path, data: bytes) -> None:
            raise OSError(errno.EACCES, "denied")

        daemon = Daemon(
            self.cfg,
            FakeDocker([info("shop-web", 100)]),
            Host(self.cfg.proc_root, self.cfg.cgroup_root),
            Reclaimer(None, denied),
            self.events,
        )
        daemon.tick(1000)
        daemon.tick(1060)
        daemon.tick(1090)
        errors = self.events.named("error")
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["error"], "error:EACCES")
        self.assertFalse(daemon.stats["shop-web"].asleep)
        self.assertEqual(daemon.stats["shop-web"].reclaims, 0)
        self.assertEqual(self.events.named("reclaim"), [])

    def test_short_healthcheck_warns(self) -> None:
        daemon = self.daemon([info("shop-web", 100, hc=1.0)])
        daemon.tick(1000)
        warns = self.events.named("warn")
        self.assertEqual(len(warns), 1)
        self.assertEqual(warns[0]["container"], "shop-web")

    def test_state_roundtrip_and_status(self) -> None:
        daemon = self.daemon()
        for t in range(1000, 1200, 30):
            daemon.tick(t)
        data = json.loads(Path(self.cfg.state_file).read_text())
        self.assertIn("shop-web", data["containers"])
        again = self.daemon()
        again.load_state()
        self.assertEqual(again.stats["shop-web"].ticks, daemon.stats["shop-web"].ticks)
        self.assertFalse(again.stats["shop-web"].asleep)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = idlenap.command_status(self.cfg, False)
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("shop-web", text)
        self.assertIn("dry-run estimate", text)

    def test_gone_container_is_marked_awake(self) -> None:
        docker = FakeDocker([info("shop-web", 100)])
        daemon = Daemon(self.cfg, docker, Host(self.cfg.proc_root, self.cfg.cgroup_root), Reclaimer(None, self.writer), self.events)
        daemon.tick(1000)
        daemon.tick(1060)
        self.assertTrue(daemon.stats["shop-web"].asleep)
        docker.infos = []
        daemon.tick(1090)
        self.assertFalse(daemon.stats["shop-web"].asleep)
        self.assertEqual(daemon.tracks, {})

    def test_state_tells_the_panel_where_to_read_memory(self) -> None:
        daemon = self.daemon([info("shop-web", 100)])
        daemon.tick(1000)
        saved = json.loads(Path(self.cfg.state_file).read_text())["containers"]["shop-web"]
        self.assertEqual(saved["cgroup"], self.rel)
        self.assertEqual(saved["idle_s"], 60)


class CliTests(unittest.TestCase):
    def test_config_from_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.toml"
            path.write_text("nope = 1\n")
            err = io.StringIO()
            with unittest.mock.patch.dict("os.environ", {"IDLENAP_CONFIG": str(path)}), contextlib.redirect_stderr(err):
                self.assertEqual(idlenap.main(["status"]), 2)
            self.assertIn("unknown keys", err.getvalue())

    def test_bad_config_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.toml"
            path.write_text("nope = 1\n")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(idlenap.main(["status", "-c", str(path)]), 2)
            self.assertIn("unknown keys", err.getvalue())

    def test_listen_address(self) -> None:
        self.assertEqual(parse_listen("0.0.0.0:9180"), ("0.0.0.0", 9180))
        self.assertEqual(parse_listen(":9180"), ("0.0.0.0", 9180))
        for bad in ("9180", "host:port", "host:70000"):
            with self.assertRaises(ValueError):
                parse_listen(bad)
        self.assertEqual(config_from_dict({"events_file": "/tmp/e.jsonl"}).events_file, "/tmp/e.jsonl")


class EventLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "events.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_rotation_loses_nothing_for_a_follower(self) -> None:
        log = EventLog(str(self.path), max_bytes=400)
        follower = EventFollower(self.path)
        self.assertEqual(follower.backlog(50), [])
        seen: list[dict[str, Any]] = []
        with contextlib.redirect_stdout(io.StringIO()):
            for n in range(12):
                log.emit("wake", {"container": "shop-web", "n": n})
                if n % 4 == 3:
                    seen += follower.poll()
        seen += follower.poll()
        self.assertEqual([record["n"] for record in seen], list(range(12)))
        self.assertTrue(rotated(self.path).exists())
        self.assertLessEqual(self.path.stat().st_size, 400)
        self.assertIsInstance(seen[0]["t"], float)
        backlog = EventFollower(self.path).backlog(50)
        self.assertEqual(backlog[-1]["n"], 11)
        self.assertEqual([record["n"] for record in backlog], sorted(record["n"] for record in backlog))

    def test_partial_line_waits_for_its_newline(self) -> None:
        self.path.write_bytes(b'{"event": "wake", "ts": "bad"}\n{"event": "rec')
        follower = EventFollower(self.path)
        backlog = follower.backlog(10)
        self.assertEqual([(r["event"], r["t"]) for r in backlog], [("wake", None)])
        self.assertEqual(follower.poll(), [])
        with open(self.path, "ab") as fh:
            fh.write(b'laim"}\nnot json\n')
        self.assertEqual([r["event"] for r in follower.poll()], ["reclaim"])


class WebSocketTests(unittest.TestCase):
    def test_accept_key_from_the_rfc(self) -> None:
        self.assertEqual(ws_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        self.assertTrue(ws_key_valid("dGhlIHNhbXBsZSBub25jZQ=="))
        self.assertFalse(ws_key_valid("not base64"))
        self.assertFalse(ws_key_valid(base64.b64encode(b"short").decode()))

    def test_frames_roundtrip_and_violations(self) -> None:
        left, right = socket.socketpair()
        with left, right:
            right.settimeout(5)
            for size in (5, 300, 70_000):
                payload = bytes(n % 251 for n in range(size))
                sender = threading.Thread(target=left.sendall, args=(ws_frame(WS_TEXT, payload, mask=b"abcd"),))
                sender.start()
                self.assertEqual(ws_read(right, 100_000), (WS_TEXT, payload))
                sender.join()
        for frame, limit, code in ((ws_frame(WS_TEXT, b"plain"), 4096, 1002), (ws_frame(WS_TEXT, b"x" * 200, mask=b"abcd"), 100, 1009)):
            left, right = socket.socketpair()
            with left, right:
                right.settimeout(5)
                left.sendall(frame)
                with self.assertRaises(WSError) as caught:
                    ws_read(right, limit)
                self.assertEqual(caught.exception.code, code)

    def test_origin(self) -> None:
        self.assertTrue(origin_allowed(None, "127.0.0.1:9180"))
        self.assertTrue(origin_allowed("http://127.0.0.1:9180", "127.0.0.1:9180"))
        self.assertTrue(origin_allowed("https://Panel.Example", "panel.example"))
        self.assertFalse(origin_allowed("https://evil.example", "panel.example"))
        self.assertFalse(origin_allowed("null", "panel.example"))
        self.assertFalse(origin_allowed("https://panel.example", None))


class PanelTests(unittest.TestCase):
    rel = "system.slice/docker-web.scope"
    key = base64.b64encode(b"0123456789abcdef").decode()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.tree = FakeTree(root)
        self.tree.add(100, self.rel)
        self.cfg = Config(
            state_file=str(root / "state.json"),
            events_file=str(root / "events.jsonl"),
            proc_root=str(self.tree.proc),
            cgroup_root=str(self.tree.cgroup),
        )
        self.write_state(asleep=True)
        self.log = EventLog(self.cfg.events_file)
        self.emit("reclaim", {"container": "shop-web", "before_mb": 200.0, "after_mb": 3.0})
        self.hub = Hub(self.cfg, Host(self.cfg.proc_root, self.cfg.cgroup_root), sample_every=0.1)
        self.hub.prime(time.time())
        self.server = PanelServer(("127.0.0.1", 0), self.hub)
        self.port = self.server.server_port
        self.threads = [
            threading.Thread(target=self.hub.run, kwargs={"poll": 0.05}),
            threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}),
        ]
        for thread in self.threads:
            thread.start()

    def tearDown(self) -> None:
        self.hub.stop.set()
        self.server.shutdown()
        self.server.server_close()
        for thread in self.threads:
            thread.join(5)
        self.tmp.cleanup()

    def emit(self, event: str, data: dict[str, Any]) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.log.emit(event, data)

    def write_state(self, asleep: bool) -> None:
        now = time.time()
        container = {
            "mode": "web",
            "ticks": 4,
            "quiet_ticks": 3,
            "saved_sum": 4 * 10 * MIB,
            "asleep": asleep,
            "last_seen": now,
            "quiet_for": 700.0,
            "cgroup": self.rel,
            "idle_s": 600,
            "current": 200 * MIB,
        }
        state = {"updated": now, "apply": True, "interval": 30, "containers": {"shop-web": container, "other": {"mode": None}}}
        Path(self.cfg.state_file).write_text(json.dumps(state))

    def handshake(self, origin: str | None) -> tuple[socket.socket, bytes]:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        lines = [
            "GET /ws HTTP/1.1",
            f"Host: 127.0.0.1:{self.port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {self.key}",
            "Sec-WebSocket-Version: 13",
        ]
        if origin is not None:
            lines.append(f"Origin: {origin}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            head += chunk
        return sock, head

    def next_message(self, sock: socket.socket, kind: str) -> dict[str, Any]:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            opcode, data = ws_read(sock, 1 << 20, masked=False)
            if opcode == WS_TEXT:
                message = json.loads(data)
                if message["type"] == kind:
                    return message
        self.fail(f"no {kind} message")

    def test_streams_hello_samples_events_and_state(self) -> None:
        sock, head = self.handshake(f"http://127.0.0.1:{self.port}")
        with sock:
            self.assertTrue(head.startswith(b"HTTP/1.1 101"))
            self.assertIn(ws_accept(self.key).encode(), head)
            hello = self.next_message(sock, "hello")
            self.assertEqual([row["name"] for row in hello["state"]["containers"]], ["shop-web"])
            row = hello["state"]["containers"][0]
            self.assertEqual((row["asleep"], row["quiet_pct"], row["saved_mb"], row["idle_s"]), (True, 75, 10.0, 600))
            self.assertEqual(hello["events"][-1]["event"], "reclaim")
            sample = self.next_message(sock, "sample")
            self.assertEqual(sample["ram"]["shop-web"], [200.0, 0.0])
            self.assertEqual(sample["host"]["swap_total_mb"], 4096.0)
            self.emit("wake", {"container": "shop-web", "ram_mb": 40.0})
            self.assertEqual(self.next_message(sock, "events")["items"][0]["event"], "wake")
            self.write_state(asleep=False)
            self.assertFalse(self.next_message(sock, "state")["state"]["containers"][0]["asleep"])
            sock.sendall(ws_frame(WS_CLOSE, (1000).to_bytes(2, "big"), mask=b"wxyz"))
            deadline = time.monotonic() + 5
            opcode = None
            while opcode != WS_CLOSE and time.monotonic() < deadline:
                opcode, _ = ws_read(sock, 1 << 20, masked=False)
            self.assertEqual(opcode, WS_CLOSE)

    def test_foreign_origin_is_rejected(self) -> None:
        sock, head = self.handshake("https://evil.example")
        sock.close()
        self.assertTrue(head.startswith(b"HTTP/1.1 403"))

    def test_page_and_script_are_served_with_csp(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/")
            page = conn.getresponse()
            body = page.read()
            self.assertEqual(page.status, 200)
            self.assertIn("script-src 'self'", page.getheader("Content-Security-Policy") or "")
            self.assertIn(b'<script src="/app.js">', body)
            conn.request("GET", "/app.js")
            script = conn.getresponse()
            self.assertEqual((script.status, script.getheader("Content-Type")), (200, "text/javascript; charset=utf-8"))
            self.assertIn(b"new WebSocket", script.read())
            conn.request("GET", "/ws")
            plain = conn.getresponse()
            plain.read()
            self.assertEqual(plain.status, 400)
        finally:
            conn.close()

    def test_state_view_marks_gone_targets(self) -> None:
        view = panel_state(
            {
                "updated": 1000,
                "interval": 30,
                "containers": {"a": {"mode": "web", "last_seen": 1000}, "b": {"mode": "web", "last_seen": 900, "asleep": True}},
            }
        )
        self.assertEqual([(r["name"], r["gone"], r["asleep"]) for r in view["containers"]], [("a", False, False), ("b", True, False)])


if __name__ == "__main__":
    unittest.main()
