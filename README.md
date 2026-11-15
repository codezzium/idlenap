# idlenap

Swap out the memory of idle containers, and let the Linux kernel bring it back on the next request.

idlenap watches your running containers. When a web container has seen no traffic for a while, it asks the kernel to push that container's memory to swap through the cgroup v2 `memory.reclaim` interface. The processes keep running and keep their database connections. When a request arrives, the kernel faults the needed pages back in. Nothing sits in the request path: no proxy, no restarts, no changes to your compose files.

```
client ──► reverse proxy / tunnel ──► nginx ──► app          (traffic path is untouched)
                                        ▲
idlenap ── reads: traffic counters ─────┤
        └─ idle for N minutes? write memory.reclaim ──► app memory goes to swap
```

> Status: alpha. Run it in dry-run mode first (the default).

## Why not stop the container?

Stopping a container frees all of its memory, but the next request has to wait for a full start. Pausing (`docker pause`) is instant to resume but frees no memory at all. Checkpoint/restore (CRIU) kills and restores the process, which breaks open database connections and is experimental in Docker.

Measured on a Django app (gunicorn, 3 sync workers, Postgres and Redis next to it). These numbers come from a local test machine (WSL2, kernel 6.18), not from production:

| Method | RAM held while idle | First request after idle |
|---|---|---|
| running normally | 228 MB | 14 ms |
| `docker pause` | 228 MB | ~0.4 s |
| `docker stop` / `start` | 0 MB | ~4.8 s |
| idlenap (`memory.reclaim`) | 3 MB, then 15-25 MB with health checks | ~0.6 s per worker |

## How it decides

Every `interval` seconds idlenap lists running containers through the Docker API and reads, for each one:

- network bytes from `/proc/<pid>/net/dev` (every interface except `lo`);
- `memory.current`, `memory.stat` and `memory.swap.current` from the container's cgroup.

Containers are matched against your rules. A container that matches no rule is only observed, never touched.

**web mode** (default): if the container saw no traffic for `idle`, idlenap writes `memory.reclaim`. The next real request wakes it, which the kernel handles on its own. While asleep, idlenap reclaims again only if memory grows by more than `topup_mb`, so the few pages a health check keeps warm are not pushed out and pulled back in a loop.

Health checks usually run inside the container over `lo`, but the app may talk to its database and cache during the check, and that traffic does cross `eth0`. To avoid counting it, idlenap watches the **front door** when it can: if the target publishes no ports and exactly one other container in the same compose project does (typically nginx), traffic is measured there. You can also name the container to watch with `watch`.

**background mode** (workers, beat, cron): these poll queues all the time, so traffic says nothing about idleness. idlenap reclaims them on a timer instead and watches `workingset_refault_anon`. If more than half of what was reclaimed comes straight back, the timer backs off (up to `background_max_interval`); if almost nothing comes back, it speeds up.

## Safety

- Dry-run by default. Nothing is written until you pass `--apply` or set `apply = true`.
- Opt-in only. Containers must match a `[[target]]` rule or carry `idlenap.enable=true`. `exclude` and `idlenap.enable=false` always win.
- No memory limits are lowered. idlenap never touches `memory.max` or `memory.high`, so it cannot cause an OOM kill. The only limit it can change is `memory.swap.max`, and only when you enable `restore_swap` (see below).
- Guards before every reclaim: enough free swap (`min_swap_free_mb`), host memory pressure below `max_pressure` (PSI `full avg10`), and `memory.reclaim` present.
- Health checks with a timeout below `healthcheck_min_timeout` are reported, because the first check after a reclaim can be slower.
- Each reclaim asks only for what can actually go: page cache, plus anonymous memory as far as the container's `memory.swap.max` allows. The write is interrupted after `reclaim_timeout` seconds. On some kernels (seen on 6.12) a request larger than what can be freed keeps one CPU busy until it is interrupted.

Every reclaim writes to swap. On SSDs this is a small, bounded amount per idle period, but keep it in mind on cheap flash.

## Requirements

- Linux with cgroup v2, kernel 5.19 or newer (`memory.reclaim`)
- swap (a swap file is fine)
- Docker, or another engine that speaks the Docker Engine API (Kiri works too)

## Run

Build the image once, put a config in `/etc/idlenap`, then start it with a single command:

```sh
docker build -t idlenap .
sudo mkdir -p /etc/idlenap && sudo cp config.example.toml /etc/idlenap/config.toml

docker run -d --name idlenap --restart unless-stopped \
  -v /proc:/host/proc:ro \
  -v /sys/fs/cgroup:/host/cgroup:rw \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc/localtime:/etc/localtime:ro \
  -v /etc/idlenap:/etc/idlenap:ro \
  -v idlenap-state:/var/lib/idlenap \
  idlenap
```

| Mount | Why |
|---|---|
| `/proc` → `/host/proc` (read-only) | traffic counters and the cgroup of each container |
| `/sys/fs/cgroup` → `/host/cgroup` (read-write) | memory statistics, and `memory.reclaim` with `apply = true` |
| `/var/run/docker.sock` | the list of running containers; with Kiri use `/run/kiri/docker.sock` on the left |
| `/etc/localtime` | log timestamps in the host's time zone |
| `/etc/idlenap` | `config.toml` |
| `idlenap-state` | statistics shown by `idlenap status` |

It does not need `privileged`, `--pid host` or `--cgroupns host`: idlenap resolves cgroup paths seen from inside a cgroup namespace by itself. These mounts still give the container control over the host, so treat it like root.

Tested on Kiri (WSL2). Hosts with AppArmor (Debian, Ubuntu) have not been tested yet.

Kiri 0.2.1 sets `memory.swap.max` to 0 for every container started with a memory or CPU limit, so only page cache can be reclaimed from those. `idlenap check` marks them. With `restore_swap = true` (and `apply = true`), idlenap sets `memory.swap.max` of such targets to their memory limit, which is what Docker does for `--memory`. Kiri writes 0 again when the container restarts, so idlenap checks on every tick.

Check the host and see which containers your rules pick:

```sh
docker exec idlenap idlenap check
```

After a day or two in dry-run mode, look at the estimate:

```sh
docker exec idlenap idlenap status
```

```
CONTAINER      MODE  STATE  QUIET  LONGEST  RAM_MB  SWAP_MB  SAVED_MB  WAKES  NOISE_KB  WATCH
codezzium-web  web   awake  92%    1m       42      188      37        1      0.3       codezzium-nginx
```

- `QUIET`: share of samples with no traffic.
- `SAVED_MB`: average memory freed (estimated in dry-run).
- `NOISE_KB`: the largest traffic sample that still counted as quiet. If it is close to `activity_bytes`, raise the threshold or set `watch`.

Then set `apply = true` in `/etc/idlenap/config.toml` and run `docker restart idlenap`.

Without Docker, the same file runs directly with Python 3.11+ (standard library only), as root: `sudo python3 idlenap.py run -c config.toml`.

## Panel

`idlenap panel` serves a live web page: host memory, swap and pressure, each target's RAM and swap every 2 seconds with a 10-minute chart, and the event feed as it happens. The browser gets everything over one WebSocket.

```
idlenap run ──► state.json + events.jsonl ──► idlenap panel ──WebSocket──► browser
                                                └─ reads memory.current every 2 s
```

Run it as a second container from the same image. It only reads: no Docker socket, the cgroup tree and the state volume are mounted read-only, and it runs as `nobody`.

```sh
docker run -d --name idlenap-panel --restart unless-stopped \
  --user 65534:65534 \
  -p 127.0.0.1:9180:9180 \
  -v /proc:/host/proc:ro \
  -v /sys/fs/cgroup:/host/cgroup:ro \
  -v /etc/localtime:/etc/localtime:ro \
  -v /etc/idlenap:/etc/idlenap:ro \
  -v idlenap-state:/var/lib/idlenap:ro \
  idlenap panel --listen 0.0.0.0:9180
```

Then open `http://127.0.0.1:9180`. The panel has no login of its own and shows container names, so keep it on `127.0.0.1` and reach it through an SSH tunnel or a reverse proxy with authentication. WebSocket connections from another origin are refused.

Sleep state, quiet time and events come from the daemon's tick (`interval`); RAM and swap come straight from the cgroup files, so they move between ticks.

## Configuration

```toml
interval = "30s"
apply = false
exclude = ["shared-*", "*-db", "*redis*", "*nginx*"]

[[target]]
match = "*-web"
idle = "10m"

[[target]]
match = "*worker*"
mode = "background"
```

| Key | Default | Meaning |
|---|---|---|
| `interval` | `30s` | sampling period |
| `apply` | `false` | really write `memory.reclaim` |
| `docker_socket` | `/var/run/docker.sock` | Docker Engine API socket |
| `state_file` | `/var/lib/idlenap/state.json` | statistics read by `idlenap status` and the panel |
| `events_file` | `/var/lib/idlenap/events.jsonl` | every event, one JSON object per line, read by the panel; rotated at 256 KB |
| `proc_root` / `cgroup_root` | `/proc` / `/sys/fs/cgroup` | host paths; `IDLENAP_PROC_ROOT` / `IDLENAP_CGROUP_ROOT` change the defaults |
| `activity_bytes` | `8192` | bytes per sample that count as traffic |
| `activity_cpu_usec` | `100000` | CPU per sample that counts as activity (host-network containers) |
| `topup_mb` | `64` | growth while asleep that triggers another reclaim |
| `min_reclaim_mb` | `8` | skip containers smaller than this |
| `min_swap_free_mb` | `512` | free swap that must remain after a reclaim |
| `max_pressure` | `10.0` | skip reclaims while PSI memory `full avg10` is above this |
| `swappiness` | unset | passed as `swappiness=` to `memory.reclaim` when the kernel supports it |
| `background_min_interval` / `background_max_interval` | `5m` / `2h` | background mode timer range |
| `healthcheck_min_timeout` | `3.0` | warn about health checks with a shorter timeout |
| `reclaim_timeout` | `5.0` | seconds before a `memory.reclaim` write is interrupted; `0` turns the limit off |
| `restore_swap` | `false` | when a target's `memory.swap.max` is 0, set it to its `memory.max` (Docker's default) |
| `exclude` | `[]` | container name globs that are never touched |

`[[target]]` keys: `match` (glob), `mode` (`web` or `background`), `idle`, `watch` (container name), `activity_bytes`.

Labels, for those who prefer to configure it per container:

```yaml
labels:
  idlenap.enable: "true"
  idlenap.mode: "web"
  idlenap.idle: "15m"
  idlenap.watch: "myapp-nginx"
```

## Logs

One JSON object per line on stdout (`docker logs idlenap`) and in `events_file`: `start`, `target`, `watch`, `swap`, `reclaim`, `wake`, `skip`, `warn`, `error`, `stop`.

```json
{"event": "reclaim", "container": "codezzium-web", "reason": "idle", "before_mb": 228.3, "after_mb": 3.7, "freed_mb": 224.6, "ms": 174, "result": "partial"}
{"event": "wake", "container": "codezzium-web", "ram_mb": 43.5, "swap_mb": 187.8}
```

`result: partial` is normal: idlenap asks for everything and the kernel frees what it can.

## Development

```sh
python3 -m unittest discover -s tests
uvx ty check idlenap.py tests/test_idlenap.py
```

The tests build fake `/proc` and `/sys/fs/cgroup` trees, so they run anywhere.

## Related work

- [Senpai](https://facebookmicrosites.github.io/resctl-demo-website/docs/demo_docs/memory_sizing_senpai/senpai) and Meta's [Transparent Memory Offloading](https://engineering.fb.com/2022/06/20/data-infrastructure/transparent-memory-offloading-more-memory-at-a-fraction-of-the-cost-and-power/) tune memory continuously for every cgroup using pressure feedback. idlenap is narrower: it targets idle containers by name or label and keeps them out of the request path.
- [DAMON_RECLAIM](https://docs.kernel.org/admin-guide/mm/damon/reclaim.html) pages out cold memory system-wide from inside the kernel.
- [Sablier](https://github.com/sablierapp/sablier) stops containers when idle and starts them on demand through a reverse proxy plugin.

## License

MIT. See [LICENSE](LICENSE).
