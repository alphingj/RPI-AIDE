# RPI-AIDE

A small file integrity monitor for Linux hosts, written in Rust. It hashes a set of
directories, stores a baseline, reports added, modified, and deleted paths, watches
for port scans, and serves a dashboard from an HTML page embedded in the binary.

The target deployment is a Raspberry Pi Zero running Pi-hole. One static ARMv6 binary,
no runtime assets, no external requests, and a polling dashboard that stays out of the
DNS fast path.

## Install with one command

On the Pi, as root:

```sh
curl -fsSL https://raw.githubusercontent.com/alphingj/RPI-AIDE/main/install.sh | sudo bash
```

The installer downloads the right static binary for the host architecture, asks a short
set of setup questions, writes the config, creates a dashboard login token, creates the
first baseline, installs a systemd service, and starts it. It prints the dashboard URL
and the login token at the end.

The same command handles upgrades. It keeps an existing config, baseline, and token
unless you pass `--reconfigure`.

Unattended install with the defaults:

```sh
curl -fsSL https://raw.githubusercontent.com/alphingj/RPI-AIDE/main/install.sh | sudo bash -s -- --yes
```

Re-run the setup later:

```sh
sudo rpi-aide-setup --reconfigure
```

Supported release assets:

| Host | Asset |
| ---- | ----- |
| Pi Zero, Pi 1, ARMv6 | `rpi-aide-armv6` |
| Pi 2, Pi 3, Pi 4 with a 32-bit OS | `rpi-aide-armv7` |
| Pi 3, Pi 4, Pi 5 with a 64-bit OS | `rpi-aide-aarch64` |
| x86_64 Linux | `rpi-aide-x86_64` |

All four are static musl binaries. The installer selects the asset from `uname -m` and
verifies it against `SHA256SUMS` before installing. If a release asset is not available,
pass `--binary /path/to/rpi-aide` or build from source.

Releases: https://github.com/alphingj/RPI-AIDE/releases

Version `0.0.2` adds the port-scan guard, token login, scheduled and fast scans,
real-time watch, notifications, severity levels, accepting changes, maintenance
windows, a tamper-evident alert log, a doctor command, and Prometheus metrics.
Upgrades keep the existing config and baseline; new settings take their defaults,
so the guard starts in `monitor` mode and does not block anything until you switch
it to `enforce`.

## What it does

- Walks the configured roots and records files, directories, symlinks, and special files.
- Hashes file contents with BLAKE3 in 4 KB chunks. Reads stop at `max_file_bytes`.
- **Fast scans** reuse a cached hash when a file's size, mtime, ctime, inode, and mode
  are all unchanged, so repeat scans on a Pi Zero take seconds instead of a minute.
  A full rehash happens automatically at `full_scan_interval_secs` or on demand.
- **Scheduled scans** run automatically after boot and then every `scan_interval_secs`
  with jitter, at lowered CPU priority so DNS is never delayed by a scan.
- **Real-time watch** uses inotify on the configured watch paths and triggers a fast
  scan about two seconds after a change lands, rate-limited to one scan per minute.
- **Port-scan guard** watches inbound TCP SYNs on one interface. When a non-allowlisted
  source probes 3 or more distinct critical ports within 10 seconds (or enough ports
  with at least one critical, or 50 SYNs against critical ports), it records the event
  and, in `enforce` mode, blocks the source through nftables or iptables for one hour.
  Repeat offenders are blocked for 24 hours. Bans survive restarts.
- **Severity levels** mark alerts on authentication, systemd, cron, Pi-hole, and boot
  paths as `critical`, binaries and the rest of `/etc` as `warning`, and everything
  else as `info`. The dashboard filters by severity and notifications can require a
  minimum severity.
- **Accept a change** folds the current state of one path into the baseline from the
  dashboard or the CLI, without losing the alert history. Parent directory mtime
  bumps caused by the change are settled too.
- **Maintenance windows** mark new alerts as `expected` and silence notifications
  during package upgrades.
- **Notifications** deliver scan results and port-scan events to a webhook, an ntfy
  topic, or Telegram, through `curl`, with bounded retries.
- **Tamper-evident alert log**: every alert record carries a BLAKE3 chain link, so
  edits or removals inside the log are detectable with `--verify-log`.
- **Token login** protects the dashboard. A 32-hex token file sits next to the config,
  logins create a session cookie, repeated failures lock the source IP out, and the
  token also works as an `Authorization: Bearer` value for scripts.
- `--doctor` prints a health report: config, roots, state permissions, baseline age,
  disk space, service reachability, token mode, notification channel, firewall
  usability, raw-socket permission, and watch paths.
- `GET /metrics` exposes Prometheus gauges for scans, alerts, guard mode, bans, and
  maintenance.
- The dashboard has status, alerts, filters, severity badges, a manual scan button,
  the guard panel, maintenance controls, and light and dark themes. The page is
  embedded with `include_str!`; there is no CDN, web font, image, or build step.

## Requirements

- Linux. The guard's packet capture additionally needs root or `CAP_NET_RAW`, and
  blocking needs nftables or iptables with `CAP_NET_ADMIN`. Everything else degrades
  gracefully: without those, the guard reports why it cannot run and never crashes.
- systemd for the service install. The binary itself does not need systemd.
- Read access to the configured roots.
- The one-command installer needs `curl` or `wget`, `sha256sum`, and `install` from
  coreutils. Raspberry Pi OS has all of them.
- Notifications need `curl` on the host. Without it, delivery is disabled and the
  dashboard says so.
- Rust stable with Cargo only for a source build. For a Pi Zero cross build:
  `rustup target add arm-unknown-linux-musleabihf` and an `arm-linux-gnueabihf-gcc`
  linker. The binary is static and does not need a sysroot at runtime.

## Build

```sh
cargo build --release
cargo test
```

The native binary is `target/release/rpi-aide`.

### Pi Zero (ARMv6, static)

The Pi Zero is ARMv6. Build the musl target with the ARMv6 CPU selected by the target:

```sh
rustup target add arm-unknown-linux-musleabihf
CARGO_TARGET_ARM_UNKNOWN_LINUX_MUSLEABIHF_LINKER=arm-linux-gnueabihf-gcc \
  cargo build --release --target arm-unknown-linux-musleabihf
```

Verify the result before copying it:

```sh
file target/arm-unknown-linux-musleabihf/release/rpi-aide
readelf -A target/arm-unknown-linux-musleabihf/release/rpi-aide | grep Tag_CPU_arch
```

Expected: `ELF 32-bit LSB executable, ARM, EABI5 ... statically linked` and
`Tag_CPU_arch: v6`. Do not use the glibc `arm-unknown-linux-gnueabihf` build for a Pi
Zero. That target is tagged ARMv7 and can fault with an illegal instruction on ARMv6.

### Other release targets

```sh
rustup target add armv7-unknown-linux-musleabihf aarch64-unknown-linux-musl x86_64-unknown-linux-musl

CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=arm-linux-gnueabihf-gcc \
  cargo build --release --target armv7-unknown-linux-musleabihf

CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl

cargo build --release --target x86_64-unknown-linux-musl
```

## Initial setup

The one-command installer is the setup wizard. It asks for:

1. The directories to monitor. The default set is `/etc`, `/boot`,
   `/boot/firmware` when present, `/usr/bin`, `/usr/sbin`, and `/usr/lib/systemd/system`.
2. The dashboard bind address. The default is `127.0.0.1:8080`.
3. The maximum file size to hash. The default is 256 MB.
4. The scheduled scan interval in seconds. The default is 3600.
5. A notification URL for a webhook or ntfy. Empty skips notifications.
6. The port-scan guard mode: `monitor` (log only), `enforce` (block), or `off`.
   The default is `monitor`.
7. The guard allowlist: IPs or CIDRs that never trigger a block. The default is
   the Tailscale range; add your admin machine here so you cannot lock yourself out.

It writes `config.json` with mode `0600`, creates `/var/lib/rpi-aide` with mode `0700`,
creates the login token next to the config, excludes the Pi-hole databases, its own
config and state directories, and volatile paths, creates the baseline, installs the
systemd unit, and starts the service. If the baseline has scan errors, the installer
says so and exits non-zero.

For unattended setup, `--yes` accepts the defaults. Environment variables override the
prompt defaults: `RPI_AIDE_ROOTS`, `RPI_AIDE_BIND`, `RPI_AIDE_MAX_MB`,
`RPI_AIDE_SCAN_SECS`, `RPI_AIDE_NOTIFY_URL`, `RPI_AIDE_GUARD_MODE`, and
`RPI_AIDE_GUARD_ALLOW`.

For example, an install for a Pi that should block scans, keep the PC and router
allowlisted, and notify an ntfy topic:

```sh
curl -fsSL https://raw.githubusercontent.com/alphingj/RPI-AIDE/main/install.sh \
  | sudo env RPI_AIDE_BIND=0.0.0.0:8111 \
        RPI_AIDE_GUARD_MODE=monitor \
        RPI_AIDE_GUARD_ALLOW='100.64.0.0/10 192.168.1.119' \
        RPI_AIDE_NOTIFY_URL='https://ntfy.sh/some-topic' \
        bash -s -- --yes
```

Run the guard in `monitor` first, look at the events in the dashboard, and only then
switch to `enforce` with the button or `rpi-aide --guard-enforce`. Switching away from
`enforce` removes active bans; restarting in `enforce` restores them.

Use `sudo rpi-aide-setup --reconfigure` to change any of these later. The installer
backs up the previous config before writing a new one. Rebuilding the baseline
invalidates the old alert rows, which is expected.

## Manual install

Use this only if you do not want the installer:

```sh
sudo install -m 0755 target/arm-unknown-linux-musleabihf/release/rpi-aide /usr/local/bin/rpi-aide
sudo install -m 0755 deploy/rpi-aide.service /etc/systemd/system/rpi-aide.service
sudo install -d -m 0700 /etc/rpi-aide /var/lib/rpi-aide
sudo /usr/local/bin/rpi-aide --config /etc/rpi-aide/config.json --init
sudo systemctl daemon-reload
sudo systemctl enable --now rpi-aide
```

`--init` writes `/etc/rpi-aide/config.json` if it is missing, using the defaults below.
It then writes `/var/lib/rpi-aide/baseline.json` and the last-scan record with mode
`0600`. It exits `1` if any path could not be read, even though it still writes a
baseline. Check the errors before treating that baseline as complete.

The service runs as root because the default roots include `/etc`, `/boot`, and the
systemd unit directories, and because the guard needs `CAP_NET_RAW` and
`CAP_NET_ADMIN`. If you use a dedicated user for a non-guard deployment, make sure it
can read every configured root and write the state files.

Check the dashboard from the Pi:

```sh
curl -s http://127.0.0.1:8080/healthz
systemctl status rpi-aide
journalctl -u rpi-aide -f
```

## Authentication

The dashboard requires a token by default. The token file sits next to the config
(`/etc/rpi-aide/token` on a default install) with mode `0600`.

- Browse to the dashboard and paste the token into the login page. You get a session
  cookie that lasts one week.
- Scripts can send `Authorization: Bearer <token>` on any API route, including
  `/metrics`.
- Five failed logins from one address lock that address out for 15 minutes.
- `rpi-aide --print-token` prints the token on the host.

Sessions live in memory, so a service restart logs everyone out. Traffic between you
and the dashboard is plain HTTP; on an untrusted network, keep the loopback bind and
tunnel over SSH, or put a TLS reverse proxy in front.

To disable authentication, set `"auth": { "enabled": false }` in the config. The
dashboard then shows a warning and opens to anyone who can reach the port.

### Open the dashboard from another device

The default bind is loopback, so only the host itself can reach the dashboard. To open
it from a PC or phone on the same network, rebind the service to the LAN interface:

```sh
sudo env RPI_AIDE_BIND=0.0.0.0:8111 rpi-aide-setup --reconfigure --no-init
```

Then browse to `http://<pi-address>:8111` and log in with the token. On a trusted LAN
this is the intended setup. Never expose the port to the internet.

If you prefer no exposure at all, keep the loopback bind and tunnel it over SSH:

```sh
ssh -L 8111:127.0.0.1:8111 user@your-pi
```

## The port-scan guard

The guard watches inbound TCP SYN packets on one interface (the default-route
interface when `interface` is `auto`), through an AF_PACKET raw socket with a classic
BPF filter, so the kernel only wakes the watcher for TCP SYNs and the CPU cost on a
Pi Zero is negligible.

A source is flagged when, within `window_secs`:

- it hits `critical_port_threshold` (3) distinct critical ports, or
- it hits `total_port_threshold` (10) distinct ports of which at least one is
  critical, or
- it sends `syn_threshold` (50) SYNs against critical ports.

Normal SSH sessions, dashboard browsing, and DNS queries never cross these.

In `monitor` mode the event is recorded and shown in the dashboard. In `enforce`
mode the source is also blocked: the address goes into an `nftables` set with a
timeout (or an `iptables` rule tagged `rpi-aide-guard` as a fallback). The default ban
is one hour; a repeat offender gets 24 hours. Bans are written to
`guard_state.json` and re-applied on service restarts, and a sweeper removes them
when they expire. An allowlist of IPs and CIDRs (plus the host's own addresses) never
triggers: put your admin machine there.

Safety properties:

- The guard only drops traffic from addresses it banned. It never changes the
  default inbound policy and never touches Pi-hole, DNS, or Tailscale rules.
- Switching modes clears active bans (visible in the dashboard), so you cannot leave
  a hidden block behind by turning the guard off.
- `rpi-aide --unban IP`, `rpi-aide --unban-all`, and the dashboard buttons lift a
  ban immediately.
- Limits: IPv4 only; VLAN-tagged frames are not parsed; a scan that touches fewer
  than the thresholds is logged only in your packet counters. The allowlist is
  exact — an allowlisted source is never banned.

## Notifications

Configure one or more of:

- `notify.webhook_url`: any URL that accepts a JSON POST, such as a self-hosted
  ntfy, Gotify, or a small script.
- `notify.ntfy_url`: an ntfy topic URL; the message is sent as plain text with a
  title.
- `notify.telegram_bot_token` and `notify.telegram_chat_id`: a Telegram bot.

Delivery runs through `curl` with a 5 second cap, three attempts, and a bounded
queue; failures appear in the dashboard's notification status. Scan messages are
skipped while a maintenance window is active; guard events are always delivered.
`notify.digest_enabled` sends one summary per day at `digest_hour_utc` UTC. The
`POST /api/notify/test` endpoint (or the button path it powers) sends a test
message so you can confirm delivery without waiting for a real alert.

## Config

The default file is `/etc/rpi-aide/config.json`. `RPI_AIDE_CONFIG` overrides the path
when `--config` is not used. Without that variable, a non-root process looks for
`./config.json`, while root looks in `/etc/rpi-aide/config.json`.

```json
{
  "roots": [
    "/etc",
    "/boot",
    "/boot/firmware",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib/systemd/system"
  ],
  "exclude": [
    "/etc/mtab",
    "/etc/resolv.conf",
    "/etc/adjtime",
    "/etc/dhcp",
    "/etc/pihole/pihole-FTL.db",
    "/etc/pihole/pihole-FTL.db-wal",
    "/etc/pihole/pihole-FTL.db-shm",
    "/etc/pihole/gravity.db",
    "/etc/pihole/gravity.db-wal",
    "/etc/pihole/gravity.db-shm",
    "/etc/pihole/gravity_old.db",
    "/etc/rpi-aide",
    "/var/log",
    "/var/cache",
    "/var/tmp",
    "/var/lib/rpi-aide",
    "/run",
    "/proc",
    "/sys",
    "/dev",
    "/tmp"
  ],
  "baseline_path": "/var/lib/rpi-aide/baseline.json",
  "alerts_path": "/var/lib/rpi-aide/alerts.jsonl",
  "bind": "127.0.0.1:8080",
  "max_alerts": 500,
  "max_file_bytes": 268435456,
  "scan_interval_secs": 3600,
  "scan_on_start_delay_secs": 600,
  "scan_jitter_secs": 300,
  "full_scan_interval_secs": 86400,
  "severity_rules": [
    { "prefix": "/etc/ssh", "severity": "critical" }
  ],
  "notify": {
    "webhook_url": null,
    "ntfy_url": null,
    "telegram_bot_token": null,
    "telegram_chat_id": null,
    "min_severity": "info",
    "on_guard_events": true,
    "digest_enabled": false,
    "digest_hour_utc": 8,
    "timeout_secs": 5,
    "retry_secs": 60,
    "max_queue": 20
  },
  "auth": {
    "enabled": true,
    "token_path": "/etc/rpi-aide/token",
    "session_ttl_secs": 604800,
    "max_failed_per_ip": 5,
    "lockout_secs": 900
  },
  "guard": {
    "mode": "monitor",
    "interface": "auto",
    "critical_ports": [22, 53, 80, 443, 8080, 8111],
    "window_secs": 10,
    "critical_port_threshold": 3,
    "total_port_threshold": 10,
    "syn_threshold": 50,
    "ban_secs": 3600,
    "repeat_ban_secs": 86400,
    "max_bans": 256,
    "allowlist": ["127.0.0.0/8", "100.64.0.0/10"],
    "state_path": "/var/lib/rpi-aide/guard_state.json"
  },
  "watch": {
    "enabled": true,
    "paths": ["/etc", "/boot"],
    "debounce_ms": 2000,
    "min_gap_secs": 60,
    "max_watches": 4096
  }
}
```

Notes:

- `roots` must contain absolute paths. `/proc`, `/sys`, `/dev`, and `/run` are rejected
  as roots.
- `exclude` entries are absolute. An entry excludes that path and everything below it.
- `scan_interval_secs` of `0` disables scheduled scans; a boot scan still runs when
  `scan_on_start_delay_secs` is non-zero. Jitter is capped at the interval.
- The fast-scan cache (`scan_cache.json`) binds each cached hash to the file's size,
  mode, mtime, ctime, and inode. A periodic full rehash is the safety net against
  forged metadata.
- `severity_rules` is a first-match list. Defaults mark authentication, sudo, systemd,
  cron, Pi-hole, DHCP, and boot paths critical; binaries and the rest of `/etc`
  warning. The dashboard port from `bind` is always treated as critical by the guard.
- `guard.mode` can be changed at runtime from the dashboard or CLI; the change is
  written back to the config file when one exists.
- The guard state, the fast-scan cache, the accepted-change sidecar, the maintenance
  window, and the chain head are all excluded from scans automatically.

## CLI

```text
rpi-aide [MODE] [OPTIONS]

--serve               Start the dashboard (default)
--init                Scan the roots and write a new baseline
--check [--fast]      Compare the filesystem with the baseline
--accept PATH         Approve the current state of one path
--maintenance 30m|off Start or stop a maintenance window
--doctor              Run read-only health checks
--verify-log          Verify the hash chain of the alerts log
--print-token         Print the dashboard login token
--guard               Show the port-scan guard status
--list-bans           List active bans
--unban IP            Remove one ban
--unban-all           Remove every ban
--guard-monitor       Switch the guard to monitor mode
--guard-enforce       Switch the guard to enforce mode (blocking)
--guard-off           Turn the guard off
```

Guard remote commands talk to the running service over the loopback port from `bind`
and authenticate with the token file, so they need the service running.

Exit codes:

| Code | Meaning |
| ---- | ------- |
| `0` | Success, or a clean check |
| `1` | Anomalies found, a warning, or a problem |
| `2` | Usage, config, baseline, or I/O error |

`--init` refuses to overwrite an existing baseline unless `--force` is passed.
`--check` exits `1` when any path was added, modified, or deleted, or when a scan error
occurred. The last scan summary is stored so the dashboard can show it after a restart.

## Dashboard and API

The dashboard binds to `127.0.0.1:8080` by default and requires the login token.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/` | Embedded dashboard (session) |
| `GET` | `/login` | Login page |
| `POST` | `/login` | Submit the token, sets a session cookie |
| `POST` | `/logout` | Drop the session |
| `GET` | `/healthz` | Plain text `ok` (public) |
| `GET` | `/api/status` | Baseline state, last scan, schedule, guard, watch, notify |
| `GET` | `/api/alerts` | Current alert rows with severity and accepted flags |
| `POST` | `/api/scan` | Start a fast scan (`?full=1` forces a full rehash) |
| `POST` | `/api/accept` | Fold one path's current state into the baseline |
| `POST` | `/api/maintenance` | Start (`{"minutes":30}`) or stop (`{"off":true}`) a window |
| `POST` | `/api/guard/mode` | Set the guard mode |
| `POST` | `/api/guard/unban` | Lift one ban |
| `POST` | `/api/guard/unban-all` | Lift every ban |
| `POST` | `/api/notify/test` | Queue a test notification |
| `GET` | `/metrics` | Prometheus text |

Every mutating `POST` requires the custom header `x-rpi-aide-scan: 1` in addition to
the session or bearer token. A browser cannot set that header on a cross-origin form
post, and the session cookie is `SameSite=Strict`, so cross-site requests cannot drive
the dashboard.

Responses set a restrictive Content Security Policy, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
The CSP allows inline style and script because the page is a single embedded file. It
blocks external scripts, images, fonts, and connections.

## Security notes

- The dashboard has token authentication with per-IP lockout. The token file is
  `0600` next to the config. Traffic is plain HTTP; on untrusted networks use the
  loopback bind plus an SSH tunnel, or a TLS reverse proxy.
- State files are written atomically through a pid-specific temporary file, flushed,
  and renamed. New state directories are created with mode `0700`; files use `0600`.
- The alert log is hash-chained: each record links to the previous one, so silent
  edits inside the log fail `--verify-log`. An attacker with root can delete the
  whole chain, which the command reports honestly.
- The monitor is read-only against the monitored roots. It only writes its state
  directory.
- Hashing follows the file metadata captured before the read and checks size and mtime
  after the read. A file that changes during hashing is reported as an error instead
  of being recorded with mixed content.
- Fast scans trust that unchanged size, mode, mtime, ctime, and inode mean unchanged
  content. Only root can attempt to forge those, and the periodic full rehash limits
  the window.
- The guard stores only source addresses, ports, counts, and timestamps. No packet
  payloads are retained.
- The guard never changes the host's default firewall policy. It adds exactly one
  table (or tagged rules) that drops traffic from addresses it banned.
- The dashboard page has no third-party assets, analytics, or outbound requests.

## Resource profile

- One async runtime thread (`#[tokio::main(flavor = "current_thread")]`).
- Three helper threads: guard capture (blocked in `recvfrom` until a SYN arrives),
  inotify watch (polling at 200 ms), and notification delivery (sleeping between
  ticks). Idle threads cost nothing measurable on a Pi Zero.
- Hashing runs at lowered CPU priority so scans never delay DNS. The BPF filter
  keeps per-packet cost at the kernel level.
- 4 KB read buffer and BLAKE3 hashing. Reads stop at `max_file_bytes`.
- Dashboard polling is every 5 seconds while the tab is visible, and pauses while hidden.
- Manual and watch-triggered scans are single-flight. A second request returns `409`.
- The release profile is size-oriented: `opt-level = "z"`, LTO, one codegen unit,
  `panic = "abort"`, and symbols stripped.

The x86_64 release binary is about 1.4 MB; the static ARMv6 musl binary is about 1.2 MB.

## Tests and verification

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The unit suite covers the scan tracker thresholds, the BPF filter through a tiny
in-code interpreter checked against the userspace parser, packet parsing, the fast
scan cache, the hash chain (clean, legacy, rotation, and tampering), accept flows
including parent directory settling, maintenance windows, severity rules, config
validation, session expiry and lockouts, command construction for nftables and
iptables, and the CLI's JSON helpers.

End-to-end checks were run against a live service and, for the guard, as root on a
real Wi-Fi interface: an external port scan from another LAN device was detected,
banned in an nftables set, verified to drop traffic, unbanned, re-banned at the repeat
duration, and restored after a service restart. The installer suite covers fresh
installs, upgrades that keep the token, and reconfigures with environment overrides.
The dashboard suite drives login, the guard panel, severity badges and filters,
accept, maintenance, scan, and logout in a real browser and checks the console stays
clean.

## Repository layout

```text
src/main.rs            CLI parsing and dispatch
src/config.rs          config schema, defaults, validation
src/monitor.rs         scan, cache, diff, baseline, chain, accept, maintenance
src/guard.rs           scan tracking, bans, nftables/iptables enforcement
src/capture.rs         AF_PACKET capture, BPF filter, packet parsing
src/watch.rs           inotify watch
src/notify.rs          webhook/ntfy/telegram delivery through curl
src/auth.rs            token file, sessions, login rate limiting
src/server.rs          HTTP server, routes, middleware, scheduler, metrics
src/httpc.rs           minimal HTTP client for the CLI's remote commands
src/doctor.rs          health checks
src/dashboard.html     embedded dashboard and styles
src/login.html         embedded login page
install.sh             one-command installer and setup wizard
deploy/rpi-aide.service
DESIGN.md              interface tokens and verification notes
```
