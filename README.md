# my-ids

A small file integrity monitor for Linux hosts, written in Rust. It hashes a set of
directories, stores a baseline, reports added, modified, and deleted paths, and serves
a dashboard from an HTML page embedded in the binary.

The target deployment is a Raspberry Pi Zero running Pi-hole. One static ARMv6 binary,
no runtime assets, no external requests, and a polling dashboard that stays out of the
DNS fast path.

## What it does

- Walks the configured roots and records files, directories, symlinks, and special files.
- Hashes file contents with BLAKE3 in 4 KB chunks. Reads stop at `max_file_bytes`.
- Writes a flat JSON baseline with size, mode, mtime, and hash per entry.
- `--check` prints `ADDED`, `MODIFIED`, and `DELETED` records and appends alerts.
- No flag starts the dashboard. `--serve` is the explicit form.
- The dashboard has status, alerts, filters, a manual scan button, and light and dark themes.
- The page is embedded with `include_str!`. There is no CDN, web font, image, or build step
  for the frontend.

## Requirements

- Linux. The monitor needs read access to the configured roots.
- Rust stable with Cargo for a native build.
- Root when monitoring `/etc`, `/boot`, or the systemd unit directories.
- For a Pi Zero cross build: `rustup target add arm-unknown-linux-musleabihf` and an
  `arm-linux-gnueabihf-gcc` linker. The binary is static and does not need a sysroot at
  runtime.

## Build

```sh
cargo build --release
cargo test
```

The native binary is `target/release/my-ids`.

### Pi Zero (ARMv6, static)

The Pi Zero is ARMv6. Build the musl target with the ARMv6 CPU selected by the target:

```sh
rustup target add arm-unknown-linux-musleabihf
CARGO_TARGET_ARM_UNKNOWN_LINUX_MUSLEABIHF_LINKER=arm-linux-gnueabihf-gcc \
  cargo build --release --target arm-unknown-linux-musleabihf
```

Verify the result before copying it:

```sh
file target/arm-unknown-linux-musleabihf/release/my-ids
readelf -A target/arm-unknown-linux-musleabihf/release/my-ids | grep Tag_CPU_arch
```

Expected: `ELF 32-bit LSB executable, ARM, EABI5 ... statically linked` and
`Tag_CPU_arch: v6`. Do not use the glibc `arm-unknown-linux-gnueabihf` build for a Pi
Zero. That target is tagged ARMv7 and can fault with an illegal instruction on ARMv6.

## Install on a Pi

```sh
sudo install -m 0755 target/arm-unknown-linux-musleabihf/release/my-ids /usr/local/bin/my-ids
sudo install -m 0755 deploy/my-ids.service /etc/systemd/system/my-ids.service
sudo install -d -m 0700 /etc/my-ids /var/lib/my-ids
sudo /usr/local/bin/my-ids --config /etc/my-ids/config.json --init
sudo systemctl daemon-reload
sudo systemctl enable --now my-ids
```

`--init` writes `/etc/my-ids/config.json` if it is missing, using the defaults below.
Then it writes `/var/lib/my-ids/baseline.json` and the last-scan record with mode `0600`.
It exits `1` if any path could not be read, even though it still writes a baseline. Check
the errors before treating that baseline as complete.

The service runs as root because the default roots include `/etc`, `/boot`, and
`/usr/lib/systemd/system`. If you use a dedicated user, make sure it can read every
configured root and write the baseline and alert paths, then change `User=` in the unit.

Check the dashboard from the Pi:

```sh
curl -s http://127.0.0.1:8080/api/status
systemctl status my-ids
journalctl -u my-ids -f
```

## Config

The default file is `/etc/my-ids/config.json`. `MY_IDS_CONFIG` overrides the path when
`--config` is not used. Without that variable, a non-root process looks for `./config.json`,
while root looks in `/etc/my-ids/config.json`.

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
    "/var/log",
    "/var/cache",
    "/var/tmp",
    "/var/lib/my-ids",
    "/run",
    "/proc",
    "/sys",
    "/dev",
    "/tmp"
  ],
  "baseline_path": "/var/lib/my-ids/baseline.json",
  "alerts_path": "/var/lib/my-ids/alerts.jsonl",
  "bind": "127.0.0.1:8080",
  "max_alerts": 500,
  "max_file_bytes": 268435456
}
```

- `roots` must contain absolute paths. `/proc`, `/sys`, `/dev`, and `/run` are rejected
  as roots.
- `exclude` entries are absolute. An entry excludes that path and everything below it.
- `baseline_path`, `alerts_path`, and the last-scan file (next to the baseline) must be
  distinct.
- `max_alerts` caps the in-memory alert history. The on-disk log rotates at 5 MB and keeps
  one previous file.
- `max_file_bytes` must be at least 4096. Files larger than the limit are reported as scan
  errors and are not hashed into the baseline.
- The baseline is tied to the roots and excludes that produced it. Changing either one
  makes `--check` exit `2` with a re-init message. This prevents silently comparing two
  different trees.

The state directory is excluded automatically, along with `/proc`, `/sys`, `/dev`, and
`/run`, even if those paths are not listed in `exclude`.

## CLI

```text
my-ids [--init | --check | --serve] [--config PATH] [--force] [--quiet]

--init      Scan the roots and write a new baseline
--check     Compare the live filesystem with the baseline
--serve     Start the dashboard (default when no mode is given)
--config    Config file path
--force     Replace an existing baseline during --init
--quiet     Suppress informational log lines
```

Exit codes:

| Code | Meaning |
| ---- | ------- |
| `0` | Success, or a clean check |
| `1` | Anomalies found, scan errors, or an incomplete init |
| `2` | Usage, config, baseline, or I/O error |

`--init` refuses to overwrite an existing baseline unless `--force` is passed.
`--check` exits `1` when any path was added, modified, or deleted, or when a scan error
occurred. The last scan summary is stored so the dashboard can show it after a restart.

## Dashboard and API

The dashboard binds to `127.0.0.1:8080` by default.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/` | Embedded dashboard |
| `GET` | `/api/status` | Baseline state, last scan, host and process metrics, poll interval |
| `GET` | `/api/alerts` | Current alert rows for the active baseline generation |
| `POST` | `/api/scan` | Start a scan. Requires `x-my-ids-scan: 1` |
| `GET` | `/healthz` | Plain text `ok` |
| `GET` | `/favicon.ico` | `204 No Content` |

The scan header is a CSRF guard. A browser cannot set a custom header on a cross-origin
form post, and a cross-origin fetch would need a CORS preflight that this server does not
grant. The dashboard sends the header on its own same-origin request.

Responses set a restrictive Content Security Policy, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
The CSP allows inline style and script because the page is a single embedded file. It
blocks external scripts, images, fonts, and connections.

## Security notes

- There is no built-in authentication. Keep `bind` on loopback, or put an authenticated
  reverse proxy in front of it. Do not expose port 8080 directly to a LAN or the internet.
- State files are written atomically through a pid-specific temporary file, flushed,
  and renamed. New state directories are created with mode `0700`; files use `0600`.
- The monitor is read-only against the monitored roots. It only writes its baseline,
  alert log, and last-scan summary.
- Hashing follows the file metadata captured before the read and checks size and mtime
  after the read. A file that changes during hashing is reported as an error instead of
  being recorded with mixed content.
- Symlinks are recorded by target path, not followed. Directory entries include mode and
  mtime so permission changes are visible.
- The dashboard page has no third-party assets, analytics, or outbound requests.

## Resource profile

- One async runtime thread (`#[tokio::main(flavor = "current_thread")]`).
- Hashing runs on a blocking worker so the HTTP loop stays responsive.
- 4 KB read buffer and BLAKE3 hashing. Reads stop at `max_file_bytes`.
- Dashboard polling is every 5 seconds while the tab is visible, and pauses while hidden.
- Manual scans are single-flight. A second request returns `409` while one is running.
- The release profile is size-oriented: `opt-level = "z"`, LTO, one codegen unit,
  `panic = "abort"`, and symbols stripped.

The x86_64 release binary is about 1.1 MB. The static ARMv6 musl binary is about 963 KB.
Measure on the target before changing the poll interval or adding roots.

## Tests and verification

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The test suite covers baseline format and version validation, config mismatch detection,
exclusion matching, diff output, alert deduplication, state path collisions, invalid UTF-8
in the alert log, mode formatting, byte formatting, and RFC 3339 timestamps.

CLI and dashboard behavior were also exercised against fixture trees and a headless
Chromium build. The verified dashboard checks include clean, loading, empty, error, scan,
filter, theme, keyboard, and mobile states. See `DESIGN.md` for the interface decisions and
the measured results.

## Repository layout

```text
src/main.rs          monitor, persistence, HTTP server, tests
src/dashboard.html   embedded dashboard and styles
deploy/my-ids.service
DESIGN.md            interface tokens and verification notes
Cargo.toml
```
