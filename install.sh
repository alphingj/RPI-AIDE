#!/usr/bin/env bash
set -euo pipefail

REPO="alphingj/RPI-AIDE"
PROJECT="RPI-AIDE"
SERVICE_NAME="rpi-aide"
VERSION="latest"
PREFIX="/"
YES=0
RECONFIGURE=0
NO_START=0
NO_INIT=0
BINARY=""
CONFIG=""
STATE_DIR=""

usage() {
  cat <<'EOF'
RPI-AIDE installer and initial setup

Usage:
  install.sh [options]

Options:
  -y, --yes             Accept defaults and do not prompt
      --reconfigure     Rewrite the config and offer to rebuild the baseline
      --binary PATH     Install a local binary instead of downloading one
      --version TAG     Release tag to download (default: latest)
      --config PATH     Config path (default: /etc/rpi-aide/config.json)
      --state-dir PATH  State directory (default: /var/lib/rpi-aide)
      --prefix PATH     Install root for testing (default: /)
      --no-init         Do not create the baseline
      --no-start        Install the service but do not start it
  -h, --help            Show this help

One command:
  curl -fsSL https://raw.githubusercontent.com/alphingj/RPI-AIDE/main/install.sh | sudo bash

The installer reads prompts from /dev/tty, so it still works when the script is
piped into bash. Use --yes for an unattended install with the defaults.

Environment overrides for unattended installs:
  RPI_AIDE_ROOTS         monitored directories
  RPI_AIDE_BIND          dashboard bind address
  RPI_AIDE_MAX_MB        maximum file size to hash
  RPI_AIDE_SCAN_SECS     scheduled scan interval (0 = off)
  RPI_AIDE_NOTIFY_URL    webhook or ntfy URL for alert delivery
  RPI_AIDE_GUARD_MODE    monitor, enforce or off
  RPI_AIDE_GUARD_ALLOW   space separated allowlisted IPs or CIDRs
  RPI_AIDE_TELEGRAM_BOT_TOKEN   telegram bot token for alert delivery
  RPI_AIDE_TELEGRAM_CHAT_ID     telegram chat id to receive alerts
EOF
}

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

ask() {
  local prompt="$1" default="$2" answer=""
  if [ "$YES" -eq 1 ] || [ ! -r /dev/tty ]; then
    printf '%s' "$default"
    return 0
  fi
  printf '%s [%s]: ' "$prompt" "$default" > /dev/tty
  IFS= read -r answer < /dev/tty || true
  printf '%s' "${answer:-$default}"
}

confirm() {
  local prompt="$1" default="${2:-y}" answer=""
  if [ "$YES" -eq 1 ]; then
    [ "$default" = "y" ]
    return
  fi
  if [ ! -r /dev/tty ]; then
    [ "$default" = "y" ]
    return
  fi
  printf '%s [%s]: ' "$prompt" "$default" > /dev/tty
  IFS= read -r answer < /dev/tty || true
  answer="${answer:-$default}"
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

download() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    die "curl or wget is required to download the binary"
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

json_array() {
  local first=1 item
  printf '['
  for item in "$@"; do
    if [ "$first" -eq 0 ]; then
      printf ', '
    fi
    first=0
    printf '"%s"' "$(json_escape "$item")"
  done
  printf ']'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -y|--yes) YES=1 ;;
    --reconfigure) RECONFIGURE=1 ;;
    --no-init) NO_INIT=1 ;;
    --no-start) NO_START=1 ;;
    --binary)
      [ "$#" -ge 2 ] || die "--binary needs a path"
      BINARY="$2"
      shift
      ;;
    --version)
      [ "$#" -ge 2 ] || die "--version needs a tag"
      VERSION="$2"
      shift
      ;;
    --config)
      [ "$#" -ge 2 ] || die "--config needs a path"
      CONFIG="$2"
      shift
      ;;
    --state-dir)
      [ "$#" -ge 2 ] || die "--state-dir needs a path"
      STATE_DIR="$2"
      shift
      ;;
    --prefix)
      [ "$#" -ge 2 ] || die "--prefix needs a path"
      PREFIX="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1 (use --help)"
      ;;
  esac
  shift
done

PREFIX="${PREFIX%/}"
[ -n "$PREFIX" ] || PREFIX="/"
if [ -z "$CONFIG" ]; then
  CONFIG="${PREFIX%/}/etc/rpi-aide/config.json"
fi
if [ -z "$STATE_DIR" ]; then
  STATE_DIR="${PREFIX%/}/var/lib/rpi-aide"
fi
BIN_PATH="${PREFIX%/}/usr/local/bin/rpi-aide"
SERVICE_PATH="${PREFIX%/}/etc/systemd/system/rpi-aide.service"
SETUP_PATH="${PREFIX%/}/usr/local/sbin/rpi-aide-setup"

if [ "$PREFIX" = "/" ] && [ "$(id -u)" -ne 0 ]; then
  die "run this installer with sudo"
fi
[ "$(uname -s)" = "Linux" ] || die "RPI-AIDE runs on Linux"
command -v install >/dev/null 2>&1 || die "the install command is required (coreutils)"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required (coreutils)"

case "$(uname -m)" in
  armv6l) ASSET="rpi-aide-armv6" ;;
  armv7l|armv8l) ASSET="rpi-aide-armv7" ;;
  aarch64|arm64) ASSET="rpi-aide-aarch64" ;;
  x86_64|amd64) ASSET="rpi-aide-x86_64" ;;
  *) die "unsupported architecture: $(uname -m). Build from source instead." ;;
esac

say ""
say "$PROJECT installer"
say "This installs a file integrity monitor with a dashboard, a port-scan"
say "guard, and notifications. It writes state under $STATE_DIR."
say ""

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ "$VERSION" != "latest" ]; then
  TAG="$VERSION"
  case "$TAG" in
    v*) ;;
    *) TAG="v$TAG" ;;
  esac
fi

if [ -n "$BINARY" ]; then
  [ -f "$BINARY" ] || die "binary not found: $BINARY"
  SOURCE_BINARY="$BINARY"
  say "Using local binary: $SOURCE_BINARY"
else
  if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/$REPO/releases/latest/download"
  else
    BASE_URL="https://github.com/$REPO/releases/download/$TAG"
  fi
  say "Downloading $ASSET from $BASE_URL"
  download "$BASE_URL/$ASSET" "$TMP/$ASSET"
  download "$BASE_URL/SHA256SUMS" "$TMP/SHA256SUMS"
  CHECKSUM_LINE="$(grep -E "[[:space:]]${ASSET}$" "$TMP/SHA256SUMS" || true)"
  [ -n "$CHECKSUM_LINE" ] || die "checksum for $ASSET is missing from SHA256SUMS"
  printf '%s\n' "$CHECKSUM_LINE" | (cd "$TMP" && sha256sum -c -) >/dev/null
  SOURCE_BINARY="$TMP/$ASSET"
fi

CONFIG_EXISTS=0
if [ -f "$CONFIG" ]; then
  CONFIG_EXISTS=1
fi

if [ "$CONFIG_EXISTS" -eq 1 ] && [ "$RECONFIGURE" -eq 0 ]; then
  say "Found existing config at $CONFIG"
  say "Keeping it. Use --reconfigure to change the monitored roots or bind address."
  BIND="$(sed -n 's/.*"bind"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | head -n 1)"
  [ -n "$BIND" ] || BIND="127.0.0.1:8080"
else
  if [ "$CONFIG_EXISTS" -eq 1 ]; then
    BACKUP="$CONFIG.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$CONFIG" "$BACKUP"
    chmod 600 "$BACKUP"
    say "Backed up the previous config to $BACKUP"
  fi

  say "Initial setup"
  say "The default roots match a Raspberry Pi running Pi-hole."
  DEFAULT_ROOTS="/etc /boot"
  if [ -d /boot/firmware ]; then
    DEFAULT_ROOTS="$DEFAULT_ROOTS /boot/firmware"
  fi
  DEFAULT_ROOTS="$DEFAULT_ROOTS /usr/bin /usr/sbin /usr/lib/systemd/system"
  ROOTS="$(ask "Directories to monitor (space separated)" "${RPI_AIDE_ROOTS:-$DEFAULT_ROOTS}")"
  ROOTS="${ROOTS//,/ }"
  [ -n "${ROOTS// /}" ] || die "at least one monitored directory is required"
  for ROOT in $ROOTS; do
    case "$ROOT" in
      /*) ;;
      *) die "monitored directory must be absolute: $ROOT" ;;
    esac
    [ -d "$ROOT" ] || warn "directory does not exist yet: $ROOT"
  done

  BIND="$(ask "Dashboard bind address" "${RPI_AIDE_BIND:-127.0.0.1:8080}")"
  case "$BIND" in
    *:*) ;;
    *) die "bind address must include a port, for example 127.0.0.1:8080" ;;
  esac
  case "$BIND" in
    127.0.0.1:*|localhost:*|\[::1\]:*) ;;
    *)
      say "The dashboard requires a token login, but traffic to $BIND is not encrypted."
      say "Use it on a trusted LAN, tunnel it over SSH, or put a reverse proxy in front."
      ;;
  esac

  MAX_MB="$(ask "Maximum file size to hash in MB" "${RPI_AIDE_MAX_MB:-256}")"
  case "$MAX_MB" in
    ''|*[!0-9]*) die "maximum file size must be a whole number of MB" ;;
  esac
  [ "$MAX_MB" -ge 1 ] || die "maximum file size must be at least 1 MB"
  [ "$MAX_MB" -le 4096 ] || die "maximum file size must be 4096 MB or less"
  MAX_BYTES=$((MAX_MB * 1024 * 1024))

  SCAN_SECS="$(ask "Scheduled scan interval in seconds (0 = off)" "${RPI_AIDE_SCAN_SECS:-3600}")"
  case "$SCAN_SECS" in
    ''|*[!0-9]*) die "scan interval must be a whole number of seconds" ;;
  esac
  if [ "$SCAN_SECS" -ne 0 ] && [ "$SCAN_SECS" -lt 60 ]; then
    die "scan interval must be 0 (off) or at least 60 seconds"
  fi

  NOTIFY_URL="$(ask "Notification URL: webhook or ntfy (empty skips)" "${RPI_AIDE_NOTIFY_URL:-}")"
  NOTIFY_WEBHOOK="null"
  NOTIFY_NTFY="null"
  case "$NOTIFY_URL" in
    https://ntfy.sh/*|https://*/topic*|*ntfy*)
      NOTIFY_NTFY="\"$(json_escape "$NOTIFY_URL")\""
      ;;
    http://*|https://*)
      NOTIFY_WEBHOOK="\"$(json_escape "$NOTIFY_URL")\""
      ;;
    "") ;;
    *)
      warn "notification URL must be http(s); delivery is disabled"
      ;;
  esac

  TELEGRAM_TOKEN="$(ask "Telegram bot token for alerts (empty skips)" "${RPI_AIDE_TELEGRAM_BOT_TOKEN:-}")"
  TELEGRAM_CHAT="$(ask "Telegram chat id (empty skips)" "${RPI_AIDE_TELEGRAM_CHAT_ID:-}")"
  TELEGRAM_BOT_TOKEN="null"
  TELEGRAM_CHAT_ID="null"
  case "$TELEGRAM_TOKEN" in
    "") ;;
    *)
      if [ -z "$TELEGRAM_CHAT" ]; then
        warn "telegram bot token set without a chat id; telegram delivery is disabled"
      else
        TELEGRAM_BOT_TOKEN="\"$(json_escape "$TELEGRAM_TOKEN")\""
        TELEGRAM_CHAT_ID="\"$(json_escape "$TELEGRAM_CHAT")\""
      fi
      ;;
  esac

  GUARD_MODE="$(ask "Port-scan guard mode: monitor, enforce or off" "${RPI_AIDE_GUARD_MODE:-monitor}")"
  case "$GUARD_MODE" in
    monitor|enforce|off) ;;
    *) die "guard mode must be monitor, enforce or off" ;;
  esac

  GUARD_ALLOW="$(ask "Guard allowlist (space separated IPs or CIDRs)" "${RPI_AIDE_GUARD_ALLOW:-100.64.0.0/10}")"
  GUARD_ALLOW_ARRAY="$(json_array $GUARD_ALLOW)"
  for ENTRY in $GUARD_ALLOW; do
    case "$ENTRY" in
      *[!0-9./]*) warn "allowlist entry may not be a valid IP or CIDR: $ENTRY" ;;
    esac
  done

  EXCLUDES=(
    "/etc/mtab"
    "/etc/resolv.conf"
    "/etc/adjtime"
    "/etc/dhcp"
    "/etc/pihole/pihole-FTL.db"
    "/etc/pihole/pihole-FTL.db-wal"
    "/etc/pihole/pihole-FTL.db-shm"
    "/etc/pihole/gravity.db"
    "/etc/pihole/gravity.db-wal"
    "/etc/pihole/gravity.db-shm"
    "/etc/pihole/gravity_old.db"
    "/etc/pihole/listsCache"
    "/etc/pihole/gravity_backups"
    "/etc/pihole/cli_pw"
    "${PREFIX%/}/etc/rpi-aide"
    "/var/log"
    "/var/cache"
    "/var/tmp"
    "$STATE_DIR"
    "/run"
    "/proc"
    "/sys"
    "/dev"
    "/tmp"
  )

  install -d -m 0700 "$(dirname "$CONFIG")" "$STATE_DIR"
  umask 077
  {
    printf '{\n  "roots": '
    json_array $ROOTS
    printf ',\n  "exclude": '
    json_array "${EXCLUDES[@]}"
    printf ',\n  "baseline_path": "%s"' "$(json_escape "$STATE_DIR/baseline.json")"
    printf ',\n  "alerts_path": "%s"' "$(json_escape "$STATE_DIR/alerts.jsonl")"
    printf ',\n  "bind": "%s"' "$(json_escape "$BIND")"
    printf ',\n  "max_alerts": 500'
    printf ',\n  "max_file_bytes": %s' "$MAX_BYTES"
    printf ',\n  "scan_interval_secs": %s' "$SCAN_SECS"
    printf ',\n  "scan_on_start_delay_secs": 600'
    printf ',\n  "scan_jitter_secs": 300'
    printf ',\n  "full_scan_interval_secs": 86400'
    printf ',\n  "notify": {\n    "webhook_url": %s' "$NOTIFY_WEBHOOK"
    printf ',\n    "ntfy_url": %s' "$NOTIFY_NTFY"
    printf ',\n    "telegram_bot_token": %s' "$TELEGRAM_BOT_TOKEN"
    printf ',\n    "telegram_chat_id": %s' "$TELEGRAM_CHAT_ID"
    printf ',\n    "min_severity": "info"'
    printf ',\n    "on_guard_events": true'
    printf ',\n    "timeout_secs": 5'
    printf ',\n    "retry_secs": 60'
    printf ',\n    "max_queue": 20\n  }'
    printf ',\n  "auth": {\n    "enabled": true'
    printf ',\n    "token_path": "%s"' "$(json_escape "$(dirname "$CONFIG")/token")"
    printf ',\n    "session_ttl_secs": 604800'
    printf ',\n    "max_failed_per_ip": 5'
    printf ',\n    "lockout_secs": 900\n  }'
    printf ',\n  "guard": {\n    "mode": "%s"' "$(json_escape "$GUARD_MODE")"
    printf ',\n    "interface": "auto"'
    printf ',\n    "critical_ports": [22, 53, 80, 443, 8080, 8111]'
    printf ',\n    "window_secs": 10'
    printf ',\n    "critical_port_threshold": 3'
    printf ',\n    "total_port_threshold": 10'
    printf ',\n    "syn_threshold": 50'
    printf ',\n    "ban_secs": 3600'
    printf ',\n    "repeat_ban_secs": 86400'
    printf ',\n    "max_bans": 256'
    printf ',\n    "allowlist": %s' "$GUARD_ALLOW_ARRAY"
    printf ',\n    "state_path": "%s"\n  }' "$(json_escape "$STATE_DIR/guard_state.json")"
    printf ',\n  "watch": {\n    "enabled": true'
    printf ',\n    "paths": ["/etc", "/boot"]'
    printf ',\n    "debounce_ms": 2000'
    printf ',\n    "min_gap_secs": 60'
    printf ',\n    "max_watches": 4096\n  }'
    printf '\n}\n'
  } > "$CONFIG"
  chmod 600 "$CONFIG"
  say "Wrote $CONFIG"
fi

# The login token: create it when missing so upgrades get auth too.
TOKEN_PATH="$(dirname "$CONFIG")/token"
TOKEN_PRINTED=""
if [ ! -s "$TOKEN_PATH" ]; then
  umask 077
  if NEW_TOKEN="$(head -c 16 /dev/urandom 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')"; then
    if [ -n "$NEW_TOKEN" ]; then
      printf '%s\n' "$NEW_TOKEN" > "$TOKEN_PATH"
      chmod 600 "$TOKEN_PATH"
      TOKEN_PRINTED="$NEW_TOKEN"
      say "Created a new dashboard login token at $TOKEN_PATH"
    fi
  fi
  [ -s "$TOKEN_PATH" ] || warn "could not create $TOKEN_PATH; the service will create one at start"
fi

case "$BIN_PATH$CONFIG$STATE_DIR" in
  *[[:space:]]*) die "paths with spaces are not supported by the generated service" ;;
esac

say "Installing binary to $BIN_PATH"
install -d -m 0755 "$(dirname "$BIN_PATH")"
if [ -e "$BIN_PATH" ] && [ "$(readlink -f "$SOURCE_BINARY")" = "$(readlink -f "$BIN_PATH")" ]; then
  say "Binary is already in place."
else
  install -m 0755 "$SOURCE_BINARY" "$BIN_PATH"
fi

install -d -m 0755 "$(dirname "$SETUP_PATH")"
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  if [ -e "$SETUP_PATH" ] && [ "$(readlink -f "${BASH_SOURCE[0]}")" = "$(readlink -f "$SETUP_PATH")" ]; then
    say "Setup script is already in place."
  else
    install -m 0755 "${BASH_SOURCE[0]}" "$SETUP_PATH"
  fi
else
  if [ "$VERSION" = "latest" ]; then
    SETUP_URL="https://raw.githubusercontent.com/$REPO/main/install.sh"
  else
    SETUP_URL="https://raw.githubusercontent.com/$REPO/$TAG/install.sh"
  fi
  if download "$SETUP_URL" "$TMP/install.sh" 2>/dev/null; then
    install -m 0755 "$TMP/install.sh" "$SETUP_PATH"
  else
    warn "could not install $SETUP_PATH; re-run the one-line installer to reconfigure"
  fi
fi

SYSTEMD_READY=0
if [ "$PREFIX" = "/" ] && command -v systemctl >/dev/null 2>&1; then
  SYSTEMD_READY=1
  CONFIG_DIR="$(dirname "$CONFIG")"
  say "Installing systemd service"
  install -d -m 0755 "$(dirname "$SERVICE_PATH")"
  cat > "$TMP/rpi-aide.service" <<EOF
[Unit]
Description=$PROJECT file integrity monitor
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_PATH --config $CONFIG --serve
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s

User=root
Group=root
UMask=0077

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=$STATE_DIR $CONFIG_DIR

SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF
  if [ -f "$SERVICE_PATH" ] && cmp -s "$TMP/rpi-aide.service" "$SERVICE_PATH"; then
    say "Service unit is already in place."
  else
    install -m 0644 "$TMP/rpi-aide.service" "$SERVICE_PATH"
  fi
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || warn "could not enable $SERVICE_NAME"
fi

INIT_STATUS=0
if [ "$NO_INIT" -eq 0 ]; then
  if [ -f "$STATE_DIR/baseline.json" ]; then
    if [ "$CONFIG_EXISTS" -eq 0 ] || [ "$RECONFIGURE" -eq 1 ]; then
      if confirm "Replace the existing baseline with a fresh scan?" "y"; then
        if "$BIN_PATH" --config "$CONFIG" --init --force; then
          INIT_STATUS=0
        else
          INIT_STATUS=$?
        fi
      else
        warn "baseline not replaced; the dashboard will report a mismatch until you run --init --force"
      fi
    else
      say "Keeping the existing baseline."
    fi
  else
    if confirm "Create the initial baseline now? This can take a while." "y"; then
      if "$BIN_PATH" --config "$CONFIG" --init; then
        INIT_STATUS=0
      else
        INIT_STATUS=$?
      fi
    else
      warn "baseline not created; the dashboard will report it as missing"
    fi
  fi
fi

if [ "$SYSTEMD_READY" -eq 1 ]; then
  if [ "$NO_START" -eq 0 ]; then
    if ! systemctl restart "$SERVICE_NAME"; then
      systemctl status --no-pager "$SERVICE_NAME" || true
      die "service failed to start; inspect with: journalctl -u $SERVICE_NAME"
    fi
    HEALTHY=0
    PORT="${BIND##*:}"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if command -v curl >/dev/null 2>&1 \
        && curl -fsS --max-time 1 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        HEALTHY=1
        break
      fi
      sleep 0.5
    done
    if [ "$HEALTHY" -eq 1 ]; then
      say "Service is running and the health check passed."
    else
      warn "health check did not pass yet; inspect with: systemctl status $SERVICE_NAME"
    fi
  else
    say "Service installed but not started (--no-start)."
  fi
else
  warn "systemd not found; run manually:"
  warn "  $BIN_PATH --config $CONFIG --serve"
fi

if [ "$INIT_STATUS" -eq 1 ]; then
  warn "the baseline was written but some paths could not be scanned"
  warn "for unreadable paths, fix permissions; for large files, add them to exclude or raise max_file_bytes"
  warn "then rebuild with: $BIN_PATH --config $CONFIG --init --force"
elif [ "$INIT_STATUS" -gt 1 ]; then
  warn "the baseline was not created (exit $INIT_STATUS)"
fi

FINAL_STATUS=0
if [ "$INIT_STATUS" -eq 1 ]; then
  FINAL_STATUS=1
elif [ "$INIT_STATUS" -gt 1 ]; then
  FINAL_STATUS=2
fi

say ""
say "Installed."
PORT="${BIND##*:}"
case "$BIND" in
  127.0.0.1:*|localhost:*|\[::1\]:*)
    URL_HOST="${BIND%:*}"
    say "Dashboard: http://$URL_HOST:$PORT"
    say "This address is local to the host. From another machine, tunnel it over SSH:"
    say "  ssh -L $PORT:127.0.0.1:$PORT user@your-pi"
    ;;
  0.0.0.0:*|\[::\]:*)
    URL_HOST="$(hostname -I 2>/dev/null | cut -d' ' -f1)"
    [ -n "$URL_HOST" ] || URL_HOST="127.0.0.1"
    say "Dashboard: http://$URL_HOST:$PORT"
    ;;
  *)
    URL_HOST="${BIND%:*}"
    say "Dashboard: http://$URL_HOST:$PORT"
    ;;
esac
say ""
if [ -n "$TOKEN_PRINTED" ]; then
  say "Dashboard login token (keep it private, it will not be shown again):"
  say "  $TOKEN_PRINTED"
else
  say "Dashboard login token: $TOKEN_PATH (view it with: $BIN_PATH --config $CONFIG --print-token)"
fi
say ""
say "Useful commands:"
say "  $BIN_PATH --config $CONFIG --check      verify files against the baseline"
say "  $BIN_PATH --config $CONFIG --guard     port-scan guard status"
say "  $BIN_PATH --config $CONFIG --unban IP  lift a guard ban"
say "  $BIN_PATH --config $CONFIG --doctor    health checks"
if command -v systemctl >/dev/null 2>&1 && [ "$PREFIX" = "/" ]; then
  say "  systemctl status $SERVICE_NAME"
  say "  journalctl -u $SERVICE_NAME -f"
fi
say "  sudo $SETUP_PATH --reconfigure"
say ""
exit "$FINAL_STATUS"
