use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use walkdir::WalkDir;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const HASH_CHUNK: usize = 4096;
const BASELINE_FORMAT: &str = "my-ids-baseline";
const BASELINE_VERSION: u32 = 1;
const ALERTS_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
const DEFAULT_CONFIG_ETC: &str = "/etc/my-ids/config.json";
const DASHBOARD: &str = include_str!("dashboard.html");
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

static QUIET: AtomicBool = AtomicBool::new(false);

const USAGE: &str = concat!(
    "my-ids ",
    env!("CARGO_PKG_VERSION"),
    "\n",
    "Lightweight file integrity monitor for small Linux hosts.\n\n",
    "USAGE:\n",
    "    my-ids [--init | --check | --serve] [--config PATH] [--force] [--quiet]\n\n",
    "MODES:\n",
    "    --init      Scan the configured roots and write a new baseline\n",
    "    --check     Compare the live filesystem with the baseline\n",
    "    --serve     Start the dashboard (default when no mode is given)\n\n",
    "OPTIONS:\n",
    "    --config PATH   Config file (default: /etc/my-ids/config.json or ./config.json)\n",
    "    --force         Replace an existing baseline during --init\n",
    "    --quiet         Suppress informational log lines\n",
    "    -h, --help      Show this help\n",
    "    -V, --version   Show the version\n\n",
    "EXIT CODES:\n",
    "    0   Success, or a clean check\n",
    "    1   Check found anomalies or scan errors\n",
    "    2   Usage, configuration or I/O error\n"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Init,
    Check,
    Serve,
    Help,
    Version,
}

#[derive(Debug)]
struct Cli {
    action: Action,
    config: Option<PathBuf>,
    force: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct Config {
    roots: Vec<PathBuf>,
    exclude: Vec<PathBuf>,
    baseline_path: PathBuf,
    alerts_path: PathBuf,
    bind: String,
    max_alerts: usize,
    max_file_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            roots: [
                "/etc",
                "/boot",
                "/boot/firmware",
                "/usr/bin",
                "/usr/sbin",
                "/usr/lib/systemd/system",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            exclude: [
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
                "/tmp",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            baseline_path: PathBuf::from("/var/lib/my-ids/baseline.json"),
            alerts_path: PathBuf::from("/var/lib/my-ids/alerts.jsonl"),
            bind: "127.0.0.1:8080".to_string(),
            max_alerts: 500,
            max_file_bytes: 256 * 1024 * 1024,
        }
    }
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if self.roots.is_empty() {
            return Err("config: `roots` must list at least one directory".to_string());
        }
        for root in &self.roots {
            if !root.is_absolute() {
                return Err(format!(
                    "config: root '{}' is not an absolute path",
                    root.display()
                ));
            }
            if is_pseudo_path(root) {
                return Err(format!(
                    "config: root '{}' is a virtual filesystem and cannot be monitored",
                    root.display()
                ));
            }
        }
        for path in &self.exclude {
            if !path.is_absolute() {
                return Err(format!(
                    "config: exclude '{}' is not an absolute path",
                    path.display()
                ));
            }
        }
        if !self.baseline_path.is_absolute() {
            return Err("config: `baseline_path` must be absolute".to_string());
        }
        if !self.alerts_path.is_absolute() {
            return Err("config: `alerts_path` must be absolute".to_string());
        }
        let last_scan = self.baseline_path.with_file_name("last_scan.json");
        if self.baseline_path == self.alerts_path
            || self.baseline_path == last_scan
            || self.alerts_path == last_scan
        {
            return Err(
                "config: baseline_path, alerts_path and the last-scan file must be distinct"
                    .to_string(),
            );
        }
        if self.max_alerts == 0 {
            return Err("config: `max_alerts` must be greater than zero".to_string());
        }
        if self.max_file_bytes < HASH_CHUNK as u64 {
            return Err(format!(
                "config: `max_file_bytes` must be at least {HASH_CHUNK}"
            ));
        }
        if self.bind.parse::<SocketAddr>().is_err() {
            return Err(format!(
                "config: `bind` is not a socket address: {}",
                self.bind
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum ConfigSource {
    File(PathBuf),
    Defaults(PathBuf),
}

impl ConfigSource {
    fn path(&self) -> &Path {
        match self {
            Self::File(path) | Self::Defaults(path) => path,
        }
    }

    fn loaded(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    path: String,
    kind: Kind,
    size: u64,
    mode: u32,
    mtime: i64,
    mtime_ns: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Baseline {
    format: String,
    version: u32,
    created_at: u64,
    roots: Vec<String>,
    exclude: Vec<String>,
    entries: Vec<Record>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Alert {
    id: u64,
    kind: ChangeKind,
    path: String,
    detected_at: u64,
    changes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    old_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    new_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    mode: String,
    #[serde(default)]
    baseline_created_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ScanSummary {
    started_at: u64,
    finished_at: u64,
    duration_ms: u64,
    added: usize,
    modified: usize,
    deleted: usize,
    errors: usize,
    files_hashed: usize,
    bytes_hashed: u64,
    entries: usize,
    #[serde(default)]
    directories: usize,
    #[serde(default)]
    symlinks: usize,
    #[serde(default)]
    skipped: usize,
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ScanError {
    path: String,
    message: String,
}

#[derive(Default)]
struct ScanStats {
    hashed: usize,
    bytes: u64,
    dirs: usize,
    symlinks: usize,
    skipped: usize,
}

struct ScanOutcome {
    entries: Vec<Record>,
    errors: Vec<ScanError>,
    stats: ScanStats,
}

struct FileHash {
    hash: String,
    bytes_read: u64,
    size: u64,
    mtime: i64,
    mtime_ns: u32,
}

struct Detected {
    kind: ChangeKind,
    path: String,
    changes: Vec<String>,
    old_hash: Option<String>,
    new_hash: Option<String>,
    size: Option<u64>,
    mode: String,
}

impl Detected {
    fn alert(self, id: u64, detected_at: u64, baseline_created_at: u64) -> Alert {
        Alert {
            id,
            kind: self.kind,
            path: self.path,
            detected_at,
            changes: self.changes,
            old_hash: self.old_hash,
            new_hash: self.new_hash,
            size: self.size,
            mode: self.mode,
            baseline_created_at,
        }
    }
}

struct CheckOutcome {
    summary: ScanSummary,
    alerts: Vec<Alert>,
}

#[derive(Clone, Debug, Serialize)]
struct BaselineMeta {
    path: String,
    exists: bool,
    valid: bool,
    created_at: u64,
    entries: usize,
    size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    hostname: Option<String>,
    system_uptime_secs: Option<u64>,
    service_uptime_secs: u64,
    load1: Option<f64>,
    rss_kb: Option<u64>,
    scanning: bool,
    config_path: String,
    config_loaded: bool,
    roots: Vec<String>,
    exclude_count: usize,
    baseline: BaselineMeta,
    last_scan: Option<ScanSummary>,
    alert_count: usize,
    server_time: u64,
    poll_interval_ms: u64,
}

#[derive(Serialize)]
struct AlertsResponse {
    alerts: Vec<Alert>,
    total: usize,
    server_time: u64,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

type FileStamp = (i64, i64, u64);

struct WebData {
    alerts: VecDeque<Alert>,
    next_id: u64,
    last_scan: Option<ScanSummary>,
    baseline: BaselineMeta,
    baseline_stamp: Option<FileStamp>,
    alerts_stamp: Option<FileStamp>,
}

fn next_id_for_alerts(alerts: &VecDeque<Alert>) -> u64 {
    alerts
        .iter()
        .map(|alert| alert.id)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

impl WebData {
    fn load(cfg: &Config) -> Self {
        let alerts = load_recent_alerts(cfg);
        let next_id = next_id_for_alerts(&alerts);
        let last_scan = load_last_scan(cfg);
        let baseline_stamp = baseline_stamp(cfg);
        let alerts_stamp = file_stamp(&cfg.alerts_path);
        let baseline = baseline_meta(cfg);
        Self {
            alerts,
            next_id,
            last_scan,
            baseline,
            baseline_stamp,
            alerts_stamp,
        }
    }
}

struct AppState {
    cfg: Config,
    config_source: ConfigSource,
    started_at: u64,
    scanning: AtomicBool,
    inner: Mutex<WebData>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let code = match run().await {
        Ok(code) => code,
        Err(message) => {
            eprintln!("my-ids: {message}");
            2
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<i32, String> {
    let cli = parse_args()?;

    match cli.action {
        Action::Help => {
            println!("{USAGE}");
            return Ok(0);
        }
        Action::Version => {
            println!("my-ids {VERSION}");
            return Ok(0);
        }
        Action::Init | Action::Check | Action::Serve => {}
    }

    let (cfg, source) = load_config(cli.config.as_deref())?;

    match cli.action {
        Action::Init => {
            if let ConfigSource::Defaults(path) = &source {
                write_json_atomic(path, &Config::default(), 0o600)?;
                info(&format!("created default config at {}", path.display()));
            }
            let summary = perform_init(&cfg, cli.force)?;
            println!("Baseline written to {}", cfg.baseline_path.display());
            println!(
                "Entries: {} | hashed: {} files, {} | errors: {} | {} ms",
                summary.entries,
                summary.files_hashed,
                human_bytes(summary.bytes_hashed),
                summary.errors,
                summary.duration_ms
            );
            Ok(if summary.ok { 0 } else { 1 })
        }
        Action::Check => {
            if !source.loaded() && !cfg.baseline_path.exists() {
                return Err("no config or baseline found; run 'my-ids --init' first".to_string());
            }
            let next_id = next_alert_id(&cfg);
            let outcome = perform_check(&cfg, next_id)?;
            print_check(&outcome);
            Ok(if outcome.summary.ok { 0 } else { 1 })
        }
        Action::Serve => serve(cfg, source).await,
        Action::Help | Action::Version => Ok(0),
    }
}

fn parse_args() -> Result<Cli, String> {
    let mut action: Option<Action> = None;
    let mut config = None;
    let mut force = false;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--init" => set_action(&mut action, Action::Init)?,
            "--check" => set_action(&mut action, Action::Check)?,
            "--serve" => set_action(&mut action, Action::Serve)?,
            "-h" | "--help" => set_action(&mut action, Action::Help)?,
            "-V" | "--version" => set_action(&mut action, Action::Version)?,
            "--force" => force = true,
            "-q" | "--quiet" => QUIET.store(true, Ordering::Relaxed),
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--config requires a path".to_string())?;
                config = Some(PathBuf::from(value));
            }
            other => {
                if let Some(value) = other.strip_prefix("--config=") {
                    if value.is_empty() {
                        return Err("--config requires a path".to_string());
                    }
                    config = Some(PathBuf::from(value));
                } else {
                    return Err(format!("unknown argument '{other}'"));
                }
            }
        }
    }

    Ok(Cli {
        action: action.unwrap_or(Action::Serve),
        config,
        force,
    })
}

fn set_action(slot: &mut Option<Action>, next: Action) -> Result<(), String> {
    match slot {
        Some(existing) if *existing != next => {
            Err("choose one of --init, --check or --serve".to_string())
        }
        _ => {
            *slot = Some(next);
            Ok(())
        }
    }
}

fn resolve_config_path(cli: Option<&Path>) -> PathBuf {
    if let Some(path) = cli {
        return path.to_path_buf();
    }
    if let Ok(value) = std::env::var("MY_IDS_CONFIG") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    let etc = PathBuf::from(DEFAULT_CONFIG_ETC);
    if etc.exists() || effective_uid() == Some(0) {
        return etc;
    }
    PathBuf::from("config.json")
}

fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let values = line.strip_prefix("Uid:")?;
        values
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u32>().ok())
    })
}

fn load_config(cli: Option<&Path>) -> Result<(Config, ConfigSource), String> {
    let path = resolve_config_path(cli);
    match fs::read(&path) {
        Ok(bytes) => {
            let cfg: Config = serde_json::from_slice(&bytes)
                .map_err(|error| format!("cannot parse config '{}': {error}", path.display()))?;
            cfg.validate()?;
            Ok((cfg, ConfigSource::File(path)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let cfg = Config::default();
            cfg.validate()?;
            Ok((cfg, ConfigSource::Defaults(path)))
        }
        Err(error) => Err(format!("cannot read config '{}': {error}", path.display())),
    }
}

fn is_pseudo_path(path: &Path) -> bool {
    ["/proc", "/sys", "/dev", "/run"]
        .iter()
        .any(|candidate| path == Path::new(candidate))
}

fn effective_excludes(cfg: &Config) -> Vec<PathBuf> {
    let mut excludes = cfg.exclude.clone();
    for pseudo in ["/proc", "/sys", "/dev", "/run"] {
        excludes.push(PathBuf::from(pseudo));
    }
    for path in [&cfg.baseline_path, &cfg.alerts_path, &last_scan_path(cfg)] {
        excludes.push(path.clone());
        if let Some(parent) = path.parent() {
            if parent != Path::new("/") && !parent.as_os_str().is_empty() {
                excludes.push(parent.to_path_buf());
            }
        }
    }
    excludes.sort();
    excludes.dedup();
    excludes
}

fn is_excluded(path: &Path, excludes: &[PathBuf]) -> bool {
    excludes
        .iter()
        .any(|exclude| path == exclude || path.starts_with(exclude))
}

fn scan_filesystem(cfg: &Config) -> Result<ScanOutcome, String> {
    let excludes = effective_excludes(cfg);
    let mut entries: Vec<Record> = Vec::with_capacity(4096);
    let mut errors: Vec<ScanError> = Vec::new();
    let mut stats = ScanStats::default();
    let skipped = Cell::new(0usize);
    let mut seen_roots: HashSet<PathBuf> = HashSet::new();
    let mut walked_roots = 0usize;

    for root in &cfg.roots {
        let canonical = match fs::canonicalize(root) {
            Ok(path) => path,
            Err(error) => {
                errors.push(ScanError {
                    path: root.display().to_string(),
                    message: format!("cannot resolve root: {error}"),
                });
                continue;
            }
        };
        match fs::metadata(&canonical) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                errors.push(ScanError {
                    path: canonical.display().to_string(),
                    message: "root is not a directory".to_string(),
                });
                continue;
            }
            Err(error) => {
                errors.push(ScanError {
                    path: canonical.display().to_string(),
                    message: format!("cannot stat root: {error}"),
                });
                continue;
            }
        }
        if !seen_roots.insert(canonical.clone()) {
            continue;
        }
        walked_roots += 1;

        let walker = WalkDir::new(&canonical)
            .follow_links(false)
            .same_file_system(true)
            .max_open(16)
            .into_iter()
            .filter_entry(|entry| {
                if is_excluded(entry.path(), &excludes) {
                    skipped.set(skipped.get() + 1);
                    false
                } else {
                    true
                }
            });

        for item in walker {
            let entry = match item {
                Ok(entry) => entry,
                Err(error) => {
                    let path = error
                        .path()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| canonical.display().to_string());
                    errors.push(ScanError {
                        path,
                        message: error.to_string(),
                    });
                    continue;
                }
            };

            let path = entry.path();
            let path_string = match path.to_str() {
                Some(value) => value.to_string(),
                None => {
                    skipped.set(skipped.get() + 1);
                    errors.push(ScanError {
                        path: path.to_string_lossy().into_owned(),
                        message: "skipping a non-UTF-8 path".to_string(),
                    });
                    continue;
                }
            };

            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    errors.push(ScanError {
                        path: path_string,
                        message: format!("stat failed: {error}"),
                    });
                    continue;
                }
            };

            let file_type = metadata.file_type();
            let mode = metadata.mode() & 0o7777;
            let mtime = metadata.mtime();
            let mtime_ns = metadata.mtime_nsec().max(0) as u32;

            if file_type.is_dir() {
                stats.dirs += 1;
                entries.push(Record {
                    path: path_string,
                    kind: Kind::Dir,
                    size: 0,
                    mode,
                    mtime,
                    mtime_ns,
                    hash: None,
                });
            } else if file_type.is_file() {
                match hash_file(path, metadata.len(), cfg.max_file_bytes, mtime, mtime_ns) {
                    Ok(hashed) => {
                        stats.hashed += 1;
                        stats.bytes = stats.bytes.saturating_add(hashed.bytes_read);
                        entries.push(Record {
                            path: path_string,
                            kind: Kind::File,
                            size: hashed.size,
                            mode,
                            mtime: hashed.mtime,
                            mtime_ns: hashed.mtime_ns,
                            hash: Some(hashed.hash),
                        });
                    }
                    Err(message) => errors.push(ScanError {
                        path: path_string,
                        message,
                    }),
                }
            } else if file_type.is_symlink() {
                stats.symlinks += 1;
                let hash = match fs::read_link(path) {
                    Ok(target) => Some(
                        blake3::hash(target.as_os_str().as_bytes())
                            .to_hex()
                            .to_string(),
                    ),
                    Err(error) => {
                        errors.push(ScanError {
                            path: path_string.clone(),
                            message: format!("readlink failed: {error}"),
                        });
                        None
                    }
                };
                entries.push(Record {
                    path: path_string,
                    kind: Kind::Symlink,
                    size: metadata.len(),
                    mode,
                    mtime,
                    mtime_ns,
                    hash,
                });
            } else {
                entries.push(Record {
                    path: path_string,
                    kind: Kind::Other,
                    size: metadata.len(),
                    mode,
                    mtime,
                    mtime_ns,
                    hash: None,
                });
            }
        }
    }

    stats.skipped = skipped.get();

    if walked_roots == 0 {
        return Err(
            "none of the configured roots could be scanned; check `roots` in the config"
                .to_string(),
        );
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries.dedup_by(|left, right| left.path == right.path);

    Ok(ScanOutcome {
        entries,
        errors,
        stats,
    })
}

fn hash_file(
    path: &Path,
    size: u64,
    max_bytes: u64,
    before_mtime: i64,
    before_mtime_ns: u32,
) -> Result<FileHash, String> {
    if size > max_bytes {
        return Err(format!(
            "skipped: {size} bytes exceeds max_file_bytes ({max_bytes})"
        ));
    }

    let mut file = File::open(path).map_err(|error| format!("open failed: {error}"))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; HASH_CHUNK];
    let mut total = 0u64;

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read failed: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(format!(
                "skipped: file grew beyond max_file_bytes ({max_bytes}) while hashing"
            ));
        }
    }

    let after =
        fs::symlink_metadata(path).map_err(|error| format!("stat after read failed: {error}"))?;
    let after_mtime = after.mtime();
    let after_mtime_ns = after.mtime_nsec().max(0) as u32;

    if after.len() != size || after_mtime != before_mtime || after_mtime_ns != before_mtime_ns {
        return Err("file changed while hashing; scan again".to_string());
    }

    Ok(FileHash {
        hash: hasher.finalize().to_hex().to_string(),
        bytes_read: total,
        size: after.len(),
        mtime: after_mtime,
        mtime_ns: after_mtime_ns,
    })
}

fn diff_entries(previous: &[Record], current: &[Record]) -> Vec<Detected> {
    let mut previous_by_path: HashMap<&str, &Record> = HashMap::with_capacity(previous.len());
    for record in previous {
        previous_by_path.insert(record.path.as_str(), record);
    }

    let mut detected = Vec::new();

    for record in current {
        match previous_by_path.remove(record.path.as_str()) {
            None => detected.push(Detected {
                kind: ChangeKind::Added,
                path: record.path.clone(),
                changes: Vec::new(),
                old_hash: None,
                new_hash: record.hash.clone(),
                size: Some(record.size),
                mode: format_mode(record.mode),
            }),
            Some(old) => {
                let changes = changes_between(old, record);
                if !changes.is_empty() {
                    detected.push(Detected {
                        kind: ChangeKind::Modified,
                        path: record.path.clone(),
                        changes,
                        old_hash: old.hash.clone(),
                        new_hash: record.hash.clone(),
                        size: Some(record.size),
                        mode: format_mode(record.mode),
                    });
                }
            }
        }
    }

    for old in previous_by_path.into_values() {
        detected.push(Detected {
            kind: ChangeKind::Deleted,
            path: old.path.clone(),
            changes: Vec::new(),
            old_hash: old.hash.clone(),
            new_hash: None,
            size: Some(old.size),
            mode: format_mode(old.mode),
        });
    }

    detected.sort_by(|left, right| left.path.cmp(&right.path));
    detected
}

fn changes_between(previous: &Record, current: &Record) -> Vec<String> {
    let mut changes = Vec::new();

    if previous.kind != current.kind {
        changes.push("type".to_string());
    }
    if previous.hash != current.hash {
        changes.push("content".to_string());
    }
    if previous.mode != current.mode {
        changes.push("mode".to_string());
    }
    if previous.size != current.size {
        changes.push("size".to_string());
    }
    if previous.mtime != current.mtime || previous.mtime_ns != current.mtime_ns {
        changes.push("mtime".to_string());
    }

    changes
}

fn format_mode(mode: u32) -> String {
    format!("{:04o}", mode)
}

fn same_path_set(left: &[String], right: &[String]) -> bool {
    let mut left: Vec<&str> = left.iter().map(String::as_str).collect();
    let mut right: Vec<&str> = right.iter().map(String::as_str).collect();
    left.sort_unstable();
    right.sort_unstable();
    left.dedup();
    right.dedup();
    left == right
}

fn baseline_matches_config(baseline: &Baseline, cfg: &Config) -> bool {
    let roots: Vec<String> = cfg
        .roots
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let excludes: Vec<String> = cfg
        .exclude
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    same_path_set(&baseline.roots, &roots) && same_path_set(&baseline.exclude, &excludes)
}

fn perform_init(cfg: &Config, force: bool) -> Result<ScanSummary, String> {
    if cfg.baseline_path.exists() && !force {
        return Err(format!(
            "baseline '{}' already exists; pass --force to replace it",
            cfg.baseline_path.display()
        ));
    }

    let started_at = now();
    let started = Instant::now();
    let outcome = scan_filesystem(cfg)?;
    let ScanOutcome {
        entries,
        errors,
        stats,
    } = outcome;

    if entries.is_empty() {
        return Err("scan produced no entries; check the `roots` in your config".to_string());
    }

    let entry_count = entries.len();
    let baseline = Baseline {
        format: BASELINE_FORMAT.to_string(),
        version: BASELINE_VERSION,
        created_at: started_at,
        roots: cfg
            .roots
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        exclude: cfg
            .exclude
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        entries,
    };

    write_json_atomic(&cfg.baseline_path, &baseline, 0o600)?;

    let summary = ScanSummary {
        started_at,
        finished_at: now(),
        duration_ms: elapsed_ms(started),
        added: 0,
        modified: 0,
        deleted: 0,
        errors: errors.len(),
        files_hashed: stats.hashed,
        bytes_hashed: stats.bytes,
        entries: entry_count,
        directories: stats.dirs,
        symlinks: stats.symlinks,
        skipped: stats.skipped,
        ok: errors.is_empty(),
        message: None,
    };

    if let Err(error) = store_last_scan(cfg, &summary) {
        warn(&format!("could not store the scan summary: {error}"));
    }
    report_scan_errors(&errors);

    Ok(summary)
}

fn perform_check(cfg: &Config, start_id: u64) -> Result<CheckOutcome, String> {
    let baseline = load_baseline(&cfg.baseline_path)?;
    if !baseline_matches_config(&baseline, cfg) {
        return Err(format!(
            "baseline '{}' was created with different roots or excludes; re-run --init with this config",
            cfg.baseline_path.display()
        ));
    }
    let started_at = now();
    let started = Instant::now();
    let outcome = scan_filesystem(cfg)?;
    let detected = diff_entries(&baseline.entries, &outcome.entries);
    let detected_at = now();

    let mut next_id = start_id;
    let alerts: Vec<Alert> = detected
        .into_iter()
        .map(|item| {
            let alert = item.alert(next_id, detected_at, baseline.created_at);
            next_id = next_id.saturating_add(1);
            alert
        })
        .collect();

    let mut message = None;
    if let Err(error) = append_alerts(cfg, &alerts) {
        warn(&format!("could not persist alerts: {error}"));
        message = Some(format!("alerts were not written to disk: {error}"));
    }

    let added = alerts
        .iter()
        .filter(|alert| alert.kind == ChangeKind::Added)
        .count();
    let modified = alerts
        .iter()
        .filter(|alert| alert.kind == ChangeKind::Modified)
        .count();
    let deleted = alerts
        .iter()
        .filter(|alert| alert.kind == ChangeKind::Deleted)
        .count();

    let summary = ScanSummary {
        started_at,
        finished_at: now(),
        duration_ms: elapsed_ms(started),
        added,
        modified,
        deleted,
        errors: outcome.errors.len(),
        files_hashed: outcome.stats.hashed,
        bytes_hashed: outcome.stats.bytes,
        entries: outcome.entries.len(),
        directories: outcome.stats.dirs,
        symlinks: outcome.stats.symlinks,
        skipped: outcome.stats.skipped,
        ok: added + modified + deleted == 0 && outcome.errors.is_empty() && message.is_none(),
        message,
    };

    if let Err(error) = store_last_scan(cfg, &summary) {
        warn(&format!("could not store the scan summary: {error}"));
    }
    report_scan_errors(&outcome.errors);

    Ok(CheckOutcome { summary, alerts })
}

fn print_check(outcome: &CheckOutcome) {
    for alert in &outcome.alerts {
        let label = match alert.kind {
            ChangeKind::Added => "ADDED",
            ChangeKind::Modified => "MODIFIED",
            ChangeKind::Deleted => "DELETED",
        };
        if alert.changes.is_empty() {
            println!("{label:<9} {}", alert.path);
        } else {
            println!("{label:<9} {}  [{}]", alert.path, alert.changes.join(", "));
        }
    }

    let summary = &outcome.summary;
    println!(
        "Scan complete: {} added, {} modified, {} deleted, {} errors | {} files hashed, {} | {} ms",
        summary.added,
        summary.modified,
        summary.deleted,
        summary.errors,
        summary.files_hashed,
        human_bytes(summary.bytes_hashed),
        summary.duration_ms
    );

    if let Some(message) = &summary.message {
        println!("Note: {message}");
    }
}

fn report_scan_errors(errors: &[ScanError]) {
    for error in errors.iter().take(10) {
        warn(&format!("{}: {}", error.path, error.message));
    }
    if errors.len() > 10 {
        warn(&format!(
            "{} additional scan errors suppressed",
            errors.len() - 10
        ));
    }
}

fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            format!(
                "baseline '{}' not found; run 'my-ids --init'",
                path.display()
            )
        } else {
            format!("cannot read baseline '{}': {error}", path.display())
        }
    })?;

    let baseline: Baseline = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse baseline '{}': {error}", path.display()))?;

    if baseline.format != BASELINE_FORMAT {
        return Err(format!("'{}' is not a my-ids baseline", path.display()));
    }
    if baseline.version != BASELINE_VERSION {
        return Err(format!(
            "unsupported baseline version {} in '{}'; re-run --init",
            baseline.version,
            path.display()
        ));
    }

    Ok(baseline)
}

fn append_alerts(cfg: &Config, alerts: &[Alert]) -> Result<(), String> {
    if alerts.is_empty() {
        return Ok(());
    }

    ensure_parent(&cfg.alerts_path)?;
    rotate_alerts(&cfg.alerts_path)?;

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&cfg.alerts_path)
        .map_err(|error| {
            format!(
                "cannot open alerts log '{}': {error}",
                cfg.alerts_path.display()
            )
        })?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            format!(
                "cannot set permissions on alerts log '{}': {error}",
                cfg.alerts_path.display()
            )
        })?;

    let mut writer = BufWriter::with_capacity(16 * 1024, file);
    for alert in alerts {
        let line = serde_json::to_string(alert)
            .map_err(|error| format!("cannot encode alert: {error}"))?;
        writer
            .write_all(line.as_bytes())
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|error| {
                format!(
                    "cannot write alerts log '{}': {error}",
                    cfg.alerts_path.display()
                )
            })?;
    }
    writer.flush().map_err(|error| {
        format!(
            "cannot flush alerts log '{}': {error}",
            cfg.alerts_path.display()
        )
    })?;

    let file = writer
        .into_inner()
        .map_err(|error| format!("cannot finish alerts log: {error}"))?;
    file.sync_data().map_err(|error| {
        format!(
            "cannot sync alerts log '{}': {error}",
            cfg.alerts_path.display()
        )
    })?;

    Ok(())
}

fn rotate_alerts(path: &Path) -> Result<(), String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot stat alerts log '{}': {error}",
                path.display()
            ));
        }
    };

    if metadata.len() < ALERTS_ROTATE_BYTES {
        return Ok(());
    }

    let mut rotated = path.as_os_str().to_os_string();
    rotated.push(".1");
    let rotated = PathBuf::from(rotated);

    if rotated.exists() {
        fs::remove_file(&rotated).map_err(|error| {
            format!(
                "cannot remove old alerts log '{}': {error}",
                rotated.display()
            )
        })?;
    }
    fs::rename(path, &rotated)
        .map_err(|error| format!("cannot rotate alerts log '{}': {error}", path.display()))?;

    Ok(())
}

fn load_recent_alerts(cfg: &Config) -> VecDeque<Alert> {
    let mut alerts = VecDeque::new();
    let bytes = match fs::read(&cfg.alerts_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            if error.kind() != io::ErrorKind::NotFound {
                warn(&format!(
                    "cannot read alerts '{}': {error}",
                    cfg.alerts_path.display()
                ));
            }
            return alerts;
        }
    };
    let data = String::from_utf8_lossy(&bytes);

    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(alert) = serde_json::from_str::<Alert>(line) {
            alerts.push_back(alert);
            while alerts.len() > cfg.max_alerts {
                alerts.pop_front();
            }
        }
    }

    alerts
}

fn next_alert_id(cfg: &Config) -> u64 {
    let bytes = fs::read(&cfg.alerts_path).unwrap_or_default();
    let data = String::from_utf8_lossy(&bytes);
    let highest = data
        .lines()
        .filter_map(|line| serde_json::from_str::<Alert>(line).ok())
        .map(|alert| alert.id)
        .max()
        .unwrap_or(0);
    highest.saturating_add(1)
}

fn last_scan_path(cfg: &Config) -> PathBuf {
    let mut path = cfg.baseline_path.clone();
    path.set_file_name("last_scan.json");
    path
}

fn store_last_scan(cfg: &Config, summary: &ScanSummary) -> Result<(), String> {
    write_json_atomic(&last_scan_path(cfg), summary, 0o600)
}

fn load_last_scan(cfg: &Config) -> Option<ScanSummary> {
    let bytes = fs::read(last_scan_path(cfg)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<(), String> {
    ensure_parent(path)?;
    let temporary = temp_path(path);

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|error| format!("cannot create '{}': {error}", temporary.display()))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| {
            format!(
                "cannot set permissions on '{}': {error}",
                temporary.display()
            )
        })?;

    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| format!("cannot encode '{}': {error}", path.display()))?;
    writer
        .flush()
        .map_err(|error| format!("cannot flush '{}': {error}", temporary.display()))?;

    let file = writer
        .into_inner()
        .map_err(|error| format!("cannot finish '{}': {error}", temporary.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync '{}': {error}", temporary.display()))?;
    drop(file);

    fs::rename(&temporary, path).map_err(|error| {
        format!(
            "cannot move '{}' into place at '{}': {error}",
            temporary.display(),
            path.display()
        )
    })?;

    if let Some(parent) = path.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }

    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(temporary)
}

fn ensure_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|error| {
                    format!("cannot create directory '{}': {error}", parent.display())
                })?;
        }
    }
    Ok(())
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.mtime(), metadata.mtime_nsec(), metadata.len()))
}

fn baseline_stamp(cfg: &Config) -> Option<FileStamp> {
    file_stamp(&cfg.baseline_path)
}

fn baseline_meta(cfg: &Config) -> BaselineMeta {
    let path = cfg.baseline_path.display().to_string();
    match fs::metadata(&cfg.baseline_path) {
        Ok(metadata) => {
            let parsed = fs::read(&cfg.baseline_path)
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    serde_json::from_slice::<Baseline>(&bytes).map_err(|error| error.to_string())
                });
            match parsed {
                Ok(baseline)
                    if baseline.format == BASELINE_FORMAT
                        && baseline.version == BASELINE_VERSION =>
                {
                    if baseline_matches_config(&baseline, cfg) {
                        BaselineMeta {
                            path,
                            exists: true,
                            valid: true,
                            created_at: baseline.created_at,
                            entries: baseline.entries.len(),
                            size_bytes: metadata.len(),
                            reason: None,
                        }
                    } else {
                        BaselineMeta {
                            path,
                            exists: true,
                            valid: false,
                            created_at: 0,
                            entries: 0,
                            size_bytes: metadata.len(),
                            reason: Some(
                                "Baseline roots or excludes differ from this config.".to_string(),
                            ),
                        }
                    }
                }
                Ok(_) => BaselineMeta {
                    path,
                    exists: true,
                    valid: false,
                    created_at: 0,
                    entries: 0,
                    size_bytes: metadata.len(),
                    reason: Some("Baseline format is not supported.".to_string()),
                },
                Err(_) => BaselineMeta {
                    path,
                    exists: true,
                    valid: false,
                    created_at: 0,
                    entries: 0,
                    size_bytes: metadata.len(),
                    reason: Some("Baseline could not be parsed.".to_string()),
                },
            }
        }
        Err(_) => BaselineMeta {
            path,
            exists: false,
            valid: false,
            created_at: 0,
            entries: 0,
            size_bytes: 0,
            reason: None,
        },
    }
}

fn refresh_baseline(cfg: &Config, data: &mut WebData) {
    let stamp = baseline_stamp(cfg);
    if stamp != data.baseline_stamp {
        data.baseline_stamp = stamp;
        data.baseline = baseline_meta(cfg);
        data.last_scan = load_last_scan(cfg);
        if !data.baseline.exists {
            data.last_scan = None;
        }
    }
}

fn refresh_alerts(cfg: &Config, data: &mut WebData) {
    let stamp = file_stamp(&cfg.alerts_path);
    if stamp == data.alerts_stamp {
        return;
    }
    data.alerts_stamp = stamp;
    data.alerts = load_recent_alerts(cfg);
    data.next_id = next_id_for_alerts(&data.alerts);
}

fn baseline_generation(data: &WebData) -> Option<u64> {
    if data.baseline.valid {
        Some(data.baseline.created_at)
    } else {
        None
    }
}

fn alert_is_current(alert: &Alert, generation: Option<u64>) -> bool {
    match generation {
        Some(created_at) => alert.baseline_created_at == created_at,
        None => true,
    }
}

fn visible_alerts(data: &WebData) -> Vec<Alert> {
    let generation = baseline_generation(data);
    let mut seen = HashSet::new();
    let mut visible = Vec::new();
    for alert in data.alerts.iter().rev() {
        if !alert_is_current(alert, generation) {
            continue;
        }
        if seen.insert(alert.path.as_str()) {
            visible.push(alert.clone());
        }
    }
    visible
}

async fn serve(cfg: Config, source: ConfigSource) -> Result<i32, String> {
    let address: SocketAddr = cfg
        .bind
        .parse()
        .map_err(|error| format!("invalid bind address '{}': {error}", cfg.bind))?;

    if !source.loaded() {
        warn(&format!(
            "no config file at '{}'; using built-in defaults",
            source.path().display()
        ));
    }
    if !cfg.baseline_path.exists() {
        warn(&format!(
            "baseline '{}' is missing; run 'my-ids --init' before scanning",
            cfg.baseline_path.display()
        ));
    }

    let data = WebData::load(&cfg);
    let state = Arc::new(AppState {
        cfg,
        config_source: source,
        started_at: now(),
        scanning: AtomicBool::new(false),
        inner: Mutex::new(data),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/favicon.ico", get(favicon))
        .route("/healthz", get(healthz))
        .route("/api/status", get(api_status))
        .route("/api/alerts", get(api_alerts))
        .route(
            "/api/scan",
            post(api_scan).layer(DefaultBodyLimit::max(1024)),
        )
        .layer(middleware::from_fn(security_headers))
        .with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("cannot bind {address}: {error}"))?;

    info(&format!("dashboard listening on http://{address}"));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| format!("server failed: {error}"))?;

    info("shutdown complete");
    Ok(0)
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD,
    )
}

async fn healthz() -> &'static str {
    "ok"
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn api_status(State(state): State<Arc<AppState>>) -> Result<Json<StatusResponse>, ApiError> {
    let mut data = state
        .inner
        .lock()
        .map_err(|_| ApiError::internal("state lock was poisoned"))?;
    refresh_alerts(&state.cfg, &mut data);
    refresh_baseline(&state.cfg, &mut data);

    let system = system_info();
    let generation = baseline_generation(&data);
    let alert_count = {
        let mut seen = HashSet::new();
        data.alerts
            .iter()
            .rev()
            .filter(|alert| alert_is_current(alert, generation))
            .filter(|alert| seen.insert(alert.path.as_str()))
            .count()
    };
    let response = StatusResponse {
        version: VERSION,
        hostname: system.hostname,
        system_uptime_secs: system.uptime_secs,
        service_uptime_secs: now().saturating_sub(state.started_at),
        load1: system.load1,
        rss_kb: system.rss_kb,
        scanning: state.scanning.load(Ordering::Relaxed),
        config_path: state.config_source.path().display().to_string(),
        config_loaded: state.config_source.loaded(),
        roots: state
            .cfg
            .roots
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        exclude_count: state.cfg.exclude.len(),
        baseline: data.baseline.clone(),
        last_scan: data.last_scan.clone(),
        alert_count,
        server_time: now(),
        poll_interval_ms: 5000,
    };

    Ok(Json(response))
}

async fn api_alerts(State(state): State<Arc<AppState>>) -> Result<Json<AlertsResponse>, ApiError> {
    let mut data = state
        .inner
        .lock()
        .map_err(|_| ApiError::internal("state lock was poisoned"))?;
    refresh_alerts(&state.cfg, &mut data);
    refresh_baseline(&state.cfg, &mut data);
    let alerts = visible_alerts(&data);
    Ok(Json(AlertsResponse {
        total: alerts.len(),
        server_time: now(),
        alerts,
    }))
}

async fn api_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // A custom header forces a CORS preflight for cross-origin callers. The
    // dashboard is same-origin, so this blocks drive-by form posts to the scan
    // endpoint without adding a token to the static page.
    if headers
        .get("x-my-ids-scan")
        .and_then(|value| value.to_str().ok())
        != Some("1")
    {
        return Err(ApiError::forbidden("missing x-my-ids-scan header"));
    }

    if !state.cfg.baseline_path.exists() {
        return Err(ApiError::conflict(
            "baseline is missing; run my-ids --init on the host",
        ));
    }

    if state
        .scanning
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(ApiError::conflict("a scan is already running"));
    }

    let worker = Arc::clone(&state);
    tokio::task::spawn_blocking(move || {
        let result = run_check_in_background(&worker);
        worker.scanning.store(false, Ordering::SeqCst);
        match result {
            Ok(summary) => info(&format!(
                "manual scan finished: {} added, {} modified, {} deleted, {} errors in {} ms",
                summary.added,
                summary.modified,
                summary.deleted,
                summary.errors,
                summary.duration_ms
            )),
            Err(message) => warn(&format!("manual scan failed: {message}")),
        }
    });

    Ok((StatusCode::ACCEPTED, Json(json!({ "started": true }))))
}

fn run_check_in_background(state: &Arc<AppState>) -> Result<ScanSummary, String> {
    let start_id = {
        let data = state
            .inner
            .lock()
            .map_err(|_| "state lock was poisoned".to_string())?;
        data.next_id
    };

    let outcome = perform_check(&state.cfg, start_id)?;

    let mut data = state
        .inner
        .lock()
        .map_err(|_| "state lock was poisoned".to_string())?;
    for alert in &outcome.alerts {
        data.alerts.push_back(alert.clone());
        while data.alerts.len() > state.cfg.max_alerts {
            data.alerts.pop_front();
        }
    }
    data.next_id = start_id.saturating_add(outcome.alerts.len() as u64);
    data.last_scan = Some(outcome.summary.clone());
    data.alerts_stamp = file_stamp(&state.cfg.alerts_path);
    refresh_baseline(&state.cfg, &mut data);

    Ok(outcome.summary)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info("shutdown signal received");
}

struct SystemInfo {
    hostname: Option<String>,
    uptime_secs: Option<u64>,
    load1: Option<f64>,
    rss_kb: Option<u64>,
}

fn system_info() -> SystemInfo {
    let hostname = read_first_line("/proc/sys/kernel/hostname");
    let uptime_secs = read_first_token("/proc/uptime")
        .and_then(|value| value.parse::<f64>().ok())
        .map(|value| value as u64);
    let load1 = read_first_token("/proc/loadavg").and_then(|value| value.parse::<f64>().ok());
    let rss_kb = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let values = line.strip_prefix("VmRSS:")?;
                values.split_whitespace().next()?.parse::<u64>().ok()
            })
        });

    SystemInfo {
        hostname,
        uptime_secs,
        load1,
        rss_kb,
    }
}

fn read_first_line(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn read_first_token(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.split_whitespace().next().map(str::to_string))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn info(message: &str) {
    if !QUIET.load(Ordering::Relaxed) {
        eprintln!("{} INFO  {}", rfc3339(now()), message);
    }
}

fn warn(message: &str) {
    eprintln!("{} WARN  {}", rfc3339(now()), message);
}

fn rfc3339(timestamp: u64) -> String {
    let days = (timestamp / 86_400) as i64;
    let seconds = timestamp % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(path: &str, kind: Kind, mode: u32, hash: Option<&str>) -> Record {
        Record {
            path: path.to_string(),
            kind,
            size: 10,
            mode,
            mtime: 100,
            mtime_ns: 0,
            hash: hash.map(str::to_string),
        }
    }

    #[test]
    fn rfc3339_matches_known_timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn exclusions_are_component_aware() {
        let excludes = vec![PathBuf::from("/var/log")];
        assert!(is_excluded(Path::new("/var/log"), &excludes));
        assert!(is_excluded(Path::new("/var/log/syslog"), &excludes));
        assert!(!is_excluded(Path::new("/var/logs/syslog"), &excludes));
    }

    #[test]
    fn diff_reports_added_modified_and_deleted() {
        let previous = vec![
            record("/etc/keep", Kind::File, 0o644, Some("aa")),
            record("/etc/gone", Kind::File, 0o644, Some("bb")),
            record("/etc/changed", Kind::File, 0o644, Some("cc")),
        ];
        let current = vec![
            record("/etc/keep", Kind::File, 0o644, Some("aa")),
            record("/etc/changed", Kind::File, 0o600, Some("cc")),
            record("/etc/new", Kind::File, 0o644, Some("dd")),
        ];

        let detected = diff_entries(&previous, &current);
        assert_eq!(detected.len(), 3);
        assert!(detected
            .iter()
            .any(|item| item.path == "/etc/new" && item.kind == ChangeKind::Added));
        assert!(detected
            .iter()
            .any(|item| item.path == "/etc/gone" && item.kind == ChangeKind::Deleted));

        let modified = detected
            .iter()
            .find(|item| item.path == "/etc/changed")
            .expect("modified entry is present");
        assert_eq!(modified.kind, ChangeKind::Modified);
        assert_eq!(modified.changes, vec!["mode".to_string()]);
    }

    #[test]
    fn content_changes_are_reported() {
        let previous = record("/etc/a", Kind::File, 0o644, Some("aa"));
        let current = record("/etc/a", Kind::File, 0o644, Some("ab"));
        assert_eq!(
            changes_between(&previous, &current),
            vec!["content".to_string()]
        );
    }

    #[test]
    fn modes_are_rendered_as_octal() {
        assert_eq!(format_mode(0o644), "0644");
        assert_eq!(format_mode(0o4755), "4755");
    }

    #[test]
    fn baseline_survives_a_round_trip() {
        let baseline = Baseline {
            format: BASELINE_FORMAT.to_string(),
            version: BASELINE_VERSION,
            created_at: 5,
            roots: vec!["/etc".to_string()],
            exclude: Vec::new(),
            entries: vec![record("/etc/a", Kind::File, 0o644, Some("aa"))],
        };
        let encoded = serde_json::to_vec(&baseline).expect("baseline encodes");
        let decoded: Baseline = serde_json::from_slice(&encoded).expect("baseline decodes");
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].path, "/etc/a");
    }

    #[test]
    fn visible_alerts_keep_one_current_row_per_path() {
        let alert = |id: u64, path: &str, kind: ChangeKind, at: u64, generation: u64| Alert {
            id,
            kind,
            path: path.to_string(),
            detected_at: at,
            changes: Vec::new(),
            old_hash: None,
            new_hash: None,
            size: Some(1),
            mode: "0644".to_string(),
            baseline_created_at: generation,
        };

        let data = WebData {
            alerts: VecDeque::from(vec![
                alert(1, "/etc/a", ChangeKind::Modified, 10, 100),
                alert(2, "/etc/a", ChangeKind::Modified, 20, 100),
                alert(3, "/etc/b", ChangeKind::Added, 15, 100),
                alert(4, "/etc/c", ChangeKind::Deleted, 30, 50),
            ]),
            next_id: 5,
            last_scan: None,
            baseline: BaselineMeta {
                path: "/var/lib/my-ids/baseline.json".to_string(),
                exists: true,
                valid: true,
                created_at: 100,
                entries: 3,
                size_bytes: 10,
                reason: None,
            },
            baseline_stamp: None,
            alerts_stamp: None,
        };

        let visible = visible_alerts(&data);
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].path, "/etc/b");
        assert_eq!(visible[0].id, 3);
        assert_eq!(visible[1].path, "/etc/a");
        assert_eq!(visible[1].id, 2);
    }

    #[test]
    fn baseline_meta_validates_format_and_version() {
        let base = std::env::temp_dir().join(format!("my-ids-meta-test-{}", std::process::id()));
        fs::create_dir_all(&base).expect("create temp directory");
        let config = Config {
            roots: vec![PathBuf::from("/etc")],
            exclude: Vec::new(),
            baseline_path: base.join("baseline.json"),
            ..Config::default()
        };

        let mut baseline = Baseline {
            format: BASELINE_FORMAT.to_string(),
            version: BASELINE_VERSION,
            created_at: 42,
            roots: vec!["/etc".to_string()],
            exclude: Vec::new(),
            entries: vec![record("/etc/a", Kind::File, 0o644, Some("aa"))],
        };
        write_json_atomic(&config.baseline_path, &baseline, 0o600).expect("write baseline");
        let meta = baseline_meta(&config);
        assert!(meta.exists);
        assert!(meta.valid);
        assert_eq!(meta.created_at, 42);
        assert_eq!(meta.entries, 1);

        baseline.version = BASELINE_VERSION + 1;
        write_json_atomic(&config.baseline_path, &baseline, 0o600).expect("rewrite baseline");
        let meta = baseline_meta(&config);
        assert!(meta.exists);
        assert!(!meta.valid);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn alert_history_survives_invalid_utf8() {
        let base = std::env::temp_dir().join(format!("my-ids-alerts-test-{}", std::process::id()));
        fs::create_dir_all(&base).expect("create temp directory");
        let config = Config {
            alerts_path: base.join("alerts.jsonl"),
            max_alerts: 10,
            ..Config::default()
        };

        let alert = |id: u64, path: &str| Alert {
            id,
            kind: ChangeKind::Added,
            path: path.to_string(),
            detected_at: 1,
            changes: Vec::new(),
            old_hash: None,
            new_hash: Some("aa".to_string()),
            size: Some(1),
            mode: "0644".to_string(),
            baseline_created_at: 1,
        };
        let first = serde_json::to_string(&alert(1, "/etc/a")).expect("encode");
        let second = serde_json::to_string(&alert(2, "/etc/b")).expect("encode");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(first.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']);
        bytes.extend_from_slice(second.as_bytes());
        bytes.push(b'\n');
        fs::write(&config.alerts_path, bytes).expect("write alerts");

        let alerts = load_recent_alerts(&config);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].id, 1);
        assert_eq!(alerts[1].id, 2);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn baseline_config_mismatch_is_detected() {
        let baseline = Baseline {
            format: BASELINE_FORMAT.to_string(),
            version: BASELINE_VERSION,
            created_at: 42,
            roots: vec!["/etc".to_string(), "/usr".to_string()],
            exclude: vec!["/etc/mtab".to_string()],
            entries: Vec::new(),
        };
        let cfg = Config {
            roots: vec![PathBuf::from("/usr"), PathBuf::from("/etc")],
            exclude: vec![PathBuf::from("/etc/mtab")],
            ..Config::default()
        };
        assert!(baseline_matches_config(&baseline, &cfg));

        let cfg = Config {
            roots: vec![PathBuf::from("/etc")],
            exclude: vec![PathBuf::from("/etc/mtab")],
            ..Config::default()
        };
        assert!(!baseline_matches_config(&baseline, &cfg));
    }

    #[test]
    fn config_rejects_colliding_state_paths() {
        let config = Config {
            baseline_path: PathBuf::from("/var/lib/my-ids/last_scan.json"),
            ..Config::default()
        };
        assert!(config.validate().is_err());

        let config = Config {
            alerts_path: PathBuf::from("/var/lib/my-ids/baseline.json"),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn human_bytes_rounds_to_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.50 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.00 MB");
    }
}
