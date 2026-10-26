//! Configuration: schema, defaults, validation, and the derived guard
//! runtime settings.

#[cfg(test)]
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util::Cidr;

pub const DEFAULT_CONFIG_ETC: &str = "/etc/rpi-aide/config.json";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    #[default]
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 3,
            Self::Warning => 2,
            Self::Info => 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeverityRule {
    pub prefix: String,
    pub severity: Severity,
}

impl SeverityRule {
    pub fn prefix(prefix: &str, severity: Severity) -> Self {
        Self {
            prefix: prefix.to_string(),
            severity,
        }
    }
}

/// First matching rule wins; unmatched paths are `Info`.
pub fn severity_for_path(path: &str, rules: &[SeverityRule]) -> Severity {
    for rule in rules {
        if path == rule.prefix
            || path
                .strip_prefix(&rule.prefix)
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return rule.severity;
        }
    }
    Severity::Info
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub webhook_url: Option<String>,
    pub ntfy_url: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub min_severity: Severity,
    pub on_guard_events: bool,
    pub digest_enabled: bool,
    pub digest_hour_utc: u32,
    pub timeout_secs: u64,
    pub retry_secs: u64,
    pub max_queue: usize,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            ntfy_url: None,
            telegram_bot_token: None,
            telegram_chat_id: None,
            min_severity: Severity::Info,
            on_guard_events: true,
            digest_enabled: false,
            digest_hour_utc: 8,
            timeout_secs: 5,
            retry_secs: 60,
            max_queue: 20,
        }
    }
}

impl NotifyConfig {
    pub fn channel_count(&self) -> usize {
        self.configured_channels().count()
    }

    pub fn configured(&self) -> bool {
        self.channel_count() > 0
    }

    pub fn configured_channels(&self) -> impl Iterator<Item = &'static str> {
        let mut channels: Vec<&'static str> = Vec::new();
        if self.webhook_url.is_some() {
            channels.push("webhook");
        }
        if self.ntfy_url.is_some() {
            channels.push("ntfy");
        }
        if self.telegram_bot_token.is_some() && self.telegram_chat_id.is_some() {
            channels.push("telegram");
        }
        channels.into_iter()
    }

    fn validate(&self) -> Result<(), String> {
        for url in [&self.webhook_url, &self.ntfy_url].into_iter().flatten() {
            if let Err(message) = validate_http_url(url) {
                return Err(format!("config: notify url '{url}' {message}"));
            }
        }
        if self.telegram_bot_token.is_some() != self.telegram_chat_id.is_some() {
            return Err(
                "config: notify telegram needs both `telegram_bot_token` and `telegram_chat_id`"
                    .to_string(),
            );
        }
        if self.timeout_secs == 0 {
            return Err("config: notify `timeout_secs` must be greater than zero".to_string());
        }
        if self.max_queue == 0 {
            return Err("config: notify `max_queue` must be greater than zero".to_string());
        }
        if self.digest_hour_utc > 23 {
            return Err("config: notify `digest_hour_utc` must be 0-23".to_string());
        }
        Ok(())
    }
}

fn validate_http_url(url: &str) -> Result<(), String> {
    if url.starts_with("https://") || url.starts_with("http://") {
        Ok(())
    } else {
        Err("must be an http:// or https:// URL".to_string())
    }
}

/// Empty `token_path` means "the file named `token` next to the config file".
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub enabled: bool,
    pub token_path: PathBuf,
    pub session_ttl_secs: u64,
    pub max_failed_per_ip: u32,
    pub lockout_secs: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            token_path: PathBuf::new(),
            session_ttl_secs: 7 * 86_400,
            max_failed_per_ip: 5,
            lockout_secs: 900,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardMode {
    Off,
    #[default]
    Monitor,
    Enforce,
}

impl GuardMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Monitor => "monitor",
            Self::Enforce => "enforce",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_lowercase().as_str() {
            "off" | "disabled" => Some(Self::Off),
            "monitor" => Some(Self::Monitor),
            "enforce" => Some(Self::Enforce),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardConfig {
    pub mode: GuardMode,
    pub interface: String,
    pub critical_ports: Vec<u16>,
    pub window_secs: u64,
    pub critical_port_threshold: usize,
    pub total_port_threshold: usize,
    pub syn_threshold: usize,
    pub ban_secs: u64,
    pub repeat_ban_secs: u64,
    pub max_bans: usize,
    pub allowlist: Vec<String>,
    pub state_path: PathBuf,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            mode: GuardMode::Monitor,
            interface: "auto".to_string(),
            critical_ports: vec![22, 53, 80, 443, 8080, 8111],
            window_secs: 10,
            critical_port_threshold: 3,
            total_port_threshold: 10,
            syn_threshold: 50,
            ban_secs: 3600,
            repeat_ban_secs: 86_400,
            max_bans: 256,
            allowlist: vec!["127.0.0.0/8".to_string(), "100.64.0.0/10".to_string()],
            state_path: PathBuf::from("/var/lib/rpi-aide/guard_state.json"),
        }
    }
}

impl GuardConfig {
    pub fn effective_interface(&self) -> String {
        if self.interface.trim().is_empty() || self.interface.trim() == "auto" {
            crate::capture::default_interface().unwrap_or_default()
        } else {
            self.interface.trim().to_string()
        }
    }

    /// The dashboard port is critical by definition: scanning for it is how
    /// someone finds the management interface.
    pub fn effective_critical_ports(&self, bind: &str) -> Vec<u16> {
        let mut ports: Vec<u16> = self.critical_ports.clone();
        if let Ok(address) = bind.parse::<SocketAddr>() {
            if address.port() != 0 && !ports.contains(&address.port()) {
                ports.push(address.port());
            }
        }
        ports.sort_unstable();
        ports
    }

    pub fn parse_allowlist(&self) -> Result<Vec<Cidr>, String> {
        let mut ranges = Vec::new();
        for entry in &self.allowlist {
            let cidr = Cidr::parse(entry)
                .ok_or_else(|| format!("config: guard allowlist entry '{entry}' is not valid"))?;
            ranges.push(cidr);
        }
        Ok(ranges)
    }

    fn validate(&self) -> Result<(), String> {
        if self.window_secs == 0 {
            return Err("config: guard `window_secs` must be greater than zero".to_string());
        }
        if self.critical_port_threshold == 0 || self.total_port_threshold == 0 {
            return Err("config: guard port thresholds must be greater than zero".to_string());
        }
        if self.ban_secs < 60 {
            return Err("config: guard `ban_secs` must be at least 60".to_string());
        }
        if self.repeat_ban_secs < self.ban_secs {
            return Err("config: guard `repeat_ban_secs` must be at least `ban_secs`".to_string());
        }
        if self.max_bans == 0 {
            return Err("config: guard `max_bans` must be greater than zero".to_string());
        }
        for port in &self.critical_ports {
            if *port == 0 {
                return Err("config: guard critical ports must not be zero".to_string());
            }
        }
        self.parse_allowlist()?;
        if !self.state_path.is_absolute() {
            return Err("config: guard `state_path` must be absolute".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchConfig {
    pub enabled: bool,
    pub paths: Vec<PathBuf>,
    pub debounce_ms: u64,
    pub min_gap_secs: u64,
    pub max_watches: usize,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: vec![PathBuf::from("/etc"), PathBuf::from("/boot")],
            debounce_ms: 2_000,
            min_gap_secs: 60,
            max_watches: 4_096,
        }
    }
}

impl WatchConfig {
    fn validate(&self) -> Result<(), String> {
        if self.debounce_ms == 0 {
            return Err("config: watch `debounce_ms` must be greater than zero".to_string());
        }
        if self.max_watches == 0 {
            return Err("config: watch `max_watches` must be greater than zero".to_string());
        }
        for path in &self.paths {
            if !path.is_absolute() {
                return Err(format!(
                    "config: watch path '{}' is not absolute",
                    path.display()
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub roots: Vec<PathBuf>,
    pub exclude: Vec<PathBuf>,
    pub baseline_path: PathBuf,
    pub alerts_path: PathBuf,
    pub bind: String,
    pub max_alerts: usize,
    pub max_file_bytes: u64,
    pub scan_interval_secs: u64,
    pub scan_on_start_delay_secs: u64,
    pub scan_jitter_secs: u64,
    pub full_scan_interval_secs: u64,
    pub severity_rules: Vec<SeverityRule>,
    pub notify: NotifyConfig,
    pub auth: AuthConfig,
    pub guard: GuardConfig,
    pub watch: WatchConfig,
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
                "/tmp",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            baseline_path: PathBuf::from("/var/lib/rpi-aide/baseline.json"),
            alerts_path: PathBuf::from("/var/lib/rpi-aide/alerts.jsonl"),
            bind: "127.0.0.1:8080".to_string(),
            max_alerts: 500,
            max_file_bytes: 256 * 1024 * 1024,
            scan_interval_secs: 3_600,
            scan_on_start_delay_secs: 600,
            scan_jitter_secs: 300,
            full_scan_interval_secs: 86_400,
            severity_rules: default_severity_rules(),
            notify: NotifyConfig::default(),
            auth: AuthConfig::default(),
            guard: GuardConfig::default(),
            watch: WatchConfig::default(),
        }
    }
}

fn default_severity_rules() -> Vec<SeverityRule> {
    let critical = [
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/ssh",
        "/etc/systemd/system",
        "/etc/cron.d",
        "/etc/crontab",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/pihole",
        "/etc/dhcp",
        "/etc/fstab",
        "/etc/passwd",
        "/etc/group",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/boot",
    ];
    let warning = ["/usr/bin", "/usr/sbin", "/usr/lib/systemd", "/etc"];
    let mut rules: Vec<SeverityRule> = critical
        .iter()
        .map(|prefix| SeverityRule::prefix(prefix, Severity::Critical))
        .collect();
    rules.extend(
        warning
            .iter()
            .map(|prefix| SeverityRule::prefix(prefix, Severity::Warning)),
    );
    rules
}

pub const HASH_CHUNK: usize = 4096;

impl Config {
    pub fn validate(&self) -> Result<(), String> {
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
        let last_scan = self.last_scan_path();
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
        if let Ok(address) = self.bind.parse::<SocketAddr>() {
            if address.port() == 0 {
                return Err("config: `bind` port must not be zero".to_string());
            }
        } else {
            return Err(format!(
                "config: `bind` is not a socket address: {}",
                self.bind
            ));
        }
        if self.scan_interval_secs != 0 && self.scan_interval_secs < 60 {
            return Err(
                "config: `scan_interval_secs` must be 0 (disabled) or at least 60".to_string(),
            );
        }
        if self.scan_interval_secs > 0 && self.scan_jitter_secs > self.scan_interval_secs {
            return Err(
                "config: `scan_jitter_secs` must not exceed `scan_interval_secs`".to_string(),
            );
        }
        if self.full_scan_interval_secs == 0 {
            return Err("config: `full_scan_interval_secs` must be greater than zero".to_string());
        }
        for rule in &self.severity_rules {
            if !rule.prefix.starts_with('/') {
                return Err(format!(
                    "config: severity rule '{}' is not an absolute path",
                    rule.prefix
                ));
            }
        }
        self.notify.validate()?;
        if !self.auth.token_path.as_os_str().is_empty() && !self.auth.token_path.is_absolute() {
            return Err("config: auth `token_path` must be absolute or empty".to_string());
        }
        if self.auth.session_ttl_secs == 0 {
            return Err("config: auth `session_ttl_secs` must be greater than zero".to_string());
        }
        self.guard.validate()?;
        self.watch.validate()?;
        Ok(())
    }

    pub fn last_scan_path(&self) -> PathBuf {
        let mut path = self.baseline_path.clone();
        path.set_file_name("last_scan.json");
        path
    }

    pub fn cache_path(&self) -> PathBuf {
        let mut path = self.baseline_path.clone();
        path.set_file_name("scan_cache.json");
        path
    }

    pub fn chain_head_path(&self) -> PathBuf {
        let mut path = self.alerts_path.clone();
        path.set_file_name("chain_head.json");
        path
    }

    pub fn accepted_path(&self) -> PathBuf {
        let mut path = self.baseline_path.clone();
        path.set_file_name("accepted.json");
        path
    }

    pub fn maintenance_path(&self) -> PathBuf {
        let mut path = self.baseline_path.clone();
        path.set_file_name("maintenance.json");
        path
    }

    pub fn notify_state_path(&self) -> PathBuf {
        let mut path = self.alerts_path.clone();
        path.set_file_name("notify_state.json");
        path
    }

    /// The token file sits next to the config unless an explicit path is set.
    pub fn token_path(&self, config_path: &Path) -> PathBuf {
        if !self.auth.token_path.as_os_str().is_empty() {
            return self.auth.token_path.clone();
        }
        match config_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.join("token"),
            _ => PathBuf::from("token"),
        }
    }
}

pub fn is_pseudo_path(path: &Path) -> bool {
    ["/proc", "/sys", "/dev", "/run"]
        .iter()
        .any(|candidate| path == Path::new(candidate))
}

pub fn effective_excludes(cfg: &Config) -> Vec<PathBuf> {
    let mut excludes = cfg.exclude.clone();
    for pseudo in ["/proc", "/sys", "/dev", "/run"] {
        excludes.push(PathBuf::from(pseudo));
    }
    for path in [
        &cfg.baseline_path,
        &cfg.alerts_path,
        &cfg.last_scan_path(),
        &cfg.cache_path(),
        &cfg.chain_head_path(),
        &cfg.accepted_path(),
        &cfg.maintenance_path(),
        &cfg.notify_state_path(),
        &cfg.guard.state_path,
    ] {
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

pub fn is_excluded(path: &Path, excludes: &[PathBuf]) -> bool {
    excludes
        .iter()
        .any(|exclude| path == exclude || path.starts_with(exclude))
}

pub fn path_is_within(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    if prefix == "/" {
        return path.starts_with('/');
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('/'))
}

pub fn same_path_set(left: &[String], right: &[String]) -> bool {
    let mut left: Vec<&str> = left.iter().map(String::as_str).collect();
    let mut right: Vec<&str> = right.iter().map(String::as_str).collect();
    left.sort_unstable();
    right.sort_unstable();
    left.dedup();
    right.dedup();
    left == right
}

#[derive(Clone, Debug)]
pub enum ConfigSource {
    File(PathBuf),
    Defaults(PathBuf),
}

impl ConfigSource {
    pub fn path(&self) -> &Path {
        match self {
            Self::File(path) | Self::Defaults(path) => path,
        }
    }

    pub fn loaded(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

/// Rewrites one JSON key inside the config file, preserving all other fields.
pub fn patch_config_file(
    path: &Path,
    mutator: impl FnOnce(&mut serde_json::Value),
) -> Result<(), String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read config '{}': {error}", path.display()))?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse config '{}': {error}", path.display()))?;
    let backup = {
        let mut name = path.as_os_str().to_os_string();
        name.push(".bak");
        PathBuf::from(name)
    };
    if let Err(error) = std::fs::copy(path, &backup) {
        return Err(format!(
            "cannot back up config '{}': {error}",
            path.display()
        ));
    }
    mutator(&mut value);
    crate::util::write_json_atomic(path, &value, 0o600)
}

pub fn load_config(cli: Option<&Path>) -> Result<(Config, ConfigSource), String> {
    let path = resolve_config_path(cli);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let cfg: Config = serde_json::from_slice(&bytes)
                .map_err(|error| format!("cannot parse config '{}': {error}", path.display()))?;
            cfg.validate()?;
            Ok((cfg, ConfigSource::File(path)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let cfg = Config::default();
            cfg.validate()?;
            Ok((cfg, ConfigSource::Defaults(path)))
        }
        Err(error) => Err(format!("cannot read config '{}': {error}", path.display())),
    }
}

pub fn resolve_config_path(cli: Option<&Path>) -> PathBuf {
    if let Some(path) = cli {
        return path.to_path_buf();
    }
    if let Ok(value) = std::env::var("RPI_AIDE_CONFIG") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    let etc = PathBuf::from(DEFAULT_CONFIG_ETC);
    if etc.exists() || crate::util::effective_uid() == Some(0) {
        return etc;
    }
    PathBuf::from("config.json")
}

/// Used by tests that need a config pointing at a temporary directory.
#[cfg(test)]
pub fn test_config(dir: &Path) -> Config {
    let state = dir.join("state");
    Config {
        roots: vec![dir.join("root")],
        exclude: Vec::new(),
        baseline_path: state.join("baseline.json"),
        alerts_path: state.join("alerts.jsonl"),
        bind: "127.0.0.1:0".to_string(),
        scan_interval_secs: 0,
        scan_on_start_delay_secs: 0,
        scan_jitter_secs: 0,
        guard: GuardConfig {
            state_path: state.join("guard_state.json"),
            ..GuardConfig::default()
        },
        ..Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rpi-aide-config-{}-{}",
            name.replace('/', "-"),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn severity_rules_pick_the_first_match() {
        let rules = default_severity_rules();
        assert_eq!(
            severity_for_path("/etc/ssh/sshd_config", &rules),
            Severity::Critical
        );
        assert_eq!(
            severity_for_path("/etc/pihole/setupVars.conf", &rules),
            Severity::Critical
        );
        assert_eq!(severity_for_path("/usr/bin/ls", &rules), Severity::Warning);
        assert_eq!(severity_for_path("/srv/data", &rules), Severity::Info);
        assert_eq!(
            severity_for_path("/etcssh/other", &rules),
            Severity::Info,
            "prefix matching must be component aware"
        );
    }

    #[test]
    fn default_config_validates() {
        Config::default().validate().expect("defaults are valid");
    }

    #[test]
    fn guard_critical_ports_include_the_dashboard_port() {
        let cfg = GuardConfig::default();
        let ports = cfg.effective_critical_ports("0.0.0.0:8111");
        assert!(ports.contains(&8111), "the dashboard port is critical");
        assert_eq!(
            ports.len(),
            6,
            "8111 is already in the default list and must not be duplicated"
        );
        let ports = cfg.effective_critical_ports("0.0.0.0:22");
        assert_eq!(ports.len(), 6, "22 must not be duplicated");
        let ports = cfg.effective_critical_ports("0.0.0.0:9000");
        assert_eq!(ports.len(), 7, "a new dashboard port is added");
        assert!(ports.contains(&9000));
    }

    #[test]
    fn token_path_defaults_next_to_the_config() {
        let cfg = Config::default();
        assert_eq!(
            cfg.token_path(Path::new("/etc/rpi-aide/config.json")),
            PathBuf::from("/etc/rpi-aide/token")
        );
        let mut cfg = Config::default();
        cfg.auth.token_path = PathBuf::from("/etc/rpi-aide/token");
        assert_eq!(
            cfg.token_path(Path::new("/x/config.json")),
            PathBuf::from("/etc/rpi-aide/token")
        );
    }

    #[test]
    fn config_rejects_bad_guard_and_notify_settings() {
        let mut cfg = Config::default();
        cfg.notify.webhook_url = Some("ftp://example.com".to_string());
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.guard.ban_secs = 10;
        assert!(cfg.validate().is_err());

        let cfg = Config {
            scan_interval_secs: 30,
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn patch_config_preserves_unknown_fields() {
        let dir = temp_dir("patch");
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"bind": "0.0.0.0:8111", "roots": ["/etc"], "future_field": {"keep": true}}"#,
        )
        .expect("write config");
        patch_config_file(&path, |value| {
            value["guard"]["mode"] = serde_json::json!("enforce");
        })
        .expect("patch config");
        let raw = std::fs::read_to_string(&path).expect("read config");
        assert!(raw.contains("future_field"));
        assert!(raw.contains("enforce"));
        let parsed: Config = serde_json::from_str(&raw).expect("config parses");
        assert_eq!(parsed.guard.mode, GuardMode::Enforce);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_paths_are_distinct_and_excluded() {
        let cfg = Config::default();
        let paths = [
            cfg.baseline_path.clone(),
            cfg.alerts_path.clone(),
            cfg.last_scan_path(),
            cfg.cache_path(),
            cfg.chain_head_path(),
            cfg.accepted_path(),
            cfg.maintenance_path(),
            cfg.notify_state_path(),
            cfg.guard.state_path.clone(),
        ];
        let mut seen = HashSet::new();
        for path in &paths {
            assert!(seen.insert(path), "state paths must be unique: {path:?}");
        }
        let excludes = effective_excludes(&cfg);
        for path in &paths {
            assert!(
                excludes.contains(path),
                "state file must be excluded from scans: {path:?}"
            );
        }
    }
}
