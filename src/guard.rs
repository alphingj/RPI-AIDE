//! The port-scan guard: per-source SYN tracking in a sliding window, ban
//! bookkeeping persisted to disk, and blocking through nftables or iptables.
//! Capture lives in `capture`; this module owns detection and enforcement.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::capture::{self, PacketSocket, SynPacket, PACKET_HOST};
use crate::config::{Config, GuardMode};
use crate::util::{ipv4_to_string, now, now_ms, parse_ipv4, warn, write_json_atomic, Cidr};

const NFT_TABLE: &str = "rpi_aide";
const IPTABLES_COMMENT: &str = "rpi-aide-guard";
const MAX_EVENTS: usize = 100;
const MAX_PORTS_PER_EVENT: usize = 24;
const SWEEP_MS: u128 = 30_000;
const ASSERT_MS: u128 = 300_000;
const ASSERT_BAN_LIMIT: usize = 32;

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Sliding window of `(time_ms, port)` hits from one source.
#[derive(Debug, Default)]
pub struct SourceWindow {
    hits: VecDeque<(u128, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub ports: Vec<u16>,
    pub distinct_critical: usize,
    pub distinct_total: usize,
    pub syns_critical: usize,
}

/// The detection thresholds, broken out of the settings so `observe` stays
/// testable without a full engine.
#[derive(Clone, Copy, Debug)]
pub struct Thresholds {
    pub window_ms: u64,
    pub critical_port_threshold: usize,
    pub total_port_threshold: usize,
    pub syn_threshold: usize,
}

/// One observation of a SYN against a critical or non-critical port. Returns
/// a detection when any threshold is crossed, and resets the window so a
/// scan produces one event, not one per packet.
pub fn observe(
    hits: &mut SourceWindow,
    port: u16,
    at_ms: u128,
    critical_ports: &HashSet<u16>,
    thresholds: &Thresholds,
) -> Option<Detection> {
    let cutoff = at_ms.saturating_sub(thresholds.window_ms as u128);
    while let Some(&(stamp, _)) = hits.hits.front() {
        if stamp < cutoff {
            hits.hits.pop_front();
        } else {
            break;
        }
    }
    hits.hits.push_back((at_ms, port));

    let mut distinct: HashSet<u16> = HashSet::new();
    let mut distinct_critical = 0usize;
    let mut syns_critical = 0usize;
    for &(_, port) in &hits.hits {
        if distinct.insert(port) && critical_ports.contains(&port) {
            distinct_critical += 1;
        }
        if critical_ports.contains(&port) {
            syns_critical += 1;
        }
    }
    let distinct_total = distinct.len();

    let triggered = distinct_critical >= thresholds.critical_port_threshold
        || (distinct_total >= thresholds.total_port_threshold && distinct_critical >= 1)
        || syns_critical >= thresholds.syn_threshold;

    if !triggered {
        return None;
    }

    let mut ports: Vec<u16> = distinct.into_iter().collect();
    ports.sort_unstable();
    ports.truncate(MAX_PORTS_PER_EVENT);

    hits.hits.clear();

    Some(Detection {
        ports,
        distinct_critical,
        distinct_total,
        syns_critical,
    })
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ban {
    pub ip: String,
    pub ports: Vec<u16>,
    pub reason: String,
    pub banned_at: u64,
    pub expires_at: u64,
    pub repeat: u32,
}

impl Ban {
    fn key(&self) -> Option<u32> {
        parse_ipv4(&self.ip)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardEvent {
    pub at: u64,
    pub ip: String,
    pub ports: Vec<u16>,
    pub distinct_critical: usize,
    pub distinct_total: usize,
    pub syns_critical: usize,
    pub blocked: bool,
    pub repeat: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GuardStateFile {
    #[serde(default)]
    bans: Vec<Ban>,
    #[serde(default)]
    events: Vec<GuardEvent>,
    #[serde(default)]
    history: HashMap<String, u32>,
}

#[derive(Clone, Debug)]
pub struct GuardSettings {
    pub interface: String,
    pub critical_ports: Vec<u16>,
    pub window_ms: u64,
    pub critical_port_threshold: usize,
    pub total_port_threshold: usize,
    pub syn_threshold: usize,
    pub ban_secs: u64,
    pub repeat_ban_secs: u64,
    pub max_bans: usize,
    pub allowlist: Vec<Cidr>,
    pub own_ips: Vec<u32>,
}

impl GuardSettings {
    pub fn from_config(cfg: &Config) -> (Self, Option<String>) {
        let interface = cfg.guard.effective_interface();
        let mut problem = None;
        if !interface.is_empty() && !capture::interface_exists(&interface) {
            problem = Some(format!("interface '{interface}' does not exist"));
        }
        let allowlist = cfg.guard.parse_allowlist().unwrap_or_default();
        let own_ips = capture::own_ipv4s();
        (
            Self {
                interface,
                critical_ports: cfg.guard.effective_critical_ports(&cfg.bind),
                window_ms: cfg.guard.window_secs * 1000,
                critical_port_threshold: cfg.guard.critical_port_threshold,
                total_port_threshold: cfg.guard.total_port_threshold,
                syn_threshold: cfg.guard.syn_threshold,
                ban_secs: cfg.guard.ban_secs,
                repeat_ban_secs: cfg.guard.repeat_ban_secs,
                max_bans: cfg.guard.max_bans,
                allowlist,
                own_ips,
            },
            problem,
        )
    }
}

struct GuardInner {
    mode: GuardMode,
    windows: HashMap<u32, SourceWindow>,
    bans: Vec<Ban>,
    events: VecDeque<GuardEvent>,
    history: HashMap<String, u32>,
    capture_running: bool,
    last_error: Option<String>,
}

pub struct GuardEngine {
    settings: GuardSettings,
    backend: Option<Backend>,
    state_path: PathBuf,
    notify: crate::notify::NotifySender,
    inner: Mutex<GuardInner>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

// ---------------------------------------------------------------------------
// Enforcement backends
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Nft,
    Iptables,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Self::Nft => "nftables",
            Self::Iptables => "iptables",
        }
    }
}

/// Runs a command to completion with a hard cap so a stuck firewall tool
/// cannot wedge the capture thread.
fn run_command(
    program: &str,
    args: &[&str],
    stdin: Option<&str>,
) -> Result<(bool, String), String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot run {program}: {error}"))?;

    if let Some(input) = stdin {
        if let Some(mut handle) = child.stdin.take() {
            if let Err(error) = handle.write_all(input.as_bytes()) {
                let _ = child.kill();
                return Err(format!("cannot feed {program}: {error}"));
            }
            // Dropping the handle closes the pipe so filters like
            // `nft -f -` see EOF and start working.
        }
    } else {
        drop(child.stdin.take());
    }

    let deadline = Duration::from_secs(5);
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut output = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut output);
                }
                if let Some(mut stdout) = child.stdout.take() {
                    let mut text = String::new();
                    if std::io::Read::read_to_string(&mut stdout, &mut text).is_ok() {
                        output.push('\n');
                        output.push_str(&text);
                    }
                }
                return Ok((status.success(), output));
            }
            Ok(None) => {
                if started.elapsed() > deadline {
                    let _ = child.kill();
                    return Err(format!("{program} did not finish within 5 s"));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(format!("cannot wait for {program}: {error}")),
        }
    }
}

pub fn detect_backend() -> Option<Backend> {
    if let Ok((ok, _)) = run_command("nft", &["list", "ruleset"], None) {
        if ok {
            return Some(Backend::Nft);
        }
    }
    if let Ok((ok, _)) = run_command("iptables", &["-L", "INPUT"], None) {
        if ok {
            return Some(Backend::Iptables);
        }
    }
    None
}

/// nftables script text that creates everything the guard needs.
pub fn nft_setup_script() -> String {
    format!(
        "add table inet {NFT_TABLE}\n\
         add set inet {NFT_TABLE} blocked_v4 {{ type ipv4_addr; flags timeout; }}\n\
         add chain inet {NFT_TABLE} input {{ type filter hook input priority -10; policy accept; }}\n\
         add rule inet {NFT_TABLE} input ip saddr @blocked_v4 counter drop\n"
    )
}

pub fn nft_ban_script(ip: &str, seconds: u64) -> String {
    format!("add element inet {NFT_TABLE} blocked_v4 {{ {ip} timeout {seconds}s }}\n")
}

pub fn nft_unban_script(ip: &str) -> String {
    format!("delete element inet {NFT_TABLE} blocked_v4 {{ {ip} }}\n")
}

pub fn iptables_ban_args(ip: &str) -> Vec<String> {
    vec![
        "-I".into(),
        "INPUT".into(),
        "1".into(),
        "-s".into(),
        format!("{ip}/32"),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        IPTABLES_COMMENT.into(),
        "-j".into(),
        "DROP".into(),
    ]
}

pub fn iptables_unban_args(ip: &str) -> Vec<String> {
    vec![
        "-D".into(),
        "INPUT".into(),
        "-s".into(),
        format!("{ip}/32"),
        "-m".into(),
        "comment".into(),
        "--comment".into(),
        IPTABLES_COMMENT.into(),
        "-j".into(),
        "DROP".into(),
    ]
}

/// IPs currently blocked with our comment tag, for the iptables fallback.
pub fn iptables_listed_bans(output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in output.lines() {
        if !line.contains(IPTABLES_COMMENT) {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        for (index, field) in fields.iter().enumerate() {
            if *field == "-s" || *field == "--source" {
                if let Some(address) = fields
                    .get(index + 1)
                    .and_then(|value| value.strip_suffix("/32").or(Some(*value)))
                {
                    if !out.iter().any(|existing| existing == address) {
                        out.push(address.to_string());
                    }
                }
            }
        }
    }
    out
}

#[derive(Clone, Copy)]
struct Enforcer {
    backend: Backend,
}

impl Enforcer {
    fn ensure(&self) -> Result<(), String> {
        match self.backend {
            Backend::Nft => {
                let (table_ok, _) =
                    run_command("nft", &["list", &format!("table inet {NFT_TABLE}")], None)
                        .unwrap_or((false, String::new()));
                if table_ok {
                    let (chain_ok, chain) = run_command(
                        "nft",
                        &["list", &format!("chain inet {NFT_TABLE} input")],
                        None,
                    )
                    .unwrap_or((false, String::new()));
                    if !chain_ok {
                        let (ok, out) =
                            run_command("nft", &["-f", "-"], Some(&nft_setup_script()))?;
                        if !ok {
                            return Err(format!("nftables setup failed: {out}"));
                        }
                        return Ok(());
                    }
                    if !chain.contains("blocked_v4") {
                        let rule = format!(
                            "add rule inet {NFT_TABLE} input ip saddr @blocked_v4 counter drop\n"
                        );
                        let (ok, out) = run_command("nft", &["-f", "-"], Some(&rule))?;
                        if !ok {
                            return Err(format!("nftables rule failed: {out}"));
                        }
                    }
                    Ok(())
                } else {
                    let (ok, out) = run_command("nft", &["-f", "-"], Some(&nft_setup_script()))?;
                    if !ok {
                        return Err(format!("nftables setup failed: {out}"));
                    }
                    Ok(())
                }
            }
            Backend::Iptables => Ok(()),
        }
    }

    fn ban(&self, ip: &str, seconds: u64) -> Result<(), String> {
        match self.backend {
            Backend::Nft => {
                // `nft -f -` is transactional: one failing line aborts the
                // rest, so a refresh delete runs as its own invocation.
                let add = nft_ban_script(ip, seconds);
                if run_command("nft", &["-f", "-"], Some(&add))
                    .map(|(ok, _)| ok)
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                let _ = run_command("nft", &["-f", "-"], Some(&nft_unban_script(ip)));
                let (ok, out) = run_command("nft", &["-f", "-"], Some(&add))?;
                if ok {
                    Ok(())
                } else {
                    Err(format!("nftables ban failed: {out}"))
                }
            }
            Backend::Iptables => {
                let owned = iptables_ban_args(ip);
                let args: Vec<&str> = owned.iter().map(String::as_str).collect();
                let (ok, out) = run_command("iptables", &args, None)?;
                if ok {
                    Ok(())
                } else {
                    Err(format!("iptables ban failed: {out}"))
                }
            }
        }
    }

    fn unban(&self, ip: &str) -> Result<(), String> {
        match self.backend {
            Backend::Nft => {
                let _ = run_command("nft", &["-f", "-"], Some(&nft_unban_script(ip)));
                Ok(())
            }
            Backend::Iptables => {
                let owned = iptables_unban_args(ip);
                let args: Vec<&str> = owned.iter().map(String::as_str).collect();
                let _ = run_command("iptables", &args, None);
                Ok(())
            }
        }
    }

    fn cleanup(&self) {
        match self.backend {
            Backend::Nft => {
                let _ = run_command("nft", &["delete", &format!("table inet {NFT_TABLE}")], None);
            }
            Backend::Iptables => {
                if let Ok((_, out)) = run_command("iptables", &["-S", "INPUT"], None) {
                    for ip in iptables_listed_bans(&out) {
                        let owned = iptables_unban_args(&ip);
                        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
                        let _ = run_command("iptables", &args, None);
                    }
                }
            }
        }
    }

    fn assert(&self, bans: &[Ban]) {
        if bans.len() > ASSERT_BAN_LIMIT {
            return; // avoid a subprocess storm; the sweeper will retry later
        }
        match self.backend {
            Backend::Nft => {
                for ban in bans {
                    let duration = ban.expires_at.saturating_sub(now()).max(60);
                    if self.ban(&ban.ip, duration).is_err() {
                        warn(&format!("guard could not re-assert the ban on {}", ban.ip));
                    }
                }
            }
            Backend::Iptables => {
                let listed = run_command("iptables", &["-S", "INPUT"], None)
                    .ok()
                    .map(|(_, out)| iptables_listed_bans(&out))
                    .unwrap_or_default();
                for ban in bans {
                    if !listed.iter().any(|ip| ip == &ban.ip) {
                        let _ = self.ban(&ban.ip, ban.expires_at.saturating_sub(now()).max(60));
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

impl GuardEngine {
    pub fn start(cfg: &Config, notify_tx: crate::notify::NotifySender) -> Arc<Self> {
        let (settings, problem) = GuardSettings::from_config(cfg);
        if let Some(message) = &problem {
            warn(&format!("guard: {message}"));
        }
        let backend = detect_backend();
        if backend.is_none() {
            warn("guard: no usable firewall found (nftables or iptables); enforce mode is unavailable");
        }

        let state_path = cfg.guard.state_path.clone();
        let state = load_state(&state_path);
        let current = now();
        let bans: Vec<Ban> = state
            .bans
            .into_iter()
            .filter(|ban| ban.expires_at > current)
            .collect();
        let inner = GuardInner {
            mode: cfg.guard.mode,
            windows: HashMap::new(),
            bans,
            events: state.events.into(),
            history: state.history,
            capture_running: false,
            last_error: problem,
        };

        let engine = Arc::new(Self {
            settings,
            backend,
            state_path,
            notify: notify_tx,
            inner: Mutex::new(inner),
            stop: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
        });

        if cfg.guard.mode == GuardMode::Off {
            if let Some(backend) = engine.backend {
                Enforcer { backend }.cleanup();
            }
            return engine;
        }

        if cfg.guard.mode == GuardMode::Enforce {
            if let Err(message) = engine.enforce_sync() {
                warn(&format!("guard: {message}"));
            }
        }
        engine.spawn_capture();
        engine
    }

    fn spawn_capture(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        let interface = engine.settings.interface.clone();
        let mut guard = engine.inner.lock().expect("guard lock");
        if interface.is_empty() {
            guard.last_error = Some("no interface to watch".to_string());
            warn("guard: no interface to watch; detection is disabled");
            return;
        }
        match PacketSocket::open(&interface) {
            Ok(socket) => {
                guard.capture_running = true;
                drop(guard);
                let thread_engine = Arc::clone(&engine);
                let worker = std::thread::Builder::new()
                    .name("rpi-aide-guard".into())
                    .spawn(move || {
                        capture_loop(thread_engine, socket);
                    })
                    .expect("spawn guard thread");
                *engine.thread.lock().expect("guard thread lock") = Some(worker);
            }
            Err(message) => {
                guard.capture_running = false;
                guard.last_error = Some(message.clone());
                warn(&format!("guard: {message}"));
            }
        }
    }

    /// Applies the current bans to the kernel and makes sure the firewall
    /// structures exist. Runs on the calling thread; callers on the async
    /// side must use `spawn_blocking`.
    pub fn enforce_sync(&self) -> Result<(), String> {
        let backend = self
            .backend
            .ok_or_else(|| "no firewall backend is available".to_string())?;
        let enforcer = Enforcer { backend };
        enforcer.ensure()?;
        let bans = {
            let guard = self.inner.lock().expect("guard lock");
            guard.bans.clone()
        };
        for ban in bans {
            let duration = ban.expires_at.saturating_sub(now()).max(60);
            if let Err(message) = enforcer.ban(&ban.ip, duration) {
                warn(&format!(
                    "guard could not restore the ban on {}: {message}",
                    ban.ip
                ));
            }
        }
        Ok(())
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn mode(&self) -> GuardMode {
        self.inner.lock().expect("guard lock").mode
    }

    pub fn backend(&self) -> Option<Backend> {
        self.backend
    }

    pub fn settings(&self) -> &GuardSettings {
        &self.settings
    }

    pub fn capture_running(&self) -> bool {
        self.inner.lock().expect("guard lock").capture_running
    }

    pub fn last_error(&self) -> Option<String> {
        self.inner.lock().expect("guard lock").last_error.clone()
    }

    /// Switches the runtime mode. Leaving enforce clears kernel blocks;
    /// entering enforce installs them again from the ban list (which leaving
    /// enforce cleared, so a fresh start is intentional).
    pub fn set_mode(self: &Arc<Self>, mode: GuardMode) -> Result<(), String> {
        let previous = self.mode();
        if previous == mode {
            return Ok(());
        }
        if let Some(backend) = self.backend {
            let enforcer = Enforcer { backend };
            if previous == GuardMode::Enforce && mode != GuardMode::Enforce {
                let bans = {
                    let mut guard = self.inner.lock().expect("guard lock");
                    std::mem::take(&mut guard.bans)
                };
                for ban in &bans {
                    let _ = enforcer.unban(&ban.ip);
                }
                if mode == GuardMode::Off {
                    enforcer.cleanup();
                }
                let mut guard = self.inner.lock().expect("guard lock");
                guard.windows.clear();
                write_state_locked(&self.state_path, &guard);
            }
        }
        {
            let mut guard = self.inner.lock().expect("guard lock");
            guard.mode = mode;
            guard.last_error = None;
            write_state_locked(&self.state_path, &guard);
        }
        if mode == GuardMode::Enforce {
            self.enforce_sync()?;
        }
        if mode != GuardMode::Off && !self.capture_running() {
            self.spawn_capture();
        }
        Ok(())
    }

    pub fn unban(&self, ip: &str) -> Result<(), String> {
        let parsed = parse_ipv4(ip).ok_or_else(|| format!("'{ip}' is not an IPv4 address"))?;
        let mut guard = self.inner.lock().expect("guard lock");
        let position = guard.bans.iter().position(|ban| ban.key() == Some(parsed));
        let ban = position
            .map(|index| guard.bans.remove(index))
            .ok_or_else(|| format!("'{ip}' is not banned"))?;
        if let Some(backend) = self.backend {
            let _ = Enforcer { backend }.unban(&ban.ip);
        }
        write_state_locked(&self.state_path, &guard);
        Ok(())
    }

    pub fn unban_all(&self) -> Result<usize, String> {
        let mut guard = self.inner.lock().expect("guard lock");
        let bans = std::mem::take(&mut guard.bans);
        if let Some(backend) = self.backend {
            let enforcer = Enforcer { backend };
            for ban in &bans {
                let _ = enforcer.unban(&ban.ip);
            }
        }
        write_state_locked(&self.state_path, &guard);
        Ok(bans.len())
    }

    pub fn bans_snapshot(&self) -> Vec<Ban> {
        self.inner.lock().expect("guard lock").bans.clone()
    }

    pub fn events_snapshot(&self) -> Vec<GuardEvent> {
        self.inner
            .lock()
            .expect("guard lock")
            .events
            .iter()
            .rev()
            .take(20)
            .cloned()
            .collect()
    }

    pub fn sweep_once(&self) {
        let expired = {
            let mut guard = self.inner.lock().expect("guard lock");
            let current = now();
            let expired: Vec<Ban> = guard
                .bans
                .iter()
                .filter(|ban| ban.expires_at <= current)
                .cloned()
                .collect();
            guard.bans.retain(|ban| ban.expires_at > current);
            if !expired.is_empty() {
                write_state_locked(&self.state_path, &guard);
            }
            expired
        };
        if let Some(backend) = self.backend {
            let enforcer = Enforcer { backend };
            for ban in expired {
                let _ = enforcer.unban(&ban.ip);
            }
        }
    }
}

fn capture_loop(engine: Arc<GuardEngine>, socket: PacketSocket) {
    crate::util::lower_thread_priority();
    let mut buffer = vec![0u8; 2048];
    let mut next_sweep = now_ms() + SWEEP_MS;
    let mut next_assert = now_ms() + ASSERT_MS;

    loop {
        if engine.stop.load(Ordering::SeqCst) {
            break;
        }
        match socket.recv(&mut buffer) {
            Ok(Some((pkttype, read))) => {
                if pkttype != PACKET_HOST {
                    continue;
                }
                if let Some(packet) = capture::parse_inbound_tcp_syn(&buffer[..read]) {
                    process_packet(&engine, &packet);
                }
            }
            Ok(None) => {}
            Err(message) => {
                warn(&format!("guard: {message}"));
                std::thread::sleep(Duration::from_secs(1));
            }
        }

        let at = now_ms();
        if at >= next_sweep {
            next_sweep = at + SWEEP_MS;
            engine.sweep_once();
        }
        if at >= next_assert {
            next_assert = at + ASSERT_MS;
            if engine.mode() == GuardMode::Enforce {
                if let Some(backend) = engine.backend {
                    let bans = engine.bans_snapshot();
                    Enforcer { backend }.assert(&bans);
                }
            }
        }
    }
}

fn process_packet(engine: &Arc<GuardEngine>, packet: &SynPacket) {
    let settings = &engine.settings;
    if !settings.own_ips.contains(&packet.dst) && !settings.own_ips.is_empty() {
        return;
    }
    if settings
        .allowlist
        .iter()
        .any(|cidr| cidr.contains(packet.src))
    {
        return;
    }
    if settings.own_ips.contains(&packet.src) {
        return;
    }

    let critical_set: HashSet<u16> = settings.critical_ports.iter().copied().collect();

    let detection = {
        let mut guard = engine.inner.lock().expect("guard lock");
        if guard.mode == GuardMode::Off {
            return;
        }
        if guard.bans.iter().any(|ban| ban.key() == Some(packet.src)) {
            return;
        }
        let window = guard.windows.entry(packet.src).or_default();
        observe(
            window,
            packet.dst_port,
            now_ms(),
            &critical_set,
            &Thresholds {
                window_ms: settings.window_ms,
                critical_port_threshold: settings.critical_port_threshold,
                total_port_threshold: settings.total_port_threshold,
                syn_threshold: settings.syn_threshold,
            },
        )
    };

    let Some(detection) = detection else {
        return;
    };

    let (event, ban) = {
        let mut guard = engine.inner.lock().expect("guard lock");
        let ip = ipv4_to_string(packet.src);
        let repeat = guard
            .history
            .get(&ip)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        guard.history.insert(ip.clone(), repeat);

        let enforce = guard.mode == GuardMode::Enforce && engine.backend.is_some();
        let event = GuardEvent {
            at: now(),
            ip: ip.clone(),
            ports: detection.ports.clone(),
            distinct_critical: detection.distinct_critical,
            distinct_total: detection.distinct_total,
            syns_critical: detection.syns_critical,
            blocked: enforce,
            repeat,
        };
        guard.events.push_back(event.clone());
        while guard.events.len() > MAX_EVENTS {
            guard.events.pop_front();
        }

        let ban = if enforce {
            let duration = if repeat <= 1 {
                settings.ban_secs
            } else {
                settings.repeat_ban_secs
            };
            let ban = Ban {
                ip: ip.clone(),
                ports: detection.ports.clone(),
                reason: "port scan".to_string(),
                banned_at: now(),
                expires_at: now().saturating_add(duration),
                repeat,
            };
            guard.bans.push(ban.clone());
            while guard.bans.len() > settings.max_bans {
                guard.bans.remove(0);
            }
            Some(ban)
        } else {
            None
        };
        write_state_locked(&engine.state_path, &guard);
        (event, ban)
    };

    if let Some(ban) = ban {
        if let Some(backend) = engine.backend {
            let enforcer = Enforcer { backend };
            let duration = ban.expires_at.saturating_sub(now()).max(60);
            if let Err(message) = enforcer.ban(&ban.ip, duration) {
                warn(&format!("guard could not block {}: {message}", ban.ip));
            }
        }
    }

    engine.notify.send_guard(event);
}

fn load_state(path: &Path) -> GuardStateFile {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return GuardStateFile::default(),
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn write_state_locked(path: &Path, guard: &GuardInner) {
    let state = GuardStateFile {
        bans: guard.bans.clone(),
        events: guard.events.iter().cloned().collect(),
        history: guard.history.clone(),
    };
    if let Err(message) = write_json_atomic(path, &state, 0o600) {
        warn(&format!("guard could not persist its state: {message}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn critical() -> HashSet<u16> {
        [22, 53, 80, 443, 8080, 8111].into_iter().collect()
    }

    fn observe_port(hits: &mut SourceWindow, port: u16, at: u128) -> Option<Detection> {
        observe(
            hits,
            port,
            at,
            &critical(),
            &Thresholds {
                window_ms: 10_000,
                critical_port_threshold: 3,
                total_port_threshold: 10,
                syn_threshold: 50,
            },
        )
    }

    #[test]
    fn three_critical_ports_trigger() {
        let mut hits = SourceWindow::default();
        assert!(observe_port(&mut hits, 22, 1_000).is_none());
        assert!(observe_port(&mut hits, 53, 2_000).is_none());
        let detection = observe_port(&mut hits, 8111, 3_000).expect("third critical port triggers");
        assert_eq!(detection.distinct_critical, 3);
        assert!(detection.ports.contains(&22));
    }

    #[test]
    fn one_critical_port_alone_does_not_trigger() {
        let mut hits = SourceWindow::default();
        for at in 0..40 {
            assert!(
                observe_port(&mut hits, 22, at * 100).is_none(),
                "SYNs to a single port must never cross the distinct-port thresholds"
            );
        }
    }

    #[test]
    fn ten_total_ports_with_one_critical_trigger() {
        let mut hits = SourceWindow::default();
        for port in 1000..1009 {
            assert!(observe_port(&mut hits, port, port as u128 * 10).is_none());
        }
        let detection =
            observe_port(&mut hits, 443, 10_000).expect("tenth port includes a critical one");
        assert_eq!(detection.distinct_total, 10);
        assert_eq!(detection.distinct_critical, 1);
    }

    #[test]
    fn ten_non_critical_ports_do_not_trigger() {
        let mut hits = SourceWindow::default();
        for port in 2000..2009 {
            assert!(observe_port(&mut hits, port, port as u128 * 10).is_none());
        }
    }

    #[test]
    fn fifty_critical_syns_trigger() {
        let mut hits = SourceWindow::default();
        let mut detection = None;
        for index in 0..50 {
            detection = observe_port(&mut hits, 22, index);
            if detection.is_some() {
                break;
            }
        }
        let detection = detection.expect("syn flood on one critical port triggers");
        assert_eq!(detection.syns_critical, 50);
    }

    #[test]
    fn window_expires_and_resets_after_detection() {
        let mut hits = SourceWindow::default();
        assert!(observe_port(&mut hits, 22, 0).is_none());
        assert!(
            observe_port(&mut hits, 53, 500).is_none(),
            "two critical ports are not a scan"
        );
        assert!(
            observe_port(&mut hits, 80, 20_000).is_none(),
            "the old hits must expire with the window"
        );
        assert!(observe_port(&mut hits, 443, 20_500).is_none());
        let detection = observe_port(&mut hits, 8111, 21_000)
            .expect("three critical ports in the fresh window trigger");
        assert_eq!(detection.distinct_critical, 3);

        // A detection clears the window: the next hit starts over.
        assert!(observe_port(&mut hits, 443, 21_100).is_none());
    }

    #[test]
    fn nft_scripts_are_well_formed() {
        let setup = nft_setup_script();
        assert!(setup.contains("add table inet rpi_aide"));
        assert!(setup.contains("flags timeout"));
        assert!(setup.contains("ip saddr @blocked_v4 counter drop"));
        let ban = nft_ban_script("192.168.1.250", 3600);
        assert_eq!(
            ban,
            "add element inet rpi_aide blocked_v4 { 192.168.1.250 timeout 3600s }\n"
        );
        let unban = nft_unban_script("10.0.0.1");
        assert_eq!(
            unban,
            "delete element inet rpi_aide blocked_v4 { 10.0.0.1 }\n"
        );
    }

    #[test]
    fn iptables_args_and_listing() {
        let args = iptables_ban_args("192.168.1.250");
        assert_eq!(args[0], "-I");
        assert!(args.contains(&"-s".to_string()));
        assert!(args.contains(&"192.168.1.250/32".to_string()));
        assert!(args.contains(&"rpi-aide-guard".to_string()));

        let listed = iptables_listed_bans(
            "-A INPUT -s 192.168.1.250/32 -m comment --comment rpi-aide-guard -j DROP\n\
             -A INPUT -s 10.1.1.1/32 -m comment --comment other -j ACCEPT\n",
        );
        assert_eq!(listed, vec!["192.168.1.250".to_string()]);
    }
}
