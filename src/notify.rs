//! Outbound alert delivery through `curl` (webhook, ntfy, Telegram) with a
//! bounded in-memory queue, retries, and rate caps. No secrets are logged.

use std::collections::VecDeque;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::json;

use crate::config::NotifyConfig;
use crate::guard::GuardEvent;
use crate::monitor::{Alert, ScanSummary};
use crate::util::{now, rfc3339, warn};

const MAX_DELIVER_PER_TICK: usize = 8;
const MAX_ATTEMPTS: u32 = 3;
const TICK_SECS: u64 = 2;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub enum NotifyMsg {
    Scan {
        summary: ScanSummary,
        top: Vec<Alert>,
    },
    Guard {
        event: GuardEvent,
    },
    Digest {
        text: String,
    },
    Test,
}

struct PendingItem {
    ready_at: u64,
    attempts: u32,
    msg: NotifyMsg,
}

#[derive(Default)]
struct QueueInner {
    pending: VecDeque<PendingItem>,
    delivered: u64,
    dropped: u64,
    last_error: Option<String>,
}

pub struct NotifyQueue {
    cfg: NotifyConfig,
    host: String,
    curl: bool,
    inner: Mutex<QueueInner>,
    warned_off: Mutex<bool>,
}

impl NotifyQueue {
    pub fn new(cfg: &NotifyConfig, host: &str) -> Arc<Self> {
        let curl = Command::new("curl")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !curl && cfg.configured() {
            warn("notify: 'curl' is not installed; delivery is disabled");
        }
        if !cfg.configured() {
            warn("notify: no channel is configured; pass a webhook or ntfy URL during setup");
        }
        Arc::new(Self {
            cfg: cfg.clone(),
            host: host.to_string(),
            curl,
            inner: Mutex::new(QueueInner::default()),
            warned_off: Mutex::new(false),
        })
    }

    pub fn configured(&self) -> bool {
        self.curl && self.cfg.configured()
    }

    pub fn channels(&self) -> Vec<&'static str> {
        self.cfg.configured_channels().collect()
    }

    pub fn enqueue(self: &Arc<Self>, msg: NotifyMsg) {
        if !self.configured() {
            let mut warned = self.warned_off.lock().expect("notify warn lock");
            if !*warned {
                *warned = true;
                warn("notify: a message was dropped because no channel is configured");
            }
            return;
        }
        let mut inner = self.inner.lock().expect("notify lock");
        if inner.pending.len() >= self.cfg.max_queue {
            inner.pending.pop_front();
            inner.dropped += 1;
        }
        inner.pending.push_back(PendingItem {
            ready_at: now(),
            attempts: 0,
            msg,
        });
    }

    pub fn status(&self) -> NotifyStatus {
        let inner = self.inner.lock().expect("notify lock");
        NotifyStatus {
            configured: self.cfg.configured(),
            curl: self.curl,
            channels: self.channels(),
            pending: inner.pending.len(),
            delivered: inner.delivered,
            dropped: inner.dropped,
            last_error: inner.last_error.clone(),
        }
    }

    /// One worker pass: deliver everything that is due.
    pub fn tick(&self) {
        let due: Vec<PendingItem> = {
            let mut inner = self.inner.lock().expect("notify lock");
            let current = now();
            let mut due = Vec::new();
            while let Some(front) = inner.pending.front() {
                if front.ready_at > current || due.len() >= MAX_DELIVER_PER_TICK {
                    break;
                }
                due.push(inner.pending.pop_front().expect("front exists"));
            }
            due
        };

        for item in due {
            let outcome = self.deliver(&item.msg);
            let mut inner = self.inner.lock().expect("notify lock");
            match outcome {
                Ok(()) => {
                    inner.delivered += 1;
                    inner.last_error = None;
                }
                Err(message) => {
                    let attempts = item.attempts + 1;
                    if attempts >= MAX_ATTEMPTS {
                        inner.dropped += 1;
                        inner.last_error = Some(message);
                    } else {
                        inner.last_error = Some(message.clone());
                        inner.pending.push_back(PendingItem {
                            ready_at: now().saturating_add(self.cfg.retry_secs),
                            attempts,
                            msg: item.msg,
                        });
                    }
                }
            }
        }
    }

    fn deliver(&self, msg: &NotifyMsg) -> Result<(), String> {
        let (plain, payload) = self.render(msg);
        let mut failures: Vec<String> = Vec::new();

        if let Some(url) = &self.cfg.webhook_url {
            match curl_post_json(url, &payload.to_string(), self.cfg.timeout_secs) {
                Ok(()) => return Ok(()),
                Err(message) => failures.push(format!("webhook: {message}")),
            }
        }
        if let Some(url) = &self.cfg.ntfy_url {
            match curl_post_ntfy(url, &plain, &self.title(msg), self.cfg.timeout_secs) {
                Ok(()) => return Ok(()),
                Err(message) => failures.push(format!("ntfy: {message}")),
            }
        }
        if self.cfg.telegram_bot_token.is_some() && self.cfg.telegram_chat_id.is_some() {
            let token = self.cfg.telegram_bot_token.clone().unwrap_or_default();
            let chat = self.cfg.telegram_chat_id.clone().unwrap_or_default();
            let url = format!("https://api.telegram.org/bot{token}/sendMessage");
            let body = json!({ "chat_id": chat, "text": plain }).to_string();
            match curl_post_json(&url, &body, self.cfg.timeout_secs) {
                Ok(()) => return Ok(()),
                Err(message) => failures.push(format!("telegram: {message}")),
            }
        }
        Err(failures.join("; "))
    }

    fn title(&self, msg: &NotifyMsg) -> String {
        match msg {
            NotifyMsg::Scan { summary, .. } => format!(
                "RPI-AIDE: {} change(s) on {}",
                summary.added + summary.modified + summary.deleted,
                self.host
            ),
            NotifyMsg::Guard { event } => {
                format!("RPI-AIDE: port scan from {} on {}", event.ip, self.host)
            }
            NotifyMsg::Digest { .. } => format!("RPI-AIDE daily digest for {}", self.host),
            NotifyMsg::Test => format!("RPI-AIDE test on {}", self.host),
        }
    }

    fn render(&self, msg: &NotifyMsg) -> (String, serde_json::Value) {
        match msg {
            NotifyMsg::Scan { summary, top } => {
                let changes = summary.added + summary.modified + summary.deleted;
                let mut lines = vec![format!(
                    "RPI-AIDE on {} — scan {} at {}",
                    self.host,
                    summary.trigger,
                    rfc3339(summary.finished_at)
                )];
                lines.push(format!(
                    "{} added, {} modified, {} deleted, {} errors ({} ms, {} scan)",
                    summary.added,
                    summary.modified,
                    summary.deleted,
                    summary.errors,
                    summary.duration_ms,
                    if summary.full { "full" } else { "fast" }
                ));
                for alert in top.iter().take(10) {
                    let label = match alert.kind {
                        crate::monitor::ChangeKind::Added => "ADDED",
                        crate::monitor::ChangeKind::Modified => "MODIFIED",
                        crate::monitor::ChangeKind::Deleted => "DELETED",
                    };
                    let mut detail = alert.changes.join("/");
                    if !detail.is_empty() {
                        detail = format!(" ({detail})");
                    }
                    lines.push(format!(
                        "{label} {}{detail} [{}]",
                        alert.path,
                        alert.severity.label()
                    ));
                }
                if changes > 10 {
                    lines.push(format!("... and {} more", changes - 10));
                }
                let plain = lines.join("\n");
                let payload = json!({
                    "source": "rpi-aide",
                    "version": VERSION,
                    "host": self.host,
                    "type": "scan",
                    "at": rfc3339(summary.finished_at),
                    "scan": {
                        "trigger": summary.trigger,
                        "added": summary.added,
                        "modified": summary.modified,
                        "deleted": summary.deleted,
                        "errors": summary.errors,
                        "duration_ms": summary.duration_ms,
                        "full": summary.full,
                    },
                    "alerts": top.iter().take(10).map(|alert| json!({
                        "path": alert.path,
                        "kind": alert.kind,
                        "severity": alert.severity.label(),
                        "changes": alert.changes,
                        "expected": alert.expected,
                    })).collect::<Vec<_>>(),
                });
                (plain, payload)
            }
            NotifyMsg::Guard { event } => {
                let plain = format!(
                    "RPI-AIDE on {} — port scan from {} at {}\nPorts: {}\nCritical ports: {}, total: {}, SYN bursts: {}\nBlocked: {} (repeat #{})",
                    self.host,
                    event.ip,
                    rfc3339(event.at),
                    event.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "),
                    event.distinct_critical,
                    event.distinct_total,
                    event.syns_critical,
                    if event.blocked { "yes" } else { "no (monitor mode)" },
                    event.repeat
                );
                let payload = json!({
                    "source": "rpi-aide",
                    "version": VERSION,
                    "host": self.host,
                    "type": "guard",
                    "event": event,
                });
                (plain, payload)
            }
            NotifyMsg::Digest { text } => {
                let plain = format!("RPI-AIDE daily digest for {}\n{text}", self.host);
                let payload = json!({
                    "source": "rpi-aide",
                    "version": VERSION,
                    "host": self.host,
                    "type": "digest",
                    "text": text,
                });
                (plain, payload)
            }
            NotifyMsg::Test => {
                let plain = format!(
                    "RPI-AIDE test notification from {} at {}\nDelivery works. Real alerts will look like the scans you see in the dashboard.",
                    self.host,
                    rfc3339(now())
                );
                let payload = json!({
                    "source": "rpi-aide",
                    "version": VERSION,
                    "host": self.host,
                    "type": "test",
                });
                (plain, payload)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NotifyStatus {
    pub configured: bool,
    pub curl: bool,
    pub channels: Vec<&'static str>,
    pub pending: usize,
    pub delivered: u64,
    pub dropped: u64,
    pub last_error: Option<String>,
}

/// A cloneable handle the guard thread and scan paths use to enqueue
/// messages without owning the queue.
#[derive(Clone)]
pub struct NotifySender {
    queue: Option<Arc<NotifyQueue>>,
}

impl NotifySender {
    pub fn live(queue: Arc<NotifyQueue>) -> Self {
        Self { queue: Some(queue) }
    }

    pub fn send_guard(&self, event: GuardEvent) {
        if let Some(queue) = &self.queue {
            queue.enqueue(NotifyMsg::Guard { event });
        }
    }

    pub fn send_scan(&self, summary: ScanSummary, top: Vec<Alert>) {
        if let Some(queue) = &self.queue {
            queue.enqueue(NotifyMsg::Scan { summary, top });
        }
    }

    pub fn send_digest(&self, text: String) {
        if let Some(queue) = &self.queue {
            queue.enqueue(NotifyMsg::Digest { text });
        }
    }

    pub fn send_test(&self) {
        if let Some(queue) = &self.queue {
            queue.enqueue(NotifyMsg::Test);
        }
    }
}

/// Spawns the delivery worker. It exits with the process; the queue is
/// advisory, so an in-flight shutdown may drop pending messages.
pub fn spawn_worker(queue: Arc<NotifyQueue>) {
    std::thread::Builder::new()
        .name("rpi-aide-notify".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(TICK_SECS));
            queue.tick();
        })
        .expect("spawn notify worker");
}

fn curl_post_json(url: &str, body: &str, timeout_secs: u64) -> Result<(), String> {
    let mut command = Command::new("curl");
    command
        .args([
            "-sS",
            "-f",
            "--max-time",
            &timeout_secs.to_string(),
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            "User-Agent: rpi-aide",
            "--data",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    run_curl(command, body)
}

fn curl_post_ntfy(url: &str, text: &str, title: &str, timeout_secs: u64) -> Result<(), String> {
    let mut command = Command::new("curl");
    command
        .args([
            "-sS",
            "-f",
            "--max-time",
            &timeout_secs.to_string(),
            "-H",
            &format!("Title: {title}"),
            "-H",
            "Tags: warning",
            "--data",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    run_curl(command, text)
}

fn run_curl(mut command: Command, body: &str) -> Result<(), String> {
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot run curl: {error}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(body.as_bytes())
            .map_err(|error| format!("cannot feed curl: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("curl failed: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        // Never include the URL: it may carry an access token.
        Err(if stderr.is_empty() {
            "delivery failed".to_string()
        } else {
            stderr
        })
    }
}

/// Used by tests and the doctor to point at a local sink.
#[allow(dead_code)]
pub fn telegram_send_url(token: &str) -> String {
    format!("https://api.telegram.org/bot{token}/sendMessage")
}
