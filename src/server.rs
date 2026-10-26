//! The dashboard server: HTTP routes, token authentication, the scheduled
//! scan loop, watch-triggered scans, the digest, and Prometheus metrics.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::json;

use crate::auth::{self, SessionStore, SESSION_COOKIE};
use crate::config::{patch_config_file, Config, ConfigSource, GuardMode, Severity};
use crate::guard::{Ban, GuardEngine, GuardEvent};
use crate::monitor::{
    self, accepted_map, alert_is_current, maintenance_active, perform_check, scan_should_be_full,
    Alert, BaselineMeta, FileStamp, ScanSummary,
};
use crate::notify::{NotifyQueue, NotifySender};
use crate::util::{info, now, random_below, warn};
use crate::watch::{WatchEvent, WatchStatus};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const DASHBOARD: &str = include_str!("dashboard.html");
const LOGIN_PAGE: &str = include_str!("login.html");

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const LOGIN_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

pub struct WebData {
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
    pub fn load(cfg: &Config) -> Self {
        let alerts = monitor::load_recent_alerts(cfg);
        let next_id = next_id_for_alerts(&alerts);
        let last_scan = monitor::load_last_scan(cfg);
        let baseline_stamp = monitor::file_stamp(&cfg.baseline_path);
        let alerts_stamp = monitor::file_stamp(&cfg.alerts_path);
        let baseline = monitor::baseline_meta(cfg);
        Self {
            alerts,
            next_id,
            last_scan,
            baseline,
            baseline_stamp,
            alerts_stamp,
        }
    }

    fn refresh_baseline(&mut self, cfg: &Config) {
        let stamp = monitor::file_stamp(&cfg.baseline_path);
        if stamp != self.baseline_stamp {
            self.baseline_stamp = stamp;
            self.baseline = monitor::baseline_meta(cfg);
            self.last_scan = monitor::load_last_scan(cfg);
            if !self.baseline.exists {
                self.last_scan = None;
            }
        }
    }

    fn refresh_alerts(&mut self, cfg: &Config) {
        let stamp = monitor::file_stamp(&cfg.alerts_path);
        if stamp == self.alerts_stamp {
            return;
        }
        self.alerts_stamp = stamp;
        self.alerts = monitor::load_recent_alerts(cfg);
        self.next_id = next_id_for_alerts(&self.alerts);
    }

    fn generation(&self) -> Option<u64> {
        if self.baseline.valid {
            Some(self.baseline.created_at)
        } else {
            None
        }
    }
}

pub struct AppState {
    pub cfg: Mutex<Config>,
    pub config_source: ConfigSource,
    pub started_at: u64,
    pub scanning: AtomicBool,
    pub inner: Mutex<WebData>,
    pub sessions: Mutex<SessionStore>,
    pub auth_enabled: bool,
    pub guard: Arc<GuardEngine>,
    pub notify: Arc<NotifyQueue>,
    pub notify_sender: NotifySender,
    pub next_scan_at: AtomicU64,
    pub watch_status: Arc<Mutex<WatchStatus>>,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Serve
// ---------------------------------------------------------------------------

pub async fn serve(cfg: Config, source: ConfigSource) -> Result<i32, String> {
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
            "baseline '{}' is missing; run 'rpi-aide --init' before scanning",
            cfg.baseline_path.display()
        ));
    }

    let auth_enabled = cfg.auth.enabled;
    let token_path = cfg.token_path(source.path());
    let sessions = if auth_enabled {
        auth::ensure_token_file(&token_path)
            .map_err(|message| format!("authentication is enabled: {message}"))?;
        let token = auth::read_token_file(&token_path)?;
        info(&format!(
            "login token at {}; view it with 'rpi-aide --print-token'",
            token_path.display()
        ));
        SessionStore::new(Some(token))
    } else {
        warn("authentication is disabled; the dashboard is open to anyone who can reach it");
        SessionStore::new(None)
    };

    let host = read_first_line("/proc/sys/kernel/hostname").unwrap_or_else(|| "unknown".into());

    let data = WebData::load(&cfg);
    let notify = NotifyQueue::new(&cfg.notify, &host);
    if notify.configured() {
        let channels = notify.channels().join(", ");
        info(&format!("notifications enabled via {channels}"));
        crate::notify::spawn_worker(Arc::clone(&notify));
    }
    let notify_sender = NotifySender::live(Arc::clone(&notify));

    let guard = GuardEngine::start(&cfg, notify_sender.clone());
    let (mode, interface, backend) = {
        (
            guard.mode(),
            guard.settings().interface.clone(),
            guard.backend().map(|b| b.label()),
        )
    };
    match mode {
        GuardMode::Off => info("guard: off"),
        GuardMode::Monitor | GuardMode::Enforce => info(&format!(
            "guard: {} on '{interface}' ({}), bans restored: {}",
            mode.label(),
            backend.unwrap_or("no firewall backend"),
            guard.bans_snapshot().len()
        )),
    }

    let (watch_tx, watch_rx) = tokio::sync::mpsc::unbounded_channel::<WatchEvent>();
    let watch_status = Arc::new(Mutex::new(WatchStatus::default()));
    let mut watch_stop = None;
    if cfg.watch.enabled {
        let stop = Arc::new(AtomicBool::new(false));
        watch_stop = Some(Arc::clone(&stop));
        crate::watch::start_watch(&cfg, watch_tx, stop, Arc::clone(&watch_status));
    }

    let state = Arc::new(AppState {
        cfg: Mutex::new(cfg),
        config_source: source,
        started_at: now(),
        scanning: AtomicBool::new(false),
        inner: Mutex::new(data),
        sessions: Mutex::new(sessions),
        auth_enabled,
        guard,
        notify: Arc::clone(&notify),
        notify_sender,
        next_scan_at: AtomicU64::new(0),
        watch_status,
    });

    let scheduler = tokio::spawn(scheduler_task(Arc::clone(&state)));
    let watcher = tokio::spawn(watch_task(Arc::clone(&state), watch_rx));
    let digester = tokio::spawn(digest_task(Arc::clone(&state)));

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/favicon.ico", get(favicon))
        .route("/healthz", get(healthz))
        .route("/api/status", get(api_status))
        .route("/api/alerts", get(api_alerts))
        .route(
            "/api/scan",
            post(api_scan).layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .route(
            "/api/accept",
            post(api_accept).layer(axum::extract::DefaultBodyLimit::max(2048)),
        )
        .route(
            "/api/maintenance",
            post(api_maintenance).layer(axum::extract::DefaultBodyLimit::max(2048)),
        )
        .route(
            "/api/guard/mode",
            post(api_guard_mode).layer(axum::extract::DefaultBodyLimit::max(512)),
        )
        .route(
            "/api/guard/unban",
            post(api_guard_unban).layer(axum::extract::DefaultBodyLimit::max(256)),
        )
        .route(
            "/api/guard/unban-all",
            post(api_guard_unban_all).layer(axum::extract::DefaultBodyLimit::max(256)),
        )
        .route(
            "/api/notify/test",
            post(api_notify_test).layer(axum::extract::DefaultBodyLimit::max(256)),
        )
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth_middleware,
        ))
        .layer(middleware::from_fn(security_headers))
        .with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("cannot bind {address}: {error}"))?;

    info(&format!("dashboard listening on http://{address}"));

    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;

    state.guard.stop();
    if let Some(stop) = &watch_stop {
        stop.store(true, Ordering::SeqCst);
    }
    scheduler.abort();
    watcher.abort();
    digester.abort();

    result.map_err(|error| format!("server failed: {error}"))?;
    info("shutdown complete");
    Ok(0)
}

// ---------------------------------------------------------------------------
// Scan execution
// ---------------------------------------------------------------------------

fn start_scan(state: &Arc<AppState>, full: bool, trigger: &str) -> Result<(), String> {
    let cfg = state.cfg.lock().expect("config lock").clone();
    if !cfg.baseline_path.exists() {
        return Err("baseline is missing; run rpi-aide --init on the host".to_string());
    }
    if state
        .scanning
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("a scan is already running".to_string());
    }
    let worker = Arc::clone(state);
    let trigger = trigger.to_string();
    tokio::task::spawn_blocking(move || {
        let result = run_scan_sync(&worker, full, &trigger);
        worker.scanning.store(false, Ordering::SeqCst);
        match &result {
            Ok(summary) => info(&format!(
                "{} scan finished: {} added, {} modified, {} deleted, {} errors in {} ms",
                trigger,
                summary.added,
                summary.modified,
                summary.deleted,
                summary.errors,
                summary.duration_ms
            )),
            Err(message) => warn(&format!("{trigger} scan failed: {message}")),
        }
    });
    Ok(())
}

fn run_scan_sync(state: &Arc<AppState>, full: bool, trigger: &str) -> Result<ScanSummary, String> {
    crate::util::lower_thread_priority();
    let cfg = state.cfg.lock().expect("config lock").clone();
    let start_id = {
        let data = state.inner.lock().expect("state lock");
        data.next_id
    };

    let outcome = perform_check(&cfg, start_id, full, trigger)?;

    let (notifyable, summary) = {
        let mut data = state.inner.lock().expect("state lock");
        for alert in &outcome.alerts {
            data.alerts.push_back(alert.clone());
            while data.alerts.len() > cfg.max_alerts {
                data.alerts.pop_front();
            }
        }
        data.next_id = start_id.saturating_add(outcome.alerts.len() as u64);
        data.last_scan = Some(outcome.summary.clone());
        data.alerts_stamp = monitor::file_stamp(&cfg.alerts_path);
        data.refresh_baseline(&cfg);
        (outcome.alerts.clone(), outcome.summary.clone())
    };

    // Notifications are suppressed during maintenance windows; the alerts
    // themselves are still recorded with the `expected` flag.
    if maintenance_active(&cfg).is_none() {
        let min_rank = cfg.notify.min_severity.rank();
        let has_content = notifyable
            .iter()
            .any(|alert| alert.severity.rank() >= min_rank);
        let has_errors = summary.errors > 0;
        if has_content || has_errors {
            let top: Vec<Alert> = notifyable
                .iter()
                .filter(|alert| alert.severity.rank() >= min_rank)
                .take(10)
                .cloned()
                .collect();
            state.notify_sender.send_scan(summary.clone(), top);
        }
    }

    Ok(summary)
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

async fn scheduler_task(state: Arc<AppState>) {
    let (interval, delay, jitter) = {
        let cfg = state.cfg.lock().expect("config lock");
        (
            cfg.scan_interval_secs,
            cfg.scan_on_start_delay_secs,
            cfg.scan_jitter_secs,
        )
    };
    if interval == 0 && delay == 0 {
        return;
    }
    let first_wait = delay.saturating_add(random_below(jitter + 1));
    let mut next_epoch = now().saturating_add(first_wait);
    state.next_scan_at.store(next_epoch, Ordering::SeqCst);
    loop {
        let wait = next_epoch.saturating_sub(now());
        tokio::time::sleep(Duration::from_secs(wait.max(1))).await;
        let full = {
            let cfg = state.cfg.lock().expect("config lock");
            scan_should_be_full(&cfg)
        };
        if let Err(message) = start_scan(&state, full, "scheduled") {
            warn(&format!("scheduled scan did not start: {message}"));
        }
        if interval == 0 {
            state.next_scan_at.store(0, Ordering::SeqCst);
            return; // boot scan only
        }
        next_epoch = now().saturating_add(interval + random_below(jitter + 1));
        state.next_scan_at.store(next_epoch, Ordering::SeqCst);
    }
}

async fn watch_task(
    state: Arc<AppState>,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<WatchEvent>,
) {
    let (debounce, gap) = {
        let cfg = state.cfg.lock().expect("config lock");
        (
            Duration::from_millis(cfg.watch.debounce_ms),
            Duration::from_secs(cfg.watch.min_gap_secs.max(1)),
        )
    };
    let mut deadline: Option<tokio::time::Instant> = None;
    let mut pending_gap: Option<tokio::time::Instant> = None;
    let mut last_trigger: Option<tokio::time::Instant> = None;

    loop {
        let deadline_fut = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending::<()>().await,
            }
        };
        let gap_fut = async {
            match pending_gap {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(WatchEvent::Overflow) => {
                        let cooled = last_trigger
                            .map(|last| last.elapsed() >= gap)
                            .unwrap_or(true);
                        if cooled {
                            let _ = start_scan(&state, true, "watch");
                            last_trigger = Some(tokio::time::Instant::now());
                            deadline = None;
                            pending_gap = None;
                        } else {
                            pending_gap = last_trigger.map(|last| last + gap);
                            deadline = None;
                        }
                    }
                    Some(WatchEvent::Changed) => {
                        deadline = Some(tokio::time::Instant::now() + debounce);
                    }
                    None => break,
                }
            }
            _ = deadline_fut => {
                deadline = None;
                let cooled = last_trigger
                    .map(|last| last.elapsed() >= gap)
                    .unwrap_or(true);
                if cooled {
                    let _ = start_scan(&state, false, "watch");
                    last_trigger = Some(tokio::time::Instant::now());
                    pending_gap = None;
                } else if pending_gap.is_none() {
                    pending_gap = last_trigger.map(|last| last + gap);
                }
            }
            _ = gap_fut => {
                pending_gap = None;
                let _ = start_scan(&state, false, "watch");
                last_trigger = Some(tokio::time::Instant::now());
            }
        }
    }
}

async fn digest_task(state: Arc<AppState>) {
    let (enabled, hour) = {
        let cfg = state.cfg.lock().expect("config lock");
        (cfg.notify.digest_enabled, cfg.notify.digest_hour_utc)
    };
    if !enabled || !state.notify.configured() {
        return;
    }
    loop {
        let current = now();
        let day_start = current - current % 86_400;
        let mut target = day_start + hour as u64 * 3_600;
        if target <= current {
            target += 86_400;
        }
        tokio::time::sleep(Duration::from_secs(target.saturating_sub(current).max(1))).await;
        let text = build_digest(&state);
        state.notify_sender.send_digest(text);
    }
}

fn build_digest(state: &Arc<AppState>) -> String {
    let cfg = state.cfg.lock().expect("config lock").clone();
    let cutoff = now().saturating_sub(86_400);
    let alerts = monitor::load_recent_alerts(&cfg);
    let recent: Vec<&Alert> = alerts
        .iter()
        .filter(|alert| alert.detected_at >= cutoff)
        .collect();
    let mut critical = 0;
    let mut warning = 0;
    let mut info = 0;
    let mut expected = 0;
    for alert in &recent {
        match alert.severity {
            Severity::Critical => critical += 1,
            Severity::Warning => warning += 1,
            Severity::Info => info += 1,
        }
        if alert.expected {
            expected += 1;
        }
    }
    let scans = state
        .guard
        .events_snapshot()
        .iter()
        .filter(|event| event.at >= cutoff)
        .count();
    let bans = state.guard.bans_snapshot().len();
    let last = monitor::load_last_scan(&cfg).map(|summary| {
        format!(
            "{} at {}, {} ms",
            if summary.ok { "clean" } else { "changes found" },
            crate::util::rfc3339(summary.finished_at),
            summary.duration_ms
        )
    });
    format!(
        "Past 24 hours: {} alert(s): {critical} critical, {warning} warning, {info} info ({expected} expected). {scans} port scan(s) detected, {bans} active ban(s). Last scan: {}.",
        recent.len(),
        last.as_deref().unwrap_or("no scan recorded")
    )
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let public = matches!(path.as_str(), "/healthz" | "/login" | "/favicon.ico");
    if !state.auth_enabled || public {
        return next.run(request).await;
    }

    let is_api = path.starts_with("/api/") || path == "/metrics";

    // Guards are dropped before any await so the middleware future stays Send.
    let bearer_ok = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().strip_prefix("Bearer "))
        .map(|candidate| {
            let sessions = state.sessions.lock().expect("session lock");
            sessions.verify_token(candidate)
        })
        .unwrap_or(false);
    if bearer_ok {
        return next.run(request).await;
    }

    let cookie_ok = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| auth::parse_cookie(cookies, SESSION_COOKIE))
        .map(|id| {
            let mut sessions = state.sessions.lock().expect("session lock");
            sessions.session_valid(&id)
        })
        .unwrap_or(false);
    if cookie_ok {
        return next.run(request).await;
    }

    if is_api {
        return ApiError::forbidden("authentication required; log in or send a bearer token")
            .into_response();
    }
    Redirect::to("/login").into_response()
}

async fn security_headers(request: Request, next: Next) -> Response {
    let login = request.uri().path() == "/login";
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
        HeaderValue::from_static(if login {
            LOGIN_CSP
        } else {
            CONTENT_SECURITY_POLICY
        }),
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

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD,
    )
        .into_response()
}

async fn login_page() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        LOGIN_PAGE,
    )
        .into_response()
}

async fn login_submit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    let ip = addr.ip().to_string();
    let cfg = state.cfg.lock().expect("config lock").clone();
    let mut sessions = state.sessions.lock().expect("session lock");

    if sessions.is_locked(&ip) {
        return redirect_to("/login?error=locked");
    }

    let candidate = auth::parse_form_token(&body);
    let verified = candidate
        .map(|token| sessions.verify_token(&token))
        .unwrap_or(false);

    if !verified {
        sessions.note_failure(&ip, cfg.auth.max_failed_per_ip, cfg.auth.lockout_secs);
        return redirect_to("/login?error=1");
    }

    sessions.note_success(&ip);
    let ttl = cfg.auth.session_ttl_secs;
    match sessions.create_session(ttl) {
        Ok(id) => {
            let mut response = redirect_to("/");
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&auth::session_cookie(&id, ttl))
                    .expect("cookie header builds"),
            );
            response
        }
        Err(message) => ApiError::internal(message).into_response(),
    }
}

fn redirect_to(path: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, path.to_string())],
    )
        .into_response()
}

async fn logout(State(state): State<Arc<AppState>>, request: Request) -> Response {
    // Drop the session server-side so a stolen cookie stops working.
    if let Some(cookies) = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
    {
        if let Some(id) = auth::parse_cookie(cookies, SESSION_COOKIE) {
            state
                .sessions
                .lock()
                .expect("session lock")
                .drop_session(&id);
        }
    }
    let mut response = redirect_to("/login");
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&auth::clear_cookie()).expect("cookie header builds"),
    );
    response
}

async fn healthz() -> &'static str {
    "ok"
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn require_action_header(headers: &HeaderMap) -> Result<(), ApiError> {
    let value = headers
        .get("x-rpi-aide-scan")
        .and_then(|value| value.to_str().ok());
    if value != Some("1") {
        return Err(ApiError::forbidden("missing x-rpi-aide-scan header"));
    }
    Ok(())
}

#[derive(Serialize)]
struct ScheduleInfo {
    enabled: bool,
    interval_secs: u64,
    next_scan_at: Option<u64>,
    last_full_scan: Option<u64>,
}

#[derive(Serialize)]
struct MaintenanceView {
    until: u64,
    note: String,
    remaining_secs: u64,
}

#[derive(Serialize)]
struct GuardView {
    mode: &'static str,
    backend: Option<&'static str>,
    enforce_available: bool,
    interface: String,
    critical_ports: Vec<u16>,
    allowlist_count: usize,
    capture_running: bool,
    last_error: Option<String>,
    bans: Vec<Ban>,
    events: Vec<GuardEvent>,
}

#[derive(Serialize)]
struct WatchView {
    enabled: bool,
    active: bool,
    watches: usize,
    note: Option<String>,
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
    schedule: ScheduleInfo,
    maintenance: Option<MaintenanceView>,
    guard: GuardView,
    watch: WatchView,
    notify: crate::notify::NotifyStatus,
    auth_enabled: bool,
}

async fn api_status(State(state): State<Arc<AppState>>) -> Result<Json<StatusResponse>, ApiError> {
    let cfg = state.cfg.lock().expect("config lock").clone();
    let mut data = state
        .inner
        .lock()
        .map_err(|_| ApiError::internal("state lock was poisoned"))?;
    data.refresh_alerts(&cfg);
    data.refresh_baseline(&cfg);

    let system = system_info();
    let generation = data.generation();
    let alert_count = {
        let mut seen = HashSet::new();
        data.alerts
            .iter()
            .rev()
            .filter(|alert| alert_is_current(alert, generation))
            .filter(|alert| seen.insert(alert.path.as_str()))
            .count()
    };

    let next_scan_raw = state.next_scan_at.load(Ordering::Relaxed);
    let schedule = ScheduleInfo {
        enabled: cfg.scan_interval_secs > 0 || cfg.scan_on_start_delay_secs > 0,
        interval_secs: cfg.scan_interval_secs,
        next_scan_at: if next_scan_raw > now() {
            Some(next_scan_raw)
        } else {
            None
        },
        last_full_scan: Some(monitor::load_cache(&cfg).last_full_scan),
    };

    let maintenance = maintenance_active(&cfg).map(|active| MaintenanceView {
        remaining_secs: active.until.saturating_sub(now()),
        until: active.until,
        note: active.note,
    });

    let guard = &state.guard;
    let guard_view = GuardView {
        mode: guard.mode().label(),
        backend: guard.backend().map(|backend| backend.label()),
        enforce_available: guard.backend().is_some(),
        interface: guard.settings().interface.clone(),
        critical_ports: guard.settings().critical_ports.clone(),
        allowlist_count: guard.settings().allowlist.len(),
        capture_running: guard.capture_running(),
        last_error: guard.last_error(),
        bans: guard.bans_snapshot(),
        events: guard.events_snapshot(),
    };

    let watch = {
        let status = state.watch_status.lock().expect("watch status lock");
        WatchView {
            enabled: cfg.watch.enabled,
            active: status.active,
            watches: status.watches,
            note: status.note.clone(),
        }
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
        roots: cfg
            .roots
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        exclude_count: cfg.exclude.len(),
        baseline: data.baseline.clone(),
        last_scan: data.last_scan.clone(),
        alert_count,
        server_time: now(),
        poll_interval_ms: 5000,
        schedule,
        maintenance,
        guard: guard_view,
        watch,
        notify: state.notify.status(),
        auth_enabled: state.auth_enabled,
    };

    Ok(Json(response))
}

#[derive(Serialize)]
struct AlertView {
    #[serde(flatten)]
    alert: Alert,
    accepted: bool,
}

#[derive(Serialize)]
struct AlertsResponse {
    alerts: Vec<AlertView>,
    total: usize,
    server_time: u64,
}

async fn api_alerts(State(state): State<Arc<AppState>>) -> Result<Json<AlertsResponse>, ApiError> {
    let cfg = state.cfg.lock().expect("config lock").clone();
    let mut data = state
        .inner
        .lock()
        .map_err(|_| ApiError::internal("state lock was poisoned"))?;
    data.refresh_alerts(&cfg);
    data.refresh_baseline(&cfg);
    let generation = data.generation();
    let visible = monitor::visible_alerts(&data.alerts, generation);
    let accepted = accepted_map(&cfg);
    let alerts: Vec<AlertView> = visible
        .into_iter()
        .map(|alert| {
            let accepted_at = accepted.get(&alert.path).copied().unwrap_or(0);
            AlertView {
                accepted: accepted_at >= alert.detected_at,
                alert,
            }
        })
        .collect();
    let total = alerts.len();
    Ok(Json(AlertsResponse {
        alerts,
        total,
        server_time: now(),
    }))
}

async fn api_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    require_action_header(&headers)?;
    let full = uri
        .query()
        .map(|query| query.contains("full=1"))
        .unwrap_or(false);
    start_scan(&state, full, "manual").map_err(ApiError::conflict)?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "started": true }))))
}

#[derive(serde::Deserialize)]
struct AcceptRequest {
    path: String,
}

async fn api_accept(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AcceptRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_action_header(&headers)?;
    let path = PathBuf::from(&body.path);
    let report = tokio::task::spawn_blocking(move || {
        let cfg = state.cfg.lock().expect("config lock").clone();
        monitor::accept_path(&cfg, &path)
    })
    .await
    .map_err(|_| ApiError::internal("the accept task did not finish"))?
    .map_err(ApiError::conflict)?;
    Ok(Json(json!({
        "accepted": {
            "path": report.path,
            "action": report.action,
            "severity": report.severity.label(),
        }
    })))
}

#[derive(serde::Deserialize)]
struct MaintenanceRequest {
    minutes: Option<u64>,
    off: Option<bool>,
    note: Option<String>,
}

async fn api_maintenance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MaintenanceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_action_header(&headers)?;
    let cfg = state.cfg.lock().expect("config lock").clone();
    if body.off.unwrap_or(false) {
        monitor::set_maintenance(&cfg, 0, "").map_err(ApiError::internal)?;
        return Ok(Json(json!({ "maintenance": null })));
    }
    let minutes = body.minutes.unwrap_or(30).clamp(1, 7 * 24 * 60);
    monitor::set_maintenance(&cfg, minutes, body.note.as_deref().unwrap_or("dashboard"))
        .map_err(ApiError::internal)?;
    let active = maintenance_active(&cfg)
        .map(|active| json!({ "until": active.until, "note": active.note }));
    Ok(Json(json!({ "maintenance": active })))
}

#[derive(serde::Deserialize)]
struct GuardModeRequest {
    mode: String,
}

async fn api_guard_mode(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<GuardModeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_action_header(&headers)?;
    let mode = GuardMode::parse(&body.mode)
        .ok_or_else(|| ApiError::bad_request("mode must be off, monitor or enforce"))?;
    if mode == GuardMode::Enforce && state.guard.backend().is_none() {
        return Err(ApiError::conflict(
            "enforce needs nftables or iptables with root or CAP_NET_ADMIN on this host",
        ));
    }

    let persist_path = state
        .config_source
        .loaded()
        .then(|| state.config_source.path().to_path_buf());
    if let Some(path) = &persist_path {
        patch_config_file(path, |value| {
            value["guard"]["mode"] = serde_json::json!(mode.label());
        })
        .map_err(ApiError::internal)?;
    }
    {
        let mut cfg = state.cfg.lock().expect("config lock");
        cfg.guard.mode = mode;
    }

    let engine = Arc::clone(&state.guard);
    tokio::task::spawn_blocking(move || engine.set_mode(mode))
        .await
        .map_err(|_| ApiError::internal("the guard did not finish switching modes"))?
        .map_err(ApiError::internal)?;

    Ok(Json(json!({ "mode": mode.label() })))
}

#[derive(serde::Deserialize)]
struct UnbanRequest {
    ip: String,
}

async fn api_guard_unban(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<UnbanRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_action_header(&headers)?;
    let engine = Arc::clone(&state.guard);
    let ip = body.ip.clone();
    tokio::task::spawn_blocking(move || engine.unban(&ip))
        .await
        .map_err(|_| ApiError::internal("the unban task did not finish"))?
        .map_err(ApiError::conflict)?;
    Ok(Json(json!({ "unbanned": body.ip })))
}

async fn api_guard_unban_all(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_action_header(&headers)?;
    let engine = Arc::clone(&state.guard);
    let removed = tokio::task::spawn_blocking(move || engine.unban_all())
        .await
        .map_err(|_| ApiError::internal("the unban task did not finish"))?
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "removed": removed })))
}

async fn api_notify_test(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_action_header(&headers)?;
    if !state.notify.configured() {
        return Err(ApiError::conflict(
            "no notification channel is configured (webhook, ntfy or telegram)",
        ));
    }
    state.notify_sender.send_test();
    Ok(Json(json!({ "queued": true })))
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let cfg = state.cfg.lock().expect("config lock").clone();
    let (baseline, last_scan, alert_count) = {
        let data = state.inner.lock().expect("state lock");
        let generation = data.generation();
        let count = {
            let mut seen = HashSet::new();
            data.alerts
                .iter()
                .rev()
                .filter(|alert| alert_is_current(alert, generation))
                .filter(|alert| seen.insert(alert.path.as_str()))
                .count()
        };
        (data.baseline.clone(), data.last_scan.clone(), count)
    };

    let maintenance = u8::from(maintenance_active(&cfg).is_some());
    let mode_value = match state.guard.mode() {
        GuardMode::Off => 0,
        GuardMode::Monitor => 1,
        GuardMode::Enforce => 2,
    };
    let last_full = monitor::load_cache(&cfg).last_full_scan;

    let mut text = String::new();
    text.push_str("# TYPE rpi_aide_up gauge\n");
    text.push_str("rpi_aide_up 1\n");
    text.push_str(&format!(
        "# TYPE rpi_aide_build_info gauge\nrpi_aide_build_info{{version=\"{VERSION}\"}} 1\n"
    ));
    text.push_str("# TYPE rpi_aide_scanning gauge\n");
    text.push_str(&format!(
        "rpi_aide_scanning {}\n",
        u8::from(state.scanning.load(Ordering::Relaxed))
    ));
    if let Some(scan) = &last_scan {
        text.push_str("# TYPE rpi_aide_last_scan_finished gauge\n");
        text.push_str(&format!(
            "rpi_aide_last_scan_finished {}\n",
            scan.finished_at
        ));
        text.push_str(&format!(
            "rpi_aide_last_scan_duration_ms {}\n",
            scan.duration_ms
        ));
        text.push_str(&format!("rpi_aide_last_scan_errors {}\n", scan.errors));
        text.push_str(&format!("rpi_aide_last_scan_added {}\n", scan.added));
        text.push_str(&format!("rpi_aide_last_scan_modified {}\n", scan.modified));
        text.push_str(&format!("rpi_aide_last_scan_deleted {}\n", scan.deleted));
    }
    text.push_str("# TYPE rpi_aide_last_full_scan gauge\n");
    text.push_str(&format!("rpi_aide_last_full_scan {}\n", last_full));
    text.push_str("# TYPE rpi_aide_baseline_entries gauge\n");
    text.push_str(&format!("rpi_aide_baseline_entries {}\n", baseline.entries));
    text.push_str("# TYPE rpi_aide_alerts_current gauge\n");
    text.push_str(&format!("rpi_aide_alerts_current {alert_count}\n"));
    text.push_str("# TYPE rpi_aide_guard_mode gauge\n");
    text.push_str(&format!("rpi_aide_guard_mode {mode_value}\n"));
    text.push_str("# TYPE rpi_aide_guard_bans gauge\n");
    text.push_str(&format!(
        "rpi_aide_guard_bans {}\n",
        state.guard.bans_snapshot().len()
    ));
    text.push_str("# TYPE rpi_aide_maintenance_active gauge\n");
    text.push_str(&format!("rpi_aide_maintenance_active {maintenance}\n"));

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Host facts
// ---------------------------------------------------------------------------

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

/// Where the CLI's remote commands should connect.
pub fn local_service_address(cfg: &Config) -> (String, u16) {
    match cfg.bind.parse::<SocketAddr>() {
        Ok(address) => {
            let host = if address.ip().is_unspecified() {
                "127.0.0.1".to_string()
            } else {
                address.ip().to_string()
            };
            (host, address.port())
        }
        Err(_) => ("127.0.0.1".to_string(), 8080),
    }
}

/// The bearer token for CLI-to-service calls, when auth is on.
pub fn service_bearer(state_token_path: &std::path::Path, auth_enabled: bool) -> Option<String> {
    if !auth_enabled {
        return None;
    }
    auth::read_token_file(state_token_path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::ChangeKind;

    fn alert(id: u64, path: &str, at: u64, generation: u64) -> Alert {
        Alert {
            id,
            kind: ChangeKind::Modified,
            path: path.to_string(),
            detected_at: at,
            changes: Vec::new(),
            old_hash: None,
            new_hash: None,
            size: Some(1),
            mode: "0644".to_string(),
            baseline_created_at: generation,
            severity: crate::config::Severity::Info,
            expected: false,
            chain: None,
        }
    }

    #[test]
    fn visible_alerts_keep_one_current_row_per_path() {
        let alerts = VecDeque::from(vec![
            alert(1, "/etc/a", 10, 100),
            alert(2, "/etc/a", 20, 100),
            alert(3, "/etc/b", 15, 100),
            alert(4, "/etc/c", 30, 50),
        ]);
        let visible = monitor::visible_alerts(&alerts, Some(100));
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].path, "/etc/b");
        assert_eq!(visible[0].id, 3);
        assert_eq!(visible[1].path, "/etc/a");
        assert_eq!(visible[1].id, 2);

        let visible_any = monitor::visible_alerts(&alerts, None);
        assert_eq!(visible_any.len(), 3, "all paths when no valid baseline");
    }

    #[test]
    fn service_address_respects_unspecified_bind() {
        let cfg = crate::config::Config {
            bind: "0.0.0.0:8111".to_string(),
            ..crate::config::Config::default()
        };
        assert_eq!(local_service_address(&cfg), ("127.0.0.1".to_string(), 8111));
        let cfg = crate::config::Config {
            bind: "192.168.1.42:8111".to_string(),
            ..crate::config::Config::default()
        };
        assert_eq!(
            local_service_address(&cfg),
            ("192.168.1.42".to_string(), 8111)
        );
    }
}
