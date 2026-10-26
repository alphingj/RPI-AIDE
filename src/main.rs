//! CLI entry point: argument parsing and dispatch across the monitor,
//! guard, and diagnostic commands.

mod auth;
mod capture;
mod config;
mod doctor;
mod guard;
mod httpc;
mod monitor;
mod notify;
mod server;
mod util;
mod watch;

use std::path::PathBuf;

use config::{Config, ConfigSource, GuardMode};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = concat!(
    "RPI-AIDE ",
    env!("CARGO_PKG_VERSION"),
    "\n",
    "Lightweight file integrity monitor with a port-scan guard.\n\n",
    "USAGE:\n",
    "    rpi-aide [MODE] [OPTIONS]\n\n",
    "MODES:\n",
    "    --serve               Start the dashboard (default)\n",
    "    --init                Scan the roots and write a new baseline\n",
    "    --check [--fast]      Compare the filesystem with the baseline\n",
    "                           (--fast reuses cached hashes; the default is a full rehash)\n",
    "    --accept PATH         Approve the current state of one path\n",
    "    --maintenance 30m|off Start or stop a maintenance window (also 2h, 1d, plain minutes)\n",
    "    --doctor              Run read-only health checks\n",
    "    --verify-log          Verify the hash chain of the alerts log\n",
    "    --print-token         Print the dashboard login token\n",
    "    --guard               Show the port-scan guard status\n",
    "    --list-bans           List active bans\n",
    "    --unban IP            Remove one ban\n",
    "    --unban-all           Remove every ban\n",
    "    --guard-monitor       Switch the guard to monitor mode\n",
    "    --guard-enforce       Switch the guard to enforce mode (blocking)\n",
    "    --guard-off           Turn the guard off\n\n",
    "OPTIONS:\n",
    "    --config PATH     Config file (default: /etc/rpi-aide/config.json or ./config.json)\n",
    "    --force           Replace an existing baseline during --init\n",
    "    --quiet, -q       Suppress informational log lines\n",
    "    -h, --help        Show this help\n",
    "    -V, --version     Show the version\n\n",
    "EXIT CODES:\n",
    "    0   Success, or a clean check\n",
    "    1   Anomalies found, a warning, or a problem\n",
    "    2   Usage, configuration or I/O error\n"
);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Init,
    Check { fast: bool },
    Serve,
    Help,
    Version,
    Accept { path: PathBuf },
    Maintenance { minutes: Option<u64> },
    Doctor,
    VerifyLog,
    PrintToken,
    GuardStatus,
    ListBans,
    Unban { ip: String },
    UnbanAll,
    GuardSet { mode: GuardMode },
}

#[derive(Debug)]
struct Cli {
    action: Action,
    config: Option<PathBuf>,
    force: bool,
}

fn set_action(slot: &mut Option<Action>, next: Action) -> Result<(), String> {
    match slot {
        Some(existing) if *existing != next => {
            Err("choose one mode; run 'rpi-aide --help' to see the list".to_string())
        }
        _ => {
            *slot = Some(next);
            Ok(())
        }
    }
}

fn parse_args() -> Result<Cli, String> {
    let mut action: Option<Action> = None;
    let mut config = None;
    let mut force = false;
    let mut fast = false;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--init" => set_action(&mut action, Action::Init)?,
            "--check" => set_action(&mut action, Action::Check { fast: false })?,
            "--fast" => fast = true,
            "--serve" => set_action(&mut action, Action::Serve)?,
            "-h" | "--help" => set_action(&mut action, Action::Help)?,
            "-V" | "--version" => set_action(&mut action, Action::Version)?,
            "--force" => force = true,
            "-q" | "--quiet" => util::set_quiet(true),
            "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--config requires a path".to_string())?;
                config = Some(PathBuf::from(value));
            }
            "--accept" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--accept requires a path".to_string())?;
                set_action(
                    &mut action,
                    Action::Accept {
                        path: PathBuf::from(value),
                    },
                )?;
            }
            "--maintenance" => {
                let value = args.next().ok_or_else(|| {
                    "--maintenance requires a duration like 30m or 'off'".to_string()
                })?;
                let minutes = if value.trim().eq_ignore_ascii_case("off") {
                    None
                } else {
                    Some(
                        util::parse_duration_minutes(&value)
                            .ok_or_else(|| format!("cannot parse '{value}' as a duration"))?,
                    )
                };
                set_action(&mut action, Action::Maintenance { minutes })?;
            }
            "--doctor" => set_action(&mut action, Action::Doctor)?,
            "--verify-log" => set_action(&mut action, Action::VerifyLog)?,
            "--print-token" => set_action(&mut action, Action::PrintToken)?,
            "--guard" => set_action(&mut action, Action::GuardStatus)?,
            "--list-bans" => set_action(&mut action, Action::ListBans)?,
            "--unban" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--unban requires an IP address".to_string())?;
                set_action(&mut action, Action::Unban { ip: value })?;
            }
            "--unban-all" => set_action(&mut action, Action::UnbanAll)?,
            "--guard-monitor" => set_action(
                &mut action,
                Action::GuardSet {
                    mode: GuardMode::Monitor,
                },
            )?,
            "--guard-enforce" => set_action(
                &mut action,
                Action::GuardSet {
                    mode: GuardMode::Enforce,
                },
            )?,
            "--guard-off" => set_action(
                &mut action,
                Action::GuardSet {
                    mode: GuardMode::Off,
                },
            )?,
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

    let action = match action {
        Some(Action::Check { .. }) => Action::Check { fast },
        Some(other) => other,
        None => Action::Serve,
    };
    if fast && !matches!(action, Action::Check { .. }) {
        return Err("--fast only applies to --check".to_string());
    }

    Ok(Cli {
        action,
        config,
        force,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let code = match run().await {
        Ok(code) => code,
        Err(message) => {
            eprintln!("rpi-aide: {message}");
            2
        }
    };
    std::process::exit(code);
}

async fn run() -> Result<i32, String> {
    let cli = parse_args()?;

    if let Action::Help = &cli.action {
        println!("{USAGE}");
        return Ok(0);
    }
    if let Action::Version = &cli.action {
        println!("RPI-AIDE {VERSION}");
        return Ok(0);
    }

    let (cfg, source) = config::load_config(cli.config.as_deref())?;

    match cli.action {
        Action::Init => {
            if let ConfigSource::Defaults(path) = &source {
                util::write_json_atomic(path, &Config::default(), 0o600)?;
                util::info(&format!("created default config at {}", path.display()));
            }
            let summary = monitor::perform_init(&cfg, cli.force)?;
            println!("Baseline written to {}", cfg.baseline_path.display());
            println!(
                "Entries: {} | hashed: {} files, {} | errors: {} | {} ms",
                summary.entries,
                summary.files_hashed,
                util::human_bytes(summary.bytes_hashed),
                summary.errors,
                summary.duration_ms
            );
            Ok(if summary.ok { 0 } else { 1 })
        }
        Action::Check { fast } => {
            if !source.loaded() && !cfg.baseline_path.exists() {
                return Err("no config or baseline found; run 'rpi-aide --init' first".to_string());
            }
            let next_id = monitor::next_alert_id(&cfg);
            let outcome = monitor::perform_check(&cfg, next_id, !fast, "manual")?;
            monitor::print_check(&outcome);
            Ok(if outcome.summary.ok { 0 } else { 1 })
        }
        Action::Serve => server::serve(cfg, source).await,
        Action::Accept { path } => {
            let report = monitor::accept_path(&cfg, &path)?;
            println!(
                "Accepted {} ({}, severity {}); the next scan will be clean for this path",
                report.path,
                report.action,
                report.severity.label()
            );
            Ok(0)
        }
        Action::Maintenance { minutes } => match minutes {
            Some(minutes) => {
                monitor::set_maintenance(&cfg, minutes, "cli")?;
                let active = monitor::maintenance_active(&cfg)
                    .ok_or_else(|| "the window did not activate".to_string())?;
                println!(
                    "Maintenance window active until {} ({} minute(s)). New alerts are recorded but marked expected and no notifications are sent.",
                    util::rfc3339(active.until),
                    minutes
                );
                Ok(0)
            }
            None => {
                monitor::set_maintenance(&cfg, 0, "")?;
                println!("Maintenance window stopped");
                Ok(0)
            }
        },
        Action::Doctor => {
            let checks = doctor::run(&cfg, &source);
            let code = doctor::print_report(&checks);
            match code {
                0 => println!("\nAll checks passed."),
                1 => println!("\nSome checks reported warnings."),
                _ => println!("\nSome checks failed."),
            }
            Ok(code)
        }
        Action::VerifyLog => match monitor::verify_alerts_chain(&cfg) {
            Ok(summary) => {
                println!("{summary}");
                Ok(0)
            }
            Err(problem) => {
                println!("alerts log: {problem}");
                Ok(1)
            }
        },
        Action::PrintToken => {
            if !cfg.auth.enabled {
                return Err("authentication is disabled in the config".to_string());
            }
            let token_path = cfg.token_path(source.path());
            let token = auth::read_token_file(&token_path)?;
            println!("{token}");
            println!(
                "Log in at the dashboard with this token. It is also accepted as: Authorization: Bearer <token>"
            );
            Ok(0)
        }
        Action::GuardStatus | Action::ListBans => {
            let body = guard_request(&cfg, &source, "GET", "/api/status", None)?;
            print_guard_status(&body);
            Ok(0)
        }
        Action::Unban { ip } => {
            let body = serde_json::json!({ "ip": ip }).to_string();
            let response = guard_request(&cfg, &source, "POST", "/api/guard/unban", Some(&body))?;
            let value: serde_json::Value = serde_json::from_str(&response)
                .map_err(|_| "the service returned a malformed response".to_string())?;
            println!("Unbanned {}", value["unbanned"].as_str().unwrap_or(&ip));
            Ok(0)
        }
        Action::UnbanAll => {
            let response =
                guard_request(&cfg, &source, "POST", "/api/guard/unban-all", Some("{}"))?;
            let value: serde_json::Value = serde_json::from_str(&response)
                .map_err(|_| "the service returned a malformed response".to_string())?;
            println!("Removed {} ban(s)", value["removed"].as_u64().unwrap_or(0));
            Ok(0)
        }
        Action::GuardSet { mode } => {
            let body = serde_json::json!({ "mode": mode.label() }).to_string();
            let response = guard_request(&cfg, &source, "POST", "/api/guard/mode", Some(&body))?;
            let value: serde_json::Value = serde_json::from_str(&response)
                .map_err(|_| "the service returned a malformed response".to_string())?;
            println!(
                "Guard mode is now '{}'",
                value["mode"].as_str().unwrap_or(mode.label())
            );
            Ok(0)
        }
        Action::Help | Action::Version => Ok(0),
    }
}

fn guard_request(
    cfg: &Config,
    source: &ConfigSource,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<String, String> {
    let (host, port) = server::local_service_address(cfg);
    let bearer = server::service_bearer(&cfg.token_path(source.path()), cfg.auth.enabled);
    let response = httpc::request(&httpc::Request {
        method,
        host: &host,
        port,
        path,
        bearer: bearer.as_deref(),
        action: method == "POST",
        body,
    })
    .map_err(|error| {
        format!(
            "{error}. The guard commands talk to the dashboard service; start it with 'systemctl start rpi-aide' or run 'rpi-aide --serve'."
        )
    })?;
    match response.status {
        200..=299 => Ok(response.body),
        401 | 403 => Err(
            "the service rejected the request; check the token file (rpi-aide --print-token)"
                .to_string(),
        ),
        _ => {
            let message = serde_json::from_str::<serde_json::Value>(&response.body)
                .ok()
                .and_then(|value| value["error"].as_str().map(str::to_string))
                .unwrap_or_else(|| format!("status {}", response.status));
            Err(message)
        }
    }
}

fn print_guard_status(body: &str) {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| "the service returned a malformed response".to_string())
        .unwrap_or_else(|message| {
            eprintln!("rpi-aide: {message}");
            std::process::exit(2);
        });

    let guard = &value["guard"];
    println!(
        "Guard mode:   {}",
        guard["mode"].as_str().unwrap_or("unknown")
    );
    println!(
        "Capture:      {}",
        if guard["capture_running"].as_bool().unwrap_or(false) {
            format!("watching {}", guard["interface"].as_str().unwrap_or("?"))
        } else {
            "not running".to_string()
        }
    );
    let backend = guard["backend"].as_str().unwrap_or("none");
    println!("Firewall:     {backend}");
    println!(
        "Critical ports: {}",
        guard["critical_ports"]
            .as_array()
            .map(|ports| {
                ports
                    .iter()
                    .filter_map(|port| port.as_u64().map(|value| value.to_string()))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    );
    if let Some(error) = guard["last_error"].as_str() {
        println!("Last error:   {error}");
    }

    println!();
    let bans = guard["bans"].as_array().cloned().unwrap_or_default();
    if bans.is_empty() {
        println!("No active bans.");
    } else {
        println!("Active bans:");
        for ban in &bans {
            let expires = ban["expires_at"].as_u64().unwrap_or(0);
            println!(
                "  {:<16} repeat #{:<3} expires {}  ports {}",
                ban["ip"].as_str().unwrap_or("?"),
                ban["repeat"].as_u64().unwrap_or(0),
                util::rfc3339(expires),
                ban["ports"]
                    .as_array()
                    .map(|ports| {
                        ports
                            .iter()
                            .filter_map(|port| port.as_u64().map(|value| value.to_string()))
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default()
            );
        }
    }

    println!();
    let events = guard["events"].as_array().cloned().unwrap_or_default();
    if events.is_empty() {
        println!("No scan events recorded.");
    } else {
        println!("Recent scan events:");
        for event in events.iter().take(10) {
            println!(
                "  {}  {:<16} ports: {}  {}",
                util::rfc3339(event["at"].as_u64().unwrap_or(0)),
                event["ip"].as_str().unwrap_or("?"),
                event["distinct_total"].as_u64().unwrap_or(0),
                if event["blocked"].as_bool().unwrap_or(false) {
                    "blocked"
                } else {
                    "logged"
                }
            );
        }
    }
}
