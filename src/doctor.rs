//! `--doctor`: read-only health checks that explain what works on this host
//! and what does not, without changing anything.

use std::path::{Path, PathBuf};

use crate::config::{Config, ConfigSource};
use crate::util::{human_bytes, now, rfc3339};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

pub fn run(cfg: &Config, source: &ConfigSource) -> Vec<Check> {
    let mut checks = Vec::new();

    checks.push(match source {
        ConfigSource::File(path) => Check {
            name: "config",
            status: CheckStatus::Pass,
            detail: path.display().to_string(),
        },
        ConfigSource::Defaults(path) => Check {
            name: "config",
            status: CheckStatus::Warn,
            detail: format!(
                "no file at {}; built-in defaults are in use",
                path.display()
            ),
        },
    });

    let mut unreadable = Vec::new();
    for root in &cfg.roots {
        match std::fs::canonicalize(root) {
            Ok(path) if path.is_dir() => {}
            _ => unreadable.push(root.display().to_string()),
        }
    }
    checks.push(if unreadable.is_empty() {
        Check {
            name: "roots",
            status: CheckStatus::Pass,
            detail: format!("{} root(s) readable", cfg.roots.len()),
        }
    } else {
        Check {
            name: "roots",
            status: CheckStatus::Fail,
            detail: format!("cannot read: {}", unreadable.join(", ")),
        }
    });

    let state_dir = cfg
        .baseline_path
        .parent()
        .map(|parent| parent.to_path_buf());
    checks.push(match &state_dir {
        Some(dir) if dir.exists() => {
            let mode = std::fs::metadata(dir)
                .ok()
                .map(|meta| {
                    use std::os::unix::fs::PermissionsExt;
                    meta.permissions().mode() & 0o777
                })
                .unwrap_or(0);
            if mode == 0o700 {
                Check {
                    name: "state directory",
                    status: CheckStatus::Pass,
                    detail: format!("{} is private (0700)", dir.display()),
                }
            } else {
                Check {
                    name: "state directory",
                    status: CheckStatus::Warn,
                    detail: format!("{} has mode {:04o}; expected 0700", dir.display(), mode),
                }
            }
        }
        Some(dir) => Check {
            name: "state directory",
            status: CheckStatus::Fail,
            detail: format!("{} does not exist", dir.display()),
        },
        None => Check {
            name: "state directory",
            status: CheckStatus::Fail,
            detail: "the baseline path has no parent".to_string(),
        },
    });

    let meta = crate::monitor::baseline_meta(cfg);
    checks.push(if !meta.exists {
        Check {
            name: "baseline",
            status: CheckStatus::Fail,
            detail: format!("{} is missing; run --init", meta.path),
        }
    } else if !meta.valid {
        Check {
            name: "baseline",
            status: CheckStatus::Fail,
            detail: meta.reason.unwrap_or_else(|| "unreadable".into()),
        }
    } else {
        let age_days = now().saturating_sub(meta.created_at) / 86_400;
        if age_days > 30 {
            Check {
                name: "baseline",
                status: CheckStatus::Warn,
                detail: format!(
                    "{} entries, created {} ({} days old)",
                    meta.entries,
                    rfc3339(meta.created_at),
                    age_days
                ),
            }
        } else {
            Check {
                name: "baseline",
                status: CheckStatus::Pass,
                detail: format!(
                    "{} entries, created {}",
                    meta.entries,
                    rfc3339(meta.created_at)
                ),
            }
        }
    });

    checks.push(match std::fs::read(&cfg.alerts_path) {
        Ok(bytes) => {
            let lines = bytes.iter().filter(|byte| **byte == b'\n').count();
            Check {
                name: "alerts log",
                status: if lines == 0 {
                    CheckStatus::Warn
                } else {
                    CheckStatus::Pass
                },
                detail: format!("{} line(s) at {}", lines, cfg.alerts_path.display()),
            }
        }
        Err(_) => Check {
            name: "alerts log",
            status: CheckStatus::Warn,
            detail: format!("{} does not exist yet", cfg.alerts_path.display()),
        },
    });

    let head_path = cfg.chain_head_path();
    checks.push(if head_path.exists() {
        Check {
            name: "chain head",
            status: CheckStatus::Pass,
            detail: "tamper-evident chain is active".to_string(),
        }
    } else {
        Check {
            name: "chain head",
            status: CheckStatus::Warn,
            detail: "no chain head yet; it is created with the first new alert".to_string(),
        }
    });

    let disk_target = state_dir.unwrap_or_else(|| PathBuf::from("/var/lib"));
    checks.push(match free_bytes(&disk_target) {
        Some(free) if free > 100 * 1024 * 1024 => Check {
            name: "disk",
            status: CheckStatus::Pass,
            detail: format!("{} free near the state directory", human_bytes(free)),
        },
        Some(free) if free > 20 * 1024 * 1024 => Check {
            name: "disk",
            status: CheckStatus::Warn,
            detail: format!("only {} free near the state directory", human_bytes(free)),
        },
        Some(free) => Check {
            name: "disk",
            status: CheckStatus::Fail,
            detail: format!("critically low: {} free", human_bytes(free)),
        },
        None => Check {
            name: "disk",
            status: CheckStatus::Warn,
            detail: "cannot measure free space".to_string(),
        },
    });

    let (host, port) = crate::server::local_service_address(cfg);
    let reachable = crate::httpc::request(&crate::httpc::Request {
        method: "GET",
        host: &host,
        port,
        path: "/healthz",
        bearer: None,
        action: false,
        body: None,
    })
    .ok()
    .filter(|response| response.status == 200);
    checks.push(match reachable {
        Some(_) => Check {
            name: "service",
            status: CheckStatus::Pass,
            detail: format!("responding on {host}:{port}"),
        },
        None => Check {
            name: "service",
            status: CheckStatus::Warn,
            detail: format!("not reachable on {host}:{port}; is rpi-aide running?"),
        },
    });

    checks.push(if cfg.auth.enabled {
        let token_path = cfg.token_path(source.path());
        if !token_path.exists() {
            Check {
                name: "auth",
                status: CheckStatus::Fail,
                detail: format!("token file {} is missing", token_path.display()),
            }
        } else {
            let mode = std::fs::metadata(&token_path)
                .ok()
                .map(|meta| {
                    use std::os::unix::fs::PermissionsExt;
                    meta.permissions().mode() & 0o777
                })
                .unwrap_or(0);
            if mode == 0o600 {
                Check {
                    name: "auth",
                    status: CheckStatus::Pass,
                    detail: format!("token file {} is private", token_path.display()),
                }
            } else {
                Check {
                    name: "auth",
                    status: CheckStatus::Warn,
                    detail: format!(
                        "token file {} has mode {:04o}; expected 0600",
                        token_path.display(),
                        mode
                    ),
                }
            }
        }
    } else {
        Check {
            name: "auth",
            status: CheckStatus::Warn,
            detail: "disabled; anyone who can reach the port can use the dashboard".to_string(),
        }
    });

    let curl = std::process::Command::new("curl")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    checks.push(if curl {
        Check {
            name: "notify",
            status: if cfg.notify.configured() {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            detail: if cfg.notify.configured() {
                format!(
                    "channels: {}",
                    cfg.notify
                        .configured_channels()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                "no channel configured; alerts stay local".to_string()
            },
        }
    } else {
        Check {
            name: "notify",
            status: CheckStatus::Warn,
            detail: "curl is not installed; delivery is disabled".to_string(),
        }
    });

    checks.push(match crate::guard::detect_backend() {
        Some(backend) => Check {
            name: "firewall",
            status: CheckStatus::Pass,
            detail: format!("{} is usable for blocking", backend.label()),
        },
        None => Check {
            name: "firewall",
            status: CheckStatus::Warn,
            detail: "neither nftables nor iptables is usable; the guard can only monitor"
                .to_string(),
        },
    });

    checks.push(match crate::capture::probe_raw_socket() {
        Ok(()) => Check {
            name: "packet capture",
            status: CheckStatus::Pass,
            detail: "a raw socket can be opened; the guard can see scans".to_string(),
        },
        Err(message) => Check {
            name: "packet capture",
            status: CheckStatus::Warn,
            detail: message,
        },
    });

    checks.push(
        if cfg.scan_interval_secs == 0 || cfg.scan_interval_secs >= 60 {
            Check {
                name: "schedule",
                status: CheckStatus::Pass,
                detail: if cfg.scan_interval_secs == 0 {
                    "scheduled scans are off".to_string()
                } else {
                    format!("a fast scan every {} s", cfg.scan_interval_secs)
                },
            }
        } else {
            Check {
                name: "schedule",
                status: CheckStatus::Fail,
                detail: "the interval must be 0 (off) or at least 60 seconds".to_string(),
            }
        },
    );

    let mut watch_problems = Vec::new();
    for path in &cfg.watch.paths {
        if !path.is_dir() {
            watch_problems.push(path.display().to_string());
        }
    }
    checks.push(if cfg.watch.enabled && watch_problems.is_empty() {
        Check {
            name: "watch",
            status: CheckStatus::Pass,
            detail: format!("{} path(s) watched", cfg.watch.paths.len()),
        }
    } else if cfg.watch.enabled {
        Check {
            name: "watch",
            status: CheckStatus::Warn,
            detail: format!("not readable: {}", watch_problems.join(", ")),
        }
    } else {
        Check {
            name: "watch",
            status: CheckStatus::Warn,
            detail: "real-time scanning is off".to_string(),
        }
    });

    checks.push(
        match std::process::Command::new("systemctl")
            .args(["is-active", "rpi-aide"])
            .output()
        {
            Ok(output) if output.status.success() => Check {
                name: "systemd",
                status: CheckStatus::Pass,
                detail: "the service is active".to_string(),
            },
            Ok(_) => Check {
                name: "systemd",
                status: CheckStatus::Warn,
                detail: "the service is not active under systemd".to_string(),
            },
            Err(_) => Check {
                name: "systemd",
                status: CheckStatus::Warn,
                detail: "systemctl is unavailable".to_string(),
            },
        },
    );

    checks
}

pub fn print_report(checks: &[Check]) -> i32 {
    let mut worst = 0;
    for check in checks {
        let (label, mark) = match check.status {
            CheckStatus::Pass => ("PASS", "[ ok ]"),
            CheckStatus::Warn => ("WARN", "[warn]"),
            CheckStatus::Fail => ("FAIL", "[fail]"),
        };
        let _ = label;
        println!("{mark:<8} {:<16} {}", check.name, check.detail);
        if check.status == CheckStatus::Fail {
            worst = worst.max(2);
        } else if check.status == CheckStatus::Warn {
            worst = worst.max(1);
        }
    }
    worst
}

fn free_bytes(path: &Path) -> Option<u64> {
    let cstring = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::statvfs(cstring.as_ptr(), &mut vfs) };
    if result != 0 {
        return None;
    }
    Some(vfs.f_bsize as u64 * vfs.f_bavail as u64)
}
