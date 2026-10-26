//! Shared helpers: time formatting, random tokens, atomic file writes,
//! IPv4/CIDR matching, thread priority, and logging.

use std::fs;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static QUIET: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

pub fn info(message: &str) {
    if !quiet() {
        eprintln!("{} INFO  {}", rfc3339(now()), message);
    }
}

pub fn warn(message: &str) {
    eprintln!("{} WARN  {}", rfc3339(now()), message);
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

pub fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

pub fn human_bytes(bytes: u64) -> String {
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

pub fn rfc3339(timestamp: u64) -> String {
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

/// A constant-time comparison for secret material such as session tokens.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Hex characters from the operating system random source.
pub fn random_hex(byte_count: usize) -> Result<String, String> {
    let mut buffer = vec![0u8; byte_count];
    read_urandom(&mut buffer)?;
    let mut out = String::with_capacity(buffer.len() * 2);
    for byte in buffer {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

fn read_urandom(buffer: &mut [u8]) -> Result<(), String> {
    let mut file = fs::File::open("/dev/urandom")
        .map_err(|error| format!("cannot open /dev/urandom: {error}"))?;
    file.read_exact(buffer)
        .map_err(|error| format!("cannot read /dev/urandom: {error}"))
}

/// A small deterministic value for jitter and tests, derived from urandom.
pub fn random_below(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    let mut buffer = [0u8; 8];
    read_urandom(&mut buffer).unwrap_or_default();
    u64::from_le_bytes(buffer) % bound
}

pub fn write_json_atomic<T: serde::Serialize>(
    path: &Path,
    value: &T,
    mode: u32,
) -> Result<(), String> {
    ensure_parent(path)?;
    let temporary = temp_path(path);

    let file = std::fs::OpenOptions::new()
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

    let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);
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
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }

    Ok(())
}

pub fn temp_path(path: &Path) -> PathBuf {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(temporary)
}

pub fn ensure_parent(path: &Path) -> Result<(), String> {
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

/// Lowers the calling thread's CPU priority so scans never delay DNS or
/// other latency-sensitive work on the single-core hosts this targets.
pub fn lower_thread_priority() {
    // PRIO_PROCESS with pid 0 adjusts the calling thread on Linux. The value
    // is best-effort; failure is expected inside containers and is ignored.
    let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 10) };
    if result != 0 {
        let _ = result;
    }
}

pub fn parse_ipv4(text: &str) -> Option<u32> {
    text.parse::<Ipv4Addr>().ok().map(u32::from)
}

pub fn ipv4_to_string(addr: u32) -> String {
    Ipv4Addr::from(addr).to_string()
}

/// An IPv4 CIDR range such as `192.168.1.0/24` or a bare address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: u32,
    mask: u32,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Self> {
        let (address_part, bits_part) = match text.split_once('/') {
            Some((address, bits)) => (address, Some(bits)),
            None => (text, None),
        };
        let address = parse_ipv4(address_part.trim())?;
        let bits = match bits_part {
            Some(bits) => bits.trim().parse::<u32>().ok()?,
            None => 32,
        };
        if bits > 32 {
            return None;
        }
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        Some(Self {
            network: address & mask,
            mask,
        })
    }

    pub fn contains(&self, address: u32) -> bool {
        address & self.mask == self.network
    }
}

/// Parses a human duration such as `30m`, `2h`, `1d`, or a bare minute count.
pub fn parse_duration_minutes(text: &str) -> Option<u64> {
    let trimmed = text.trim().to_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    let (value_part, unit) = trimmed.split_at(trimmed.len() - 1);
    let value_text = if unit.chars().all(|c| c.is_ascii_digit()) {
        trimmed.as_str()
    } else {
        value_part
    };
    let value: u64 = value_text.trim().parse().ok()?;
    match unit.as_bytes().first() {
        Some(b'm') if !unit.chars().all(|c| c.is_ascii_digit()) => Some(value),
        Some(b'h') if !unit.chars().all(|c| c.is_ascii_digit()) => Some(value.saturating_mul(60)),
        Some(b'd') if !unit.chars().all(|c| c.is_ascii_digit()) => {
            Some(value.saturating_mul(24 * 60))
        }
        _ => {
            if trimmed.chars().all(|c| c.is_ascii_digit()) {
                Some(value)
            } else {
                None
            }
        }
    }
}

pub fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let values = line.strip_prefix("Uid:")?;
        values
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u32>().ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_has_expected_length_and_alphabet() {
        let value = random_hex(16).expect("urandom available on Linux");
        assert_eq!(value.len(), 32);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn constant_time_compare_rejects_length_and_value_drift() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abcd", b"abcde"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn cidr_matches_ranges() {
        let net = Cidr::parse("192.168.1.0/24").expect("valid cidr");
        assert!(net.contains(parse_ipv4("192.168.1.65").unwrap()));
        assert!(!net.contains(parse_ipv4("192.168.2.65").unwrap()));

        let host = Cidr::parse("10.0.0.1").expect("bare address is /32");
        assert!(host.contains(parse_ipv4("10.0.0.1").unwrap()));
        assert!(!host.contains(parse_ipv4("10.0.0.2").unwrap()));

        let all = Cidr::parse("0.0.0.0/0").expect("zero cidr");
        assert!(all.contains(parse_ipv4("203.0.113.9").unwrap()));

        assert!(Cidr::parse("192.168.1.0/33").is_none());
        assert!(Cidr::parse("not-an-ip").is_none());
    }

    #[test]
    fn durations_parse_in_minutes() {
        assert_eq!(parse_duration_minutes("30m"), Some(30));
        assert_eq!(parse_duration_minutes("2h"), Some(120));
        assert_eq!(parse_duration_minutes("1d"), Some(1440));
        assert_eq!(parse_duration_minutes("45"), Some(45));
        assert_eq!(parse_duration_minutes(""), None);
        assert_eq!(parse_duration_minutes("xx"), None);
    }

    #[test]
    fn ipv4_round_trips() {
        let raw = parse_ipv4("203.0.113.9").expect("parse");
        assert_eq!(ipv4_to_string(raw), "203.0.113.9");
    }
}
