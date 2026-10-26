//! Token authentication for the dashboard: the token file, in-memory
//! sessions with expiry, and per-IP login rate limiting. No cookies or
//! secrets are logged.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::util::{constant_time_eq, now, random_hex};

pub const SESSION_COOKIE: &str = "rpiaide_session";
const MAX_SESSIONS: usize = 32;

pub struct SessionStore {
    token_hash: Option<[u8; 32]>,
    sessions: HashMap<String, u64>,
    failures: HashMap<String, (u32, u64)>,
}

impl SessionStore {
    pub fn new(token: Option<String>) -> Self {
        let token_hash = token.map(|token| *blake3::hash(token.trim().as_bytes()).as_bytes());
        Self {
            token_hash,
            sessions: HashMap::new(),
            failures: HashMap::new(),
        }
    }

    /// Constant-time comparison through the hash, so the raw token never
    /// sits in comparison code.
    pub fn verify_token(&self, candidate: &str) -> bool {
        match self.token_hash {
            Some(expected) => {
                let provided = blake3::hash(candidate.trim().as_bytes());
                constant_time_eq(provided.as_bytes(), &expected)
            }
            None => false,
        }
    }

    pub fn create_session(&mut self, ttl_secs: u64) -> Result<String, String> {
        let id = random_hex(32)?;
        let current = now();
        self.sessions.retain(|_, expires| *expires > current);
        if self.sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, expires)| **expires)
                .map(|(id, _)| id.clone())
            {
                self.sessions.remove(&oldest);
            }
        }
        self.sessions
            .insert(id.clone(), current.saturating_add(ttl_secs.max(60)));
        Ok(id)
    }

    pub fn session_valid(&mut self, id: &str) -> bool {
        let current = now();
        self.sessions.retain(|_, expires| *expires > current);
        self.sessions.contains_key(id)
    }

    pub fn drop_session(&mut self, id: &str) {
        self.sessions.remove(id);
    }

    pub fn note_failure(&mut self, ip: &str, max_failures: u32, lockout_secs: u64) {
        let entry = self.failures.entry(ip.to_string()).or_insert((0, 0));
        entry.0 += 1;
        if entry.0 >= max_failures {
            entry.1 = now().saturating_add(lockout_secs);
        }
    }

    pub fn is_locked(&self, ip: &str) -> bool {
        match self.failures.get(ip) {
            Some((_, lockout_until)) => now() < *lockout_until,
            None => false,
        }
    }

    pub fn note_success(&mut self, ip: &str) {
        self.failures.remove(ip);
    }
}

/// Reads the login token, creating a fresh one when the file is missing.
pub fn ensure_token_file(path: &Path) -> Result<(), String> {
    if let Ok(text) = fs::read_to_string(path) {
        if !text.trim().is_empty() {
            return Ok(());
        }
    }
    let token = random_hex(32)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot create '{}': {error}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot secure '{}': {error}", path.display()))?;
    writeln!(file, "{token}")
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("cannot write '{}': {error}", path.display()))?;
    Ok(())
}

pub fn read_token_file(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read '{}': {error}", path.display()))?;
    let token = text.trim();
    if token.is_empty() {
        return Err(format!("'{}' is empty", path.display()));
    }
    Ok(token.to_string())
}

/// Minimal `application/x-www-form-urlencoded` decode for `token=...`.
pub fn parse_form_token(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    for pair in text.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key.trim() == "token" {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let hex = bytes
                    .get(index + 1..index + 3)
                    .and_then(|slice| std::str::from_utf8(slice).ok())
                    .and_then(|text| u8::from_str_radix(text, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_cookie(headers: &str, name: &str) -> Option<String> {
    for pair in headers.split(';') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=') {
            if key.trim() == name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

pub fn session_cookie(id: &str, ttl_secs: u64) -> String {
    format!("{SESSION_COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl_secs}")
}

pub fn clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_verification_is_exact() {
        let store = SessionStore::new(Some("secret-token".to_string()));
        assert!(store.verify_token("secret-token"));
        assert!(!store.verify_token("secret-tokEn"));
        assert!(!store.verify_token(""));
        let none = SessionStore::new(None);
        assert!(!none.verify_token("anything"));
    }

    #[test]
    fn sessions_expire_and_are_capped() {
        let mut store = SessionStore::new(Some("t".to_string()));
        let first = store.create_session(60).expect("session");
        assert!(store.session_valid(&first));
        // Force expiry by rewriting the deadline to now.
        let deadline = now();
        store.sessions.insert(first.clone(), deadline);
        assert!(!store.session_valid(&first), "expired sessions drop out");

        for _ in 0..MAX_SESSIONS + 5 {
            store.create_session(60).expect("session");
        }
        assert!(store.sessions.len() <= MAX_SESSIONS, "sessions are capped");
    }

    #[test]
    fn failures_lock_the_ip() {
        let mut store = SessionStore::new(Some("t".to_string()));
        assert!(!store.is_locked("10.0.0.9"));
        for _ in 0..5 {
            store.note_failure("10.0.0.9", 5, 900);
        }
        assert!(store.is_locked("10.0.0.9"));
        store.note_success("10.0.0.9");
        assert!(!store.is_locked("10.0.0.9"));
    }

    #[test]
    fn form_and_cookie_parsing() {
        let body = b"token=abc%20def%2Bghi&other=1";
        assert_eq!(parse_form_token(body).as_deref(), Some("abc def+ghi"));
        assert!(parse_form_token(b"other=1").is_none());
        assert!(parse_form_token(b"not a form").is_none());

        let cookie = "theme=dark; rpiaide_session=abc123; other=x";
        assert_eq!(
            parse_cookie(cookie, SESSION_COOKIE).as_deref(),
            Some("abc123")
        );
        assert_eq!(parse_cookie(cookie, "missing"), None);
    }
}
