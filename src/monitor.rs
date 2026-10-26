//! The integrity engine: filesystem scan with a hash cache, baseline
//! management, diffing, the hash-chained alert log, accepted-change records,
//! and maintenance windows.

use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::config::{
    effective_excludes, is_excluded, path_is_within, same_path_set, Config, Severity,
};
use crate::util::{elapsed_ms, human_bytes, now, warn, write_json_atomic};

pub const BASELINE_FORMAT: &str = "rpi-aide-baseline";
pub const BASELINE_VERSION: u32 = 1;
pub const ALERTS_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
pub const CACHE_VERSION: u32 = 1;
pub const CHAIN_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub path: String,
    pub kind: Kind,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub mtime_ns: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub format: String,
    pub version: u32,
    pub created_at: u64,
    pub roots: Vec<String>,
    pub exclude: Vec<String>,
    pub entries: Vec<Record>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    pub kind: ChangeKind,
    pub path: String,
    pub detected_at: u64,
    pub changes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub mode: String,
    #[serde(default)]
    pub baseline_created_at: u64,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub expected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub started_at: u64,
    pub finished_at: u64,
    pub duration_ms: u64,
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
    pub errors: usize,
    pub files_hashed: usize,
    #[serde(default)]
    pub files_reused: usize,
    pub bytes_hashed: u64,
    pub entries: usize,
    #[serde(default)]
    pub directories: usize,
    #[serde(default)]
    pub symlinks: usize,
    #[serde(default)]
    pub skipped: usize,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub trigger: String,
    #[serde(default)]
    pub full: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanError {
    pub path: String,
    pub message: String,
}

#[derive(Default)]
pub struct ScanStats {
    pub hashed: usize,
    pub reused: usize,
    pub bytes: u64,
    pub dirs: usize,
    pub symlinks: usize,
    pub skipped: usize,
}

pub struct ScanOutcome {
    pub entries: Vec<Record>,
    pub errors: Vec<ScanError>,
    pub stats: ScanStats,
    pub cache: HashMap<String, CacheEntry>,
}

pub struct FileHash {
    pub hash: String,
    pub bytes_read: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_ns: u32,
}

pub struct Detected {
    pub kind: ChangeKind,
    pub path: String,
    pub changes: Vec<String>,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub size: Option<u64>,
    pub mode: String,
}

impl Detected {
    pub fn alert(self, id: u64, detected_at: u64, baseline_created_at: u64) -> Alert {
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
            severity: Severity::Info,
            expected: false,
            chain: None,
        }
    }
}

pub struct CheckOutcome {
    pub summary: ScanSummary,
    pub alerts: Vec<Alert>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BaselineMeta {
    pub path: String,
    pub exists: bool,
    pub valid: bool,
    pub created_at: u64,
    pub entries: usize,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub type FileStamp = (i64, i64, u64);

// ---------------------------------------------------------------------------
// Scan cache: file metadata plus hash so unchanged files skip rehashing.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub kind: Kind,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub mtime_ns: u32,
    pub ctime: i64,
    pub ctime_ns: u32,
    pub inode: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl CacheEntry {
    fn matches(&self, facts: &FileFacts) -> bool {
        self.kind == Kind::File
            && self.hash.is_some()
            && self.size == facts.size
            && self.mode == facts.mode
            && self.mtime == facts.mtime
            && self.mtime_ns == facts.mtime_ns
            && self.ctime == facts.ctime
            && self.ctime_ns == facts.ctime_ns
            && self.inode == facts.inode
    }
}

/// The metadata a cached hash is bound to; if none of it moved, the file
/// content did not change since the hash was computed.
#[derive(Clone, Copy, Debug)]
pub struct FileFacts {
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub mtime_ns: u32,
    pub ctime: i64,
    pub ctime_ns: u32,
    pub inode: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanCache {
    pub version: u32,
    #[serde(default)]
    pub last_full_scan: u64,
    pub entries: HashMap<String, CacheEntry>,
}

impl Default for ScanCache {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            last_full_scan: 0,
            entries: HashMap::new(),
        }
    }
}

pub fn load_cache(cfg: &Config) -> ScanCache {
    let bytes = match fs::read(cfg.cache_path()) {
        Ok(bytes) => bytes,
        Err(_) => return ScanCache::default(),
    };
    match serde_json::from_slice::<ScanCache>(&bytes) {
        Ok(cache) if cache.version == CACHE_VERSION => cache,
        _ => ScanCache::default(),
    }
}

pub fn write_cache(cfg: &Config, cache: &ScanCache) -> Result<(), String> {
    write_json_atomic(&cfg.cache_path(), cache, 0o600)
}

/// A fast scan is skipped when the last full rehash is older than the
/// configured interval, so content is always re-read periodically.
pub fn scan_should_be_full(cfg: &Config) -> bool {
    let cache = load_cache(cfg);
    cache.entries.is_empty()
        || cache
            .last_full_scan
            .saturating_add(cfg.full_scan_interval_secs)
            <= now()
}

// ---------------------------------------------------------------------------
// Filesystem scan
// ---------------------------------------------------------------------------

pub fn scan_filesystem(
    cfg: &Config,
    prior_cache: Option<&HashMap<String, CacheEntry>>,
) -> Result<ScanOutcome, String> {
    let excludes = effective_excludes(cfg);
    let mut entries: Vec<Record> = Vec::with_capacity(4096);
    let mut errors: Vec<ScanError> = Vec::new();
    let mut stats = ScanStats::default();
    let mut cache: HashMap<String, CacheEntry> = HashMap::with_capacity(4096);
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
            let ctime = metadata.ctime();
            let ctime_ns = metadata.ctime_nsec().max(0) as u32;
            let inode = metadata.ino();

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
                let facts = FileFacts {
                    size: metadata.len(),
                    mode,
                    mtime,
                    mtime_ns,
                    ctime,
                    ctime_ns,
                    inode,
                };
                let cached_hash = prior_cache
                    .and_then(|prior| prior.get(&path_string))
                    .and_then(|cached| {
                        if cached.matches(&facts) {
                            cached.hash.clone()
                        } else {
                            None
                        }
                    });

                if let Some(hash) = cached_hash {
                    stats.reused += 1;
                    entries.push(Record {
                        path: path_string.clone(),
                        kind: Kind::File,
                        size: facts.size,
                        mode: facts.mode,
                        mtime: facts.mtime,
                        mtime_ns: facts.mtime_ns,
                        hash: Some(hash.clone()),
                    });
                    cache.insert(
                        path_string,
                        CacheEntry {
                            kind: Kind::File,
                            size: facts.size,
                            mode: facts.mode,
                            mtime: facts.mtime,
                            mtime_ns: facts.mtime_ns,
                            ctime: facts.ctime,
                            ctime_ns: facts.ctime_ns,
                            inode: facts.inode,
                            hash: Some(hash),
                        },
                    );
                    continue;
                }

                match hash_file(path, metadata.len(), cfg.max_file_bytes, mtime, mtime_ns) {
                    Ok(hashed) => {
                        stats.hashed += 1;
                        stats.bytes = stats.bytes.saturating_add(hashed.bytes_read);
                        let hash = hashed.hash.clone();
                        entries.push(Record {
                            path: path_string.clone(),
                            kind: Kind::File,
                            size: hashed.size,
                            mode,
                            mtime: hashed.mtime,
                            mtime_ns: hashed.mtime_ns,
                            hash: Some(hash.clone()),
                        });
                        cache.insert(
                            path_string,
                            CacheEntry {
                                kind: Kind::File,
                                size: hashed.size,
                                mode: facts.mode,
                                mtime: hashed.mtime,
                                mtime_ns: hashed.mtime_ns,
                                ctime: facts.ctime,
                                ctime_ns: facts.ctime_ns,
                                inode: facts.inode,
                                hash: Some(hash),
                            },
                        );
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
        cache,
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

    let mut file = fs::File::open(path).map_err(|error| format!("open failed: {error}"))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 4096];
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

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

pub fn diff_entries_scanned(
    previous: &[Record],
    current: &[Record],
    errors: &[ScanError],
) -> Vec<Detected> {
    if errors.is_empty() {
        return diff_entries(previous, current);
    }
    diff_entries(previous, current)
        .into_iter()
        .filter(|item| {
            !errors
                .iter()
                .any(|error| path_is_within(&item.path, &error.path))
        })
        .collect()
}

pub fn diff_entries(previous: &[Record], current: &[Record]) -> Vec<Detected> {
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

pub fn changes_between(previous: &Record, current: &Record) -> Vec<String> {
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

pub fn format_mode(mode: u32) -> String {
    format!("{:04o}", mode)
}

pub fn baseline_matches_config(baseline: &Baseline, cfg: &Config) -> bool {
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

// ---------------------------------------------------------------------------
// Init and check
// ---------------------------------------------------------------------------

pub fn perform_init(cfg: &Config, force: bool) -> Result<ScanSummary, String> {
    if cfg.baseline_path.exists() && !force {
        return Err(format!(
            "baseline '{}' already exists; pass --force to replace it",
            cfg.baseline_path.display()
        ));
    }

    let started_at = now();
    let started = Instant::now();
    let outcome = scan_filesystem(cfg, None)?;
    let ScanOutcome {
        entries,
        errors,
        stats,
        cache,
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

    if let Err(error) = write_cache(
        cfg,
        &ScanCache {
            version: CACHE_VERSION,
            last_full_scan: started_at,
            entries: cache,
        },
    ) {
        warn(&format!("could not write the scan cache: {error}"));
    }

    let summary = ScanSummary {
        started_at,
        finished_at: now(),
        duration_ms: elapsed_ms(started),
        added: 0,
        modified: 0,
        deleted: 0,
        errors: errors.len(),
        files_hashed: stats.hashed,
        files_reused: 0,
        bytes_hashed: stats.bytes,
        entries: entry_count,
        directories: stats.dirs,
        symlinks: stats.symlinks,
        skipped: stats.skipped,
        ok: errors.is_empty(),
        message: None,
        trigger: "init".to_string(),
        full: true,
    };

    if let Err(error) = store_last_scan(cfg, &summary) {
        warn(&format!("could not store the scan summary: {error}"));
    }
    report_scan_errors(&errors);

    Ok(summary)
}

pub fn perform_check(
    cfg: &Config,
    start_id: u64,
    full: bool,
    trigger: &str,
) -> Result<CheckOutcome, String> {
    let baseline = load_baseline(&cfg.baseline_path)?;
    if !baseline_matches_config(&baseline, cfg) {
        return Err(format!(
            "baseline '{}' was created with different roots or excludes; re-run --init with this config",
            cfg.baseline_path.display()
        ));
    }

    let expected = maintenance_active(cfg).is_some();
    let prior_cache = if full {
        None
    } else {
        let cache = load_cache(cfg);
        Some(cache.entries)
    };
    let prior_ref = prior_cache.as_ref();

    let started_at = now();
    let started = Instant::now();
    let outcome = scan_filesystem(cfg, prior_ref)?;
    let detected = diff_entries_scanned(&baseline.entries, &outcome.entries, &outcome.errors);
    let detected_at = now();

    let mut next_id = start_id;
    let mut alerts: Vec<Alert> = detected
        .into_iter()
        .map(|item| {
            let mut alert = item.alert(next_id, detected_at, baseline.created_at);
            alert.severity = crate::config::severity_for_path(&alert.path, &cfg.severity_rules);
            alert.expected = expected;
            next_id = next_id.saturating_add(1);
            alert
        })
        .collect();

    let mut message = None;
    if let Err(error) = append_alerts(cfg, &mut alerts) {
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
        files_reused: outcome.stats.reused,
        bytes_hashed: outcome.stats.bytes,
        entries: outcome.entries.len(),
        directories: outcome.stats.dirs,
        symlinks: outcome.stats.symlinks,
        skipped: outcome.stats.skipped,
        ok: added + modified + deleted == 0 && outcome.errors.is_empty() && message.is_none(),
        message,
        trigger: trigger.to_string(),
        full,
    };

    if full {
        if let Err(error) = write_cache(
            cfg,
            &ScanCache {
                version: CACHE_VERSION,
                last_full_scan: summary.finished_at,
                entries: outcome.cache,
            },
        ) {
            warn(&format!("could not write the scan cache: {error}"));
        }
    } else if let Err(error) = write_cache(
        cfg,
        &ScanCache {
            version: CACHE_VERSION,
            last_full_scan: load_cache(cfg).last_full_scan,
            entries: outcome.cache,
        },
    ) {
        warn(&format!("could not write the scan cache: {error}"));
    }

    if let Err(error) = store_last_scan(cfg, &summary) {
        warn(&format!("could not store the scan summary: {error}"));
    }
    report_scan_errors(&outcome.errors);

    Ok(CheckOutcome { summary, alerts })
}

pub fn print_check(outcome: &CheckOutcome) {
    for alert in &outcome.alerts {
        let label = match alert.kind {
            ChangeKind::Added => "ADDED",
            ChangeKind::Modified => "MODIFIED",
            ChangeKind::Deleted => "DELETED",
        };
        let mut details = alert.changes.clone();
        if alert.severity != Severity::Info {
            details.push(alert.severity.label().to_string());
        }
        if alert.expected {
            details.push("expected".to_string());
        }
        if details.is_empty() {
            println!("{label:<9} {}", alert.path);
        } else {
            println!("{label:<9} {}  [{}]", alert.path, details.join(", "));
        }
    }

    let summary = &outcome.summary;
    println!(
        "Scan complete: {} added, {} modified, {} deleted, {} errors | {} files hashed, {} reused, {} | {} ms ({}, {} scan)",
        summary.added,
        summary.modified,
        summary.deleted,
        summary.errors,
        summary.files_hashed,
        summary.files_reused,
        human_bytes(summary.bytes_hashed),
        summary.duration_ms,
        summary.trigger,
        if summary.full { "full" } else { "fast" }
    );

    if let Some(message) = &summary.message {
        println!("Note: {message}");
    }
}

pub fn report_scan_errors(errors: &[ScanError]) {
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

pub fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!(
                "baseline '{}' not found; run 'rpi-aide --init'",
                path.display()
            )
        } else {
            format!("cannot read baseline '{}': {error}", path.display())
        }
    })?;

    let baseline: Baseline = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse baseline '{}': {error}", path.display()))?;

    if baseline.format != BASELINE_FORMAT {
        return Err(format!("'{}' is not a rpi-aide baseline", path.display()));
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

// ---------------------------------------------------------------------------
// Hash-chained alert log
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainHead {
    pub start: String,
    pub head: String,
    pub lines: u64,
    pub skip: u64,
}

fn chain_for(prev: &str, alert: &Alert) -> Result<String, String> {
    let mut bare = alert.clone();
    bare.chain = None;
    let canonical = serde_json::to_vec(&bare).map_err(|error| error.to_string())?;
    let mut input = Vec::with_capacity(prev.len() + canonical.len());
    input.extend_from_slice(prev.as_bytes());
    input.extend_from_slice(&canonical);
    Ok(blake3::hash(&input).to_hex().to_string())
}

fn read_chain_head(cfg: &Config) -> Option<ChainHead> {
    let bytes = fs::read(cfg.chain_head_path()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn count_log_lines(path: &Path) -> u64 {
    fs::read(path)
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count() as u64
        })
        .unwrap_or(0)
}

/// Adopts the file as the truth when the head and the log disagree after a
/// crash, but never papers over unparseable trailing lines: verification
/// reports those as tampering.
fn reconcile_head(cfg: &Config) -> ChainHead {
    let total = count_log_lines(&cfg.alerts_path);
    match read_chain_head(cfg) {
        None => ChainHead {
            start: CHAIN_GENESIS.to_string(),
            head: CHAIN_GENESIS.to_string(),
            lines: 0,
            skip: total,
        },
        Some(head) => {
            let chained = total.saturating_sub(head.skip);
            if chained == head.lines {
                return head;
            }
            if let Some(chain) = last_line_chain(cfg) {
                ChainHead {
                    start: head.start,
                    head: chain,
                    lines: chained,
                    skip: head.skip,
                }
            } else {
                head
            }
        }
    }
}

fn last_line_chain(cfg: &Config) -> Option<String> {
    let bytes = fs::read(&cfg.alerts_path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let last = text.lines().rev().find(|line| !line.trim().is_empty())?;
    let alert: Alert = serde_json::from_str(last).ok()?;
    alert.chain
}

fn rotate_alerts(path: &Path, limit_bytes: u64) -> Result<bool, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "cannot stat alerts log '{}': {error}",
                path.display()
            ));
        }
    };

    if metadata.len() < limit_bytes {
        return Ok(false);
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

    Ok(true)
}

pub fn append_alerts(cfg: &Config, alerts: &mut [Alert]) -> Result<(), String> {
    append_alerts_with_limit(cfg, alerts, ALERTS_ROTATE_BYTES)
}

fn append_alerts_with_limit(
    cfg: &Config,
    alerts: &mut [Alert],
    rotate_limit: u64,
) -> Result<(), String> {
    if alerts.is_empty() {
        return Ok(());
    }

    crate::util::ensure_parent(&cfg.alerts_path)?;
    let rotated = rotate_alerts(&cfg.alerts_path, rotate_limit)?;

    let mut head = reconcile_head(cfg);
    if rotated {
        let continuation = head.head;
        head = ChainHead {
            start: continuation.clone(),
            head: continuation,
            lines: 0,
            skip: 0,
        };
    }

    let mut prev = head.head.clone();
    for alert in alerts.iter_mut() {
        let chain = chain_for(&prev, alert)?;
        alert.chain = Some(chain.clone());
        prev = chain;
    }

    let file = fs::OpenOptions::new()
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

    let mut writer = std::io::BufWriter::with_capacity(16 * 1024, file);
    for alert in alerts.iter() {
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

    head.head = prev;
    head.lines = head.lines.saturating_add(alerts.len() as u64);
    write_json_atomic(&cfg.chain_head_path(), &head, 0o600)?;

    Ok(())
}

/// Returns a human summary on success, or a problem description.
pub fn verify_alerts_chain(cfg: &Config) -> Result<String, String> {
    let bytes = fs::read(&cfg.alerts_path).map_err(|error| {
        format!(
            "cannot read alerts log '{}': {error}",
            cfg.alerts_path.display()
        )
    })?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();

    let head = match read_chain_head(cfg) {
        Some(head) => head,
        None => {
            if lines.is_empty() {
                return Ok("alerts log is empty; nothing to verify".to_string());
            }
            return Err(
                "this log predates chained records; chains start with the first new alert"
                    .to_string(),
            );
        }
    };

    let total = lines.len() as u64;
    let skip = head.skip.min(total);
    let chained = total.saturating_sub(skip);

    if total != head.skip.saturating_add(head.lines) {
        return Err(format!(
            "line count is {total} but the chain head records {} chained lines; lines may have been added or removed outside rpi-aide",
            head.skip.saturating_add(head.lines)
        ));
    }

    let mut prev = head.start.clone();
    for (index, line) in lines.iter().enumerate() {
        if (index as u64) < skip {
            continue;
        }
        let alert: Alert = serde_json::from_str(line).map_err(|_| {
            format!(
                "line {} is not a valid chained record; the log was modified",
                index + 1
            )
        })?;
        let chain = alert.chain.clone().ok_or_else(|| {
            format!(
                "line {} carries no chain record; it may be from an older version or edited",
                index + 1
            )
        })?;
        let computed = chain_for(&prev, &alert)?;
        if computed != chain {
            return Err(format!(
                "chain mismatch at line {}: the log was modified after it was written",
                index + 1
            ));
        }
        prev = chain;
    }

    if prev != head.head {
        return Err(
            "the chain head does not match the last line; the log or the head was edited"
                .to_string(),
        );
    }

    Ok(format!(
        "verified {} chained line(s) plus {skip} legacy line(s)",
        chained
    ))
}

pub fn load_recent_alerts(cfg: &Config) -> VecDeque<Alert> {
    let mut alerts = VecDeque::new();
    let bytes = match fs::read(&cfg.alerts_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
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

pub fn next_alert_id(cfg: &Config) -> u64 {
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

pub fn store_last_scan(cfg: &Config, summary: &ScanSummary) -> Result<(), String> {
    write_json_atomic(&cfg.last_scan_path(), summary, 0o600)
}

pub fn load_last_scan(cfg: &Config) -> Option<ScanSummary> {
    let bytes = fs::read(cfg.last_scan_path()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn file_stamp(path: &Path) -> Option<FileStamp> {
    fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.mtime(), metadata.mtime_nsec(), metadata.len()))
}

pub fn baseline_meta(cfg: &Config) -> BaselineMeta {
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

pub fn alert_is_current(alert: &Alert, generation: Option<u64>) -> bool {
    match generation {
        Some(created_at) => alert.baseline_created_at == created_at,
        None => true,
    }
}

/// The latest alert per path for the current baseline generation.
pub fn visible_alerts(alerts: &VecDeque<Alert>, generation: Option<u64>) -> Vec<Alert> {
    let mut seen = HashSet::new();
    let mut visible = Vec::new();
    for alert in alerts.iter().rev() {
        if !alert_is_current(alert, generation) {
            continue;
        }
        if seen.insert(alert.path.as_str()) {
            visible.push(alert.clone());
        }
    }
    visible
}

// ---------------------------------------------------------------------------
// Accept one change
// ---------------------------------------------------------------------------

pub type AcceptedMap = std::collections::BTreeMap<String, u64>;

pub fn load_accepted(cfg: &Config) -> AcceptedMap {
    let bytes = match fs::read(cfg.accepted_path()) {
        Ok(bytes) => bytes,
        Err(_) => return AcceptedMap::new(),
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn accepted_map(cfg: &Config) -> AcceptedMap {
    load_accepted(cfg)
}

const MAX_ACCEPTED: usize = 500;

pub fn mark_accepted(cfg: &Config, path: &str) -> Result<(), String> {
    let mut accepted = load_accepted(cfg);
    accepted.insert(path.to_string(), now());
    if accepted.len() > MAX_ACCEPTED {
        let mut ordered: Vec<(String, u64)> = accepted
            .iter()
            .map(|(path, at)| (path.clone(), *at))
            .collect();
        ordered.sort_by_key(|(_, at)| *at);
        let excess = ordered.len() - MAX_ACCEPTED;
        for (path, _) in ordered.into_iter().take(excess) {
            accepted.remove(&path);
        }
    }
    write_json_atomic(&cfg.accepted_path(), &accepted, 0o600)
}

#[derive(Clone, Debug, Serialize)]
pub struct AcceptReport {
    pub path: String,
    pub action: &'static str,
    pub severity: Severity,
}

fn record_for_path(path: &Path, max_bytes: u64) -> Result<Record, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("stat failed: {error}"))?;
    let mode = metadata.mode() & 0o7777;
    let mtime = metadata.mtime();
    let mtime_ns = metadata.mtime_nsec().max(0) as u32;
    let path_string = path.display().to_string();

    let file_type = metadata.file_type();
    if file_type.is_dir() {
        return Ok(Record {
            path: path_string,
            kind: Kind::Dir,
            size: 0,
            mode,
            mtime,
            mtime_ns,
            hash: None,
        });
    }
    if file_type.is_file() {
        let hashed = hash_file(path, metadata.len(), max_bytes, mtime, mtime_ns)?;
        return Ok(Record {
            path: path_string,
            kind: Kind::File,
            size: hashed.size,
            mode,
            mtime: hashed.mtime,
            mtime_ns: hashed.mtime_ns,
            hash: Some(hashed.hash),
        });
    }
    if file_type.is_symlink() {
        let target = fs::read_link(path).map_err(|error| format!("readlink failed: {error}"))?;
        return Ok(Record {
            path: path_string,
            kind: Kind::Symlink,
            size: metadata.len(),
            mode,
            mtime,
            mtime_ns,
            hash: Some(
                blake3::hash(target.as_os_str().as_bytes())
                    .to_hex()
                    .to_string(),
            ),
        });
    }
    Ok(Record {
        path: path_string,
        kind: Kind::Other,
        size: metadata.len(),
        mode,
        mtime,
        mtime_ns,
        hash: None,
    })
}

/// Approves the current state of one path and folds it into the baseline so
/// it stops alerting. The alert history is preserved.
pub fn accept_path(cfg: &Config, path: &Path) -> Result<AcceptReport, String> {
    if !path.is_absolute() {
        return Err("the path to accept must be absolute".to_string());
    }
    // Symlinks are recorded at their own path; canonicalize would follow the
    // link and target the destination instead of the link record.
    let is_link = fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false);
    let normalized = if is_link {
        path.to_path_buf()
    } else {
        fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    };
    let path_string = normalized.display().to_string();

    let within_roots = cfg
        .roots
        .iter()
        .any(|root| path_is_within(&path_string, &root.display().to_string()));
    if !within_roots {
        return Err(format!("'{path_string}' is not under a monitored root"));
    }
    if is_excluded(&normalized, &effective_excludes(cfg)) {
        return Err(format!("'{path_string}' is excluded from monitoring"));
    }

    let mut baseline = load_baseline(&cfg.baseline_path)?;
    if !baseline_matches_config(&baseline, cfg) {
        return Err(
            "the baseline was created with different roots or excludes; re-run --init first"
                .to_string(),
        );
    }

    let severity = crate::config::severity_for_path(&path_string, &cfg.severity_rules);

    let position = baseline
        .entries
        .binary_search_by(|record| record.path.as_str().cmp(&path_string));
    let exists_on_disk = normalized.exists() || fs::symlink_metadata(&normalized).is_ok();

    let action: &'static str = match (position, exists_on_disk) {
        (Ok(index), true) => {
            let record = record_for_path(&normalized, cfg.max_file_bytes)?;
            let had_hash = baseline.entries[index].hash.is_some();
            let now_hash = record.hash.is_some();
            let unchanged = baseline.entries[index].kind == record.kind
                && baseline.entries[index].mode == record.mode
                && baseline.entries[index].size == record.size
                && had_hash == now_hash
                && baseline.entries[index].hash == record.hash;
            if unchanged {
                "already-current"
            } else {
                baseline.entries[index] = record;
                "updated"
            }
        }
        (Ok(index), false) => {
            baseline.entries.remove(index);
            "removed"
        }
        (Err(index), true) => {
            let record = record_for_path(&normalized, cfg.max_file_bytes)?;
            baseline.entries.insert(index, record);
            "recorded"
        }
        (Err(_), false) => {
            return Err(format!(
                "'{path_string}' is not in the baseline and no longer exists on disk"
            ));
        }
    };

    // Adding or removing a file also bumps the parent directory mtimes.
    // Approving the file settles those side effects, since the directories
    // did not otherwise change.
    let mut ancestor = normalized.parent().map(Path::to_path_buf);
    while let Some(dir) = ancestor {
        let dir_string = dir.display().to_string();
        if let Ok(index) = baseline
            .entries
            .binary_search_by(|record| record.path.as_str().cmp(&dir_string))
        {
            if let Ok(record) = record_for_path(&dir, cfg.max_file_bytes) {
                if record.kind == Kind::Dir {
                    let old = &mut baseline.entries[index];
                    let only_mtime = old.kind == Kind::Dir
                        && old.mode == record.mode
                        && old.size == record.size
                        && old.hash.is_none()
                        && record.hash.is_none()
                        && (old.mtime != record.mtime || old.mtime_ns != record.mtime_ns);
                    if only_mtime {
                        *old = record;
                    }
                }
            }
        }
        ancestor = dir.parent().map(Path::to_path_buf);
    }

    write_json_atomic(&cfg.baseline_path, &baseline, 0o600)?;
    mark_accepted(cfg, &path_string)?;

    Ok(AcceptReport {
        path: path_string,
        action,
        severity,
    })
}

// ---------------------------------------------------------------------------
// Maintenance window
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaintenanceState {
    pub until: u64,
    pub note: String,
}

pub fn set_maintenance(cfg: &Config, minutes: u64, note: &str) -> Result<(), String> {
    if minutes == 0 {
        let _ = fs::remove_file(cfg.maintenance_path());
        return Ok(());
    }
    let state = MaintenanceState {
        until: now().saturating_add(minutes * 60),
        note: note.to_string(),
    };
    write_json_atomic(&cfg.maintenance_path(), &state, 0o600)
}

pub fn maintenance_active(cfg: &Config) -> Option<MaintenanceState> {
    let bytes = fs::read(cfg.maintenance_path()).ok()?;
    let state: MaintenanceState = serde_json::from_slice(&bytes).ok()?;
    if now() < state.until {
        Some(state)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{test_config, Config, Severity, SeverityRule};
    use crate::util::{ensure_parent, write_json_atomic};

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

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rpi-aide-{}-{}-{}",
            name.replace('/', "-"),
            std::process::id(),
            now()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write file");
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
    fn baseline_meta_validates_format_and_version() {
        let base = temp_dir("meta");
        let config = Config {
            roots: vec![PathBuf::from("/etc")],
            baseline_path: base.join("baseline.json"),
            exclude: Vec::new(),
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
        let base = temp_dir("alerts");
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
            severity: Severity::Info,
            expected: false,
            chain: None,
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
    fn unscanned_files_do_not_become_deleted_alerts() {
        let previous = vec![
            record("/etc/a", Kind::File, 0o644, Some("aa")),
            record("/etc/b", Kind::File, 0o644, Some("bb")),
        ];
        let errors = vec![ScanError {
            path: "/etc/a".to_string(),
            message: "open failed: permission denied".to_string(),
        }];
        let detected = diff_entries_scanned(&previous, &[], &errors);
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].kind, ChangeKind::Deleted);
        assert_eq!(detected[0].path, "/etc/b");
    }

    #[test]
    fn unscanned_directories_suppress_descendant_deletions() {
        let previous = vec![
            record("/srv/a", Kind::File, 0o644, Some("aa")),
            record("/srv/b", Kind::File, 0o644, Some("bb")),
        ];
        let errors = vec![ScanError {
            path: "/srv".to_string(),
            message: "read_dir failed".to_string(),
        }];
        assert!(diff_entries_scanned(&previous, &[], &errors).is_empty());
    }

    #[test]
    fn path_prefix_matching_is_component_aware() {
        assert!(path_is_within("/srv/a", "/srv"));
        assert!(path_is_within("/srv", "/srv"));
        assert!(path_is_within("/etc/passwd", "/"));
        assert!(!path_is_within("/srv2/a", "/srv"));
        assert!(!path_is_within("/etc", "/etc/passwd"));
    }

    #[test]
    fn default_excludes_pihole_databases() {
        let excludes = Config::default().exclude;
        for path in [
            "/etc/pihole/pihole-FTL.db",
            "/etc/pihole/pihole-FTL.db-wal",
            "/etc/pihole/pihole-FTL.db-shm",
            "/etc/pihole/gravity.db",
            "/etc/pihole/gravity.db-wal",
            "/etc/pihole/gravity.db-shm",
            "/etc/pihole/gravity_old.db",
            "/etc/rpi-aide",
        ] {
            assert!(
                is_excluded(Path::new(path), &excludes),
                "default excludes must include {path}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Cache and fast scans
    // -----------------------------------------------------------------------

    #[test]
    fn fast_scan_reuses_hashes_and_detects_changes() {
        let base = temp_dir("fastscan");
        let cfg = test_config(&base);
        let root = base.join("root");
        write_file(&root.join("a.txt"), "alpha");
        write_file(&root.join("b.txt"), "bravo");

        perform_init(&cfg, false).expect("init");
        let first = load_cache(&cfg);
        assert_eq!(first.entries.len(), 2);

        // A full scan rehashes everything.
        let outcome = scan_filesystem(&cfg, None).expect("full scan");
        assert_eq!(outcome.stats.hashed, 2);
        assert_eq!(outcome.stats.reused, 0);

        // A fast scan with the cache rehashes nothing.
        let prior = load_cache(&cfg);
        let outcome = scan_filesystem(&cfg, Some(&prior.entries)).expect("fast scan");
        assert_eq!(outcome.stats.reused, 2);
        assert_eq!(outcome.stats.hashed, 0);

        // Changing one file forces a rehash of only that file.
        write_file(&root.join("a.txt"), "alpha-changed");
        let prior = load_cache(&cfg);
        let outcome = scan_filesystem(&cfg, Some(&prior.entries)).expect("fast scan 2");
        assert_eq!(outcome.stats.reused, 1);
        assert_eq!(outcome.stats.hashed, 1);

        // The alert appears in a fast check and disappears after accepting.
        let outcome = perform_check(&cfg, 1, false, "watch").expect("check");
        assert_eq!(outcome.summary.added + outcome.summary.modified, 1);
        assert_eq!(outcome.summary.files_reused, 1);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn scan_should_be_full_when_cache_is_stale() {
        let base = temp_dir("stale");
        let cfg = test_config(&base);
        write_file(&base.join("root/a.txt"), "a");
        perform_init(&cfg, false).expect("init");
        assert!(!scan_should_be_full(&cfg));

        let mut cache = load_cache(&cfg);
        cache.last_full_scan = now().saturating_sub(cfg.full_scan_interval_secs + 10);
        write_cache(&cfg, &cache).expect("write cache");
        assert!(scan_should_be_full(&cfg));

        let _ = fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------------
    // Chain
    // -----------------------------------------------------------------------

    fn sample_alert(id: u64, path: &str) -> Alert {
        Alert {
            id,
            kind: ChangeKind::Modified,
            path: path.to_string(),
            detected_at: now(),
            changes: vec!["content".to_string()],
            old_hash: Some("aa".to_string()),
            new_hash: Some("bb".to_string()),
            size: Some(3),
            mode: "0644".to_string(),
            baseline_created_at: 1,
            severity: Severity::Warning,
            expected: false,
            chain: None,
        }
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let base = temp_dir("chain");
        let cfg = test_config(&base);
        ensure_parent(&cfg.alerts_path).expect("parent");

        let mut batch = vec![sample_alert(1, "/etc/one"), sample_alert(2, "/etc/two")];
        append_alerts(&cfg, &mut batch).expect("append");
        verify_alerts_chain(&cfg).expect("clean chain verifies");

        let raw = fs::read_to_string(&cfg.alerts_path).expect("read log");
        let mut lines: Vec<String> = raw
            .lines()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"chain\""));

        // Tamper with the first record's path.
        let mut value: serde_json::Value =
            serde_json::from_str(&lines[0]).expect("parse first line");
        value["path"] = serde_json::json!("/etc/tampered");
        lines[0] = serde_json::to_string(&value).expect("re-encode");
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(&cfg.alerts_path, text).expect("write tampered log");
        assert!(
            verify_alerts_chain(&cfg).is_err(),
            "tampering must be caught"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn chain_skips_legacy_lines_and_rotates() {
        let base = temp_dir("legacy");
        let cfg = test_config(&base);
        ensure_parent(&cfg.alerts_path).expect("parent");

        let legacy = Alert {
            id: 0,
            kind: ChangeKind::Added,
            path: "/etc/legacy".to_string(),
            detected_at: 1,
            changes: Vec::new(),
            old_hash: None,
            new_hash: None,
            size: None,
            mode: "0644".to_string(),
            baseline_created_at: 1,
            severity: Severity::Info,
            expected: false,
            chain: None,
        };
        let line = serde_json::to_string(&legacy).expect("encode legacy");
        fs::write(&cfg.alerts_path, format!("{line}\n")).expect("write legacy");

        let mut batch = vec![sample_alert(1, "/etc/one")];
        append_alerts(&cfg, &mut batch).expect("append after legacy");
        let outcome = verify_alerts_chain(&cfg).expect("legacy lines are skipped");
        assert!(outcome.contains("1 legacy"));

        // Rotation: force a rotate with a tiny limit and verify continuity.
        let mut batch = vec![sample_alert(2, "/etc/two")];
        append_alerts_with_limit(&cfg, &mut batch, 1).expect("append with rotate");
        assert!(cfg.alerts_path.with_file_name("alerts.jsonl.1").exists());
        verify_alerts_chain(&cfg).expect("chain continues across rotation");
        let raw = fs::read_to_string(&cfg.alerts_path).expect("read log");
        assert!(!raw.contains("/etc/legacy"));
        assert!(raw.contains("/etc/two"));

        let _ = fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------------
    // Accept
    // -----------------------------------------------------------------------

    #[test]
    fn accept_folds_a_change_into_the_baseline() {
        let base = temp_dir("accept");
        let cfg = test_config(&base);
        let root = base.join("root");
        write_file(&root.join("keep.conf"), "stable");
        write_file(&root.join("edit.conf"), "one");
        perform_init(&cfg, false).expect("init");

        write_file(&root.join("edit.conf"), "two");
        let outcome = perform_check(&cfg, 1, false, "manual").expect("check");
        assert_eq!(outcome.summary.modified, 1);

        let report = accept_path(&cfg, &root.join("edit.conf")).expect("accept");
        assert_eq!(report.action, "updated");

        let outcome = perform_check(&cfg, 10, false, "manual").expect("check after accept");
        assert_eq!(
            outcome.summary.added + outcome.summary.modified + outcome.summary.deleted,
            0
        );

        let accepted = accepted_map(&cfg);
        assert!(accepted.contains_key(&report.path));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn accept_handles_deletions_and_new_files() {
        let base = temp_dir("accept2");
        let cfg = test_config(&base);
        let root = base.join("root");
        write_file(&root.join("doomed.conf"), "gone soon");
        write_file(&root.join("stay.conf"), "stays");
        perform_init(&cfg, false).expect("init");

        fs::remove_file(root.join("doomed.conf")).expect("remove file");
        let report = accept_path(&cfg, &root.join("doomed.conf")).expect("accept deletion");
        assert_eq!(report.action, "removed");
        let outcome = perform_check(&cfg, 1, false, "manual").expect("check");
        assert_eq!(outcome.summary.deleted, 0);

        write_file(&root.join("fresh.conf"), "brand new");
        let outcome = perform_check(&cfg, 10, false, "manual").expect("check with addition");
        assert_eq!(outcome.summary.added, 1);
        let report = accept_path(&cfg, &root.join("fresh.conf")).expect("accept addition");
        assert_eq!(report.action, "recorded");
        let outcome = perform_check(&cfg, 20, false, "manual").expect("clean check");
        assert!(
            outcome.summary.ok,
            "accepting a new file must also settle the parent directory mtime"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn accept_rejects_paths_outside_the_roots() {
        let base = temp_dir("accept3");
        let cfg = test_config(&base);
        write_file(&base.join("root/a.conf"), "a");
        perform_init(&cfg, false).expect("init");

        assert!(accept_path(&cfg, Path::new("/etc/passwd")).is_err());
        assert!(accept_path(&cfg, Path::new("relative/path")).is_err());
        assert!(accept_path(&cfg, &base.join("outside.conf")).is_err());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn accepted_alerts_are_marked_in_the_sidecar() {
        let base = temp_dir("accept4");
        let cfg = test_config(&base);
        let root = base.join("root");
        write_file(&root.join("a.conf"), "a");
        perform_init(&cfg, false).expect("init");
        write_file(&root.join("a.conf"), "b");
        let outcome = perform_check(&cfg, 1, false, "manual").expect("check");
        let alert = outcome.alerts[0].clone();

        accept_path(&cfg, &root.join("a.conf")).expect("accept");
        let accepted = accepted_map(&cfg);
        let accepted_at = accepted.get(&alert.path).copied().unwrap_or(0);
        assert!(accepted_at >= alert.detected_at);

        let _ = fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------------

    #[test]
    fn maintenance_window_activates_and_expires() {
        let base = temp_dir("maint");
        let cfg = test_config(&base);
        assert!(maintenance_active(&cfg).is_none());

        set_maintenance(&cfg, 30, "apt upgrade").expect("set");
        let active = maintenance_active(&cfg).expect("active");
        assert_eq!(active.note, "apt upgrade");

        let state = MaintenanceState {
            until: now().saturating_sub(1),
            note: "stale".to_string(),
        };
        write_json_atomic(&cfg.maintenance_path(), &state, 0o600).expect("write stale");
        assert!(maintenance_active(&cfg).is_none());

        set_maintenance(&cfg, 0, "").expect("clear");
        assert!(!cfg.maintenance_path().exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn maintenance_alerts_are_flagged_expected() {
        let base = temp_dir("maint2");
        let cfg = test_config(&base);
        let root = base.join("root");
        write_file(&root.join("a.conf"), "a");
        perform_init(&cfg, false).expect("init");

        set_maintenance(&cfg, 10, "test window").expect("set");
        write_file(&root.join("a.conf"), "b");
        let outcome = perform_check(&cfg, 1, false, "manual").expect("check");
        assert_eq!(outcome.alerts.len(), 1);
        assert!(outcome.alerts[0].expected);

        set_maintenance(&cfg, 0, "").expect("clear");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn severity_is_attached_to_new_alerts() {
        let base = temp_dir("sev");
        let cfg = Config {
            roots: vec![base.join("root")],
            baseline_path: base.join("baseline.json"),
            alerts_path: base.join("alerts.jsonl"),
            severity_rules: vec![SeverityRule::prefix("/etc/ssh", Severity::Critical)],
            ..Config::default()
        };

        let alert = sample_alert(1, "/etc/ssh/sshd_config");
        let severity = crate::config::severity_for_path(&alert.path, &cfg.severity_rules);
        assert_eq!(severity, Severity::Critical);

        let _ = fs::remove_dir_all(&base);
    }
}
