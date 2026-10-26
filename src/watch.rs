//! Real-time watch: inotify on the configured directories. Events are
//! debounced and rate-limited server-side; a watch trigger runs a fast scan.

use std::collections::HashMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::{effective_excludes, is_excluded, Config};
use crate::util::warn;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchEvent {
    Changed,
    Overflow,
}

#[derive(Clone, Debug, Default)]
pub struct WatchStatus {
    pub active: bool,
    pub watches: usize,
    pub note: Option<String>,
}

const WATCH_MASK: u32 = libc::IN_MODIFY
    | libc::IN_ATTRIB
    | libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF;

struct Watcher {
    fd: i32,
    paths: HashMap<i32, PathBuf>,
    count: usize,
    max: usize,
    saturated: bool,
}

impl Watcher {
    fn add_dir(&mut self, path: &Path) -> bool {
        if self.count >= self.max {
            if !self.saturated {
                self.saturated = true;
                warn(&format!(
                    "watch: reached the cap of {} watches; new directories are not watched",
                    self.max
                ));
            }
            return false;
        }
        let wd = unsafe {
            libc::inotify_add_watch(
                self.fd,
                path.as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                WATCH_MASK,
            )
        };
        if wd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOSPC) && !self.saturated {
                self.saturated = true;
                warn(&format!(
                    "watch: the kernel watch limit is full; new directories are not watched ({error})"
                ));
            }
            return false;
        }
        if let Some(old) = self.paths.insert(wd, path.to_path_buf()) {
            if old != path {
                self.paths.insert(wd, old);
                return false;
            }
            return true;
        }
        self.count += 1;
        true
    }

    fn add_tree(&mut self, root: &Path, excludes: &[PathBuf]) {
        if !root.is_dir() {
            return;
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if is_excluded(&dir, excludes) {
                continue;
            }
            self.add_dir(&dir);
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() && !path.is_symlink() {
                        stack.push(path);
                    }
                }
            }
        }
    }
}

/// Starts the watcher thread. Returns immediately; `status` reports the
/// outcome. The thread exits when `stop` is set.
pub fn start_watch(
    cfg: &Config,
    tx: tokio::sync::mpsc::UnboundedSender<WatchEvent>,
    stop: Arc<AtomicBool>,
    status: Arc<Mutex<WatchStatus>>,
) {
    let paths: Vec<PathBuf> = cfg.watch.paths.clone();
    let excludes = effective_excludes(cfg);
    let max = cfg.watch.max_watches;

    std::thread::Builder::new()
        .name("rpi-aide-watch".into())
        .spawn(move || {
            let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                let mut state = status.lock().expect("watch status lock");
                state.note = Some(format!("inotify failed: {error}"));
                warn(&format!("watch: inotify failed: {error}"));
                return;
            }

            let mut watcher = Watcher {
                fd,
                paths: HashMap::new(),
                count: 0,
                max,
                saturated: false,
            };
            for path in &paths {
                watcher.add_tree(path, &excludes);
            }
            if watcher.count == 0 {
                let mut state = status.lock().expect("watch status lock");
                state.note = Some("no readable watch paths".to_string());
                warn("watch: no readable watch paths; real-time scanning is off");
                unsafe { libc::close(fd) };
                return;
            }

            {
                let mut state = status.lock().expect("watch status lock");
                state.active = true;
                state.watches = watcher.count;
            }
            crate::util::info(&format!("watch: {} directories watched", watcher.count));

            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let mut poll_fd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut poll_fd, 1, 200) };
                if ready < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    warn(&format!("watch: poll failed: {error}"));
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }
                if ready == 0 {
                    continue;
                }

                let read = unsafe {
                    libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len())
                };
                if read <= 0 {
                    continue;
                }
                let bytes = read as usize;
                let mut offset = 0usize;
                let header = std::mem::size_of::<libc::inotify_event>();
                while offset + header <= bytes {
                    let event =
                        unsafe { &*(buffer.as_ptr().add(offset) as *const libc::inotify_event) };
                    let name_len = event.len as usize;
                    let name_bytes =
                        &buffer[offset + header..(offset + header + name_len).min(bytes)];
                    let name = name_bytes
                        .split(|byte| *byte == 0)
                        .next()
                        .unwrap_or(&[])
                        .to_vec();
                    let name = String::from_utf8_lossy(&name).into_owned();

                    if event.mask & libc::IN_Q_OVERFLOW != 0 {
                        warn("watch: the event queue overflowed; a full scan is due");
                        let _ = tx.send(WatchEvent::Overflow);
                    } else {
                        if event.mask & libc::IN_ISDIR != 0
                            && (event.mask & (libc::IN_CREATE | libc::IN_MOVED_TO)) != 0
                        {
                            if let Some(parent) = watcher.paths.get(&event.wd) {
                                let child = if name.is_empty() {
                                    parent.clone()
                                } else {
                                    parent.join(&name)
                                };
                                watcher.add_tree(&child, &excludes);
                                let mut state = status.lock().expect("watch status lock");
                                state.watches = watcher.count;
                            }
                        }
                        let _ = tx.send(WatchEvent::Changed);
                    }

                    offset += header + name_len;
                }
            }

            unsafe { libc::close(fd) };
            status.lock().expect("watch status lock").active = false;
        })
        .expect("spawn watch thread");
}
