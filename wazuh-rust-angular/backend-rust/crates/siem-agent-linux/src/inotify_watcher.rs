use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tracing::info;

/// File Integrity Monitoring event action type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FimActionType {
    Added,
    Modified,
    Deleted,
    AttributesChanged,
}

impl FimActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::AttributesChanged => "permission_change",
        }
    }
}

/// A normalized file modification event emitted by the real-time watcher
#[derive(Debug, Clone)]
pub struct FimWatchEvent {
    pub path: PathBuf,
    pub action: FimActionType,
    pub is_dir: bool,
    pub timestamp: SystemTime,
}

/// Recursively discovers all subdirectories under `root` up to `max_depth`
pub fn discover_directories_recursive(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if !root.exists() {
        return dirs;
    }

    if root.is_dir() {
        dirs.push(root.to_path_buf());
        collect_subdirs(root, 1, max_depth, &mut dirs);
    }

    dirs
}

fn collect_subdirs(dir: &Path, current_depth: usize, max_depth: usize, acc: &mut Vec<PathBuf>) {
    if current_depth > max_depth {
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            acc.push(path.clone());
            collect_subdirs(&path, current_depth + 1, max_depth, acc);
        }
    }
}

/// Linux Real-Time inotify watcher with recursive subfolder watching and dynamic folder insertion
pub struct LinuxInotifyWatcher {
    #[cfg(target_os = "linux")]
    inotify_fd: i32,
    #[cfg(target_os = "linux")]
    wd_to_path: HashMap<i32, PathBuf>,
    #[cfg(target_os = "linux")]
    path_to_wd: HashMap<PathBuf, i32>,
    #[allow(dead_code)]
    debounce_cache: HashMap<PathBuf, Instant>,
    #[allow(dead_code)]
    debounce_duration: Duration,
    tx_events: mpsc::Sender<FimWatchEvent>,
}

impl LinuxInotifyWatcher {
    /// Initialize inotify watcher instance and hook channel receiver
    pub fn new(tx_events: mpsc::Sender<FimWatchEvent>) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
            if inotify_fd < 0 {
                return Err(format!("Failed to initialize inotify: errno {}", std::io::Error::last_os_error()));
            }

            Ok(Self {
                inotify_fd,
                wd_to_path: HashMap::new(),
                path_to_wd: HashMap::new(),
                debounce_cache: HashMap::new(),
                debounce_duration: Duration::from_millis(100),
                tx_events,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {
                debounce_cache: HashMap::new(),
                debounce_duration: Duration::from_millis(100),
                tx_events,
            })
        }
    }

    /// Recursively attach inotify watches across a directory tree
    pub fn watch_tree(&mut self, root: &Path) {
        let all_dirs = discover_directories_recursive(root, 64);
        let count = all_dirs.len();

        for dir in all_dirs {
            self.add_single_watch(&dir);
        }

        if root.is_file() {
            self.add_single_watch(root);
        }

        info!(
            "wazuh-syscheckd: inotify recursive watch established on '{}' ({} nested directories tracked)",
            root.display(),
            count
        );
    }

    /// Add a watch descriptor for a single directory or file
    fn add_single_watch(&mut self, path: &Path) {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;

            if self.path_to_wd.contains_key(path) {
                return;
            }

            let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
                return;
            };

            let mask = libc::IN_MODIFY
                | libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_ATTRIB
                | libc::IN_DELETE_SELF;

            let wd = unsafe { libc::inotify_add_watch(self.inotify_fd, c_path.as_ptr(), mask) };
            if wd >= 0 {
                let pb = path.to_path_buf();
                self.wd_to_path.insert(wd, pb.clone());
                self.path_to_wd.insert(pb, wd);
                debug!("wazuh-syscheckd: inotify added watch [wd={}] for '{}'", wd, path.display());
            } else {
                debug!("wazuh-syscheckd: Could not attach inotify watch to '{}': {}", path.display(), std::io::Error::last_os_error());
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = path;
    }

    /// Read pending inotify events from kernel buffer
    pub async fn poll_events(&mut self) {
        #[cfg(target_os = "linux")]
        {
            const BUF_SIZE: usize = 4096 * (std::mem::size_of::<libc::inotify_event>() + 256);
            let mut buf = vec![0u8; BUF_SIZE];

            let bytes_read = unsafe { libc::read(self.inotify_fd, buf.as_mut_ptr() as *mut libc::c_void, BUF_SIZE) };
            if bytes_read <= 0 {
                return;
            }

            let mut offset = 0;
            while offset < bytes_read as usize {
                let event = unsafe { &*(buf.as_ptr().add(offset) as *const libc::inotify_event) };
                let wd = event.wd;
                let mask = event.mask;
                let name_len = event.len as usize;

                let file_name = if name_len > 0 {
                    let name_bytes = &buf[offset + std::mem::size_of::<libc::inotify_event>()..offset + std::mem::size_of::<libc::inotify_event>() + name_len];
                    let nul_pos = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
                    String::from_utf8_lossy(&name_bytes[..nul_pos]).to_string()
                } else {
                    String::new()
                };

                offset += std::mem::size_of::<libc::inotify_event>() + name_len;

                // Handle directory deletion / watch invalidation
                if (mask & libc::IN_IGNORED) != 0 || (mask & libc::IN_DELETE_SELF) != 0 {
                    if let Some(removed_path) = self.wd_to_path.remove(&wd) {
                        self.path_to_wd.remove(&removed_path);
                    }
                    continue;
                }

                let Some(parent_path) = self.wd_to_path.get(&wd).cloned() else {
                    continue;
                };

                let target_path = if file_name.is_empty() {
                    parent_path.clone()
                } else {
                    parent_path.join(file_name)
                };

                let is_dir = (mask & libc::IN_ISDIR) != 0;

                // If a new directory is created inside any watched path, automatically watch it!
                if is_dir && ((mask & libc::IN_CREATE) != 0 || (mask & libc::IN_MOVED_TO) != 0) {
                    info!("wazuh-syscheckd: Dynamic subfolder creation detected. Watching '{}' recursively.", target_path.display());
                    self.watch_tree(&target_path);
                }

                // Determine FIM action
                let action = if (mask & libc::IN_CREATE) != 0 || (mask & libc::IN_MOVED_TO) != 0 {
                    FimActionType::Added
                } else if (mask & libc::IN_DELETE) != 0 || (mask & libc::IN_MOVED_FROM) != 0 {
                    FimActionType::Deleted
                } else if (mask & libc::IN_ATTRIB) != 0 {
                    FimActionType::AttributesChanged
                } else {
                    FimActionType::Modified
                };

                // Debounce rapid bursts
                let now = Instant::now();
                if let Some(prev) = self.debounce_cache.get(&target_path) {
                    if now.duration_since(*prev) < self.debounce_duration && action == FimActionType::Modified {
                        continue;
                    }
                }
                self.debounce_cache.insert(target_path.clone(), now);

                let watch_evt = FimWatchEvent {
                    path: target_path,
                    action,
                    is_dir,
                    timestamp: SystemTime::now(),
                };

                let _ = self.tx_events.send(watch_evt).await;
            }

            // Prune old debounce entries periodically
            if self.debounce_cache.len() > 1000 {
                let now = Instant::now();
                self.debounce_cache.retain(|_, last| now.duration_since(*last) < Duration::from_secs(2));
            }
        }
    }

    /// Simulate manual event injection (for automated unit testing and cross-platform verification)
    pub async fn simulate_event(&mut self, event: FimWatchEvent) {
        let _ = self.tx_events.send(event).await;
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxInotifyWatcher {
    fn drop(&mut self) {
        if self.inotify_fd >= 0 {
            unsafe { libc::close(self.inotify_fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_directories_recursive() {
        let temp_dir = std::env::temp_dir().join(format!("test_inotify_rec_{}", uuid::Uuid::new_v4()));
        let sub1 = temp_dir.join("level1").join("level2").join("level3");
        let sub2 = temp_dir.join("branch_b").join("sub_b");

        std::fs::create_dir_all(&sub1).unwrap();
        std::fs::create_dir_all(&sub2).unwrap();

        // Discover up to depth 10
        let discovered = discover_directories_recursive(&temp_dir, 10);
        assert!(discovered.contains(&temp_dir));
        assert!(discovered.contains(&temp_dir.join("level1")));
        assert!(discovered.contains(&temp_dir.join("level1").join("level2")));
        assert!(discovered.contains(&sub1));
        assert!(discovered.contains(&temp_dir.join("branch_b")));
        assert!(discovered.contains(&sub2));

        // Discover with depth limit 1
        let shallow = discover_directories_recursive(&temp_dir, 1);
        assert!(shallow.contains(&temp_dir));
        assert!(shallow.contains(&temp_dir.join("level1")));
        assert!(shallow.contains(&temp_dir.join("branch_b")));
        assert!(!shallow.contains(&temp_dir.join("level1").join("level2")));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_watcher_channel_event_handling() {
        let (tx, mut rx) = mpsc::channel(100);
        let mut watcher = LinuxInotifyWatcher::new(tx).unwrap();

        let test_path = PathBuf::from("/etc/test_config.yaml");
        let evt = FimWatchEvent {
            path: test_path.clone(),
            action: FimActionType::Modified,
            is_dir: false,
            timestamp: SystemTime::now(),
        };

        watcher.simulate_event(evt).await;

        let received = rx.recv().await;
        assert!(received.is_some());
        let rec_evt = received.unwrap();
        assert_eq!(rec_evt.path, test_path);
        assert_eq!(rec_evt.action, FimActionType::Modified);
        assert_eq!(rec_evt.action.as_str(), "modified");
    }
}
