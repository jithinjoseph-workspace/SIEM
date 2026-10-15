use crate::buffer::AgentBuffer;
use sha2::{Digest, Sha256};
use siem_core::{EventSource, RawEvent};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
#[allow(unused_imports)]
use tracing::{error, info, warn};

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct WhoDataInfo {
    pub user_name: Option<String>,
    pub user_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub parent_name: Option<String>,
    pub audit_uid: Option<u32>,
}

impl WhoDataInfo {
    /// Attempt to resolve process and user context for a path using Linux /proc and audit facilities
    pub fn resolve_for_path(_path: &Path) -> Self {
        #[cfg(target_os = "linux")]
        {
            // Look for matching process in /proc that might be accessing the file
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let file_name = entry.file_name();
                    let pid_str = file_name.to_string_lossy();
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        // Check if /proc/[pid]/fd contains target path
                        let fd_dir = entry.path().join("fd");
                        if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                            for fd in fds.flatten() {
                                if let Ok(target) = std::fs::read_link(fd.path()) {
                                    if target == _path {
                                        let pname = std::fs::read_to_string(entry.path().join("comm"))
                                            .map(|s| s.trim().to_string())
                                            .ok();
                                        let ppid = std::fs::read_to_string(entry.path().join("status"))
                                            .ok()
                                            .and_then(|status| {
                                                for line in status.lines() {
                                                    if line.starts_with("PPid:") {
                                                        return line.split_whitespace().nth(1)?.parse::<u32>().ok();
                                                    }
                                                }
                                                None
                                            });
                                        let (uid, uname) = std::fs::read_to_string(entry.path().join("status"))
                                            .ok()
                                            .and_then(|status| {
                                                for line in status.lines() {
                                                    if line.starts_with("Uid:") {
                                                        let u = line.split_whitespace().nth(1)?.parse::<u32>().ok()?;
                                                        let name = if u == 0 { "root".into() } else { format!("user-{}", u) };
                                                        return Some((u, name));
                                                    }
                                                }
                                                None
                                            })
                                            .unwrap_or((0, "root".into()));

                                        return WhoDataInfo {
                                            user_name: Some(uname),
                                            user_id: Some(uid),
                                            process_name: pname,
                                            process_id: Some(pid),
                                            parent_process_id: ppid,
                                            parent_name: None,
                                            audit_uid: Some(uid),
                                        };
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        WhoDataInfo::default()
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FileRecord {
    hash: String,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

pub struct SyscheckEngine {
    agent_id: String,
    monitored_paths: Vec<PathBuf>,
    baseline: HashMap<PathBuf, FileRecord>,
}

impl SyscheckEngine {
    pub fn new(agent_id: String, paths: Vec<PathBuf>) -> Self {
        Self {
            agent_id,
            monitored_paths: paths,
            baseline: HashMap::new(),
        }
    }

    /// Extract POSIX file metadata (mode, uid, gid) mirroring Wazuh create_db.c
    pub fn get_file_metadata(path: &Path) -> (u32, u32, u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = path.metadata() {
                return (meta.mode(), meta.uid(), meta.gid());
            }
        }
        #[cfg(not(unix))]
        let _ = path;
        (0o644, 0, 0)
    }

    /// Calculate SHA256 checksum and size of a file
    pub fn compute_sha256(path: &Path) -> Option<(String, u64)> {
        let mut file = File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0u64;

        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buffer[..n]);
                    total_bytes += n as u64;
                }
                Err(_) => return None,
            }
        }

        let result = hasher.finalize();
        Some((hex::encode(result), total_bytes))
    }

    /// Build initial baseline of monitored paths
    pub fn build_baseline(&mut self) {
        for path in &self.monitored_paths {
            if path.is_file() {
                if let Some((hash, size)) = Self::compute_sha256(path) {
                    let (mode, uid, gid) = Self::get_file_metadata(path);
                    self.baseline.insert(path.clone(), FileRecord { hash, size, mode, uid, gid });
                }
            } else if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if entry_path.is_file() {
                            if let Some((hash, size)) = Self::compute_sha256(&entry_path) {
                                let (mode, uid, gid) = Self::get_file_metadata(&entry_path);
                                self.baseline.insert(entry_path, FileRecord { hash, size, mode, uid, gid });
                            }
                        }
                    }
                }
            }
        }
        info!("wazuh-syscheckd: Baseline computed with {} tracked files (hashes + POSIX metadata)", self.baseline.len());
    }

    /// Handle single file change event (e.g. from inotify real-time trigger)
    #[allow(dead_code)]
    pub async fn handle_file_event(&mut self, path: &Path, buffer: &AgentBuffer, action_hint: Option<&str>) {
        let who = WhoDataInfo::resolve_for_path(path);

        if path.exists() && path.is_file() {
            if let Some((new_hash, new_size)) = Self::compute_sha256(path) {
                let (new_mode, new_uid, new_gid) = Self::get_file_metadata(path);
                let new_record = FileRecord {
                    hash: new_hash.clone(),
                    size: new_size,
                    mode: new_mode,
                    uid: new_uid,
                    gid: new_gid,
                };

                match self.baseline.get(path) {
                    Some(old_record) => {
                        if old_record.hash != new_hash {
                            let mut msg = format!(
                                "syscheckd: File integrity check: Integrity checksum changed for '{}' (Old SHA256: {} -> New SHA256: {})",
                                path.display(),
                                &old_record.hash[..8.min(old_record.hash.len())],
                                &new_hash[..8.min(new_hash.len())]
                            );
                            if let Some(ref u) = who.user_name {
                                msg.push_str(&format!(" by user '{}' (UID: {})", u, who.user_id.unwrap_or(0)));
                            }
                            if let Some(ref p) = who.process_name {
                                msg.push_str(&format!(" via process '{}' [PID: {}]", p, who.process_id.unwrap_or(0)));
                            }
                            info!("{}", msg);

                            let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/integrity", msg);
                            event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                            event.metadata.insert("action".into(), "modified".into());
                            event.metadata.insert("old_hash".into(), old_record.hash.clone());
                            event.metadata.insert("new_hash".into(), new_hash);
                            event.metadata.insert("os_type".into(), "linux".into());
                            event.metadata.insert("detection_mode".into(), "realtime-inotify".into());
                            if let Some(u) = who.user_name { event.metadata.insert("who_user".into(), u); }
                            if let Some(uid) = who.user_id { event.metadata.insert("who_uid".into(), uid.to_string()); }
                            if let Some(p) = who.process_name { event.metadata.insert("who_process".into(), p); }
                            if let Some(pid) = who.process_id { event.metadata.insert("who_pid".into(), pid.to_string()); }
                            buffer.push(event).await;
                        } else if old_record.mode != new_mode {
                            let msg = format!(
                                "syscheckd: File integrity check: Permissions changed for '{}' (Old Mode: {:o} -> New Mode: {:o})",
                                path.display(),
                                old_record.mode & 0o7777,
                                new_mode & 0o7777
                            );
                            warn!("{}", msg);

                            let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/permissions", msg);
                            event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                            event.metadata.insert("action".into(), "permission_change".into());
                            event.metadata.insert("old_mode".into(), format!("{:o}", old_record.mode & 0o7777));
                            event.metadata.insert("new_mode".into(), format!("{:o}", new_mode & 0o7777));
                            event.metadata.insert("os_type".into(), "linux".into());
                            buffer.push(event).await;
                        }
                    }
                    None => {
                        let mut msg = format!(
                            "syscheckd: File integrity check: New file added to monitored location '{}' (SHA256: {})",
                            path.display(),
                            &new_hash[..8.min(new_hash.len())]
                        );
                        if let Some(ref u) = who.user_name {
                            msg.push_str(&format!(" by user '{}'", u));
                        }
                        info!("{}", msg);

                        let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/integrity", msg);
                        event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                        event.metadata.insert("action".into(), "added".into());
                        event.metadata.insert("new_hash".into(), new_hash);
                        event.metadata.insert("os_type".into(), "linux".into());
                        event.metadata.insert("detection_mode".into(), "realtime-inotify".into());
                        buffer.push(event).await;
                    }
                }
                self.baseline.insert(path.to_path_buf(), new_record);
            }
        } else if action_hint == Some("deleted") || !path.exists() {
            if let Some(old_record) = self.baseline.remove(path) {
                let msg = format!(
                    "syscheckd: File integrity check: Monitored file was deleted '{}' (Prior SHA256: {})",
                    path.display(),
                    &old_record.hash[..8.min(old_record.hash.len())]
                );
                warn!("{}", msg);

                let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/integrity", msg);
                event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                event.metadata.insert("action".into(), "deleted".into());
                event.metadata.insert("os_type".into(), "linux".into());
                event.metadata.insert("detection_mode".into(), "realtime-inotify".into());
                buffer.push(event).await;
            }
        }
    }

    /// Full periodic scan and comparison (scheduled sweep)
    pub async fn check_changes(&mut self, buffer: &AgentBuffer) {
        let mut current_state: HashMap<PathBuf, FileRecord> = HashMap::new();

        for path in &self.monitored_paths {
            if path.is_file() {
                if let Some((hash, size)) = Self::compute_sha256(path) {
                    let (mode, uid, gid) = Self::get_file_metadata(path);
                    current_state.insert(path.clone(), FileRecord { hash, size, mode, uid, gid });
                }
            } else if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if entry_path.is_file() {
                            if let Some((hash, size)) = Self::compute_sha256(&entry_path) {
                                let (mode, uid, gid) = Self::get_file_metadata(&entry_path);
                                current_state.insert(entry_path, FileRecord { hash, size, mode, uid, gid });
                            }
                        }
                    }
                }
            }
        }

        // Detect modified or added files
        for (path, record) in &current_state {
            match self.baseline.get(path) {
                Some(old_record) => {
                    if old_record.hash != record.hash {
                        let msg = format!(
                            "syscheckd: File integrity check: Integrity checksum changed for '{}' (Old SHA256: {} -> New SHA256: {})",
                            path.display(),
                            &old_record.hash[..8.min(old_record.hash.len())],
                            &record.hash[..8.min(record.hash.len())]
                        );
                        info!("{}", msg);

                        let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/integrity", msg);
                        event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                        event.metadata.insert("action".into(), "modified".into());
                        event.metadata.insert("old_hash".into(), old_record.hash.clone());
                        event.metadata.insert("new_hash".into(), record.hash.clone());
                        event.metadata.insert("os_type".into(), "linux".into());
                        buffer.push(event).await;
                    }
                    if old_record.mode != record.mode {
                        let msg = format!(
                            "syscheckd: File integrity check: Permissions changed for '{}' (Old Mode: {:o} -> New Mode: {:o})",
                            path.display(),
                            old_record.mode & 0o7777,
                            record.mode & 0o7777
                        );
                        warn!("{}", msg);

                        let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/permissions", msg);
                        event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                        event.metadata.insert("action".into(), "permission_change".into());
                        event.metadata.insert("old_mode".into(), format!("{:o}", old_record.mode & 0o7777));
                        event.metadata.insert("new_mode".into(), format!("{:o}", record.mode & 0o7777));
                        event.metadata.insert("os_type".into(), "linux".into());
                        buffer.push(event).await;
                    }
                }
                None => {
                    let msg = format!(
                        "syscheckd: File integrity check: New file added to monitored location '{}' (SHA256: {})",
                        path.display(),
                        &record.hash[..8.min(record.hash.len())]
                    );
                    info!("{}", msg);

                    let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/integrity", msg);
                    event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                    event.metadata.insert("action".into(), "added".into());
                    event.metadata.insert("new_hash".into(), record.hash.clone());
                    event.metadata.insert("os_type".into(), "linux".into());
                    buffer.push(event).await;
                }
            }
        }

        // Detect deleted files
        for (path, old_record) in &self.baseline {
            if !current_state.contains_key(path) {
                let msg = format!(
                    "syscheckd: File integrity check: Monitored file was deleted '{}' (Prior SHA256: {})",
                    path.display(),
                    &old_record.hash[..8.min(old_record.hash.len())]
                );
                warn!("{}", msg);

                let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/integrity", msg);
                event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                event.metadata.insert("action".into(), "deleted".into());
                event.metadata.insert("os_type".into(), "linux".into());
                buffer.push(event).await;
            }
        }

        self.baseline = current_state;
    }
}

/// Spawns the Linux inotify real-time filesystem watcher (mirroring Wazuh run_realtime.c)
#[cfg(target_os = "linux")]
async fn run_inotify_realtime_loop(
    engine: Arc<Mutex<SyscheckEngine>>,
    paths: Vec<PathBuf>,
    buffer: Arc<AgentBuffer>,
) {
    use std::os::unix::io::FromRawFd;

    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if inotify_fd < 0 {
        warn!("wazuh-syscheckd: inotify_init1 failed with errno {}. Operating in standard polling mode.", std::io::Error::last_os_error());
        return;
    }

    let mut wd_to_path: HashMap<i32, PathBuf> = HashMap::new();
    let mask = libc::IN_MODIFY
        | libc::IN_ATTRIB
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF;

    for p in &paths {
        if let Ok(c_path) = std::ffi::CString::new(p.to_string_lossy().as_bytes()) {
            let wd = unsafe { libc::inotify_add_watch(inotify_fd, c_path.as_ptr(), mask) };
            if wd >= 0 {
                wd_to_path.insert(wd, p.clone());
            } else {
                warn!("wazuh-syscheckd: Failed to add inotify watch on {}: {}", p.display(), std::io::Error::last_os_error());
            }
        }
    }

    info!("wazuh-syscheckd: Linux real-time inotify watcher initialized for {} root targets", wd_to_path.len());

    let file = unsafe { File::from_raw_fd(inotify_fd) };
    let async_fd = match tokio::io::unix::AsyncFd::new(file) {
        Ok(afd) => afd,
        Err(e) => {
            error!("wazuh-syscheckd: Failed to register AsyncFd for inotify: {}", e);
            return;
        }
    };

    let mut raw_buf = [0u8; 8192];
    loop {
        match async_fd.readable().await {
            Ok(mut guard) => {
                let res = guard.try_io(|inner| {
                    use std::io::Read;
                    (&*inner.get_ref()).read(&mut raw_buf)
                });

                match res {
                    Ok(Ok(bytes_read)) if bytes_read > 0 => {
                        let mut offset = 0;
                        while offset + std::mem::size_of::<libc::inotify_event>() <= bytes_read {
                            let event_ptr = raw_buf[offset..].as_ptr() as *const libc::inotify_event;
                            let event = unsafe { &*event_ptr };
                            let name_len = event.len as usize;

                            let event_name = if name_len > 0 {
                                let name_bytes = &raw_buf[offset + std::mem::size_of::<libc::inotify_event>()..offset + std::mem::size_of::<libc::inotify_event>() + name_len];
                                let trimmed = name_bytes.split(|&b| b == 0).next().unwrap_or(name_bytes);
                                String::from_utf8_lossy(trimmed).to_string()
                            } else {
                                String::new()
                            };

                            if let Some(dir_path) = wd_to_path.get(&event.wd) {
                                let full_path = if event_name.is_empty() {
                                    dir_path.clone()
                                } else {
                                    dir_path.join(&event_name)
                                };

                                let action = if (event.mask & (libc::IN_DELETE | libc::IN_DELETE_SELF | libc::IN_MOVED_FROM)) != 0 {
                                    Some("deleted")
                                } else if (event.mask & (libc::IN_CREATE | libc::IN_MOVED_TO)) != 0 {
                                    Some("created")
                                } else {
                                    Some("modified")
                                };

                                let mut eng = engine.lock().await;
                                eng.handle_file_event(&full_path, &buffer, action).await;
                            }

                            offset += std::mem::size_of::<libc::inotify_event>() + name_len;
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                error!("wazuh-syscheckd: Async inotify read error: {}", e);
                break;
            }
        }
    }
}

/// Spawns the Linux Syscheckd / FIM worker task (combining Real-time inotify + Scheduled baseline verification)
pub fn spawn_syscheck_worker(
    agent_id: String,
    paths: Vec<PathBuf>,
    buffer: Arc<AgentBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut initial_engine = SyscheckEngine::new(agent_id, paths.clone());
        initial_engine.build_baseline();

        let shared_engine = Arc::new(Mutex::new(initial_engine));

        #[cfg(target_os = "linux")]
        {
            let rt_engine = shared_engine.clone();
            let rt_paths = paths.clone();
            let rt_buffer = buffer.clone();
            tokio::spawn(async move {
                run_inotify_realtime_loop(rt_engine, rt_paths, rt_buffer).await;
            });
        }

        // Scheduled periodic sweep loop (mirroring Wazuh's scheduled integrity check)
        loop {
            tokio::time::sleep(interval).await;
            let mut eng = shared_engine.lock().await;
            eng.check_changes(&buffer).await;
        }
    })
}
