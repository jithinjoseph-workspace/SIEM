use crate::buffer::AgentBuffer;
use crate::inotify_watcher::{discover_directories_recursive, FimActionType, FimWatchEvent, LinuxInotifyWatcher};
use crate::whodata::{AuditWhodataEngine, WhodataInfo};
use sha2::{Digest, Sha256};
use siem_core::{EventSource, RawEvent};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub hash: String,
    #[allow(dead_code)]
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Linux Real-Time & Whodata File Integrity Monitoring Engine
pub struct SyscheckEngine {
    agent_id: String,
    monitored_paths: Vec<PathBuf>,
    baseline: HashMap<PathBuf, FileRecord>,
    whodata: Arc<AuditWhodataEngine>,
    watcher: Option<LinuxInotifyWatcher>,
    rx_events: Option<mpsc::Receiver<FimWatchEvent>>,
}

impl SyscheckEngine {
    /// Initialize with monitored paths and internal whodata engine
    pub fn new(agent_id: String, paths: Vec<PathBuf>) -> Self {
        let whodata = Arc::new(AuditWhodataEngine::new(1000));
        Self::with_whodata(agent_id, paths, whodata)
    }

    /// Initialize with an explicit Whodata engine (used for testing or shared audit stream)
    pub fn with_whodata(agent_id: String, paths: Vec<PathBuf>, whodata: Arc<AuditWhodataEngine>) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        let watcher = LinuxInotifyWatcher::new(tx).ok();

        Self {
            agent_id,
            monitored_paths: paths,
            baseline: HashMap::new(),
            whodata,
            watcher,
            rx_events: Some(rx),
        }
    }

    /// Access the underlying whodata engine
    #[allow(dead_code)]
    pub fn whodata_engine(&self) -> Arc<AuditWhodataEngine> {
        Arc::clone(&self.whodata)
    }

    /// Access the inotify watcher (if initialized)
    #[allow(dead_code)]
    pub fn watcher_mut(&mut self) -> Option<&mut LinuxInotifyWatcher> {
        self.watcher.as_mut()
    }

    /// Extract POSIX file metadata (mode, uid, gid).
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

    /// Build initial recursive baseline of all monitored roots and nested subdirectories
    pub fn build_baseline(&mut self) {
        let mut new_baseline = HashMap::new();

        for root in &self.monitored_paths {
            if root.is_file() {
                if let Some((hash, size)) = Self::compute_sha256(root) {
                    let (mode, uid, gid) = Self::get_file_metadata(root);
                    new_baseline.insert(root.clone(), FileRecord { hash, size, mode, uid, gid });
                }
                if let Some(w) = self.watcher.as_mut() {
                    w.watch_tree(root);
                }
            } else if root.is_dir() {
                // Recursive traversal: index files across all nested subdirectories
                let all_dirs = discover_directories_recursive(root, 64);
                for dir in &all_dirs {
                    if let Ok(entries) = std::fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            let entry_path = entry.path();
                            if entry_path.is_file() {
                                if let Some((hash, size)) = Self::compute_sha256(&entry_path) {
                                    let (mode, uid, gid) = Self::get_file_metadata(&entry_path);
                                    new_baseline.insert(entry_path, FileRecord { hash, size, mode, uid, gid });
                                }
                            }
                        }
                    }
                }
                if let Some(w) = self.watcher.as_mut() {
                    w.watch_tree(root);
                }
            }
        }

        info!(
            "provigil-syscheckd: Deep baseline computed with {} tracked files across all nested subdirectories",
            new_baseline.len()
        );

        self.baseline = new_baseline;
    }

    /// Process a real-time file event, recompute checksums, correlate whodata, and emit alert
    pub async fn handle_file_event(
        &mut self,
        path: &Path,
        buffer: &AgentBuffer,
        _hint: Option<FimActionType>,
    ) -> Option<RawEvent> {
        let path_buf = path.to_path_buf();
        let exists = path.is_file();

        if !exists {
            // Deleted file
            if let Some(old_record) = self.baseline.remove(&path_buf) {
                let whodata = self.whodata.correlate(path);
                let mode = if whodata.is_some() { "whodata" } else { "realtime" };

                let msg = if let Some(ref w) = whodata {
                    format!(
                        "syscheckd: [whodata] File deleted '{}' by user '{}' (UID: {:?}, Process: '{}' [PID: {:?}], Prior SHA256: {})",
                        path.display(),
                        w.user_name.as_deref().unwrap_or("unknown"),
                        w.user_id.unwrap_or(0),
                        w.process_name.as_deref().unwrap_or("unknown"),
                        w.process_id.unwrap_or(0),
                        &old_record.hash[..8]
                    )
                } else {
                    format!(
                        "syscheckd: [realtime] File deleted '{}' (Prior SHA256: {})",
                        path.display(),
                        &old_record.hash[..8]
                    )
                };

                warn!("{}", msg);

                let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/integrity", msg);
                event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                event.metadata.insert("action".into(), "deleted".into());
                event.metadata.insert("mode".into(), mode.into());
                event.metadata.insert("old_hash".into(), old_record.hash);
                event.metadata.insert("os_type".into(), "linux".into());

                Self::enrich_event_whodata(&mut event, whodata);
                buffer.push(event.clone()).await;
                return Some(event);
            }
            return None;
        }

        // File exists: recompute SHA256 and metadata
        let Some((new_hash, new_size)) = Self::compute_sha256(path) else {
            return None;
        };
        let (new_mode, new_uid, new_gid) = Self::get_file_metadata(path);
        let new_record = FileRecord {
            hash: new_hash.clone(),
            size: new_size,
            mode: new_mode,
            uid: new_uid,
            gid: new_gid,
        };

        let old_opt = self.baseline.get(&path_buf).cloned();

        let (action, alert_msg, loc) = match old_opt {
            None => {
                // New file added
                let whodata = self.whodata.correlate(path);
                let msg = if let Some(ref w) = whodata {
                    format!(
                        "syscheckd: [whodata] New file created '{}' by user '{}' (UID: {:?}, Process: '{}' [PID: {:?}], SHA256: {})",
                        path.display(),
                        w.user_name.as_deref().unwrap_or("unknown"),
                        w.user_id.unwrap_or(0),
                        w.process_name.as_deref().unwrap_or("unknown"),
                        w.process_id.unwrap_or(0),
                        &new_hash[..8]
                    )
                } else {
                    format!(
                        "syscheckd: [realtime] New file added '{}' (SHA256: {})",
                        path.display(),
                        &new_hash[..8]
                    )
                };
                info!("{}", msg);
                self.baseline.insert(path_buf.clone(), new_record);

                let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/integrity", msg);
                event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                event.metadata.insert("action".into(), "added".into());
                event.metadata.insert("mode".into(), if whodata.is_some() { "whodata".into() } else { "realtime".into() });
                event.metadata.insert("new_hash".into(), new_hash);
                event.metadata.insert("os_type".into(), "linux".into());
                Self::enrich_event_whodata(&mut event, whodata);
                buffer.push(event.clone()).await;
                return Some(event);
            }
            Some(old_record) => {
                let whodata = self.whodata.correlate(path);
                let mode_label = if whodata.is_some() { "whodata" } else { "realtime" };

                if old_record.hash != new_hash {
                    let msg = if let Some(ref w) = whodata {
                        format!(
                            "syscheckd: [{}] File modified '{}' by user '{}' (UID: {:?}, Process: '{}' [PID: {:?}], SHA256: {} -> {})",
                            mode_label,
                            path.display(),
                            w.user_name.as_deref().unwrap_or("unknown"),
                            w.user_id.unwrap_or(0),
                            w.process_name.as_deref().unwrap_or("unknown"),
                            w.process_id.unwrap_or(0),
                            &old_record.hash[..8],
                            &new_hash[..8]
                        )
                    } else {
                        format!(
                            "syscheckd: [{}] Integrity checksum changed for '{}' (Old SHA256: {} -> New SHA256: {})",
                            mode_label,
                            path.display(),
                            &old_record.hash[..8],
                            &new_hash[..8]
                        )
                    };
                    info!("{}", msg);
                    ("modified", msg, "syscheck/integrity")
                } else if old_record.mode != new_mode {
                    let msg = format!(
                        "syscheckd: [{}] File permissions changed for '{}' (Old Mode: {:o} -> New Mode: {:o})",
                        mode_label,
                        path.display(),
                        old_record.mode & 0o7777,
                        new_mode & 0o7777
                    );
                    warn!("{}", msg);
                    ("permission_change", msg, "syscheck/permissions")
                } else if old_record.uid != new_uid || old_record.gid != new_gid {
                    let msg = format!(
                        "syscheckd: [{}] File ownership changed for '{}' (Old UID/GID: {}:{} -> New UID/GID: {}:{})",
                        mode_label,
                        path.display(),
                        old_record.uid, old_record.gid,
                        new_uid, new_gid
                    );
                    warn!("{}", msg);
                    ("ownership_change", msg, "syscheck/ownership")
                } else {
                    // No observable change in hash or attributes
                    return None;
                }
            }
        };

        let whodata = self.whodata.correlate(path);
        let mode = if whodata.is_some() { "whodata" } else { "realtime" };

        let old_rec = self.baseline.insert(path_buf.clone(), new_record);

        let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, loc, alert_msg);
        event.metadata.insert("file_path".into(), path.to_string_lossy().into());
        event.metadata.insert("action".into(), action.into());
        event.metadata.insert("mode".into(), mode.into());
        if let Some(old) = old_rec {
            event.metadata.insert("old_hash".into(), old.hash);
            event.metadata.insert("old_mode".into(), format!("{:o}", old.mode & 0o7777));
            event.metadata.insert("old_uid".into(), old.uid.to_string());
        }
        event.metadata.insert("new_hash".into(), new_hash);
        event.metadata.insert("new_mode".into(), format!("{:o}", new_mode & 0o7777));
        event.metadata.insert("new_uid".into(), new_uid.to_string());
        event.metadata.insert("os_type".into(), "linux".into());

        Self::enrich_event_whodata(&mut event, whodata);
        buffer.push(event.clone()).await;
        Some(event)
    }

    /// Inject attribution fields into RawEvent metadata
    fn enrich_event_whodata(event: &mut RawEvent, whodata: Option<WhodataInfo>) {
        if let Some(w) = whodata {
            if let Some(u) = w.user_name {
                event.metadata.insert("user_name".into(), u);
            }
            if let Some(uid) = w.user_id {
                event.metadata.insert("user_id".into(), uid.to_string());
            }
            if let Some(aname) = w.audit_name {
                event.metadata.insert("audit_name".into(), aname);
            }
            if let Some(auid) = w.audit_uid {
                event.metadata.insert("audit_uid".into(), auid.to_string());
            }
            if let Some(p) = w.process_name {
                event.metadata.insert("process_name".into(), p);
            }
            if let Some(pid) = w.process_id {
                event.metadata.insert("process_id".into(), pid.to_string());
            }
            if let Some(ppid) = w.parent_process_id {
                event.metadata.insert("parent_process_id".into(), ppid.to_string());
            }
            if let Some(pname) = w.parent_name {
                event.metadata.insert("parent_name".into(), pname);
            }
            if let Some(cwd) = w.cwd {
                event.metadata.insert("cwd".into(), cwd);
            }
        }
    }

    /// Full recursive scan comparing on-disk filesystem with current baseline (used for periodic audits)
    pub async fn check_changes(&mut self, buffer: &AgentBuffer) {
        let mut scanned_files: HashMap<PathBuf, FileRecord> = HashMap::new();

        for root in &self.monitored_paths {
            if root.is_file() {
                if let Some((hash, size)) = Self::compute_sha256(root) {
                    let (mode, uid, gid) = Self::get_file_metadata(root);
                    scanned_files.insert(root.clone(), FileRecord { hash, size, mode, uid, gid });
                }
            } else if root.is_dir() {
                let all_dirs = discover_directories_recursive(root, 64);
                for dir in all_dirs {
                    if let Ok(entries) = std::fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            let entry_path = entry.path();
                            if entry_path.is_file() {
                                if let Some((hash, size)) = Self::compute_sha256(&entry_path) {
                                    let (mode, uid, gid) = Self::get_file_metadata(&entry_path);
                                    scanned_files.insert(entry_path, FileRecord { hash, size, mode, uid, gid });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Compare scanned state with baseline
        let mut changed_paths = Vec::new();

        // 1. Check added or modified
        for (path, record) in &scanned_files {
            match self.baseline.get(path) {
                Some(old_record) if old_record.hash != record.hash || old_record.mode != record.mode || old_record.uid != record.uid => {
                    changed_paths.push(path.clone());
                }
                None => {
                    changed_paths.push(path.clone());
                }
                _ => {}
            }
        }

        // 2. Check deleted
        for path in self.baseline.keys() {
            if !scanned_files.contains_key(path) {
                changed_paths.push(path.clone());
            }
        }

        for path in changed_paths {
            self.handle_file_event(&path, buffer, None).await;
        }
    }

    /// Drain inotify events and process them in real-time
    pub async fn poll_and_process_events(&mut self, buffer: &AgentBuffer) {
        if let Some(w) = self.watcher.as_mut() {
            w.poll_events().await;
        }

        let mut events = Vec::new();
        if let Some(rx) = self.rx_events.as_mut() {
            while let Ok(evt) = rx.try_recv() {
                events.push(evt);
            }
        }

        for evt in events {
            if !evt.is_dir {
                self.handle_file_event(&evt.path, buffer, Some(evt.action)).await;
            }
        }
    }
}

/// Spawns the Linux Syscheckd / FIM real-time inotify & audit whodata worker
pub fn spawn_syscheck_worker(
    agent_id: String,
    paths: Vec<PathBuf>,
    buffer: Arc<AgentBuffer>,
    lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let whodata = Arc::new(AuditWhodataEngine::new(1000));
        let _tailer_handle = whodata.clone().spawn_audit_tailer();
        AuditWhodataEngine::setup_audit_watch_rules(&paths);

        let mut engine = SyscheckEngine::with_whodata(agent_id, paths, whodata);
        engine.build_baseline();

        let mut last_periodic_scan = Instant::now();

        loop {
            // Drain real-time inotify events frequently (every 100ms) for zero-latency detection
            tokio::time::sleep(Duration::from_millis(100)).await;

            if lifecycle.is_terminated() {
                break;
            }
            if !lifecycle.is_active() {
                continue;
            }

            engine.poll_and_process_events(&buffer).await;

            // Periodic baseline synchronization loop
            if last_periodic_scan.elapsed() >= interval {
                engine.check_changes(&buffer).await;
                last_periodic_scan = Instant::now();
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn test_syscheck_baseline_and_whodata_enrichment() {
        let temp_dir = std::env::temp_dir().join(format!("test_fim_engine_{}", uuid::Uuid::new_v4()));
        let nested_dir = temp_dir.join("sub1").join("sub2");
        std::fs::create_dir_all(&nested_dir).unwrap();

        let target_file = nested_dir.join("critical_config.conf");
        std::fs::write(&target_file, "initial_value=123\n").unwrap();

        let whodata = Arc::new(AuditWhodataEngine::new(50));
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Seed an audit event for this file
        let path_str = target_file.to_string_lossy().to_string();
        let syscall = format!(
            "type=SYSCALL msg=audit({}.100:888): arch=c000003e syscall=2 items=1 ppid=999 pid=4567 auid=1001 uid=1001 comm=\"nano\" exe=\"/bin/nano\"",
            now_sec
        );
        let path_line = format!(
            "type=PATH msg=audit({}.100:888): item=0 name=\"{}\" inode=9999 dev=08:01 mode=0100644",
            now_sec, path_str
        );
        whodata.ingest_audit_line(&syscall);
        whodata.ingest_audit_line(&path_line);

        let mut engine = SyscheckEngine::with_whodata("test-agent".into(), vec![temp_dir.clone()], whodata);
        engine.build_baseline();

        assert!(
            engine.baseline.contains_key(&target_file),
            "Baseline must index files in deeply nested directories"
        );

        let (buffer, mut rx) = AgentBuffer::mock(100);

        // Modify the file
        std::fs::write(&target_file, "initial_value=999\n").unwrap();

        // Handle modification event
        engine
            .handle_file_event(&target_file, &buffer, Some(FimActionType::Modified))
            .await;

        let alert = rx.try_recv().expect("Expected FIM alert in buffer");
        assert_eq!(alert.location, "syscheck/integrity");
        assert_eq!(alert.metadata.get("action").map(|s| s.as_str()), Some("modified"));
        assert_eq!(alert.metadata.get("mode").map(|s| s.as_str()), Some("whodata"));
        assert_eq!(
            alert.metadata.get("process_name").map(|s| s.as_str()),
            Some("/bin/nano")
        );
        assert_eq!(
            alert.metadata.get("process_id").map(|s| s.as_str()),
            Some("4567")
        );
        assert_eq!(
            alert.metadata.get("parent_process_id").map(|s| s.as_str()),
            Some("999")
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
