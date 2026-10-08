use crate::buffer::AgentBuffer;
use sha2::{Digest, Sha256};
use siem_core::{EventSource, RawEvent};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

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

    /// Scan monitored files and detect changes (created, modified, deleted, permissions, ownership)
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

        // 1. Detect Modified or Added files
        for (path, record) in &current_state {
            match self.baseline.get(path) {
                Some(old_record) => {
                    // Check checksum modification
                    if old_record.hash != record.hash {
                        let msg = format!(
                            "syscheckd: File integrity check: Integrity checksum changed for '{}' (Old SHA256: {} -> New SHA256: {})",
                            path.display(),
                            &old_record.hash[..8],
                            &record.hash[..8]
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

                    // Check permission tampering (e.g. chmod 777)
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

                    // Check ownership tampering (chown)
                    if old_record.uid != record.uid || old_record.gid != record.gid {
                        let msg = format!(
                            "syscheckd: File integrity check: Ownership changed for '{}' (Old UID/GID: {}:{} -> New UID/GID: {}:{})",
                            path.display(),
                            old_record.uid, old_record.gid,
                            record.uid, record.gid
                        );
                        warn!("{}", msg);

                        let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, "syscheck/ownership", msg);
                        event.metadata.insert("file_path".into(), path.to_string_lossy().into());
                        event.metadata.insert("action".into(), "ownership_change".into());
                        event.metadata.insert("old_uid".into(), old_record.uid.to_string());
                        event.metadata.insert("new_uid".into(), record.uid.to_string());
                        event.metadata.insert("os_type".into(), "linux".into());
                        buffer.push(event).await;
                    }
                }
                None => {
                    let msg = format!(
                        "syscheckd: File integrity check: New file added to monitored location '{}' (SHA256: {})",
                        path.display(),
                        &record.hash[..8]
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

        // 2. Detect Deleted files
        for (path, old_record) in &self.baseline {
            if !current_state.contains_key(path) {
                let msg = format!(
                    "syscheckd: File integrity check: Monitored file was deleted '{}' (Prior SHA256: {})",
                    path.display(),
                    &old_record.hash[..8]
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

/// Spawns the Linux Syscheckd / FIM worker task
pub fn spawn_syscheck_worker(
    agent_id: String,
    paths: Vec<PathBuf>,
    buffer: Arc<AgentBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut engine = SyscheckEngine::new(agent_id, paths);
        engine.build_baseline();

        loop {
            tokio::time::sleep(interval).await;
            engine.check_changes(&buffer).await;
        }
    })
}
