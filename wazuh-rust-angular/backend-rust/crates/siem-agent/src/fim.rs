use crate::buffer::AgentBuffer;
use sha2::{Digest, Sha256};
use siem_core::{EventSource, RawEvent};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileRecord {
    hash: String,
    size: u64,
}

pub struct FimWatcher {
    agent_id: String,
    monitored_paths: Vec<PathBuf>,
    baseline: HashMap<PathBuf, FileRecord>,
}

impl FimWatcher {
    pub fn new(agent_id: String, paths: Vec<PathBuf>) -> Self {
        Self {
            agent_id,
            monitored_paths: paths,
            baseline: HashMap::new(),
        }
    }

    fn get_db_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            if let Ok(prog_data) = std::env::var("ProgramData") {
                let dir = PathBuf::from(format!(r"{}\Wazuh-Agent", prog_data));
                let _ = std::fs::create_dir_all(&dir);
                return dir.join("syscheck.db.json");
            }
        }
        PathBuf::from("syscheck.db.json")
    }

    /// Load existing baseline from disk if available, otherwise build fresh baseline
    pub fn load_or_build_baseline(&mut self) {
        let db_path = Self::get_db_path();
        if db_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&db_path) {
                if let Ok(loaded) = serde_json::from_str::<HashMap<PathBuf, FileRecord>>(&content) {
                    info!("FIM: Loaded baseline database from {:?} with {} tracked files", db_path, loaded.len());
                    self.baseline = loaded;
                    return;
                }
            }
        }
        self.build_baseline();
    }

    /// Save baseline state to disk (mirroring Wazuh syscheck.db)
    pub fn save_baseline(&self) {
        let db_path = Self::get_db_path();
        if let Ok(json) = serde_json::to_string_pretty(&self.baseline) {
            let _ = std::fs::write(&db_path, json);
        }
    }

    /// Calculate SHA256 checksum of a file
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
                    self.baseline.insert(path.clone(), FileRecord { hash, size });
                }
            } else if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if entry_path.is_file() {
                            if let Some((hash, size)) = Self::compute_sha256(&entry_path) {
                                self.baseline.insert(entry_path, FileRecord { hash, size });
                            }
                        }
                    }
                }
            }
        }
        info!("FIM: Initialized baseline with {} tracked files", self.baseline.len());
        self.save_baseline();
    }

    /// Perform a scan and emit events for changes
    pub async fn scan_and_emit(&mut self, buffer: &AgentBuffer) -> (usize, usize, usize) {
        let mut current_files: HashMap<PathBuf, FileRecord> = HashMap::new();
        let mut modified_count = 0usize;
        let mut added_count = 0usize;
        let mut deleted_count = 0usize;

        for path in &self.monitored_paths {
            if path.is_file() {
                if let Some((hash, size)) = Self::compute_sha256(path) {
                    current_files.insert(path.clone(), FileRecord { hash, size });
                }
            } else if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if entry_path.is_file() {
                            if let Some((hash, size)) = Self::compute_sha256(&entry_path) {
                                current_files.insert(entry_path, FileRecord { hash, size });
                            }
                        }
                    }
                }
            }
        }

        // Check for modifications and new files
        for (path, current) in &current_files {
            let path_str = path.to_string_lossy().to_string();
            match self.baseline.get(path) {
                Some(prev) => {
                    if prev.hash != current.hash {
                        modified_count += 1;
                        let msg = format!(
                            "File '{}' modified: checksum changed from {} to {} (size: {} bytes)",
                            path_str, prev.hash, current.hash, current.size
                        );
                        info!("FIM Alert: {}", msg);
                        let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, &path_str, msg);
                        event.metadata.insert("action".into(), "modified".into());
                        event.metadata.insert("sha256".into(), current.hash.clone());
                        buffer.push(event).await;

                        // Check for NTFS Alternate Data Streams (matching Wazuh rootcheck/win-common.c: os_check_ads)
                        if let Some(stream_name) = Self::check_ntfs_ads(path) {
                            let ads_msg = format!(
                                "rootcheck: NTFS Alternate Data Stream found: '{}:{}'. Possible hidden backdoor payload.",
                                path_str, stream_name
                            );
                            warn!("{}", ads_msg);
                            let mut ads_event = RawEvent::new(&self.agent_id, EventSource::Fim, &path_str, ads_msg);
                            ads_event.metadata.insert("threat_type".into(), "ntfs_alternate_data_stream".into());
                            ads_event.metadata.insert("stream_name".into(), stream_name);
                            buffer.push(ads_event).await;
                        }
                    }
                }
                None => {
                    added_count += 1;
                    let msg = format!(
                        "File '{}' added: checksum {} (size: {} bytes)",
                        path_str, current.hash, current.size
                    );
                    info!("FIM Alert: {}", msg);
                    let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, &path_str, msg);
                    event.metadata.insert("action".into(), "added".into());
                    event.metadata.insert("sha256".into(), current.hash.clone());
                    buffer.push(event).await;

                    // Check for NTFS Alternate Data Streams (matching Wazuh rootcheck/win-common.c: os_check_ads)
                    if let Some(stream_name) = Self::check_ntfs_ads(path) {
                        let ads_msg = format!(
                            "rootcheck: NTFS Alternate Data Stream found: '{}:{}'. Possible hidden backdoor payload.",
                            path_str, stream_name
                        );
                        warn!("{}", ads_msg);
                        let mut ads_event = RawEvent::new(&self.agent_id, EventSource::Fim, &path_str, ads_msg);
                        ads_event.metadata.insert("threat_type".into(), "ntfs_alternate_data_stream".into());
                        ads_event.metadata.insert("stream_name".into(), stream_name);
                        buffer.push(ads_event).await;
                    }
                }
            }
        }

        // Check for deleted files
        for (path, prev) in &self.baseline {
            if !current_files.contains_key(path) {
                deleted_count += 1;
                let path_str = path.to_string_lossy().to_string();
                let msg = format!("File '{}' deleted (previous checksum: {})", path_str, prev.hash);
                warn!("FIM Alert: {}", msg);
                let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, &path_str, msg);
                event.metadata.insert("action".into(), "deleted".into());
                buffer.push(event).await;
            }
        }

        self.baseline = current_files;
        self.save_baseline();

        // Run rootcheck signature sweep for known trojan artifacts (win_malware_rcl.txt)
        self.check_rootkit_signatures(buffer).await;

        (modified_count, added_count, deleted_count)
    }

    /// Check for known Windows malware/rootkit files (mirroring Wazuh win_malware_rcl.txt & check_rc_files.c)
    pub async fn check_rootkit_signatures(&self, buffer: &AgentBuffer) {
        #[cfg(target_os = "windows")]
        {
            let win_dir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
            let known_trojans = [
                ("zsyhide.dll", "Ginwui Backdoor"),
                ("zsydll.dll", "Ginwui Backdoor"),
                ("wgareg.exe", "Wargbot Backdoor"),
                ("clonzips.ssc", "Sober Worm"),
                ("winsend32.dal", "Sober Worm"),
                ("explore.exe", "Hotword Trojan"),
                ("mmsystem.dlx", "Hotword Trojan"),
            ];

            let check_dirs = [
                format!(r"{}\System32", win_dir),
                format!(r"{}\Sysnative", win_dir),
            ];

            for dir in &check_dirs {
                for (file, name) in &known_trojans {
                    let target = Path::new(dir).join(file);
                    if target.exists() {
                        let msg = format!(
                            "rootcheck: Known trojan/rootkit signature detected: '{}' ({})",
                            target.to_string_lossy(), name
                        );
                        warn!("{}", msg);
                        let mut event = RawEvent::new(&self.agent_id, EventSource::Fim, target.to_string_lossy().as_ref(), msg);
                        event.metadata.insert("threat_type".into(), "rootkit_malware_detected".into());
                        event.metadata.insert("signature".into(), name.to_string());
                        buffer.push(event).await;
                    }
                }
            }
        }
    }

    /// Check for NTFS Alternate Data Streams (mirroring Wazuh rootcheck/win-common.c: os_check_ads)
    fn check_ntfs_ads(path: &Path) -> Option<String> {
        #[cfg(target_os = "windows")]
        {
            if let Some(path_str) = path.to_str() {
                let cmd = format!(
                    "Get-Item -LiteralPath '{}' -Stream * -ErrorAction SilentlyContinue | Where-Object {{ $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }} | Select-Object -ExpandProperty Stream",
                    path_str.replace('\'', "''")
                );
                if let Ok(output) = std::process::Command::new("powershell")
                    .args(["-NoProfile", "-Command", &cmd])
                    .output()
                {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !stdout.is_empty() {
                            return Some(stdout);
                        }
                    }
                }
            }
        }
        None
    }
}

pub fn spawn_fim_worker(
    agent_id: String,
    paths: Vec<PathBuf>,
    buffer: Arc<AgentBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watcher = FimWatcher::new(agent_id, paths);
        watcher.load_or_build_baseline();

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            debug!("FIM: Running scheduled integrity scan...");
            watcher.scan_and_emit(&buffer).await;
        }
    })
}
