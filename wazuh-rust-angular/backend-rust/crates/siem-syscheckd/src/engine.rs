use crate::config::{
    SyscheckConfig, CHECK_ALL, CHECK_OWNER, CHECK_PERM, CHECK_SEECHANGES,
    CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_SIZE,
};
use crate::diff_engine::DiffEngine;
use crate::registry::RegistryMonitor;
use crate::syscom::SyscheckStatus;
use crate::whodata::WhodataInfo;
use chrono::Utc;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use siem_wdb::{FimAction, FimDelta, FimEntry, FimEntryType};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone)]
pub struct FimAlert {
    pub delta: FimDelta,
    pub diff: Option<String>,
    pub whodata: Option<WhodataInfo>,
}

pub struct SyscheckEngine {
    pub config: SyscheckConfig,
    pub diff_engine: DiffEngine,
    pub registry_monitor: RegistryMonitor,
    baseline: RwLock<HashMap<PathBuf, FimEntry>>,
    last_scan_time: RwLock<Option<i64>>,
    is_scanning: RwLock<bool>,
}

impl SyscheckEngine {
    pub fn new(config: SyscheckConfig, diff_storage_dir: impl Into<PathBuf>) -> Self {
        let max_size = config.file_size_limit_mb;
        Self {
            config,
            diff_engine: DiffEngine::new(diff_storage_dir, max_size),
            registry_monitor: RegistryMonitor::new(),
            baseline: RwLock::new(HashMap::new()),
            last_scan_time: RwLock::new(None),
            is_scanning: RwLock::new(false),
        }
    }

    /// Computes hashes and gathers metadata for a file based on options bitmask
    pub fn inspect_file(&self, path: &Path, options: u32) -> Option<FimEntry> {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }

        let size = if (options & CHECK_SIZE) != 0 || (options & CHECK_ALL) != 0 {
            Some(meta.len())
        } else {
            None
        };

        let perm = if (options & CHECK_PERM) != 0 || (options & CHECK_ALL) != 0 {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                Some(format!("{:04o}", meta.permissions().mode() & 0o7777))
            }
            #[cfg(not(unix))]
            Some("0644".to_string())
        } else {
            None
        };

        let (uid, gid) = if (options & CHECK_OWNER) != 0 || (options & CHECK_ALL) != 0 {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                (Some(meta.uid().to_string()), Some(meta.gid().to_string()))
            }
            #[cfg(not(unix))]
            (Some("0".to_string()), Some("0".to_string()))
        } else {
            (None, None)
        };

        let mut file = File::open(path).ok()?;
        let mut buffer = [0u8; 8192];

        let compute_sha256 = (options & CHECK_SHA256SUM) != 0 || (options & CHECK_ALL) != 0;
        let compute_sha1 = (options & CHECK_SHA1SUM) != 0;

        let mut sha256_hasher = if compute_sha256 { Some(Sha256::new()) } else { None };
        let mut sha1_hasher = if compute_sha1 { Some(Sha1::new()) } else { None };

        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let slice = &buffer[..n];
                    if let Some(h) = sha256_hasher.as_mut() { h.update(slice); }
                    if let Some(h) = sha1_hasher.as_mut() { h.update(slice); }
                }
                Err(_) => return None,
            }
        }

        let sha256 = sha256_hasher.map(|h| format!("{:02x}", h.finalize()));
        let sha1 = sha1_hasher.map(|h| format!("{:02x}", h.finalize()));

        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        Some(FimEntry {
            full_path: path.to_string_lossy().to_string(),
            file_name,
            entry_type: FimEntryType::File,
            size,
            perm,
            uid,
            gid,
            md5: None,
            sha1,
            sha256,
            mtime: meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0),
            inode: None,
            changes: 0,
            date: Utc::now().timestamp() as u64,
        })
    }

    /// Evaluates a single file and detects Added / Modified changes
    pub fn evaluate_file(&self, path: &Path, options: u32, whodata: Option<WhodataInfo>) -> Option<FimAlert> {
        let path_str = path.to_string_lossy();
        if self.config.is_ignored(&path_str) {
            return None;
        }

        let current_entry = self.inspect_file(path, options)?;
        let mut baseline = self.baseline.write().unwrap();

        if let Some(old) = baseline.get(path) {
            if old.sha256 != current_entry.sha256 || old.size != current_entry.size || old.perm != current_entry.perm {
                let old_clone = old.clone();
                baseline.insert(path.to_path_buf(), current_entry.clone());

                let diff = if (options & CHECK_SEECHANGES) != 0 && !self.config.is_nodiff(&path_str) {
                    self.diff_engine.generate_and_update_diff(path)
                } else {
                    None
                };

                Some(FimAlert {
                    delta: FimDelta {
                        path: path_str.to_string(),
                        action: FimAction::Modified,
                        old_entry: Some(old_clone),
                        new_entry: Some(current_entry),
                    },
                    diff,
                    whodata,
                })
            } else {
                None
            }
        } else {
            // New file detected
            baseline.insert(path.to_path_buf(), current_entry.clone());

            if (options & CHECK_SEECHANGES) != 0 && !self.config.is_nodiff(&path_str) {
                let _ = self.diff_engine.generate_and_update_diff(path);
            }

            Some(FimAlert {
                delta: FimDelta {
                    path: path_str.to_string(),
                    action: FimAction::Added,
                    old_entry: None,
                    new_entry: Some(current_entry),
                },
                diff: None,
                whodata,
            })
        }
    }

    /// Runs a complete scheduled or on-demand integrity scan across all configured directories
    pub fn run_integrity_scan(&self) -> Vec<FimAlert> {
        *self.is_scanning.write().unwrap() = true;
        info!("Starting Syscheck integrity scan...");

        let mut alerts = Vec::new();

        for dir_cfg in &self.config.directories {
            if dir_cfg.path.is_dir() {
                self.scan_dir_recursive(&dir_cfg.path, dir_cfg.options, &mut alerts);
            } else if dir_cfg.path.is_file() {
                if let Some(alert) = self.evaluate_file(&dir_cfg.path, dir_cfg.options, None) {
                    alerts.push(alert);
                }
            }
        }

        *self.last_scan_time.write().unwrap() = Some(Utc::now().timestamp());
        *self.is_scanning.write().unwrap() = false;
        info!("Syscheck integrity scan completed. Detected {} changes.", alerts.len());

        alerts
    }

    fn scan_dir_recursive(&self, dir: &Path, options: u32, alerts: &mut Vec<FimAlert>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let path_str = path.to_string_lossy();
                if self.config.is_ignored(&path_str) {
                    continue;
                }

                if path.is_dir() {
                    self.scan_dir_recursive(&path, options, alerts);
                } else if path.is_file() {
                    if let Some(alert) = self.evaluate_file(&path, options, None) {
                        alerts.push(alert);
                    }
                }
            }
        }
    }

    /// Queries the current daemon status
    pub fn get_status(&self) -> SyscheckStatus {
        SyscheckStatus {
            is_scanning: *self.is_scanning.read().unwrap(),
            last_scan_time: *self.last_scan_time.read().unwrap(),
            files_monitored: self.baseline.read().unwrap().len(),
            registry_entries_monitored: self.registry_monitor.total_entries(),
        }
    }
}
