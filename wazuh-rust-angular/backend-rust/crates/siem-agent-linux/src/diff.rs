use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default maximum diff string size before truncation (bytes).
pub const DEFAULT_MAX_DIFF_SIZE: usize = 59_392;
/// Default maximum file size to compute diff for (10 MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
/// Default diff storage directory quota (50 MB).
pub const DEFAULT_DISK_QUOTA_BYTES: u64 = 50 * 1024 * 1024;
/// Marker appended when diff exceeds maximum allowed size.
pub const STR_MORE_CHANGES: &str = "\nMore changes...\n";

/// Configuration for the Diff Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffConfig {
    pub enabled: bool,
    pub storage_dir: PathBuf,
    pub max_diff_size: usize,
    pub max_file_size: u64,
    pub disk_quota_bytes: u64,
    pub compress_snapshots: bool,
}

impl Default for DiffConfig {
    fn default() -> Self {
        let candidate = Path::new("/opt/provigil-agent/data/diff");
        let dir = if candidate.parent().map(|p| p.exists()).unwrap_or(false) {
            candidate.to_path_buf()
        } else {
            PathBuf::from("data").join("diff")
        };

        Self {
            enabled: true,
            storage_dir: dir,
            max_diff_size: DEFAULT_MAX_DIFF_SIZE,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            disk_quota_bytes: DEFAULT_DISK_QUOTA_BYTES,
            compress_snapshots: true,
        }
    }
}

/// Result of computing a file diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub path: String,
    pub has_changes: bool,
    pub diff_content: Option<String>,
    pub previous_timestamp: Option<String>,
    pub current_timestamp: String,
    pub truncated: bool,
    pub quota_full: bool,
}

/// The File Diff Engine.
pub struct DiffEngine {
    config: DiffConfig,
}

impl DiffEngine {
    pub fn new(config: DiffConfig) -> Self {
        if config.enabled {
            let _ = fs::create_dir_all(&config.storage_dir);
        }
        Self { config }
    }

    fn get_snapshot_path(&self, target_path: &Path) -> PathBuf {
        let hash = Sha256::digest(target_path.to_string_lossy().as_bytes());
        let ext = if self.config.compress_snapshots { "gz" } else { "snap" };
        self.config.storage_dir.join(format!("{hash:x}.{ext}"))
    }

    pub fn remove_snapshot(&self, target_path: &Path) {
        let _ = fs::remove_file(self.get_snapshot_path(target_path));
    }

    pub fn calculate_storage_usage(&self) -> u64 {
        let mut total = 0;
        if let Ok(entries) = fs::read_dir(&self.config.storage_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    total += metadata.len();
                }
            }
        }
        total
    }

    fn read_previous_snapshot(&self, snapshot_path: &Path) -> Option<String> {
        if !snapshot_path.exists() {
            return None;
        }

        if self.config.compress_snapshots {
            let file = File::open(snapshot_path).ok()?;
            let mut decoder = GzDecoder::new(file);
            let mut content = String::new();
            decoder.read_to_string(&mut content).ok()?;
            Some(content)
        } else {
            fs::read_to_string(snapshot_path).ok()
        }
    }

    fn save_snapshot(&self, snapshot_path: &Path, content: &str) -> std::io::Result<bool> {
        let current_usage = self.calculate_storage_usage();
        if current_usage >= self.config.disk_quota_bytes {
            tracing::warn!(
                "Diff storage quota reached ({} / {} bytes). Skipping snapshot write.",
                current_usage,
                self.config.disk_quota_bytes
            );
            return Ok(false);
        }

        if let Some(parent) = snapshot_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if self.config.compress_snapshots {
            let file = File::create(snapshot_path)?;
            let mut encoder = GzEncoder::new(file, Compression::default());
            encoder.write_all(content.as_bytes())?;
            encoder.finish()?;
        } else {
            fs::write(snapshot_path, content)?;
        }

        Ok(true)
    }

    fn replace_snapshot(&self, snapshot_path: &Path, content: &str) -> bool {
        let saved = self.save_snapshot(snapshot_path, content);
        if !matches!(saved, Ok(true)) {
            let _ = fs::remove_file(snapshot_path);
        }
        matches!(saved, Ok(false))
    }

    pub fn process_file_diff(&self, file_path: &Path) -> std::io::Result<Option<DiffResult>> {
        if !self.config.enabled || !file_path.exists() || !file_path.is_file() {
            return Ok(None);
        }

        let metadata = fs::metadata(file_path)?;
        if metadata.len() > self.config.max_file_size {
            return Ok(None);
        }

        let current_content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        let snapshot_path = self.get_snapshot_path(file_path);
        let previous_content = self.read_previous_snapshot(&snapshot_path);
        let now_str = Utc::now().to_rfc3339();

        let result = match previous_content {
            Some(prev) => {
                if prev == current_content {
                    None
                } else {
                    let (diff_text, truncated) = self.generate_unified_diff(
                        &file_path.to_string_lossy(),
                        &prev,
                        &current_content,
                    );

                    let quota_full = self.replace_snapshot(&snapshot_path, &current_content);

                    Some(DiffResult {
                        path: file_path.to_string_lossy().to_string(),
                        has_changes: true,
                        diff_content: Some(diff_text),
                        previous_timestamp: None,
                        current_timestamp: now_str,
                        truncated,
                        quota_full,
                    })
                }
            }
            None => {
                let quota_full = self.replace_snapshot(&snapshot_path, &current_content);
                Some(DiffResult {
                    path: file_path.to_string_lossy().to_string(),
                    has_changes: false,
                    diff_content: None,
                    previous_timestamp: None,
                    current_timestamp: now_str,
                    truncated: false,
                    quota_full,
                })
            }
        };

        Ok(result)
    }

    fn generate_unified_diff(&self, file_name: &str, old_text: &str, new_text: &str) -> (String, bool) {
        let old_lines: Vec<&str> = old_text.lines().collect();
        let new_lines: Vec<&str> = new_text.lines().collect();

        let mut diff = String::new();
        diff.push_str(&format!("--- {}\n+++ {}\n", file_name, file_name));

        let mut truncated = false;
        let mut i = 0;
        let mut j = 0;

        while i < old_lines.len() || j < new_lines.len() {
            if diff.len() >= self.config.max_diff_size.saturating_sub(STR_MORE_CHANGES.len()) {
                diff.push_str(STR_MORE_CHANGES);
                truncated = true;
                break;
            }

            if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
                i += 1;
                j += 1;
            } else if j < new_lines.len() && (i >= old_lines.len() || !old_lines.contains(&new_lines[j])) {
                diff.push_str(&format!("+{}\n", new_lines[j]));
                j += 1;
            } else if i < old_lines.len() {
                diff.push_str(&format!("-{}\n", old_lines[i]));
                i += 1;
            }
        }

        (diff, truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_engine_snapshot_and_delta() {
        let temp_dir = std::env::temp_dir().join(format!("test_diff_{}", uuid::Uuid::new_v4()));
        let mut cfg = DiffConfig::default();
        cfg.storage_dir = temp_dir.clone();
        let engine = DiffEngine::new(cfg);

        let test_file = temp_dir.join("test.conf");
        let _ = fs::create_dir_all(&temp_dir);
        fs::write(&test_file, "key=value1\nsetting=true\n").unwrap();

        // 1. First run creates initial snapshot
        let res1 = engine.process_file_diff(&test_file).unwrap().unwrap();
        assert!(!res1.has_changes);
        assert_eq!(res1.diff_content, None);

        // 2. Modify file
        fs::write(&test_file, "key=value2\nsetting=true\nnew_item=123\n").unwrap();
        let res2 = engine.process_file_diff(&test_file).unwrap().unwrap();
        assert!(res2.has_changes);
        let diff = res2.diff_content.unwrap();
        assert!(diff.contains("-key=value1"));
        assert!(diff.contains("+key=value2"));
        assert!(diff.contains("+new_item=123"));

        let _ = fs::remove_dir_all(temp_dir);
    }
}
