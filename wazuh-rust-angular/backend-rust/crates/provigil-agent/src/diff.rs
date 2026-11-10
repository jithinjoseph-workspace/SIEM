//! ProVigil Endpoint Agent - Clean-Room File Diff Engine
//!
//! Provides file diff calculation for Integrity Monitoring (FIM).
//! When a monitored file is modified, computes a unified diff against
//! the previous stored snapshot, updates the snapshot with optional
//! gzip compression, and enforces disk quota limits.
//!
//! 100% clean-room Rust implementation (zero GPL derivation).

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
        Self {
            enabled: true,
            storage_dir: PathBuf::from("data").join("diff"),
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
    /// The snapshot could not be stored (quota full): the next change has no diff.
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
            // snapshots named by the earlier scheme (path with `_` for separators) would only fill the quota
            for e in fs::read_dir(&config.storage_dir).into_iter().flatten().flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.split('.').next().is_none_or(|stem| stem.len() != 64 || !stem.bytes().all(|b| b.is_ascii_hexdigit())) {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        Self { config }
    }

    /// The snapshot file of `target_path`: named by the SHA-256 of the full path, so two
    /// paths never share one.
    fn get_snapshot_path(&self, target_path: &Path) -> PathBuf {
        let hash = Sha256::digest(target_path.to_string_lossy().as_bytes());
        let ext = if self.config.compress_snapshots { "gz" } else { "snap" };
        self.config.storage_dir.join(format!("{hash:x}.{ext}"))
    }

    /// Forgets the snapshot of a deleted file.
    pub fn remove_snapshot(&self, target_path: &Path) {
        let _ = fs::remove_file(self.get_snapshot_path(target_path));
    }

    /// Calculates total size of files in the diff storage directory.
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

    /// Reads previous snapshot content from disk (decompressing if gzip).
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

    /// Saves the current file content as the new snapshot on disk; `false` when the quota is full.
    fn save_snapshot(&self, snapshot_path: &Path, content: &str) -> std::io::Result<bool> {
        // Check disk quota before saving
        let current_usage = self.calculate_storage_usage();
        if current_usage >= self.config.disk_quota_bytes {
            tracing::warn!(
                "Diff storage quota reached ({} / {} bytes). Skipping snapshot write.",
                current_usage,
                self.config.disk_quota_bytes
            );
            return Ok(false);
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

    /// Stores `content` as the snapshot; when that fails the old one is removed (a later diff
    /// against it would be stale). True when the quota is full.
    fn replace_snapshot(&self, snapshot_path: &Path, content: &str) -> bool {
        let saved = self.save_snapshot(snapshot_path, content);
        if !matches!(saved, Ok(true)) {
            let _ = fs::remove_file(snapshot_path);
        }
        matches!(saved, Ok(false))
    }

    /// Computes unified diff between previous snapshot and current file content.
    /// If the file is new, initializes snapshot and returns None.
    pub fn process_file_diff(&self, file_path: &Path) -> std::io::Result<Option<DiffResult>> {
        if !self.config.enabled {
            return Ok(None);
        }

        if !file_path.exists() || !file_path.is_file() {
            return Ok(None);
        }

        // Check file size limit
        let metadata = fs::metadata(file_path)?;
        if metadata.len() > self.config.max_file_size {
            tracing::debug!(
                "File {} exceeds max diff file size ({} > {} bytes). Skipping diff.",
                file_path.display(),
                metadata.len(),
                self.config.max_file_size
            );
            return Ok(None);
        }

        let current_content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => {
                // Binary or non-UTF-8 file; diff calculation skipped
                return Ok(None);
            }
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
                // First time seeing this file: establish baseline snapshot
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

    /// Generates unified diff between old text and new text.
    /// Truncates output if exceeding `max_diff_size`.
    fn generate_unified_diff(
        &self,
        file_name: &str,
        old_text: &str,
        new_text: &str,
    ) -> (String, bool) {
        let old_lines: Vec<&str> = old_text.lines().collect();
        let new_lines: Vec<&str> = new_text.lines().collect();

        let mut diff_output = format!("--- {}\t(original)\n+++ {}\t(modified)\n", file_name, file_name);
        let mut truncated = false;

        // Clean-room line comparison
        let mut i = 0;
        let mut j = 0;

        while i < old_lines.len() || j < new_lines.len() {
            if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
                i += 1;
                j += 1;
            } else {
                let chunk_start_i = i + 1;
                let chunk_start_j = j + 1;
                let mut chunk = String::new();

                // Consume removed lines
                while i < old_lines.len() && (j >= new_lines.len() || old_lines[i] != new_lines[j]) {
                    chunk.push_str(&format!("-{}\n", old_lines[i]));
                    i += 1;
                    if i > chunk_start_i + 50 { break; }
                }

                // Consume added lines
                while j < new_lines.len() && (i >= old_lines.len() || old_lines.get(i) != new_lines.get(j)) {
                    chunk.push_str(&format!("+{}\n", new_lines[j]));
                    j += 1;
                    if j > chunk_start_j + 50 { break; }
                }

                let header = format!("@@ -{},1 +{},1 @@\n", chunk_start_i, chunk_start_j);

                if diff_output.len() + header.len() + chunk.len() > self.config.max_diff_size {
                    diff_output.push_str(STR_MORE_CHANGES);
                    truncated = true;
                    break;
                }

                diff_output.push_str(&header);
                diff_output.push_str(&chunk);
            }
        }

        (diff_output, truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_diff_creation_and_compression() {
        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("diff_store");
        let test_file = dir.path().join("test.txt");

        let config = DiffConfig {
            enabled: true,
            storage_dir: storage_dir.clone(),
            max_diff_size: 1024,
            max_file_size: 1024 * 1024,
            disk_quota_bytes: 10 * 1024 * 1024,
            compress_snapshots: true,
        };

        let engine = DiffEngine::new(config);

        // 1. Initial creation
        fs::write(&test_file, "Line 1\nLine 2\nLine 3\n").unwrap();
        let res1 = engine.process_file_diff(&test_file).unwrap().unwrap();
        assert!(!res1.has_changes);
        assert!(res1.diff_content.is_none());

        // 2. Modify file
        fs::write(&test_file, "Line 1\nLine 2 modified\nLine 3\nLine 4 added\n").unwrap();
        let res2 = engine.process_file_diff(&test_file).unwrap().unwrap();
        assert!(res2.has_changes);
        let diff = res2.diff_content.unwrap();
        assert!(diff.contains("-Line 2"));
        assert!(diff.contains("+Line 2 modified"));
        assert!(diff.contains("+Line 4 added"));

        // 3. Storage snapshot was created and compressed
        assert!(engine.calculate_storage_usage() > 0);
    }

    /// Paths the earlier naming mixed up (`a_b\c.txt`, `a\b_c.txt`) keep their own snapshots;
    /// with the quota full the next diff says so instead of using a stale snapshot.
    #[test]
    fn snapshot_names_and_quota() {
        let dir = tempdir().unwrap();
        let (x, y) = (dir.path().join("a_b").join("c.txt"), dir.path().join("a").join("b_c.txt"));
        fs::create_dir_all(x.parent().unwrap()).unwrap();
        fs::create_dir_all(y.parent().unwrap()).unwrap();
        let store = dir.path().join("store");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("C_a_b_c.txt.snap"), "old scheme").unwrap();
        let config = |quota| DiffConfig {
            enabled: true,
            storage_dir: store.clone(),
            max_diff_size: 1024,
            max_file_size: 1024 * 1024,
            disk_quota_bytes: quota,
            compress_snapshots: false,
        };
        let engine = DiffEngine::new(config(1 << 20));
        assert!(!store.join("C_a_b_c.txt.snap").exists(), "old-scheme snapshot kept");
        assert_ne!(engine.get_snapshot_path(&x), engine.get_snapshot_path(&y));
        fs::write(&x, "x1\n").unwrap();
        fs::write(&y, "y1\n").unwrap();
        engine.process_file_diff(&x).unwrap();
        engine.process_file_diff(&y).unwrap();
        fs::write(&x, "x2\n").unwrap();
        let d = engine.process_file_diff(&x).unwrap().unwrap().diff_content.unwrap();
        assert!(d.contains("-x1") && d.contains("+x2"), "{d}");
        engine.remove_snapshot(&y);
        assert_eq!(fs::read_dir(&store).unwrap().count(), 1);

        // quota full: this diff is right, the snapshot goes, the next change says so
        let engine = DiffEngine::new(config(1));
        fs::write(&x, "x3\n").unwrap();
        let r = engine.process_file_diff(&x).unwrap().unwrap();
        assert!(r.diff_content.unwrap().contains("+x3"));
        assert!(r.quota_full);
        fs::write(store.join(format!("{}.snap", "0".repeat(64))), "filler").unwrap();
        fs::write(&x, "x4\n").unwrap();
        let r = engine.process_file_diff(&x).unwrap().unwrap();
        assert!(r.diff_content.is_none() && r.quota_full);
    }

    #[test]
    fn test_diff_truncation() {
        let dir = tempdir().unwrap();
        let storage_dir = dir.path().join("diff_store");
        let test_file = dir.path().join("large_change.txt");

        let config = DiffConfig {
            enabled: true,
            storage_dir,
            max_diff_size: 150, // very small limit to trigger truncation
            max_file_size: 1024 * 1024,
            disk_quota_bytes: 10 * 1024 * 1024,
            compress_snapshots: false,
        };

        let engine = DiffEngine::new(config);
        fs::write(&test_file, "original 1\noriginal 2\n").unwrap();
        let _ = engine.process_file_diff(&test_file).unwrap();

        let mut large_change = String::new();
        for i in 0..100 {
            large_change.push_str(&format!("new line {}\n", i));
        }
        fs::write(&test_file, large_change).unwrap();

        let res = engine.process_file_diff(&test_file).unwrap().unwrap();
        assert!(res.has_changes);
        assert!(res.truncated);
        assert!(res.diff_content.unwrap().contains("More changes..."));
    }
}

