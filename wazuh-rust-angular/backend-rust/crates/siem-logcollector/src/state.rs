//! Wazuh Logcollector State Manager (src/logcollector/state.c, state.h)
//!
//! Manages persistent file positions and SHA-1 hashes saved in `file_status.json`.
//! This ensures that when the logcollector daemon restarts, it resumes reading
//! from the exact byte offset where it left off, avoiding duplicate alert processing.

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Status for a single monitored file matching `file_status.json`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStateEntry {
    pub path: String,
    pub offset: u64,
    pub hash: String,
    #[serde(default)]
    pub lines_read: u64,
    #[serde(default)]
    pub drop_lines: u64,
    #[serde(default)]
    pub status: String,
}

impl Default for FileStateEntry {
    fn default() -> Self {
        Self {
            path: String::new(),
            offset: 0,
            hash: String::new(),
            lines_read: 0,
            drop_lines: 0,
            status: "active".to_string(),
        }
    }
}

/// JSON container for `file_status.json`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FileStatusJson {
    pub files: Vec<FileStateEntry>,
}

/// Thread-safe File State Manager
#[derive(Debug, Clone)]
pub struct FileStateManager {
    status_file: PathBuf,
    entries: Arc<Mutex<HashMap<String, FileStateEntry>>>,
}

impl FileStateManager {
    pub fn new<P: AsRef<Path>>(status_file: P) -> Self {
        let manager = Self {
            status_file: status_file.as_ref().to_path_buf(),
            entries: Arc::new(Mutex::new(HashMap::new())),
        };
        let _ = manager.load();
        manager
    }

    /// Load existing state from `file_status.json`
    pub fn load(&self) -> Result<(), String> {
        if !self.status_file.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.status_file).map_err(|e| e.to_string())?;
        let json: FileStatusJson = serde_json::from_str(&content).map_err(|e| e.to_string())?;

        let mut map = self.entries.lock().unwrap();
        for entry in json.files {
            map.insert(entry.path.clone(), entry);
        }

        Ok(())
    }

    /// Persist current state to `file_status.json`
    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.status_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let map = self.entries.lock().unwrap();
        let json = FileStatusJson {
            files: map.values().cloned().collect(),
        };

        let content = serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?;
        std::fs::write(&self.status_file, content).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Updates offset, lines, and hash for a given file path
    pub fn update(&self, path: &str, offset: u64, hash: &str, lines: u64, drops: u64) {
        let mut map = self.entries.lock().unwrap();
        let entry = map.entry(path.to_string()).or_default();
        entry.path = path.to_string();
        entry.offset = offset;
        entry.hash = hash.to_string();
        entry.lines_read += lines;
        entry.drop_lines += drops;
        entry.status = "active".to_string();
    }

    /// Gets current offset for a file
    pub fn get_offset(&self, path: &str) -> Option<u64> {
        let map = self.entries.lock().unwrap();
        map.get(path).map(|e| e.offset)
    }

    /// Checks if a file has changed its identity or rotated by inspecting initial SHA-1 hash
    pub fn calculate_file_hash<P: AsRef<Path>>(path: P, bytes_to_hash: usize) -> Result<String, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; bytes_to_hash];
        let bytes_read = file.read(&mut buffer).map_err(|e| e.to_string())?;

        let mut hasher = Sha1::new();
        hasher.update(&buffer[..bytes_read]);
        let result = hasher.finalize();

        Ok(format!("{:x}", result))
    }

    /// Returns JSON state for `lccom` `getstate` command
    pub fn get_state_json(&self) -> serde_json::Value {
        let map = self.entries.lock().unwrap();
        let list: Vec<serde_json::Value> = map.values().map(|e| {
            serde_json::json!({
                "path": e.path,
                "offset": e.offset,
                "hash": e.hash,
                "lines_read": e.lines_read,
                "drop_lines": e.drop_lines,
                "status": e.status,
            })
        }).collect();

        serde_json::json!({
            "files": list,
            "total_files": list.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_file_state_persistence_and_update() {
        let tmp = NamedTempFile::new().unwrap();
        let state_path = tmp.path().to_path_buf();

        let manager = FileStateManager::new(&state_path);
        manager.update("/var/log/syslog", 1024, "abcd1234sha1", 50, 2);
        manager.save().unwrap();

        let manager2 = FileStateManager::new(&state_path);
        assert_eq!(manager2.get_offset("/var/log/syslog"), Some(1024));

        let json = manager2.get_state_json();
        assert_eq!(json["total_files"], 1);
        assert_eq!(json["files"][0]["hash"], "abcd1234sha1");
    }
}
