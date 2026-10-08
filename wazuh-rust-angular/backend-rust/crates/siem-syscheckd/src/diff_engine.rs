use std::path::{Path, PathBuf};

pub struct DiffEngine {
    pub diff_storage_dir: PathBuf,
    pub max_file_size_bytes: u64,
}

impl DiffEngine {
    pub fn new(storage_dir: impl Into<PathBuf>, max_size_mb: usize) -> Self {
        let dir = storage_dir.into();
        let _ = std::fs::create_dir_all(&dir);
        Self {
            diff_storage_dir: dir,
            max_file_size_bytes: (max_size_mb as u64) * 1024 * 1024,
        }
    }

    /// Computes a unified diff between two text strings
    pub fn compute_unified_diff(old_text: &str, new_text: &str, file_label: &str) -> String {
        let old_lines: Vec<&str> = old_text.lines().collect();
        let new_lines: Vec<&str> = new_text.lines().collect();

        if old_lines == new_lines {
            return String::new();
        }

        let mut diff = String::new();
        diff.push_str(&format!("--- {file_label} (original)\n"));
        diff.push_str(&format!("+++ {file_label} (current)\n"));
        diff.push_str("@@ -1 +1 @@\n");

        // Simple line-by-line comparison
        let max_len = old_lines.len().max(new_lines.len());
        for i in 0..max_len {
            match (old_lines.get(i), new_lines.get(i)) {
                (Some(&o), Some(&n)) => {
                    if o != n {
                        diff.push_str(&format!("-{o}\n"));
                        diff.push_str(&format!("+{n}\n"));
                    } else {
                        diff.push_str(&format!(" {o}\n"));
                    }
                }
                (Some(&o), None) => {
                    diff.push_str(&format!("-{o}\n"));
                }
                (None, Some(&n)) => {
                    diff.push_str(&format!("+{n}\n"));
                }
                (None, None) => {}
            }
        }

        diff
    }

    /// Generates diff for a file against its previous stored snapshot, and updates snapshot
    pub fn generate_and_update_diff(&self, file_path: &Path) -> Option<String> {
        let meta = std::fs::metadata(file_path).ok()?;
        if meta.len() > self.max_file_size_bytes {
            return Some("[Diff skipped: File size exceeds file_size_limit]".to_string());
        }

        let new_content = std::fs::read_to_string(file_path).ok()?;

        // Safe relative path representation for snapshot storage
        let sanitized = file_path
            .to_string_lossy()
            .replace([':', '\\', '/'], "_");
        let snapshot_file = self.diff_storage_dir.join(&sanitized);

        let diff_result = if snapshot_file.exists() {
            let old_content = std::fs::read_to_string(&snapshot_file).unwrap_or_default();
            let d = Self::compute_unified_diff(&old_content, &new_content, &file_path.to_string_lossy());
            if d.is_empty() { None } else { Some(d) }
        } else {
            // First time seeing this file, save snapshot, no diff yet
            None
        };

        // Update stored snapshot
        let _ = std::fs::write(&snapshot_file, &new_content);

        diff_result
    }
}
