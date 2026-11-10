//! Diff generator for FIM and file change detection (parity with src/analysisd/dodiff.c)

use std::fs;
use std::path::PathBuf;
use tracing::warn;

pub struct DiffEngine {
    diff_dir: PathBuf,
}

impl DiffEngine {
    pub fn new(diff_dir: impl Into<PathBuf>) -> Self {
        Self {
            diff_dir: diff_dir.into(),
        }
    }

    /// Computes diff between previous output and current output for a specific agent and rule.
    /// Updates the stored last-entry file.
    pub fn compute_diff(
        &self,
        agent_id: &str,
        rule_id: u32,
        current_content: &str,
    ) -> Option<String> {
        let agent_clean = agent_id.replace(['/', '\\', '(', ')'], "_");
        let rule_dir = self.diff_dir.join(&agent_clean).join(rule_id.to_string());

        if let Err(e) = fs::create_dir_all(&rule_dir) {
            warn!("DiffEngine: Failed to create diff directory {:?}: {}", rule_dir, e);
            return None;
        }

        let last_file = rule_dir.join("last-entry");

        let previous_content = if last_file.exists() {
            fs::read_to_string(&last_file).unwrap_or_default()
        } else {
            // First time seeing this file or entry; write current and return initial notice
            if let Err(e) = fs::write(&last_file, current_content) {
                warn!("DiffEngine: Failed to write initial last-entry {:?}: {}", last_file, e);
            }
            return Some(format!("Initial baseline recorded for agent {} (rule {})", agent_id, rule_id));
        };

        if previous_content == current_content {
            return None; // No changes
        }

        // Generate line-by-line diff
        let diff = generate_unified_diff(&previous_content, current_content);

        // Update the last-entry file
        if let Err(e) = fs::write(&last_file, current_content) {
            warn!("DiffEngine: Failed to update last-entry {:?}: {}", last_file, e);
        }

        Some(diff)
    }
}

/// Simple unified diff generator (lines prefixed with - for deletions, + for additions)
pub fn generate_unified_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let mut out = String::new();
    out.push_str("--- Previous\n+++ Current\n");

    let max_len = old_lines.len().max(new_lines.len());
    for i in 0..max_len {
        let old_line = old_lines.get(i);
        let new_line = new_lines.get(i);

        match (old_line, new_line) {
            (Some(o), Some(n)) if o == n => {
                out.push_str(&format!(" {}\n", o));
            }
            (Some(o), Some(n)) => {
                out.push_str(&format!("-{}\n", o));
                out.push_str(&format!("+{}\n", n));
            }
            (Some(o), None) => {
                out.push_str(&format!("-{}\n", o));
            }
            (None, Some(n)) => {
                out.push_str(&format!("+{}\n", n));
            }
            (None, None) => {}
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_diff() {
        let old = "line 1\nline 2\nline 3";
        let new = "line 1\nline 2 modified\nline 3\nline 4";

        let diff = generate_unified_diff(old, new);
        assert!(diff.contains("-line 2"));
        assert!(diff.contains("+line 2 modified"));
        assert!(diff.contains("+line 4"));
    }

    #[test]
    fn test_diff_engine_flow() {
        let tmp = std::env::temp_dir().join("wazuh_diff_test");
        let engine = DiffEngine::new(&tmp);

        let res1 = engine.compute_diff("001", 550, "root:x:0:0:root:/root:/bin/bash");
        assert!(res1.is_some());
        assert!(res1.unwrap().contains("Initial baseline"));

        let res2 = engine.compute_diff("001", 550, "root:x:0:0:root:/root:/bin/bash\nattacker:x:0:0::/root:/bin/sh");
        assert!(res2.is_some());
        assert!(res2.unwrap().contains("+attacker:x:0:0::/root:/bin/sh"));

        let _ = fs::remove_dir_all(tmp);
    }
}
