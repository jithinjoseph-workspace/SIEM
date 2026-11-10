//! Shared Configuration Download & Merged File Generator (shared_download.c, cfga-forward.c)
//!
//! Generates `merged.mg` bundles (`agent.conf`) for agent groups and multigroups,
//! and coordinates configuration synchronization with connected agents.

use sha1::{Digest as Sha1Digest, Sha1};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFile {
    pub name: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct SharedConfigManager {
    // Group name -> list of shared files (e.g. agent.conf)
    groups: HashMap<String, Vec<SharedFile>>,
}

impl SharedConfigManager {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Add or update a configuration file for a specific agent group.
    pub fn set_group_file(&mut self, group: &str, file_name: &str, content: Vec<u8>) {
        let files = self.groups.entry(group.to_string()).or_default();
        if let Some(existing) = files.iter_mut().find(|f| f.name == file_name) {
            existing.content = content;
        } else {
            files.push(SharedFile {
                name: file_name.to_string(),
                content,
            });
        }
    }

    /// Generate the canonical `merged.mg` binary format:
    /// For each file: `!{size} {name}\n{content}`
    pub fn generate_merged_mg(&self, group: &str) -> Vec<u8> {
        let mut bundle = Vec::new();
        if let Some(files) = self.groups.get(group) {
            for file in files {
                let header = format!("!{} {}\n", file.content.len(), file.name);
                bundle.extend_from_slice(header.as_bytes());
                bundle.extend_from_slice(&file.content);
            }
        }
        bundle
    }

    /// Resolve and merge multiple groups for an agent (multigroup: e.g. "default,web,prod")
    /// Concat/merges the files across all groups.
    pub fn generate_multigroup_merged_mg(&self, multigroup_str: &str) -> Vec<u8> {
        let group_names: Vec<&str> = multigroup_str.split(',').map(|s| s.trim()).collect();
        let mut combined_files: HashMap<String, Vec<u8>> = HashMap::new();

        for grp in group_names {
            if let Some(files) = self.groups.get(grp) {
                for file in files {
                    if file.name == "agent.conf" {
                        // Concatenate agent.conf sections
                        let entry = combined_files.entry("agent.conf".to_string()).or_default();
                        entry.extend_from_slice(&file.content);
                        entry.push(b'\n');
                    } else {
                        combined_files.insert(file.name.clone(), file.content.clone());
                    }
                }
            }
        }

        let mut bundle = Vec::new();
        let mut sorted_keys: Vec<&String> = combined_files.keys().collect();
        sorted_keys.sort();

        for key in sorted_keys {
            let content = &combined_files[key];
            let header = format!("!{} {}\n", content.len(), key);
            bundle.extend_from_slice(header.as_bytes());
            bundle.extend_from_slice(content);
        }

        bundle
    }

    /// Compute SHA-1 checksum of group's `merged.mg` bundle.
    pub fn compute_merged_checksum(&self, group: &str) -> String {
        let bundle = self.generate_merged_mg(group);
        let mut hasher = Sha1::new();
        hasher.update(&bundle);
        format!("{:x}", hasher.finalize())
    }

    /// Compute SHA-1 checksum of multigroup `merged.mg` bundle.
    pub fn compute_multigroup_checksum(&self, multigroup_str: &str) -> String {
        let bundle = self.generate_multigroup_merged_mg(multigroup_str);
        let mut hasher = Sha1::new();
        hasher.update(&bundle);
        format!("{:x}", hasher.finalize())
    }

    /// Parse a `merged.mg` bundle back into individual files (used by agent).
    pub fn parse_merged_mg(bundle: &[u8]) -> Result<Vec<SharedFile>, String> {
        let mut files = Vec::new();
        let mut cursor = 0;

        while cursor < bundle.len() {
            let next_nl = bundle[cursor..]
                .iter()
                .position(|&b| b == b'\n')
                .ok_or_else(|| "Malformed merged.mg header (missing newline)".to_string())?;

            let header_str = std::str::from_utf8(&bundle[cursor..cursor + next_nl])
                .map_err(|e| format!("Invalid UTF-8 in header: {}", e))?;

            if !header_str.starts_with('!') {
                return Err("Header does not start with '!'".to_string());
            }

            let parts: Vec<&str> = header_str[1..].split_whitespace().collect();
            if parts.len() < 2 {
                return Err(format!("Invalid header tokens: '{}'", header_str));
            }

            let file_size: usize = parts[0]
                .parse()
                .map_err(|e| format!("Invalid file size in header: {}", e))?;
            let file_name = parts[1].to_string();

            let content_start = cursor + next_nl + 1;
            let content_end = content_start + file_size;

            if content_end > bundle.len() {
                return Err("File content exceeds bundle boundary".to_string());
            }

            let content = bundle[content_start..content_end].to_vec();
            files.push(SharedFile {
                name: file_name,
                content,
            });

            cursor = content_end;
        }

        Ok(files)
    }
}
