use std::collections::HashMap;
use crate::models::{FimAction, FimDelta, FimEntry};

#[derive(Debug, Clone, Default)]
pub struct FimStore {
    entries: HashMap<String, FimEntry>,
}

impl FimStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Upsert a FIM entry, automatically detecting whether it was Added or Modified
    pub fn upsert(&mut self, mut new_entry: FimEntry) -> Option<FimDelta> {
        let path = new_entry.full_path.clone();

        if let Some(old) = self.entries.get_mut(&path) {
            // Check if checksum, size, or perm changed
            let checksum_changed = old.sha256 != new_entry.sha256
                || old.md5 != new_entry.md5
                || old.sha1 != new_entry.sha1;
            let size_changed = old.size != new_entry.size;
            let perm_changed = old.perm != new_entry.perm;
            let mtime_changed = old.mtime != new_entry.mtime;

            if checksum_changed || size_changed || perm_changed || mtime_changed {
                new_entry.changes = old.changes + 1;
                let delta = FimDelta {
                    path: path.clone(),
                    action: FimAction::Modified,
                    old_entry: Some(old.clone()),
                    new_entry: Some(new_entry.clone()),
                };
                *old = new_entry;
                Some(delta)
            } else {
                // Unchanged
                None
            }
        } else {
            // New file added
            new_entry.changes = 1;
            let delta = FimDelta {
                path: path.clone(),
                action: FimAction::Added,
                old_entry: None,
                new_entry: Some(new_entry.clone()),
            };
            self.entries.insert(path, new_entry);
            Some(delta)
        }
    }

    /// Delete a FIM entry (e.g. file removed on agent)
    pub fn delete(&mut self, path: &str) -> Option<FimDelta> {
        if let Some(old) = self.entries.remove(path) {
            Some(FimDelta {
                path: path.to_string(),
                action: FimAction::Deleted,
                old_entry: Some(old),
                new_entry: None,
            })
        } else {
            None
        }
    }

    pub fn get(&self, path: &str) -> Option<&FimEntry> {
        self.entries.get(path)
    }

    pub fn list(&self) -> Vec<FimEntry> {
        self.entries.values().cloned().collect()
    }

    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::FimEntryType;

    #[test]
    fn test_fim_upsert_added_and_modified() {
        let mut store = FimStore::new();

        let file1 = FimEntry {
            full_path: "/etc/passwd".to_string(),
            file_name: "passwd".to_string(),
            entry_type: FimEntryType::File,
            size: Some(1024),
            perm: Some("0644".to_string()),
            uid: Some("0".to_string()),
            gid: Some("0".to_string()),
            md5: Some("md5_initial".to_string()),
            sha1: None,
            sha256: Some("sha256_initial".to_string()),
            mtime: 1700000000,
            inode: Some(12345),
            changes: 0,
            date: 1700000000,
        };

        // 1. Initial addition
        let delta1 = store.upsert(file1.clone()).expect("Should generate Added delta");
        assert_eq!(delta1.action, FimAction::Added);
        assert_eq!(store.get("/etc/passwd").unwrap().changes, 1);

        // 2. Exact same file: no delta
        let delta_noop = store.upsert(file1.clone());
        assert!(delta_noop.is_none());

        // 3. File modified: changed sha256
        let mut modified = file1;
        modified.sha256 = Some("sha256_modified".to_string());
        modified.size = Some(1080);
        let delta2 = store.upsert(modified).expect("Should generate Modified delta");
        assert_eq!(delta2.action, FimAction::Modified);
        assert_eq!(store.get("/etc/passwd").unwrap().changes, 2);

        // 4. File deleted
        let delta3 = store.delete("/etc/passwd").expect("Should generate Deleted delta");
        assert_eq!(delta3.action, FimAction::Deleted);
        assert_eq!(store.total_entries(), 0);
    }
}
