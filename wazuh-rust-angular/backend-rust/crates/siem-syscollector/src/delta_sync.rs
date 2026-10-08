use serde::{Deserialize, Serialize};
use sha1_smol::Sha1;
use std::collections::{HashMap, HashSet};

/// Synchronization operations matching Wazuh dbsync / syscollectorImp.cpp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SyncOperation {
    Inserted,
    Modified,
    Deleted,
}

/// Delta sync message payload sent from agent to manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDelta {
    pub table: String,
    pub operation: SyncOperation,
    pub item_id: String,
    pub checksum: String,
    pub data: serde_json::Value,
}

/// Calculates the SHA-1 item ID based on primary key fields.
/// Matches Wazuh getItemId in syscollectorImp.cpp.
pub fn get_item_id(item: &serde_json::Value, id_fields: &[&str]) -> String {
    let mut hasher = Sha1::new();

    for field in id_fields {
        if let Some(val) = item.get(*field) {
            if let Some(s) = val.as_str() {
                hasher.update(s.as_bytes());
            } else if let Some(n) = val.as_i64() {
                hasher.update(n.to_string().as_bytes());
            } else if let Some(u) = val.as_u64() {
                hasher.update(u.to_string().as_bytes());
            }
        }
    }

    hasher.digest().to_string()
}

/// Calculates the SHA-1 checksum of the entire item content.
/// Matches Wazuh getItemChecksum in syscollectorImp.cpp.
pub fn get_item_checksum(item: &serde_json::Value) -> String {
    let mut hasher = Sha1::new();
    let content = item.to_string();
    hasher.update(content.as_bytes());
    hasher.digest().to_string()
}

/// Agent-side or manager-side table sync cache tracking item IDs and checksums.
/// Ported from Wazuh syscollectorImp.cpp.
#[derive(Debug, Clone, Default)]
pub struct TableSyncCache {
    /// Maps item_id -> checksum
    state: HashMap<String, String>,
}

impl TableSyncCache {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }

    /// Compute delta updates (Inserted, Modified, Deleted) between previous scan and current items.
    pub fn compute_deltas(
        &mut self,
        table_name: &str,
        current_items: &[serde_json::Value],
        id_fields: &[&str],
    ) -> Vec<SyncDelta> {
        let mut deltas = Vec::new();
        let mut seen_ids = HashSet::new();

        for item in current_items {
            let item_id = get_item_id(item, id_fields);
            let checksum = get_item_checksum(item);
            seen_ids.insert(item_id.clone());

            if let Some(prev_checksum) = self.state.get(&item_id) {
                if *prev_checksum != checksum {
                    // Item content changed
                    deltas.push(SyncDelta {
                        table: table_name.to_string(),
                        operation: SyncOperation::Modified,
                        item_id: item_id.clone(),
                        checksum: checksum.clone(),
                        data: item.clone(),
                    });
                    self.state.insert(item_id, checksum);
                }
            } else {
                // New item added
                deltas.push(SyncDelta {
                    table: table_name.to_string(),
                    operation: SyncOperation::Inserted,
                    item_id: item_id.clone(),
                    checksum: checksum.clone(),
                    data: item.clone(),
                });
                self.state.insert(item_id, checksum);
            }
        }

        // Check for deleted items
        let mut deleted_ids = Vec::new();
        for (id, prev_checksum) in &self.state {
            if !seen_ids.contains(id) {
                deleted_ids.push((id.clone(), prev_checksum.clone()));
            }
        }

        for (id, checksum) in deleted_ids {
            self.state.remove(&id);
            deltas.push(SyncDelta {
                table: table_name.to_string(),
                operation: SyncOperation::Deleted,
                item_id: id,
                checksum,
                data: serde_json::Value::Null,
            });
        }

        deltas
    }

    /// Total items currently in cache.
    pub fn len(&self) -> usize {
        self.state.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_delta_computation_lifecycle() {
        let mut cache = TableSyncCache::new();

        // 1. First scan: 2 packages inserted
        let scan_1 = vec![
            json!({"name": "curl", "version": "7.74.0", "architecture": "x86_64"}),
            json!({"name": "sudo", "version": "1.8.31", "architecture": "x86_64"}),
        ];

        let deltas_1 = cache.compute_deltas("packages", &scan_1, &["name", "architecture"]);
        assert_eq!(deltas_1.len(), 2);
        assert_eq!(deltas_1[0].operation, SyncOperation::Inserted);
        assert_eq!(deltas_1[1].operation, SyncOperation::Inserted);

        // 2. Second scan: curl upgraded, sudo unchanged, nginx added -> 1 Modified, 1 Inserted
        let scan_2 = vec![
            json!({"name": "curl", "version": "8.4.0", "architecture": "x86_64"}),
            json!({"name": "sudo", "version": "1.8.31", "architecture": "x86_64"}),
            json!({"name": "nginx", "version": "1.24.0", "architecture": "x86_64"}),
        ];

        let deltas_2 = cache.compute_deltas("packages", &scan_2, &["name", "architecture"]);
        assert_eq!(deltas_2.len(), 2);
        let ops: Vec<SyncOperation> = deltas_2.iter().map(|d| d.operation).collect();
        assert!(ops.contains(&SyncOperation::Modified));
        assert!(ops.contains(&SyncOperation::Inserted));

        // 3. Third scan: sudo removed -> 1 Deleted
        let scan_3 = vec![
            json!({"name": "curl", "version": "8.4.0", "architecture": "x86_64"}),
            json!({"name": "nginx", "version": "1.24.0", "architecture": "x86_64"}),
        ];

        let deltas_3 = cache.compute_deltas("packages", &scan_3, &["name", "architecture"]);
        assert_eq!(deltas_3.len(), 1);
        assert_eq!(deltas_3[0].operation, SyncOperation::Deleted);
    }
}
