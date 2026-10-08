//! Database synchronization engine (dbsync)
//!
//! Provides table snapshot synchronization, row hashing (item ID),
//! composite checksum generation, and delta calculation (INSERTED, MODIFIED, DELETED).

use crate::common::{ReturnType, Result, SharedModuleError};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

/// Operation types in a database synchronization delta stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SyncOperation {
    Inserted,
    Modified,
    Deleted,
}

/// A synchronization change event for a table row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncRowDelta {
    pub table: String,
    pub operation: SyncOperation,
    pub item_id: String,
    pub primary_keys: HashMap<String, serde_json::Value>,
    pub data: serde_json::Value,
    pub checksum: String,
}

/// Schema definition for a table in the sync engine.
#[derive(Debug, Clone)]
pub struct TableSchema {
    pub name: String,
    pub primary_keys: Vec<String>,
}

/// Internal stored record in table state.
#[derive(Debug, Clone)]
struct StoredRow {
    #[allow(dead_code)]
    item_id: String,
    primary_keys: HashMap<String, serde_json::Value>,
    data: serde_json::Value,
    checksum: String,
}

/// Generic Database Sync Engine maintaining table states and producing deltas.
#[derive(Debug, Clone, Default)]
pub struct DbSyncEngine {
    tables: Arc<RwLock<HashMap<String, TableState>>>,
}

#[derive(Debug, Clone)]
struct TableState {
    schema: TableSchema,
    // Keyed by item_id (sorted for deterministic checksum ranges)
    rows: BTreeMap<String, StoredRow>,
}

impl DbSyncEngine {
    pub fn new() -> Self {
        Self {
            tables: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a table with its primary key column names.
    pub fn register_table(&self, table_name: &str, primary_keys: Vec<&str>) -> Result<()> {
        let mut tables = self.tables.write().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        tables.insert(
            table_name.to_string(),
            TableState {
                schema: TableSchema {
                    name: table_name.to_string(),
                    primary_keys: primary_keys.into_iter().map(|s| s.to_string()).collect(),
                },
                rows: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Compute canonical SHA-1 item ID from primary keys.
    pub fn compute_item_id(
        primary_keys: &[String],
        row: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<String> {
        let mut hasher = Sha1::new();
        for key in primary_keys {
            let val = row.get(key).unwrap_or(&serde_json::Value::Null);
            hasher.update(key.as_bytes());
            hasher.update(b"=");
            hasher.update(val.to_string().as_bytes());
            hasher.update(b";");
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Compute canonical SHA-1 checksum of row content.
    pub fn compute_row_checksum(row: &serde_json::Map<String, serde_json::Value>) -> String {
        let mut hasher = Sha1::new();
        // Sort keys for deterministic hashing
        let mut sorted_keys: Vec<&String> = row.keys().collect();
        sorted_keys.sort();

        for key in sorted_keys {
            let val = &row[key];
            hasher.update(key.as_bytes());
            hasher.update(b":");
            hasher.update(val.to_string().as_bytes());
            hasher.update(b"|");
        }
        format!("{:x}", hasher.finalize())
    }

    /// Synchronize a full snapshot of rows for a table, computing INSERTED, MODIFIED, and DELETED deltas.
    pub fn sync_snapshot(
        &self,
        table_name: &str,
        rows: Vec<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<Vec<SyncRowDelta>> {
        let mut tables = self.tables.write().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let state = tables.get_mut(table_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Table '{}' not registered", table_name),
            )
        })?;

        let mut deltas = Vec::new();
        let mut current_item_ids = std::collections::HashSet::new();

        for row_map in rows {
            let item_id = Self::compute_item_id(&state.schema.primary_keys, &row_map)?;
            current_item_ids.insert(item_id.clone());

            let checksum = Self::compute_row_checksum(&row_map);
            let mut pk_map = HashMap::new();
            for pk in &state.schema.primary_keys {
                if let Some(v) = row_map.get(pk) {
                    pk_map.insert(pk.clone(), v.clone());
                }
            }

            let row_val = serde_json::Value::Object(row_map);

            if let Some(existing) = state.rows.get_mut(&item_id) {
                if existing.checksum != checksum {
                    // MODIFIED
                    existing.checksum = checksum.clone();
                    existing.data = row_val.clone();
                    deltas.push(SyncRowDelta {
                        table: table_name.to_string(),
                        operation: SyncOperation::Modified,
                        item_id: item_id.clone(),
                        primary_keys: pk_map,
                        data: row_val,
                        checksum,
                    });
                }
            } else {
                // INSERTED
                state.rows.insert(
                    item_id.clone(),
                    StoredRow {
                        item_id: item_id.clone(),
                        primary_keys: pk_map.clone(),
                        data: row_val.clone(),
                        checksum: checksum.clone(),
                    },
                );
                deltas.push(SyncRowDelta {
                    table: table_name.to_string(),
                    operation: SyncOperation::Inserted,
                    item_id,
                    primary_keys: pk_map,
                    data: row_val,
                    checksum,
                });
            }
        }

        // Detect DELETED rows (present in state but missing in snapshot)
        let to_remove: Vec<String> = state
            .rows
            .keys()
            .filter(|k| !current_item_ids.contains(*k))
            .cloned()
            .collect();

        for deleted_id in to_remove {
            if let Some(removed) = state.rows.remove(&deleted_id) {
                deltas.push(SyncRowDelta {
                    table: table_name.to_string(),
                    operation: SyncOperation::Deleted,
                    item_id: deleted_id,
                    primary_keys: removed.primary_keys,
                    data: removed.data,
                    checksum: removed.checksum,
                });
            }
        }

        Ok(deltas)
    }

    /// Calculate aggregate checksum for a table (or range of item IDs).
    pub fn get_table_checksum(&self, table_name: &str) -> Result<String> {
        let tables = self.tables.read().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let state = tables.get(table_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Table '{}' not registered", table_name),
            )
        })?;

        let mut hasher = Sha1::new();
        for (item_id, row) in &state.rows {
            hasher.update(item_id.as_bytes());
            hasher.update(b":");
            hasher.update(row.checksum.as_bytes());
            hasher.update(b"\n");
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Get total row count for a table.
    pub fn get_row_count(&self, table_name: &str) -> Result<usize> {
        let tables = self.tables.read().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let state = tables.get(table_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Table '{}' not registered", table_name),
            )
        })?;

        Ok(state.rows.len())
    }
}
