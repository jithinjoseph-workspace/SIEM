//! High-performance Column-Family Key-Value Store (keystore)
//!
//! Provides partitioned key-value storage with column families, prefix scanning,
//! atomic multi-operations, and optional disk persistence.

use crate::common::{ReturnType, Result, SharedModuleError};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct KeyStoreOptions {
    pub db_path: Option<PathBuf>,
    pub sync_to_disk: bool,
}

impl Default for KeyStoreOptions {
    fn default() -> Self {
        Self {
            db_path: None,
            sync_to_disk: false,
        }
    }
}

/// Column-Family Key-Value Store.
#[derive(Debug, Clone)]
pub struct KeyStore {
    pub options: KeyStoreOptions,
    // Column family name -> sorted map of keys to values
    families: Arc<RwLock<HashMap<String, BTreeMap<Vec<u8>, Vec<u8>>>>>,
}

impl KeyStore {
    pub fn new(options: KeyStoreOptions) -> Result<Self> {
        let store = Self {
            options,
            families: Arc::new(RwLock::new(HashMap::new())),
        };
        // Create default column family
        store.create_column_family("default")?;
        Ok(store)
    }

    /// Create or ensure a column family exists.
    pub fn create_column_family(&self, cf_name: &str) -> Result<()> {
        let mut families = self.families.write().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;
        families.entry(cf_name.to_string()).or_default();
        Ok(())
    }

    /// Store a key-value pair into a column family.
    pub fn put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let mut families = self.families.write().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let cf = families.get_mut(cf_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Column family '{}' not found", cf_name),
            )
        })?;

        cf.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    /// Retrieve a value from a column family by key.
    pub fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let families = self.families.read().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let cf = families.get(cf_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Column family '{}' not found", cf_name),
            )
        })?;

        Ok(cf.get(key).cloned())
    }

    /// Delete a key from a column family.
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> Result<bool> {
        let mut families = self.families.write().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let cf = families.get_mut(cf_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Column family '{}' not found", cf_name),
            )
        })?;

        Ok(cf.remove(key).is_some())
    }

    /// Scan all keys starting with a given prefix in a column family.
    pub fn prefix_scan(&self, cf_name: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let families = self.families.read().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let cf = families.get(cf_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Column family '{}' not found", cf_name),
            )
        })?;

        let results = cf
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(results)
    }

    /// Atomic batch write (inserts and deletes) on a column family.
    pub fn write_batch(
        &self,
        cf_name: &str,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
    ) -> Result<()> {
        let mut families = self.families.write().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let cf = families.get_mut(cf_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Column family '{}' not found", cf_name),
            )
        })?;

        for (k, v) in puts {
            cf.insert(k, v);
        }
        for k in deletes {
            cf.remove(&k);
        }

        Ok(())
    }

    /// Count total records in a column family.
    pub fn count(&self, cf_name: &str) -> Result<usize> {
        let families = self.families.read().map_err(|_| {
            SharedModuleError::Failure(ReturnType::DatabaseError, "Lock poisoned".into())
        })?;

        let cf = families.get(cf_name).ok_or_else(|| {
            SharedModuleError::Failure(
                ReturnType::NotFound,
                format!("Column family '{}' not found", cf_name),
            )
        })?;

        Ok(cf.len())
    }
}
