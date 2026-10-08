use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValue {
    pub key_path: String,
    pub name: String,
    pub val_type: String,
    pub data: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryAction {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryDelta {
    pub action: RegistryAction,
    pub value: RegistryValue,
    pub old_value: Option<RegistryValue>,
}

pub struct RegistryMonitor {
    baseline: RwLock<HashMap<String, RegistryValue>>, // keyed by "key_path\value_name"
}

impl Default for RegistryMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryMonitor {
    pub fn new() -> Self {
        Self {
            baseline: RwLock::new(HashMap::new()),
        }
    }

    /// Upsert a registry value and check for modifications
    pub fn upsert_value(&self, val: RegistryValue) -> Option<RegistryDelta> {
        let key = format!("{}\\{}", val.key_path, val.name);
        let mut baseline = self.baseline.write().unwrap();

        if let Some(existing) = baseline.get(&key) {
            if existing.hash != val.hash || existing.data != val.data {
                let old = existing.clone();
                baseline.insert(key, val.clone());
                Some(RegistryDelta {
                    action: RegistryAction::Modified,
                    value: val,
                    old_value: Some(old),
                })
            } else {
                None
            }
        } else {
            baseline.insert(key, val.clone());
            Some(RegistryDelta {
                action: RegistryAction::Added,
                value: val,
                old_value: None,
            })
        }
    }

    /// Mark a registry value as deleted
    pub fn delete_value(&self, key_path: &str, name: &str) -> Option<RegistryDelta> {
        let key = format!("{}\\{}", key_path, name);
        let mut baseline = self.baseline.write().unwrap();
        baseline.remove(&key).map(|old| RegistryDelta {
            action: RegistryAction::Deleted,
            value: old.clone(),
            old_value: Some(old),
        })
    }

    pub fn total_entries(&self) -> usize {
        self.baseline.read().unwrap().len()
    }
}
