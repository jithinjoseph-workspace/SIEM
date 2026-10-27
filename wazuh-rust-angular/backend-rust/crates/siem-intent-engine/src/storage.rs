use std::fs;
use std::path::Path;
use crate::models::EntityIntentDossier;

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct IntentEngineStorage {
    pub dossiers: Vec<EntityIntentDossier>,
    pub executed_actions: Vec<String>,
}

pub fn load_storage(path: &Path) -> Option<IntentEngineStorage> {
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(store) = serde_json::from_str::<IntentEngineStorage>(&content) {
                return Some(store);
            }
        }
    }
    None
}

pub fn save_storage(path: &Path, store: &IntentEngineStorage) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(store) {
        let _ = fs::write(path, json);
    }
}

pub fn default_storage() -> IntentEngineStorage {
    IntentEngineStorage {
        dossiers: Vec::new(),
        executed_actions: Vec::new(),
    }
}

