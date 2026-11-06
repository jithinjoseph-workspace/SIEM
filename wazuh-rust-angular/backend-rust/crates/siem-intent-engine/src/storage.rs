//! The dossier file of earlier versions, read once to move it to ClickHouse: from then on
//! siem-api stores the dossiers (`IntentEngine::take_changed`).

use std::fs;
use std::path::Path;
use crate::models::EntityIntentDossier;

#[derive(serde::Deserialize)]
pub struct IntentEngineStorage {
    pub dossiers: Vec<EntityIntentDossier>,
}

pub fn load_storage(path: &Path) -> Option<IntentEngineStorage> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}
