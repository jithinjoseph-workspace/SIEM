//! The dossier file of earlier versions, read once to move it to ClickHouse: from then on
//! siem-api stores the dossiers (`IntentEngine::take_changed`) and the extras
//! (`IntentEngine::take_extras`).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::models::{ActionAuditRecord, EntityIntentDossier, SimulationIntentRequest};

/// The executed actions, the action audit log and the simulation overrides.
#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct IntentExtras {
    #[serde(default)]
    pub executed_actions: Vec<String>,
    #[serde(default)]
    pub action_audit: Vec<ActionAuditRecord>,
    #[serde(default)]
    pub simulation_overrides: HashMap<String, SimulationIntentRequest>,
}

#[derive(serde::Deserialize)]
pub struct IntentEngineStorage {
    pub dossiers: Vec<EntityIntentDossier>,
    #[serde(flatten)]
    pub extras: IntentExtras,
}

pub fn load_storage(path: &Path) -> Option<IntentEngineStorage> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}
