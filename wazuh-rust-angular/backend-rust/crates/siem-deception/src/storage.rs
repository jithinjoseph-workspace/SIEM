use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::error;

use crate::models::{DeceptionAsset, TripwireEvent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionStorage {
    pub assets: Vec<DeceptionAsset>,
    pub tripwire_events: Vec<TripwireEvent>,
}

/// A new install starts with no deception assets and no tripwire events.
pub fn default_storage() -> DeceptionStorage {
    DeceptionStorage { assets: Vec::new(), tripwire_events: Vec::new() }
}

/// The demo entries earlier versions started with, removed from stored data.
const DEMO_ASSETS: [&str; 3] = ["Production KeePass Master Vault Tripwire", "Cloud IAM Root Honeytoken Profile", "DMZ Redis Decoy Recon Trap"];

pub fn without_demo(mut s: DeceptionStorage) -> DeceptionStorage {
    s.assets.retain(|a| !DEMO_ASSETS.contains(&a.name.as_str()));
    s.tripwire_events.retain(|t| !DEMO_ASSETS.contains(&t.asset_name.as_str()));
    s
}

pub fn load_storage(path: &Path) -> Option<DeceptionStorage> {
    if !path.exists() {
        return None;
    }
    match fs::read_to_string(path) {
        Ok(data) => match serde_json::from_str::<DeceptionStorage>(&data) {
            Ok(store) => Some(store),
            Err(e) => {
                error!("Failed to parse deception storage from {:?}: {}", path, e);
                None
            }
        },
        Err(e) => {
            error!("Failed to read deception storage from {:?}: {}", path, e);
            None
        }
    }
}
