use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{error, info};
use uuid::Uuid;

use crate::models::{AssetDeploymentStatus, DeceptionAsset, DeceptionAssetType, TripwireEvent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionStorage {
    pub assets: Vec<DeceptionAsset>,
    pub tripwire_events: Vec<TripwireEvent>,
}

pub fn default_storage() -> DeceptionStorage {
    let now = Utc::now();
    let asset1_id = format!("dec-{}", Uuid::new_v4());
    let asset2_id = format!("dec-{}", Uuid::new_v4());
    let asset3_id = format!("dec-{}", Uuid::new_v4());

    let assets = vec![
        DeceptionAsset {
            id: asset1_id.clone(),
            name: "Production KeePass Master Vault Tripwire".into(),
            asset_type: DeceptionAssetType::CanaryFile,
            target_agent_id: "001".into(),
            target_agent_name: "srv-prod-ubuntu-01".into(),
            target_path_or_port: "/var/data/shared/master_passwords_2026.kdbx".into(),
            decoy_payload_preview: "Encrypted KDBX4 format canary binary beacon".into(),
            status: AssetDeploymentStatus::Armed,
            tripped_count: 0,
            last_tripped_at: None,
            created_at: now,
            tags: vec!["canary".into(), "fim".into(), "credentials".into()],
            risk_reduction_score: 85,
        },
        DeceptionAsset {
            id: asset2_id.clone(),
            name: "Cloud IAM Root Honeytoken Profile".into(),
            asset_type: DeceptionAssetType::HoneytokenCredential,
            target_agent_id: "001".into(),
            target_agent_name: "srv-prod-ubuntu-01".into(),
            target_path_or_port: "/home/ubuntu/.aws/credentials".into(),
            decoy_payload_preview: "AKIA_TRIPWIRE_PROVIGIL_DEC [STS Beacon Active]".into(),
            status: AssetDeploymentStatus::Armed,
            tripped_count: 0,
            last_tripped_at: None,
            created_at: now,
            tags: vec!["aws".into(), "honeytoken".into(), "cloud".into()],
            risk_reduction_score: 92,
        },
        DeceptionAsset {
            id: asset3_id.clone(),
            name: "DMZ Redis Decoy Recon Trap".into(),
            asset_type: DeceptionAssetType::DecoyNetworkService,
            target_agent_id: "002".into(),
            target_agent_name: "dmz-web-nginx".into(),
            target_path_or_port: "tcp/6379".into(),
            decoy_payload_preview: "Ghost Redis v7 RESP Protocol Listener".into(),
            status: AssetDeploymentStatus::Triggered,
            tripped_count: 1,
            last_tripped_at: Some(now),
            created_at: now,
            tags: vec!["port-scan".into(), "decoy-service".into(), "dmz".into()],
            risk_reduction_score: 78,
        },
    ];

    let tripwire_events = vec![
        TripwireEvent {
            id: format!("trip-{}", Uuid::new_v4()),
            asset_id: asset3_id,
            asset_name: "DMZ Redis Decoy Recon Trap".into(),
            asset_type: DeceptionAssetType::DecoyNetworkService,
            agent_id: "002".into(),
            agent_name: "dmz-web-nginx".into(),
            attacker_ip: "185.220.101.5".into(),
            attacker_user: "unauthenticated".into(),
            process_name: "redis-probe-scanner".into(),
            mitre_technique: "T1046".into(),
            raw_evidence: "Adversary connected to ghost port 6379 and issued 'CONFIG GET *; INFO replication' commands.".into(),
            severity: "High".into(),
            timestamp: now,
        },
    ];

    DeceptionStorage {
        assets,
        tripwire_events,
    }
}

pub fn load_storage(path: &Path) -> Option<DeceptionStorage> {
    if !path.exists() {
        return None;
    }
    match fs::read_to_string(path) {
        Ok(data) => match serde_json::from_str::<DeceptionStorage>(&data) {
            Ok(store) => Some(store),
            Err(e) => {
                error!("Failed to parse deception config from {:?}: {}", path, e);
                None
            }
        },
        Err(e) => {
            error!("Failed to read deception config from {:?}: {}", path, e);
            None
        }
    }
}

pub fn save_storage(path: &Path, storage: &DeceptionStorage) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(storage) {
        Ok(json) => {
            let tmp_path = path.with_extension("tmp");
            if let Err(e) = fs::write(&tmp_path, json) {
                error!("Failed to write temporary deception file {:?}: {}", tmp_path, e);
                return;
            }
            if let Err(e) = fs::rename(&tmp_path, path) {
                error!("Failed to commit deception file {:?}: {}", path, e);
            } else {
                info!("Persisted deception grid configuration to {:?}", path);
            }
        }
        Err(e) => error!("Failed to serialize deception storage: {}", e),
    }
}
