use chrono::Utc;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::models::{
    AssetDeploymentStatus, CreateAssetRequest, DeceptionAsset, DeceptionAssetType,
    DeceptionBlueprint, DeceptionSummary, SimulateTripwireRequest, TripwireEvent,
};
use crate::storage::{self, DeceptionStorage};
use crate::templates::get_default_blueprints;

#[derive(Clone)]
pub struct DeceptionEngine {
    assets: Arc<RwLock<Vec<DeceptionAsset>>>,
    tripwire_events: Arc<RwLock<Vec<TripwireEvent>>>,
    blueprints: Vec<DeceptionBlueprint>,
    config_path: PathBuf,
}

impl DeceptionEngine {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        let path = config_path.into();
        let store = storage::load_storage(&path).unwrap_or_else(storage::default_storage);
        storage::save_storage(&path, &store);

        Self {
            assets: Arc::new(RwLock::new(store.assets)),
            tripwire_events: Arc::new(RwLock::new(store.tripwire_events)),
            blueprints: get_default_blueprints(),
            config_path: path,
        }
    }

    pub fn save(&self) {
        let store = DeceptionStorage {
            assets: self.assets.read().unwrap().clone(),
            tripwire_events: self.tripwire_events.read().unwrap().clone(),
        };
        storage::save_storage(&self.config_path, &store);
    }

    pub fn get_assets(&self) -> Vec<DeceptionAsset> {
        self.assets.read().unwrap().clone()
    }

    pub fn get_asset(&self, id: &str) -> Option<DeceptionAsset> {
        self.assets.read().unwrap().iter().find(|a| a.id == id).cloned()
    }

    pub fn get_triggers(&self) -> Vec<TripwireEvent> {
        let mut events = self.tripwire_events.read().unwrap().clone();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events
    }

    pub fn get_blueprints(&self) -> Vec<DeceptionBlueprint> {
        self.blueprints.clone()
    }

    pub fn create_asset(&self, req: CreateAssetRequest) -> DeceptionAsset {
        let now = Utc::now();
        let risk_reduction = match req.asset_type {
            DeceptionAssetType::HoneytokenCredential => 92,
            DeceptionAssetType::CanaryFile => 88,
            DeceptionAssetType::ActiveDirectoryDecoy => 95,
            DeceptionAssetType::DecoyNetworkService => 84,
            DeceptionAssetType::CanaryRegistryKey => 80,
        };

        let asset = DeceptionAsset {
            id: format!("dec-{}", Uuid::new_v4()),
            name: req.name,
            asset_type: req.asset_type,
            target_agent_id: req.target_agent_id,
            target_agent_name: req.target_agent_name,
            target_path_or_port: req.target_path_or_port,
            decoy_payload_preview: req.decoy_payload_preview.unwrap_or_else(|| "Active Deception Beacon".into()),
            status: AssetDeploymentStatus::Armed,
            tripped_count: 0,
            last_tripped_at: None,
            created_at: now,
            tags: req.tags.unwrap_or_else(|| vec!["deception".into(), "canary".into()]),
            risk_reduction_score: risk_reduction,
        };

        let mut list = self.assets.write().unwrap();
        list.push(asset.clone());
        drop(list);
        self.save();
        asset
    }

    pub fn delete_asset(&self, id: &str) -> Result<(), String> {
        let mut list = self.assets.write().unwrap();
        let initial_len = list.len();
        list.retain(|a| a.id != id);
        if list.len() < initial_len {
            drop(list);
            self.save();
            Ok(())
        } else {
            Err(format!("Deception asset with id '{}' not found", id))
        }
    }

    pub fn simulate_tripwire(&self, req: SimulateTripwireRequest) -> Result<TripwireEvent, String> {
        let now = Utc::now();
        let mut list = self.assets.write().unwrap();
        let asset = list.iter_mut().find(|a| a.id == req.asset_id);

        if let Some(a) = asset {
            a.status = AssetDeploymentStatus::Triggered;
            a.tripped_count += 1;
            a.last_tripped_at = Some(now);

            let event = TripwireEvent {
                id: format!("trip-{}", Uuid::new_v4()),
                asset_id: a.id.clone(),
                asset_name: a.name.clone(),
                asset_type: a.asset_type.clone(),
                agent_id: a.target_agent_id.clone(),
                agent_name: a.target_agent_name.clone(),
                attacker_ip: req.attacker_ip.unwrap_or_else(|| "198.51.100.44".into()),
                attacker_user: req.attacker_user.unwrap_or_else(|| "adversary_recon".into()),
                process_name: req.process_name.unwrap_or_else(|| "unauthorized_probe".into()),
                mitre_technique: req.mitre_technique.unwrap_or_else(|| "T1078".into()),
                raw_evidence: req.notes.unwrap_or_else(|| {
                    format!("Direct unauthorized access detected on armed deception asset '{}'", a.name)
                }),
                severity: "Critical".into(),
                timestamp: now,
            };

            drop(list);
            self.tripwire_events.write().unwrap().push(event.clone());
            self.save();
            Ok(event)
        } else {
            Err(format!("Asset with id '{}' not found", req.asset_id))
        }
    }

    /// Dynamically ingests real-time SIEM alerts and triggers matching canaries/decoys
    pub fn ingest_live_alerts(&self, alerts: &[siem_core::Alert]) {
        if alerts.is_empty() {
            return;
        }

        let now = Utc::now();
        let mut list = self.assets.write().unwrap();
        let mut new_trips = Vec::new();

        for alert in alerts {
            let log_text = alert.full_log.to_lowercase();
            let rule_desc = alert.rule.description.to_lowercase();
            let agent_id = &alert.agent.id;

            for asset in list.iter_mut() {
                let target_match = asset.target_agent_id == *agent_id || asset.target_agent_name == alert.agent.name;
                if !target_match {
                    continue;
                }

                let path_lower = asset.target_path_or_port.to_lowercase();
                let triggered = log_text.contains(&path_lower)
                    || rule_desc.contains(&path_lower)
                    || (log_text.contains("canary") && log_text.contains(&asset.name.to_lowercase()))
                    || (rule_desc.contains("tripwire") && rule_desc.contains(&asset.name.to_lowercase()));

                if triggered {
                    asset.status = AssetDeploymentStatus::Triggered;
                    asset.tripped_count += 1;
                    asset.last_tripped_at = Some(now);

                    let technique = alert
                        .rule
                        .mitre
                        .as_ref()
                        .map(|m| m.id.clone())
                        .unwrap_or_else(|| "T1059".into());

                    let src_ip = alert.decoded.src_ip.clone().unwrap_or_else(|| alert.agent.ip.clone());
                    let user = alert.decoded.user.clone().unwrap_or_else(|| "unknown".into());

                    new_trips.push(TripwireEvent {
                        id: format!("trip-{}", Uuid::new_v4()),
                        asset_id: asset.id.clone(),
                        asset_name: asset.name.clone(),
                        asset_type: asset.asset_type.clone(),
                        agent_id: alert.agent.id.clone(),
                        agent_name: alert.agent.name.clone(),
                        attacker_ip: src_ip,
                        attacker_user: user,
                        process_name: "fim_syscheck_detector".into(),
                        mitre_technique: technique,
                        raw_evidence: format!("Wazuh Alert {}: {}", alert.rule.id, alert.rule.description),
                        severity: "Critical".into(),
                        timestamp: now,
                    });
                }
            }
        }

        drop(list);

        if !new_trips.is_empty() {
            let mut events = self.tripwire_events.write().unwrap();
            events.extend(new_trips);
            drop(events);
            self.save();
        }
    }

    pub fn get_summary(&self) -> DeceptionSummary {
        let assets = self.assets.read().unwrap();
        let events = self.tripwire_events.read().unwrap();

        let total = assets.len();
        let armed = assets.iter().filter(|a| a.status == AssetDeploymentStatus::Armed).count();
        let triggered = assets.iter().filter(|a| a.status == AssetDeploymentStatus::Triggered).count();
        let decommissioned = assets.iter().filter(|a| a.status == AssetDeploymentStatus::Decommissioned).count();

        let mut recent: Vec<TripwireEvent> = events.clone();
        recent.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        recent.truncate(10);

        let total_trips = events.len();
        let high_fidelity = events.iter().filter(|e| e.severity == "Critical" || e.severity == "High").count();

        DeceptionSummary {
            total_assets: total,
            armed_assets: armed,
            triggered_assets: triggered,
            decommissioned_assets: decommissioned,
            total_trips,
            high_fidelity_alerts: high_fidelity,
            recent_triggers: recent,
            fleet_coverage_percentage: 78,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_trigger_deception_asset() {
        let temp_dir = std::env::temp_dir().join(format!("test_deception_{}.json", Uuid::new_v4()));
        let engine = DeceptionEngine::new(&temp_dir);

        let created = engine.create_asset(CreateAssetRequest {
            name: "Test Canary Token".into(),
            asset_type: DeceptionAssetType::CanaryFile,
            target_agent_id: "agent-01".into(),
            target_agent_name: "db-server".into(),
            target_path_or_port: "/etc/canary.conf".into(),
            decoy_payload_preview: Some("test payload".into()),
            tags: Some(vec!["test".into()]),
        });

        assert_eq!(created.status, AssetDeploymentStatus::Armed);
        assert_eq!(created.tripped_count, 0);

        let trigger_res = engine.simulate_tripwire(SimulateTripwireRequest {
            asset_id: created.id.clone(),
            attacker_ip: Some("192.0.2.1".into()),
            attacker_user: Some("attacker".into()),
            process_name: Some("cat".into()),
            mitre_technique: Some("T1005".into()),
            notes: Some("Read test canary".into()),
        });

        assert!(trigger_res.is_ok());
        let updated = engine.get_asset(&created.id).unwrap();
        assert_eq!(updated.status, AssetDeploymentStatus::Triggered);
        assert_eq!(updated.tripped_count, 1);
    }
}
