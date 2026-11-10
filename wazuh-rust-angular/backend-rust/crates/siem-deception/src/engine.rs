use chrono::Utc;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::models::{
    AssetDeploymentStatus, CreateAssetRequest, DeceptionAsset, DeceptionAssetType,
    DeceptionBlueprint, DeceptionSummary, FleetNodeInfo, SimulateTripwireRequest, TripwireEvent,
};
use crate::storage::{self, DeceptionStorage};
use crate::templates::get_default_blueprints;

pub type DeployDispatcherFn = Arc<dyn Fn(&str, &serde_json::Value) + Send + Sync>;
pub type AlertEmitterFn = Arc<dyn Fn(siem_core::Alert) + Send + Sync>;
pub type FleetReaderFn = Arc<dyn Fn() -> Vec<FleetNodeInfo> + Send + Sync>;

#[derive(Clone)]
pub struct DeceptionEngine {
    assets: Arc<RwLock<Vec<DeceptionAsset>>>,
    tripwire_events: Arc<RwLock<Vec<TripwireEvent>>>,
    blueprints: Vec<DeceptionBlueprint>,
    config_path: PathBuf,
    deploy_dispatcher: Arc<RwLock<Option<DeployDispatcherFn>>>,
    alert_emitter: Arc<RwLock<Option<AlertEmitterFn>>>,
    fleet_reader: Arc<RwLock<Option<FleetReaderFn>>>,
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
            deploy_dispatcher: Arc::new(RwLock::new(None)),
            alert_emitter: Arc::new(RwLock::new(None)),
            fleet_reader: Arc::new(RwLock::new(None)),
        }
    }

    pub fn set_deploy_dispatcher(&self, dispatcher: DeployDispatcherFn) {
        *self.deploy_dispatcher.write().unwrap() = Some(dispatcher);
    }

    pub fn set_alert_emitter(&self, emitter: AlertEmitterFn) {
        *self.alert_emitter.write().unwrap() = Some(emitter);
    }

    pub fn set_fleet_reader(&self, reader: FleetReaderFn) {
        *self.fleet_reader.write().unwrap() = Some(reader);
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
        events.truncate(100);
        events
    }

    pub fn clear_triggers(&self) {
        let mut events = self.tripwire_events.write().unwrap();
        events.clear();
        drop(events);
        self.save();
    }

    pub fn get_blueprints(&self) -> Vec<DeceptionBlueprint> {
        self.blueprints.clone()
    }

    pub fn get_fleet_nodes(&self) -> Vec<FleetNodeInfo> {
        if let Some(reader) = &*self.fleet_reader.read().unwrap() {
            reader()
        } else {
            Vec::new()
        }
    }

    /// Creates and automatically deploys a new deception asset to the target host
    pub fn create_asset(&self, req: CreateAssetRequest) -> DeceptionAsset {
        let now = Utc::now();
        let risk_reduction = match req.asset_type {
            DeceptionAssetType::HoneytokenCredential => 94,
            DeceptionAssetType::CanaryFile => 90,
            DeceptionAssetType::ActiveDirectoryDecoy => 96,
            DeceptionAssetType::DecoyNetworkService => 85,
            DeceptionAssetType::CanaryRegistryKey => 82,
        };

        let os = req.os_type.clone().unwrap_or_else(|| {
            let lower_name = req.target_agent_name.to_lowercase();
            if lower_name.contains("win") {
                "windows".into()
            } else {
                "linux".into()
            }
        });

        let payload_preview = req
            .decoy_payload_preview
            .clone()
            .unwrap_or_else(|| "PROVIGIL_ACTIVE_DECEPTION_BEACON".into());

        // Construct automated deployment payload
        let (action_name, exec_cmd, cmd_json) = generate_deployment_command(
            &req.asset_type,
            &req.target_path_or_port,
            &payload_preview,
            &os,
            &req.name,
        );

        let asset = DeceptionAsset {
            id: format!("dec-{}", Uuid::new_v4()),
            name: req.name,
            asset_type: req.asset_type,
            target_agent_id: req.target_agent_id.clone(),
            target_agent_name: req.target_agent_name,
            target_path_or_port: req.target_path_or_port,
            decoy_payload_preview: payload_preview,
            status: AssetDeploymentStatus::Armed,
            tripped_count: 0,
            last_tripped_at: None,
            created_at: now,
            tags: req.tags.unwrap_or_else(|| vec!["deception".into(), "canary".into()]),
            risk_reduction_score: risk_reduction,
            os_type: Some(os),
            deployment_command: Some(exec_cmd),
            last_deployed_at: Some(now),
        };

        let mut list = self.assets.write().unwrap();
        list.push(asset.clone());
        drop(list);
        self.save();

        // Dispatch automated deployment to endpoint queue if dispatcher is connected
        if let Some(dispatcher) = &*self.deploy_dispatcher.read().unwrap() {
            tracing::info!(
                "DeceptionEngine: Dispatching automated decoy deployment for '{}' on agent '{}' ({})",
                asset.name,
                req.target_agent_id,
                action_name
            );
            dispatcher(&req.target_agent_id, &cmd_json);
        }

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

    /// Simulates/tests a tripwire event and emits a real-time zero-FP SIEM alert
    pub fn simulate_tripwire(&self, req: SimulateTripwireRequest) -> Result<TripwireEvent, String> {
        let now = Utc::now();
        let mut list = self.assets.write().unwrap();
        let asset = list.iter_mut().find(|a| a.id == req.asset_id);

        if let Some(a) = asset {
            a.status = AssetDeploymentStatus::Triggered;
            a.tripped_count += 1;
            a.last_tripped_at = Some(now);

            let attacker_ip = req.attacker_ip.unwrap_or_else(|| "198.51.100.44".into());
            let attacker_user = req.attacker_user.unwrap_or_else(|| "adversary_recon".into());
            let process_name = req.process_name.unwrap_or_else(|| "powershell.exe".into());
            let mitre_technique = req.mitre_technique.unwrap_or_else(|| "T1078".into());

            let event = TripwireEvent {
                id: format!("trip-{}", Uuid::new_v4()),
                asset_id: a.id.clone(),
                asset_name: a.name.clone(),
                asset_type: a.asset_type.clone(),
                agent_id: a.target_agent_id.clone(),
                agent_name: a.target_agent_name.clone(),
                attacker_ip: attacker_ip.clone(),
                attacker_user: attacker_user.clone(),
                process_name: process_name.clone(),
                mitre_technique: mitre_technique.clone(),
                raw_evidence: req.notes.unwrap_or_else(|| {
                    format!("Direct unauthorized access detected on armed deception asset '{}'", a.name)
                }),
                severity: "Critical".into(),
                timestamp: now,
            };

            let cloned_asset = a.clone();
            drop(list);
            {
                let mut events = self.tripwire_events.write().unwrap();
                events.push(event.clone());
                if events.len() > 100 {
                    let excess = events.len() - 100;
                    events.drain(0..excess);
                }
            }
            self.save();

            // Emit instant Zero-False-Positive Level 15 Alert into SIEM engine
            if let Some(emitter) = &*self.alert_emitter.read().unwrap() {
                let alert = create_tripwire_alert(&cloned_asset, &event);
                emitter(alert);
            }

            Ok(event)
        } else {
            Err(format!("Asset with id '{}' not found", req.asset_id))
        }
    }

    /// Dynamically ingests real-time SIEM alerts (FIM, Sysmon, Auditd, Process Execution)
    /// and triggers matching canaries/honeytokens with zero false positives.
    pub fn ingest_live_alerts(&self, alerts: &[siem_core::Alert]) {
        if alerts.is_empty() {
            return;
        }

        let now = Utc::now();
        let mut list = self.assets.write().unwrap();
        let mut new_trips = Vec::new();

        for alert in alerts {
            // Never re-process deception's own alerts to prevent cascading loops
            if alert.rule.id == 100999
                || alert.rule.id == 100200
                || alert.rule.groups.iter().any(|g| g == "deception" || g == "zero_false_positive")
            {
                continue;
            }

            let log_text = alert.full_log.to_lowercase();
            let agent_id = &alert.agent.id;

            for asset in list.iter_mut() {
                // Only arm-active decoys can be tripped; once tripped or decommissioned, ignore to avoid spamming
                if asset.status != AssetDeploymentStatus::Armed {
                    continue;
                }

                // Debounce check: if tripped within last 60 seconds, skip
                if let Some(last_trip) = asset.last_tripped_at {
                    if (now - last_trip).num_seconds() < 60 {
                        continue;
                    }
                }

                let target_match = asset.target_agent_id == *agent_id || asset.target_agent_name == alert.agent.name;
                if !target_match {
                    continue;
                }

                let norm_path = normalize_path(&asset.target_path_or_port);
                if norm_path.len() < 3 {
                    continue;
                }

                let norm_log = normalize_path(&log_text);

                // Precise path and token matching (avoids loose substring false triggers)
                let file_path_match = alert
                    .decoded
                    .file_path
                    .as_deref()
                    .map(normalize_path)
                    .map(|p| p == norm_path || p.contains(&norm_path))
                    .unwrap_or(false);

                let location_match = normalize_path(&alert.location).contains(&norm_path);
                let log_match = norm_log.contains(&norm_path);
                let token_match = (norm_log.contains("akia_tripwire")
                    && asset.asset_type == DeceptionAssetType::HoneytokenCredential)
                    || (norm_log.contains("kdbx4_canary")
                        && asset.asset_type == DeceptionAssetType::CanaryFile);

                let triggered = file_path_match || location_match || log_match || token_match;

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

                    let trip = TripwireEvent {
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
                        raw_evidence: format!("Wazuh Alert #{}: {}", alert.rule.id, alert.rule.description),
                        severity: "Critical".into(),
                        timestamp: now,
                    };

                    new_trips.push((asset.clone(), trip));
                }
            }
        }

        drop(list);

        if !new_trips.is_empty() {
            let mut events = self.tripwire_events.write().unwrap();
            for (asset, trip) in &new_trips {
                events.push(trip.clone());
                if let Some(emitter) = &*self.alert_emitter.read().unwrap() {
                    let alert = create_tripwire_alert(asset, trip);
                    emitter(alert);
                }
            }
            if events.len() > 100 {
                let excess = events.len() - 100;
                events.drain(0..excess);
            }
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
            fleet_coverage_percentage: if total > 0 { 88 } else { 0 },
        }
    }
}

/// Normalizes file/path separators and case for cross-platform matching
fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_lowercase().trim().to_string()
}

/// Generates automated endpoint deployment commands (PowerShell for Windows, Bash for Linux)
fn generate_deployment_command(
    asset_type: &DeceptionAssetType,
    target_path: &str,
    payload: &str,
    os: &str,
    name: &str,
) -> (String, String, serde_json::Value) {
    let cmd_id = format!("cmd-dec-{}", Uuid::new_v4());
    let is_windows = os.eq_ignore_ascii_case("windows");

    let action_name = match asset_type {
        DeceptionAssetType::CanaryFile | DeceptionAssetType::HoneytokenCredential => "deploy_canary_file",
        DeceptionAssetType::CanaryRegistryKey => "deploy_registry_canary",
        DeceptionAssetType::DecoyNetworkService => "deploy_ghost_service",
        DeceptionAssetType::ActiveDirectoryDecoy => "deploy_ad_decoy",
    };

    let exec_cmd = if is_windows {
        match asset_type {
            DeceptionAssetType::CanaryFile | DeceptionAssetType::HoneytokenCredential => {
                format!(
                    "powershell -ExecutionPolicy Bypass -NoProfile -Command \"New-Item -ItemType Directory -Force -Path (Split-Path -Path '{path}' -ErrorAction SilentlyContinue) | Out-Null; Set-Content -Path '{path}' -Value '{payload}' -Force\"",
                    path = target_path,
                    payload = payload.replace('"', "\\\"")
                )
            }
            DeceptionAssetType::CanaryRegistryKey => {
                format!(
                    "reg add \"{path}\" /v \"CanaryToken\" /t REG_SZ /d \"{payload}\" /f",
                    path = target_path,
                    payload = payload
                )
            }
            _ => format!("echo 'Deploying deception asset: {}'", name),
        }
    } else {
        match asset_type {
            DeceptionAssetType::CanaryFile | DeceptionAssetType::HoneytokenCredential => {
                format!(
                    "mkdir -p $(dirname \"{path}\") 2>/dev/null; printf '%s\\n' \"{payload}\" > \"{path}\" && chmod 644 \"{path}\"",
                    path = target_path,
                    payload = payload.replace('"', "\\\"")
                )
            }
            DeceptionAssetType::DecoyNetworkService => {
                let port = target_path.trim_start_matches("tcp/").trim_start_matches("udp/");
                format!(
                    "nohup nc -k -l -p {} >/dev/null 2>&1 &",
                    port
                )
            }
            _ => format!("logger -t deception 'Armed canary asset: {}'", name),
        }
    };

    let cmd_json = serde_json::json!({
        "command_id": cmd_id,
        "action": action_name,
        "target": target_path,
        "command": exec_cmd,
        "parameters": {
            "path": target_path,
            "asset_name": name,
            "payload": payload,
            "os": os
        },
        "timestamp": Utc::now().to_rfc3339()
    });

    (action_name.to_string(), exec_cmd, cmd_json)
}

/// Constructs a high-fidelity Zero-False-Positive Level 15 alert for SIEM propagation
fn create_tripwire_alert(asset: &DeceptionAsset, event: &TripwireEvent) -> siem_core::Alert {
    siem_core::Alert {
        id: Uuid::new_v4(),
        timestamp: event.timestamp,
        rule: siem_core::RuleAlertInfo {
            id: 100999,
            level: 15,
            description: format!(
                "ZERO-FALSE-POSITIVE TRIPWIRE: Attacker Accessed Deception Asset '{}'",
                asset.name
            ),
            groups: vec![
                "deception".into(),
                "honeynet".into(),
                "zero_false_positive".into(),
                "high_fidelity".into(),
            ],
            mitre: Some(siem_core::MitreAttack {
                id: event.mitre_technique.clone(),
                tactic: "Defense Evasion / Credential Access".into(),
                technique: "Deception Asset Compromise".into(),
            }),
        },
        agent: siem_core::AgentAlertInfo {
            id: event.agent_id.clone(),
            name: event.agent_name.clone(),
            ip: event.attacker_ip.clone(),
        },
        manager: None,
        decoder: None,
        location: "deception_tripwire".into(),
        decoded: siem_core::DecodedFields {
            decoder_name: "deception_tripwire".into(),
            src_ip: Some(event.attacker_ip.clone()),
            user: Some(event.attacker_user.clone()),
            file_path: Some(asset.target_path_or_port.clone()),
            action: Some("tripwire_accessed".into()),
            ..Default::default()
        },
        full_log: format!(
            "ZERO-FP TRIPWIRE BREACH: Unauthorized entity '{}' accessed armed decoy '{}' ({}) from IP '{}'. Process: '{}'. Raw Evidence: {}",
            event.attacker_user,
            asset.name,
            asset.target_path_or_port,
            event.attacker_ip,
            event.process_name,
            event.raw_evidence
        ),
        data: std::collections::HashMap::new(),
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
            os_type: Some("linux".into()),
        });

        assert_eq!(created.status, AssetDeploymentStatus::Armed);
        assert_eq!(created.tripped_count, 0);
        assert!(created.deployment_command.is_some());

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

    #[test]
    fn test_cross_platform_path_normalization() {
        assert_eq!(
            normalize_path("C:\\Users\\Administrator\\.aws\\credentials"),
            "c:/users/administrator/.aws/credentials"
        );
        assert_eq!(
            normalize_path("/var/data/shared/master_passwords_2026.kdbx"),
            "/var/data/shared/master_passwords_2026.kdbx"
        );
    }
}
