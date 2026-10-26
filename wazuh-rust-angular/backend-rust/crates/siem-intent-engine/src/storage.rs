use std::fs;
use std::path::Path;
use chrono::Utc;
use crate::models::{EntityIntentDossier, IntentHypothesisScore, KillChainMilestone, PreemptiveAction};

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
    let now = Utc::now();

    let ransomware_dossier = EntityIntentDossier {
        id: "dossier-rw-001".to_string(),
        entity_id: "001".to_string(),
        entity_name: "srv-prod-ubuntu-01".to_string(),
        entity_ip: "192.168.10.15".to_string(),
        primary_intent: "Ransomware & Double Extortion".to_string(),
        primary_probability: 0.84,
        confidence_score: 91,
        kill_chain_velocity: "Rapid (Hours)".to_string(),
        progression_percent: 78,
        hypotheses: vec![
            IntentHypothesisScore {
                intent_type: "ransomware_extortion".to_string(),
                display_name: "Ransomware & Double Extortion".to_string(),
                probability: 0.84,
                confidence: 0.91,
                impact_severity: "Critical".to_string(),
                key_indicators: vec![
                    "Inhibit System Recovery (T1490): vssadmin shadow deletion detected".into(),
                    "Impair Defenses (T1562): Security daemon stop signals".into(),
                    "Credential Access (T1003): Memory dump of auth service".into(),
                ],
                projected_impact: "Immediate threat of volume encryption across PCI-DSS transactional datastores with secondary extortion threat.".into(),
            },
            IntentHypothesisScore {
                intent_type: "destructive_sabotage".to_string(),
                display_name: "Destructive Wiper / Sabotage".to_string(),
                probability: 0.11,
                confidence: 0.65,
                impact_severity: "Catastrophic".to_string(),
                key_indicators: vec![
                    "High write velocity on root partition".into(),
                    "Indicator Removal (T1070)".into(),
                ],
                projected_impact: "System bricking and irreversible partition damage.".into(),
            },
            IntentHypothesisScore {
                intent_type: "data_exfiltration".to_string(),
                display_name: "Data Theft & Exfiltration".to_string(),
                probability: 0.05,
                confidence: 0.52,
                impact_severity: "High".to_string(),
                key_indicators: vec![
                    "Staging directory creations under /tmp".into(),
                ],
                projected_impact: "Unauthorized transfer of proprietary records.".into(),
            },
        ],
        milestones: vec![
            KillChainMilestone {
                stage_index: 0,
                stage_name: "Initial Access".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1190".into()],
                first_observed_at: Some(now - chrono::Duration::hours(3)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 1,
                stage_name: "Execution".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1059".into(), "T1047".into()],
                first_observed_at: Some(now - chrono::Duration::hours(2)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 2,
                stage_name: "Persistence".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1543".into()],
                first_observed_at: Some(now - chrono::Duration::hours(2)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 3,
                stage_name: "Privilege Escalation".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1548".into()],
                first_observed_at: Some(now - chrono::Duration::minutes(90)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 4,
                stage_name: "Defense Evasion".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1562".into(), "T1070".into()],
                first_observed_at: Some(now - chrono::Duration::minutes(45)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 5,
                stage_name: "Credential Access".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1003".into()],
                first_observed_at: Some(now - chrono::Duration::minutes(20)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 6,
                stage_name: "Discovery".into(),
                status: "current".into(),
                observed_techniques: vec!["T1082".into(), "T1087".into()],
                first_observed_at: Some(now - chrono::Duration::minutes(5)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 7,
                stage_name: "Lateral Movement".into(),
                status: "predicted_next".into(),
                observed_techniques: vec![],
                first_observed_at: None,
                prediction_reason: Some("High probability (89%) of SMB/PsExec lateral spread to adjacent database nodes within 30-45 minutes.".into()),
            },
            KillChainMilestone {
                stage_index: 8,
                stage_name: "Collection & Staging".into(),
                status: "predicted_next".into(),
                observed_techniques: vec![],
                first_observed_at: None,
                prediction_reason: Some("Archival of PCI cardholder logs prior to mass encryption.".into()),
            },
            KillChainMilestone {
                stage_index: 9,
                stage_name: "Impact & Exfiltration".into(),
                status: "unreached".into(),
                observed_techniques: vec![],
                first_observed_at: None,
                prediction_reason: Some("Final detonation: AES-256 locker payload deployment.".into()),
            },
        ],
        recommended_actions: vec![
            PreemptiveAction {
                id: "act-isolate-001".into(),
                title: "Preemptively Isolate Endpoint 'srv-prod-ubuntu-01'".into(),
                action_type: "host_isolation".into(),
                target_agent_id: "001".into(),
                target_agent_name: "srv-prod-ubuntu-01".into(),
                target_entity: "192.168.10.15".into(),
                urgency: "Immediate".into(),
                risk_reduction_percent: 92,
                description: "Cut lateral east-west network interfaces to stop imminent lateral movement while preserving SOC telemetry tunnel.".into(),
                execution_command: Some("iptables -A OUTPUT -d 192.168.0.0/16 -j DROP".into()),
                status: "pending_approval".into(),
                created_at: now,
            },
            PreemptiveAction {
                id: "act-canary-001".into(),
                title: "Deploy Canary Decoy Tripwires on Critical File Shares".into(),
                action_type: "canary_tripwire".into(),
                target_agent_id: "001".into(),
                target_agent_name: "srv-prod-ubuntu-01".into(),
                target_entity: "/var/data/shared/".into(),
                urgency: "Elevated".into(),
                risk_reduction_percent: 85,
                description: "Place high-entropy canary files. Any encryption modification immediately triggers instant kill-switch response.".into(),
                execution_command: Some("touch /var/data/shared/.vault_canary_token.docx".into()),
                status: "pending_approval".into(),
                created_at: now,
            },
        ],
        alerts_analyzed: 18,
        last_updated_at: now,
    };

    let exfiltration_dossier = EntityIntentDossier {
        id: "dossier-exfil-002".to_string(),
        entity_id: "004".to_string(),
        entity_name: "dmz-web-nginx".to_string(),
        entity_ip: "10.0.1.20".to_string(),
        primary_intent: "Data Theft & Exfiltration".to_string(),
        primary_probability: 0.79,
        confidence_score: 86,
        kill_chain_velocity: "Moderate (Days)".to_string(),
        progression_percent: 62,
        hypotheses: vec![
            IntentHypothesisScore {
                intent_type: "data_exfiltration".to_string(),
                display_name: "Data Theft & Exfiltration".to_string(),
                probability: 0.79,
                confidence: 0.86,
                impact_severity: "High".to_string(),
                key_indicators: vec![
                    "Archive Collected Data (T1560): High-volume tar.gz compression in /tmp".into(),
                    "Execution (T1059): Unusual curl/rclone processes".into(),
                ],
                projected_impact: "Loss of confidential web application configurations and hashed database credentials.".into(),
            },
            IntentHypothesisScore {
                intent_type: "apt_espionage".to_string(),
                display_name: "Long-Term APT & Identity Dominance".to_string(),
                probability: 0.16,
                confidence: 0.71,
                impact_severity: "Critical".to_string(),
                key_indicators: vec![
                    "Web shell persistence in Nginx document root".into(),
                ],
                projected_impact: "Persistent backdoor for ongoing eavesdropping.".into(),
            },
            IntentHypothesisScore {
                intent_type: "cryptojacking".to_string(),
                display_name: "Cryptojacking & Resource Hijacking".to_string(),
                probability: 0.05,
                confidence: 0.40,
                impact_severity: "Medium".to_string(),
                key_indicators: vec![],
                projected_impact: "Cloud compute resource theft.".into(),
            },
        ],
        milestones: vec![
            KillChainMilestone {
                stage_index: 0,
                stage_name: "Initial Access".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1190".into()],
                first_observed_at: Some(now - chrono::Duration::hours(12)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 1,
                stage_name: "Execution".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1059".into()],
                first_observed_at: Some(now - chrono::Duration::hours(8)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 2,
                stage_name: "Persistence".into(),
                status: "observed".into(),
                observed_techniques: vec!["T1505.003".into()],
                first_observed_at: Some(now - chrono::Duration::hours(6)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 8,
                stage_name: "Collection & Staging".into(),
                status: "current".into(),
                observed_techniques: vec!["T1560".into()],
                first_observed_at: Some(now - chrono::Duration::minutes(15)),
                prediction_reason: None,
            },
            KillChainMilestone {
                stage_index: 9,
                stage_name: "Impact & Exfiltration".into(),
                status: "predicted_next".into(),
                observed_techniques: vec![],
                first_observed_at: None,
                prediction_reason: Some("Projected egress transfer to external IP via TLS tunnel within 60 minutes.".into()),
            },
        ],
        recommended_actions: vec![
            PreemptiveAction {
                id: "act-block-004".into(),
                title: "Preemptively Block Egress IP Ranges".into(),
                action_type: "firewall_block".into(),
                target_agent_id: "004".into(),
                target_agent_name: "dmz-web-nginx".into(),
                target_entity: "198.51.100.44".into(),
                urgency: "Immediate".into(),
                risk_reduction_percent: 88,
                description: "Block outbound network traffic to destination server flagged as external staging server.".into(),
                execution_command: Some("iptables -A OUTPUT -d 198.51.100.44 -j DROP".into()),
                status: "pending_approval".into(),
                created_at: now,
            },
        ],
        alerts_analyzed: 11,
        last_updated_at: now,
    };

    IntentEngineStorage {
        dossiers: vec![ransomware_dossier, exfiltration_dossier],
        executed_actions: Vec::new(),
    }
}
