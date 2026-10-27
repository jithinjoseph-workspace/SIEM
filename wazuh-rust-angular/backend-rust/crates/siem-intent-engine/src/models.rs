use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical Attacker Strategic Intent Archetypes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AttackerIntentType {
    RansomwareExtortion,
    DataExfiltration,
    AptEspionage,
    DestructiveSabotage,
    Cryptojacking,
}

impl AttackerIntentType {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::RansomwareExtortion => "Ransomware & Double Extortion",
            Self::DataExfiltration => "Data Theft & Exfiltration",
            Self::AptEspionage => "Long-Term APT & Identity Dominance",
            Self::DestructiveSabotage => "Destructive Wiper / Sabotage",
            Self::Cryptojacking => "Cryptojacking & Resource Hijacking",
        }
    }

    pub fn severity(&self) -> &'static str {
        match self {
            Self::RansomwareExtortion => "Critical",
            Self::DestructiveSabotage => "Catastrophic",
            Self::DataExfiltration => "High",
            Self::AptEspionage => "Critical",
            Self::Cryptojacking => "Medium",
        }
    }
}

/// A scored hypothesis representing one potential adversary end-goal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntentHypothesisScore {
    pub intent_type: String,
    pub display_name: String,
    pub probability: f64,
    pub confidence: f64,
    pub impact_severity: String,
    pub key_indicators: Vec<String>,
    pub projected_impact: String,
}

/// Attack kill-chain milestone state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KillChainMilestone {
    pub stage_index: usize,
    pub stage_name: String,
    pub status: String, // "observed" | "current" | "predicted_next" | "unreached"
    pub observed_techniques: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_observed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prediction_reason: Option<String>,
}

/// Actionable micro-containment or defensive countermeasure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreemptiveAction {
    pub id: String,
    pub title: String,
    pub action_type: String, // "host_isolation" | "process_termination" | "identity_stepup" | "canary_tripwire" | "firewall_block"
    pub target_agent_id: String,
    pub target_agent_name: String,
    pub target_entity: String,
    pub urgency: String, // "Immediate" | "Elevated" | "Advisory"
    pub risk_reduction_percent: u32,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_command: Option<String>,
    pub status: String, // "pending_approval" | "executed" | "dismissed"
    pub created_at: DateTime<Utc>,
}

/// Real-time or historical alert record for kill-chain evidence mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveAlertRecord {
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub agent_name: String,
    pub agent_ip: String,
    pub mitre_id: String,
    #[serde(default)]
    pub mitre_tactic: String,
    #[serde(default)]
    pub mitre_technique: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub os_type: Option<String>,
    pub rule_id: u32,
    #[serde(default)]
    pub rule_description: String,
}

/// Comprehensive Intent Dossier for an endpoint, campaign, or user identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntityIntentDossier {
    pub id: String,
    pub entity_id: String,
    pub entity_name: String,
    pub entity_ip: String,
    #[serde(default)]
    pub os_type: Option<String>,
    pub primary_intent: String,
    pub primary_probability: f64,
    pub confidence_score: f64,
    pub kill_chain_velocity: String, // "Accelerating" | "Steady" | "Lurking"
    pub progression_percent: u8,
    pub hypotheses: Vec<IntentHypothesisScore>,
    pub milestones: Vec<KillChainMilestone>,
    pub recommended_actions: Vec<PreemptiveAction>,
    pub alerts_analyzed: usize,
    pub last_updated_at: DateTime<Utc>,
}



/// Executive posture and summary report
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntentSummaryReport {
    pub total_dossiers_monitored: usize,
    pub critical_intent_count: usize,
    pub ransomware_risk_count: usize,
    pub exfiltration_risk_count: usize,
    pub espionage_risk_count: usize,
    pub wiper_risk_count: usize,
    pub top_dossiers: Vec<EntityIntentDossier>,
    pub pending_preemptive_actions: Vec<PreemptiveAction>,
    pub average_advance_warning_hours: f64,
}

/// Interactive Sandbox / Simulation request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationIntentRequest {
    pub agent_id: String,
    pub agent_name: String,
    pub agent_ip: String,
    pub observed_techniques: Vec<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub custom_context: Option<String>,
}

/// Action execution dispatch request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteActionRequest {
    pub action_id: String,
    #[serde(default)]
    pub dry_run: bool,
}
