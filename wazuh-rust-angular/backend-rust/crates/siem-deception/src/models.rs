use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical Types of Deception Assets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DeceptionAssetType {
    CanaryFile,
    HoneytokenCredential,
    DecoyNetworkService,
    CanaryRegistryKey,
    ActiveDirectoryDecoy,
}

impl DeceptionAssetType {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::CanaryFile => "Canary File / Document",
            Self::HoneytokenCredential => "Honeytoken API / Credential",
            Self::DecoyNetworkService => "Decoy Port / Ghost Service",
            Self::CanaryRegistryKey => "Canary Registry Key",
            Self::ActiveDirectoryDecoy => "Decoy Active Directory SPN",
        }
    }
}

/// Operational Status of a Deployed Deception Asset
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetDeploymentStatus {
    Armed,
    Triggered,
    Decommissioned,
    PendingDeploy,
}

/// Core Deception Asset Record (Deception-as-Code entity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionAsset {
    pub id: String,
    pub name: String,
    pub asset_type: DeceptionAssetType,
    pub target_agent_id: String,
    pub target_agent_name: String,
    pub target_path_or_port: String,
    pub decoy_payload_preview: String,
    pub status: AssetDeploymentStatus,
    pub tripped_count: u32,
    pub last_tripped_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub risk_reduction_score: u8,
}

/// High-Fidelity Zero False-Positive Attacker Interaction Tripwire Record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripwireEvent {
    pub id: String,
    pub asset_id: String,
    pub asset_name: String,
    pub asset_type: DeceptionAssetType,
    pub agent_id: String,
    pub agent_name: String,
    pub attacker_ip: String,
    pub attacker_user: String,
    pub process_name: String,
    pub mitre_technique: String,
    pub raw_evidence: String,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
}

/// Pre-Packaged Deception-as-Code Blueprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionBlueprint {
    pub template_id: String,
    pub title: String,
    pub description: String,
    pub asset_type: DeceptionAssetType,
    pub category: String,
    pub recommended_target: String,
    pub default_path: String,
    pub default_payload: String,
    pub threat_mitigation: String,
}

/// Global Summary & Health Report for the Deception Grid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionSummary {
    pub total_assets: usize,
    pub armed_assets: usize,
    pub triggered_assets: usize,
    pub decommissioned_assets: usize,
    pub total_trips: usize,
    pub high_fidelity_alerts: usize,
    pub recent_triggers: Vec<TripwireEvent>,
    pub fleet_coverage_percentage: u8,
}

/// Request to create a new deception asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAssetRequest {
    pub name: String,
    pub asset_type: DeceptionAssetType,
    pub target_agent_id: String,
    pub target_agent_name: String,
    pub target_path_or_port: String,
    pub decoy_payload_preview: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Request to simulate/test a tripwire event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateTripwireRequest {
    pub asset_id: String,
    pub attacker_ip: Option<String>,
    pub attacker_user: Option<String>,
    pub process_name: Option<String>,
    pub mitre_technique: Option<String>,
    pub notes: Option<String>,
}
