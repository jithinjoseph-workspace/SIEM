use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Log and telemetry event sources
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Syslog,
    WindowsEvent,
    Fim,
    Registry,
    Syscollector,
    Sca,
    Auth,
    Network,
    ActiveResponse,
    Custom(String),
}

/// Raw ingested event from an agent or syslog collector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub source: EventSource,
    pub location: String,
    pub message: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl RawEvent {
    pub fn new(agent_id: impl Into<String>, source: EventSource, location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent_id: agent_id.into(),
            source,
            location: location.into(),
            message: message.into(),
            metadata: HashMap::new(),
        }
    }
}

/// Decoded event fields extracted by regex decoders
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecodedFields {
    pub decoder_name: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub user: Option<String>,
    pub program_name: Option<String>,
    pub process_id: Option<u32>,
    pub file_path: Option<String>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub extra: HashMap<String, String>,
}

/// MITRE ATT&CK framework mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttack {
    pub id: String,          // e.g. "T1110"
    pub tactic: String,      // e.g. "Credential Access"
    pub technique: String,   // e.g. "Brute Force"
}

/// Rule definition in SIEM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u32,
    pub level: u8, // 1 to 15 (matching Wazuh standard)
    pub description: String,
    pub regex_pattern: String,
    pub groups: Vec<String>,
    pub mitre: Option<MitreAttack>,
}

pub mod config_parser;
pub use config_parser::*;

/// Rule metadata attached to a triggered alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAlertInfo {
    pub id: u32,
    pub level: u8,
    pub description: String,
    pub groups: Vec<String>,
    pub mitre: Option<MitreAttack>,
}

/// Agent details attached to an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAlertInfo {
    pub id: String,
    pub name: String,
    pub ip: String,
}

/// Manager node details attached to an alert
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManagerAlertInfo {
    pub name: String,
}

/// Decoder details attached to an alert
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecoderAlertInfo {
    pub name: String,
}

/// Final Security Alert produced by the correlation engine (matching Wazuh Alert structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub rule: RuleAlertInfo,
    pub agent: AgentAlertInfo,
    #[serde(default)]
    pub manager: Option<ManagerAlertInfo>,
    #[serde(default)]
    pub decoder: Option<DecoderAlertInfo>,
    pub full_log: String,
    pub decoded: DecodedFields,
    pub location: String,
    #[serde(default)]
    pub data: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_fabric: Option<RiskFabricScore>,
}

/// Agent lifecycle status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Active,
    Disconnected,
    Pending,
}

/// Monitored endpoint agent registered in the SIEM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub os: String,
    pub version: String,
    pub status: AgentStatus,
    pub last_keepalive: DateTime<Utc>,
    pub os_type: String, // "linux" | "windows" | "macos"
}

/// System-wide SOC metrics & statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiemStats {
    pub total_events: u64,
    pub total_alerts: u64,
    pub critical_alerts: u64, // Level 12 - 15
    pub high_alerts: u64,     // Level 8 - 11
    pub medium_alerts: u64,   // Level 4 - 7
    pub low_alerts: u64,      // Level 1 - 3
    pub active_agents: usize,
    pub total_agents: usize,
}

/// Dynamic score & context produced by the Business-Process Risk Fabric Engine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskFabricScore {
    pub business_process: String,
    pub process_criticality: String,
    pub asset_weight: f64,
    pub identity_weight: f64,
    pub time_window_multiplier: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_window_name: Option<String>,
    pub technical_severity: u8,
    pub dynamic_risk_score: u8,
    pub dynamic_risk_tier: String,
    pub executive_impact: String,
    pub evaluated_at: DateTime<Utc>,
}

/// Business Process definition mapping assets and identities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BusinessProcessDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub criticality: String,
    pub asset_weight: f64,
    pub identity_weight: f64,
    pub asset_patterns: Vec<String>,
    pub identity_patterns: Vec<String>,
    pub impact_template: String,
    pub enabled: bool,
}

/// Temporal business time-window configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BusinessTimeWindow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub multiplier: f64,
    pub window_type: String, // "recurring_schedule" | "date_range" | "business_hours"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    pub active: bool,
    #[serde(default)]
    pub target_processes: Vec<String>,
}
