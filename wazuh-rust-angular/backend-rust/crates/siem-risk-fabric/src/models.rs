use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFabricConfig {
    pub processes: Vec<BusinessProcessDefinition>,
    pub time_windows: Vec<BusinessTimeWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessRiskStat {
    pub name: String,
    pub criticality: String,
    pub alerts_count: usize,
    pub max_risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskFabricSummary {
    pub total_processes: usize,
    pub active_time_windows: usize,
    pub average_dynamic_risk: f64,
    pub catastrophic_alerts_count: usize,
    pub critical_alerts_count: usize,
    pub high_alerts_count: usize,
    pub medium_alerts_count: usize,
    pub low_alerts_count: usize,
    pub top_critical_processes: Vec<ProcessRiskStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvaluationRequest {
    pub rule_level: u8,
    pub rule_id: Option<u32>,
    pub rule_description: Option<String>,
    pub agent_name: String,
    pub agent_ip: String,
    pub user: Option<String>,
}
