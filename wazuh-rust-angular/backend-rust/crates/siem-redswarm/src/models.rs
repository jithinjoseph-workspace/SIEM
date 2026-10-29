use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use siem_core::Alert;
use uuid::Uuid;

/// Swarm operational modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmExecutionMode {
    /// Injects realistic attack telemetry directly into SIEM engine. Zero impact on endpoints. (DEFAULT)
    SafeTelemetryOnly,
    /// Runs carefully selected, reversible commands on endpoints tagged `redteam-allowed` or `lab`.
    ControlledLive,
    /// Approval-gated broader live techniques for scheduled red-team windows.
    FullLive,
}

impl Default for SwarmExecutionMode {
    fn default() -> Self {
        Self::SafeTelemetryOnly
    }
}

/// Operational Risk Level for an attack technique
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Payload specification for live command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPayload {
    pub command: String,
    pub timeout_seconds: u32,
    pub requires_elevation: bool,
}

/// MITRE ATT&CK technique catalog item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id: String,                 // e.g. "T1110.001"
    pub name: String,               // e.g. "Password Guessing"
    pub tactic: String,             // e.g. "Credential Access"
    pub platforms: Vec<String>,     // ["linux", "windows", "macos"]
    pub risk_level: RiskLevel,
    pub reversible: bool,
    pub cleanup_guaranteed: bool,
    pub execution: CommandPayload,
    pub cleanup: CommandPayload,
    pub expected_telemetry: Vec<String>,
    pub expected_mitre_ids: Vec<String>,
    pub expected_rule_groups: Vec<String>,
    pub detection_indicators: Vec<String>,
    pub banned_in_controlled_live: bool,
    pub sample_raw_logs: Vec<String>,
}

/// Multi-signal detection verification outcome
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionVerdict {
    /// Clear matching alert with expected MITRE ID or related rule fired.
    Defended,
    /// Weak or partial indicator detected (e.g. low-level generic rule, missing MITRE tag).
    SoftGap,
    /// Zero detection fired for the attack within the verification window.
    HardGap,
}

/// Cleanup execution status for live operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    NotApplicable, // SafeTelemetryOnly
    Succeeded,
    Failed,
    Pending,
}

/// Verification result containing evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub verdict: DetectionVerdict,
    pub matched_alert_id: Option<Uuid>,
    pub matched_rule_id: Option<u32>,
    pub matched_rule_description: Option<String>,
    pub matched_alert: Option<Alert>,
    pub retry_count: u32,
    pub evaluated_signals: Vec<String>,
    pub reason: String,
    pub latency_ms: u64,
}

/// Synthesized draft detection rule staged for human review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizedRuleDraft {
    pub id: Uuid,
    pub execution_id: Uuid,
    pub technique_id: String,
    pub technique_name: String,
    pub rule_xml: String,
    pub logtest_passed: bool,
    pub logtest_output: String,
    pub hardening_recommendation: String,
    pub created_at: DateTime<Utc>,
    pub status: DraftRuleStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftRuleStatus {
    PendingApproval,
    ApprovedAndDeployed,
    Rejected,
    RolledBack,
}

/// Immutable record of an executed swarm attack round
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub id: Uuid,
    pub campaign_id: String,
    pub tenant_id: String,
    pub timestamp: DateTime<Utc>,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub mode: SwarmExecutionMode,
    pub target_agent_id: String,
    pub target_agent_name: String,
    pub target_agent_ip: String,
    pub target_os: String,
    pub execution_success: bool,
    pub execution_output: String,
    pub cleanup_status: CleanupStatus,
    pub cleanup_output: Option<String>,
    pub verification: VerificationEvidence,
    pub draft_rule: Option<SynthesizedRuleDraft>,
}

/// Rules of Engagement (ROE) Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesOfEngagement {
    pub allowed_agent_tags: Vec<String>, // e.g. ["redteam-allowed", "lab"]
    pub denied_agent_ids: Vec<String>,
    pub max_attacks_per_hour: u32,
    pub max_concurrent_live_executions: usize,
    pub per_agent_cooldown_seconds: u64,
    pub allowed_tactics: Vec<String>,
    pub banned_techniques: Vec<String>,
    pub max_risk_level: RiskLevel,
}

impl Default for RulesOfEngagement {
    fn default() -> Self {
        Self {
            allowed_agent_tags: vec!["redteam-allowed".to_string(), "lab".to_string()],
            denied_agent_ids: vec![],
            max_attacks_per_hour: 60,
            max_concurrent_live_executions: 1,
            per_agent_cooldown_seconds: 300, // 5 minute minimum between live probes on same agent
            allowed_tactics: vec![
                "Reconnaissance".into(),
                "Initial Access".into(),
                "Execution".into(),
                "Persistence".into(),
                "Privilege Escalation".into(),
                "Defense Evasion".into(),
                "Credential Access".into(),
                "Discovery".into(),
                "Lateral Movement".into(),
                "Collection".into(),
            ],
            banned_techniques: vec![
                "T1485".into(), // Data Destruction
                "T1486".into(), // Data Encrypted for Impact (Ransomware)
                "T1529".into(), // System Shutdown/Reboot
            ],
            max_risk_level: RiskLevel::Medium,
        }
    }
}

/// Configured Swarm Campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmCampaign {
    pub id: String,
    pub name: String,
    pub description: String,
    pub mode: SwarmExecutionMode,
    pub enabled: bool,
    pub interval_seconds: u64,
    pub roe: RulesOfEngagement,
    #[serde(default = "default_campaign_owner")]
    pub owner: String,
    /// The tenant whose agents it tests; empty: a platform campaign over every tenant.
    #[serde(default)]
    pub tenant_id: String,
    pub approved_by: Option<String>,
    pub approval_expires_at: Option<DateTime<Utc>>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub total_executed: u64,
    pub total_defended: u64,
    pub total_gaps: u64,
}

fn default_campaign_owner() -> String {
    "admin".to_string()
}

/// Global Swarm Health & Status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmStatusReport {
    pub running: bool,
    pub kill_switch_active: bool,
    pub default_mode: SwarmExecutionMode,
    pub active_campaigns_count: usize,
    pub attacks_last_24h: u64,
    pub defense_rate_percent: f64,
    pub open_gaps_count: usize,
    pub approved_rules_count: usize,
    pub current_risk_budget_used: u32,
    pub max_risk_budget_per_hour: u32,
}

/// Target endpoint information dynamically queried from the live agent fleet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetAgentTarget {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub os_type: String, // "windows" | "linux" | "macos"
    pub status: String,  // "active" | "disconnected" | "pending"
    pub tags: Vec<String>,
    /// The tenant the agent belongs to: the round's records and alerts are its.
    #[serde(default)]
    pub tenant_id: String,
}
