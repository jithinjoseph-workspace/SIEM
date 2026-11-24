// SIEM Correlation Engine — Shared Types
// Mirrors the ndr.unified_alerts schema (init.sql lines 968-1000)
// License: Apache-2.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// SiemEvent — parsed OCSF event consumed from the siem-logs Kafka topic.
// Dev 1 publishes these; Dev 2 (us) consumes them.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    /// Unique log identifier (UUIDv4 set by Dev 1 ingest)
    pub log_id: String,
    pub tenant_id: String,
    pub timestamp: DateTime<Utc>,

    // OCSF normalised fields
    pub event_type: String,           // e.g. "authentication", "process_activity"
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub src_ip_token: Option<String>, // HMAC-SHA256 token (not raw IP)
    pub dst_ip_token: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub process_name: Option<String>,
    pub parent_process: Option<String>,
    pub command_line: Option<String>,
    pub bytes_out: Option<u64>,
    pub event_result: Option<String>,  // "success" | "failure"
    pub registry_key: Option<String>,
    pub service_name: Option<String>,
    /// Original unparsed payload (JSON string)
    pub raw: String,

    // UEBA helpers enriched at ingest time
    pub department: Option<String>,
    pub subnet: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertStatus — maps to `status` column in unified_alerts
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    Investigating,
    Escalated,
    Resolved,
    Closed,
    Suppressed,
}

impl AlertStatus {
    pub fn as_str(&self) -> &str {
        match self {
            AlertStatus::New          => "New",
            AlertStatus::Investigating => "Investigating",
            AlertStatus::Escalated    => "Escalated",
            AlertStatus::Resolved     => "Resolved",
            AlertStatus::Closed       => "Closed",
            AlertStatus::Suppressed   => "Suppressed",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SiemAlert — ready to INSERT into ndr.unified_alerts
// Field names exactly match the ClickHouse schema in init.sql line 968.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemAlert {
    pub alert_id: String,
    pub tenant_id: String,
    /// "siem" for SIEM-engine rule output; "corroborated" only when NDR+SIEM cross-match
    pub source: String,
    /// CRITICAL / HIGH / MEDIUM / LOW / INFO
    pub severity: String,
    pub rule_id: String,
    pub rule_name: String,
    pub title: String,
    pub description: String,
    /// Hosts involved (hostname or ip_token)
    pub affected_hosts: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub mitre_sources: Vec<String>,
    pub mitre_confidences: Vec<f32>,
    pub status: String,
    pub linked_siem_log_ids: Vec<String>,
    pub sla_started_at: Option<DateTime<Utc>>,
    pub sla_breached_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// For dedup tracking — not stored in CH
    #[serde(skip)]
    pub occurrence_count: u32,
}

impl SiemAlert {
    pub fn new(
        tenant_id: impl Into<String>,
        rule_id: impl Into<String>,
        rule_name: impl Into<String>,
        severity: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        affected_hosts: Vec<String>,
        linked_log_ids: Vec<String>,
        mitre_techniques: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        let rule_id = rule_id.into();
        let severity_str = severity.into();

        // SLA clock: time-to-acknowledge by severity
        let sla_minutes: i64 = match severity_str.as_str() {
            "CRITICAL" => 15,
            "HIGH"     => 60,
            "MEDIUM"   => 240,   // 4 hours
            _          => 1440,  // 24 hours (LOW / INFO)
        };
        let sla_breached_at = now + chrono::Duration::minutes(sla_minutes);

        Self {
            alert_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.into(),
            source: "siem".to_string(),
            severity: severity_str,
            rule_id,
            rule_name: rule_name.into(),
            title: title.into(),
            description: description.into(),
            affected_hosts,
            mitre_techniques,
            mitre_sources: vec!["siem-engine".to_string()],
            mitre_confidences: vec![0.85],
            status: AlertStatus::New.as_str().to_string(),
            linked_siem_log_ids: linked_log_ids,
            sla_started_at: Some(now),
            sla_breached_at: Some(sla_breached_at),
            created_at: now,
            updated_at: now,
            occurrence_count: 1,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleMatch — result returned by the engine for a triggered rule
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub mitre_techniques: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CorrelationRule — metadata for /api/siem/rules listing
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub enabled: bool,
    pub mitre_techniques: Vec<String>,
    pub fitness_score: f32,
    pub true_positive_rate: f32,
    pub suppression_rate: f32,
    pub avg_resolve_minutes: f32,
}

// ─────────────────────────────────────────────────────────────────────────────
// SuppressionRule — loaded from ndr.siem_suppression_rules
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRule {
    pub id: String,
    pub tenant_id: String,
    pub rule_id: Option<String>,       // None = match any rule
    pub hostname_pattern: Option<String>,
    pub username_pattern: Option<String>,
    pub enabled: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// SlaBreachRow — minimal projection for SLA checker query
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SlaBreachRow {
    pub alert_id: String,
    pub tenant_id: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub sla_breached_at: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────────────────────────
// GenomeFitness — per-rule fitness record written to siem_rule_fitness
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomeFitness {
    pub rule_id: String,
    pub tenant_id: String,
    pub fitness_score: f32,
    pub true_positive_rate: f32,
    pub suppression_rate: f32,
    pub avg_resolve_minutes: f32,
    pub alert_count: u64,
    pub scored_at: DateTime<Utc>,
}
