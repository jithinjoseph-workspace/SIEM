// SIEM Correlation Engine — Alert Write/Query Layer
//
// Write targets:
//   ndr_{tenant}.siem_alerts    ← SIEM rule engine output (per-tenant DB)
//   ndr_{tenant}.unified_alerts ← corroboration module ONLY (per-tenant DB)
// License: Apache-2.0

use anyhow::Result;
use clickhouse::Client;
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::correlation::types::SiemAlert;

pub fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" || tenant_id.is_empty() {
        "ndr".to_string()
    } else {
        format!("ndr_{}", tenant_id.replace('-', "_"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClickHouse row struct — matches ndr.siem_alerts schema
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct SiemAlertRow {
    pub alert_id:             String,
    pub tenant_id:            String,
    pub severity:             String,
    pub rule_id:              String,
    pub rule_name:            String,
    pub title:                String,
    pub description:          String,
    pub affected_hosts:       Vec<String>,
    pub mitre_techniques:     Vec<String>,
    pub mitre_sources:        Vec<String>,
    pub mitre_confidences:    Vec<f32>,
    pub status:               String,
    pub linked_siem_log_ids:  Vec<String>,
    pub sla_started_at:       Option<u32>,
    pub sla_breached_at:      Option<u32>,
    pub created_at:           u32,
    pub updated_at:           u32,
}

impl From<&SiemAlert> for SiemAlertRow {
    fn from(a: &SiemAlert) -> Self {
        Self {
            alert_id:            a.alert_id.clone(),
            tenant_id:           a.tenant_id.clone(),
            severity:            a.severity.clone(),
            rule_id:             a.rule_id.clone(),
            rule_name:           a.rule_name.clone(),
            title:               a.title.clone(),
            description:         a.description.clone(),
            affected_hosts:      a.affected_hosts.clone(),
            mitre_techniques:    a.mitre_techniques.clone(),
            mitre_sources:       a.mitre_sources.clone(),
            mitre_confidences:   a.mitre_confidences.clone(),
            status:              a.status.clone(),
            linked_siem_log_ids: a.linked_siem_log_ids.clone(),
            sla_started_at:      a.sla_started_at.map(|dt| dt.timestamp() as u32),
            sla_breached_at:     a.sla_breached_at.map(|dt| dt.timestamp() as u32),
            created_at:          a.created_at.timestamp() as u32,
            updated_at:          a.updated_at.timestamp() as u32,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Write operations — target: ndr.siem_alerts
// ─────────────────────────────────────────────────────────────────────────────

/// INSERT a new SIEM rule alert into the tenant's siem_alerts table.
pub async fn write_alert(ch: &Client, alert: &SiemAlert) -> Result<()> {
    let db  = tenant_db(&alert.tenant_id);
    let row = SiemAlertRow::from(alert);
    let table = format!("{db}.siem_alerts");
    let mut insert = ch.insert(&table)?;
    insert.write(&row).await?;
    insert.end().await?;
    tracing::info!(
        alert_id = %alert.alert_id,
        rule_id  = %alert.rule_id,
        severity = %alert.severity,
        tenant   = %alert.tenant_id,
        "SIEM alert written to ndr.siem_alerts"
    );
    Ok(())
}

/// UPDATE an existing SIEM alert: bump updated_at / change status.
pub async fn update_alert(
    ch:         &Client,
    alert_id:   &str,
    tenant_id:  &str,
    new_status: Option<&str>,
) -> Result<()> {
    let db         = tenant_db(tenant_id);
    let updated_at = Utc::now().timestamp() as u32;
    let status_expr = if let Some(s) = new_status {
        format!("'{}' AS status", escape(s))
    } else {
        "status".to_string()
    };

    let sql = format!(
        "INSERT INTO {db}.siem_alerts \
         (alert_id, tenant_id, severity, rule_id, rule_name, title, description, \
          affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, \
          status, linked_siem_log_ids, sla_started_at, sla_breached_at, created_at, updated_at) \
         SELECT \
          alert_id, tenant_id, severity, rule_id, rule_name, title, description, \
          affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, \
          {status}, linked_siem_log_ids, sla_started_at, sla_breached_at, \
          created_at, {ts} AS updated_at \
         FROM {db}.siem_alerts FINAL \
         WHERE alert_id = '{aid}'",
        db     = db,
        status = status_expr,
        ts     = updated_at,
        aid    = escape(alert_id),
    );

    ch.query(&sql).execute().await?;
    tracing::debug!(alert_id = %alert_id, "SIEM alert updated");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Query operations (for REST API)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct AlertListRow {
    pub alert_id:         String,
    pub source:           String,   // always "siem" for ndr.siem_alerts rows
    pub severity:         String,
    pub rule_id:          String,
    pub rule_name:        String,
    pub title:            String,
    pub description:      String,
    pub affected_hosts:   Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub status:           String,
    pub created_at:       u32,
    pub updated_at:       u32,
    pub sla_breached_at:  Option<u32>,
}

pub struct AlertQuery {
    pub tenant_id:  String,
    pub status:     Option<String>,
    pub severity:   Option<String>,
    pub source:     Option<String>,  // optional filter; "siem" returns rows, anything else returns empty
    pub limit:      u32,
    pub offset:     u32,
}

/// Query the tenant's siem_alerts with filters for the REST API.
pub async fn get_alerts(ch: &Client, q: &AlertQuery) -> Result<Vec<AlertListRow>> {
    if let Some(ref s) = q.source {
        if s != "siem" { return Ok(vec![]); }
    }

    let db = tenant_db(&q.tenant_id);
    let mut conditions = vec![
        format!("tenant_id = '{}'", escape(&q.tenant_id))
    ];
    if let Some(ref s) = q.status   { conditions.push(format!("status = '{}'",   escape(s))); }
    if let Some(ref s) = q.severity { conditions.push(format!("severity = '{}'", escape(s))); }

    let sql = format!(
        "SELECT alert_id, 'siem' AS source, severity, rule_id, rule_name, title, description, \
                affected_hosts, mitre_techniques, status, \
                toUnixTimestamp(created_at) AS created_at, \
                toUnixTimestamp(updated_at) AS updated_at, \
                toUnixTimestamp(sla_breached_at) AS sla_breached_at \
         FROM {db}.siem_alerts FINAL \
         WHERE {where_clause} \
         ORDER BY created_at DESC \
         LIMIT {limit} OFFSET {offset}",
        db = db,
        where_clause = conditions.join(" AND "),
        limit        = q.limit,
        offset       = q.offset,
    );

    let rows = ch.query(&sql).fetch_all::<AlertListRow>().await?;
    Ok(rows)
}

/// Count total matching SIEM alerts (for pagination).
pub async fn count_alerts(ch: &Client, q: &AlertQuery) -> Result<u64> {
    if let Some(ref s) = q.source {
        if s != "siem" { return Ok(0); }
    }

    let db = tenant_db(&q.tenant_id);
    let mut conditions = vec![
        format!("tenant_id = '{}'", escape(&q.tenant_id))
    ];
    if let Some(ref s) = q.status   { conditions.push(format!("status = '{}'",   escape(s))); }
    if let Some(ref s) = q.severity { conditions.push(format!("severity = '{}'", escape(s))); }

    let sql = format!(
        "SELECT count() FROM {db}.siem_alerts FINAL WHERE {where_clause}",
        db           = db,
        where_clause = conditions.join(" AND "),
    );
    let count: u64 = ch.query(&sql).fetch_one().await?;
    Ok(count)
}

/// Mark SLA as breached on a SIEM alert (called by sla.rs).
pub async fn mark_sla_breached(ch: &Client, alert_id: &str, tenant_id: &str) -> Result<()> {
    let db  = tenant_db(tenant_id);
    let now = Utc::now().timestamp() as u32;
    let sql = format!(
        "INSERT INTO {db}.siem_alerts \
         (alert_id, tenant_id, severity, rule_id, rule_name, title, description, \
          affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, status, \
          linked_siem_log_ids, sla_started_at, sla_breached_at, created_at, updated_at) \
         SELECT alert_id, tenant_id, severity, rule_id, rule_name, title, description, \
                affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, \
                status, linked_siem_log_ids, sla_started_at, sla_breached_at, \
                created_at, {now} AS updated_at \
         FROM {db}.siem_alerts FINAL \
         WHERE alert_id = '{aid}'",
        db  = db,
        now = now,
        aid = escape(alert_id),
    );
    ch.query(&sql).execute().await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
