//! Each Wazuh agent's latest SCA results in ClickHouse, `siem_sca_checks` in the agent's
//! tenant's database (one row per check, with its scan's summary): the one copy of agent
//! data siem-api keeps, because the compliance audit (compliance.rs) scores every agent of
//! a tenant against every check in one query. The agent pages read wazuh-db (the agent's
//! SQLite database), the source; FIM, rootcheck and inventory are not copied at all.
//! Copied when the scan changed (a cheap query on `sca_scan_info` tells), within seconds of
//! the agent's SCA event; every agent once at start.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

pub const DDL: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS siem_sca_checks (agent_id String, policy_id String, policy_name String, check_id String, title String, status LowCardinality(String), reason String, \
     score UInt32, passed UInt32, failed UInt32, not_applicable UInt32, scanned_at String, synced_at UInt64) ENGINE = ReplacingMergeTree(synced_at) ORDER BY (agent_id, policy_id, check_id)",
    // each check's text and frameworks (the agent's own), for compliance and the fixes
    "ALTER TABLE siem_sca_checks ADD COLUMN IF NOT EXISTS description String DEFAULT '', ADD COLUMN IF NOT EXISTS rationale String DEFAULT '', \
     ADD COLUMN IF NOT EXISTS remediation String DEFAULT '', ADD COLUMN IF NOT EXISTS compliance String DEFAULT '{}'",
];

/// How often the changed agents are copied.
const CHANGED_EVERY: Duration = Duration::from_secs(5);
/// Agents copied at the same time (wazuh-db answers with 8 workers).
const PARALLEL: usize = 8;
/// Agents with an SCA event since the last copy (or whose copy failed: tried again).
static CHANGED: Mutex<Option<std::collections::BTreeSet<String>>> = Mutex::new(None);

/// An agent's SCA results changed (an SCA event of theirs on the stream).
pub fn changed(agent_id: &str) {
    CHANGED.lock().unwrap().get_or_insert_with(Default::default).insert(agent_id.to_string());
}

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct ScaRow {
    agent_id: String,
    policy_id: String,
    policy_name: String,
    check_id: String,
    title: String,
    status: String,
    reason: String,
    score: u32,
    passed: u32,
    failed: u32,
    not_applicable: u32,
    scanned_at: String,
    synced_at: u64,
    description: String,
    rationale: String,
    remediation: String,
    /// {"pci_dss_v4.0": ["8.3.4"], "soc_2": ["CC6.1"], ...}
    compliance: String,
}

fn st(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        x => x.to_string(),
    }
}

fn num(v: &Value) -> u64 {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).unwrap_or(0)
}

/// The scan last copied per agent, with the tenant it was copied to: an agent bound to
/// another tenant is copied again, into that tenant's database.
static LAST: Mutex<Option<HashMap<String, (String, String)>>> = Mutex::new(None);

fn tenant_of(state: &AppState, agent_id: &str) -> String {
    crate::tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id)
}

/// Replaces the agent's rows: a lightweight delete, then the new rows.
async fn replace(state: &AppState, tenant: &str, agent: &str, rows: &[ScaRow]) -> Result<(), String> {
    let c = state.db.tenant_client(tenant);
    c.query("DELETE FROM siem_sca_checks WHERE agent_id = ?").bind(agent).execute().await.map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Ok(());
    }
    let mut ins = c.insert("siem_sca_checks").map_err(|e| e.to_string())?;
    for r in rows {
        ins.write(r).await.map_err(|e| e.to_string())?;
    }
    ins.end().await.map_err(|e| e.to_string())
}

/// The rows of one scan, as `provigil_manager::agent_sca` gives it.
fn rows_of(agent_id: &str, s: &Value, synced_at: u64) -> Vec<ScaRow> {
    s["checks"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|c| ScaRow {
                    agent_id: agent_id.to_string(),
                    policy_id: st(&s["policy_id"]),
                    policy_name: st(&s["policy_name"]),
                    check_id: st(&c["check_id"]),
                    title: st(&c["title"]),
                    status: st(&c["status"]),
                    reason: st(&c["reason"]),
                    score: num(&s["score"]) as u32,
                    passed: num(&s["passed"]) as u32,
                    failed: num(&s["failed"]) as u32,
                    not_applicable: num(&s["not_applicable"]) as u32,
                    scanned_at: st(&s["scanned_at"]),
                    synced_at,
                    description: st(&c["description"]),
                    rationale: st(&c["rationale"]),
                    remediation: st(&c["remediation"]),
                    compliance: c["compliance"].to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Copies the agent's SCA results when its scan changed; whether it copied.
pub async fn sync_agent(state: &AppState, agent_id: &str) -> bool {
    let Ok(n) = agent_id.parse::<u32>() else { return false };
    let id = format!("{n:03}");
    let tenant = tenant_of(state, agent_id);
    let Some(marker) = crate::provigil_manager::agent_sql(&id, "SELECT policy_id, end_scan, score FROM sca_scan_info ORDER BY end_scan DESC LIMIT 1;").await.map(|r| json!(r).to_string()) else {
        return false;
    };
    let last = LAST.lock().unwrap().get_or_insert_with(HashMap::new).get(agent_id).cloned();
    if last.as_ref() == Some(&(tenant.clone(), marker.clone())) {
        return false;
    }
    let Some(s) = crate::provigil_manager::agent_sca(agent_id).await else { return false };
    let rows = rows_of(agent_id, &s, chrono::Utc::now().timestamp_millis().max(0) as u64);
    match replace(state, &tenant, agent_id, &rows).await {
        Ok(()) => {
            // copied before into another tenant's database: not that tenant's any more
            if let Some((old, _)) = last.filter(|(t, _)| *t != tenant) {
                if let Err(e) = replace(state, &old, agent_id, &[]).await {
                    tracing::warn!("SCA of agent {agent_id}: rows in tenant {old} not removed: {e}");
                }
            }
            LAST.lock().unwrap().get_or_insert_with(HashMap::new).insert(agent_id.to_string(), (tenant, marker));
            true
        }
        Err(e) => {
            tracing::warn!("SCA of agent {agent_id} not stored (tried again in {}s): {e}", CHANGED_EVERY.as_secs());
            changed(agent_id);
            false
        }
    }
}

/// A removed agent's SCA rows (its tenant's database).
pub async fn forget(state: &AppState, tenant: &str, agent_id: &str) {
    LAST.lock().unwrap().get_or_insert_with(HashMap::new).remove(agent_id);
    if let Err(e) = replace(state, tenant, agent_id, &[]).await {
        tracing::warn!("SCA rows of removed agent {agent_id} not deleted: {e}");
    }
}

/// Every Wazuh agent 90 s after start, then the agents with an SCA event on the stream
/// (`changed`), within seconds; `PARALLEL` at a time.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(90)).await;
        let mut ids: Vec<String> = state.agents.read().unwrap().keys().cloned().collect();
        loop {
            if state.db.is_connected() && crate::provigil_manager::enabled() && !ids.is_empty() {
                let wazuh: Vec<String> = ids.iter().filter(|k| k.parse::<u32>().is_ok_and(|n| n > 0)).cloned().collect();
                let n = futures_util::stream::iter(wazuh)
                    .map(|id| {
                        let st = state.clone();
                        async move { sync_agent(&st, &id).await as usize }
                    })
                    .buffer_unordered(PARALLEL)
                    .fold(0, |t, c| std::future::ready(t + c))
                    .await;
                if n > 0 {
                    tracing::info!("SCA: {n} agent(s) updated in ClickHouse");
                }
            }
            tokio::time::sleep(CHANGED_EVERY).await;
            ids = CHANGED.lock().unwrap().take().unwrap_or_default().into_iter().collect();
        }
    });
}
