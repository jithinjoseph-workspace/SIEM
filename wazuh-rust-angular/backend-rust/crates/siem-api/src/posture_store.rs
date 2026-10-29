//! Each Wazuh agent's CIS / SCA results and FIM file list in ClickHouse (per tenant):
//! `siem_sca_checks` (one row per check, with its scan's summary) and `siem_fim_files` (one
//! row per monitored file or registry value). Copied from the manager's wazuh-db every 10
//! minutes when they changed — a cheap query tells (the scan's end, the FIM row count and
//! last change) —, and read by the agent pages; wazuh-db stays the manager's working copy.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

pub const DDL: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS siem_sca_checks (agent_id String, policy_id String, policy_name String, check_id String, title String, status LowCardinality(String), reason String, \
     score UInt32, passed UInt32, failed UInt32, not_applicable UInt32, scanned_at String, synced_at UInt64) ENGINE = ReplacingMergeTree(synced_at) ORDER BY (agent_id, policy_id, check_id)",
    "CREATE TABLE IF NOT EXISTS siem_fim_files (agent_id String, full_path String, key String, type LowCardinality(String), size UInt64, uname String, gname String, \
     md5 String, sha1 String, sha256 String, mtime String, date String, changes UInt64, synced_at UInt64) ENGINE = ReplacingMergeTree(synced_at) ORDER BY (agent_id, full_path, key)",
];

const SYNC_SECS: u64 = 600;
/// FIM entries copied per agent (the page shows the newest 1,000 and the total).
const MAX_FIM: usize = 100_000;

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
}

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct FimRow {
    agent_id: String,
    full_path: String,
    key: String,
    r#type: String,
    size: u64,
    uname: String,
    gname: String,
    md5: String,
    sha1: String,
    sha256: String,
    mtime: String,
    date: String,
    changes: u64,
    synced_at: u64,
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

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

/// What was last copied per agent: (SCA marker, FIM marker).
static LAST: Mutex<Option<HashMap<String, (String, String)>>> = Mutex::new(None);

fn last(agent: &str) -> (String, String) {
    LAST.lock().unwrap().get_or_insert_with(HashMap::new).get(agent).cloned().unwrap_or_default()
}

fn remember(agent: &str, sca: Option<String>, fim: Option<String>) {
    let mut g = LAST.lock().unwrap();
    let e = g.get_or_insert_with(HashMap::new).entry(agent.to_string()).or_default();
    if let Some(s) = sca {
        e.0 = s;
    }
    if let Some(f) = fim {
        e.1 = f;
    }
}

fn tenant_of(state: &AppState, agent_id: &str) -> String {
    crate::tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id)
}

/// Replaces the agent's rows: a lightweight delete, then the new rows.
async fn replace<T: clickhouse::Row + Serialize>(state: &AppState, tenant: &str, table: &str, agent: &str, rows: &[T]) -> Result<(), String> {
    let c = state.db.tenant_client(tenant);
    c.query(&format!("DELETE FROM {table} WHERE agent_id = ?")).bind(agent).execute().await.map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Ok(());
    }
    let mut ins = c.insert(table).map_err(|e| e.to_string())?;
    for r in rows {
        ins.write(r).await.map_err(|e| e.to_string())?;
    }
    ins.end().await.map_err(|e| e.to_string())
}

/// Copies the agent's SCA results and FIM list when they changed; whether anything did.
pub async fn sync_agent(state: &AppState, agent_id: &str) -> bool {
    let Ok(n) = agent_id.parse::<u32>() else { return false };
    let id = format!("{n:03}");
    let tenant = tenant_of(state, agent_id);
    let (sca_seen, fim_seen) = last(agent_id);
    let mut changed = false;

    let sca_marker = crate::wazuh_manager::agent_sql(&id, "SELECT policy_id, end_scan, score FROM sca_scan_info ORDER BY end_scan DESC LIMIT 1;").await.map(|r| json!(r).to_string());
    if let Some(marker) = sca_marker.filter(|m| *m != sca_seen) {
        if let Some(s) = crate::wazuh_manager::agent_sca(agent_id).await {
            let synced_at = now_ms();
            let rows: Vec<ScaRow> = s["checks"]
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
                        })
                        .collect()
                })
                .unwrap_or_default();
            match replace(state, &tenant, "siem_sca_checks", agent_id, &rows).await {
                Ok(()) => {
                    remember(agent_id, Some(marker), None);
                    changed = true;
                }
                Err(e) => tracing::warn!("SCA of agent {agent_id} not stored: {e}"),
            }
        }
    }

    let fim_marker = crate::wazuh_manager::agent_sql(&id, "SELECT count(*) AS n, max(date) AS last FROM fim_entry;").await.map(|r| json!(r).to_string());
    if let Some(marker) = fim_marker.filter(|m| *m != fim_seen) {
        if let Some(f) = crate::wazuh_manager::agent_fim_upto(agent_id, MAX_FIM).await {
            if f["total"].as_u64().unwrap_or(0) > MAX_FIM as u64 {
                tracing::warn!("FIM of agent {agent_id}: {} entries, the {MAX_FIM} most recently changed kept in ClickHouse", f["total"]);
            }
            let synced_at = now_ms();
            let rows: Vec<FimRow> = f["entries"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|e| FimRow {
                            agent_id: agent_id.to_string(),
                            full_path: st(&e["full_path"]),
                            key: st(&e["key"]),
                            r#type: st(&e["type"]),
                            size: num(&e["size"]),
                            uname: st(&e["uname"]),
                            gname: st(&e["gname"]),
                            md5: st(&e["md5"]),
                            sha1: st(&e["sha1"]),
                            sha256: st(&e["sha256"]),
                            mtime: st(&e["mtime"]),
                            date: st(&e["date"]),
                            changes: num(&e["changes"]),
                            synced_at,
                        })
                        .collect()
                })
                .unwrap_or_default();
            match replace(state, &tenant, "siem_fim_files", agent_id, &rows).await {
                Ok(()) => {
                    remember(agent_id, None, Some(marker));
                    changed = true;
                }
                Err(e) => tracing::warn!("FIM of agent {agent_id} not stored: {e}"),
            }
        }
    }
    changed
}

/// Every Wazuh agent every 10 minutes (the first pass 90 s after start).
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(90)).await;
        loop {
            if state.db.is_connected() && crate::wazuh_manager::enabled() {
                let ids: Vec<String> = state.agents.read().unwrap().keys().filter(|k| k.parse::<u32>().is_ok_and(|n| n > 0)).cloned().collect();
                let mut n = 0;
                for id in ids {
                    if sync_agent(&state, &id).await {
                        n += 1;
                    }
                }
                if n > 0 {
                    tracing::info!("SCA / FIM: {n} agent(s) updated in ClickHouse");
                }
            }
            tokio::time::sleep(Duration::from_secs(SYNC_SECS)).await;
        }
    });
}

/// The agent's SCA results as `wazuh_manager::agent_sca` gives them, from ClickHouse.
pub async fn sca(state: &AppState, agent_id: &str) -> Option<Value> {
    let rows = state
        .db
        .tenant_client(&tenant_of(state, agent_id))
        .query("SELECT ?fields FROM siem_sca_checks FINAL WHERE agent_id = ? ORDER BY toUInt32OrZero(check_id), check_id")
        .bind(agent_id)
        .fetch_all::<ScaRow>()
        .await
        .ok()?;
    let f = rows.first()?;
    let checks: Vec<Value> = rows.iter().map(|r| json!({ "check_id": r.check_id, "title": r.title, "status": r.status, "reason": r.reason })).collect();
    Some(json!({
        "agent_id": agent_id, "policy_id": f.policy_id, "policy_name": f.policy_name, "score": f.score, "passed": f.passed, "failed": f.failed,
        "not_applicable": f.not_applicable, "scanned_at": f.scanned_at, "checks": checks, "source": "clickhouse",
    }))
}

/// The agent's FIM list as `wazuh_manager::agent_fim` gives it, from ClickHouse.
pub async fn fim(state: &AppState, agent_id: &str) -> Option<Value> {
    let c = state.db.tenant_client(&tenant_of(state, agent_id));
    let total = c.query("SELECT count() FROM siem_fim_files FINAL WHERE agent_id = ?").bind(agent_id).fetch_one::<u64>().await.ok()?;
    let rows = c.query("SELECT ?fields FROM siem_fim_files FINAL WHERE agent_id = ? ORDER BY date DESC LIMIT 1000").bind(agent_id).fetch_all::<FimRow>().await.ok()?;
    if rows.is_empty() {
        return None;
    }
    let entries: Vec<Value> = rows
        .iter()
        .map(|r| {
            let mut e = json!({ "full_path": r.full_path, "type": r.r#type, "size": r.size, "uname": r.uname, "gname": r.gname, "md5": r.md5, "sha1": r.sha1, "sha256": r.sha256, "mtime": r.mtime, "date": r.date, "changes": r.changes });
            if !r.key.is_empty() {
                e["key"] = json!(r.key);
            }
            e
        })
        .collect();
    Some(json!({ "agent_id": agent_id, "total": total, "entries": entries, "source": "clickhouse" }))
}
