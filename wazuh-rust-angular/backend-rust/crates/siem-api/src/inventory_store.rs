//! Agent inventory in ClickHouse (`siem_agent_inventory`, per tenant): each
//! agent's latest OS, hardware, packages, ports, network interfaces and
//! processes. Synced every 10 minutes from where the agent reports it (Wazuh
//! agents: the manager's wazuh-db; siem-agents: siem-api's store), and read by
//! the inventory endpoints. wazuh-db's files stay the manager's own copy.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use crate::db::DocTable;
use crate::AppState;

const SYNC_SECS: u64 = 600;
/// The last synced content of each agent (only a change is written).
static LAST: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

fn tenant_of(state: &AppState, agent_id: &str) -> String {
    crate::tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id)
}

fn digest(v: &Value) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    v.to_string().hash(&mut h);
    h.finish()
}

/// What wazuh-db holds for a Wazuh agent.
async fn from_wazuh_db(agent_id: &str) -> Option<Value> {
    let summary = crate::wazuh_manager::agent_inventory(agent_id).await?;
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    let one = |sql: &'static str| {
        let id = id.clone();
        async move { crate::wazuh_manager::agent_sql(&id, sql).await.unwrap_or_default().into_iter().next() }
    };
    Some(json!({
        "summary": summary,
        "os": one("SELECT * FROM sys_osinfo LIMIT 1;").await,
        "hardware": one("SELECT * FROM sys_hwinfo LIMIT 1;").await,
        "packages": paged(&id, "SELECT name, version, vendor, architecture, format, install_time, size, description FROM sys_programs ORDER BY name", 5000).await,
        "ports": paged(&id, "SELECT protocol, local_ip, local_port, remote_ip, remote_port, state, pid, process FROM sys_ports ORDER BY local_port", 2000).await,
        "netiface": paged(&id, "SELECT name, adapter, type, state, mtu, mac FROM sys_netiface ORDER BY name", 200).await,
        "processes": paged(&id, "SELECT pid, name, cmd, euser, ppid, start_time FROM sys_processes ORDER BY name", 2000).await,
        "source": "wazuh-db",
    }))
}

/// Rows of an agent table, 100 at a time: one wazuh-db reply is at most 64 KB,
/// so a large SELECT (full process command lines) would come back empty. A page
/// wazuh-db refuses (too long) is asked again in halves; a single row it still
/// refuses is skipped (a few in a row: wazuh-db is down, stop).
pub(crate) async fn paged(id: &str, sql: &str, max: usize) -> Vec<Value> {
    let (mut page, mut offset, mut skipped) = (100usize, 0usize, 0usize);
    let mut out = Vec::new();
    while out.len() < max {
        let Some(rows) = crate::wazuh_manager::agent_sql(id, &format!("{sql} LIMIT {page} OFFSET {offset};")).await else {
            if page > 1 {
                page /= 2;
            } else if skipped < 5 {
                (offset, skipped) = (offset + 1, skipped + 1);
            } else {
                break;
            }
            continue;
        };
        let n = rows.len();
        (offset, skipped) = (offset + n, 0);
        out.extend(rows);
        if n < page {
            break;
        }
        page = (page * 2).min(100);
    }
    out.truncate(max);
    out
}

/// What siem-api's own store holds for a siem-agent.
fn from_siem_agent(state: &AppState, agent_id: &str) -> Option<Value> {
    let db = state.wdb.get(agent_id)?;
    let db = db.read().unwrap();
    let s = &db.syscollector;
    if s.os_info.is_none() && s.hw_info.is_none() && s.programs.is_empty() && s.ports.is_empty() {
        return None;
    }
    let summary = {
        let events = state.events.read().unwrap();
        events.iter().rev().find(|e| e.agent_id == agent_id && e.metadata.contains_key("inventory_json")).and_then(|e| e.metadata.get("inventory_json")).and_then(|j| serde_json::from_str::<Value>(j).ok())
    };
    Some(json!({
        "summary": summary,
        "os": s.os_info,
        "hardware": s.hw_info,
        "packages": s.programs.values().collect::<Vec<_>>(),
        "ports": s.ports,
        "netiface": s.netifaces,
        "processes": [],
        "source": "siem-agent",
    }))
}

/// Copies one agent's inventory to ClickHouse when it changed.
pub async fn sync_agent(state: &AppState, agent_id: &str) -> bool {
    let doc = match from_wazuh_db(agent_id).await {
        Some(d) => Some(d),
        None => from_siem_agent(state, agent_id),
    };
    let Some(mut doc) = doc else { return false };
    let h = digest(&doc);
    if LAST.lock().unwrap().get_or_insert_with(HashMap::new).get(agent_id) == Some(&h) {
        return false;
    }
    doc["agent_id"] = json!(agent_id);
    doc["synced_at"] = json!(chrono::Utc::now().to_rfc3339());
    let tenant = tenant_of(state, agent_id);
    match state.db.put_doc(&tenant, DocTable::Inventory, agent_id, &doc.to_string()).await {
        Ok(()) => {
            LAST.lock().unwrap().get_or_insert_with(HashMap::new).insert(agent_id.to_string(), h);
            true
        }
        Err(e) => {
            tracing::warn!("inventory of agent {agent_id} not stored: {e}");
            false
        }
    }
}

/// Every agent, every 10 minutes (first pass a minute after start).
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        loop {
            if state.db.is_connected() {
                let ids: Vec<String> = state.agents.read().unwrap().keys().cloned().collect();
                let mut n = 0;
                for id in ids {
                    if sync_agent(&state, &id).await {
                        n += 1;
                    }
                }
                if n > 0 {
                    tracing::info!("inventory: {n} agent(s) updated in ClickHouse");
                }
            }
            tokio::time::sleep(Duration::from_secs(SYNC_SECS)).await;
        }
    });
}

/// The agent's stored inventory (ClickHouse); synced first when there is none yet.
pub async fn get(state: &AppState, agent_id: &str) -> Option<Value> {
    if !state.db.is_connected() {
        return None;
    }
    let tenant = tenant_of(state, agent_id);
    let read = || async { state.db.doc(&tenant, DocTable::Inventory, agent_id).await.ok().flatten().and_then(|d| serde_json::from_str::<Value>(&d).ok()) };
    if let Some(v) = read().await {
        return Some(v);
    }
    if sync_agent(state, agent_id).await {
        return read().await;
    }
    None
}
