//! Agent inventory, read live, nothing copied: a Wazuh agent's from the manager's
//! wazuh-db (the agent's own SQLite database, `queue/db/<id>.db`), a siem-agent's from
//! siem-api's store. Callers have checked the agent is the caller's tenant's (the
//! `/api/v1/agents/<id>` middleware, `agent_in_scope`, or the tenant's own agent list).

use serde_json::{json, Value};

use crate::AppState;

/// One part of an agent's inventory.
#[derive(Clone, Copy)]
pub enum Part {
    Os,
    Hardware,
    Packages,
    Ports,
    Netiface,
}

/// The part from wazuh-db; None when the agent is not a Wazuh agent (a siem-agent: its store).
pub async fn part(agent_id: &str, part: Part) -> Option<Value> {
    if !crate::provigil_manager::is_provigil_agent(agent_id).await {
        return None;
    }
    let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
    Some(match part {
        Part::Os => first(&id, "SELECT * FROM sys_osinfo LIMIT 1;").await,
        Part::Hardware => first(&id, "SELECT * FROM sys_hwinfo LIMIT 1;").await,
        Part::Packages => Value::Array(paged(&id, "SELECT name, version, vendor, architecture, format, install_time, size, description FROM sys_programs ORDER BY name", 5000).await),
        Part::Ports => Value::Array(paged(&id, "SELECT protocol, local_ip, local_port, remote_ip, remote_port, state, pid, process FROM sys_ports ORDER BY local_port", 2000).await),
        Part::Netiface => Value::Array(paged(&id, "SELECT name, adapter, type, state, mtu, mac FROM sys_netiface ORDER BY name", 200).await),
    })
}

/// What an investigation shows of a host: OS, hardware, how many packages, ports, processes.
pub async fn host(state: &AppState, agent_id: &str) -> Option<Value> {
    if crate::provigil_manager::is_provigil_agent(agent_id).await {
        let id = format!("{:03}", agent_id.parse::<u32>().ok()?);
        return Some(json!({
            "os": first(&id, "SELECT * FROM sys_osinfo LIMIT 1;").await,
            "hardware": first(&id, "SELECT * FROM sys_hwinfo LIMIT 1;").await,
            "packages": count(&id, "sys_programs").await,
            "ports": count(&id, "sys_ports").await,
            "processes": count(&id, "sys_processes").await,
            "source": "wazuh-db",
        }));
    }
    let db = state.wdb.get(agent_id)?;
    let db = db.read().unwrap();
    let s = &db.syscollector;
    Some(json!({ "os": s.os_info, "hardware": s.hw_info, "packages": s.programs.len(), "ports": s.ports.len(), "processes": 0, "source": "siem-agent" }))
}

/// The first row of an agent query (null: none).
async fn first(id: &str, sql: &str) -> Value {
    crate::provigil_manager::agent_sql(id, sql).await.unwrap_or_default().into_iter().next().unwrap_or(Value::Null)
}

/// The rows of one of the agent's tables (`table`: a constant name, never user input).
pub(crate) async fn count(id: &str, table: &'static str) -> u64 {
    crate::provigil_manager::agent_sql(id, &format!("SELECT count(*) AS n FROM {table};"))
        .await
        .and_then(|r| r.first().and_then(|x| x.get("n")).and_then(Value::as_u64))
        .unwrap_or(0)
}

/// Rows of an agent table, 100 at a time: one wazuh-db reply is at most 64 KB,
/// so a large SELECT (full process command lines) would come back empty. A page
/// wazuh-db refuses (too long) is asked again in halves; a single row it still
/// refuses is skipped (a few in a row: wazuh-db is down, stop).
pub(crate) async fn paged(id: &str, sql: &str, max: usize) -> Vec<Value> {
    let (mut page, mut offset, mut skipped) = (100usize, 0usize, 0usize);
    let mut out = Vec::new();
    while out.len() < max {
        let Some(rows) = crate::provigil_manager::agent_sql(id, &format!("{sql} LIMIT {page} OFFSET {offset};")).await else {
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
