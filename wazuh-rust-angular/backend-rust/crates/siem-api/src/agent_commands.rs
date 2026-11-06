//! The ProVigil agents' commands and their "talks the ProVigil protocol" mark, kept in the shared
//! ClickHouse tables `provigil-gateway` uses (`specs/provigil-gateway.md` 3.3): a siem-api restart
//! loses nothing and routes correctly at once. Memory stays the working copy, so a keepalive never
//! waits on ClickHouse; every change goes to one background writer, in order.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use clickhouse::Client;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tracing::{info, warn};

use crate::AppState;

// shortcut: only this file of the crate, which is still being built; phase 2 of the gateway makes it a dependency
#[path = "../../provigil-agent-server/src/commands.rs"]
pub mod table;

use table::{CommandRow, ProtocolRow, DEFAULT_TTL_MS, DONE, FAILED, PROTOCOL_DDL, PROTOCOL_TABLE, QUEUED, TABLE};

/// The protocol name of the mark.
const PROVIGIL: &str = "provigil";
/// A result stored is at most this long: an agent must not fill the table.
const RESULT_MAX: usize = 256 * 1024;

enum Write {
    Row(Box<CommandRow>),
    Mark(ProtocolRow),
    Result { agent: String, command_id: String, state: &'static str, result: String, at: u64, version: u64 },
}

static WRITES: OnceLock<UnboundedSender<Write>> = OnceLock::new();
static TENANTS: OnceLock<std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>> = OnceLock::new();

pub fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

/// Grows with every change, also within a millisecond: the last write of a row wins.
pub fn next_version() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = now_ms();
    LAST.fetch_max(now, Ordering::SeqCst);
    LAST.fetch_add(1, Ordering::SeqCst) + 1
}

pub fn tenant_of(agent: &str) -> String {
    match TENANTS.get() {
        Some(t) => crate::tenancy::tenant_of(&t.read().unwrap(), agent),
        None => crate::tenancy::DEFAULT_TENANT.to_string(),
    }
}

fn send(w: Write) {
    // no ClickHouse at start: memory only, as before
    if let Some(tx) = WRITES.get() {
        let _ = tx.send(w);
    }
}

pub fn save(row: CommandRow) {
    send(Write::Row(Box::new(row)));
}

pub fn save_mark(agent: &str) {
    let updated_at = now_ms();
    send(Write::Mark(ProtocolRow { agent_id: agent.to_string(), protocol: PROVIGIL.to_string(), updated_at }));
}

/// An agent's result, by command id. The row is copied in ClickHouse, which holds its other columns.
pub fn save_result(agent: &str, result: &serde_json::Value) {
    let Some(command_id) = result["command_id"].as_str().filter(|c| !c.is_empty()) else { return };
    let mut text = result.to_string();
    if text.len() > RESULT_MAX {
        text = serde_json::json!({ "command_id": command_id, "status": result["status"], "truncated": true }).to_string();
    }
    let state = if result["status"] == "error" { FAILED } else { DONE };
    send(Write::Result { agent: agent.to_string(), command_id: command_id.to_string(), state, result: text, at: now_ms(), version: next_version() });
}

async fn insert_rows<T: clickhouse::Row + serde::Serialize>(c: &Client, table: &str, rows: &[&T]) -> Result<(), clickhouse::error::Error> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut ins = c.insert(table)?;
    for r in rows {
        ins.write(*r).await?;
    }
    ins.end().await
}

async fn apply(c: &Client, batch: &[Write]) -> Result<(), clickhouse::error::Error> {
    let rows: Vec<&CommandRow> = batch.iter().filter_map(|w| if let Write::Row(r) = w { Some(&**r) } else { None }).collect();
    let marks: Vec<&ProtocolRow> = batch.iter().filter_map(|w| if let Write::Mark(m) = w { Some(m) } else { None }).collect();
    insert_rows(c, TABLE, &rows).await?;
    insert_rows(c, PROTOCOL_TABLE, &marks).await?;
    // after the rows: a result in this batch may be of a command handed out in it
    for w in batch {
        if let Write::Result { agent, command_id, state, result, at, version } = w {
            c.query(&format!("INSERT INTO {TABLE} SELECT agent_id, command_id, tenant_id, command, origin, created_at, expires_at, ?, ?, gateway, attempts, ?, ? FROM {TABLE} FINAL WHERE agent_id = ? AND command_id = ?"))
                .bind(*state)
                .bind(*at)
                .bind(result.as_str())
                .bind(*version)
                .bind(agent.as_str())
                .bind(command_id.as_str())
                .execute()
                .await?;
        }
    }
    Ok(())
}

/// Writes in order; ClickHouse away: the same batch again, while agents go on from memory.
async fn writer(c: Client, mut rx: tokio::sync::mpsc::UnboundedReceiver<Write>) {
    let mut batch = Vec::new();
    while rx.recv_many(&mut batch, 1000).await > 0 {
        let mut wait = Duration::from_secs(1);
        while let Err(e) = apply(&c, &batch).await {
            warn!("agent command queue not written ({} changes wait): {e}", batch.len());
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(Duration::from_secs(30));
        }
        batch.clear();
    }
}

/// The marks, and the commands still waiting (oldest first).
async fn load(c: &Client) -> Result<(Vec<String>, Vec<CommandRow>), clickhouse::error::Error> {
    let marks = c.query(&format!("SELECT agent_id FROM {PROTOCOL_TABLE} FINAL WHERE protocol = ?")).bind(PROVIGIL).fetch_all::<String>().await?;
    let rows = c.query(&format!("SELECT ?fields FROM {TABLE} FINAL WHERE state = ? ORDER BY created_at, command_id")).bind(QUEUED).fetch_all::<CommandRow>().await?;
    Ok((marks, rows))
}

async fn open(c: &Client) -> Result<(Vec<String>, Vec<CommandRow>), clickhouse::error::Error> {
    c.query(table::DDL).execute().await?;
    c.query(PROTOCOL_DDL).execute().await?;
    load(c).await
}

/// Loads the queue and the marks (before any agent is served) and starts the writer.
pub async fn start(state: &AppState) {
    let _ = TENANTS.set(state.agent_tenants.clone());
    if !state.db.is_connected() {
        warn!("ClickHouse not reachable: agent commands stay in memory until the next start");
        return;
    }
    let c = state.db.tenant_client(crate::tenancy::DEFAULT_TENANT);
    match open(&c).await {
        Ok((marks, rows)) => {
            info!("Agent commands from ClickHouse: {} ProVigil agents, {} commands waiting", marks.len(), rows.len());
            run(c, marks, rows);
        }
        Err(e) => warn!("agent command queue not loaded, commands stay in memory: {e}"),
    }
}

fn run(c: Client, marks: Vec<String>, rows: Vec<CommandRow>) {
    let (tx, rx) = unbounded_channel();
    if WRITES.set(tx).is_ok() {
        tokio::spawn(writer(c, rx));
    }
    crate::provigil_manager::restore_http_queue(marks, rows);
}

/// How long a command may wait: a timed response (`firewall-drop600`) is pointless after its time.
pub fn ttl_ms(cmd: &serde_json::Value) -> u64 {
    let name = cmd["message"]["command"].as_str().unwrap_or("");
    let digits = name.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    match name[digits..].parse::<u64>() {
        Ok(secs) if secs > 0 => secs.saturating_mul(1000).min(DEFAULT_TTL_MS),
        _ => DEFAULT_TTL_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_timed_response_expires_with_its_time() {
        assert_eq!(ttl_ms(&json!({ "type": "ar", "message": { "command": "firewall-drop600" } })), 600_000);
        assert_eq!(ttl_ms(&json!({ "type": "ar", "message": { "command": "kill-process0" } })), DEFAULT_TTL_MS);
        assert_eq!(ttl_ms(&json!({ "type": "ar", "message": { "command": "isolate-host99999999999" } })), DEFAULT_TTL_MS);
        assert_eq!(ttl_ms(&json!({ "type": "scan" })), DEFAULT_TTL_MS);
    }

    #[test]
    fn versions_only_grow() {
        let (a, b) = (next_version(), next_version());
        assert!(b > a && a >= now_ms() - 60_000);
    }

    /// Against the real ClickHouse (`CLICKHOUSE_URL`, `_USER`, `_PASSWORD`), in a database of its
    /// own: what was queued, marked and answered is there after a "restart".
    #[tokio::test]
    #[ignore]
    async fn a_restart_loses_nothing() {
        use crate::provigil_manager::{is_http_agent, mark_http_agent, on_command_result, push_http_command, restore_http_queue, take_http_commands};
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let root = Client::default()
            .with_url(env("CLICKHOUSE_URL", "http://localhost:8123"))
            .with_user(env("CLICKHOUSE_USER", "default"))
            .with_password(env("CLICKHOUSE_PASSWORD", ""));
        let db = format!("agent_commands_test_{}", uuid::Uuid::new_v4().simple());
        root.query(&format!("CREATE DATABASE {db}")).execute().await.unwrap();
        let c = root.clone().with_database(&db);
        let (marks, rows) = open(&c).await.unwrap();
        run(c.clone(), marks, rows);

        mark_http_agent("941");
        for n in 0..3 {
            push_http_command("941", json!({ "command_id": format!("c{n}"), "type": "scan" }));
        }
        // the first command reaches the agent and is answered, the other two stay queued
        let handed = take_http_commands("941");
        assert_eq!(handed.len(), 3);
        push_http_command("941", json!({ "command_id": "c3", "type": "ar", "message": { "command": "firewall-drop600" } }));
        on_command_result("941", &json!({ "command_id": "c1", "status": "error", "error": "no" }));

        let settled = async {
            for _ in 0..100 {
                let n: u64 = c.query(&format!("SELECT count() FROM {TABLE} FINAL WHERE state = ?")).bind(FAILED).fetch_one().await.unwrap();
                if n == 1 {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            false
        };
        assert!(settled.await, "the result was not written");

        // a restart: memory is gone
        crate::provigil_manager::forget_http_queue();
        assert!(!is_http_agent("941"));
        let (marks, rows) = load(&c).await.unwrap();
        restore_http_queue(marks, rows);
        assert!(is_http_agent("941"), "routes to the keepalive at once");
        let left = take_http_commands("941");
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0]["command_id"], "c3");
        assert_eq!(left[0]["message"]["command"], "firewall-drop600");

        let r: (String, String, String) = c.query(&format!("SELECT state, result, command FROM {TABLE} FINAL WHERE agent_id = '941' AND command_id = 'c1'")).fetch_one().await.unwrap();
        assert_eq!(r.0, FAILED);
        assert!(r.1.contains("\"error\":\"no\"") && r.2.contains("\"scan\""), "{r:?}");
        root.query(&format!("DROP DATABASE {db}")).execute().await.unwrap();
    }
}
