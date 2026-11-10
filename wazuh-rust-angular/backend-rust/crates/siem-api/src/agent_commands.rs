//! The ProVigil agents' commands and their "talks the ProVigil protocol" mark, in the shared
//! ClickHouse tables (`specs/provigil-gateway.md` 3.3). siem-api writes queued commands and
//! cancellations; `provigil-gateway` hands them out, writes the marks and the agents' results.
//! Writes go to one background writer, in order, so a console action never waits on ClickHouse.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use clickhouse::Client;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tracing::{info, warn};

use crate::AppState;

pub use provigil_agent_server::commands as table;

use table::{CommandRow, DEFAULT_TTL_MS, PROTOCOL_DDL, PROTOCOL_TABLE, TABLE};

/// How often the marks the gateways write are read again.
const MARKS_EVERY: Duration = Duration::from_secs(5);

static WRITES: OnceLock<UnboundedSender<CommandRow>> = OnceLock::new();
static CLIENT: OnceLock<Client> = OnceLock::new();
static TENANTS: OnceLock<std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>> = OnceLock::new();

/// Without ClickHouse (tests): the rows written, newest last.
#[cfg(test)]
pub static SAVED: std::sync::Mutex<Vec<CommandRow>> = std::sync::Mutex::new(Vec::new());

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

pub fn save(row: CommandRow) {
    match WRITES.get() {
        Some(tx) => {
            let _ = tx.send(row);
        }
        #[cfg(test)]
        None => SAVED.lock().unwrap().push(row),
        #[cfg(not(test))]
        None => warn!("ClickHouse not reachable: command {} for agent {} not queued", row.command_id, row.agent_id),
    }
}

/// A command's row as it is now: the gateway writes its hand-out and the agent's result.
pub async fn row(agent: &str, command_id: &str) -> Option<CommandRow> {
    #[cfg(test)]
    if CLIENT.get().is_none() {
        return SAVED.lock().unwrap().iter().rev().find(|r| r.agent_id == agent && r.command_id == command_id).cloned();
    }
    CLIENT.get()?.query(&format!("SELECT ?fields FROM {TABLE} FINAL WHERE agent_id = ? AND command_id = ?")).bind(agent).bind(command_id).fetch_optional().await.ok()?
}

async fn insert(c: &Client, rows: &[CommandRow]) -> Result<(), clickhouse::error::Error> {
    let mut ins = c.insert(TABLE)?;
    for r in rows {
        ins.write(r).await?;
    }
    ins.end().await
}

/// Writes in order; ClickHouse away: the same batch again.
async fn writer(c: Client, mut rx: tokio::sync::mpsc::UnboundedReceiver<CommandRow>) {
    let mut batch = Vec::new();
    while rx.recv_many(&mut batch, 1000).await > 0 {
        let mut wait = Duration::from_secs(1);
        while let Err(e) = insert(&c, &batch).await {
            warn!("agent command queue not written ({} changes wait): {e}", batch.len());
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(Duration::from_secs(30));
        }
        batch.clear();
    }
}

/// The agents marked since `since` (ms).
async fn marks(c: &Client, since: u64) -> Result<Vec<(String, u64)>, clickhouse::error::Error> {
    c.query(&format!("SELECT agent_id, updated_at FROM {PROTOCOL_TABLE} FINAL WHERE updated_at >= ?")).bind(since).fetch_all::<(String, u64)>().await
}

/// The marks, at start and every few seconds after (a gateway marks an agent at its first keepalive).
async fn follow_marks(c: Client) {
    let mut since = 0u64;
    loop {
        match marks(&c, since.saturating_sub(10_000)).await {
            Ok(m) => {
                since = since.max(m.iter().map(|(_, t)| *t).max().unwrap_or(0));
                crate::provigil_manager::restore_http_queue(m.into_iter().map(|(a, _)| a).collect());
            }
            Err(e) => warn!("agent protocol marks not read: {e}"),
        }
        tokio::time::sleep(MARKS_EVERY).await;
    }
}

async fn open(c: &Client) -> Result<(), clickhouse::error::Error> {
    c.query(table::DDL).execute().await?;
    c.query(PROTOCOL_DDL).execute().await
}

/// Opens the tables and starts the writer and the marks reader.
pub async fn start(state: &AppState) {
    let _ = TENANTS.set(state.agent_tenants.clone());
    if !state.db.is_connected() {
        warn!("ClickHouse not reachable: console actions cannot reach ProVigil agents until the next start");
        return;
    }
    let c = state.db.tenant_client(crate::tenancy::DEFAULT_TENANT);
    if let Err(e) = open(&c).await {
        return warn!("agent command queue not opened: {e}");
    }
    let (tx, rx) = unbounded_channel();
    if WRITES.set(tx).is_ok() {
        let _ = CLIENT.set(c.clone());
        tokio::spawn(writer(c.clone(), rx));
        tokio::spawn(follow_marks(c));
        info!("Agent commands: shared queue in ClickHouse");
    }
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
    /// own: queued rows and marks are where the gateway reads them, cancellation included.
    #[tokio::test]
    #[ignore]
    async fn rows_and_marks_reach_clickhouse() {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let root = Client::default().with_url(env("CLICKHOUSE_URL", "http://localhost:8123")).with_user(env("CLICKHOUSE_USER", "default")).with_password(env("CLICKHOUSE_PASSWORD", ""));
        let db = format!("agent_commands_test_{}", uuid::Uuid::new_v4().simple());
        root.query(&format!("CREATE DATABASE {db}")).execute().await.unwrap();
        let c = root.clone().with_database(&db);
        open(&c).await.unwrap();
        let now = now_ms();
        let row = CommandRow { agent_id: "941".into(), command_id: "c1".into(), tenant_id: "t".into(), command: json!({ "command_id": "c1", "type": "scan" }).to_string(), origin: "console".into(), created_at: now, expires_at: now + 60_000, state: table::QUEUED.into(), state_at: now, gateway: String::new(), attempts: 0, result: String::new(), version: next_version() };
        insert(&c, &[row.clone(), CommandRow { state: table::CANCELLED.into(), version: next_version(), ..row }]).await.unwrap();
        let state: String = c.query(&format!("SELECT state FROM {TABLE} FINAL WHERE command_id = 'c1'")).fetch_one().await.unwrap();
        assert_eq!(state, table::CANCELLED, "the last version wins");
        c.query(&format!("INSERT INTO {PROTOCOL_TABLE} VALUES ('941', 'grpc', ?)")).bind(now).execute().await.unwrap();
        assert_eq!(marks(&c, now - 1).await.unwrap(), vec![("941".to_string(), now)]);
        assert!(marks(&c, now + 1).await.unwrap().is_empty());
        root.query(&format!("DROP DATABASE {db}")).execute().await.unwrap();
    }
}
