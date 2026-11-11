//! The Risk Fabric and Deception engines' settings, one JSON document each, in ClickHouse
//! (`siem_engine_docs` in the default tenant's database, the engines are shared): read at
//! start, written when they change. A settings file of an earlier version is stored once and
//! removed.

use std::time::Duration;

use serde::Serialize;

use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_engine_docs (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";
const TENANT: &str = "default";
const EVERY: Duration = Duration::from_secs(5);

#[derive(clickhouse::Row, Serialize)]
struct DocRow {
    id: String,
    doc: String,
    version: u64,
}

async fn read(state: &AppState, id: &str) -> Option<String> {
    let q = state.db.tenant_client(TENANT).query("SELECT doc FROM siem_engine_docs FINAL WHERE id = ?").bind(id);
    match q.fetch_all::<String>().await {
        Ok(docs) => docs.into_iter().next(),
        Err(e) => {
            tracing::warn!("{id} settings not loaded from ClickHouse: {e}");
            None
        }
    }
}

/// The stored settings into the engines (a stored document is newer than an old file).
pub async fn load(state: &AppState) {
    if let Some(d) = read(state, "risk_fabric").await {
        state.risk_fabric.load(&d);
    }
    if let Some(d) = read(state, "deception").await {
        state.deception_engine.load(&d);
    }
}

async fn write(state: &AppState, id: &str, doc: String) -> Result<(), clickhouse::error::Error> {
    let client = state.db.tenant_client(TENANT);
    let mut ins = client.insert("siem_engine_docs")?;
    let version = chrono::Utc::now().timestamp_micros().max(0) as u64;
    ins.write(&DocRow { id: id.into(), doc, version }).await?;
    ins.end().await
}

async fn flush(state: &AppState) {
    if let Some(doc) = state.risk_fabric.take_changed() {
        match write(state, "risk_fabric", doc).await {
            Ok(()) => state.risk_fabric.stored(),
            Err(e) => {
                tracing::warn!("risk fabric settings not stored (tried again in {}s): {e}", EVERY.as_secs());
                state.risk_fabric.store_failed();
            }
        }
    }
    if let Some(doc) = state.deception_engine.take_changed() {
        match write(state, "deception", doc).await {
            Ok(()) => state.deception_engine.stored(),
            Err(e) => {
                tracing::warn!("deception settings not stored (tried again in {}s): {e}", EVERY.as_secs());
                state.deception_engine.store_failed();
            }
        }
    }
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            if state.db.is_connected() {
                flush(&state).await;
            }
            tokio::time::sleep(EVERY).await;
        }
    });
}
