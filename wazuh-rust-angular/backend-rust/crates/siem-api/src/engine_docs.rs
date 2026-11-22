//! The Risk Fabric and Deception engines' settings, JSON documents in ClickHouse
//! (`siem_engine_docs` in the default tenant's database): read at start, written when they
//! change. Risk Fabric keeps each tenant's own settings (`risk_fabric:<tenant>`) beside the
//! shared ones a tenant starts from (`risk_fabric`). A settings file of an earlier version is stored once and
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
        state.risk_fabric.load(siem_risk_fabric::engine::SHARED, &d);
    }
    let q = state.db.tenant_client(TENANT).query("SELECT id, doc FROM siem_engine_docs FINAL WHERE startsWith(id, 'risk_fabric:')");
    match q.fetch_all::<(String, String)>().await {
        Ok(rows) => {
            for (id, doc) in rows {
                state.risk_fabric.load(&id["risk_fabric:".len()..], &doc);
            }
        }
        Err(e) => tracing::warn!("tenants' risk fabric settings not loaded from ClickHouse: {e}"),
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
    for (tenant, doc) in state.risk_fabric.take_changed() {
        let id = if tenant == siem_risk_fabric::engine::SHARED { "risk_fabric".to_string() } else { format!("risk_fabric:{tenant}") };
        match write(state, &id, doc).await {
            Ok(()) => state.risk_fabric.stored(&tenant),
            Err(e) => {
                tracing::warn!("risk fabric settings not stored (tried again in {}s): {e}", EVERY.as_secs());
                state.risk_fabric.store_failed(&tenant);
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
