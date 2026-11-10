//! Each agent's intent dossier in ClickHouse, `siem_intent_dossiers` in the agent's tenant's
//! database: one row per agent, written for the agents that changed, read at start. A dossier
//! file of an earlier version is stored once and removed (`IntentEngine::new`).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;
use siem_intent_engine::EntityIntentDossier;

use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_intent_dossiers (agent_id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY agent_id";

/// The engine's executed actions, audit log and simulation overrides: one row, in the default
/// tenant's database (the engine is shared), written only when an analyst acts or simulates.
pub const EXTRAS_DDL: &str = "CREATE TABLE IF NOT EXISTS siem_intent_extras (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";
const EXTRAS_TENANT: &str = "default";

/// How often the changed dossiers are stored.
const EVERY: Duration = Duration::from_secs(5);

#[derive(clickhouse::Row, Serialize)]
struct DossierRow {
    agent_id: String,
    doc: String,
    version: u64,
}

fn tenant_of(state: &AppState, agent_id: &str) -> String {
    crate::tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id)
}

/// The stored dossiers of every tenant into the engine (an agent moved to another tenant
/// counts in its tenant now).
pub async fn load(state: &AppState) {
    let extras = state.db.tenant_client(EXTRAS_TENANT).query("SELECT doc FROM siem_intent_extras FINAL WHERE id = 'extras'").fetch_all::<String>().await;
    match extras {
        Ok(docs) => {
            if let Some(x) = docs.first().and_then(|d| serde_json::from_str::<siem_intent_engine::IntentExtras>(d).ok()) {
                state.intent_engine.load_extras(x);
            }
        }
        Err(e) => tracing::warn!("intent engine audit log and simulations not loaded: {e}"),
    }
    for tenant in crate::predictions::tenant_ids(state) {
        let docs = state.db.tenant_client(&tenant).query("SELECT doc FROM siem_intent_dossiers FINAL").fetch_all::<String>().await;
        match docs {
            Ok(docs) => {
                let dossiers = docs.iter().filter_map(|d| serde_json::from_str::<EntityIntentDossier>(d).ok()).filter(|d| tenant_of(state, &d.entity_id) == tenant && !state.deleted_agents.read().unwrap().contains(&d.entity_id)).collect();
                state.intent_engine.load(dossiers);
            }
            Err(e) => tracing::warn!("intent dossiers of tenant {tenant} not loaded: {e}"),
        }
    }
}

async fn insert(state: &AppState, tenant: &str, rows: &[DossierRow]) -> Result<(), clickhouse::error::Error> {
    let client = state.db.tenant_client(tenant);
    let mut ins = client.insert("siem_intent_dossiers")?;
    for r in rows {
        ins.write(r).await?;
    }
    ins.end().await
}

/// Stores the dossiers that changed, one INSERT per tenant; what failed stays changed.
async fn flush(state: &AppState) {
    let version = chrono::Utc::now().timestamp_micros().max(0) as u64;
    let mut tenants: BTreeMap<String, Vec<DossierRow>> = BTreeMap::new();
    for d in state.intent_engine.take_changed() {
        let Ok(doc) = serde_json::to_string(&d) else { continue };
        tenants.entry(tenant_of(state, &d.entity_id)).or_default().push(DossierRow { agent_id: d.entity_id, doc, version });
    }
    let mut ok = true;
    for (tenant, rows) in tenants {
        if let Err(e) = insert(state, &tenant, &rows).await {
            tracing::warn!("{} intent dossier(s) of tenant {tenant} not stored (tried again in {}s): {e}", rows.len(), EVERY.as_secs());
            state.intent_engine.store_failed(rows.into_iter().map(|r| r.agent_id));
            ok = false;
        }
    }
    if ok {
        state.intent_engine.stored();
    }
    if let Some(x) = state.intent_engine.take_extras() {
        let doc = serde_json::to_string(&x).unwrap_or_default();
        let stored = async {
            let client = state.db.tenant_client(EXTRAS_TENANT);
            let mut ins = client.insert("siem_intent_extras")?;
            ins.write(&ExtrasRow { id: "extras".into(), doc, version }).await?;
            ins.end().await
        };
        if let Err(e) = stored.await {
            tracing::warn!("intent engine audit log and simulations not stored (tried again in {}s): {e}", EVERY.as_secs());
            state.intent_engine.extras_store_failed();
        }
    }
}

#[derive(clickhouse::Row, Serialize)]
struct ExtrasRow {
    id: String,
    doc: String,
    version: u64,
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

#[cfg(test)]
mod tests {
    /// With a private ClickHouse (`PV_BENCH_CLICKHOUSE`, see provigil_stream_bench.rs).
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn dossiers_survive_a_restart() {
        let state = crate::test_state::state().await;
        assert!(state.db.is_connected());
        state.intent_engine.sync_enrolled_fleet(&[("7001".into(), "pc-1".into(), "10.0.0.1".into(), None)]);
        super::flush(&state).await;
        let mut d = state.intent_engine.get_dossier("7001").unwrap();
        d.alerts_analyzed = 5;
        state.intent_engine.upsert_dossier(d);
        super::flush(&state).await;
        let fresh = siem_intent_engine::IntentEngine::new("no-such-file.json");
        assert!(fresh.get_dossier("7001").is_none());
        let mut after = state.clone();
        after.intent_engine = std::sync::Arc::new(fresh);
        super::load(&after).await;
        assert_eq!(after.intent_engine.get_dossier("7001").unwrap().alerts_analyzed, 5, "the newest row, one per agent");
    }
}
