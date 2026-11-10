//! A state for tests: nothing here talks to the services running on this PC (ClickHouse
//! unreachable unless `PV_BENCH_CLICKHOUSE` names a private one, manager off, a temp home).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::AppState;

fn home() -> PathBuf {
    std::env::temp_dir().join(format!("pv-test-state-{}", std::process::id()))
}

pub(crate) async fn state() -> AppState {
    std::env::set_var("CLICKHOUSE_URL", std::env::var("PV_BENCH_CLICKHOUSE").unwrap_or_else(|_| "http://127.0.0.1:1".into()));
    std::env::set_var("PROVIGIL_MANAGER", "0");
    std::env::set_var("PROVIGIL_MANAGER_HOME", home());
    state_with(crate::db::ClickHouseDb::init().await)
}

/// A state that leaves the process environment alone (tests run side by side).
pub(crate) fn state_with(db: crate::db::ClickHouseDb) -> AppState {
    let (broadcast_tx, _) = tokio::sync::broadcast::channel(16);
    let tmp = |n: &str| home().join(format!("{n}.json"));
    AppState {
        engine: siem_engine::AnalysisEngine::new(),
        events: Arc::new(RwLock::new(Vec::new())),
        alerts: Arc::new(RwLock::new(Vec::new())),
        agents: Arc::new(RwLock::new(HashMap::new())),
        broadcast_tx,
        pending_commands: Arc::new(RwLock::new(HashMap::new())),
        db,
        wdb: Arc::new(siem_wdb::ProVigilDbManager::new()),
        threat_intel: Arc::new(siem_cdb::ThreatIntelManager::new()),
        active_responses: Arc::new(RwLock::new(Vec::new())),
        parser_registry: Arc::new(siem_parser_gen::DynamicParserRegistry::new("")),
        parser_tenants: Arc::new(RwLock::new(HashMap::new())),
        auth_keystore: Arc::new(RwLock::new(siem_crypto::keys::KeyStore::new())),
        tenants: Arc::new(RwLock::new(Vec::new())),
        agent_keys: Arc::new(crate::tenancy::AgentKeys::new()),
        agent_tenants: Arc::new(RwLock::new(HashMap::new())),
        enrolled: Arc::new(RwLock::new(HashMap::new())),
        max_agent_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        deleted_agents: Arc::new(RwLock::new(std::collections::HashSet::new())),
        deleted_agent_names: Arc::new(RwLock::new(std::collections::HashSet::new())),
        risk_fabric: Arc::new(siem_risk_fabric::RiskFabricEngine::new("")),
        redswarm: Arc::new(siem_redswarm::RedSwarmService::new()),
        intent_engine: Arc::new(siem_intent_engine::IntentEngine::new(tmp("intent"))),
        deception_engine: Arc::new(siem_deception::DeceptionEngine::new(tmp("deception"))),
    }
}
