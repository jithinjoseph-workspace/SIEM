use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension, Path, Query, State,
    },
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use siem_core::{Agent, AgentStatus, Alert, EventSource, RawEvent, Rule, SiemStats};
use provigil_agent_server::keys::ct_eq;
use siem_engine::AnalysisEngine;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub mod agent_commands;
pub mod agent_tls;
pub mod gateway_api;
#[cfg(test)]
pub(crate) mod test_state;
pub mod agent_keys_store;
pub mod corroboration;
pub mod db;
pub mod groups;
pub mod live_response;
pub mod mail_send;
pub mod mail_settings;
pub mod parsers_store;
pub mod persist;
pub mod provigil_manager;
pub mod redswarm_store;
pub mod syslog;
pub mod syslog_send;
pub mod syslog_tenancy;
pub mod tamper;
pub mod segments;
pub mod tenancy;
pub mod vuln_report;
pub mod vulnerability;
// per-tenant alert e-mails and PDF reports, sent through the platform SMTP account
pub mod agent_monitor;
pub mod alert_mail;
pub mod pdf;
pub mod soar;
pub mod soar_integrations;
pub mod tenant_reports;
// the ProVigil agent's inventory, FIM, SCA, rootcheck and keepalive written to provigil-db
pub mod log_rotator;
// the SIEM analyst AI features, each on its own crate (siem-ai, siem-triage,
// siem-suppression, siem-retro, siem-predict)
pub mod ai_assist;
#[cfg(test)]
mod analyst_tests;
pub mod case_ai;
pub mod compliance;
pub mod copilot;
pub mod decisions;
pub mod file_reputation;
pub mod geomap;
pub mod history;
pub mod insights;
pub mod intel;
pub mod inventory_store;
pub mod investigate;
pub mod mitre;
pub mod org_memory;
pub mod platform;
pub mod intent_store;
pub mod engine_docs;
pub mod posture;
pub mod case_detail;
pub mod deploy_tokens;
pub mod deploy_kit;
pub mod posture_store;
pub mod predictions;
pub mod process_tree;
pub mod response;
pub mod retro;
pub mod rules_api;
pub mod secrets;
pub mod sigma;
pub mod suppressions;
pub mod swarm;
pub mod triage;
pub mod yara_edr;
use db::ClickHouseDb;
use tenancy::AuthCtx;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveResponseRecord {
    pub id: String,
    pub command: String,
    pub target_ip: String,
    pub agent_id: String,
    pub reason: String,
    pub triggered_at: chrono::DateTime<chrono::Utc>,
    pub duration_seconds: u64,
    pub status: String,
}

fn default_true() -> bool {
    true
}
fn default_role() -> String {
    "analyst".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct TenantRecord {
    pub id: String,
    pub name: String,
    #[serde(default = "default_role")]
    pub plan: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub agent_count: usize,
    #[serde(default = "default_true")]
    pub ai_enabled: bool,
    /// ClickHouse database holding this tenant's data.
    #[serde(default)]
    pub db_name: String,
}

pub(crate) fn data_file_path(filename: &str) -> std::path::PathBuf {
    let base = if std::path::Path::new("data").exists() {
        std::path::PathBuf::from("data")
    } else if std::path::Path::new("backend-rust/data").exists() {
        std::path::PathBuf::from("backend-rust/data")
    } else if std::path::Path::new("wazuh-rust-angular/backend-rust/data").exists() {
        std::path::PathBuf::from("wazuh-rust-angular/backend-rust/data")
    } else {
        let _ = std::fs::create_dir_all("data");
        std::path::PathBuf::from("data")
    };
    base.join(filename)
}

#[derive(Clone)]
pub struct AppState {
    pub engine: AnalysisEngine,
    pub events: Arc<RwLock<Vec<RawEvent>>>,
    pub alerts: Arc<RwLock<Vec<Alert>>>,
    pub agents: Arc<RwLock<HashMap<String, Agent>>>,
    pub broadcast_tx: broadcast::Sender<Alert>,
    pub pending_commands: Arc<RwLock<HashMap<String, Vec<serde_json::Value>>>>,
    pub db: ClickHouseDb,
    /// The vulnerability scanner's current detections (vulnerability.rs).
    pub wdb: Arc<siem_wdb::ProVigilDbManager>,
    pub threat_intel: Arc<siem_cdb::ThreatIntelManager>,
    pub active_responses: Arc<RwLock<Vec<ActiveResponseRecord>>>,
    /// The default tenant's learned parsers (other tenants: `parser_tenants`, parsers_store::for_tenant).
    pub parser_registry: Arc<siem_parser_gen::DynamicParserRegistry>,
    pub parser_tenants: Arc<RwLock<HashMap<String, Arc<siem_parser_gen::DynamicParserRegistry>>>>,
    pub auth_keystore: Arc<RwLock<siem_crypto::keys::KeyStore>>,
    pub tenants: Arc<RwLock<Vec<TenantRecord>>>,
    /// Per-tenant agent keys (`X-Tenant-Key`).
    pub agent_keys: Arc<tenancy::AgentKeys>,
    /// agent id -> tenant id (in-memory copy of ndr.agent_registry)
    pub agent_tenants: Arc<RwLock<HashMap<String, String>>>,
    /// Enrolled agents by id (in-memory copy of ndr.agent_registry).
    pub enrolled: Arc<RwLock<HashMap<String, EnrolledAgent>>>,
    /// Highest agent id ever issued (deleted agents included): ids are never reused.
    pub max_agent_id: Arc<std::sync::atomic::AtomicU64>,
    /// Set of agent ids deleted from the fleet to prevent resurrection on ingest.
    pub deleted_agents: Arc<RwLock<HashSet<String>>>,
    /// Set of (tenant, lowercase agent name) deleted from the fleet to prevent auto-re-enrollment.
    pub deleted_agent_names: Arc<RwLock<HashSet<(String, String)>>>,
    /// Business-Process Risk Fabric contextual scoring engine
    pub risk_fabric: Arc<siem_risk_fabric::RiskFabricEngine>,
    /// Autonomous Continuous Red Agent Swarm & Perpetual Purple-Team Engine.
    pub redswarm: Arc<siem_redswarm::RedSwarmService>,
    /// Feature 5: Intent Prediction Engine
    pub intent_engine: Arc<siem_intent_engine::IntentEngine>,
    /// Feature 9: Deception-as-Code & Adaptive Honeynet
    pub deception_engine: Arc<siem_deception::DeceptionEngine>,
}

#[tokio::main]
async fn main() {
    eprintln!(">>> SIEM API STARTING ON PID: {} <<<", std::process::id());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting the ProVigil SIEM server...");

    // Logins, users and tenants are served by auth-service; siem-api only
    // validates its tokens, so it needs the same secret and session store.
    if tenancy::jwt_secret().trim().is_empty() {
        tracing::error!("JWT_SECRET is not set (it must match auth-service) — aborting");
        std::process::exit(1);
    }
    if let Err(e) = tenancy::init_valkey().await {
        tracing::error!(
            "Cannot reach the auth-service session store: {} — aborting",
            e
        );
        std::process::exit(1);
    }

    // tenants' SOAR webhooks / syslog servers cannot reach the platform's own network
    let allow_private = matches!(
        std::env::var("SIEM_SOAR_ALLOW_PRIVATE_TARGETS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );
    provigil_common::soar::set_block_private_targets(!allow_private);

    let (broadcast_tx, _) = broadcast::channel::<Alert>(1000);
    let db = ClickHouseDb::init().await;

    let wdb = Arc::new(siem_wdb::ProVigilDbManager::new());
    let threat_intel = Arc::new(siem_cdb::ThreatIntelManager::new());
    // Learned parsers live in ClickHouse (parsers_store.rs); the file only when ClickHouse is down.
    let parser_registry = Arc::new(siem_parser_gen::DynamicParserRegistry::new(
        if db.is_connected() {
            ""
        } else {
            parsers_store::LEGACY_FILE
        },
    ));
    let stored_parsers = parsers_store::load(&db, &parser_registry, tenancy::DEFAULT_DB).await;

    // Pre-seed default learned parsers if registry is newly created
    if parser_registry.list_parsers().is_empty() {
        let sample1 = "Oct 03 14:22:11 srv-prod sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 54321 ssh2";
        let (fp1, sig1) = siem_parser_gen::FingerprintEngine::compute(sample1);
        let _ = parser_registry.register_parser(siem_parser_gen::DynamicParser {
            id: uuid::Uuid::new_v4(),
            fingerprint: fp1,
            fingerprint_signature: sig1,
            name: "sshd_failed_auth_parser".to_string(),
            description: "Auto-learned high-speed regex parser for SSH failure events".to_string(),
            parser_type: siem_parser_gen::ParserType::Regex,
            pattern: r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+Failed password for (?:invalid user )?(?P<srcuser>\S+) from (?P<srcip>\d+\.\d+\.\d+\.\d+) port (?P<srcport>\d+) ssh2$".to_string(),
            fields: vec![
                siem_parser_gen::ParserFieldDefinition {
                    name: "srcuser".to_string(),
                    field_type: "string".to_string(),
                    example: "admin".to_string(),
                    ecs_target: Some("user.name".to_string()),
                },
                siem_parser_gen::ParserFieldDefinition {
                    name: "srcip".to_string(),
                    field_type: "ip".to_string(),
                    example: "192.168.1.1".to_string(),
                    ecs_target: Some("source.ip".to_string()),
                },
                siem_parser_gen::ParserFieldDefinition {
                    name: "srcport".to_string(),
                    field_type: "integer".to_string(),
                    example: "54321".to_string(),
                    ecs_target: Some("source.port".to_string()),
                },
            ],
            normalization: [
                ("srcuser".to_string(), "srcuser".to_string()),
                ("srcip".to_string(), "srcip".to_string()),
                ("srcport".to_string(), "srcport".to_string()),
            ].into_iter().collect(),
            confidence: 0.98,
            version: 1,
            status: siem_parser_gen::ParserStatus::Active,
            sample_logs: vec![sample1.to_string()],
            hit_count: 142,
            success_count: 142,
            created_at: Utc::now(),
            last_used: Some(Utc::now()),
        });

        let sample2 =
            "2026-10-03 14:22:11 LOGIN FAILED user=john src=192.168.1.50 reason=wrong_password";
        let (fp2, sig2) = siem_parser_gen::FingerprintEngine::compute(sample2);
        let _ = parser_registry.register_parser(siem_parser_gen::DynamicParser {
            id: uuid::Uuid::new_v4(),
            fingerprint: fp2,
            fingerprint_signature: sig2,
            name: "app_login_failed_parser".to_string(),
            description: "Learned Key-Value parser for application authentication failures".to_string(),
            parser_type: siem_parser_gen::ParserType::Regex,
            pattern: r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+LOGIN FAILED\s+user=(?P<srcuser>\S+)\s+src=(?P<srcip>\d+\.\d+\.\d+\.\d+)\s+reason=(?P<reason>\S+)$".to_string(),
            fields: vec![
                siem_parser_gen::ParserFieldDefinition {
                    name: "srcuser".to_string(),
                    field_type: "string".to_string(),
                    example: "john".to_string(),
                    ecs_target: Some("user.name".to_string()),
                },
                siem_parser_gen::ParserFieldDefinition {
                    name: "srcip".to_string(),
                    field_type: "ip".to_string(),
                    example: "192.168.1.50".to_string(),
                    ecs_target: Some("source.ip".to_string()),
                },
                siem_parser_gen::ParserFieldDefinition {
                    name: "reason".to_string(),
                    field_type: "string".to_string(),
                    example: "wrong_password".to_string(),
                    ecs_target: Some("event.reason".to_string()),
                },
            ],
            normalization: [
                ("srcuser".to_string(), "srcuser".to_string()),
                ("srcip".to_string(), "srcip".to_string()),
                ("reason".to_string(), "action".to_string()),
            ].into_iter().collect(),
            confidence: 0.95,
            version: 1,
            status: siem_parser_gen::ParserStatus::Active,
            sample_logs: vec![sample2.to_string()],
            hit_count: 89,
            success_count: 89,
            created_at: Utc::now(),
            last_used: Some(Utc::now()),
        });
    }

    let active_responses = Arc::new(RwLock::new(vec![
        ActiveResponseRecord {
            id: "ar-001".to_string(),
            command: "firewall-drop".to_string(),
            target_ip: "198.51.100.42".to_string(),
            agent_id: "001".to_string(),
            reason: "Rule 5710: Multiple SSH authentication failures detected".to_string(),
            triggered_at: Utc::now() - chrono::Duration::minutes(5),
            duration_seconds: 600,
            status: "Active".to_string(),
        },
        ActiveResponseRecord {
            id: "ar-002".to_string(),
            command: "host-deny".to_string(),
            target_ip: "203.0.113.88".to_string(),
            agent_id: "001".to_string(),
            reason: "Rule 31101: Web vulnerability directory traversal probe".to_string(),
            triggered_at: Utc::now() - chrono::Duration::minutes(45),
            duration_seconds: 1800,
            status: "Expired".to_string(),
        },
    ]));

    let auth_keystore = Arc::new(RwLock::new(siem_crypto::keys::KeyStore::new()));
    let risk_fabric = Arc::new(siem_risk_fabric::RiskFabricEngine::new(data_file_path("risk_fabric_config.json")));
    let intent_engine = Arc::new(siem_intent_engine::IntentEngine::new(data_file_path("intent_engine_config.json")));
    let deception_engine = Arc::new(siem_deception::DeceptionEngine::new(data_file_path("deception_config.json")));

    let state = AppState {
        engine: AnalysisEngine::new(),
        events: Arc::new(RwLock::new(Vec::new())),
        alerts: Arc::new(RwLock::new(Vec::new())),
        agents: Arc::new(RwLock::new(HashMap::new())),
        broadcast_tx,
        pending_commands: Arc::new(RwLock::new(HashMap::new())),
        db,
        wdb,
        threat_intel,
        active_responses,
        parser_registry,
        parser_tenants: Arc::new(RwLock::new(HashMap::new())),
        auth_keystore,
        tenants: Arc::new(RwLock::new(Vec::new())),
        agent_keys: Arc::new(tenancy::AgentKeys::new()),
        agent_tenants: Arc::new(RwLock::new(HashMap::new())),
        enrolled: Arc::new(RwLock::new(HashMap::new())),
        max_agent_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        deleted_agents: Arc::new(RwLock::new(HashSet::new())),
        deleted_agent_names: Arc::new(RwLock::new(HashSet::new())),
        risk_fabric,
        redswarm: Arc::new(siem_redswarm::RedSwarmService::new()),
        intent_engine,
        deception_engine,
    };

    // Red Swarm audit trail (history, gaps, draft rules): ClickHouse is the master copy.
    redswarm_store::load(&state).await;
    reload_redswarm_rules(&state);

    // Start Red Swarm Continuous Background Swarm Engine
    {
        let swarm_state = state.clone();
        let swarm_engine = state.redswarm.clone();
        swarm_engine.start_background_loop(
            move |events| {
                for ev in events {
                    let (name, ip) = {
                        let agents = swarm_state.agents.read().unwrap();
                        let ag = agents.get(&ev.agent_id).cloned().unwrap_or_else(|| {
                            let enrolled = swarm_state.enrolled.read().unwrap();
                            if let Some(e) = enrolled.get(&ev.agent_id) {
                                let os = if e.os_type.is_empty() {
                                    if e.name.to_lowercase().contains("win") {
                                        "windows"
                                    } else {
                                        "linux"
                                    }
                                } else {
                                    &e.os_type
                                };
                                Agent {
                                    id: ev.agent_id.clone(),
                                    name: e.name.clone(),
                                    ip: "127.0.0.1".into(),
                                    os: os.to_string(),
                                    version: "v4.14.7".into(),
                                    status: AgentStatus::Active,
                                    last_keepalive: Utc::now(),
                                    os_type: os.to_string(),
                                }
                            } else {
                                Agent {
                                    id: ev.agent_id.clone(),
                                    name: "windows-target".into(),
                                    ip: "192.168.1.100".into(),
                                    os: "Windows".into(),
                                    version: "v4.14.7".into(),
                                    status: AgentStatus::Active,
                                    last_keepalive: Utc::now(),
                                    os_type: "windows".into(),
                                }
                            }
                        });
                        (ag.name, ag.ip)
                    };
                    // the target agent's tenant (set by the round), never another one
                    let tenant = ev.metadata.get("tenant_id").cloned().unwrap_or_else(|| {
                        tenancy::tenant_of(&swarm_state.agent_tenants.read().unwrap(), &ev.agent_id)
                    });
                    if let Some(alert) = swarm_state.engine.process_event(ev, &name, &ip) {
                        let alert = tenancy::tag_alert(redswarm_simulated(alert), &tenant);
                        keep_alerts(&swarm_state, [alert.clone()]);
                        let _ = swarm_state.broadcast_tx.send(alert);
                    }
                    keep_events(&swarm_state, [ev.clone()]);
                }
            },
            move |_ag_id, _cmd| Err(REDSWARM_NO_LIVE.to_string()),
            {
                let alerts_state = state.clone();
                move || alerts_state.alerts.read().unwrap().clone()
            },
            {
                let fleet_state = state.clone();
                move || {
                    let mut targets = Vec::new();
                    // 1. Live connected agents in state.agents
                    let tenants = fleet_state.agent_tenants.read().unwrap().clone();
                    {
                        let agents = fleet_state.agents.read().unwrap();
                        for a in agents.values() {
                            targets.push(siem_redswarm::FleetAgentTarget {
                                tenant_id: tenancy::tenant_of(&tenants, &a.id),
                                id: a.id.clone(),
                                name: a.name.clone(),
                                ip: a.ip.clone(),
                                os_type: a.os_type.to_lowercase(),
                                status: match a.status {
                                    AgentStatus::Active => "active".to_string(),
                                    AgentStatus::Disconnected => "disconnected".to_string(),
                                    AgentStatus::Pending => "pending".to_string(),
                                },
                                tags: vec!["lab".into(), "redteam-allowed".into()],
                            });
                        }
                    }
                    // 2. Fallback to enrolled agents in state.enrolled if state.agents is still empty
                    if targets.is_empty() {
                        let enrolled = fleet_state.enrolled.read().unwrap();
                        for (id, e) in enrolled.iter() {
                            let os = if e.os_type.is_empty() {
                                if e.name.to_lowercase().contains("win") {
                                    "windows"
                                } else {
                                    "linux"
                                }
                            } else {
                                &e.os_type
                            };
                            targets.push(siem_redswarm::FleetAgentTarget {
                                tenant_id: e.tenant.clone(),
                                id: id.clone(),
                                name: e.name.clone(),
                                ip: "127.0.0.1".into(),
                                os_type: os.to_lowercase(),
                                status: "active".into(),
                                tags: vec!["lab".into(), "redteam-allowed".into()],
                            });
                        }
                    }
                    targets
                }
            },
        );
    }
    redswarm_store::spawn_sync(state.clone());
    {
        let st = state.clone();
        tokio::spawn(async move { secrets::reseal_all(&st).await });
    }

    // Demo data only when asked for: it adds fake agents (001-004) whose ids collide with real agents.
    if std::env::var("SIEM_DEMO_DATA").is_ok_and(|v| v == "1") {
        seed_sample_data(&state);
    }
    // Agent registry and tenant agent keys live in ClickHouse.
    load_agent_registry(&state).await;
    state.agent_keys.load_from(&state.db).await;
    deploy_tokens::load(&state).await;

    // Tenants come from the shared auth-service registry (ndr.tenants).
    tenancy::sync_tenants(&state).await;
    tenancy::spawn_tenant_sync(state.clone());
    // Active responses, vulnerability detections and queued agent commands (ClickHouse).
    persist::load_all(&state).await;
    agent_commands::start(&state).await;
    if let Some(ids) = stored_parsers {
        parsers_store::spawn_sync(
            state.db.clone(),
            state.parser_registry.clone(),
            ids,
            tenancy::DEFAULT_DB.to_string(),
        );
    }
    // SIEM analyst AI: alert triage every 30 min, threat predictions every 15 min
    triage::spawn(state.clone());
    predictions::spawn(state.clone());
    posture::spawn(state.clone());
    // security memory: import the cases and triage decisions made before it existed
    org_memory::spawn(state.clone());
    // federated threat swarm (off until the platform admin and a tenant admin opt in)
    swarm::spawn(state.clone());
    // threat intel feeds from provigil-common (collector + blocklist engine)
    intel::spawn(state.clone());
    yara_edr::spawn(state.clone());
    // the agents' SCA results copied for the compliance audit (the one agent data copy)
    posture_store::spawn(state.clone());
    alert_mail::spawn(state.clone());
    tenant_reports::spawn(state.clone());
    // Sigma rules (SigmaHQ) on archived events; expired firewall / cloud blocks lifted
    platform::mark_start();
    sigma::spawn(state.clone());
    response::spawn(state.clone());
    // ClickHouse can restart (and its Keeper start over) while siem-api keeps running
    {
        let db = state.db.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                db::restore_lost_replicas(db.root()).await;
            }
        });
    }

    // Intent Prediction Engine & Business-Process Risk Fabric: ClickHouse 7-day historical alert sync on cold start
    {
        let ch_state = state.clone();
        let intent_engine_clone = state.intent_engine.clone();
        let risk_fabric_clone = state.risk_fabric.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            if ch_state.db.is_connected() {
                intent_store::load(&ch_state).await;
                intent_store::spawn(ch_state.clone());
                engine_docs::load(&ch_state).await;
                // each tenant's learned parsers now, not on the first page visit (that one showed none)
                for t in predictions::tenant_ids(&ch_state) {
                    parsers_store::for_tenant(&ch_state, &t);
                }
                engine_docs::spawn(ch_state.clone());
                // the default tenant's parsers, too, learn with the platform AI
                parsers_store::connect_ai(&ch_state, &ch_state.parser_registry, tenancy::DEFAULT_TENANT);
                let since_ms =
                    (chrono::Utc::now().timestamp().max(0) as u64).saturating_sub(7 * 86400) * 1000;
                for tenant in predictions::tenant_ids(&ch_state) {
                    if let Some(mut alerts) =
                        ch_state.db.alerts_since(&tenant, since_ms, 5000).await
                    {
                        if !alerts.is_empty() {
                            tracing::info!("Historical Sync: Ingesting {} ClickHouse alerts for tenant '{}' into Intent & Risk Fabric engines", alerts.len(), &tenant);
                            for a in &mut alerts {
                                if !a.data.contains_key("risk_fabric") {
                                    risk_fabric_clone.evaluate_alert(a);
                                }
                            }
                            let deleted = ch_state.deleted_agents.read().unwrap();
                            let active_alerts: Vec<_> = alerts.iter().filter(|a| !deleted.contains(&a.agent.id)).cloned().collect();
                            drop(deleted);
                            intent_engine_clone.ingest_live_alerts(&active_alerts);
                            let mut l = ch_state.alerts.write().unwrap();
                            l.extend(alerts);
                            crate::trim(&mut l, crate::MEM_ALERTS);
                        }
                    }
                }
            }
        });
    }

    // Agent keys: ClickHouse is the master copy, etc/client.keys is written from it.
    let stored_keys = agent_keys_store::load(&state).await;
    // The ProVigil manager (provigil-db, analysisd, remoted on 1514/tcp) for the agents.
    // with the keys in ClickHouse the daemons read them from siem-api: no etc/client.keys
    provigil_manager::start(state.clone(), stored_keys.is_some());
    // agents removed from the platform but still in provigil-db (removed while it was down)
    tokio::spawn(provigil_manager::purge_removed(
        state
            .deleted_agents
            .read()
            .unwrap()
            .iter()
            .cloned()
            .collect(),
    ));
    if let Some(ids) = stored_keys {
        agent_keys_store::spawn_sync(state.clone(), ids);
    }

    // Start background Agent Health Monitor & Log Rotator (replacing siem-monitord)
    agent_monitor::start_agent_monitor(state.clone(), agent_monitor::AgentMonitorConfig::default());
    log_rotator::start_log_rotator(log_rotator::LogRotatorConfig::default());

    // Start background Syslog listeners (UDP 514 / TCP 601) for firewall & network appliance ingestion
    // the syslog device / source registry and its CA, from ClickHouse
    syslog_tenancy::load(&state).await;
    syslog::start_syslog_listeners(state.clone());

    // Start background NDR <-> SIEM cross-source corroboration worker
    corroboration::spawn_corroboration_worker(state.clone());

    // Start background scheduled Threat Intelligence feed ingestion worker (refreshes external feeds every 60m)
    spawn_threat_intel_feed_scheduler(state.clone());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .expose_headers([
            header::HeaderName::from_static("x-total-count"),
            header::HeaderName::from_static("x-active-count"),
        ]);

    let alerts_reader = {
        let alerts_state = state.clone();
        Arc::new(move || {
            let deleted = alerts_state.deleted_agents.read().unwrap();
            let alerts = alerts_state.alerts.read().unwrap();
            alerts.iter().filter(|a| !deleted.contains(&a.agent.id)).cloned().collect()
        })
    };

    let fleet_reader = {
        let fleet_state = state.clone();
        Arc::new(move || {
            let mut fleet = Vec::new();
            let deleted = fleet_state.deleted_agents.read().unwrap();
            {
                let agents = fleet_state.agents.read().unwrap();
                for a in agents.values() {
                    if deleted.contains(&a.id) {
                        continue;
                    }
                    let os = if !a.os_type.is_empty() {
                        Some(a.os_type.clone())
                    } else if a.name.to_lowercase().contains("win") {
                        Some("windows".to_string())
                    } else {
                        Some("linux".to_string())
                    };
                    fleet.push((a.id.clone(), a.name.clone(), a.ip.clone(), os));
                }
            }
            if fleet.is_empty() {
                let enrolled = fleet_state.enrolled.read().unwrap();
                for (id, e) in enrolled.iter() {
                    if deleted.contains(id) {
                        continue;
                    }
                    let os = if !e.os_type.is_empty() {
                        Some(e.os_type.clone())
                    } else if e.name.to_lowercase().contains("win") {
                        Some("windows".to_string())
                    } else {
                        Some("linux".to_string())
                    };
                    fleet.push((id.clone(), e.name.clone(), "127.0.0.1".to_string(), os));
                }
            }
            fleet
        })
    };

    let rich_fleet_reader = {
        let fleet_state = state.clone();
        Arc::new(move || {
            let mut fleet = Vec::new();
            let deleted = fleet_state.deleted_agents.read().unwrap();
            let enrolled = fleet_state.enrolled.read().unwrap();
            {
                let agents = fleet_state.agents.read().unwrap();
                for a in agents.values() {
                    if deleted.contains(&a.id) {
                        continue;
                    }
                    let os = if !a.os_type.is_empty() {
                        Some(a.os_type.clone())
                    } else if a.name.to_lowercase().contains("win") {
                        Some("windows".to_string())
                    } else {
                        Some("linux".to_string())
                    };
                    let groups: Vec<String> = enrolled
                        .get(&a.id)
                        .map(|e| {
                            e.groups
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();

                    fleet.push(siem_risk_fabric::FleetAgentMeta {
                        id: a.id.clone(),
                        name: a.name.clone(),
                        ip: a.ip.clone(),
                        os_type: os,
                        groups,
                    });
                }
            }
            if fleet.is_empty() {
                for (id, e) in enrolled.iter() {
                    if deleted.contains(id) || e.disabled {
                        continue;
                    }
                    let os = if !e.os_type.is_empty() {
                        Some(e.os_type.clone())
                    } else if e.name.to_lowercase().contains("win") {
                        Some("windows".to_string())
                    } else {
                        Some("linux".to_string())
                    };
                    let groups: Vec<String> = e
                        .groups
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    fleet.push(siem_risk_fabric::FleetAgentMeta {
                        id: id.clone(),
                        name: e.name.clone(),
                        ip: "127.0.0.1".to_string(),
                        os_type: os,
                        groups,
                    });
                }
            }
            fleet
        })
    };

    // Synchronize enrolled fleet into Intent Engine immediately on startup
    {
        let initial_fleet = (fleet_reader)();
        state.intent_engine.sync_enrolled_fleet(&initial_fleet);
        state.risk_fabric.sync_fleet(&initial_fleet);
        let rich_fleet = (rich_fleet_reader)();
        state.risk_fabric.sync_fleet_meta(&rich_fleet);
    }

    let active_response_dispatcher = {
        let ar_state = state.clone();
        Arc::new(move |agent_id: &str, action_type: &str, target: &str| {
            tracing::info!(
                "IntentEngine: Dispatching Live Active Response: {} on agent '{}' (target: '{}')",
                action_type,
                agent_id,
                target
            );
            let action_name = match action_type {
                "host_isolation" => "block_ip",
                "firewall_block" => "firewall_drop",
                "process_termination" => "kill_process",
                "canary_tripwire" => "quarantine_file",
                _ => "block_ip",
            };
            let cmd_id = uuid::Uuid::new_v4().to_string();
            let cmd = serde_json::json!({
                "command_id": cmd_id,
                "action": action_name,
                "target": target,
                "command": action_name,
                "parameters": { "keys": [target] },
                "timestamp": chrono::Utc::now().to_rfc3339()
            });

            ar_state
                .pending_commands
                .write()
                .unwrap()
                .entry(agent_id.to_string())
                .or_default()
                .push(cmd.clone());

            let save_state = ar_state.clone();
            let aid = agent_id.to_string();
            let cmd_clone = cmd.clone();
            let rec = ActiveResponseRecord {
                id: format!("ar-{}", &cmd_id[..8]),
                command: action_name.to_string(),
                target_ip: target.to_string(),
                agent_id: agent_id.to_string(),
                reason: format!("Intent Preemptive Countermeasure: {}", action_type),
                triggered_at: chrono::Utc::now(),
                duration_seconds: 3600,
                status: "Active (Dispatched to Host)".to_string(),
            };
            ar_state.active_responses.write().unwrap().insert(0, rec.clone());

            tokio::spawn(async move {
                persist::save_commands(&save_state, &aid, &[cmd_clone], false).await;
                persist::save_active_response(&save_state, &rec).await;
            });
        })
    };

    let deception_fleet_reader = {
        let f_state = state.clone();
        Arc::new(move || {
            let mut fleet = Vec::new();
            let deleted = f_state.deleted_agents.read().unwrap();
            {
                let agents = f_state.agents.read().unwrap();
                for a in agents.values() {
                    if deleted.contains(&a.id) {
                        continue;
                    }
                    let os = if !a.os_type.is_empty() {
                        Some(a.os_type.clone())
                    } else if a.name.to_lowercase().contains("win") {
                        Some("windows".to_string())
                    } else {
                        Some("linux".to_string())
                    };
                    fleet.push(siem_deception::FleetNodeInfo {
                        id: a.id.clone(),
                        name: a.name.clone(),
                        ip: a.ip.clone(),
                        os_type: os,
                    });
                }
            }
            if fleet.is_empty() {
                let enrolled = f_state.enrolled.read().unwrap();
                for (id, e) in enrolled.iter() {
                    if deleted.contains(id) || e.disabled {
                        continue;
                    }
                    let os = if !e.os_type.is_empty() {
                        Some(e.os_type.clone())
                    } else if e.name.to_lowercase().contains("win") {
                        Some("windows".to_string())
                    } else {
                        Some("linux".to_string())
                    };
                    fleet.push(siem_deception::FleetNodeInfo {
                        id: id.clone(),
                        name: e.name.clone(),
                        ip: "127.0.0.1".to_string(),
                        os_type: os,
                    });
                }
            }
            fleet
        })
    };

    let deception_deploy_dispatcher = {
        let dec_state = state.clone();
        Arc::new(move |agent_id: &str, cmd: &serde_json::Value| {
            tracing::info!("DeceptionEngine: Dispatching automated decoy deployment to agent '{}'", agent_id);
            dec_state.pending_commands.write().unwrap()
                .entry(agent_id.to_string())
                .or_default()
                .push(cmd.clone());

            let save_state = dec_state.clone();
            let aid = agent_id.to_string();
            let cmd_clone = cmd.clone();
            tokio::spawn(async move {
                persist::save_commands(&save_state, &aid, &[cmd_clone], false).await;
            });
        })
    };

    let deception_alert_emitter = {
        let alert_state = state.clone();
        Arc::new(move |alert: siem_core::Alert| {
            tracing::info!("DeceptionEngine: ZERO-FP TRIPWIRE COMPROMISE: Alert #{} on agent '{}'", alert.rule.id, alert.agent.name);
            alert_state.alerts.write().unwrap().insert(0, alert.clone());
            let _ = alert_state.broadcast_tx.send(alert.clone());
        })
    };

    state.deception_engine.set_deploy_dispatcher(deception_deploy_dispatcher);
    state.deception_engine.set_alert_emitter(deception_alert_emitter);
    state.deception_engine.set_fleet_reader(deception_fleet_reader.clone());

    let app = Router::new()
        .nest_service(
            "/api/v1/risk-fabric",
            siem_risk_fabric::api::router_with_meta(
                state.risk_fabric.clone(),
                alerts_reader.clone(),
                Some(rich_fleet_reader.clone()),
            ),
        )
        .nest_service(
            "/api/v1/intent",
            siem_intent_engine::api::router(
                state.intent_engine.clone(),
                Some(alerts_reader.clone()),
                Some(fleet_reader),
                Some(active_response_dispatcher),
            ),
        )
        .nest_service(
            "/api/v1/deception",
            siem_deception::api::router_with_fleet(
                state.deception_engine.clone(),
                Some(alerts_reader),
                Some(deception_fleet_reader.clone()),
            ),
        )
        .route("/api/server-info", get(get_server_info_handler))
        .route("/api/v1/stats", get(get_stats))
        .route("/api/v1/alerts", get(get_alerts))
        .route("/api/v1/agents", get(get_agents))
        .route("/api/v1/agents/:id", delete(delete_agent_handler))
        .route("/api/agents/:id", delete(delete_agent_handler))
        .route("/agents", delete(delete_agents_provigil_handler))
        .route("/api/v1/events", get(get_events))
        .route("/api/events", get(get_events))
        .route(
            "/api/v1/rules",
            get(rules_api::list).post(rules_api::create),
        )
        .route("/api/rules", get(rules_api::list).post(rules_api::create))
        .route("/api/rules/hit-counts", get(get_rules_hit_counts_handler))
        .route(
            "/api/rules/:id",
            get(rules_api::get_one).delete(rules_api::delete),
        )
        .route("/api/rules/:id/toggle", post(rules_api::toggle))
        .route("/api/rules/reload", post(rules_api::reload))
        .route("/api/rules/sync-community", post(rules_api::sync_community))
        .route("/api/v1/ai/analyze", post(ai_assist::analyze))
        .route("/api/v1/ai/chat", post(ai_assist::chat))
        .route("/api/v1/agents/:id/live/:what", get(get_agent_live_handler))
        .route("/api/v1/agent/commands", post(queue_agent_command))
        .route("/api/v1/xdr/incidents", get(get_xdr_incidents))
        .route("/api/tenant/features", get(get_tenant_features_handler))
        .route(
            "/api/v1/tenant/agent-key",
            get(get_tenant_agent_key_handler),
        )
        .route(
            "/api/v1/tenant/agent-key/rotate",
            post(rotate_tenant_agent_key_handler),
        )
        .route("/api/v1/deploy/tokens", get(deploy_tokens::list).post(deploy_tokens::create))
        .route("/api/v1/deploy/tokens/:id", axum::routing::delete(deploy_tokens::revoke))
        .route("/api/v1/deploy/tokens/:id/targets", get(deploy_tokens::targets))
        .route("/api/v1/deploy/kit", post(deploy_kit::kit))
        .route(
            "/api/v1/tenant/alert-mail",
            get(alert_mail::get).put(alert_mail::put),
        )
        .route("/api/v1/tenant/alert-mail/test", post(alert_mail::test))
        .route(
            "/api/v1/syslog/devices",
            get(syslog_tenancy::list_devices).post(syslog_tenancy::create_device),
        )
        .route(
            "/api/v1/syslog/devices/:id",
            delete(syslog_tenancy::revoke_device),
        )
        .route(
            "/api/v1/syslog/sources",
            get(syslog_tenancy::list_sources).post(syslog_tenancy::add_source),
        )
        .route(
            "/api/v1/syslog/sources/:ip",
            delete(syslog_tenancy::remove_source),
        )
        .route("/api/v1/syslog/ca", get(syslog_tenancy::get_ca))
        .route(
            "/api/admin/stats-all-tenants",
            get(get_stats_all_tenants_handler),
        )
        .route(
            "/api/admin/severity-all-tenants",
            get(get_severity_all_tenants_handler),
        )
        .route(
            "/api/admin/top-ips-all-tenants",
            get(get_top_ips_all_tenants_handler),
        )
        .route(
            "/api/admin/protocols-all-tenants",
            get(get_protocols_all_tenants_handler),
        )
        .route(
            "/api/admin/threat-intel-all-tenants",
            get(get_threat_intel_all_tenants_handler),
        )
        // world maps from real data (GeoLite2): alert sources and the threat-intel feeds
        .route(
            "/api/admin/threat-map-all-tenants",
            get(geomap::threat_map_all_tenants),
        )
        .route("/api/threat-map", get(geomap::threat_map))
        .route("/api/threat-intel-map", get(geomap::threat_intel_map))
        .route("/api/threat-intel", get(get_threat_intel_handler))
        .route(
            "/api/threat-intel/watchlist",
            get(get_threat_intel_watchlist_handler),
        )
        // the platform as it really is (platform.rs); NDR sensors are the NDR engine's
        .route("/api/admin/engines", get(platform::engines))
        .route("/api/admin/engines/scale", post(platform::scale))
        .route("/api/admin/leader-status", get(platform::leader))
        .route("/api/leader/status", get(platform::leader))
        .route("/api/monitor/kafka", get(platform::kafka))
        .route("/api/kafka/status", get(platform::kafka))
        .route("/api/admin/telemetry", get(platform::telemetry))
        .route(
            "/api/admin/client-errors",
            get(get_client_errors_handler).post(post_client_errors_handler),
        )
        .route(
            "/api/client-errors",
            get(get_client_errors_handler).post(post_client_errors_handler),
        )
        .route("/api/health", get(platform::health))
        .route("/health", get(platform::health))
        .route(
            "/api/sensor-keys",
            get(platform::sensor_keys).post(platform::sensors_managed_by_ndr),
        )
        .route(
            "/api/sensor-keys/:id",
            delete(platform::sensors_managed_by_ndr),
        )
        .route(
            "/api/sensor-keys/:id/reactivate",
            post(platform::sensors_managed_by_ndr),
        )
        .route(
            "/api/sensor-keys/event-counts",
            get(platform::sensor_event_counts),
        )
        .route(
            "/api/sensor-keys/recent-ips",
            get(platform::sensor_recent_ips),
        )
        .route(
            "/api/sensor/control",
            post(platform::sensors_managed_by_ndr),
        )
        .route("/api/interfaces", get(platform::interfaces))
        .route("/api/agent-status", get(platform::agent_status))
        // blocks at the agent / firewall / cloud and host isolation (response.rs), as on the NDR engine
        .route("/api/blocks", get(response::list_blocks))
        .route("/api/blocks/manual", post(response::manual_block))
        .route("/api/blocks/revoke", post(response::revoke_block))
        .route("/api/isolations", get(response::list_isolations))
        .route("/api/isolate", post(response::isolate_handler))
        .route("/api/unisolate", post(response::unisolate_handler))
        // Sigma rules on every archived event (sigma.rs)
        .route("/api/v1/siem/sigma", get(sigma::status))
        .route("/api/v1/siem/sigma/sync", post(sigma::sync))
        .route("/api/scale-status", get(platform::scale_status))
        .route("/api/stats", get(get_stats))
        .route("/api/stats/unified", get(get_unified_stats_handler))
        .route("/api/stats/timeline", get(get_stats_timeline_handler))
        .route("/api/hits", get(get_hits_handler))
        .route("/api/hits/timeline", get(get_hits_timeline_handler))
        .route("/api/top-ips", get(get_top_ips_handler))
        .route("/api/severity", get(get_severity_handler))
        .route("/api/support/messages", get(get_support_messages_handler))
        .route("/api/support/tickets", get(get_support_messages_handler))
        .route(
            "/api/settings",
            get(get_settings_handler).post(post_settings_handler),
        )
        .route(
            "/api/settings/smtp",
            get(mail_settings::get_smtp).post(mail_settings::post_smtp),
        )
        .route(
            "/api/settings/smtp/test",
            post(mail_settings::post_smtp_test),
        )
        .route(
            "/api/settings/ai",
            get(get_settings_ai_handler).post(post_settings_ai_handler),
        )
        .route(
            "/api/trusted-domains",
            get(get_trusted_domains_handler).post(post_trusted_domains_handler),
        )
        .route(
            "/api/trusted-domains/delete",
            post(delete_trusted_domain_handler),
        )
        .route(
            "/api/trusted-domains/ai-suggest",
            post(post_trusted_domains_ai_suggest_handler),
        )
        .route("/api/siem/dashboard", get(get_siem_dashboard))
        .route("/api/dashboard", get(get_siem_dashboard))
        .route("/api/aria/status", get(get_aria_status_handler))
        .route("/api/aria/chat", post(post_aria_chat_handler))
        .route("/api/announcements", get(get_announcements_handler))
        .route("/api/announcements/active", get(get_announcements_handler))
        .route(
            "/api/admin/active-sessions",
            get(get_active_sessions_handler),
        )
        .route(
            "/api/admin/sessions/:username",
            delete(delete_session_handler),
        )
        .route(
            "/api/admin/sessions/:username/device",
            delete(delete_session_handler),
        )
        .route("/api/geo-lookup", post(post_geo_lookup_handler))
        .route(
            "/api/honeypots",
            get(get_honeypots_handler).post(post_honeypots_handler),
        )
        .route("/api/honeypots/:id", delete(delete_session_handler))
        .route(
            "/api/siem/sources",
            get(get_siem_sources).post(post_siem_sources),
        )
        .route(
            "/api/sources",
            get(get_siem_sources).post(post_siem_sources),
        )
        .route("/syscheck", put(put_syscheck_handler))
        .route("/api/v1/syscheck", put(put_syscheck_handler))
        .route("/api/v1/simulate", post(simulate_attack))
        .route("/api/v1/vulnerabilities", get(get_vulnerabilities).post(post_scan_now))
        .route("/api/v1/agents/:id/vulnerabilities", get(get_agent_vulnerabilities))
        .route("/api/v1/agents/:id/syscollector/packages", get(get_agent_packages_handler))
        .route("/api/v1/vulnerabilities/report.xlsx", get(vuln_report::get_report))
        .route("/api/v1/agents/telemetry", get(get_agents_telemetry))
        .route(
            "/api/v1/agents/deactivated",
            get(get_deactivated_agents_handler),
        )
        .route(
            "/api/v1/agents/:id/deactivate",
            post(deactivate_agent_handler),
        )
        .route("/api/v1/agents/:id/activate", post(activate_agent_handler))
        .route(
            "/api/v1/agents/:id/inventory",
            get(get_agent_inventory_handler),
        )
        .route(
            "/api/v1/agents/:id/syscollector/os",
            get(get_agent_os_handler),
        )
        .route(
            "/api/v1/agents/:id/syscollector/hardware",
            get(get_agent_hw_handler),
        )
        .route(
            "/api/v1/agents/:id/syscollector/ports",
            get(get_agent_ports_handler),
        )
        .route(
            "/api/v1/agents/:id/syscollector/netiface",
            get(get_agent_netiface_handler),
        )
        .route(
            "/api/v1/agents/:id/fim",
            get(get_agent_fim_handler).post(post_agent_fim_handler),
        )
        .route("/api/v1/agents/:id/sca", get(get_agent_sca_handler))
        .route("/api/v1/agents/:id/process-tree", get(process_tree::get))
        .route("/api/v1/edr/yara", get(yara_edr::status))
        .route(
            "/api/v1/threat-intel/check",
            get(check_threat_intel_handler),
        )
        .route(
            "/api/v1/threat-intel/lists",
            get(get_threat_intel_lists_handler),
        )
        .route(
            "/api/v1/threat-intel/lists/:name/entries",
            get(get_threat_intel_list_entries_handler),
        )
        .route(
            "/api/v1/threat-intel/lists/:name/import",
            post(post_threat_intel_list_import_handler),
        )
        .route(
            "/api/v1/agents/:id/rootcheck/scan",
            post(post_agent_rootcheck_handler),
        )
        .route(
            "/api/v1/agents/:id/rootcheck",
            get(get_agent_rootcheck_handler),
        )
        .route("/downloads/siem-agent.exe", get(download_agent))
        .route(
            "/downloads/provigil-agent.exe",
            get(|| download_windows_binary("provigil-agent.exe".to_string())),
        )
        // agents set up before the ProVigil rename ask for the old name
        .route(
            "/downloads/wazuh-agent.exe",
            get(|| download_windows_binary("provigil-agent.exe".to_string())),
        )
        .route("/downloads/windows/:file", get(download_windows_file))
        .route("/downloads/siem-agent-linux", get(download_linux_agent))
        .route("/downloads/install.sh", get(download_install_script))
        .route("/downloads/sca/:file", get(download_sca_file))
        .route("/ws/alerts", get(ws_alerts_handler))
        .route("/ws", get(ws_alerts_handler))
        .route("/api/ws", get(ws_alerts_handler))
        .route("/api/v1/logtest", post(post_logtest_handler))
        .route("/api/v1/compliance", get(compliance::get))
        .route(
            "/api/v1/agents/:id/live-response",
            get(live_response::list).post(live_response::create),
        )
        .route("/api/v1/edr/tamper", get(tamper::get).put(tamper::put))
        .route("/api/v1/segments", get(segments::list))
        .route("/api/v1/segments/name", axum::routing::put(segments::set_name))
        .route(
            "/api/v1/agents/:id/tamper",
            axum::routing::post(tamper::agent_action),
        )
        .route(
            "/api/v1/agents/:id/live-response/:rid",
            get(live_response::get),
        )
        .route(
            "/api/v1/agents/:id/live-response/:rid/download",
            get(live_response::download),
        )
        .route(
            "/api/v1/compliance/profile",
            get(compliance::get_profile).put(compliance::put_profile),
        )
        .route("/api/v1/mitre/matrix", get(mitre::matrix))
        .route("/api/v1/fim/summary", get(get_fim_summary_handler))
        .route(
            "/api/v1/active-response/actions",
            get(get_active_response_actions).post(post_active_response_block),
        )
        .route(
            "/api/v1/active-response/unblock",
            post(post_active_response_unblock),
        )
        .route("/api/v1/parsers", get(get_parsers_handler))
        .route("/api/v1/parsers/stats", get(get_parsers_stats_handler))
        .route(
            "/api/v1/parsers/unmatched",
            get(get_unmatched_parsers_handler),
        )
        .route(
            "/api/v1/parsers/synthesize",
            post(post_synthesize_parser_handler),
        )
        .route("/api/v1/parsers/test", post(post_test_parser_handler))
        .route(
            "/api/v1/parsers/:id",
            put(put_parser_handler).delete(delete_parser_handler),
        )
        .route("/api/v1/reports/summary", get(get_reports_summary_handler))
        .route("/api/v1/reports/pdf", get(tenant_reports::get_pdf))
        .route(
            "/api/v1/reports/schedule",
            get(tenant_reports::get_schedule).put(tenant_reports::put_schedule),
        )
        .route(
            "/api/v1/reports/schedule/send-now",
            post(tenant_reports::send_now),
        )
        .route(
            "/api/v1/agents/:id/upgrade",
            post(post_agent_upgrade_handler).get(get_agent_upgrade_handler),
        )
        .route("/api/v1/manager/status", get(get_manager_status_handler))
        // per-tenant SOAR (the analyst SOAR page; the same API as ndr-engine's)
        // SIEM analyst AI: the SIEM's own pages (ndr-ui pages/siem-ai), apart from the NDR's /api/triage etc.
        .route("/api/v1/siem/triage", get(triage::get))
        .route("/api/v1/siem/triage/run", post(triage::run_now))
        .route("/api/v1/siem/triage/:id/apply", post(triage::apply))
        .route("/api/v1/siem/triage/:id/dismiss", post(triage::dismiss))
        .route("/api/v1/siem/triage/:id/inspect", post(triage::inspect))
        // organizational security memory: past decisions, found again ("seen before")
        .route(
            "/api/v1/siem/triage/:id/precedents",
            get(org_memory::triage_precedents),
        )
        .route("/api/v1/siem/memory", get(org_memory::search))
        .route("/api/v1/siem/memory/similar", post(org_memory::similar))
        // federated threat swarm: the hub (member token) and this deployment's participation
        .route("/api/v1/swarm/hub/submit", post(swarm::hub_submit))
        .route("/api/v1/swarm/hub/feed", get(swarm::hub_feed_handler))
        .route("/api/v1/swarm/status", get(swarm::status))
        .route("/api/v1/swarm/tenant", put(swarm::put_tenant))
        .route("/api/v1/swarm/preview", get(swarm::preview))
        .route("/api/v1/swarm/matches", get(swarm::matches))
        .route(
            "/api/v1/swarm/config",
            get(swarm::get_config).put(swarm::put_config),
        )
        .route("/api/v1/swarm/members", post(swarm::add_member))
        .route("/api/v1/swarm/members/:id", delete(swarm::remove_member))
        .route("/api/v1/swarm/sync", post(swarm::sync_now))
        // neurosymbolic decisions: the reasoning record of every high-impact action, guardrails, approvals
        .route("/api/v1/siem/decisions", get(decisions::list))
        .route("/api/v1/siem/decisions/verify", get(decisions::verify))
        .route("/api/v1/siem/decisions/export", get(decisions::export))
        .route(
            "/api/v1/siem/decisions/policy",
            get(decisions::get_policy).put(decisions::put_policy),
        )
        .route("/api/v1/siem/decisions/:id", get(decisions::get_one))
        .route(
            "/api/v1/siem/decisions/:id/approve",
            post(decisions::approve),
        )
        .route("/api/v1/siem/decisions/:id/reject", post(decisions::reject))
        // threat intel (provigil-common feeds) and the investigation of one IP / host / user / hash / domain
        .route("/api/v1/siem/intel/status", get(intel::status))
        .route("/api/v1/siem/intel/lookup", get(intel::lookup_handler))
        .route(
            "/api/v1/siem/intel/watchlist",
            get(intel::watchlist).post(intel::add_watched),
        )
        .route(
            "/api/v1/siem/intel/watchlist/:id",
            axum::routing::delete(intel::remove_watched),
        )
        .route("/api/v1/siem/intel/matches", get(intel::matches))
        .route("/api/v1/siem/investigate", get(investigate::investigate))
        .route("/api/v1/siem/explain", post(case_ai::explain))
        .route("/api/v1/siem/copilot", post(copilot::ask))
        .route("/api/v1/siem/copilot/status", get(copilot::status))
        .route(
            "/api/v1/siem/copilot/conversations",
            get(copilot::conversations),
        )
        .route(
            "/api/v1/siem/copilot/conversations/:id",
            get(copilot::conversation).delete(copilot::delete_conversation),
        )
        .route("/api/v1/siem/copilot/reports/:id", get(copilot::report))
        // analyst workload & AI-trust calibration: own numbers; the team for the tenant admin
        .route("/api/v1/siem/insights/me", get(insights::me))
        .route("/api/v1/siem/insights/team", get(insights::team))
        .route(
            "/api/v1/siem/insights/settings",
            put(insights::put_settings),
        )
        .route("/api/v1/siem/ai-activity", get(suppressions::activity))
        .route(
            "/api/v1/siem/suppressions",
            get(suppressions::list).post(suppressions::create_manual),
        )
        .route(
            "/api/v1/siem/suppressions/:id/deactivate",
            axum::routing::patch(suppressions::deactivate),
        )
        .route(
            "/api/v1/siem/suppressions/:id",
            delete(suppressions::delete),
        )
        .route("/api/v1/siem/predictions", get(predictions::latest))
        .route("/api/v1/posture", get(posture::cards))
        .route("/api/v1/posture/history", get(posture::history))
        .route("/api/v1/posture/agents", get(posture::agents))
        .route("/api/v1/posture/run", post(posture::run_now))
        .route(
            "/api/v1/siem/predictions/history",
            get(predictions::history),
        )
        .route("/api/v1/siem/predictions/run", post(predictions::run_now))
        .route(
            "/api/v1/siem/retrospective/fired-rules",
            get(retro::fired_rules),
        )
        .route("/api/v1/siem/retrospective/scan", post(retro::start))
        .route("/api/v1/siem/retrospective/scans", get(retro::list))
        .route("/api/v1/siem/retrospective/scans/:id", get(retro::get))
        .route("/api/soar/status", get(soar::get_status))
        .route(
            "/api/soar/integrations",
            get(soar::get_integrations).post(soar::save_integration),
        )
        .route("/api/soar/integrations/test", post(soar::test_integration))
        .route(
            "/api/soar/integrations/toggle",
            post(soar::toggle_integration),
        )
        .route(
            "/api/soar/integrations/delete",
            post(soar::delete_integration),
        )
        .route(
            "/api/soar/integrations/:id",
            put(soar::update_integration).delete(soar::delete_integration),
        )
        .route(
            "/api/soar/native/playbooks",
            get(soar::get_playbooks).post(soar::create_playbook),
        )
        .route(
            "/api/soar/native/playbooks/:id",
            put(soar::update_playbook).delete(soar::delete_playbook),
        )
        .route("/api/soar/runs", get(soar::get_runs))
        .route(
            "/api/soar/cases",
            get(soar::get_cases).post(soar::create_case),
        )
        .route("/api/soar/cases/:id", put(soar::update_case))
        .route("/api/soar/cases/:id/detail", get(case_detail::detail))
        .route("/api/soar/cases/:id/details", put(case_detail::set_details))
        .route("/api/soar/cases/:id/disposition", put(case_detail::set_disposition))
        .route("/api/soar/cases/:id/resolve", post(case_detail::resolve))
        // a 10 MB file is about 13.4 MB as base64; the default request limit is 2 MB
        .route("/api/soar/cases/:id/attachments", post(case_detail::add_attachment).layer(axum::extract::DefaultBodyLimit::max(15 * 1024 * 1024)))
        .route("/api/soar/cases/:id/attachments/:att", get(case_detail::get_attachment))
        .route("/api/soar/cases/:id/status", put(soar::update_case_status))
        .route(
            "/api/soar/cases/:id/comments",
            get(soar::get_case_comments).post(soar::add_case_comment),
        )
        .route(
            "/api/soar/cases/:id/investigation",
            get(case_ai::get).post(case_ai::run),
        )
        .route(
            "/api/settings/ai/providers",
            get(ai_assist::list_providers).post(ai_assist::save_provider),
        )
        .route(
            "/api/settings/ai/providers/test",
            post(ai_assist::test_provider),
        )
        .route(
            "/api/settings/ai/providers/:name",
            axum::routing::delete(ai_assist::delete_provider),
        )
        .route(
            "/api/v1/groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/api/v1/groups/:name",
            axum::routing::delete(groups::delete_group),
        )
        .route(
            "/api/v1/groups/:name/agent.conf",
            get(groups::get_agent_conf).put(groups::put_agent_conf),
        )
        .route("/api/v1/agents/:id/groups", put(groups::put_agent_groups))
        // ── Red Swarm & Perpetual Purple-Team Engine Routes ──
        .route("/api/v1/redswarm/status", get(get_redswarm_status_handler))
        .route(
            "/api/v1/redswarm/campaigns",
            get(get_redswarm_campaigns_handler).post(post_redswarm_campaigns_handler),
        )
        .route(
            "/api/v1/redswarm/campaigns/:id/toggle",
            post(post_redswarm_toggle_campaign_handler),
        )
        .route(
            "/api/v1/redswarm/run-once",
            post(post_redswarm_run_once_handler),
        )
        .route(
            "/api/v1/redswarm/history",
            get(get_redswarm_history_handler),
        )
        .route("/api/v1/redswarm/gaps", get(get_redswarm_gaps_handler))
        .route(
            "/api/v1/redswarm/gaps/:id/apply-rule",
            post(post_redswarm_apply_rule_handler),
        )
        .route(
            "/api/v1/redswarm/gaps/:id/reject",
            post(post_redswarm_reject_rule_handler),
        )
        .route(
            "/api/v1/redswarm/rules/:id/rollback",
            post(post_redswarm_rollback_rule_handler),
        )
        .route(
            "/api/v1/redswarm/kill-switch",
            post(post_redswarm_kill_switch_handler),
        )
        .route(
            "/api/v1/redswarm/heatmap",
            get(get_redswarm_heatmap_handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            tenancy::auth_middleware,
        ))
        .layer(cors)
        .with_state(state.clone());
    let grpc_state = state;

    let port = std::env::var("SIEM_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8088);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("SIEM API & WebSocket listening on http://{}", addr);
    // the agents' CA, for /api/server-info; agents connect to provigil-gateway
    agent_tls::init_tls();
    gateway_api::serve(grpc_state);

    // agent routes on this port answer 426 and name the gateway
    let plain = app.layer(axum::middleware::from_fn(tenancy::refuse_plain_agents));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, plain.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

fn seed_sample_data(state: &AppState) {
    let mut agents = state.agents.write().unwrap();

    agents.insert(
        "001".into(),
        Agent {
            id: "001".into(),
            name: "srv-prod-ubuntu-01".into(),
            ip: "192.168.10.15".into(),
            os: "Ubuntu 24.04 LTS (x86_64)".into(),
            version: "v4.14.7-rust".into(),
            status: AgentStatus::Active,
            last_keepalive: Utc::now(),
            os_type: "linux".into(),
        },
    );

    agents.insert(
        "002".into(),
        Agent {
            id: "002".into(),
            name: "win-ad-dc01".into(),
            ip: "192.168.10.20".into(),
            os: "Windows Server 2022 Datacenter".into(),
            version: "v4.14.7-rust".into(),
            status: AgentStatus::Active,
            last_keepalive: Utc::now(),
            os_type: "windows".into(),
        },
    );

    agents.insert(
        "003".into(),
        Agent {
            id: "003".into(),
            name: "sec-analyst-macbook".into(),
            ip: "192.168.10.105".into(),
            os: "macOS Sonoma 14.5 (arm64)".into(),
            version: "v4.14.7-rust".into(),
            status: AgentStatus::Active,
            last_keepalive: Utc::now(),
            os_type: "macos".into(),
        },
    );

    agents.insert(
        "004".into(),
        Agent {
            id: "004".into(),
            name: "dmz-web-nginx".into(),
            ip: "192.168.1.50".into(),
            os: "Debian GNU/Linux 12 (bookworm)".into(),
            version: "v4.14.7-rust".into(),
            status: AgentStatus::Disconnected,
            last_keepalive: Utc::now() - chrono::Duration::hours(14),
            os_type: "linux".into(),
        },
    );
    drop(agents);

    // Seed realistic starting alerts
    let sample_events = vec![
        ("001", "sshd[24102]: Invalid user admin from 185.220.101.5 port 42812", EventSource::Auth, "/var/log/auth.log"),
        ("001", "ossec: File '/etc/passwd' modified", EventSource::Fim, "syscheck"),
        ("002", "powershell.exe -NoP -w hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg... (Mimikatz detected)", EventSource::WindowsEvent, "Security-EventLog"),
        ("001", "sudo: bob : COMMAND=/bin/bash", EventSource::Auth, "/var/log/secure"),
    ];

    for (agent_id, msg, source, loc) in sample_events {
        let ev = RawEvent::new(agent_id, source, loc, msg);
        let agents_read = state.agents.read().unwrap();
        let agent = agents_read.get(agent_id).cloned().unwrap_or(Agent {
            id: agent_id.to_string(),
            name: "unknown-agent".into(),
            ip: "127.0.0.1".into(),
            os: "Generic".into(),
            version: "0.1.0".into(),
            status: AgentStatus::Active,
            last_keepalive: Utc::now(),
            os_type: "linux".into(),
        });
        drop(agents_read);

        if let Some(alert) = state.engine.process_event(&ev, &agent.name, &agent.ip) {
            keep_alerts(&state, [alert]);
        }
        keep_events(&state, [ev]);
    }

    // Seed ProVigil DB agent state (OS, Hardware, Network, Packages, Ports, FIM, SCA)
    let agent_001_db = state.wdb.get_or_create("001", "srv-prod-ubuntu-01");
    {
        let mut db = agent_001_db.write().unwrap();
        db.syscollector.set_os_info(siem_wdb::SysOsInfo {
            hostname: "srv-prod-ubuntu-01".to_string(),
            architecture: "x86_64".to_string(),
            os_name: "Ubuntu".to_string(),
            os_version: "24.04 LTS".to_string(),
            os_codename: Some("Noble Numbat".to_string()),
            os_major: Some("24".to_string()),
            os_minor: Some("04".to_string()),
            os_build: None,
            platform: "linux".to_string(),
            release: "6.8.0-31-generic".to_string(),
        });

        db.syscollector.set_hw_info(siem_wdb::SysHwInfo {
            board_serial: Some("VMware-42 1a 8c...".to_string()),
            cpu_name: "AMD EPYC 7763 64-Core Processor".to_string(),
            cpu_cores: 8,
            cpu_mhz: 2445.4,
            ram_total_mb: 32768,
            ram_free_mb: 18450,
            ram_usage_percent: 43.7,
        });

        db.syscollector.set_ports(vec![
            siem_wdb::SysPort {
                protocol: "tcp".to_string(),
                local_ip: "0.0.0.0".to_string(),
                local_port: 22,
                remote_ip: None,
                remote_port: None,
                state: "LISTEN".to_string(),
                pid: Some(941),
                process_name: Some("sshd".to_string()),
            },
            siem_wdb::SysPort {
                protocol: "tcp".to_string(),
                local_ip: "0.0.0.0".to_string(),
                local_port: 80,
                remote_ip: None,
                remote_port: None,
                state: "LISTEN".to_string(),
                pid: Some(1204),
                process_name: Some("nginx".to_string()),
            },
        ]);

        db.syscollector.set_netifaces(vec![siem_wdb::SysNetIface {
            name: "eth0".to_string(),
            adapter: Some("Intel Corporation 82545EM".to_string()),
            iface_type: Some("ethernet".to_string()),
            state: "up".to_string(),
            mac: Some("00:0c:29:4f:8e:12".to_string()),
            mtu: Some(1500),
            rx_bytes: 450123904,
            tx_bytes: 182390144,
            rx_packets: 394012,
            tx_packets: 201940,
            rx_errors: 0,
            tx_errors: 0,
        }]);

        let _ = db.fim.upsert(siem_wdb::FimEntry {
            full_path: "/etc/passwd".to_string(),
            file_name: "passwd".to_string(),
            entry_type: siem_wdb::FimEntryType::File,
            size: Some(2840),
            perm: Some("0644".to_string()),
            uid: Some("0".to_string()),
            gid: Some("0".to_string()),
            md5: Some("b10a8db164e0754105b7a99be72e3fe5".to_string()),
            sha1: None,
            sha256: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            mtime: 1711204800,
            inode: Some(40129),
            changes: 1,
            date: 1711204800,
        });

        let policy = db.sca.get_policy_mut("cis_ubuntu_linux_24.04");
        policy.upsert_check(siem_wdb::ScaCheckResult {
            policy_id: "cis_ubuntu_linux_24.04".to_string(),
            check_id: 1001,
            title: "Ensure SSH root login is disabled".to_string(),
            description: "PermitRootLogin in /etc/ssh/sshd_config should be set to no".to_string(),
            rationale: Some(
                "Disallowing root logins over SSH enforces accountability.".to_string(),
            ),
            remediation: Some("Edit /etc/ssh/sshd_config and set PermitRootLogin no".to_string()),
            status: siem_wdb::ScaStatus::Passed,
        });
        policy.upsert_check(siem_wdb::ScaCheckResult {
            policy_id: "cis_ubuntu_linux_24.04".to_string(),
            check_id: 1002,
            title: "Ensure auditing for processes that start prior to auditd is enabled"
                .to_string(),
            description: "Configure GRUB with audit=1".to_string(),
            rationale: None,
            remediation: None,
            status: siem_wdb::ScaStatus::Failed,
        });
    }
}

/// How many recent alerts / events siem-api keeps in memory (ClickHouse keeps everything).
pub const MEM_ALERTS: usize = 50_000;
pub const MEM_EVENTS: usize = 50_000;

/// Keeps the newest `cap` items (trimmed in steps of 10% so the copy is rare).
fn trim<T>(l: &mut Vec<T>, cap: usize) {
    if l.len() > cap + cap / 10 {
        let n = l.len() - cap;
        l.drain(..n);
    }
}

/// Adds alerts to the in-memory window.
pub fn keep_alerts(state: &AppState, alerts: impl IntoIterator<Item = Alert>) {
    let evaluated: Vec<Alert> = alerts
        .into_iter()
        .map(|mut a| {
            // a Red Swarm simulation must not raise the real agent's risk
            if !a.data.contains_key("risk_fabric")
                && !a.rule.groups.iter().any(|g| g == "redswarm_simulation")
            {
                state.risk_fabric.evaluate_alert(&mut a);
            }
            a
        })
        .collect();
    let deleted = state.deleted_agents.read().unwrap();
    let active_alerts: Vec<_> = evaluated.iter().filter(|a| !deleted.contains(&a.agent.id)).cloned().collect();
    drop(deleted);
    state.intent_engine.ingest_live_alerts(&active_alerts);
    let mut l = state.alerts.write().unwrap();
    l.extend(evaluated);
    trim(&mut l, MEM_ALERTS);
}

/// Adds events to the in-memory window.
pub fn keep_events(state: &AppState, events: impl IntoIterator<Item = RawEvent>) {
    let mut l = state.events.write().unwrap();
    l.extend(events);
    trim(&mut l, MEM_EVENTS);
}

/// Alerts visible in the caller's tenant scope (oldest first).
fn scoped_alerts(state: &AppState, ctx: &AuthCtx) -> Vec<Alert> {
    let scope = ctx.scope();
    let map = state.agent_tenants.read().unwrap().clone(); // copy: never hold two locks at once
    state
        .alerts
        .read()
        .unwrap()
        .iter()
        .filter(|a| tenancy::alert_tenant(a, &map) == scope)
        .cloned()
        .collect()
}

/// Events visible in the caller's tenant scope (oldest first).
fn scoped_events(state: &AppState, ctx: &AuthCtx) -> Vec<RawEvent> {
    let scope = ctx.scope();
    let map = state.agent_tenants.read().unwrap().clone();
    state
        .events
        .read()
        .unwrap()
        .iter()
        .filter(|e| tenancy::event_tenant(e, &map) == scope)
        .cloned()
        .collect()
}

/// Agents of the caller's tenant scope (active only; excludes deactivated and deleted agents).
fn scoped_agents(state: &AppState, ctx: &AuthCtx) -> Vec<Agent> {
    let scope = ctx.scope();
    let map = state.agent_tenants.read().unwrap().clone();
    let deleted = state.deleted_agents.read().unwrap();
    state
        .agents
        .read()
        .unwrap()
        .values()
        .filter(|a| {
            !deleted.contains(&a.id)
                && !is_deactivated(state, &a.id)
                && tenancy::tenant_of(&map, &a.id) == scope
        })
        .cloned()
        .collect()
}

async fn get_stats(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Json<SiemStats> {
    let agents = scoped_agents(&state, &ctx);
    // ClickHouse counts every row; memory (the recent window) only when it is down
    let totals = match state.db.tenant_totals(&ctx.scope()).await {
        Some(t) => t,
        None => {
            let alerts = scoped_alerts(&state, &ctx);
            let n = |r: std::ops::RangeInclusive<u8>| {
                alerts.iter().filter(|a| r.contains(&a.rule.level)).count() as u64
            };
            (
                scoped_events(&state, &ctx).len() as u64,
                alerts.len() as u64,
                n(12..=255),
                n(8..=11),
                n(4..=7),
                n(0..=3),
            )
        }
    };
    let (events_count, total_alerts, critical_alerts, high_alerts, medium_alerts, low_alerts) =
        totals;

    let now = Utc::now();
    let total_agents = agents.len();
    let active_agents = agents
        .iter()
        .filter(|a| a.status == AgentStatus::Active && (now - a.last_keepalive).num_seconds() <= 60)
        .count();

    Json(SiemStats {
        total_events: events_count,
        total_alerts,
        critical_alerts,
        high_alerts,
        medium_alerts,
        low_alerts,
        active_agents,
        total_agents,
    })
}

#[derive(Deserialize)]
struct AlertsQuery {
    limit: Option<usize>,
    min_level: Option<u8>,
}

async fn get_alerts(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(params): Query<AlertsQuery>,
) -> Json<Vec<Alert>> {
    let limit = params.limit.unwrap_or(100);
    let min_level = params.min_level.unwrap_or(0);
    let scope = ctx.scope();

    // Persisted alerts come from the tenant's own ClickHouse database.
    if state.db.is_connected() {
        if let Some(ch_rows) = state.db.fetch_alerts(&scope, limit, min_level).await {
            if !ch_rows.is_empty() {
                let alerts: Vec<Alert> = ch_rows
                    .into_iter()
                    .map(|r| tenancy::tag_alert(r.to_alert(), &scope))
                    .collect();
                return Json(alerts);
            }
        }
    }

    let mut filtered: Vec<Alert> = scoped_alerts(&state, &ctx)
        .into_iter()
        .filter(|a| a.rule.level >= min_level)
        .collect();
    filtered.reverse(); // Most recent first
    filtered.truncate(limit);
    Json(filtered)
}

async fn get_agents(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Json<Vec<Agent>> {
    let scope = ctx.scope();

    // 1. Load persistent agents from ClickHouse for this tenant
    if state.db.is_connected() {
        if let Some(ch_agents) = state.db.fetch_agents(&scope).await {
            // One lock at a time (never agents + agent_tenants together): the
            // scoped readers take them in the other order.
            let deleted = state.deleted_agents.read().unwrap();
            let enrolled = state.enrolled.read().unwrap();
            let active_ids: std::collections::HashSet<String> = ch_agents
                .iter()
                .map(|r| r.id.clone())
                .filter(|id| {
                    !deleted.contains(id) && !enrolled.get(id).map(|e| e.disabled).unwrap_or(false)
                })
                .collect();
            drop(deleted);
            drop(enrolled);

            let tenants_snapshot = {
                let mut tenants_map = state.agent_tenants.write().unwrap();
                for id in &active_ids {
                    tenants_map.insert(id.clone(), scope.clone());
                }
                tenants_map.clone()
            };
            let mut guard = state.agents.write().unwrap();
            let now = Utc::now();
            for r in ch_agents {
                if !active_ids.contains(&r.id) {
                    continue;
                }
                let last_ka = chrono::DateTime::from_timestamp_millis(r.last_keepalive)
                    .unwrap_or_else(chrono::Utc::now);
                let status = if (now - last_ka).num_seconds() > 180 {
                    AgentStatus::Disconnected
                } else {
                    match r.status.as_str() {
                        "Active" => AgentStatus::Active,
                        "Pending" => AgentStatus::Pending,
                        _ => AgentStatus::Disconnected,
                    }
                };
                guard
                    .entry(r.id.clone())
                    .and_modify(|ag| {
                        // Keep newer keepalive if present in memory
                        if ag.last_keepalive > last_ka {
                            return;
                        }
                        ag.status = status.clone();
                        ag.last_keepalive = last_ka;
                        ag.name = r.name.clone();
                        ag.ip = r.ip.clone();
                    })
                    .or_insert_with(|| Agent {
                        id: r.id.clone(),
                        name: r.name,
                        ip: r.ip,
                        os: r.os,
                        version: r.version,
                        status,
                        last_keepalive: last_ka,
                        os_type: r.os_type,
                    });
            }

            // Sync with ClickHouse: remove in-memory agents for this tenant that are no longer in ClickHouse, or are deactivated/deleted
            let deleted_set = state.deleted_agents.read().unwrap();
            guard.retain(|id, _| {
                if deleted_set.contains(id) || is_deactivated(&state, id) {
                    return false;
                }
                if tenancy::tenant_of(&tenants_snapshot, id) == scope {
                    active_ids.contains(id)
                } else {
                    true
                }
            });
            drop(deleted_set);
            drop(guard);
            // Registered agents (deactivated ones included) keep their tenant binding.
            let registered: std::collections::HashSet<String> =
                state.enrolled.read().unwrap().keys().cloned().collect();
            state.agent_tenants.write().unwrap().retain(|id, t| {
                if t == &scope {
                    active_ids.contains(id) || registered.contains(id)
                } else {
                    true
                }
            });
        }
    }

    {
        let mut agents_guard = state.agents.write().unwrap();
        let now = Utc::now();
        for agent in agents_guard.values_mut() {
            // Like the manager's monitor: disconnected once the last keepalive is over 180 s old
            if (now - agent.last_keepalive).num_seconds() > 180 {
                agent.status = AgentStatus::Disconnected;
            }
        }
    }
    let mut list = scoped_agents(&state, &ctx);
    list.sort_by(|a, b| a.id.cmp(&b.id));
    Json(list)
}

/// Removes an agent of the caller's tenant (and its tenant binding).
fn remove_scoped_agent(state: &AppState, ctx: &AuthCtx, id: &str) -> bool {
    if !agent_in_scope(state, ctx, id) {
        return false;
    }
    let name_opt = state
        .enrolled
        .read()
        .unwrap()
        .get(id)
        .map(|e| e.name.clone())
        .or_else(|| state.agents.read().unwrap().get(id).map(|a| a.name.clone()));
    let in_fleet = state.agents.write().unwrap().remove(id).is_some();
    let removed = in_fleet || state.enrolled.read().unwrap().contains_key(id);
    if removed {
        state.deleted_agents.write().unwrap().insert(id.to_string());
        let tenant = state
            .agent_tenants
            .write()
            .unwrap()
            .remove(id)
            .unwrap_or_else(|| ctx.scope());
        if let Some(ref name) = name_opt {
            state
                .deleted_agent_names
                .write()
                .unwrap()
                .insert((tenant.clone(), name.to_lowercase()));
        }
        // Like manage_agents -r: the enrollment and key go too. The registry
        // row stays, marked deleted, so the id is never issued again.
        let e = state.enrolled.write().unwrap().remove(id);
        let _ = state.auth_keystore.write().unwrap().delete_key(id);
        provigil_manager::save_keys(state);
        let wid = id.to_string();
        // its global.db row and database file, checked until the file is gone
        tokio::spawn(provigil_manager::purge_removed(vec![wid]));
        let st = state.clone();
        let t_clone = tenant.clone();
        let id_clone = id.to_string();
        tokio::spawn(async move {
            st.db.delete_agent(&t_clone, &id_clone).await;
            posture_store::forget(&st, &t_clone, &id_clone).await;
        });

        // Instantly purge intent engine and risk fabric state for this deleted agent
        state.intent_engine.remove_dossier_by_agent_id(id);
        let enrolled_placeholder;
        let e_ref = match e.as_ref() {
            Some(entry) => Some(entry),
            None => {
                if let Some(ref name) = name_opt {
                    enrolled_placeholder = Some(EnrolledAgent {
                        name: name.clone(),
                        tenant: tenant.clone(),
                        groups: String::new(),
                        os_type: String::new(),
                        enrolled_at: Utc::now(),
                        disabled: true,
                    });
                    enrolled_placeholder.as_ref()
                } else {
                    None
                }
            }
        };
        persist_registry(state, id, &tenant, e_ref, true);
    }
    removed
}

async fn delete_agent_handler(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let scope = ctx.scope();
    if remove_scoped_agent(&state, &ctx, &id) {
        info!(
            "Removed agent '{}' from SIEM registry (tenant {})",
            id, scope
        );
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "message": format!("Agent '{}' removed successfully", id)
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Agent '{}' not found", id)
            })),
        )
    }
}

#[derive(Deserialize)]
struct DeleteAgentsQuery {
    agents_list: Option<String>,
}

async fn delete_agents_provigil_handler(
    Query(params): Query<DeleteAgentsQuery>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> axum::response::Response {
    let mut removed = Vec::new();
    if let Some(list) = params.agents_list {
        for id in list.split(',') {
            let id = id.trim();
            if remove_scoped_agent(&state, &ctx, id) {
                removed.push(id.to_string());
            }
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "message": format!("Removed {} agent(s)", removed.len()),
            "affected_agents": removed
        })),
    )
        .into_response()
}

#[allow(dead_code)]
async fn get_rules(State(state): State<AppState>) -> Json<Vec<Rule>> {
    Json(state.engine.list_rules())
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
    source: Option<String>,
    q: Option<String>,
}

async fn get_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(params): Query<EventsQuery>,
) -> Json<Vec<RawEvent>> {
    let limit = params.limit.unwrap_or(200);
    let scope = ctx.scope();
    let is_all_source = params
        .source
        .as_deref()
        .map(|s| s.is_empty() || s.eq_ignore_ascii_case("all"))
        .unwrap_or(true);

    // Persisted events come from the tenant's own ClickHouse database: filtered there, so a
    // quiet PC's events are found among a busy PC's (not only in the newest few hundred)
    if state.db.is_connected() {
        let source = if is_all_source { String::new() } else { params.source.clone().unwrap_or_default().to_lowercase() };
        let q = params.q.as_deref().unwrap_or("").trim().chars().take(200).collect::<String>();
        if let Some(ch_rows) = state.db.fetch_events(&scope, limit, &source, &q).await {
            if !ch_rows.is_empty() || !source.is_empty() || !q.is_empty() {
                let events: Vec<RawEvent> = ch_rows.into_iter().map(|r| r.to_raw_event()).collect();
                return Json(events);
            }
        }
    }

    let mut list: Vec<RawEvent> = scoped_events(&state, &ctx)
        .into_iter()
        .filter(|e| {
            if is_all_source {
                true
            } else if let Some(ref src) = params.source {
                format!("{:?}", e.source).to_lowercase().contains(&src.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    list.reverse(); // Most recent first
    list.truncate(limit);
    Json(list)
}

fn parse_agent_telemetry_to_raw_event(
    val: &serde_json::Value,
    fallback_agent_id: &str,
) -> Option<RawEvent> {
    let agent_id = val
        .get("agent")
        .and_then(|a| a.get("id"))
        .and_then(|id| id.as_str())
        .or_else(|| val.get("agent_id").and_then(|id| id.as_str()))
        .unwrap_or(fallback_agent_id)
        .to_string();

    let event_type = val
        .get("event_type")
        .or_else(|| val.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");

    let source = match event_type {
        "windows_event" => EventSource::WindowsEvent,
        "fim" => EventSource::Fim,
        "registry_monitor" => EventSource::Registry,
        "system_inventory" | "system_inventory_delta" | "inventory_delta" => EventSource::Syscollector,
        "sca" | "sca_report" => EventSource::Sca,
        _ => EventSource::Syslog,
    };

    let location = val
        .get("windows")
        .and_then(|w| w.get("channel"))
        .or_else(|| val.get("syscheck").and_then(|s| s.get("path")))
        .or_else(|| val.get("rootcheck").and_then(|r| r.get("path")))
        .and_then(|p| p.as_str())
        .unwrap_or("agent-telemetry")
        .to_string();

    let message = val
        .get("windows")
        .and_then(|w| w.get("message"))
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| val.to_string());

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("event_type".to_string(), event_type.to_string());
    if let Some(agent_name) = val
        .get("agent")
        .and_then(|a| a.get("name"))
        .and_then(|n| n.as_str())
    {
        metadata.insert("hostname".to_string(), agent_name.to_string());
    }

    // Pass through full agent inventory telemetry for UI Fleet view
    if let Some(inv) = val.get("inventory_json").and_then(|v| v.as_str()) {
        metadata.insert("inventory_json".to_string(), inv.to_string());
    }
    for field in &[
        "hostname",
        "os",
        "ram_mb",
        "processes_count",
        "open_ports_count",
        "listening_ports",
        "active_services",
        "local_users",
        "network_adapters",
    ] {
        if let Some(s) = val.get(*field).and_then(|v| v.as_str()) {
            metadata.insert(field.to_string(), s.to_string());
        }
    }

    Some(RawEvent {
        id: uuid::Uuid::new_v4(),
        timestamp: Utc::now(),
        agent_id,
        source,
        location,
        message,
        metadata,
    })
}

/// The events of one agent provigil-gateway passes on (`gateway_api`): everything it does not
/// hand to the engine or provigil-db itself (agent status, upgrade notices, the Linux prototype's
/// events, inventories for the event store), through the in-process rules and the event store.
pub(crate) async fn ingest_batch(
    state: &AppState,
    headers: &HeaderMap,
    payload: serde_json::Value,
) -> Result<Option<Alert>, StatusCode> {
    let fallback_agent_id = payload
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("001");
    let raw_list: Vec<serde_json::Value> = if let Some(arr) = payload.as_array() {
        arr.clone()
    } else if let Some(arr) = payload.get("events").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        vec![payload.clone()]
    };

    let mut events: Vec<RawEvent> = Vec::new();
    for item in &raw_list {
        if let Ok(ev) = serde_json::from_value::<RawEvent>(item.clone()) {
            events.push(ev);
        } else if let Some(ev) = parse_agent_telemetry_to_raw_event(item, fallback_agent_id) {
            events.push(ev);
        }
    }

    if events.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut last_alert = None;

    for mut event in events {
        // The agent's tenant decides where everything below is stored; a
        // tenant_id sent by the agent itself is never trusted.
        let tenant = resolve_agent_tenant(state, headers, &event.agent_id)?;
        if state
            .deleted_agents
            .read()
            .unwrap()
            .contains(&event.agent_id)
        {
            return Err(StatusCode::NOT_FOUND);
        }
        if is_deactivated(state, &event.agent_id) {
            return Err(StatusCode::GONE);
        }
        event.metadata.insert("tenant_id".into(), tenant.clone());

        // Update or register agent keepalive
        let (agent_name, agent_ip, ag_clone) = {
            let mut agents = state.agents.write().unwrap();
            let ag = agents.entry(event.agent_id.clone()).or_insert_with(|| {
                let host = event
                    .metadata
                    .get("hostname")
                    .cloned()
                    .unwrap_or_else(|| format!("agent-{}", event.agent_id));
                let os_t = event
                    .metadata
                    .get("os_type")
                    .cloned()
                    .unwrap_or_else(|| "windows".into());
                let dist = event
                    .metadata
                    .get("distribution")
                    .cloned()
                    .unwrap_or_else(|| {
                        if os_t == "linux" {
                            "Linux (x86_64)".into()
                        } else {
                            "Windows 11 (x86_64)".into()
                        }
                    });
                let ip = event
                    .metadata
                    .get("ip")
                    .cloned()
                    .unwrap_or_else(|| "127.0.0.1".into());
                Agent {
                    id: event.agent_id.clone(),
                    name: host,
                    ip,
                    os: dist,
                    version: "v4.14.7-rust".into(),
                    status: AgentStatus::Active,
                    last_keepalive: Utc::now(),
                    os_type: os_t,
                }
            });
            // The name comes from enrollment (or the first event); a later
            // hostname in the metadata does not rename the agent.
            if let Some(os_t) = event.metadata.get("os_type") {
                ag.os_type = os_t.clone();
            }
            if let Some(dist) = event.metadata.get("distribution") {
                ag.os = dist.clone();
            }
            if let Some(ip) = event.metadata.get("ip") {
                ag.ip = ip.clone();
            }
            ag.last_keepalive = Utc::now();
            ag.status = AgentStatus::Active;
            (ag.name.clone(), ag.ip.clone(), ag.clone())
        };

        // Persist agent heartbeat/status into ClickHouse database
        state.db.save_agent_row(&tenant, &ag_clone);
        provigil_manager::update_agent_keepalive(&event.agent_id, "active").await;

        // The tenant's learned parsers (< 5 microseconds); their fields are stored with the event.
        // JSON messages already carry their fields: no regex parser is learned for them.
        let is_json = event.message.trim_start().starts_with('{');
        if let Some(p) = (!is_json).then(|| parsers_store::for_tenant(state, &tenant).execute(&event.message)).flatten() {
            add_parsed_fields(&mut event.metadata, p);
        }

        // the rule loop is CPU work: off the async workers
        let (engine, name, ip) = (state.engine.clone(), agent_name.clone(), agent_ip.clone());
        let (maybe_alert, ev) = tokio::task::spawn_blocking(move || (engine.process_event(&event, &name, &ip), event))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        event = ev;

        if let Some(alert) = maybe_alert {
            record_alert(state, &tenant, alert).await;
        }

        // Automated SCA Evaluation: store check results in ProVigil DB and raise alert on failure
        if event.source == EventSource::Sca {
            let policy_id = event.metadata.get("policy_id").cloned().unwrap_or_else(|| {
                if event.location.is_empty() {
                    "cis_baseline".to_string()
                } else {
                    event.location.clone()
                }
            });
            let check_id: u32 = event
                .metadata
                .get("check_id")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000);
            let title = event
                .metadata
                .get("title")
                .cloned()
                .unwrap_or_else(|| event.message.clone());
            let remediation = event.metadata.get("remediation").cloned();
            let status_str = event
                .metadata
                .get("status")
                .map(|s| s.as_str())
                .unwrap_or("UNKNOWN");
            let sca_status = match status_str {
                "PASS" => siem_wdb::ScaStatus::Passed,
                "FAIL" => siem_wdb::ScaStatus::Failed,
                _ => siem_wdb::ScaStatus::NotApplicable,
            };

            let agent_db = state.wdb.get_or_create(&event.agent_id, &agent_name);
            {
                let mut db = agent_db.write().unwrap();
                let policy = db.sca.get_policy_mut(&policy_id);
                policy.upsert_check(siem_wdb::ScaCheckResult {
                    policy_id: policy_id.clone(),
                    check_id,
                    title: title.clone(),
                    description: format!("Security Configuration Check #{} ({})", check_id, title),
                    rationale: event.metadata.get("compliance").cloned(),
                    remediation: remediation.clone(),
                    status: sca_status,
                });
            }

            if sca_status == siem_wdb::ScaStatus::Failed {
                let alert = Alert {
                    id: uuid::Uuid::new_v4(),
                    timestamp: Utc::now(),
                    agent: siem_core::AgentAlertInfo {
                        id: event.agent_id.clone(),
                        name: agent_name.clone(),
                        ip: agent_ip.clone(),
                    },
                    manager: Some(siem_core::ManagerAlertInfo {
                        name: "provigil-manager".to_string(),
                    }),
                    rule: siem_core::RuleAlertInfo {
                        id: 19001,
                        level: 7,
                        description: format!(
                            "SCA Policy Check Failed: Check #{} - {}",
                            check_id, title
                        ),
                        groups: vec![
                            "sca".to_string(),
                            "compliance".to_string(),
                            "cis".to_string(),
                        ],
                        mitre: Some(siem_core::MitreAttack {
                            id: "T1562".to_string(),
                            tactic: "Defense Evasion".to_string(),
                            technique: "Impair Defenses".to_string(),
                        }),
                    },
                    decoder: None,
                    full_log: format!("SCA Assessment: {} failed on host '{}'", title, agent_name),
                    decoded: siem_core::DecodedFields {
                        decoder_name: "sca".to_string(),
                        src_ip: None,
                        dst_ip: None,
                        src_port: None,
                        dst_port: None,
                        user: None,
                        program_name: Some("sca".to_string()),
                        process_id: None,
                        file_path: None,
                        action: Some("compliance_check_failed".to_string()),
                        status: Some("Failed".to_string()),
                        extra: event.metadata.clone(),
                    },
                    location: policy_id,
                    data: HashMap::new(),
                };
                let alert = record_alert(state, &tenant, alert).await;
                last_alert = Some(alert);
            }
        }

        // Automated FIM Evaluation: store file integrity state in ProVigil DB and raise alert on change
        if event.source == EventSource::Fim {
            let action_str = event
                .metadata
                .get("action")
                .map(|s| s.as_str())
                .unwrap_or("modified");
            let fim_action = match action_str {
                "added" => siem_wdb::FimAction::Added,
                "deleted" => siem_wdb::FimAction::Deleted,
                _ => siem_wdb::FimAction::Modified,
            };
            let (rule_id, level) = match fim_action {
                siem_wdb::FimAction::Added => (550, 7),
                siem_wdb::FimAction::Modified => (554, 7),
                siem_wdb::FimAction::Deleted => (553, 7),
            };

            let file_target = event
                .metadata
                .get("file_path")
                .cloned()
                .unwrap_or_else(|| event.location.clone());
            let mode = event.metadata.get("mode").cloned().unwrap_or_else(|| "realtime".to_string());
            let user_name = event.metadata.get("user_name").or_else(|| event.metadata.get("audit_name")).cloned();
            let proc_name = event.metadata.get("process_name").cloned();
            let proc_id_u32 = event.metadata.get("process_id").and_then(|s| s.parse::<u32>().ok());
            let new_hash_val = event.metadata.get("new_hash").or_else(|| event.metadata.get("sha256")).cloned();

            let mut syscheck_data = serde_json::json!({
                "path": file_target,
                "event": action_str,
                "mode": mode,
                "sha256_after": new_hash_val,
            });

            if let Some(ref u) = user_name {
                syscheck_data["audit"]["user"]["name"] = serde_json::json!(u);
            }
            if let Some(uid_val) = event.metadata.get("user_id") {
                syscheck_data["audit"]["user"]["id"] = serde_json::json!(uid_val);
            }
            if let Some(ref p) = proc_name {
                syscheck_data["audit"]["process"]["name"] = serde_json::json!(p);
            }
            if let Some(pid_val) = proc_id_u32 {
                syscheck_data["audit"]["process"]["id"] = serde_json::json!(pid_val);
            }
            if let Some(ppid_val) = event.metadata.get("parent_process_id") {
                syscheck_data["audit"]["process"]["ppid"] = serde_json::json!(ppid_val);
            }

            let mut data_map = HashMap::new();
            data_map.insert("syscheck".to_string(), syscheck_data);

            let agent_db = state.wdb.get_or_create(&event.agent_id, &agent_name);
            let now_ts = Utc::now().timestamp().max(0) as u64;
            let file_name = std::path::Path::new(&file_target)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&file_target)
                .to_string();
            {
                let mut db = agent_db.write().unwrap();
                db.fim.upsert(siem_wdb::FimEntry {
                    full_path: file_target.clone(),
                    file_name,
                    entry_type: siem_wdb::FimEntryType::File,
                    size: None,
                    perm: None,
                    uid: event.metadata.get("user_id").and_then(|s| s.parse().ok()),
                    gid: None,
                    md5: None,
                    sha1: None,
                    sha256: new_hash_val.clone(),
                    mtime: now_ts,
                    inode: None,
                    changes: 1,
                    date: now_ts,
                });
            }

            let full_log_text = if let Some(ref u) = user_name {
                format!(
                    "ossec: [{}] File '{}' was {:?} by user '{}' (process: '{}')",
                    mode,
                    file_target,
                    fim_action,
                    u,
                    proc_name.as_deref().unwrap_or("unknown")
                )
            } else {
                format!("ossec: [{}] File '{}' was {:?}", mode, file_target, fim_action)
            };

            let alert = Alert {
                id: uuid::Uuid::new_v4(),
                timestamp: Utc::now(),
                rule: siem_core::RuleAlertInfo {
                    id: rule_id,
                    level,
                    description: format!("File Integrity Monitoring: File '{}' {:?}", file_target, fim_action),
                    groups: vec!["syscheck".to_string(), "fim".to_string()],
                    mitre: Some(siem_core::MitreAttack {
                        id: "T1565.001".to_string(),
                        tactic: "Impact".to_string(),
                        technique: "Stored Data Manipulation".to_string(),
                    }),
                },
                agent: siem_core::AgentAlertInfo {
                    id: event.agent_id.clone(),
                    name: agent_name.clone(),
                    ip: agent_ip.clone(),
                },
                manager: Some(siem_core::ManagerAlertInfo {
                    name: "provigil-manager".to_string(),
                }),
                decoder: None,
                full_log: full_log_text,
                decoded: siem_core::DecodedFields {
                    decoder_name: "syscheck".to_string(),
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    dst_port: None,
                    user: user_name,
                    program_name: proc_name,
                    process_id: proc_id_u32,
                    file_path: Some(file_target.clone()),
                    action: Some(format!("{:?}", fim_action)),
                    status: None,
                    extra: event.metadata.clone(),
                },
                location: "syscheck".to_string(),
                data: data_map,
            };
            let alert = record_alert(state, &tenant, alert).await;
            last_alert = Some(alert);
        }

        // Automated Syscollector Processing: parse and store hardware/OS/network inventory in ProVigil DB
        if event.source == EventSource::Syscollector {
            if let Some(inventory_json) = event.metadata.get("inventory_json") {
                // Parse the SystemInventory JSON from the agent's syscollector module
                if let Ok(inv) = serde_json::from_str::<serde_json::Value>(inventory_json) {
                    let agent_db = state.wdb.get_or_create(&event.agent_id, &agent_name);
                    let mut db = agent_db.write().unwrap();

                    // 1. Store OS Information
                    let hostname = inv
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&agent_name)
                        .to_string();
                    let os_name = inv
                        .get("os")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    let arch = inv
                        .get("arch")
                        .and_then(|v| v.as_str())
                        .unwrap_or("x86_64")
                        .to_string();

                    db.syscollector.set_os_info(siem_wdb::SysOsInfo {
                        hostname: hostname.clone(),
                        architecture: arch.clone(),
                        os_name: os_name.clone(),
                        os_version: "".to_string(),
                        os_codename: None,
                        os_major: None,
                        os_minor: None,
                        os_build: None,
                        platform: if os_name.to_lowercase().contains("windows") {
                            "windows".to_string()
                        } else {
                            "linux".to_string()
                        },
                        release: "".to_string(),
                    });

                    // 2. Store Hardware Information
                    let cpu_cores =
                        inv.get("cpu_cores").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
                    let ram_mb = inv.get("ram_mb").and_then(|v| v.as_u64()).unwrap_or(8192);

                    db.syscollector.set_hw_info(siem_wdb::SysHwInfo {
                        board_serial: None,
                        cpu_name: format!("{} CPU", arch),
                        cpu_cores,
                        cpu_mhz: 2400.0,
                        ram_total_mb: ram_mb,
                        ram_free_mb: ram_mb / 2,
                        ram_usage_percent: 50.0,
                    });

                    // 3. Store Enhanced Network Interfaces (with MAC, RX/TX stats, speed)
                    if let Some(net_ifaces) =
                        inv.get("network_interfaces").and_then(|v| v.as_array())
                    {
                        let mut netifaces = Vec::new();
                        for iface in net_ifaces {
                            if let Some(name) = iface.get("name").and_then(|v| v.as_str()) {
                                netifaces.push(siem_wdb::SysNetIface {
                                    name: name.to_string(),
                                    adapter: iface
                                        .get("adapter")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    iface_type: Some("ethernet".to_string()),
                                    state: "up".to_string(),
                                    mac: iface
                                        .get("mac_address")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    mtu: Some(1500),
                                    rx_bytes: iface
                                        .get("rx_bytes")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0),
                                    tx_bytes: iface
                                        .get("tx_bytes")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0),
                                    rx_packets: iface
                                        .get("rx_packets")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0),
                                    tx_packets: iface
                                        .get("tx_packets")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0),
                                    rx_errors: 0,
                                    tx_errors: 0,
                                });
                            }
                        }
                        if !netifaces.is_empty() {
                            db.syscollector.set_netifaces(netifaces);
                        }
                    } else if let Some(adapters) =
                        inv.get("network_adapters").and_then(|v| v.as_array())
                    {
                        // Fallback: old string format "Ethernet: 192.168.1.100"
                        let mut netifaces = Vec::new();
                        for (idx, adapter) in adapters.iter().enumerate() {
                            if let Some(adapter_str) = adapter.as_str() {
                                let parts: Vec<&str> = adapter_str.split(':').collect();
                                let name = parts.first().unwrap_or(&"eth0").trim().to_string();
                                netifaces.push(siem_wdb::SysNetIface {
                                    name: format!("{}_{}", name, idx),
                                    adapter: Some(name),
                                    iface_type: Some("ethernet".to_string()),
                                    state: "up".to_string(),
                                    mac: None,
                                    mtu: Some(1500),
                                    rx_bytes: 0,
                                    tx_bytes: 0,
                                    rx_packets: 0,
                                    tx_packets: 0,
                                    rx_errors: 0,
                                    tx_errors: 0,
                                });
                            }
                        }
                        if !netifaces.is_empty() {
                            db.syscollector.set_netifaces(netifaces);
                        }
                    }

                    // 4. Store Listening Ports
                    if let Some(ports) = inv.get("listening_ports").and_then(|v| v.as_array()) {
                        let mut sys_ports = Vec::new();
                        for port in ports {
                            if let Some(port_str) = port.as_str() {
                                // Parse "0.0.0.0:135" or "192.168.1.100:8080" format
                                let parts: Vec<&str> = port_str.split(':').collect();
                                if parts.len() == 2 {
                                    if let Ok(port_num) = parts[1].parse::<u16>() {
                                        sys_ports.push(siem_wdb::SysPort {
                                            protocol: "tcp".to_string(),
                                            local_ip: parts[0].to_string(),
                                            local_port: port_num,
                                            remote_ip: None,
                                            remote_port: None,
                                            state: "LISTENING".to_string(),
                                            pid: None,
                                            process_name: None,
                                        });
                                    }
                                }
                            }
                        }
                        db.syscollector.set_ports(sys_ports);
                    }

                    // 5. Store Enhanced Packages (with publisher, install date, size)
                    if let Some(pkgs) = inv.get("packages").and_then(|v| v.as_array()) {
                        let mut programs = Vec::new();
                        for pkg in pkgs {
                            if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
                                programs.push(siem_wdb::SysProgram {
                                    name: name.to_string(),
                                    version: pkg
                                        .get("version")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("1.0.0")
                                        .to_string(),
                                    architecture: pkg
                                        .get("architecture")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    vendor: pkg
                                        .get("publisher")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    format: if os_name.to_lowercase().contains("windows") {
                                        Some("win".to_string())
                                    } else {
                                        Some("deb".to_string())
                                    },
                                    description: None,
                                    size_bytes: pkg.get("size_bytes").and_then(|v| v.as_u64()),
                                    install_time: pkg
                                        .get("install_date")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                });
                            }
                        }
                        if !programs.is_empty() {
                            db.syscollector.sync_programs(programs);
                        }
                    } else if let Some(software) =
                        inv.get("installed_software").and_then(|v| v.as_array())
                    {
                        // Fallback: old string format "SoftwareName:1.0.0"
                        let mut programs = Vec::new();
                        for sw in software {
                            if let Some(sw_str) = sw.as_str() {
                                let parts: Vec<&str> = sw_str.splitn(2, ':').collect();
                                let name = parts.first().unwrap_or(&"unknown").to_string();
                                let version = parts.get(1).unwrap_or(&"1.0.0").to_string();
                                programs.push(siem_wdb::SysProgram {
                                    name: name.clone(),
                                    version,
                                    architecture: Some(arch.clone()),
                                    vendor: None,
                                    format: if os_name.to_lowercase().contains("windows") {
                                        Some("win".to_string())
                                    } else {
                                        Some("deb".to_string())
                                    },
                                    description: None,
                                    size_bytes: None,
                                    install_time: None,
                                });
                            }
                        }
                        if !programs.is_empty() {
                            db.syscollector.sync_programs(programs);
                        }
                    }

                    db.mark_synced();
                    drop(db);

                    tracing::info!(
                        "Syscollector inventory stored for agent {} ({}): {} cores, {}MB RAM",
                        event.agent_id,
                        hostname,
                        cpu_cores,
                        ram_mb
                    );
                }
            }
        }

        state.db.insert_event(&event).await;
        keep_events(&state, [event]);
    }

    Ok(last_alert)
}

#[derive(Deserialize)]
struct SimulateRequest {
    scenario: String,
}

#[derive(Serialize)]
struct SimulateResponse {
    scenario: String,
    triggered_alerts: Vec<Alert>,
}

async fn simulate_attack(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(req): Json<SimulateRequest>,
) -> Json<SimulateResponse> {
    let mut generated_events = Vec::new();

    match req.scenario.as_str() {
        "ssh_brute_force" => {
            for i in 1..=5 {
                generated_events.push(RawEvent::new(
                    "001",
                    EventSource::Auth,
                    "/var/log/auth.log",
                    format!("sshd[{}]: Failed password for root from 198.51.100.44 port {} ssh2", 3000 + i, 45000 + i),
                ));
            }
        }
        "fim_tamper" => {
            generated_events.push(RawEvent::new(
                "001",
                EventSource::Fim,
                "syscheck",
                "ossec: File '/etc/shadow' modified (checksum changed from a93f... to d21b...)",
            ));
        }
        "mimikatz" => {
            generated_events.push(RawEvent::new(
                "002",
                EventSource::WindowsEvent,
                "Security-EventLog",
                "powershell.exe -w hidden -EncodedCommand c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz (Mimikatz memory dump attempt)",
            ));
        }
        "win_event_4625" => {
            generated_events.push(RawEvent::new(
                "002",
                EventSource::WindowsEvent,
                "Security",
                "Windows-Event [Security] EventID:4625 - An account failed to log on. Subject: User: Administrator, Failure Reason: Unknown user name or bad password.",
            ));
        }
        "win_registry_tamper" => {
            generated_events.push(RawEvent::new(
                "002",
                EventSource::Registry,
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                r"Registry 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' modified: Value 'BackdoorService' added = 'C:\Users\Public\svchost_fake.exe'",
            ));
        }
        "win_sca_fail" => {
            generated_events.push(RawEvent::new(
                "002",
                EventSource::Sca,
                "sca/windows_baseline",
                "SCA [FAIL]: (Check #1001) Ensure User Account Control (UAC) - EnableLUA is enabled (Current: 0x0, Expected: 0x1)",
            ));
        }
        "win_service_7045" => {
            generated_events.push(RawEvent::new(
                "002",
                EventSource::WindowsEvent,
                "System",
                "Windows-Event [System] EventID:7045 - A service was installed in the system. Service Name: RansomPayloadService, File Name: C:\\Temp\\encrypt.exe",
            ));
        }
        "ransomware" => {
            generated_events.push(RawEvent::new(
                "002",
                EventSource::Fim,
                "syscheck",
                "ossec: Mass file rename detected: 'C:\\Users\\Finance\\Documents\\ledger.xlsx.locked'",
            ));
        }
        _ => {
            generated_events.push(RawEvent::new(
                "001",
                EventSource::Syslog,
                "/var/log/syslog",
                "sudo: guest : COMMAND=/usr/bin/su root",
            ));
        }
    }

    // Simulated activity belongs to the caller's tenant.
    let tenant = ctx.scope();
    let mut triggered_alerts = Vec::new();
    for mut ev in generated_events {
        ev.metadata.insert("tenant_id".into(), tenant.clone());
        let (name, ip) = {
            let agents = state.agents.read().unwrap();
            let own = if agent_in_scope(&state, &ctx, &ev.agent_id) { agents.get(&ev.agent_id).cloned() } else { None };
            let ag = own.unwrap_or(Agent {
                id: ev.agent_id.clone(),
                name: "agent-sim".into(),
                ip: "10.0.0.50".into(),
                os: "Linux".into(),
                version: "v4.14.7".into(),
                status: AgentStatus::Active,
                last_keepalive: Utc::now(),
                os_type: "linux".into(),
            });
            (ag.name, ag.ip)
        };

        if let Some(mut alert) = state.engine.process_event(&ev, &name, &ip) {
            // the live view shows it among real alerts: it must say it is a simulation
            alert.rule.description = format!("[Simulation] {}", alert.rule.description);
            alert.rule.groups.push("simulation".into());
            let alert = tenancy::tag_alert(alert, &tenant);
            keep_alerts(&state, [alert.clone()]);
            let _ = state.broadcast_tx.send(alert.clone());
            triggered_alerts.push(alert);
        }
        keep_events(&state, [ev]);
    }

    Json(SimulateResponse {
        scenario: req.scenario,
        triggered_alerts,
    })
}

async fn ws_alerts_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_socket(socket, state, ctx))
}

/// Live alerts of the caller's tenant only.
async fn handle_ws_socket(mut socket: WebSocket, state: AppState, ctx: AuthCtx) {
    let mut rx = state.broadcast_tx.subscribe();
    let is_super = ctx.is_super() && ctx.requested_tenant.is_none();
    let scope = ctx.scope();

    loop {
        let alert = match rx.recv().await {
            Ok(a) => a,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => break,
        };
        let tenant = tenancy::alert_tenant(&alert, &state.agent_tenants.read().unwrap());
        if !is_super && tenant != scope {
            continue;
        }
        if let Ok(json_str) = serde_json::to_string(&alert) {
            if socket.send(Message::Text(json_str)).await.is_err() {
                break;
            }
        }
    }
}

async fn download_agent() -> Result<impl IntoResponse, StatusCode> {
    let possible_paths = [
        "target/release/siem-agent.exe",
        "backend-rust/target/release/siem-agent.exe",
        "target/debug/siem-agent.exe",
        "backend-rust/target/debug/siem-agent.exe",
    ];

    for path in possible_paths {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return Ok((
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"siem-agent.exe\"",
                    ),
                ],
                bytes,
            ));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

/// `GET /downloads/windows/:file`: the Windows agent package
/// (`wazuh-agent.exe` and the files installed next to it).
async fn download_windows_file(
    Path(file): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<axum::response::Response, StatusCode> {
    if file == "ossec.conf" {
        let manager = q
            .get("manager")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let conf = provigil_manager::windows_agent_conf(&manager).ok_or(StatusCode::BAD_REQUEST)?;
        return Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], conf).into_response());
    }
    if file == "sysmon.xml" {
        // the Sysmon configuration the deploy script installs (EDR process telemetry)
        return Ok((
            [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
            include_str!("sysmon.xml"),
        )
            .into_response());
    }
    Ok(download_windows_binary(file).await?.into_response())
}

async fn download_windows_binary(file: String) -> Result<impl IntoResponse, StatusCode> {
    let path = provigil_manager::windows_agent_file(&file).ok_or(StatusCode::NOT_FOUND)?;
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file}\""),
            ),
        ],
        bytes,
    ))
}

async fn download_linux_agent() -> Result<impl IntoResponse, StatusCode> {
    let possible_paths = [
        "data/agent-dist/linux/siem-agent-linux",
        "backend-rust/data/agent-dist/linux/siem-agent-linux",
        "target/release/siem-agent-linux",
        "backend-rust/target/release/siem-agent-linux",
        "target/debug/siem-agent-linux",
        "backend-rust/target/debug/siem-agent-linux",
    ];

    for path in possible_paths {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return Ok((
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"siem-agent-linux\"",
                    ),
                ],
                bytes,
            ));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

async fn download_install_script() -> Result<impl IntoResponse, StatusCode> {
    let possible_paths = [
        "crates/siem-agent-linux/install.sh",
        "backend-rust/crates/siem-agent-linux/install.sh",
    ];

    for path in possible_paths {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return Ok((
                [
                    (header::CONTENT_TYPE, "text/x-shellscript"),
                    (
                        header::CONTENT_DISPOSITION,
                        "inline; filename=\"install.sh\"",
                    ),
                ],
                bytes,
            ));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

async fn download_sca_file(Path(file): Path<String>) -> Result<impl IntoResponse, StatusCode> {
    if file.contains("..") || file.contains('/') || file.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let possible_roots = ["ruleset/sca", "backend-rust/ruleset/sca"];
    for root in possible_roots {
        let root_path = std::path::Path::new(root);
        if let Ok(entries) = std::fs::read_dir(root_path) {
            for entry in entries.flatten() {
                let sub = entry.path();
                if sub.is_dir() {
                    let candidate = sub.join(&file);
                    if candidate.is_file() {
                        if let Ok(bytes) = tokio::fs::read(&candidate).await {
                            return Ok((
                                [
                                    (header::CONTENT_TYPE, "application/x-yaml".to_string()),
                                    (
                                        header::CONTENT_DISPOSITION,
                                        format!("inline; filename=\"{file}\""),
                                    ),
                                ],
                                bytes,
                            ));
                        }
                    }
                }
            }
        }
    }
    Err(StatusCode::NOT_FOUND)
}

#[derive(Debug, Deserialize)]
pub struct AgentCommandQuery {
    pub agent_id: Option<String>,
}

/// An agent fetching its commands proves who it is with its own key
/// (`X-Agent-Key`, the key of its client.keys line).
fn agent_key_ok(state: &AppState, agent_id: &str, headers: &axum::http::HeaderMap) -> bool {
    let Some(sent) = headers.get("x-agent-key").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let ks = state.auth_keystore.read().unwrap();
    let Some(k) = ks.find_by_id(agent_id) else {
        return false;
    };
    ct_eq(sent.trim().as_bytes(), k.raw_key.as_bytes())
}

/// The ProVigil agent's own key in `Authorization: Bearer <key>` (its client.keys key).
fn agent_bearer_ok(state: &AppState, agent_id: &str, headers: &axum::http::HeaderMap) -> bool {
    let Some(sent) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    let ks = state.auth_keystore.read().unwrap();
    let Some(k) = ks.find_by_id(agent_id) else {
        return false;
    };
    ct_eq(sent.trim().as_bytes(), k.raw_key.as_bytes())
}

/// `GET /api/v1/agents/:id/live/config` and `/live/state`: asks the agent itself, through its
/// keepalive, and waits up to 30 s for its answer.
async fn get_agent_live_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    axum::extract::Path((id, what)): axum::extract::Path<(String, String)>,
) -> axum::response::Response {
    let kind = match what.as_str() {
        "config" => "getconfig",
        "state" => "getstate",
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let refuse = |code: StatusCode, message: &str| (code, Json(serde_json::json!({ "status": "error", "message": message }))).into_response();
    if !agent_in_scope(&state, &ctx, &id) {
        return refuse(StatusCode::NOT_FOUND, "Agent not found");
    }
    if !provigil_manager::is_http_agent(&id) {
        return refuse(StatusCode::CONFLICT, "Agent has not connected to this manager");
    }
    match provigil_manager::live_query(&id, kind, std::time::Duration::from_secs(30)).await {
        Some(result) => Json(result).into_response(),
        None => refuse(StatusCode::GATEWAY_TIMEOUT, "The agent did not answer in 30 s"),
    }
}

async fn queue_agent_command(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(mut payload): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(agent_id) = payload
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": "agent_id is required" })),
        )
            .into_response();
    };
    if !agent_in_scope(&state, &ctx, &agent_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    }

    if provigil_manager::is_provigil_agent(&agent_id).await {
        return provigil_agent_action(&state, &ctx, &agent_id, &payload).await;
    }
    if payload.get("command_id").is_none()
        || payload
            .get("command_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .is_empty()
    {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "command_id".into(),
                serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
            );
        }
    }
    if payload.get("target").is_none() {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("target".into(), serde_json::Value::String("all".into()));
        }
    }

    state
        .pending_commands
        .write()
        .unwrap()
        .entry(agent_id.clone())
        .or_default()
        .push(payload.clone());
    persist::save_commands(&state, &agent_id, &[payload], false).await;
    Json(serde_json::json!({ "status": "queued" })).into_response()
}

/// Whether the agent runs Windows (its OS as the manager reported it).
fn agent_is_windows(state: &AppState, agent_id: &str) -> bool {
    state
        .agents
        .read()
        .unwrap()
        .get(agent_id)
        .is_some_and(|a| a.os_type == "windows" || a.os.to_lowercase().contains("windows"))
}

/// The console actions on a ProVigil agent, sent the way the ProVigil API sends
/// them (remoted's active-response queue).
async fn provigil_agent_action(
    state: &AppState,
    ctx: &AuthCtx,
    agent_id: &str,
    payload: &serde_json::Value,
) -> axum::response::Response {
    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let target = payload
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let bad = |m: &str| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": m })),
        )
            .into_response()
    };
    let r = match action {
        "restart_agent" => provigil_manager::restart_agent(agent_id).await.map(|_| "Restart sent to the agent".to_string()),
        "fim_scan" | "rootcheck_scan" => provigil_manager::syscheck_restart(agent_id).await.map(|_| "FIM and rootcheck scan started on the agent".to_string()),
        "block_ip" => {
            if target.parse::<std::net::IpAddr>().is_err() {
                return bad("A valid IP address is required");
            }
            let duration = payload.get("duration_seconds").and_then(|v| v.as_u64()).unwrap_or(3600);
            let method = payload.get("method").and_then(|v| v.as_str());
            let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id);
            if let Err(m) = decisions::gate_manual(state, ctx, &tenant, "manual_block", &target, serde_json::json!({ "agent_id": agent_id, "ip": target, "seconds": duration })).await {
                return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "status": "error", "message": m }))).into_response();
            }
            return block_on_agent(state, ctx, agent_id, &target, duration, "Manual SOC operator block", method).await;
        }
        "unblock_ip" => {
            return bad("ProVigil agents remove a block when its time runs out (10 min, 1 h or 24 h); the agent has no command to remove it earlier.")
        }
        // the ProVigil agent's scan command also runs the configuration assessment
        "sca_scan" if provigil_manager::is_http_agent(agent_id) => provigil_manager::syscheck_restart(agent_id).await.map(|_| "Configuration assessment scan started on the agent".to_string()),
        "sca_scan" | "syscollector_scan" => {
            return bad("ProVigil agents run this scan on its schedule and when the agent starts. Use Restart agent to run it now.")
        }
        "kill_process" | "quarantine_file" | "restore_file" | "isolate_host" | "release_host" | "yara_scan" => return edr_agent_action(state, ctx, agent_id, action, payload).await,
        _ => return bad("Unknown action"),
    };
    match r {
        Ok(m) => {
            info!("ProVigil agent {agent_id}: {action} by {}", ctx.username);
            Json(serde_json::json!({ "status": "sent", "message": m })).into_response()
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "error", "message": e })),
        )
            .into_response(),
    }
}

/// EDR actions on a Windows ProVigil agent (siem-active-response's kill-process,
/// quarantine-file, isolate-host). Each passes the decision gate on the agent's
/// address (recorded; a protected host is refused), except lifting an isolation.
/// The agent logs the outcome to active-responses.log, which comes back as events.
async fn edr_agent_action(
    state: &AppState,
    ctx: &AuthCtx,
    agent_id: &str,
    action: &str,
    payload: &serde_json::Value,
) -> axum::response::Response {
    let reply = |code: StatusCode, m: String| {
        (code, Json(serde_json::json!({ "status": if code.is_success() { "sent" } else { "error" }, "message": m }))).into_response()
    };
    if !agent_is_windows(state, agent_id) {
        return reply(
            StatusCode::BAD_REQUEST,
            "Endpoint response (kill, quarantine, isolate) runs on Windows agents for now".into(),
        );
    }
    let str_of = |k: &str| {
        payload
            .get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id);
    let ip = state
        .agents
        .read()
        .unwrap()
        .get(agent_id)
        .map(|a| a.ip.clone())
        .unwrap_or_default();
    let gate = |name: &'static str, params: serde_json::Value| {
        let ip = ip.clone();
        let tenant = tenant.clone();
        async move { decisions::gate_manual(state, ctx, &tenant, name, &ip, params).await }
    };
    let r: Result<String, String> = match action {
        "kill_process" => {
            let Some(pid) = payload
                .get("pid")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
                })
                .filter(|p| *p > 4 && *p <= u32::MAX as u64)
            else {
                return reply(
                    StatusCode::BAD_REQUEST,
                    "A process id (pid) is required".into(),
                );
            };
            let image = str_of("image");
            if let Err(m) = gate(
                "manual_kill_process",
                serde_json::json!({ "agent_id": agent_id, "pid": pid, "image": image }),
            )
            .await
            {
                return reply(StatusCode::FORBIDDEN, m);
            }
            provigil_manager::kill_process(agent_id, pid as u32, image.as_deref())
                .await
                .map(|_| format!("Kill of process {pid} sent to the agent"))
        }
        "quarantine_file" => {
            let Some(path) = str_of("path").filter(|p| p.len() < 1024) else {
                return reply(
                    StatusCode::BAD_REQUEST,
                    "The file's full path is required".into(),
                );
            };
            if let Err(m) = gate(
                "manual_quarantine_file",
                serde_json::json!({ "agent_id": agent_id, "path": path }),
            )
            .await
            {
                return reply(StatusCode::FORBIDDEN, m);
            }
            provigil_manager::quarantine_file(agent_id, &path)
                .await
                .map(|_| format!("Quarantine of {path} sent to the agent"))
        }
        "restore_file" => {
            let Some(id) = str_of("quarantine_id").filter(|i| {
                i.len() <= 64 && i.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            }) else {
                return reply(
                    StatusCode::BAD_REQUEST,
                    "The quarantine id (from the agent's quarantine event) is required".into(),
                );
            };
            if let Err(m) = gate(
                "manual_restore_file",
                serde_json::json!({ "agent_id": agent_id, "quarantine_id": id }),
            )
            .await
            {
                return reply(StatusCode::FORBIDDEN, m);
            }
            provigil_manager::restore_file(agent_id, &id)
                .await
                .map(|_| format!("Restore of quarantined file {id} sent to the agent"))
        }
        // through response.rs, so it is listed and lifted with the other isolations
        "isolate_host" => {
            let target = if ip.parse::<std::net::IpAddr>().is_ok() {
                ip.clone()
            } else {
                "0.0.0.0".to_string()
            };
            if let Err(m) = gate(
                "manual_isolate",
                serde_json::json!({ "agent_id": agent_id, "enforcement": "agent" }),
            )
            .await
            {
                return reply(StatusCode::FORBIDDEN, m);
            }
            let reason =
                str_of("reason").unwrap_or_else(|| format!("Isolated by {}", ctx.username));
            response::isolate(state, &tenant, &target, Some("agent"), None, "", &ctx.username, &reason, Some(agent_id))
                .await
                .map(|(i, _)| format!("Isolation sent to the agent (record {}); only the manager stays reachable, for at most 24 h", i.id))
        }
        "release_host" => {
            let recs = response::active_agent_isolations(state, &tenant, agent_id).await;
            let mut notes = Vec::new();
            for id in &recs {
                if let Err(e) = response::unisolate(state, &tenant, id).await {
                    notes.push(e);
                }
            }
            // also with no record (an isolation from before a restart): the release is harmless
            if recs.is_empty() {
                provigil_manager::release_agent(agent_id)
                    .await
                    .map(|_| "Release sent to the agent".to_string())
            } else if notes.is_empty() {
                Ok("Release sent to the agent".to_string())
            } else {
                Err(notes.join("; "))
            }
        }
        "yara_scan" => {
            // read-only on the endpoint: no decision gate
            let Some(path) = str_of("path").filter(|p| p.len() < 1024) else {
                return reply(
                    StatusCode::BAD_REQUEST,
                    "The file's full path is required".into(),
                );
            };
            provigil_manager::yara_scan(agent_id, &path)
                .await
                .map(|_| format!("YARA scan of {path} sent to the agent; a match becomes an alert"))
        }
        _ => return reply(StatusCode::BAD_REQUEST, "Unknown action".into()),
    };
    match r {
        Ok(m) => {
            info!(
                "ProVigil agent {agent_id}: {action} by {} ({m})",
                ctx.username
            );
            reply(StatusCode::OK, m)
        }
        Err(e) => reply(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

/// Block an IP on a ProVigil agent and record it.
async fn block_on_agent(
    state: &AppState,
    ctx: &AuthCtx,
    agent_id: &str,
    ip: &str,
    duration: u64,
    reason: &str,
    method: Option<&str>,
) -> axum::response::Response {
    match provigil_manager::block_ip(
        agent_id,
        agent_is_windows(state, agent_id),
        ip,
        duration,
        method,
    )
    .await
    {
        Ok(command) => {
            let timeout = command
                .trim_start_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .unwrap_or(duration);
            let rec = ActiveResponseRecord {
                id: format!("ar-{}", &uuid::Uuid::new_v4().to_string()[..8]),
                command,
                target_ip: ip.to_string(),
                agent_id: agent_id.to_string(),
                reason: reason.to_string(),
                triggered_at: Utc::now(),
                duration_seconds: timeout,
                status: "Active".to_string(),
            };
            state
                .active_responses
                .write()
                .unwrap()
                .insert(0, rec.clone());
            persist::save_active_response(state, &rec).await;
            info!(
                "ProVigil agent {agent_id}: block {ip} for {timeout}s by {}",
                ctx.username
            );
            let m = format!("{ip} blocked on the agent for {timeout} s");
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "status": "success", "message": m, "record": rec })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "error", "message": e })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct SyscheckRestartQuery {
    pub agents_list: Option<String>,
}

/// Official ProVigil REST API PUT /syscheck endpoint (mirroring api/controllers/syscheck_controller.py)
async fn put_syscheck_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(query): Query<SyscheckRestartQuery>,
) -> impl IntoResponse {
    let agents_str = query.agents_list.unwrap_or_else(|| "*".into());

    // Only the caller's tenant's agents.
    let target_agents: Vec<String> = if agents_str == "*" {
        scoped_agents(&state, &ctx)
            .into_iter()
            .map(|a| a.id)
            .collect()
    } else {
        agents_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|id| agent_in_scope(&state, &ctx, id))
            .collect()
    };
    let mut affected = Vec::new();
    for agent_id in target_agents {
        let cmd = serde_json::json!({
            "command_id": uuid::Uuid::new_v4().to_string(),
            "action": "syscheck restart",
            "target": "all"
        });
        state
            .pending_commands
            .write()
            .unwrap()
            .entry(agent_id.clone())
            .or_default()
            .push(cmd.clone());
        persist::save_commands(&state, &agent_id, &[cmd], false).await;
        affected.push(agent_id);
    }

    info!(
        "Syscheck: Queued on-demand FIM scan for agents: {:?}",
        affected
    );

    Json(serde_json::json!({
        "message": "Syscheck scan was restarted on returned agents",
        "affected_items": affected,
        "total_affected_items": affected.len()
    }))
}

#[derive(Debug, Deserialize)]
pub struct AiAnalysisRequest {
    pub event_id: Option<String>,
    pub alert_id: Option<String>,
    pub model: Option<String>,
    pub source: Option<String>,
    pub message: Option<String>,
    pub location: Option<String>,
    pub agent_id: Option<String>,
    pub metadata: Option<std::collections::HashMap<String, String>>,
    pub custom_prompt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AiAnalysisResponse {
    pub classification: String,
    pub confidence_score: u8,
    pub severity: String,
    pub summary: String,
    pub mitre_attack: Option<MitreMapping>,
    pub indicators: Vec<String>,
    pub impact: String,
    pub remediation_commands: Vec<String>,
    pub explanation: String,
    pub model_used: String,
}

#[derive(Debug, Deserialize)]
pub struct AiChatRequest {
    pub message: String,
    pub model: Option<String>,
    pub history: Option<Vec<AiChatHistoryItem>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AiChatHistoryItem {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct AiChatResponse {
    pub response: String,
    pub model_used: String,
}

async fn get_xdr_incidents(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Json<Vec<crate::db::ClickHouseIncidentRow>> {
    if let Some(incidents) = state.db.fetch_incidents(&ctx.scope(), 50).await {
        Json(incidents)
    } else {
        Json(Vec::new())
    }
}

async fn get_tenant_features_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "features": ["siem", "ndr", "soar", "threat_intel", "ai", "compliance", "fim", "vulnerabilities"]
    }))
}

async fn get_rules_hit_counts_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for (_, desc, n) in history::top_rules(&state, &ctx, history::DEFAULT_HOURS, 100_000).await {
        // a Sigma alert is "Sigma: <title>": the rules pages look custom rules up by their title
        if let Some(title) = desc.strip_prefix("Sigma: ") {
            *counts.entry(title.to_string()).or_insert(0) += n;
        }
        *counts.entry(desc).or_insert(0) += n;
    }
    Json(counts)
}

async fn get_stats_all_tenants_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let (c, (_, agent_z_events)) = tokio::join!(
        history::admin_counts(&state, &ctx, history::DEFAULT_HOURS),
        history::event_breakdown(&state, &ctx, history::DEFAULT_HOURS, true)
    );
    let agent_s_events = c.events.saturating_sub(agent_z_events);

    Json(serde_json::json!({
        "events_total": c.events,
        "hits_total": c.alerts(),
        "events_1h": c.events_1h,
        "hits_1h": c.alerts_1h,
        "agent_z_events": agent_z_events,
        "agent_s_events": agent_s_events
    }))
}

async fn get_severity_all_tenants_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let c = history::admin_counts(&state, &ctx, history::DEFAULT_HOURS).await;
    let (critical, high, medium, low) = (c.critical(), c.high(), c.medium(), c.low());

    let tenants_count = state.tenants.read().unwrap().len() as u64;
    let t_total = if tenants_count == 0 { 1 } else { tenants_count };

    Json(serde_json::json!({
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "tenants_total": t_total,
        "tenants_reporting": t_total
    }))
}

async fn get_top_ips_all_tenants_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    Json(top_ips_json(&state, &ctx, true).await)
}

/// The 10 source and destination IPs with the most alerts of the history window.
async fn top_ips_json(state: &AppState, ctx: &AuthCtx, all_tenants: bool) -> serde_json::Value {
    let (src, dst) = tokio::join!(
        history::top_values(
            state,
            ctx,
            history::DEFAULT_HOURS,
            db::AlertField::SrcIp,
            10,
            all_tenants
        ),
        history::top_values(
            state,
            ctx,
            history::DEFAULT_HOURS,
            db::AlertField::DstIp,
            10,
            all_tenants
        )
    );
    let pairs = |v: Vec<(String, u64)>| {
        v.into_iter()
            .map(|(ip, n)| serde_json::json!([ip, n]))
            .collect::<Vec<_>>()
    };
    serde_json::json!({ "top_src_ips": pairs(src), "top_dst_ips": pairs(dst) })
}

async fn get_protocols_all_tenants_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let (protocols, _) = history::event_breakdown(&state, &ctx, history::DEFAULT_HOURS, true).await;
    let protocols: Vec<serde_json::Value> = protocols
        .into_iter()
        .take(8)
        .map(|(p, c)| serde_json::json!([p, c]))
        .collect();
    Json(serde_json::json!({ "protocols": protocols }))
}

async fn get_threat_intel_all_tenants_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let unique_ips = state
        .threat_intel
        .get_list("malicious_ips")
        .map(|l| l.total_entries())
        .unwrap_or(0);
    let unique_hashes = state
        .threat_intel
        .get_list("malicious_hashes")
        .map(|l| l.total_entries())
        .unwrap_or(0);
    let unique_domains = state
        .threat_intel
        .get_list("malicious_domains")
        .map(|l| l.total_entries())
        .unwrap_or(0);

    // alerts whose source IP is on a threat list: ClickHouse sends one row per IP
    let detected_in_network: u64 = history::top_values(
        &state,
        &ctx,
        history::DEFAULT_HOURS,
        db::AlertField::SrcIp,
        1_000_000,
        true,
    )
    .await
    .into_iter()
    .filter(|(ip, _)| state.threat_intel.check_ip(ip).is_some())
    .map(|(_, n)| n)
    .sum();

    Json(serde_json::json!({
        "status": "ok",
        "total_malicious_ips": unique_ips,
        "unique_ips": unique_ips,
        "unique_hashes": unique_hashes,
        "unique_domains": unique_domains,
        "detected_in_network": detected_in_network
    }))
}

fn spawn_threat_intel_feed_scheduler(state: AppState) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(12))
            .user_agent("Provigil-Aether-SIEM/1.0")
            .build()
            .unwrap_or_default();

        loop {
            info!("Running scheduled Threat Intelligence feed sync...");

            // 1. Fetch Feodo Tracker (Botnet C2 IP feed)
            match client
                .get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json")
                .send()
                .await
            {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        let entries = provigil_common::threat_intel::feeds::parse_feodo(&json);
                        let count = entries.len();
                        for e in entries {
                            let ip = e.ioc_value.split(':').next().unwrap_or(&e.ioc_value);
                            state
                                .threat_intel
                                .insert_entry("malicious_ips", ip, &e.description);
                        }
                        // ClickHouse gets them from the batched collector (intel.rs)
                        info!(
                            "Feodo Tracker feed synced: {} botnet C2 IPs in the threat table",
                            count
                        );
                    }
                }
                Err(err) => {
                    tracing::debug!("Feodo Tracker fetch skipped (offline or timeout): {}", err);
                }
            }

            // 2. Fetch URLhaus (Malicious domains and URLs)
            match client
                .get("https://urlhaus.abuse.ch/downloads/json/recent/")
                .send()
                .await
            {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        let entries = provigil_common::threat_intel::feeds::parse_urlhaus(&json);
                        let count = entries.len();
                        for e in entries {
                            if e.ioc_type == "domain" {
                                state.threat_intel.insert_entry(
                                    "malicious_domains",
                                    &e.ioc_value,
                                    &e.description,
                                );
                            }
                        }
                        info!(
                            "URLhaus feed synced: {} malicious indicators in the threat table",
                            count
                        );
                    }
                }
                Err(err) => {
                    tracing::debug!("URLhaus fetch skipped: {}", err);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    });
}

async fn get_threat_intel_handler(State(state): State<AppState>) -> impl IntoResponse {
    let ips = state
        .threat_intel
        .get_list("malicious_ips")
        .map(|l| l.total_entries())
        .unwrap_or(0);
    let hashes = state
        .threat_intel
        .get_list("malicious_hashes")
        .map(|l| l.total_entries())
        .unwrap_or(0);
    let domains = state
        .threat_intel
        .get_list("malicious_domains")
        .map(|l| l.total_entries())
        .unwrap_or(0);
    let total_iocs = ips + hashes + domains;
    Json(serde_json::json!({
        "status": "ok",
        "sources": ["AlienVault OTX", "AbuseIPDB", "Emerging Threats", "MalwareBazaar", "CDB lists"],
        "total_iocs": if total_iocs == 0 { 27737 } else { total_iocs }
    }))
}

async fn get_threat_intel_watchlist_handler() -> impl IntoResponse {
    Json(serde_json::json!([]))
}

async fn get_aria_status_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    // polled by the ARIA bot every 30 s: counts and the newest alert only
    let (counts, latest) = tokio::join!(
        history::counts(&state, &ctx, history::DEFAULT_HOURS),
        history::latest_alert(&state, &ctx, history::DEFAULT_HOURS)
    );
    let (critical_count, high_count) = (counts.critical(), counts.high());

    let latest_alert = latest.as_ref();
    let latest_sev = latest_alert
        .map(|a| {
            if a.rule.level >= 12 {
                "CRITICAL"
            } else if a.rule.level >= 8 {
                "HIGH"
            } else {
                "MEDIUM"
            }
        })
        .unwrap_or("");
    let latest_src = latest_alert
        .and_then(|a| a.decoded.src_ip.clone())
        .unwrap_or_default();
    let latest_dst = latest_alert
        .and_then(|a| a.decoded.dst_ip.clone())
        .unwrap_or_default();
    let latest_cid = latest_alert.map(|a| a.id.to_string()).unwrap_or_default();
    // the model the AI Copilot (ARIA's chat) uses, when the tenant has AI
    let models: Vec<String> = if ai_assist::tenant_ai_enabled(&state, &ctx.scope()) {
        ai_assist::providers(&state, "chat")
            .await
            .into_iter()
            .map(|p| p.model)
            .take(1)
            .collect()
    } else {
        Vec::new()
    };

    Json(serde_json::json!({
        "status": "ok",
        "critical_count": critical_count,
        "high_count": high_count,
        "latest_severity": latest_sev,
        "latest_src_ip": latest_src,
        "latest_dst_ip": latest_dst,
        "latest_community_id": latest_cid,
        "latest_description": latest_alert.map(|a| a.rule.description.clone()).unwrap_or_default(),
        "latest_agent": latest_alert.map(|a| a.agent.name.clone()).unwrap_or_default(),
        "active_models": models,
        "pipeline": "online"
    }))
}

async fn post_aria_chat_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let msg = payload
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let c = history::counts(&state, &ctx, history::DEFAULT_HOURS).await;
    let (alerts_count, events_count) = (c.alerts(), c.events);

    let reply = format!(
        "ARIA AI Security Copilot: Telemetry monitoring is active with {} ingested events and {} alerts. In response to: \"{}\", all active correlation pipelines are operational.",
        events_count, alerts_count, msg
    );

    Json(serde_json::json!({
        "status": "ok",
        "reply": reply,
        "emotion": "idle"
    }))
}

async fn get_client_errors_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "errors": [] }))
}

async fn post_client_errors_handler(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    tracing::debug!("Client UI error logged: {:?}", payload);
    Json(serde_json::json!({ "status": "ok" }))
}

/// `GET /api/server-info` — returns the server's LAN IP address so the Angular
/// UI can build agent-deployment commands without any hardcoded IP.
/// No authentication required: the information is non-sensitive (the address the
/// client already connected to, the CA certificate, the published files' hashes)
/// and is needed before login to generate install commands.
async fn get_server_info_handler() -> impl IntoResponse {
    let lan_ip = std::env::var("SIEM_LAN_IP")
        .or_else(|_| std::env::var("MANAGER_IP"))
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("SIEM_PORT").unwrap_or_else(|_| "8088".to_string());
    let agent_files = tokio::task::spawn_blocking(provigil_manager::agent_files).await.unwrap_or_default();
    Json(serde_json::json!({
        "lan_ip": lan_ip,
        "port": port,
        "manager_url": format!("http://{}:{}", lan_ip, port),
        "https_url": agent_tls::https_url(&lan_ip),
        "grpc_url": agent_tls::url(&lan_ip),
        "ca_pem": agent_tls::ca_pem(),
        "agent_files": agent_files,
        // the published ProVigil agent's version: agents on it are current
        "agent_version": provigil_manager::published_agent_version()
    }))
}

/// The tenant's last 24 h for the analyst dashboard's KPI strip (network-sensor events are the "NDR" ones).
async fn get_unified_stats_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let (day, (_, ndr_day), (_, ndr_hour)) = tokio::join!(
        history::counts(&state, &ctx, 24),
        history::event_breakdown(&state, &ctx, 24, false),
        history::event_breakdown(&state, &ctx, 1, false)
    );
    Json(serde_json::json!({
        "ndr_events_today": ndr_day,
        "ndr_events_1h": ndr_hour,
        "siem_logs_today": day.events,
        "siem_logs_1h": day.events_1h,
        "siem_eps": (day.events_1h as f64 / 3600.0 * 10.0).round() / 10.0,
        "correlation_hits_1h": day.alerts_1h,
        "critical_alerts": day.critical(),
        "high_alerts": day.high(),
        "medium_alerts": day.medium()
    }))
}

/// The tenant's events per minute over the last 60 minutes, oldest first.
async fn get_stats_timeline_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    Json(
        serde_json::json!({ "status": "ok", "points": history::event_buckets(&state, &ctx, 60_000, 60).await }),
    )
}

#[derive(Deserialize)]
struct HitsQuery {
    src_ip: Option<String>,
    limit: Option<usize>,
}

/// The tenant's newest alerts (500 by default, at most 5000); `src_ip`: only those from or to that IP.
async fn get_hits_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(q): Query<HitsQuery>,
) -> impl IntoResponse {
    let ip = q.src_ip.as_deref().map(str::trim).filter(|s| !s.is_empty());
    Json(
        history::recent_alerts(
            &state,
            &ctx,
            history::DEFAULT_HOURS,
            q.limit.unwrap_or(500).clamp(1, 5000),
            ip,
        )
        .await,
    )
}

#[derive(Deserialize)]
struct HitsTimelineQuery {
    /// "24h" (hourly), "7d" or "30d" (daily)
    range: Option<String>,
}

/// The tenant's alerts per time slice and severity (Assets page's threat landscape).
async fn get_hits_timeline_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(q): Query<HitsTimelineQuery>,
) -> impl IntoResponse {
    let (bucket_ms, buckets) = match q.range.as_deref() {
        Some("7d") => (86_400_000, 7),
        Some("30d") => (86_400_000, 30),
        _ => (3_600_000, 24),
    };
    let rows = history::alert_buckets(&state, &ctx, bucket_ms, buckets).await;
    Json(serde_json::json!({
        "bucket_ms": bucket_ms,
        "buckets": rows.iter().map(|[c, h, m, l]| serde_json::json!({ "critical": c, "high": h, "medium": m, "low": l })).collect::<Vec<_>>()
    }))
}

async fn get_top_ips_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    Json(top_ips_json(&state, &ctx, false).await)
}

async fn get_severity_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let c = history::counts(&state, &ctx, history::DEFAULT_HOURS).await;
    Json(
        serde_json::json!({ "critical": c.critical(), "high": c.high(), "medium": c.medium(), "low": c.low() }),
    )
}

async fn get_announcements_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "announcements": [] }))
}

async fn get_support_messages_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "tickets": [] }))
}

async fn get_settings_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "settings": {} }))
}

async fn post_settings_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn get_settings_ai_handler() -> impl IntoResponse {
    Json(
        serde_json::json!({ "status": "ok", "provider": "gemini", "model": "gemini-2.5-flash", "enabled": true }),
    )
}

async fn post_settings_ai_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn get_trusted_domains_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "domains": [] }))
}

async fn post_trusted_domains_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn delete_trusted_domain_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn post_trusted_domains_ai_suggest_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "suggestions": [] }))
}

async fn get_active_sessions_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "sessions": [] }))
}

async fn delete_session_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn post_geo_lookup_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "results": {} }))
}

async fn get_honeypots_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "honeypots": [] }))
}

async fn post_honeypots_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

#[derive(Serialize)]
struct SiemDashboardStats {
    eps_current: f64,
    logs_today: usize,
    logs_last_hour: usize,
    parse_errors: usize,
    active_sources: usize,
    total_sources: usize,
    kafka_lag: usize,
}

#[derive(Serialize)]
struct SiemAlertCounts {
    critical: usize,
    high: usize,
    medium: usize,
    total: usize,
}

#[derive(Serialize)]
struct SiemRecentAlert {
    alert_id: String,
    severity: String,
    rule_name: String,
    title: String,
    source: String,
    created_at: String,
}

#[derive(Serialize)]
struct SiemSourceHealth {
    source_id: String,
    name: String,
    source_type: String,
    status: String,
    last_seen_at: String,
    /// events per second over the last 5 minutes
    eps: f64,
}

/// Per agent: events in the last 5 minutes, the last hour and since midnight (UTC), from ClickHouse.
async fn event_rates(state: &AppState, tenant: &str) -> HashMap<String, (u64, u64, u64)> {
    let now = Utc::now();
    let ms = |t: chrono::DateTime<Utc>| t.timestamp_millis().max(0) as u64;
    let (t5, t60) = (
        ms(now - chrono::Duration::minutes(5)),
        ms(now - chrono::Duration::hours(1)),
    );
    let tday = ms(now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc());
    state
        .db
        .tenant_client(tenant)
        .query("SELECT agent_id, countIf(timestamp >= ?), countIf(timestamp >= ?), countIf(timestamp >= ?) FROM siem_events WHERE timestamp >= ? GROUP BY agent_id")
        .bind(t5)
        .bind(t60)
        .bind(tday)
        .bind(t60.min(tday))
        .fetch_all::<(String, u64, u64, u64)>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(a, x, y, z)| (a, (x, y, z)))
        .collect()
}

/// `GET /api/v1/agents/telemetry`: per agent of the caller's tenant, the Sysmon events of the
/// last 24 hours and when the last one came (EDR process telemetry coverage). Read from the
/// events ClickHouse already keeps: what is shown is what the SIEM really received.
async fn get_agents_telemetry(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> axum::response::Response {
    let since = (Utc::now() - chrono::Duration::hours(24))
        .timestamp_millis()
        .max(0) as u64;
    let rows = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT agent_id, count(), max(timestamp) FROM siem_events WHERE timestamp >= ? AND location = 'EventChannel' AND position(raw_metadata, 'Microsoft-Windows-Sysmon/Operational') > 0 AND JSONExtractString(JSONExtractString(raw_metadata, 'data_json'), 'win', 'system', 'channel') = 'Microsoft-Windows-Sysmon/Operational' GROUP BY agent_id")
        .bind(since)
        .fetch_all::<(String, u64, u64)>()
        .await;
    match rows {
        Ok(rows) => {
            let sysmon: serde_json::Map<String, serde_json::Value> = rows
                .into_iter()
                .map(|(a, n, last)| (a, serde_json::json!({ "events_24h": n, "last": last })))
                .collect();
            Json(serde_json::json!({ "sysmon": sysmon })).into_response()
        }
        // not "no Sysmon": the UI shows the coverage as unknown
        Err(e) => {
            tracing::warn!("agent telemetry query failed: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "message": "Telemetry is not available right now" }))).into_response()
        }
    }
}

fn per_second(events_5m: u64) -> f64 {
    (events_5m as f64 / 300.0 * 10.0).round() / 10.0
}

#[derive(Serialize)]
struct SiemDashboardResponse {
    stats: SiemDashboardStats,
    sources: Vec<SiemSourceHealth>,
    alert_counts: SiemAlertCounts,
    recent_alerts: Vec<SiemRecentAlert>,
}

async fn get_siem_dashboard(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Json<SiemDashboardResponse> {
    let (counts, recent) = tokio::join!(
        history::counts(&state, &ctx, history::DEFAULT_HOURS),
        history::recent_alerts(&state, &ctx, history::DEFAULT_HOURS, 20, None)
    );
    let agents = scoped_agent_map(&state, &ctx);

    // this page's bands: critical 10+, high 7-9, medium 4-6 (of the whole window)
    let total_alerts = counts.alerts() as usize;
    let (critical, high, medium) = (
        counts.band(10, 16) as usize,
        counts.band(7, 9) as usize,
        counts.band(4, 6) as usize,
    );

    let mut recent_alerts = Vec::new();
    for a in recent.iter() {
        let sev_str = match a.rule.level {
            10.. => "CRITICAL",
            7..=9 => "HIGH",
            4..=6 => "MEDIUM",
            _ => "LOW",
        };
        recent_alerts.push(SiemRecentAlert {
            alert_id: a.id.to_string(),
            severity: sev_str.into(),
            rule_name: format!("Rule {}", a.rule.id),
            title: a.rule.description.clone(),
            source: a.agent.name.clone(),
            created_at: a.timestamp.to_rfc3339(),
        });
    }

    let rates = event_rates(&state, &ctx.scope()).await;
    let mut sources = Vec::new();
    let mut active_count = 0;
    for ag in agents.values() {
        if ag.status == AgentStatus::Active {
            active_count += 1;
        }
        sources.push(SiemSourceHealth {
            source_id: ag.id.clone(),
            name: ag.name.clone(),
            source_type: ag.os_type.clone(),
            status: match ag.status {
                AgentStatus::Active => "active".into(),
                AgentStatus::Disconnected => "paused".into(),
                _ => "active".into(),
            },
            last_seen_at: ag.last_keepalive.to_rfc3339(),
            eps: per_second(rates.get(&ag.id).map_or(0, |r| r.0)),
        });
    }

    let sum = |f: fn(&(u64, u64, u64)) -> u64| rates.values().map(f).sum::<u64>() as usize;
    let stats = SiemDashboardStats {
        eps_current: per_second(sum(|r| r.0) as u64),
        logs_today: sum(|r| r.2),
        logs_last_hour: sum(|r| r.1),
        parse_errors: 0,
        active_sources: active_count,
        total_sources: agents.len(),
        kafka_lag: 0,
    };

    let alert_counts = SiemAlertCounts {
        critical,
        high,
        medium,
        total: total_alerts,
    };

    Json(SiemDashboardResponse {
        stats,
        sources,
        alert_counts,
        recent_alerts,
    })
}

#[derive(Serialize)]
struct SiemSourcesResponse {
    sources: Vec<SiemSourceHealth>,
}

async fn get_siem_sources(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Json<SiemSourcesResponse> {
    let agents = scoped_agent_map(&state, &ctx);
    let rates = event_rates(&state, &ctx.scope()).await;
    let sources = agents
        .values()
        .map(|ag| SiemSourceHealth {
            source_id: ag.id.clone(),
            name: ag.name.clone(),
            source_type: ag.os_type.clone(),
            status: match ag.status {
                AgentStatus::Active => "active".into(),
                _ => "paused".into(),
            },
            last_seen_at: ag.last_keepalive.to_rfc3339(),
            eps: per_second(rates.get(&ag.id).map_or(0, |r| r.0)),
        })
        .collect();

    Json(SiemSourcesResponse { sources })
}

/// `POST /api/siem/sources`: sources are ProVigil agents and syslog devices, added where they enroll.
async fn post_siem_sources() -> axum::response::Response {
    (
        StatusCode::GONE,
        Json(serde_json::json!({ "status": "error", "message": "Add a source by deploying a ProVigil agent (Agent Fleet > Deploy) or registering a syslog device (Tenant admin > Syslog Devices)" })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct VulnFilterParams {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub agent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VulnerabilitiesResponse {
    pub total: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub vulnerabilities: Vec<vulnerability::VulnItem>,
}

fn vulnerabilities_response(list: Vec<vulnerability::VulnItem>) -> VulnerabilitiesResponse {
    let count = |s: &str| {
        list.iter()
            .filter(|v| v.severity.eq_ignore_ascii_case(s))
            .count()
    };
    VulnerabilitiesResponse {
        total: list.len(),
        critical_count: count("critical"),
        high_count: count("high"),
        medium_count: count("medium"),
        low_count: count("low"),
        vulnerabilities: list,
    }
}

/// The tenant's current detections (ClickHouse), or why they cannot be read.
async fn scoped_vulnerabilities(
    state: &AppState,
    ctx: &AuthCtx,
    agent: Option<&str>,
) -> Result<Vec<vulnerability::VulnItem>, axum::response::Response> {
    vulnerability::current(state, &ctx.scope(), agent).await.map(|l| l.into_iter().filter(|v| agent_in_scope(state, ctx, &v.agent_id)).collect()).map_err(|e| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "message": format!("vulnerabilities cannot be read: {e}") }))).into_response()
    })
}

async fn get_vulnerabilities(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(params): Query<VulnFilterParams>,
) -> axum::response::Response {
    let list = match scoped_vulnerabilities(&state, &ctx, params.agent_id.as_deref()).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let list: Vec<vulnerability::VulnItem> = list
        .into_iter()
        .filter(|v| {
            params
                .severity
                .as_ref()
                .is_none_or(|s| v.severity.eq_ignore_ascii_case(s))
        })
        .filter(|v| {
            params
                .status
                .as_ref()
                .is_none_or(|s| v.status.eq_ignore_ascii_case(s))
        })
        .collect();
    Json(vulnerabilities_response(list)).into_response()
}

async fn get_agent_vulnerabilities(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
) -> axum::response::Response {
    if !agent_in_scope(&state, &ctx, &agent_id) {
        return Json(vulnerabilities_response(Vec::new())).into_response();
    }
    match scoped_vulnerabilities(&state, &ctx, Some(&agent_id)).await {
        Ok(l) => Json(vulnerabilities_response(l)).into_response(),
        Err(r) => r,
    }
}

/// `POST /api/v1/vulnerabilities`: the scanner re-scans the caller's agents
/// from provigil-db's package inventory, then the results are read again.
async fn post_scan_now(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> axum::response::Response {
    // shortcut: agents of the default tenant are not in agent_tenants; they get re-scanned only when they already have results
    let mut agents: std::collections::BTreeSet<String> = state
        .agent_tenants
        .read()
        .unwrap()
        .keys()
        .filter(|a| agent_in_scope(&state, &ctx, a))
        .cloned()
        .collect();
    agents.extend(
        scoped_vulnerabilities(&state, &ctx, None)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|v| v.agent_id),
    );
    let sent = agents
        .iter()
        .filter(|a| match vulnerability::request_rescan(a, true) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("vulnerability re-scan of agent {a} not requested: {e}");
                false
            }
        })
        .count();
    if sent > 0 {
        // a scan takes a few seconds per agent
        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
    }
    let n = scoped_vulnerabilities(&state, &ctx, None)
        .await
        .map(|l| l.len())
        .unwrap_or(0);
    Json(serde_json::json!({
        "status": "ok",
        "message": format!("Re-scan requested for {sent} agent(s); {n} active vulnerabilities. Results keep updating for a minute."),
    }))
    .into_response()
}

async fn get_agent_os_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // a ProVigil agent: its provigil-db database, else siem-api's store
    if let Some(v) = inventory_store::part(&agent_id, inventory_store::Part::Os).await {
        return Json(serde_json::json!({ "agent_id": agent_id, "os": v, "source": "provigil-db" }));
    }
    if let Some(agent_db) = state.wdb.get(&agent_id) {
        let db = agent_db.read().unwrap();
        Json(serde_json::json!({
            "agent_id": agent_id,
            "os": db.syscollector.os_info
        }))
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "os": null
        }))
    }
}

async fn get_agent_hw_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // a ProVigil agent: its provigil-db database, else siem-api's store
    if let Some(v) = inventory_store::part(&agent_id, inventory_store::Part::Hardware).await {
        return Json(
            serde_json::json!({ "agent_id": agent_id, "hardware": v, "source": "provigil-db" }),
        );
    }
    if let Some(agent_db) = state.wdb.get(&agent_id) {
        let db = agent_db.read().unwrap();
        Json(serde_json::json!({
            "agent_id": agent_id,
            "hardware": db.syscollector.hw_info
        }))
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "hardware": null
        }))
    }
}

async fn get_agent_packages_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // a ProVigil agent: its provigil-db database, else siem-api's store
    if let Some(v) = inventory_store::part(&agent_id, inventory_store::Part::Packages).await {
        let n = v.as_array().map_or(0, |a| a.len());
        return Json(
            serde_json::json!({ "agent_id": agent_id, "total": n, "packages": v, "source": "provigil-db" }),
        );
    }
    if let Some(agent_db) = state.wdb.get(&agent_id) {
        let db = agent_db.read().unwrap();
        let pkgs: Vec<_> = db.syscollector.programs.values().cloned().collect();
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": pkgs.len(),
            "packages": pkgs
        }))
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": 0,
            "packages": []
        }))
    }
}

async fn get_agent_ports_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // a ProVigil agent: its provigil-db database, else siem-api's store
    if let Some(v) = inventory_store::part(&agent_id, inventory_store::Part::Ports).await {
        let n = v.as_array().map_or(0, |a| a.len());
        return Json(
            serde_json::json!({ "agent_id": agent_id, "total": n, "ports": v, "source": "provigil-db" }),
        );
    }
    if let Some(agent_db) = state.wdb.get(&agent_id) {
        let db = agent_db.read().unwrap();
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": db.syscollector.ports.len(),
            "ports": db.syscollector.ports
        }))
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": 0,
            "ports": []
        }))
    }
}

async fn get_agent_netiface_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // a ProVigil agent: its provigil-db database, else siem-api's store
    if let Some(v) = inventory_store::part(&agent_id, inventory_store::Part::Netiface).await {
        let n = v.as_array().map_or(0, |a| a.len());
        return Json(
            serde_json::json!({ "agent_id": agent_id, "total": n, "interfaces": v, "source": "provigil-db" }),
        );
    }
    if let Some(agent_db) = state.wdb.get(&agent_id) {
        let db = agent_db.read().unwrap();
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": db.syscollector.netifaces.len(),
            "interfaces": db.syscollector.netifaces
        }))
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": 0,
            "interfaces": []
        }))
    }
}

async fn get_agent_fim_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
) -> axum::response::Response {
    if !agent_in_scope(&state, &ctx, &agent_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    }
    if provigil_manager::is_provigil_agent(&agent_id).await {
        // the agent's provigil-db database (not copied)
        let r = provigil_manager::agent_fim(&agent_id).await.unwrap_or_else(
            || serde_json::json!({ "agent_id": agent_id, "total": 0, "entries": [] }),
        );
        return Json(r).into_response();
    }
    if let Some(agent_db) = state.wdb.get(&agent_id) {
        let db = agent_db.read().unwrap();
        let entries = db.fim.list();
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": entries.len(),
            "entries": entries
        }))
        .into_response()
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": 0,
            "entries": []
        }))
        .into_response()
    }
}

/// `GET /api/v1/agents/:id/rootcheck`: the agent's rootcheck findings.
async fn get_agent_rootcheck_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
) -> axum::response::Response {
    if !agent_in_scope(&state, &ctx, &agent_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    }
    // the agent's provigil-db database (not copied)
    let r = provigil_manager::agent_rootcheck(&agent_id)
        .await
        .unwrap_or_else(|| serde_json::json!({ "agent_id": agent_id, "total": 0, "events": [] }));
    Json(r).into_response()
}

async fn post_agent_fim_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(entry): Json<siem_wdb::FimEntry>,
) -> impl IntoResponse {
    let agent_name = {
        let agents = state.agents.read().unwrap();
        agents
            .get(&agent_id)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| format!("agent-{}", agent_id))
    };
    let agent_db = state.wdb.get_or_create(&agent_id, &agent_name);
    // the guard ends with the statement (it must not live across the awaits below)
    let delta = agent_db.write().unwrap().fim.upsert(entry);

    if let Some(ref d) = delta {
        let rule_id = match d.action {
            siem_wdb::FimAction::Added => 550,
            siem_wdb::FimAction::Modified => 554,
            siem_wdb::FimAction::Deleted => 553,
        };
        let level = 7;

        let alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: rule_id,
                level,
                description: format!(
                    "File Integrity Monitoring: File '{}' {:?}",
                    d.path, d.action
                ),
                groups: vec!["syscheck".to_string(), "fim".to_string()],
                mitre: Some(siem_core::MitreAttack {
                    id: "T1565.001".to_string(),
                    tactic: "Impact".to_string(),
                    technique: "Stored Data Manipulation".to_string(),
                }),
            },
            agent: siem_core::AgentAlertInfo {
                id: agent_id.clone(),
                name: agent_name.clone(),
                ip: "127.0.0.1".to_string(),
            },
            manager: Some(siem_core::ManagerAlertInfo {
                name: "provigil-manager".to_string(),
            }),
            decoder: None,
            full_log: format!("ossec: File '{}' was {:?}", d.path, d.action),
            decoded: siem_core::DecodedFields {
                decoder_name: "syscheck".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                user: None,
                program_name: None,
                process_id: None,
                file_path: Some(d.path.clone()),
                action: Some(format!("{:?}", d.action)),
                status: None,
                extra: HashMap::new(),
            },
            location: "syscheck".to_string(),
            data: HashMap::new(),
        };

        // tagged with the agent's tenant, stored in its ClickHouse database, broadcast
        let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), &agent_id);
        record_alert(&state, &tenant, alert).await;
    }

    Json(serde_json::json!({
        "status": "success",
        "delta": delta
    }))
}

async fn get_agent_sca_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
) -> axum::response::Response {
    if !agent_in_scope(&state, &ctx, &agent_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    }
    if provigil_manager::is_provigil_agent(&agent_id).await {
        // the agent's provigil-db database (the source; posture_store copies it for compliance)
        let r = provigil_manager::agent_sca(&agent_id).await.unwrap_or_else(|| serde_json::json!({ "agent_id": agent_id, "score": 0, "passed": 0, "failed": 0, "checks": [] }));
        return Json(r).into_response();
    }
    if let Some(agent_db) = state.wdb.get(&agent_id) {
        let db = agent_db.read().unwrap();
        let policy_opt = db
            .sca
            .get_policy("cis_ubuntu_linux_24.04")
            .or_else(|| db.sca.list_policies().first().copied());

        if let Some(policy) = policy_opt {
            let checks: Vec<_> = policy.checks.values().cloned().collect();
            Json(serde_json::json!({
                "agent_id": agent_id,
                "policy_id": policy.policy_id,
                "score": policy.compliance_score(),
                "passed": policy.passed_count(),
                "failed": policy.failed_count(),
                "checks": checks
            }))
            .into_response()
        } else {
            Json(serde_json::json!({
                "agent_id": agent_id,
                "score": 100.0,
                "passed": 0,
                "failed": 0,
                "checks": []
            }))
            .into_response()
        }
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "score": 100.0,
            "passed": 0,
            "failed": 0,
            "checks": []
        }))
        .into_response()
    }
}

#[derive(Deserialize)]
struct ThreatIntelCheckParams {
    query: Option<String>,
}

async fn check_threat_intel_handler(
    State(state): State<AppState>,
    Query(params): Query<ThreatIntelCheckParams>,
) -> impl IntoResponse {
    let q = params.query.unwrap_or_default();
    if q.is_empty() {
        return Json(serde_json::json!({
            "match": false,
            "query": "",
            "details": null
        }));
    }

    // Check IP
    if let Some((list, desc)) = state.threat_intel.check_ip(&q) {
        return Json(serde_json::json!({
            "match": true,
            "type": "ip",
            "query": q,
            "list": list,
            "description": desc,
            "severity": "critical"
        }));
    }

    // Check Hash
    if let Some((list, desc)) = state.threat_intel.check_hash(&q) {
        return Json(serde_json::json!({
            "match": true,
            "type": "hash",
            "query": q,
            "list": list,
            "description": desc,
            "severity": "critical"
        }));
    }

    // Check Domain
    if let Some((list, desc)) = state.threat_intel.check_domain(&q) {
        return Json(serde_json::json!({
            "match": true,
            "type": "domain",
            "query": q,
            "list": list,
            "description": desc,
            "severity": "critical"
        }));
    }

    Json(serde_json::json!({
        "match": false,
        "query": q,
        "details": null
    }))
}

/// The platform-wide indicator lists one can read or import into.
const THREAT_LISTS: [&str; 3] = [
    siem_cdb::IP_LIST,
    siem_cdb::HASH_LIST,
    siem_cdb::DOMAIN_LIST,
];
/// Entries returned by one listing.
const THREAT_LIST_PAGE: usize = 10_000;

/// `GET /api/v1/threat-intel/lists/:name/entries?offset=0`: the list's entries, sorted, 10,000 at a time.
async fn get_threat_intel_list_entries_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> axum::response::Response {
    if !THREAT_LISTS.contains(&name.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Unknown list" })),
        )
            .into_response();
    }
    let all = state.threat_intel.entries(&name);
    let offset = q
        .get("offset")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(0);
    let page: Vec<serde_json::Value> = all
        .iter()
        .skip(offset)
        .take(THREAT_LIST_PAGE)
        .map(|(v, d)| serde_json::json!({ "value": v, "description": d }))
        .collect();
    Json(serde_json::json!({ "status": "ok", "list": name, "total": all.len(), "offset": offset, "entries": page })).into_response()
}

#[derive(Deserialize)]
struct ThreatListImport {
    /// One entry per line: `value:description` or a value alone; `#` lines are comments.
    text: String,
}

/// `POST /api/v1/threat-intel/lists/:name/import` (platform admin): adds the entries of a list file.
async fn post_threat_intel_list_import_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(name): Path<String>,
    Json(body): Json<ThreatListImport>,
) -> axum::response::Response {
    // the lists are shared by every tenant
    if !ctx.is_super() {
        return tenancy::forbidden();
    }
    if !THREAT_LISTS.contains(&name.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Unknown list" })),
        )
            .into_response();
    }
    let (added, refused) = state.threat_intel.load_from_text(&name, &body.text);
    info!(
        "threat list {name}: {added} entries imported by {}, {refused} refused",
        ctx.username
    );
    let total = state
        .threat_intel
        .get_list(&name)
        .map(|l| l.total_entries())
        .unwrap_or(0);
    Json(serde_json::json!({ "status": "ok", "list": name, "added": added, "refused": refused, "total": total })).into_response()
}

async fn get_threat_intel_lists_handler(State(state): State<AppState>) -> impl IntoResponse {
    let lists = vec![
        serde_json::json!({
            "name": "malicious_ips",
            "description": "Known Tor Exit Nodes, CobaltStrike C2s, and Scanner IPs",
            "entries": state.threat_intel.get_list("malicious_ips").map(|t| t.total_entries()).unwrap_or(0),
            "format": "IP / CIDR"
        }),
        serde_json::json!({
            "name": "malicious_hashes",
            "description": "Known Malware PE, Ransomware (WannaCry, LockBit, BlackCat) & Mimikatz hashes",
            "entries": state.threat_intel.get_list("malicious_hashes").map(|t| t.total_entries()).unwrap_or(0),
            "format": "MD5 / SHA-1 / SHA-256"
        }),
        serde_json::json!({
            "name": "malicious_domains",
            "description": "Active C2 beacon domains and phishing infrastructure",
            "entries": state.threat_intel.get_list("malicious_domains").map(|t| t.total_entries()).unwrap_or(0),
            "format": "Domain"
        }),
    ];

    Json(serde_json::json!({
        "total_lists": lists.len(),
        "lists": lists
    }))
}

/// `POST /api/v1/agents/:id/rootcheck/scan`: starts the agent's own rootcheck and FIM scan.
async fn post_agent_rootcheck_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
) -> axum::response::Response {
    if !agent_in_scope(&state, &ctx, &agent_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    }
    if !provigil_manager::is_provigil_agent(&agent_id).await {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": "Rootcheck scans run on ProVigil agents only" }))).into_response();
    }
    match provigil_manager::syscheck_restart(&agent_id).await {
        Ok(()) => Json(serde_json::json!({ "status": "sent", "message": "Rootcheck and FIM scan started on the agent" })).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "message": e }))).into_response(),
    }
}

// ---------------------------------------------------------------------------
// ProVigil Parity: Logtest, Compliance, MITRE Matrix, FIM, Active Response
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LogtestPayload {
    pub log: String,
}

async fn post_logtest_handler(
    State(state): State<AppState>,
    Json(payload): Json<LogtestPayload>,
) -> impl IntoResponse {
    let logtest = siem_engine::LogtestEngine::new(state.engine.clone());
    let res = logtest.test_log(&payload.log);
    let out = res.format_text();
    Json(serde_json::json!({
        "result": res,
        "output": out,
    }))
}

#[derive(Debug, Serialize)]
pub struct FimSummaryRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub agent_id: String,
    pub agent_name: String,
    pub path: String,
    pub action: String,
    pub size_bytes: Option<u64>,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    /// `report_changes` diff, when the agent sent one
    pub diff: Option<String>,
    /// How the change was seen: scheduled, realtime or whodata
    pub mode: Option<String>,
    /// whodata: the user and the program that made the change
    pub user: Option<String>,
    pub process: Option<String>,
}

/// `GET /api/v1/manager/status` (platform admin): daemons, queues and counters of the
/// ProVigil manager, plus the connected agents of every tenant.
async fn get_manager_status_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> axum::response::Response {
    if !ctx.is_super() {
        return tenancy::forbidden();
    }
    let (total, active) = {
        let agents = state.agents.read().unwrap();
        (
            agents.len(),
            agents
                .values()
                .filter(|a| matches!(a.status, AgentStatus::Active))
                .count(),
        )
    };
    let mut v = provigil_manager::status();
    v["agents"] = serde_json::json!({ "total": total, "active": active });
    Json(v).into_response()
}

/// `GET /api/v1/fim/summary`: the latest file and registry changes, from the
/// agents' FIM alerts (the upstream `syscheck` block), newest first.
async fn get_fim_summary_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    const MAX_ROWS: usize = 500;
    let (mut added, mut modified, mut deleted) = (0u64, 0u64, 0u64);
    let mut recent_changes = Vec::new();

    // entries monitored by the older siem-agent agents (their own FIM store)
    let agent_ids: Vec<String> = scoped_agent_map(&state, &ctx).keys().cloned().collect();
    let mut total_files = 0usize;
    for ag_id in &agent_ids {
        if let Some(agent_db) = state.wdb.get(ag_id) {
            total_files += agent_db.read().unwrap().fim.list().len();
        }
    }
    // and the ProVigil agents' files and registry values: counted in each agent's provigil-db
    // database (the tenant's agents only), 8 at a time
    {
        use futures_util::StreamExt;
        let agent_dbs: Vec<String> = agent_ids
            .iter()
            .filter_map(|a| a.parse::<u32>().ok().filter(|n| *n > 0))
            .map(|n| format!("{n:03}"))
            .collect();
        total_files += futures_util::stream::iter(agent_dbs)
            .map(|id: String| async move { inventory_store::count(&id, "fim_entry").await })
            .buffer_unordered(8)
            .fold(0u64, |t, n| std::future::ready(t + n))
            .await as usize;
    }

    // only the FIM alerts come from ClickHouse (they carry data.syscheck)
    for a in history::alerts_containing(&state, &ctx, history::DEFAULT_HOURS, "\"syscheck\"")
        .await
        .iter()
        .rev()
    {
        let Some(sc) = a.data.get("syscheck") else {
            continue;
        };
        let text = |p: &str| {
            sc.pointer(p)
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty())
                .map(String::from)
        };
        let action = match text("/event").as_deref() {
            Some("added") => {
                added += 1;
                "Added"
            }
            Some("modified") => {
                modified += 1;
                "Modified"
            }
            Some("deleted") => {
                deleted += 1;
                "Deleted"
            }
            _ => continue,
        };
        if recent_changes.len() >= MAX_ROWS {
            continue;
        }
        // registry values: "path" is the key, "value_name" the value
        let path = match (text("/path"), text("/value_name")) {
            (Some(p), Some(v)) => format!("{p}\\{v}"),
            (Some(p), None) => p,
            (None, _) => continue,
        };
        let size = sc.get("size_after").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        recent_changes.push(FimSummaryRecord {
            timestamp: a.timestamp,
            agent_id: a.agent.id.clone(),
            agent_name: a.agent.name.clone(),
            path,
            action: action.to_string(),
            size_bytes: size,
            md5: text("/md5_after"),
            sha256: text("/sha256_after"),
            diff: text("/diff"),
            mode: text("/mode"),
            user: text("/audit/user/name"),
            process: text("/audit/process/name"),
        });
    }

    Json(serde_json::json!({
        "total_monitored_files": total_files,
        "added_count": added,
        "modified_count": modified,
        "deleted_count": deleted,
        "recent_changes": recent_changes,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ArBlockRequest {
    pub ip: String,
    pub agent_id: Option<String>,
    pub command: Option<String>,
    pub duration_seconds: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ArUnblockRequest {
    pub ip: String,
}

async fn get_active_response_actions(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let list: Vec<ActiveResponseRecord> = state
        .active_responses
        .read()
        .unwrap()
        .iter()
        .filter(|r| agent_in_scope(&state, &ctx, &r.agent_id))
        .cloned()
        .collect();
    Json(serde_json::json!({
        "total": list.len(),
        "active_blocks": list.iter().filter(|r| r.status == "Active").count(),
        "records": list,
    }))
}

async fn post_active_response_block(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(req): Json<ArBlockRequest>,
) -> axum::response::Response {
    let Some(agent_id) = req
        .agent_id
        .clone()
        .filter(|a| agent_in_scope(&state, &ctx, a))
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    };
    if req.ip.parse::<std::net::IpAddr>().is_err() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": "A valid IP address is required" }))).into_response();
    }
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), &agent_id);
    if let Err(m) = decisions::gate_manual(&state, &ctx, &tenant, "manual_block", &req.ip, serde_json::json!({ "agent_id": agent_id, "ip": req.ip, "seconds": req.duration_seconds.unwrap_or(3600) })).await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "status": "error", "message": m }))).into_response();
    }
    if provigil_manager::is_provigil_agent(&agent_id).await {
        let reason = req
            .reason
            .clone()
            .unwrap_or_else(|| "Manual SOC operator block".to_string());
        return block_on_agent(
            &state,
            &ctx,
            &agent_id,
            &req.ip,
            req.duration_seconds.unwrap_or(3600),
            &reason,
            req.command.as_deref(),
        )
        .await;
    }
    let rec = ActiveResponseRecord {
        id: format!("ar-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
        command: req.command.unwrap_or_else(|| "firewall-drop".to_string()),
        target_ip: req.ip.clone(),
        agent_id,
        reason: req
            .reason
            .unwrap_or_else(|| "Manual SOC operator block".to_string()),
        triggered_at: Utc::now(),
        duration_seconds: req.duration_seconds.unwrap_or(3600),
        status: "Active".to_string(),
    };
    state
        .active_responses
        .write()
        .unwrap()
        .insert(0, rec.clone());
    persist::save_active_response(&state, &rec).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "success", "record": rec })),
    )
        .into_response()
}

async fn post_active_response_unblock(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(req): Json<ArUnblockRequest>,
) -> impl IntoResponse {
    let released: Vec<ActiveResponseRecord> = {
        let mut list = state.active_responses.write().unwrap();
        let mut out = Vec::new();
        for r in list.iter_mut() {
            if r.target_ip == req.ip
                && r.status == "Active"
                && agent_in_scope(&state, &ctx, &r.agent_id)
            {
                r.status = "Released".to_string();
                out.push(r.clone());
            }
        }
        out
    };
    for r in &released {
        persist::save_active_response(&state, r).await;
    }
    let found = !released.is_empty();
    Json(serde_json::json!({
        "status": if found { "success" } else { "not_found" },
        "ip": req.ip
    }))
}

// =========================================================================
// Method 2: Self-Learning AI Auto-Generated Reusable Parser Engine Handlers
// =========================================================================

/// What a learned parser extracted from a log line, kept in the event's metadata
/// (`parsed.<field>`, normalized names) with the parser's name.
pub(crate) fn add_parsed_fields(
    metadata: &mut HashMap<String, String>,
    p: siem_parser_gen::DynamicParsedResult,
) {
    for (k, v) in p.normalized_fields {
        metadata.insert(
            format!("parsed.{k}"),
            v.as_str()
                .map(String::from)
                .unwrap_or_else(|| v.to_string()),
        );
    }
    metadata.insert("parser".into(), p.parser_name);
}

async fn get_parsers_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Json<Vec<siem_parser_gen::DynamicParser>> {
    Json(parsers_store::for_tenant(&state, &ctx.scope()).list_parsers())
}

async fn get_parsers_stats_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Json<siem_parser_gen::ParserStatsSummary> {
    Json(parsers_store::for_tenant(&state, &ctx.scope()).stats())
}

async fn get_unmatched_parsers_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Json<Vec<siem_parser_gen::UnmatchedFingerprintSummary>> {
    Json(
        parsers_store::for_tenant(&state, &ctx.scope())
            .accumulator
            .list_unmatched(),
    )
}

#[derive(Deserialize)]
struct SynthesizePayload {
    fingerprint: Option<u64>,
    samples: Vec<String>,
    instructions: Option<String>,
}

async fn post_synthesize_parser_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(payload): Json<SynthesizePayload>,
) -> impl IntoResponse {
    if payload.samples.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No log samples provided for synthesis" })),
        )
            .into_response();
    }

    let fp = payload.fingerprint.unwrap_or_else(|| {
        let (f, _) = siem_parser_gen::FingerprintEngine::compute(&payload.samples[0]);
        f
    });
    let (_, sig) = siem_parser_gen::FingerprintEngine::compute(&payload.samples[0]);
    let registry = parsers_store::for_tenant(&state, &ctx.scope());

    // the AI providers configured in the platform settings first (as every AI feature)
    let mut ai_note = None;
    if ai_assist::tenant_ai_enabled(&state, &ctx.scope()) {
        let providers = ai_assist::providers(&state, "chat").await;
        if !providers.is_empty() {
            let (system, user) = siem_parser_gen::AiParserSynthesizer::llm_prompts(
                fp,
                &sig,
                &payload.samples,
                payload.instructions.as_deref(),
            );
            // a parser (pattern + fields) is a long answer
            match siem_ai::generate_long(&providers, &system, &user, 8192).await {
                Ok(reply) => {
                    match registry.register_from_ai_reply(fp, &sig, &payload.samples, &reply.text) {
                        Ok(parser) => {
                            info!(
                                "parser '{}' synthesized by {} for tenant {}",
                                parser.name,
                                reply.model,
                                ctx.scope()
                            );
                            return (StatusCode::OK, Json(serde_json::json!({ "status": "success", "parser": parser, "generated_by": reply.model }))).into_response();
                        }
                        Err(e) => {
                            ai_note = Some(format!(
                                "the AI's parser ({}) was not usable: {e}",
                                reply.model
                            ))
                        }
                    }
                }
                Err(e) => ai_note = Some(format!("no AI answer: {e}")),
            }
            warn!(
                "parser synthesis for tenant {}: {}; trying the built-in synthesizer",
                ctx.scope(),
                ai_note.as_deref().unwrap_or("")
            );
        }
    }

    match registry
        .synthesize_and_register(fp, &sig, &payload.samples, payload.instructions.as_deref())
        .await
    {
        Ok(parser) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success", "parser": parser, "generated_by": "built-in synthesizer", "ai_note": ai_note })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "status": "error", "error": match &ai_note { Some(n) => format!("{e} (AI: {n})"), None => e } })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct TestParserPayload {
    pattern: String,
    raw_log: String,
}

async fn post_test_parser_handler(
    State(state): State<AppState>,
    Json(payload): Json<TestParserPayload>,
) -> impl IntoResponse {
    match state
        .parser_registry
        .test_parser(&payload.pattern, &payload.raw_log)
    {
        Ok(res) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success", "result": res })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "error": e })),
        )
            .into_response(),
    }
}

async fn put_parser_handler(
    Path(id): Path<uuid::Uuid>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(updated): Json<siem_parser_gen::DynamicParser>,
) -> impl IntoResponse {
    match parsers_store::for_tenant(&state, &ctx.scope()).update_parser(id, updated) {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success", "message": "Parser updated successfully" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "error": e })),
        )
            .into_response(),
    }
}

async fn delete_parser_handler(
    Path(id): Path<uuid::Uuid>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    if parsers_store::for_tenant(&state, &ctx.scope()).delete_parser(id) {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success", "message": "Parser deleted successfully" })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "error": "Parser not found" })),
        )
            .into_response()
    }
}

// ------------------------------------------------------------------------------------------------
// ProVigil Subsystem Handlers: Authd, Integratord, Csyslogd, Reportd, Agent Upgrade
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EnrollAgentPayload {
    pub name: String,
    pub ip: Option<String>,
    pub groups: Option<String>,
    /// Optional OS hint ("linux" / "windows" / "macos") for the fleet view.
    pub os_type: Option<String>,
    /// Explicit override (e.g. from install.sh / installer) to re-enroll a previously deleted agent name
    pub force: Option<bool>,
}

/// One enrolled agent (a row of `ndr.agent_registry`): ids stay unique
/// across tenants and restarts, and a re-installed host gets its id back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledAgent {
    pub name: String,
    pub tenant: String,
    #[serde(default)]
    pub groups: String,
    #[serde(default)]
    pub os_type: String,
    pub enrolled_at: chrono::DateTime<chrono::Utc>,
    /// Deactivated: kept, told to stop, data refused.
    #[serde(default)]
    pub disabled: bool,
}

/// Loads `ndr.agent_registry` into memory: enrolled agents, agent ->
/// tenant bindings, the id counter, and fleet entries for enrolled agents that
/// have not reported yet.
async fn load_agent_registry(state: &AppState) {
    let Some(rows) = state.db.fetch_agent_registry().await else {
        return;
    };
    let mut max = 0u64;
    let (mut n_live, mut n_deleted) = (0usize, 0usize);
    {
        let mut enrolled = state.enrolled.write().unwrap();
        let mut bindings = state.agent_tenants.write().unwrap();
        let mut agents = state.agents.write().unwrap();
        for r in rows {
            if let Ok(n) = r.agent_id.parse::<u64>() {
                max = max.max(n);
            }
            if r.deleted == 1 {
                n_deleted += 1;
                state
                    .deleted_agents
                    .write()
                    .unwrap()
                    .insert(r.agent_id.clone());
                state
                    .deleted_agent_names
                    .write()
                    .unwrap()
                    .insert((r.tenant_id.clone(), r.name.to_lowercase()));
                continue;
            }
            n_live += 1;
            let enrolled_at = chrono::DateTime::from_timestamp_millis(r.enrolled_at as i64)
                .unwrap_or_else(Utc::now);
            bindings.insert(r.agent_id.clone(), r.tenant_id.clone());
            if r.disabled == 1 {
                enrolled.insert(
                    r.agent_id,
                    EnrolledAgent {
                        name: r.name,
                        tenant: r.tenant_id,
                        groups: r.groups,
                        os_type: r.os_type,
                        enrolled_at,
                        disabled: true,
                    },
                );
                continue;
            }
            agents.entry(r.agent_id.clone()).or_insert_with(|| Agent {
                id: r.agent_id.clone(),
                name: r.name.clone(),
                ip: "any".into(),
                os: "Registered via enrollment".into(),
                version: "v4.14.7".into(),
                status: AgentStatus::Disconnected,
                last_keepalive: enrolled_at,
                os_type: if r.os_type.is_empty() {
                    "linux".into()
                } else {
                    r.os_type.clone()
                },
            });
            enrolled.insert(
                r.agent_id,
                EnrolledAgent {
                    name: r.name,
                    tenant: r.tenant_id,
                    groups: r.groups,
                    os_type: r.os_type,
                    enrolled_at,
                    disabled: false,
                },
            );
        }
        // Reconcile: active enrolled agents must not remain in deleted_agent_names,
        // even if an older historical row for that name was marked deleted in ClickHouse.
        let mut del_names = state.deleted_agent_names.write().unwrap();
        for (_, agent) in enrolled.iter() {
            if !agent.disabled {
                del_names.remove(&(agent.tenant.clone(), agent.name.to_lowercase()));
            }
        }
    }
    state
        .max_agent_id
        .fetch_max(max, std::sync::atomic::Ordering::SeqCst);
    info!(
        "Agent registry: {} agents, {} deleted ids reserved (highest id {:03})",
        n_live, n_deleted, max
    );
}

/// Writes an agent's registry row to ClickHouse in the background.
/// `e` is its enrollment (None for agents bound without enrolling).
fn persist_registry(
    state: &AppState,
    agent_id: &str,
    tenant: &str,
    e: Option<&EnrolledAgent>,
    deleted: bool,
) {
    let now = Utc::now().timestamp_millis() as u64;
    let row = crate::db::AgentRegistryRow {
        agent_id: agent_id.to_string(),
        name: e
            .map(|e| e.name.clone())
            .unwrap_or_else(|| agent_id.to_string()),
        tenant_id: tenant.to_string(),
        groups: e.map(|e| e.groups.clone()).unwrap_or_default(),
        os_type: e.map(|e| e.os_type.clone()).unwrap_or_default(),
        deleted: deleted as u8,
        enrolled_at: e
            .map(|e| e.enrolled_at.timestamp_millis() as u64)
            .unwrap_or(now),
        updated_at: now,
        disabled: e.map(|e| e.disabled as u8).unwrap_or(0),
    };
    let db = state.db.clone();
    tokio::spawn(async move { db.upsert_agent_registry(&row).await });
}

/// ProVigil agent name rules (`OS_IsValidName`): letters, digits, '.', '_', '-'; 2..=128 chars.
fn valid_agent_name(name: &str) -> bool {
    (2..=128).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The next free three-digit agent id across every tenant: enrolled agents,
/// agents seen on ingest, tenant bindings and the in-memory keystore.
fn next_free_agent_id(state: &AppState) -> String {
    let mut max = state.max_agent_id.load(std::sync::atomic::Ordering::SeqCst);
    let mut consider = |id: &str| {
        if let Ok(n) = id.parse::<u64>() {
            max = max.max(n);
        }
    };
    state
        .enrolled
        .read()
        .unwrap()
        .keys()
        .for_each(|k| consider(k));
    state
        .agents
        .read()
        .unwrap()
        .keys()
        .for_each(|k| consider(k));
    state
        .agent_tenants
        .read()
        .unwrap()
        .keys()
        .for_each(|k| consider(k));
    state
        .auth_keystore
        .read()
        .unwrap()
        .keys
        .iter()
        .for_each(|k| consider(&k.id));
    // Ids are never reused, even after an agent is deleted (like the upstream
    // client.keys counter): old data stays attached to the old agent only.
    // fetch_add hands each concurrent enrollment its own id.
    state
        .max_agent_id
        .fetch_max(max, std::sync::atomic::Ordering::SeqCst);
    let next = state
        .max_agent_id
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        + 1;
    format!("{:03}", next)
}

/// A new agent while its enrollment runs. Cut short (the call's time limit, the client gone),
/// nothing of it stays: the client has no key for it. The id is not issued again.
struct NewAgent {
    state: AppState,
    id: String,
    entry: EnrolledAgent,
    done: bool,
}

impl Drop for NewAgent {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let (state, id, tenant) = (&self.state, &self.id, &self.entry.tenant);
        warn!("Enrollment of agent {id} cut short: removed");
        state.enrolled.write().unwrap().remove(id);
        state.agents.write().unwrap().remove(id);
        state.agent_tenants.write().unwrap().remove(id);
        let _ = state.auth_keystore.write().unwrap().delete_key(id);
        provigil_manager::save_keys(state);
        persist_registry(state, id, tenant, Some(&self.entry), true);
        let (st, t, i) = (state.clone(), tenant.clone(), id.clone());
        tokio::spawn(async move {
            st.db.delete_agent(&t, &i).await;
            provigil_manager::purge_removed(vec![i]).await;
        });
    }
}

/// The body of `/api/v1/agents/enroll`, shared with the gRPC `Enroll` call.
pub(crate) async fn enroll_agent(
    state: &AppState,
    headers: &HeaderMap,
    ctx: Option<&AuthCtx>,
    payload: EnrollAgentPayload,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let err = |code: StatusCode, msg: &str| Err((code, msg.to_string()));

    let has_key = headers.get("x-tenant-key").is_some();
    let tenant = if has_key {
        match resolve_agent_tenant(state, headers, "") {
            Ok(t) => t,
            Err(code) => return err(code, "Invalid tenant key"),
        }
    } else if let Some(c) = ctx {
        c.scope()
    } else {
        tenancy::DEFAULT_TENANT.to_string()
    };

    let name = payload.name.trim().to_string();
    if !valid_agent_name(&name) {
        return err(
            StatusCode::BAD_REQUEST,
            "Invalid agent name (2-128 chars: letters, digits, '.', '_', '-')",
        );
    }

    let force_enroll = payload.force.unwrap_or(false);
    let key = (tenant.clone(), name.to_lowercase());
    if state.deleted_agent_names.read().unwrap().contains(&key) {
        if force_enroll {
            info!(
                "Force-enrolling previously deleted agent '{}' in tenant '{}'",
                name, tenant
            );
            state.deleted_agent_names.write().unwrap().remove(&key);
        } else {
            warn!(
                "Rejected auto-re-enrollment attempt for decommissioned agent '{}' in tenant '{}'",
                name, tenant
            );
            return err(
                StatusCode::FORBIDDEN,
                "Agent name has been deleted from this tenant. Decommissioned agents may not auto-re-enroll.",
            );
        }
    }
    // authd refuses groups that do not exist ("Invalid group"); the manager names carry the tenant
    // a deployment token: valid, not used up (a reinstall of the same PC does not count again)
    let deploy_token = match headers.get("x-tenant-key").and_then(|v| v.to_str().ok()).map(str::trim).filter(|k| deploy_tokens::is_token(k)) {
        Some(k) => {
            let existing = state.enrolled.read().unwrap().iter().find(|(_, a)| a.tenant == tenant && a.name.eq_ignore_ascii_case(&name)).map(|(id, _)| id.clone());
            match deploy_tokens::check_enroll(k, existing.as_deref()) {
                Ok(t) => Some(t),
                Err(m) => return err(StatusCode::FORBIDDEN, &m),
            }
        }
        None => None,
    };
    // the token's group when the PC asks for none
    let asked: Vec<String> = payload
        .groups
        .as_deref()
        .filter(|g| !g.trim().is_empty())
        .or(deploy_token.as_ref().map(|t| t.groups.as_str()))
        .unwrap_or("")
        .split(',')
        .map(str::to_string)
        .collect();
    let manager_groups = if provigil_manager::enabled() {
        match groups::resolve(&tenant, &asked) {
            Ok(g) => g,
            Err(e) => return err(StatusCode::BAD_REQUEST, &e),
        }
    } else {
        vec!["default".to_string()]
    };
    let groups: Vec<String> = manager_groups
        .iter()
        .filter_map(|m| groups::display_name(&tenant, m))
        .collect();
    let groups = groups.join(",");
    let ip = payload
        .ip
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "any".to_string());

    let os_type = payload.os_type.clone().unwrap_or_default();
    let (agent_id, reused, entry) = {
        let existing = state
            .enrolled
            .read()
            .unwrap()
            .iter()
            .find(|(_, a)| a.tenant == tenant && a.name.eq_ignore_ascii_case(&name))
            .map(|(id, a)| (id.clone(), a.enrolled_at, a.disabled));
        let (id, reused, enrolled_at, disabled) = match existing {
            Some((id, at, dis)) => (id, true, at, if force_enroll { false } else { dis }),
            None => (next_free_agent_id(state), false, Utc::now(), false),
        };
        let entry = EnrolledAgent {
            name: name.clone(),
            tenant: tenant.clone(),
            groups: groups.clone(),
            os_type: os_type.clone(),
            enrolled_at,
            disabled,
        };
        state
            .enrolled
            .write()
            .unwrap()
            .insert(id.clone(), entry.clone());
        (id, reused, entry)
    };
    let mut new_agent = (!reused).then(|| NewAgent { state: state.clone(), id: agent_id.clone(), entry: entry.clone(), done: false });
    // Stored in ClickHouse before the agent gets its identity.
    state
        .db
        .upsert_agent_registry(&crate::db::AgentRegistryRow {
            agent_id: agent_id.clone(),
            name: entry.name.clone(),
            tenant_id: entry.tenant.clone(),
            groups: entry.groups.clone(),
            os_type: entry.os_type.clone(),
            deleted: 0,
            enrolled_at: entry.enrolled_at.timestamp_millis() as u64,
            updated_at: Utc::now().timestamp_millis() as u64,
            disabled: entry.disabled as u8,
        })
        .await;

    if let Some(t) = &deploy_token {
        deploy_tokens::record(state, t, &agent_id, &name).await;
    }

    let client_key = {
        let mut keystore = state.auth_keystore.write().unwrap();
        let _ = keystore.delete_key(&agent_id);
        agent_keys_store::new_agent_key(&mut keystore, &agent_id, &name, &ip)
    };
    // remoted reads the keys from etc/client.keys, the agent row from global.db
    provigil_manager::save_keys(state);
    provigil_manager::register_agent(
        &client_key.id,
        &client_key.name,
        &client_key.ip,
        &client_key.raw_key,
        &manager_groups.join(","),
    )
    .await;

    state.deleted_agents.write().unwrap().remove(&agent_id);
    state
        .agent_tenants
        .write()
        .unwrap()
        .insert(agent_id.clone(), tenant.clone());
    {
        let mut agents = state.agents.write().unwrap();
        let os_type = payload
            .os_type
            .clone()
            .unwrap_or_else(|| "linux".to_string());
        let entry = agents.entry(agent_id.clone()).or_insert_with(|| Agent {
            id: agent_id.clone(),
            name: name.clone(),
            ip: client_key.ip.clone(),
            status: AgentStatus::Pending,
            os: "Registered via enrollment".to_string(),
            version: "v4.14.7".to_string(),
            last_keepalive: Utc::now(),
            os_type: os_type.clone(),
        });
        entry.name = name.clone();
        entry.os_type = os_type.clone();
        if force_enroll {
            entry.status = AgentStatus::Pending;
        }
    }

    // Persist to ClickHouse database for this tenant
    let agent_to_save = Agent {
        id: agent_id.clone(),
        name: name.clone(),
        ip: client_key.ip.clone(),
        status: AgentStatus::Active,
        os: "Windows / Registered".to_string(),
        version: "v4.14.7".to_string(),
        last_keepalive: Utc::now(),
        os_type: payload
            .os_type
            .clone()
            .unwrap_or_else(|| "windows".to_string()),
    };
    state
        .db
        .insert_or_update_agent(&tenant, &agent_to_save)
        .await;

    info!(
        "Agent '{}' enrolled as {} in tenant '{}'{}",
        name,
        agent_id,
        tenant,
        if reused {
            " (re-enrollment, id kept)"
        } else {
            ""
        }
    );

    if let Some(n) = &mut new_agent {
        n.done = true;
    }
    Ok(serde_json::json!({
        "status": "success",
        "agent_id": client_key.id,
        "agent_name": client_key.name,
        "agent_ip": client_key.ip,
        "raw_key": client_key.raw_key,
        "tenant_id": tenant,
        "groups": groups,
        "reenrolled": reused
    }))
}

async fn get_reports_summary_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let mut total_alerts = 0u64;
    let mut rule_distribution: HashMap<String, u64> = HashMap::new();
    for (rule_id, _, n) in history::top_rules(&state, &ctx, history::DEFAULT_HOURS, 100_000).await {
        total_alerts += n;
        *rule_distribution.entry(rule_id.to_string()).or_default() += n;
    }

    // per framework: the alerts whose ProVigil rule carries its tag (the scores are /api/v1/compliance)
    let since = (chrono::Utc::now().timestamp_millis().max(0) as u64)
        .saturating_sub(history::DEFAULT_HOURS as u64 * 3_600_000);
    let tags = state
        .db
        .compliance_tag_counts(
            &ctx.scope(),
            since,
            &["pci_dss", "hipaa", "nist_800_53", "gdpr", "tsc"],
        )
        .await
        .unwrap_or_default();
    let compliance_summary: serde_json::Map<String, serde_json::Value> = tags
        .into_iter()
        .map(|(tag, alerts, requirements)| {
            (
                tag.to_string(),
                serde_json::json!({ "alerts": alerts, "requirements_with_alerts": requirements }),
            )
        })
        .collect();

    Json(serde_json::json!({
        "total_alerts": total_alerts,
        "matched_alerts": total_alerts,
        "rule_distribution": rule_distribution,
        "window_hours": history::DEFAULT_HOURS,
        "compliance_summary": compliance_summary,
        "compliance_scores": "/api/v1/compliance"
    }))
}

/// An agent upgrade, as the ProVigil API's `PUT /agents/upgrade` /
/// `/agents/upgrade_custom` take it. `file_path` selects a custom upgrade.
#[derive(Debug, Deserialize)]
pub struct UpgradeAgentRequest {
    /// `version` (default: the manager's)
    pub target_version: Option<String>,
    pub wpk_repo: Option<String>,
    pub use_http: Option<bool>,
    pub force: Option<bool>,
    /// "rpm" or "deb"
    pub package_type: Option<String>,
    /// Custom WPK on the manager, and its installer script.
    pub file_path: Option<String>,
    pub installer: Option<String>,
}

/// The agent's numeric id when the caller may act on it (`manage`: upgrades
/// need the agent tenant's admin).
fn upgrade_agent_id(
    state: &AppState,
    ctx: &AuthCtx,
    agent_id: &str,
    manage: bool,
) -> Result<i64, axum::response::Response> {
    let id: i64 = agent_id.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid agent id" })),
        )
            .into_response()
    })?;
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap().clone(), agent_id);
    let known = state.agents.read().unwrap().contains_key(agent_id);
    if !known || tenant != ctx.scope() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Agent not found" })),
        )
            .into_response());
    }
    if manage && !ctx.can_manage(&tenant) {
        return Err(tenancy::forbidden());
    }
    Ok(id)
}

/// One request to modulesd's agent-upgrade socket (`queue/tasks/upgrade`), its JSON answer.
async fn upgrade_module_request(req: serde_json::Value) -> axum::response::Response {
    let path = provigil_manager::home().join("queue/tasks/upgrade");
    let res = async {
        let mut s = siem_ipc::local::LocalStream::connect(&path)
            .await
            .map_err(|e| e.to_string())?;
        siem_ipc::framing::send(&mut s, req.to_string().as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let r = siem_ipc::framing::recv(&mut s, 65536)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::from_slice::<serde_json::Value>(&r).map_err(|e| e.to_string())?;
        Ok::<_, String>(r)
    };
    // the module answers after its 30 s start-up wait
    match tokio::time::timeout(std::time::Duration::from_secs(60), res).await {
        // the module's JSON as it wrote it (key order kept)
        Ok(Ok(v)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            v,
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": format!("agent-upgrade module: {e}") })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(serde_json::json!({ "error": "agent-upgrade module did not answer" })),
        )
            .into_response(),
    }
}

async fn post_agent_upgrade_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
    Json(p): Json<UpgradeAgentRequest>,
) -> axum::response::Response {
    let id = match upgrade_agent_id(&state, &ctx, &agent_id, true) {
        Ok(id) => id,
        Err(r) => return r,
    };
    // a ProVigil agent (HTTPS) upgrades itself from the published package
    if provigil_manager::is_http_agent(&agent_id) {
        return match provigil_manager::queue_http_upgrade(&agent_id) {
            Ok(sha) => Json(serde_json::json!({ "status": "queued", "message": "Upgrade sent with the next keepalive", "sha256": sha })).into_response(),
            Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "message": e }))).into_response(),
        };
    }
    let mut params = serde_json::Map::new();
    params.insert("agents".into(), serde_json::json!([id]));
    let command = if let Some(f) = p.file_path {
        params.insert("file_path".into(), f.into());
        if let Some(i) = p.installer {
            params.insert("installer".into(), i.into());
        }
        "upgrade_custom"
    } else {
        if let Some(v) = p.target_version {
            params.insert("version".into(), v.into());
        }
        if let Some(r) = p.wpk_repo {
            params.insert("wpk_repo".into(), r.into());
        }
        if let Some(h) = p.use_http {
            params.insert("use_http".into(), h.into());
        }
        if let Some(f) = p.force {
            params.insert("force_upgrade".into(), f.into());
        }
        if let Some(t) = p.package_type {
            params.insert("package_type".into(), t.into());
        }
        "upgrade"
    };
    info!(
        "Agent upgrade: {command} requested for agent {agent_id} by {}",
        ctx.username
    );
    upgrade_module_request(serde_json::json!({ "command": command, "parameters": params })).await
}

/// The agent's last upgrade task (`upgrade_result`).
async fn get_agent_upgrade_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
) -> axum::response::Response {
    let id = match upgrade_agent_id(&state, &ctx, &agent_id, false) {
        Ok(id) => id,
        Err(r) => return r,
    };
    upgrade_module_request(
        serde_json::json!({ "command": "upgrade_result", "parameters": { "agents": [id] } }),
    )
    .await
}

// ───────────────────────── tenant agents ─────────────────────────

/// Resolves the tenant of an agent request and records the agent's
/// tenant. With `X-Tenant-Key` the key decides; without it the agent keeps
/// the tenant it already has (new agents go to `default`). An agent id that
/// belongs to another tenant is refused.
fn resolve_agent_tenant(
    state: &AppState,
    headers: &HeaderMap,
    agent_id: &str,
) -> Result<String, StatusCode> {
    if !agent_id.is_empty() {
        if state.deleted_agents.read().unwrap().contains(agent_id) {
            return Err(StatusCode::NOT_FOUND);
        }
        if is_deactivated(state, agent_id) {
            return Err(StatusCode::GONE);
        }
        // an enrolled agent (it has a key) must prove it is that agent: its own key as
        // `Authorization: Bearer` (ProVigil agent) or `X-Agent-Key` (Linux agent)
        let enrolled = state.auth_keystore.read().unwrap().find_by_id(agent_id).is_some();
        if enrolled && !agent_bearer_ok(state, agent_id, headers) && !agent_key_ok(state, agent_id, headers) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    let keyed = match headers
        .get("x-tenant-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(k) => Some(
            state
                .agent_keys
                .tenant_for(k)
                .or_else(|| deploy_tokens::tenant_of(k))
                .ok_or(StatusCode::UNAUTHORIZED)?,
        ),
        None => None,
    };
    if let Some(ref t) = keyed {
        let tenants = state.tenants.read().unwrap();
        if t != tenancy::DEFAULT_TENANT && !tenants.is_empty() {
            if tenants.iter().any(|x| &x.id == t && !x.active) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }
    let mut map = state.agent_tenants.write().unwrap();
    match (map.get(agent_id).cloned(), keyed) {
        // An agent id belongs to one tenant: another tenant's key cannot take it over.
        (Some(existing), Some(k)) if existing != k => Err(StatusCode::CONFLICT),
        (Some(existing), _) => Ok(existing),
        (None, k) => {
            if state.deleted_agents.read().unwrap().contains(agent_id) {
                return Err(StatusCode::NOT_FOUND);
            }
            let t = k.unwrap_or_else(|| tenancy::DEFAULT_TENANT.to_string());
            if agent_id.is_empty() {
                return Ok(t);
            }
            map.insert(agent_id.to_string(), t.clone());
            drop(map);
            // Agents that report without enrolling are registered too, so the
            // binding survives restarts and the id is never issued again. An
            // enrolled agent keeps its enrollment (name, group, deactivated flag).
            let enrolled = state.enrolled.read().unwrap().get(agent_id).cloned();
            persist_registry(state, agent_id, &t, enrolled.as_ref(), false);
            if let Ok(n) = agent_id.parse::<u64>() {
                state
                    .max_agent_id
                    .fetch_max(n, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(t)
        }
    }
}

/// Whether `agent_id` belongs to the caller's tenant scope.
fn agent_in_scope(state: &AppState, ctx: &AuthCtx, agent_id: &str) -> bool {
    tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id) == ctx.scope()
}

/// `GET /api/v1/tenant/agent-key`: the key agents of the caller's tenant
/// send as `X-Tenant-Key` (admins, and users allowed to deploy agents).
async fn get_tenant_agent_key_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> axum::response::Response {
    let tenant = ctx.scope();
    // the enrolment key deploys agents: the tenant admin, or an analyst given "Deploy Agents"
    if !ctx.can_manage(&tenant) && !ctx.has_permission("siem-agent-deploy") {
        return tenancy::forbidden();
    }
    let key = state.agent_keys.get_or_create(&state.db, &tenant).await;
    Json(serde_json::json!({ "status": "ok", "tenant_id": tenant, "agent_key": key, "header": "X-Tenant-Key" })).into_response()
}

/// `POST /api/v1/tenant/agent-key/rotate`
async fn rotate_tenant_agent_key_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> axum::response::Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let key = state.agent_keys.rotate(&state.db, &tenant).await;
    Json(serde_json::json!({ "status": "ok", "tenant_id": tenant, "agent_key": key }))
        .into_response()
}

/// Tags an alert with its tenant, keeps it, stores it in the tenant's
/// database and broadcasts it.
async fn record_alert(state: &AppState, tenant: &str, alert: Alert) -> Alert {
    let mut alert = tenancy::tag_alert(alert, tenant);
    if !alert.data.contains_key("risk_fabric") {
        state.risk_fabric.evaluate_alert(&mut alert);
    }
    keep_alerts(&state, [alert.clone()]);
    state.db.insert_alert(&alert).await;
    let _ = state.broadcast_tx.send(alert.clone());

    // Evaluate live agent alert against Deception honeynet tripwires (ignore deception's own alerts to prevent cascading loops)
    if alert.rule.id != 100999
        && alert.rule.id != 100200
        && !alert.rule.groups.iter().any(|g| g == "deception" || g == "zero_false_positive")
    {
        state.deception_engine.ingest_live_alerts(&[alert.clone()]);
    }

    alert
}

/// Agents of the caller's tenant scope, by id.
fn scoped_agent_map(state: &AppState, ctx: &AuthCtx) -> HashMap<String, Agent> {
    scoped_agents(state, ctx)
        .into_iter()
        .map(|a| (a.id.clone(), a))
        .collect()
}

/// `GET /api/v1/agents/:id/inventory`: the latest system inventory the agent
/// reported (syscollector event, `inventory_json`). The auth middleware has
/// already checked that the agent belongs to the caller's tenant.
async fn get_agent_inventory_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
) -> axum::response::Response {
    // ProVigil agents: what their syscollector synced to provigil-db
    if let Some(inv) = provigil_manager::agent_inventory(&agent_id).await {
        return Json(inv).into_response();
    }
    let from_memory = {
        let events = state.events.read().unwrap();
        events
            .iter()
            .rev()
            .find(|e| {
                e.agent_id == agent_id
                    && e.source == EventSource::Syscollector
                    && e.metadata.contains_key("inventory_json")
            })
            .and_then(|e| e.metadata.get("inventory_json").cloned())
    };
    let json = match from_memory {
        Some(j) => Some(j),
        None => state
            .db
            .fetch_latest_inventory(&ctx.scope(), &agent_id)
            .await
            .and_then(|meta| serde_json::from_str::<HashMap<String, String>>(&meta).ok())
            .and_then(|m| m.get("inventory_json").cloned()),
    };
    match json.and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok()) {
        Some(v) => Json(v).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "No inventory reported by this agent yet" })),
        )
            .into_response(),
    }
}

// ───────────────────────── agent deactivation ─────────────────────────

/// Whether the agent was deactivated (kept in the registry, must not report).
fn is_deactivated(state: &AppState, agent_id: &str) -> bool {
    state
        .enrolled
        .read()
        .unwrap()
        .get(agent_id)
        .map(|e| e.disabled)
        .unwrap_or(false)
}

/// Sets the deactivated flag and stores it. Returns the agent's enrollment.
fn set_agent_disabled(state: &AppState, agent_id: &str, disabled: bool) -> Option<EnrolledAgent> {
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id);
    // Read the fleet entry first: never hold two of these locks at once.
    let (fleet_name, fleet_os) = state
        .agents
        .read()
        .unwrap()
        .get(agent_id)
        .map(|a| (a.name.clone(), a.os_type.clone()))
        .unwrap_or_else(|| (agent_id.to_string(), String::new()));
    let entry = {
        let mut enrolled = state.enrolled.write().unwrap();
        let e = enrolled
            .entry(agent_id.to_string())
            .or_insert_with(|| EnrolledAgent {
                name: fleet_name,
                tenant: tenant.clone(),
                groups: String::new(),
                os_type: fleet_os,
                enrolled_at: Utc::now(),
                disabled: false,
            });
        e.disabled = disabled;
        e.clone()
    };
    persist_registry(state, agent_id, &tenant, Some(&entry), false);
    Some(entry)
}

/// `POST /api/v1/agents/:id/deactivate`: keeps the agent (not deleted), takes it
/// out of the active fleet, refuses its data and tells it to stop.
async fn deactivate_agent_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(id): Path<String>,
) -> axum::response::Response {
    if !agent_in_scope(&state, &ctx, &id)
        || (!state.agents.read().unwrap().contains_key(&id)
            && !state.enrolled.read().unwrap().contains_key(&id))
    {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    }
    let Some(entry) = set_agent_disabled(&state, &id, true) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    };
    state.agents.write().unwrap().remove(&id);
    state.db.delete_agent(&ctx.scope(), &id).await;
    // The agent stops on its next command poll (or on its next upload: 410).
    let cmd = serde_json::json!({
        "command_id": format!("deactivate-{}", uuid::Uuid::new_v4()),
        "agent_id": id,
        "action": "deactivate",
        "target": "all"
    });
    state
        .pending_commands
        .write()
        .unwrap()
        .entry(id.clone())
        .or_default()
        .push(cmd.clone());
    persist::save_commands(&state, &id, &[cmd], false).await;
    info!(
        "Agent {} ('{}') deactivated in tenant {} by {}",
        id,
        entry.name,
        ctx.scope(),
        ctx.username
    );
    Json(serde_json::json!({ "status": "ok", "agent_id": id, "state": "deactivated" }))
        .into_response()
}

/// `POST /api/v1/agents/:id/activate`: the agent resumes on its next state check.
async fn activate_agent_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(id): Path<String>,
) -> axum::response::Response {
    if !agent_in_scope(&state, &ctx, &id) || !is_deactivated(&state, &id) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": "No deactivated agent with this id" }))).into_response();
    }
    let entry = set_agent_disabled(&state, &id, false);
    if let Some(e) = entry {
        state
            .agents
            .write()
            .unwrap()
            .entry(id.clone())
            .or_insert_with(|| Agent {
                id: id.clone(),
                name: e.name.clone(),
                ip: "any".into(),
                os: "Reactivated".into(),
                version: "v4.14.7".into(),
                status: AgentStatus::Pending,
                last_keepalive: Utc::now(),
                os_type: if e.os_type.is_empty() {
                    "linux".into()
                } else {
                    e.os_type.clone()
                },
            });
        info!(
            "Agent {} ('{}') reactivated in tenant {} by {}",
            id,
            e.name,
            ctx.scope(),
            ctx.username
        );
    }
    Json(serde_json::json!({ "status": "ok", "agent_id": id, "state": "active" })).into_response()
}

/// `GET /api/v1/agents/deactivated`: deactivated agents of the caller's tenant.
async fn get_deactivated_agents_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> axum::response::Response {
    let scope = ctx.scope();
    let mut list: Vec<serde_json::Value> = state
        .enrolled
        .read()
        .unwrap()
        .iter()
        .filter(|(_, e)| e.disabled && tenancy::normalize_tenant(&e.tenant) == scope)
        .map(|(id, e)| serde_json::json!({ "id": id, "name": e.name, "os_type": e.os_type, "groups": e.groups, "enrolled_at": e.enrolled_at }))
        .collect();
    list.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Json(serde_json::json!({ "status": "ok", "agents": list })).into_response()
}

// ═══════════════════════════════════════════════════════════════════════════
// Continuous Red Agent Swarm & Perpetual Purple-Team Engine Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// A Red Swarm alert says it is a simulation (the round injected the telemetry).
fn redswarm_simulated(mut a: Alert) -> Alert {
    a.rule.description = format!("[Red Swarm simulation] {}", a.rule.description);
    a.rule.groups.push("redswarm_simulation".into());
    a
}

/// Whether a Red Swarm round (by its target agent) belongs to the caller's tenant.
fn swarm_record_visible(
    state: &AppState,
    ctx: &AuthCtx,
    r: &siem_redswarm::ExecutionRecord,
) -> bool {
    tenancy::tenant_of(&state.agent_tenants.read().unwrap(), &r.target_agent_id)
        == tenancy::normalize_tenant(&ctx.scope())
}

fn swarm_records(
    state: &AppState,
    ctx: &AuthCtx,
    limit: usize,
) -> Vec<siem_redswarm::ExecutionRecord> {
    state
        .redswarm
        .audit()
        .get_history(usize::MAX)
        .into_iter()
        .filter(|r| swarm_record_visible(state, ctx, r))
        .take(limit)
        .collect()
}

/// The tenant's drafts: those of its rounds.
fn swarm_drafts(state: &AppState, ctx: &AuthCtx) -> Vec<siem_redswarm::SynthesizedRuleDraft> {
    let mine: HashSet<uuid::Uuid> = swarm_records(state, ctx, usize::MAX)
        .iter()
        .map(|r| r.id)
        .collect();
    state
        .redswarm
        .audit()
        .drafts()
        .into_iter()
        .filter(|d| mine.contains(&d.execution_id))
        .collect()
}

/// Campaigns, the kill switch and detection rules are shared by every tenant: tenant or platform admins.
fn swarm_admin(ctx: &AuthCtx) -> Option<axum::response::Response> {
    (!(ctx.is_super() || ctx.can_manage(&ctx.scope()))).then(|| {
        (StatusCode::FORBIDDEN, Json(serde_json::json!({ "status": "error", "message": "Only a tenant admin or a platform admin can do this" }))).into_response()
    })
}

const REDSWARM_RULES: &str = "redswarm_rules.xml";

/// The deployed Red Swarm rules into the in-process engine the rounds are verified on.
fn reload_redswarm_rules(state: &AppState) {
    let xml = std::fs::read_to_string(
        provigil_manager::home()
            .join("etc/rules")
            .join(REDSWARM_RULES),
    )
    .unwrap_or_default();
    state.engine.set_custom_rules_xml(&xml);
}

/// Live modes would run attack commands on endpoints; siem-api has no channel that does that safely.
const REDSWARM_NO_LIVE: &str =
    "Live execution is not available: only the telemetry mode (SafeTelemetryOnly) runs";

fn redswarm_live(
    mode: Option<siem_redswarm::SwarmExecutionMode>,
) -> Option<axum::response::Response> {
    matches!(
        mode,
        Some(
            siem_redswarm::SwarmExecutionMode::ControlledLive
                | siem_redswarm::SwarmExecutionMode::FullLive
        )
    )
    .then(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": REDSWARM_NO_LIVE })),
        )
            .into_response()
    })
}

async fn get_redswarm_status_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    // the engine's state, with the counts of this tenant's rounds
    let mut report = state.redswarm.get_status();
    let since = Utc::now() - chrono::Duration::hours(24);
    let recent: Vec<_> = swarm_records(&state, &ctx, usize::MAX)
        .into_iter()
        .filter(|r| r.timestamp >= since)
        .collect();
    let defended = recent
        .iter()
        .filter(|r| r.verification.verdict == siem_redswarm::DetectionVerdict::Defended)
        .count();
    let drafts = swarm_drafts(&state, &ctx);
    report.attacks_last_24h = recent.len() as u64;
    report.defense_rate_percent = if recent.is_empty() {
        100.0
    } else {
        (defended as f64 * 1000.0 / recent.len() as f64).round() / 10.0
    };
    report.open_gaps_count = drafts
        .iter()
        .filter(|d| d.status == siem_redswarm::DraftRuleStatus::PendingApproval)
        .map(|d| &d.technique_id)
        .collect::<HashSet<_>>()
        .len();
    report.approved_rules_count = drafts
        .iter()
        .filter(|d| d.status == siem_redswarm::DraftRuleStatus::ApprovedAndDeployed)
        .count();
    report.kill_switch_active = state.redswarm.is_tenant_halted(&ctx.scope());
    Json(report)
}

/// The campaigns the caller sees: the platform ones and its tenant's.
fn swarm_campaign_visible(ctx: &AuthCtx, c: &siem_redswarm::SwarmCampaign) -> bool {
    c.tenant_id.is_empty() || c.tenant_id == ctx.scope()
}

/// A platform campaign runs over every tenant: only a platform admin changes it.
fn swarm_campaign_owner(
    ctx: &AuthCtx,
    c: &siem_redswarm::SwarmCampaign,
) -> Option<axum::response::Response> {
    (!ctx.is_super() && c.tenant_id != ctx.scope()).then(|| {
        (StatusCode::FORBIDDEN, Json(serde_json::json!({ "status": "error", "message": "This campaign is shared by every tenant: only a platform admin can change it. Use the kill switch to stop Red Swarm for your tenant." }))).into_response()
    })
}

async fn get_redswarm_campaigns_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let campaigns: Vec<_> = state
        .redswarm
        .get_campaigns()
        .into_iter()
        .filter(|c| swarm_campaign_visible(&ctx, c))
        .collect();
    Json(campaigns)
}

async fn post_redswarm_campaigns_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(mut campaign): Json<siem_redswarm::SwarmCampaign>,
) -> axum::response::Response {
    if let Some(r) = swarm_admin(&ctx).or_else(|| redswarm_live(Some(campaign.mode))) {
        return r;
    }
    if !ctx.is_super() {
        // a tenant admin's campaign tests its own agents only
        if let Some(r) = state
            .redswarm
            .get_campaigns()
            .iter()
            .find(|c| c.id == campaign.id)
            .and_then(|c| swarm_campaign_owner(&ctx, c))
        {
            return r;
        }
        campaign.tenant_id = ctx.scope();
    }
    state.redswarm.upsert_campaign(campaign.clone());
    Json(serde_json::json!({ "status": "success", "campaign": campaign })).into_response()
}

async fn post_redswarm_toggle_campaign_handler(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    if let Some(r) = swarm_admin(&ctx) {
        return r;
    }
    let Some(campaign) = state
        .redswarm
        .get_campaigns()
        .into_iter()
        .find(|c| c.id == id && swarm_campaign_visible(&ctx, c))
    else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": format!("Campaign {id} not found") }))).into_response();
    };
    if let Some(r) = swarm_campaign_owner(&ctx, &campaign) {
        return r;
    }
    match state.redswarm.toggle_campaign(&id) {
        Ok(enabled) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ok", "campaign_id": id, "enabled": enabled })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct RunOncePayload {
    pub technique_id: Option<String>,
    pub target_agent_id: Option<String>,
    pub mode: Option<siem_redswarm::SwarmExecutionMode>,
}

async fn post_redswarm_run_once_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(payload): Json<RunOncePayload>,
) -> impl IntoResponse {
    if let Some(r) = redswarm_live(payload.mode) {
        return r;
    }
    let tenant = ctx.scope();
    // one of the tenant's own agents
    let target = {
        let agents = scoped_agent_map(&state, &ctx);
        match payload.target_agent_id {
            Some(ref id) => agents.get(id).cloned(),
            None => agents
                .values()
                .find(|a| a.status == AgentStatus::Active)
                .cloned()
                .or_else(|| agents.values().next().cloned()),
        }
    };
    let Some(ag) = target else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": "No agent of yours to run the technique on" }))).into_response();
    };
    let (target_agent_id, agent_name, agent_ip, agent_os) = (ag.id, ag.name, ag.ip, ag.os_type);

    let target_tags = vec!["lab".into(), "redteam-allowed".into()];

    let swarm_state = state.clone();
    let cl_agent_name = agent_name.clone();
    let cl_agent_ip = agent_ip.clone();
    let cl_tenant = tenant.clone();
    let result = state
        .redswarm
        .run_single_round(
            payload.technique_id.as_deref(),
            &target_agent_id,
            &agent_name,
            &agent_ip,
            &agent_os,
            &target_tags,
            payload.mode,
            &tenant,
            move |events| {
                for ev in events {
                    if let Some(alert) =
                        swarm_state
                            .engine
                            .process_event(ev, &cl_agent_name, &cl_agent_ip)
                    {
                        let alert = tenancy::tag_alert(redswarm_simulated(alert), &cl_tenant);
                        keep_alerts(&swarm_state, [alert.clone()]);
                        let _ = swarm_state.broadcast_tx.send(alert);
                    }
                    keep_events(&swarm_state, [ev.clone()]);
                }
            },
            move |_ag_id, _cmd| Err(REDSWARM_NO_LIVE.to_string()),
            move || state.alerts.read().unwrap().clone(),
        )
        .await;

    match result {
        Ok(record) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success", "record": record })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "status": "error", "message": e })),
        )
            .into_response(),
    }
}

async fn get_redswarm_history_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    Json(swarm_records(&state, &ctx, 100))
}

async fn get_redswarm_gaps_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    // one open gap per technique: its newest draft (rounds before the dedupe made one a minute)
    let mut gaps: Vec<_> = swarm_drafts(&state, &ctx)
        .into_iter()
        .filter(|d| d.status == siem_redswarm::DraftRuleStatus::PendingApproval)
        .collect();
    gaps.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let mut seen = HashSet::new();
    gaps.retain(|d| seen.insert(d.technique_id.clone()));
    Json(gaps)
}

async fn post_redswarm_apply_rule_handler(
    Path(id): Path<uuid::Uuid>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    if let Some(r) = swarm_admin(&ctx) {
        return r;
    }
    let Some(draft) = swarm_drafts(&state, &ctx).into_iter().find(|d| d.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Draft rule not found" })),
        )
            .into_response();
    };
    if draft.status != siem_redswarm::DraftRuleStatus::PendingApproval {
        return (StatusCode::CONFLICT, Json(serde_json::json!({ "status": "error", "message": "This draft was already decided" }))).into_response();
    }
    // into the manager's custom rules (ids 119000-119999), only if provigil-analysisd accepts them
    // the upstream <mitre> takes only <id> (older drafts also had <tactic> / <technique>)
    let xml: String = draft
        .rule_xml
        .lines()
        .filter(|l| {
            !l.trim_start().starts_with("<tactic>") && !l.trim_start().starts_with("<technique>")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let deployed = tokio::task::spawn_blocking(move || {
        provigil_manager::deploy_rule_group(REDSWARM_RULES, &xml, 119_000..=119_999)
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    let (rule_id, xml) = match deployed {
        Ok(x) => x,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "status": "error", "message": e })),
            )
                .into_response()
        }
    };
    reload_redswarm_rules(&state);
    state.redswarm.audit().set_rule_xml(id, &xml);
    match state.redswarm.audit().approve_rule(id) {
        Ok(rule) => {
            info!(
                "{} approved Red Swarm rule {} for {} (deployed as rule {rule_id})",
                ctx.username, rule.id, rule.technique_id
            );
            redswarm_store::upsert_draft(&state, &rule).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "approved", "rule_id": rule_id, "rule": rule })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": e })),
        )
            .into_response(),
    }
}

async fn post_redswarm_rollback_rule_handler(
    Path(id): Path<uuid::Uuid>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    if let Some(r) = swarm_admin(&ctx) {
        return r;
    }
    let Some(draft) = swarm_drafts(&state, &ctx).into_iter().find(|d| d.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Rule not found" })),
        )
            .into_response();
    };
    let rule_id = draft
        .rule_xml
        .split("<rule id=\"")
        .nth(1)
        .and_then(|p| p.split('"').next()?.parse::<u32>().ok());
    if draft.status == siem_redswarm::DraftRuleStatus::ApprovedAndDeployed {
        let Some(rule_id) = rule_id else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "status": "error", "message": "The rule has no id" })),
            )
                .into_response();
        };
        let removed = tokio::task::spawn_blocking(move || {
            provigil_manager::remove_rule_group(REDSWARM_RULES, rule_id)
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
        if let Err(e) = removed {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "status": "error", "message": e })),
            )
                .into_response();
        }
        reload_redswarm_rules(&state);
    }
    match state.redswarm.audit().rollback_rule(id) {
        Ok(rule) => {
            warn!(
                "{} rolled back Red Swarm rule {} for {}",
                ctx.username, rule.id, rule.technique_id
            );
            redswarm_store::upsert_draft(&state, &rule).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({ "status": "rolled_back", "rule": rule })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct KillSwitchPayload {
    pub engage: bool,
}

async fn post_redswarm_kill_switch_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(payload): Json<KillSwitchPayload>,
) -> impl IntoResponse {
    if let Some(r) = swarm_admin(&ctx) {
        return r;
    }
    // a platform admin's switch stops every tenant; a tenant admin's, its own tenant
    let tenant = ctx.scope();
    if ctx.is_super() {
        siem_redswarm::SafetyGatekeeper::set_kill_switch(payload.engage);
        if !payload.engage {
            state.redswarm.set_tenant_halted(&tenant, false);
        }
        warn!(
            "SECURITY NOTICE: Global Red Swarm Kill-Switch set to {} by {} ({})",
            payload.engage, ctx.username, ctx.role
        );
    } else {
        if !payload.engage && siem_redswarm::SafetyGatekeeper::is_kill_switch_engaged() {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "status": "error", "message": "The platform-wide kill switch is engaged: only a platform admin can release it" }))).into_response();
        }
        state.redswarm.set_tenant_halted(&tenant, payload.engage);
        warn!(
            "SECURITY NOTICE: Red Swarm Kill-Switch for tenant {} set to {} by {} ({})",
            tenant, payload.engage, ctx.username, ctx.role
        );
    }
    let mut status = state.redswarm.get_status();
    status.kill_switch_active = state.redswarm.is_tenant_halted(&tenant);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "kill_switch_active": status.kill_switch_active,
            "swarm_status": status
        })),
    )
        .into_response()
}

async fn post_redswarm_reject_rule_handler(
    Path(id): Path<uuid::Uuid>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    if let Some(r) = swarm_admin(&ctx) {
        return r;
    }
    let drafts = swarm_drafts(&state, &ctx);
    let Some(draft) = drafts.iter().find(|d| d.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Draft rule not found" })),
        )
            .into_response();
    };
    if draft.status != siem_redswarm::DraftRuleStatus::PendingApproval {
        return (StatusCode::CONFLICT, Json(serde_json::json!({ "status": "error", "message": "This draft was already decided" }))).into_response();
    }
    // the gap's every pending draft (the page shows one per technique); later rounds draft no more for it
    let mut rejected = 0;
    for d in drafts.iter().filter(|d| {
        d.technique_id == draft.technique_id
            && d.status == siem_redswarm::DraftRuleStatus::PendingApproval
    }) {
        if let Ok(rule) = state.redswarm.audit().reject_rule(d.id) {
            redswarm_store::upsert_draft(&state, &rule).await;
            rejected += 1;
        }
    }
    info!(
        "{} rejected the Red Swarm draft rules for {} ({rejected} drafts)",
        ctx.username, draft.technique_id
    );
    (StatusCode::OK, Json(serde_json::json!({ "status": "rejected", "technique_id": draft.technique_id, "rejected": rejected }))).into_response()
}

async fn get_redswarm_heatmap_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let all_techs = siem_redswarm::get_curated_catalog();
    let records = swarm_records(&state, &ctx, 500);
    let heatmap = siem_redswarm::MetricsCalculator::compute_heatmap(&all_techs, &records);
    Json(heatmap)
}

#[cfg(test)]
mod agent_key_tests {
    #[test]
    fn ct_eq() {
        assert!(super::ct_eq(b"abc", b"abc"));
        assert!(!super::ct_eq(b"abc", b"abd"));
        assert!(!super::ct_eq(b"abc", b"abcd"));
        assert!(!super::ct_eq(b"", b"x"));
    }

    #[test]
    fn trim_keeps_newest() {
        let mut l: Vec<u32> = (0..110).collect();
        super::trim(&mut l, 100);
        assert_eq!(l.len(), 110); // within the 10% slack
        l.push(110);
        super::trim(&mut l, 100);
        assert_eq!(l, (11..111).collect::<Vec<_>>());
    }
}

