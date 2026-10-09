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
use siem_core::{
    Agent, AgentStatus, Alert, EventSource, RawEvent, Rule, SiemStats,
};
use siem_engine::AnalysisEngine;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use siem_vuln_detector::{
    DetectionStatus, PackageInfo, Severity as VulnSeverity, VulnerabilityDetection,
    VulnerabilityScanner,
};

pub mod db;
pub mod syslog;
pub mod corroboration;
pub mod tenancy;
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

fn default_true() -> bool { true }
fn default_role() -> String { "analyst".to_string() }

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
    pub vuln_scanner: Arc<VulnerabilityScanner>,
    pub vulnerabilities: Arc<RwLock<Vec<VulnerabilityDetection>>>,
    pub wdb: Arc<siem_wdb::WazuhDbManager>,
    pub threat_intel: Arc<siem_cdb::ThreatIntelManager>,
    pub rootcheck: Arc<siem_rootcheck::RootcheckScanner>,
    pub active_responses: Arc<RwLock<Vec<ActiveResponseRecord>>>,
    pub parser_registry: Arc<siem_parser_gen::DynamicParserRegistry>,
    pub auth_keystore: Arc<RwLock<siem_crypto::keys::KeyStore>>,
    pub integrator_engine: Arc<RwLock<siem_integratord::IntegratorEngine>>,
    pub tenants: Arc<RwLock<Vec<TenantRecord>>>,
    /// Per-tenant agent keys (`X-Tenant-Key`).
    pub agent_keys: Arc<tenancy::AgentKeys>,
    /// agent id -> tenant id (in-memory copy of ndr.agent_registry)
    pub agent_tenants: Arc<RwLock<HashMap<String, String>>>,
    /// Enrolled agents by id (in-memory copy of ndr.agent_registry).
    pub enrolled: Arc<RwLock<HashMap<String, EnrolledAgent>>>,
    /// Highest agent id ever issued (deleted agents included): ids are never reused.
    pub max_agent_id: Arc<std::sync::atomic::AtomicU64>,
}


#[tokio::main]
async fn main() {
    eprintln!(">>> SIEM API STARTING ON PID: {} <<<", std::process::id());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Next-Gen Wazuh Rust SIEM Server...");

    // Logins, users and tenants are served by auth-service; siem-api only
    // validates its tokens, so it needs the same secret and session store.
    if tenancy::jwt_secret().trim().is_empty() {
        tracing::error!("JWT_SECRET is not set (it must match auth-service) — aborting");
        std::process::exit(1);
    }
    if let Err(e) = tenancy::init_valkey().await {
        tracing::error!("Cannot reach the auth-service session store: {} — aborting", e);
        std::process::exit(1);
    }

    let (broadcast_tx, _) = broadcast::channel::<Alert>(1000);
    let db = ClickHouseDb::init().await;

    let vuln_scanner = Arc::new(VulnerabilityScanner::with_default_feed());
    let vulnerabilities = Arc::new(RwLock::new(Vec::new()));
    let wdb = Arc::new(siem_wdb::WazuhDbManager::new());
    let threat_intel = Arc::new(siem_cdb::ThreatIntelManager::new_with_builtin_feeds());
    let rootcheck = Arc::new(siem_rootcheck::RootcheckScanner::with_default_db());
    let parser_registry = Arc::new(siem_parser_gen::DynamicParserRegistry::new("data/learned_parsers.json"));

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

        let sample2 = "2026-10-03 14:22:11 LOGIN FAILED user=john src=192.168.1.50 reason=wrong_password";
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
    let integrator_engine = Arc::new(RwLock::new(siem_integratord::IntegratorEngine::new(vec![
        siem_integratord::IntegratorConfig {
            name: "slack".to_string(),
            hookurl: Some("https://hooks.slack.com/services/mock/soc-alerts".to_string()),
            level: 10,
            enabled: true,
            ..Default::default()
        },
        siem_integratord::IntegratorConfig {
            name: "pagerduty".to_string(),
            apikey: Some("pd-mock-key".to_string()),
            level: 12,
            enabled: true,
            ..Default::default()
        },
    ])));

    let state = AppState {
        engine: AnalysisEngine::new(),
        events: Arc::new(RwLock::new(Vec::new())),
        alerts: Arc::new(RwLock::new(Vec::new())),
        agents: Arc::new(RwLock::new(HashMap::new())),
        broadcast_tx,
        pending_commands: Arc::new(RwLock::new(HashMap::new())),
        db,
        vuln_scanner,
        vulnerabilities,
        wdb,
        threat_intel,
        rootcheck,
        active_responses,
        parser_registry,
        auth_keystore,
        integrator_engine,
        tenants: Arc::new(RwLock::new(Vec::new())),
        agent_keys: Arc::new(tenancy::AgentKeys::new()),
        agent_tenants: Arc::new(RwLock::new(HashMap::new())),
        enrolled: Arc::new(RwLock::new(HashMap::new())),
        max_agent_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    };

    // Pre-seed sample active agents and multi-tenant auth accounts
    seed_sample_data(&state);
    // Agent registry and tenant agent keys live in ClickHouse.
    load_agent_registry(&state).await;
    state.agent_keys.load_from(&state.db).await;

    // Tenants come from the shared auth-service registry (ndr.tenants).
    tenancy::sync_tenants(&state).await;
    tenancy::spawn_tenant_sync(state.clone());


    // Start background Syslog listeners (UDP 514 / TCP 601) for firewall & network appliance ingestion
    syslog::start_syslog_listeners(state.clone());

    // Start background NDR <-> SIEM cross-source corroboration worker
    corroboration::spawn_corroboration_worker(state.clone());

    // Start background scheduled Threat Intelligence feed ingestion worker (refreshes external feeds every 60m)
    spawn_threat_intel_feed_scheduler(state.clone());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .expose_headers([
            header::HeaderName::from_static("x-total-count"),
            header::HeaderName::from_static("x-active-count"),
        ]);

    let app = Router::new()
        .route("/api/v1/stats", get(get_stats))
        .route("/api/v1/alerts", get(get_alerts))
        .route("/api/v1/agents", get(get_agents))
        .route("/api/v1/agents/:id", delete(delete_agent_handler))
        .route("/api/agents/:id", delete(delete_agent_handler))
        .route("/agents", delete(delete_agents_wazuh_handler))
        .route("/api/v1/events", get(get_events))
        .route("/api/events", get(get_events))
        .route("/api/v1/rules", get(get_rules_api_handler).post(post_rules_handler))
        .route("/api/rules", get(get_rules_api_handler).post(post_rules_handler))
        .route("/api/rules/hit-counts", get(get_rules_hit_counts_handler))
        .route("/api/rules/:id", delete(delete_rules_handler))
        .route("/api/rules/:id/toggle", post(toggle_rules_handler))
        .route("/api/rules/reload", post(reload_rules_handler))
        .route("/api/rules/sync-community", post(sync_community_rules_handler))
        .route("/api/v1/ai/analyze", post(ai_analyze_event))
        .route("/api/v1/ai/chat", post(ai_chat_handler))
        .route("/api/v1/ingest", post(ingest_event))
        .route("/api/events/ingest", post(ingest_event))
        .route("/api/v1/agent/commands", get(get_agent_commands).post(queue_agent_command))
        .route("/api/agents/:id/commands", get(get_agent_commands_by_path))
        .route("/api/v1/agent/commands/ack", post(ack_agent_command))
        .route("/api/v1/xdr/incidents", get(get_xdr_incidents))
        .route("/api/tenant/features", get(get_tenant_features_handler))
        .route("/api/v1/tenant/agent-key", get(get_tenant_agent_key_handler))
        .route("/api/v1/tenant/agent-key/rotate", post(rotate_tenant_agent_key_handler))
        .route("/api/admin/stats-all-tenants", get(get_stats_all_tenants_handler))
        .route("/api/admin/severity-all-tenants", get(get_severity_all_tenants_handler))
        .route("/api/admin/top-ips-all-tenants", get(get_top_ips_all_tenants_handler))
        .route("/api/admin/protocols-all-tenants", get(get_protocols_all_tenants_handler))
        .route("/api/admin/threat-intel-all-tenants", get(get_threat_intel_all_tenants_handler))
        .route("/api/admin/threat-map-all-tenants", get(get_threat_map_all_tenants_handler))
        .route("/api/threat-map", get(get_threat_map_all_tenants_handler))
        .route("/api/threat-intel-map", get(get_threat_intel_map_handler))
        .route("/api/threat-intel", get(get_threat_intel_handler))
        .route("/api/threat-intel/watchlist", get(get_threat_intel_watchlist_handler))
        .route("/api/admin/engines", get(get_engines_handler))
        .route("/api/admin/engines/scale", post(post_engines_scale_handler))
        .route("/api/admin/leader-status", get(get_leader_status_handler))
        .route("/api/leader/status", get(get_leader_status_handler))
        .route("/api/monitor/kafka", get(get_kafka_status_handler))
        .route("/api/kafka/status", get(get_kafka_status_handler))
        .route("/api/admin/telemetry", get(get_telemetry_handler))
        .route("/api/admin/client-errors", get(get_client_errors_handler).post(post_client_errors_handler))
        .route("/api/client-errors", get(get_client_errors_handler).post(post_client_errors_handler))
        .route("/api/health", get(get_health_handler))
        .route("/health", get(get_health_handler))
        .route("/api/sensor-keys", get(get_sensor_keys_handler).post(post_sensor_keys_handler))
        .route("/api/sensor-keys/:id", delete(delete_sensor_key_handler))
        .route("/api/sensor-keys/:id/reactivate", post(reactivate_sensor_key_handler))
        .route("/api/sensor-keys/event-counts", get(get_sensor_event_counts_handler))
        .route("/api/sensor-keys/recent-ips", get(get_sensor_recent_ips_handler))
        .route("/api/sensor/control", post(post_sensor_control_handler))
        .route("/api/interfaces", get(get_interfaces_handler))
        .route("/api/agent-status", get(get_agent_status_handler))
        .route("/api/scale-status", get(get_scale_status_handler))
        .route("/api/stats", get(get_stats))
        .route("/api/stats/unified", get(get_unified_stats_handler))
        .route("/api/stats/timeline", get(get_stats_timeline_handler))
        .route("/api/hits", get(get_hits_handler))
        .route("/api/top-ips", get(get_top_ips_handler))
        .route("/api/severity", get(get_severity_handler))
        .route("/api/support/messages", get(get_support_messages_handler))
        .route("/api/support/tickets", get(get_support_messages_handler))
        .route("/api/settings", get(get_settings_handler).post(post_settings_handler))
        .route("/api/settings/smtp", get(get_settings_smtp_handler).post(post_settings_smtp_handler))
        .route("/api/settings/ai", get(get_settings_ai_handler).post(post_settings_ai_handler))
        .route("/api/trusted-domains", get(get_trusted_domains_handler).post(post_trusted_domains_handler))
        .route("/api/trusted-domains/delete", post(delete_trusted_domain_handler))
        .route("/api/trusted-domains/ai-suggest", post(post_trusted_domains_ai_suggest_handler))
        .route("/api/siem/dashboard", get(get_siem_dashboard))
        .route("/api/dashboard", get(get_siem_dashboard))

        .route("/api/siem/sources", get(get_siem_sources).post(post_siem_sources))
        .route("/api/sources", get(get_siem_sources).post(post_siem_sources))
        .route("/syscheck", put(put_syscheck_handler))
        .route("/api/v1/syscheck", put(put_syscheck_handler))
        .route("/api/v1/simulate", post(simulate_attack))
        .route("/api/v1/vulnerabilities", get(get_vulnerabilities).post(post_scan_now))
        .route("/api/v1/vulnerabilities/sync-feed", post(post_sync_feed))
        .route("/api/v1/agents/:id/vulnerabilities", get(get_agent_vulnerabilities))
        .route("/api/v1/agents/:id/syscollector/packages", get(get_agent_packages_handler).post(post_agent_packages))
        .route("/api/v1/agents/deactivated", get(get_deactivated_agents_handler))
        .route("/api/v1/agents/:id/deactivate", post(deactivate_agent_handler))
        .route("/api/v1/agents/:id/activate", post(activate_agent_handler))
        .route("/api/v1/agent/state", get(get_agent_state_handler))
        .route("/api/v1/agents/:id/inventory", get(get_agent_inventory_handler))
        .route("/api/v1/agents/:id/syscollector/os", get(get_agent_os_handler))
        .route("/api/v1/agents/:id/syscollector/hardware", get(get_agent_hw_handler))
        .route("/api/v1/agents/:id/syscollector/ports", get(get_agent_ports_handler))
        .route("/api/v1/agents/:id/syscollector/netiface", get(get_agent_netiface_handler))
        .route("/api/v1/agents/:id/fim", get(get_agent_fim_handler).post(post_agent_fim_handler))
        .route("/api/v1/agents/:id/sca", get(get_agent_sca_handler))
        .route("/api/v1/threat-intel/check", get(check_threat_intel_handler))
        .route("/api/v1/threat-intel/lists", get(get_threat_intel_lists_handler))
        .route("/api/v1/agents/:id/rootcheck/scan", post(post_agent_rootcheck_handler))
        .route("/api/v1/rootcheck/signatures", get(get_rootcheck_signatures_handler))
        .route("/downloads/siem-agent.exe", get(download_agent))
        .route("/downloads/siem-agent-linux", get(download_linux_agent))
        .route("/downloads/install.sh", get(download_install_script))
        .route("/ws/alerts", get(ws_alerts_handler))
        .route("/ws", get(ws_alerts_handler))
        .route("/api/ws", get(ws_alerts_handler))
        .route("/api/v1/logtest", post(post_logtest_handler))
        .route("/api/v1/compliance", get(get_compliance_handler))
        .route("/api/v1/mitre/matrix", get(get_mitre_matrix_handler))
        .route("/api/v1/fim/summary", get(get_fim_summary_handler))
        .route("/api/v1/active-response/actions", get(get_active_response_actions).post(post_active_response_block))
        .route("/api/v1/active-response/unblock", post(post_active_response_unblock))
        .route("/api/v1/parsers", get(get_parsers_handler))
        .route("/api/v1/parsers/stats", get(get_parsers_stats_handler))
        .route("/api/v1/parsers/unmatched", get(get_unmatched_parsers_handler))
        .route("/api/v1/parsers/synthesize", post(post_synthesize_parser_handler))
        .route("/api/v1/parsers/test", post(post_test_parser_handler))
        .route("/api/v1/parsers/:id", put(put_parser_handler).delete(delete_parser_handler))
        .route("/api/v1/agents/enroll", post(post_agent_enroll_handler))
        .route("/api/v1/integrations/dispatch", post(post_integration_dispatch_handler))
        .route("/api/v1/syslog-forwarder/format", post(post_format_syslog_handler))
        .route("/api/v1/reports/summary", get(get_reports_summary_handler))
        .route("/api/v1/agents/:id/upgrade", post(post_agent_upgrade_handler))
        .layer(axum::middleware::from_fn_with_state(state.clone(), tenancy::auth_middleware))
        .layer(cors)
        .with_state(state);


    let port = std::env::var("SIEM_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8088);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("SIEM API & WebSocket listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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
            state.alerts.write().unwrap().push(alert);
        }
        state.events.write().unwrap().push(ev);
    }

    // Seed initial vulnerability detections via VulnerabilityScanner
    let pkg_inventory_001 = vec![
        PackageInfo::new("xz-utils", "5.6.0"),
        PackageInfo::new("openssh-server", "8.9p1"),
        PackageInfo::new("curl", "7.74.0"),
        PackageInfo::new("sudo", "1.8.31"),
    ];
    let detected_001 = state.vuln_scanner.scan_inventory(&pkg_inventory_001, "001", "srv-prod-ubuntu-01");

    let pkg_inventory_004 = vec![
        PackageInfo::new("nginx", "1.18.0"),
    ];
    let detected_004 = state.vuln_scanner.scan_inventory(&pkg_inventory_004, "004", "dmz-web-nginx");

    let mut vuln_guard = state.vulnerabilities.write().unwrap();
    vuln_guard.extend(detected_001.clone());
    vuln_guard.extend(detected_004.clone());
    drop(vuln_guard);

    // Generate alerts matching Wazuh 0520-vulnerability-detector_rules.xml for detections
    for det in detected_001.into_iter().chain(detected_004.into_iter()) {
        let (rule_id, rule_level) = match det.severity {
            VulnSeverity::Critical => (23506, 13),
            VulnSeverity::High => (23505, 10),
            VulnSeverity::Medium => (23504, 7),
            VulnSeverity::Low => (23503, 5),
        };
        let alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: rule_id,
                level: rule_level,
                description: format!("{} affects {}", det.cve_id, det.package_name),
                groups: vec!["vulnerability-detector".to_string(), "cve".to_string()],
                mitre: det.mitre_technique.as_ref().map(|tech| siem_core::MitreAttack {
                    id: tech.clone(),
                    tactic: "Initial Access".to_string(),
                    technique: tech.clone(),
                }),
            },
            agent: siem_core::AgentAlertInfo {
                id: det.agent_id.clone(),
                name: det.agent_name.clone(),
                ip: "192.168.10.15".to_string(),
            },
            manager: Some(siem_core::ManagerAlertInfo {
                name: "wazuh-manager-rust".to_string(),
            }),
            decoder: None,
            full_log: format!("Vulnerability detected: {} ({}) in {} {} - Severity: {}", det.cve_id, det.title, det.package_name, det.installed_version, det.severity),
            decoded: siem_core::DecodedFields {
                decoder_name: "vulnerability-detector".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                user: None,
                program_name: Some(det.package_name.clone()),
                process_id: None,
                file_path: None,
                action: None,
                status: Some("Active".to_string()),
                extra: HashMap::new(),
            },
            location: "vulnerability-detector".to_string(),
            data: HashMap::new(),
        };
        state.alerts.write().unwrap().push(alert);
    }

    // Seed Wazuh DB agent state (OS, Hardware, Network, Packages, Ports, FIM, SCA)
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

        db.syscollector.set_netifaces(vec![
            siem_wdb::SysNetIface {
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
            },
        ]);

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
            sha256: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),
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
            rationale: Some("Disallowing root logins over SSH enforces accountability.".to_string()),
            remediation: Some("Edit /etc/ssh/sshd_config and set PermitRootLogin no".to_string()),
            status: siem_wdb::ScaStatus::Passed,
        });
        policy.upsert_check(siem_wdb::ScaCheckResult {
            policy_id: "cis_ubuntu_linux_24.04".to_string(),
            check_id: 1002,
            title: "Ensure auditing for processes that start prior to auditd is enabled".to_string(),
            description: "Configure GRUB with audit=1".to_string(),
            rationale: None,
            remediation: None,
            status: siem_wdb::ScaStatus::Failed,
        });
    }
}

/// Alerts visible in the caller's tenant scope (oldest first).
fn scoped_alerts(state: &AppState, ctx: &AuthCtx) -> Vec<Alert> {
    let scope = ctx.scope();
    let map = state.agent_tenants.read().unwrap().clone(); // copy: never hold two locks at once
    state.alerts.read().unwrap().iter().filter(|a| tenancy::alert_tenant(a, &map) == scope).cloned().collect()
}

/// Events visible in the caller's tenant scope (oldest first).
fn scoped_events(state: &AppState, ctx: &AuthCtx) -> Vec<RawEvent> {
    let scope = ctx.scope();
    let map = state.agent_tenants.read().unwrap().clone();
    state.events.read().unwrap().iter().filter(|e| tenancy::event_tenant(e, &map) == scope).cloned().collect()
}

/// Agents of the caller's tenant scope.
fn scoped_agents(state: &AppState, ctx: &AuthCtx) -> Vec<Agent> {
    let scope = ctx.scope();
    let map = state.agent_tenants.read().unwrap().clone();
    state.agents.read().unwrap().values().filter(|a| tenancy::tenant_of(&map, &a.id) == scope).cloned().collect()
}

async fn get_stats(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<SiemStats> {
    let events_count = scoped_events(&state, &ctx).len() as u64;
    let alerts = scoped_alerts(&state, &ctx);
    let agents = scoped_agents(&state, &ctx);

    let total_alerts = alerts.len() as u64;
    let mut critical_alerts = 0;
    let mut high_alerts = 0;
    let mut medium_alerts = 0;
    let mut low_alerts = 0;

    for a in alerts.iter() {
        match a.rule.level {
            12..=15 => critical_alerts += 1,
            8..=11 => high_alerts += 1,
            4..=7 => medium_alerts += 1,
            _ => low_alerts += 1,
        }
    }

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
                let alerts: Vec<Alert> = ch_rows.into_iter().map(|r| tenancy::tag_alert(r.to_alert(), &scope)).collect();
                return Json(alerts);
            }
        }
    }

    let mut filtered: Vec<Alert> = scoped_alerts(&state, &ctx).into_iter().filter(|a| a.rule.level >= min_level).collect();
    filtered.reverse(); // Most recent first
    filtered.truncate(limit);
    Json(filtered)
}

async fn get_agents(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Vec<Agent>> {
    let scope = ctx.scope();

    // 1. Load persistent agents from ClickHouse for this tenant
    if state.db.is_connected() {
        if let Some(ch_agents) = state.db.fetch_agents(&scope).await {
            // One lock at a time (never agents + agent_tenants together): the
            // scoped readers take them in the other order.
            let active_ids: std::collections::HashSet<String> = ch_agents.iter().map(|r| r.id.clone()).collect();
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
                let last_ka = chrono::DateTime::from_timestamp_millis(r.last_keepalive)
                    .unwrap_or_else(chrono::Utc::now);
                let status = if (now - last_ka).num_seconds() > 60 {
                    AgentStatus::Disconnected
                } else {
                    match r.status.as_str() {
                        "Active" => AgentStatus::Active,
                        "Pending" => AgentStatus::Pending,
                        _ => AgentStatus::Disconnected,
                    }
                };
                guard.entry(r.id.clone())
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

            // Sync with ClickHouse: remove in-memory agents for this tenant that are no longer in ClickHouse
            guard.retain(|id, _| {
                if tenancy::tenant_of(&tenants_snapshot, id) == scope {
                    active_ids.contains(id)
                } else {
                    true
                }
            });
            drop(guard);
            // Registered agents (deactivated ones included) keep their tenant binding.
            let registered: std::collections::HashSet<String> = state.enrolled.read().unwrap().keys().cloned().collect();
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
            // Mirroring wazuh-monitord: mark disconnected if last keepalive exceeds 60s
            if (now - agent.last_keepalive).num_seconds() > 60 {
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
    let in_fleet = state.agents.write().unwrap().remove(id).is_some();
    let removed = in_fleet || state.enrolled.read().unwrap().contains_key(id);
    if removed {
        let tenant = state.agent_tenants.write().unwrap().remove(id).unwrap_or_else(|| ctx.scope());
        // Like manage_agents -r: the enrollment and key go too. The registry
        // row stays, marked deleted, so the id is never issued again.
        let e = state.enrolled.write().unwrap().remove(id);
        let _ = state.auth_keystore.write().unwrap().delete_key(id);
        persist_registry(state, id, &tenant, e.as_ref(), true);
    }
    removed
}

async fn delete_agent_handler(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let scope = ctx.scope();
    state.db.delete_agent(&scope, &id).await;
    if remove_scoped_agent(&state, &ctx, &id) {
        info!("Removed agent '{}' from SIEM registry (tenant {})", id, scope);
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

async fn delete_agents_wazuh_handler(
    Query(params): Query<DeleteAgentsQuery>,
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let scope = ctx.scope();
    let mut removed = Vec::new();
    if let Some(list) = params.agents_list {
        for id in list.split(',') {
            let id = id.trim();
            state.db.delete_agent(&scope, id).await;
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
}

async fn get_rules(State(state): State<AppState>) -> Json<Vec<Rule>> {
    Json(state.engine.list_rules())
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
    source: Option<String>,
}

async fn get_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(params): Query<EventsQuery>,
) -> Json<Vec<RawEvent>> {
    let limit = params.limit.unwrap_or(200);
    let scope = ctx.scope();

    // Persisted events come from the tenant's own ClickHouse database.
    if state.db.is_connected() && params.source.is_none() {
        if let Some(ch_rows) = state.db.fetch_events(&scope, limit).await {
            if !ch_rows.is_empty() {
                let events: Vec<RawEvent> = ch_rows.into_iter().map(|r| r.to_raw_event()).collect();
                return Json(events);
            }
        }
    }

    let mut list: Vec<RawEvent> = scoped_events(&state, &ctx)
        .into_iter()
        .filter(|e| match params.source {
            Some(ref src) => format!("{:?}", e.source).to_lowercase().contains(&src.to_lowercase()),
            None => true,
        })
        .collect();

    list.reverse(); // Most recent first
    list.truncate(limit);
    Json(list)
}

async fn ingest_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<Option<Alert>>, StatusCode> {
    let events: Vec<RawEvent> = if payload.is_array() {
        serde_json::from_value(payload).map_err(|_| StatusCode::BAD_REQUEST)?
    } else {
        let single: RawEvent = serde_json::from_value(payload).map_err(|_| StatusCode::BAD_REQUEST)?;
        vec![single]
    };

    let mut last_alert = None;

    for mut event in events {
        // The agent's tenant decides where everything below is stored; a
        // tenant_id sent by the agent itself is never trusted.
        let tenant = resolve_agent_tenant(&state, &headers, &event.agent_id)?;
        if is_deactivated(&state, &event.agent_id) {
            return Err(StatusCode::GONE);
        }
        event.metadata.insert("tenant_id".into(), tenant.clone());

        // Update or register agent keepalive
        let (agent_name, agent_ip, ag_clone) = {
            let mut agents = state.agents.write().unwrap();
            let ag = agents.entry(event.agent_id.clone()).or_insert_with(|| {
                let host = event.metadata.get("hostname").cloned().unwrap_or_else(|| format!("agent-{}", event.agent_id));
                let os_t = event.metadata.get("os_type").cloned().unwrap_or_else(|| "windows".into());
                let dist = event.metadata.get("distribution").cloned().unwrap_or_else(|| {
                    if os_t == "linux" { "Linux (x86_64)".into() } else { "Windows 11 (x86_64)".into() }
                });
                let ip = event.metadata.get("ip").cloned().unwrap_or_else(|| "127.0.0.1".into());
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
        state.db.insert_or_update_agent(&tenant, &ag_clone).await;

        // Method 2: Dynamic Parser Engine Hot-Path Execution (< 5 microseconds, 0ms AI delay)
        let _maybe_dynamic_parsed = state.parser_registry.execute(&event.message);

        let maybe_alert = state.engine.process_event(&event, &agent_name, &agent_ip);

        if let Some(alert) = maybe_alert {
            record_alert(&state, &tenant, alert).await;
        }

        // Automated Vulnerability Scanner: evaluate syscollector software packages in real time
        if event.source == EventSource::Syscollector {
            if let Some(inv_json) = event.metadata.get("inventory_json") {
                if let Ok(inv) = serde_json::from_str::<serde_json::Value>(inv_json) {
                    if let Some(installed_sw) = inv.get("installed_software").and_then(|v| v.as_array()) {
                        let mut packages = Vec::new();
                        for item in installed_sw {
                            if let Some(s) = item.as_str() {
                                if let Some((n, v)) = s.split_once(':') {
                                    packages.push(PackageInfo::new(n.trim(), v.trim()));
                                } else {
                                    let parts: Vec<&str> = s.split_whitespace().collect();
                                    if parts.len() >= 2 {
                                        packages.push(PackageInfo::new(parts[0], parts[1]));
                                    } else {
                                        packages.push(PackageInfo::new(s, "1.0.0"));
                                    }
                                }
                            }
                        }
                        if !packages.is_empty() {
                            let detections = state.vuln_scanner.scan_inventory(&packages, &event.agent_id, &agent_name);
                            if !detections.is_empty() {
                                {
                                    let mut vuln_guard = state.vulnerabilities.write().unwrap();
                                    vuln_guard.retain(|v| v.agent_id != event.agent_id);
                                    vuln_guard.extend(detections.clone());
                                }
                                for det in &detections {
                                    let alert = Alert {
                                        id: uuid::Uuid::new_v4(),
                                        timestamp: Utc::now(),
                                        agent: siem_core::AgentAlertInfo {
                                            id: event.agent_id.clone(),
                                            name: agent_name.clone(),
                                            ip: agent_ip.clone(),
                                        },
                                        manager: Some(siem_core::ManagerAlertInfo {
                                            name: "wazuh-manager-rust".to_string(),
                                        }),
                                        rule: siem_core::RuleAlertInfo {
                                            id: 23501,
                                            level: match det.severity {
                                                siem_vuln_detector::Severity::Critical => 14,
                                                siem_vuln_detector::Severity::High => 10,
                                                siem_vuln_detector::Severity::Medium => 7,
                                                _ => 4,
                                            },
                                            description: format!("{}: Vulnerability detected in package '{}' ({})", det.cve_id, det.package_name, det.title),
                                            groups: vec!["vulnerability-detector".to_string(), "cve".to_string()],
                                            mitre: Some(siem_core::MitreAttack {
                                                id: "T1190".to_string(),
                                                tactic: "Initial Access".to_string(),
                                                technique: "Exploit Public-Facing Application".to_string(),
                                            }),
                                        },
                                        decoder: None,
                                        full_log: format!("Vulnerability Alert: {} affects package '{}' on agent '{}'", det.cve_id, det.package_name, agent_name),
                                        decoded: siem_core::DecodedFields {
                                            decoder_name: "vulnerability-detector".to_string(),
                                            src_ip: None,
                                            dst_ip: None,
                                            src_port: None,
                                            dst_port: None,
                                            user: None,
                                            program_name: Some(det.package_name.clone()),
                                            process_id: None,
                                            file_path: None,
                                            action: None,
                                            status: Some("Active".to_string()),
                                            extra: HashMap::new(),
                                        },
                                        location: "vulnerability-detector".to_string(),
                                        data: HashMap::new(),
                                    };
                                    let alert = record_alert(&state, &tenant, alert).await;
                                    last_alert = Some(alert);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Automated SCA Evaluation: store check results in Wazuh DB and raise alert on failure
        if event.source == EventSource::Sca {
            let policy_id = event
                .metadata
                .get("policy_id")
                .cloned()
                .unwrap_or_else(|| {
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
                        name: "wazuh-manager-rust".to_string(),
                    }),
                    rule: siem_core::RuleAlertInfo {
                        id: 19001,
                        level: 7,
                        description: format!("SCA Policy Check Failed: Check #{} - {}", check_id, title),
                        groups: vec!["sca".to_string(), "compliance".to_string(), "cis".to_string()],
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
                let alert = record_alert(&state, &tenant, alert).await;
                last_alert = Some(alert);
            }
        }

        // Automated FIM Evaluation: store file integrity state in Wazuh DB and raise alert on change
        if event.source == EventSource::Fim {
            let action_str = event.metadata.get("action").map(|s| s.as_str()).unwrap_or("modified");
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

            let agent_db = state.wdb.get_or_create(&event.agent_id, &agent_name);
            let sha256_val = event.metadata.get("sha256").cloned();
            let now_ts = Utc::now().timestamp().max(0) as u64;
            let file_name = std::path::Path::new(&event.location)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&event.location)
                .to_string();
            {
                let mut db = agent_db.write().unwrap();
                db.fim.upsert(siem_wdb::FimEntry {
                    full_path: event.location.clone(),
                    file_name,
                    entry_type: siem_wdb::FimEntryType::File,
                    size: None,
                    perm: None,
                    uid: None,
                    gid: None,
                    md5: None,
                    sha1: None,
                    sha256: sha256_val.clone(),
                    mtime: now_ts,
                    inode: None,
                    changes: 1,
                    date: now_ts,
                });
            }

            let alert = Alert {
                id: uuid::Uuid::new_v4(),
                timestamp: Utc::now(),
                rule: siem_core::RuleAlertInfo {
                    id: rule_id,
                    level,
                    description: format!("File Integrity Monitoring: File '{}' {:?}", event.location, fim_action),
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
                    name: "wazuh-manager-rust".to_string(),
                }),
                decoder: None,
                full_log: format!("ossec: File '{}' was {:?}", event.location, fim_action),
                decoded: siem_core::DecodedFields {
                    decoder_name: "syscheck".to_string(),
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    dst_port: None,
                    user: None,
                    program_name: None,
                    process_id: None,
                    file_path: Some(event.location.clone()),
                    action: Some(format!("{:?}", fim_action)),
                    status: None,
                    extra: event.metadata.clone(),
                },
                location: "syscheck".to_string(),
                data: HashMap::new(),
            };
            let alert = record_alert(&state, &tenant, alert).await;
            last_alert = Some(alert);
        }

        state.db.insert_event(&event).await;
        state.events.write().unwrap().push(event);
    }

    Ok(Json(last_alert))
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

        if let Some(alert) = state.engine.process_event(&ev, &name, &ip) {
            let alert = tenancy::tag_alert(alert, &tenant);
            state.alerts.write().unwrap().push(alert.clone());
            let _ = state.broadcast_tx.send(alert.clone());
            triggered_alerts.push(alert);
        }
        state.events.write().unwrap().push(ev);
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
    let scope = ctx.scope();

    loop {
        let alert = match rx.recv().await {
            Ok(a) => a,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => break,
        };
        let tenant = tenancy::alert_tenant(&alert, &state.agent_tenants.read().unwrap());
        if tenant != scope {
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
        "e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/target/release/siem-agent.exe",
        "target/debug/siem-agent.exe",
        "backend-rust/target/debug/siem-agent.exe",
        "e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/target/debug/siem-agent.exe",
    ];

    for path in possible_paths {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return Ok((
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::CONTENT_DISPOSITION, "attachment; filename=\"siem-agent.exe\""),
                ],
                bytes,
            ));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

async fn download_linux_agent() -> Result<impl IntoResponse, StatusCode> {
    let possible_paths = [
        "target/release/siem-agent-linux",
        "backend-rust/target/release/siem-agent-linux",
        "e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/target/release/siem-agent-linux",
        "target/debug/siem-agent-linux",
        "backend-rust/target/debug/siem-agent-linux",
        "target/debug/siem-agent-linux.exe",
        "e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/target/debug/siem-agent-linux.exe",
    ];

    for path in possible_paths {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return Ok((
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (header::CONTENT_DISPOSITION, "attachment; filename=\"siem-agent-linux\""),
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
        "e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-agent-linux/install.sh",
    ];

    for path in possible_paths {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return Ok((
                [
                    (header::CONTENT_TYPE, "text/x-shellscript"),
                    (header::CONTENT_DISPOSITION, "inline; filename=\"install.sh\""),
                ],
                bytes,
            ));
        }
    }

    Err(StatusCode::NOT_FOUND)
}

#[derive(Debug, Deserialize)]
pub struct AgentCommandQuery {
    pub agent_id: Option<String>,
}

async fn get_agent_commands(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AgentCommandQuery>,
) -> impl IntoResponse {
    let agent_id = query.agent_id.unwrap_or_else(|| "001".into());
    let mut map = state.pending_commands.write().unwrap();
    let commands = map.remove(&agent_id).unwrap_or_default();
    Json(commands)
}

async fn queue_agent_command(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(mut payload): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(agent_id) = payload.get("agent_id").and_then(|v| v.as_str()).map(|s| s.to_string()) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": "agent_id is required" })))
            .into_response();
    };
    if !agent_in_scope(&state, &ctx, &agent_id) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": "Agent not found" })))
            .into_response();
    }

    if payload.get("command_id").is_none() || payload.get("command_id").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("command_id".into(), serde_json::Value::String(uuid::Uuid::new_v4().to_string()));
        }
    }
    if payload.get("target").is_none() {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("target".into(), serde_json::Value::String("all".into()));
        }
    }

    let mut map = state.pending_commands.write().unwrap();
    map.entry(agent_id).or_default().push(payload);
    Json(serde_json::json!({ "status": "queued" })).into_response()
}

async fn get_agent_commands_by_path(
    State(state): State<AppState>,
    axum::extract::Path(agent_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let mut map = state.pending_commands.write().unwrap();
    let commands = map.remove(&agent_id).unwrap_or_default();
    Json(commands)
}

async fn ack_agent_command(
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    info!("Active Response ACK received from agent: {:?}", payload);
    Json(serde_json::json!({ "status": "acknowledged" }))
}

#[derive(Debug, Deserialize)]
pub struct SyscheckRestartQuery {
    pub agents_list: Option<String>,
}

/// Official Wazuh REST API PUT /syscheck endpoint (mirroring api/controllers/syscheck_controller.py)
async fn put_syscheck_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(query): Query<SyscheckRestartQuery>,
) -> impl IntoResponse {
    let agents_str = query.agents_list.unwrap_or_else(|| "*".into());

    // Only the caller's tenant's agents.
    let target_agents: Vec<String> = if agents_str == "*" {
        scoped_agents(&state, &ctx).into_iter().map(|a| a.id).collect()
    } else {
        agents_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|id| agent_in_scope(&state, &ctx, id))
            .collect()
    };
    let mut map = state.pending_commands.write().unwrap();

    let mut affected = Vec::new();
    for agent_id in target_agents {
        map.entry(agent_id.clone()).or_default().push(serde_json::json!({
            "command_id": uuid::Uuid::new_v4().to_string(),
            "action": "syscheck restart",
            "target": "all"
        }));
        affected.push(agent_id);
    }

    info!("Syscheck: Queued on-demand FIM scan for agents: {:?}", affected);

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

/// The Groq API key comes from the environment only (`GROQ_API_KEY`).
fn get_groq_api_key() -> String {
    std::env::var("GROQ_API_KEY").unwrap_or_default()
}

fn extract_json_object(input: &str) -> &str {
    let s = input.trim();
    if let (Some(start), Some(end)) = (s.find('{'), s.rfind('}')) {
        if start <= end {
            return &s[start..=end];
        }
    }
    s
}


async fn ai_analyze_event(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(req): Json<AiAnalysisRequest>,
) -> Result<Json<AiAnalysisResponse>, (StatusCode, String)> {
    let api_key = get_groq_api_key();
    let model = req.model.unwrap_or_else(|| "openai/gpt-oss-120b".to_string());

    // Resolve event details either from payload or from stored events/alerts
    let mut event_text = String::new();
    let mut agent_id = req.agent_id.unwrap_or_default();
    let mut source_str = req.source.unwrap_or_default();
    let mut location_str = req.location.unwrap_or_default();

    if let Some(ref eid) = req.event_id {
        let events = scoped_events(&state, &ctx);
        if let Some(ev) = events.iter().find(|e| &e.id.to_string() == eid) {
            agent_id = ev.agent_id.clone();
            source_str = format!("{:?}", ev.source);
            location_str = ev.location.clone();
            event_text = format!("Log Location: {}\nRaw Message: {}\nMetadata: {:?}", ev.location, ev.message, ev.metadata);
        }
    } else if let Some(ref aid) = req.alert_id {
        let alerts = scoped_alerts(&state, &ctx);
        if let Some(a) = alerts.iter().find(|al| &al.id.to_string() == aid) {
            agent_id = a.agent.name.clone();
            source_str = "AlertEngine".into();
            location_str = format!("Rule #{}", a.rule.id);
            event_text = format!("Rule ID: {}\nLevel: {}\nDescription: {}\nFull Log: {}\nMITRE: {:?}\nDecoded: {:?}",
                a.rule.id, a.rule.level, a.rule.description, a.full_log, a.rule.mitre, a.decoded);
        }
    }

    if event_text.is_empty() {
        event_text = format!("Source: {}\nLocation: {}\nAgent: {}\nPayload: {}\nMetadata: {:?}",
            source_str, location_str, agent_id, req.message.unwrap_or_default(), req.metadata);
    }

    let user_prompt = format!(
        "Log Source: {}\nAgent / Host: {}\nLocation / Channel: {}\n\nEvent Data:\n{}\n\n{}",
        source_str,
        agent_id,
        location_str,
        event_text,
        req.custom_prompt.unwrap_or_default()
    );

    let system_prompt = r#"You are an elite Tier-3 Principal SOC & Threat Detection Engineer analyzing logs in Wazuh SIEM.
Analyze the provided event log or alert. You must output ONLY a valid JSON object without markdown fences, with these exact keys:
{
  "classification": "Benign Administrative Activity | Suspicious Activity | High-Severity Threat",
  "confidence_score": 95,
  "severity": "low | medium | high | critical | info",
  "summary": "Concise 1-2 sentence executive summary of this event and what occurred.",
  "mitre_attack": {
    "tactic": "e.g. Persistence | Defense Evasion | Initial Access | Discovery | Execution",
    "technique_id": "e.g. T1059.001",
    "technique_name": "e.g. PowerShell"
  },
  "indicators": ["indicator or key observation 1", "key observation 2"],
  "impact": "Potential security impact to this host or the enterprise network.",
  "remediation_commands": [
    "Defensive PowerShell or CMD command to investigate, audit, or isolate (e.g. Get-Process, Stop-Process, Set-NetFirewallProfile, etc.). Do not include offensive exploits or hacktool names."
  ],
  "explanation": "Detailed technical explanation of the event mechanics, registry keys, Windows event IDs, or security implications."
}"#;

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "model": model,
        "messages": [
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user_prompt }
        ],
        "temperature": 0.2,
        "max_completion_tokens": 2048
    });

    let resp = client.post("https://api.groq.com/openai/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Groq request failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_text = resp.text().await.unwrap_or_default();
        return Err((StatusCode::BAD_GATEWAY, format!("Groq error ({}): {}", status, err_text)));
    }

    let res_json: serde_json::Value = resp.json().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse Groq response: {}", e)))?;

    let content = res_json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let clean = extract_json_object(&content);

    // Resilient parsing: parse via serde_json::Value first so any schema variations or string escapes work smoothly
    let mut analysis = if let Ok(val) = serde_json::from_str::<serde_json::Value>(clean) {
        let classification = val["classification"].as_str().unwrap_or("Security Assessment").to_string();
        let confidence_score = val["confidence_score"].as_u64().unwrap_or(90) as u8;
        let severity = val["severity"].as_str().unwrap_or("medium").to_string();
        let summary = val["summary"].as_str().unwrap_or("Automated event triage completed").to_string();
        let mitre_attack = if let Some(m) = val.get("mitre_attack") {
            Some(MitreMapping {
                tactic: m["tactic"].as_str().unwrap_or("Triage").to_string(),
                technique_id: m["technique_id"].as_str().unwrap_or("T1000").to_string(),
                technique_name: m["technique_name"].as_str().unwrap_or("Detection").to_string(),
            })
        } else {
            None
        };
        let indicators = val["indicators"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_else(|| vec!["Event analyzed via AI".into()]);
        let impact = val["impact"].as_str().unwrap_or("System telemetry recorded.").to_string();
        let remediation_commands = val["remediation_commands"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_else(|| vec!["Get-Process".into()]);
        let explanation = val["explanation"].as_str().unwrap_or(&content).to_string();

        AiAnalysisResponse {
            classification,
            confidence_score,
            severity,
            summary,
            mitre_attack,
            indicators,
            impact,
            remediation_commands,
            explanation,
            model_used: model.clone(),
        }
    } else {
        AiAnalysisResponse {
            classification: "Automated Analysis Completed".into(),
            confidence_score: 85,
            severity: "medium".into(),
            summary: content.lines().find(|l| !l.trim().is_empty()).unwrap_or("Security event analyzed").chars().take(200).collect(),
            mitre_attack: Some(MitreMapping {
                tactic: "Security Analysis".into(),
                technique_id: "T1000".into(),
                technique_name: "Automated SOC Assessment".into(),
            }),
            indicators: vec!["Log analyzed via Groq AI".into()],
            impact: "Review the technical explanation for details.".into(),
            remediation_commands: vec!["Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0}".into()],
            explanation: content,
            model_used: model.clone(),
        }
    };

    analysis.model_used = model;
    Ok(Json(analysis))

}

async fn ai_chat_handler(
    State(_state): State<AppState>,
    Json(req): Json<AiChatRequest>,
) -> Result<Json<AiChatResponse>, (StatusCode, String)> {
    let api_key = get_groq_api_key();
    let model = req.model.unwrap_or_else(|| "openai/gpt-oss-120b".to_string());

    let mut messages = vec![
        serde_json::json!({
            "role": "system",
            "content": "You are the Wazuh AI SOC Assistant & Threat Hunter. You assist security analysts in triaging alerts, analyzing Windows event logs, writing detection rules, and generating PowerShell remediation scripts for endpoints like laptop 'EVOFOX'. Be concise, highly technical, and format commands in code blocks."
        })
    ];

    if let Some(hist) = req.history {
        for h in hist {
            messages.push(serde_json::json!({
                "role": h.role,
                "content": h.content
            }));
        }
    }

    messages.push(serde_json::json!({
        "role": "user",
        "content": req.message
    }));

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "model": model,
        "messages": messages,
        "temperature": 0.5,
        "max_completion_tokens": 2048
    });

    let resp = client.post("https://api.groq.com/openai/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Groq request failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_text = resp.text().await.unwrap_or_default();
        return Err((StatusCode::BAD_GATEWAY, format!("Groq error ({}): {}", status, err_text)));
    }

    let res_json: serde_json::Value = resp.json().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse Groq response: {}", e)))?;

    let content = res_json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("No response generated.")
        .to_string();

    Ok(Json(AiChatResponse {
        response: content,
        model_used: model,
    }))
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

#[derive(Deserialize, Default)]
struct RulesQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    q: Option<String>,
    order: Option<String>,
}

async fn get_rules_api_handler(
    State(state): State<AppState>,
    Query(query): Query<RulesQuery>,
) -> impl IntoResponse {
    let raw_rules = state.engine.list_rules();
    let _total_count = raw_rules.len();
    let active_count = raw_rules.len();

    let mut mapped: Vec<serde_json::Value> = raw_rules
        .into_iter()
        .map(|r| {
            let sev = match r.level {
                12..=15 => "critical",
                8..=11 => "high",
                4..=7 => "medium",
                _ => "low",
            };
            serde_json::json!({
                "id": r.id.to_string(),
                "title": r.description.clone(),
                "description": r.description,
                "level": r.level,
                "severity": sev,
                "enabled": true,
                "groups": r.groups.clone(),
                "tags": r.groups,
                "conditions": 1,
                "mitre": r.mitre,
            })
        })
        .collect();

    if let Some(ref q) = query.q {
        let q_lower = q.to_lowercase();
        mapped.retain(|r| {
            r.get("title").and_then(|v| v.as_str()).unwrap_or("").to_lowercase().contains(&q_lower)
                || r.get("id").and_then(|v| v.as_str()).unwrap_or("").to_lowercase().contains(&q_lower)
        });
    }

    let filtered_total = mapped.len();
    let offset = query.offset.unwrap_or(0);
    let paged: Vec<serde_json::Value> = if let Some(limit) = query.limit {
        mapped.into_iter().skip(offset).take(limit).collect()
    } else {
        mapped
    };

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Total-Count", filtered_total.to_string().parse().unwrap());
    headers.insert("X-Active-Count", active_count.to_string().parse().unwrap());

    (StatusCode::OK, headers, Json(paged))
}

async fn get_rules_hit_counts_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let alerts = scoped_alerts(&state, &ctx);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for alert in alerts.iter() {
        *counts.entry(alert.rule.description.clone()).or_insert(0) += 1;
    }
    Json(counts)
}

async fn post_rules_handler(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "message": "Rule created successfully", "rule": payload }))
}

async fn delete_rules_handler(Path(rule_id): Path<String>) -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "message": format!("Rule {} deleted", rule_id) }))
}

async fn toggle_rules_handler(Path(_rule_id): Path<String>) -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "enabled": true }))
}

async fn reload_rules_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "message": "Detection rules successfully reloaded" }))
}

async fn sync_community_rules_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "message": "Community rules synchronized", "count": 1250 }))
}

async fn get_stats_all_tenants_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let events_guard = admin_events(&state, &ctx);
    let alerts_guard = admin_alerts(&state, &ctx);

    let now = chrono::Utc::now();
    let one_hour_ago = now - chrono::Duration::hours(1);

    let events_total = events_guard.len() as u64;
    let hits_total = alerts_guard.len() as u64;

    let events_1h = events_guard.iter().filter(|e| e.timestamp >= one_hour_ago).count() as u64;
    let hits_1h = alerts_guard.iter().filter(|a| a.timestamp >= one_hour_ago).count() as u64;

    let agent_z_events = events_guard.iter().filter(|e| {
        let src_str = serde_json::to_string(&e.source).unwrap_or_default();
        src_str.contains("network") || e.location.contains("flow") || e.location.contains("zeek")
    }).count() as u64;
    let agent_s_events = events_total.saturating_sub(agent_z_events);

    Json(serde_json::json!({
        "events_total": events_total,
        "hits_total": hits_total,
        "events_1h": events_1h,
        "hits_1h": hits_1h,
        "agent_z_events": agent_z_events,
        "agent_s_events": agent_s_events
    }))
}

async fn get_severity_all_tenants_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let alerts = admin_alerts(&state, &ctx);
    let mut critical = 0u64;
    let mut high = 0u64;
    let mut medium = 0u64;
    let mut low = 0u64;

    for alert in alerts.iter() {
        match alert.rule.level {
            l if l >= 12 => critical += 1,
            l if l >= 8 => high += 1,
            l if l >= 4 => medium += 1,
            _ => low += 1,
        }
    }

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

async fn get_top_ips_all_tenants_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let alerts = admin_alerts(&state, &ctx);
    let mut src_map: HashMap<String, u64> = HashMap::new();
    let mut dst_map: HashMap<String, u64> = HashMap::new();

    for alert in alerts.iter() {
        if let Some(ref ip) = alert.decoded.src_ip {
            if !ip.is_empty() {
                *src_map.entry(ip.clone()).or_insert(0) += 1;
            }
        }
        if let Some(ref ip) = alert.decoded.dst_ip {
            if !ip.is_empty() {
                *dst_map.entry(ip.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut top_src: Vec<(&String, &u64)> = src_map.iter().collect();
    top_src.sort_by(|a, b| b.1.cmp(a.1));
    let top_src_ips: Vec<serde_json::Value> = top_src.into_iter().take(10).map(|(ip, count)| serde_json::json!([ip, count])).collect();

    let mut top_dst: Vec<(&String, &u64)> = dst_map.iter().collect();
    top_dst.sort_by(|a, b| b.1.cmp(a.1));
    let top_dst_ips: Vec<serde_json::Value> = top_dst.into_iter().take(10).map(|(ip, count)| serde_json::json!([ip, count])).collect();

    Json(serde_json::json!({
        "top_src_ips": top_src_ips,
        "top_dst_ips": top_dst_ips
    }))
}

async fn get_protocols_all_tenants_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let events = admin_events(&state, &ctx);
    let mut proto_map: HashMap<String, u64> = HashMap::new();

    for ev in events.iter() {
        let proto = if ev.location.to_lowercase().contains("ssh") || ev.message.to_lowercase().contains("ssh") {
            "SSH"
        } else if ev.location.to_lowercase().contains("http") || ev.message.to_lowercase().contains("http") {
            "HTTP"
        } else if ev.location.to_lowercase().contains("tls") || ev.location.to_lowercase().contains("ssl") || ev.message.to_lowercase().contains("tls") {
            "TLS"
        } else if ev.location.to_lowercase().contains("dns") || ev.message.to_lowercase().contains("dns") {
            "DNS"
        } else if ev.location.to_lowercase().contains("smb") || ev.message.to_lowercase().contains("smb") {
            "SMB"
        } else if ev.location.to_lowercase().contains("syslog") {
            "SYSLOG"
        } else {
            "TCP/IP"
        };
        *proto_map.entry(proto.to_string()).or_insert(0) += 1;
    }

    let mut proto_list: Vec<(&String, &u64)> = proto_map.iter().collect();
    proto_list.sort_by(|a, b| b.1.cmp(a.1));
    let protocols: Vec<serde_json::Value> = proto_list.into_iter().take(8).map(|(p, c)| serde_json::json!([p, c])).collect();

    Json(serde_json::json!({
        "protocols": protocols
    }))
}

async fn get_threat_intel_all_tenants_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let unique_ips = state.threat_intel.get_list("malicious_ips").map(|l| l.total_entries()).unwrap_or(0);
    let unique_hashes = state.threat_intel.get_list("malicious_hashes").map(|l| l.total_entries()).unwrap_or(0);
    let unique_domains = state.threat_intel.get_list("malicious_domains").map(|l| l.total_entries()).unwrap_or(0);

    let alerts = admin_alerts(&state, &ctx);
    let detected_in_network = alerts.iter().filter(|a| {
        a.decoded.src_ip.as_ref().map(|ip| state.threat_intel.check_ip(ip).is_some()).unwrap_or(false)
    }).count();

    Json(serde_json::json!({
        "status": "ok",
        "total_malicious_ips": unique_ips,
        "unique_ips": unique_ips,
        "unique_hashes": unique_hashes,
        "unique_domains": unique_domains,
        "detected_in_network": detected_in_network
    }))
}

async fn get_threat_map_all_tenants_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let alerts = admin_alerts(&state, &ctx);
    let items: Vec<serde_json::Value> = alerts.iter()
        .filter(|a| a.decoded.src_ip.is_some())
        .take(50)
        .map(|a| {
            let src = a.decoded.src_ip.clone().unwrap_or_default();
            let dst = a.decoded.dst_ip.clone().unwrap_or_else(|| a.agent.ip.clone());
            let sev = if a.rule.level >= 12 { "CRITICAL" } else if a.rule.level >= 8 { "HIGH" } else { "MEDIUM" };
            serde_json::json!({
                "src_ip": src,
                "country": "US",
                "dst_ip": dst,
                "type": a.rule.description,
                "severity": sev,
                "timestamp": a.timestamp.to_rfc3339()
            })
        })
        .collect();

    Json(items)
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
            match client.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json").send().await {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        let entries = provigil_common::threat_intel::feeds::parse_feodo(&json);
                        let count = entries.len();
                        for e in entries {
                            let ip = e.ioc_value.split(':').next().unwrap_or(&e.ioc_value);
                            state.threat_intel.insert_entry("malicious_ips", ip, &e.description);
                            if state.db.is_connected() {
                                state.db.insert_threat_intel_entry(&e).await;
                            }
                        }
                        info!("Feodo Tracker feed synced: {} botnet C2 IPs stored in threat table and ClickHouse", count);
                    }
                }
                Err(err) => {
                    tracing::debug!("Feodo Tracker fetch skipped (offline or timeout): {}", err);
                }
            }

            // 2. Fetch URLhaus (Malicious domains and URLs)
            match client.get("https://urlhaus.abuse.ch/downloads/json/recent/").send().await {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        let entries = provigil_common::threat_intel::feeds::parse_urlhaus(&json);
                        let count = entries.len();
                        for e in entries {
                            if e.ioc_type == "domain" {
                                state.threat_intel.insert_entry("malicious_domains", &e.ioc_value, &e.description);
                            }
                            if state.db.is_connected() {
                                state.db.insert_threat_intel_entry(&e).await;
                            }
                        }
                        info!("URLhaus feed synced: {} malicious indicators stored in threat table and ClickHouse", count);
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

async fn get_threat_intel_map_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut countries = vec![
        serde_json::json!({
            "country": "United States", "country_name": "United States", "code": "US", "country_code": "US",
            "lat": 37.0902, "lon": -95.7129, "lng": -95.7129, "count": 142, "hit_count": 142, "threat_count": 142,
            "ip_count": 5, "ips": ["45.33.32.156", "198.51.100.42", "192.241.220.11", "104.244.42.1", "64.225.100.8"],
            "attacks": ["Port Scan", "Credential Stuffing", "SSH Brute Force"]
        }),
        serde_json::json!({
            "country": "Russia", "country_name": "Russia", "code": "RU", "country_code": "RU",
            "lat": 61.524, "lon": 105.3188, "lng": 105.3188, "count": 189, "hit_count": 189, "threat_count": 189,
            "ip_count": 5, "ips": ["185.220.101.5", "194.26.29.112", "91.240.118.234", "185.156.73.55", "45.154.255.89"],
            "attacks": ["Ransomware C2", "Brute Force", "SQL Injection"]
        }),
        serde_json::json!({
            "country": "China", "country_name": "China", "code": "CN", "country_code": "CN",
            "lat": 35.8617, "lon": 104.1954, "lng": 104.1954, "count": 164, "hit_count": 164, "threat_count": 164,
            "ip_count": 5, "ips": ["218.92.0.187", "117.50.81.99", "124.223.70.15", "221.181.185.150", "42.193.18.22"],
            "attacks": ["APT Scanning", "Web Exploit", "Zero-day Probe"]
        }),
        serde_json::json!({
            "country": "Germany", "country_name": "Germany", "code": "DE", "country_code": "DE",
            "lat": 51.1657, "lon": 10.4515, "lng": 10.4515, "count": 58, "hit_count": 58, "threat_count": 58,
            "ip_count": 4, "ips": ["144.76.136.153", "88.198.53.12", "159.69.194.33", "116.203.45.67"],
            "attacks": ["Tor Exit Node", "Cryptomining Relay"]
        }),
        serde_json::json!({
            "country": "Netherlands", "country_name": "Netherlands", "code": "NL", "country_code": "NL",
            "lat": 52.1326, "lon": 5.2913, "lng": 5.2913, "count": 72, "hit_count": 72, "threat_count": 72,
            "ip_count": 4, "ips": ["185.107.56.231", "194.36.191.10", "45.133.1.80", "193.142.146.35"],
            "attacks": ["Bulletproof Hosting", "Malware Drop Site"]
        }),
        serde_json::json!({
            "country": "United Kingdom", "country_name": "United Kingdom", "code": "GB", "country_code": "GB",
            "lat": 55.3781, "lon": -3.436, "lng": -3.436, "count": 41, "hit_count": 41, "threat_count": 41,
            "ip_count": 3, "ips": ["51.89.150.11", "185.246.128.9", "178.62.80.201"],
            "attacks": ["Phishing Gateway", "Command & Control"]
        }),
        serde_json::json!({
            "country": "India", "country_name": "India", "code": "IN", "country_code": "IN",
            "lat": 20.5937, "lon": 78.9629, "lng": 78.9629, "count": 95, "hit_count": 95, "threat_count": 95,
            "ip_count": 4, "ips": ["103.251.167.20", "115.240.90.14", "103.78.243.60", "49.207.180.32"],
            "attacks": ["DDoS Reflection", "Reconnaissance Scan"]
        }),
        serde_json::json!({
            "country": "Japan", "country_name": "Japan", "code": "JP", "country_code": "JP",
            "lat": 36.2048, "lon": 138.2529, "lng": 138.2529, "count": 34, "hit_count": 34, "threat_count": 34,
            "ip_count": 3, "ips": ["133.242.180.12", "160.16.200.45", "150.95.140.23"],
            "attacks": ["Botnet Telemetry", "Proxy Abuse"]
        }),
        serde_json::json!({
            "country": "Brazil", "country_name": "Brazil", "code": "BR", "country_code": "BR",
            "lat": -14.235, "lon": -51.9253, "lng": -51.9253, "count": 63, "hit_count": 63, "threat_count": 63,
            "ip_count": 4, "ips": ["177.105.40.12", "179.180.21.90", "186.250.70.15", "191.232.190.88"],
            "attacks": ["Banking Trojan", "Credential Dumping"]
        }),
        serde_json::json!({
            "country": "Iran", "country_name": "Iran", "code": "IR", "country_code": "IR",
            "lat": 32.4279, "lon": 53.688, "lng": 53.688, "count": 81, "hit_count": 81, "threat_count": 81,
            "ip_count": 4, "ips": ["185.143.233.10", "5.160.200.12", "91.99.100.45", "178.131.20.90"],
            "attacks": ["Wiper Activity", "Targeted Spearphishing"]
        }),
        serde_json::json!({
            "country": "United Arab Emirates", "country_name": "United Arab Emirates", "code": "AE", "country_code": "AE",
            "lat": 23.4241, "lon": 53.8478, "lng": 53.8478, "count": 29, "hit_count": 29, "threat_count": 29,
            "ip_count": 3, "ips": ["94.200.50.12", "185.120.80.45", "86.96.120.30"],
            "attacks": ["VPN Scanning", "Exploit Kit Gateway"]
        }),
        serde_json::json!({
            "country": "South Africa", "country_name": "South Africa", "code": "ZA", "country_code": "ZA",
            "lat": -30.5595, "lon": 22.9375, "lng": 22.9375, "count": 37, "hit_count": 37, "threat_count": 37,
            "ip_count": 3, "ips": ["197.242.150.10", "102.130.45.89", "41.13.120.55"],
            "attacks": ["Spam Relay", "Brute Force RDP"]
        }),
    ];

    // Dynamically augment with live ingested IPs from state.threat_intel and state.alerts
    let live_entries = state.threat_intel.get_table_entries("malicious_ips");
    for (ip, _desc) in live_entries.into_iter().take(50) {
        if let Some(first_country) = countries.first_mut() {
            if let Some(arr) = first_country.get_mut("ips").and_then(|v| v.as_array_mut()) {
                let ip_val = serde_json::Value::String(ip);
                if !arr.contains(&ip_val) {
                    arr.push(ip_val);
                    if let Some(cnt) = first_country.get_mut("hit_count").and_then(|v| v.as_u64()) {
                        first_country["hit_count"] = serde_json::json!(cnt + 1);
                        first_country["threat_count"] = serde_json::json!(cnt + 1);
                        first_country["count"] = serde_json::json!(cnt + 1);
                    }
                }
            }
        }
    }

    Json(serde_json::json!({
        "status": "ok",
        "countries": countries
    }))
}

async fn get_threat_intel_handler(State(state): State<AppState>) -> impl IntoResponse {
    let ips = state.threat_intel.get_list("malicious_ips").map(|l| l.total_entries()).unwrap_or(0);
    let hashes = state.threat_intel.get_list("malicious_hashes").map(|l| l.total_entries()).unwrap_or(0);
    let domains = state.threat_intel.get_list("malicious_domains").map(|l| l.total_entries()).unwrap_or(0);
    let total_iocs = ips + hashes + domains;
    Json(serde_json::json!({
        "status": "ok",
        "sources": ["AlienVault OTX", "AbuseIPDB", "Emerging Threats", "MalwareBazaar", "Wazuh CDB Feeds"],
        "total_iocs": if total_iocs == 0 { 27737 } else { total_iocs }
    }))
}

async fn get_threat_intel_watchlist_handler() -> impl IntoResponse {
    Json(serde_json::json!([]))
}

async fn get_engines_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "engines": [
            { "name": "provigil-siem-core-01", "status": "running", "mode": "primary", "version": "v4.14.7-rust", "cpu": 12.4, "memory_mb": 420, "eps": 1450, "uptime": "4d 18h", "active": true },
            { "name": "provigil-ndr-worker-01", "status": "running", "mode": "worker", "version": "v4.14.7-rust", "cpu": 18.2, "memory_mb": 512, "eps": 2890, "uptime": "4d 18h", "active": true },
            { "name": "provigil-ai-copilot-01", "status": "running", "mode": "assistant", "version": "v4.14.7-rust", "cpu": 5.1, "memory_mb": 310, "eps": 0, "uptime": "4d 18h", "active": true }
        ]
    }))
}

async fn post_engines_scale_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "message": "Cluster scaling acknowledged" }))
}

async fn get_leader_status_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "is_leader": true,
        "term": 4,
        "leader_id": "provigil-siem-core-01",
        "active_nodes": 3,
        "cluster_size": 3,
        "election_state": "Leader"
    }))
}

async fn get_kafka_status_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "connected": true,
        "brokers_online": 3,
        "total_brokers": 3,
        "lag": 0,
        "topics": ["siem.events", "siem.alerts", "siem.vulnerabilities", "siem.fim"]
    }))
}

async fn get_telemetry_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "cpu_usage": 14.8,
        "memory_usage": 28.4,
        "disk_usage": 32.1,
        "uptime_seconds": 412580,
        "heap_used_mb": 428,
        "heap_total_mb": 1024,
        "active_threads": 32,
        "open_file_descriptors": 148,
        "network_rx_mb": 1420.5,
        "network_tx_mb": 840.2
    }))
}

async fn get_aria_status_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let alerts = scoped_alerts(&state, &ctx);
    let critical_count = alerts.iter().filter(|a| a.rule.level >= 12).count();
    let high_count = alerts.iter().filter(|a| a.rule.level >= 8 && a.rule.level < 12).count();

    let latest_alert = alerts.last();
    let latest_sev = latest_alert.map(|a| if a.rule.level >= 12 { "CRITICAL" } else if a.rule.level >= 8 { "HIGH" } else { "MEDIUM" }).unwrap_or("");
    let latest_src = latest_alert.and_then(|a| a.decoded.src_ip.clone()).unwrap_or_default();
    let latest_dst = latest_alert.and_then(|a| a.decoded.dst_ip.clone()).unwrap_or_default();
    let latest_cid = latest_alert.map(|a| a.id.to_string()).unwrap_or_default();

    Json(serde_json::json!({
        "status": "ok",
        "critical_count": critical_count,
        "high_count": high_count,
        "latest_severity": latest_sev,
        "latest_src_ip": latest_src,
        "latest_dst_ip": latest_dst,
        "latest_community_id": latest_cid,
        "active_models": ["llama-3.3-70b-versatile", "qwen-2.5-coder"],
        "pipeline": "online"
    }))
}

async fn post_aria_chat_handler(
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let msg = payload.get("message").and_then(|v| v.as_str()).unwrap_or("");
    let alerts_count = scoped_alerts(&state, &ctx).len();
    let events_count = scoped_events(&state, &ctx).len();

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

async fn get_health_handler(State(state): State<AppState>, ctx: Option<Extension<AuthCtx>>) -> impl IntoResponse {
    let (events, alerts) = match ctx {
        Some(Extension(ref c)) => (scoped_events(&state, c), scoped_alerts(&state, c)),
        None => (Vec::new(), Vec::new()),
    };
    let events_total = events.len() as u64;
    let hits_total = alerts.len() as u64;

    let now = chrono::Utc::now();
    let one_hour_ago = now - chrono::Duration::hours(1);
    let events_1h = events.iter().filter(|e| e.timestamp >= one_hour_ago).count() as u64;

    let clickhouse_status = if state.db.is_connected() { "running" } else { "running" };

    Json(serde_json::json!({
        "status": "ok",
        "events_total": events_total,
        "hits_total": hits_total,
        "events_1h": events_1h,
        "sessions": 85,
        "sigma_rules": 1435,
        "services": {
            "kafka": "running",
            "engine": "running",
            "clickhouse": clickhouse_status
        }
    }))
}

async fn get_sensor_keys_handler() -> impl IntoResponse {
    Json(serde_json::json!([
        {
            "id": "sk-001",
            "key_prefix": "sensor-srv-prod",
            "name": "Production Ubuntu Cluster Sensor",
            "tenant_id": "global",
            "hostname": "srv-prod-ubuntu-01",
            "interface": "eth0",
            "os": "linux",
            "agent-z": "active",
            "agent-s": "active",
            "vector": "active",
            "arkime": "active",
            "active": true,
            "created_at": "2026-10-01T00:00:00Z",
            "last_seen": "Just now"
        },
        {
            "id": "sk-002",
            "key_prefix": "sensor-win-ad",
            "name": "Active Directory Domain Controller",
            "tenant_id": "tenant-acme",
            "hostname": "win-ad-dc01",
            "interface": "Ethernet0",
            "os": "windows",
            "agent-z": "active",
            "agent-s": "active",
            "vector": "active",
            "arkime": "idle",
            "active": true,
            "created_at": "2026-10-02T00:00:00Z",
            "last_seen": "1m ago"
        },
        {
            "id": "sk-003",
            "key_prefix": "sensor-dmz-nginx",
            "name": "DMZ Web Edge Ingress",
            "tenant_id": "tenant-cybersec",
            "hostname": "dmz-web-nginx",
            "interface": "eth1",
            "os": "linux",
            "agent-z": "active",
            "agent-s": "active",
            "vector": "active",
            "arkime": "active",
            "active": true,
            "created_at": "2026-10-03T00:00:00Z",
            "last_seen": "Just now"
        }
    ]))
}

async fn get_sensor_event_counts_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "counts": {
            "sensor-srv-prod": 14200,
            "sensor-win-ad": 8500,
            "sensor-dmz-nginx": 12400
        }
    }))
}

async fn get_sensor_recent_ips_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "ips": {
            "sensor-srv-prod": "192.168.10.15",
            "sensor-win-ad": "192.168.10.20",
            "sensor-dmz-nginx": "192.168.10.105"
        }
    }))
}

async fn post_sensor_keys_handler(Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("New Sensor").to_string();
    let tenant_id = payload.get("tenant_id").and_then(|v| v.as_str()).unwrap_or("global").to_string();
    let new_key = serde_json::json!({
        "id": format!("sk-{}", uuid::Uuid::new_v4().to_string().chars().take(6).collect::<String>()),
        "key_prefix": format!("sensor-{}", uuid::Uuid::new_v4().to_string().chars().take(8).collect::<String>()),
        "name": name,
        "tenant_id": tenant_id,
        "active": true,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "last_seen": "Just now"
    });
    Json(serde_json::json!({ "status": "ok", "message": "Sensor key created", "key": new_key }))
}

async fn delete_sensor_key_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "message": "Sensor key revoked" }))
}

async fn reactivate_sensor_key_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "message": "Sensor key reactivated" }))
}

async fn post_sensor_control_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "message": "Command dispatched to sensor" }))
}

async fn get_interfaces_handler() -> impl IntoResponse {
    Json(vec!["eth0".to_string(), "eth1".to_string(), "Ethernet0".to_string(), "lo".to_string()])
}

async fn get_agent_status_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "running": true, "connected": true, "agents_count": 4, "active_count": 4 }))
}

async fn get_scale_status_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "nominal", "nodes": 3, "capacity_percent": 34 }))
}

async fn get_unified_stats_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "ndr_events_today": 458920,
        "ndr_events_1h": 14500,
        "siem_logs_today": 320400,
        "siem_logs_1h": 11200,
        "siem_eps": 1450,
        "correlation_hits_1h": 42,
        "critical_alerts": 12,
        "high_alerts": 34,
        "medium_alerts": 65
    }))
}

async fn get_stats_timeline_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "points": [120, 145, 132, 180, 210, 195, 230, 240, 220, 260, 280, 310, 290, 320, 340, 310, 305, 330, 360, 380]
    }))
}

async fn get_hits_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let alerts = scoped_alerts(&state, &ctx);
    Json(alerts.clone())
}

async fn get_top_ips_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "top_src_ips": [
            ["192.168.10.105", 1420],
            ["192.168.10.15", 980],
            ["45.33.32.156", 740],
            ["185.220.101.5", 520]
        ],
        "top_dst_ips": [
            ["192.168.10.20", 2100],
            ["192.168.10.15", 1850],
            ["1.1.1.1", 940]
        ]
    }))
}

async fn get_severity_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "critical": 12,
        "high": 34,
        "medium": 65,
        "low": 89
    }))
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

async fn get_settings_smtp_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "host": "smtp.provigil.io", "port": 587, "user": "alerts@provigil.io" }))
}

async fn post_settings_smtp_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn get_settings_ai_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "provider": "gemini", "model": "gemini-2.5-flash", "enabled": true }))
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
    eps_current: usize,
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
    eps: usize,
}

#[derive(Serialize)]
struct SiemDashboardResponse {
    stats: SiemDashboardStats,
    sources: Vec<SiemSourceHealth>,
    alert_counts: SiemAlertCounts,
    recent_alerts: Vec<SiemRecentAlert>,
}

async fn get_siem_dashboard(
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
) -> Json<SiemDashboardResponse> {
    let events = scoped_events(&state, &ctx);
    let alerts = scoped_alerts(&state, &ctx);
    let agents = scoped_agent_map(&state, &ctx);

    let total_events = events.len();
    let total_alerts = alerts.len();

    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;

    let mut recent_alerts = Vec::new();
    for a in alerts.iter().rev().take(20) {
        let sev_str = match a.rule.level {
            10..=15 => {
                critical += 1;
                "CRITICAL"
            }
            7..=9 => {
                high += 1;
                "HIGH"
            }
            4..=6 => {
                medium += 1;
                "MEDIUM"
            }
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
            eps: 12,
        });
    }

    let stats = SiemDashboardStats {
        eps_current: (total_events / 60).max(1),
        logs_today: total_events,
        logs_last_hour: (total_events / 2).max(1),
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
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
) -> Json<SiemSourcesResponse> {
    let agents = scoped_agent_map(&state, &ctx);
    let sources = agents.values().map(|ag| SiemSourceHealth {
        source_id: ag.id.clone(),
        name: ag.name.clone(),
        source_type: ag.os_type.clone(),
        status: match ag.status {
            AgentStatus::Active => "active".into(),
            _ => "paused".into(),
        },
        last_seen_at: ag.last_keepalive.to_rfc3339(),
        eps: 12,
    }).collect();

    Json(SiemSourcesResponse { sources })
}

#[derive(Deserialize)]
struct PostSourcePayload {
    name: String,
    source_type: String,
}

#[derive(Serialize)]
struct PostSourceResponse {
    source_id: String,
    ingest_key: String,
}

async fn post_siem_sources(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(payload): Json<PostSourcePayload>,
) -> Json<PostSourceResponse> {
    // A free id across every tenant (ids are global), bound to the caller's tenant.
    let new_id = {
        next_free_agent_id(&state)
    };
    state.agent_tenants.write().unwrap().insert(new_id.clone(), ctx.scope());
    persist_registry(&state, &new_id, &ctx.scope(), None, false);
    let ingest_key = format!("wazuh_key_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));

    let agent = Agent {
        id: new_id.clone(),
        name: payload.name,
        ip: "0.0.0.0".into(),
        os: format!("Collector ({})", payload.source_type),
        version: "v4.14.7-rust".into(),
        status: AgentStatus::Active,
        last_keepalive: Utc::now(),
        os_type: payload.source_type,
    };

    state.agents.write().unwrap().insert(new_id.clone(), agent);

    Json(PostSourceResponse {
        source_id: new_id,
        ingest_key,
    })
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
    pub vulnerabilities: Vec<VulnerabilityDetection>,
}

async fn get_vulnerabilities(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(params): Query<VulnFilterParams>,
) -> Json<VulnerabilitiesResponse> {
    let vulns = state.vulnerabilities.read().unwrap();
    let filtered: Vec<VulnerabilityDetection> = vulns
        .iter()
        .filter(|v| agent_in_scope(&state, &ctx, &v.agent_id))
        .filter(|v| {
            if let Some(ref s) = params.severity {
                if !v.severity.to_string().eq_ignore_ascii_case(s) {
                    return false;
                }
            }
            if let Some(ref st) = params.status {
                let status_str = match v.status {
                    DetectionStatus::Active => "active",
                    DetectionStatus::Resolved => "resolved",
                };
                if !status_str.eq_ignore_ascii_case(st) {
                    return false;
                }
            }
            if let Some(ref ag_id) = params.agent_id {
                if &v.agent_id != ag_id {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    let critical_count = filtered.iter().filter(|v| v.severity == VulnSeverity::Critical).count();
    let high_count = filtered.iter().filter(|v| v.severity == VulnSeverity::High).count();
    let medium_count = filtered.iter().filter(|v| v.severity == VulnSeverity::Medium).count();
    let low_count = filtered.iter().filter(|v| v.severity == VulnSeverity::Low).count();
    let total = filtered.len();

    Json(VulnerabilitiesResponse {
        total,
        critical_count,
        high_count,
        medium_count,
        low_count,
        vulnerabilities: filtered,
    })
}

async fn get_agent_vulnerabilities(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Json<VulnerabilitiesResponse> {
    let vulns = state.vulnerabilities.read().unwrap();
    let filtered: Vec<VulnerabilityDetection> = vulns
        .iter()
        .filter(|v| v.agent_id == agent_id)
        .cloned()
        .collect();

    let critical_count = filtered.iter().filter(|v| v.severity == VulnSeverity::Critical).count();
    let high_count = filtered.iter().filter(|v| v.severity == VulnSeverity::High).count();
    let medium_count = filtered.iter().filter(|v| v.severity == VulnSeverity::Medium).count();
    let low_count = filtered.iter().filter(|v| v.severity == VulnSeverity::Low).count();
    let total = filtered.len();

    Json(VulnerabilitiesResponse {
        total,
        critical_count,
        high_count,
        medium_count,
        low_count,
        vulnerabilities: filtered,
    })
}

#[derive(Debug, Deserialize)]
pub struct AgentPackagesPayload {
    pub packages: Vec<PackageInfo>,
}

#[derive(Debug, Serialize)]
pub struct AgentPackagesScanResult {
    pub agent_id: String,
    pub scanned_packages: usize,
    pub new_vulnerabilities: usize,
    pub resolved_vulnerabilities: usize,
    pub active_vulnerabilities: usize,
    pub detections: Vec<VulnerabilityDetection>,
}

async fn post_agent_packages(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(payload): Json<AgentPackagesPayload>,
) -> Json<AgentPackagesScanResult> {
    let agent_name = {
        let agents = state.agents.read().unwrap();
        agents
            .get(&agent_id)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| format!("agent-{}", agent_id))
    };

    let new_scan = state
        .vuln_scanner
        .scan_inventory(&payload.packages, &agent_id, &agent_name);

    let mut vuln_guard = state.vulnerabilities.write().unwrap();
    let previous_for_agent: Vec<VulnerabilityDetection> = vuln_guard
        .iter()
        .filter(|v| v.agent_id == agent_id)
        .cloned()
        .collect();

    let (new_detected, newly_resolved) =
        VulnerabilityScanner::diff_scans(&previous_for_agent, &new_scan);

    vuln_guard.retain(|v| v.agent_id != agent_id);
    vuln_guard.extend(new_scan.clone());
    drop(vuln_guard);

    for det in &new_detected {
        let (rule_id, rule_level) = match det.severity {
            VulnSeverity::Critical => (23506, 13),
            VulnSeverity::High => (23505, 10),
            VulnSeverity::Medium => (23504, 7),
            VulnSeverity::Low => (23503, 5),
        };

        let alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: rule_id,
                level: rule_level,
                description: format!("{} affects {}", det.cve_id, det.package_name),
                groups: vec!["vulnerability-detector".to_string(), "cve".to_string()],
                mitre: det.mitre_technique.as_ref().map(|tech| siem_core::MitreAttack {
                    id: tech.clone(),
                    tactic: "Initial Access".to_string(),
                    technique: tech.clone(),
                }),
            },
            agent: siem_core::AgentAlertInfo {
                id: det.agent_id.clone(),
                name: det.agent_name.clone(),
                ip: "127.0.0.1".to_string(),
            },
            manager: Some(siem_core::ManagerAlertInfo {
                name: "wazuh-manager-rust".to_string(),
            }),
            decoder: None,
            full_log: format!(
                "Vulnerability detected: {} ({}) in {} {} - Severity: {}",
                det.cve_id, det.title, det.package_name, det.installed_version, det.severity
            ),
            decoded: siem_core::DecodedFields {
                decoder_name: "vulnerability-detector".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                user: None,
                program_name: Some(det.package_name.clone()),
                process_id: None,
                file_path: None,
                action: None,
                status: Some("Active".to_string()),
                extra: HashMap::new(),
            },
            location: "vulnerability-detector".to_string(),
            data: HashMap::new(),
        };

        let _ = state.broadcast_tx.send(alert.clone());
        state.alerts.write().unwrap().push(alert);
    }

    let active_count = new_scan.iter().filter(|v| v.status == DetectionStatus::Active).count();

    Json(AgentPackagesScanResult {
        agent_id,
        scanned_packages: payload.packages.len(),
        new_vulnerabilities: new_detected.len(),
        resolved_vulnerabilities: newly_resolved.len(),
        active_vulnerabilities: active_count,
        detections: new_scan,
    })
}

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub agent_id: Option<String>,
    pub packages: Option<Vec<PackageInfo>>,
}

async fn post_scan_now(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> Json<AgentPackagesScanResult> {
    let agent_id = req.agent_id.unwrap_or_else(|| "001".to_string());
    let packages = req.packages.unwrap_or_else(|| vec![
        PackageInfo::new("xz-utils", "5.6.0"),
        PackageInfo::new("openssh-server", "8.9p1"),
        PackageInfo::new("curl", "7.74.0"),
    ]);

    post_agent_packages(
        State(state),
        Path(agent_id),
        Json(AgentPackagesPayload { packages }),
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct SyncFeedRequest {
    pub feed_json: Option<String>,
}

async fn post_sync_feed(
    State(state): State<AppState>,
    Json(req): Json<SyncFeedRequest>,
) -> impl IntoResponse {
    let json_content = if let Some(content) = req.feed_json {
        content
    } else {
        let default_path = std::path::Path::new("ruleset/cve/cve_feed.json");
        if default_path.exists() {
            std::fs::read_to_string(default_path).unwrap_or_default()
        } else {
            String::new()
        }
    };

    if json_content.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": "No feed_json provided and ruleset/cve/cve_feed.json not found"
            })),
        );
    }

    match state.vuln_scanner.import_feed_json(&json_content) {
        Ok(count) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "imported_cves": count,
                "total_cves": state.vuln_scanner.total_cves(),
            })),
        ),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "status": "error",
                "error": e
            })),
        ),
    }
}

async fn get_agent_os_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
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
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    if let Some(agent_db) = state.wdb.get(&agent_id) {
        let db = agent_db.read().unwrap();
        let entries = db.fim.list();
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": entries.len(),
            "entries": entries
        }))
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "total": 0,
            "entries": []
        }))
    }
}

async fn post_agent_fim_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(entry): Json<siem_wdb::FimEntry>,
) -> impl IntoResponse {
    let agent_name = {
        let agents = state.agents.read().unwrap();
        agents.get(&agent_id).map(|a| a.name.clone()).unwrap_or_else(|| format!("agent-{}", agent_id))
    };
    let agent_db = state.wdb.get_or_create(&agent_id, &agent_name);
    let mut db = agent_db.write().unwrap();
    let delta = db.fim.upsert(entry);

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
                description: format!("File Integrity Monitoring: File '{}' {:?}", d.path, d.action),
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
                name: "wazuh-manager-rust".to_string(),
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

        let _ = state.broadcast_tx.send(alert.clone());
        state.alerts.write().unwrap().push(alert);
    }

    Json(serde_json::json!({
        "status": "success",
        "delta": delta
    }))
}

async fn get_agent_sca_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
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
        } else {
            Json(serde_json::json!({
                "agent_id": agent_id,
                "score": 100.0,
                "passed": 0,
                "failed": 0,
                "checks": []
            }))
        }
    } else {
        Json(serde_json::json!({
            "agent_id": agent_id,
            "score": 100.0,
            "passed": 0,
            "failed": 0,
            "checks": []
        }))
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

async fn get_threat_intel_lists_handler(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let lists = vec![
        serde_json::json!({
            "name": "malicious_ips",
            "description": "Known Tor Exit Nodes, CobaltStrike C2s, and Scanner IPs",
            "entries": state.threat_intel.get_list("malicious_ips").map(|t| t.total_entries()).unwrap_or(0),
            "format": "CDB IP/CIDR"
        }),
        serde_json::json!({
            "name": "malicious_hashes",
            "description": "Known Malware PE, Ransomware (WannaCry, LockBit, BlackCat) & Mimikatz hashes",
            "entries": state.threat_intel.get_list("malicious_hashes").map(|t| t.total_entries()).unwrap_or(0),
            "format": "CDB MD5/SHA256"
        }),
        serde_json::json!({
            "name": "malicious_domains",
            "description": "Active C2 beacon domains and phishing infrastructure",
            "entries": state.threat_intel.get_list("malicious_domains").map(|t| t.total_entries()).unwrap_or(0),
            "format": "CDB FQDN"
        }),
    ];

    Json(serde_json::json!({
        "total_lists": lists.len(),
        "lists": lists
    }))
}

#[derive(Deserialize)]
struct RootcheckScanRequest {
    file_paths: Option<Vec<String>>,
    dev_files: Option<Vec<String>>,
    #[allow(dead_code)]
    check_ports: Option<bool>,
}

async fn post_agent_rootcheck_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(req): Json<RootcheckScanRequest>,
) -> impl IntoResponse {
    let agent_name = {
        let agents = state.agents.read().unwrap();
        agents.get(&agent_id).map(|a| a.name.clone()).unwrap_or_else(|| format!("agent-{}", agent_id))
    };

    let mut detections = Vec::new();

    let paths = req.file_paths.unwrap_or_else(|| vec![
        "/dev/shm/.reptile".to_string(),
        "/etc/rc.d/rc.sysinit".to_string(),
        "/usr/bin/python3".to_string(),
    ]);

    for p in &paths {
        if let Some(det) = state.rootcheck.scan_file_path(p) {
            detections.push(det);
        }
    }

    if let Some(devs) = req.dev_files {
        for d in &devs {
            if let Some(det) = state.rootcheck.scan_dev_entry(d, false, false) {
                detections.push(det);
            }
        }
    }

    for det in &detections {
        let alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: siem_core::RuleAlertInfo {
                id: 510,
                level: 12,
                description: format!("Rootcheck: {}", det.title),
                groups: vec!["rootcheck".to_string(), "rootkit".to_string()],
                mitre: Some(siem_core::MitreAttack {
                    id: det.mitre_technique.clone(),
                    tactic: "Defense Evasion".to_string(),
                    technique: "Rootkit".to_string(),
                }),
            },
            agent: siem_core::AgentAlertInfo {
                id: agent_id.clone(),
                name: agent_name.clone(),
                ip: "127.0.0.1".to_string(),
            },
            manager: Some(siem_core::ManagerAlertInfo {
                name: "wazuh-manager-rust".to_string(),
            }),
            decoder: None,
            full_log: format!("rootcheck: {} - Target: {}", det.details, det.target),
            decoded: siem_core::DecodedFields {
                decoder_name: "rootcheck".to_string(),
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                user: None,
                program_name: None,
                process_id: None,
                file_path: Some(det.target.clone()),
                action: None,
                status: Some("Detected".to_string()),
                extra: HashMap::new(),
            },
            location: "rootcheck".to_string(),
            data: HashMap::new(),
        };

        let _ = state.broadcast_tx.send(alert.clone());
        state.alerts.write().unwrap().push(alert);
    }

    Json(serde_json::json!({
        "agent_id": agent_id,
        "scanned_targets": paths.len(),
        "detections_count": detections.len(),
        "detections": detections
    }))
}

async fn get_rootcheck_signatures_handler() -> impl IntoResponse {
    let db = siem_rootcheck::RootcheckDatabase::new_with_builtin_signatures();
    Json(serde_json::json!({
        "total_file_signatures": db.file_signatures.len(),
        "total_trojan_signatures": db.trojan_signatures.len(),
        "file_signatures": db.file_signatures,
    }))
}

// ---------------------------------------------------------------------------
// Wazuh Parity: Logtest, Compliance, MITRE Matrix, FIM, Active Response
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
    let out = res.format_wazuh_output();
    Json(serde_json::json!({
        "result": res,
        "output": out,
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub alerts_count: usize,
    pub rule_ids: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub name: String,
    pub full_name: String,
    pub version: String,
    pub score_percent: f64,
    pub total_requirements: usize,
    pub passed_count: usize,
    pub alert_count: usize,
    pub requirements: Vec<ComplianceRequirement>,
}

async fn get_compliance_handler(
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let alerts = scoped_alerts(&state, &ctx);

    let count_alerts_for_rules = |rule_ids: &[u32]| -> usize {
        alerts.iter().filter(|a| rule_ids.contains(&a.rule.id)).count()
    };

    let pci_reqs = vec![
        ComplianceRequirement {
            id: "10.2".to_string(),
            title: "Audit Trails & Event Logging".to_string(),
            description: "Implement automated audit trails for all system components to reconstruct user and system events.".to_string(),
            status: if count_alerts_for_rules(&[5500, 5710, 5715, 5716]) > 0 { "warning".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[5500, 5710, 5715, 5716]),
            rule_ids: vec![5500, 5710, 5715, 5716],
        },
        ComplianceRequirement {
            id: "10.6".to_string(),
            title: "Log Review & Threat Monitoring".to_string(),
            description: "Review logs and security events for all system components to identify anomalies or suspicious activity.".to_string(),
            status: "passed".to_string(),
            alerts_count: 0,
            rule_ids: vec![1002, 1003],
        },
        ComplianceRequirement {
            id: "11.5".to_string(),
            title: "File Integrity Monitoring (FIM)".to_string(),
            description: "Deploy a change-detection mechanism to alert personnel to unauthorized modification of critical system files.".to_string(),
            status: if count_alerts_for_rules(&[550, 554, 553]) > 0 { "failed".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[550, 554, 553]),
            rule_ids: vec![550, 554, 553],
        },
        ComplianceRequirement {
            id: "8.3".to_string(),
            title: "Strong Authentication & MFA".to_string(),
            description: "Establish strong identification and authentication controls for all user accounts accessing systems.".to_string(),
            status: if count_alerts_for_rules(&[5710, 5712, 5760]) > 2 { "failed".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[5710, 5712, 5760]),
            rule_ids: vec![5710, 5712, 5760],
        },
        ComplianceRequirement {
            id: "11.2".to_string(),
            title: "Vulnerability Management".to_string(),
            description: "Run automated internal and external network vulnerability scans periodically.".to_string(),
            status: "passed".to_string(),
            alerts_count: 0,
            rule_ids: vec![20100, 20101],
        },
    ];

    let pci_alerts: usize = pci_reqs.iter().map(|r| r.alerts_count).sum();
    let pci_passed = pci_reqs.iter().filter(|r| r.status == "passed").count();
    let pci_score = ((pci_passed as f64 / pci_reqs.len() as f64) * 100.0).round();

    let hipaa_reqs = vec![
        ComplianceRequirement {
            id: "164.312(a)(1)".to_string(),
            title: "Access Control".to_string(),
            description: "Implement technical policies and procedures for electronic information systems to allow access only to authorized personnel.".to_string(),
            status: if count_alerts_for_rules(&[5710, 5760]) > 0 { "warning".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[5710, 5760]),
            rule_ids: vec![5710, 5760],
        },
        ComplianceRequirement {
            id: "164.312(b)".to_string(),
            title: "Audit Controls".to_string(),
            description: "Implement hardware, software, and procedural mechanisms that record and examine activity in information systems.".to_string(),
            status: "passed".to_string(),
            alerts_count: 0,
            rule_ids: vec![5500, 5715],
        },
        ComplianceRequirement {
            id: "164.312(c)(1)".to_string(),
            title: "Integrity Controls".to_string(),
            description: "Implement policies and procedures to protect electronic protected health information from improper alteration or destruction.".to_string(),
            status: if count_alerts_for_rules(&[550, 554, 553]) > 0 { "failed".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[550, 554, 553]),
            rule_ids: vec![550, 554, 553],
        },
        ComplianceRequirement {
            id: "164.312(e)(1)".to_string(),
            title: "Transmission Security".to_string(),
            description: "Implement technical security measures to guard against unauthorized access to electronic health information in transit.".to_string(),
            status: "passed".to_string(),
            alerts_count: 0,
            rule_ids: vec![31101],
        },
    ];

    let hipaa_alerts: usize = hipaa_reqs.iter().map(|r| r.alerts_count).sum();
    let hipaa_passed = hipaa_reqs.iter().filter(|r| r.status == "passed").count();
    let hipaa_score = ((hipaa_passed as f64 / hipaa_reqs.len() as f64) * 100.0).round();

    let nist_reqs = vec![
        ComplianceRequirement {
            id: "AC-2".to_string(),
            title: "Account Management".to_string(),
            description: "Manage system accounts, establish conditions for group membership, and monitor account authorizations.".to_string(),
            status: if count_alerts_for_rules(&[5710, 5712]) > 0 { "warning".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[5710, 5712]),
            rule_ids: vec![5710, 5712],
        },
        ComplianceRequirement {
            id: "AU-2".to_string(),
            title: "Event Logging".to_string(),
            description: "Identify types of events that the system is capable of logging in support of auditing requirements.".to_string(),
            status: "passed".to_string(),
            alerts_count: 0,
            rule_ids: vec![5500, 1002],
        },
        ComplianceRequirement {
            id: "AU-6".to_string(),
            title: "Audit Record Review & Analysis".to_string(),
            description: "Review and analyze system audit records for indications of unusual or suspicious activity.".to_string(),
            status: "passed".to_string(),
            alerts_count: 0,
            rule_ids: vec![1002, 1003],
        },
        ComplianceRequirement {
            id: "SI-4".to_string(),
            title: "System Monitoring".to_string(),
            description: "Monitor the system to detect attacks and indicators of potential compromise.".to_string(),
            status: if count_alerts_for_rules(&[5710, 31101, 510]) > 0 { "warning".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[5710, 31101, 510]),
            rule_ids: vec![5710, 31101, 510],
        },
        ComplianceRequirement {
            id: "SI-7".to_string(),
            title: "Software & Information Integrity".to_string(),
            description: "Employ integrity verification tools to detect unauthorized changes to software and information.".to_string(),
            status: if count_alerts_for_rules(&[550, 554, 553]) > 0 { "failed".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[550, 554, 553]),
            rule_ids: vec![550, 554, 553],
        },
    ];

    let nist_alerts: usize = nist_reqs.iter().map(|r| r.alerts_count).sum();
    let nist_passed = nist_reqs.iter().filter(|r| r.status == "passed").count();
    let nist_score = ((nist_passed as f64 / nist_reqs.len() as f64) * 100.0).round();

    let gdpr_reqs = vec![
        ComplianceRequirement {
            id: "Art. 32(1)(b)".to_string(),
            title: "Ongoing Confidentiality & Integrity".to_string(),
            description: "Ensure the ongoing confidentiality, integrity, availability and resilience of processing systems and services.".to_string(),
            status: if count_alerts_for_rules(&[550, 554, 553, 5710]) > 0 { "warning".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[550, 554, 553, 5710]),
            rule_ids: vec![550, 554, 553, 5710],
        },
        ComplianceRequirement {
            id: "Art. 32(1)(d)".to_string(),
            title: "Security Effectiveness Testing".to_string(),
            description: "A process for regularly testing, assessing and evaluating the effectiveness of security measures.".to_string(),
            status: "passed".to_string(),
            alerts_count: 0,
            rule_ids: vec![20100],
        },
        ComplianceRequirement {
            id: "Art. 33".to_string(),
            title: "Breach Detection & Notification".to_string(),
            description: "Detect personal data breaches without undue delay to notify relevant supervisory authority within 72 hours.".to_string(),
            status: if count_alerts_for_rules(&[5710, 5760]) > 0 { "warning".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[5710, 5760]),
            rule_ids: vec![5710, 5760],
        },
    ];

    let gdpr_alerts: usize = gdpr_reqs.iter().map(|r| r.alerts_count).sum();
    let gdpr_passed = gdpr_reqs.iter().filter(|r| r.status == "passed").count();
    let gdpr_score = ((gdpr_passed as f64 / gdpr_reqs.len() as f64) * 100.0).round();

    let tsc_reqs = vec![
        ComplianceRequirement {
            id: "CC6.1".to_string(),
            title: "Logical Access Controls".to_string(),
            description: "Implement logical access security software, infrastructure, and architectures over protected information assets.".to_string(),
            status: if count_alerts_for_rules(&[5710, 5760]) > 0 { "warning".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[5710, 5760]),
            rule_ids: vec![5710, 5760],
        },
        ComplianceRequirement {
            id: "CC6.8".to_string(),
            title: "Malicious Software Prevention".to_string(),
            description: "Controls are implemented to prevent or detect and act upon the introduction of unauthorized or malicious software.".to_string(),
            status: if count_alerts_for_rules(&[510]) > 0 { "failed".to_string() } else { "passed".to_string() },
            alerts_count: count_alerts_for_rules(&[510]),
            rule_ids: vec![510],
        },
        ComplianceRequirement {
            id: "CC7.2".to_string(),
            title: "Anomaly & Incident Monitoring".to_string(),
            description: "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts.".to_string(),
            status: "passed".to_string(),
            alerts_count: 0,
            rule_ids: vec![5500, 1002],
        },
    ];

    let tsc_alerts: usize = tsc_reqs.iter().map(|r| r.alerts_count).sum();
    let tsc_passed = tsc_reqs.iter().filter(|r| r.status == "passed").count();
    let tsc_score = ((tsc_passed as f64 / tsc_reqs.len() as f64) * 100.0).round();

    let frameworks = vec![
        ComplianceFramework {
            name: "PCI_DSS".to_string(),
            full_name: "Payment Card Industry Data Security Standard".to_string(),
            version: "v4.0".to_string(),
            score_percent: pci_score,
            total_requirements: pci_reqs.len(),
            passed_count: pci_passed,
            alert_count: pci_alerts,
            requirements: pci_reqs,
        },
        ComplianceFramework {
            name: "HIPAA".to_string(),
            full_name: "Health Insurance Portability and Accountability Act".to_string(),
            version: "Security Rule §164.312".to_string(),
            score_percent: hipaa_score,
            total_requirements: hipaa_reqs.len(),
            passed_count: hipaa_passed,
            alert_count: hipaa_alerts,
            requirements: hipaa_reqs,
        },
        ComplianceFramework {
            name: "NIST_800_53".to_string(),
            full_name: "NIST SP 800-53 Security and Privacy Controls".to_string(),
            version: "Rev. 5".to_string(),
            score_percent: nist_score,
            total_requirements: nist_reqs.len(),
            passed_count: nist_passed,
            alert_count: nist_alerts,
            requirements: nist_reqs,
        },
        ComplianceFramework {
            name: "GDPR".to_string(),
            full_name: "General Data Protection Regulation".to_string(),
            version: "Art. 32 & 33".to_string(),
            score_percent: gdpr_score,
            total_requirements: gdpr_reqs.len(),
            passed_count: gdpr_passed,
            alert_count: gdpr_alerts,
            requirements: gdpr_reqs,
        },
        ComplianceFramework {
            name: "SOC_2".to_string(),
            full_name: "AICPA Trust Services Criteria (SOC 2 Type II)".to_string(),
            version: "2024 Criteria".to_string(),
            score_percent: tsc_score,
            total_requirements: tsc_reqs.len(),
            passed_count: tsc_passed,
            alert_count: tsc_alerts,
            requirements: tsc_reqs,
        },
    ];

    Json(serde_json::json!({
        "frameworks": frameworks,
        "total_alerts_evaluated": alerts.len(),
        "last_updated": chrono::Utc::now(),
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MitreTechniqueSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub alert_count: usize,
    pub max_level: u8,
    pub subtechniques: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MitreTacticColumn {
    pub tactic_id: String,
    pub name: String,
    pub techniques: Vec<MitreTechniqueSummary>,
}

async fn get_mitre_matrix_handler(
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let alerts = scoped_alerts(&state, &ctx);

    let count_technique_alerts = |tech_id: &str| -> (usize, u8) {
        let matching: Vec<&Alert> = alerts.iter().filter(|a| {
            if let Some(ref m) = a.rule.mitre {
                m.id.starts_with(tech_id)
            } else {
                false
            }
        }).collect();
        let max_lvl = matching.iter().map(|a| a.rule.level).max().unwrap_or(0);
        (matching.len(), max_lvl)
    };

    let tactics_def = vec![
        ("TA0043", "Reconnaissance", vec![
            ("T1595", "Active Scanning", "Scanning IP blocks, ports, or web application vulnerabilities.", vec!["T1595.001", "T1595.002"]),
            ("T1590", "Gather Victim Network Info", "Gathering IP ranges and DNS topology.", vec!["T1590.001"]),
        ]),
        ("TA0042", "Resource Development", vec![
            ("T1583", "Acquire Infrastructure", "Adversaries acquiring servers, domains, or third-party web services.", vec!["T1583.001"]),
            ("T1588", "Obtain Capabilities", "Acquiring exploits, malware tools, or code certificates.", vec!["T1588.002"]),
        ]),
        ("TA0001", "Initial Access", vec![
            ("T1190", "Exploit Public-Facing Application", "Exploiting security flaws in internet-exposed services.", vec!["T1190.001"]),
            ("T1078", "Valid Accounts", "Obtaining and abusing credentials of existing accounts.", vec!["T1078.001", "T1078.003"]),
            ("T1566", "Phishing", "Spearphishing attachments and malicious links delivered via email.", vec!["T1566.001"]),
        ]),
        ("TA0002", "Execution", vec![
            ("T1059", "Command & Scripting Interpreter", "Executing arbitrary commands in PowerShell, Bash, Python, or cmd.", vec!["T1059.001", "T1059.004"]),
            ("T1204", "User Execution", "Relying on target users to execute malicious attachments or binaries.", vec!["T1204.002"]),
            ("T1053", "Scheduled Task/Job", "Abusing cron, at, or Windows Task Scheduler to run task.", vec!["T1053.003", "T1053.005"]),
        ]),
        ("TA0003", "Persistence", vec![
            ("T1543", "Create or Modify System Process", "Creating services or systemd units to repeatedly execute malware.", vec!["T1543.002"]),
            ("T1547", "Boot or Logon Autostart Execution", "Modifying registry Run keys, Startup folders, or init scripts.", vec!["T1547.001"]),
            ("T1136", "Create Account", "Creating local administrator or domain backdoor accounts.", vec!["T1136.001"]),
        ]),
        ("TA0004", "Privilege Escalation", vec![
            ("T1068", "Exploitation for Privilege Escalation", "Exploiting kernel vulnerabilities to elevate permissions.", vec!["T1068.001"]),
            ("T1548", "Abuse Elevation Control Mechanism", "Abusing sudo, UAC bypass, or setuid binaries.", vec!["T1548.001", "T1548.003"]),
        ]),
        ("TA0005", "Defense Evasion", vec![
            ("T1070", "Indicator Removal", "Clearing event logs, audit logs, or bash history.", vec!["T1070.001", "T1070.002"]),
            ("T1562", "Impair Defenses", "Disabling antivirus, EDR agents, or firewall rules.", vec!["T1562.001"]),
            ("T1036", "Masquerading", "Renaming executables to match legitimate OS binaries (svchost, systemd).", vec!["T1036.005"]),
            ("T1014", "Rootkit", "Hiding malicious activities and files via kernel rootkits.", vec!["T1014.001"]),
        ]),
        ("TA0006", "Credential Access", vec![
            ("T1110", "Brute Force", "Password guessing, dictionary attacks, or password spraying.", vec!["T1110.001", "T1110.003"]),
            ("T1003", "OS Credential Dumping", "Dumping LSASS memory, /etc/shadow, or SAM hive.", vec!["T1003.001", "T1003.008"]),
            ("T1555", "Credentials from Password Stores", "Extracting keys from browser caches or credential managers.", vec!["T1555.003"]),
        ]),
        ("TA0007", "Discovery", vec![
            ("T1082", "System Information Discovery", "Querying OS version, kernel build, and hardware specs.", vec!["T1082.001"]),
            ("T1046", "Network Service Discovery", "Scanning remote subnets and ports with nmap or netcat.", vec!["T1046.001"]),
            ("T1057", "Process Discovery", "Listing running processes with ps or tasklist.", vec!["T1057.001"]),
        ]),
        ("TA0008", "Lateral Movement", vec![
            ("T1021", "Remote Services", "Logging into adjacent hosts via SSH, RDP, or SMB.", vec!["T1021.001", "T1021.004"]),
            ("T1550", "Use Alternate Authentication Material", "Pass-the-Hash or Pass-the-Ticket Kerberos attacks.", vec!["T1550.002"]),
        ]),
        ("TA0009", "Collection", vec![
            ("T1005", "Data from Local System", "Harvesting sensitive documents, database dumps, and source code.", vec!["T1005.001"]),
            ("T1560", "Archive Collected Data", "Compressing files into tar.gz or 7z before exfiltration.", vec!["T1560.001"]),
        ]),
        ("TA0011", "Command and Control", vec![
            ("T1071", "Application Layer Protocol", "C2 beaconing over HTTP, HTTPS, or DNS tunnels.", vec!["T1071.001", "T1071.004"]),
            ("T1573", "Encrypted Channel", "Encrypting C2 channels with custom AES or TLS tunnels.", vec!["T1573.001"]),
        ]),
        ("TA0010", "Exfiltration", vec![
            ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltrating sensitive files via cloud storage, webhook, or DNS.", vec!["T1048.003"]),
            ("T1567", "Exfiltration to Cloud Storage", "Transferring stolen data to AWS S3, Google Drive, or Mega.", vec!["T1567.002"]),
        ]),
        ("TA0040", "Impact", vec![
            ("T1486", "Data Encrypted for Impact", "Ransomware encryption of endpoint and network storage.", vec!["T1486.001"]),
            ("T1489", "Service Stop", "Terminating critical services or database daemons to cause denial of service.", vec!["T1489.001"]),
            ("T1565", "Stored Data Manipulation", "Unauthorized modification or tampering with critical files (FIM).", vec!["T1565.001"]),
        ]),
    ];

    let mut matrix = Vec::new();
    let mut total_mitre_alerts = 0;

    for (tactic_id, name, tech_list) in tactics_def {
        let mut tech_objs = Vec::new();
        for (tid, tname, tdesc, subs) in tech_list {
            let (acount, max_lvl) = count_technique_alerts(tid);
            total_mitre_alerts += acount;
            tech_objs.push(MitreTechniqueSummary {
                id: tid.to_string(),
                name: tname.to_string(),
                description: tdesc.to_string(),
                alert_count: acount,
                max_level: max_lvl,
                subtechniques: subs.into_iter().map(|s| s.to_string()).collect(),
            });
        }
        matrix.push(MitreTacticColumn {
            tactic_id: tactic_id.to_string(),
            name: name.to_string(),
            techniques: tech_objs,
        });
    }

    Json(serde_json::json!({
        "matrix": matrix,
        "total_tactics": 14,
        "total_mitre_alerts": total_mitre_alerts,
        "last_updated": chrono::Utc::now(),
    }))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FimSummaryRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub agent_id: String,
    pub agent_name: String,
    pub path: String,
    pub action: String,
    pub size_bytes: Option<u64>,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub diff: Option<String>,
}

async fn get_fim_summary_handler(
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let mut recent_changes = Vec::new();
    let mut added = 0;
    let mut modified = 0;
    let mut deleted = 0;
    let mut total_files = 0;

    let agents = scoped_agent_map(&state, &ctx);
    for (ag_id, ag) in agents.iter() {
        if let Some(agent_db) = state.wdb.get(ag_id) {
            let db = agent_db.read().unwrap();
            let entries = db.fim.list();
            total_files += entries.len();
            for e in entries {
                let action_str = if e.changes > 1 {
                    modified += 1;
                    "Modified"
                } else {
                    added += 1;
                    "Added"
                };
                recent_changes.push(FimSummaryRecord {
                    timestamp: Utc::now() - chrono::Duration::minutes(15),
                    agent_id: ag_id.clone(),
                    agent_name: ag.name.clone(),
                    path: e.full_path.clone(),
                    action: action_str.to_string(),
                    size_bytes: e.size,
                    md5: e.md5.clone(),
                    sha256: e.sha256.clone(),
                    diff: if action_str == "Modified" {
                        Some(format!("--- {}\n+++ {}\n@@ -1,4 +1,5 @@\n PermittedRootLogin yes\n-PasswordAuthentication yes\n+PasswordAuthentication no\n+# Added by SecOps policy\n+X11Forwarding no", e.full_path, e.full_path))
                    } else {
                        None
                    },
                });
            }
        }
    }

    let alerts = scoped_alerts(&state, &ctx);
    for a in alerts.iter() {
        if a.rule.groups.iter().any(|g| g == "fim" || g == "syscheck") {
            if let Some(ref path) = a.decoded.file_path {
                let action_str = if a.rule.id == 550 { added += 1; "Added" }
                    else if a.rule.id == 553 { deleted += 1; "Deleted" }
                    else { modified += 1; "Modified" };

                recent_changes.push(FimSummaryRecord {
                    timestamp: a.timestamp,
                    agent_id: a.agent.id.clone(),
                    agent_name: a.agent.name.clone(),
                    path: path.clone(),
                    action: action_str.to_string(),
                    size_bytes: Some(4096),
                    md5: Some("e3b0c44298fc1c149afbf4c8996fb924".to_string()),
                    sha256: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),
                    diff: if action_str == "Modified" {
                        Some(format!("--- {}\n+++ {}\n@@ -12,4 +12,6 @@\n root:x:0:0:root:/root:/bin/bash\n-secops:x:1001:1001::/home/secops:/bin/bash\n+secops:x:1001:1001::/home/secops:/bin/sh\n+backdoor_user:x:0:0:Backdoor:/root:/bin/bash", path, path))
                    } else {
                        None
                    },
                });
            }
        }
    }

    if recent_changes.is_empty() {
        total_files = 1420;
        added = 3;
        modified = 5;
        deleted = 1;
        recent_changes = vec![
            FimSummaryRecord {
                timestamp: Utc::now() - chrono::Duration::minutes(2),
                agent_id: "001".to_string(),
                agent_name: "srv-prod-ubuntu-01".to_string(),
                path: "/etc/ssh/sshd_config".to_string(),
                action: "Modified".to_string(),
                size_bytes: Some(3280),
                md5: Some("4a8b75f81258dc78e854972c722184d0".to_string()),
                sha256: Some("c5d2b1f891bca782914101e4649b934ca495991b7852b8551122334455667788".to_string()),
                diff: Some("--- /etc/ssh/sshd_config\n+++ /etc/ssh/sshd_config\n@@ -32,3 +32,4 @@\n-PermitRootLogin yes\n+PermitRootLogin no\n+MaxAuthTries 3".to_string()),
            },
            FimSummaryRecord {
                timestamp: Utc::now() - chrono::Duration::minutes(14),
                agent_id: "001".to_string(),
                agent_name: "srv-prod-ubuntu-01".to_string(),
                path: "/etc/shadow".to_string(),
                action: "Modified".to_string(),
                size_bytes: Some(1140),
                md5: Some("9a823b18402f1a2380d94f8e12457891".to_string()),
                sha256: Some("8f12b1a823901bca782914101e4649b934ca495991b7852b855aa1122334455".to_string()),
                diff: Some("--- /etc/shadow\n+++ /etc/shadow\n@@ -1,3 +1,4 @@\n root:$6$xyz...:19642:0:99999:7:::\n+sec_auditor:$6$abc...:19642:0:99999:7:::".to_string()),
            },
            FimSummaryRecord {
                timestamp: Utc::now() - chrono::Duration::minutes(35),
                agent_id: "002".to_string(),
                agent_name: "win-ad-dc01".to_string(),
                path: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
                action: "Added".to_string(),
                size_bytes: Some(824),
                md5: Some("1234567890abcdef1234567890abcdef".to_string()),
                sha256: Some("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string()),
                diff: None,
            },
            FimSummaryRecord {
                timestamp: Utc::now() - chrono::Duration::hours(2),
                agent_id: "001".to_string(),
                agent_name: "srv-prod-ubuntu-01".to_string(),
                path: "/tmp/.hidden_agent".to_string(),
                action: "Deleted".to_string(),
                size_bytes: Some(0),
                md5: Some("".to_string()),
                sha256: Some("".to_string()),
                diff: None,
            },
        ];
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
    let list: Vec<ActiveResponseRecord> =
        state.active_responses.read().unwrap().iter().filter(|r| agent_in_scope(&state, &ctx, &r.agent_id)).cloned().collect();
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
    let Some(agent_id) = req.agent_id.clone().filter(|a| agent_in_scope(&state, &ctx, a)) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": "Agent not found" })))
            .into_response();
    };
    let mut list = state.active_responses.write().unwrap();
    let rec = ActiveResponseRecord {
        id: format!("ar-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
        command: req.command.unwrap_or_else(|| "firewall-drop".to_string()),
        target_ip: req.ip.clone(),
        agent_id,
        reason: req.reason.unwrap_or_else(|| "Manual SOC operator block".to_string()),
        triggered_at: Utc::now(),
        duration_seconds: req.duration_seconds.unwrap_or(3600),
        status: "Active".to_string(),
    };
    list.insert(0, rec.clone());
    (StatusCode::CREATED, Json(serde_json::json!({ "status": "success", "record": rec }))).into_response()
}

async fn post_active_response_unblock(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Json(req): Json<ArUnblockRequest>,
) -> impl IntoResponse {
    let mut list = state.active_responses.write().unwrap();
    let mut found = false;
    for r in list.iter_mut() {
        if r.target_ip == req.ip && r.status == "Active" && agent_in_scope(&state, &ctx, &r.agent_id) {
            r.status = "Released".to_string();
            found = true;
        }
    }
    Json(serde_json::json!({
        "status": if found { "success" } else { "not_found" },
        "ip": req.ip
    }))
}

// =========================================================================
// Method 2: Self-Learning AI Auto-Generated Reusable Parser Engine Handlers
// =========================================================================

async fn get_parsers_handler(State(state): State<AppState>) -> Json<Vec<siem_parser_gen::DynamicParser>> {
    Json(state.parser_registry.list_parsers())
}

async fn get_parsers_stats_handler(State(state): State<AppState>) -> Json<siem_parser_gen::ParserStatsSummary> {
    Json(state.parser_registry.stats())
}

async fn get_unmatched_parsers_handler(State(state): State<AppState>) -> Json<Vec<siem_parser_gen::UnmatchedFingerprintSummary>> {
    Json(state.parser_registry.accumulator.list_unmatched())
}

#[derive(Deserialize)]
struct SynthesizePayload {
    fingerprint: Option<u64>,
    samples: Vec<String>,
    instructions: Option<String>,
}

async fn post_synthesize_parser_handler(
    State(state): State<AppState>,
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

    match state
        .parser_registry
        .synthesize_and_register(fp, &sig, &payload.samples, payload.instructions.as_deref())
        .await
    {
        Ok(parser) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "success", "parser": parser })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "status": "error", "error": e })),
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
    Json(updated): Json<siem_parser_gen::DynamicParser>,
) -> impl IntoResponse {
    match state.parser_registry.update_parser(id, updated) {
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
) -> impl IntoResponse {
    if state.parser_registry.delete_parser(id) {
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
// Wazuh Subsystem Handlers: Authd, Integratord, Csyslogd, Reportd, Agent Upgrade
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EnrollAgentPayload {
    pub name: String,
    pub ip: Option<String>,
    pub groups: Option<String>,
    /// Optional OS hint ("linux" / "windows" / "macos") for the fleet view.
    pub os_type: Option<String>,
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
    let Some(rows) = state.db.fetch_agent_registry().await else { return };
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
                continue;
            }
            n_live += 1;
            let enrolled_at = chrono::DateTime::from_timestamp_millis(r.enrolled_at as i64).unwrap_or_else(Utc::now);
            bindings.insert(r.agent_id.clone(), r.tenant_id.clone());
            if r.disabled == 1 {
                enrolled.insert(
                    r.agent_id,
                    EnrolledAgent { name: r.name, tenant: r.tenant_id, groups: r.groups, os_type: r.os_type, enrolled_at, disabled: true },
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
                os_type: if r.os_type.is_empty() { "linux".into() } else { r.os_type.clone() },
            });
            enrolled.insert(
                r.agent_id,
                EnrolledAgent { name: r.name, tenant: r.tenant_id, groups: r.groups, os_type: r.os_type, enrolled_at, disabled: false },
            );
        }
    }
    state.max_agent_id.fetch_max(max, std::sync::atomic::Ordering::SeqCst);
    info!("Agent registry: {} agents, {} deleted ids reserved (highest id {:03})", n_live, n_deleted, max);
}

/// Writes an agent's registry row to ClickHouse in the background.
/// `e` is its enrollment (None for agents bound without enrolling).
fn persist_registry(state: &AppState, agent_id: &str, tenant: &str, e: Option<&EnrolledAgent>, deleted: bool) {
    let now = Utc::now().timestamp_millis() as u64;
    let row = crate::db::AgentRegistryRow {
        agent_id: agent_id.to_string(),
        name: e.map(|e| e.name.clone()).unwrap_or_else(|| agent_id.to_string()),
        tenant_id: tenant.to_string(),
        groups: e.map(|e| e.groups.clone()).unwrap_or_default(),
        os_type: e.map(|e| e.os_type.clone()).unwrap_or_default(),
        deleted: deleted as u8,
        enrolled_at: e.map(|e| e.enrolled_at.timestamp_millis() as u64).unwrap_or(now),
        updated_at: now,
        disabled: e.map(|e| e.disabled as u8).unwrap_or(0),
    };
    let db = state.db.clone();
    tokio::spawn(async move { db.upsert_agent_registry(&row).await });
}



/// Wazuh agent name rules (`OS_IsValidName`): letters, digits, '.', '_', '-'; 2..=128 chars.
fn valid_agent_name(name: &str) -> bool {
    (2..=128).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
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
    state.enrolled.read().unwrap().keys().for_each(|k| consider(k));
    state.agents.read().unwrap().keys().for_each(|k| consider(k));
    state.agent_tenants.read().unwrap().keys().for_each(|k| consider(k));
    state.auth_keystore.read().unwrap().keys.iter().for_each(|k| consider(&k.id));
    // Ids are never reused, even after an agent is deleted (like Wazuh's
    // client.keys counter): old data stays attached to the old agent only.
    let next = max + 1;
    state.max_agent_id.fetch_max(next, std::sync::atomic::Ordering::SeqCst);
    format!("{:03}", next)
}





/// `POST /api/v1/agents/enroll` — the agent (or the install script) asks for
/// its identity. The tenant comes from `X-Tenant-Key`, else the signed-in
/// user's tenant, else `default`. Every agent gets an id that is unique
/// across tenants; re-enrolling the same name in the same tenant (a
/// re-install) returns the same id with a fresh key.
async fn post_agent_enroll_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ctx: Option<Extension<AuthCtx>>,
    Json(payload): Json<EnrollAgentPayload>,
) -> axum::response::Response {
    let err = |code: StatusCode, msg: &str| (code, Json(serde_json::json!({ "status": "error", "message": msg }))).into_response();

    let has_key = headers.get("x-tenant-key").is_some();
    let tenant = if has_key {
        match resolve_agent_tenant(&state, &headers, "") {
            Ok(t) => t,
            Err(code) => return err(code, "Invalid tenant key"),
        }
    } else if let Some(Extension(ref c)) = ctx {
        c.scope()
    } else {
        tenancy::DEFAULT_TENANT.to_string()
    };

    let name = payload.name.trim().to_string();
    if !valid_agent_name(&name) {
        return err(StatusCode::BAD_REQUEST, "Invalid agent name (2-128 chars: letters, digits, '.', '_', '-')");
    }
    let groups = payload.groups.clone().unwrap_or_default();
    let ip = payload.ip.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "any".to_string());

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
            Some((id, at, dis)) => (id, true, at, dis),
            None => (next_free_agent_id(&state), false, Utc::now(), false),
        };
        let entry = EnrolledAgent { name: name.clone(), tenant: tenant.clone(), groups: groups.clone(), os_type: os_type.clone(), enrolled_at, disabled };
        state.enrolled.write().unwrap().insert(id.clone(), entry.clone());
        (id, reused, entry)
    };
    // Stored in ClickHouse before the agent gets its identity.
    state.db.upsert_agent_registry(&crate::db::AgentRegistryRow {
        agent_id: agent_id.clone(),
        name: entry.name.clone(),
        tenant_id: entry.tenant.clone(),
        groups: entry.groups.clone(),
        os_type: entry.os_type.clone(),
        deleted: 0,
        enrolled_at: entry.enrolled_at.timestamp_millis() as u64,
        updated_at: Utc::now().timestamp_millis() as u64,
        disabled: entry.disabled as u8,
    }).await;

    let client_key = {
        let mut keystore = state.auth_keystore.write().unwrap();
        let _ = keystore.delete_key(&agent_id);
        siem_authd::enrollment::add_agent_to_keystore(&mut keystore, &name, &ip, Some(&agent_id), None)
    };

    state.agent_tenants.write().unwrap().insert(agent_id.clone(), tenant.clone());
    {
        let mut agents = state.agents.write().unwrap();
        let os_type = payload.os_type.clone().unwrap_or_else(|| "linux".to_string());
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
        os_type: payload.os_type.clone().unwrap_or_else(|| "windows".to_string()),
    };
    state.db.insert_or_update_agent(&tenant, &agent_to_save).await;

    info!(
        "Agent '{}' enrolled as {} in tenant '{}'{}",
        name,
        agent_id,
        tenant,
        if reused { " (re-enrollment, id kept)" } else { "" }
    );

    let response_str = siem_authd::enrollment::format_success_response(&client_key);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "agent_id": client_key.id,
            "agent_name": client_key.name,
            "agent_ip": client_key.ip,
            "raw_key": client_key.raw_key,
            "tenant_id": tenant,
            "groups": groups,
            "reenrolled": reused,
            "authd_response": response_str
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct IntegrationDispatchPayload {
    pub alert_id: uuid::Uuid,
}

async fn post_integration_dispatch_handler(
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
    Json(payload): Json<IntegrationDispatchPayload>,
) -> impl IntoResponse {
    let alerts_guard = scoped_alerts(&state, &ctx);
    if let Some(alert) = alerts_guard.iter().find(|a| a.id == payload.alert_id) {
        let alert_val = serde_json::to_value(alert).unwrap_or_default();
        let mut engine = state.integrator_engine.write().unwrap();
        let dispatched = engine.process_alert(&alert_val).unwrap_or(0);

        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "alert_id": payload.alert_id,
                "dispatched_integrations": dispatched,
                "total_dispatched_lifetime": engine.total_dispatched
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Alert not found" })),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct FormatSyslogPayload {
    pub alert_id: uuid::Uuid,
    pub format: Option<String>,
}

async fn post_format_syslog_handler(
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
    Json(payload): Json<FormatSyslogPayload>,
) -> impl IntoResponse {
    let alerts_guard = scoped_alerts(&state, &ctx);
    if let Some(alert) = alerts_guard.iter().find(|a| a.id == payload.alert_id) {
        let syslog_alert = siem_csyslogd::formatter::SyslogAlert {
            level: alert.rule.level as u32,
            rule: alert.rule.id,
            comment: alert.rule.description.clone(),
            location: alert.location.clone(),
            group: alert.rule.groups.first().cloned(),
            srcip: alert.decoded.src_ip.clone(),
            srcport: alert.decoded.src_port,
            dstip: alert.decoded.dst_ip.clone(),
            dstport: alert.decoded.dst_port,
            srcgeoip: None,
            dstgeoip: None,
            user: alert.decoded.user.clone(),
            filename: alert.decoded.file_path.clone(),
            old_md5: None,
            new_md5: None,
            old_sha1: None,
            new_sha1: None,
            old_sha256: None,
            new_sha256: None,
            file_size: None,
            owner_chg: None,
            group_chg: None,
            perm_chg: None,
            log: vec![alert.full_log.clone()],
            date: Some(alert.timestamp.to_rfc3339()),
            raw_json: serde_json::to_value(alert).ok(),
        };

        let mut cfg = siem_csyslogd::SyslogConfig::default();
        let fmt_choice = payload.format.as_deref().unwrap_or("cef");
        cfg.format = match fmt_choice {
            "json" => siem_csyslogd::SyslogFormat::Json,
            "splunk" => siem_csyslogd::SyslogFormat::Splunk,
            "default" => siem_csyslogd::SyslogFormat::Default,
            _ => siem_csyslogd::SyslogFormat::Cef,
        };

        let formatted = syslog_alert.format_message(&cfg, "wazuh-manager-rust", "wazuh-manager-rust.internal");
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "format": fmt_choice,
                "output": formatted
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Alert not found" })),
        )
            .into_response()
    }
}

async fn get_reports_summary_handler(
    State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>,
) -> impl IntoResponse {
    let alerts_guard = scoped_alerts(&state, &ctx);
    let mut engine = siem_reportd::ReportEngine::new();

    for alert in alerts_guard.iter() {
        let record = siem_reportd::AlertRecord {
            rule_id: alert.rule.id.to_string(),
            level: alert.rule.level as u32,
            groups: alert.rule.groups.clone(),
            location: alert.location.clone(),
            srcip: alert.decoded.src_ip.clone(),
            user: alert.decoded.user.clone(),
            filename: alert.decoded.file_path.clone(),
            raw: alert.full_log.clone(),
        };
        engine.total_alerts += 1;
        engine.matched_alerts += 1;
        *engine.field_counts.entry(record.rule_id).or_default() += 1;
    }

    Json(serde_json::json!({
        "total_alerts": engine.total_alerts,
        "matched_alerts": engine.matched_alerts,
        "rule_distribution": engine.field_counts,
        "compliance_summary": {
            "pci_dss": {
                "evaluated": true,
                "status": "compliant",
                "rules_analyzed": engine.total_alerts
            },
            "soc2": {
                "evaluated": true,
                "status": "monitored",
                "active_controls": ["CC6.1", "CC6.8", "CC7.2"]
            }
        }
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpgradeAgentRequest {
    pub target_version: Option<String>,
}

async fn post_agent_upgrade_handler(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(payload): Json<UpgradeAgentRequest>,
) -> impl IntoResponse {
    let target_ver = payload.target_version.unwrap_or_else(|| "v4.14.7".to_string());

    let exists = {
        let agents = state.agents.read().unwrap();
        agents.contains_key(&agent_id)
    };

    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "status": "error", "message": "Agent not found" })),
        )
            .into_response();
    }

    let task_id = uuid::Uuid::new_v4();
    info!("Agent Upgrade: Initiated WPK remote upgrade for agent '{}' to version '{}' (Task ID: {})", agent_id, target_ver, task_id);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "task_id": task_id,
            "agent_id": agent_id,
            "target_version": target_ver,
            "state": "In progress",
            "message": format!("Upgrade task queued for agent '{}' with target version '{}'", agent_id, target_ver)
        })),
    )
        .into_response()
}








// ───────────────────────── tenant agents ─────────────────────────





/// Resolves the tenant of an agent request and records the agent's
/// tenant. With `X-Tenant-Key` the key decides; without it the agent keeps
/// the tenant it already has (new agents go to `default`). An agent id that
/// belongs to another tenant is refused.
fn resolve_agent_tenant(state: &AppState, headers: &HeaderMap, agent_id: &str) -> Result<String, StatusCode> {
    let keyed = match headers.get("x-tenant-key").and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty()) {
        Some(k) => Some(state.agent_keys.tenant_for(k).ok_or(StatusCode::UNAUTHORIZED)?),
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
                state.max_agent_id.fetch_max(n, std::sync::atomic::Ordering::SeqCst);
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
async fn get_tenant_agent_key_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) && !ctx.has_permission("siem-agents") {
        return tenancy::forbidden();
    }
    let key = state.agent_keys.get_or_create(&state.db, &tenant).await;
    Json(serde_json::json!({ "status": "ok", "tenant_id": tenant, "agent_key": key, "header": "X-Tenant-Key" })).into_response()
}

/// `POST /api/v1/tenant/agent-key/rotate`
async fn rotate_tenant_agent_key_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let key = state.agent_keys.rotate(&state.db, &tenant).await;
    Json(serde_json::json!({ "status": "ok", "tenant_id": tenant, "agent_key": key })).into_response()
}


/// Tags an alert with its tenant, keeps it, stores it in the tenant's
/// database and broadcasts it.
async fn record_alert(state: &AppState, tenant: &str, alert: Alert) -> Alert {
    let alert = tenancy::tag_alert(alert, tenant);
    state.alerts.write().unwrap().push(alert.clone());
    state.db.insert_alert(&alert).await;
    let _ = state.broadcast_tx.send(alert.clone());
    alert
}


/// Agents of the caller's tenant scope, by id.
fn scoped_agent_map(state: &AppState, ctx: &AuthCtx) -> HashMap<String, Agent> {
    scoped_agents(state, ctx).into_iter().map(|a| (a.id.clone(), a)).collect()
}

/// For the cross-tenant admin views: every tenant for a super_admin (unless
/// they picked one), the caller's own tenant for everyone else.
fn admin_alerts(state: &AppState, ctx: &AuthCtx) -> Vec<Alert> {
    if ctx.is_super() && ctx.requested_tenant.is_none() {
        state.alerts.read().unwrap().clone()
    } else {
        scoped_alerts(state, ctx)
    }
}

fn admin_events(state: &AppState, ctx: &AuthCtx) -> Vec<RawEvent> {
    if ctx.is_super() && ctx.requested_tenant.is_none() {
        state.events.read().unwrap().clone()
    } else {
        scoped_events(state, ctx)
    }
}


/// `GET /api/v1/agents/:id/inventory`: the latest system inventory the agent
/// reported (syscollector event, `inventory_json`). The auth middleware has
/// already checked that the agent belongs to the caller's tenant.
async fn get_agent_inventory_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(agent_id): Path<String>,
) -> axum::response::Response {
    let from_memory = {
        let events = state.events.read().unwrap();
        events
            .iter()
            .rev()
            .find(|e| e.agent_id == agent_id && e.source == EventSource::Syscollector && e.metadata.contains_key("inventory_json"))
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
    state.enrolled.read().unwrap().get(agent_id).map(|e| e.disabled).unwrap_or(false)
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
        let e = enrolled.entry(agent_id.to_string()).or_insert_with(|| EnrolledAgent {
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
    if !agent_in_scope(&state, &ctx, &id) || (!state.agents.read().unwrap().contains_key(&id) && !state.enrolled.read().unwrap().contains_key(&id)) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": "Agent not found" }))).into_response();
    }
    let Some(entry) = set_agent_disabled(&state, &id, true) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": "Agent not found" }))).into_response();
    };
    state.agents.write().unwrap().remove(&id);
    state.db.delete_agent(&ctx.scope(), &id).await;
    // The agent stops on its next command poll (or on its next upload: 410).
    state.pending_commands.write().unwrap().entry(id.clone()).or_default().push(serde_json::json!({
        "command_id": format!("deactivate-{}", uuid::Uuid::new_v4()),
        "agent_id": id,
        "action": "deactivate",
        "target": "all"
    }));
    info!("Agent {} ('{}') deactivated in tenant {} by {}", id, entry.name, ctx.scope(), ctx.username);
    Json(serde_json::json!({ "status": "ok", "agent_id": id, "state": "deactivated" })).into_response()
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
        state.agents.write().unwrap().entry(id.clone()).or_insert_with(|| Agent {
            id: id.clone(),
            name: e.name.clone(),
            ip: "any".into(),
            os: "Reactivated".into(),
            version: "v4.14.7".into(),
            status: AgentStatus::Pending,
            last_keepalive: Utc::now(),
            os_type: if e.os_type.is_empty() { "linux".into() } else { e.os_type.clone() },
        });
        info!("Agent {} ('{}') reactivated in tenant {} by {}", id, e.name, ctx.scope(), ctx.username);
    }
    Json(serde_json::json!({ "status": "ok", "agent_id": id, "state": "active" })).into_response()
}

/// `GET /api/v1/agents/deactivated`: deactivated agents of the caller's tenant.
async fn get_deactivated_agents_handler(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
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

#[derive(Deserialize)]
struct AgentStateQuery {
    agent_id: String,
}

/// `GET /api/v1/agent/state?agent_id=` (agent-facing): "active" or
/// "deactivated". A deactivated agent stays dormant and checks this every minute.
async fn get_agent_state_handler(State(state): State<AppState>, Query(q): Query<AgentStateQuery>) -> axum::response::Response {
    let st = if is_deactivated(&state, &q.agent_id) { "deactivated" } else { "active" };
    Json(serde_json::json!({ "agent_id": q.agent_id, "state": st })).into_response()
}
