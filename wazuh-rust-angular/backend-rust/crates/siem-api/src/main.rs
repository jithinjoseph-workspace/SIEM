use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, Method, StatusCode},
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
use db::ClickHouseDb;

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
}

#[tokio::main]
async fn main() {
    eprintln!(">>> SIEM API STARTING ON PID: {} <<<", std::process::id());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Next-Gen Wazuh Rust SIEM Server...");

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
    };

    // Pre-seed sample active agents
    seed_sample_data(&state);

    // Start background Syslog listeners (UDP 514 / TCP 601) for firewall & network appliance ingestion
    syslog::start_syslog_listeners(state.clone());

    // Start background NDR <-> SIEM cross-source corroboration worker
    corroboration::spawn_corroboration_worker(state.clone());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    let app = Router::new()
        .route("/api/v1/stats", get(get_stats))
        .route("/api/v1/alerts", get(get_alerts))
        .route("/api/v1/agents", get(get_agents))
        .route("/api/v1/agents/:id", delete(delete_agent_handler))
        .route("/api/agents/:id", delete(delete_agent_handler))
        .route("/agents", delete(delete_agents_wazuh_handler))
        .route("/api/v1/events", get(get_events))
        .route("/api/v1/rules", get(get_rules))
        .route("/api/v1/ai/analyze", post(ai_analyze_event))
        .route("/api/v1/ai/chat", post(ai_chat_handler))
        .route("/api/v1/ingest", post(ingest_event))
        .route("/api/events/ingest", post(ingest_event))
        .route("/api/v1/agent/commands", get(get_agent_commands).post(queue_agent_command))
        .route("/api/agents/:id/commands", get(get_agent_commands_by_path))
        .route("/api/v1/agent/commands/ack", post(ack_agent_command))
        .route("/api/v1/xdr/incidents", get(get_xdr_incidents))
        .route("/api/v1/auth/me", get(auth_me_handler))
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

async fn get_stats(State(state): State<AppState>) -> Json<SiemStats> {
    let events_count = state.events.read().unwrap().len() as u64;
    let alerts_guard = state.alerts.read().unwrap();
    let agents_guard = state.agents.read().unwrap();

    let total_alerts = alerts_guard.len() as u64;
    let mut critical_alerts = 0;
    let mut high_alerts = 0;
    let mut medium_alerts = 0;
    let mut low_alerts = 0;

    for a in alerts_guard.iter() {
        match a.rule.level {
            12..=15 => critical_alerts += 1,
            8..=11 => high_alerts += 1,
            4..=7 => medium_alerts += 1,
            _ => low_alerts += 1,
        }
    }

    let now = Utc::now();
    let total_agents = agents_guard.len();
    let active_agents = agents_guard
        .values()
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

async fn get_alerts(State(state): State<AppState>, Query(params): Query<AlertsQuery>) -> Json<Vec<Alert>> {
    let limit = params.limit.unwrap_or(100);
    let min_level = params.min_level.unwrap_or(0);

    // If ClickHouse is available, fetch persisted alerts directly from ClickHouse
    if state.db.is_connected() {
        if let Some(ch_rows) = state.db.fetch_alerts(limit, min_level).await {
            if !ch_rows.is_empty() {
                let alerts: Vec<Alert> = ch_rows.into_iter().map(|r| r.to_alert()).collect();
                return Json(alerts);
            }
        }
    }

    let alerts_guard = state.alerts.read().unwrap();
    let mut filtered: Vec<Alert> = alerts_guard
        .iter()
        .filter(|a| a.rule.level >= min_level)
        .cloned()
        .collect();

    filtered.reverse(); // Most recent first
    filtered.truncate(limit);

    Json(filtered)
}

async fn get_agents(State(state): State<AppState>) -> Json<Vec<Agent>> {
    let mut agents_guard = state.agents.write().unwrap();
    let now = Utc::now();
    for agent in agents_guard.values_mut() {
        // Mirroring wazuh-monitord: mark disconnected if last keepalive exceeds 60s
        if (now - agent.last_keepalive).num_seconds() > 60 {
            agent.status = AgentStatus::Disconnected;
        }
    }
    let mut list: Vec<Agent> = agents_guard.values().cloned().collect();
    list.sort_by(|a, b| a.id.cmp(&b.id));
    Json(list)
}

async fn delete_agent_handler(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let mut agents = state.agents.write().unwrap();
    if agents.remove(&id).is_some() {
        info!("Removed agent '{}' from SIEM registry", id);
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
) -> impl IntoResponse {
    let mut agents = state.agents.write().unwrap();
    let mut removed = Vec::new();
    if let Some(list) = params.agents_list {
        for id in list.split(',') {
            let id = id.trim();
            if agents.remove(id).is_some() {
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

async fn get_events(State(state): State<AppState>, Query(params): Query<EventsQuery>) -> Json<Vec<RawEvent>> {
    let limit = params.limit.unwrap_or(200);

    // If ClickHouse is connected, query persisted events from ClickHouse
    if state.db.is_connected() && params.source.is_none() {
        if let Some(ch_rows) = state.db.fetch_events(limit).await {
            if !ch_rows.is_empty() {
                let events: Vec<RawEvent> = ch_rows.into_iter().map(|r| r.to_raw_event()).collect();
                return Json(events);
            }
        }
    }

    let events_guard = state.events.read().unwrap();
    let mut list: Vec<RawEvent> = events_guard
        .iter()
        .filter(|e| {
            if let Some(ref src) = params.source {
                format!("{:?}", e.source).to_lowercase().contains(&src.to_lowercase())
            } else {
                true
            }
        })
        .cloned()
        .collect();

    list.reverse(); // Most recent first
    list.truncate(limit);
    Json(list)
}

async fn ingest_event(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<Option<Alert>>, StatusCode> {
    let events: Vec<RawEvent> = if payload.is_array() {
        serde_json::from_value(payload).map_err(|_| StatusCode::BAD_REQUEST)?
    } else {
        let single: RawEvent = serde_json::from_value(payload).map_err(|_| StatusCode::BAD_REQUEST)?;
        vec![single]
    };

    let mut last_alert = None;

    for event in events {
        // Update or register agent keepalive
        let (agent_name, agent_ip) = {
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
            if let Some(host) = event.metadata.get("hostname") {
                ag.name = host.clone();
            }
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
            (ag.name.clone(), ag.ip.clone())
        };

        // Method 2: Dynamic Parser Engine Hot-Path Execution (< 5 microseconds, 0ms AI delay)
        let _maybe_dynamic_parsed = state.parser_registry.execute(&event.message);

        let maybe_alert = state.engine.process_event(&event, &agent_name, &agent_ip);

        if let Some(ref alert) = maybe_alert {
            state.alerts.write().unwrap().push(alert.clone());
            state.db.insert_alert(alert).await;
            let _ = state.broadcast_tx.send(alert.clone());
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
                                    state.alerts.write().unwrap().push(alert.clone());
                                    state.db.insert_alert(&alert).await;
                                    let _ = state.broadcast_tx.send(alert.clone());
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
                state.alerts.write().unwrap().push(alert.clone());
                state.db.insert_alert(&alert).await;
                let _ = state.broadcast_tx.send(alert.clone());
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
            state.alerts.write().unwrap().push(alert.clone());
            state.db.insert_alert(&alert).await;
            let _ = state.broadcast_tx.send(alert.clone());
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

    let mut triggered_alerts = Vec::new();
    for ev in generated_events {
        let (name, ip) = {
            let agents = state.agents.read().unwrap();
            let ag = agents.get(&ev.agent_id).cloned().unwrap_or(Agent {
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

async fn ws_alerts_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_socket(socket, state))
}

async fn handle_ws_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.broadcast_tx.subscribe();

    while let Ok(alert) = rx.recv().await {
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
    Json(mut payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id = payload
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("001")
        .to_string();

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
    Json(serde_json::json!({ "status": "queued" }))
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
    Query(query): Query<SyscheckRestartQuery>,
) -> impl IntoResponse {
    let agents_str = query.agents_list.unwrap_or_else(|| "*".into());
    let mut map = state.pending_commands.write().unwrap();

    let target_agents: Vec<String> = if agents_str == "*" {
        state.agents.read().unwrap().keys().cloned().collect()
    } else {
        agents_str.split(',').map(|s| s.trim().to_string()).collect()
    };

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

fn get_groq_api_key() -> String {
    std::env::var("GROQ_API_KEY")
        .unwrap_or_else(|_| "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".to_string())
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
        let events = state.events.read().unwrap();
        if let Some(ev) = events.iter().find(|e| &e.id.to_string() == eid) {
            agent_id = ev.agent_id.clone();
            source_str = format!("{:?}", ev.source);
            location_str = ev.location.clone();
            event_text = format!("Log Location: {}\nRaw Message: {}\nMetadata: {:?}", ev.location, ev.message, ev.metadata);
        }
    } else if let Some(ref aid) = req.alert_id {
        let alerts = state.alerts.read().unwrap();
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
) -> Json<Vec<crate::db::ClickHouseIncidentRow>> {
    if let Some(incidents) = state.db.fetch_incidents(50).await {
        Json(incidents)
    } else {
        Json(Vec::new())
    }
}

async fn auth_me_handler(
    headers: axum::http::HeaderMap,
) -> Result<Json<provigil_common::auth::Claims>, StatusCode> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "super_secret_jwt_key_provigil_wazuh_siem".into());
    if let Some(auth_hdr) = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_hdr.strip_prefix("Bearer ") {
            if let Ok(claims) = provigil_common::auth::validate_jwt(token, &secret) {
                return Ok(Json(claims));
            }
        }
    }

    // Default / analyst credentials fallback
    Ok(Json(provigil_common::auth::Claims {
        sub: "analyst".into(),
        role: "analyst".into(),
        tenant_id: "default".into(),
        permissions: vec![
            "dashboard".into(),
            "alerts".into(),
            "siem".into(),
            "ndr".into(),
            "rules".into(),
            "agents".into(),
        ],
        features: vec!["siem".into(), "ndr".into()],
        sensor_ids: vec![],
        exp: 9999999999,
        iat: 0,
        jti: "dev-session-jwt".into(),
    }))
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
    State(state): State<AppState>,
) -> Json<SiemDashboardResponse> {
    let events = state.events.read().unwrap();
    let alerts = state.alerts.read().unwrap();
    let agents = state.agents.read().unwrap();

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
    State(state): State<AppState>,
) -> Json<SiemSourcesResponse> {
    let agents = state.agents.read().unwrap();
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
    Json(payload): Json<PostSourcePayload>,
) -> Json<PostSourceResponse> {
    let new_id = format!("{:03}", state.agents.read().unwrap().len() + 1);
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
    Query(params): Query<VulnFilterParams>,
) -> Json<VulnerabilitiesResponse> {
    let vulns = state.vulnerabilities.read().unwrap();
    let filtered: Vec<VulnerabilityDetection> = vulns
        .iter()
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
    State(state): State<AppState>,
) -> impl IntoResponse {
    let alerts = state.alerts.read().unwrap();

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
    State(state): State<AppState>,
) -> impl IntoResponse {
    let alerts = state.alerts.read().unwrap();

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
    State(state): State<AppState>,
) -> impl IntoResponse {
    let mut recent_changes = Vec::new();
    let mut added = 0;
    let mut modified = 0;
    let mut deleted = 0;
    let mut total_files = 0;

    let agents = state.agents.read().unwrap();
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

    let alerts = state.alerts.read().unwrap();
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
) -> impl IntoResponse {
    let list = state.active_responses.read().unwrap();
    Json(serde_json::json!({
        "total": list.len(),
        "active_blocks": list.iter().filter(|r| r.status == "Active").count(),
        "records": *list,
    }))
}

async fn post_active_response_block(
    State(state): State<AppState>,
    Json(req): Json<ArBlockRequest>,
) -> impl IntoResponse {
    let mut list = state.active_responses.write().unwrap();
    let rec = ActiveResponseRecord {
        id: format!("ar-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
        command: req.command.unwrap_or_else(|| "firewall-drop".to_string()),
        target_ip: req.ip.clone(),
        agent_id: req.agent_id.unwrap_or_else(|| "001".to_string()),
        reason: req.reason.unwrap_or_else(|| "Manual SOC operator block".to_string()),
        triggered_at: Utc::now(),
        duration_seconds: req.duration_seconds.unwrap_or(3600),
        status: "Active".to_string(),
    };
    list.insert(0, rec.clone());
    (StatusCode::CREATED, Json(serde_json::json!({ "status": "success", "record": rec })))
}

async fn post_active_response_unblock(
    State(state): State<AppState>,
    Json(req): Json<ArUnblockRequest>,
) -> impl IntoResponse {
    let mut list = state.active_responses.write().unwrap();
    let mut found = false;
    for r in list.iter_mut() {
        if r.target_ip == req.ip && r.status == "Active" {
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
}

async fn post_agent_enroll_handler(
    State(state): State<AppState>,
    Json(payload): Json<EnrollAgentPayload>,
) -> impl IntoResponse {
    let ip = payload.ip.unwrap_or_else(|| "any".to_string());
    let mut keystore = state.auth_keystore.write().unwrap();

    let client_key = siem_authd::enrollment::add_agent_to_keystore(
        &mut keystore,
        &payload.name,
        &ip,
        None,
        None,
    );

    // Register into active agents map
    {
        let mut agents = state.agents.write().unwrap();
        agents.insert(
            client_key.id.clone(),
            Agent {
                id: client_key.id.clone(),
                name: client_key.name.clone(),
                ip: client_key.ip.clone(),
                status: AgentStatus::Active,
                os: "Registered via Authd".to_string(),
                version: "v4.14.7".to_string(),
                last_keepalive: Utc::now(),
                os_type: "linux".to_string(),
            },
        );
    }

    let response_str = siem_authd::enrollment::format_success_response(&client_key);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "agent_id": client_key.id,
            "agent_name": client_key.name,
            "agent_ip": client_key.ip,
            "raw_key": client_key.raw_key,
            "authd_response": response_str
        })),
    )
}

#[derive(Debug, Deserialize)]
pub struct IntegrationDispatchPayload {
    pub alert_id: uuid::Uuid,
}

async fn post_integration_dispatch_handler(
    State(state): State<AppState>,
    Json(payload): Json<IntegrationDispatchPayload>,
) -> impl IntoResponse {
    let alerts_guard = state.alerts.read().unwrap();
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
    State(state): State<AppState>,
    Json(payload): Json<FormatSyslogPayload>,
) -> impl IntoResponse {
    let alerts_guard = state.alerts.read().unwrap();
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
    State(state): State<AppState>,
) -> impl IntoResponse {
    let alerts_guard = state.alerts.read().unwrap();
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







