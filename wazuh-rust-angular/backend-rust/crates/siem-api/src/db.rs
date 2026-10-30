use clickhouse::Client;
use serde::{Deserialize, Serialize};
use siem_core::{Alert, RawEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ClickHouseEventRow {
    pub id: String,
    pub timestamp: u64,
    pub agent_id: String,
    pub source: String,
    pub location: String,
    pub message: String,
    pub raw_metadata: String,
}

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ClickHouseAlertRow {
    pub id: String,
    pub timestamp: u64,
    pub agent_id: String,
    pub agent_name: String,
    pub agent_ip: String,
    pub rule_id: u32,
    pub rule_level: u8,
    pub rule_description: String,
    pub mitre_id: String,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub full_log: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub user: String,
    pub location: String,
    /// The whole alert (groups, decoded fields, FIM data...), so the pages that
    /// read history from ClickHouse see what the live alert had. Empty in older rows.
    #[serde(default)]
    pub alert_json: String,
}

/// Counts of a time window: events (and of its last hour), alerts per rule level (and of the last hour).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct WindowCounts {
    pub events: u64,
    pub events_1h: u64,
    pub alerts_1h: u64,
    /// Alerts per rule level (0..=16).
    pub levels: [u64; 17],
}

impl WindowCounts {
    pub fn alerts(&self) -> u64 {
        self.levels.iter().sum()
    }
    /// Alerts with a level in `lo..=hi`.
    pub fn band(&self, lo: u8, hi: u8) -> u64 {
        self.levels[lo.min(16) as usize..=hi.min(16) as usize].iter().sum()
    }
    pub fn critical(&self) -> u64 {
        self.band(12, 16)
    }
    pub fn high(&self) -> u64 {
        self.band(8, 11)
    }
    pub fn medium(&self) -> u64 {
        self.band(4, 7)
    }
    pub fn low(&self) -> u64 {
        self.band(0, 3)
    }
    pub fn add_alert(&mut self, level: u8, last_hour: bool) {
        self.levels[level.min(16) as usize] += 1;
        self.alerts_1h += last_hour as u64;
    }
    pub fn merge(&mut self, o: &WindowCounts) {
        self.events += o.events;
        self.events_1h += o.events_1h;
        self.alerts_1h += o.alerts_1h;
        for (a, b) in self.levels.iter_mut().zip(o.levels) {
            *a += b;
        }
    }
}

/// An alert column the history pages group by (a fixed column name, never caller input).
#[derive(Debug, Clone, Copy)]
pub enum AlertField {
    SrcIp,
    DstIp,
}

impl AlertField {
    fn column(self) -> &'static str {
        match self {
            Self::SrcIp => "src_ip",
            Self::DstIp => "dst_ip",
        }
    }
}

/// The protocol an event is counted under (dashboard protocol chart), as ClickHouse
/// computes it; [`event_protocol`] is the same for the in-memory window.
const PROTOCOL_SQL: &str = "multiIf(\
    positionCaseInsensitive(location, 'ssh') > 0 OR positionCaseInsensitive(message, 'ssh') > 0, 'SSH', \
    positionCaseInsensitive(location, 'http') > 0 OR positionCaseInsensitive(message, 'http') > 0, 'HTTP', \
    positionCaseInsensitive(location, 'tls') > 0 OR positionCaseInsensitive(location, 'ssl') > 0 OR positionCaseInsensitive(message, 'tls') > 0, 'TLS', \
    positionCaseInsensitive(location, 'dns') > 0 OR positionCaseInsensitive(message, 'dns') > 0, 'DNS', \
    positionCaseInsensitive(location, 'smb') > 0 OR positionCaseInsensitive(message, 'smb') > 0, 'SMB', \
    positionCaseInsensitive(location, 'syslog') > 0, 'SYSLOG', 'TCP/IP')";
/// Events from network sensors (flows, Zeek).
const NETWORK_SQL: &str = "position(source, 'network') > 0 OR position(location, 'flow') > 0 OR position(location, 'zeek') > 0";

pub fn event_protocol(location: &str, message: &str) -> &'static str {
    let (l, m) = (location.to_lowercase(), message.to_lowercase());
    let any = |w: &str| l.contains(w) || m.contains(w);
    if any("ssh") {
        "SSH"
    } else if any("http") {
        "HTTP"
    } else if l.contains("tls") || l.contains("ssl") || m.contains("tls") {
        "TLS"
    } else if any("dns") {
        "DNS"
    } else if any("smb") {
        "SMB"
    } else if l.contains("syslog") {
        "SYSLOG"
    } else {
        "TCP/IP"
    }
}

pub fn event_is_network(source: &str, location: &str) -> bool {
    source.contains("network") || location.contains("flow") || location.contains("zeek")
}

/// Columns added to an existing table (every tenant database, at start and provisioning).
pub const ALERT_COLUMNS: [&str; 1] = ["ALTER TABLE siem_alerts ADD COLUMN IF NOT EXISTS alert_json String DEFAULT ''"];

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ClickHouseUserRow {
    pub id: String,
    pub tenant_id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub permissions: String,
    pub mfa_enabled: u8,
    pub active: u8,
    pub password_hash: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ClickHouseTenantRow {
    pub id: String,
    pub name: String,
    pub plan: String,
    pub features: String,
    pub active: u8,
    pub ai_enabled: u8,
    pub created_at: u64,
}

impl ClickHouseAlertRow {
    pub fn to_alert(&self) -> Alert {
        if !self.alert_json.is_empty() {
            if let Ok(a) = serde_json::from_str::<Alert>(&self.alert_json) {
                return a;
            }
        }
        Alert {
            id: uuid::Uuid::parse_str(&self.id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            timestamp: chrono::DateTime::from_timestamp_millis(self.timestamp as i64).unwrap_or_else(chrono::Utc::now),
            rule: siem_core::RuleAlertInfo {
                id: self.rule_id,
                level: self.rule_level,
                description: self.rule_description.clone(),
                groups: Vec::new(),
                mitre: if !self.mitre_id.is_empty() {
                    Some(siem_core::MitreAttack {
                        id: self.mitre_id.clone(),
                        tactic: self.mitre_tactic.clone(),
                        technique: self.mitre_technique.clone(),
                    })
                } else {
                    None
                },
            },
            agent: siem_core::AgentAlertInfo {
                id: self.agent_id.clone(),
                name: self.agent_name.clone(),
                ip: self.agent_ip.clone(),
            },
            manager: Some(siem_core::ManagerAlertInfo {
                name: "wazuh-manager-rust".to_string(),
            }),
            decoder: None,
            full_log: self.full_log.clone(),
            decoded: siem_core::DecodedFields {
                decoder_name: String::new(),
                src_ip: if !self.src_ip.is_empty() { Some(self.src_ip.clone()) } else { None },
                dst_ip: if !self.dst_ip.is_empty() { Some(self.dst_ip.clone()) } else { None },
                src_port: None,
                dst_port: None,
                user: if !self.user.is_empty() { Some(self.user.clone()) } else { None },
                program_name: None,
                process_id: None,
                file_path: None,
                action: None,
                status: None,
                extra: std::collections::HashMap::new(),
            },
            location: self.location.clone(),
            data: std::collections::HashMap::new(),
        }
    }
}

impl ClickHouseEventRow {
    pub fn to_raw_event(&self) -> RawEvent {
        let meta: std::collections::HashMap<String, String> =
            serde_json::from_str(&self.raw_metadata).unwrap_or_default();
        let src = match self.source.as_str() {
            "syslog" => siem_core::EventSource::Syslog,
            "windows_event" => siem_core::EventSource::WindowsEvent,
            "fim" => siem_core::EventSource::Fim,
            "registry" => siem_core::EventSource::Registry,
            "syscollector" => siem_core::EventSource::Syscollector,
            "sca" => siem_core::EventSource::Sca,
            "auth" => siem_core::EventSource::Auth,
            "network" => siem_core::EventSource::Network,
            "active_response" => siem_core::EventSource::ActiveResponse,
            other => siem_core::EventSource::Custom(other.to_string()),
        };
        RawEvent {
            id: uuid::Uuid::parse_str(&self.id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
            timestamp: chrono::DateTime::from_timestamp_millis(self.timestamp as i64).unwrap_or_else(chrono::Utc::now),
            agent_id: self.agent_id.clone(),
            source: src,
            location: self.location.clone(),
            message: self.message.clone(),
            metadata: meta,
        }
    }
}

/// The SOAR tables of the NDR schema (ndr/config/clickhouse/init.sql), created
/// in `ndr` and in each tenant database when missing (a SIEM-only install, or a
/// tenant provisioned here: the replicated `ndr.soar_*` cannot be cloned with `AS`).
pub const SOAR_DDL: [&str; 5] = [
    "CREATE TABLE IF NOT EXISTS soar_integrations (id String, name String, type String, config String, enabled UInt8 DEFAULT 1, tenant_id String DEFAULT 'default', created_at DateTime DEFAULT now()) ENGINE = ReplacingMergeTree(created_at) ORDER BY id",
    "CREATE TABLE IF NOT EXISTS soar_native_playbooks (id String DEFAULT toString(generateUUIDv4()), name String, description String DEFAULT '', enabled UInt8 DEFAULT 1, cond_field String, cond_op String, cond_value String, action_type String, action_config String, run_count UInt64 DEFAULT 0, last_run Nullable(DateTime), created_at DateTime DEFAULT now(), updated_at DateTime DEFAULT now(), tenant_id String DEFAULT 'default') ENGINE = ReplacingMergeTree(updated_at) ORDER BY (tenant_id, id)",
    "CREATE TABLE IF NOT EXISTS soar_playbook_runs (id String DEFAULT toString(generateUUIDv4()), playbook_id String, playbook_name String, hit_id String, status String, detail String, created_at DateTime DEFAULT now(), tenant_id String DEFAULT 'default') ENGINE = MergeTree ORDER BY (tenant_id, created_at) TTL created_at + INTERVAL 90 DAY",
    "CREATE TABLE IF NOT EXISTS soar_cases (id String DEFAULT toString(generateUUIDv4()), case_number String DEFAULT '', priority String DEFAULT 'P2', title String, description String DEFAULT '', severity String DEFAULT 'MEDIUM', status String DEFAULT 'New', assigned_to String DEFAULT '', src_ip String DEFAULT '', dst_ip String DEFAULT '', community_id String DEFAULT '', hit_ids Array(String) DEFAULT [], tags Array(String) DEFAULT [], created_at DateTime DEFAULT now(), updated_at DateTime DEFAULT now(), closed_at Nullable(DateTime), tenant_id String DEFAULT 'default') ENGINE = ReplacingMergeTree(updated_at) ORDER BY (tenant_id, created_at)",
    "CREATE TABLE IF NOT EXISTS soar_case_comments (id String DEFAULT toString(generateUUIDv4()), case_id String, author String, comment String, created_at DateTime DEFAULT now(), tenant_id String DEFAULT 'default') ENGINE = MergeTree ORDER BY (tenant_id, case_id, created_at) TTL created_at + INTERVAL 730 DAY",
];

/// The SIEM analyst features' tables (one JSON document per row; a new
/// `version` replaces a row): suppressions, triage state, retrospective scans,
/// and the threat prediction history.
pub const ANALYST_DDL: [&str; 18] = [
    crate::decisions::DDL,
    crate::case_ai::DDL,
    crate::intel::WATCHLIST_DDL,
    crate::response::DDL[0],
    crate::response::DDL[1],
    "CREATE TABLE IF NOT EXISTS siem_swarm_matches (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
    crate::org_memory::DDL,
    // each agent's latest system inventory (os, hardware, packages, ports, processes...)
    "CREATE TABLE IF NOT EXISTS siem_agent_inventory (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
    // each agent's CIS / SCA results and FIM file list (posture_store.rs)
    crate::posture_store::DDL[0],
    crate::posture_store::DDL[1],
    crate::posture_store::DDL[2],
    crate::posture_store::DDL[3],
    "CREATE TABLE IF NOT EXISTS siem_yara_rules (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
    // what analysts do on the triage / suppression pages (siem-analyst-insight), 30 days
    "CREATE TABLE IF NOT EXISTS siem_analyst_actions (ts UInt64, user String, action LowCardinality(String), rec_id String, verdict LowCardinality(String), source LowCardinality(String), confidence UInt8) ENGINE = MergeTree ORDER BY (user, ts) TTL toDateTime(ts) + INTERVAL 30 DAY",
    "CREATE TABLE IF NOT EXISTS siem_suppressions (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
    "CREATE TABLE IF NOT EXISTS siem_analyst_state (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
    "CREATE TABLE IF NOT EXISTS siem_retro_scans (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id",
    "CREATE TABLE IF NOT EXISTS siem_threat_predictions (id String, attack_type String, doc String, predicted_at DateTime DEFAULT now()) ENGINE = MergeTree ORDER BY predicted_at TTL predicted_at + INTERVAL 90 DAY",
];

/// A Replicated* table whose Keeper metadata is gone (Keeper started over, as on
/// 2026-10-20) stays read-only for good: every insert fails. Its data is still on
/// disk, and `SYSTEM RESTORE REPLICA` rebuilds the metadata from it. Only tried
/// while Keeper is connected; on a table whose metadata exists it just fails.
pub async fn restore_lost_replicas(root: &Client) -> Vec<String> {
    let connected = root.query("SELECT count() FROM system.zookeeper_connection").fetch_one::<u64>().await.unwrap_or(0) > 0;
    if !connected {
        return Vec::new();
    }
    let readonly = root.query("SELECT database, table FROM system.replicas WHERE is_readonly").fetch_all::<(String, String)>().await.unwrap_or_default();
    let mut restored = Vec::new();
    for (db, table) in readonly {
        let name = format!("`{}`.`{}`", db.replace('`', ""), table.replace('`', ""));
        match root.query(&format!("SYSTEM RESTORE REPLICA {name}")).execute().await {
            Ok(()) => {
                warn!("{name} had lost its Keeper metadata (read-only); restored from the data on disk");
                restored.push(format!("{db}.{table}"));
            }
            Err(e) => warn!("{name} is read-only and could not be restored: {e}"),
        }
    }
    restored
}

/// The tables the per-tenant documents live in (never user input).
#[derive(Clone, Copy)]
pub enum DocTable {
    Suppressions,
    AnalystState,
    RetroScans,
    /// id = agent id
    Inventory,
    /// Alerts that other organisations reported too (swarm.rs)
    SwarmMatches,
    /// The hash-chained decision records (decisions.rs)
    Decisions,
    /// IP blocks and host isolations (response.rs)
    Blocks,
    Isolations,
    /// The tenant's own threat indicators (intel.rs)
    Watchlist,
    /// The investigation of each SOAR case (case_ai.rs), id = case id
    CaseInvestigations,
    /// The YARA rule set the agents get (yara_edr.rs), id "current", default tenant
    YaraRules,
}

impl DocTable {
    fn name(self) -> &'static str {
        match self {
            DocTable::Suppressions => "siem_suppressions",
            DocTable::AnalystState => "siem_analyst_state",
            DocTable::RetroScans => "siem_retro_scans",
            DocTable::Inventory => "siem_agent_inventory",
            DocTable::SwarmMatches => "siem_swarm_matches",
            DocTable::Decisions => "siem_decisions",
            DocTable::Blocks => "siem_blocks",
            DocTable::Isolations => "siem_isolations",
            DocTable::Watchlist => "siem_intel_watchlist",
            DocTable::CaseInvestigations => "siem_case_investigations",
            DocTable::YaraRules => "siem_yara_rules",
        }
    }
}

#[derive(Clone)]
pub struct ClickHouseDb {
    client: Client,
    /// Client without a default database (`db.table` names, DDL).
    root: Client,
    is_available: Arc<AtomicBool>,
}

/// The statements of a ClickHouse SQL script: `--` comments dropped, split
/// on `;` outside string literals.
fn sql_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = false;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if quote {
            cur.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == '\'' {
                quote = false;
            }
        } else if c == '\'' {
            quote = true;
            cur.push(c);
        } else if c == '-' && chars.peek() == Some(&'-') {
            while chars.peek().is_some_and(|&n| n != '\n') {
                chars.next();
            }
        } else if c == ';' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// The global `ndr` schema of the NDR install (`<INSTALL_DIR>/config/clickhouse/init.sql`,
/// which the ClickHouse container only loads on a fresh volume): auth-service reads
/// `ndr.settings`, `ndr.announcements`, ... from it. Idempotent (IF NOT EXISTS).
async fn apply_ndr_init_sql(root: &Client) {
    let dir = std::env::var("INSTALL_DIR").unwrap_or_else(|_| ".".into());
    let paths = [format!("{dir}/config/clickhouse/init.sql"), "./config/clickhouse/init.sql".into(), "../../ndr/config/clickhouse/init.sql".into()];
    let Some((path, sql)) = paths.iter().find_map(|p| std::fs::read_to_string(p).ok().map(|s| (p.clone(), s))) else {
        warn!("NDR init.sql not found (INSTALL_DIR={dir}); global ndr tables such as ndr.settings may be missing");
        return;
    };
    let (mut ok, mut failed) = (0, 0);
    for stmt in sql_statements(&sql) {
        match root.query(&stmt).execute().await {
            Ok(_) => ok += 1,
            Err(e) => {
                failed += 1;
                warn!("init.sql statement failed: {}: {e}", stmt.lines().next().unwrap_or(""));
            }
        }
    }
    info!("Global ndr schema from {path}: {ok} statements applied, {failed} failed");
}

impl ClickHouseDb {
    pub async fn init() -> Self {
        let url = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into());
        let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into());
        let password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
        let database = std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "ndr".into());

        info!("Initializing ClickHouse connection: url={}, database={}", url, database);

        let mut root_client = Client::default()
            .with_url(&url)
            .with_user(&user)
            .with_compression(clickhouse::Compression::None);

        if !password.is_empty() {
            root_client = root_client.with_password(&password);
        }

        let is_available = Arc::new(AtomicBool::new(false));

        // Attempt to create database if it doesn't exist
        match root_client.query(&format!("CREATE DATABASE IF NOT EXISTS {}", database)).execute().await {
            Ok(_) => {
                info!("Database '{}' verified on ClickHouse", database);
            }
            Err(e) => {
                warn!("ClickHouse is not currently reachable at {}: {}. Running in-memory mode until ClickHouse becomes available.", url, e);
                return Self {
                    client: root_client.clone().with_database(database),
                    root: root_client,
                    is_available,
                };
            }
        };

        if database == "ndr" {
            apply_ndr_init_sql(&root_client).await;
        }

        // Ensure global ndr.tenants table schema has ai_enabled and updated_at columns
        let _ = root_client.query("ALTER TABLE ndr.tenants ADD COLUMN IF NOT EXISTS ai_enabled UInt8 DEFAULT 1").execute().await;
        let _ = root_client.query("ALTER TABLE ndr.tenants ADD COLUMN IF NOT EXISTS updated_at DateTime DEFAULT now()").execute().await;

        let client = root_client.clone().with_database(&database);

        // Create siem_events table
        let create_events_sql = r#"
            CREATE TABLE IF NOT EXISTS siem_events (
                id String,
                timestamp UInt64,
                agent_id LowCardinality(String),
                source LowCardinality(String),
                location String,
                message String,
                raw_metadata String
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, agent_id);
        "#;

        // Create siem_alerts table
        let create_alerts_sql = r#"
            CREATE TABLE IF NOT EXISTS siem_alerts (
                id String,
                timestamp UInt64,
                agent_id LowCardinality(String),
                agent_name LowCardinality(String),
                agent_ip String,
                rule_id UInt32,
                rule_level UInt8,
                rule_description String,
                mitre_id LowCardinality(String),
                mitre_tactic LowCardinality(String),
                mitre_technique LowCardinality(String),
                full_log String,
                src_ip String,
                dst_ip String,
                user String,
                location String
            ) ENGINE = MergeTree()
            ORDER BY (rule_level, timestamp);
        "#;

        if let Err(e) = client.query(create_events_sql).execute().await {
            error!("Failed to create siem_events table: {}", e);
            return Self { client, root: root_client, is_available };
        }

        if let Err(e) = client.query(create_alerts_sql).execute().await {
            error!("Failed to create siem_alerts table: {}", e);
            return Self { client, root: root_client, is_available };
        }

        // Create xdr_incidents table for cross-source NDR + SIEM correlation
        let create_incidents_sql = r#"
            CREATE TABLE IF NOT EXISTS xdr_incidents (
                incident_id String,
                timestamp UInt64,
                title String,
                severity LowCardinality(String),
                host_ip String,
                agent_id LowCardinality(String),
                agent_name LowCardinality(String),
                attacker_ip String,
                ndr_threat_id String,
                siem_alert_id String,
                ndr_signature String,
                siem_rule_description String,
                status LowCardinality(String)
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, host_ip);
        "#;
        let _ = client.query(create_incidents_sql).execute().await;

        // SIEM threat-intel feed IOCs (NDR keeps its own `threat_intel` table in `ndr`)
        let create_threat_intel_sql = r#"
            CREATE TABLE IF NOT EXISTS siem_threat_intel (
                id String,
                source LowCardinality(String),
                attack_type LowCardinality(String),
                severity LowCardinality(String),
                ioc_type LowCardinality(String),
                ioc_value String,
                description String,
                threat_pattern String
            ) ENGINE = ReplacingMergeTree()
            ORDER BY (ioc_type, ioc_value);
        "#;
        let _ = client.query(create_threat_intel_sql).execute().await;

        // Remaining SIEM data tables: every tenant database gets a copy of them.
        // active responses, vulnerability detections, queued agent commands
        crate::persist::ensure_tables(&root_client, &database).await;
        let create_flows_sql = r#"
            CREATE TABLE IF NOT EXISTS ndr_network_flows (
                id UUID DEFAULT generateUUIDv4(),
                timestamp DateTime64(3, 'UTC'),
                proto LowCardinality(String),
                src_ip String,
                src_port UInt16,
                dst_ip String,
                dst_port UInt16,
                bytes_in UInt64,
                bytes_out UInt64,
                duration_ms UInt32,
                service LowCardinality(String),
                app_proto LowCardinality(String)
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (timestamp, src_ip, dst_ip)
            TTL toDateTime(timestamp) + INTERVAL 30 DAY;
        "#;
        let _ = client.query(create_flows_sql).execute().await;
        let create_threats_sql = r#"
            CREATE TABLE IF NOT EXISTS ndr_threats (
                id UUID DEFAULT generateUUIDv4(),
                timestamp DateTime64(3, 'UTC'),
                signature String,
                category LowCardinality(String),
                severity UInt8,
                src_ip String,
                dst_ip String,
                dst_port UInt16,
                proto LowCardinality(String),
                mitre_id LowCardinality(String),
                payload_snippet String CODEC(ZSTD)
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (severity, timestamp, src_ip)
            TTL toDateTime(timestamp) + INTERVAL 180 DAY;
        "#;
        let _ = client.query(create_threats_sql).execute().await;

        // Create siem_agents table for persistent agent storage in ClickHouse
        let create_agents_sql = r#"
            CREATE TABLE IF NOT EXISTS siem_agents (
                id String,
                tenant_id LowCardinality(String),
                name String,
                ip String,
                os String,
                version String,
                status LowCardinality(String),
                last_keepalive UInt64,
                os_type LowCardinality(String)
            ) ENGINE = ReplacingMergeTree(last_keepalive)
            ORDER BY (id);
        "#;
        let _ = client.query(create_agents_sql).execute().await;

        // Create tenant_agent_keys table for persistent tenant key mapping in ClickHouse
        let create_keys_sql = r#"
            CREATE TABLE IF NOT EXISTS tenant_agent_keys (
                tenant_id LowCardinality(String),
                agent_key String,
                created_at UInt64
            ) ENGINE = ReplacingMergeTree()
            ORDER BY (tenant_id);
        "#;
        let _ = client.query(create_keys_sql).execute().await;

        // Global agent registry: every enrolled agent of every tenant. Ids are
        // unique across tenants and never reused (deleted agents keep their row
        // with deleted = 1).
        let create_registry_sql = r#"
            CREATE TABLE IF NOT EXISTS agent_registry (
                agent_id String,
                name String,
                tenant_id LowCardinality(String),
                groups String,
                os_type LowCardinality(String),
                deleted UInt8,
                enrolled_at UInt64,
                updated_at UInt64
            ) ENGINE = ReplacingMergeTree(updated_at)
            ORDER BY (agent_id);
        "#;
        let _ = client.query(create_registry_sql).execute().await;
        // Deactivated agents keep their row (disabled = 1) and stop reporting.
        let _ = client
            .query("ALTER TABLE agent_registry ADD COLUMN IF NOT EXISTS disabled UInt8 DEFAULT 0")
            .execute()
            .await;

        for sql in SOAR_DDL.iter().chain(ANALYST_DDL.iter()).chain(ALERT_COLUMNS.iter()) {
            if let Err(e) = client.query(sql).execute().await {
                warn!("SOAR table not created: {e}");
            }
        }

        info!("SIEM tables ready in '{}' (siem_events, siem_alerts, siem_agents, xdr_incidents, siem_threat_intel, agent_registry, tenant_agent_keys, soar_*)", database);
        restore_lost_replicas(&root_client).await;
        is_available.store(true, Ordering::SeqCst);

        Self {
            client,
            root: root_client,
            is_available,
        }
    }

    /// Client bound to a tenant's database (`ndr` for the default tenant).
    pub fn tenant_client(&self, tenant_id: &str) -> Client {
        self.root.clone().with_database(crate::tenancy::tenant_db_name(tenant_id))
    }

    /// Stores a document (a new version replaces the row with the same id).
    pub async fn put_doc(&self, tenant_id: &str, t: DocTable, id: &str, doc: &str) -> Result<(), String> {
        let version = chrono::Utc::now().timestamp_micros().max(0) as u64;
        self.tenant_client(tenant_id)
            .query(&format!("INSERT INTO {} (id, doc, version) VALUES (?, ?, ?)", t.name()))
            .bind(id)
            .bind(doc)
            .bind(version)
            .execute()
            .await
            .map_err(|e| e.to_string())
    }

    /// The latest version of every document, newest first.
    pub async fn docs(&self, tenant_id: &str, t: DocTable, limit: u32) -> Result<Vec<String>, String> {
        self.tenant_client(tenant_id)
            .query(&format!("SELECT doc FROM {} FINAL ORDER BY version DESC LIMIT {limit}", t.name()))
            .fetch_all::<String>()
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn doc(&self, tenant_id: &str, t: DocTable, id: &str) -> Result<Option<String>, String> {
        let rows = self
            .tenant_client(tenant_id)
            .query(&format!("SELECT doc FROM {} FINAL WHERE id = ? LIMIT 1", t.name()))
            .bind(id)
            .fetch_all::<String>()
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows.into_iter().next())
    }

    pub async fn delete_doc(&self, tenant_id: &str, t: DocTable, id: &str) -> Result<(), String> {
        self.tenant_client(tenant_id)
            .query(&format!("ALTER TABLE {} DELETE WHERE id = ? SETTINGS mutations_sync = 1", t.name()))
            .bind(id)
            .execute()
            .await
            .map_err(|e| e.to_string())
    }

    /// Creates the tenant's database and its data tables (cloned from
    /// `ndr`), like the NDR tenant provisioning.
    pub async fn provision_tenant_db(&self, tenant_id: &str) -> Result<String, String> {
        if !self.is_connected() {
            return Err("ClickHouse is not available".into());
        }
        let db = crate::tenancy::tenant_db_name(tenant_id);
        if db == crate::tenancy::DEFAULT_DB {
            return Ok(db);
        }
        self.root
            .query(&format!("CREATE DATABASE IF NOT EXISTS `{db}`"))
            .execute()
            .await
            .map_err(|e| format!("CREATE DATABASE {db}: {e}"))?;
        for t in crate::tenancy::TENANT_TABLES {
            let r = self
                .root
                .query(&format!(
                    "CREATE TABLE IF NOT EXISTS `{db}`.`{t}` AS `{}`.`{t}`",
                    crate::tenancy::DEFAULT_DB
                ))
                .execute()
                .await;
            if let Err(e) = r {
                // siem_events / siem_alerts / xdr_incidents always exist (created
                // at startup); the NDR tables only when init.sql was loaded.
                if matches!(*t, "siem_events" | "siem_alerts" | "xdr_incidents") {
                    return Err(format!("CREATE TABLE {db}.{t}: {e}"));
                }
                warn!("Skipping {}.{}: {}", db, t, e);
            }
        }
        let tc = self.tenant_client(tenant_id);
        for sql in SOAR_DDL.iter().chain(ANALYST_DDL.iter()).chain(ALERT_COLUMNS.iter()) {
            if let Err(e) = tc.query(sql).execute().await {
                warn!("SOAR table not created in {db}: {e}");
            }
        }
        tracing::debug!("Provisioned tenant database '{}' ({} tables)", db, crate::tenancy::TENANT_TABLES.len());
        Ok(db)
    }

    /// Client without a default database (fully qualified table names).
    pub fn root(&self) -> &Client {
        &self.root
    }

    pub fn is_connected(&self) -> bool {
        self.is_available.load(Ordering::SeqCst)
    }

    pub async fn insert_event(&self, event: &RawEvent) {
        self.insert_events(std::slice::from_ref(event)).await;
    }

    /// One INSERT per tenant for the whole batch (ClickHouse makes a part per insert).
    /// The tenants whose rows could not be written (empty when ClickHouse is not in use).
    pub async fn insert_events(&self, events: &[RawEvent]) -> Vec<String> {
        let mut failed = Vec::new();
        if !self.is_connected() {
            return failed;
        }
        let mut by_tenant: std::collections::BTreeMap<&str, Vec<ClickHouseEventRow>> = std::collections::BTreeMap::new();
        for event in events {
            let source_str = serde_json::to_string(&event.source).unwrap_or_default().trim_matches('"').to_string();
            let row = ClickHouseEventRow {
                id: event.id.to_string(),
                timestamp: event.timestamp.timestamp_millis() as u64,
                agent_id: event.agent_id.clone(),
                source: source_str,
                location: event.location.clone(),
                message: event.message.clone(),
                raw_metadata: serde_json::to_string(&event.metadata).unwrap_or_default(),
            };
            let tenant = event.metadata.get("tenant_id").map(|s| s.as_str()).unwrap_or(crate::tenancy::DEFAULT_TENANT);
            by_tenant.entry(tenant).or_default().push(row);
        }
        for (tenant, rows) in by_tenant {
            let client = self.tenant_client(tenant);
            let mut insert = match client.insert("siem_events") {
                Ok(ins) => ins,
                Err(e) => {
                    warn!("ClickHouse insert handle error: {}", e);
                    failed.push(tenant.to_string());
                    continue;
                }
            };
            let mut ok = true;
            for row in &rows {
                if let Err(e) = insert.write(row).await {
                    warn!("Failed to stream event to ClickHouse: {}", e);
                    ok = false;
                    break;
                }
            }
            if ok {
                if let Err(e) = insert.end().await {
                    warn!("Failed to commit event to ClickHouse: {}", e);
                    ok = false;
                }
            }
            if !ok {
                failed.push(tenant.to_string());
            }
        }
        failed
    }

    /// false when ClickHouse is in use and the row could not be written.
    pub async fn insert_alert(&self, alert: &Alert) -> bool {
        self.insert_alerts(std::slice::from_ref(alert)).await.is_empty()
    }

    /// One INSERT per tenant for the whole batch. The tenants whose rows
    /// could not be written (empty when ClickHouse is not in use).
    pub async fn insert_alerts(&self, alerts: &[Alert]) -> Vec<String> {
        let mut failed = Vec::new();
        if !self.is_connected() {
            return failed;
        }
        let mut by_tenant: std::collections::BTreeMap<String, Vec<ClickHouseAlertRow>> = std::collections::BTreeMap::new();
        for alert in alerts {
            let tenant = alert.data.get("tenant_id").and_then(|v| v.as_str()).unwrap_or(crate::tenancy::DEFAULT_TENANT).to_string();
            by_tenant.entry(tenant).or_default().push(Self::alert_row(alert));
        }
        for (tenant, rows) in by_tenant {
            let client = self.tenant_client(&tenant);
            let mut insert = match client.insert("siem_alerts") {
                Ok(ins) => ins,
                Err(e) => {
                    warn!("ClickHouse insert handle error: {}", e);
                    failed.push(tenant);
                    continue;
                }
            };
            let mut ok = true;
            for row in &rows {
                if let Err(e) = insert.write(row).await {
                    warn!("Failed to stream alert to ClickHouse: {}", e);
                    ok = false;
                    break;
                }
            }
            if ok {
                if let Err(e) = insert.end().await {
                    warn!("Failed to commit alert to ClickHouse: {}", e);
                    ok = false;
                }
            }
            if !ok {
                failed.push(tenant);
            }
        }
        failed
    }

    fn alert_row(alert: &Alert) -> ClickHouseAlertRow {
        ClickHouseAlertRow {
            id: alert.id.to_string(),
            timestamp: alert.timestamp.timestamp_millis() as u64,
            agent_id: alert.agent.id.clone(),
            agent_name: alert.agent.name.clone(),
            agent_ip: alert.agent.ip.clone(),
            rule_id: alert.rule.id,
            rule_level: alert.rule.level,
            rule_description: alert.rule.description.clone(),
            mitre_id: alert.rule.mitre.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
            mitre_tactic: alert.rule.mitre.as_ref().map(|m| m.tactic.clone()).unwrap_or_default(),
            mitre_technique: alert.rule.mitre.as_ref().map(|m| m.technique.clone()).unwrap_or_default(),
            full_log: alert.full_log.clone(),
            src_ip: alert.decoded.src_ip.clone().unwrap_or_default(),
            dst_ip: alert.decoded.dst_ip.clone().unwrap_or_default(),
            user: alert.decoded.user.clone().unwrap_or_default(),
            location: alert.location.clone(),
            alert_json: serde_json::to_string(alert).unwrap_or_default(),
        }
    }

    /// A tenant's alerts since `since_ms` (newest first, at most `limit`): the
    /// history the dashboard, MITRE, compliance, FIM and report pages read.
    pub async fn alerts_since(&self, tenant_id: &str, since_ms: u64, limit: usize) -> Option<Vec<Alert>> {
        if !self.is_connected() {
            return None;
        }
        match self
            .tenant_client(tenant_id)
            .query("SELECT ?fields FROM siem_alerts WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?")
            .bind(since_ms)
            .bind(limit as u64)
            .fetch_all::<ClickHouseAlertRow>()
            .await
        {
            Ok(rows) => Some(rows.iter().map(|r| r.to_alert()).collect()),
            Err(e) => {
                warn!("Failed to query alerts from ClickHouse: {}", e);
                None
            }
        }
    }

    /// A tenant's alerts since `since_ms` whose stored alert contains `needle` (ClickHouse
    /// filters them, so only those rows are sent), newest first, at most `limit`.
    pub async fn alerts_since_containing(&self, tenant_id: &str, since_ms: u64, limit: usize, needle: &str) -> Option<Vec<Alert>> {
        if !self.is_connected() {
            return None;
        }
        self.tenant_client(tenant_id)
            .query("SELECT ?fields FROM siem_alerts WHERE timestamp >= ? AND position(alert_json, ?) > 0 ORDER BY timestamp DESC LIMIT ?")
            .bind(since_ms)
            .bind(needle)
            .bind(limit as u64)
            .fetch_all::<ClickHouseAlertRow>()
            .await
            .map_err(|e| warn!("Failed to query alerts from ClickHouse: {}", e))
            .ok()
            .map(|rows| rows.iter().map(|r| r.to_alert()).collect())
    }

    /// Counts of a tenant's window, computed by ClickHouse (no rows are sent).
    pub async fn window_counts(&self, tenant_id: &str, since_ms: u64, hour_ago_ms: u64) -> Option<WindowCounts> {
        if !self.is_connected() {
            return None;
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Ev {
            events: u64,
            events_1h: u64,
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Level {
            level: u8,
            n: u64,
            n_1h: u64,
        }
        let c = self.tenant_client(tenant_id);
        let ev = c
            .query("SELECT count() AS events, countIf(timestamp >= ?) AS events_1h FROM siem_events WHERE timestamp >= ?")
            .bind(hour_ago_ms)
            .bind(since_ms)
            .fetch_one::<Ev>();
        let al = c
            .query("SELECT rule_level AS level, count() AS n, countIf(timestamp >= ?) AS n_1h FROM siem_alerts WHERE timestamp >= ? GROUP BY rule_level")
            .bind(hour_ago_ms)
            .bind(since_ms)
            .fetch_all::<Level>();
        match tokio::join!(ev, al) {
            (Ok(e), Ok(levels)) => {
                let mut w = WindowCounts { events: e.events, events_1h: e.events_1h, ..Default::default() };
                for l in levels {
                    w.levels[l.level.min(16) as usize] += l.n;
                    w.alerts_1h += l.n_1h;
                }
                Some(w)
            }
            (Err(e), _) | (_, Err(e)) => {
                warn!("Failed to count events/alerts in ClickHouse: {}", e);
                None
            }
        }
    }

    /// Alerts per (rule id, description) since `since_ms`, most frequent first.
    pub async fn top_rules(&self, tenant_id: &str, since_ms: u64, limit: usize) -> Option<Vec<(u32, String, u64)>> {
        if !self.is_connected() {
            return None;
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct R {
            rule_id: u32,
            rule_description: String,
            n: u64,
        }
        self.tenant_client(tenant_id)
            .query("SELECT rule_id, rule_description, count() AS n FROM siem_alerts WHERE timestamp >= ? GROUP BY rule_id, rule_description ORDER BY n DESC LIMIT ?")
            .bind(since_ms)
            .bind(limit as u64)
            .fetch_all::<R>()
            .await
            .map_err(|e| warn!("Failed to group alerts by rule in ClickHouse: {}", e))
            .ok()
            .map(|rows| rows.into_iter().map(|r| (r.rule_id, r.rule_description, r.n)).collect())
    }

    /// Alerts per non-empty value of `field` since `since_ms`, most frequent first.
    pub async fn top_values(&self, tenant_id: &str, since_ms: u64, field: AlertField, limit: usize) -> Option<Vec<(String, u64)>> {
        if !self.is_connected() {
            return None;
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct R {
            v: String,
            n: u64,
        }
        let c = field.column();
        self.tenant_client(tenant_id)
            .query(&format!("SELECT {c} AS v, count() AS n FROM siem_alerts WHERE timestamp >= ? AND {c} != '' GROUP BY v ORDER BY n DESC LIMIT ?"))
            .bind(since_ms)
            .bind(limit as u64)
            .fetch_all::<R>()
            .await
            .map_err(|e| warn!("Failed to group alerts by {c} in ClickHouse: {}", e))
            .ok()
            .map(|rows| rows.into_iter().map(|r| (r.v, r.n)).collect())
    }

    /// Alerts per MITRE technique id since `since_ms`: (id, alerts, highest level).
    pub async fn mitre_counts(&self, tenant_id: &str, since_ms: u64) -> Option<Vec<(String, u64, u8)>> {
        if !self.is_connected() {
            return None;
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct R {
            mitre_id: String,
            n: u64,
            max_level: u8,
        }
        self.tenant_client(tenant_id)
            .query("SELECT mitre_id, count() AS n, max(rule_level) AS max_level FROM siem_alerts WHERE timestamp >= ? AND mitre_id != '' GROUP BY mitre_id")
            .bind(since_ms)
            .fetch_all::<R>()
            .await
            .map_err(|e| warn!("Failed to group alerts by MITRE technique in ClickHouse: {}", e))
            .ok()
            .map(|rows| rows.into_iter().map(|r| (r.mitre_id, r.n, r.max_level)).collect())
    }

    /// Events since `since_ms` per protocol (most frequent first), and how many came from network sensors.
    pub async fn event_breakdown(&self, tenant_id: &str, since_ms: u64) -> Option<(Vec<(String, u64)>, u64)> {
        if !self.is_connected() {
            return None;
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct R {
            proto: String,
            n: u64,
            network: u64,
        }
        let q = format!("SELECT {PROTOCOL_SQL} AS proto, count() AS n, countIf({NETWORK_SQL}) AS network FROM siem_events WHERE timestamp >= ? GROUP BY proto ORDER BY n DESC");
        self.tenant_client(tenant_id)
            .query(&q)
            .bind(since_ms)
            .fetch_all::<R>()
            .await
            .map_err(|e| warn!("Failed to group events by protocol in ClickHouse: {}", e))
            .ok()
            .map(|rows| {
                let network = rows.iter().map(|r| r.network).sum();
                (rows.into_iter().map(|r| (r.proto, r.n)).collect(), network)
            })
    }

    /// Alerts in `buckets` time slices of `bucket_ms` ending at `now_ms`, oldest first:
    /// [critical 12+, high 8-11, medium 4-7, low 0-3] per slice.
    pub async fn alert_buckets(&self, tenant_id: &str, now_ms: u64, bucket_ms: u64, buckets: usize) -> Option<Vec<[u64; 4]>> {
        if !self.is_connected() {
            return None;
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct R {
            ago: u64,
            critical: u64,
            high: u64,
            medium: u64,
            low: u64,
        }
        let since = now_ms.saturating_sub(bucket_ms * buckets as u64);
        let rows = self
            .tenant_client(tenant_id)
            .query(
                "SELECT intDiv(? - timestamp, ?) AS ago, countIf(rule_level >= 12) AS critical, countIf(rule_level BETWEEN 8 AND 11) AS high, \
                 countIf(rule_level BETWEEN 4 AND 7) AS medium, countIf(rule_level <= 3) AS low \
                 FROM siem_alerts WHERE timestamp > ? AND timestamp <= ? GROUP BY ago",
            )
            .bind(now_ms)
            .bind(bucket_ms.max(1))
            .bind(since)
            .bind(now_ms)
            .fetch_all::<R>()
            .await
            .map_err(|e| warn!("Failed to bucket alerts in ClickHouse: {}", e))
            .ok()?;
        let mut out = vec![[0u64; 4]; buckets];
        for r in rows {
            if let Some(slot) = (r.ago as usize).checked_add(1).and_then(|a| buckets.checked_sub(a)) {
                out[slot] = [r.critical, r.high, r.medium, r.low];
            }
        }
        Some(out)
    }

    /// Events in `buckets` time slices of `bucket_ms` ending at `now_ms`, oldest first.
    pub async fn event_buckets(&self, tenant_id: &str, now_ms: u64, bucket_ms: u64, buckets: usize) -> Option<Vec<u64>> {
        if !self.is_connected() {
            return None;
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct R {
            ago: u64,
            n: u64,
        }
        let since = now_ms.saturating_sub(bucket_ms * buckets as u64);
        let rows = self
            .tenant_client(tenant_id)
            .query("SELECT intDiv(? - timestamp, ?) AS ago, count() AS n FROM siem_events WHERE timestamp > ? AND timestamp <= ? GROUP BY ago")
            .bind(now_ms)
            .bind(bucket_ms.max(1))
            .bind(since)
            .bind(now_ms)
            .fetch_all::<R>()
            .await
            .map_err(|e| warn!("Failed to bucket events in ClickHouse: {}", e))
            .ok()?;
        let mut out = vec![0u64; buckets];
        for r in rows {
            if let Some(slot) = (r.ago as usize).checked_add(1).and_then(|a| buckets.checked_sub(a)) {
                out[slot] = r.n;
            }
        }
        Some(out)
    }

    /// The newest alerts since `since_ms` (newest first, at most `limit`); with `ip`, only
    /// those whose source or destination is that IP.
    pub async fn recent_alerts(&self, tenant_id: &str, since_ms: u64, limit: usize, ip: Option<&str>) -> Option<Vec<Alert>> {
        if !self.is_connected() {
            return None;
        }
        let ip = ip.unwrap_or("");
        self.tenant_client(tenant_id)
            .query("SELECT ?fields FROM siem_alerts WHERE timestamp >= ? AND (? = '' OR src_ip = ? OR dst_ip = ?) ORDER BY timestamp DESC LIMIT ?")
            .bind(since_ms)
            .bind(ip)
            .bind(ip)
            .bind(ip)
            .bind(limit as u64)
            .fetch_all::<ClickHouseAlertRow>()
            .await
            .map_err(|e| warn!("Failed to query alerts from ClickHouse: {}", e))
            .ok()
            .map(|rows| rows.iter().map(|r| r.to_alert()).collect())
    }

    /// Per compliance tag of the Wazuh rules (`pci_dss`, `hipaa`, ...): the alerts since
    /// `since_ms` that carry it and how many distinct requirements they name.
    pub async fn compliance_tag_counts(&self, tenant_id: &str, since_ms: u64, tags: &[&'static str]) -> Option<Vec<(&'static str, u64, u64)>> {
        if !self.is_connected() {
            return None;
        }
        let mut out = Vec::new();
        for &tag in tags {
            #[derive(clickhouse::Row, serde::Deserialize)]
            struct R {
                alerts: u64,
                requirements: u64,
            }
            let r = self
                .tenant_client(tenant_id)
                .query(
                    "SELECT count() AS alerts, uniqExactArray(JSONExtract(alert_json, 'data', 'wazuh_rule', ?, 'Array(String)')) AS requirements \
                     FROM siem_alerts WHERE timestamp >= ? AND JSONHas(alert_json, 'data', 'wazuh_rule', ?)",
                )
                .bind(tag)
                .bind(since_ms)
                .bind(tag)
                .fetch_one::<R>()
                .await
                .map_err(|e| warn!("Failed to count {tag} alerts in ClickHouse: {}", e))
                .ok()?;
            out.push((tag, r.alerts, r.requirements));
        }
        Some(out)
    }

    /// One event of the tenant by id.
    pub async fn event_by_id(&self, tenant_id: &str, id: &str) -> Option<siem_core::RawEvent> {
        if !self.is_connected() {
            return None;
        }
        self.tenant_client(tenant_id).query("SELECT ?fields FROM siem_events WHERE id = ? LIMIT 1").bind(id).fetch_all::<ClickHouseEventRow>().await.ok()?.first().map(|r| r.to_raw_event())
    }

    /// One alert of the tenant by id.
    pub async fn alert_by_id(&self, tenant_id: &str, id: &str) -> Option<Alert> {
        self.tenant_client(tenant_id).query("SELECT ?fields FROM siem_alerts WHERE id = ? LIMIT 1").bind(id).fetch_all::<ClickHouseAlertRow>().await.ok()?.first().map(|r| r.to_alert())
    }

    /// A tenant's events since `since_ms` (newest first, at most `limit`).
    pub async fn events_since(&self, tenant_id: &str, since_ms: u64, limit: usize) -> Option<Vec<siem_core::RawEvent>> {
        if !self.is_connected() {
            return None;
        }
        self.tenant_client(tenant_id)
            .query("SELECT ?fields FROM siem_events WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?")
            .bind(since_ms)
            .bind(limit as u64)
            .fetch_all::<ClickHouseEventRow>()
            .await
            .map_err(|e| warn!("Failed to query events from ClickHouse: {}", e))
            .ok()
            .map(|rows| rows.iter().map(|r| r.to_raw_event()).collect())
    }

    /// Totals of a tenant: (events, alerts, critical 12-15, high 8-11, medium 4-7, low 0-3).
    pub async fn tenant_totals(&self, tenant_id: &str) -> Option<(u64, u64, u64, u64, u64, u64)> {
        if !self.is_connected() {
            return None;
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Totals {
            events: u64,
            alerts: u64,
            critical: u64,
            high: u64,
            medium: u64,
            low: u64,
        }
        // a scalar subquery is Nullable: RowBinary would carry a null-flag byte
        let q = "SELECT toUInt64(ifNull((SELECT count() FROM siem_events), 0)) AS events, count() AS alerts, \
                 countIf(rule_level >= 12) AS critical, countIf(rule_level BETWEEN 8 AND 11) AS high, \
                 countIf(rule_level BETWEEN 4 AND 7) AS medium, countIf(rule_level <= 3) AS low FROM siem_alerts";
        match self.tenant_client(tenant_id).query(q).fetch_one::<Totals>().await {
            Ok(t) => Some((t.events, t.alerts, t.critical, t.high, t.medium, t.low)),
            Err(e) => {
                warn!("Failed to query totals from ClickHouse: {}", e);
                None
            }
        }
    }

    pub async fn fetch_alerts(&self, tenant_id: &str, limit: usize, min_level: u8) -> Option<Vec<ClickHouseAlertRow>> {
        if !self.is_connected() {
            return None;
        }

        let query = format!(
            "SELECT ?fields FROM siem_alerts WHERE rule_level >= {} ORDER BY timestamp DESC LIMIT {}",
            min_level, limit
        );

        match self.tenant_client(tenant_id).query(&query).fetch_all::<ClickHouseAlertRow>().await {
            Ok(rows) => Some(rows),
            Err(e) => {
                warn!("Failed to query alerts from ClickHouse: {}", e);
                None
            }
        }
    }

    pub async fn fetch_events(&self, tenant_id: &str, limit: usize) -> Option<Vec<ClickHouseEventRow>> {
        if !self.is_connected() {
            return None;
        }

        let query = format!(
            "SELECT * FROM siem_events ORDER BY timestamp DESC LIMIT {}",
            limit
        );

        match self.tenant_client(tenant_id).query(&query).fetch_all::<ClickHouseEventRow>().await {
            Ok(rows) => Some(rows),
            Err(e) => {
                warn!("Failed to query events from ClickHouse: {}", e);
                None
            }
        }
    }

    pub async fn insert_incident(&self, tenant_id: &str, inc: &ClickHouseIncidentRow) {
        if !self.is_connected() {
            return;
        }
        let mut insert = match self.tenant_client(tenant_id).insert("xdr_incidents") {
            Ok(ins) => ins,
            Err(e) => {
                warn!("ClickHouse insert handle error for xdr_incidents: {}", e);
                return;
            }
        };
        if let Err(e) = insert.write(inc).await {
            warn!("Failed to stream incident to ClickHouse: {}", e);
            return;
        }
        let _ = insert.end().await;
    }

    /// `raw_metadata` of the agent's latest syscollector event in its tenant database.
    pub async fn fetch_latest_inventory(&self, tenant_id: &str, agent_id: &str) -> Option<String> {
        if !self.is_connected() || !agent_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
            return None;
        }
        #[derive(clickhouse::Row, Deserialize)]
        struct Row {
            raw_metadata: String,
        }
        let q = format!(
            "SELECT raw_metadata FROM siem_events WHERE agent_id = '{agent_id}' AND source = 'syscollector' AND position(raw_metadata, 'inventory_json') > 0 ORDER BY timestamp DESC LIMIT 1"
        );
        self.tenant_client(tenant_id).query(&q).fetch_optional::<Row>().await.ok().flatten().map(|r| r.raw_metadata)
    }

    pub async fn fetch_incidents(&self, tenant_id: &str, limit: usize) -> Option<Vec<ClickHouseIncidentRow>> {
        if !self.is_connected() {
            return None;
        }
        let query = format!(
            "SELECT * FROM xdr_incidents ORDER BY timestamp DESC LIMIT {}",
            limit
        );
        match self.tenant_client(tenant_id).query(&query).fetch_all::<ClickHouseIncidentRow>().await {
            Ok(rows) => Some(rows),
            Err(e) => {
                warn!("Failed to query incidents from ClickHouse: {}", e);
                None
            }
        }
    }

    /// Many entries in one INSERT (one ClickHouse part); the number written.
    pub async fn insert_threat_intel_entries(&self, entries: &[provigil_common::threat_intel::ThreatIntelEntry]) -> usize {
        if entries.is_empty() || !self.is_connected() {
            return 0;
        }
        let Ok(mut insert) = self.client.insert("siem_threat_intel") else { return 0 };
        for e in entries {
            let row = ClickHouseThreatIntelRow {
                id: uuid::Uuid::new_v4().to_string(),
                source: e.source.clone(),
                attack_type: e.attack_type.clone(),
                severity: e.severity.clone(),
                ioc_type: e.ioc_type.clone(),
                ioc_value: e.ioc_value.clone(),
                description: e.description.clone(),
                threat_pattern: e.threat_pattern.clone(),
            };
            if let Err(err) = insert.write(&row).await {
                warn!("threat intel entries not stored: {err}");
                return 0;
            }
        }
        match insert.end().await {
            Ok(()) => entries.len(),
            Err(err) => {
                warn!("threat intel entries not stored: {err}");
                0
            }
        }
    }

    pub async fn insert_or_update_agent(&self, tenant_id: &str, agent: &siem_core::Agent) {
        if !self.is_connected() {
            return;
        }
        let status_str = match agent.status {
            siem_core::AgentStatus::Active => "Active",
            siem_core::AgentStatus::Disconnected => "Disconnected",
            siem_core::AgentStatus::Pending => "Pending",
        };
        let ms = agent.last_keepalive.timestamp_millis();
        let sql = format!(
            "INSERT INTO siem_agents (id, name, ip, os, version, status, last_keepalive, os_type) VALUES ('{}', '{}', '{}', '{}', '{}', '{}', fromUnixTimestamp64Milli({}), '{}')",
            agent.id.replace('\'', "''"),
            agent.name.replace('\'', "''"),
            agent.ip.replace('\'', "''"),
            agent.os.replace('\'', "''"),
            agent.version.replace('\'', "''"),
            status_str,
            ms,
            agent.os_type.replace('\'', "''"),
        );

        // Insert strictly into tenant database
        let _ = self.tenant_client(tenant_id).query(&sql).execute().await;
    }

    pub async fn fetch_agents(&self, tenant_id: &str) -> Option<Vec<ClickHouseAgentRow>> {
        if !self.is_connected() {
            return None;
        }
        let client = self.tenant_client(tenant_id);
        let query = "SELECT id, name, ip, os, version, status, toUnixTimestamp64Milli(last_keepalive) AS last_keepalive, os_type FROM siem_agents FINAL ORDER BY id";
        match client.query(query).fetch_all::<ClickHouseAgentRow>().await {
            Ok(rows) => Some(rows),
            Err(e) => {
                warn!("Failed to query agents for tenant '{}': {}", tenant_id, e);
                None
            }
        }
    }

    pub async fn delete_agent(&self, tenant_id: &str, agent_id: &str) {
        if !self.is_connected() {
            return;
        }
        let sql = format!(
            "ALTER TABLE siem_agents DELETE WHERE id = '{}'",
            agent_id.replace('\'', "''")
        );
        let _ = self.tenant_client(tenant_id).query(&sql).execute().await;
    }

    pub async fn save_tenant_agent_key(&self, tenant_id: &str, key: &str) {
        if !self.is_connected() {
            return;
        }
        let row = ClickHouseAgentKeyRow {
            tenant_id: tenant_id.to_string(),
            agent_key: key.to_string(),
            created_at: chrono::Utc::now().timestamp_millis() as u64,
        };
        if let Ok(mut insert) = self.client.insert("tenant_agent_keys") {
            if insert.write(&row).await.is_ok() {
                let _ = insert.end().await;
            }
        }
    }

    /// Writes (or replaces) an agent's registry row.
    pub async fn upsert_agent_registry(&self, row: &AgentRegistryRow) {
        if !self.is_connected() {
            return;
        }
        match self.client.insert("agent_registry") {
            Ok(mut insert) => {
                if let Err(e) = insert.write(row).await {
                    warn!("agent_registry write for {} failed: {}", row.agent_id, e);
                    return;
                }
                if let Err(e) = insert.end().await {
                    warn!("agent_registry commit for {} failed: {}", row.agent_id, e);
                }
            }
            Err(e) => warn!("agent_registry insert handle: {}", e),
        }
    }

    /// Every registry row (latest version of each agent, deleted ones included).
    pub async fn fetch_agent_registry(&self) -> Option<Vec<AgentRegistryRow>> {
        if !self.is_connected() {
            return None;
        }
        match self.client.query("SELECT ?fields FROM agent_registry FINAL").fetch_all::<AgentRegistryRow>().await {
            Ok(rows) => Some(rows),
            Err(e) => {
                warn!("Failed to load agent_registry: {}", e);
                None
            }
        }
    }

    pub async fn fetch_tenant_agent_keys(&self) -> Option<Vec<ClickHouseAgentKeyRow>> {
        if !self.is_connected() {
            return None;
        }
        match self.client.query("SELECT * FROM tenant_agent_keys FINAL").fetch_all::<ClickHouseAgentKeyRow>().await {
            Ok(rows) => Some(rows),
            Err(_) => None,
        }
    }
}

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ClickHouseAgentRow {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub os: String,
    pub version: String,
    pub status: String,
    pub last_keepalive: i64,
    pub os_type: String,
}

/// `agent_registry` row (one per enrolled agent, across all tenants).
#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct AgentRegistryRow {
    pub agent_id: String,
    pub name: String,
    pub tenant_id: String,
    pub groups: String,
    pub os_type: String,
    pub deleted: u8,
    pub enrolled_at: u64,
    pub updated_at: u64,
    /// 1 = deactivated: the agent is told to stop and its data is refused.
    pub disabled: u8,
}

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ClickHouseAgentKeyRow {
    pub tenant_id: String,
    pub agent_key: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ClickHouseThreatIntelRow {
    pub id: String,
    pub source: String,
    pub attack_type: String,
    pub severity: String,
    pub ioc_type: String,
    pub ioc_value: String,
    pub description: String,
    pub threat_pattern: String,
}

#[derive(Debug, Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ClickHouseIncidentRow {
    pub incident_id: String,
    pub timestamp: u64,
    pub title: String,
    pub severity: String,
    pub host_ip: String,
    pub agent_id: String,
    pub agent_name: String,
    pub attacker_ip: String,
    pub ndr_threat_id: String,
    pub siem_alert_id: String,
    pub ndr_signature: String,
    pub siem_rule_description: String,
    pub status: String,
}


#[cfg(test)]
mod tests {
    #[test]
    fn sql_statements_skip_comment_semicolons() {
        let s = super::sql_statements("-- a; b\nCREATE x (a String, -- c; d\n b String DEFAULT 'x;y');\nINSERT 1;");
        assert_eq!(s, vec!["CREATE x (a String, \n b String DEFAULT 'x;y')", "INSERT 1"]);
    }
}
