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
}

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

#[derive(Clone)]
pub struct ClickHouseDb {
    client: Client,
    /// Client without a default database (`db.table` names, DDL).
    root: Client,
    is_available: Arc<AtomicBool>,
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
        let create_active_responses_sql = r#"
            CREATE TABLE IF NOT EXISTS siem_active_responses (
                id UUID DEFAULT generateUUIDv4(),
                timestamp DateTime64(3, 'UTC'),
                agent_id LowCardinality(String),
                action LowCardinality(String),
                target String,
                success UInt8,
                reverted UInt8 DEFAULT 0
            ) ENGINE = MergeTree()
            ORDER BY (timestamp, agent_id);
        "#;
        let _ = client.query(create_active_responses_sql).execute().await;
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

        info!("SIEM tables ready in '{}' (siem_events, siem_alerts, siem_agents, xdr_incidents, siem_threat_intel, agent_registry, tenant_agent_keys)", database);
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
        if !self.is_connected() {
            return;
        }

        let metadata_str = serde_json::to_string(&event.metadata).unwrap_or_default();
        let source_str = serde_json::to_string(&event.source)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();

        let row = ClickHouseEventRow {
            id: event.id.to_string(),
            timestamp: event.timestamp.timestamp_millis() as u64,
            agent_id: event.agent_id.clone(),
            source: source_str,
            location: event.location.clone(),
            message: event.message.clone(),
            raw_metadata: metadata_str,
        };

        let tenant = event.metadata.get("tenant_id").map(|s| s.as_str()).unwrap_or(crate::tenancy::DEFAULT_TENANT);
        let client = self.tenant_client(tenant);
        let mut insert = match client.insert("siem_events") {
            Ok(ins) => ins,
            Err(e) => {
                warn!("ClickHouse insert handle error: {}", e);
                return;
            }
        };

        if let Err(e) = insert.write(&row).await {
            warn!("Failed to stream event to ClickHouse: {}", e);
            return;
        }

        if let Err(e) = insert.end().await {
            warn!("Failed to commit event to ClickHouse: {}", e);
        }
    }

    pub async fn insert_alert(&self, alert: &Alert) {
        if !self.is_connected() {
            return;
        }

        let row = ClickHouseAlertRow {
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
        };

        let tenant = alert.data.get("tenant_id").and_then(|v| v.as_str()).unwrap_or(crate::tenancy::DEFAULT_TENANT);
        let client = self.tenant_client(tenant);
        let mut insert = match client.insert("siem_alerts") {
            Ok(ins) => ins,
            Err(e) => {
                warn!("ClickHouse insert handle error: {}", e);
                return;
            }
        };

        if let Err(e) = insert.write(&row).await {
            warn!("Failed to stream alert to ClickHouse: {}", e);
            return;
        }

        if let Err(e) = insert.end().await {
            warn!("Failed to commit alert to ClickHouse: {}", e);
        }
    }

    pub async fn fetch_alerts(&self, tenant_id: &str, limit: usize, min_level: u8) -> Option<Vec<ClickHouseAlertRow>> {
        if !self.is_connected() {
            return None;
        }

        let query = format!(
            "SELECT * FROM siem_alerts WHERE rule_level >= {} ORDER BY timestamp DESC LIMIT {}",
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

    pub async fn insert_threat_intel_entry(&self, entry: &provigil_common::threat_intel::ThreatIntelEntry) {
        if !self.is_connected() {
            return;
        }

        let row = ClickHouseThreatIntelRow {
            id: uuid::Uuid::new_v4().to_string(),
            source: entry.source.clone(),
            attack_type: entry.attack_type.clone(),
            severity: entry.severity.clone(),
            ioc_type: entry.ioc_type.clone(),
            ioc_value: entry.ioc_value.clone(),
            description: entry.description.clone(),
            threat_pattern: entry.threat_pattern.clone(),
        };

        if let Ok(mut insert) = self.client.insert("siem_threat_intel") {
            if insert.write(&row).await.is_ok() {
                let _ = insert.end().await;
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

