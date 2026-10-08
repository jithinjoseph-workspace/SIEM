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
    is_available: Arc<AtomicBool>,
}

impl ClickHouseDb {
    pub async fn init() -> Self {
        let url = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into());
        let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into());
        let password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
        let database = std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "wazuh_siem".into());

        info!("Initializing ClickHouse connection: url={}, database={}", url, database);

        let root_client = Client::default()
            .with_url(&url)
            .with_user(&user)
            .with_password(&password);

        let is_available = Arc::new(AtomicBool::new(false));

        // Attempt to create database if it doesn't exist
        match root_client.query(&format!("CREATE DATABASE IF NOT EXISTS {}", database)).execute().await {
            Ok(_) => {
                info!("Database '{}' verified on ClickHouse", database);
            }
            Err(e) => {
                warn!("ClickHouse is not currently reachable at {}: {}. Running in-memory mode until ClickHouse becomes available.", url, e);
                return Self {
                    client: root_client.with_database(database),
                    is_available,
                };
            }
        };

        let client = root_client.with_database(&database);

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
            return Self { client, is_available };
        }

        if let Err(e) = client.query(create_alerts_sql).execute().await {
            error!("Failed to create siem_alerts table: {}", e);
            return Self { client, is_available };
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

        info!("ClickHouse tables 'siem_events', 'siem_alerts', and 'xdr_incidents' ready");
        is_available.store(true, Ordering::SeqCst);

        Self {
            client,
            is_available,
        }
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

        let mut insert = match self.client.insert("siem_events") {
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

        let mut insert = match self.client.insert("siem_alerts") {
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

    pub async fn fetch_alerts(&self, limit: usize, min_level: u8) -> Option<Vec<ClickHouseAlertRow>> {
        if !self.is_connected() {
            return None;
        }

        let query = format!(
            "SELECT * FROM siem_alerts WHERE rule_level >= {} ORDER BY timestamp DESC LIMIT {}",
            min_level, limit
        );

        match self.client.query(&query).fetch_all::<ClickHouseAlertRow>().await {
            Ok(rows) => Some(rows),
            Err(e) => {
                warn!("Failed to query alerts from ClickHouse: {}", e);
                None
            }
        }
    }

    pub async fn fetch_events(&self, limit: usize) -> Option<Vec<ClickHouseEventRow>> {
        if !self.is_connected() {
            return None;
        }

        let query = format!(
            "SELECT * FROM siem_events ORDER BY timestamp DESC LIMIT {}",
            limit
        );

        match self.client.query(&query).fetch_all::<ClickHouseEventRow>().await {
            Ok(rows) => Some(rows),
            Err(e) => {
                warn!("Failed to query events from ClickHouse: {}", e);
                None
            }
        }
    }

    pub async fn insert_incident(&self, inc: &ClickHouseIncidentRow) {
        if !self.is_connected() {
            return;
        }
        let mut insert = match self.client.insert("xdr_incidents") {
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

    pub async fn fetch_incidents(&self, limit: usize) -> Option<Vec<ClickHouseIncidentRow>> {
        if !self.is_connected() {
            return None;
        }
        let query = format!(
            "SELECT * FROM xdr_incidents ORDER BY timestamp DESC LIMIT {}",
            limit
        );
        match self.client.query(&query).fetch_all::<ClickHouseIncidentRow>().await {
            Ok(rows) => Some(rows),
            Err(e) => {
                warn!("Failed to query incidents from ClickHouse: {}", e);
                None
            }
        }
    }
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
