//! ProVigil shared types: events coming in, alerts going out, agents, rules and console
//! statistics. The JSON form of each type is stored in ClickHouse and read by the console,
//! so field names and nesting must not change.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Where an event came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Syslog,
    WindowsEvent,
    Fim,
    Registry,
    Syscollector,
    Sca,
    Auth,
    Network,
    ActiveResponse,
    Custom(String),
}

/// One received event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub source: EventSource,
    /// e.g. a log file path or channel name
    pub location: String,
    /// the original log line
    pub message: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl RawEvent {
    /// A new event with a random id, the current time and empty metadata.
    pub fn new(
        agent_id: impl Into<String>,
        source: EventSource,
        location: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent_id: agent_id.into(),
            source,
            location: location.into(),
            message: message.into(),
            metadata: HashMap::new(),
        }
    }
}

/// Fields taken out of a log line.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecodedFields {
    pub decoder_name: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub user: Option<String>,
    pub program_name: Option<String>,
    pub process_id: Option<u32>,
    pub file_path: Option<String>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttack {
    /// e.g. `T1110`
    pub id: String,
    /// e.g. `Credential Access`
    pub tactic: String,
    /// e.g. `Brute Force`
    pub technique: String,
}

/// A detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u32,
    pub level: u8,
    pub description: String,
    pub regex_pattern: String,
    pub groups: Vec<String>,
    pub mitre: Option<MitreAttack>,
}

/// The rule part of an alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAlertInfo {
    pub id: u32,
    pub level: u8,
    pub description: String,
    pub groups: Vec<String>,
    pub mitre: Option<MitreAttack>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAlertInfo {
    pub id: String,
    pub name: String,
    pub ip: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagerAlertInfo {
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecoderAlertInfo {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub rule: RuleAlertInfo,
    pub agent: AgentAlertInfo,
    #[serde(default)]
    pub manager: Option<ManagerAlertInfo>,
    #[serde(default)]
    pub decoder: Option<DecoderAlertInfo>,
    pub full_log: String,
    pub decoded: DecodedFields,
    pub location: String,
    #[serde(default)]
    pub data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Active,
    Disconnected,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub os: String,
    pub version: String,
    pub status: AgentStatus,
    pub last_keepalive: DateTime<Utc>,
    /// `linux`, `windows` or `macos`
    pub os_type: String,
}

/// Console totals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiemStats {
    pub total_events: u64,
    pub total_alerts: u64,
    /// levels 12 and up
    pub critical_alerts: u64,
    /// levels 8-11
    pub high_alerts: u64,
    /// levels 4-7
    pub medium_alerts: u64,
    /// levels 1-3
    pub low_alerts: u64,
    pub active_agents: usize,
    pub total_agents: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn sample_alert() -> Alert {
        let mut data = HashMap::new();
        data.insert("srcuser".to_string(), json!("root"));
        data.insert("count".to_string(), json!(3));
        Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            rule: RuleAlertInfo {
                id: 5710,
                level: 10,
                description: "SSH brute force".into(),
                groups: vec!["sshd".into(), "authentication_failed".into()],
                mitre: Some(MitreAttack {
                    id: "T1110".into(),
                    tactic: "Credential Access".into(),
                    technique: "Brute Force".into(),
                }),
            },
            agent: AgentAlertInfo { id: "001".into(), name: "web01".into(), ip: "10.0.0.5".into() },
            manager: Some(ManagerAlertInfo { name: "provigil".into() }),
            decoder: Some(DecoderAlertInfo { name: "sshd".into() }),
            full_log: "Failed password for root from 1.2.3.4".into(),
            decoded: DecodedFields {
                decoder_name: "sshd".into(),
                src_ip: Some("1.2.3.4".into()),
                src_port: Some(2222),
                process_id: Some(42),
                user: Some("root".into()),
                ..Default::default()
            },
            location: "/var/log/auth.log".into(),
            data,
        }
    }

    #[test]
    fn alert_round_trip_and_field_names() {
        let a = sample_alert();
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["rule"]["level"], json!(10));
        assert_eq!(v["agent"]["ip"], json!("10.0.0.5"));
        assert_eq!(v["decoded"]["src_ip"], json!("1.2.3.4"));
        assert_eq!(v["decoded"]["dst_ip"], Value::Null);
        assert_eq!(v["data"]["srcuser"], json!("root"));
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["agent", "data", "decoded", "decoder", "full_log", "id", "location", "manager", "rule", "timestamp"]
        );

        let b: Alert = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(b.id, a.id);
        assert_eq!(b.timestamp, a.timestamp);
        assert_eq!(b.rule.id, a.rule.id);
        assert_eq!(b.rule.level, a.rule.level);
        assert_eq!(b.rule.description, a.rule.description);
        assert_eq!(b.rule.groups, a.rule.groups);
        assert_eq!(b.rule.mitre.as_ref().unwrap().id, "T1110");
        assert_eq!(b.agent.ip, a.agent.ip);
        assert_eq!(b.manager.as_ref().unwrap().name, "provigil");
        assert_eq!(b.decoder.as_ref().unwrap().name, "sshd");
        assert_eq!(b.full_log, a.full_log);
        assert_eq!(b.decoded.src_ip, a.decoded.src_ip);
        assert_eq!(b.decoded.src_port, Some(2222));
        assert_eq!(b.decoded.process_id, Some(42));
        assert_eq!(b.location, a.location);
        assert_eq!(b.data, a.data);
        // and the whole thing serialises back identically
        assert_eq!(serde_json::to_value(&b).unwrap(), v);
    }

    #[test]
    fn alert_without_optional_parts() {
        let mut v = serde_json::to_value(sample_alert()).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("manager");
        obj.remove("decoder");
        obj.remove("data");
        let a: Alert = serde_json::from_value(v).unwrap();
        assert!(a.manager.is_none());
        assert!(a.decoder.is_none());
        assert!(a.data.is_empty());
    }

    #[test]
    fn event_source_json() {
        assert_eq!(serde_json::to_value(EventSource::WindowsEvent).unwrap(), json!("windows_event"));
        assert_eq!(serde_json::to_value(EventSource::ActiveResponse).unwrap(), json!("active_response"));
        assert_eq!(serde_json::to_value(EventSource::Custom("x".into())).unwrap(), json!({"custom": "x"}));
        assert_eq!(
            serde_json::from_value::<EventSource>(json!("windows_event")).unwrap(),
            EventSource::WindowsEvent
        );
        assert_eq!(
            serde_json::from_value::<EventSource>(json!({"custom": "x"})).unwrap(),
            EventSource::Custom("x".into())
        );
    }

    #[test]
    fn agent_status_lower_case() {
        assert_eq!(serde_json::to_value(AgentStatus::Active).unwrap(), json!("active"));
        assert_eq!(serde_json::to_value(AgentStatus::Disconnected).unwrap(), json!("disconnected"));
        assert_eq!(serde_json::to_value(AgentStatus::Pending).unwrap(), json!("pending"));
        assert_eq!(serde_json::from_value::<AgentStatus>(json!("pending")).unwrap(), AgentStatus::Pending);
    }

    #[test]
    fn raw_event_new_and_missing_metadata() {
        let before = Utc::now();
        let e = RawEvent::new("001", EventSource::Syslog, "/var/log/syslog", String::from("hello"));
        assert!(!e.id.is_nil());
        assert!(e.timestamp >= before && e.timestamp <= Utc::now());
        assert!(e.metadata.is_empty());
        assert_eq!(e.agent_id, "001");
        assert_ne!(RawEvent::new("001", EventSource::Fim, "x", "y").id, e.id);

        let mut v = serde_json::to_value(&e).unwrap();
        v.as_object_mut().unwrap().remove("metadata");
        let back: RawEvent = serde_json::from_value(v).unwrap();
        assert!(back.metadata.is_empty());
        assert_eq!(back.id, e.id);
        assert_eq!(back.source, EventSource::Syslog);
    }
}
