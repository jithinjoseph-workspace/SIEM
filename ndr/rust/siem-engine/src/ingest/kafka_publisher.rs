// Kafka publisher — converts OcsfEvent → SiemEvent and publishes to siem-logs topic.
// SiemEvent is the canonical Kafka format consumed by the correlation engine.
// Uses rdkafka FutureProducer with idempotent delivery (acks=all, retries=MAX)

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;
use tracing::info;
use chrono::{DateTime, Utc};

use crate::ingest::normalizer::OcsfEvent;
use crate::correlation::types::SiemEvent;

pub struct KafkaPublisher {
    producer: FutureProducer,
}

impl KafkaPublisher {
    pub fn new(brokers: &str) -> Self {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .set("retries", "2147483647")
            .set("max.in.flight.requests.per.connection", "5")
            .set("compression.type", "lz4")
            .set("linger.ms", "5")
            .set("batch.size", "65536")
            .create()
            .expect("Kafka FutureProducer creation failed");

        info!("Kafka producer connected to {brokers}");
        Self { producer }
    }

    pub async fn publish(&self, event: &OcsfEvent) -> anyhow::Result<()> {
        let siem_event = to_siem_event(event);
        let payload = serde_json::to_string(&siem_event)?;

        let record = FutureRecord::to("siem-logs")
            .key(event.tenant_id.as_str())  // same tenant → same partition → ordered
            .payload(payload.as_str());

        self.producer
            .send(record, Duration::from_secs(10))
            .await
            .map_err(|(e, _)| anyhow::anyhow!("Kafka send failed: {e}"))?;

        info!(
            "Kafka: published log_id={} tenant={} event_type={} bytes={}",
            event.log_id, event.tenant_id, event.event_class, payload.len()
        );
        Ok(())
    }
}

/// Convert OcsfEvent (ingest format) → SiemEvent (correlation format).
/// Extracts flattened fields from the nested OCSF `parsed` JSON value.
fn to_siem_event(e: &OcsfEvent) -> SiemEvent {
    let p = &e.parsed;
    let ed = p.get("event_data"); // Windows event_data object

    let str_field = |v: &serde_json::Value| -> Option<String> {
        v.as_str().map(|s| s.to_string())
    };

    // hostname: syslog → parsed["hostname"], Windows → parsed["computer"]
    let hostname = p.get("hostname").and_then(str_field)
        .or_else(|| p.get("computer").and_then(str_field));

    // username: Windows event_data TargetUserName or SubjectUserName
    let username = ed.and_then(|d| {
        d.get("TargetUserName").and_then(str_field)
            .or_else(|| d.get("SubjectUserName").and_then(str_field))
    });

    // process: Windows EventID 4688 → NewProcessName / ParentProcessName / CommandLine
    // syslog → app_name (e.g. "sshd", "sudo")
    let process_name = ed.and_then(|d| d.get("NewProcessName").and_then(str_field))
        .or_else(|| p.get("app_name").and_then(str_field))
        .or_else(|| p.get("tag").and_then(str_field));

    let parent_process = ed.and_then(|d| d.get("ParentProcessName").and_then(str_field));
    let command_line   = ed.and_then(|d| d.get("CommandLine").and_then(str_field));

    // IP tokens: pipeline sets them in order [src, dst, ...]
    let src_ip_token = e.ip_tokens.first().cloned();
    let dst_ip_token = e.ip_tokens.get(1).cloned();

    // Parse ISO8601 timestamp string → DateTime<Utc>
    let timestamp = DateTime::parse_from_rfc3339(&e.timestamp)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    SiemEvent {
        log_id:        e.log_id.clone(),
        tenant_id:     e.tenant_id.clone(),
        timestamp,
        event_type:    e.event_class.clone(),
        hostname,
        username,
        src_ip_token,
        dst_ip_token,
        src_port:      None,
        dst_port:      None,
        process_name,
        parent_process,
        command_line,
        bytes_out:     None,
        event_result:  None,
        registry_key:  None,
        service_name:  None,
        raw:           e.raw_log.clone(),
        department:    None,
        subnet:        None,
    }
}
