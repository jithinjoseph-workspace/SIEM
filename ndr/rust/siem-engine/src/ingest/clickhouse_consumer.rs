// ClickHouse consumer — reads siem-logs Kafka topic, inserts into siem_logs table
// Consumer group: siem-engine-consumers (all replicas share one group)
// → each message processed by exactly ONE replica (idempotency via Kafka + Valkey dedup)

use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer, CommitMode};
use rdkafka::Message;
use futures::StreamExt;
use tracing::{info, error, debug, warn};

use crate::ingest::{normalizer::OcsfEvent, dedup};

/// Convert ISO8601/RFC3339 timestamp to ClickHouse DateTime64 format: "YYYY-MM-DD HH:MM:SS.mmm"
fn to_ch_timestamp(ts: &str) -> String {
    // Replace T separator, strip timezone suffix (+00:00, Z, etc.)
    let s = ts.replace('T', " ");
    // Strip timezone: find + or Z after the time part
    let s = if let Some(pos) = s[10..].find(['+', 'Z']).map(|p| p + 10) {
        s[..pos].to_string()
    } else {
        s
    };
    // Ensure milliseconds — pad or truncate to 3 decimal places
    if let Some(dot) = s.find('.') {
        let decimals = &s[dot + 1..];
        if decimals.len() >= 3 {
            format!("{}.{}", &s[..dot], &decimals[..3])
        } else {
            format!("{}.{:0<3}", &s[..dot], decimals)
        }
    } else {
        format!("{}.000", s)
    }
}

pub struct ClickHouseConsumer {
    pub clickhouse_url: String,
    pub valkey_url:     String,
    pub kafka_brokers:  String,
}

impl ClickHouseConsumer {
    pub async fn run(&self) {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", "siem-engine-consumers")
            .set("bootstrap.servers", &self.kafka_brokers)
            .set("auto.offset.reset", "earliest")
            .set("enable.auto.commit", "false")   // manual commit after successful insert
            .set("session.timeout.ms", "30000")
            .set("max.poll.interval.ms", "300000")
            .create()
            .expect("Kafka StreamConsumer creation failed");

        consumer.subscribe(&["siem-logs"])
            .expect("Kafka subscribe to siem-logs failed");

        info!("ClickHouse consumer started — group=siem-engine-consumers topic=siem-logs");

        let mut stream = consumer.stream();
        while let Some(result) = stream.next().await {
            match result {
                Ok(msg) => {
                    let payload = match msg.payload() {
                        Some(p) => p,
                        None => {
                            warn!("Empty Kafka message — skipping");
                            let _ = consumer.commit_message(&msg, CommitMode::Async);
                            continue;
                        }
                    };

                    match serde_json::from_slice::<OcsfEvent>(payload) {
                        Ok(event) => {
                            // Valkey dedup — skip if this log_id was already inserted
                            if !dedup::is_new(&event.log_id, &self.valkey_url).await {
                                debug!("Dedup skip: log_id={}", event.log_id);
                                let _ = consumer.commit_message(&msg, CommitMode::Async);
                                continue;
                            }

                            match self.insert_clickhouse(&event).await {
                                Ok(_) => {
                                    // Commit offset ONLY after successful insert
                                    let _ = consumer.commit_message(&msg, CommitMode::Async);
                                }
                                Err(e) => {
                                    // Do NOT commit — Kafka will redeliver.
                                    // Unmark from Valkey so the redelivered message is not skipped.
                                    error!("CH insert failed log_id={}: {e}", event.log_id);
                                    dedup::unmark(&event.log_id, &self.valkey_url).await;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to deserialise Kafka message: {e}");
                            let _ = consumer.commit_message(&msg, CommitMode::Async);
                        }
                    }
                }
                Err(e) => error!("Kafka consume error: {e}"),
            }
        }
    }

    async fn insert_clickhouse(&self, event: &OcsfEvent) -> anyhow::Result<()> {
        let db = if event.tenant_id == "default" {
            "ndr".to_string()
        } else {
            format!("ndr_{}", event.tenant_id)
        };

        let threat_json = serde_json::to_string(&event.threat_match)
            .unwrap_or_else(|_| "{}".to_string());
        let parsed_json = serde_json::to_string(&event.parsed)
            .unwrap_or_else(|_| "{}".to_string());

        let row = serde_json::json!({
            "log_id":           event.log_id,
            "source_id":        event.source_id,
            "source_type":      event.source_type,
            "event_class":      event.event_class,
            "severity":         event.severity,
            "timestamp":        to_ch_timestamp(&event.timestamp),
            "raw_log":          event.raw_log,
            "parsed_json":      parsed_json,
            "ip_tokens":        event.ip_tokens,
            "threat_match_json":threat_json,
        });

        let query = format!(
            "INSERT INTO {db}.siem_logs \
             (log_id, source_id, source_type, event_class, severity, timestamp, \
              raw_log, parsed_json, ip_tokens, threat_match_json, ingested_at) \
             FORMAT JSONEachRow"
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(&self.clickhouse_url)
            .query(&[("query", &query)])
            .json(&row)
            .send()
            .await?;

        if resp.status().is_success() {
            info!("CH insert ok: log_id={} db={}", event.log_id, db);
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("ClickHouse error: {body}"))
        }
    }
}
