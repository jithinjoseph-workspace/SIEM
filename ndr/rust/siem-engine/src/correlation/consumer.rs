// SIEM Correlation Engine — Kafka Consumer
// Group: siem-engine-consumers
// Topic: siem-logs (published by Dev 1 ingest pipeline)
// Idempotent: Valkey offset tracking prevents duplicate processing on restart.
// Pipeline: consume → UEBA update → evaluate rules → suppression check →
//           dedup check → write/update alert in ClickHouse → SLA clock.
// License: Apache-2.0

use std::sync::Arc;
use anyhow::Result;
use clickhouse::Client;
use futures::StreamExt;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use rdkafka::config::ClientConfig;

use crate::correlation::types::{SiemEvent, SiemAlert};
use crate::correlation::engine::RuleEngine;
use crate::correlation::suppression::SuppressionCache;
use crate::correlation::dedup;
use crate::correlation::alerts as ch_alerts;
use crate::correlation::ueba;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

pub const CONSUMER_GROUP:    &str = "siem-engine-consumers";
pub const TOPIC_SIEM_LOGS:   &str = "siem-logs";
const CLIENT_ID:             &str = "siem-engine-correlation";

// ─────────────────────────────────────────────────────────────────────────────
// Start the consumer
// ─────────────────────────────────────────────────────────────────────────────

/// Build and start the Kafka consumer loop in a background task.
pub fn spawn_consumer(
    kafka_brokers: String,
    ch:            Client,
    redis_url:     String,
    engine:        Arc<RuleEngine>,
    suppression:   Arc<SuppressionCache>,
) {
    tokio::spawn(async move {
        loop {
            match run_consumer_loop(
                &kafka_brokers, &ch, &redis_url,
                Arc::clone(&engine),
                Arc::clone(&suppression),
            ).await {
                Ok(_) => tracing::info!("Consumer loop exited cleanly — restarting"),
                Err(e) => {
                    tracing::error!("Consumer loop error: {} — restarting in 5s", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    });
}

async fn run_consumer_loop(
    brokers:     &str,
    ch:          &Client,
    redis_url:   &str,
    engine:      Arc<RuleEngine>,
    suppression: Arc<SuppressionCache>,
) -> Result<()> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id",            CONSUMER_GROUP)
        .set("bootstrap.servers",   brokers)
        .set("enable.auto.commit",  "true")          // commit after delivery to pipeline
        .set("auto.offset.reset",   "latest")
        .set("client.id",           CLIENT_ID)
        .set("session.timeout.ms",  "30000")
        .set("heartbeat.interval.ms", "10000")
        .create()?;

    consumer.subscribe(&[TOPIC_SIEM_LOGS])?;
    tracing::info!(
        group = CONSUMER_GROUP,
        topic = TOPIC_SIEM_LOGS,
        "SIEM correlation consumer started"
    );

    // Valkey connection for dedup and offset tracking
    let redis_client = redis::Client::open(redis_url)?;
    let mut redis_conn = redis_client.get_multiplexed_async_connection().await?;

    let mut stream = consumer.stream();

    while let Some(msg_result) = stream.next().await {
        let msg = match msg_result {
            Ok(m)  => m,
            Err(e) => {
                tracing::warn!("Kafka receive error: {}", e);
                continue;
            }
        };

        let partition = msg.partition();
        let offset    = msg.offset();
        let topic     = msg.topic().to_string();

        // ── Idempotency check ────────────────────────────────────────────────
        if dedup::is_offset_processed(&mut redis_conn, &topic, partition, offset).await {
            tracing::debug!("Skipping already-processed offset {}:{}", partition, offset);
            continue;
        }

        // ── Deserialise payload ──────────────────────────────────────────────
        let payload = match msg.payload() {
            Some(p) => p,
            None    => { continue; }
        };

        let event: SiemEvent = match serde_json::from_slice(payload) {
            Ok(e)  => e,
            Err(e) => {
                tracing::warn!(
                    offset = offset,
                    error  = %e,
                    "Failed to deserialise SiemEvent — skipping"
                );
                // Mark as processed anyway to avoid infinite retry loop on bad messages
                let _ = dedup::mark_offset_processed(
                    &mut redis_conn, &topic, partition, offset
                ).await;
                continue;
            }
        };

        // ── UEBA baseline update ─────────────────────────────────────────────
        let ueba_anomalies = match ueba::update_and_check(&mut redis_conn, &event).await {
            Ok(a)  => a,
            Err(e) => {
                tracing::warn!("UEBA update error for log_id {}: {}", event.log_id, e);
                vec![]
            }
        };

        if !ueba_anomalies.is_empty() {
            tracing::debug!(
                log_id = %event.log_id,
                anomalies = ?ueba_anomalies,
                "UEBA anomalies detected"
            );
        }

        // ── Evaluate all 10 OOTB rules ───────────────────────────────────────
        let rule_matches = engine.evaluate(&event).await;

        for rule_match in &rule_matches {
            // ── Suppression check ────────────────────────────────────────────
            if suppression.is_suppressed(&event, rule_match).await {
                tracing::debug!(
                    rule_id = %rule_match.rule_id,
                    "Alert suppressed for tenant '{}'", event.tenant_id
                );
                continue;
            }

            // Build the candidate alert
            let entity = dedup::entity_from_event(&event);
            let affected_hosts = event.hostname.iter()
                .chain(event.src_ip_token.iter())
                .cloned()
                .collect::<Vec<_>>();

            let alert = SiemAlert::new(
                &event.tenant_id,
                &rule_match.rule_id,
                &rule_match.rule_name,
                &rule_match.severity,
                &rule_match.title,
                &rule_match.description,
                if affected_hosts.is_empty() { vec![entity.clone()] } else { affected_hosts },
                vec![event.log_id.clone()],
                rule_match.mitre_techniques.clone(),
            );

            // ── Alert deduplication ──────────────────────────────────────────
            match dedup::check_or_insert(
                &mut redis_conn,
                &rule_match.rule_id,
                &event.tenant_id,
                &entity,
                &alert.alert_id,
            ).await {
                Ok(dedup::DedupResult::New) => {
                    // Fresh alert — INSERT into ClickHouse
                    if let Err(e) = ch_alerts::write_alert(ch, &alert).await {
                        tracing::error!(
                            rule_id  = %rule_match.rule_id,
                            alert_id = %alert.alert_id,
                            "Failed to write alert to ClickHouse: {}", e
                        );
                    }
                }
                Ok(dedup::DedupResult::Duplicate { alert_id }) => {
                    // Existing alert within 5-min window — UPDATE updated_at only
                    tracing::debug!(
                        alert_id = %alert_id,
                        rule_id  = %rule_match.rule_id,
                        "Dedup hit — updating existing alert"
                    );
                    if let Err(e) = ch_alerts::update_alert(ch, &alert_id, &event.tenant_id, None).await {
                        tracing::warn!("Alert update failed for {}: {}", alert_id, e);
                    }
                }
                Err(e) => {
                    tracing::warn!("Dedup check failed: {} — creating new alert anyway", e);
                    let _ = ch_alerts::write_alert(ch, &alert).await;
                }
            }
        }

        // ── Mark offset as processed ─────────────────────────────────────────
        if let Err(e) = dedup::mark_offset_processed(
            &mut redis_conn, &topic, partition, offset
        ).await {
            tracing::warn!("Could not mark offset {}:{} as processed: {}", partition, offset, e);
        }
    }

    Ok(())
}
