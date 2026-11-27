use rdkafka::config::ClientConfig;
use rdkafka::consumer::StreamConsumer;
use rdkafka::producer::FutureProducer;
use serde::{Deserialize, Serialize};

pub const ENV_KAFKA_BROKERS:     &str = "KAFKA_BROKERS";
pub const DEFAULT_KAFKA_BROKERS: &str = "kafka:9092";

pub const TOPIC_NDR_EVENTS:  &str = "ndr-events";
pub const TOPIC_SIEM_EVENTS: &str = "siem-events";
pub const TOPIC_ALERTS:      &str = "ndr-alerts";

#[derive(Debug, Clone)]
pub struct KafkaConfig {
    pub brokers: String,
}

impl KafkaConfig {
    pub fn from_env() -> Self {
        let brokers = std::env::var(ENV_KAFKA_BROKERS)
            .unwrap_or_else(|_| DEFAULT_KAFKA_BROKERS.to_string());
        Self { brokers }
    }

    pub fn build_producer(&self) -> FutureProducer {
        ClientConfig::new()
            .set("bootstrap.servers", &self.brokers)
            .set("message.timeout.ms", "5000")
            .set("queue.buffering.max.messages", "100000")
            .set("batch.num.messages", "1000")
            .set("linger.ms", "5")
            .create()
            .expect("Kafka producer creation failed")
    }

    pub fn build_consumer(&self, group_id: &str, client_id: &str) -> StreamConsumer {
        ClientConfig::new()
            .set("group.id", group_id)
            .set("bootstrap.servers", &self.brokers)
            .set("enable.auto.commit", "true")
            // a new group (a fresh install) starts at the oldest waiting data: with "latest", what the
            // sensors sent before the engines first read was skipped (seen in the 1.0.38 install test);
            // once offsets are committed this has no effect, so nothing is read twice
            .set("auto.offset.reset", "earliest")
            .set("client.id", client_id)
            .create()
            .expect("Kafka consumer creation failed")
    }
}

/// Typed envelope for messages sent over Kafka topics.
#[derive(Debug, Serialize, Deserialize)]
pub struct KafkaEnvelope<T> {
    pub tenant_id:  String,
    pub source:     String,
    pub payload:    T,
    pub timestamp:  String,
}
