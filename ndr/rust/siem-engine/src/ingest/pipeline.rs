// Pipeline — orchestrates the full ingest flow for every log source:
// raw log → normalise (or AI parser) → ip_token → threat_intel → kafka publish

use std::sync::Arc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{info, warn, error};

use crate::ingest::{normalizer, ip_token, threat_intel, kafka_publisher, ai_parser};
use crate::ingest::normalizer::OcsfEvent;
use crate::ingest::ai_parser::{ParserCache, SampleBuffer};

type HmacSha256 = Hmac<Sha256>;

// ─── Context ────────────────────────────────────────────────────────────────

/// Shared pipeline context — stored in AppState as Arc<Pipeline>
pub struct Pipeline {
    pub base_hmac_key:  Vec<u8>,
    pub clickhouse_url: String,
    pub valkey_url:     String,
    pub publisher:      kafka_publisher::KafkaPublisher,
    pub parser_cache:   Arc<ParserCache>,
    pub sample_buffer:  Arc<SampleBuffer>,
}

impl Pipeline {
    pub fn new(
        base_hmac_key: Vec<u8>,
        clickhouse_url: String,
        valkey_url: String,
        kafka_brokers: &str,
    ) -> Arc<Self> {
        Arc::new(Self {
            publisher:      kafka_publisher::KafkaPublisher::new(kafka_brokers),
            base_hmac_key,
            clickhouse_url,
            valkey_url,
            parser_cache:  ParserCache::new(),
            sample_buffer: SampleBuffer::new(),
        })
    }

    /// Call once at startup — loads any previously AI-generated parsers from ClickHouse.
    pub async fn init_parsers(&self, ch: &clickhouse::Client) {
        self.parser_cache.load_all(ch).await;
    }

    /// Derive a per-tenant HMAC key so the same IP in different tenants
    /// produces different tokens (tenant isolation at the token level).
    fn tenant_key(&self, tenant_id: &str) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.base_hmac_key)
            .expect("HMAC accepts any key size");
        mac.update(tenant_id.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Full pipeline for a Windows XML EventLog batch (may produce N events)
    pub async fn process_wec(&self, xml: &str, tenant_id: &str, source_id: &str) {
        let events = normalizer::parse_windows_xml(xml, tenant_id, source_id);
        for event in events {
            self.run(event).await;
        }
    }

    /// Full pipeline for a single syslog line
    pub async fn process_syslog(&self, raw: &str, peer_ip: &str, tenant_id: &str, source_id: &str) {
        let event = normalizer::parse_syslog(raw, peer_ip, tenant_id, source_id);
        self.run(event).await;
    }

    /// Full pipeline for a CEF line
    pub async fn process_cef(&self, raw: &str, tenant_id: &str, source_id: &str) {
        let event = normalizer::parse_cef(raw, tenant_id, source_id);
        self.run(event).await;
    }

    /// Full pipeline for generic REST JSON payload
    pub async fn process_generic(&self, raw: &str, tenant_id: &str, source_id: &str) {
        let event = normalizer::parse_generic(raw, tenant_id, source_id);
        self.run(event).await;
    }

    /// Full pipeline for a completely unknown log format.
    ///
    /// Flow:
    ///   1. Check in-memory cache for an existing AI-generated parser for this source.
    ///   2. If found → apply mapping → OCSF output → ip_token → threat_intel → Kafka.
    ///   3. If not found → buffer raw sample; fall through to generic parse for storage.
    ///      When 10 samples collected → spawn ONE Claude API call → save parser → cache it.
    ///      All subsequent logs from this source then hit path 2 — no further AI calls.
    pub async fn process_unknown(
        self: &Arc<Self>,
        raw: &str,
        tenant_id: &str,
        source_id: &str,
    ) {
        // Path 1 — saved AI parser exists: apply it
        if let Some(parser) = self.parser_cache.get(tenant_id, source_id).await {
            let event = ai_parser::apply(&parser, raw, tenant_id, source_id);
            self.run(event).await;
            return;
        }

        // Path 2 — no parser yet: buffer sample + run generic as fallback so log isn't lost
        let ready = self.sample_buffer.push(tenant_id, source_id, raw).await;
        let event = normalizer::parse_generic(raw, tenant_id, source_id);
        self.run(event).await;

        // Trigger ONE async parser generation when we have 10 samples.
        // Uses the DB-configured AI provider (super admin Settings > AI Configuration).
        if ready && !self.sample_buffer.is_generating(tenant_id, source_id).await {
            self.sample_buffer.set_generating(tenant_id, source_id).await;
            let samples  = self.sample_buffer.take(tenant_id, source_id).await;
            let pipeline = Arc::clone(self);
            let tid      = tenant_id.to_string();
            let sid      = source_id.to_string();

            tokio::spawn(async move {
                let ch = provigil_common::clickhouse::ClickHouseConfig::from_env().build_client();

                match ai_parser::generate_parser(&samples, &ch, &sid).await {
                    Some((mappings, event_class)) => {
                        if let Some(saved) = ai_parser::save_parser(
                            &ch, &tid, &sid, &mappings, &event_class
                        ).await {
                            info!("ai_parser: parser for {sid} live — future logs fully OCSF correlated");
                            pipeline.parser_cache.insert(saved).await;
                        }
                    }
                    None => warn!("ai_parser: parser generation failed for {sid}"),
                }

                pipeline.sample_buffer.clear_generating(&tid, &sid).await;
            });
        }
    }

    /// Core pipeline steps — shared by all source types
    async fn run(&self, mut event: OcsfEvent) {
        // Step 1 — ip_token: replace all IPs in parsed JSON with HMAC tokens
        let tenant_key = self.tenant_key(&event.tenant_id);
        event.ip_tokens = ip_token::tokenize_json(&mut event.parsed, &tenant_key);

        // Step 2 — threat intel enrichment
        event = threat_intel::enrich(event, &self.clickhouse_url, &"").await;

        // Step 3 — publish to Kafka siem-logs topic
        if let Err(e) = self.publisher.publish(&event).await {
            error!(
                "Pipeline: Kafka publish failed log_id={} tenant={}: {e}",
                event.log_id, event.tenant_id
            );
        } else {
            info!(
                "Pipeline: published log_id={} class={} severity={} tenant={}",
                event.log_id, event.event_class, event.severity, event.tenant_id
            );
        }
    }
}
