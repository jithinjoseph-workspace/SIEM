// Threat Intel enrichment — called on every parsed event
// Uses provigil-common::threat_intel::check_ip() to match IOCs

use crate::ingest::normalizer::{OcsfEvent, ThreatMatch};
use tracing::debug;

/// Enrich a parsed event with threat intel matches.
/// Returns the event with threat_match populated if an IOC is found.
pub async fn enrich(mut event: OcsfEvent, clickhouse_url: &str, tenant_id: &str) -> OcsfEvent {
    // Check each ip_token against the threat_iocs table for this tenant.
    // ip_tokens are already HMAC values — we store tokens in threat_iocs too
    // so raw IPs never appear in the DB.
    for token in &event.ip_tokens {
        if let Some(m) = check_ioc(token, clickhouse_url, tenant_id).await {
            debug!("Threat Intel match for token {} in tenant {}", token, tenant_id);
            event.threat_match = Some(m);
            break; // first match is enough; correlation engine handles dedup
        }
    }
    event
}

async fn check_ioc(
    ip_token: &str,
    clickhouse_url: &str,
    tenant_id: &str,
) -> Option<ThreatMatch> {
    // Query: SELECT type, value, severity, source FROM ndr_{tenant_id}.threat_iocs
    //        WHERE value = ? AND (expires_at IS NULL OR expires_at > now())
    // TODO: wire up actual ClickHouse HTTP client query here
    let _ = (ip_token, clickhouse_url, tenant_id);
    None
}
