// NDR Engine — Zeek Log Normalizer
// Field mapping concepts from Malcolm's 1200_zeek_mutate.conf (public domain, CC0).
// Zero code copied — all logic freshly implemented. License: Apache-2.0

use serde_json::Value;
use super::{NormalizedEvent, EventSource};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Normalise a raw Zeek JSON event from Vector into our canonical model.
/// Zeek conn.log TSV is pre-parsed by Vector into JSON fields.
pub fn normalize_zeek(raw: &Value) -> Option<NormalizedEvent> {
    // community_id preferred; uid fallback for http/dns/ssl/files logs that don't carry it
    let community_id = raw.get("community_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "-")
        .or_else(|| raw.get("uid").and_then(|v| v.as_str()))
        .map(String::from);

    // Malcolm maps id.orig_h → source.ip; Vector renames it to src_ip
    let source_ip = raw.get("src_ip")
        .or_else(|| raw.get("id.orig_h"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let dest_ip = raw.get("dst_ip")
        .or_else(|| raw.get("id.resp_h"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Ports may arrive as strings (TSV origin) or integers
    let source_port = raw.get("src_port")
        .or_else(|| raw.get("id.orig_p"))
        .and_then(|v| {
            v.as_u64().map(|n| n as u16)
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });

    let dest_port = raw.get("dst_port")
        .or_else(|| raw.get("id.resp_p"))
        .and_then(|v| {
            v.as_u64().map(|n| n as u16)
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });

    let proto = raw.get("proto")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase());

    // Malcolm: network.protocol ← Zeek service field (e.g. "http", "dns", "ssl")
    // or_else must run AFTER filtering so an empty network_protocol falls through to service
    let network_protocol = raw.get("network_protocol")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "-")
        .or_else(|| raw.get("service").and_then(|v| v.as_str()).filter(|s| !s.is_empty() && *s != "-"))
        .map(|s| s.to_lowercase());

    let uid = raw.get("uid")
        .and_then(|v| v.as_str())
        .map(String::from);

    let conn_state = raw.get("conn_state")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "-")
        .map(String::from);

    // log_source helps the drop filter (stats, capture_loss, etc.)
    // Prefer explicit tag from Vector/Filebeat; fall back to field-presence inference
    // when the pipeline doesn't add log_type or _path (common for conn.log entries).
    let log_source = raw.get("log_type")
        .or_else(|| raw.get("_path"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            // Infer Zeek log type from field signatures exclusive to each log type
            if raw.get("conn_state").is_some() || raw.get("history").is_some() {
                Some("conn".to_string())
            } else if raw.get("query").is_some() || raw.get("qtype_name").is_some() {
                Some("dns".to_string())
            } else if raw.get("method").is_some() && raw.get("uri").is_some() {
                Some("http".to_string())
            } else if raw.get("server_name").is_some() || raw.get("cipher").is_some() {
                Some("ssl".to_string())
            } else if raw.get("mime_type").is_some() || raw.get("fuid").is_some() {
                Some("files".to_string())
            } else if raw.get("name").is_some() && raw.get("peer").is_some() {
                Some("weird".to_string())
            } else {
                None
            }
        });

    // Zeek ts is a Unix float (seconds.microseconds)
    let timestamp = raw.get("ts")
        .and_then(|v| v.as_f64())
        .map(|f| (f * 1000.0) as u64)
        .unwrap_or_else(now_ms);

    Some(NormalizedEvent {
        source_ip,
        source_port,
        dest_ip,
        dest_port,
        proto,
        network_protocol,
        community_id,
        event_source: EventSource::Zeek,
        log_source,
        timestamp,
        uid,
        conn_state,
        event_type: None,
        alert: None,
        raw: raw.clone(),
        is_malicious: false,
        src_country_code: String::new(),
        dst_country_code: String::new(),
        src_asn_org:      String::new(),
        dst_asn_org:      String::new(),
        direction:        String::new(),
    })
}
