// NDR Engine — Suricata eve.json Normalizer
// Field mapping concepts from Malcolm's 11_suricata_logs.conf (public domain, CC0).
// Zero code copied — all logic freshly implemented. License: Apache-2.0

use serde_json::Value;
use super::{NormalizedEvent, EventSource, AlertInfo};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Normalise a raw Suricata eve.json event from Vector.
pub fn normalize_suricata(raw: &Value) -> Option<NormalizedEvent> {
    let community_id = raw.get("community_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "-")
        .map(String::from);

    let event_type = raw.get("event_type")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Malcolm: src_ip → source.ip (field name is the same in Suricata eve.json)
    let source_ip = raw.get("src_ip").and_then(|v| v.as_str()).map(String::from);
    let dest_ip   = raw.get("dest_ip").and_then(|v| v.as_str()).map(String::from);
    let source_port = raw.get("src_port").and_then(|v| v.as_u64()).map(|p| p as u16);
    let dest_port   = raw.get("dest_port").and_then(|v| v.as_u64()).map(|p| p as u16);

    let proto = raw.get("proto")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase());

    // Malcolm: app_proto → network.protocol
    let network_protocol = raw.get("app_proto")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "unknown" && *s != "failed")
        .map(|s| s.to_lowercase());

    // SIDs suppressed cloud-side — sensor heartbeat / infrastructure noise
    const SUPPRESSED_SIDS: &[u64] = &[
        2066052, // ET INFO ngrok-free.dev TLS SNI — sensor tunnel to cloud
        2066057, // ET INFO ngrok tunneling protocol
        2049049, // ET INFO DNS query to *.ngrok domain (ngrok-free.dev) — sensor tunnel noise
        2049052, // ET INFO DNS query to *.ngrok domain (ngrok-free.app) — sensor tunnel noise
    ];

    // Parse Suricata alert sub-object only when event_type == "alert"
    let alert = if event_type.as_deref() == Some("alert") {
        let parsed = raw.get("alert").and_then(|a| parse_alert(a));
        // Drop suppressed SIDs before they reach scoring/hits
        if let Some(ref a) = parsed {
            if SUPPRESSED_SIDS.contains(&a.signature_id) {
                return None;
            }
        }
        parsed
    } else {
        None
    };

    // Suricata timestamp is ISO8601: "2024-04-09T10:30:00.123456+0000"
    let timestamp = raw.get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp_millis() as u64)
        .unwrap_or_else(now_ms);

    Some(NormalizedEvent {
        source_ip,
        source_port,
        dest_ip,
        dest_port,
        proto,
        network_protocol,
        community_id,
        event_source: EventSource::Suricata,
        log_source: event_type.clone(),
        timestamp,
        uid: None,
        conn_state: None,
        event_type,
        alert,
        raw: raw.clone(),
        is_malicious: false,
        src_country_code: String::new(),
        dst_country_code: String::new(),
        src_asn_org:      String::new(),
        dst_asn_org:      String::new(),
        direction:        String::new(),
    })
}

fn parse_alert(a: &Value) -> Option<AlertInfo> {
    let signature    = a.get("signature").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
    let signature_id = a.get("signature_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let category     = a.get("category").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let severity     = a.get("severity").and_then(|v| v.as_u64()).unwrap_or(3) as u8;

    // MITRE ATT&CK comes from alert.metadata.mitre_tactic_id[] (SO + Malcolm confirmed)
    let mitre_tactics = extract_str_array(a, "metadata", "mitre_tactic_id");
    let mitre_techniques = extract_str_array(a, "metadata", "mitre_technique_id");

    Some(AlertInfo { signature, signature_id, category, severity, mitre_tactics, mitre_techniques })
}

fn extract_str_array(obj: &Value, key1: &str, key2: &str) -> Vec<String> {
    obj.get(key1)
        .and_then(|m| m.get(key2))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default()
}
