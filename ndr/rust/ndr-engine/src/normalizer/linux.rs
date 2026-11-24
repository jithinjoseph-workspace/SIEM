// Linux endpoint normalizer — auditd events from Vector.
// Maps auditd key=value fields (parsed by VRL) into NormalizedEvent.
// All SIGMA linux rule fields live in .raw and are served by get_field() fallback.

use super::{EventSource, NormalizedEvent};
use serde_json::Value;

pub fn normalize_linux(raw: &Value) -> Option<NormalizedEvent> {
    let record_type = raw.get("record_type")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_string();

    let dest_ip = raw.get("DestinationIp")
        .and_then(|v| v.as_str())
        .map(String::from);

    let dest_port = raw.get("DestinationPort")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u16>().ok());

    let pid  = raw.get("pid").and_then(|v| v.as_str()).unwrap_or("0");
    let ts   = raw.get("audit_ts").and_then(|v| v.as_str()).unwrap_or("0");
    // Synthetic join key — no real community_id exists for process events.
    // Uniqueness comes from pid + audit timestamp serial.
    let community_id = format!("linux-{}-{}", pid, ts);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    Some(NormalizedEvent {
        source_ip:        None,
        source_port:      None,
        dest_ip,
        dest_port,
        proto:            None,
        network_protocol: None,
        community_id:     Some(community_id),
        event_source:     EventSource::Linux,
        log_source:       Some(record_type),
        timestamp,
        uid:              Some(pid.to_string()),
        conn_state:       None,
        event_type:       Some("endpoint".to_string()),
        alert:            None,
        raw: raw.clone(),
        is_malicious: false,
        src_country_code: String::new(),
        dst_country_code: String::new(),
        src_asn_org:      String::new(),
        dst_asn_org:      String::new(),
        direction:        String::new(),
    })
}
