// NDR Engine — normalizer routing
// NormalizedEvent, EventSource, AlertInfo live in provigil-common so they can
// be shared with siem-engine. NDR-specific parsers stay here.
// License: Apache-2.0

mod zeek;
mod suricata;
mod linux;

pub use zeek::normalize_zeek;
pub use suricata::normalize_suricata;
pub use linux::normalize_linux;
pub use provigil_common::normalizer::{NormalizedEvent, EventSource, AlertInfo};

use serde_json::Value;

/// Parse a raw JSON value arriving from Vector into a NormalizedEvent.
/// Returns None if the event is totally malformed.
pub fn normalize(raw: &Value) -> Option<NormalizedEvent> {
    let source = raw.get("source").and_then(|v| v.as_str()).unwrap_or("");

    // Linux endpoint events from auditd take priority — they have no community_id
    if source == "linux" {
        return normalize_linux(raw);
    }

    // Use explicit source tag from Vector, fallback to heuristic
    let is_zeek = source == "agent-z" || source == "zeek"
        || raw.get("uid").is_some()
        || raw.get("_path").is_some()
        || (raw.get("proto").is_some() && raw.get("conn_state").is_some());

    if is_zeek {
        normalize_zeek(raw)
    } else {
        normalize_suricata(raw)
    }
}
