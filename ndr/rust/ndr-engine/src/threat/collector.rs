// Threat intel collection lives in provigil-common so ndr-engine and siem-engine
// share the same feed runners, parsers, and ClickHouse persistence logic.

pub fn spawn_collector(ch: std::sync::Arc<crate::storage::ClickhouseStorage>) {
    provigil_common::threat_intel::collector::spawn_collector(ch);
}
