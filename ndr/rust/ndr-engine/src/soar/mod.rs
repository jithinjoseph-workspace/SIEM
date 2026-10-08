pub mod actions;
pub mod conditions;
pub mod firewall;
pub mod switch;

// Re-export shared types from provigil-common — no duplication.
pub use provigil_common::soar::{
    SoarNativePlaybook,
    SoarPlaybookRun,
    ActiveBlock,
    DeviceIsolation,
    SoarContext,
    SoarStore,
};

use crate::api::AppState;
use crate::correlator::CorrelationHit;
use crate::scoring::RiskResult;
use crate::enrichment::EnrichmentData;
use std::time::{Duration, Instant};

const SOAR_DEDUPE_WINDOW_SECS: u64 = 1800;

const PRIMARY_INCIDENT_TAGS: &[&str] = &[
    "dns-beaconing", "port-scan", "lateral-movement", "credential-stuffing", "slow-scan",
    "beaconing", "threat-intel", "ids-alert", "abnormal-rst", "data-staging",
    "internal-recon", "volume-anomaly", "new-external-contact", "icmp-flood",
    "abnormal-hours", "nxdomain-flood", "dns-tunneling", "tls-cert-anomaly",
    "protocol-misuse", "large-volume-exfil", "sensitive-country",
    "ip-conflict", "sigma", "dga", "doh-evasion", "malicious-domain",
    "c2",
];

fn primary_incident_tag(tags: &[String]) -> String {
    for canonical in PRIMARY_INCIDENT_TAGS {
        if let Some(tag) = tags.iter().find(|t| t.as_str() == *canonical) {
            return tag.clone();
        }
    }

    tags.iter()
        .find(|t| !t.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| "alert".to_string())
}

pub fn incident_key_for_hit(
    tenant_id: &str,
    hit: &CorrelationHit,
    risk: &RiskResult,
) -> String {
    let (src, dst) = match hit.source.as_str() {
        "agent-s" => (
            hit.agent_s.source_ip.clone().unwrap_or_default(),
            hit.agent_s.dest_ip.clone().unwrap_or_default(),
        ),
        _ => (
            hit.agent_z.source_ip.clone().or_else(|| hit.agent_s.source_ip.clone()).unwrap_or_default(),
            hit.agent_z.dest_ip.clone().or_else(|| hit.agent_s.dest_ip.clone()).unwrap_or_default(),
        ),
    };

    let tag = primary_incident_tag(&risk.tags);
    format!("soar:{}:{}:{}:{}", tenant_id, src, dst, tag)
}

pub fn should_fire_soar_for_incident(state: &AppState, incident_key: &str) -> bool {
    let now = Instant::now();
    let mut should_fire = true;

    if let Some(mut last) = state.soar_dedupe.get_mut(incident_key) {
        if last.elapsed() < Duration::from_secs(SOAR_DEDUPE_WINDOW_SECS) {
            should_fire = false;
        } else {
            *last = now;
        }
    } else {
        state.soar_dedupe.insert(incident_key.to_string(), now);
    }

    should_fire
}

pub async fn execute_native_playbooks(
    state: &AppState,
    hit: CorrelationHit,
    risk: RiskResult,
    enrichment: EnrichmentData,
    tenant_id: &str,
) {
    let incident_key = incident_key_for_hit(tenant_id, &hit, &risk);
    if !should_fire_soar_for_incident(state, &incident_key) {
        return;
    }

    let playbooks = match state.ch_storage.get_native_playbooks(tenant_id).await {
        Ok(p) => p,
        Err(_) => return,
    };

    // Build context once — shared by both condition evaluation and action execution.
    let ctx = conditions::build_soar_context(&hit, &risk, &enrichment, tenant_id);

    for pb in playbooks {
        if pb.enabled != 1 { continue; }

        let triggered = provigil_common::soar::conditions::evaluate_condition(&pb, &ctx);
        if triggered {
            provigil_common::soar::actions::execute_action(
                state.ch_storage.as_ref(),
                &pb,
                &ctx,
            ).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlator::session::CorrelationHit;
    use crate::normalizer::{EventSource, NormalizedEvent};
    use serde_json::json;

    #[test]
    fn incident_key_is_stable_for_same_attacker_target_group() {
        let base_event = |source: EventSource| NormalizedEvent {
            source_ip: Some("10.0.0.5".into()),
            source_port: None,
            dest_ip: Some("8.8.8.8".into()),
            dest_port: None,
            proto: None,
            network_protocol: None,
            community_id: None,
            event_source: source,
            log_source: None,
            timestamp: 0,
            uid: None,
            conn_state: None,
            event_type: None,
            alert: None,
            raw: json!({}),
            is_malicious: false,
            src_country_code: String::new(),
            dst_country_code: String::new(),
            src_asn_org: String::new(),
            dst_asn_org: String::new(),
            direction: String::new(),
        };

        let hit_a = CorrelationHit {
            community_id: "cid-1".into(),
            agent_z: base_event(EventSource::Zeek),
            agent_s: base_event(EventSource::Suricata),
            hit_time: 0,
            source: "agent-z+agent-s".into(),
        };

        let hit_b = CorrelationHit {
            community_id: "cid-2".into(),
            agent_z: base_event(EventSource::Zeek),
            agent_s: base_event(EventSource::Suricata),
            hit_time: 0,
            source: "agent-z+agent-s".into(),
        };

        let risk_a = RiskResult {
            score: 80.0,
            severity: crate::scoring::Severity::High,
            tags: vec!["beaconing".into()],
            reasons: vec![],
        };
        let risk_b = RiskResult {
            score: 80.0,
            severity: crate::scoring::Severity::High,
            tags: vec!["beaconing".into()],
            reasons: vec![],
        };

        assert_eq!(incident_key_for_hit("tenant", &hit_a, &risk_a), incident_key_for_hit("tenant", &hit_b, &risk_b));
    }

    #[test]
    fn incident_key_stays_stable_when_tag_order_changes() {
        let base_event = |source: EventSource| NormalizedEvent {
            source_ip: Some("10.0.0.5".into()),
            source_port: None,
            dest_ip: Some("8.8.8.8".into()),
            dest_port: None,
            proto: None,
            network_protocol: None,
            community_id: None,
            event_source: source,
            log_source: None,
            timestamp: 0,
            uid: None,
            conn_state: None,
            event_type: None,
            alert: None,
            raw: json!({}),
            is_malicious: false,
            src_country_code: String::new(),
            dst_country_code: String::new(),
            src_asn_org: String::new(),
            dst_asn_org: String::new(),
            direction: String::new(),
        };

        let hit = CorrelationHit {
            community_id: "cid-3".into(),
            agent_z: base_event(EventSource::Zeek),
            agent_s: base_event(EventSource::Suricata),
            hit_time: 0,
            source: "agent-z+agent-s".into(),
        };

        let risk_a = RiskResult {
            score: 75.0,
            severity: crate::scoring::Severity::High,
            tags: vec!["ids-alert".into(), "threat-intel".into()],
            reasons: vec![],
        };
        let risk_b = RiskResult {
            score: 90.0,
            severity: crate::scoring::Severity::High,
            tags: vec!["threat-intel".into(), "ids-alert".into()],
            reasons: vec![],
        };

        assert_eq!(incident_key_for_hit("tenant", &hit, &risk_a), incident_key_for_hit("tenant", &hit, &risk_b));
    }

    #[test]
    fn incident_key_differs_by_primary_tag_and_tenant() {
        let base_event = |source: EventSource| NormalizedEvent {
            source_ip: Some("10.0.0.5".into()),
            source_port: None,
            dest_ip: Some("8.8.8.8".into()),
            dest_port: None,
            proto: None,
            network_protocol: None,
            community_id: None,
            event_source: source,
            log_source: None,
            timestamp: 0,
            uid: None,
            conn_state: None,
            event_type: None,
            alert: None,
            raw: json!({}),
            is_malicious: false,
            src_country_code: String::new(),
            dst_country_code: String::new(),
            src_asn_org: String::new(),
            dst_asn_org: String::new(),
            direction: String::new(),
        };

        let hit = CorrelationHit {
            community_id: "cid-4".into(),
            agent_z: base_event(EventSource::Zeek),
            agent_s: base_event(EventSource::Suricata),
            hit_time: 0,
            source: "agent-z+agent-s".into(),
        };

        let beacon = RiskResult {
            score: 80.0,
            severity: crate::scoring::Severity::High,
            tags: vec!["beaconing".into()],
            reasons: vec![],
        };
        let scan = RiskResult {
            score: 80.0,
            severity: crate::scoring::Severity::High,
            tags: vec!["port-scan".into()],
            reasons: vec![],
        };

        assert_ne!(incident_key_for_hit("tenant-a", &hit, &beacon), incident_key_for_hit("tenant-a", &hit, &scan));
        assert_ne!(incident_key_for_hit("tenant-a", &hit, &beacon), incident_key_for_hit("tenant-b", &hit, &beacon));
    }
}
