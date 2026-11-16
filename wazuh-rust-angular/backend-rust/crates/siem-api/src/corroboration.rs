//! XDR incidents: a host alert (level 7 or more) and a network threat an NDR sensor saw
//! (`ndr_threats` of the alert's tenant) that involve the same host IP within [`WINDOW_MS`].
//! The incident carries the real threat (id, signature, the other side as attacker). Each alert
//! becomes at most one incident. Without network threats (no sensor) nothing is created.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use chrono::Utc;
use tracing::warn;
use uuid::Uuid;

use crate::db::ClickHouseIncidentRow;
use crate::AppState;

/// Host alerts from this level take part.
const LEVEL: u8 = 7;
/// How far apart the alert and the network threat may be.
const WINDOW_MS: u64 = 10 * 60 * 1000;
/// Alerts this recent are looked at each cycle.
const RECENT_MS: u64 = 30 * 60 * 1000;
/// Alert ids already turned into an incident (or found to have one), the most recent ones.
const REMEMBER: usize = 20_000;

/// Spawns the background cross-source corroboration worker.
pub fn spawn_corroboration_worker(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(e) = run_corroboration_cycle(&state).await {
                warn!("Corroboration cycle notice: {}", e);
            }
        }
    });
}

#[derive(Debug, Clone, clickhouse::Row, serde::Deserialize)]
pub struct NdrThreatRow {
    pub id: String,
    pub ts: u64,
    pub signature: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub severity: u8,
}

/// A host alert taking part: (alert id, time in ms, host IP).
pub type HostAlert = (String, u64, String);

/// For each alert, the network threat on its host IP nearest in time within [`WINDOW_MS`].
pub fn correlate<'a>(alerts: &[HostAlert], threats: &'a [NdrThreatRow]) -> Vec<(usize, &'a NdrThreatRow)> {
    alerts
        .iter()
        .enumerate()
        .filter_map(|(i, (_, ts, ip))| {
            threats
                .iter()
                .filter(|t| (&t.src_ip == ip || &t.dst_ip == ip) && t.ts.abs_diff(*ts) <= WINDOW_MS)
                .min_by_key(|t| t.ts.abs_diff(*ts))
                .map(|t| (i, t))
        })
        .collect()
}

/// The side of the threat that is not the host.
fn attacker(t: &NdrThreatRow, host_ip: &str) -> String {
    if t.src_ip == host_ip { t.dst_ip.clone() } else { t.src_ip.clone() }
}

fn seen() -> &'static Mutex<(HashSet<String>, VecDeque<String>)> {
    static S: std::sync::OnceLock<Mutex<(HashSet<String>, VecDeque<String>)>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

fn remember(id: &str) {
    let mut s = seen().lock().unwrap();
    if s.0.insert(id.to_string()) {
        s.1.push_back(id.to_string());
        if s.1.len() > REMEMBER {
            if let Some(old) = s.1.pop_front() {
                s.0.remove(&old);
            }
        }
    }
}

async fn run_corroboration_cycle(state: &AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !state.db.is_connected() {
        return Ok(());
    }
    let now = Utc::now().timestamp_millis().max(0) as u64;
    let agent_tenants = state.agent_tenants.read().unwrap().clone();
    // recent host alerts per tenant, not yet decided
    let mut per_tenant: HashMap<String, Vec<(HostAlert, siem_core::Alert)>> = HashMap::new();
    {
        let alerts = state.alerts.read().unwrap();
        let done = seen().lock().unwrap();
        for a in alerts.iter().rev().take(2000) {
            let ts = a.timestamp.timestamp_millis().max(0) as u64;
            let ip = a.agent.ip.trim();
            if a.rule.level < LEVEL || ip.is_empty() || ip == "any" || ip == "127.0.0.1" || now.saturating_sub(ts) > RECENT_MS || done.0.contains(&a.id.to_string()) {
                continue;
            }
            let tenant = crate::tenancy::alert_tenant(a, &agent_tenants);
            per_tenant.entry(tenant).or_default().push(((a.id.to_string(), ts, ip.to_string()), a.clone()));
        }
    }
    for (tenant, list) in per_tenant {
        let ips: Vec<String> = list.iter().map(|((_, _, ip), _)| ip.clone()).collect::<HashSet<_>>().into_iter().collect();
        let from = list.iter().map(|((_, ts, _), _)| *ts).min().unwrap_or(now).saturating_sub(WINDOW_MS);
        let client = state.db.tenant_client(&tenant);
        let threats: Vec<NdrThreatRow> = match client
            .query("SELECT toString(id) AS id, toUInt64(toUnixTimestamp64Milli(timestamp)) AS ts, signature, src_ip, dst_ip, severity FROM ndr_threats WHERE timestamp >= fromUnixTimestamp64Milli(toInt64(?)) AND (has(?, src_ip) OR has(?, dst_ip)) ORDER BY timestamp LIMIT 5000")
            .bind(from)
            .bind(&ips)
            .bind(&ips)
            .fetch_all()
            .await
        {
            Ok(t) => t,
            // a tenant without the NDR tables: nothing to corroborate
            Err(_) => continue,
        };
        if threats.is_empty() {
            continue;
        }
        let host: Vec<HostAlert> = list.iter().map(|(h, _)| h.clone()).collect();
        for (i, t) in correlate(&host, &threats) {
            let ((id, _, ip), alert) = &list[i];
            // stored before (an earlier run of this service): never twice
            let have: u64 = client.query("SELECT count() FROM xdr_incidents WHERE siem_alert_id = ?").bind(id).fetch_one().await.unwrap_or(0);
            remember(id);
            if have > 0 {
                continue;
            }
            let inc = ClickHouseIncidentRow {
                incident_id: Uuid::new_v4().to_string(),
                timestamp: now,
                title: format!("Cross-Corroborated Incident on {}: {}", alert.agent.name, alert.rule.description),
                severity: if alert.rule.level >= 10 || t.severity >= 3 { "critical".into() } else { "high".into() },
                host_ip: ip.clone(),
                agent_id: alert.agent.id.clone(),
                agent_name: alert.agent.name.clone(),
                attacker_ip: attacker(t, ip),
                ndr_threat_id: t.id.clone(),
                siem_alert_id: id.clone(),
                ndr_signature: t.signature.clone(),
                siem_rule_description: alert.rule.description.clone(),
                status: "open".into(),
            };
            state.db.insert_incident(&tenant, &inc).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(id: &str, ts: u64, src: &str, dst: &str) -> NdrThreatRow {
        NdrThreatRow { id: id.into(), ts, signature: format!("sig-{id}"), src_ip: src.into(), dst_ip: dst.into(), severity: 2 }
    }

    #[test]
    fn only_a_real_threat_on_the_same_host_in_the_window_corroborates() {
        let alerts: Vec<HostAlert> = vec![
            ("a1".into(), 1_000_000, "10.0.0.5".into()),
            ("a2".into(), 1_000_000, "10.0.0.9".into()),
            ("a3".into(), 1_000_000 + WINDOW_MS + 60_000, "10.0.0.5".into()),
        ];
        let threats = vec![t("far", 1_000_000 - WINDOW_MS - 1, "203.0.113.7", "10.0.0.5"), t("near", 1_000_000 + 30_000, "10.0.0.5", "198.51.100.3"), t("other-host", 1_000_000, "203.0.113.7", "10.0.0.6")];
        let m = correlate(&alerts, &threats);
        assert_eq!(m.iter().map(|(i, t)| (alerts[*i].0.as_str(), t.id.as_str())).collect::<Vec<_>>(), [("a1", "near")], "a2: no threat on its host; a3: the threat is more than the window away");
        assert_eq!(attacker(m[0].1, "10.0.0.5"), "198.51.100.3", "the other side of the threat");
        assert!(correlate(&alerts, &[]).is_empty(), "no sensor: no incident");
    }
}
