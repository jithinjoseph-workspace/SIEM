//! UEBA, first part (specs/ueba.md; it replaces the UEBA of NDR's old siem-engine, with the same
//! method): every hour each user's and computer's activity in the hour that just ended is compared
//! with its own last 7 days, hour by hour. An hour more than 3 standard deviations above its
//! normal, once at least 24 hours have been learned, is a UEBA alert (rules 930001-930003,
//! MITRE-tagged), which goes through suppressions, triage, SOAR, cases and alert e-mails like
//! any alert.
//!
//! What is counted (from the stored Windows events): logons per user (4624), failed logons per
//! user (4625), different destinations each computer connects to (Sysmon 3). The old engine's
//! third count, bytes sent, comes from network flows (NDR), not from PCs' events.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::AppState;

const Z: f64 = 3.0;
const MIN_HOURS: usize = 24;
const WINDOW_HOURS: i64 = 168;

struct Model {
    rule: u32,
    level: u8,
    /// what is counted, for the sentence ("logons", ...)
    what: &'static str,
    /// the entity's kind in the sentence
    of: &'static str,
    mitre: (&'static str, &'static str, &'static str),
    /// event ID and source, and the SQL of the entity and of the count
    event_id: &'static str,
    provider: &'static str,
    entity: &'static str,
    count: &'static str,
}

const MODELS: [Model; 3] = [
    Model {
        rule: 930001,
        level: 8,
        what: "logons",
        of: "user",
        mitre: ("T1078", "Defense Evasion", "Valid Accounts"),
        event_id: "4624",
        provider: "Microsoft-Windows-Security-Auditing",
        entity: "lower(JSONExtractString(dj, 'win', 'eventdata', 'targetUserName'))",
        count: "count()",
    },
    Model {
        rule: 930002,
        level: 10,
        what: "failed logons",
        of: "user",
        mitre: ("T1110", "Credential Access", "Brute Force"),
        event_id: "4625",
        provider: "Microsoft-Windows-Security-Auditing",
        entity: "lower(JSONExtractString(dj, 'win', 'eventdata', 'targetUserName'))",
        count: "count()",
    },
    Model {
        rule: 930003,
        level: 8,
        what: "different network destinations",
        of: "computer",
        mitre: ("T1046", "Discovery", "Network Service Discovery"),
        event_id: "3",
        provider: "Microsoft-Windows-Sysmon",
        entity: "lower(JSONExtractString(dj, 'win', 'system', 'computer'))",
        count: "uniqExact(JSONExtractString(dj, 'win', 'eventdata', 'destinationIp'))",
    },
];

/// Accounts that are not people: machine accounts and Windows' own.
fn is_person(user: &str) -> bool {
    !(user.is_empty()
        || user.ends_with('$')
        || ["system", "local service", "network service", "anonymous logon", "-"].contains(&user)
        || user.starts_with("dwm-")
        || user.starts_with("umfd-"))
}

/// Mean and (population) standard deviation.
fn stats(values: &[f64]) -> (f64, f64) {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    (mean, (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n).sqrt())
}

/// The finding for one entity: (observed, mean, std, z) when the last hour is unusual.
/// `hours`: hour number -> count; only hours with activity are kept, as the old engine did.
fn unusual(hours: &HashMap<i64, f64>, current: i64) -> Option<(f64, f64, f64, f64)> {
    let observed = *hours.get(&current)?;
    let past: Vec<f64> = hours.iter().filter(|(h, _)| **h < current && **h >= current - WINDOW_HOURS).map(|(_, v)| *v).collect();
    if past.len() < MIN_HOURS {
        return None;
    }
    let (mean, sd) = stats(&past);
    if sd < 1e-6 {
        return None;
    }
    let z = (observed - mean) / sd;
    (z > Z).then_some((observed, mean, sd, z))
}

/// (tenant, rule, entity, hour) already raised, so an hour is never raised twice.
fn raised() -> &'static Mutex<HashSet<(String, u32, String, i64)>> {
    static R: std::sync::OnceLock<Mutex<HashSet<(String, u32, String, i64)>>> = std::sync::OnceLock::new();
    R.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct Row {
    entity: String,
    hour: i64,
    n: f64,
    agent_id: String,
    agent_name: String,
}

async fn check_tenant(state: &AppState, tenant: &str, current: i64) -> Vec<siem_core::Alert> {
    let since = (current - WINDOW_HOURS - 1) * 3_600_000;
    let until = (current + 1) * 3_600_000;
    let mut out = Vec::new();
    for m in &MODELS {
        let sql = format!(
            "SELECT {entity} AS entity, intDiv(toInt64(timestamp), 3600000) AS hour, toFloat64({count}) AS n, \
             anyLast(agent_id) AS agent_id, anyLast(JSONExtractString(raw_metadata, 'hostname')) AS agent_name \
             FROM (SELECT timestamp, agent_id, raw_metadata, JSONExtractString(raw_metadata, 'data_json') AS dj FROM siem_events \
                   WHERE timestamp >= ? AND timestamp < ? AND position(raw_metadata, ?) > 0) \
             WHERE JSONExtractString(dj, 'win', 'system', 'eventID') = ? AND JSONExtractString(dj, 'win', 'system', 'providerName') = ? AND entity != '' \
             GROUP BY entity, hour",
            entity = m.entity,
            count = m.count,
        );
        let rows: Vec<Row> = match state
            .db
            .tenant_client(tenant)
            .query(&sql)
            .bind(since)
            .bind(until)
            .bind(format!("\"eventID\\\":\\\"{}\\\"", m.event_id))
            .bind(m.event_id)
            .bind(m.provider)
            .fetch_all()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("UEBA {} for tenant {tenant}: {e}", m.what);
                continue;
            }
        };
        let mut by_entity: HashMap<String, (HashMap<i64, f64>, String, String)> = HashMap::new();
        for r in rows {
            if m.of == "user" && !is_person(&r.entity) {
                continue;
            }
            let e = by_entity.entry(r.entity).or_insert_with(|| (HashMap::new(), String::new(), String::new()));
            if r.hour == current {
                (e.1, e.2) = (r.agent_id, r.agent_name);
            }
            e.0.insert(r.hour, r.n);
        }
        for (entity, (hours, agent_id, agent_name)) in by_entity {
            let Some((obs, mean, sd, z)) = unusual(&hours, current) else { continue };
            if !raised().lock().unwrap().insert((tenant.to_string(), m.rule, entity.clone(), current)) {
                continue;
            }
            out.push(alert(tenant, m, &entity, &agent_id, &agent_name, current, obs, mean, sd, z));
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn alert(tenant: &str, m: &Model, entity: &str, agent_id: &str, agent_name: &str, hour: i64, obs: f64, mean: f64, sd: f64, z: f64) -> siem_core::Alert {
    let at = chrono::DateTime::from_timestamp(hour * 3600, 0).map(|d| d.format("%Y-%m-%d %H:00 UTC").to_string()).unwrap_or_default();
    let description = format!("UEBA: unusual number of {} for {} {}", m.what, m.of, entity);
    let full_log = format!(
        "{} {entity} had {obs:.0} {} in the hour from {at}; normally {mean:.1} (± {sd:.1}) over the last 7 days, {z:.1} standard deviations above.",
        if m.of == "user" { "User" } else { "Computer" },
        m.what
    );
    let mut data: HashMap<String, serde_json::Value> = HashMap::new();
    data.insert("ueba".into(), serde_json::json!({ "model": m.what, "entity": entity, "entity_type": m.of, "hour": at, "observed": obs, "mean": mean, "std_dev": sd, "z_score": z }));
    let a = siem_core::Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        rule: siem_core::RuleAlertInfo {
            id: m.rule,
            level: m.level,
            description,
            groups: vec!["ueba".into(), "anomaly".into()],
            mitre: Some(siem_core::MitreAttack { id: m.mitre.0.into(), tactic: m.mitre.1.into(), technique: m.mitre.2.into() }),
        },
        agent: siem_core::AgentAlertInfo { id: if agent_id.is_empty() { "000".into() } else { agent_id.into() }, name: agent_name.into(), ip: String::new() },
        manager: None,
        decoder: None,
        full_log,
        decoded: siem_core::DecodedFields {
            decoder_name: "ueba".into(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            user: (m.of == "user").then(|| entity.to_string()),
            program_name: None,
            process_id: None,
            file_path: None,
            action: None,
            status: None,
            extra: HashMap::new(),
        },
        location: "ueba".into(),
        data,
    };
    crate::tenancy::tag_alert(a, tenant)
}

/// Every hour, 5 minutes past: the hour that just ended, for every client with the SIEM module.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            let now = chrono::Utc::now().timestamp();
            let next = (now / 3600 + 1) * 3600 + 300;
            tokio::time::sleep(std::time::Duration::from_secs((next - now).max(60) as u64)).await;
            let current = chrono::Utc::now().timestamp() / 3600 - 1;
            let tenants: Vec<(String, Vec<String>)> = state.tenants.read().unwrap().iter().filter(|t| t.active).map(|t| (crate::tenancy::normalize_tenant(&t.id), t.features.clone())).collect();
            let mut all = vec![(crate::tenancy::DEFAULT_TENANT.to_string(), Vec::new())];
            all.extend(tenants.into_iter().filter(|(id, _)| id != crate::tenancy::DEFAULT_TENANT));
            // several tenants at once (bounded, so ClickHouse is not flooded)
            futures_util::StreamExt::for_each_concurrent(futures_util::stream::iter(all), crate::TENANTS_AT_ONCE, |(tenant, features)| {
                let state = &state;
                async move {
                    let features = crate::licence::features_for(&tenant).unwrap_or(features);
                    if !provigil_common::modules::client_has(&features, provigil_common::modules::SIEM) {
                        return;
                    }
                    let alerts = check_tenant(state, &tenant, current).await;
                    if !alerts.is_empty() {
                        tracing::info!("UEBA: {} unusual hour(s) for tenant {tenant}", alerts.len());
                        let json: Vec<serde_json::Value> = alerts.iter().map(|a| serde_json::to_value(a).unwrap_or_default()).collect();
                        crate::provigil_manager::deliver(state, alerts, json).await;
                    }
                }
            })
            .await;
            // forget hours long past
            raised().lock().unwrap().retain(|k| k.3 >= current - 2);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hours(pairs: &[(i64, f64)]) -> HashMap<i64, f64> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn an_unusual_hour() {
        // 30 learned hours of 2-4 logons, then 40 in the hour just ended
        let mut h: Vec<(i64, f64)> = (0..30).map(|i| (1000 + i, 2.0 + (i % 3) as f64)).collect();
        h.push((1030, 40.0));
        let (obs, mean, sd, z) = unusual(&hours(&h), 1030).unwrap();
        assert_eq!(obs, 40.0);
        assert!((mean - 3.0).abs() < 0.1 && sd > 0.5 && z > 3.0);
        // the same hour at a normal level is not unusual
        h.pop();
        h.push((1030, 4.0));
        assert!(unusual(&hours(&h), 1030).is_none());
    }

    #[test]
    fn learns_before_judging() {
        let mut h: Vec<(i64, f64)> = (0..10).map(|i| (1000 + i, 2.0 + (i % 2) as f64)).collect();
        h.push((1010, 500.0));
        assert!(unusual(&hours(&h), 1010).is_none(), "fewer than 24 learned hours: no verdict");
        let flat: Vec<(i64, f64)> = (0..30).map(|i| (1000 + i, 5.0)).chain([(1030, 9.0)]).collect();
        assert!(unusual(&hours(&flat), 1030).is_none(), "no spread: no verdict (as before)");
        let old: Vec<(i64, f64)> = (0..30).map(|i| (i, 2.0 + (i % 3) as f64)).chain([(1000, 40.0)]).collect();
        assert!(unusual(&hours(&old), 1000).is_none(), "only the last 7 days count");
    }

    #[test]
    fn people_only() {
        for u in ["alice", "ravi.k"] {
            assert!(is_person(u));
        }
        for u in ["pc-01$", "system", "local service", "dwm-1", "umfd-0", "anonymous logon", ""] {
            assert!(!is_person(u), "{u}");
        }
        let a = alert("acm", &MODELS[1], "alice", "001", "PC-01", 500_000, 40.0, 3.0, 1.2, 30.8);
        assert_eq!(a.rule.id, 930002);
        assert!(a.full_log.contains("User alice had 40 failed logons"));
        assert_eq!(a.data["tenant_id"], "acm");
    }
}
