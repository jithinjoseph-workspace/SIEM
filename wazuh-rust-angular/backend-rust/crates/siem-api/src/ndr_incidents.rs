//! NDR incidents: high and critical NDR detections open cases on their own, as host alerts do
//! (incidents.rs), so an NDR customer's SOAR page fills without hand-made playbooks. One case per
//! detection, internal host and day ("one case per computer and rule"), tagged `ndr-incident` and
//! `key:<key>`. While it is open the case takes that day's further detections of its key; a case
//! someone closed takes no more, and newer detections open a new case. Only for tenants with the
//! NDR module. Read from the tenant's `ndr_hits` every minute; restart-safe (cases are found again
//! by their key tag).

use std::collections::HashMap;
use std::net::IpAddr;

use crate::AppState;

const EVERY_SECS: u64 = 60;
pub const TAG: &str = "ndr-incident";
/// Detection ids kept per case (the count in the description goes on).
const MAX_IDS: usize = 200;
const CLOSED: &str = "('Closed', 'Resolved', 'False Positive')";

#[derive(Debug, Clone, clickhouse::Row, serde::Deserialize)]
pub struct Hit {
    pub id: String,
    pub ts: u32,
    pub name: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub sev: String,
}

const HITS_SQL: &str = "SELECT concat(community_id, '@', toString(toUnixTimestamp(timestamp))) AS id, toUInt32(toUnixTimestamp(timestamp)) AS ts, \
     if(notEmpty(sigma_hits), sigma_hits[1], if(notEmpty(tags), tags[1], 'NDR detection')) AS name, src_ip, dst_ip, upper(toString(severity)) AS sev \
     FROM ndr_hits WHERE timestamp >= toDateTime(today()) AND upper(toString(severity)) IN ('HIGH', 'CRITICAL') ORDER BY timestamp LIMIT 20000";

#[derive(clickhouse::Row, serde::Deserialize)]
struct CaseRow {
    id: String,
    status: String,
    tags: Vec<String>,
    hit_ids: Vec<String>,
    closed: u32,
}

/// One case's worth of detections.
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub key: String,
    /// the internal computer
    pub host: String,
    pub name: String,
    /// (detection id, time), oldest first
    pub hits: Vec<(String, u32)>,
    pub critical: bool,
    pub src_ip: String,
    pub dst_ip: String,
    pub community_id: String,
}

fn internal(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => v.is_private() || v.is_loopback() || v.is_link_local(),
        Ok(IpAddr::V6(v)) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

/// The day's detections by detection, internal host (the source unless only the destination is
/// internal) and day.
pub fn group(hits: &[Hit], day: &str) -> Vec<Group> {
    let mut by: HashMap<String, Group> = HashMap::new();
    let mut order = Vec::new();
    for h in hits {
        let host = if internal(&h.src_ip) || !internal(&h.dst_ip) { &h.src_ip } else { &h.dst_ip };
        let key = format!("ndr|{host}|{}|{day}", h.name);
        let g = by.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            Group {
                key: key.clone(),
                host: host.clone(),
                name: h.name.clone(),
                hits: Vec::new(),
                critical: false,
                src_ip: h.src_ip.clone(),
                dst_ip: h.dst_ip.clone(),
                community_id: h.id.split('@').next().unwrap_or_default().to_string(),
            }
        });
        g.hits.push((h.id.clone(), h.ts));
        g.critical |= h.sev == "CRITICAL";
    }
    order.into_iter().filter_map(|k| by.remove(&k)).collect()
}

fn describe(g: &Group, hits: &[(String, u32)]) -> String {
    let at = |t: u32| chrono::DateTime::from_timestamp(i64::from(t), 0).map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default();
    format!(
        "Incident opened automatically: {} network detection(s) involving {} between {} and {} UTC ({} -> {}). Detection: {}.",
        hits.len(),
        g.host,
        at(hits.first().map_or(0, |h| h.1)),
        at(hits.last().map_or(0, |h| h.1)),
        g.src_ip,
        g.dst_ip,
        g.name
    )
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(45)).await;
        loop {
            if state.db.is_connected() {
                let tenants: Vec<(String, Vec<String>)> = state.tenants.read().unwrap().iter().filter(|t| t.active).map(|t| (crate::tenancy::normalize_tenant(&t.id), t.features.clone())).collect();
                let mut all = vec![(crate::tenancy::DEFAULT_TENANT.to_string(), Vec::new())];
                all.extend(tenants.into_iter().filter(|(id, _)| id != crate::tenancy::DEFAULT_TENANT));
                for (tenant, features) in all {
                    let features = crate::licence::features_for(&tenant).unwrap_or(features);
                    if provigil_common::modules::client_has(&features, provigil_common::modules::NDR) {
                        cycle(&state, &tenant).await;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(EVERY_SECS)).await;
        }
    });
}

async fn cycle(state: &AppState, tenant: &str) {
    let client = state.db.tenant_client(tenant);
    // a tenant without NDR tables (no sensor yet): nothing to do
    let Ok(hits) = client.query(HITS_SQL).fetch_all::<Hit>().await else { return };
    if hits.is_empty() {
        return;
    }
    let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let cases: Vec<CaseRow> = match client
        .query("SELECT id, status, tags, hit_ids, toUInt32(ifNull(toUnixTimestamp(closed_at), 0)) AS closed FROM soar_cases FINAL WHERE has(tags, ?) AND created_at >= now() - INTERVAL 2 DAY")
        .bind(TAG)
        .fetch_all()
        .await
    {
        Ok(c) => c,
        Err(e) => return tracing::warn!("NDR incidents of {tenant}: cases not read: {e}"),
    };
    let closed = |s: &str| ["Closed", "Resolved", "False Positive"].contains(&s);
    for g in group(&hits, &day) {
        let tag = format!("key:{}", g.key);
        let mine: Vec<&CaseRow> = cases.iter().filter(|c| c.tags.contains(&tag)).collect();
        if let Some(open) = mine.iter().find(|c| !closed(&c.status)) {
            // detections since the case opened (the ones before a closed case belong to that one)
            let after = mine.iter().filter(|c| closed(&c.status)).map(|c| c.closed).max().unwrap_or(0);
            let hits: Vec<(String, u32)> = g.hits.iter().filter(|h| h.1 > after).cloned().collect();
            let ids: Vec<String> = hits.iter().map(|h| h.0.clone()).take(MAX_IDS).collect();
            if ids.len() == open.hit_ids.len() {
                continue;
            }
            let sql = format!(
                "INSERT INTO soar_cases ({c}) SELECT id, case_number, title, ? AS description, ? AS severity, priority, status, assigned_to, src_ip, dst_ip, community_id, ? AS hit_ids, tags, tenant_id, created_at, now() AS updated_at, closed_at FROM soar_cases FINAL WHERE id = ? AND status NOT IN {CLOSED}",
                c = "id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, hit_ids, tags, tenant_id, created_at, updated_at, closed_at"
            );
            let sev = if g.critical { "CRITICAL" } else { "HIGH" };
            if let Err(e) = client.query(&sql).bind(describe(&g, &hits)).bind(sev).bind(&ids).bind(&open.id).execute().await {
                tracing::warn!("NDR incident {} of {tenant} not updated: {e}", open.id);
            }
            continue;
        }
        // no open case: one for the detections after the last closed case of this key
        let after = mine.iter().map(|c| c.closed).max().unwrap_or(0);
        let hits: Vec<(String, u32)> = g.hits.iter().filter(|h| h.1 > after).cloned().collect();
        if hits.is_empty() {
            continue;
        }
        let id = uuid::Uuid::new_v4().to_string();
        let number = crate::soar::next_case_number(state, tenant).await;
        let now = chrono::Utc::now().timestamp();
        let newest: u32 = client.query("SELECT toUInt32(toUnixTimestamp(max(created_at))) FROM soar_cases").fetch_one().await.unwrap_or(0);
        let created = crate::incidents::unique_second(now, i64::from(newest));
        let sev = if g.critical { "CRITICAL" } else { "HIGH" };
        let ids: Vec<String> = hits.iter().map(|h| h.0.clone()).take(MAX_IDS).collect();
        let tags = vec![TAG.to_string(), tag];
        let made = client
            .query("INSERT INTO soar_cases (id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, hit_ids, tags, tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'New', '', ?, ?, ?, ?, ?, ?, toDateTime(?), toDateTime(?))")
            .bind(&id).bind(&number).bind(format!("{}: {}", g.host, g.name)).bind(describe(&g, &hits)).bind(sev).bind(crate::incidents::priority(sev))
            .bind(&g.src_ip).bind(&g.dst_ip).bind(&g.community_id).bind(&ids).bind(&tags).bind(tenant).bind(created).bind(created)
            .execute()
            .await;
        match made {
            Ok(()) => {
                tracing::info!("NDR incident {number} opened for {tenant}: {} on {}", g.name, g.host);
                // like every new case: its history starts, and it is triaged (recommend only)
                crate::case_detail::created(state, tenant, &id, "ProVigil").await;
                crate::case_ai::spawn_for_new_case(state.clone(), tenant.to_string(), id);
            }
            Err(e) => tracing::warn!("NDR incident of {tenant} not opened: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(id: &str, ts: u32, name: &str, src: &str, dst: &str, sev: &str) -> Hit {
        Hit { id: format!("{id}@{ts}"), ts, name: name.into(), src_ip: src.into(), dst_ip: dst.into(), sev: sev.into() }
    }

    #[test]
    fn one_case_per_detection_internal_host_and_day() {
        let hits = vec![
            hit("1:a", 10, "ET MALWARE C2", "10.0.0.5", "185.220.101.1", "HIGH"),
            // the same host and detection to another C2 address: the same case
            hit("1:b", 20, "ET MALWARE C2", "10.0.0.5", "185.220.101.2", "CRITICAL"),
            // inbound: the internal destination is the host
            hit("1:c", 30, "ET SCAN inbound", "45.155.205.1", "192.168.1.20", "HIGH"),
            // another detection on the same host: its own case
            hit("1:d", 40, "ET TROJAN beacon", "10.0.0.5", "91.92.240.1", "HIGH"),
        ];
        let g = group(&hits, "2026-11-25");
        assert_eq!(g.len(), 3);
        assert_eq!(g[0].key, "ndr|10.0.0.5|ET MALWARE C2|2026-11-25");
        assert_eq!(g[0].hits.len(), 2);
        assert!(g[0].critical, "a critical detection makes the case critical");
        assert_eq!(g[0].community_id, "1:a");
        assert_eq!(g[1].host, "192.168.1.20");
        assert_eq!(g[2].name, "ET TROJAN beacon");
        assert!(describe(&g[0], &g[0].hits).contains("2 network detection(s) involving 10.0.0.5"));
    }
}
