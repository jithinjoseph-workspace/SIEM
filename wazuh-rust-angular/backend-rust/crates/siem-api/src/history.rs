//! History for the SIEM pages (dashboard, MITRE, compliance, FIM, reports, rule
//! hit counts, health, ARIA, AI chat): the caller's tenant's alerts and events
//! of a time window, read from ClickHouse. ClickHouse computes the counts, groups
//! and time buckets, and sends only those (or the newest rows a page lists): the
//! window is never loaded into siem-api. The in-memory window only feeds the live
//! view; it is used here only while ClickHouse is down. The manager's files
//! (alerts.json, archives.json) stay as the backup copy.

use std::collections::HashMap;

use siem_core::{Alert, RawEvent};

use crate::db::{AlertField, WindowCounts};
use crate::tenancy::AuthCtx;
use crate::AppState;

/// The window the history pages show.
pub const DEFAULT_HOURS: u32 = 7 * 24;
/// The most rows a page gets as a list (FIM changes, alert lists).
pub const MAX_ROWS: usize = 50_000;

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn since_ms(hours: u32) -> u64 {
    now_ms().saturating_sub(hours as u64 * 3_600_000)
}

/// The tenants an aggregate covers: every tenant for a super admin who picked
/// none (the cross-tenant admin views), else the caller's tenant.
fn scopes(state: &AppState, ctx: &AuthCtx, all_tenants: bool) -> Vec<String> {
    if all_tenants && ctx.is_super() && ctx.requested_tenant.is_none() {
        crate::predictions::tenant_ids(state)
    } else {
        vec![ctx.scope()]
    }
}

/// The in-memory window (ClickHouse down): the caller's tenant, or every tenant for the admin views.
fn mem_alerts(state: &AppState, ctx: &AuthCtx, all_tenants: bool) -> Vec<Alert> {
    if all_tenants && ctx.is_super() && ctx.requested_tenant.is_none() {
        state.alerts.read().unwrap().clone()
    } else {
        crate::scoped_alerts(state, ctx)
    }
}

fn mem_events(state: &AppState, ctx: &AuthCtx, all_tenants: bool) -> Vec<RawEvent> {
    if all_tenants && ctx.is_super() && ctx.requested_tenant.is_none() {
        state.events.read().unwrap().clone()
    } else {
        crate::scoped_events(state, ctx)
    }
}

/// Counts of the last `hours` (and of its last hour).
pub async fn counts(state: &AppState, ctx: &AuthCtx, hours: u32) -> WindowCounts {
    counts_in(state, ctx, hours, false).await
}

/// [`counts`] summed over every tenant for a super admin (the cross-tenant views).
pub async fn admin_counts(state: &AppState, ctx: &AuthCtx, hours: u32) -> WindowCounts {
    counts_in(state, ctx, hours, true).await
}

async fn counts_in(state: &AppState, ctx: &AuthCtx, hours: u32, all_tenants: bool) -> WindowCounts {
    let mut total = WindowCounts::default();
    for t in scopes(state, ctx, all_tenants) {
        match state.db.window_counts(&t, since_ms(hours), since_ms(1)).await {
            Some(c) => total.merge(&c),
            None => return mem_counts(state, ctx, all_tenants),
        }
    }
    total
}

fn mem_counts(state: &AppState, ctx: &AuthCtx, all_tenants: bool) -> WindowCounts {
    let hour_ago = chrono::Utc::now() - chrono::Duration::hours(1);
    let events = mem_events(state, ctx, all_tenants);
    let mut c = WindowCounts { events: events.len() as u64, events_1h: events.iter().filter(|e| e.timestamp >= hour_ago).count() as u64, ..Default::default() };
    for a in mem_alerts(state, ctx, all_tenants) {
        c.add_alert(a.rule.level, a.timestamp >= hour_ago);
    }
    c
}

/// Alerts per (rule id, description) of the last `hours`, most frequent first.
pub async fn top_rules(state: &AppState, ctx: &AuthCtx, hours: u32, limit: usize) -> Vec<(u32, String, u64)> {
    if let Some(v) = state.db.top_rules(&ctx.scope(), since_ms(hours), limit).await {
        return v;
    }
    let mut m: HashMap<(u32, String), u64> = HashMap::new();
    for a in crate::scoped_alerts(state, ctx) {
        *m.entry((a.rule.id, a.rule.description)).or_default() += 1;
    }
    sorted_top(m.into_iter(), limit).into_iter().map(|((id, d), n)| (id, d, n)).collect()
}

/// Alerts per source or destination IP of the last `hours` (most frequent first),
/// over every tenant for a super admin when `all_tenants`.
pub async fn top_values(state: &AppState, ctx: &AuthCtx, hours: u32, field: AlertField, limit: usize, all_tenants: bool) -> Vec<(String, u64)> {
    let mut m: HashMap<String, u64> = HashMap::new();
    for t in scopes(state, ctx, all_tenants) {
        match state.db.top_values(&t, since_ms(hours), field, limit).await {
            Some(v) => v.into_iter().for_each(|(k, n)| *m.entry(k).or_default() += n),
            None => {
                m.clear();
                for a in mem_alerts(state, ctx, all_tenants) {
                    let v = match field {
                        AlertField::SrcIp => a.decoded.src_ip,
                        AlertField::DstIp => a.decoded.dst_ip,
                    };
                    if let Some(v) = v.filter(|v| !v.is_empty()) {
                        *m.entry(v).or_default() += 1;
                    }
                }
                break;
            }
        }
    }
    sorted_top(m.into_iter(), limit)
}

/// Alerts per MITRE technique id of the last `hours`: (id, alerts, highest level).
pub async fn mitre_counts(state: &AppState, ctx: &AuthCtx, hours: u32) -> Vec<(String, u64, u8)> {
    if let Some(v) = state.db.mitre_counts(&ctx.scope(), since_ms(hours)).await {
        return v;
    }
    let mut m: HashMap<String, (u64, u8)> = HashMap::new();
    for a in crate::scoped_alerts(state, ctx) {
        if let Some(t) = a.rule.mitre {
            let e = m.entry(t.id).or_default();
            e.0 += 1;
            e.1 = e.1.max(a.rule.level);
        }
    }
    m.into_iter().map(|(id, (n, l))| (id, n, l)).collect()
}

/// Events of the last `hours` per protocol (most frequent first), and how many came
/// from network sensors; over every tenant for a super admin when `all_tenants`.
pub async fn event_breakdown(state: &AppState, ctx: &AuthCtx, hours: u32, all_tenants: bool) -> (Vec<(String, u64)>, u64) {
    let (mut m, mut network): (HashMap<String, u64>, u64) = (HashMap::new(), 0);
    for t in scopes(state, ctx, all_tenants) {
        match state.db.event_breakdown(&t, since_ms(hours)).await {
            Some((v, n)) => {
                v.into_iter().for_each(|(k, c)| *m.entry(k).or_default() += c);
                network += n;
            }
            None => {
                (m, network) = (HashMap::new(), 0);
                for e in mem_events(state, ctx, all_tenants) {
                    *m.entry(crate::db::event_protocol(&e.location, &e.message).to_string()).or_default() += 1;
                    network += crate::db::event_is_network(&serde_json::to_string(&e.source).unwrap_or_default(), &e.location) as u64;
                }
                break;
            }
        }
    }
    (sorted_top(m.into_iter(), usize::MAX), network)
}

/// The tenant's alerts in `buckets` slices of `bucket_ms` up to now, oldest first:
/// [critical 12+, high 8-11, medium 4-7, low 0-3] per slice.
pub async fn alert_buckets(state: &AppState, ctx: &AuthCtx, bucket_ms: u64, buckets: usize) -> Vec<[u64; 4]> {
    let now = now_ms();
    if let Some(v) = state.db.alert_buckets(&ctx.scope(), now, bucket_ms, buckets).await {
        return v;
    }
    let mut out = vec![[0u64; 4]; buckets];
    for a in crate::scoped_alerts(state, ctx) {
        let ago = now.saturating_sub(a.timestamp.timestamp_millis().max(0) as u64) / bucket_ms.max(1);
        if let Some(slot) = (ago as usize).checked_add(1).and_then(|x| buckets.checked_sub(x)) {
            out[slot][match a.rule.level {
                12.. => 0,
                8..=11 => 1,
                4..=7 => 2,
                _ => 3,
            }] += 1;
        }
    }
    out
}

/// The tenant's events in `buckets` slices of `bucket_ms` up to now, oldest first.
pub async fn event_buckets(state: &AppState, ctx: &AuthCtx, bucket_ms: u64, buckets: usize) -> Vec<u64> {
    let now = now_ms();
    if let Some(v) = state.db.event_buckets(&ctx.scope(), now, bucket_ms, buckets).await {
        return v;
    }
    let mut out = vec![0u64; buckets];
    for e in crate::scoped_events(state, ctx) {
        let ago = now.saturating_sub(e.timestamp.timestamp_millis().max(0) as u64) / bucket_ms.max(1);
        if let Some(slot) = (ago as usize).checked_add(1).and_then(|x| buckets.checked_sub(x)) {
            out[slot] += 1;
        }
    }
    out
}

/// The tenant's newest alerts of the last `hours` (newest first, at most `limit`);
/// with `ip`, only those whose source or destination is that IP.
pub async fn recent_alerts(state: &AppState, ctx: &AuthCtx, hours: u32, limit: usize, ip: Option<&str>) -> Vec<Alert> {
    if let Some(v) = state.db.recent_alerts(&ctx.scope(), since_ms(hours), limit, ip).await {
        return v;
    }
    let mut v: Vec<Alert> = crate::scoped_alerts(state, ctx)
        .into_iter()
        .filter(|a| ip.map_or(true, |ip| a.decoded.src_ip.as_deref() == Some(ip) || a.decoded.dst_ip.as_deref() == Some(ip)))
        .collect();
    v.reverse();
    v.truncate(limit);
    v
}

/// The tenant's alerts of the last `hours` whose stored alert contains `needle`
/// (e.g. `"syscheck"`), oldest first: ClickHouse filters them.
pub async fn alerts_containing(state: &AppState, ctx: &AuthCtx, hours: u32, needle: &str) -> Vec<Alert> {
    match state.db.alerts_since_containing(&ctx.scope(), since_ms(hours), MAX_ROWS, needle).await {
        Some(mut v) => {
            v.reverse();
            v
        }
        None => crate::scoped_alerts(state, ctx),
    }
}

/// The tenant's newest alert of the last `hours`.
pub async fn latest_alert(state: &AppState, ctx: &AuthCtx, hours: u32) -> Option<Alert> {
    recent_alerts(state, ctx, hours, 1, None).await.into_iter().next()
}

/// One alert of the tenant by id (ClickHouse, else memory).
pub async fn alert(state: &AppState, ctx: &AuthCtx, id: &str) -> Option<Alert> {
    if state.db.is_connected() {
        if let Some(a) = state.db.alert_by_id(&ctx.scope(), id).await {
            return Some(a);
        }
    }
    crate::scoped_alerts(state, ctx).into_iter().find(|a| a.id.to_string() == id)
}

/// One event of the tenant by id (ClickHouse, else memory).
pub async fn event(state: &AppState, ctx: &AuthCtx, id: &str) -> Option<RawEvent> {
    if let Some(e) = state.db.event_by_id(&ctx.scope(), id).await {
        return Some(e);
    }
    crate::scoped_events(state, ctx).into_iter().find(|e| e.id.to_string() == id)
}

/// The `limit` largest counts, largest first.
fn sorted_top<K: Ord>(it: impl Iterator<Item = (K, u64)>, limit: usize) -> Vec<(K, u64)> {
    let mut v: Vec<(K, u64)> = it.collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(limit);
    v
}
