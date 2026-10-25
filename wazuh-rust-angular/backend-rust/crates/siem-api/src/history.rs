//! History for the SIEM pages (dashboard, MITRE, compliance, FIM, reports, rule
//! hit counts, health, ARIA, AI chat): the caller's tenant's alerts and events
//! of a time window, read from ClickHouse. The in-memory window only feeds the
//! live view; it is used here only while ClickHouse is down. The manager's files
//! (alerts.json, archives.json) stay as the backup copy.

use siem_core::{Alert, RawEvent};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// The window the history pages show.
pub const DEFAULT_HOURS: u32 = 7 * 24;
// shortcut: rows are loaded and counted in Rust; move the counts into SQL
// (GROUP BY) when a tenant has more alerts per window than this.
pub const MAX_ROWS: usize = 50_000;

fn since_ms(hours: u32) -> u64 {
    (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(hours as u64 * 3_600_000)
}

/// The tenant's alerts of the last `hours`, oldest first (like the memory list).
pub async fn alerts(state: &AppState, ctx: &AuthCtx, hours: u32) -> Vec<Alert> {
    match state.db.alerts_since(&ctx.scope(), since_ms(hours), MAX_ROWS).await {
        Some(mut v) => {
            v.reverse();
            v
        }
        None => crate::scoped_alerts(state, ctx),
    }
}

/// The tenant's events of the last `hours`, oldest first.
pub async fn events(state: &AppState, ctx: &AuthCtx, hours: u32) -> Vec<RawEvent> {
    match state.db.events_since(&ctx.scope(), since_ms(hours), MAX_ROWS).await {
        Some(mut v) => {
            v.reverse();
            v
        }
        None => crate::scoped_events(state, ctx),
    }
}

/// The cross-tenant admin views: every tenant for a super admin who picked
/// none (each tenant's share of [`MAX_ROWS`]), else the caller's tenant.
pub async fn admin_alerts(state: &AppState, ctx: &AuthCtx, hours: u32) -> Vec<Alert> {
    if !(ctx.is_super() && ctx.requested_tenant.is_none()) {
        return alerts(state, ctx, hours).await;
    }
    if !state.db.is_connected() {
        return state.alerts.read().unwrap().clone();
    }
    let tenants = crate::predictions::tenant_ids(state);
    let per = (MAX_ROWS / tenants.len().max(1)).max(1000);
    let mut all = Vec::new();
    for t in &tenants {
        all.extend(state.db.alerts_since(t, since_ms(hours), per).await.unwrap_or_default());
    }
    all.sort_by_key(|a| a.timestamp);
    all
}

pub async fn admin_events(state: &AppState, ctx: &AuthCtx, hours: u32) -> Vec<RawEvent> {
    if !(ctx.is_super() && ctx.requested_tenant.is_none()) {
        return events(state, ctx, hours).await;
    }
    if !state.db.is_connected() {
        return state.events.read().unwrap().clone();
    }
    let tenants = crate::predictions::tenant_ids(state);
    let per = (MAX_ROWS / tenants.len().max(1)).max(1000);
    let mut all = Vec::new();
    for t in &tenants {
        all.extend(state.db.events_since(t, since_ms(hours), per).await.unwrap_or_default());
    }
    all.sort_by_key(|e| e.timestamp);
    all
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
