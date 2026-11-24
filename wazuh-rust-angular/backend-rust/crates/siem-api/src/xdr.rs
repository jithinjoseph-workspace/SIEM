//! `GET /api/xdr/alerts`: the XDR queue (it replaces the old siem-engine's unified queue, same
//! answer shape): XDR incidents (a host alert and an NDR detection on the same host, made by
//! corroboration.rs), host alerts of level 7 or more, and NDR detections, newest first. SIEM
//! items need the `siem` module and NDR items `ndr`. Filters: source, severity, status; pages.

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::Json;
use provigil_common::modules::{allows, NDR, SIEM};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// Host alerts from this level are in the queue (as for XDR incidents).
const LEVEL: u8 = 7;
/// The deepest the pages go.
const MAX_DEPTH: u32 = 5000;

#[derive(Deserialize)]
pub struct Params {
    source: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

#[derive(clickhouse::Row, Deserialize)]
struct Item {
    alert_id: String,
    ts: u64,
    severity: String,
    rule_id: String,
    rule_name: String,
    title: String,
    description: String,
    hosts: Vec<String>,
    mitre: Vec<String>,
    status: String,
}

/// The SQL severity of a host alert from its level (as the alert views grade it).
const LEVEL_SEVERITY: &str = "multiIf(rule_level >= 12, 'CRITICAL', rule_level >= 10, 'HIGH', 'MEDIUM')";

/// Each source's items as one SELECT with the queue's columns, and a WHERE for its filters.
fn source_sql(source: &str) -> (&'static str, &'static str) {
    match source {
        "corroborated" => (
            "SELECT incident_id AS alert_id, timestamp AS ts, upper(severity) AS severity, '' AS rule_id, ndr_signature AS rule_name, title, \
             concat('Host alert: ', siem_rule_description, '. Network: ', ndr_signature, if(attacker_ip != '', concat(' (other side ', attacker_ip, ')'), '')) AS description, \
             arrayFilter(x -> x != '', [agent_name, host_ip]) AS hosts, CAST([], 'Array(String)') AS mitre, \
             if(status = 'open', 'New', concat(upper(substring(status, 1, 1)), substring(status, 2))) AS status FROM xdr_incidents",
            "1",
        ),
        "siem" => (
            // the level is a bound value: see `fetch`
            "SELECT id AS alert_id, timestamp AS ts, LEVEL_SEVERITY AS severity, toString(rule_id) AS rule_id, rule_description AS rule_name, \
             rule_description AS title, full_log AS description, arrayFilter(x -> x != '', [agent_name, agent_ip]) AS hosts, \
             arrayFilter(x -> x != '', [mitre_id]) AS mitre, 'New' AS status FROM siem_alerts",
            "rule_level >= LEVEL",
        ),
        _ => (
            "SELECT concat(community_id, '@', toString(toUnixTimestamp(timestamp))) AS alert_id, toUInt64(toUnixTimestamp(timestamp)) * 1000 AS ts, \
             upper(toString(severity)) AS severity, '' AS rule_id, if(notEmpty(sigma_hits), sigma_hits[1], if(notEmpty(tags), tags[1], 'NDR detection')) AS rule_name, \
             concat(if(notEmpty(sigma_hits), sigma_hits[1], if(notEmpty(tags), tags[1], 'NDR detection')), ': ', src_ip, ' -> ', dst_ip) AS title, \
             arrayStringConcat(reasons, '; ') AS description, arrayFilter(x -> x != '', [src_ip, dst_ip]) AS hosts, CAST([], 'Array(String)') AS mitre, 'New' AS status FROM ndr_hits",
            "1",
        ),
    }
}

/// One source's page (newest `depth`) and its total, with the filters.
async fn fetch(state: &AppState, tenant: &str, source: &str, severity: Option<&str>, status: Option<&str>, depth: u32) -> Result<(Vec<Item>, u64), String> {
    let (select, cond) = source_sql(source);
    let select = select.replace("LEVEL_SEVERITY", LEVEL_SEVERITY);
    let cond = cond.replace("LEVEL", &LEVEL.to_string());
    // the source's rows with the queue's columns; the filters work on those columns
    let mut filter = String::from("1");
    if severity.is_some() {
        filter.push_str(" AND severity = ?");
    }
    if status.is_some() {
        filter.push_str(" AND status = ?");
    }
    let inner = format!("SELECT * FROM ({select} WHERE {cond}) WHERE {filter}");
    let client = state.db.tenant_client(tenant);
    let bind = |mut q: clickhouse::query::Query| {
        if let Some(s) = severity {
            q = q.bind(s);
        }
        if let Some(s) = status {
            q = q.bind(s);
        }
        q
    };
    let rows = bind(client.query(&format!("{inner} ORDER BY ts DESC LIMIT {depth}"))).fetch_all::<Item>();
    let total = bind(client.query(&format!("SELECT count() FROM ({inner})"))).fetch_one::<u64>();
    let (rows, total) = tokio::join!(rows, total);
    Ok((rows.map_err(|e| e.to_string())?, total.map_err(|e| e.to_string())?))
}

/// Newest first across the sources, then the page.
fn merge(mut items: Vec<Item>, offset: u32, limit: u32) -> Vec<Item> {
    items.sort_by(|a, b| b.ts.cmp(&a.ts));
    items.into_iter().skip(offset as usize).take(limit as usize).collect()
}

/// `GET /api/xdr/alerts`
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Query(p): Query<Params>) -> (StatusCode, Json<Value>) {
    let limit = p.limit.unwrap_or(50).clamp(1, 500);
    let page = p.page.unwrap_or(1).max(1).min(MAX_DEPTH / limit);
    let offset = (page - 1) * limit;
    let severity = p.severity.as_deref().map(str::to_uppercase).filter(|s| s != "ALL");
    let status = p.status.as_deref().filter(|s| *s != "all");
    let wanted = p.source.as_deref().filter(|s| *s != "all");
    let (siem, ndr) = (allows(&ctx.role, &ctx.features, SIEM), allows(&ctx.role, &ctx.features, NDR));
    let sources: Vec<&str> = [("corroborated", siem), ("siem", siem), ("ndr", ndr)]
        .into_iter()
        .filter(|(s, on)| *on && wanted.is_none_or(|w| w == *s))
        .map(|(s, _)| s)
        .collect();
    let tenant = ctx.scope();
    let mut items = Vec::new();
    let mut total = 0;
    for source in sources {
        match fetch(&state, &tenant, source, severity.as_deref(), status, offset + limit).await {
            Ok((rows, n)) => {
                items.extend(rows.into_iter().map(|r| (source, r)));
                total += n;
            }
            // a client without NDR tables (never had a sensor): no NDR items
            Err(e) if source == "ndr" => tracing::debug!("XDR queue: no NDR detections for {tenant}: {e}"),
            Err(e) => {
                tracing::error!("XDR queue ({source}) for {tenant}: {e}");
                return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "Failed to query alerts", "detail": e })));
            }
        }
    }
    let sources_of: std::collections::HashMap<String, &str> = items.iter().map(|(s, r)| (r.alert_id.clone(), *s)).collect();
    let alerts: Vec<Value> = merge(items.into_iter().map(|(_, r)| r).collect(), offset, limit)
        .into_iter()
        .map(|r| {
            json!({
                "alert_id": r.alert_id, "tenant_id": tenant, "source": sources_of.get(&r.alert_id).copied().unwrap_or(""),
                "severity": r.severity, "rule_id": r.rule_id, "rule_name": r.rule_name, "title": r.title, "description": r.description,
                "affected_hosts": r.hosts, "mitre_techniques": r.mitre, "status": r.status,
                "created_at": chrono::DateTime::from_timestamp_millis(r.ts as i64).map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect();
    let pages = (total as u32).div_ceil(limit).max(1);
    (StatusCode::OK, Json(json!({ "alerts": alerts, "total": total, "page": page, "limit": limit, "pages": pages })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, ts: u64) -> Item {
        Item { alert_id: id.into(), ts, severity: "HIGH".into(), rule_id: String::new(), rule_name: String::new(), title: String::new(), description: String::new(), hosts: vec![], mitre: vec![], status: "New".into() }
    }

    #[test]
    fn newest_first_across_sources_then_the_page() {
        let all = vec![item("siem-old", 1), item("ndr-new", 5), item("xdr-mid", 3), item("siem-new", 4)];
        let ids = |v: Vec<Item>| v.into_iter().map(|i| i.alert_id).collect::<Vec<_>>();
        assert_eq!(ids(merge(all, 0, 2)), ["ndr-new", "siem-new"]);
        let all = vec![item("siem-old", 1), item("ndr-new", 5), item("xdr-mid", 3), item("siem-new", 4)];
        assert_eq!(ids(merge(all, 2, 2)), ["xdr-mid", "siem-old"]);
    }

    #[test]
    fn every_source_has_the_queue_columns() {
        for s in ["corroborated", "siem", "ndr"] {
            let (select, _) = source_sql(s);
            for col in ["AS alert_id", "AS ts", "AS severity", "AS rule_id", "AS rule_name", "title", "AS description", "AS hosts", "AS mitre", "AS status"] {
                assert!(select.contains(col), "{s}: {col}");
            }
        }
    }
}
