//! `GET /api/xdr/alerts`: the XDR queue (it replaces the old siem-engine's unified queue, same
//! answer shape): XDR incidents (a host alert and an NDR detection on the same host, made by
//! corroboration.rs), and the high and critical host alerts and NDR detections, newest first.
//! Repeats are one item: a host alert per rule, host and day, an NDR detection per name, pair of
//! addresses and day, titled with the count ("591× ...") and opening the latest. Medium and low
//! stay on each module's alert pages. SIEM items need the `siem` module and NDR items `ndr`.
//! Filters: source, severity, status; pages.

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::Json;
use provigil_common::modules::{allows, NDR, SIEM};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// Host alerts from this level (high) are in the queue.
const MIN_LEVEL: u8 = 10;
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
    /// the case it is worked in (XDR incidents)
    case_id: String,
}

/// Each source's items as one SELECT with the queue's columns.
fn source_sql(source: &str) -> String {
    match source {
        // the case of the incident (corroboration.rs opens one) gives the status: worked and closed there
        "corroborated" => "SELECT incident_id AS alert_id, timestamp AS ts, upper(severity) AS severity, '' AS rule_id, ndr_signature AS rule_name, title,              concat('Host alert: ', siem_rule_description, '. Network: ', ndr_signature, if(attacker_ip != '', concat(' (other side ', attacker_ip, ')'), '')) AS description,              arrayFilter(x -> x != '', [agent_name, host_ip]) AS hosts, CAST([], 'Array(String)') AS mitre,              if(c_status != '', c_status, if(status = 'open', 'New', concat(upper(substring(status, 1, 1)), substring(status, 2)))) AS status, c_id AS case_id              FROM xdr_incidents LEFT JOIN (SELECT id AS c_id, status AS c_status, arrayJoin(arrayFilter(t -> startsWith(t, 'xdr:'), tags)) AS c_key FROM soar_cases FINAL WHERE has(tags, 'xdr-incident')) AS c              ON c.c_key = concat('xdr:', incident_id)"
            .to_string(),
        // grouped inside, the queue's columns outside (no alias hides a column it is made from)
        "siem" => SIEM_SQL.replace("MIN_LEVEL", &MIN_LEVEL.to_string()),
        _ => NDR_SQL.to_string(),
    }
}

const SIEM_SQL: &str = "SELECT a_id AS alert_id, a_ts AS ts, multiIf(a_lvl >= 12, 'CRITICAL', a_lvl >= 10, 'HIGH', 'MEDIUM') AS severity, toString(a_rule) AS rule_id, a_desc AS rule_name, if(a_n > 1, concat(toString(a_n), '× ', a_desc), a_desc) AS title, a_log AS description, arrayFilter(x -> x != '', [a_agent, a_ip]) AS hosts, arrayFilter(x -> x != '', [a_mitre]) AS mitre, 'New' AS status, '' AS case_id FROM (SELECT argMax(id, timestamp) AS a_id, max(timestamp) AS a_ts, max(rule_level) AS a_lvl, rule_id AS a_rule, any(rule_description) AS a_desc, count() AS a_n, argMax(full_log, timestamp) AS a_log, agent_name AS a_agent, any(agent_ip) AS a_ip, any(mitre_id) AS a_mitre FROM siem_alerts WHERE rule_level >= MIN_LEVEL GROUP BY rule_id, agent_name, toDate(toDateTime(intDiv(timestamp, 1000))))";

const NDR_SQL: &str = "SELECT concat(a_cid, '@', toString(toUnixTimestamp(a_ts))) AS alert_id, toUInt64(toUnixTimestamp(a_ts)) * 1000 AS ts, a_sev AS severity, '' AS rule_id, a_name AS rule_name, concat(if(a_n > 1, concat(toString(a_n), '× '), ''), a_name, ': ', a_src, ' -> ', a_dst) AS title, a_why AS description, arrayFilter(x -> x != '', [a_src, a_dst]) AS hosts, CAST([], 'Array(String)') AS mitre, 'New' AS status, '' AS case_id FROM (SELECT if(notEmpty(sigma_hits), sigma_hits[1], if(notEmpty(tags), tags[1], 'NDR detection')) AS a_name, src_ip AS a_src, dst_ip AS a_dst, argMax(community_id, timestamp) AS a_cid, max(timestamp) AS a_ts, if(countIf(upper(toString(severity)) = 'CRITICAL') > 0, 'CRITICAL', 'HIGH') AS a_sev, count() AS a_n, arrayStringConcat(argMax(reasons, timestamp), '; ') AS a_why FROM ndr_hits WHERE upper(toString(severity)) IN ('HIGH', 'CRITICAL') GROUP BY a_name, a_src, a_dst, toDate(timestamp))";

/// One source's page (newest `depth`) and its total, with the filters.
async fn fetch(state: &AppState, tenant: &str, source: &str, severity: Option<&str>, status: Option<&str>, depth: u32) -> Result<(Vec<Item>, u64), String> {
    let select = source_sql(source);
    // the source's rows with the queue's columns; the filters work on those columns
    let mut filter = String::from("1");
    if severity.is_some() {
        filter.push_str(" AND severity = ?");
    }
    if status.is_some() {
        filter.push_str(" AND status = ?");
    }
    let inner = format!("SELECT * FROM ({select}) WHERE {filter}");
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
                "affected_hosts": r.hosts, "mitre_techniques": r.mitre, "status": r.status, "case_id": r.case_id,
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
        Item { alert_id: id.into(), ts, severity: "HIGH".into(), rule_id: String::new(), rule_name: String::new(), title: String::new(), description: String::new(), hosts: vec![], mitre: vec![], status: "New".into(), case_id: String::new() }
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
    fn repeats_are_one_item_and_only_high_and_critical() {
        let siem = source_sql("siem");
        assert!(siem.contains("rule_level >= 10") && !siem.contains("MIN_LEVEL"));
        assert!(siem.contains("GROUP BY rule_id, agent_name, toDate("));
        let ndr = source_sql("ndr");
        assert!(ndr.contains("IN ('HIGH', 'CRITICAL')") && ndr.contains("GROUP BY a_name, a_src, a_dst, toDate(timestamp)"));
    }

    #[test]
    fn every_source_has_the_queue_columns() {
        for s in ["corroborated", "siem", "ndr"] {
            let select = source_sql(s);
            for col in ["AS alert_id", "AS ts", "AS severity", "AS rule_id", "AS rule_name", "title", "AS description", "AS hosts", "AS mitre", "AS status", "AS case_id"] {
                assert!(select.contains(col), "{s}: {col}");
            }
        }
    }
}
