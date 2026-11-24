// GET /api/siem/dashboard — ingest health stats for the SIEM dashboard page

use axum::{extract::{State, Extension}, Json, http::StatusCode};
use serde::Serialize;
use tracing::error;

use crate::AppState;
use crate::api::middleware::Claims;

#[derive(Serialize)]
pub struct DashboardResponse {
    pub stats:          SiemStats,
    pub sources:        Vec<SourceHealth>,
    pub alert_counts:   AlertCounts,
    pub recent_alerts:  Vec<RecentAlert>,
}

#[derive(Serialize, Default)]
pub struct AlertCounts {
    pub critical: u64,
    pub high:     u64,
    pub medium:   u64,
    pub total:    u64,
}

#[derive(Serialize)]
pub struct RecentAlert {
    pub alert_id:   String,
    pub severity:   String,
    pub rule_name:  String,
    pub title:      String,
    pub source:     String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct SiemStats {
    pub eps_current:    f64,
    pub logs_today:     u64,
    pub logs_last_hour: u64,
    pub parse_errors:   u64,
    pub active_sources: u64,
    pub total_sources:  u64,
    pub kafka_lag:      u64,
}

#[derive(Serialize)]
pub struct SourceHealth {
    pub source_id:    String,
    pub name:         String,
    pub source_type:  String,
    pub status:       String,
    pub last_seen_at: String,
    pub eps:          f64,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    let db = tenant_db(&claims.tenant_id);
    let client = reqwest::Client::new();

    // Logs ingested today
    let logs_today = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_logs WHERE toDate(timestamp) = today()").await;

    // Logs last hour
    let logs_last_hour = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_logs WHERE timestamp >= now() - INTERVAL 1 HOUR").await;

    // EPS = logs last 60 seconds / 60
    let logs_last_min = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_logs WHERE timestamp >= now() - INTERVAL 1 MINUTE").await;
    let eps_current = logs_last_min as f64 / 60.0;

    // Parse errors today
    let parse_errors = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_parse_errors WHERE toDate(created_at) = today()").await;

    // Source counts
    let total_sources = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_sources FINAL").await;
    let active_sources = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_sources FINAL WHERE status = 'active'").await;

    // Source health list
    let sources = query_sources(&client, &state.clickhouse_url, &db).await;

    // Alert counts — unified_alerts is in the shared ndr DB (not per-tenant)
    let alert_counts = query_alert_counts(&client, &state.clickhouse_url, &claims.tenant_id).await;
    let recent_alerts = query_recent_alerts(&client, &state.clickhouse_url, &claims.tenant_id).await;

    Ok(Json(DashboardResponse {
        stats: SiemStats {
            eps_current,
            logs_today,
            logs_last_hour,
            parse_errors,
            active_sources,
            total_sources,
            kafka_lag: 0,
        },
        sources,
        alert_counts,
        recent_alerts,
    }))
}

async fn query_u64(client: &reqwest::Client, url: &str, db: &str, sql: &str) -> u64 {
    let resp = client.get(url)
        .query(&[("query", &format!("{sql} FORMAT TabSeparated")), ("database", &db.to_string())])
        .send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            r.text().await.unwrap_or_default().trim().parse().unwrap_or(0)
        }
        Ok(r) => { error!("CH query failed: {}", r.text().await.unwrap_or_default()); 0 }
        Err(e) => { error!("CH request error: {e}"); 0 }
    }
}

async fn query_sources(client: &reqwest::Client, url: &str, db: &str) -> Vec<SourceHealth> {
    // Join siem_sources config with live activity from siem_logs:
    // real EPS = logs per source in last 60s / 60
    // real last_seen_at = max(timestamp) per source from siem_logs
    let sql = format!(
        "SELECT
            s.source_id,
            s.name,
            s.source_type,
            s.status,
            toString(coalesce(l.last_seen, s.last_seen_at)) AS last_seen_at,
            round(coalesce(l.logs_last_min, 0) / 60.0, 2) AS eps
         FROM {db}.siem_sources AS s FINAL
         LEFT JOIN (
             SELECT
                 source_id,
                 max(timestamp)                                          AS last_seen,
                 countIf(timestamp >= now() - INTERVAL 1 MINUTE)        AS logs_last_min
             FROM {db}.siem_logs
             GROUP BY source_id
         ) AS l ON s.source_id = l.source_id
         ORDER BY s.name
         LIMIT 100
         FORMAT JSONEachRow",
        db = db
    );

    let resp = client.get(url)
        .query(&[("query", &sql)])
        .send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let text = r.text().await.unwrap_or_default();
            text.lines().filter_map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).ok()?;
                Some(SourceHealth {
                    source_id:    v["source_id"].as_str().unwrap_or("").to_string(),
                    name:         v["name"].as_str().unwrap_or("").to_string(),
                    source_type:  v["source_type"].as_str().unwrap_or("").to_string(),
                    status:       v["status"].as_str().unwrap_or("active").to_string(),
                    last_seen_at: v["last_seen_at"].as_str().unwrap_or("").to_string(),
                    eps:          v["eps"].as_f64().unwrap_or(0.0),
                })
            }).collect()
        }
        _ => vec![],
    }
}

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" || tenant_id.is_empty() {
        "ndr".into()
    } else {
        format!("ndr_{}", tenant_id.replace('-', "_"))
    }
}

async fn query_alert_counts(client: &reqwest::Client, url: &str, tenant_id: &str) -> AlertCounts {
    let db  = tenant_db(tenant_id);
    let sql = format!(
        "SELECT severity, count() AS cnt \
         FROM {db}.unified_alerts FINAL \
         WHERE tenant_id = '{tid}' AND status IN ('New','Investigating') \
           AND created_at >= now() - INTERVAL 24 HOUR \
         GROUP BY severity FORMAT JSONEachRow",
        db  = db,
        tid = tenant_id.replace('\\', "\\\\").replace('\'', "\\'")
    );
    let resp = client.get(url).query(&[("query", &sql)]).send().await;
    let mut counts = AlertCounts::default();
    if let Ok(r) = resp {
        if r.status().is_success() {
            let text = r.text().await.unwrap_or_default();
            for line in text.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    let sev = v["severity"].as_str().unwrap_or("").to_uppercase();
                    let cnt = v["cnt"].as_u64().unwrap_or(0);
                    match sev.as_str() {
                        "CRITICAL" => counts.critical += cnt,
                        "HIGH"     => counts.high     += cnt,
                        "MEDIUM"   => counts.medium   += cnt,
                        _ => {}
                    }
                }
            }
            counts.total = counts.critical + counts.high + counts.medium;
        }
    }
    counts
}

async fn query_recent_alerts(client: &reqwest::Client, url: &str, tenant_id: &str) -> Vec<RecentAlert> {
    let db  = tenant_db(tenant_id);
    let sql = format!(
        "SELECT alert_id, severity, rule_name, title, source, \
                toString(created_at) AS created_at \
         FROM {db}.unified_alerts FINAL \
         WHERE tenant_id = '{tid}' AND status IN ('New','Investigating') \
         ORDER BY created_at DESC \
         LIMIT 10 FORMAT JSONEachRow",
        db  = db,
        tid = tenant_id.replace('\\', "\\\\").replace('\'', "\\'")
    );
    let resp = client.get(url).query(&[("query", &sql)]).send().await;
    match resp {
        Ok(r) if r.status().is_success() => {
            let text = r.text().await.unwrap_or_default();
            text.lines().filter_map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).ok()?;
                Some(RecentAlert {
                    alert_id:   v["alert_id"].as_str().unwrap_or("").to_string(),
                    severity:   v["severity"].as_str().unwrap_or("").to_string(),
                    rule_name:  v["rule_name"].as_str().unwrap_or("").to_string(),
                    title:      v["title"].as_str().unwrap_or("").to_string(),
                    source:     v["source"].as_str().unwrap_or("").to_string(),
                    created_at: v["created_at"].as_str().unwrap_or("").to_string(),
                })
            }).collect()
        }
        _ => vec![],
    }
}
