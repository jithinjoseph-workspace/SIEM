// GET /api/siem/logs — log search with keyword, filters, date range, CSV export

use axum::{extract::{State, Extension, Query}, Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::AppState;
use crate::api::middleware::Claims;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct LogQuery {
    pub q:           Option<String>,
    pub source:      Option<String>,
    pub severity:    Option<String>,
    pub event_class: Option<String>,
    pub from:        Option<String>,
    pub to:          Option<String>,
    pub page:        Option<u64>,
    pub size:        Option<u64>,
    pub format:      Option<String>,
}

#[derive(Serialize)]
pub struct LogSearchResponse {
    pub logs:    Vec<SiemLogRow>,
    pub total:   u64,
    pub took_ms: u64,
}

#[derive(Serialize)]
pub struct SiemLogRow {
    pub log_id:      String,
    pub source_id:   String,
    pub source_type: String,
    pub event_class: String,
    pub severity:    String,
    pub timestamp:   String,
    pub raw_log:     String,
    pub parsed:      serde_json::Value,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(q): Query<LogQuery>,
) -> Result<Json<LogSearchResponse>, StatusCode> {
    let db   = tenant_db(&claims.tenant_id);
    let page = q.page.unwrap_or(1).max(1);
    let size = q.size.unwrap_or(50).min(1000);
    let offset = (page - 1) * size;
    let start = std::time::Instant::now();

    let where_clause = build_where(&q);

    let count_sql = format!(
        "SELECT count() FROM {db}.siem_logs {where_clause} FORMAT TabSeparated"
    );
    let data_sql = format!(
        "SELECT log_id, source_id, source_type, event_class, severity, \
                toString(timestamp), raw_log, parsed_json \
         FROM {db}.siem_logs {where_clause} \
         ORDER BY timestamp DESC LIMIT {size} OFFSET {offset} FORMAT JSONEachRow"
    );

    let client = reqwest::Client::new();

    let total = {
        let r = client.get(&state.clickhouse_url).query(&[("query", &count_sql)]).send().await
            .map_err(|e| { error!("CH count error: {e}"); StatusCode::INTERNAL_SERVER_ERROR })?;
        r.text().await.unwrap_or_default().trim().parse::<u64>().unwrap_or(0)
    };

    let logs = {
        let r = client.get(&state.clickhouse_url).query(&[("query", &data_sql)]).send().await
            .map_err(|e| { error!("CH logs error: {e}"); StatusCode::INTERNAL_SERVER_ERROR })?;
        let text = r.text().await.unwrap_or_default();
        text.lines().filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let parsed = serde_json::from_str(
                v["parsed_json"].as_str().unwrap_or("{}")
            ).unwrap_or(serde_json::json!({}));
            Some(SiemLogRow {
                log_id:      v["log_id"].as_str().unwrap_or("").to_string(),
                source_id:   v["source_id"].as_str().unwrap_or("").to_string(),
                source_type: v["source_type"].as_str().unwrap_or("").to_string(),
                event_class: v["event_class"].as_str().unwrap_or("").to_string(),
                severity:    v["severity"].as_str().unwrap_or("").to_string(),
                timestamp:   v["toString(timestamp)"].as_str().unwrap_or("").to_string(),
                raw_log:     v["raw_log"].as_str().unwrap_or("").to_string(),
                parsed,
            })
        }).collect::<Vec<_>>()
    };

    let took_ms = start.elapsed().as_millis() as u64;
    Ok(Json(LogSearchResponse { logs, total, took_ms }))
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Build WHERE clause from search params — all inputs are sanitised (no raw interpolation of user strings)
fn build_where(q: &LogQuery) -> String {
    let mut conditions: Vec<String> = vec![];

    if let Some(ref keyword) = q.q {
        let safe = escape(keyword);
        conditions.push(format!(
            "(raw_log ILIKE '%{safe}%' OR parsed_json ILIKE '%{safe}%')"
        ));
    }
    if let Some(ref s) = q.source {
        let safe = escape(s);
        conditions.push(format!("source_type = '{safe}'"));
    }
    if let Some(ref s) = q.severity {
        let safe = escape(s);
        conditions.push(format!("severity = '{safe}'"));
    }
    if let Some(ref c) = q.event_class {
        let safe = escape(c);
        conditions.push(format!("event_class = '{safe}'"));
    }
    if let Some(ref from) = q.from {
        let safe = escape(from);
        conditions.push(format!("timestamp >= '{safe}'"));
    }
    if let Some(ref to) = q.to {
        let safe = escape(to);
        conditions.push(format!("timestamp <= '{safe}'"));
    }

    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" { "ndr".into() } else { format!("ndr_{}", tenant_id.replace('-', "_")) }
}
