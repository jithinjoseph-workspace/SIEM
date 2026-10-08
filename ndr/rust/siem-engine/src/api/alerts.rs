// GET /api/xdr/alerts — Unified alert queue (NDR + SIEM + corroborated).
// Reads from ndr.unified_alerts in ClickHouse.
// Tenant-scoped via JWT claims. Supports filters: status, severity, source.
// Returns paginated JSON with total count.
// License: Apache-2.0

use axum::{extract::{State, Query, Extension}, Json};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::AppState;
use crate::api::middleware::Claims;
use crate::correlation::alerts::{AlertQuery, get_alerts, count_alerts, AlertListRow};

// ─────────────────────────────────────────────────────────────────────────────
// Request parameters
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AlertsParams {
    pub status:   Option<String>,
    pub severity: Option<String>,
    pub source:   Option<String>,
    pub page:     Option<u32>,
    pub limit:    Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Response shape
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AlertListResponse {
    pub alerts: Vec<AlertItem>,
    pub total:  u64,
    pub page:   u32,
    pub limit:  u32,
    pub pages:  u32,
}

#[derive(Debug, Serialize)]
pub struct AlertItem {
    pub alert_id:         String,
    pub source:           String,
    pub severity:         String,
    pub rule_id:          String,
    pub rule_name:        String,
    pub title:            String,
    pub description:      String,
    pub affected_hosts:   Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub status:           String,
    pub created_at:       u32,
    pub updated_at:       u32,
    pub sla_breached_at:  Option<u32>,
}

impl From<AlertListRow> for AlertItem {
    fn from(r: AlertListRow) -> Self {
        Self {
            alert_id:         r.alert_id,
            source:           r.source,
            severity:         r.severity,
            rule_id:          r.rule_id,
            rule_name:        r.rule_name,
            title:            r.title,
            description:      r.description,
            affected_hosts:   r.affected_hosts,
            mitre_techniques: r.mitre_techniques,
            status:           r.status,
            created_at:       r.created_at,
            updated_at:       r.updated_at,
            sla_breached_at:  r.sla_breached_at,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler
// ─────────────────────────────────────────────────────────────────────────────

/// GET /api/xdr/alerts — unified alert queue (NDR + SIEM + corroborated).
/// Reads from ndr.unified_alerts in ClickHouse, filtered by tenant_id from JWT.
pub async fn list(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<AlertsParams>,
) -> (StatusCode, Json<Value>) {
    let tenant_id = claims.tenant_id.clone();

    let page  = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).min(500);
    let offset = (page - 1) * limit;

    let ch = crate::correlation::build_ch_client(&state.clickhouse_url);

    let q = AlertQuery {
        tenant_id: tenant_id.clone(),
        status:    params.status.clone(),
        severity:  params.severity.clone(),
        source:    params.source.clone(),
        limit,
        offset,
    };

    // Fetch alerts and count in parallel
    let (rows_result, count_result) = tokio::join!(
        get_alerts(&ch, &q),
        count_alerts(&ch, &q),
    );

    let rows = match rows_result {
        Ok(r)  => r,
        Err(e) => {
            tracing::error!("GET /api/xdr/alerts query error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to query alerts", "detail": e.to_string() }))
            );
        }
    };

    let total = count_result.unwrap_or(0);
    let pages = if limit == 0 { 1 } else { ((total as u32) + limit - 1) / limit };

    let items: Vec<AlertItem> = rows.into_iter().map(AlertItem::from).collect();

    (StatusCode::OK, Json(serde_json::to_value(AlertListResponse {
        alerts: items,
        total,
        page,
        limit,
        pages,
    }).unwrap_or(json!({ "error": "serialization error" }))))
}

