// GET /api/siem/rules  — list all 10 OOTB correlation rules + fitness scores
// PUT /api/siem/rules/:id — enable/disable a rule (admin only)
// License: Apache-2.0

use axum::{
    extract::{State, Path, Extension},
    Json,
};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;
use crate::api::middleware::Claims;
use crate::correlation::engine::RuleEngine;

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/siem/rules
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list_rules(
    State(state): State<AppState>,
) -> (StatusCode, Json<Value>) {
    let ch = crate::correlation::build_ch_client(&state.clickhouse_url);

    // Fetch enabled flags + fitness scores from ClickHouse
    let base_rules = RuleEngine::rule_catalog();

    // Query current enabled state from siem_rules
    let enabled_sql = "SELECT id, enabled FROM ndr.siem_rules FINAL WHERE tenant_id = '*'";

    #[derive(serde::Deserialize, clickhouse::Row)]
    struct EnabledRow { id: String, enabled: u8 }

    let enabled_map: std::collections::HashMap<String, bool> =
        ch.query(enabled_sql).fetch_all::<EnabledRow>().await
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.id, r.enabled != 0))
            .collect();

    // Query latest fitness scores
    let fitness_sql = r#"
        SELECT rule_id, fitness_score, true_positive_rate, suppression_rate, avg_resolve_minutes
        FROM ndr.siem_rule_fitness FINAL
        ORDER BY scored_at DESC
        LIMIT 10 BY rule_id
    "#;

    #[derive(serde::Deserialize, clickhouse::Row)]
    struct FitnessRow {
        rule_id:             String,
        fitness_score:       f32,
        true_positive_rate:  f32,
        suppression_rate:    f32,
        avg_resolve_minutes: f32,
    }

    let fitness_map: std::collections::HashMap<String, FitnessRow> =
        ch.query(fitness_sql).fetch_all::<FitnessRow>().await
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.rule_id.clone(), r))
            .collect();

    // Merge
    let rules: Vec<serde_json::Value> = base_rules.into_iter().map(|mut rule| {
        if let Some(&enabled) = enabled_map.get(&rule.id) {
            rule.enabled = enabled;
        }
        if let Some(fitness) = fitness_map.get(&rule.id) {
            rule.fitness_score       = fitness.fitness_score;
            rule.true_positive_rate  = fitness.true_positive_rate;
            rule.suppression_rate    = fitness.suppression_rate;
            rule.avg_resolve_minutes = fitness.avg_resolve_minutes;
        }
        serde_json::to_value(&rule).unwrap_or(json!({}))
    }).collect();

    let total = rules.len();
    (StatusCode::OK, Json(json!({
        "rules": rules,
        "total": total
    })))
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/siem/rules/:id
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UpdateRuleBody {
    pub enabled: bool,
}

pub async fn update_rule(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(rule_id): Path<String>,
    Json(body): Json<UpdateRuleBody>,
) -> (StatusCode, Json<Value>) {
    // These correlation rules are shared across every tenant (tenant_id = '*'),
    // so only a platform super_admin may toggle them — not a per-tenant role.
    if claims.role != "super_admin" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "only super_admin can modify correlation rules" }))
        );
    }

    // Validate rule_id is one of the known OOTB rules
    let known: Vec<String> = RuleEngine::rule_catalog()
        .into_iter()
        .map(|r| r.id)
        .collect();

    if !known.contains(&rule_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("Unknown rule ID: {}", rule_id) }))
        );
    }

    let ch      = crate::correlation::build_ch_client(&state.clickhouse_url);
    let enabled = if body.enabled { 1u8 } else { 0u8 };
    let now     = chrono::Utc::now().timestamp() as u32;

    let sql = format!(
        "INSERT INTO ndr.siem_rules (id, name, description, severity, enabled, tenant_id, updated_at) \
         SELECT id, name, description, severity, {}, tenant_id, {} AS updated_at \
         FROM ndr.siem_rules FINAL \
         WHERE id = '{}' AND tenant_id = '*' \
         LIMIT 1",
        enabled, now, escape(&rule_id)
    );

    match ch.query(&sql).execute().await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "rule_id": rule_id,
                "enabled": body.enabled,
                "message": format!("Rule {} {}", rule_id, if body.enabled { "enabled" } else { "disabled" })
            }))
        ),
        Err(e) => {
            tracing::error!("PUT /api/siem/rules/{} error: {}", rule_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to update rule", "detail": e.to_string() }))
            )
        }
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
