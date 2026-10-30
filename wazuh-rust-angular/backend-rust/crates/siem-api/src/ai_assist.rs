//! AI for the SIEM analyst pages (siem-ai): the AI chat and "analyze event",
//! and the provider list the other AI features (triage, predictions) use.
//!
//! Providers are the ones the super admin configures in Settings > AI
//! (`ndr.ai_providers`); `GROQ_API_KEY` still works as a fallback provider.
//! A tenant whose AI is switched off gets no AI calls.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use siem_ai::{Message, Provider};

use crate::tenancy::AuthCtx;
use crate::{AiAnalysisRequest, AiAnalysisResponse, AiChatRequest, AiChatResponse, AppState, MitreMapping};

const PROVIDER_TTL: Duration = Duration::from_secs(300);
static PROVIDERS: Mutex<Option<HashMap<String, (Instant, Vec<Provider>)>>> = Mutex::new(None);

#[derive(clickhouse::Row, Deserialize)]
struct ProviderRow {
    name: String,
    provider_type: String,
    api_key: String,
    model: String,
    base_url: String,
    endpoint_path: String,
    priority: u8,
}

/// The enabled providers for a use case ("chat", "threat" or "all"), by priority.
pub async fn providers(state: &AppState, use_case: &str) -> Vec<Provider> {
    if let Some((t, p)) = PROVIDERS.lock().unwrap().get_or_insert_with(HashMap::new).get(use_case) {
        if t.elapsed() < PROVIDER_TTL {
            return p.clone();
        }
    }
    let mut list: Vec<Provider> = if state.db.is_connected() {
        state
            .db
            .root()
            .query("SELECT name, provider_type, api_key, model, base_url, endpoint_path, priority FROM ndr.ai_providers FINAL WHERE enabled = 1 AND (use_case = 'all' OR use_case = ?) ORDER BY priority ASC LIMIT 10")
            .bind(use_case)
            .fetch_all::<ProviderRow>()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| Provider { name: r.name, provider_type: r.provider_type, api_key: crate::secrets::open(&r.api_key), model: r.model, base_url: r.base_url, endpoint_path: r.endpoint_path, priority: r.priority })
            .collect()
    } else {
        Vec::new()
    };
    // the earlier setup: a Groq key in the environment
    let groq = std::env::var("GROQ_API_KEY").unwrap_or_default();
    if !groq.trim().is_empty() {
        list.push(Provider { name: "GROQ_API_KEY".into(), provider_type: "groq".into(), api_key: groq.trim().into(), model: "openai/gpt-oss-120b".into(), base_url: "https://api.groq.com/openai".into(), endpoint_path: "/v1/chat/completions".into(), priority: 255 });
    }
    PROVIDERS.lock().unwrap().get_or_insert_with(HashMap::new).insert(use_case.to_string(), (Instant::now(), list.clone()));
    list
}

/// The tenant's AI switch (tenants without a record: on).
pub fn tenant_ai_enabled(state: &AppState, tenant: &str) -> bool {
    let t = crate::tenancy::normalize_tenant(tenant);
    state.tenants.read().unwrap().iter().find(|r| crate::tenancy::normalize_tenant(&r.id) == t).map_or(true, |r| r.ai_enabled)
}

fn ai_off() -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, "AI is switched off for this tenant".into())
}

const CHAT_SYSTEM: &str = "You are the SOC assistant of a Wazuh-based SIEM. You help security analysts triage alerts, \
understand Windows and Linux logs, write Wazuh decoders and rules, and plan defensive investigation and remediation. \
Be concise and technical; put commands and rules in code blocks. Only suggest defensive actions. \
When you use the tenant summary below, say so; do not invent alerts, hosts or numbers that are not in it.";

/// A read-only summary of the caller's tenant (last 24 h, ClickHouse), for the chat.
async fn tenant_summary(state: &AppState, ctx: &AuthCtx) -> String {
    let (c, top) = tokio::join!(crate::history::counts(state, ctx, 24), crate::history::top_rules(state, ctx, 24, 8));
    let agents = crate::scoped_agent_map(state, ctx);
    let (crit, high, med, low) = (c.critical(), c.high(), c.medium(), c.low());
    let top: Vec<String> = top.into_iter().map(|(id, d, n)| format!("rule {id} x{n}: {}", d.chars().take(120).collect::<String>())).collect();
    format!(
        "Tenant summary (last 24 h): {} agents; {} alerts (critical {crit}, high {high}, medium {med}, low {low}).\nMost frequent rules:\n{}",
        agents.len(),
        c.alerts(),
        siem_ai::untrusted(&top.join("\n"), 2000)
    )
}

/// `POST /api/v1/ai/chat`
pub async fn chat(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(req): Json<AiChatRequest>) -> Result<Json<AiChatResponse>, (StatusCode, String)> {
    if !tenant_ai_enabled(&state, &ctx.scope()) {
        return Err(ai_off());
    }
    let system = format!("{CHAT_SYSTEM}\n{}\n\n{}", siem_ai::UNTRUSTED_RULE, tenant_summary(&state, &ctx).await);
    let mut messages: Vec<Message> = req.history.unwrap_or_default().into_iter().rev().take(20).rev().map(|h| Message { role: h.role, content: h.content.chars().take(8000).collect() }).collect();
    messages.push(Message { role: "user".into(), content: req.message.chars().take(8000).collect() });
    let ps = providers(&state, "chat").await;
    match siem_ai::chat(&ps, &system, &messages).await {
        Ok(r) => Ok(Json(AiChatResponse { response: r.text, model_used: r.model })),
        Err(e) => Err((StatusCode::BAD_GATEWAY, e)),
    }
}

const ANALYZE_SYSTEM: &str = r#"You are a Tier-3 SOC and detection engineer analyzing one event or alert from a Wazuh SIEM.
Output ONLY a JSON object, no markdown fences, with exactly these keys:
{
  "classification": "Benign Administrative Activity | Suspicious Activity | High-Severity Threat",
  "confidence_score": 0-100,
  "severity": "info | low | medium | high | critical",
  "summary": "1-2 sentence summary of what happened",
  "mitre_attack": { "tactic": "...", "technique_id": "T....", "technique_name": "..." },
  "indicators": ["key observation", "..."],
  "impact": "possible impact on this host or the organization",
  "remediation_commands": ["defensive command to investigate, audit or contain; no offensive tools"],
  "explanation": "technical explanation: event IDs, registry keys, processes, why it matters"
}"#;

/// `POST /api/v1/ai/analyze`: one event or alert of the caller's tenant.
pub async fn analyze(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(req): Json<AiAnalysisRequest>) -> Result<Json<AiAnalysisResponse>, (StatusCode, String)> {
    if !tenant_ai_enabled(&state, &ctx.scope()) {
        return Err(ai_off());
    }
    let mut host = req.agent_id.clone().unwrap_or_default();
    let mut source = req.source.clone().unwrap_or_default();
    let mut location = req.location.clone().unwrap_or_default();
    let mut text = String::new();
    if let Some(eid) = &req.event_id {
        if let Some(ev) = crate::history::event(&state, &ctx, eid).await {
            host = ev.agent_id.clone();
            source = format!("{:?}", ev.source);
            location = ev.location.clone();
            text = format!("Log location: {}\nRaw message: {}\nMetadata: {:?}", ev.location, ev.message, ev.metadata);
        }
    } else if let Some(aid) = &req.alert_id {
        if let Some(a) = crate::history::alert(&state, &ctx, aid).await {
            host = a.agent.name.clone();
            source = "Wazuh alert".into();
            location = format!("Rule #{}", a.rule.id);
            text = format!("Rule ID: {}\nLevel: {}\nDescription: {}\nFull log: {}\nMITRE: {:?}\nDecoded: {:?}", a.rule.id, a.rule.level, a.rule.description, a.full_log, a.rule.mitre, a.decoded);
        }
    }
    if text.is_empty() {
        text = format!("Payload: {}\nMetadata: {:?}", req.message.clone().unwrap_or_default(), req.metadata);
    }
    let prompt = format!(
        "Log source: {source}\nHost: {host}\nLocation: {location}\n\nEvent:\n{}\n{}",
        siem_ai::untrusted(&text, 6000),
        req.custom_prompt.as_deref().map(|p| format!("\nAnalyst's question: {}", p.chars().take(1000).collect::<String>())).unwrap_or_default()
    );
    let system = format!("{ANALYZE_SYSTEM}\n{}", siem_ai::UNTRUSTED_RULE);
    let r = siem_ai::generate(&providers(&state, "chat").await, &system, &prompt).await.map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    Ok(Json(parse_analysis(&r.text, r.model)))
}

/// The model's JSON, with defaults for what it left out (or the raw text).
pub fn parse_analysis(content: &str, model: String) -> AiAnalysisResponse {
    let strs = |v: &serde_json::Value| -> Vec<String> { v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default() };
    match siem_ai::json_object(content) {
        Some(v) => AiAnalysisResponse {
            classification: v["classification"].as_str().unwrap_or("Security Assessment").into(),
            confidence_score: v["confidence_score"].as_u64().unwrap_or(0).min(100) as u8,
            severity: v["severity"].as_str().unwrap_or("medium").into(),
            summary: v["summary"].as_str().unwrap_or("").into(),
            mitre_attack: v.get("mitre_attack").filter(|m| m.is_object()).map(|m| MitreMapping {
                tactic: m["tactic"].as_str().unwrap_or("").into(),
                technique_id: m["technique_id"].as_str().unwrap_or("").into(),
                technique_name: m["technique_name"].as_str().unwrap_or("").into(),
            }),
            indicators: strs(&v["indicators"]),
            impact: v["impact"].as_str().unwrap_or("").into(),
            remediation_commands: strs(&v["remediation_commands"]),
            explanation: v["explanation"].as_str().unwrap_or("").into(),
            model_used: model,
        },
        None => AiAnalysisResponse {
            classification: "Analysis (unstructured)".into(),
            confidence_score: 0,
            severity: "info".into(),
            summary: content.lines().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(200).collect(),
            mitre_attack: None,
            indicators: Vec::new(),
            impact: String::new(),
            remediation_commands: Vec::new(),
            explanation: content.into(),
            model_used: model,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_json_and_fallback() {
        let a = parse_analysis("```json\n{\"classification\":\"Suspicious Activity\",\"confidence_score\":140,\"severity\":\"high\",\"mitre_attack\":{\"tactic\":\"Execution\",\"technique_id\":\"T1059.001\",\"technique_name\":\"PowerShell\"},\"indicators\":[\"encoded command\"]}\n```", "m".into());
        assert_eq!((a.classification.as_str(), a.confidence_score, a.indicators.len()), ("Suspicious Activity", 100, 1));
        assert_eq!(a.mitre_attack.unwrap().technique_id, "T1059.001");
        let b = parse_analysis("It looks fine.", "m".into());
        assert_eq!((b.confidence_score, b.summary.as_str()), (0, "It looks fine."));
        assert!(b.mitre_attack.is_none(), "no invented MITRE mapping");
    }
}

// ───────────────────────── provider settings (platform admins) ─────────────────────────

/// After a change the next AI call reads the providers again.
fn forget_providers() {
    *PROVIDERS.lock().unwrap() = None;
}

fn platform_admin(ctx: &AuthCtx) -> Option<axum::response::Response> {
    use axum::response::IntoResponse;
    (!ctx.is_super()).then(|| (StatusCode::FORBIDDEN, Json(serde_json::json!({ "status": "error", "error": "Only platform admins manage AI providers" }))).into_response())
}

#[derive(clickhouse::Row, Deserialize)]
struct ProviderListRow {
    name: String,
    provider_type: String,
    api_key: String,
    model: String,
    base_url: String,
    endpoint_path: String,
    msg_format: String,
    use_case: String,
    priority: u8,
    enabled: u8,
}

/// `GET /api/settings/ai/providers` (the keys are never returned)
pub async fn list_providers(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(r) = platform_admin(&ctx) {
        return r;
    }
    let rows = state
        .db
        .root()
        .query("SELECT name, provider_type, api_key, model, base_url, endpoint_path, msg_format, use_case, priority, enabled FROM ndr.ai_providers FINAL ORDER BY priority, name")
        .fetch_all::<ProviderListRow>()
        .await;
    match rows {
        Ok(rows) => Json(serde_json::json!({
            "providers": rows.iter().map(|r| serde_json::json!({
                "name": r.name, "provider_type": r.provider_type, "model": r.model, "base_url": r.base_url, "endpoint_path": r.endpoint_path,
                "msg_format": r.msg_format, "use_case": r.use_case, "priority": r.priority, "enabled": r.enabled == 1, "key_set": !r.api_key.is_empty(),
            })).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "error": e.to_string() }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ProviderReq {
    pub name: String,
    #[serde(default)]
    pub provider_type: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub endpoint_path: String,
    #[serde(default)]
    pub msg_format: String,
    #[serde(default)]
    pub use_case: String,
    #[serde(default)]
    pub priority: Option<u8>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl ProviderReq {
    /// The provider as the AI client calls it; an empty key is the stored one.
    async fn provider(&self, state: &AppState) -> Provider {
        let key = if self.api_key.trim().is_empty() { stored_key(state, self.name.trim()).await } else { self.api_key.trim().to_string() };
        Provider {
            name: self.name.trim().into(),
            provider_type: if self.provider_type.is_empty() { "openai".into() } else { self.provider_type.clone() },
            api_key: key,
            model: self.model.trim().into(),
            base_url: self.base_url.trim().trim_end_matches('/').into(),
            endpoint_path: if self.endpoint_path.trim().is_empty() { "/v1/chat/completions".into() } else { self.endpoint_path.trim().into() },
            priority: self.priority.unwrap_or(10),
        }
    }
}

async fn stored_key(state: &AppState, name: &str) -> String {
    let k = state.db.root().query("SELECT api_key FROM ndr.ai_providers FINAL WHERE name = ? LIMIT 1").bind(name).fetch_optional::<String>().await.ok().flatten().unwrap_or_default();
    crate::secrets::open(&k)
}

/// Provider keys still stored in plain text, written again sealed; how many.
pub async fn reseal_provider_keys(state: &AppState) -> usize {
    let rows = state
        .db
        .root()
        .query("SELECT name, provider_type, api_key, model, base_url, endpoint_path, msg_format, use_case, priority, enabled FROM ndr.ai_providers FINAL WHERE api_key != '' AND NOT startsWith(api_key, 'enc:v1:')")
        .fetch_all::<ProviderListRow>()
        .await
        .unwrap_or_default();
    for r in &rows {
        let _ = state
            .db
            .root()
            .query("INSERT INTO ndr.ai_providers (name, provider_type, api_key, model, base_url, endpoint_path, msg_format, use_case, priority, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())")
            .bind(&r.name)
            .bind(&r.provider_type)
            .bind(crate::secrets::seal(&r.api_key))
            .bind(&r.model)
            .bind(&r.base_url)
            .bind(&r.endpoint_path)
            .bind(&r.msg_format)
            .bind(&r.use_case)
            .bind(r.priority)
            .bind(r.enabled)
            .execute()
            .await;
    }
    if !rows.is_empty() {
        let _ = state.db.root().query("OPTIMIZE TABLE ndr.ai_providers FINAL").execute().await;
        forget_providers();
    }
    rows.len()
}

/// `POST /api/settings/ai/providers`: add, or replace the one of that name.
pub async fn save_provider(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<ProviderReq>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(x) = platform_admin(&ctx) {
        return x;
    }
    let bad = |m: &str| (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "error": m }))).into_response();
    if r.name.trim().is_empty() || r.name.len() > 80 {
        return bad("A name is required");
    }
    if !(r.base_url.starts_with("https://") || r.base_url.starts_with("http://")) {
        return bad("The base URL must start with https:// or http://");
    }
    let use_case = if r.use_case.is_empty() { "all".to_string() } else { r.use_case.clone() };
    if !matches!(use_case.as_str(), "all" | "chat" | "threat") {
        return bad("use_case is all, chat or threat");
    }
    let p = r.provider(&state).await;
    // created_at (the version) makes each save a new row: the replicated table drops a repeated identical insert
    let saved = state
        .db
        .root()
        .query("INSERT INTO ndr.ai_providers (name, provider_type, api_key, model, base_url, endpoint_path, msg_format, use_case, priority, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())")
        .bind(&p.name)
        .bind(&p.provider_type)
        .bind(crate::secrets::seal(&p.api_key))
        .bind(&p.model)
        .bind(&p.base_url)
        .bind(&p.endpoint_path)
        .bind(if r.msg_format.is_empty() { "openai" } else { r.msg_format.as_str() })
        .bind(&use_case)
        .bind(p.priority)
        .bind(u8::from(r.enabled.unwrap_or(true)))
        .execute()
        .await;
    forget_providers();
    match saved {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "error": e.to_string() }))).into_response(),
    }
}

/// `DELETE /api/settings/ai/providers/:name`
pub async fn delete_provider(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, axum::extract::Path(name): axum::extract::Path<String>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(x) = platform_admin(&ctx) {
        return x;
    }
    let r = state.db.root().query("ALTER TABLE ndr.ai_providers DELETE WHERE name = ? SETTINGS mutations_sync = 2").bind(&name).execute().await;
    forget_providers();
    match r {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "error": e.to_string() }))).into_response(),
    }
}

/// `POST /api/settings/ai/providers/test`: one short request to the provider.
pub async fn test_provider(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<ProviderReq>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(x) = platform_admin(&ctx) {
        return x;
    }
    let p = r.provider(&state).await;
    match siem_ai::generate(&[p], "You are a connectivity check.", "Reply with the single word OK.").await {
        Ok(reply) => Json(serde_json::json!({ "status": "ok", "response": reply.text, "model": reply.model })).into_response(),
        Err(e) => Json(serde_json::json!({ "status": "error", "error": e })).into_response(),
    }
}
