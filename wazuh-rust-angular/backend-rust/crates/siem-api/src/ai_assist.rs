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
            .map(|r| Provider { name: r.name, provider_type: r.provider_type, api_key: r.api_key, model: r.model, base_url: r.base_url, endpoint_path: r.endpoint_path, priority: r.priority })
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
    let alerts = crate::history::alerts(state, ctx, 24).await;
    let agents = crate::scoped_agent_map(state, ctx);
    let (mut crit, mut high, mut med, mut low) = (0, 0, 0, 0);
    let mut rules: HashMap<(u32, String), u32> = HashMap::new();
    for a in &alerts {
        match a.rule.level {
            12.. => crit += 1,
            8..=11 => high += 1,
            4..=7 => med += 1,
            _ => low += 1,
        }
        *rules.entry((a.rule.id, a.rule.description.clone())).or_default() += 1;
    }
    let mut top: Vec<_> = rules.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    let top: Vec<String> = top.into_iter().take(8).map(|((id, d), n)| format!("rule {id} x{n}: {}", d.chars().take(120).collect::<String>())).collect();
    format!(
        "Tenant summary (last 24 h): {} agents; {} alerts (critical {crit}, high {high}, medium {med}, low {low}).\nMost frequent rules:\n{}",
        agents.len(),
        alerts.len(),
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
        if let Some(ev) = crate::history::events(&state, &ctx, crate::history::DEFAULT_HOURS).await.into_iter().find(|e| &e.id.to_string() == eid) {
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
