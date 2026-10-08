// Shared AI provider registry — loaded from ndr.ai_providers (super admin UI).
// Both ndr-engine (ARIA chat + verdict) and siem-engine (log parser generation) use this.
// Super admin adds any provider — OpenAI, Anthropic, Groq, or any custom endpoint.
// All AI calls from both engines route through the priority-ordered provider list.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use clickhouse::Client;
use tracing::{error, warn};

// ── Provider record ───────────────────────────────────────────────────────────

#[derive(clickhouse::Row, serde::Deserialize, Clone, Debug)]
pub struct AiProvider {
    pub name:          String,
    pub provider_type: String,
    pub api_key:       String,
    pub model:         String,
    pub base_url:      String,
    pub endpoint_path: String,
    pub msg_format:    String,
    pub priority:      u8,
}

// ── Process-level provider cache (TTL 5 min) ──────────────────────────────────
// One global cache keyed by use_case tag. Mutex prevents thundering herd on miss.

static CACHE: std::sync::OnceLock<Arc<Mutex<HashMap<String, (Vec<AiProvider>, Instant)>>>> =
    std::sync::OnceLock::new();

fn cache() -> Arc<Mutex<HashMap<String, (Vec<AiProvider>, Instant)>>> {
    CACHE.get_or_init(|| Arc::new(Mutex::new(HashMap::new()))).clone()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Load enabled providers for a use_case ("threat"|"chat"|"all"), sorted by priority.
/// Results cached for 5 minutes. Concurrent callers share the refreshed result.
pub async fn get_ai_providers(ch: &Client, use_case: &str) -> Vec<AiProvider> {
    let cache = cache();
    let mut guard = cache.lock().await;
    let needs_refresh = guard.get(use_case)
        .map(|(_, ts)| ts.elapsed() > Duration::from_secs(300))
        .unwrap_or(true);
    if needs_refresh {
        let fresh = load_from_db(ch, use_case).await;
        guard.insert(use_case.to_string(), (fresh.clone(), Instant::now()));
        fresh
    } else {
        guard[use_case].0.clone()
    }
}

/// System + single user prompt → response text.
/// Tries providers in priority order; returns empty string when all fail or none configured.
/// Used by: siem-engine log parser generation, ndr-engine verdict (auto-investigate).
pub async fn generate_simple(ch: &Client, use_case: &str, system: &str, prompt: &str) -> String {
    let providers = get_ai_providers(ch, use_case).await;
    if providers.is_empty() {
        warn!("ai_providers: no providers configured for use_case={use_case} — add one in Settings > AI Configuration");
        return String::new();
    }
    for p in &providers {
        if p.api_key.is_empty() { continue; }
        let result = call_simple(p, system, prompt).await;
        if !result.is_empty() { return result; }
        warn!("ai_providers: '{}' returned empty, trying next", p.name);
    }
    String::new()
}

// ── DB load ───────────────────────────────────────────────────────────────────

async fn load_from_db(ch: &Client, use_case: &str) -> Vec<AiProvider> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        name: String, provider_type: String, api_key: String,
        model: String, base_url: String, endpoint_path: String,
        msg_format: String, priority: u8,
    }

    fn esc(s: &str) -> String { s.replace('\'', "''") }

    let sql = format!(
        "SELECT name, provider_type, api_key, model, base_url, endpoint_path, msg_format, priority \
         FROM ndr.ai_providers FINAL \
         WHERE enabled = 1 AND (use_case = 'all' OR use_case = '{}') \
         ORDER BY priority ASC LIMIT 10",
        esc(use_case)
    );

    match ch.query(&sql).fetch_all::<Row>().await {
        Ok(rows) => rows.into_iter().map(|r| AiProvider {
            name: r.name, provider_type: r.provider_type, api_key: r.api_key,
            model: r.model, base_url: r.base_url, endpoint_path: r.endpoint_path,
            msg_format: r.msg_format, priority: r.priority,
        }).collect(),
        Err(e) => {
            warn!("ai_providers: DB load failed (table may not exist yet): {e}");
            vec![]
        }
    }
}

// ── HTTP dispatch ─────────────────────────────────────────────────────────────

async fn call_simple(p: &AiProvider, system: &str, prompt: &str) -> String {
    if p.provider_type == "anthropic" {
        return call_anthropic(p, system, prompt).await;
    }
    let base  = if p.base_url.is_empty()      { "https://api.openai.com".to_string() }
                else { p.base_url.trim_end_matches('/').to_string() };
    let path  = if p.endpoint_path.is_empty() { "/v1/chat/completions".to_string() }
                else { p.endpoint_path.clone() };
    let model = if p.model.is_empty()         { "gpt-4o-mini".to_string() }
                else { p.model.clone() };
    call_openai_compat(&p.api_key, &model, &format!("{base}{path}"), system, prompt).await
}

async fn call_openai_compat(key: &str, model: &str, endpoint: &str, system: &str, prompt: &str) -> String {
    let http = match reqwest::Client::builder().timeout(Duration::from_secs(60)).build() {
        Ok(c)  => c,
        Err(e) => { error!("ai_providers: reqwest build failed: {e}"); return String::new(); }
    };

    let body = serde_json::json!({
        "model": model, "temperature": 0.1, "max_tokens": 1024,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt}
        ]
    });

    let resp = match http.post(endpoint).bearer_auth(key).json(&body).send().await {
        Ok(r)  => r,
        Err(e) => { error!("ai_providers: request to {endpoint} failed: {e}"); return String::new(); }
    };

    let data = match resp.json::<serde_json::Value>().await {
        Ok(d)  => d,
        Err(e) => { error!("ai_providers: response parse failed: {e}"); return String::new(); }
    };

    data["choices"][0]["message"]["content"].as_str().unwrap_or("").trim().to_string()
}

async fn call_anthropic(p: &AiProvider, system: &str, prompt: &str) -> String {
    let model    = if p.model.is_empty()         { "claude-sonnet-4-6"         } else { p.model.as_str() };
    let base     = if p.base_url.is_empty()      { "https://api.anthropic.com" } else { p.base_url.trim_end_matches('/') };
    let path     = if p.endpoint_path.is_empty() { "/v1/messages"              } else { p.endpoint_path.as_str() };
    let endpoint = format!("{base}{path}");

    let http = match reqwest::Client::builder().timeout(Duration::from_secs(60)).build() {
        Ok(c)  => c,
        Err(e) => { error!("ai_providers: reqwest build failed: {e}"); return String::new(); }
    };

    let resp = match http.post(&endpoint)
        .header("x-api-key", &p.api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": model, "max_tokens": 1024, "system": system,
            "messages": [{"role": "user", "content": prompt}]
        })).send().await
    {
        Ok(r)  => r,
        Err(e) => { error!("ai_providers: Anthropic request to {endpoint} failed: {e}"); return String::new(); }
    };

    let data = match resp.json::<serde_json::Value>().await {
        Ok(d)  => d,
        Err(_) => return String::new(),
    };

    data["content"][0]["text"].as_str().unwrap_or("").trim().to_string()
}
