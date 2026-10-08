// AI provider dispatch — delegates to provigil_common::ai for provider loading,
// caching, and simple (non-chat) generation. Adds generate_chat() with full
// conversation history support for ARIA, and test/admin helpers for the settings UI.

pub use provigil_common::ai::AiProvider;
use tracing::warn;

// ── Use-case tags ─────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub enum UseCase {
    ThreatPrediction,
    AriaChatResponse,
}

impl UseCase {
    pub fn tag(&self) -> &'static str {
        match self {
            UseCase::ThreatPrediction => "threat",
            UseCase::AriaChatResponse => "chat",
        }
    }
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// System + single prompt → plain text.
/// Delegates to provigil_common::ai::generate_simple() — DB-driven, priority-ordered.
pub async fn generate(
    storage: &crate::storage::ClickhouseStorage,
    use_case: UseCase,
    system: &str,
    prompt: &str,
) -> String {
    provigil_common::ai::generate_simple(&storage.client, use_case.tag(), system, prompt).await
}

/// ARIA chat — full conversation history → (text, emotion).
/// Uses the same DB-driven provider list; adds multi-turn history support.
pub async fn generate_chat(
    storage: &crate::storage::ClickhouseStorage,
    system: &str,
    history: &[serde_json::Value],
    user_msg: &str,
) -> anyhow::Result<(String, String)> {
    let providers = provigil_common::ai::get_ai_providers(&storage.client, "chat").await;

    for p in &providers {
        if p.api_key.is_empty() { continue; }
        let result = call_provider_chat(p, system, history, user_msg).await;
        if let Ok((ref text, _)) = result {
            if !text.is_empty() { return result; }
        }
        warn!("Chat provider '{}' returned empty", p.name);
    }

    env_fallback_chat(system, history, user_msg).await
}

// ── Admin/test helpers (settings UI) ─────────────────────────────────────────

/// Called by the test endpoint — tries a specific provider and returns the raw error
/// instead of a generic message so the admin can diagnose misconfiguration.
pub async fn call_provider_test(p: &AiProvider, system: &str, prompt: &str) -> Result<String, String> {
    if p.provider_type == "anthropic" {
        return call_anthropic_test(p, system, prompt).await;
    }
    let (base, path, model) = resolve_openai_params(p);
    call_openai_compat_test(&p.api_key, &model, &format!("{base}{path}"), system, prompt).await
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn resolve_openai_params(p: &AiProvider) -> (String, String, String) {
    let base = if p.base_url.is_empty() {
        "https://api.openai.com".to_string()
    } else {
        p.base_url.trim_end_matches('/').to_string()
    };
    let path = if p.endpoint_path.is_empty() {
        "/v1/chat/completions".to_string()
    } else {
        p.endpoint_path.clone()
    };
    let model = if p.model.is_empty() { "gpt-4o-mini".to_string() } else { p.model.clone() };
    (base, path, model)
}

async fn call_provider_chat(
    p: &AiProvider,
    system: &str,
    history: &[serde_json::Value],
    user_msg: &str,
) -> anyhow::Result<(String, String)> {
    if p.provider_type == "anthropic" {
        return call_claude_chat(p, system, history, user_msg).await;
    }
    let (base, path, model) = resolve_openai_params(p);
    call_openai_chat(&p.api_key, &model, &format!("{base}{path}"), system, history, user_msg).await
}

async fn call_openai_compat_test(key: &str, model: &str, endpoint: &str, system: &str, prompt: &str) -> Result<String, String> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let body = serde_json::json!({
        "model": model, "temperature": 0.1, "max_tokens": 64,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt}
        ]
    });

    let resp = http.post(endpoint).bearer_auth(key).json(&body).send().await
        .map_err(|e| format!("Connection failed: {}", e))?;

    let status = resp.status();
    let data: serde_json::Value = resp.json().await
        .map_err(|e| format!("Response parse failed (HTTP {}): {}", status, e))?;

    if let Some(err) = data["error"]["message"].as_str() {
        return Err(err.to_string());
    }

    let text = data["choices"][0]["message"]["content"].as_str().unwrap_or("").trim().to_string();
    if text.is_empty() { Err(format!("API returned empty content (HTTP {})", status)) } else { Ok(text) }
}

async fn call_anthropic_test(p: &AiProvider, system: &str, prompt: &str) -> Result<String, String> {
    let model    = if p.model.is_empty()         { "claude-sonnet-4-6"         } else { p.model.as_str() };
    let base     = if p.base_url.is_empty()      { "https://api.anthropic.com" } else { p.base_url.trim_end_matches('/') };
    let path     = if p.endpoint_path.is_empty() { "/v1/messages"              } else { p.endpoint_path.as_str() };
    let endpoint = format!("{base}{path}");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = http.post(&endpoint)
        .header("x-api-key", &p.api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": model, "max_tokens": 64, "system": system,
            "messages": [{"role": "user", "content": prompt}]
        })).send().await
        .map_err(|e| format!("Connection to {} failed: {}", endpoint, e))?;

    let status = resp.status();
    let data: serde_json::Value = resp.json().await
        .map_err(|e| format!("Response parse failed (HTTP {}): {}", status, e))?;

    if let Some(err) = data["error"]["message"].as_str() {
        return Err(err.to_string());
    }

    let text = data["content"][0]["text"].as_str().unwrap_or("").trim().to_string();
    if text.is_empty() { Err(format!("Empty content from {} (HTTP {})", endpoint, status)) } else { Ok(text) }
}

async fn call_openai_chat(
    key: &str, model: &str, endpoint: &str,
    system: &str, history: &[serde_json::Value], user_msg: &str,
) -> anyhow::Result<(String, String)> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut messages = vec![serde_json::json!({"role": "system", "content": system})];
    messages.extend_from_slice(history);
    messages.push(serde_json::json!({"role": "user", "content": user_msg}));

    let resp = http.post(endpoint).bearer_auth(key)
        .json(&serde_json::json!({"model": model, "temperature": 0.7, "max_tokens": 1024, "messages": messages}))
        .send().await?;

    let data: serde_json::Value = resp.json().await?;
    if let Some(err) = data["error"]["message"].as_str() {
        anyhow::bail!("API error: {}", err);
    }

    let text = data["choices"][0]["message"]["content"].as_str().unwrap_or("").trim().to_string();
    let (clean, emotion) = crate::ai::extract_emotion(&text);
    Ok((clean, emotion))
}

async fn call_claude_chat(
    p: &AiProvider, system: &str, history: &[serde_json::Value], user_msg: &str,
) -> anyhow::Result<(String, String)> {
    let model    = if p.model.is_empty()         { "claude-sonnet-4-6"         } else { p.model.as_str() };
    let base     = if p.base_url.is_empty()      { "https://api.anthropic.com" } else { p.base_url.trim_end_matches('/') };
    let path     = if p.endpoint_path.is_empty() { "/v1/messages"              } else { p.endpoint_path.as_str() };
    let endpoint = format!("{base}{path}");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut messages: Vec<serde_json::Value> = history.to_vec();
    messages.push(serde_json::json!({"role": "user", "content": user_msg}));

    let resp = http.post(&endpoint)
        .header("x-api-key", &p.api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({"model": model, "max_tokens": 1024, "system": system, "messages": messages}))
        .send().await?;

    let data: serde_json::Value = resp.json().await?;
    if let Some(err) = data["error"]["message"].as_str() {
        anyhow::bail!("Anthropic error: {}", err);
    }

    let text = data["content"][0]["text"].as_str().unwrap_or("").trim().to_string();
    let (clean, emotion) = crate::ai::extract_emotion(&text);
    Ok((clean, emotion))
}

async fn env_fallback_chat(
    _system: &str, _history: &[serde_json::Value], _user_msg: &str,
) -> anyhow::Result<(String, String)> {
    Ok(("AI not configured — add a provider in Settings > AI Configuration.".to_string(), "sad".to_string()))
}
