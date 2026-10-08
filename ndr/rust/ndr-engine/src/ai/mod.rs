//! ARIA — AI SOC Assistant
//! Handles OpenAI / Anthropic / custom Chat Completions API calls with live NDR context.

pub mod provider;
pub mod investigator;
pub mod context;
pub mod throttle;

use serde_json::{json, Value};

/// Runtime AI provider configuration — read from ClickHouse settings at request time.
pub struct AiConfig {
    /// "openai" | "anthropic" | "custom"
    pub provider:      String,
    /// API key stored in DB — must be set explicitly; no env var fallback
    pub api_key:       String,
    /// Model override (empty = use provider default)
    pub model:         String,
    /// Base URL, e.g. "https://apifreellm.com" or "http://localhost:11434"
    pub base_url:      String,
    /// Path after base_url, e.g. "/api/v1/chat" or "/v1/chat/completions"
    /// Empty = use provider default
    pub endpoint_path: String,
    /// "openai"  → sends {messages:[...]} array, reads choices[0].message.content
    /// "simple"  → sends {message:"..."} string, reads response field
    pub msg_format:    String,
}

impl AiConfig {
    pub fn from_settings(settings: &Value) -> Self {
        AiConfig {
            provider:      settings["ai_provider"].as_str()
                .unwrap_or("openai").to_string(),
            api_key:       settings["ai_api_key"].as_str()
                .unwrap_or("").to_string(),
            model:         settings["ai_model"].as_str()
                .unwrap_or("").to_string(),
            base_url:      settings["ai_base_url"].as_str()
                .unwrap_or("").to_string(),
            endpoint_path: settings["ai_endpoint_path"].as_str()
                .unwrap_or("").to_string(),
            msg_format:    settings["ai_msg_format"].as_str()
                .unwrap_or("openai").to_string(),
        }
    }

    /// Returns the DB-configured API key only — no env var fallback.
    pub fn effective_key(&self) -> String {
        self.api_key.clone()
    }

    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }
}

/// Build the system prompt with live NDR context
/// injected so Claude knows current threat state.
pub fn build_system_prompt(
    username: &str,
    tenant_id: &str,
    critical_count: u64,
    high_count: u64,
    bundle_count: u64,
    real_context: &str,
) -> String {
    format!(r#"You are ARIA (Autonomous Response & Intelligence Assistant), a SOC assistant built into the NDR (Network Detection & Response) platform.

You are talking to analyst: {username}
Tenant: {tenant_id}

LIVE SYSTEM STATUS:
- Critical alerts (last 24h): {critical_count}
- High alerts (last 24h): {high_count}
- Evidence bundles captured: {bundle_count}

STRICT DATA RULE — THIS IS MANDATORY:
You MUST only answer based on the real data provided below in the DATA section.
NEVER invent, guess, or assume any IP addresses, hostnames, community IDs, rule names, or events.
If the data does not contain what the analyst is asking about, say exactly: "I don't see any [X] in your current data."
Do not use example IPs like 192.168.x.x or 10.x.x.x unless they appear in the DATA section below.

YOUR PERSONALITY:
- Professional but friendly and approachable
- Direct and concise — analysts are busy
- Proactive — always suggest next steps based on REAL data only
- Show genuine concern when threats are real

YOUR CAPABILITIES (mention when relevant):
- Show alert details and evidence bundles
- Explain what a community_id or IP means
- Explain attack narratives from Agent-Z / Agent-S
- Explain conn_state codes (OTH, SF, REJ etc)

NDR PLATFORM CONTEXT:
- Alerts come from Agent-Z + Agent-S via Kafka
- Community ID links Agent-Z conn + Agent-S alert
- HIGH/CRITICAL alerts auto-capture evidence bundles

RESPONSE FORMAT:
- Keep under 150 words unless explaining an attack
- Use plain text, no markdown formatting
- Reference specific IPs, timestamps, rule names from the DATA section
- End with a suggested next action

EMOTION HINTS (include at very END of response):
[EMO:alert] — new threats found
[EMO:cheer] — all clear
[EMO:think] — analyzing
[EMO:sad]   — concerning pattern
[EMO:wave]  — greeting
[EMO:idle]  — default

=== DATA FROM {tenant_id} TENANT (use ONLY this) ===
{real_context}
=== END OF DATA ===
"#)
}

/// Parse emotion hint from response
pub fn extract_emotion(text: &str)
    -> (String, String)
{
    let emotions = [
        "[EMO:alert]", "[EMO:cheer]",
        "[EMO:think]", "[EMO:sad]",
        "[EMO:wave]",  "[EMO:idle]",
    ];
    for tag in &emotions {
        if text.contains(tag) {
            let clean = text.replace(tag, "")
                .trim().to_string();
            let emo = tag
                .trim_start_matches("[EMO:")
                .trim_end_matches(']')
                .to_string();
            return (clean, emo);
        }
    }
    (text.to_string(), "idle".to_string())
}

/// Route AI call using the multi-provider system from DB.
#[allow(dead_code)]
pub async fn call_ai(
    config: &AiConfig,
    system_prompt: &str,
    history: &[Value],
    user_message: &str,
) -> anyhow::Result<(String, String)> {
    let key = config.effective_key();

    if config.provider == "anthropic" {
        return call_claude(&key, system_prompt, history, user_message).await;
    }

    let base_url = if !config.base_url.is_empty() {
        config.base_url.trim_end_matches('/').to_string()
    } else {
        "https://api.openai.com".to_string()
    };
    let path = if !config.endpoint_path.is_empty() {
        config.endpoint_path.clone()
    } else {
        "/v1/chat/completions".to_string()
    };
    let endpoint = format!("{}{}", base_url, path);

    if config.msg_format == "simple" {
        call_simple_format(&key, &endpoint, system_prompt, history, user_message).await
    } else {
        let model = if !config.model.is_empty() {
            config.model.clone()
        } else {
            "gpt-4o-mini".to_string()
        };
        call_openai_format(&key, &model, &endpoint, system_prompt, history, user_message).await
    }
}

/// OpenAI-compatible format: sends {messages:[...]} array,
/// reads choices[0].message.content from response.
async fn call_openai_format(
    api_key: &str,
    model: &str,
    endpoint: &str,
    system_prompt: &str,
    history: &[Value],
    user_message: &str,
) -> anyhow::Result<(String, String)> {
    if api_key.is_empty() {
        return Ok((
            "AI not configured — add an API key in Settings > AI Configuration."
                .to_string(),
            "sad".to_string(),
        ));
    }

    let mut messages: Vec<Value> = vec![
        json!({ "role": "system", "content": system_prompt })
    ];
    for m in history {
        let role = m["role"].as_str().unwrap_or("");
        if role == "user" || role == "assistant" {
            messages.push(m.clone());
        }
    }
    messages.push(json!({ "role": "user", "content": user_message }));

    if messages.len() > 21 {
        let system_msg = messages.remove(0);
        let keep = messages.split_off(messages.len() - 20);
        messages = std::iter::once(system_msg).chain(keep).collect();
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = http
        .post(endpoint)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(&json!({ "model": model, "max_tokens": 350, "messages": messages }))
        .send()
        .await?;

    let data = resp.json::<Value>().await?;

    let raw = data["choices"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c["message"]["content"].as_str())
        .unwrap_or(
            "I'm having trouble connecting to the AI provider. \
             Check AI configuration in Settings."
        )
        .to_string();

    Ok(extract_emotion(&raw))
}

/// Simple format: sends {"message":"..."} string,
/// reads top-level "response" field from reply.
#[allow(dead_code)]
async fn call_simple_format(
    api_key: &str,
    endpoint: &str,
    system_prompt: &str,
    history: &[Value],
    user_message: &str,
) -> anyhow::Result<(String, String)> {
    if api_key.is_empty() {
        return Ok((
            "AI not configured — add an API key in Settings > AI Configuration."
                .to_string(),
            "sad".to_string(),
        ));
    }

    // Flatten system prompt + history + user message into one string
    let mut parts: Vec<String> = Vec::new();
    let sys_short: String = system_prompt.chars().take(400).collect();
    parts.push(format!("[System]: {}", sys_short.replace('\n', " ")));

    let history_slice = if history.len() > 6 { &history[history.len() - 6..] } else { history };
    for m in history_slice {
        let role    = m["role"].as_str().unwrap_or("user");
        let content = m["content"].as_str().unwrap_or("");
        parts.push(format!("[{}]: {}", if role == "assistant" { "Assistant" } else { "User" }, content));
    }
    parts.push(format!("[User]: {}", user_message));

    let combined = parts.join("\n");

    // Use 70 s timeout — free tier APIs often have processing delay
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(70))
        .build()?;

    let resp = http
        .post(endpoint)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(&json!({ "message": combined }))
        .send()
        .await?;

    let data = resp.json::<Value>().await?;

    let raw = data["response"]
        .as_str()
        .unwrap_or(
            "I'm having trouble connecting. \
             Check AI configuration in Settings."
        )
        .to_string();

    Ok(extract_emotion(&raw))
}

/// Call OpenAI Chat Completions API with default endpoint and model.
#[allow(dead_code)]
pub async fn call_openai(
    api_key: &str,
    system_prompt: &str,
    history: &[Value],
    user_message: &str,
) -> anyhow::Result<(String, String)> {
    call_openai_format(
        api_key,
        "gpt-4o-mini",
        "https://api.openai.com/v1/chat/completions",
        system_prompt,
        history,
        user_message,
    ).await
}

#[allow(dead_code)]
pub async fn call_claude(
    api_key: &str,
    system_prompt: &str,
    history: &[Value],
    user_message: &str,
) -> anyhow::Result<(String, String)> {
    if api_key.is_empty() {
        return Ok((
            "AI not configured — add an Anthropic API key in Settings > AI Configuration."
                .to_string(),
            "sad".to_string(),
        ));
    }

    let mut messages: Vec<Value> = history
        .iter()
        .filter(|m| {
            m["role"].as_str()
                .map(|r| r == "user"
                      || r == "assistant")
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    messages.push(json!({
        "role": "user",
        "content": user_message
    }));

    if messages.len() > 20 {
        let len = messages.len();
        messages = messages[len - 20..].to_vec();
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = http
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 300,
            "system": system_prompt,
            "messages": messages
        }))
        .send()
        .await?;

    let data = resp.json::<Value>().await?;

    let raw = data["content"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or(
            "I'm having trouble connecting. \
             Check AI configuration in Settings."
        )
        .to_string();

    Ok(extract_emotion(&raw))
}

#[allow(dead_code)]
async fn call_ollama_chat(
    system_prompt: &str,
    history: &[Value],
    user_message: &str,
) -> anyhow::Result<(String, String)> {
    let url = std::env::var("OLLAMA_URL")
        .unwrap_or_else(|_| "http://localhost:11434".to_string());
    let model = std::env::var("OLLAMA_MODEL")
        .unwrap_or_else(|_| "deepseek-r1:8b".to_string());

    let mut messages = vec![json!({"role": "system", "content": system_prompt})];

    for msg in history {
        let role = msg["role"].as_str().unwrap_or("user");
        let content = msg["content"].as_str().unwrap_or("");
        if !content.is_empty() {
            messages.push(json!({"role": role, "content": content}));
        }
    }
    messages.push(json!({"role": "user", "content": user_message}));

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .unwrap_or_default();

    let resp = http
        .post(format!("{}/api/chat", url))
        .json(&json!({
            "model": model,
            "stream": false,
            "options": {"temperature": 0.7, "num_predict": 1024},
            "messages": messages
        }))
        .send().await
        .map_err(|e| anyhow::anyhow!("Ollama request failed: {}", e))?;

    let data: Value = resp.json().await
        .map_err(|e| anyhow::anyhow!("Ollama parse failed: {}", e))?;

    let raw = data["message"]["content"]
        .as_str()
        .unwrap_or("I'm having trouble connecting.")
        .to_string();

    // Strip DeepSeek-R1 think tags
    let cleaned = if let Some(end) = raw.rfind("</think>") {
        raw[end + 8..].trim().to_string()
    } else {
        raw.trim().to_string()
    };

    tracing::debug!("Ollama ARIA response: {} chars", cleaned.len());
    Ok(extract_emotion(&cleaned))
}
