//! siem-api's internal API, for the work that stays there (`specs/provigil-gateway.md` 3.4).
//! siem-api does not serve it yet: phase 2 adds these three routes.

use std::time::Duration;

use serde_json::{json, Value};

const LIMIT: Duration = Duration::from_secs(5);

pub struct Upstream {
    url: String,
    token: String,
    http: reqwest::Client,
}

/// Status when siem-api refused or was not reached (503): (code, message).
pub type Refused = (u16, String);

impl Upstream {
    pub fn new(url: &str, token: &str) -> Self {
        Self { url: url.to_string(), token: token.to_string(), http: reqwest::Client::builder().timeout(LIMIT).build().expect("HTTP client") }
    }

    async fn call(&self, path: &str, body: &Value) -> Result<Value, Refused> {
        if self.url.is_empty() {
            return Err((503, "SIEM_API_INTERNAL_URL is not set".into()));
        }
        let r = self.http.post(format!("{}/internal/gateway/{path}", self.url)).bearer_auth(&self.token).json(body).send().await.map_err(|e| (503, e.to_string()))?;
        let code = r.status().as_u16();
        if r.status().is_success() {
            return Ok(r.json().await.unwrap_or_default());
        }
        let message = r.text().await.unwrap_or_default();
        // siem-api's own failure is the agent's "come back later"
        Err((if code >= 500 { 503 } else { code }, message))
    }

    /// An agent's enrollment: the answer of S14.
    pub async fn enroll(&self, request: &Value, tenant_key: &str, peer: &str) -> Result<Value, Refused> {
        self.call("enroll", &json!({ "request": request, "tenant_key": tenant_key, "peer": peer })).await
    }

    pub async fn ar_log(&self, agent: &str, tenant: &str, name: &str, ip: &str, lines: &[String]) -> Result<(), Refused> {
        self.call("ar_log", &json!({ "agent_id": agent, "tenant_id": tenant, "name": name, "ip": ip, "lines": lines })).await.map(drop)
    }

    pub async fn events(&self, agent: &str, tenant: &str, events: &[Value]) -> Result<(), Refused> {
        self.call("events", &json!({ "agent_id": agent, "tenant_id": tenant, "events": events })).await.map(drop)
    }
}
