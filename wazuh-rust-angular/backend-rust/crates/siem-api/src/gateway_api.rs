//! siem-api's internal API for `provigil-gateway` (`specs/provigil-gateway.md` 3.4): the rare work
//! that stays here. On `SIEM_API_INTERNAL_ADDR` (127.0.0.1:9102), each call with
//! `GATEWAY_INTERNAL_TOKEN`; the gateway has checked the agent's key and tenant already.

use std::net::SocketAddr;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use provigil_agent_server::keys::ct_eq;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use crate::AppState;

/// An events batch of the agent (`http.rs` of the gateway) and a little more.
const BODY_LIMIT: usize = 17 * 1024 * 1024;

fn refused(code: StatusCode, message: &str) -> Response {
    (code, Json(json!({ "status": "error", "message": message }))).into_response()
}

async fn guard(State(token): State<String>, req: Request, next: Next) -> Response {
    let sent = req.headers().get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or_default();
    if !ct_eq(sent.as_bytes(), token.as_bytes()) {
        return refused(StatusCode::UNAUTHORIZED, "invalid gateway token");
    }
    next.run(req).await
}

/// `POST /internal/gateway/enroll`: `{request, tenant_key, peer}` → the enrollment's answer.
async fn enroll(State(state): State<AppState>, Json(v): Json<Value>) -> Response {
    let r = &v["request"];
    let s = |k: &str| r[k].as_str().map(str::to_string).filter(|x| !x.is_empty());
    let mut headers = HeaderMap::new();
    if let Some(k) = v["tenant_key"].as_str().and_then(|k| HeaderValue::from_str(k).ok()) {
        headers.insert("x-tenant-key", k);
    }
    let payload = crate::EnrollAgentPayload { name: s("name").unwrap_or_default(), ip: None, groups: s("groups"), os_type: s("os_type"), force: r["force"].as_bool() };
    match crate::enroll_agent(&state, &headers, None, payload).await {
        Ok(a) => Json(a).into_response(),
        Err((code, msg)) => refused(code, &msg),
    }
}

/// `POST /internal/gateway/ar_log`: an agent's response program lines.
async fn ar_log(State(state): State<AppState>, Json(v): Json<Value>) -> Response {
    let (agent, name, ip) = (v["agent_id"].as_str().unwrap_or_default(), v["name"].as_str().unwrap_or_default(), v["ip"].as_str().unwrap_or_default());
    let lines: Vec<String> = v["lines"].as_array().into_iter().flatten().filter_map(|l| l.as_str().map(str::to_string)).collect();
    if agent.is_empty() {
        return refused(StatusCode::BAD_REQUEST, "agent_id is required");
    }
    crate::provigil_manager::on_agent_ar_lines(&state, agent, name, ip, lines).await;
    Json(json!({ "status": "ok" })).into_response()
}

/// `POST /internal/gateway/events`: an agent's events that are siem-api's to handle.
async fn events(State(state): State<AppState>, Json(v): Json<Value>) -> Response {
    let agent = v["agent_id"].as_str().unwrap_or_default().to_string();
    // the gateway proved the key: the agent's own key lets the usual tenant checks pass
    let key = state.auth_keystore.read().unwrap().find_by_id(&agent).map(|k| k.raw_key.clone());
    let Some(key) = key.and_then(|k| HeaderValue::from_str(&format!("Bearer {k}")).ok()) else {
        return refused(StatusCode::NOT_FOUND, "agent not enrolled here");
    };
    let mut headers = HeaderMap::new();
    headers.insert("authorization", key);
    match crate::ingest_batch(&state, &headers, json!({ "agent_id": agent, "events": v["events"] })).await {
        Ok(_) => Json(json!({ "status": "ok" })).into_response(),
        Err(code) => refused(code, "events refused"),
    }
}

/// `POST /internal/gateway/deploy_report`: `{token, from, rows}`, a mass deployment's results.
async fn deploy_report(State(state): State<AppState>, Json(v): Json<Value>) -> Response {
    match crate::deploy_tokens::report(&state, &v).await {
        Ok(n) => Json(json!({ "status": "ok", "stored": n })).into_response(),
        Err((code, msg)) => refused(code, &msg),
    }
}

/// `POST /internal/gateway/keepalives`: batched agent keepalive updates from `provigil-gateway`.
async fn keepalives(State(state): State<AppState>, Json(v): Json<Value>) -> Response {
    let Some(items) = v["items"].as_array() else {
        return refused(StatusCode::BAD_REQUEST, "items array is required");
    };
    let now = chrono::Utc::now();
    let mut updated = 0usize;
    let mut to_save: Vec<(String, siem_core::Agent)> = Vec::new();
    for item in items {
        let Some(agent_id) = item["agent_id"].as_str().map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        if state.deleted_agents.read().unwrap().contains(agent_id)
            || crate::is_deactivated(&state, agent_id)
        {
            continue;
        }
        let enrolled_opt = state.enrolled.read().unwrap().get(agent_id).cloned();
        let tenant = crate::tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id);
        let ip = item["ip"].as_str().map(str::trim).filter(|s| !s.is_empty());
        let version = item["version"].as_str().map(str::trim).filter(|s| !s.is_empty());

        let ag_clone = {
            let mut agents = state.agents.write().unwrap();
            let ag = agents.entry(agent_id.to_string()).or_insert_with(|| {
                let (name, os_type) = enrolled_opt
                    .as_ref()
                    .map(|e| {
                        (
                            e.name.clone(),
                            if e.os_type.is_empty() { "linux".to_string() } else { e.os_type.clone() },
                        )
                    })
                    .unwrap_or_else(|| (agent_id.to_string(), "linux".to_string()));
                siem_core::Agent {
                    id: agent_id.to_string(),
                    name,
                    ip: ip.unwrap_or("any").to_string(),
                    os: if os_type.eq_ignore_ascii_case("windows") { "Windows".into() } else { "Linux".into() },
                    version: version.unwrap_or("1.0.0").to_string(),
                    status: siem_core::AgentStatus::Active,
                    last_keepalive: now,
                    os_type,
                }
            });
            ag.last_keepalive = now;
            ag.status = siem_core::AgentStatus::Active;
            if let Some(ip_val) = ip {
                if ip_val != "any" {
                    ag.ip = ip_val.to_string();
                }
            }
            if let Some(ver_val) = version {
                ag.version = ver_val.to_string();
            }
            ag.clone()
        };
        to_save.push((tenant, ag_clone));
        updated += 1;
    }
    for (tenant, ag) in to_save {
        state.db.save_agent_row(&tenant, &ag);
    }
    Json(json!({ "status": "ok", "updated": updated })).into_response()
}

pub fn app(state: AppState, token: String) -> Router {
    Router::new()
        .route("/internal/gateway/enroll", post(enroll))
        .route("/internal/gateway/ar_log", post(ar_log))
        .route("/internal/gateway/events", post(events))
        .route("/internal/gateway/deploy_report", post(deploy_report))
        .route("/internal/gateway/keepalives", post(keepalives))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(from_fn_with_state(token, guard))
        .with_state(state)
}

/// Starts the listener; without a token there is none (the gateway then answers 503 for this work).
pub fn serve(state: AppState) {
    let Some(token) = std::env::var("GATEWAY_INTERNAL_TOKEN").ok().filter(|t| !t.trim().is_empty()) else {
        return warn!("GATEWAY_INTERNAL_TOKEN is not set: agent enrollment through the gateway is off");
    };
    let addr = std::env::var("SIEM_API_INTERNAL_ADDR").unwrap_or_else(|_| "127.0.0.1:9102".into());
    let Ok(addr) = addr.parse::<SocketAddr>() else {
        return error!("SIEM_API_INTERNAL_ADDR is not an address: {addr}");
    };
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                info!("Gateway internal API on http://{addr}");
                if let Err(e) = axum::serve(l, app(state, token.trim().to_string())).await {
                    error!("Gateway internal API stopped: {e}");
                }
            }
            Err(e) => error!("Gateway internal API not started on {addr}: {e}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn call(app: &Router, path: &str, token: &str, body: Value) -> (u16, Value) {
        use tower::ServiceExt;
        let req = axum::http::Request::post(path).header("authorization", format!("Bearer {token}")).header("content-type", "application/json").body(axum::body::Body::from(body.to_string())).unwrap();
        let r = app.clone().oneshot(req).await.unwrap();
        let code = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (code, serde_json::from_slice(&b).unwrap_or_default())
    }

    #[tokio::test]
    async fn token_enroll_and_events() {
        let state = crate::test_state::state().await;
        state.agent_keys.set_for_test("acme", "tk-acme");
        let app = app(state.clone(), "secret".into());
        assert_eq!(call(&app, "/internal/gateway/enroll", "wrong", json!({})).await.0, 401);
        let (code, a) = call(&app, "/internal/gateway/enroll", "secret", json!({ "request": { "name": "gw-pc", "os_type": "windows" }, "tenant_key": "tk-acme", "peer": "10.0.0.1" })).await;
        assert_eq!((code, a["tenant_id"].as_str()), (200, Some("acme")), "{a}");
        assert!(a["raw_key"].as_str().is_some_and(|k| !k.is_empty()));
        let (code, _) = call(&app, "/internal/gateway/enroll", "secret", json!({ "request": { "name": "x" }, "tenant_key": "nope" })).await;
        assert_eq!(code, 401, "an unknown tenant key");
        let id = a["agent_id"].as_str().unwrap();
        let ev = json!({ "agent": { "id": id, "name": "gw-pc" }, "event_type": "agent_status", "message": "hello" });
        assert_eq!(call(&app, "/internal/gateway/events", "secret", json!({ "agent_id": id, "events": [ev] })).await.0, 200);
        assert_eq!(call(&app, "/internal/gateway/events", "secret", json!({ "agent_id": "99999", "events": [] })).await.0, 404);
        assert_eq!(call(&app, "/internal/gateway/ar_log", "secret", json!({ "agent_id": id, "lines": [] })).await.0, 200);
        if let Some(ag) = state.agents.write().unwrap().get_mut(id) {
            ag.status = siem_core::AgentStatus::Disconnected;
        }
        let (code, kresp) = call(&app, "/internal/gateway/keepalives", "secret", json!({ "items": [{ "agent_id": id, "ip": "10.0.0.5", "version": "1.0.0" }] })).await;
        assert_eq!((code, kresp["updated"].as_u64()), (200, Some(1)));
        assert_eq!(state.agents.read().unwrap().get(id).map(|a| a.status.clone()), Some(siem_core::AgentStatus::Active));
    }
}
