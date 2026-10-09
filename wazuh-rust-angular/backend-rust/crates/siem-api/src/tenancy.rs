//! Multi-tenancy for the SIEM API on top of the shared NDR auth-service.
//!
//! * **Identity is auth-service's.** Users, tenants, login, logout and
//!   sessions live in auth-service (`ndr.users`, `ndr.tenants`, Valkey).
//!   siem-api only validates its tokens with provigil-common's
//!   `validate_jwt` (same `JWT_SECRET`) and checks that the session is still
//!   alive in Valkey (`ndr:session:<jti>`), so logouts and revocations apply
//!   here too.
//! * **One ClickHouse database per tenant.** auth-service creates
//!   `ndr_<id>` with the NDR tables. siem-api adds the SIEM tables (cloned
//!   from `ndr`) to every tenant database it finds in `ndr.tenants`.
//!   The NDR `default` tenant keeps `ndr`.
//! * **Scoping.** Agents belong to the tenant whose agent key they use
//!   (`X-Tenant-Key`), events carry `metadata["tenant_id"]` and alerts
//!   `data["tenant_id"]`. A user sees only their tenant's data. A
//!   super_admin sees `default` and can pick another tenant with
//!   `?tenant_id=` or the `X-Tenant-Id` header.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use siem_core::{Alert, RawEvent};

use crate::AppState;

/// The NDR main tenant (super admins belong to it).
pub const DEFAULT_TENANT: &str = "default";
pub const DEFAULT_DB: &str = "ndr";

/// SIEM data tables every tenant database gets (cloned from `ndr`).
pub const TENANT_TABLES: &[&str] = &[
    "siem_events",
    "siem_alerts",
    "siem_agents",
    "siem_active_responses",
    "ndr_network_flows",
    "ndr_threats",
    "xdr_incidents",
];

/// The authenticated caller (from an auth-service token).
#[derive(Debug, Clone)]
pub struct AuthCtx {
    pub username: String,
    pub role: String,
    pub tenant_id: String,
    pub permissions: Vec<String>,
    pub features: Vec<String>,
    /// Tenant picked with `?tenant_id=` / `X-Tenant-Id` (super_admin only).
    pub requested_tenant: Option<String>,
}

impl AuthCtx {
    pub fn is_super(&self) -> bool {
        self.role == "super_admin" || self.role == "admin"
    }

    pub fn is_tenant_admin(&self) -> bool {
        self.role == "tenant_admin"
    }

    /// The single tenant whose data this request reads and writes.
    pub fn scope(&self) -> String {
        if self.is_super() {
            if let Some(t) = self.requested_tenant.as_deref().filter(|t| !t.is_empty()) {
                return normalize_tenant(t);
            }
        }
        normalize_tenant(&self.tenant_id)
    }

    /// Page permission check, as in the UI: admin roles have every page.
    pub fn has_permission(&self, perm: &str) -> bool {
        self.is_super() || self.is_tenant_admin() || self.permissions.iter().any(|p| p == perm || p == "all")
    }

    /// Whether the caller administers `tenant`.
    pub fn can_manage(&self, tenant: &str) -> bool {
        self.is_super() || (self.is_tenant_admin() && normalize_tenant(&self.tenant_id) == normalize_tenant(tenant))
    }
}

/// Untagged legacy data and the old SIEM-only `global` id mean `default`.
pub fn normalize_tenant(t: &str) -> String {
    if t.is_empty() || t == "global" {
        DEFAULT_TENANT.to_string()
    } else {
        t.to_string()
    }
}

/// The JWT secret shared with auth-service. There is no default: without
/// it siem-api refuses to start.
pub fn jwt_secret() -> &'static str {
    static SECRET: OnceLock<String> = OnceLock::new();
    SECRET.get_or_init(|| {
        std::env::var("JWT_SECRET").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| {
            std::fs::read_to_string(crate::data_file_path("jwt_secret.txt"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        })
    })
}

/// Same naming as auth-service (`ndr_<id>`, '-' becomes '_'); `default`
/// keeps `ndr`.
pub fn tenant_db_name(tenant_id: &str) -> String {
    let t = normalize_tenant(tenant_id);
    if t == DEFAULT_TENANT {
        return DEFAULT_DB.to_string();
    }
    let s: String = t.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    format!("ndr_{s}")
}

pub fn tenant_of(map: &HashMap<String, String>, agent_id: &str) -> String {
    map.get(agent_id).cloned().unwrap_or_else(|| DEFAULT_TENANT.to_string())
}

/// Tenant of an alert: `data["tenant_id"]`, else its agent's tenant.
pub fn alert_tenant(a: &Alert, agent_tenants: &HashMap<String, String>) -> String {
    if let Some(t) = a.data.get("tenant_id").and_then(|v| v.as_str()) {
        return normalize_tenant(t);
    }
    tenant_of(agent_tenants, &a.agent.id)
}

/// Tenant of an event: `metadata["tenant_id"]`, else its agent's tenant.
pub fn event_tenant(e: &RawEvent, agent_tenants: &HashMap<String, String>) -> String {
    if let Some(t) = e.metadata.get("tenant_id") {
        return normalize_tenant(t);
    }
    tenant_of(agent_tenants, &e.agent_id)
}

pub fn tag_alert(mut a: Alert, tenant: &str) -> Alert {
    a.data.insert("tenant_id".into(), serde_json::Value::String(normalize_tenant(tenant)));
    a
}

// ───────────────────────── agent keys ─────────────────────────

/// Per-tenant agent keys: agents send their tenant's key as `X-Tenant-Key`.
/// Stored in ClickHouse (`ndr.tenant_agent_keys`); this is the
/// in-memory copy, loaded at startup and written through on every change.
pub struct AgentKeys {
    keys: RwLock<HashMap<String, String>>,
}

impl AgentKeys {
    pub fn new() -> Self {
        Self { keys: RwLock::new(HashMap::new()) }
    }

    /// Loads the keys stored in ClickHouse.
    pub async fn load_from(&self, db: &crate::db::ClickHouseDb) {
        if let Some(rows) = db.fetch_tenant_agent_keys().await {
            let mut m = self.keys.write().unwrap();
            for r in rows {
                m.insert(normalize_tenant(&r.tenant_id), r.agent_key);
            }
            tracing::info!("Loaded {} tenant agent keys from ClickHouse", m.len());
        }
    }

    fn new_key() -> String {
        format!("tk_{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
    }

    /// The tenant's key, created (and stored) on first use.
    pub async fn get_or_create(&self, db: &crate::db::ClickHouseDb, tenant: &str) -> String {
        let t = normalize_tenant(tenant);
        let created = {
            let mut m = self.keys.write().unwrap();
            if let Some(k) = m.get(&t) {
                return k.clone();
            }
            let k = Self::new_key();
            m.insert(t.clone(), k.clone());
            k
        };
        db.save_tenant_agent_key(&t, &created).await;
        created
    }

    /// Issues a new key for the tenant (the old one stops working).
    pub async fn rotate(&self, db: &crate::db::ClickHouseDb, tenant: &str) -> String {
        let t = normalize_tenant(tenant);
        let k = Self::new_key();
        self.keys.write().unwrap().insert(t.clone(), k.clone());
        db.save_tenant_agent_key(&t, &k).await;
        k
    }

    /// The tenant a key belongs to.
    pub fn tenant_for(&self, key: &str) -> Option<String> {
        let m = self.keys.read().unwrap();
        m.iter().find(|(_, k)| constant_time_eq(k.as_bytes(), key.as_bytes())).map(|(t, _)| t.clone())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ───────────────────────── sessions (Valkey) ─────────────────────────

static VALKEY: OnceLock<redis::aio::ConnectionManager> = OnceLock::new();

/// Connects to the Valkey instance auth-service writes its sessions to.
pub async fn init_valkey() -> Result<(), String> {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let client = redis::Client::open(url.as_str()).map_err(|e| format!("VALKEY_URL {url}: {e}"))?;
    let cm = redis::aio::ConnectionManager::new(client).await.map_err(|e| format!("Valkey {url}: {e}"))?;
    let _ = VALKEY.set(cm);
    Ok(())
}

/// Whether auth-service still has this session (logout / force-logout
/// delete it).
async fn session_alive(jti: &str) -> Result<bool, Response> {
    let Some(cm) = VALKEY.get() else {
        return Err(service_unavailable());
    };
    let mut c = cm.clone();
    redis::cmd("EXISTS")
        .arg(format!("ndr:session:{jti}"))
        .query_async::<_, i64>(&mut c)
        .await
        .map(|n| n > 0)
        .map_err(|_| service_unavailable())
}

fn service_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "status": "error", "message": "Session store unavailable" })),
    )
        .into_response()
}

fn unauthorized(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "status": "error", "message": msg }))).into_response()
}

pub fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, Json(serde_json::json!({ "status": "error", "message": "Forbidden" }))).into_response()
}

/// Routes that work without a user token (agents, health, downloads).
fn is_public(method: &Method, path: &str) -> bool {
    let p = path.trim_end_matches('/');
    matches!(
        p,
        "/api/health" | "/health" | "/api/v1/ingest" | "/api/events/ingest" | "/api/v1/agent/commands/ack" | "/api/v1/agents/enroll" | "/api/v1/agent/state"
    ) || (method == Method::GET && p == "/api/v1/agent/commands")
        || (method == Method::GET && p.starts_with("/api/agents/") && p.ends_with("/commands"))
        || p.starts_with("/downloads/")
        || (method == Method::POST && (p == "/api/client-errors" || p == "/api/admin/client-errors"))
        || method == Method::OPTIONS
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| percent_decode(v))
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Token from `Authorization: Bearer`, the auth-service `ndr_token` cookie,
/// or (WebSockets only) `?token=`.
fn extract_token(req: &Request<Body>, allow_query: bool) -> Option<String> {
    let h = req.headers();
    if let Some(t) = h
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(t.trim().to_string());
    }
    if let Some(t) = h
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').find_map(|p| p.trim().strip_prefix("ndr_token=").map(str::to_owned)))
    {
        return Some(t);
    }
    if allow_query {
        return query_param(req.uri().query(), "token");
    }
    None
}

/// Builds the caller's context from an auth-service token.
pub async fn ctx_from_token(state: &AppState, token: &str) -> Result<AuthCtx, Response> {
    let claims = provigil_common::validate_jwt(token, jwt_secret()).map_err(|_| unauthorized("Token invalid or expired"))?;
    if !session_alive(&claims.jti).await? {
        return Err(unauthorized("Session revoked — please log in again"));
    }
    let tenant = normalize_tenant(&claims.tenant_id);
    if tenant != DEFAULT_TENANT {
        let tenants = state.tenants.read().unwrap();
        // Unknown until the first registry sync: let auth-service's word stand.
        if let Some(t) = tenants.iter().find(|t| t.id == tenant) {
            if !t.active {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({ "status": "error", "code": "TENANT_DISABLED", "message": "Tenant is disabled" })),
                )
                    .into_response());
            }
        }
    }
    let role = if claims.role == "admin" { "super_admin".to_string() } else { claims.role };
    Ok(AuthCtx {
        username: claims.sub,
        role,
        tenant_id: tenant,
        permissions: claims.permissions,
        features: claims.features,
        requested_tenant: None,
    })
}

/// Axum middleware: authenticates every non-public route.
pub async fn auth_middleware(State(state): State<AppState>, mut req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let is_ws = matches!(path.as_str(), "/ws" | "/ws/alerts" | "/api/ws");
    let token = extract_token(&req, is_ws);

    if is_public(req.method(), &path) {
        // Public routes still get the caller's context when a valid token came along.
        if let Some(t) = token {
            if let Ok(ctx) = ctx_from_token(&state, &t).await {
                req.extensions_mut().insert(ctx);
            }
        }
        return next.run(req).await;
    }

    let Some(token) = token else {
        return unauthorized("Unauthorized");
    };
    let mut ctx = match ctx_from_token(&state, &token).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if ctx.is_super() {
        ctx.requested_tenant = req
            .headers()
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| query_param(req.uri().query(), "tenant_id"));
    }
    // Page permissions (assigned in auth-service): analysts only reach the
    // APIs of the pages they were given. Admin roles see every page.
    if let Some(perm) = required_permission(req.method(), &path) {
        if !ctx.has_permission(perm) {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "status": "error", "code": "PERMISSION_DENIED", "message": format!("Missing permission '{perm}'") })),
            )
                .into_response();
        }
    }
    // Per-agent routes: another tenant's agent does not exist for the caller.
    if let Some(agent_id) = agent_id_in_path(&path) {
        let owner = tenant_of(&state.agent_tenants.read().unwrap(), agent_id);
        if owner != ctx.scope() {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "error", "message": "Agent not found" })))
                .into_response();
        }
    }
    req.extensions_mut().insert(ctx);
    next.run(req).await
}

/// The page permission an API belongs to (the same keys the user editor
/// assigns: `siem-agents`, `siem-fim`, ...). `None`: any signed-in user.
fn required_permission(method: &Method, path: &str) -> Option<&'static str> {
    let p = path.trim_end_matches('/');
    let starts = |prefix: &str| p == prefix || p.starts_with(&format!("{prefix}/"));
    let agent_sub = |sub: &str| {
        (p.starts_with("/api/v1/agents/") || p.starts_with("/api/agents/")) && p.contains(&format!("/{sub}"))
    };
    if starts("/api/v1/vulnerabilities") || agent_sub("vulnerabilities") || agent_sub("syscollector/packages") {
        Some("siem-vulnerabilities")
    } else if starts("/api/v1/compliance") || agent_sub("sca") {
        Some("siem-compliance")
    } else if starts("/api/v1/mitre") {
        Some("siem-mitre")
    } else if starts("/api/v1/fim") || agent_sub("fim") || p == "/syscheck" || p == "/api/v1/syscheck" {
        Some("siem-fim")
    } else if starts("/api/v1/active-response") {
        Some("siem-active-response")
    } else if starts("/api/v1/logtest") {
        Some("siem-logtest")
    } else if starts("/api/v1/parsers") {
        Some("siem-parsers")
    } else if starts("/api/siem/sources") || starts("/api/sources") {
        Some("siem-sources")
    } else if starts("/api/v1/xdr") || starts("/api/threat-map") {
        Some("alerts")
    } else if starts("/api/v1/agents") || starts("/api/agents") || p == "/agents" || (method == Method::POST && p == "/api/v1/agent/commands") {
        Some("siem-agents")
    } else {
        None
    }
}

/// The `<id>` of `/api/v1/agents/<id>[/...]` and `/api/agents/<id>[/...]`.
fn agent_id_in_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/api/v1/agents/").or_else(|| path.strip_prefix("/api/agents/"))?;
    let id = rest.split('/').next().filter(|s| !s.is_empty())?;
    (id != "enroll" && id != "deactivated").then_some(id)
}

// ───────────────────────── tenant registry sync ─────────────────────────

#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct NdrTenantRow {
    id: String,
    name: String,
    active: u8,
    ai_enabled: u8,
    features: String,
}

/// Loads `ndr.tenants` into `state.tenants` and makes sure every tenant
/// database has the SIEM tables. Runs at startup and every 30 s, so tenants
/// created in auth-service become usable here within that time.
pub async fn sync_tenants(state: &AppState) {
    if !state.db.is_connected() {
        return;
    }
    let rows = match state
        .db
        .root()
        .query("SELECT id, name, active, ai_enabled, coalesce(features, '') AS features FROM ndr.tenants FINAL")
        .fetch_all::<NdrTenantRow>()
        .await
    {
        Ok(r) if !r.is_empty() => r,
        _ => match state
            .db
            .root()
            .query("SELECT id, name, active, ai_enabled, coalesce(features, '') AS features FROM ndr.tenants FINAL")
            .fetch_all::<NdrTenantRow>()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Tenant registry sync: cannot read tenants from ClickHouse: {}", e);
                return;
            }
        },
    };
    let mut list = Vec::with_capacity(rows.len());
    for r in rows {
        let db = tenant_db_name(&r.id);
        if r.active == 1 {
            if let Err(e) = state.db.provision_tenant_db(&r.id).await {
                tracing::warn!("Tenant '{}': SIEM tables in {} not ready: {}", r.id, db, e);
            }
        }
        list.push(crate::TenantRecord {
            id: r.id,
            name: r.name,
            plan: "enterprise".into(),
            features: r.features.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            created_at: chrono::Utc::now(),
            active: r.active == 1,
            agent_count: 0,
            ai_enabled: r.ai_enabled == 1,
            db_name: db,
        });
    }
    {
        let agent_tenants = state.agent_tenants.read().unwrap();
        for t in list.iter_mut() {
            t.agent_count = agent_tenants.values().filter(|v| **v == t.id).count();
        }
    }
    *state.tenants.write().unwrap() = list;
}

pub fn spawn_tenant_sync(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            sync_tenants(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_names() {
        assert_eq!(tenant_db_name("default"), "ndr");
        assert_eq!(tenant_db_name("global"), "ndr");
        assert_eq!(tenant_db_name("akm"), "ndr_akm");
        assert_eq!(tenant_db_name("acme-corp"), "ndr_acme_corp");
    }

    #[test]
    fn public_routes() {
        assert!(is_public(&Method::POST, "/api/v1/ingest"));
        assert!(is_public(&Method::GET, "/api/v1/agent/commands"));
        assert!(!is_public(&Method::POST, "/api/v1/agent/commands"));
        assert!(!is_public(&Method::GET, "/api/v1/alerts"));
        assert!(!is_public(&Method::POST, "/api/auth/tenants"));
        assert_eq!(query_param(Some("a=1&token=x%2Fy"), "token").as_deref(), Some("x/y"));
    }

    #[test]
    fn scope() {
        let mut c = AuthCtx {
            username: "u".into(),
            role: "analyst".into(),
            tenant_id: "akm".into(),
            permissions: vec![],
            features: vec![],
            requested_tenant: Some("other".into()),
        };
        assert_eq!(c.scope(), "akm");
        c.role = "super_admin".into();
        assert_eq!(c.scope(), "other");
        c.requested_tenant = None;
        c.tenant_id = "default".into();
        assert_eq!(c.scope(), "default");
    }
}
