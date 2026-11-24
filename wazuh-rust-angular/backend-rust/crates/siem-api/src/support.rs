//! Support requests (`ndr.support_messages`): users and tenant admins ask, tenant admins answer
//! or forward to the platform's super admin, who answers forwarded requests and those of the
//! `default` client. siem-api is the platform server, so this works in every install (it used
//! to live only in the NDR engine; the same table, checks and replies).

use axum::extract::{Extension, Path, State};
use axum::Json;
use serde_json::{json, Value};
use std::time::Duration;

use crate::tenancy::AuthCtx;
use crate::AppState;

const SELECT: &str = "SELECT id, tenant_id, sender_username, sender_role, subject, category, message, \
    status, admin_reply, replied_by, forwarded, forwarded_by, deleted, \
    toString(created_at) AS created_at, toString(updated_at) AS updated_at, \
    if(isNull(replied_at), '', toString(assumeNotNull(replied_at))) AS replied_at, \
    if(isNull(forwarded_at), '', toString(assumeNotNull(forwarded_at))) AS forwarded_at \
    FROM ndr.support_messages FINAL";
const TIMEOUT: Duration = Duration::from_secs(8);

#[derive(clickhouse::Row, serde::Deserialize)]
struct Row {
    id: String,
    tenant_id: String,
    sender_username: String,
    sender_role: String,
    subject: String,
    category: String,
    message: String,
    status: String,
    admin_reply: String,
    replied_by: String,
    forwarded: u8,
    forwarded_by: String,
    deleted: u8,
    created_at: String,
    updated_at: String,
    replied_at: String,
    forwarded_at: String,
}

fn to_json(r: Row) -> Value {
    json!({
        "id": r.id, "tenant_id": r.tenant_id, "sender_username": r.sender_username, "sender_role": r.sender_role,
        "subject": r.subject, "category": r.category, "message": r.message, "status": r.status,
        "admin_reply": r.admin_reply, "replied_by": r.replied_by, "forwarded": r.forwarded,
        "forwarded_by": r.forwarded_by, "deleted": r.deleted, "created_at": r.created_at,
        "updated_at": r.updated_at, "replied_at": r.replied_at, "forwarded_at": r.forwarded_at,
    })
}

fn is_super(ctx: &AuthCtx) -> bool {
    ctx.role == "super_admin" || ctx.role == "admin"
}

/// Who may review, answer or delete a request: the super admin a forwarded request or one of the
/// `default` client; a tenant admin their own client's.
fn can_manage(ctx: &AuthCtx, tenant_id: &str, forwarded: u8) -> bool {
    if is_super(ctx) {
        return forwarded == 1 || tenant_id == "default";
    }
    ctx.role == "tenant_admin" && ctx.tenant_id == tenant_id
}

fn error(m: impl Into<String>) -> Json<Value> {
    Json(json!({ "status": "error", "message": m.into() }))
}

/// `GET /api/support/messages`
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let db = state.db.root();
    let q = if is_super(&ctx) {
        db.query(&format!("{SELECT} WHERE deleted = 0 AND (forwarded = 1 OR tenant_id = 'default') ORDER BY updated_at DESC"))
    } else if ctx.role == "tenant_admin" {
        db.query(&format!("{SELECT} WHERE tenant_id = ? AND deleted = 0 ORDER BY updated_at DESC")).bind(&ctx.tenant_id)
    } else {
        db.query(&format!("{SELECT} WHERE tenant_id = ? AND sender_username = ? AND deleted = 0 ORDER BY updated_at DESC"))
            .bind(&ctx.tenant_id)
            .bind(&ctx.username)
    };
    match tokio::time::timeout(TIMEOUT, q.fetch_all::<Row>()).await {
        Ok(Ok(rows)) => Json(json!({ "status": "ok", "messages": rows.into_iter().map(to_json).collect::<Vec<_>>() })),
        Ok(Err(e)) => Json(json!({ "status": "error", "message": e.to_string(), "messages": [] })),
        Err(_) => Json(json!({ "status": "error", "message": "Support messages request timed out", "messages": [] })),
    }
}

/// `POST /api/support/messages` `{subject, category, message}`
pub async fn create(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(p): Json<Value>) -> Json<Value> {
    let subject = p["subject"].as_str().unwrap_or("").trim();
    let category = p["category"].as_str().unwrap_or("General").trim();
    let message = p["message"].as_str().unwrap_or("").trim();
    if subject.is_empty() || message.is_empty() {
        return error("Subject and message are required");
    }
    if subject.len() > 300 || message.len() > 20_000 || category.len() > 100 {
        return error("Subject, category or message is too long");
    }
    let id = uuid::Uuid::new_v4().to_string();
    let q = state
        .db
        .root()
        .query("INSERT INTO ndr.support_messages (id, tenant_id, sender_username, sender_role, subject, category, message) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(&ctx.tenant_id)
        .bind(&ctx.username)
        .bind(&ctx.role)
        .bind(subject)
        .bind(if category.is_empty() { "General" } else { category })
        .bind(message);
    match tokio::time::timeout(TIMEOUT, q.execute()).await {
        Ok(Ok(())) => Json(json!({ "status": "ok", "id": id, "message": "Support request sent" })),
        Ok(Err(e)) => error(e.to_string()),
        Err(_) => error("Support request timed out"),
    }
}

/// The request's (tenant, sender, forwarded), or the error answer.
async fn scope(state: &AppState, id: &str, what: &str) -> Result<(String, String, u8), Json<Value>> {
    let q = state.db.root().query("SELECT tenant_id, sender_username, forwarded FROM ndr.support_messages FINAL WHERE id = ? AND deleted = 0 LIMIT 1").bind(id);
    match tokio::time::timeout(TIMEOUT, q.fetch_all::<(String, String, u8)>()).await {
        Ok(Ok(rows)) => rows.into_iter().next().ok_or_else(|| error("Support message not found")),
        Ok(Err(e)) => Err(error(e.to_string())),
        Err(_) => Err(error(format!("Support {what} timed out"))),
    }
}

async fn mutate(state: &AppState, sql: &str, binds: &[&str], what: &str) -> Result<(), Json<Value>> {
    let mut q = state.db.root().query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    match tokio::time::timeout(TIMEOUT, q.execute()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(error(e.to_string())),
        Err(_) => Err(error(format!("Support {what} timed out"))),
    }
}

/// `POST /api/support/messages/:id/review`
pub async fn review(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    let (tenant, _, fwd) = match scope(&state, &id, "lookup").await {
        Ok(s) => s,
        Err(e) => return e,
    };
    if !can_manage(&ctx, &tenant, fwd) {
        return error("Forbidden");
    }
    match mutate(&state, "ALTER TABLE ndr.support_messages UPDATE status = 'reviewed' WHERE id = ? SETTINGS mutations_sync=1", &[&id], "review").await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Support request marked reviewed" })),
        Err(e) => e,
    }
}

/// `POST /api/support/messages/:id/reply` `{reply}`
pub async fn reply(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Json<Value> {
    let text = p["reply"].as_str().unwrap_or("").trim();
    if text.is_empty() {
        return error("Reply is required");
    }
    if text.len() > 20_000 {
        return error("Reply is too long");
    }
    let (tenant, _, fwd) = match scope(&state, &id, "lookup").await {
        Ok(s) => s,
        Err(e) => return e,
    };
    if !can_manage(&ctx, &tenant, fwd) {
        return error("Forbidden");
    }
    let sql = "ALTER TABLE ndr.support_messages UPDATE admin_reply = ?, replied_by = ?, replied_at = now(), status = 'replied' WHERE id = ? SETTINGS mutations_sync=1";
    match mutate(&state, sql, &[text, &ctx.username, &id], "reply").await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Reply sent" })),
        Err(e) => e,
    }
}

/// `POST /api/support/messages/:id/forward`: a tenant admin passes a request to the super admin.
pub async fn forward(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    if ctx.role != "tenant_admin" {
        return error("Only tenant admins can forward support requests");
    }
    let (tenant, _, _) = match scope(&state, &id, "lookup").await {
        Ok(s) => s,
        Err(e) => return e,
    };
    if tenant != ctx.tenant_id {
        return error("Forbidden");
    }
    let sql = "ALTER TABLE ndr.support_messages UPDATE forwarded = 1, forwarded_by = ?, forwarded_at = now(), status = 'forwarded' WHERE id = ? SETTINGS mutations_sync=1";
    match mutate(&state, sql, &[&ctx.username, &id], "forward").await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Support request forwarded to super admin" })),
        Err(e) => e,
    }
}

/// `DELETE /api/support/messages/:id` (kept, marked deleted)
pub async fn delete(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    let (tenant, _, fwd) = match scope(&state, &id, "delete").await {
        Ok(s) => s,
        Err(e) => return e,
    };
    if !can_manage(&ctx, &tenant, fwd) {
        return error("Forbidden");
    }
    match mutate(&state, "ALTER TABLE ndr.support_messages UPDATE deleted = 1, status = 'deleted' WHERE id = ? SETTINGS mutations_sync=1", &[&id], "delete").await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Support request deleted" })),
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(role: &str, tenant: &str) -> AuthCtx {
        AuthCtx { username: "u".into(), role: role.into(), tenant_id: tenant.into(), permissions: vec![], features: vec![], requested_tenant: None }
    }

    #[test]
    fn who_manages_a_request() {
        assert!(can_manage(&ctx("super_admin", "default"), "acm", 1), "forwarded: the super admin");
        assert!(!can_manage(&ctx("super_admin", "default"), "acm", 0), "not forwarded: the client's own admin");
        assert!(can_manage(&ctx("super_admin", "default"), "default", 0), "the default client's: the super admin");
        assert!(can_manage(&ctx("tenant_admin", "acm"), "acm", 0));
        assert!(!can_manage(&ctx("tenant_admin", "acm"), "other", 1), "never another client's");
        assert!(!can_manage(&ctx("analyst", "acm"), "acm", 0), "analysts only ask");
    }
}
