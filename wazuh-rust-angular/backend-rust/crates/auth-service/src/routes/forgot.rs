use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::{db::AuthDb, AppState};
use super::login::validate_password_strength;

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/forgot/verify-secret  — no auth required
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifySecretPayload {
    pub username:    String,
    pub secret_code: String,
}

pub async fn verify_secret(
    State(state): State<AppState>,
    Json(payload): Json<VerifySecretPayload>,
) -> impl IntoResponse {
    let username    = payload.username.trim();
    let secret_code = payload.secret_code.trim();

    match state.db.verify_tenant_admin_secret(username, secret_code).await {
        Ok(Some(gmail)) => {
            let masked = mask_email(&gmail);
            (StatusCode::OK, Json(json!({
                "status": "ok",
                "gmail_hint": masked,
            }))).into_response()
        }
        Ok(None) => (StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Invalid username or secret code" }))).into_response(),
        Err(e) => {
            tracing::error!("verify_tenant_admin_secret error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Service unavailable" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/forgot/send-otp  — no auth required
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendOtpPayload {
    pub username: String,
    pub gmail:    String,
}

pub async fn send_otp(
    State(state): State<AppState>,
    Json(payload): Json<SendOtpPayload>,
) -> impl IntoResponse {
    let username = payload.username.trim().to_string();
    let gmail    = payload.gmail.trim().to_string();

    // Verify the supplied gmail matches what's in the DB
    let db_gmail = match state.db.get_gmail_for_user(&username).await {
        Ok(Some(g)) => g,
        Ok(None) => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_gmail_for_user error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Service unavailable" }))).into_response();
        }
    };

    if db_gmail.trim().to_lowercase() != gmail.to_lowercase() {
        return (StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Email does not match records" }))).into_response();
    }

    // Generate 6-digit OTP
    let otp = {
        use rand::Rng;
        format!("{:06}", rand::thread_rng().gen_range(0..=999999u32))
    };

    // Store OTP in Valkey with 600s TTL
    {
        let mut conn = state.valkey.clone();
        let key = format!("otp_reset:{}", username);
        let _: redis::RedisResult<String> = conn.set_ex(&key, &otp, 600usize).await;
    }

    // Send OTP email
    let subject = "NDR Password Reset OTP".to_string();
    let body = format!(
        "Your password reset OTP is: {}\n\nThis code expires in 10 minutes.\n\nIf you did not request this, please ignore this email.",
        otp
    );

    if let Err(e) = send_email(&state.db, &gmail, &subject, &body).await {
        tracing::error!("send_email error: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": "Failed to send email" }))).into_response();
    }

    (StatusCode::OK, Json(json!({ "status": "ok", "message": "OTP sent to your email" }))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/forgot/reset-password  — no auth required
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ForgotResetPayload {
    pub username:     String,
    pub otp:          String,
    pub new_password: String,
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotResetPayload>,
) -> impl IntoResponse {
    let username     = payload.username.trim().to_string();
    let otp          = payload.otp.trim().to_string();
    let new_password = payload.new_password.trim();

    if let Err(msg) = validate_password_strength(new_password) {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg }))).into_response();
    }

    // Retrieve OTP from Valkey
    let stored_otp: Option<String> = {
        let mut conn = state.valkey.clone();
        let key = format!("otp_reset:{}", username);
        conn.get(&key).await.unwrap_or(None)
    };

    match stored_otp {
        None => return (StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "OTP expired or not found" }))).into_response(),
        Some(ref s) if s != &otp => return (StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Invalid OTP" }))).into_response(),
        _ => {}
    }

    // Hash new password
    let hash = match bcrypt::hash(new_password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("bcrypt error: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Internal error" }))).into_response();
        }
    };

    // Update DB
    if let Err(e) = state.db.reset_password_by_username(&username, &hash).await {
        tracing::error!("reset_password_by_username error: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": "Failed to reset password" }))).into_response();
    }

    // Delete OTP from Valkey
    {
        let mut conn = state.valkey.clone();
        let key = format!("otp_reset:{}", username);
        let _: redis::RedisResult<()> = conn.del(&key).await;
    }

    (StatusCode::OK, Json(json!({ "status": "ok", "message": "Password reset successfully" }))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Email sending helper via lettre + SMTP settings from DB
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn send_email(
    db: &Arc<AuthDb>,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    use lettre::{
        message::header::ContentType,
        transport::smtp::authentication::Credentials,
        AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    };

    let (host, port_str, user, pass) = db
        .get_smtp_settings()
        .await
        .map_err(|e| format!("SMTP settings error: {}", e))?;

    let port: u16 = port_str.parse().unwrap_or(587);

    let email = Message::builder()
        .from(user.parse().map_err(|e| format!("Invalid from address: {}", e))?)
        .to(to.parse().map_err(|e| format!("Invalid to address: {}", e))?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| format!("Email build error: {}", e))?;

    let creds = Credentials::new(user.clone(), pass);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
        .map_err(|e| format!("SMTP relay error: {}", e))?
        .port(port)
        .credentials(creds)
        .build();

    mailer
        .send(email)
        .await
        .map_err(|e| format!("Send error: {}", e))?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Email masking helper
// ─────────────────────────────────────────────────────────────────────────────

fn mask_email(email: &str) -> String {
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return "***".to_string();
    }
    let local = parts[0];
    let domain = parts[1];
    let visible = if local.len() <= 2 { local.len() } else { 2 };
    let masked = format!("{}{}", &local[..visible], "*".repeat(local.len().saturating_sub(visible)));
    format!("{}@{}", masked, domain)
}
