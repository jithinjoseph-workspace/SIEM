use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// JWT claims — layout must stay stable; all three services share this struct.
///
/// Field names match what the Angular frontend expects:
///   sub          → username
///   role         → analyst | admin | tenant_admin | super_admin
///   tenant_id    → tenant slug
///   permissions  → feature flags e.g. ["ndr", "siem"]
///   sensor_ids   → scoped sensor UUIDs (empty = all sensors for tenant)
///   jti          → session ID; used by force-logout revocation in Valkey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub tenant_id: String,
    pub permissions: Vec<String>,
    pub features: Vec<String>,
    pub sensor_ids: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid or expired token")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),
    #[error("JWT_SECRET not configured")]
    MissingSecret,
}

/// Sign a new JWT.  Called ONLY by auth-service.
/// Returns (token, jti) so the caller can register the session in Valkey.
pub fn create_jwt(
    username: &str,
    role: &str,
    tenant_id: &str,
    permissions: Vec<String>,
    features: Vec<String>,
    sensor_ids: Vec<String>,
    secret: &str,
    ttl_seconds: usize,
) -> Result<(String, String), AuthError> {
    let now = chrono::Utc::now().timestamp() as usize;
    let jti = Uuid::new_v4().to_string();
    let claims = Claims {
        sub: username.to_string(),
        role: role.to_string(),
        tenant_id: tenant_id.to_string(),
        permissions,
        features,
        sensor_ids,
        exp: now + ttl_seconds,
        iat: now,
        jti: jti.clone(),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok((token, jti))
}

/// Verify a JWT signature and expiry.  Called by ndr-engine and siem-engine.
/// Never creates tokens — verify only.
pub fn validate_jwt(token: &str, secret: &str) -> Result<Claims, AuthError> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}
