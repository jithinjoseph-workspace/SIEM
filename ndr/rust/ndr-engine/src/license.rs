use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use base64::Engine as _;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseClaims {
    pub tenant_id:   String,
    pub tenant_name: String,
    pub features:    Vec<String>,  // ["ndr", "ai", "soar"]
    pub max_sensors: u32,
    pub issued_by:   String,
    pub iat:         u64,
    pub exp:         u64,
}

impl LicenseClaims {
    pub fn has_feature(&self, f: &str) -> bool {
        self.features.iter().any(|x| x == f)
    }
}

fn wrap_pem(b64_der: &str, header: &str) -> String {
    let clean: String = b64_der.chars().filter(|c| !c.is_whitespace()).collect();
    let body: String = clean.as_bytes().chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {header}-----\n{body}\n-----END {header}-----\n")
}

pub fn load_private_key() -> anyhow::Result<String> {
    let raw = std::env::var("LICENSE_PRIVATE_KEY")
        .map_err(|_| anyhow::anyhow!("LICENSE_PRIVATE_KEY not set"))?;
    if raw.trim().is_empty() {
        return Err(anyhow::anyhow!("LICENSE_PRIVATE_KEY is empty"));
    }
    let trimmed = raw.trim();
    if trimmed.starts_with("-----") {
        return Ok(trimmed.to_string());
    }
    // base64-encoded: might be base64(PEM) or base64(DER)
    let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(&clean)?;
    if let Ok(s) = String::from_utf8(bytes) {
        return Ok(s); // was base64(PEM) — already has headers
    }
    // raw DER base64 — wrap
    Ok(wrap_pem(&clean, "RSA PRIVATE KEY"))
}

pub fn load_public_key() -> anyhow::Result<String> {
    let raw = std::env::var("LICENSE_PUBLIC_KEY")
        .map_err(|_| anyhow::anyhow!("LICENSE_PUBLIC_KEY not set"))?;
    if raw.trim().is_empty() {
        return Err(anyhow::anyhow!("LICENSE_PUBLIC_KEY is empty"));
    }
    let trimmed = raw.trim();
    if trimmed.starts_with("-----") {
        return Ok(trimmed.to_string());
    }
    // base64-encoded: might be base64(PEM) or raw DER base64
    let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(&clean)?;
    if let Ok(s) = String::from_utf8(bytes) {
        return Ok(s); // was base64(PEM) — already has headers
    }
    // raw DER base64 — wrap in PEM headers so DecodingKey::from_rsa_pem works
    Ok(wrap_pem(&clean, "PUBLIC KEY"))
}

pub fn generate_license(
    tenant_id:    &str,
    tenant_name:  &str,
    features:     Vec<String>,
    max_sensors:  u32,
    expires_days: u32,
    private_key_pem: &str,
) -> anyhow::Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = LicenseClaims {
        tenant_id:   tenant_id.to_string(),
        tenant_name: tenant_name.to_string(),
        features,
        max_sensors,
        issued_by:   "PromaSecure".to_string(),
        iat:         now,
        exp:         now + (expires_days as u64 * 86400),
    };
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid RSA private key: {}", e))?;
    Ok(encode(&Header::new(Algorithm::RS256), &claims, &key)?)
}

pub fn verify_license(token: &str, public_key_pem: &str) -> anyhow::Result<LicenseClaims> {
    let mut v = Validation::new(Algorithm::RS256);
    v.validate_exp = true;
    let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid RSA public key: {}", e))?;
    Ok(decode::<LicenseClaims>(token, &key, &v)?.claims)
}
