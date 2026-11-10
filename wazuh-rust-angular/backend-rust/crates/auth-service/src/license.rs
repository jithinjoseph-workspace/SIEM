use base64::Engine as _;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseClaims {
    pub tenant_id:   String,
    pub tenant_name: String,
    pub features:    Vec<String>,
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

pub fn verify_license(token: &str, public_key_b64_or_pem: &str) -> anyhow::Result<LicenseClaims> {
    let pem = decode_key_if_needed(public_key_b64_or_pem)?;
    let mut v = Validation::new(Algorithm::RS256);
    v.validate_exp = true;
    let key = DecodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
    Ok(decode::<LicenseClaims>(token, &key, &v)?.claims)
}

fn decode_key_if_needed(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.starts_with("-----") {
        return Ok(trimmed.to_string());
    }
    let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(&clean)?;
    if let Ok(s) = String::from_utf8(bytes.clone()) {
        if s.trim().starts_with("-----") {
            return Ok(s);
        }
    }
    // raw DER — wrap in PEM
    let body: String = clean.as_bytes().chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"))
}
