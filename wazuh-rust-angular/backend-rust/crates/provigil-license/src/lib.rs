//! ProVigil licences and signed update packages.
//!
//! A licence is an RS256 token with the sign-in service's claims (auth-service `license.rs`) plus
//! the SIEM's limits, so one licence serves SIEM and NDR. Update packages are signed with the same
//! key pair: the signature covers the package's SHA-256, so any changed byte fails the check.
//! Only the public key ships to clients; the private key stays with ProVigil.

use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::io::Read;

/// The public key built into on-premises release builds (`PROVIGIL_LICENSE_PUBLIC_KEY` at build
/// time, PEM or base64 of PEM). With it a licence is required; without it (cloud builds) none is.
pub const BUILT_IN_KEY: Option<&str> = option_env!("PROVIGIL_LICENSE_PUBLIC_KEY");

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    pub tenant_id: String,
    pub tenant_name: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub max_sensors: u32,
    #[serde(default)]
    pub issued_by: String,
    pub iat: u64,
    pub exp: u64,
    /// PCs that may be enrolled; 0 = no limit.
    #[serde(default)]
    pub max_agents: u32,
    /// The event rate the licence is sized for (24-hour average); 0 = no limit. Reported only:
    /// events are never dropped for a licence.
    #[serde(default)]
    pub max_eps: u32,
}

/// A key as PEM, or base64 of PEM (an environment variable cannot hold the line breaks).
pub fn pem(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.starts_with("-----") {
        return Ok(t.to_string());
    }
    let clean: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(clean).map_err(|_| "the key is neither PEM nor base64 of PEM".to_string())?;
    let s = String::from_utf8(bytes).map_err(|_| "the key is not text".to_string())?;
    if s.trim().starts_with("-----") {
        Ok(s.trim().to_string())
    } else {
        Err("the key is neither PEM nor base64 of PEM".into())
    }
}

fn decoding_key(public: &str) -> Result<DecodingKey, String> {
    DecodingKey::from_rsa_pem(pem(public)?.as_bytes()).map_err(|e| format!("bad public key: {e}"))
}

fn encoding_key(private: &str) -> Result<EncodingKey, String> {
    EncodingKey::from_rsa_pem(pem(private)?.as_bytes()).map_err(|e| format!("bad private key: {e}"))
}

/// The licence's claims when its signature is good. Expiry is NOT checked here: the caller
/// reports an expired licence with its dates instead of an opaque failure.
pub fn verify(token: &str, public: &str) -> Result<Claims, String> {
    let mut v = Validation::new(Algorithm::RS256);
    v.validate_exp = false;
    v.required_spec_claims.clear();
    jsonwebtoken::decode::<Claims>(token.trim(), &decoding_key(public)?, &v).map(|d| d.claims).map_err(|e| format!("licence not valid: {e}"))
}

pub fn issue(claims: &Claims, private: &str) -> Result<String, String> {
    jsonwebtoken::encode(&Header::new(Algorithm::RS256), claims, &encoding_key(private)?).map_err(|e| e.to_string())
}

/// SHA-256 of a file, hex.
pub fn file_sha256(path: &std::path::Path) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

/// The signature text for an update package (its SHA-256, signed).
pub fn sign_file(path: &std::path::Path, private: &str) -> Result<String, String> {
    let sum = file_sha256(path)?;
    jsonwebtoken::crypto::sign(sum.as_bytes(), &encoding_key(private)?, Algorithm::RS256).map_err(|e| e.to_string())
}

pub fn verify_file(path: &std::path::Path, signature: &str, public: &str) -> Result<(), String> {
    let sum = file_sha256(path)?;
    match jsonwebtoken::crypto::verify(signature.trim(), sum.as_bytes(), &decoding_key(public)?, Algorithm::RS256) {
        Ok(true) => Ok(()),
        _ => Err(format!("{}: the signature does not match (changed or not from ProVigil)", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIV: &str = include_str!("../testdata/TEST-ONLY-private.pem");
    const PUB: &str = include_str!("../testdata/TEST-ONLY-public.pem");

    fn claims() -> Claims {
        Claims { tenant_id: "acm".into(), tenant_name: "ACME".into(), features: vec!["siem".into()], issued_by: "ProVigil".into(), iat: 1, exp: 4_000_000_000, max_agents: 500, max_eps: 1000, ..Default::default() }
    }

    #[test]
    fn licence_round_trip_and_tamper() {
        let t = issue(&claims(), PRIV).unwrap();
        assert_eq!(verify(&t, PUB).unwrap(), claims());
        // base64 of the PEM works as the environment variable form
        assert!(verify(&t, &base64::engine::general_purpose::STANDARD.encode(PUB)).is_ok());
        // a changed limit breaks the signature
        let parts: Vec<&str> = t.split('.').collect();
        let mut c = claims();
        c.max_agents = 50_000;
        let forged = format!("{}.{}.{}", parts[0], base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap()), parts[2]);
        assert!(verify(&forged, PUB).is_err());
        assert!(verify("junk", PUB).is_err());
    }

    #[test]
    fn the_sign_in_service_reads_the_same_token() {
        // auth-service's LicenseClaims needs these fields; the SIEM limits are extra and ignored there
        let v: serde_json::Value = serde_json::to_value(claims()).unwrap();
        for k in ["tenant_id", "tenant_name", "features", "max_sensors", "issued_by", "iat", "exp"] {
            assert!(v.get(k).is_some(), "{k}");
        }
    }

    #[test]
    fn signed_files() {
        let dir = std::env::temp_dir().join(format!("pv-lic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("update.zip");
        std::fs::write(&f, b"package bytes").unwrap();
        let sig = sign_file(&f, PRIV).unwrap();
        assert!(verify_file(&f, &sig, PUB).is_ok());
        std::fs::write(&f, b"package bytez").unwrap();
        assert!(verify_file(&f, &sig, PUB).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
