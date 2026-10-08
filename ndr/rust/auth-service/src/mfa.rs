use anyhow::Result;
use totp_rs::{Algorithm, Secret, TOTP};

/// Verify a TOTP code against the user's stored base32 secret.
/// Compatible with Google Authenticator and any RFC 6238 app.
///
/// Not called yet — routes/mfa.rs::handle doesn't invoke this because there's
/// no per-user secret column in the schema to check against. Kept ready for
/// when MFA enrollment is actually built.
#[allow(dead_code)]
pub fn verify_totp(secret_base32: &str, code: &str) -> Result<bool> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,      // digits
        1,      // step (30s windows — 1 = current only; set to 2 for ±1 drift tolerance)
        30,     // period
        Secret::Encoded(secret_base32.to_uppercase()).to_bytes()
            .map_err(|e| anyhow::anyhow!("Invalid MFA secret: {}", e))?,
    )
    .map_err(|e| anyhow::anyhow!("TOTP build error: {}", e))?;

    let expected = totp.generate_current()
        .map_err(|e| anyhow::anyhow!("TOTP generate error: {}", e))?;

    Ok(expected == code.trim())
}
