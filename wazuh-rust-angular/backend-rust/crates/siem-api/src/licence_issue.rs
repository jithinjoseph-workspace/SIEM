//! Issuing licences to customers (super admin, on ProVigil's own server): signs a licence with
//! `LICENSE_PRIVATE_KEY` (RS256, the provigil-license format the sign-in service, siem-api and
//! the NDR engine all verify) and keeps a copy in `ndr.licenses` to look up later. siem-api is
//! the platform server, so this works in every install (it used to live only in the NDR engine;
//! the same table, request and replies). The key: PEM, base64 of PEM, or base64 of DER.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

use crate::tenancy::AuthCtx;
use crate::AppState;

#[derive(Deserialize)]
pub struct GenerateReq {
    tenant_id: String,
    tenant_name: String,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    max_sensors: u32,
    expires_days: u32,
    #[serde(default)]
    admin_user: String,
    /// The SIEM's limits (0 = none); the console may leave them out.
    #[serde(default)]
    max_pcs: u32,
    #[serde(default)]
    max_eps: u32,
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": "Platform admins only" }))).into_response()
}

/// The private key as PEM: PEM as it is, base64 of PEM decoded, base64 of DER wrapped (as the
/// NDR engine read it).
fn private_key_pem(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("LICENSE_PRIVATE_KEY not configured on this server".into());
    }
    if t.starts_with("-----") {
        return Ok(t.to_string());
    }
    let clean: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(&clean).map_err(|_| "LICENSE_PRIVATE_KEY is neither PEM nor base64".to_string())?;
    match String::from_utf8(bytes) {
        Ok(s) if s.trim_start().starts_with("-----") => Ok(s),
        _ => {
            let body: Vec<&str> = clean.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
            Ok(format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n", body.join("\n")))
        }
    }
}

/// `POST /api/license/generate`
pub async fn generate(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<GenerateReq>) -> Response {
    if !ctx.is_super() {
        return forbidden();
    }
    // an error status, so the console shows the reason instead of an empty licence
    let bad = |m: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": m }))).into_response();
    let unavailable = |m: &str| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": m }))).into_response();
    if r.tenant_id.trim().is_empty() || r.tenant_name.trim().is_empty() {
        return bad("tenant_id and tenant_name are required");
    }
    if r.expires_days == 0 || r.expires_days > 3650 {
        return bad("expires_days must be 1 to 3650");
    }
    let key = match private_key_pem(&std::env::var("LICENSE_PRIVATE_KEY").unwrap_or_default()) {
        Ok(k) => k,
        Err(e) => return unavailable(&e),
    };
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let claims = provigil_license::Claims {
        tenant_id: r.tenant_id.trim().into(),
        tenant_name: r.tenant_name.trim().into(),
        features: r.features.iter().map(|f| f.trim().to_string()).filter(|f| !f.is_empty()).collect(),
        max_sensors: r.max_sensors,
        issued_by: "PromaSecure".into(),
        iat: now,
        exp: now + u64::from(r.expires_days) * 86_400,
        max_agents: r.max_pcs,
        max_eps: r.max_eps,
    };
    let token = match provigil_license::issue(&claims, &key) {
        Ok(t) => t,
        Err(e) => return unavailable(&e),
    };
    // a copy, so the super admin can look it up again (the token is the licence; losing the copy
    // does not invalidate it)
    let saved = state
        .db
        .root()
        .query("INSERT INTO ndr.licenses (id, tenant_id, tenant_name, features, max_sensors, admin_user, issued_at, expires_at, token) VALUES (?, ?, ?, ?, ?, ?, now(), now() + toIntervalDay(?), ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&claims.tenant_id)
        .bind(&claims.tenant_name)
        .bind(claims.features.join(","))
        .bind(claims.max_sensors)
        .bind(r.admin_user.trim())
        .bind(r.expires_days)
        .bind(&token)
        .execute()
        .await;
    if let Err(e) = saved {
        tracing::warn!("licence issued for '{}' but not recorded: {e}", claims.tenant_id);
    }
    tracing::info!("licence issued for '{}' ({} days, modules {:?})", claims.tenant_id, r.expires_days, claims.features);
    Json(json!({ "token": token, "status": "ok" })).into_response()
}

/// `GET /api/license/public-key`: the value customers put in their install (single line).
pub async fn public_key(Extension(ctx): Extension<AuthCtx>) -> Response {
    if !ctx.is_super() {
        return forbidden();
    }
    match std::env::var("LICENSE_PUBLIC_KEY").ok().filter(|k| !k.trim().is_empty()) {
        Some(k) => Json(json!({ "public_key": k.trim() })).into_response(),
        None => Json(json!({ "error": "LICENSE_PUBLIC_KEY not configured" })).into_response(),
    }
}

/// `GET /api/licenses?tenant_id=`
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Query(q): Query<HashMap<String, String>>) -> Response {
    if !ctx.is_super() {
        return forbidden();
    }
    let sql = "SELECT id, tenant_id, tenant_name, features, max_sensors, admin_user, formatDateTime(issued_at, '%Y-%m-%dT%H:%i:%SZ'), formatDateTime(expires_at, '%Y-%m-%dT%H:%i:%SZ'), token FROM ndr.licenses FINAL";
    let db = state.db.root();
    let query = match q.get("tenant_id").filter(|t| !t.is_empty()) {
        Some(t) => db.query(&format!("{sql} WHERE tenant_id = ? ORDER BY issued_at DESC LIMIT 200")).bind(t),
        None => db.query(&format!("{sql} ORDER BY issued_at DESC LIMIT 200")),
    };
    match query.fetch_all::<(String, String, String, String, u32, String, String, String, String)>().await {
        Ok(rows) => Json(json!({ "licenses": rows.into_iter().map(|r| json!({
            "id": r.0, "tenant_id": r.1, "tenant_name": r.2,
            "features": r.3.split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>(),
            "max_sensors": r.4, "admin_user": r.5, "issued_at": r.6, "expires_at": r.7, "token": r.8,
        })).collect::<Vec<_>>() }))
        .into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}

/// Where customers download ProVigil's installer (a GitHub releases API address; one setting so the
/// download place can move).
fn download_url() -> String {
    std::env::var("PROVIGIL_DOWNLOAD_URL").ok().filter(|u| !u.trim().is_empty()).unwrap_or_else(|| "https://api.github.com/repos/jithinjoseph-workspace/NDR-Demo/releases".into())
}

/// One customer's installer zip: their licence, `install.sh` (fetches ProVigil's installer, checks
/// its signature with the key built in, runs it with the licence) and a README.
fn installer_zip(token: &str, claims: &provigil_license::Claims, public_b64: &str, url: &str) -> Result<Vec<u8>, String> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    let customer = if claims.tenant_name.is_empty() { &claims.tenant_id } else { &claims.tenant_name };
    // Unix line ends whatever the build machine checked out (bash fails on a carriage return)
    let launcher = include_str!("licence_installer.sh").replace("\r\n", "\n").replace("@CUSTOMER@", customer).replace("@KEY@", public_b64).replace("@URL@", url);
    let modules = if claims.features.is_empty() { "all".to_string() } else { claims.features.join(", ") };
    let until = chrono::DateTime::from_timestamp(claims.exp as i64, 0).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default();
    let readme = format!(
        "ProVigil for {customer}\r\nModules: {modules}. Valid until {until}.\r\n\r\n\
         Ubuntu 22.04/24.04, on each PC, in this folder:\r\n    sudo bash install.sh\r\n\
         It asks what the PC is: all-in-one, master, data lake, AI node or NDR sensor.\r\n\
         For three PCs: the data lake first (it prints the address and password the master asks for),\r\n\
         then the AI node (optional), then the master. Only the licensed modules are installed.\r\n\r\n\
         Windows master (SIEM): download ProVigil-Setup-<version>.msi from the ProVigil release into this\r\n\
         folder and run it (it uses licence.jwt next to it). Install the data lake first, answering that the\r\n\
         master is a Windows PC.\r\n\
         No internet on the PCs? Ask ProVigil for the offline zip (the same installer with every part).\r\n\
         Keep licence.jwt private: it is this installation's licence.\r\n"
    );
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let file = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, body, mode) in [("licence.jwt", format!("{token}\n"), 0o600), ("install.sh", launcher, 0o755), ("README.txt", readme, 0o644)] {
        w.start_file(name, file.unix_permissions(mode)).map_err(|e| e.to_string())?;
        w.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(w.finish().map_err(|e| e.to_string())?.into_inner())
}

#[derive(Deserialize)]
pub struct InstallerReq {
    token: String,
}

/// `POST /api/license/installer` {token}: the customer's installer zip (a licence this server signed).
pub async fn installer(Extension(ctx): Extension<AuthCtx>, Json(r): Json<InstallerReq>) -> Response {
    if !ctx.is_super() {
        return forbidden();
    }
    let bad = |m: String| (StatusCode::BAD_REQUEST, Json(json!({ "error": m }))).into_response();
    let Some(public) = std::env::var("LICENSE_PUBLIC_KEY").ok().map(|k| k.trim().to_string()).filter(|k| !k.is_empty()) else {
        return bad("LICENSE_PUBLIC_KEY not configured on this server".into());
    };
    let token = r.token.trim();
    let claims = match provigil_license::verify(token, &public) {
        Ok(c) => c,
        Err(e) => return bad(e),
    };
    // the launcher decodes base64 of PEM (the form installers store), whatever form the setting has
    let public_b64 = match provigil_license::pem(&public) {
        Ok(p) => base64::engine::general_purpose::STANDARD.encode(p),
        Err(e) => return bad(e),
    };
    match installer_zip(token, &claims, &public_b64, &download_url()) {
        Ok(bytes) => {
            let name: String = claims.tenant_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
            (
                [(axum::http::header::CONTENT_TYPE, "application/zip".to_string()), (axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"ProVigil-{name}.zip\""))],
                bytes,
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

/// `DELETE /api/licenses/:id`: removes the record (a licence already handed out stays valid until
/// it expires: the token is the licence).
pub async fn delete(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    if !ctx.is_super() {
        return forbidden();
    }
    match state.db.root().query("ALTER TABLE ndr.licenses DELETE WHERE id = ? SETTINGS mutations_sync=1").bind(&id).execute().await {
        Ok(()) => Json(json!({ "status": "ok" })).into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_installer_zip() {
        let private = include_str!("../../provigil-license/testdata/TEST-ONLY-private.pem");
        let public = include_str!("../../provigil-license/testdata/TEST-ONLY-public.pem");
        let claims = provigil_license::Claims { tenant_id: "acme".into(), tenant_name: "Acme Ltd".into(), features: vec!["siem".into(), "soar".into()], exp: 1_900_000_000, ..Default::default() };
        let token = provigil_license::issue(&claims, private).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(public.trim());
        let z = installer_zip(&token, &claims, &b64, "https://example.test/releases").unwrap();
        let mut a = zip::ZipArchive::new(std::io::Cursor::new(z)).unwrap();
        let mut read = |n: &str| {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut a.by_name(n).unwrap(), &mut s).unwrap();
            s
        };
        assert_eq!(read("licence.jwt").trim(), token);
        let sh = read("install.sh");
        assert!(sh.contains(&format!("KEY=\"{b64}\"")) && sh.contains("https://example.test/releases") && sh.contains("for Acme Ltd"));
        assert!(!sh.contains('\r'), "bash needs Unix line ends");
        assert!(!["@KEY@", "@URL@", "@CUSTOMER@"].iter().any(|p| sh.contains(p)), "every placeholder filled");
        assert!(read("README.txt").contains("Modules: siem, soar. Valid until 2030-03-17."));
    }

    #[test]
    fn key_forms() {
        let pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
        assert_eq!(private_key_pem(pem).unwrap(), pem);
        let b64_pem = base64::engine::general_purpose::STANDARD.encode(pem);
        assert!(private_key_pem(&b64_pem).unwrap().starts_with("-----BEGIN PRIVATE KEY-----"));
        let der = base64::engine::general_purpose::STANDARD.encode([0x30u8, 0x82, 0x01, 0x02, 0xff, 0xfe]);
        assert!(private_key_pem(&der).unwrap().starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(private_key_pem("").is_err());
        assert!(private_key_pem("not base64 !!").is_err());
    }
}
