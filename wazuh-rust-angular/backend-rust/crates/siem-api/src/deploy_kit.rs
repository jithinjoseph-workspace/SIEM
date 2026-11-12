//! The mass-deployment kit (specs/provigil-mass-deploy.md, C8): one zip with the deployment scripts,
//! the helper program, the Windows and Linux agents, the CA and `deploy.json` (gateway addresses,
//! the deployment token, the SHA-256 of every file). Built for a token the console just created:
//! the token is only ever in the console's memory and in this zip.

use std::io::Write;

use axum::extract::{Extension, Json};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::tenancy::AuthCtx;
use crate::{agent_tls, provigil_manager};

const DEPLOY_SCRIPT: &str = include_str!("../../../deploy/deploy-provigil.ps1");
const INSTALL_SCRIPT: &str = include_str!("../../../deploy/install-provigil.ps1");
const GUIDE: &str = include_str!("../../../deploy/GUIDE.md");
const LINUX_INSTALL: &str = include_str!("../../siem-agent-linux/install.sh");
const SYSMON_XML: &str = include_str!("sysmon.xml");
const ROOT: &str = "ProVigilDeploy/";

fn bad(code: StatusCode, m: &str) -> Response {
    (code, Json(json!({ "status": "error", "message": m }))).into_response()
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02X}")).collect()
}

/// The first of `paths` that is a file.
fn first(paths: &[&str]) -> Option<Vec<u8>> {
    paths.iter().find_map(|p| std::fs::read(p).ok())
}

/// A host for the agents' addresses: a DNS name or an IP, as the console was reached at.
fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Windows (CRLF) line ends for the scripts, whatever the checkout has.
fn crlf(s: &str) -> Vec<u8> {
    s.replace("\r\n", "\n").replace('\n', "\r\n").into_bytes()
}

/// The kit's files (path in the kit -> bytes), without `deploy.json`.
fn files(sysmon: bool) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut out = vec![
        ("deploy-provigil.ps1".to_string(), crlf(DEPLOY_SCRIPT)),
        ("install-provigil.ps1".to_string(), crlf(INSTALL_SCRIPT)),
        ("GUIDE.md".to_string(), crlf(GUIDE)),
        ("linux/install.sh".to_string(), LINUX_INSTALL.replace("\r\n", "\n").into_bytes()),
    ];
    let ca = agent_tls::ca_pem().ok_or("The manager has no agent CA (TLS did not start): agents could not connect")?;
    out.push(("ca.pem".into(), ca.as_bytes().to_vec()));
    if sysmon {
        out.push(("sysmon.xml".into(), SYSMON_XML.as_bytes().to_vec()));
    }
    for name in provigil_manager::agent_files().keys() {
        let path = provigil_manager::windows_agent_file(name).ok_or_else(|| format!("{name} is not published"))?;
        out.push((format!("windows/{name}"), std::fs::read(&path).map_err(|e| format!("{name}: {e}"))?));
    }
    if !out.iter().any(|(n, _)| n == "windows/provigil-agent.exe") {
        return Err("The Windows agent (provigil-agent.exe) is not published".into());
    }
    let linux = first(&["data/agent-dist/linux/siem-agent-linux", "backend-rust/data/agent-dist/linux/siem-agent-linux", "target/release/siem-agent-linux", "backend-rust/target/release/siem-agent-linux"]).ok_or("The Linux agent (siem-agent-linux) is not published")?;
    out.push(("linux/siem-agent-linux".into(), linux));
    let helper = first(&["data/agent-dist/windows/provigil-deploy.exe", "backend-rust/data/agent-dist/windows/provigil-deploy.exe", "target/release/provigil-deploy.exe", "backend-rust/target/release/provigil-deploy.exe"]).ok_or("The deployment helper (provigil-deploy.exe) is not built")?;
    out.push(("provigil-deploy.exe".into(), helper));
    Ok(out)
}

/// `deploy.json`: what the scripts read. Every file's SHA-256 is checked before it is used.
fn deploy_json(label: &str, host: &str, token: &str, groups: &str, options: &Value, files: &[(String, Vec<u8>)]) -> Value {
    let hashes: Map<String, Value> = files.iter().filter(|(n, _)| n != "GUIDE.md").map(|(n, b)| (n.clone(), json!(sha256_hex(b)))).collect();
    json!({
        "label": label,
        "manager_url": agent_tls::https_url(host),
        "grpc_url": agent_tls::url(host),
        "token": token,
        "groups": groups,
        "options": { "sysmon": options["sysmon"].as_bool().unwrap_or(false), "audit_policy": options["audit_policy"].as_bool().unwrap_or(false), "ps_logging": options["ps_logging"].as_bool().unwrap_or(false) },
        "files": hashes,
    })
}

fn zip(files: &[(String, Vec<u8>)], deploy: &Value) -> Result<Vec<u8>, String> {
    use zip::write::SimpleFileOptions;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let json = serde_json::to_vec_pretty(deploy).map_err(|e| e.to_string())?;
    for (name, data) in files.iter().map(|(n, b)| (n.as_str(), b.as_slice())).chain([("deploy.json", json.as_slice())]) {
        let o = if name.ends_with(".sh") || name.ends_with("siem-agent-linux") { opts.unix_permissions(0o755) } else { opts };
        w.start_file(format!("{ROOT}{name}"), o).map_err(|e| e.to_string())?;
        w.write_all(data).map_err(|e| e.to_string())?;
    }
    Ok(w.finish().map_err(|e| e.to_string())?.into_inner())
}

/// `POST /api/v1/deploy/kit` `{token, host, options: {sysmon, audit_policy, ps_logging}}` (tenant
/// admin): the kit as a zip, for a deployment token of this tenant that can still enroll.
pub async fn kit(Extension(ctx): Extension<AuthCtx>, Json(p): Json<Value>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return crate::tenancy::forbidden();
    }
    let token = p["token"].as_str().unwrap_or("").trim().to_string();
    let host = p["host"].as_str().unwrap_or("").trim().to_string();
    if !valid_host(&host) {
        return bad(StatusCode::BAD_REQUEST, "host: the address agents reach the ProVigil gateway at");
    }
    let t = match crate::deploy_tokens::check_enroll(&token, None) {
        Ok(t) if t.tenant_id == tenant => t,
        Ok(_) => return bad(StatusCode::NOT_FOUND, "Unknown deployment token"),
        Err(e) => return bad(StatusCode::BAD_REQUEST, &e),
    };
    let options = p["options"].clone();
    let built = tokio::task::spawn_blocking(move || {
        let f = files(options["sysmon"].as_bool().unwrap_or(false))?;
        zip(&f, &deploy_json(&t.label, &host, &token, &t.groups, &options, &f))
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));
    match built {
        Ok(bytes) => ([(header::CONTENT_TYPE, "application/zip"), (header::CONTENT_DISPOSITION, "attachment; filename=\"ProVigilDeploy.zip\"")], bytes).into_response(),
        Err(e) => bad(StatusCode::SERVICE_UNAVAILABLE, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_json_lists_every_file_hash_but_the_guide() {
        let f = vec![("GUIDE.md".to_string(), b"g".to_vec()), ("ca.pem".to_string(), b"x".to_vec()), ("windows/provigil-agent.exe".to_string(), b"y".to_vec())];
        let d = deploy_json("HQ", "pv.example.com", "pvd_1_abc", "", &json!({ "sysmon": true }), &f);
        assert_eq!(d["token"], "pvd_1_abc");
        assert_eq!(d["files"]["ca.pem"], sha256_hex(b"x"));
        assert!(d["files"]["GUIDE.md"].is_null());
        assert_eq!(d["options"]["sysmon"], true);
        assert_eq!(d["options"]["ps_logging"], false);
        assert!(d["manager_url"].as_str().unwrap().starts_with("https://pv.example.com:"));
        // the scripts compare with Get-FileHash, which is upper case
        assert_eq!(sha256_hex(b"x"), sha256_hex(b"x").to_uppercase());
    }

    #[test]
    fn the_zip_holds_the_kit_under_one_folder() {
        let f = vec![("install-provigil.ps1".to_string(), crlf("a\nb\n"))];
        let z = zip(&f, &json!({ "token": "t" })).unwrap();
        let mut a = zip::ZipArchive::new(std::io::Cursor::new(z)).unwrap();
        let mut names: Vec<String> = a.file_names().map(str::to_string).collect();
        names.sort();
        assert_eq!(names, ["ProVigilDeploy/deploy.json", "ProVigilDeploy/install-provigil.ps1"]);
        let mut s = String::new();
        std::io::Read::read_to_string(&mut a.by_name("ProVigilDeploy/install-provigil.ps1").unwrap(), &mut s).unwrap();
        assert_eq!(s, "a\r\nb\r\n");
        assert!(valid_host("10.0.0.5") && valid_host("pv.example.com") && !valid_host("a b") && !valid_host("x/y"));
    }
}
