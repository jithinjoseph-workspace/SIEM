//! The agents' addresses and CA for `/api/server-info`. Agents connect to `provigil-gateway`
//! (gRPC `SIEM_GRPC_PORT` 8089, HTTPS `SIEM_TLS_PORT` 8443); siem-api makes the install-wide CA
//! in `data/tls/` at the first start, and the gateway issues its certificate from it.

use std::path::Path;
use std::sync::OnceLock;

use provigil_agent_server::tls::{named_ca_params, CA_CN};
use tracing::{error, info};

fn port() -> u16 {
    std::env::var("SIEM_GRPC_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8089)
}

fn tls_port() -> u16 {
    std::env::var("SIEM_TLS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8443)
}

/// The gRPC address agents use (`/api/server-info`).
pub fn url(host: &str) -> String {
    format!("grpcs://{host}:{}", port())
}

/// The HTTPS address agents use (`/api/server-info`).
pub fn https_url(host: &str) -> String {
    format!("https://{host}:{}", tls_port())
}

static CA_PEM: OnceLock<String> = OnceLock::new();

/// The CA certificate agents trust (public), once loaded.
pub fn ca_pem() -> Option<&'static str> {
    CA_PEM.get().map(String::as_str)
}

/// `data` to a new file only the service account and Administrators can open.
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let err = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    // the empty file gets its permissions first: the data is never there with inherited ones
    #[cfg(windows)]
    {
        use std::process::Command;
        std::fs::File::create(path).map_err(|e| err(&e))?;
        let me = Command::new("whoami").output().map_err(|e| err(&e))?;
        let me = String::from_utf8_lossy(&me.stdout).trim().to_string();
        let ok = !me.is_empty()
            && Command::new("icacls").arg(path).args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"]).arg(format!("{me}:F")).output().is_ok_and(|o| o.status.success());
        if !ok {
            let _ = std::fs::remove_file(path);
            return Err(err(&"could not be restricted to the service account and Administrators"));
        }
        std::fs::write(path, data).map_err(|e| err(&e))
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).and_then(|mut f| f.write_all(data)).map_err(|e| err(&e))
    }
}

/// The install-wide CA in `dir`, made at the first start: the certificate's PEM. Not the syslog CA:
/// that one needs ClickHouse up and `AGENT_KEYS_SECRET` at start, and agents must connect without them.
fn load_ca(dir: &Path) -> Result<String, String> {
    let (key_file, cert_file) = (dir.join("ca.key.pem"), dir.join("ca.crt.pem"));
    let key = match std::fs::read_to_string(&key_file) {
        Ok(pem) => rcgen::KeyPair::from_pem(&pem).map_err(|e| format!("{}: {e}", key_file.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
            write_private(&key_file, key.serialize_pem().as_bytes())?;
            info!("Agent CA created in {}", dir.display());
            key
        }
        // a key that exists but cannot be read is never replaced: agents trust its CA
        Err(e) => return Err(format!("{}: {e}", key_file.display())),
    };
    match std::fs::read_to_string(&cert_file) {
        Ok(pem) => Ok(pem),
        Err(_) => {
            // same name and key as the gateway uses: what it issues chains to this certificate
            let pem = named_ca_params(CA_CN).self_signed(&key).map_err(|e| e.to_string())?.pem();
            std::fs::write(&cert_file, &pem).map_err(|e| format!("{}: {e}", cert_file.display()))?;
            Ok(pem)
        }
    }
}

/// The agents' CA, at start.
pub fn init_tls() {
    match load_ca(&crate::data_file_path("tls")) {
        Ok(pem) => {
            let _ = CA_PEM.set(pem);
        }
        Err(e) => error!("Agent CA not available, agents cannot connect: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn ca_key_is_private_kept_and_read_by_the_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let pem = load_ca(dir.path()).unwrap();
        let file = dir.path().join("ca.key.pem");
        #[cfg(windows)]
        {
            let out = std::process::Command::new("icacls").arg(&file).output().unwrap();
            let acl = String::from_utf8_lossy(&out.stdout).to_lowercase();
            assert!(!acl.contains("(i)"), "no inherited entries: {acl}");
            // SYSTEM, Administrators and whoever runs the service, nobody else
            assert!(acl.matches(":(f)").count() <= 3, "{acl}");
            assert!(!acl.contains("authenticated users") && !acl.contains("builtin\\users") && !acl.contains("everyone"), "{acl}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let key = std::fs::read_to_string(&file).unwrap();
        assert_eq!(load_ca(dir.path()).unwrap(), pem, "agents keep their CA");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), key, "the same key at the next start");
        // the gateway issues from it
        assert_eq!(provigil_agent_server::tls::read_ca(dir.path()).unwrap().2, pem);
        // a damaged key is an error, never a new CA
        std::fs::write(&file, "damaged").unwrap();
        assert!(load_ca(dir.path()).is_err());
    }

    #[tokio::test]
    async fn server_info_fields() {
        use axum::response::IntoResponse;
        let dir = tempfile::tempdir().unwrap();
        let _ = CA_PEM.set(load_ca(dir.path()).unwrap());
        let r = crate::get_server_info_handler().await.into_response();
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("PRIVATE KEY"), "{text}");
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert!(v["https_url"].as_str().unwrap().starts_with("https://"), "{v}");
        assert!(v["grpc_url"].as_str().unwrap().starts_with("grpcs://"), "{v}");
        assert!(v["ca_pem"].as_str().unwrap().contains("BEGIN CERTIFICATE"), "{v}");
        assert!(v["agent_files"].is_object(), "{v}");
    }
}
