//! Per-tenant syslog.
//!
//! * Syslog over TLS (`SYSLOG_TLS_PORT`, default 6514): every device presents a
//!   client certificate issued by the platform CA; its SHA-256 fingerprint
//!   names the device and its tenant. Revoking a device removes it from the
//!   registry, and its open connections stop at the next line.
//! * Plain syslog (514/601): a source IP -> tenant map, for private networks
//!   and VPNs only (the sender is not authenticated). Unmapped senders keep
//!   going to the default tenant.
//!
//! Storage: ClickHouse `ndr.siem_syslog_registry` (`devices`, `sources`, and `ca`: the
//! CA certificate with its key encrypted by `AGENT_KEYS_SECRET`, like the agent keys).
//! The files of earlier versions (`data/syslog/`) are imported once, then removed.
//! Device private keys are returned once and never stored.

use provigil_agent_server::tls::{named_ca_params, server_cert};
use std::sync::{Arc, OnceLock, RwLock};

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::tenancy::{self, normalize_tenant, AuthCtx};
use crate::AppState;

const CA_CN: &str = "Provigil AETHER Syslog CA";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Device {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    /// SHA-256 of the client certificate (DER), lowercase hex.
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    /// In memory only (not written on every line).
    #[serde(skip)]
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Source {
    pub ip: String,
    pub tenant_id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
}

pub struct SyslogTenancy {
    ca: rcgen::Certificate,
    ca_key: KeyPair,
    ca_pem: String,
    devices: RwLock<Vec<Device>>,
    sources: RwLock<Vec<Source>>,
}

static ST: OnceLock<SyslogTenancy> = OnceLock::new();
static DB: OnceLock<crate::db::ClickHouseDb> = OnceLock::new();
/// One registry change at a time: saved to ClickHouse, then applied.
static EDIT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Where earlier versions kept the registry (imported once, then removed).
fn dir() -> std::path::PathBuf {
    crate::data_file_path("syslog")
}

#[derive(Serialize, Deserialize)]
struct CaDoc {
    cert_pem: String,
    key_enc: String,
}

fn table() -> String {
    format!("`{}`.siem_syslog_registry", tenancy::DEFAULT_DB)
}

async fn read_doc(id: &str) -> Result<Option<String>, String> {
    let db = DB.get().ok_or("registry not loaded")?;
    db.root().query(&format!("SELECT doc FROM {} FINAL WHERE id = ?", table())).bind(id).fetch_optional::<String>().await.map_err(|e| e.to_string())
}

async fn write_doc(id: &str, doc: &str) -> Result<(), String> {
    let db = DB.get().ok_or("registry not loaded")?;
    let version = Utc::now().timestamp_micros().max(0) as u64;
    db.root().query(&format!("INSERT INTO {} (id, doc, version) VALUES (?, ?, ?)", table())).bind(id).bind(doc).bind(version).execute().await.map_err(|e| e.to_string())
}

async fn save<T: Serialize>(id: &str, v: &[T]) -> Result<(), String> {
    write_doc(id, &serde_json::to_string(v).map_err(|e| e.to_string())?).await
}

/// A stored list, or the earlier version's file (imported) when none is stored yet.
async fn list_doc<T: Serialize + for<'de> Deserialize<'de>>(id: &str, file: &str) -> Result<Vec<T>, String> {
    if let Some(d) = read_doc(id).await? {
        return serde_json::from_str(&d).map_err(|e| format!("{id}: {e}"));
    }
    let v: Vec<T> = std::fs::read(dir().join(file)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    save(id, &v).await?;
    Ok(v)
}

/// Loads the registry from ClickHouse at start (the files of earlier versions are imported
/// once). Without ClickHouse or `AGENT_KEYS_SECRET`, devices and sources stay unavailable.
pub async fn load(state: &AppState) {
    if !state.db.is_connected() {
        error!("Syslog tenancy unavailable: ClickHouse is not connected");
        return;
    }
    let Some(c) = crate::agent_keys_store::cipher() else {
        error!("Syslog tenancy unavailable: AGENT_KEYS_SECRET is needed to keep its CA key (encrypted in ClickHouse)");
        return;
    };
    let ddl = format!("CREATE TABLE IF NOT EXISTS {} (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id", table());
    if let Err(e) = state.db.root().query(&ddl).execute().await {
        error!("Syslog tenancy unavailable: {e}");
        return;
    }
    let _ = DB.set(state.db.clone());
    match init(&c).await {
        Ok(s) => {
            let _ = ST.set(s);
        }
        Err(e) => error!("Syslog tenancy init failed: {e}"),
    }
}

/// The CA identity. Rebuilt from the saved key on every start: issued
/// certificates chain to the saved `ca.crt.pem` (same name and key).
fn ca_params() -> CertificateParams {
    named_ca_params(CA_CN)
}

async fn init(c: &ring::aead::LessSafeKey) -> Result<SyslogTenancy, String> {
    let d = dir();
    let (ca_key, ca_pem) = match read_doc("ca").await? {
        Some(doc) => {
            let ca: CaDoc = serde_json::from_str(&doc).map_err(|e| format!("ca: {e}"))?;
            let key = crate::agent_keys_store::decrypt(c, &ca.key_enc).ok_or("the CA key cannot be decrypted (AGENT_KEYS_SECRET changed?)")?;
            (KeyPair::from_pem(&key).map_err(|e| e.to_string())?, ca.cert_pem)
        }
        None => {
            let (key, pem) = match (std::fs::read_to_string(d.join("ca.key.pem")), std::fs::read_to_string(d.join("ca.crt.pem"))) {
                (Ok(k), Ok(p)) => (KeyPair::from_pem(&k).map_err(|e| e.to_string())?, p),
                _ => {
                    let key = KeyPair::generate().map_err(|e| e.to_string())?;
                    let cert = ca_params().self_signed(&key).map_err(|e| e.to_string())?;
                    info!("Syslog CA created");
                    (key, cert.pem())
                }
            };
            let key_enc = crate::agent_keys_store::encrypt(c, &key.serialize_pem()).ok_or("the CA key could not be encrypted")?;
            write_doc("ca", &serde_json::to_string(&CaDoc { cert_pem: pem.clone(), key_enc }).map_err(|e| e.to_string())?).await?;
            (key, pem)
        }
    };
    let devices: Vec<Device> = list_doc("devices", "devices.json").await?;
    let sources: Vec<Source> = list_doc("sources", "sources.json").await?;
    // everything is in ClickHouse now: the earlier version's files go (the CA key included)
    for f in ["ca.key.pem", "ca.crt.pem", "devices.json", "sources.json"] {
        if std::fs::remove_file(d.join(f)).is_ok() {
            info!("Syslog registry: {f} imported into ClickHouse and removed");
        }
    }
    let _ = std::fs::remove_dir(&d);
    let ca = ca_params().self_signed(&ca_key).map_err(|e| e.to_string())?;
    Ok(SyslogTenancy { ca, ca_key, ca_pem, devices: RwLock::new(devices), sources: RwLock::new(sources) })
}

pub fn get() -> Option<&'static SyslogTenancy> {
    ST.get()
}

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect()
}

impl SyslogTenancy {
    /// The tenant of a plain-syslog sender (`None`: unmapped).
    pub fn tenant_for_ip(&self, ip: &str) -> Option<String> {
        self.sources.read().unwrap().iter().find(|s| s.ip == ip).map(|s| s.tenant_id.clone())
    }

    /// The device behind a client certificate, if it is still registered.
    pub fn device_by_fingerprint(&self, fp: &str) -> Option<Device> {
        let mut devs = self.devices.write().unwrap();
        let d = devs.iter_mut().find(|d| d.fingerprint == fp)?;
        d.last_seen = Some(Utc::now());
        Some(d.clone())
    }

    pub fn device_active(&self, id: &str) -> bool {
        self.devices.read().unwrap().iter().any(|d| d.id == id)
    }

    /// Issues a client certificate and registers the device: (device, cert pem, key pem).
    async fn issue(&self, tenant: &str, name: &str) -> Result<(Device, String, String), String> {
        let (dev, cert, key) = self.sign_device(tenant, name)?;
        let _edit = EDIT.lock().await;
        let mut devs = self.devices.read().unwrap().clone();
        devs.push(dev.clone());
        save("devices", &devs).await?;
        *self.devices.write().unwrap() = devs;
        Ok((dev, cert, key))
    }

    /// A client certificate for a new device (not registered yet).
    fn sign_device(&self, tenant: &str, name: &str) -> Result<(Device, String, String), String> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        dn.push(DnType::OrganizationName, tenant);
        dn.push(DnType::OrganizationalUnitName, id.as_str());
        p.distinguished_name = dn;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let now = Utc::now();
        // valid from the start of this year for 5 years (revocation is the registry)
        use chrono::Datelike;
        p.not_before = rcgen::date_time_ymd(now.year(), 1, 1);
        p.not_after = rcgen::date_time_ymd(now.year() + 5, 1, 1);
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let cert = p.signed_by(&key, &self.ca, &self.ca_key).map_err(|e| e.to_string())?;
        let dev = Device { id, tenant_id: tenant.to_string(), name: name.to_string(), fingerprint: fingerprint(cert.der()), created_at: now, last_seen: None };
        Ok((dev, cert.pem(), key.serialize_pem()))
    }

    /// The rustls server: our CA is the only trust root for client certificates.
    pub fn tls_config(&self) -> Result<rustls::ServerConfig, String> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let mut hosts: Vec<String> = std::env::var("SYSLOG_TLS_HOSTNAMES")
            .or_else(|_| std::env::var("SITE_DOMAIN"))
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        for h in ["localhost", "127.0.0.1"] {
            if !hosts.iter().any(|x| x == h) {
                hosts.push(h.to_string());
            }
        }
        let (cert, key, _) = server_cert(&self.ca, &self.ca_key, "Provigil AETHER Syslog", hosts)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca.der().clone()).map_err(|e| e.to_string())?;
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().map_err(|e| e.to_string())?;
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert.der().clone(), CertificateDer::from(self.ca.der().to_vec())], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
            .map_err(|e| e.to_string())
    }
}

// ───────────────────────── API ─────────────────────────

fn not_ready() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "status": "error", "message": "syslog tenancy is not available" }))).into_response()
}

fn bad(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "status": "error", "message": msg }))).into_response()
}

/// Which tenants the caller sees: every one for a super admin without a
/// picked tenant, else the caller's scope.
fn visible(ctx: &AuthCtx, tenant: &str) -> bool {
    (ctx.is_super() && ctx.requested_tenant.is_none()) || normalize_tenant(tenant) == ctx.scope()
}

/// `GET /api/v1/syslog/devices`
pub async fn list_devices(Extension(ctx): Extension<AuthCtx>) -> Response {
    if !ctx.can_manage(&ctx.scope()) {
        return tenancy::forbidden();
    }
    let Some(st) = get() else { return not_ready() };
    let devs: Vec<Device> = st.devices.read().unwrap().iter().filter(|d| visible(&ctx, &d.tenant_id)).cloned().collect();
    let out: Vec<serde_json::Value> = devs
        .iter()
        .map(|d| serde_json::json!({ "id": d.id, "tenant_id": d.tenant_id, "name": d.name, "fingerprint": d.fingerprint, "created_at": d.created_at, "last_seen": d.last_seen }))
        .collect();
    Json(serde_json::json!({ "status": "ok", "devices": out })).into_response()
}

#[derive(Deserialize)]
pub struct NewDevice {
    pub name: String,
}

/// `POST /api/v1/syslog/devices` `{"name"}`: the certificate bundle (the key is shown once).
pub async fn create_device(Extension(ctx): Extension<AuthCtx>, Json(body): Json<NewDevice>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let name = body.name.trim();
    if name.is_empty() || name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_. ".contains(c)) {
        return bad("name: 1-64 characters, letters, digits, space, '-', '_', '.'");
    }
    let Some(st) = get() else { return not_ready() };
    match st.issue(&tenant, name).await {
        Ok((dev, cert, key)) => {
            info!("Syslog device '{}' issued for tenant {} by {}", dev.name, tenant, ctx.username);
            Json(serde_json::json!({
                "status": "ok",
                "device": { "id": dev.id, "tenant_id": dev.tenant_id, "name": dev.name, "fingerprint": dev.fingerprint, "created_at": dev.created_at },
                "ca_crt": st.ca_pem,
                "client_crt": cert,
                "client_key": key,
                "port": tls_port(),
            }))
            .into_response()
        }
        Err(e) => {
            error!("Syslog device issue failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "status": "error", "message": "certificate could not be issued" }))).into_response()
        }
    }
}

/// `DELETE /api/v1/syslog/devices/:id`: revokes the device (open connections stop).
pub async fn revoke_device(Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    let Some(st) = get() else { return not_ready() };
    let _edit = EDIT.lock().await;
    let mut devs = st.devices.read().unwrap().clone();
    let Some(i) = devs.iter().position(|d| d.id == id) else { return StatusCode::NOT_FOUND.into_response() };
    if !ctx.can_manage(&devs[i].tenant_id) {
        return tenancy::forbidden();
    }
    let d = devs.remove(i);
    if let Err(e) = save("devices", &devs).await {
        error!("Syslog devices not saved: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    *st.devices.write().unwrap() = devs;
    info!("Syslog device '{}' of tenant {} revoked by {}", d.name, d.tenant_id, ctx.username);
    Json(serde_json::json!({ "status": "ok" })).into_response()
}

/// `GET /api/v1/syslog/ca`: the CA certificate (devices verify the server with it).
pub async fn get_ca() -> Response {
    match get() {
        Some(st) => ([(axum::http::header::CONTENT_TYPE, "application/x-pem-file")], st.ca_pem.clone()).into_response(),
        None => not_ready(),
    }
}

/// `GET /api/v1/syslog/sources`
pub async fn list_sources(Extension(ctx): Extension<AuthCtx>) -> Response {
    if !ctx.can_manage(&ctx.scope()) {
        return tenancy::forbidden();
    }
    let Some(st) = get() else { return not_ready() };
    let v: Vec<Source> = st.sources.read().unwrap().iter().filter(|s| visible(&ctx, &s.tenant_id)).cloned().collect();
    Json(serde_json::json!({ "status": "ok", "sources": v })).into_response()
}

#[derive(Deserialize)]
pub struct NewSource {
    pub ip: String,
    #[serde(default)]
    pub label: String,
}

/// `POST /api/v1/syslog/sources` `{"ip", "label"}`: maps a plain-syslog sender to the caller's tenant.
pub async fn add_source(Extension(ctx): Extension<AuthCtx>, Json(body): Json<NewSource>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let Ok(ip) = body.ip.trim().parse::<std::net::IpAddr>() else { return bad("ip: an IPv4 or IPv6 address") };
    let ip = ip.to_string();
    let Some(st) = get() else { return not_ready() };
    let _edit = EDIT.lock().await;
    let mut srcs = st.sources.read().unwrap().clone();
    if let Some(s) = srcs.iter().find(|s| s.ip == ip) {
        // one owner per address, so events are never attributed to two tenants
        let msg = if s.tenant_id == tenant { "this address is already mapped" } else { "this address belongs to another tenant" };
        return (StatusCode::CONFLICT, Json(serde_json::json!({ "status": "error", "message": msg }))).into_response();
    }
    let label: String = body.label.chars().take(64).collect();
    srcs.push(Source { ip: ip.clone(), tenant_id: tenant.clone(), label, created_at: Utc::now() });
    if let Err(e) = save("sources", &srcs).await {
        error!("Syslog sources not saved: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    *st.sources.write().unwrap() = srcs;
    info!("Syslog source {ip} mapped to tenant {tenant} by {}", ctx.username);
    Json(serde_json::json!({ "status": "ok" })).into_response()
}

/// `DELETE /api/v1/syslog/sources/:ip`
pub async fn remove_source(Extension(ctx): Extension<AuthCtx>, Path(ip): Path<String>) -> Response {
    let Some(st) = get() else { return not_ready() };
    let _edit = EDIT.lock().await;
    let mut srcs = st.sources.read().unwrap().clone();
    let Some(i) = srcs.iter().position(|s| s.ip == ip) else { return StatusCode::NOT_FOUND.into_response() };
    if !ctx.can_manage(&srcs[i].tenant_id) {
        return tenancy::forbidden();
    }
    srcs.remove(i);
    if let Err(e) = save("sources", &srcs).await {
        error!("Syslog sources not saved: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    *st.sources.write().unwrap() = srcs;
    Json(serde_json::json!({ "status": "ok" })).into_response()
}

pub fn tls_port() -> u16 {
    std::env::var("SYSLOG_TLS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(6514)
}

// ───────────────────────── TLS listener ─────────────────────────

/// Syslog over TLS (RFC 5425 framing is octet-counted; newline framing is accepted too).
pub async fn start_tls(state: AppState) {
    let Some(st) = get() else { return };
    let cfg = match st.tls_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Syslog TLS config failed: {e}");
            return;
        }
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], tls_port()));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Syslog TLS failed to bind {addr}: {e}");
            return;
        }
    };
    info!("Syslog TLS receiver listening on {addr} (client certificates required)");
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Syslog TLS accept error: {e}");
                continue;
            }
        };
        let (acceptor, state) = (acceptor.clone(), state.clone());
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(sock)).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    warn!("Syslog TLS handshake from {peer} failed: {e}");
                    return;
                }
                Err(_) => {
                    warn!("Syslog TLS handshake from {peer} timed out");
                    return;
                }
            };
            let fp = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| fingerprint(c.as_ref()));
            let Some(dev) = fp.and_then(|fp| st.device_by_fingerprint(&fp)) else {
                warn!("Syslog TLS from {peer}: certificate is not a registered device (revoked?)");
                return;
            };
            info!("Syslog TLS device '{}' (tenant {}) connected from {peer}", dev.name, dev.tenant_id);
            crate::syslog::read_lines(tls, peer.ip().to_string(), state, crate::syslog::Origin::Device(dev)).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenancy() -> SyslogTenancy {
        let key = KeyPair::generate().unwrap();
        let ca = ca_params().self_signed(&key).unwrap();
        SyslogTenancy { ca_pem: ca.pem(), ca, ca_key: key, devices: RwLock::new(vec![]), sources: RwLock::new(vec![]) }
    }

    /// A client with this certificate and key connects to the listener's config and sends a line.
    async fn handshake(st: &'static SyslogTenancy, cert_pem: &str, key_pem: &str) -> Option<(String, String)> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(st.tls_config().unwrap()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.ok()?;
            let fp = fingerprint(tls.get_ref().1.peer_certificates()?.first()?.as_ref());
            let dev = st.device_by_fingerprint(&fp)?;
            let mut s = String::new();
            tls.read_to_string(&mut s).await.ok()?;
            Some((dev.tenant_id, s))
        });
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(st.ca_pem.as_bytes()).unwrap()).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap()], PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap())
            .unwrap();
        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        if let Ok(mut tls) = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(ServerName::try_from("localhost").unwrap(), sock).await {
            let _ = tls.write_all(b"<13>fw1 test\n").await;
            let _ = tls.shutdown().await;
        }
        server.await.ok().flatten()
    }

    #[tokio::test]
    async fn tls_device_gets_its_tenant() {
        let st: &'static SyslogTenancy = Box::leak(Box::new(tenancy()));
        let (dev, cert, key) = st.sign_device("acme", "fw1").unwrap();
        st.devices.write().unwrap().push(dev);
        assert_eq!(handshake(st, &cert, &key).await, Some(("acme".to_string(), "<13>fw1 test\n".to_string())));
        // a certificate from another CA never gets a tenant
        let other = tenancy();
        let ok = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let foreign = p.signed_by(&ok, &other.ca, &other.ca_key).unwrap();
        assert_eq!(handshake(st, &foreign.pem(), &ok.serialize_pem()).await, None);
        // revoked: the handshake passes (same CA) but the registry has no device
        st.devices.write().unwrap().clear();
        assert_eq!(handshake(st, &cert, &key).await, None);
    }

    #[test]
    fn issued_cert_chains_to_rebuilt_ca() {
        let key = KeyPair::generate().unwrap();
        let ca1 = ca_params().self_signed(&key).unwrap();
        // a restart: the CA is rebuilt from the saved key
        let st = SyslogTenancy { ca: ca_params().self_signed(&key).unwrap(), ca_key: KeyPair::from_pem(&key.serialize_pem()).unwrap(), ca_pem: ca1.pem(), devices: RwLock::new(vec![]), sources: RwLock::new(vec![]) };
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, "fw1");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let lk = KeyPair::generate().unwrap();
        let leaf = p.signed_by(&lk, &st.ca, &st.ca_key).unwrap();
        // the client verifier with only the original CA as root accepts it
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca1.der().clone()).unwrap();
        let v = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        let now = rustls::pki_types::UnixTime::now();
        assert!(v.verify_client_cert(leaf.der(), &[], now).is_ok());
        // a certificate from another CA is refused
        let other_key = KeyPair::generate().unwrap();
        let other = ca_params().self_signed(&other_key).unwrap();
        let lk2 = KeyPair::generate().unwrap();
        let mut p2 = CertificateParams::default();
        p2.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf2 = p2.signed_by(&lk2, &other, &other_key).unwrap();
        assert!(v.verify_client_cert(leaf2.der(), &[], now).is_err());
    }
}
