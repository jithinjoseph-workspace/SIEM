//! Secure Telemetry Streaming & Bidirectional Command Transport.
//!
//! Replaces legacy `siem-agentd` and `siem-remoted` (Blowfish over UDP 1514)
//! with high-throughput, encrypted HTTPS/gRPC telemetry streams.
//!
//! The manager's operations are a [`Link`], over HTTPS ([`HttpsLink`]) or gRPC ([`GrpcLink`],
//! `provigil.agent.v1.AgentService`). A manager with a gRPC and an HTTPS address uses gRPC
//! first and HTTPS for 10 minutes after 3 failed gRPC connections in a row ([`Fallback`]).
//!
//! Several managers: the agent works with one at a time ([`Failover`]); after `max_retries`
//! failed requests in a row it waits `retry_interval_secs` and moves to the next one.

use std::collections::VecDeque;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use chrono::Utc;
use provigil_proto::{
    AgentServiceClient, Chunk, ConfigRequest, EnrollRequest, EventsRequest, KeepaliveRequest, ResultRequest,
    UpgradeChunkRequest, YaraRequest,
};
use serde_json::{json, Value};
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, error, info, warn};

use crate::buffer::EventBuffer;
use crate::config::{AgentConfig, Label};
use crate::edr::EdrExecutor;
use crate::identity::AgentIdentity;
use crate::upgrade::{self, UpgradeSupervisor};

const REQUEST_LIMIT: Duration = Duration::from_secs(15);
const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// Failed gRPC connections in a row before HTTPS is used instead.
const GRPC_FAILS: u32 = 3;
const HTTPS_FOR: Duration = Duration::from_secs(600);

/// Why a request to the manager did not succeed.
#[derive(Debug)]
pub enum Fail {
    /// The manager was not reached (connection, timeout).
    Down(String),
    /// The manager refused: an HTTP status (gRPC codes as their HTTP equivalents) and its text.
    Status(u16, String),
    /// The manager answered, but not with what was expected.
    Bad(String),
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Down(e) | Fail::Bad(e) => f.write_str(e),
            Fail::Status(c, t) if t.is_empty() => write!(f, "status {c}"),
            Fail::Status(c, t) => write!(f, "status {c}: {t}"),
        }
    }
}

/// Who the agent is to the manager (empty before enrollment).
#[derive(Debug, Clone, Default)]
pub struct Creds {
    pub agent_id: String,
    pub key: String,
    pub tenant_id: String,
    /// Only when a real one is configured; without it the manager uses the tenant the agent
    /// was enrolled into.
    pub tenant_key: Option<String>,
}

/// The agent package being downloaded.
pub enum Download {
    Http(reqwest::Response),
    Grpc(Box<tonic::Streaming<Chunk>>),
}

impl Download {
    /// The size, when the manager said it.
    pub fn size(&self) -> Option<u64> {
        match self {
            Download::Http(r) => r.content_length(),
            Download::Grpc(_) => None,
        }
    }

    pub async fn chunk(&mut self) -> Result<Option<Vec<u8>>, String> {
        match self {
            Download::Http(r) => r.chunk().await.map(|c| c.map(|b| b.to_vec())).map_err(|e| e.to_string()),
            Download::Grpc(s) => s.message().await.map(|c| c.map(|c| c.data)).map_err(|e| e.message().to_string()),
        }
    }
}

/// The manager's operations, over HTTPS or gRPC. JSON values are the same on both.
#[tonic::async_trait]
pub trait Link: Send + Sync {
    /// The address, for logs and the local address.
    fn url(&self) -> &str;
    /// The enrollment answer (`agent_id`, `raw_key`, `tenant_id`, ...).
    async fn enroll(&self, body: &Value) -> Result<Value, Fail>;
    /// The commands the manager queued.
    async fn keepalive(&self, body: &Value) -> Result<Vec<Value>, Fail>;
    async fn events(&self, events: &[Value]) -> Result<(), Fail>;
    async fn result(&self, result: &Value) -> Result<(), Fail>;
    /// `{"version", "config"}`.
    async fn config(&self) -> Result<Value, Fail>;
    async fn yara(&self) -> Result<Vec<u8>, Fail>;
    /// The agent package of an `upgrade` command (its `url` and `version`).
    async fn download(&self, url: &str, version: &str) -> Result<Download, Fail>;
}

/// HTTPS/JSON: the manager API's routes.
pub struct HttpsLink {
    base: String,
    creds: Creds,
    client: reqwest::Client,
}

impl HttpsLink {
    pub fn new(base: &str, creds: Creds, client: reqwest::Client) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), creds, client }
    }

    fn agent_url(&self, op: &str) -> String {
        format!("{}/api/v1/agents/{}/{op}", self.base, self.creds.agent_id)
    }

    fn tenant(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.creds.tenant_key {
            Some(k) => req.header("X-Tenant-Key", k),
            None => req,
        }
    }

    /// The agent key, and the tenant key only when a real one is configured.
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        self.tenant(req.header("Authorization", format!("Bearer {}", self.creds.key)))
    }

    async fn send(req: reqwest::RequestBuilder) -> Result<reqwest::Response, Fail> {
        match req.send().await {
            Err(e) => Err(Fail::Down(e.to_string())),
            Ok(r) if r.status().is_success() => Ok(r),
            Ok(r) => Err(Fail::Status(r.status().as_u16(), r.text().await.unwrap_or_default())),
        }
    }

    async fn json(req: reqwest::RequestBuilder) -> Result<Value, Fail> {
        Self::send(req).await?.json().await.map_err(|e| Fail::Bad(e.to_string()))
    }
}

#[tonic::async_trait]
impl Link for HttpsLink {
    fn url(&self) -> &str {
        &self.base
    }

    async fn enroll(&self, body: &Value) -> Result<Value, Fail> {
        // the manager reads the tenant key from the header, not from the body
        Self::json(self.tenant(self.client.post(format!("{}/api/v1/agents/enroll", self.base))).json(body)).await
    }

    async fn keepalive(&self, body: &Value) -> Result<Vec<Value>, Fail> {
        let r = Self::send(self.authed(self.client.post(self.agent_url("keepalive"))).json(body)).await?;
        Ok(r.json::<Value>().await.ok().and_then(|b| b["commands"].as_array().cloned()).unwrap_or_default())
    }

    async fn events(&self, events: &[Value]) -> Result<(), Fail> {
        let payload = json!({ "agent_id": self.creds.agent_id, "tenant_id": self.creds.tenant_id, "events": events, "batch_id": batch_id(events.iter().map(Value::to_string)) });
        Self::send(self.authed(self.client.post(format!("{}/api/v1/events/ingest", self.base))).json(&payload)).await.map(drop)
    }

    async fn result(&self, result: &Value) -> Result<(), Fail> {
        Self::send(self.authed(self.client.post(self.agent_url("response_result"))).json(result)).await.map(drop)
    }

    async fn config(&self) -> Result<Value, Fail> {
        Self::json(self.authed(self.client.get(self.agent_url("config")))).await
    }

    async fn yara(&self) -> Result<Vec<u8>, Fail> {
        let r = Self::send(self.authed(self.client.get(self.agent_url("yara-rules")))).await?;
        Ok(r.bytes().await.map_err(|e| Fail::Down(e.to_string()))?.to_vec())
    }

    async fn download(&self, url: &str, _version: &str) -> Result<Download, Fail> {
        let url = if url.starts_with('/') { format!("{}{url}", self.base) } else { url.to_string() };
        Self::send(self.authed(self.client.get(url)).timeout(upgrade::DOWNLOAD_LIMIT)).await.map(Download::Http)
    }
}

/// gRPC: `provigil.agent.v1.AgentService` at `grpc://host:port` or `grpcs://host:port`.
pub struct GrpcLink {
    url: String,
    creds: Creds,
    client: AgentServiceClient,
}

impl GrpcLink {
    /// Connects when first used. With TLS the certificate is verified unless `insecure`.
    pub fn new(url: &str, creds: Creds, insecure: bool, ca: &[Cert]) -> Result<Self, String> {
        let client = AgentServiceClient::new(grpc_channel(url, insecure, ca)?)
            .max_decoding_message_size(MAX_MESSAGE)
            .max_encoding_message_size(MAX_MESSAGE);
        Ok(Self { url: url.to_string(), creds, client })
    }

    /// The HTTPS headers as metadata, and the agent id.
    fn req<M>(&self, m: M) -> tonic::Request<M> {
        let mut r = tonic::Request::new(m);
        let md = r.metadata_mut();
        let mut put = |k: &'static str, v: &str| {
            if let Ok(v) = v.parse() {
                md.insert(k, v);
            }
        };
        if !self.creds.key.is_empty() {
            put("authorization", &format!("Bearer {}", self.creds.key));
            put("x-agent-id", &self.creds.agent_id);
        }
        if let Some(k) = &self.creds.tenant_key {
            put("x-tenant-key", k);
        }
        r
    }

    async fn call<A>(f: impl Future<Output = Result<tonic::Response<A>, tonic::Status>>) -> Result<A, Fail> {
        match tokio::time::timeout(REQUEST_LIMIT, f).await {
            Err(_) => Err(Fail::Down("request timed out".into())),
            Ok(r) => r.map(tonic::Response::into_inner).map_err(grpc_fail),
        }
    }
}

/// A gRPC status as the HTTPS answer it stands for.
fn grpc_fail(s: tonic::Status) -> Fail {
    use tonic::Code;
    let code = match s.code() {
        // Unknown / Cancelled: the connection was reset or dropped
        Code::Unavailable | Code::Unknown | Code::Cancelled => return Fail::Down(s.message().to_string()),
        Code::InvalidArgument => 400,
        Code::Unauthenticated => 401,
        Code::PermissionDenied => 403,
        Code::NotFound => 404,
        Code::DeadlineExceeded => 408,
        Code::AlreadyExists => 409,
        Code::FailedPrecondition => 412,
        Code::ResourceExhausted => 429,
        Code::Unimplemented => 501,
        _ => 500,
    };
    Fail::Status(code, s.message().to_string())
}

/// The id of a batch of events, from their JSON: a batch sent again (re-queued after a lost
/// answer) has the same id, so the manager takes it once.
fn batch_id<S: AsRef<str>>(events: impl IntoIterator<Item = S>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for e in events {
        h.update(e.as_ref().as_bytes());
        h.update([0]);
    }
    uuid::Uuid::from_bytes(h.finalize()[..16].try_into().unwrap()).to_string()
}

fn json_text(s: &str) -> Result<Value, Fail> {
    serde_json::from_str(s).map_err(|e| Fail::Bad(e.to_string()))
}

#[tonic::async_trait]
impl Link for GrpcLink {
    fn url(&self) -> &str {
        &self.url
    }

    async fn enroll(&self, body: &Value) -> Result<Value, Fail> {
        let s = |k: &str| body[k].as_str().unwrap_or_default().to_string();
        let q = EnrollRequest {
            name: s("name"),
            os_type: s("os_type"),
            groups: s("groups"),
            force: body["force"].as_bool().unwrap_or(false),
            hostname: s("hostname"),
            version: s("version"),
        };
        let a = Self::call(self.client.clone().enroll(self.req(q))).await?;
        Ok(json!({
            "agent_id": a.agent_id, "agent_name": a.agent_name, "agent_ip": a.agent_ip,
            "raw_key": a.raw_key, "tenant_id": a.tenant_id, "groups": a.groups,
        }))
    }

    async fn keepalive(&self, body: &Value) -> Result<Vec<Value>, Fail> {
        let a = Self::call(self.client.clone().keepalive(self.req(KeepaliveRequest { body_json: body.to_string() }))).await?;
        a.commands_json.iter().map(|c| json_text(c)).collect()
    }

    async fn events(&self, events: &[Value]) -> Result<(), Fail> {
        let events_json: Vec<String> = events.iter().map(Value::to_string).collect();
        let q = EventsRequest { batch_id: batch_id(&events_json), events_json };
        Self::call(self.client.clone().events(self.req(q))).await.map(drop)
    }

    async fn result(&self, result: &Value) -> Result<(), Fail> {
        Self::call(self.client.clone().result(self.req(ResultRequest { result_json: result.to_string() }))).await.map(drop)
    }

    async fn config(&self) -> Result<Value, Fail> {
        let a = Self::call(self.client.clone().config(self.req(ConfigRequest {}))).await?;
        Ok(json!({ "version": a.version, "config": json_text(&a.config_json)? }))
    }

    async fn yara(&self) -> Result<Vec<u8>, Fail> {
        Ok(Self::call(self.client.clone().yara(self.req(YaraRequest {}))).await?.data)
    }

    async fn download(&self, url: &str, version: &str) -> Result<Download, Fail> {
        let mut q = self.req(UpgradeChunkRequest { version: version.to_string() });
        // which published file: the last part of its address
        if let Ok(name) = url.rsplit('/').next().unwrap_or_default().parse() {
            q.metadata_mut().insert("x-file-name", name);
        }
        let r = self.client.clone().upgrade(q).await.map_err(grpc_fail)?;
        Ok(Download::Grpc(Box::new(r.into_inner())))
    }
}

/// The channel to a `grpc://` (plain) or `grpcs://` (TLS) address.
fn grpc_channel(url: &str, insecure: bool, ca: &[Cert]) -> Result<Channel, String> {
    let (tls, rest) = match url.split_once("://") {
        Some(("grpc", r)) => (false, r),
        Some(("grpcs", r)) => (true, r),
        _ => return Err(format!("not a gRPC address: {url}")),
    };
    // pings find a connection that went dead without closing (a stale NAT or balancer flow)
    let endpoint = Endpoint::from_shared(format!("http://{rest}"))
        .map_err(|e| format!("{url}: {e}"))?
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .connect_timeout(Duration::from_secs(5));
    if !tls {
        return Ok(endpoint.connect_lazy());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let mut cfg = if insecure {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(AnyCert(provider))).with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        roots.add_parsable_certificates(ca.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    Ok(endpoint.connect_with_connector_lazy(tower::service_fn(move |uri: tonic::transport::Uri| {
        let tls = tls.clone();
        async move {
            let host = uri.host().unwrap_or_default().trim_matches(['[', ']']).to_string();
            let tcp = tokio::net::TcpStream::connect((host.as_str(), uri.port_u16().unwrap_or(443))).await?;
            let name = rustls::pki_types::ServerName::try_from(host).map_err(std::io::Error::other)?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls.connect(name, tcp).await?))
        }
    })))
}

/// `tls_insecure`: any certificate is accepted (the handshake signatures are still checked).
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The HTTPS client: the certificate is verified unless `tls_insecure`; `ca` trusted besides
/// the built-in roots.
pub fn http_client(insecure: bool, ca: &[Cert]) -> reqwest::Client {
    // rustls also when a build with siem-api turns reqwest's native TLS on
    let mut b = reqwest::Client::builder().use_rustls_tls().danger_accept_invalid_certs(insecure).timeout(REQUEST_LIMIT);
    for c in ca.iter().filter_map(|c| reqwest::Certificate::from_der(c).ok()) {
        b = b.add_root_certificate(c);
    }
    b.build().expect("HTTP Client")
}

pub type Cert = rustls::pki_types::CertificateDer<'static>;

/// The certificates of `ca_file` (PEM); none, with an error logged, when it cannot be read.
pub fn ca_certs(path: Option<&std::path::Path>) -> Vec<Cert> {
    use rustls::pki_types::pem::PemObject;
    let Some(path) = path else { return Vec::new() };
    let certs: Result<Vec<Cert>, String> = std::fs::read(path)
        .map_err(|e| e.to_string())
        .and_then(|pem| Cert::pem_slice_iter(&pem).collect::<Result<_, _>>().map_err(|e| e.to_string()));
    match certs {
        Ok(c) if !c.is_empty() => c,
        r => {
            error!(file = %path.display(), error = ?r.err(), "ca_file has no usable certificate");
            Vec::new()
        }
    }
}

/// gRPC or HTTPS for a manager that has both.
#[derive(Debug, Default)]
pub struct Fallback {
    fails: u32,
    https_until: Option<Instant>,
}

impl Fallback {
    /// Whether gRPC is used at `now`. After the HTTPS period only a `probe` (the keepalive)
    /// tries gRPC, and its outcome decides for the other requests.
    pub fn grpc(&mut self, now: Instant, probe: bool, manager: &str) -> bool {
        match self.https_until {
            Some(t) if now < t || !probe => false,
            Some(_) => {
                info!("Trying gRPC again for manager '{manager}'.");
                true
            }
            None => true,
        }
    }

    /// Counts a gRPC request: reached the manager or not.
    pub fn report(&mut self, connected: bool, now: Instant, manager: &str) {
        if connected {
            *self = Fallback::default();
            return;
        }
        self.fails += 1;
        if self.https_until.is_some() {
            // the probe failed
            self.https_until = Some(now + HTTPS_FOR);
        } else if self.fails >= GRPC_FAILS {
            warn!("gRPC to manager '{manager}' failed {GRPC_FAILS} times in a row; using HTTPS for 10 minutes.");
            self.https_until = Some(now + HTTPS_FOR);
        }
    }
}

/// One manager: its gRPC and / or HTTPS link.
pub struct Manager {
    pub name: String,
    grpc: Option<Arc<dyn Link>>,
    https: Option<Arc<dyn Link>>,
    fallback: Mutex<Fallback>,
}

impl Manager {
    /// Its links, gRPC first.
    pub fn links(&self) -> impl Iterator<Item = &Arc<dyn Link>> {
        self.grpc.iter().chain(&self.https)
    }

    /// The link to use at `now` (`probe`: for the keepalive), and whether it is the gRPC one.
    fn link(&self, now: Instant, probe: bool) -> (Arc<dyn Link>, bool) {
        match (&self.grpc, &self.https) {
            (Some(g), Some(h)) => {
                if self.fallback.lock().unwrap().grpc(now, probe, &self.name) { (g.clone(), true) } else { (h.clone(), false) }
            }
            (Some(g), None) => (g.clone(), true),
            (None, Some(h)) => (h.clone(), false),
            (None, None) => unreachable!("a manager has a link"),
        }
    }

    fn report<T>(&self, grpc: bool, r: &Result<T, Fail>) {
        if grpc && self.https.is_some() {
            self.fallback.lock().unwrap().report(!matches!(r, Err(Fail::Down(_))), Instant::now(), &self.name);
        }
    }
}

fn is_grpc(url: &str) -> bool {
    url.starts_with("grpc://") || url.starts_with("grpcs://")
}

/// The managers in failover order: gRPC for a `grpc(s)://` entry and, with `grpc_url`, for
/// `manager_url`'s; HTTPS for an `http(s)://` entry.
pub fn managers(config: &AgentConfig, creds: &Creds) -> Vec<Manager> {
    let ca = ca_certs(config.ca_file.as_deref());
    let client = http_client(config.tls_insecure, &ca);
    let primary = config.manager_url.trim().trim_end_matches('/');
    let grpc_url = config.grpc_url.trim();
    config
        .manager_list()
        .into_iter()
        .map(|url| {
            let g = if is_grpc(&url) { Some(url.as_str()) } else { (url == primary && !grpc_url.is_empty()).then_some(grpc_url) };
            let grpc = g.and_then(|g| match GrpcLink::new(g, creds.clone(), config.tls_insecure, &ca) {
                Ok(l) => Some(Arc::new(l) as Arc<dyn Link>),
                Err(e) => {
                    error!("gRPC address not usable: {e}");
                    None
                }
            });
            // a gRPC entry that is not usable fails like any bad address does
            let https = (!is_grpc(&url) || grpc.is_none()).then(|| Arc::new(HttpsLink::new(&url, creds.clone(), client.clone())) as Arc<dyn Link>);
            Manager { name: url, grpc, https, fallback: Mutex::default() }
        })
        .collect()
}

/// The manager in use and the count of failed requests to it.
pub struct Failover {
    urls: Vec<String>,
    current: AtomicUsize,
    failures: AtomicU32,
    max_retries: u32,
    retry_interval: Duration,
}

impl Failover {
    pub fn new(urls: Vec<String>, max_retries: u32, retry_interval: Duration) -> Self {
        assert!(!urls.is_empty(), "at least one manager");
        Self { urls, current: AtomicUsize::new(0), failures: AtomicU32::new(0), max_retries: max_retries.max(1), retry_interval }
    }

    /// The manager requests go to now.
    pub fn current(&self) -> &str {
        &self.urls[self.index()]
    }

    pub fn index(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }

    /// Counts one request's outcome. The failure that reaches `max_retries` waits
    /// `retry_interval` and switches manager: `Some(wrapped)`, `wrapped` when it went back to
    /// the first.
    pub async fn report(&self, ok: bool) -> Option<bool> {
        if ok {
            self.failures.store(0, Ordering::SeqCst);
            return None;
        }
        if self.failures.fetch_add(1, Ordering::SeqCst) + 1 != self.max_retries {
            return None;
        }
        tokio::time::sleep(self.retry_interval).await;
        let next = (self.current.load(Ordering::SeqCst) + 1) % self.urls.len();
        let wrapped = next == 0;
        if wrapped {
            warn!("Unable to connect to any manager.");
        }
        info!("Trying next manager in the line: '{}'.", self.urls[next]);
        self.current.store(next, Ordering::SeqCst);
        self.failures.store(0, Ordering::SeqCst);
        Some(wrapped)
    }

    /// Counts a request: not reached or a server error is a failure, an answer a success,
    /// other refusals neither.
    async fn note<T>(&self, r: &Result<T, Fail>) {
        match r {
            Ok(_) | Err(Fail::Bad(_)) => { self.report(true).await; }
            Err(Fail::Status(c, _)) if *c >= 500 => { self.report(false).await; }
            Err(Fail::Status(..)) => {}
            Err(Fail::Down(_)) => { self.report(false).await; }
        }
    }
}

/// The IPv4 address this machine uses to reach `base` (no packet is sent).
pub async fn local_ipv4(base: &str) -> Option<String> {
    let url = reqwest::Url::parse(base).ok()?;
    let (host, port) = (url.host_str()?.to_string(), url.port_or_known_default()?);
    let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    s.connect((host.as_str(), port)).await.ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip.to_string()),
        _ => None,
    }
}

/// The keepalive body: `status` `active`, or `stopping` for the last one.
pub fn keepalive_body(identity: &AgentIdentity, labels: &[Label], agent_ip: Option<String>, group_config_version: Option<&str>, status: &str) -> Value {
    json!({
        "agent_id": identity.agent_id,
        "agent_name": identity.agent_name,
        "tenant_id": identity.tenant_id,
        "timestamp": Utc::now().to_rfc3339(),
        "status": status,
        "labels": labels,
        "agent_ip": agent_ip,
        "version": env!("CARGO_PKG_VERSION"),
        "group_config_version": group_config_version,
        // a file integrity baseline to send: the manager answers with a slot when one is free
        "fim_state_wanted": crate::fim::state_wanted(),
    })
}

/// The keepalive answer's entry that lets this agent send its file integrity baseline now.
const FIM_STATE_ALLOWED: &str = "fim_state_allowed";
/// Event batches hold this many events at most (fewer after a batch too large for the manager).
const BATCH: usize = 100;
/// Keepalives refused in a row (401, 404, 410) before the agent enrolls again.
const REFUSALS: u32 = 3;
/// Command results kept while the manager cannot be reached.
const RESULTS: usize = 100;
/// Command ids remembered: one handed out again (its answer was lost) is not run twice.
const RAN: usize = 256;

pub struct AgentTransport {
    failover: Arc<Failover>,
    managers: Vec<Manager>,
    /// The effective settings: replaced when the group configuration changes.
    config: Mutex<AgentConfig>,
    /// The last keepalive the manager accepted.
    last_keepalive: Mutex<Option<String>>,
    /// Events the manager accepted since the start.
    sent: AtomicU64,
    /// The group configuration version applied.
    group_version: Mutex<Option<String>>,
    /// Keepalives refused in a row: the manager does not know this agent's key or id.
    refused: AtomicU32,
    batch: AtomicUsize,
    /// Command results not delivered yet.
    results: Mutex<VecDeque<Value>>,
    /// The last [`RAN`] command ids run, with their result once there is one.
    ran: Mutex<VecDeque<(String, Option<Value>)>>,
    identity: AgentIdentity,
    buffer: Arc<EventBuffer>,
    edr: Arc<EdrExecutor>,
    pub upgrades: UpgradeSupervisor,
}

impl AgentTransport {
    pub fn new(
        config: &AgentConfig,
        identity: AgentIdentity,
        buffer: Arc<EventBuffer>,
        edr: Arc<EdrExecutor>,
    ) -> Self {
        let creds = Creds {
            agent_id: identity.agent_id.clone(),
            key: identity.auth_token.clone(),
            tenant_id: identity.tenant_id.clone(),
            tenant_key: crate::identity::real_tenant_key(&config.tenant_key).map(String::from),
        };
        let managers = managers(config, &creds);
        Self {
            failover: Arc::new(Failover::new(
                managers.iter().map(|m| m.name.clone()).collect(),
                config.max_retries,
                Duration::from_secs(config.retry_interval_secs),
            )),
            managers,
            config: Mutex::new(config.clone()),
            last_keepalive: Mutex::default(),
            sent: AtomicU64::new(0),
            group_version: Mutex::default(),
            refused: AtomicU32::new(0),
            batch: AtomicUsize::new(BATCH),
            results: Mutex::default(),
            ran: Mutex::default(),
            identity,
            buffer,
            edr,
            upgrades: UpgradeSupervisor::new(upgrade::DIR, config.upgrade_enabled),
        }
    }

    pub fn set_config(&self, config: AgentConfig) {
        *self.config.lock().unwrap() = config;
    }

    pub fn set_group_version(&self, version: Option<String>) {
        *self.group_version.lock().unwrap() = version;
    }

    /// The manager refused the keepalive 3 times in a row: the agent must enroll again.
    pub fn must_reenroll(&self) -> bool {
        self.refused.load(Ordering::SeqCst) >= REFUSALS
    }

    async fn keepalive_payload(&self, url: &str, status: &str) -> Value {
        let labels = self.config.lock().unwrap().labels.clone();
        let version = self.group_version.lock().unwrap().clone();
        keepalive_body(&self.identity, &labels, local_ipv4(url).await, version.as_deref(), status)
    }

    /// The last keepalive, at service stop (no failover: the agent is ending).
    pub async fn send_stopping(&self) {
        let (_, link, _) = self.link(false);
        if let Err(e) = link.keepalive(&self.keepalive_payload(link.url(), "stopping").await).await {
            warn!(error = %e, "Stopping keepalive not delivered");
        }
    }

    /// The manager requests go to now.
    pub fn manager(&self) -> &str {
        self.failover.current()
    }

    /// The manager in use, its link now (`probe`: for the keepalive), and whether that is gRPC.
    fn link(&self, probe: bool) -> (&Manager, Arc<dyn Link>, bool) {
        let m = &self.managers[self.failover.index()];
        let (link, grpc) = m.link(Instant::now(), probe);
        (m, link, grpc)
    }

    /// Counts a request for the gRPC / HTTPS choice and for the failover.
    async fn done<T>(&self, m: &Manager, grpc: bool, r: &Result<T, Fail>) {
        m.report(grpc, r);
        self.failover.note(r).await;
    }

    /// Sends a periodic keepalive heartbeat and polls for pending manager commands.
    pub async fn send_heartbeat(self: &Arc<Self>) -> Result<(), String> {
        let (m, link, grpc) = self.link(true);
        let payload = self.keepalive_payload(link.url(), "active").await;

        let r = link.keepalive(&payload).await;
        self.done(m, grpc, &r).await;
        match &r {
            Err(Fail::Status(401 | 404 | 410, _)) => {
                self.refused.fetch_add(1, Ordering::SeqCst);
            }
            Err(Fail::Down(_)) => {}
            _ => self.refused.store(0, Ordering::SeqCst),
        }
        let commands = r.map_err(|e| format!("Heartbeat failed: {e}"))?;
        debug!("Heartbeat acknowledged by manager");
        *self.last_keepalive.lock().unwrap() = Some(Utc::now().to_rfc3339());
        let unsent: Vec<Value> = self.results.lock().unwrap().drain(..).collect();
        if !unsent.is_empty() {
            let me = self.clone();
            tokio::spawn(async move {
                for r in unsent {
                    me.send_result(&r).await;
                }
            });
        }
        // the baseline slot rides in the answer as long as the manager holds it for this agent
        crate::fim::allow_state(commands.iter().any(|c| c["type"] == FIM_STATE_ALLOWED));
        for cmd in commands.into_iter().filter(|c| c["type"] != FIM_STATE_ALLOWED) {
            let id = cmd["command_id"].as_str().unwrap_or_default().to_string();
            match self.first_run(&id) {
                Ok(()) => {}
                // run before: its result again (still running: it comes when done)
                Err(Some(result)) => {
                    let me = self.clone();
                    tokio::spawn(async move { me.send_result(&result).await });
                    continue;
                }
                Err(None) => continue,
            }
            let (me, link) = (self.clone(), link.clone());
            tokio::spawn(async move {
                let (result, stop) = match cmd["type"].as_str() {
                    Some("upgrade") => me.upgrades.handle(&cmd, link.as_ref()).await,
                    Some("getconfig" | "getstate") => (me.query(&cmd), false),
                    _ => (me.edr.execute_command(&cmd).await, false),
                };
                me.ran_result(&id, &result);
                me.send_result(&result).await;
                if stop {
                    crate::service::request_stop();
                }
            });
        }
        Ok(())
    }

    /// Whether command `id` is new (then remembered); else `Err` with its result when it has one.
    /// A command without an id is always new.
    fn first_run(&self, id: &str) -> Result<(), Option<Value>> {
        if id.is_empty() {
            return Ok(());
        }
        let mut ran = self.ran.lock().unwrap();
        if let Some((_, r)) = ran.iter().find(|(i, _)| i == id) {
            return Err(r.clone());
        }
        if ran.len() >= RAN {
            ran.pop_front();
        }
        ran.push_back((id.to_string(), None));
        Ok(())
    }

    fn ran_result(&self, id: &str, result: &Value) {
        if let Some(e) = self.ran.lock().unwrap().iter_mut().find(|(i, _)| i == id) {
            e.1 = Some(result.clone());
        }
    }

    /// The answer to a manager query: the effective settings (`getconfig`) or this agent's state
    /// (`getstate`).
    fn query(&self, cmd: &Value) -> Value {
        let id = &cmd["command_id"];
        if cmd["type"] == "getconfig" {
            let mut config = serde_json::to_value(&*self.config.lock().unwrap()).unwrap_or_default();
            // the agent's own key is in its identity, not in the settings
            if let Some(c) = config.as_object_mut() {
                c.remove("tenant_key");
            }
            return json!({ "command_id": id, "status": "done", "config": config });
        }
        let (_, _, grpc) = self.link(false);
        let state = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "group_config_version": *self.group_version.lock().unwrap(),
            "manager": self.manager(),
            "transport": if grpc { "grpc" } else { "https" },
            "buffer": { "events": self.buffer.len(), "state": self.buffer.state() },
            "last_keepalive": *self.last_keepalive.lock().unwrap(),
            "last_scans": crate::last_scans(),
            "events": { "sent": self.sent.load(Ordering::SeqCst), "dropped": self.buffer.dropped() },
        });
        json!({ "command_id": id, "status": "done", "state": state })
    }

    /// Reports a command's result to the manager; one the manager did not get is kept (the
    /// last [`RESULTS`]) and sent again after the next keepalive.
    pub async fn send_result(&self, result: &Value) {
        let (m, link, grpc) = self.link(false);
        let r = link.result(result).await;
        if let Err(e) = &r {
            warn!(error = %e, "Response result not delivered to the manager");
            if matches!(e, Fail::Down(_)) || matches!(e, Fail::Status(c, _) if *c >= 500) {
                let mut q = self.results.lock().unwrap();
                if q.len() >= RESULTS {
                    q.pop_front();
                }
                q.push_back(result.clone());
            }
        }
        self.done(m, grpc, &r).await;
    }

    /// The agent's group configuration: `{"version", "config"}`.
    pub async fn fetch_group_config(&self) -> Result<Value, String> {
        let (m, link, grpc) = self.link(false);
        let r = link.config().await;
        self.done(m, grpc, &r).await;
        r.map_err(|e| e.to_string())
    }

    /// The YARA rule file the manager keeps for its agents (encoded, as yara-scan reads it).
    pub async fn fetch_yara_rules(&self) -> Result<Vec<u8>, String> {
        let (m, link, grpc) = self.link(false);
        let r = link.yara().await;
        self.done(m, grpc, &r).await;
        r.map_err(|e| e.to_string())
    }

    /// Flushes buffered telemetry events to the manager (paced by the buffer).
    pub async fn flush_events(&self) -> Result<usize, String> {
        if self.buffer.is_empty() {
            return Ok(0);
        }

        let limit = self.batch.load(Ordering::SeqCst);
        let batch = self.buffer.next_batch(limit).await;
        let count = batch.len();
        if count == 0 {
            return Ok(0);
        }

        let (m, link, grpc) = self.link(false);
        let r = link.events(&batch).await;
        let result = match &r {
            Ok(()) => {
                debug!(count = count, "Successfully transmitted event batch to manager");
                self.sent.fetch_add(count as u64, Ordering::SeqCst);
                self.batch.store((limit * 2).min(BATCH), Ordering::SeqCst);
                Ok(count)
            }
            Err(Fail::Status(413, _)) if count > 1 => {
                warn!(count = count, "Event batch too large for the manager; sending it in halves");
                self.batch.store(count / 2, Ordering::SeqCst);
                self.buffer.prepend_batch(batch);
                Err("Ingest refused: batch too large".into())
            }
            Err(Fail::Status(413, _)) => {
                error!(event_type = %batch[0]["event_type"], "Event too large for the manager; dropping it");
                Err("Ingest refused: event too large".into())
            }
            Err(Fail::Status(c, _)) if (400..500).contains(c) && !matches!(c, 401 | 403 | 408 | 429) => {
                // malformed, or for an unknown / removed agent: sending it again can never work,
                // and re-queuing it would block every later event
                error!(status = %c, count = count, "Manager refused event batch; dropping it");
                Err(format!("Ingest refused: status {c}"))
            }
            Err(Fail::Down(e)) => {
                error!(error = %e, "Network transmission error; events preserved in offline buffer");
                self.buffer.prepend_batch(batch);
                Err(e.clone())
            }
            Err(e) => {
                warn!(error = %e, "Manager rejected event batch; requeuing");
                self.buffer.prepend_batch(batch);
                Err(format!("Ingest rejected: {e}"))
            }
        };
        // after the re-queue: a switch sends these events to the next manager
        self.done(m, grpc, &r).await;
        result
    }
}

#[cfg(test)]
#[path = "transport_bench.rs"]
mod bench;

#[cfg(test)]
mod tests {
    use super::*;
    use provigil_proto::{
        AgentService, AgentServiceServer, ChunkStream, ConfigReply, Empty, EnrollReply, EventsReply, KeepaliveReply, YaraReply,
    };
    use tonic::{Request, Response, Status};

    #[test]
    fn keepalive_carries_labels_and_agent_ip() {
        let ident = AgentIdentity {
            agent_id: "001".into(),
            agent_name: "pc".into(),
            tenant_id: "t1".into(),
            auth_token: "k".into(),
            enrolled_at: Utc::now(),
        };
        let labels = vec![
            Label { key: "env".into(), value: "prod".into(), hidden: false },
            Label { key: "owner".into(), value: "ops".into(), hidden: true },
        ];
        let b = keepalive_body(&ident, &labels, Some("10.0.0.7".into()), Some("v3"), "active");
        assert_eq!(b["labels"], json!([
            {"key": "env", "value": "prod", "hidden": false},
            {"key": "owner", "value": "ops", "hidden": true},
        ]));
        assert_eq!(b["agent_ip"], "10.0.0.7");
        assert_eq!(b["agent_id"], "001");
        assert_eq!(b["status"], "active");
        assert_eq!(b["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(b["group_config_version"], "v3");
        let b = keepalive_body(&ident, &[], None, None, "stopping");
        assert_eq!(b["status"], "stopping");
        assert!(b["group_config_version"].is_null());
        assert!(b.as_object().unwrap().contains_key("agent_ip") && b["agent_ip"].is_null());
        // a label without `hidden` in the configuration is not hidden
        let l: Label = serde_json::from_value(json!({"key": "a", "value": "b"})).unwrap();
        assert!(!l.hidden);
    }

    #[tokio::test]
    async fn local_ipv4_of_loopback_manager() {
        assert_eq!(local_ipv4("http://127.0.0.1:8088").await.as_deref(), Some("127.0.0.1"));
        assert_eq!(local_ipv4("grpc://127.0.0.1:8089").await.as_deref(), Some("127.0.0.1"));
        assert_eq!(local_ipv4("not a url").await, None);
    }

    #[tokio::test]
    async fn failover_switches_resets_and_wraps() {
        let f = Failover::new(vec!["http://a".into(), "http://b".into(), "http://c".into()], 5, Duration::ZERO);
        assert_eq!(f.current(), "http://a");
        for _ in 0..4 {
            assert_eq!(f.report(false).await, None);
        }
        assert_eq!(f.report(false).await, Some(false));
        assert_eq!(f.current(), "http://b");
        // a success resets the count
        for _ in 0..4 {
            f.report(false).await;
        }
        f.report(true).await;
        for _ in 0..4 {
            assert_eq!(f.report(false).await, None);
        }
        assert_eq!(f.current(), "http://b");
        assert_eq!(f.report(false).await, Some(false));
        assert_eq!(f.current(), "http://c");
        // after the last one: back to the first, with the warning
        for _ in 0..4 {
            f.report(false).await;
        }
        assert_eq!(f.report(false).await, Some(true));
        assert_eq!(f.current(), "http://a");
    }

    #[test]
    fn https_after_three_grpc_failures_then_grpc_again() {
        let mut f = Fallback::default();
        let t0 = Instant::now();
        assert!(f.grpc(t0, false, "m"));
        f.report(false, t0, "m");
        f.report(false, t0, "m");
        f.report(true, t0, "m");
        f.report(false, t0, "m");
        f.report(false, t0, "m");
        assert!(f.grpc(t0, false, "m"), "a success resets the count");
        f.report(false, t0, "m");
        assert!(!f.grpc(t0, true, "m"));
        assert!(!f.grpc(t0 + Duration::from_secs(599), true, "m"));
        // after 10 minutes the keepalive probes gRPC; the other requests wait for it
        let t1 = t0 + HTTPS_FOR;
        assert!(!f.grpc(t1, false, "m"));
        assert!(f.grpc(t1, true, "m"));
        f.report(false, t1, "m");
        assert!(!f.grpc(t1, true, "m"), "a failed probe: HTTPS for another 10 minutes");
        assert!(!f.grpc(t1 + HTTPS_FOR - Duration::from_secs(1), true, "m"));
        let t2 = t1 + HTTPS_FOR;
        assert!(f.grpc(t2, true, "m"));
        f.report(true, t2, "m");
        assert!(f.grpc(t2, false, "m"), "a probe that worked: gRPC for every request");
        f.report(false, t2, "m");
        assert!(f.grpc(t2, false, "m"), "the count started again");
    }

    #[tokio::test]
    async fn grpc_url_pairs_with_manager_url() {
        let config = AgentConfig {
            manager_url: "http://10.0.0.5:8088/".into(),
            grpc_url: "grpc://10.0.0.5:8089".into(),
            manager_urls: vec!["http://10.0.0.5:8088".into(), "grpcs://backup:8089".into(), "http://other".into()],
            ..AgentConfig::default()
        };
        let m = managers(&config, &Creds::default());
        let kinds: Vec<(Option<&str>, Option<&str>)> =
            m.iter().map(|m| (m.grpc.as_ref().map(|l| l.url()), m.https.as_ref().map(|l| l.url()))).collect();
        assert_eq!(kinds, [
            (Some("grpc://10.0.0.5:8089"), Some("http://10.0.0.5:8088")),
            (Some("grpcs://backup:8089"), None),
            (None, Some("http://other")),
        ]);
        assert!(grpc_channel("http://x", false, &[]).is_err());
    }

    /// The manager's side for these tests: agent 007 with key k7, tenant key tk.
    struct Fake;

    #[allow(clippy::result_large_err)]
    fn check<T>(r: &Request<T>) -> Result<(), Status> {
        let md = r.metadata();
        let get = |k| md.get(k).and_then(|v| v.to_str().ok());
        if get("authorization") != Some("Bearer k7") || get("x-agent-id") != Some("007") || get("x-tenant-key") != Some("tk") {
            return Err(Status::unauthenticated("invalid agent key"));
        }
        Ok(())
    }

    #[tonic::async_trait]
    impl AgentService for Fake {
        async fn enroll(&self, r: Request<provigil_proto::EnrollRequest>) -> Result<Response<EnrollReply>, Status> {
            assert_eq!(r.metadata().get("x-tenant-key").unwrap(), "tk");
            assert!(r.metadata().get("authorization").is_none());
            let q = r.into_inner();
            Ok(Response::new(EnrollReply { agent_id: "007".into(), agent_name: q.name, raw_key: "k7".into(), tenant_id: "acme".into(), ..Default::default() }))
        }
        async fn keepalive(&self, r: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status> {
            check(&r)?;
            let body: Value = serde_json::from_str(&r.get_ref().body_json).unwrap();
            assert_eq!(body["status"], "active");
            Ok(Response::new(KeepaliveReply { commands_json: vec![r#"{"command_id":"c-1","type":"scan"}"#.into()] }))
        }
        async fn events(&self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status> {
            check(&r)?;
            if r.get_ref().events_json.iter().any(|e| e.contains("bad")) {
                return Err(Status::invalid_argument("bad"));
            }
            Ok(Response::new(EventsReply { accepted: r.get_ref().events_json.len() as u32 }))
        }
        async fn result(&self, r: Request<ResultRequest>) -> Result<Response<Empty>, Status> {
            check(&r)?;
            Ok(Response::new(Empty {}))
        }
        async fn config(&self, r: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status> {
            check(&r)?;
            Ok(Response::new(ConfigReply { version: "v1".into(), config_json: r#"{"sca_interval_secs":600}"#.into() }))
        }
        async fn yara(&self, r: Request<YaraRequest>) -> Result<Response<YaraReply>, Status> {
            check(&r)?;
            Ok(Response::new(YaraReply { data: b"RULES".to_vec() }))
        }
        async fn upgrade(&self, r: Request<UpgradeChunkRequest>) -> Result<Response<ChunkStream>, Status> {
            check(&r)?;
            assert_eq!(r.get_ref().version, "9.9.9");
            assert_eq!(r.metadata().get("x-file-name").unwrap(), "provigil-agent.exe");
            let chunks = vec![Ok(Chunk { data: b"NEW ".to_vec() }), Ok(Chunk { data: b"AGENT".to_vec() })];
            Ok(Response::new(Box::pin(tonic::codegen::tokio_stream::iter(chunks))))
        }
    }

    async fn fake_manager() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = tonic::transport::server::TcpIncoming::from_listener(listener, true, None).unwrap();
        tokio::spawn(tonic::transport::Server::builder().add_service(AgentServiceServer::new(Fake)).serve_with_incoming(incoming));
        format!("grpc://{addr}")
    }

    fn creds() -> Creds {
        Creds { agent_id: "007".into(), key: "k7".into(), tenant_id: "acme".into(), tenant_key: Some("tk".into()) }
    }

    #[tokio::test]
    async fn grpc_link_against_a_manager() {
        let url = fake_manager().await;
        let enroll = GrpcLink::new(&url, Creds { tenant_key: Some("tk".into()), ..Creds::default() }, false, &[]).unwrap();
        let a = enroll.enroll(&json!({ "name": "pc", "hostname": "PC", "version": "1.0.0" })).await.unwrap();
        assert_eq!((a["agent_id"].as_str(), a["raw_key"].as_str(), a["tenant_id"].as_str()), (Some("007"), Some("k7"), Some("acme")));

        let link = GrpcLink::new(&url, creds(), false, &[]).unwrap();
        let cmds = link.keepalive(&json!({ "status": "active" })).await.unwrap();
        assert_eq!(cmds, [json!({ "command_id": "c-1", "type": "scan" })]);
        link.events(&[json!({ "event_type": "fim" })]).await.unwrap();
        assert!(matches!(link.events(&[json!("bad")]).await, Err(Fail::Status(400, _))));
        link.result(&json!({ "command_id": "c-1", "status": "done" })).await.unwrap();
        assert_eq!(link.config().await.unwrap(), json!({ "version": "v1", "config": { "sca_interval_secs": 600 } }));
        assert_eq!(link.yara().await.unwrap(), b"RULES");
        let mut d = link.download("/downloads/provigil-agent.exe", "9.9.9").await.unwrap();
        let mut got = Vec::new();
        while let Some(c) = d.chunk().await.unwrap() {
            got.extend(c);
        }
        assert_eq!(got, b"NEW AGENT");

        let wrong = GrpcLink::new(&url, Creds { key: "nope".into(), ..creds() }, false, &[]).unwrap();
        assert!(matches!(wrong.keepalive(&json!({})).await, Err(Fail::Status(401, _))));
        let down = GrpcLink::new("grpc://127.0.0.1:1", creds(), false, &[]).unwrap();
        assert!(matches!(down.yara().await, Err(Fail::Down(_))), "{:?}", down.yara().await);
    }

    #[tokio::test]
    async fn failover_from_an_unreachable_grpc_manager() {
        let url = fake_manager().await;
        let config = AgentConfig {
            manager_url: "grpc://127.0.0.1:1".into(),
            manager_urls: vec!["grpc://127.0.0.1:1".into(), url.clone()],
            tenant_key: "tk".into(),
            max_retries: 1,
            retry_interval_secs: 0,
            ..AgentConfig::default()
        };
        let ident = AgentIdentity { agent_id: "007".into(), agent_name: "pc".into(), tenant_id: "acme".into(), auth_token: "k7".into(), enrolled_at: Utc::now() };
        let buffer = Arc::new(EventBuffer::with_limits(100, &config.buffer, json!({})));
        let t = AgentTransport::new(&config, ident, buffer.clone(), Arc::new(EdrExecutor::new()));
        assert!(t.fetch_yara_rules().await.is_err());
        assert_eq!(t.manager(), url);
        assert_eq!(t.fetch_yara_rules().await.unwrap(), b"RULES");
        buffer.push(json!({ "event_type": "fim" }));
        assert_eq!(t.flush_events().await, Ok(1));
    }

    fn ident() -> AgentIdentity {
        AgentIdentity { agent_id: "007".into(), agent_name: "pc".into(), tenant_id: "acme".into(), auth_token: "k7".into(), enrolled_at: Utc::now() }
    }

    #[tokio::test]
    async fn enroll_again_after_three_refused_keepalives() {
        let url = fake_manager().await;
        let config = AgentConfig { manager_url: url.clone(), tenant_key: "tk".into(), ..AgentConfig::default() };
        let refused = AgentIdentity { auth_token: "removed".into(), ..ident() };
        let t = Arc::new(AgentTransport::new(&config, refused, Arc::new(EventBuffer::new(10)), Arc::new(EdrExecutor::new())));
        for _ in 0..2 {
            assert!(t.send_heartbeat().await.is_err());
        }
        assert!(!t.must_reenroll());
        assert!(t.send_heartbeat().await.is_err());
        assert!(t.must_reenroll(), "401 three times in a row");

        // network errors do not count, an accepted keepalive resets the count
        let down = AgentConfig { manager_url: "grpc://127.0.0.1:1".into(), max_retries: 100, ..config.clone() };
        let t = Arc::new(AgentTransport::new(&down, ident(), Arc::new(EventBuffer::new(10)), Arc::new(EdrExecutor::new())));
        for _ in 0..4 {
            assert!(t.send_heartbeat().await.is_err());
        }
        assert!(!t.must_reenroll());
        let t = Arc::new(AgentTransport::new(&config, ident(), Arc::new(EventBuffer::new(10)), Arc::new(EdrExecutor::new())));
        t.refused.store(2, Ordering::SeqCst);
        t.send_heartbeat().await.unwrap();
        assert_eq!(t.refused.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn undelivered_results_kept_and_sent_after_the_keepalive() {
        let down = AgentConfig { manager_url: "grpc://127.0.0.1:1".into(), max_retries: 100, ..AgentConfig::default() };
        let t = AgentTransport::new(&down, ident(), Arc::new(EventBuffer::new(10)), Arc::new(EdrExecutor::new()));
        t.results.lock().unwrap().extend((0..RESULTS).map(|i| json!({ "command_id": i })));
        t.send_result(&json!({ "command_id": "last" })).await;
        let q = t.results.lock().unwrap().clone();
        assert_eq!((q.len(), q[0]["command_id"].clone(), q[RESULTS - 1]["command_id"].clone()), (RESULTS, json!(1), json!("last")), "the oldest dropped");

        let config = AgentConfig { manager_url: fake_manager().await, tenant_key: "tk".into(), ..AgentConfig::default() };
        let t = Arc::new(AgentTransport::new(&config, ident(), Arc::new(EventBuffer::new(10)), Arc::new(EdrExecutor::new())));
        t.results.lock().unwrap().push_back(json!({ "command_id": "c-0" }));
        t.send_heartbeat().await.unwrap();
        for _ in 0..50 {
            if t.results.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(t.results.lock().unwrap().is_empty());
    }

    #[test]
    fn getconfig_answers_the_settings_without_keys() {
        let config = AgentConfig { manager_url: "http://127.0.0.1:9".into(), tenant_key: "the-tenant-key".into(), sca_interval_secs: 77, ..AgentConfig::default() };
        let identity = AgentIdentity { auth_token: "the-agent-key".into(), ..ident() };
        let t = AgentTransport::new(&config, identity, Arc::new(EventBuffer::new(10)), Arc::new(EdrExecutor::new()));
        let r = t.query(&json!({ "command_id": "q-1", "type": "getconfig" }));
        assert_eq!((r["command_id"].as_str(), r["status"].as_str(), r["config"]["sca_interval_secs"].as_u64()), (Some("q-1"), Some("done"), Some(77)));
        assert!(r["config"].get("tenant_key").is_none());
        let text = r.to_string();
        assert!(!text.contains("the-tenant-key") && !text.contains("the-agent-key"), "{text}");

        t.set_config(AgentConfig { sca_interval_secs: 88, ..config });
        let r = t.query(&json!({ "command_id": "q-2", "type": "getconfig" }));
        assert_eq!(r["config"]["sca_interval_secs"], 88, "the settings in force, after a group change");
    }

    #[tokio::test]
    async fn getstate_tells_versions_manager_buffer_scans_and_counts() {
        let config = AgentConfig { manager_url: fake_manager().await, tenant_key: "tk".into(), ..AgentConfig::default() };
        let buffer = Arc::new(EventBuffer::new(10));
        let t = Arc::new(AgentTransport::new(&config, ident(), buffer.clone(), Arc::new(EdrExecutor::new())));
        t.set_group_version(Some("v3".into()));
        crate::scan_done("fim");
        buffer.push(json!({ "event_type": "fim" }));
        assert_eq!(t.flush_events().await, Ok(1));
        buffer.push(json!({ "event_type": "fim" }));
        t.send_heartbeat().await.unwrap();
        let r = t.query(&json!({ "command_id": "q-1", "type": "getstate" }));
        let s = &r["state"];
        assert_eq!((r["command_id"].as_str(), s["version"].as_str(), s["group_config_version"].as_str()), (Some("q-1"), Some(env!("CARGO_PKG_VERSION")), Some("v3")));
        assert_eq!((s["manager"].as_str(), s["transport"].as_str()), (Some(config.manager_url.as_str()), Some("grpc")));
        assert_eq!(s["buffer"], json!({ "events": 1, "state": "normal" }));
        assert_eq!(s["events"], json!({ "sent": 1, "dropped": 0 }));
        assert!(s["last_keepalive"].is_string() && s["last_scans"]["fim"].is_string(), "{s}");
    }

    #[test]
    fn a_command_id_runs_once() {
        let t = AgentTransport::new(&AgentConfig::default(), ident(), Arc::new(EventBuffer::new(10)), Arc::new(EdrExecutor::new()));
        assert_eq!(t.first_run("c1"), Ok(()));
        assert_eq!(t.first_run("c1"), Err(None), "still running: nothing to send");
        t.ran_result("c1", &json!({ "command_id": "c1", "status": "done" }));
        assert_eq!(t.first_run("c1"), Err(Some(json!({ "command_id": "c1", "status": "done" }))), "its result again");
        assert_eq!(t.first_run(""), Ok(()));
        assert_eq!(t.first_run(""), Ok(()), "no id: always run");
        for n in 0..RAN {
            t.first_run(&n.to_string()).unwrap();
        }
        assert_eq!(t.first_run("c1"), Ok(()), "only the last 256");
    }

    #[test]
    fn batch_id_follows_the_events() {
        let a = [json!({ "seq": 1 }), json!({ "seq": 2 })].map(|e| e.to_string());
        assert_eq!(batch_id(&a), batch_id(a.clone()));
        assert_ne!(batch_id(&a), batch_id(&a[..1]));
        assert_eq!(batch_id(&a).len(), 36);
    }

    #[test]
    fn reset_connections_are_network_errors() {
        for code in [tonic::Code::Unavailable, tonic::Code::Unknown, tonic::Code::Cancelled] {
            assert!(matches!(grpc_fail(tonic::Status::new(code, "x")), Fail::Down(_)), "{code:?}");
        }
        assert!(matches!(grpc_fail(tonic::Status::internal("x")), Fail::Status(500, _)));
    }

    /// An HTTP manager that answers 413 to a batch of more than 2 events or with a `huge` one;
    /// the `n` of the events it took.
    fn small_batch_manager() -> (String, Arc<Mutex<Vec<u64>>>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let took = Arc::new(Mutex::new(Vec::new()));
        let seen = took.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut len = 0;
                let mut line = String::new();
                while r.read_line(&mut line).unwrap() > 2 {
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    line.clear();
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let events = serde_json::from_slice::<Value>(&body).unwrap()["events"].as_array().cloned().unwrap();
                let status = if events.len() > 2 || events.iter().any(|e| e["event_type"] == "huge") {
                    "413 Payload Too Large"
                } else {
                    seen.lock().unwrap().extend(events.iter().filter_map(|e| e["n"].as_u64()));
                    "200 OK"
                };
                let _ = write!(&s, "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        });
        (format!("http://{addr}"), took)
    }

    #[tokio::test]
    async fn too_large_batches_split_and_too_large_event_dropped() {
        let (url, took) = small_batch_manager();
        let config = AgentConfig { manager_url: url, buffer: crate::config::BufferConfig { disabled: true, ..Default::default() }, ..AgentConfig::default() };
        let buffer = Arc::new(EventBuffer::with_limits(100, &config.buffer, json!({})));
        for n in 0..3 {
            buffer.push(json!({ "event_type": "x", "n": n }));
        }
        buffer.push(json!({ "event_type": "huge" }));
        for n in 3..6 {
            buffer.push(json!({ "event_type": "x", "n": n }));
        }
        let t = AgentTransport::new(&config, ident(), buffer.clone(), Arc::new(EdrExecutor::new()));
        for _ in 0..20 {
            if buffer.is_empty() {
                break;
            }
            let _ = t.flush_events().await;
        }
        assert!(buffer.is_empty());
        assert_eq!(*took.lock().unwrap(), [0, 1, 2, 3, 4, 5], "every small event sent once, in order; the huge one dropped");
        assert_eq!(t.batch.load(Ordering::SeqCst), 4, "the batch size grows again after successes");
    }

    #[test]
    fn private_ca_trusted() {
        const PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUET8+4hYxrZBkxLN1hdzfMmSiQh8wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQUHJvVmlnaWwgVGVzdCBDQTAeFw0yNjExMDQxNTM2MThaFw0z
NjExMDExNTM2MThaMBsxGTAXBgNVBAMMEFByb1ZpZ2lsIFRlc3QgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ7rD+TO/3Htf11U7E38FoFlKBDhbyEhev//Ah2
CD0CtyUuMo1qQUJOjiE9AoTnOhbPFTu9W+X6MOhw2B6js9c3o1MwUTAdBgNVHQ4E
FgQUZGmUUPbEseKVOGh6huzhdYIcNgIwHwYDVR0jBBgwFoAUZGmUUPbEseKVOGh6
huzhdYIcNgIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAw8X1A
zm4a2VfLegY7AxvFqw5rB4eCZf/3IFlIoeY00gIgIj0nQ1pVITfp/S/Fo/54kbJ9
yAqXiUhE4Ry8EpBlrME=
-----END CERTIFICATE-----
";
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ca.pem");
        std::fs::write(&p, PEM).unwrap();
        let ca = ca_certs(Some(&p));
        assert_eq!(ca.len(), 1);
        assert!(reqwest::Certificate::from_der(&ca[0]).is_ok());
        let mut roots = rustls::RootCertStore::empty();
        assert_eq!(roots.add_parsable_certificates(ca.iter().cloned()), (1, 0), "a root rustls takes");
        std::fs::write(&p, "not a certificate").unwrap();
        assert!(ca_certs(Some(&p)).is_empty());
        assert!(ca_certs(Some(&dir.path().join("missing.pem"))).is_empty());
        assert!(ca_certs(None).is_empty());
    }
}
