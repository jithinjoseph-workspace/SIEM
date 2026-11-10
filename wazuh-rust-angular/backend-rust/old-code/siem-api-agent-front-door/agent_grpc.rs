//! The agent API over gRPC (`provigil.agent.v1.AgentService`, crate provigil-proto): each call
//! runs the same function as its HTTPS route, with the same checks. Listens on
//! `SIEM_GRPC_PORT` (8089).
//!
//! Agent traffic is TLS, here and on the HTTPS listener (`SIEM_TLS_PORT`, 8443, the API's router):
//! an install-wide CA in `data/tls/` issues the certificate at each start, and agents trust that
//! CA (`ca_pem` of `/api/server-info`). `SIEM_GRPC_TLS_CERT` / `SIEM_GRPC_TLS_KEY` replace the
//! certificate on the gRPC port.

// tonic::Status is the service's error type
#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use provigil_proto::*;
use serde_json::{json, Value};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use crate::AppState;

const MAX_MESSAGE: usize = 16 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;
const AGENT_EXE: &str = "provigil-agent.exe";
const CA_CN: &str = "ProVigil Agent CA";

fn port() -> u16 {
    std::env::var("SIEM_GRPC_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8089)
}

fn tls_port() -> u16 {
    std::env::var("SIEM_TLS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8443)
}

fn tls_files() -> Option<(String, String)> {
    let var = |k| std::env::var(k).ok().filter(|v: &String| !v.trim().is_empty());
    Some((var("SIEM_GRPC_TLS_CERT")?, var("SIEM_GRPC_TLS_KEY")?))
}

/// The gRPC address agents use (`/api/server-info`).
pub fn url(host: &str) -> String {
    format!("grpcs://{host}:{}", port())
}

/// The HTTPS address agents use (`/api/server-info`).
pub fn https_url(host: &str) -> String {
    format!("https://{host}:{}", tls_port())
}

/// An agent port's listener, with a long accept queue: agents reconnecting at once (a manager
/// restart) are refused by the OS when it is full. tokio's `bind` asks for 1,024, which desktop
/// Windows cuts to 200; there a negative backlog is `SOMAXCONN_HINT`, taken as asked.
fn agent_listener(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let s = tokio::net::TcpSocket::new_v4()?;
    #[cfg(unix)]
    s.set_reuseaddr(true)?;
    s.bind(addr)?;
    s.listen(if cfg!(windows) { -65535i32 as u32 } else { 65535 })
}

/// The certificates of the agent listeners. The key stays in memory: a new one at each start.
struct AgentTls {
    ca_pem: String,
    chain_pem: String,
    key_pem: String,
}

static TLS: OnceLock<AgentTls> = OnceLock::new();

/// The CA certificate agents trust (public), once TLS is up.
pub fn ca_pem() -> Option<&'static str> {
    TLS.get().map(|t| t.ca_pem.as_str())
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

/// The install-wide CA in `dir`, made at the first start: certificate, key, certificate PEM.
/// Not the syslog CA: that one needs ClickHouse up and `AGENT_KEYS_SECRET` at start, and
/// agents must be able to connect without them.
fn load_ca(dir: &Path) -> Result<(rcgen::Certificate, rcgen::KeyPair, String), String> {
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
    // same name and key: what it issues chains to the saved certificate
    let ca = crate::syslog_tenancy::named_ca_params(CA_CN).self_signed(&key).map_err(|e| e.to_string())?;
    let pem = match std::fs::read_to_string(&cert_file) {
        Ok(pem) => pem,
        Err(_) => {
            std::fs::write(&cert_file, ca.pem()).map_err(|e| format!("{}: {e}", cert_file.display()))?;
            ca.pem()
        }
    };
    Ok((ca, key, pem))
}

/// The names agents reach this host by. `SIEM_LAN_IP` is often unset (start-all.bat finds it
/// after siem-api starts), so the host's own IPv4 addresses are in too.
fn tls_hosts() -> Vec<String> {
    let mut hosts: Vec<String> = ["SIEM_LAN_IP", "MANAGER_IP", "SITE_DOMAIN"].iter().filter_map(|k| std::env::var(k).ok()).flat_map(|v| v.split(',').map(|h| h.trim().to_string()).collect::<Vec<_>>()).collect();
    hosts.extend(sysinfo::System::host_name());
    hosts.extend(local_ip_address::list_afinet_netifas().into_iter().flatten().map(|(_, ip)| ip).filter(|ip| ip.is_ipv4()).map(|ip| ip.to_string()));
    hosts.extend(["localhost".to_string(), "127.0.0.1".to_string()]);
    hosts.retain(|h| !h.is_empty() && h.is_ascii());
    hosts.sort();
    hosts.dedup();
    hosts
}

// shortcut: renewed at each start only (host list and expiry with it); a process up for over 2
// years serves an expired certificate. Add a timer and a reload of both listeners if that happens.
fn issue(ca: &rcgen::Certificate, ca_key: &rcgen::KeyPair, ca_pem: &str, hosts: Vec<String>) -> Result<AgentTls, String> {
    let (cert, key) = crate::syslog_tenancy::server_cert(ca, ca_key, "ProVigil Manager", hosts)?;
    Ok(AgentTls { ca_pem: ca_pem.to_string(), chain_pem: format!("{}{ca_pem}", cert.pem()), key_pem: key.serialize_pem() })
}

/// The agent listeners' certificate, at start. Without it they stay down (never plain).
pub fn init_tls() {
    let hosts = tls_hosts();
    let listed = hosts.join(", ");
    match load_ca(&crate::data_file_path("tls")).and_then(|(ca, key, pem)| issue(&ca, &key, &pem, hosts)) {
        Ok(t) => {
            info!("Agent TLS certificate issued for {listed}");
            let _ = TLS.set(t);
        }
        Err(e) => error!("Agent TLS not available, agents cannot connect: {e}"),
    }
}

fn https_config(t: &AgentTls) -> Result<rustls::ServerConfig, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_slice_iter(t.chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    let key = PrivateKeyDer::from_pem_slice(t.key_pem.as_bytes()).map_err(|e| e.to_string())?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Serves the router over TLS, until the process ends.
async fn serve_tls(listener: tokio::net::TcpListener, app: axum::Router, cfg: rustls::ServerConfig) {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use hyper_util::service::TowerToHyperService;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Agent HTTPS accept error: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (acceptor, app) = (acceptor.clone(), app.clone());
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(sock)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => return warn!("Agent HTTPS handshake from {peer} failed: {e}"),
                Err(_) => return warn!("Agent HTTPS handshake from {peer} timed out"),
            };
            // connection errors are the peer going away
            let _ = auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(TokioIo::new(tls), TowerToHyperService::new(app)).await;
        });
    }
}

/// The API's router over TLS for agents (the plain port refuses them).
pub async fn serve_https(app: axum::Router) {
    let Some(t) = TLS.get() else { return };
    let cfg = match https_config(t) {
        Ok(c) => c,
        Err(e) => return error!("Agent HTTPS not started: {e}"),
    };
    let addr = SocketAddr::from(([0, 0, 0, 0], tls_port()));
    match agent_listener(addr) {
        Ok(l) => {
            info!("Agent HTTPS listening on https://{addr}");
            serve_tls(l, app, cfg).await;
        }
        Err(e) => error!("Agent HTTPS not started on {addr}: {e}"),
    }
}

pub struct AgentGrpc {
    state: AppState,
    /// The published agent program.
    agent_exe: fn() -> Option<PathBuf>,
}

fn server(state: AppState, agent_exe: fn() -> Option<PathBuf>) -> AgentServiceServer<AgentGrpc> {
    AgentServiceServer::new(AgentGrpc { state, agent_exe })
        .max_decoding_message_size(MAX_MESSAGE)
        .max_encoding_message_size(MAX_MESSAGE)
}

/// Runs the gRPC server on the HTTP API's addresses until it fails.
pub async fn serve(state: AppState) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port()));
    // pings find dead connections; a limit per connection and per call (under the agent's 15 s)
    let identity = match (tls_files(), TLS.get()) {
        (Some((cert, key)), _) => {
            let (Ok(cert), Ok(key)) = (std::fs::read(&cert), std::fs::read(&key)) else {
                error!("Agent gRPC not started: SIEM_GRPC_TLS_CERT / SIEM_GRPC_TLS_KEY not readable");
                return;
            };
            Identity::from_pem(cert, key)
        }
        (None, Some(t)) => Identity::from_pem(&t.chain_pem, &t.key_pem),
        (None, None) => return error!("Agent gRPC not started: no certificate"),
    };
    let builder = Server::builder()
        .http2_keepalive_interval(Some(Duration::from_secs(60)))
        .concurrency_limit_per_connection(8)
        .timeout(Duration::from_secs(14));
    let mut builder = match builder.tls_config(ServerTlsConfig::new().identity(identity)) {
        Ok(b) => b,
        Err(e) => {
            error!("Agent gRPC not started: TLS: {e}");
            return;
        }
    };
    let incoming = match agent_listener(addr).and_then(|l| tonic::transport::server::TcpIncoming::from_listener(l, true, Some(Duration::from_secs(60))).map_err(std::io::Error::other)) {
        Ok(i) => i,
        Err(e) => return error!("Agent gRPC not started on {addr}: {e}"),
    };
    info!("Agent gRPC listening on {}", url(&addr.ip().to_string()));
    let svc = server(state, || crate::provigil_manager::windows_agent_file("provigil-agent.exe"));
    if let Err(e) = builder.add_service(svc).serve_with_incoming(incoming).await {
        error!("Agent gRPC stopped: {e}");
    }
}

/// An HTTPS route's refusal as a gRPC status.
fn status(code: StatusCode) -> Status {
    let msg = code.to_string();
    match code {
        StatusCode::BAD_REQUEST => Status::invalid_argument(msg),
        StatusCode::UNAUTHORIZED => Status::unauthenticated(msg),
        StatusCode::FORBIDDEN | StatusCode::GONE => Status::permission_denied(msg),
        StatusCode::NOT_FOUND => Status::not_found(msg),
        StatusCode::CONFLICT => Status::already_exists(msg),
        StatusCode::TOO_MANY_REQUESTS => Status::resource_exhausted(msg),
        _ => Status::internal(msg),
    }
}

fn json_arg(s: &str) -> Result<Value, Status> {
    serde_json::from_str(s).map_err(|e| Status::invalid_argument(e.to_string()))
}

impl AgentGrpc {
    /// The metadata as the HTTPS headers (`authorization`, `x-tenant-key`), and the agent id
    /// (`x-agent-id`) once its key is checked.
    fn agent<T>(&self, r: &Request<T>) -> Result<(String, HeaderMap), Status> {
        let headers = r.metadata().clone().into_headers();
        let id = headers.get("x-agent-id").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        if !crate::agent_bearer_ok(&self.state, &id, &headers) {
            return Err(Status::unauthenticated("invalid agent key"));
        }
        Ok((id, headers))
    }
}

#[tonic::async_trait]
impl AgentService for AgentGrpc {
    async fn enroll(&self, r: Request<EnrollRequest>) -> Result<Response<EnrollReply>, Status> {
        let headers = r.metadata().clone().into_headers();
        let q = r.into_inner();
        let payload = crate::EnrollAgentPayload {
            name: q.name,
            ip: None,
            groups: Some(q.groups),
            os_type: Some(q.os_type).filter(|s| !s.is_empty()),
            force: Some(q.force),
        };
        let v = crate::enroll_agent(&self.state, &headers, None, payload)
            .await
            .map_err(|(code, msg)| Status::new(status(code).code(), msg))?;
        let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
        Ok(Response::new(EnrollReply {
            agent_id: s("agent_id"),
            agent_name: s("agent_name"),
            agent_ip: s("agent_ip"),
            raw_key: s("raw_key"),
            tenant_id: s("tenant_id"),
            groups: s("groups"),
        }))
    }

    async fn keepalive(&self, r: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status> {
        let (id, headers) = self.agent(&r)?;
        let commands = crate::agent_keepalive(&self.state, &id, &headers, r.get_ref().body_json.as_bytes())
            .await
            .map_err(status)?;
        Ok(Response::new(KeepaliveReply { commands_json: commands.iter().map(Value::to_string).collect() }))
    }

    async fn events(&self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status> {
        let (id, headers) = self.agent(&r)?;
        let events = r.get_ref().events_json.iter().map(|e| json_arg(e)).collect::<Result<Vec<_>, _>>()?;
        let accepted = events.len() as u32;
        crate::ingest(&self.state, &headers, json!({ "agent_id": id, "events": events, "batch_id": r.get_ref().batch_id }))
            .await
            .map_err(status)?;
        Ok(Response::new(EventsReply { accepted }))
    }

    async fn result(&self, r: Request<ResultRequest>) -> Result<Response<Empty>, Status> {
        let (id, headers) = self.agent(&r)?;
        let result = json_arg(&r.get_ref().result_json)?;
        crate::agent_response_result(&self.state, &id, &headers, &result).map_err(status)?;
        Ok(Response::new(Empty {}))
    }

    async fn config(&self, r: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status> {
        let (id, headers) = self.agent(&r)?;
        let v = crate::agent_config::for_agent(&self.state, &id, &headers).map_err(status)?;
        Ok(Response::new(ConfigReply {
            version: v["version"].as_str().unwrap_or_default().to_string(),
            config_json: v["config"].to_string(),
        }))
    }

    async fn yara(&self, r: Request<YaraRequest>) -> Result<Response<YaraReply>, Status> {
        let (id, headers) = self.agent(&r)?;
        let data = crate::agent_yara_rules(&self.state, &id, &headers).map_err(status)?;
        Ok(Response::new(YaraReply { data }))
    }

    async fn upgrade(&self, r: Request<UpgradeChunkRequest>) -> Result<Response<ChunkStream>, Status> {
        self.agent(&r)?;
        // the file's name comes in `x-file-name`: the agent program, or a response program
        let name = r.metadata().get("x-file-name").and_then(|v| v.to_str().ok()).unwrap_or(AGENT_EXE);
        let not_published = || Status::not_found(format!("{name} is not published"));
        let path = if name == AGENT_EXE { (self.agent_exe)() } else { crate::provigil_manager::windows_agent_file(name) }.ok_or_else(not_published)?;
        if name == AGENT_EXE {
            let bytes = tokio::fs::read(&path).await.map_err(|_| not_published())?;
            let published = crate::provigil_manager::exe_version(&bytes).unwrap_or_default();
            drop(bytes);
            let asked = &r.get_ref().version;
            if !asked.is_empty() && *asked != published {
                return Err(Status::failed_precondition(format!("the published agent is version '{published}', not '{asked}'")));
            }
        }
        // read as the agent takes it: a stalled download holds one chunk, not the package
        let file = tokio::fs::File::open(&path).await.map_err(|_| not_published())?;
        let chunks = futures_util::stream::unfold(Some(file), |file| async move {
            use tokio::io::AsyncReadExt;
            let mut f = file?;
            let mut data = Vec::with_capacity(CHUNK);
            match (&mut f).take(CHUNK as u64).read_to_end(&mut data).await {
                Ok(0) => None,
                Ok(_) => Some((Ok(Chunk { data }), Some(f))),
                Err(e) => Some((Err(Status::internal(e.to_string())), None)),
            }
        });
        Ok(Response::new(Box::pin(chunks)))
    }
}

#[cfg(test)]
#[path = "agent_grpc_bench.rs"]
pub(crate) mod bench;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, RwLock};
    use tonic::codegen::tokio_stream::StreamExt;
    use tonic::transport::{server::TcpIncoming, Endpoint};

    fn authed<M>(id: &str, key: &str, m: M) -> Request<M> {
        let mut r = Request::new(m);
        r.metadata_mut().insert("authorization", format!("Bearer {key}").parse().unwrap());
        r.metadata_mut().insert("x-agent-id", id.parse().unwrap());
        r
    }

    fn agent_exe() -> Option<PathBuf> {
        Some(std::env::temp_dir().join(format!("pv-grpc-test-agent-{}.exe", std::process::id())))
    }

    /// A state that writes nowhere: ClickHouse unreachable, the manager off, its home a temp folder.
    async fn state(home: &std::path::Path) -> AppState {
        std::env::set_var("CLICKHOUSE_URL", "http://127.0.0.1:1");
        std::env::set_var("PROVIGIL_MANAGER", "0");
        std::env::set_var("PROVIGIL_MANAGER_HOME", home);
        let (broadcast_tx, _) = tokio::sync::broadcast::channel(16);
        let tmp = |n: &str| std::env::temp_dir().join(format!("siem-grpc-test-{n}-{}.json", std::process::id()));
        AppState {
            engine: siem_engine::AnalysisEngine::new(),
            events: Arc::new(RwLock::new(Vec::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
            agents: Arc::new(RwLock::new(HashMap::new())),
            broadcast_tx,
            pending_commands: Arc::new(RwLock::new(HashMap::new())),
            db: crate::db::ClickHouseDb::init().await,
            wdb: Arc::new(siem_wdb::ProVigilDbManager::new()),
            threat_intel: Arc::new(siem_cdb::ThreatIntelManager::new()),
            active_responses: Arc::new(RwLock::new(Vec::new())),
            parser_registry: Arc::new(siem_parser_gen::DynamicParserRegistry::new("")),
            parser_tenants: Arc::new(RwLock::new(HashMap::new())),
            auth_keystore: Arc::new(RwLock::new(siem_crypto::keys::KeyStore::new())),
            tenants: Arc::new(RwLock::new(Vec::new())),
            agent_keys: Arc::new(crate::tenancy::AgentKeys::new()),
            agent_tenants: Arc::new(RwLock::new(HashMap::new())),
            enrolled: Arc::new(RwLock::new(HashMap::new())),
            max_agent_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            deleted_agents: Arc::new(RwLock::new(HashSet::new())),
            deleted_agent_names: Arc::new(RwLock::new(HashSet::new())),
            risk_fabric: Arc::new(siem_risk_fabric::RiskFabricEngine::new("")),
            redswarm: Arc::new(siem_redswarm::RedSwarmService::new()),
            intent_engine: Arc::new(siem_intent_engine::IntentEngine::new(tmp("intent"))),
            deception_engine: Arc::new(siem_deception::DeceptionEngine::new(tmp("deception"))),
        }
    }

    /// A burst well past tokio's default queue, with nothing accepting yet: nobody is refused.
    #[tokio::test]
    async fn a_burst_of_connections_waits_in_the_accept_queue() {
        let l = agent_listener(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = l.local_addr().unwrap();
        let burst: Vec<_> = (0..3000).map(|_| tokio::spawn(tokio::net::TcpStream::connect(addr))).collect();
        let mut held = Vec::new();
        for c in burst {
            held.push(c.await.unwrap().expect("connected"));
        }
        assert!(l.accept().await.is_ok());
    }

    /// Both TLS listeners with this certificate, on random ports: gRPC, HTTPS.
    async fn tls_listeners(state: &AppState, t: &AgentTls) -> (u16, u16) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let grpc = l.local_addr().unwrap().port();
        let tls = ServerTlsConfig::new().identity(Identity::from_pem(&t.chain_pem, &t.key_pem));
        let incoming = TcpIncoming::from_listener(l, true, None).unwrap();
        tokio::spawn(Server::builder().tls_config(tls).unwrap().add_service(server(state.clone(), agent_exe)).serve_with_incoming(incoming));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https = l.local_addr().unwrap().port();
        let app = axum::Router::new().route("/api/v1/agents/enroll", axum::routing::post(crate::post_agent_enroll_handler)).with_state(state.clone());
        tokio::spawn(serve_tls(l, app, https_config(t).unwrap()));
        (grpc, https)
    }

    /// The real agent links against real listeners, with generated certificates.
    #[tokio::test]
    async fn agent_tls_end_to_end() {
        use provigil_agent::transport::{ca_certs, http_client, Cert, Creds, Fail, GrpcLink, HttpsLink, Link};
        let (home, dir, other) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let state = state(home.path()).await;
        let (ca, key, pem) = load_ca(dir.path()).unwrap();
        let (grpc, https) = tls_listeners(&state, &issue(&ca, &key, &pem, vec!["localhost".into()]).unwrap()).await;

        let links = |host: &str, roots: &[Cert]| -> [Box<dyn Link>; 2] {
            [
                Box::new(GrpcLink::new(&format!("grpcs://{host}:{grpc}"), Creds::default(), false, roots).unwrap()),
                Box::new(HttpsLink::new(&format!("https://{host}:{https}"), Creds::default(), http_client(false, roots))),
            ]
        };
        let body = |name: &str, force: bool| json!({ "name": name, "os_type": "windows", "groups": "", "force": force });
        let trusted = ca_certs(Some(&dir.path().join("ca.crt.pem")));
        assert_eq!(trusted.len(), 1);

        for (i, link) in links("localhost", &trusted).iter().enumerate() {
            let a = link.enroll(&body(&format!("tls-pc-{i}"), false)).await.unwrap_or_else(|e| panic!("{}: {e}", link.url()));
            assert!(!a["raw_key"].as_str().unwrap().is_empty());
        }

        // force_enroll: a removed name comes back only when asked
        let removed = (crate::tenancy::DEFAULT_TENANT.to_string(), "tls-removed".to_string());
        for link in links("localhost", &trusted) {
            state.deleted_agent_names.write().unwrap().insert(removed.clone());
            let no = link.enroll(&body("tls-removed", false)).await;
            assert!(matches!(no, Err(Fail::Status(403, _))), "{}", link.url());
            link.enroll(&body("tls-removed", true)).await.unwrap();
        }

        // another CA, and no CA at all
        load_ca(other.path()).unwrap();
        let foreign = ca_certs(Some(&other.path().join("ca.crt.pem")));
        for roots in [&foreign[..], &[]] {
            for link in links("localhost", roots) {
                let e = link.enroll(&body("tls-untrusted", false)).await;
                assert!(matches!(&e, Err(Fail::Down(m)) if !m.contains("timed out")), "{}: {:?}", link.url(), e.err());
            }
        }

        // the certificate names localhost, not 127.0.0.1
        for link in links("127.0.0.1", &trusted) {
            let e = link.enroll(&body("tls-wrong-host", false)).await;
            assert!(matches!(&e, Err(Fail::Down(m)) if !m.contains("timed out")), "{}: {:?}", link.url(), e.err());
        }
    }

    /// A new host list: a new certificate from the same CA, which agents already trust.
    #[test]
    fn certificate_reissued_from_the_same_ca() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        let dir = tempfile::tempdir().unwrap();
        let (ca, key, first_pem) = load_ca(dir.path()).unwrap();
        let before = issue(&ca, &key, &first_pem, vec!["localhost".into()]).unwrap();

        // the next start
        let (ca, key, pem) = load_ca(dir.path()).unwrap();
        assert_eq!(pem, first_pem, "agents keep their CA");
        let after = issue(&ca, &key, &pem, vec!["localhost".into(), "10.1.2.3".into(), "manager.corp".into()]).unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(first_pem.as_bytes()).unwrap()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        let ok = |t: &AgentTls, host: &'static str| {
            let leaf = CertificateDer::from_pem_slice(t.chain_pem.as_bytes()).unwrap();
            verifier.verify_server_cert(&leaf, &[], &ServerName::try_from(host).unwrap(), &[], UnixTime::now()).is_ok()
        };
        assert!(ok(&before, "localhost"));
        assert!(!ok(&before, "manager.corp"));
        for host in ["localhost", "manager.corp", "10.1.2.3"] {
            assert!(ok(&after, host), "{host}");
        }
    }

    #[test]
    fn ca_key_is_private_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (_, key, _) = load_ca(dir.path()).unwrap();
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
        let (_, again, _) = load_ca(dir.path()).unwrap();
        assert_eq!(again.serialize_pem(), key.serialize_pem(), "the same key at the next start");
        // a damaged key is an error, never a new CA
        std::fs::write(&file, "damaged").unwrap();
        assert!(load_ca(dir.path()).is_err());
    }

    #[test]
    fn hosts_for_the_certificate() {
        let hosts = tls_hosts();
        for h in ["localhost", "127.0.0.1"] {
            assert!(hosts.iter().any(|x| x == h), "{hosts:?}");
        }
        assert!(hosts.windows(2).all(|w| w[0] < w[1]), "sorted, no repeats: {hosts:?}");
    }

    #[tokio::test]
    async fn server_info_fields() {
        use axum::response::IntoResponse;
        let dir = tempfile::tempdir().unwrap();
        let (ca, key, pem) = load_ca(dir.path()).unwrap();
        let _ = TLS.set(issue(&ca, &key, &pem, vec!["localhost".into()]).unwrap());
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

    /// `agent_keepalive` and `ingest` against a stand-in for ClickHouse: the rows it receives.
    #[tokio::test]
    async fn agent_row_reaches_clickhouse_throttled() {
        let home = tempfile::tempdir().unwrap();
        let mut state = state(home.path()).await;
        let sql: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let got = sql.clone();
        let app = axum::Router::new().fallback(move |body: String| {
            let got = got.clone();
            async move {
                got.lock().unwrap().push(body);
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        state.db = crate::db::ClickHouseDb::for_test(&format!("http://{addr}"));

        let h = HeaderMap::new();
        let writes = || async {
            state.db.flush_agent_rows().await;
            sql.lock().unwrap().iter().filter(|q| q.starts_with("INSERT INTO siem_agents")).count()
        };
        crate::agent_keepalive(&state, "7701", &h, b"{}").await.unwrap();
        assert_eq!(writes().await, 1, "the first keepalive");
        crate::agent_keepalive(&state, "7701", &h, b"{}").await.unwrap();
        assert_eq!(writes().await, 1, "a second keepalive within 60 s writes nothing");

        let mut gone = state.agents.read().unwrap()["7701"].clone();
        gone.status = siem_core::AgentStatus::Disconnected;
        state.db.save_agent_row("default", &gone);
        assert_eq!(writes().await, 2, "a status change writes");
        assert!(sql.lock().unwrap()[1].contains("'Disconnected'"));
        crate::agent_keepalive(&state, "7701", &h, b"{}").await.unwrap();
        assert_eq!(writes().await, 3, "and so does coming back");

        let ev = json!({ "event_type": "grpc_test", "agent": { "id": "7702", "name": "pc" }, "message": "hello" });
        let batch = json!({ "agent_id": "7702", "events": [ev, ev] });
        crate::ingest(&state, &h, batch.clone()).await.unwrap();
        assert_eq!(writes().await, 4, "a batch: its agent's row once");
        crate::ingest(&state, &h, batch).await.unwrap();
        assert_eq!(writes().await, 4, "the next batch within 60 s writes nothing");
    }

    #[tokio::test]
    async fn agent_service_end_to_end() {
        let home = tempfile::tempdir().unwrap();
        let shared = home.path().join("etc").join("shared").join("default");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(shared.join("siem-yara.rules"), b"YARA RULES").unwrap();
        let mut exe = b"MZ provigil-agent-version:9.9.9 ".to_vec();
        exe.extend((0..3 * CHUNK + 5).map(|i| i as u8));
        std::fs::write(agent_exe().unwrap(), &exe).unwrap();
        let state = state(home.path()).await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = TcpIncoming::from_listener(listener, true, None).unwrap();
        tokio::spawn(Server::builder().add_service(server(state.clone(), agent_exe)).serve_with_incoming(incoming));
        let channel = Endpoint::from_shared(format!("http://{addr}")).unwrap().connect().await.unwrap();
        let mut c = AgentServiceClient::new(channel).max_decoding_message_size(MAX_MESSAGE);

        let e = c.enroll(Request::new(EnrollRequest { name: "grpc-test-pc".into(), ..Default::default() })).await.unwrap().into_inner();
        assert!(!e.agent_id.is_empty() && !e.raw_key.is_empty());
        assert_eq!((e.agent_name.as_str(), e.tenant_id.as_str()), ("grpc-test-pc", "default"));
        let (id, key) = (e.agent_id.as_str(), e.raw_key.as_str());

        state.pending_commands.write().unwrap().insert(e.agent_id.clone(), vec![json!({ "command_id": "c-1", "type": "scan" })]);
        // provigil-db is not running here: its writes do not hold up the answer
        let t = std::time::Instant::now();
        let k = c.keepalive(authed(id, key, KeepaliveRequest { body_json: "{}".into() })).await.unwrap().into_inner();
        assert!(t.elapsed() < Duration::from_secs(3), "keepalive took {:?}", t.elapsed());
        assert_eq!(k.commands_json.len(), 1);
        assert_eq!(serde_json::from_str::<Value>(&k.commands_json[0]).unwrap()["command_id"], "c-1");

        let ev = json!({ "event_type": "grpc_test", "agent": { "id": e.agent_id, "name": "grpc-test-pc" }, "message": "hello" });
        let kept = || state.events.read().unwrap().len();
        let before = kept();
        let batch = || EventsRequest { events_json: vec![ev.to_string()], batch_id: "b-1".into() };
        let r = c.events(authed(id, key, batch())).await.unwrap().into_inner();
        assert_eq!((r.accepted, kept()), (1, before + 1));
        // the same batch again: answered, not taken twice
        assert_eq!(c.events(authed(id, key, batch())).await.unwrap().into_inner().accepted, 1);
        assert_eq!(kept(), before + 1);
        let bad = c.events(authed(id, key, EventsRequest { events_json: vec!["{not json".into()], ..Default::default() })).await.unwrap_err();
        assert_eq!(bad.code(), tonic::Code::InvalidArgument);

        c.result(authed(id, key, ResultRequest { result_json: r#"{"command_id":"c-1","status":"done"}"#.into() })).await.unwrap();

        // a console query reaches this agent with its keepalive; its answer comes back by command id
        let user = |tenant: &str| crate::tenancy::AuthCtx { username: "u".into(), role: "analyst".into(), tenant_id: tenant.into(), permissions: vec![], features: vec![], requested_tenant: None };
        let live = |ctx, agent: &str, what: &str| crate::get_agent_live_handler(axum::extract::State(state.clone()), axum::Extension(ctx), axum::extract::Path((agent.to_string(), what.to_string())));
        assert_eq!(live(user("other"), id, "config").await.status(), StatusCode::NOT_FOUND, "another tenant's agent");
        assert_eq!(live(user("default"), id, "nothing").await.status(), StatusCode::NOT_FOUND);
        assert_eq!(live(user("default"), "99999", "state").await.status(), StatusCode::CONFLICT, "never seen by this manager");
        let query = tokio::spawn(live(user("default"), id, "config"));
        let cmd = loop {
            let k = c.keepalive(authed(id, key, KeepaliveRequest { body_json: "{}".into() })).await.unwrap().into_inner();
            if let Some(c) = k.commands_json.first() {
                break serde_json::from_str::<Value>(c).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(cmd["type"], "getconfig");
        let answer = json!({ "command_id": cmd["command_id"], "status": "done", "config": { "sca_interval_secs": 77 } });
        c.result(authed(id, key, ResultRequest { result_json: answer.to_string() })).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), query).await.expect("within the wait").unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        let body = axum::body::to_bytes(reply.into_body(), usize::MAX).await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), answer);

        let cfg = c.config(authed(id, key, ConfigRequest {})).await.unwrap().into_inner();
        assert_eq!(cfg.version.len(), 16);
        assert!(serde_json::from_str::<Value>(&cfg.config_json).unwrap().is_object());

        assert_eq!(c.yara(authed(id, key, YaraRequest {})).await.unwrap().into_inner().data, b"YARA RULES");

        let mut s = c.upgrade(authed(id, key, UpgradeChunkRequest { version: "9.9.9".into() })).await.unwrap().into_inner();
        let (mut got, mut chunks) = (Vec::new(), 0);
        while let Some(ch) = s.next().await {
            got.extend(ch.unwrap().data);
            chunks += 1;
        }
        assert_eq!((got == exe, chunks), (true, 4));
        let wrong = c.upgrade(authed(id, key, UpgradeChunkRequest { version: "1.0.0".into() })).await.unwrap_err();
        assert_eq!(wrong.code(), tonic::Code::FailedPrecondition);
        // only the package's files: the name cannot reach anything else
        for bad in ["..\\secret.txt", "evil.exe"] {
            let mut q = authed(id, key, UpgradeChunkRequest { version: "9.9.9".into() });
            q.metadata_mut().insert("x-file-name", bad.parse().unwrap());
            assert_eq!(c.upgrade(q).await.unwrap_err().code(), tonic::Code::NotFound);
        }

        // a wrong key, or none, is refused on every call but enroll
        let no = c.keepalive(authed(id, "not-the-key", KeepaliveRequest::default())).await.unwrap_err();
        assert_eq!(no.code(), tonic::Code::Unauthenticated);
        assert!(state.pending_commands.read().unwrap().get(&e.agent_id).is_none());
        assert_eq!(c.config(Request::new(ConfigRequest {})).await.unwrap_err().code(), tonic::Code::Unauthenticated);
        assert_eq!(c.events(authed(id, "x", EventsRequest::default())).await.unwrap_err().code(), tonic::Code::Unauthenticated);

        // a deleted agent: refused like on HTTPS
        state.deleted_agents.write().unwrap().insert(e.agent_id.clone());
        let gone = c.keepalive(authed(id, key, KeepaliveRequest { body_json: "{}".into() })).await.unwrap_err();
        assert_eq!(gone.code(), tonic::Code::NotFound);
        let _ = std::fs::remove_file(agent_exe().unwrap());
    }
}
