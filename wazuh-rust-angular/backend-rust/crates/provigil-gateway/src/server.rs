//! The listeners: long accept queue, connection limits, TLS with a certificate that can be swapped
//! under open connections, graceful stop.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use provigil_agent_server::tls;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify};
use tower::ServiceExt;
use tracing::{error, info, warn};

use crate::core::Gw;

const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
const HEADER_LIMIT: u32 = 16 * 1024;
const CALLS_PER_CONNECTION: u32 = 8;
const KEEPALIVE: Duration = Duration::from_secs(60);
/// A certificate is renewed this long before it ends.
const RENEW_BEFORE_SECS: i64 = 30 * 86_400;
const RENEW_CHECK: Duration = Duration::from_secs(3600);

static CONNECTION: AtomicU64 = AtomicU64::new(1);

/// The connection a request came on.
#[derive(Clone)]
pub struct Conn {
    pub id: u64,
    pub peer: SocketAddr,
    pub close: Arc<Notify>,
}

/// An agent port's listener: long accept queue (agents reconnecting at once are refused by the OS
/// when it is full; on Windows a negative backlog is `SOMAXCONN_HINT`, taken as asked), several
/// processes on one port on Linux.
pub fn listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    #[cfg(unix)]
    s.set_reuse_address(true)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    s.set_reuse_port(true)?;
    s.bind(&addr.into())?;
    s.listen(if cfg!(windows) { -65535 } else { 65535 })?;
    s.set_nonblocking(true)?;
    TcpListener::from_std(s.into())
}

/// The addresses of a port: `bind`, or all of IPv4 and IPv6.
pub fn listeners(bind: Option<IpAddr>, port: u16) -> io::Result<Vec<TcpListener>> {
    if let Some(ip) = bind {
        return Ok(vec![listener((ip, port).into())?]);
    }
    let mut out = vec![listener(SocketAddr::from(([0, 0, 0, 0], port)))?];
    match listener(SocketAddr::from(([0u16; 8], port))) {
        Ok(l) => out.push(l),
        Err(e) => warn!("No IPv6 listener on port {port}: {e}"),
    }
    Ok(out)
}

/// The certificate in force: swapped under open connections, which keep theirs.
#[derive(Debug)]
pub struct Certificates(RwLock<Arc<CertifiedKey>>);

impl ResolvesServerCert for Certificates {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().unwrap().clone())
    }
}

fn certified(chain_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>, String> {
    let chain = CertificateDer::pem_slice_iter(chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(chain, any_supported_type(&key).map_err(|e| e.to_string())?)))
}

/// A certificate from the install CA for `hosts`: it and when it ends.
fn issue(dir: &std::path::Path, hosts: Vec<String>) -> Result<(Arc<CertifiedKey>, i64), String> {
    let (ca, ca_key, ca_pem) = tls::read_ca(dir)?;
    let (cert, key, end) = tls::server_cert(&ca, &ca_key, "ProVigil Manager", hosts)?;
    Ok((certified(&format!("{}{ca_pem}", cert.pem()), &key.serialize_pem())?, end))
}

/// The listeners' certificate at start; without it the gateway does not start (never plain).
pub fn start_tls(gw: &Arc<Gw>) -> Result<(Arc<Certificates>, rustls::ServerConfig), String> {
    let hosts = tls::hosts(&gw.s.public_hosts);
    let (key, end, renew) = match &gw.s.tls_files {
        Some((c, k)) => {
            let read = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
            (certified(&read(c)?, &read(k)?)?, 0, false)
        }
        None => {
            let (key, end) = issue(&gw.s.tls_dir, hosts.clone())?;
            info!("Agent TLS certificate issued for {}", hosts.join(", "));
            (key, end, true)
        }
    };
    let certs = Arc::new(Certificates(RwLock::new(key)));
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().map_err(|e| e.to_string())?.with_no_client_auth().with_cert_resolver(certs.clone());
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    if renew {
        tokio::spawn(renew_loop(gw.clone(), certs.clone(), hosts, end));
    }
    Ok((certs, cfg))
}

/// Renews 30 days before the end and when the host list changes.
async fn renew_loop(gw: Arc<Gw>, certs: Arc<Certificates>, mut hosts: Vec<String>, mut end: i64) {
    loop {
        tokio::time::sleep(RENEW_CHECK).await;
        let now_hosts = tls::hosts(&gw.s.public_hosts);
        if now_hosts == hosts && chrono::Utc::now().timestamp() < end - RENEW_BEFORE_SECS {
            continue;
        }
        match issue(&gw.s.tls_dir, now_hosts.clone()) {
            Ok((key, e)) => {
                *certs.0.write().unwrap() = key;
                (hosts, end) = (now_hosts, e);
                info!("Agent TLS certificate renewed for {}", hosts.join(", "));
            }
            Err(e) => error!("Agent TLS certificate not renewed: {e}"),
        }
    }
}

/// Bytes through a socket, for the counters.
struct Counted {
    io: TcpStream,
    gw: Arc<Gw>,
}

impl AsyncRead for Counted {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.io).poll_read(cx, buf);
        self.gw.stats.c.bytes_in.fetch_add((buf.filled().len() - before) as u64, Relaxed);
        r
    }
}

impl AsyncWrite for Counted {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.io).poll_write(cx, b);
        if let Poll::Ready(Ok(n)) = r {
            self.gw.stats.c.bytes_out.fetch_add(n as u64, Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Connections open, per listener and in all.
pub struct Open {
    pub total: AtomicUsize,
    pub by_listener: [AtomicUsize; 3],
}

pub static OPEN: Open = Open { total: AtomicUsize::new(0), by_listener: [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)] };

struct Held(usize);

impl Drop for Held {
    fn drop(&mut self) {
        OPEN.total.fetch_sub(1, Relaxed);
        OPEN.by_listener[self.0].fetch_sub(1, Relaxed);
    }
}

/// Serves `l` until `stop`, then stops accepting. `slot`: its place in [`OPEN`].
pub async fn serve(l: TcpListener, app: Router, tls: Option<tokio_rustls::TlsAcceptor>, gw: Arc<Gw>, slot: usize, mut stop: watch::Receiver<bool>) {
    let mut handshakes: HashMap<IpAddr, (u64, u32)> = HashMap::new();
    loop {
        let (sock, peer) = tokio::select! {
            r = l.accept() => match r {
                Ok(v) => v,
                Err(e) => {
                    gw.stats.c.accept_errors.fetch_add(1, Relaxed);
                    error!("Agent accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = stop.changed() => return,
        };
        if OPEN.total.load(Relaxed) >= gw.s.max_connections {
            gw.stats.c.connections_refused.fetch_add(1, Relaxed);
            continue;
        }
        let second = crate::queue::now_ms() / 1000;
        if handshakes.len() > 10_000 {
            handshakes.retain(|_, (s, _)| *s == second);
        }
        let seen = handshakes.entry(peer.ip()).or_insert((second, 0));
        if seen.0 != second {
            *seen = (second, 0);
        }
        seen.1 += 1;
        if seen.1 > gw.s.handshakes_per_addr {
            gw.stats.c.handshakes_limited.fetch_add(1, Relaxed);
            continue;
        }
        OPEN.total.fetch_add(1, Relaxed);
        OPEN.by_listener[slot].fetch_add(1, Relaxed);
        gw.stats.c.connections_opened.fetch_add(1, Relaxed);
        let (app, tls, gw, stop) = (app.clone(), tls.clone(), gw.clone(), stop.clone());
        tokio::spawn(async move {
            let _held = Held(slot);
            let _ = sock.set_nodelay(true);
            let _ = socket2::SockRef::from(&sock).set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(KEEPALIVE));
            let conn = Conn { id: CONNECTION.fetch_add(1, Relaxed), peer, close: Arc::new(Notify::new()) };
            let io = Counted { io: sock, gw: gw.clone() };
            match tls {
                None => connection(io, app, conn, stop).await,
                Some(acceptor) => match tokio::time::timeout(HANDSHAKE_LIMIT, acceptor.accept(io)).await {
                    Ok(Ok(s)) => {
                        gw.stats.c.tls_ok.fetch_add(1, Relaxed);
                        connection(s, app, conn, stop).await;
                    }
                    Ok(Err(e)) => {
                        gw.stats.c.tls_failed.fetch_add(1, Relaxed);
                        warn!("Agent TLS handshake from {peer} failed: {e}");
                    }
                    Err(_) => {
                        gw.stats.c.tls_timed_out.fetch_add(1, Relaxed);
                        warn!("Agent TLS handshake from {peer} timed out");
                    }
                },
            }
        });
    }
}

/// One connection until it ends, told to end (`stop`, or a key's newest connection took over).
async fn connection<I>(io: I, app: Router, conn: Conn, mut stop: watch::Receiver<bool>) where I: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    let close = conn.close.clone();
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(conn.clone());
        app.clone().oneshot(req.map(Body::new))
    });
    let mut b = auto::Builder::new(TokioExecutor::new());
    b.http1().timer(TokioTimer::new()).header_read_timeout(HANDSHAKE_LIMIT).max_buf_size(HEADER_LIMIT as usize);
    b.http2().timer(TokioTimer::new()).max_concurrent_streams(CALLS_PER_CONNECTION).max_header_list_size(HEADER_LIMIT).keep_alive_interval(KEEPALIVE).keep_alive_timeout(Duration::from_secs(20));
    let c = b.serve_connection(TokioIo::new(io), svc);
    tokio::pin!(c);
    let mut told = false;
    loop {
        tokio::select! {
            // connection errors are the peer going away
            _ = c.as_mut() => return,
            _ = stop.changed(), if !told => {
                told = true;
                c.as_mut().graceful_shutdown();
            }
            _ = close.notified(), if !told => {
                told = true;
                c.as_mut().graceful_shutdown();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A burst well past any default queue, with nothing accepting yet: nobody is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_of_10000_connections_waits_in_the_accept_queue() {
        let l = listener(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = l.local_addr().unwrap();
        let burst: Vec<_> = (0..10_000).map(|_| tokio::spawn(TcpStream::connect(addr))).collect();
        let mut held = Vec::with_capacity(burst.len());
        for c in burst {
            held.push(c.await.unwrap().expect("connected"));
        }
        for _ in 0..100 {
            l.accept().await.unwrap();
        }
    }
}
