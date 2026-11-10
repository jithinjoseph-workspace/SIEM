//! Reliability checks of the gRPC transport (`#[ignore]`, run by hand):
//!
//! cargo test --release -p provigil-agent --lib transport::bench:: -- --ignored --nocapture --test-threads=1
//!
//! The managers here are in-process test servers on random loopback ports.

#![allow(clippy::result_large_err)]

use super::*;
use provigil_proto::{AgentService, AgentServiceServer, ChunkStream, ConfigReply, Empty, EnrollReply, EventsReply, KeepaliveReply, YaraReply};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use tonic::{Request, Response, Status};

use crate::config::BufferConfig;

/// A manager that records every event's `seq` (then waits `delay` before answering); as
/// siem-api, a batch id it took already is answered without taking the events again.
#[derive(Clone, Default)]
struct Counter {
    seen: Arc<Mutex<HashMap<u64, u32>>>,
    batches: Arc<AtomicU64>,
    batch_ids: Arc<Mutex<std::collections::HashSet<String>>>,
    repeats: Arc<AtomicU64>,
    delay: Duration,
}

#[tonic::async_trait]
impl AgentService for Counter {
    async fn enroll(&self, _: Request<EnrollRequest>) -> Result<Response<EnrollReply>, Status> {
        Ok(Response::new(EnrollReply::default()))
    }
    async fn keepalive(&self, _: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status> {
        Ok(Response::new(KeepaliveReply::default()))
    }
    async fn events(&self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status> {
        self.batches.fetch_add(1, Ordering::SeqCst);
        let id = &r.get_ref().batch_id;
        if !id.is_empty() && !self.batch_ids.lock().unwrap().insert(id.clone()) {
            self.repeats.fetch_add(1, Ordering::SeqCst);
        } else {
            let mut m = self.seen.lock().unwrap();
            for e in &r.get_ref().events_json {
                let v: Value = serde_json::from_str(e).unwrap();
                if let Some(s) = v["seq"].as_u64() {
                    *m.entry(s).or_default() += 1;
                }
            }
        }
        tokio::time::sleep(self.delay).await;
        Ok(Response::new(EventsReply { accepted: r.get_ref().events_json.len() as u32 }))
    }
    async fn result(&self, _: Request<ResultRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }
    async fn config(&self, _: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status> {
        Ok(Response::new(ConfigReply::default()))
    }
    async fn yara(&self, _: Request<YaraRequest>) -> Result<Response<YaraReply>, Status> {
        Ok(Response::new(YaraReply::default()))
    }
    async fn upgrade(&self, _: Request<UpgradeChunkRequest>) -> Result<Response<ChunkStream>, Status> {
        Err(Status::unimplemented(""))
    }
}

/// The manager in a runtime of its own on `port` (0: any): dropping the returned sender kills
/// it like a process kill (every connection task dropped at once).
fn run_manager(port: u16, svc: Counter) -> (u16, std::sync::mpsc::Sender<()>) {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (ptx, prx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async {
            let l = loop {
                match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                    Ok(l) => break l,
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            };
            ptx.send(l.local_addr().unwrap().port()).unwrap();
            let inc = tonic::transport::server::TcpIncoming::from_listener(l, true, None).unwrap();
            // as siem-api: default Server::builder(), 16 MiB messages
            let svc = AgentServiceServer::new(svc).max_decoding_message_size(MAX_MESSAGE).max_encoding_message_size(MAX_MESSAGE);
            tokio::spawn(tonic::transport::Server::builder().add_service(svc).serve_with_incoming(inc));
        });
        let _ = rx.recv();
        rt.shutdown_background();
    });
    (prx.recv().unwrap(), tx)
}

fn ident() -> AgentIdentity {
    AgentIdentity { agent_id: "007".into(), agent_name: "pc".into(), tenant_id: "acme".into(), auth_token: "k7".into(), enrolled_at: Utc::now() }
}

fn transport(url: &str, buffer: Arc<EventBuffer>, retry_secs: u64) -> AgentTransport {
    let config = AgentConfig { manager_url: url.into(), manager_urls: vec![url.into()], retry_interval_secs: retry_secs, ..AgentConfig::default() };
    AgentTransport::new(&config, ident(), buffer, Arc::new(EdrExecutor::new()))
}

/// The agent's flush loop (lib.rs), until the buffer is empty or `limit`; the errors seen.
async fn flush_until_empty(t: &AgentTransport, buffer: &EventBuffer, limit: Duration) -> Vec<(f64, String)> {
    let start = Instant::now();
    let mut errors = Vec::new();
    while !buffer.is_empty() && start.elapsed() < limit {
        match t.flush_events().await {
            Ok(n) if n > 0 => {}
            Ok(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            Err(e) => {
                errors.push((start.elapsed().as_secs_f64(), e));
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    errors
}

/// The manager is killed while batches are in flight and started again 2 s later: lost and
/// duplicated events, and the time to recover.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn manager_restart_mid_stream() {
    const N: u64 = 10_000;
    let svc = Counter { delay: Duration::from_millis(50), ..Counter::default() };
    let (port, kill) = run_manager(0, svc.clone());
    let cfg = BufferConfig { disabled: false, queue_size: 100_000, events_per_second: 1000, min_eps: 1 };
    let buffer = Arc::new(EventBuffer::with_limits(100_000, &cfg, json!({})));
    for i in 0..N {
        buffer.push(json!({ "event_type": "fim", "seq": i, "pad": "x".repeat(200) }));
    }
    let t = Arc::new(transport(&format!("grpc://127.0.0.1:{port}"), buffer.clone(), 10));
    let start = Instant::now();
    let (t2, b2) = (t.clone(), buffer.clone());
    let flusher = tokio::spawn(async move { flush_until_empty(&t2, &b2, Duration::from_secs(120)).await });

    tokio::time::sleep(Duration::from_millis(3050)).await;
    drop(kill);
    let killed_at = start.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (_, kill2) = run_manager(port, svc.clone());
    let back_at = start.elapsed().as_secs_f64();
    let errors = flusher.await.unwrap();
    let done = start.elapsed().as_secs_f64();

    let seen = svc.seen.lock().unwrap();
    let dup: u64 = seen.values().map(|c| (*c as u64).saturating_sub(1)).sum();
    let missing = (0..N).filter(|i| !seen.contains_key(i)).count();
    println!("RESTART killed at {killed_at:.2}s, back at {back_at:.2}s, buffer empty at {done:.2}s (left {})", buffer.len());
    println!("RESTART sent {N}: received unique={} duplicates={dup} missing={missing} batches={}", seen.len(), svc.batches.load(Ordering::SeqCst));
    for (at, e) in &errors {
        println!("RESTART flush error at {at:.2}s: {e}");
    }
    drop(kill2);
}

/// A TCP proxy whose existing connections can be frozen (bytes swallowed, sockets kept open,
/// as a peer that ACKs but never answers: a stale load-balancer flow, a NAT that kept the
/// socket) while new connections pass.
async fn freezable_proxy(to: u16) -> (u16, Arc<AtomicU64>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let frozen_before = Arc::new(AtomicU64::new(0)); // connections with gen < this are frozen
    let fb = frozen_before.clone();
    tokio::spawn(async move {
        let mut gen = 0u64;
        loop {
            let (a, _) = l.accept().await.unwrap();
            gen += 1;
            let my = gen;
            let b = tokio::net::TcpStream::connect(("127.0.0.1", to)).await.unwrap();
            let (ar, aw) = a.into_split();
            let (br, bw) = b.into_split();
            type R = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
            type W = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;
            let pairs: [(R, W); 2] = [(Box::new(ar), Box::new(bw)), (Box::new(br), Box::new(aw))];
            for (mut r, mut w) in pairs {
                let fb = fb.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 64 * 1024];

                    loop {
                        let Ok(n) = r.read(&mut buf).await else { break };
                        if n == 0 {
                            break;
                        }
                        if my < fb.load(Ordering::SeqCst) {
                            continue; // swallowed
                        }
                        if w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    // keep both halves open
                    std::future::pending::<()>().await;
                    drop(w);
                });
            }

        }
    });
    (port, frozen_before)
}


/// Calls on a frozen connection: a channel without HTTP/2 keepalive keeps using it; the
/// agent's channel (`grpc_channel`: pings every 30 s, 10 s to answer) moves to a new connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn frozen_connection() {
    let (port, _kill) = run_manager(0, Counter::default());
    for keepalive in [false, true] {
        let (pport, freeze) = freezable_proxy(port).await;
        let url = format!("grpc://127.0.0.1:{pport}");
        let ch = if keepalive {
            grpc_channel(&url, false, &[]).unwrap()
        } else {
            Endpoint::from_shared(format!("http://127.0.0.1:{pport}")).unwrap().connect_lazy()
        };
        let link = GrpcLink { url, creds: Creds::default(), client: AgentServiceClient::new(ch) };
        link.keepalive(&json!({})).await.unwrap();
        freeze.store(2, Ordering::SeqCst); // the connection in use (the first) is frozen; new ones pass
        let t0 = Instant::now();
        for i in 0..5 {
            let t = Instant::now();
            let r = link.keepalive(&json!({})).await;
            println!("FROZEN keepalive_pings={keepalive} call {i}: {:?} after {:.1}s (t={:.1}s)", r.as_ref().map(drop).map_err(|e| e.to_string()), t.elapsed().as_secs_f64(), t0.elapsed().as_secs_f64());
            if r.is_ok() {
                break;
            }
        }
    }
}

/// A batch over the 16 MiB message limit: what flush_events does with it, and with the events
/// queued behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn oversized_batch() {
    let svc = Counter::default();
    let (port, _kill) = run_manager(0, svc.clone());
    let cfg = BufferConfig { disabled: false, queue_size: 5000, events_per_second: 500, min_eps: 1 };
    let buffer = Arc::new(EventBuffer::with_limits(10_000, &cfg, json!({})));
    for i in 0..100 {
        buffer.push(json!({ "event_type": "system_inventory", "seq": i, "inventory_json": "x".repeat(170_000) }));
    }
    for i in 100..300 {
        buffer.push(json!({ "event_type": "fim", "seq": i }));
    }
    let t = transport(&format!("grpc://127.0.0.1:{port}"), buffer.clone(), 0);
    let start = Instant::now();
    for i in 0..12 {
        let r = t.flush_events().await;
        println!("OVERSIZE flush {i}: {:?} buffer={} manager={} (t={:.1}s)", r.map_err(|e| e.chars().take(120).collect::<String>()), buffer.len(), t.manager(), start.elapsed().as_secs_f64());
    }
    println!("OVERSIZE manager received {} events", svc.seen.lock().unwrap().len());
}

/// Flapping: a gRPC port that accepts nothing (connection refused) next to a working HTTPS
/// address: which link each request uses over time (the Fallback alone, simulated clock).
#[test]
#[ignore]
fn fallback_flapping_timeline() {
    let mut f = Fallback::default();
    let t0 = Instant::now();
    let mut grpc_attempts = 0;
    let mut timeline = Vec::new();
    // one request every 10 s (the keepalive) for 1 hour, gRPC always down
    for s in (0..3600).step_by(10) {
        let now = t0 + Duration::from_secs(s);
        if f.grpc(now, true, "m") {
            grpc_attempts += 1;
            timeline.push(s);
            f.report(false, now, "m");
        }
    }
    println!("FLAP gRPC down for 1 h, a request every 10 s: {grpc_attempts} gRPC attempts at {timeline:?}");
}

/// A proxy whose `cut` drops every open connection at once (both sockets closed) and closes
/// new ones until `cut` is cleared: a manager process killed and started again.
async fn cuttable_proxy(to: u16) -> (u16, Arc<AtomicU64>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let cut = Arc::new(AtomicU64::new(0)); // 0: up; else the cut number (connections older die)
    let epoch = Arc::new(AtomicU64::new(1));
    let (c2, e2) = (cut.clone(), epoch.clone());
    tokio::spawn(async move {
        loop {
            let (a, _) = l.accept().await.unwrap();
            if c2.load(Ordering::SeqCst) != 0 {
                drop(a);
                continue;
            }
            let my = e2.load(Ordering::SeqCst);
            let b = tokio::net::TcpStream::connect(("127.0.0.1", to)).await.unwrap();
            let (c3, e3) = (c2.clone(), e2.clone());
            tokio::spawn(async move {
                let (mut a, mut b) = (a, b);
                let watch = async {
                    while e3.load(Ordering::SeqCst) == my {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                };
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut a, &mut b) => {}
                    _ = watch => {}
                }
                let _ = c3;
            });
        }
    });
    // `cut` set: bump the epoch so open connections end
    let (c4, e4) = (cut.clone(), epoch);
    tokio::spawn(async move {
        let mut last = 0;
        loop {
            let c = c4.load(Ordering::SeqCst);
            if c != last && c != 0 {
                e4.fetch_add(1, Ordering::SeqCst);
            }
            last = c;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    (port, cut)
}

/// The manager's connection is cut while batches are in flight (handler 50 ms, so a cut often
/// lands after the manager stored a batch and before the agent got the answer), down 2 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn connection_cut_mid_stream() {
    const N: u64 = 10_000;
    let svc = Counter { delay: Duration::from_millis(50), ..Counter::default() };
    let (sport, _kill) = run_manager(0, svc.clone());
    let (port, cut) = cuttable_proxy(sport).await;
    let cfg = BufferConfig { disabled: false, queue_size: 100_000, events_per_second: 1000, min_eps: 1 };
    let buffer = Arc::new(EventBuffer::with_limits(100_000, &cfg, json!({})));
    for i in 0..N {
        buffer.push(json!({ "event_type": "fim", "seq": i, "pad": "x".repeat(200) }));
    }
    let t = Arc::new(transport(&format!("grpc://127.0.0.1:{port}"), buffer.clone(), 10));
    let start = Instant::now();
    let (t2, b2) = (t.clone(), buffer.clone());
    let flusher = tokio::spawn(async move { flush_until_empty(&t2, &b2, Duration::from_secs(120)).await });
    for k in 1..=3u64 {
        tokio::time::sleep(Duration::from_millis(2025)).await;
        cut.store(k, Ordering::SeqCst);
        let at = start.elapsed().as_secs_f64();
        tokio::time::sleep(Duration::from_secs(2)).await;
        cut.store(0, Ordering::SeqCst);
        println!("CUT {k}: down {at:.2}s .. {:.2}s", start.elapsed().as_secs_f64());
    }
    let errors = flusher.await.unwrap();
    let seen = svc.seen.lock().unwrap();
    let dup: u64 = seen.values().map(|c| (*c as u64).saturating_sub(1)).sum();
    let missing = (0..N).filter(|i| !seen.contains_key(i)).count();
    println!("CUT buffer empty at {:.2}s (left {}); sent {N}: unique={} duplicates={dup} missing={missing} batches={} repeated batch ids={}", start.elapsed().as_secs_f64(), buffer.len(), seen.len(), svc.batches.load(Ordering::SeqCst), svc.repeats.load(Ordering::SeqCst));
    for (at, e) in &errors {
        println!("CUT flush error at {at:.2}s: {e}");
    }
}
