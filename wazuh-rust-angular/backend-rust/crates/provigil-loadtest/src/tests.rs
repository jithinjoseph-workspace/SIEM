//! The tool end to end against a stand-in manager, ClickHouse and console API on random ports.

// tonic::Status is the service's error type
#![allow(clippy::result_large_err)]

use std::sync::Mutex;

use axum::extract::Query;
use provigil_proto::*;
use tonic::transport::server::TcpIncoming;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use super::*;

const KEY: &str = "tk_test";
const TEST_CA: &str = "-----BEGIN CERTIFICATE-----
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

#[derive(Default)]
struct Seen {
    agents: Vec<String>,
    keepalives: Vec<Value>,
    events: Vec<Value>,
    batch_ids: Vec<String>,
    /// Event batches to refuse (429), and enrollments to time out after doing them.
    refuse: u32,
    lost_answers: u32,
}

struct Manager(Arc<Mutex<Seen>>);

fn agent_of<M>(r: &Request<M>) -> Result<String, Status> {
    let m = r.metadata();
    let id = m.get("x-agent-id").and_then(|v| v.to_str().ok()).unwrap_or_default();
    let bearer = m.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
    if bearer != format!("Bearer key-{id}") {
        return Err(Status::unauthenticated("wrong key"));
    }
    Ok(id.to_string())
}

#[tonic::async_trait]
impl AgentService for Manager {
    async fn enroll(&self, r: Request<EnrollRequest>) -> Result<Response<EnrollReply>, Status> {
        if r.metadata().get("x-tenant-key").and_then(|v| v.to_str().ok()) != Some(KEY) {
            return Err(Status::unauthenticated("tenant key"));
        }
        let mut s = self.0.lock().unwrap();
        // the same name is the same agent, like the manager
        let name = r.get_ref().name.clone();
        let id = match s.agents.iter().position(|a| *a == name) {
            Some(i) => format!("{:03}", i + 1),
            None => {
                s.agents.push(name);
                format!("{:03}", s.agents.len())
            }
        };
        if s.lost_answers > 0 {
            s.lost_answers -= 1;
            return Err(Status::unavailable("the answer was lost"));
        }
        Ok(Response::new(EnrollReply { raw_key: format!("key-{id}"), agent_id: id, agent_name: r.into_inner().name, tenant_id: "load-test".into(), ..Default::default() }))
    }
    async fn keepalive(&self, r: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status> {
        agent_of(&r)?;
        self.0.lock().unwrap().keepalives.push(serde_json::from_str(&r.get_ref().body_json).unwrap());
        Ok(Response::new(KeepaliveReply::default()))
    }
    async fn events(&self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status> {
        agent_of(&r)?;
        let mut s = self.0.lock().unwrap();
        if s.refuse > 0 {
            s.refuse -= 1;
            return Err(Status::resource_exhausted("the engine is behind"));
        }
        s.batch_ids.push(r.get_ref().batch_id.clone());
        s.events.extend(r.get_ref().events_json.iter().map(|e| serde_json::from_str::<Value>(e).unwrap()));
        Ok(Response::new(EventsReply { accepted: r.get_ref().events_json.len() as u32 }))
    }
    async fn result(&self, _: Request<ResultRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }
    async fn config(&self, r: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status> {
        agent_of(&r)?;
        Ok(Response::new(ConfigReply { version: "cfg-1".into(), config_json: "{}".into() }))
    }
    async fn yara(&self, _: Request<YaraRequest>) -> Result<Response<YaraReply>, Status> {
        Err(Status::unimplemented(""))
    }
    async fn upgrade(&self, _: Request<UpgradeChunkRequest>) -> Result<Response<ChunkStream>, Status> {
        Err(Status::unimplemented(""))
    }
}

fn args(list: &[&str]) -> Args {
    Args::parse(list.iter().map(|s| s.to_string())).unwrap()
}

fn manager_saw_the_run(s: &Seen, state: &RunState) {
    assert_eq!(state.tenant, "load-test");
    assert_eq!(state.agents.len(), 20);
    assert_eq!(s.keepalives.len(), 20, "one keepalive per agent in 4 s");
    let body = &s.keepalives[0];
    assert_eq!((body["group_config_version"].as_str(), body["labels"][0]["key"].as_str()), (Some("cfg-1"), Some("site")));
    assert!(body["version"].is_string());

    let of = |t: &str| s.events.iter().filter(|e| e["event_type"] == t).collect::<Vec<_>>();
    let windows = of("windows_eventchannel");
    assert_eq!(windows.len() as u64, state.sent, "every accepted event reached the manager once");
    assert!(state.sent >= 20 * 4 && state.unconfirmed == 0, "sent {}", state.sent);
    assert!(windows.iter().all(|e| e["message"].as_str().unwrap().contains(&state.run)), "each carries the run id");
    let payload: Value = serde_json::from_str(windows[0]["message"].as_str().unwrap()).unwrap();
    assert!(payload["Message"].is_string() && payload["Event"].as_str().unwrap().contains("<Channel>Application</Channel>"));
    assert_eq!(windows[0]["location"], "EventChannel");
    assert!(windows.iter().all(|e| !e["agent"]["id"].as_str().unwrap_or_default().is_empty()));
    assert!(windows.iter().any(|e| e["message"].as_str().unwrap().contains("<Level>2</Level>")), "1 in 20 raises an alert");
    let mut ids = s.batch_ids.clone();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), s.batch_ids.len(), "no batch id twice: the manager would drop the batch");

    let sca = of("sca");
    assert_eq!(sca.len(), 20 * (SCA_CHECKS + 2 + 2), "the policies message, the checks, the summary of each agent; then policies and summary");
    assert!(sca.iter().all(|e| e["message"].is_string()));
    let inventories = of("system_inventory");
    assert_eq!(inventories.len(), 20);
    let deltas = of("system_inventory_delta");
    assert_eq!(deltas.len(), 20, "then only what changed");
    let packages = &deltas[0]["tables"]["packages"];
    assert_eq!((packages["added"].as_array().unwrap().len(), packages["removed"].as_array().unwrap().len()), (1, 1), "a new version is another package");
    assert_eq!(packages["count"].as_u64(), Some(PACKAGES as u64));
    let inv: Value = serde_json::from_str(inventories[0]["inventory_json"].as_str().unwrap()).unwrap();
    assert_eq!(inv["packages"].as_array().unwrap().len(), PACKAGES);
    assert!(inventories[0]["os_info"]["os_name"].is_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_verify_cleanup() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("grpc://{}", listener.local_addr().unwrap());
    let incoming = TcpIncoming::from_listener(listener, true, None).unwrap();
    tokio::spawn(Server::builder().add_service(AgentServiceServer::new(Manager(seen.clone())).max_decoding_message_size(16 << 20)).serve_with_incoming(incoming));

    let dir = tempfile::tempdir().unwrap();
    let state_file = dir.path().join("state.json");
    let state_path = state_file.to_str().unwrap();
    let a = args(&["--url", &url, "--tenant-key", KEY, "--agents", "20", "--eps", "8", "--secs", "4", "--ramp", "1", "--flush-secs", "0.5", "--state", state_path]);
    assert_eq!(run_args(&a).await, Ok(true));

    let state = RunState::load(state_path).unwrap();
    manager_saw_the_run(&seen.lock().unwrap(), &state);
    let sent = state.sent;

    // ClickHouse and the console API
    let stored = Arc::new(Mutex::new(sent));
    let (asked, removed) = (Arc::new(Mutex::new(Vec::<String>::new())), Arc::new(Mutex::new(Vec::<String>::new())));
    let (st, q, r) = (stored.clone(), asked.clone(), removed.clone());
    let app = axum::Router::new()
        .route("/", axum::routing::post(move |Query(p): Query<HashMap<String, String>>, sql: String| async move {
            q.lock().unwrap().push(format!("{} {sql}", p["database"]));
            st.lock().unwrap().to_string()
        }))
        .route("/agents", axum::routing::delete(move |Query(p): Query<HashMap<String, String>>, h: axum::http::HeaderMap| async move {
            assert_eq!(h["authorization"], "Bearer jwt");
            let ids: Vec<String> = p["agents_list"].split(',').map(str::to_string).collect();
            r.lock().unwrap().extend(ids.clone());
            axum::Json(json!({ "affected_agents": ids }))
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });

    let analysisd = dir.path().join("analysisd.state");
    std::fs::write(&analysisd, "# comment\ntotal_events_decoded='5'\nevents_dropped='0'\nevent_queue_usage='0.1'\nuptime='3'\n").unwrap();
    let v = args(&["--verify", "--clickhouse", &http, "--state", state_path, "--analysisd-state", analysisd.to_str().unwrap()]);
    assert_eq!(run_args(&v).await, Ok(true));
    let q = asked.lock().unwrap()[0].clone();
    assert!(q.starts_with("ndr_load_test SELECT count() FROM siem_events") && q.contains(&state.run), "{q}");
    *stored.lock().unwrap() = sent - 1;
    assert_eq!(run_args(&v).await, Ok(false), "one event missing");

    assert!(run_args(&args(&["--cleanup", "--state", state_path])).await.unwrap_err().contains("--api-url"));
    assert_eq!(run_args(&args(&["--cleanup", "--api-url", &http, "--api-token", "jwt", "--state", state_path])).await, Ok(true));
    assert_eq!(removed.lock().unwrap().len(), 20);
    assert!(!state_file.exists());
}

#[tokio::test]
async fn refused_enrollment_is_reported() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("grpc://{}", listener.local_addr().unwrap());
    let incoming = TcpIncoming::from_listener(listener, true, None).unwrap();
    tokio::spawn(Server::builder().add_service(AgentServiceServer::new(Manager(seen))).serve_with_incoming(incoming));
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("s.json");
    let a = args(&["--url", &url, "--tenant-key", "wrong", "--agents", "3", "--state", state.to_str().unwrap()]);
    let e = run_args(&a).await.unwrap_err();
    assert!(e.contains("enroll: status 401") && e.contains('3'), "{e}");
}

/// As a real agent: a refused batch waits and goes again, so `sent` is what was accepted; an
/// enrollment whose answer was lost is asked again and leaves no agent behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_batches_are_sent_again_and_lost_enrollments_asked_again() {
    let seen = Arc::new(Mutex::new(Seen { refuse: 40, lost_answers: 6, ..Default::default() }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("grpc://{}", listener.local_addr().unwrap());
    let incoming = TcpIncoming::from_listener(listener, true, None).unwrap();
    tokio::spawn(Server::builder().add_service(AgentServiceServer::new(Manager(seen.clone())).max_decoding_message_size(16 << 20)).serve_with_incoming(incoming));
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("s.json");
    let a = args(&["--url", &url, "--tenant-key", KEY, "--agents", "5", "--eps", "10", "--secs", "4", "--ramp", "1", "--flush-secs", "0.25", "--state", state.to_str().unwrap()]);
    assert_eq!(run_args(&a).await, Ok(true));

    let st = RunState::load(state.to_str().unwrap()).unwrap();
    let s = seen.lock().unwrap();
    assert_eq!(s.refuse, 0, "the refusals happened");
    assert_eq!((st.agents.len(), s.agents.len()), (5, 5), "every agent the manager has is known here");
    let accepted = s.events.iter().filter(|e| e["event_type"] == "windows_eventchannel").count() as u64;
    assert_eq!(st.sent, accepted, "sent is what the manager accepted");
    assert!(accepted > 5 * 10 * 2, "the refused batches came back: {accepted}");
    let mut seqs: Vec<(String, u64)> = s.events.iter().filter(|e| e["event_type"] == "windows_eventchannel").map(|e| {
        let m: Value = serde_json::from_str(e["message"].as_str().unwrap()).unwrap();
        let text = m["Message"].as_str().unwrap();
        (e["agent"]["id"].as_str().unwrap().to_string(), text.split("event ").nth(1).unwrap().split(',').next().unwrap().parse().unwrap())
    }).collect();
    let all = seqs.len();
    seqs.sort();
    seqs.dedup();
    assert_eq!(seqs.len(), all, "none accepted twice");
}

#[test]
fn arguments_and_names() {
    assert!(Args::parse(["--agents".to_string()]).is_err());
    assert!(Args::parse(["agents".to_string()]).is_err());
    let a = args(&["--eps", "0.4", "--verify", "--insecure"]);
    assert!(a.verify && a.insecure && !a.cleanup);
    assert!(a.ca.is_empty());
    // a CA that cannot be used stops the run instead of failing every agent's handshake
    let dir = tempfile::tempdir().unwrap();
    let pem = dir.path().join("ca.pem");
    let parse = |p: &std::path::Path| Args::parse(["--ca".to_string(), p.display().to_string()]);
    assert!(parse(&pem).is_err(), "missing");
    std::fs::write(&pem, "not a certificate").unwrap();
    assert!(parse(&pem).is_err(), "not PEM");
    std::fs::write(&pem, TEST_CA).unwrap();
    assert_eq!(parse(&pem).unwrap().ca.len(), 1);
    assert_eq!(a.num("eps", 1.0), Ok(0.4));
    assert_eq!(a.num("secs", 7.0), Ok(7.0));
    assert!(args(&["--eps", "x"]).num("eps", 1.0).is_err());
    assert!(args(&["--eps", "-1"]).num("eps", 1.0).is_err());
    assert_eq!(tenant_db("default"), "ndr");
    assert_eq!(tenant_db("acme-corp"), "ndr_acme_corp");
    assert_eq!(analysisd_counters("# x\nevents_dropped='0'\nuptime='3'\nevent_queue_usage='0.5'"), ["events_dropped='0'", "event_queue_usage='0.5'"]);
}

#[test]
fn bursts_fall_inside_the_run() {
    let start = tokio::time::Instant::now();
    for place in [0.0, 0.25, 0.75, 0.999] {
        let s = Schedule { start, end: start + Duration::from_secs(100), place, ramp: 10.0, flush: 1.0, eps: 1.0 };
        let (sca, inventory) = s.burst_offsets();
        assert!(sca >= Duration::from_secs(10) && sca < Duration::from_secs(100), "{sca:?}");
        assert!(inventory >= Duration::from_secs(10) && inventory < Duration::from_secs(100), "{inventory:?}");
        assert_ne!(sca, inventory);
        let (at, next) = (start + sca, s.follow_up(start + sca));
        assert!(next > at && next < s.end);
    }
}

#[test]
fn second_sends_are_small_and_keep_the_hash() {
    let a = SimAgent { id: "001".into(), name: "lt-1".into(), key: "k".into() };
    let message = |e: &Value| serde_json::from_str::<Value>(e["message"].as_str().unwrap()).unwrap();
    let (full, again) = (sca_events(&a, true), sca_events(&a, false));
    assert_eq!((full.len(), again.len()), (SCA_CHECKS + 2, 2));
    let (one, two) = (message(full.last().unwrap()), message(again.last().unwrap()));
    assert_eq!(one["hash"], two["hash"], "the same results");
    assert_eq!(one["hash"].as_str().unwrap().len(), 64);
    assert!(one["first_scan"] == 1 && two.get("first_scan").is_none());

    let (first, saved) = inventory_event(&a, 7, 1, None);
    let inv: Value = serde_json::from_str(first["inventory_json"].as_str().unwrap()).unwrap();
    assert!(inv["packages"][0]["_h"].is_string() && first["os_info"]["_h"].is_string());
    let (same, _) = inventory_event(&a, 7, 1, Some(&saved));
    assert!(same["tables"]["packages"].get("added").is_none(), "a heartbeat");
    let (next, _) = inventory_event(&a, 7, 2, Some(&saved));
    assert_eq!(next["tables"]["packages"]["added"].as_array().unwrap().len(), 1);
    assert!(next.to_string().len() * 20 < first.to_string().len(), "{} of {}", next.to_string().len(), first.to_string().len());
}
