//! Simulated ProVigil agents against a manager, over the agent's own links (gRPC or HTTPS).
//!
//! Run (`--url` picks the protocol: `grpc://`, `grpcs://`, `https://`, `http://`):
//!   provigil-loadtest --url grpcs://HOST:8089 --ca ca.pem --tenant-key KEY --agents 1000 --eps 1 --secs 180
//! Each agent enrolls, then until `--secs` sends a keepalive every 10 s, Windows events at
//! `--eps`, and like a real agent one full SCA burst and one full inventory spread over the run,
//! then a scan with no change (its summary) and an inventory with one package changed; a full send
//! the manager asks for is sent. The run is kept in `--state` (default loadtest-state.json, with
//! the agents' keys).
//!
//! After a run:
//!   provigil-loadtest --verify --clickhouse http://HOST:8123 [--analysisd-state PATH]
//!     events sent vs stored (every event carries the run id), analysisd's counters, siem-api's
//!     CPU and memory. `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` as for siem-api.
//!   provigil-loadtest --cleanup --api-url http://HOST:8088 --api-token JWT
//!     removes the run's agents (a console token of their tenant).
//!
//! Other options: `--ramp` seconds to start the agents over (30), `--flush-secs` between event
//! batches (1), `--ca FILE` the manager's CA certificate (`ca_pem` of /api/server-info), as real
//! agents have it, `--insecure` any TLS certificate, `--api-process` the process to watch (siem-api).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures_util::{stream, StreamExt};
use provigil_agent::identity::AgentIdentity;
use provigil_agent::sca::{results_hash, Outcome};
use provigil_agent::syscollector::delta;
use provigil_agent::transport::{ca_certs, http_client, keepalive_body, Cert, Creds, Fail, GrpcLink, HttpsLink, Link};
use provigil_agent::wevt::build_payload;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sysinfo::System;

const KEEPALIVE_EVERY: Duration = Duration::from_secs(10);
/// The agent's largest batch.
const BATCH: usize = 100;
const ENROLL_AT_ONCE: usize = 16;
const SCA_CHECKS: usize = 60;
const PACKAGES: usize = 150;
const AGENT_VERSION: &str = "1.0.0";
/// Rows of one removal call.
const REMOVE_CHUNK: usize = 200;
/// Tries of one enrollment: the same name gets the same agent, so one whose answer was lost
/// is not left behind.
const ENROLL_TRIES: usize = 4;

#[derive(Clone)]
struct Args {
    options: HashMap<String, String>,
    verify: bool,
    cleanup: bool,
    insecure: bool,
    ca: Vec<Cert>,
}

impl Args {
    fn parse(argv: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut a = Self { options: HashMap::new(), verify: false, cleanup: false, insecure: false, ca: Vec::new() };
        let mut argv = argv.into_iter();
        while let Some(k) = argv.next() {
            match k.as_str() {
                "--verify" => a.verify = true,
                "--cleanup" => a.cleanup = true,
                "--insecure" => a.insecure = true,
                _ => {
                    let name = k.strip_prefix("--").ok_or(format!("unknown argument {k}"))?;
                    a.options.insert(name.to_string(), argv.next().ok_or(format!("{k} needs a value"))?);
                }
            }
        }
        if let Some(file) = a.options.get("ca") {
            a.ca = ca_certs(Some(std::path::Path::new(file)));
            if a.ca.is_empty() {
                return Err(format!("--ca {file}: no usable certificate"));
            }
        }
        Ok(a)
    }

    fn get(&self, name: &str) -> Result<&str, String> {
        self.options.get(name).map(String::as_str).ok_or(format!("--{name} is required"))
    }

    fn or<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.options.get(name).map_or(default, String::as_str)
    }

    fn num(&self, name: &str, default: f64) -> Result<f64, String> {
        match self.options.get(name) {
            None => Ok(default),
            Some(v) => v.parse().ok().filter(|n: &f64| n.is_finite() && *n >= 0.0).ok_or(format!("--{name}: not a number: {v}")),
        }
    }

    fn state_path(&self) -> &str {
        self.or("state", "loadtest-state.json")
    }

    fn link(&self, creds: Creds) -> Result<Arc<dyn Link>, String> {
        let url = self.get("url")?;
        Ok(if url.starts_with("grpc") {
            Arc::new(GrpcLink::new(url, creds, self.insecure, &self.ca)?)
        } else {
            Arc::new(HttpsLink::new(url, creds, http_client(self.insecure, &self.ca)))
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SimAgent {
    id: String,
    name: String,
    key: String,
}

/// What a later `--verify` or `--cleanup` needs.
#[derive(Serialize, Deserialize)]
struct RunState {
    run: String,
    tenant: String,
    started_ms: i64,
    /// Windows events the manager accepted.
    sent: u64,
    /// Windows events not accepted when the run ended: the manager may have those of a batch
    /// whose answer was lost.
    unconfirmed: u64,
    agents: Vec<SimAgent>,
}

impl RunState {
    fn save(&self, path: &str) -> Result<(), String> {
        std::fs::write(path, serde_json::to_vec(self).map_err(|e| e.to_string())?).map_err(|e| format!("{path}: {e}"))
    }

    fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        serde_json::from_slice(&text).map_err(|e| format!("{path}: {e}"))
    }
}

/// What one agent (or all of them) measured.
#[derive(Default)]
struct Stats {
    keepalive_ms: Vec<f32>,
    batch_ms: Vec<f32>,
    sent: u64,
    unconfirmed: u64,
    sca_bursts: u64,
    inventories: u64,
    inventory_deltas: u64,
    errors: BTreeMap<String, u64>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.keepalive_ms.extend(o.keepalive_ms);
        self.batch_ms.extend(o.batch_ms);
        self.sent += o.sent;
        self.unconfirmed += o.unconfirmed;
        self.sca_bursts += o.sca_bursts;
        self.inventories += o.inventories;
        self.inventory_deltas += o.inventory_deltas;
        for (k, n) in o.errors {
            *self.errors.entry(k).or_default() += n;
        }
    }

    fn error(&mut self, op: &str, e: &Fail) {
        let kind = match e {
            Fail::Status(code, _) => format!("{op}: status {code}"),
            Fail::Bad(_) => format!("{op}: bad answer"),
            Fail::Down(m) => format!("{op}: {}", m.chars().take(60).collect::<String>()),
        };
        *self.errors.entry(kind).or_default() += 1;
    }
}

fn ms_since(t: Instant) -> f32 {
    t.elapsed().as_secs_f32() * 1000.0
}

/// `n=... p50=... p99=...`
fn latency(v: &mut [f32]) -> String {
    if v.is_empty() {
        return "n=0".into();
    }
    v.sort_by(f32::total_cmp);
    let at = |p: f64| v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1];
    format!("n={} p50={:.1}ms p99={:.1}ms max={:.1}ms", v.len(), at(0.5), at(0.99), at(1.0))
}

/// An Application event as the agent's event channel reader sends it; 1 in 20 is an error,
/// which raises an alert, as in the 16 Oct test.
fn windows_event(a: &SimAgent, run: &str, seq: u64) -> Value {
    let now = Utc::now();
    let level = if seq % 20 == 19 { 2 } else { 4 };
    let message = format!("Faulting application name: loadtest.exe, run {run}, agent {}, event {seq}, version: 10.0.22621.1, time stamp: 0x65a1b2c3", a.id);
    let xml = format!(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Error' Guid='{{a0e9b465-b939-57d7-b27d-95d8e925ff57}}'/><EventID>1000</EventID><Version>0</Version><Level>{level}</Level><Task>100</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='{}'/><EventRecordID>{seq}</EventRecordID><Correlation/><Execution ProcessID='4312' ThreadID='8120'/><Channel>Application</Channel><Computer>{}</Computer><Security/></System><EventData><Data Name='AppName'>loadtest.exe</Data><Data Name='RunId'>{run}</Data><Data Name='Seq'>{seq}</Data></EventData></Event>",
        now.format("%Y-%m-%dT%H:%M:%S%.6fZ"),
        a.name
    );
    json!({
        "event_type": "windows_eventchannel",
        "timestamp": now.to_rfc3339(),
        "agent": { "id": a.id, "name": a.name },
        "location": "EventChannel",
        "channel": "Application",
        "message": build_payload(Some(&message), &xml),
    })
}

/// One policy's scan as the agent's SCA module sends it: the checks (`full`, else none: nothing
/// changed), then the summary.
fn sca_events(a: &SimAgent, full: bool) -> Vec<Value> {
    let event = |message: Value| {
        json!({ "event_type": "sca", "timestamp": Utc::now().to_rfc3339(), "agent": { "id": a.id, "name": a.name }, "location": "sca", "message": message.to_string() })
    };
    let (policy, policy_id, scan_id) = ("ProVigil load test policy", "provigil_loadtest", (uuid::Uuid::new_v4().as_u128() as u32 & 0x7FFF_FFFF).max(1));
    let mut out = vec![event(json!({ "type": "policies", "policies": [policy_id] }))];
    let outcome = |i: usize| if i.is_multiple_of(3) { Outcome::Failed } else { Outcome::Passed };
    for i in (0..SCA_CHECKS).filter(|_| full) {
        let check = json!({ "id": 90000 + i, "title": format!("Ensure load test setting {i} is enabled"), "description": "A setting of the load test policy.", "remediation": "Enable the setting.",
            "compliance": { "cis": format!("1.{i}") }, "rules": [format!("r:HKLM\\Software\\LoadTest -> Setting{i} -> 1")], "condition": "all", "result": outcome(i).as_str() });
        out.push(event(json!({ "type": "check", "id": scan_id, "policy": policy, "policy_id": policy_id, "check": check })));
    }
    let now = Utc::now().timestamp();
    let outcomes: Vec<Outcome> = (0..SCA_CHECKS).map(outcome).collect();
    let results: Vec<(u32, &Outcome)> = outcomes.iter().enumerate().map(|(i, o)| (90000 + i as u32, o)).collect();
    let mut summary = json!({ "type": "summary", "scan_id": scan_id, "name": policy, "policy_id": policy_id, "file": "provigil_loadtest.yml", "start_time": now - 5, "end_time": now,
        "passed": SCA_CHECKS * 2 / 3, "failed": SCA_CHECKS / 3, "invalid": 0, "total_checks": SCA_CHECKS, "score": 66, "hash": results_hash(&results), "hash_file": format!("{:064x}", 1) });
    if full {
        summary["first_scan"] = json!(1);
    }
    out.push(event(summary));
    out
}

/// What the manager has of an agent's inventory: table -> key -> hash.
type Saved = HashMap<String, HashMap<String, String>>;

/// The inventory of a typical workstation; each `generation` has another first package version.
fn inventory(index: usize, generation: usize) -> Value {
    let list = |n: usize, f: &dyn Fn(usize) -> Value| Value::Array((0..n).map(f).collect());
    let mut inv = json!({
        "hardware": { "board_serial": format!("LT{index:08}"), "cpu_name": "Intel(R) Core(TM) i7-1165G7", "cpu_cores": 8, "cpu_mhz": 2803, "ram_total_kb": 16_000_000, "ram_free_kb": 7_000_000, "ram_usage_percent": 56 },
        "packages": list(PACKAGES, &|i| json!({ "name": format!("Load Test Package {i}"), "version": format!("{}.{}.0", i % 9 + 1, i % 7), "publisher": "ProVigil", "architecture": "x86_64", "location": format!("C:\\Program Files\\LoadTest{i}"), "install_date": "20260101", "size_bytes": 1_000_000 + i })),
        "processes": list(80, &|i| json!({ "pid": 1000 + i, "name": format!("process{i}.exe"), "parent_pid": 4, "command_line": format!("C:\\Windows\\System32\\process{i}.exe -k netsvcs"), "owner": "SYSTEM", "memory_mb": 20, "priority": 8, "threads": 6 })),
        "ports": list(30, &|i| json!({ "protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 49000 + i, "state": "listening", "pid": 1000 + i, "process": format!("process{i}.exe") })),
        "network_interfaces": [{ "name": "Ethernet", "mac_address": "00:15:5d:00:00:01", "ipv4": [format!("10.{}.{}.{}/24", index / 65536 % 256, index / 256 % 256, index % 256)], "mtu": 1500, "gateway": "10.0.0.1", "dhcp": "enabled" }],
        "services": list(100, &|i| json!({ "name": format!("LoadTestSvc{i}"), "display_name": format!("Load Test Service {i}"), "state": "running", "startup_type": "auto", "path": format!("C:\\Windows\\System32\\svc{i}.exe") })),
        "users": [{ "name": "Administrator", "sid": "S-1-5-21-1-500", "groups": ["Administrators"] }, { "name": "analyst", "sid": "S-1-5-21-1-1001", "groups": ["Users"] }],
        "groups": [{ "name": "Administrators", "sid": "S-1-5-32-544", "members": ["Administrator"] }],
    });
    inv["packages"][0]["version"] = json!(format!("1.0.{generation}"));
    inv
}

/// The agent's inventory event of this state, and what the manager then has: everything without
/// `saved`, else a `system_inventory_delta`.
fn inventory_event(a: &SimAgent, index: usize, generation: usize, saved: Option<&Saved>) -> (Value, Saved) {
    let (mut inv, hotfixes) = (inventory(index, generation), ["KB5031455".to_string(), "KB5032189".to_string()]);
    let mut os_info = json!({ "hostname": a.name, "architecture": "x86_64", "os_name": "Microsoft Windows 11 Pro", "os_version": "10.0.22631.4317", "os_major": "10", "os_minor": "0", "os_build": "22631", "os_patch": "4317", "os_display_version": "23H2", "os_platform": "windows", "sysname": "Windows", "release": "22631.4317" });
    let tables = delta::tables(&inv, &os_info, &hotfixes);
    let now_saved = tables.iter().map(|t| (t.name.to_string(), t.items.iter().map(|(k, (h, _))| (k.clone(), h.clone())).collect())).collect();
    if let Some(saved) = saved {
        let (changes, n) = delta::changes(&tables, saved);
        return (delta::event((&a.id, &a.name), changes, n), now_saved);
    }
    delta::mark_full(&tables, &mut inv, &mut os_info);
    let event = json!({
        "event_type": "system_inventory",
        "timestamp": Utc::now().to_rfc3339(),
        "agent": { "id": a.id, "name": a.name },
        "location": "syscollector/inventory",
        "message": format!("syscollector: System inventory scan completed. Host: {}", a.name),
        "inventory_json": inv.to_string(),
        "os_info": os_info,
        "hotfixes": hotfixes,
        "hostname": a.name,
        "os": "Microsoft Windows 11 Pro 10.0.22631",
    });
    (event, now_saved)
}

/// When the agent's events, keepalives and one-time bursts fall.
struct Schedule {
    start: tokio::time::Instant,
    end: tokio::time::Instant,
    /// The agent's place in the fleet, 0 to 1: spreads the agents over each interval.
    place: f64,
    ramp: f64,
    flush: f64,
    eps: f64,
}

impl Schedule {
    /// A burst's follow-up, between it and the end of the run.
    fn follow_up(&self, at: tokio::time::Instant) -> tokio::time::Instant {
        at + (self.end - at) / 2
    }

    /// The agent's SCA burst and inventory: spread over the run after the ramp, half a run apart.
    fn burst_offsets(&self) -> (Duration, Duration) {
        let span = (self.end - self.start).as_secs_f64() - self.ramp;
        let at = |p: f64| Duration::from_secs_f64(self.ramp + span.max(0.0) * p.fract() * 0.9);
        (at(self.place), at(self.place + 0.5))
    }
}

/// A batch waiting for the manager: like the real agent's buffer, one that is refused (429) or
/// fails stays first in line and goes again at the next flush, with the same batch id.
struct Waiting {
    events: Vec<Value>,
    /// Windows events among them.
    windows: u64,
    tally: fn(&mut Stats),
}

/// Sends what waits, in order, until a batch is not accepted.
async fn send_waiting(link: &dyn Link, waiting: &mut VecDeque<Waiting>, st: &mut Stats) {
    while let Some(b) = waiting.front() {
        let t = Instant::now();
        match link.events(&b.events).await {
            Ok(()) => {
                if b.windows > 0 {
                    st.batch_ms.push(ms_since(t));
                }
                st.sent += b.windows;
                (b.tally)(st);
                waiting.pop_front();
            }
            Err(e) => return st.error("events", &e),
        }
    }
}

async fn run_agent(link: Arc<dyn Link>, a: SimAgent, index: usize, run: Arc<String>, tenant: String, s: Schedule) -> Stats {
    let mut st = Stats::default();
    let begin = s.start + Duration::from_secs_f64(s.ramp * s.place);
    tokio::time::sleep_until(begin).await;
    let identity = AgentIdentity { agent_id: a.id.clone(), agent_name: a.name.clone(), tenant_id: tenant, auth_token: a.key.clone(), enrolled_at: Utc::now() };
    let labels = [provigil_agent::config::Label { key: "site".into(), value: "loadtest".into(), hidden: false }];
    let ip = format!("10.{}.{}.{}", index / 65536 % 256, index / 256 % 256, index % 256);
    // the agent fetches its group configuration, and reports the version it runs
    let group_version = match link.config().await {
        Ok(c) => c["version"].as_str().map(str::to_string),
        Err(e) => {
            st.error("config", &e);
            None
        }
    };

    let (sca_at, inventory_at) = s.burst_offsets();
    let (mut sca_at, mut inventory_at) = (Some(s.start + sca_at), Some(s.start + inventory_at));
    let (mut next_keepalive, mut next_flush) = (begin, begin + Duration::from_secs_f64(s.flush * s.place));
    let flush_every = Duration::from_secs_f64(s.flush);
    let (mut credit, mut seq) = (0.0, 0u64);
    let mut waiting = VecDeque::new();
    // nothing sent yet: both go in full; what the manager asks for goes in full again
    let (mut sca_full, mut saved, mut generation) = (true, None::<Saved>, 0);
    loop {
        let next = [Some(next_keepalive), Some(next_flush), sca_at, inventory_at].into_iter().flatten().min().unwrap();
        if next >= s.end {
            st.unconfirmed = waiting.iter().map(|b: &Waiting| b.windows).sum();
            return st;
        }
        tokio::time::sleep_until(next).await;

        if next_keepalive <= next {
            next_keepalive += KEEPALIVE_EVERY;
            let body = keepalive_body(&identity, &labels, Some(ip.clone()), group_version.as_deref(), "active");
            let t = Instant::now();
            match link.keepalive(&body).await {
                Ok(commands) => {
                    st.keepalive_ms.push(ms_since(t));
                    let asked = |kind: &str| commands.iter().any(|c| c["type"] == kind);
                    if asked("sca_full") {
                        (sca_full, sca_at) = (true, Some(next));
                    }
                    if asked("inventory_full") {
                        (saved, inventory_at) = (None, Some(next));
                    }
                }
                Err(e) => st.error("keepalive", &e),
            }
        }
        if next_flush <= next {
            next_flush += flush_every;
            credit += s.eps * s.flush;
            let n = (credit as usize).min(BATCH);
            credit -= n as f64;
            if n > 0 {
                let events: Vec<Value> = (0..n as u64).map(|i| windows_event(&a, &run, seq + i)).collect();
                seq += n as u64;
                waiting.push_back(Waiting { events, windows: n as u64, tally: |_| {} });
            }
        }
        if sca_at.is_some_and(|at| at <= next) {
            sca_at = sca_full.then(|| s.follow_up(next));
            let events = sca_events(&a, std::mem::take(&mut sca_full));
            let chunks = events.chunks(BATCH).count();
            for (i, batch) in events.chunks(BATCH).enumerate() {
                waiting.push_back(Waiting { events: batch.to_vec(), windows: 0, tally: if i + 1 == chunks { |s| s.sca_bursts += 1 } else { |_| {} } });
            }
        }
        if inventory_at.is_some_and(|at| at <= next) {
            inventory_at = saved.is_none().then(|| s.follow_up(next));
            generation += 1;
            let (event, now_saved) = inventory_event(&a, index, generation, saved.as_ref());
            let tally: fn(&mut Stats) = if saved.is_some() { |s| s.inventory_deltas += 1 } else { |s| s.inventories += 1 };
            waiting.push_back(Waiting { events: vec![event], windows: 0, tally });
            saved = Some(now_saved);
        }
        send_waiting(link.as_ref(), &mut waiting, &mut st).await;
    }
}

/// Memory (MiB) and CPU (% of one core) of the processes named `name`; `None` when there is
/// none on this machine. CPU needs a second call some time after the first.
fn process_usage(sys: &mut System, name: &str) -> Option<(f64, f32)> {
    sys.refresh_processes();
    sys.processes_by_name(name).fold(None, |sum, p| {
        let (mem, cpu) = sum.unwrap_or((0.0, 0.0));
        Some((mem + p.memory() as f64 / 1_048_576.0, cpu + p.cpu_usage()))
    })
}

async fn enroll_all(a: &Args, key: &str, n: usize, run: &str) -> Result<(Vec<SimAgent>, String, Stats), String> {
    let link = a.link(Creds { tenant_key: Some(key.to_string()), ..Default::default() })?;
    let prefix = format!("{}-{run}", a.or("prefix", "lt"));
    let t0 = Instant::now();
    let mut calls = stream::iter(0..n)
        .map(|i| {
            let (link, name) = (link.clone(), format!("{prefix}-{i:05}"));
            async move {
                let t = Instant::now();
                let body = json!({ "name": name, "os_type": "windows", "hostname": name, "version": AGENT_VERSION, "groups": "" });
                let mut r = link.enroll(&body).await;
                for _ in 1..ENROLL_TRIES {
                    if !matches!(&r, Err(Fail::Down(_))) && !matches!(&r, Err(Fail::Status(c, _)) if *c == 429 || *c >= 500) {
                        break;
                    }
                    r = link.enroll(&body).await;
                }
                (name, r, ms_since(t))
            }
        })
        .buffer_unordered(ENROLL_AT_ONCE);
    let (mut agents, mut tenant, mut st, mut times) = (Vec::with_capacity(n), String::new(), Stats::default(), Vec::with_capacity(n));
    while let Some((name, r, ms)) = calls.next().await {
        match r {
            Ok(v) => {
                let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
                tenant = s("tenant_id");
                times.push(ms);
                agents.push(SimAgent { id: s("agent_id"), name, key: s("raw_key") });
            }
            Err(e) => st.error("enroll", &e),
        }
    }
    println!("enrolled {} of {n} in tenant '{tenant}' in {:.1}s ({:.0}/s): {}", agents.len(), t0.elapsed().as_secs_f64(), agents.len() as f64 / t0.elapsed().as_secs_f64().max(0.001), latency(&mut times));
    Ok((agents, tenant, st))
}

async fn run(a: &Args) -> Result<(), String> {
    let (key, n) = (a.get("tenant-key")?, a.num("agents", 100.0)? as usize);
    let (eps, secs, ramp, flush) = (a.num("eps", 1.0)?, a.num("secs", 180.0)?, a.num("ramp", 30.0)?, a.num("flush-secs", 1.0)?.max(0.05));
    let run_id = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
    println!("run {run_id}: {n} agents, {eps} events/s each, {secs} s");
    let (agents, tenant, enrolled) = enroll_all(a, key, n, &run_id).await?;
    if agents.is_empty() {
        return Err(format!("no agent enrolled: {:?}", enrolled.errors));
    }
    let mut state = RunState { run: run_id, tenant: tenant.clone(), started_ms: Utc::now().timestamp_millis(), sent: 0, unconfirmed: 0, agents };
    // written now too: a run cut short can still be cleaned up
    state.save(a.state_path())?;

    let name = a.or("api-process", "siem-api").to_string();
    let (watch_stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
    let watcher = tokio::spawn(async move {
        let mut sys = System::new();
        let (mut peak, mut cpu_sum, mut cpu_n) = (0.0f64, 0.0f64, 0u32);
        process_usage(&mut sys, &name);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = &mut stopped => return (peak, cpu_sum / cpu_n.max(1) as f64, cpu_n),
            }
            if let Some((mem, cpu)) = process_usage(&mut sys, &name) {
                peak = peak.max(mem);
                cpu_sum += cpu as f64;
                cpu_n += 1;
            }
        }
    });

    let start = tokio::time::Instant::now() + Duration::from_millis(200);
    let end = start + Duration::from_secs_f64(secs);
    let (run_id, count) = (Arc::new(state.run.clone()), state.agents.len());
    let mut tasks = Vec::with_capacity(count);
    for (i, sim) in state.agents.iter().cloned().enumerate() {
        let creds = Creds { agent_id: sim.id.clone(), key: sim.key.clone(), tenant_id: tenant.clone(), tenant_key: Some(key.to_string()) };
        let schedule = Schedule { start, end, place: i as f64 / count as f64, ramp, flush, eps };
        tasks.push(tokio::spawn(run_agent(a.link(creds)?, sim, i, run_id.clone(), tenant.clone(), schedule)));
    }
    let mut all = Stats::default();
    for t in tasks {
        all.merge(t.await.map_err(|e| e.to_string())?);
    }
    let _ = watch_stop.send(());
    let (peak, cpu, samples) = watcher.await.map_err(|e| e.to_string())?;

    all.errors.extend(enrolled.errors);
    state.sent = all.sent;
    state.unconfirmed = all.unconfirmed;
    state.save(a.state_path())?;
    println!("events accepted: {} ({:.0}/s); still waiting at the end: {}", all.sent, all.sent as f64 / secs.max(0.001), all.unconfirmed);
    println!("sca bursts: {}; inventories: {}; inventory deltas: {}", all.sca_bursts, all.inventories, all.inventory_deltas);
    println!("keepalive: {}", latency(&mut all.keepalive_ms));
    println!("batch: {}", latency(&mut all.batch_ms));
    println!("errors: {}", if all.errors.is_empty() { "none".to_string() } else { format!("{:?}", all.errors) });
    if samples > 0 {
        println!("siem-api during the run: peak {peak:.0} MiB, average CPU {cpu:.0}% of one core");
    }
    println!("state: {} (next: --verify, then --cleanup)", a.state_path());
    Ok(())
}

/// The tenant's ClickHouse database (`tenancy::tenant_db_name`).
fn tenant_db(tenant: &str) -> String {
    if matches!(tenant, "" | "global" | "default") {
        return "ndr".into();
    }
    format!("ndr_{}", tenant.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect::<String>())
}

/// The queue, drop and event counters of a `key='value'` daemon state file.
fn analysisd_counters(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| !l.starts_with('#') && l.contains('='))
        .filter(|l| ["queue", "dropped", "decoded", "processed", "received", "edps"].iter().any(|k| l.split('=').next().unwrap_or("").contains(k)))
        .collect()
}

/// Whether every sent event is stored.
async fn verify(a: &Args) -> Result<bool, String> {
    let state = RunState::load(a.state_path())?;
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let url = a.options.get("clickhouse").cloned().unwrap_or_else(|| env("CLICKHOUSE_URL", "http://localhost:8123"));
    // the run id is in the event's text (and in the agents' names, so SCA and inventory rows are
    // left out); five minutes of margin for the two machines' clocks
    let sql = format!(
        "SELECT count() FROM siem_events WHERE timestamp >= {} AND source = 'windows_event' AND (position(message, '{run}') > 0 OR position(raw_metadata, '{run}') > 0)",
        (state.started_ms - 300_000).max(0),
        run = state.run
    );
    let mut q = reqwest::Client::new().post(url.trim_end_matches('/')).query(&[("database", tenant_db(&state.tenant))]).header("X-ClickHouse-User", env("CLICKHOUSE_USER", "default")).body(sql);
    if let Ok(p) = std::env::var("CLICKHOUSE_PASSWORD") {
        q = q.header("X-ClickHouse-Key", p);
    }
    let r = q.send().await.map_err(|e| format!("ClickHouse: {e}"))?;
    let (status, text) = (r.status(), r.text().await.map_err(|e| e.to_string())?);
    if !status.is_success() {
        return Err(format!("ClickHouse: {status}: {text}"));
    }
    let stored: u64 = text.trim().parse().map_err(|_| format!("ClickHouse answered: {text}"))?;
    println!("run {} ({} agents, tenant '{}'): sent {}, stored {stored}, missing {}, in failed batches {}", state.run, state.agents.len(), state.tenant, state.sent, state.sent as i64 - stored as i64, state.unconfirmed);

    if let Some(path) = a.options.get("analysisd-state") {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        println!("analysisd ({path}):");
        analysisd_counters(&text).iter().for_each(|l| println!("  {l}"));
    }
    let name = a.or("api-process", "siem-api");
    let mut sys = System::new();
    process_usage(&mut sys, name);
    tokio::time::sleep(Duration::from_secs(1)).await;
    match process_usage(&mut sys, name) {
        Some((mem, cpu)) => println!("{name} now: {mem:.0} MiB, {cpu:.0}% of one core"),
        None => println!("{name}: not running on this machine"),
    }
    Ok(stored >= state.sent)
}

async fn cleanup(a: &Args) -> Result<(), String> {
    let state = RunState::load(a.state_path())?;
    let (api, token) = (a.get("api-url")?.trim_end_matches('/').to_string(), a.get("api-token")?);
    let mut client = reqwest::Client::builder().use_rustls_tls().danger_accept_invalid_certs(a.insecure).timeout(Duration::from_secs(120));
    for c in &a.ca {
        client = client.add_root_certificate(reqwest::Certificate::from_der(c).map_err(|e| e.to_string())?);
    }
    let client = client.build().map_err(|e| e.to_string())?;
    let mut removed = 0;
    for chunk in state.agents.chunks(REMOVE_CHUNK) {
        let ids = chunk.iter().map(|x| x.id.as_str()).collect::<Vec<_>>().join(",");
        let r = client.delete(format!("{api}/agents")).query(&[("agents_list", ids)]).bearer_auth(token).header("X-Tenant-Id", &state.tenant).send().await.map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!("removal refused: {}: {}", r.status(), r.text().await.unwrap_or_default()));
        }
        let v: Value = r.json().await.map_err(|e| e.to_string())?;
        removed += v["affected_agents"].as_array().map_or(0, Vec::len);
    }
    println!("removed {removed} of {} agents of run {}", state.agents.len(), state.run);
    if removed == state.agents.len() {
        std::fs::remove_file(a.state_path()).map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err(format!("{} agents left; {} kept", state.agents.len() - removed, a.state_path()))
    }
}

async fn run_args(a: &Args) -> Result<bool, String> {
    let mut complete = true;
    if a.verify {
        complete = verify(a).await?;
    }
    if a.cleanup {
        cleanup(a).await?;
    }
    if !a.verify && !a.cleanup {
        run(a).await?;
    }
    Ok(complete)
}

#[tokio::main]
async fn main() -> ExitCode {
    match Args::parse(std::env::args().skip(1)) {
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
        Ok(a) => match run_args(&a).await {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => {
                eprintln!("events are missing");
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
    }
}

#[cfg(test)]
mod tests;
