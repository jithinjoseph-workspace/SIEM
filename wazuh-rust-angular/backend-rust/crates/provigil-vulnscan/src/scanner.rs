//! The running scanner: start sequence, policy changes, event and delayed threads, feed
//! callback, router subscriptions and stop.

use crate::agentdb::AgentDb;
use crate::config::{self, ModuleConfig, UPDATER_DIR};
use crate::event::{pad_agent, Event, Origin};
use crate::feed::FeedDb;
use crate::json::{compact, s, Error};
use crate::kvstore::{KvStore, DEFAULT_COLUMN};
use crate::legacy_names::{CONTENT_VERSION, INDEX_PREFIX, PREBUILT_FEED_PATH};
use crate::log::Log;
use crate::lru::Lru;
use crate::queue::DurableQueue;
use crate::report::{self, Datagram, ReportQueue, ReportSink};
use crate::scan::{Core, Settings, L1_SIZE};
use crate::sink::{DocSink, StreamSpool};
use crate::updater::{Callback, StopSignal, Updater};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const POSTPONE: Duration = Duration::from_secs(60);
const START_FAILED: &str = "Vulnerability scanner start failed";
const RSYNC_SUBSCRIPTION: &str = "Inventory sync subscription failed";
const EVENT_FAILED: &str = "Event processing failed";
const DELAYED_FAILED: &str = "Delayed event processing failed";
const NOT_READY: &str = "Agent data not ready";
const INCOMPLETE: &str = "Agent re-scan incomplete";

/// The manager's local message router.
// shortcut: the router owns the binary delta/sync message schemas; its adapter delivers each
// message already converted to JSON (malformed buffers dropped there). Upgrade when the router
// library exposes its schemas to this crate.
pub trait Router: Send + Sync {
    fn subscribe(&self, topic: &str, subscriber_id: &str, cb: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String>;
}

/// Publish frame on `queue/router/<topic>`: u32 LE size of what follows, u32 LE header size
/// (1), header `P`, body.
pub fn router_publish_frame(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(body.len() + 9);
    v.extend_from_slice(&((body.len() + 5) as u32).to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.push(b'P');
    v.extend_from_slice(body);
    v
}


/// The core, set once the start sequence has opened everything; the feed callback waits for it.
#[derive(Default)]
pub struct CoreSlot {
    core: Mutex<Option<Arc<Mutex<Core>>>>,
    ready: std::sync::Condvar,
}

impl CoreSlot {
    pub fn set(&self, c: Arc<Mutex<Core>>) {
        *self.core.lock().unwrap() = Some(c);
        self.ready.notify_all();
    }

    /// Waits until the core is set; `None` when stopped first.
    pub fn wait(&self, stop: &StopSignal) -> Option<Arc<Mutex<Core>>> {
        let mut g = self.core.lock().unwrap();
        loop {
            if let Some(c) = g.as_ref() {
                return Some(c.clone());
            }
            if stop.is_set() {
                return None;
            }
            g = self.ready.wait_timeout(g, Duration::from_millis(100)).unwrap().0;
        }
    }
}
pub struct StartOptions {
    pub agent_db: Arc<dyn AgentDb>,
    /// Collector for tests; `None` creates the scanner's own report dispatcher.
    pub report_sink: Option<Arc<dyn ReportSink>>,
    /// Report socket endpoint; `None` uses the platform default.
    pub report_socket: Option<Box<dyn Datagram>>,
    pub manager_name: String,
    pub content_updater: bool,
    pub router: Option<Arc<dyn Router>>,
    /// Stream adapter, used when the stream environment is set.
    pub stream: Option<Arc<dyn StreamSpool>>,
    /// Starts the event and delayed threads (tests drive the queues by hand).
    pub threads: bool,
}

pub struct Scanner {
    pub core: Arc<Mutex<Core>>,
    pub events: Arc<DurableQueue>,
    pub delayed: Arc<DurableQueue>,
    postponed: Arc<Mutex<HashMap<String, Instant>>>,
    stop: Arc<StopSignal>,
    updater: Option<Updater>,
    /// The router handle (and so every subscription), owned until the scanner is stopped.
    router: Arc<Mutex<Option<Arc<dyn Router>>>>,
    log: Log,
}

#[derive(Default, Debug, PartialEq)]
struct Actions {
    agents_rescan: bool,
    manager: Option<&'static str>,
}

fn state_of(b: bool) -> &'static str {
    if b {
        "enabled"
    } else {
        "disabled"
    }
}

/// Policy changes between runs (3.5). Returns `None` when the module is disabled.
fn policy(store: &KvStore, enabled: bool, cfg: &ModuleConfig, log: &Log) -> Option<Actions> {
    let get = |k: &str| store.get_text(DEFAULT_COLUMN, k).ok().flatten();
    let put = |k: &str, v: &str| {
        let _ = store.put_text(DEFAULT_COLUMN, k, v);
    };
    let mut a = Actions::default();
    if get("vulnerability_scanner_previous_state").as_deref() == Some("disabled") && enabled {
        vs!(log, Debug, "Vulnerability scanner module was re-enabled (agents re-scan needed)");
        a.agents_rescan = true;
    }
    put("vulnerability_scanner_previous_state", state_of(enabled));
    if !enabled {
        return None;
    }
    let manager_now = state_of(!cfg.manager_disabled_scan);
    match (get("manager_scan_previous_state").as_deref(), manager_now) {
        (Some("enabled"), "disabled") => {
            vs!(log, Debug, "Vulnerability scanner in manager disabled (manager clean-up needed)");
            a.manager = Some("cleanup");
        }
        (Some("disabled"), "enabled") => {
            vs!(log, Debug, "Vulnerability scanner in manager enabled (manager re-scan needed)");
            a.manager = Some("rescan");
        }
        (Some("disabled"), "disabled") => {
            vs!(log, Debug, "Vulnerability scanner in manager still disabled");
            a.manager = Some("none");
        }
        _ => {}
    }
    put("manager_scan_previous_state", manager_now);
    if get("cluster_previous_name").is_some_and(|v| v != cfg.cluster_name) {
        vs!(log, Debug, "Cluster name changed (agents re-scan needed)");
        a.agents_rescan = true;
    }
    put("cluster_previous_name", &cfg.cluster_name);
    let cluster_now = state_of(cfg.cluster_enabled);
    if get("cluster_previous_state").is_some_and(|v| v != cluster_now) {
        vs!(log, Debug, "Cluster was enabled/disabled (agents re-scan needed)");
        a.agents_rescan = true;
    }
    put("cluster_previous_state", cluster_now);
    if get("cluster_node_name").is_some_and(|v| v != cfg.cluster_node_name) && !matches!(a.manager, Some("cleanup") | Some("none")) {
        vs!(log, Debug, "Cluster node name changed (manager re-scan needed)");
        a.manager = Some("rescan");
    }
    put("cluster_node_name", &cfg.cluster_node_name);
    Some(a)
}

fn push_actions(a: &Actions, cluster_enabled: bool, q: &DurableQueue, log: &Log) {
    let push = |v: Value| {
        vs!(log, Debug2, "actionData: {}", compact(&v));
        q.push("", &Event::json(v).encode());
    };
    if a.agents_rescan {
        vs!(log, Info, "Policy changed. Performing re-scan over all agents.");
        push(json!({"action":"reboot","no-index":cluster_enabled}));
    } else {
        vs!(log, Debug2, "No policy has changed or no action is needed for the agents.");
    }
    if a.manager == Some("rescan") && !a.agents_rescan {
        vs!(log, Info, "Policy changed. Performing re-scan over the manager.");
        push(json!({"action":"scanAgent","agent_info":{"agent_id":"000"}}));
    } else if a.manager == Some("cleanup") {
        vs!(log, Info, "Policy changed. Performing clean-up over the manager.");
        push(json!({"action":"deleteAgent","agent_info":{"agent_id":"000"}}));
    } else {
        vs!(log, Debug2, "No policy has changed or no action is needed for the manager.");
    }
}

impl Scanner {
    /// Start entry point. `None` when the module is disabled or the start failed.
    pub fn start(home: &Path, log: Log, mut cfg: ModuleConfig, opts: StartOptions) -> Option<Scanner> {
        vs!(log, Info, "Starting vulnerability_scanner module.");
        for (k, v) in [("enabled", "yes"), ("index-status", "yes"), ("feed-update-interval", "60m")] {
            cfg.vd.entry(k).or_insert_with(|| v.into());
        }
        vs!(log, Debug, "{}", cfg.debug_json());
        match Self::start_inner(home, &log, cfg, opts) {
            Ok(s) => s,
            Err(e) => {
                vs!(log, Error, "{START_FAILED}: {e}.");
                None
            }
        }
    }

    fn start_inner(home: &Path, log: &Log, mut cfg: ModuleConfig, opts: StartOptions) -> Result<Option<Scanner>, String> {
        let params = config::validate(&mut cfg, log)?;
        let p = |rel: &str| -> PathBuf { home.join(rel) };
        let state = KvStore::open(&p("queue/vd/state_track"))?;
        let enabled = match cfg.get("enabled") {
            Some("yes") => true,
            Some("no") => false,
            _ => return Err("Invalid input.".into()),
        };
        let Some(actions) = policy(&state, enabled, &cfg, log) else {
            vs!(log, Info, "Vulnerability scanner module is disabled.");
            return Ok(None);
        };
        let index = format!("{INDEX_PREFIX}{}", cfg.cluster_name.to_ascii_lowercase());
        // Without a stream adapter the stream cannot be opened: the local mode is used.
        let stream = if crate::sink::stream_env() { opts.stream.clone() } else { None };
        let sink = DocSink::open(home, &index, stream, log.clone())?;
        // The sender runs for the life of the process.
        let sender_stop = Arc::new(AtomicBool::new(false));
        let reports: Arc<dyn ReportSink> = match opts.report_sink.clone() {
            Some(r) => r,
            None => {
                let q = Arc::new(DurableQueue::open(&p("queue/vd/reports"))?);
                let dg: Box<dyn Datagram> = opts.report_socket.unwrap_or_else(|| report::local_datagram(home));
                report::spawn_sender(q.clone(), dg, cfg.wm_max_eps, sender_stop.clone(), log.clone());
                Arc::new(ReportQueue::new(q, cfg.report_queue_size))
            }
        };
        let events = Arc::new(DurableQueue::open(&p("queue/vd/event"))?);
        push_actions(&actions, cfg.cluster_enabled, &events, log);

        if let Ok(Some(v)) = state.get_text(DEFAULT_COLUMN, "installed_content") {
            vs!(log, Debug, "Database version: {v}");
        }
        let installed = state.get_text(DEFAULT_COLUMN, "installed_content").ok().flatten();
        if installed.as_deref() != Some(CONTENT_VERSION) && p("tmp").is_dir() && !p(PREBUILT_FEED_PATH).exists() {
            vs!(log, Debug2, "No database compressed file found at '{PREBUILT_FEED_PATH}'. Skipping decompression.");
        }

        FeedDb::recover(&p("queue/vd/feed"));
        let mut feed = FeedDb::open(home, &p("queue/vd/feed"))?;
        if let Err(e) = feed.load_maps(cfg.translation_lru_size) {
            let _ = std::fs::remove_dir_all(p(UPDATER_DIR));
            vs!(log, Error, "Error opening the database: {e}.");
        }
        // The updater starts before the rest is opened (2.5 order); its callback waits for the core.
        let slot = Arc::new(CoreSlot::default());
        let stop = Arc::new(StopSignal::default());
        let updater = if opts.content_updater {
            let cb = Self::feed_callback(slot.clone(), events.clone(), stop.clone(), cfg.cluster_enabled, log.clone());
            Some(Updater::create(home, &params, cb, stop.clone(), log.clone())?)
        } else {
            None
        };
        let opened = (|| -> Result<_, String> {
            let inventory = crate::inventory::open(&p("queue/vd/inventory"))?;
            let delayed = Arc::new(DurableQueue::open(&p("queue/vd/delayed"))?);
            let job = Arc::new(DurableQueue::open(&p("queue/vd/rescan"))?);
            Ok((inventory, delayed, job))
        })();
        let (inventory, delayed, job) = match opened {
            Ok(x) => x,
            Err(e) => {
                if let Some(u) = &updater {
                    u.stop();
                }
                return Err(e);
            }
        };
        let core = Arc::new(Mutex::new(Core {
            log: log.clone(),
            feed,
            inventory,
            agent_db: opts.agent_db.clone(),
            os_cache: Lru::new(cfg.osdata_lru_size),
            hotfix_cache: Lru::new(cfg.remediation_lru_size),
            l1: [Lru::new(L1_SIZE), Lru::new(L1_SIZE), Lru::new(L1_SIZE)],
            sink,
            reports,
            delayed: delayed.clone(),
            job,
            collect: None,
            missing_agent: Default::default(),
            settings: Settings {
                manager_name: if opts.manager_name.is_empty() { "manager".into() } else { opts.manager_name.clone() },
                cluster_enabled: cfg.cluster_enabled,
                cluster_name: cfg.cluster_name.clone(),
                node_name: cfg.cluster_node_name.clone(),
                manager_disabled_scan: cfg.manager_disabled_scan,
                translation_cap: cfg.translation_lru_size,
            },
        }));
        slot.set(core.clone());
        let s = Scanner { core, events, delayed, postponed: Arc::default(), stop, updater, router: Arc::default(), log: log.clone() };
        if opts.threads {
            s.spawn_threads();
        }
        vs!(log, Info, "Vulnerability scanner module started.");
        if let Some(r) = &opts.router {
            s.subscribe(r.as_ref());
            *s.router.lock().unwrap() = Some(r.clone());
        }
        Ok(Some(s))
    }

    /// The feed-processing callback (6.8).
    pub fn feed_callback(slot: Arc<CoreSlot>, events: Arc<DurableQueue>, stop: Arc<StopSignal>, cluster_enabled: bool, log: Log) -> Callback {
        Arc::new(move |msg: &str| {
            vs!(log, Info, "Initiating update feed process.");
            let Some(core) = slot.wait(&stop) else { return (0, String::new(), false) };
            let m = match serde_json::from_str::<Value>(msg) {
                Ok(m) => m,
                Err(e) => {
                    vs!(log, Error, "Error updating feed: JSON parse error: {e}.");
                    return (0, String::new(), false);
                }
            };
            let (mut c, r) = if FeedDb::is_full_rebuild(&m) {
                // a full rebuild is built beside the feed without holding the core, so scans go
                // on; it is switched in at once when complete, and a stopped or failed one leaves
                // the current feed as it was
                vs!(log, Info, "Building the full feed beside the current one; scans continue meanwhile.");
                let (home, dir) = core.lock().unwrap().feed.location();
                match crate::feed::build_full(&home, &dir, &m, stop.flag(), &log) {
                    Ok((built, r)) => {
                        let mut c = core.lock().unwrap();
                        let switched = c.feed.switch_to(built).map(|_| r);
                        (c, switched)
                    }
                    Err(e) => (core.lock().unwrap(), Err(e)),
                }
            } else {
                let c = core.lock().unwrap();
                c.feed.take_changes();
                let r = c.feed.apply_message(&m, stop.flag(), &log);
                (c, r)
            };
            let (offset, hash, ok) = match r {
                Ok(x) => x,
                Err(e) => {
                    vs!(log, Error, "Error updating feed: {e}.");
                    return (0, String::new(), false);
                }
            };
            if stop.is_set() || !ok {
                vs!(log, Debug2, "Feed update process interrupted or failed. Offset: {offset}, Hash: {hash}.");
                return (offset, hash, ok);
            }
            let cap = c.settings.translation_cap;
            if let Err(e) = c.feed.load_maps(cap) {
                vs!(log, Error, "Error updating feed: {e}.");
                return (0, String::new(), false);
            }
            if c.feed.take_changes() == 0 {
                vs!(log, Info, "Feed update changed no vulnerability data; no re-scan.");
            } else {
                events.push("", &Event::json(json!({"action":"reboot","no-index":cluster_enabled})).encode());
                vs!(log, Info, "Triggered a re-scan after content update.");
            }
            vs!(log, Info, "Feed update process completed.");
            (offset, hash, ok)
        })
    }

    fn spawn_threads(&self) {
        let (s1, s2) = (self.handle(), self.handle());
        std::thread::spawn(move || {
            while !s1.stop.is_set() {
                s1.work_step(Duration::from_secs(1));
            }
        });
        std::thread::spawn(move || {
            while !s2.stop.is_set() {
                if !s2.delayed_step() {
                    s2.stop.wait(Duration::from_secs(1));
                }
            }
        });
    }

    /// A handle sharing the scanner's queues and state (for the threads).
    fn handle(&self) -> Scanner {
        Scanner {
            core: self.core.clone(),
            events: self.events.clone(),
            delayed: self.delayed.clone(),
            postponed: self.postponed.clone(),
            stop: self.stop.clone(),
            updater: None,
            router: self.router.clone(),
            log: self.log.clone(),
        }
    }

    fn subscribe(&self, r: &dyn Router) {
        if !cfg!(any(target_os = "linux", windows)) {
            return;
        }
        let log = self.log.clone();
        let fail = |e: String| vs!(log, Error, "{START_FAILED}: {e}.");
        let q = self.events.clone();
        let push = move |q: &DurableQueue, origin: Origin, v: Value| {
            q.push("", &Event { origin, body: v }.encode());
        };
        let (q1, q2, q3, q4) = (q.clone(), q.clone(), q.clone(), q);
        if let Err(e) = r.subscribe("deltas-syscollector", "vulnerability_scanner_deltas", Box::new(move |v| {
            if matches!(s(&v, "data_type"), "dbsync_osinfo" | "dbsync_packages" | "dbsync_hotfixes") {
                push(&q1, Origin::Delta, v);
            }
        })) {
            fail(e);
        }
        let l2 = self.log.clone();
        if let Err(e) = r.subscribe("rsync", "vulnerability_scanner_rsync", Box::new(move |v| {
            if !matches!(s(&v, "data_type"), "state" | "integrity_clear" | "integrity_check_global") {
                return;
            }
            match v.pointer("/data/attributes_type").and_then(Value::as_str) {
                // Only integrity messages report a missing type; a state message is dropped silently.
                None if s(&v, "data_type") != "state" => vs!(l2, Error, "{RSYNC_SUBSCRIPTION}: attributes_type is null"),
                Some("syscollector_packages" | "syscollector_hotfixes" | "syscollector_osinfo") => push(&q2, Origin::Rsync, v),
                _ => {}
            }
        })) {
            fail(e);
        }
        if let Err(e) = r.subscribe("wdb-agent-events", "vulnerability_scanner_database", Box::new(move |v| push(&q3, Origin::Json, v))) {
            fail(e);
        }
        if let Err(e) = r.subscribe("wdb-inventory-events", "vulnerability_scanner_database", Box::new(move |v| {
            if matches!(s(&v, "action"), "deletePackage" | "deleteHotfix") {
                push(&q4, Origin::Json, v);
            }
        })) {
            fail(e);
        }
    }

    // ---- entry points -------------------------------------------------------------------------

    /// Appends an event to the persistent queue and wakes the event thread.
    pub fn push_event(&self, ev: &Event) {
        self.events.push("", &ev.encode());
    }

    pub fn change_interval(&self, secs: u64) {
        if let Some(u) = &self.updater {
            u.change_interval(secs);
        }
    }

    pub fn stop(&self) {
        vs!(self.log, Info, "Stopping vulnerability_scanner module.");
        // Releasing the router handle ends the subscriptions.
        self.router.lock().unwrap().take();
        self.stop.set();
        if let Some(u) = &self.updater {
            u.stop();
        }
    }

    pub fn queued(&self) -> usize {
        self.events.len()
    }

    /// Removes and returns the oldest queued event.
    pub fn take_next(&self) -> Option<Event> {
        let (seq, _, item) = self.events.front(|_| true)?;
        self.events.remove(seq);
        Event::decode(&item)
    }


    /// One step of the event thread: real-time events first; when none is waiting, one agent
    /// of the background re-scan job; otherwise wait up to `wait` for an event.
    pub fn work_step(&self, wait: Duration) -> bool {
        if !self.events.is_empty() {
            return self.event_step(Duration::ZERO);
        }
        let job = self.core.lock().unwrap().job.clone();
        if !job.is_empty() {
            return self.core.lock().unwrap().job_step();
        }
        self.event_step(wait)
    }
    /// Event thread step: waits up to `wait` for an event, processes it, removes it.
    pub fn event_step(&self, wait: Duration) -> bool {
        let Some((seq, _, item)) = self.events.wait_front(wait) else { return false };
        if let Some(ev) = Event::decode(&item) {
            self.process_event(&ev);
        }
        self.events.remove(seq);
        true
    }

    /// Processes one normal event and handles its result (7.7).
    pub fn process_event(&self, ev: &Event) {
        let r = self.core.lock().unwrap().process(ev, false);
        match r {
            Ok(()) => {}
            Err(Error::NotReady { agent, text }) => {
                vs!(self.log, Debug2, "{NOT_READY} (Agent {agent}). Reason: {text}");
                self.delayed.push(&agent, &ev.encode());
            }
            Err(Error::Incomplete { agents, no_index }) => {
                vs!(self.log, Debug2, "{INCOMPLETE}. Reason: Error executing rescan for multiple agents.");
                for a in agents {
                    self.delayed.push(&a, &Self::scan_agent(&a, no_index).encode());
                }
            }
            Err(Error::Json { id, text }) => vs!(self.log, Error, "{EVENT_FAILED}: json exception [{id}]({text}) - Event message: {}", compact(&ev.body)),
            Err(Error::Other(t)) => vs!(self.log, Error, "{EVENT_FAILED}: {t}."),
        }
    }

    fn scan_agent(agent: &str, no_index: bool) -> Event {
        Event::json(json!({"action":"scanAgent","agent_info":{"agent_id":agent},"no-index":no_index}))
    }

    /// Delayed thread step; false when nothing could be processed.
    pub fn delayed_step(&self) -> bool {
        loop {
            let now = Instant::now();
            let postponed = self.postponed.lock().unwrap().clone();
            let Some((seq, _, item)) = self.delayed.front(|p| postponed.get(p).is_none_or(|t| *t <= now)) else { return false };
            let Some(ev) = Event::decode(&item) else {
                self.delayed.remove(seq);
                continue;
            };
            let r = self.core.lock().unwrap().process(&ev, true);
            match r {
                Ok(()) => self.delayed.remove(seq),
                Err(Error::NotReady { agent, .. }) => {
                    self.postponed.lock().unwrap().insert(agent.clone(), Instant::now() + POSTPONE);
                    vs!(self.log, Debug2, "Postponed delayed event for agent {agent}");
                }
                Err(Error::Incomplete { agents, no_index }) => {
                    self.delayed.remove(seq);
                    vs!(self.log, Debug2, "{INCOMPLETE}. Reason: Error executing rescan for multiple agents.");
                    for a in agents {
                        self.delayed.push(&a, &Self::scan_agent(&a, no_index).encode());
                        self.postponed.lock().unwrap().insert(a, Instant::now() + POSTPONE);
                    }
                }
                Err(Error::Json { id, text }) => {
                    self.delayed.remove(seq);
                    vs!(self.log, Error, "{DELAYED_FAILED}: json exception [{id}]({text}) - Event message: {}", compact(&ev.body));
                }
                Err(Error::Other(t)) => {
                    self.delayed.remove(seq);
                    vs!(self.log, Error, "Error processing delayed event: {t}.");
                }
            }
            return true;
        }
    }

    pub fn is_postponed(&self, agent: &str) -> bool {
        self.postponed.lock().unwrap().get(&pad_agent(agent)).is_some_and(|t| *t > Instant::now())
    }
}

