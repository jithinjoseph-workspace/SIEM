//! The running service (spec sections 2.1 to 2.3, 2.9, 2.22): loading the ruleset, the input
//! queue, decoding (database decoders on worker threads), rule matching, the writers (alert,
//! archive and firewall files with daily folders and rotation, or siem-api's stream), hourly
//! statistics, the labels cache, active responses, the analysis and logtest sockets.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use provigil_ipc::agentdb::{parse_answer, DbError, DbQuery, DbSocket, Status, DB_SOCKET};
use provigil_ipc::platform_stream::{self as stream, Stream};
use provigil_json::Json;

use crate::builtin::{self, Builtin, DbDecoders, DbSettings, Decoded, Workers};
use crate::config::{Config, Response, Socket};
use crate::engine::{Engine, EngineSettings};
use crate::event::*;
use crate::host::Host;
use crate::limits::Limits;
use crate::logtest::{self, Logtest};
use crate::messages::{Level, Messages};
use crate::process::{stats_rule, Options, Outcome, Stats as HourStats};
use crate::queues::{self, InQueues, Kind, KINDS};
use crate::responses::{AgentVersion, ResponseSink, WhiteList};
use crate::rules::RuleSettings;
use crate::stats::{Component, Queues, QueueUse, Stats};

pub const NAME: &str = "provigil-analysisd";
const MAX_MESSAGE: usize = 65536;
/// Threads for the decoders that wait on provigil-db.
const DB_WORKERS: usize = 4;

// ---------------------------------------------------------------- logging

/// The service log: `logs/ossec.log`, and stderr while not running in the background (the
/// settings check of siem-api reads it).
pub struct ServiceLog {
    log: provigil_daemon::Log,
    echo: AtomicBool,
}

impl ServiceLog {
    pub fn new(log: provigil_daemon::Log, echo: bool) -> ServiceLog {
        ServiceLog { log, echo: AtomicBool::new(echo) }
    }

    pub fn set_debug(&self, level: u8) {
        self.log.set_debug(level);
    }

    pub fn debug_level(&self) -> u8 {
        self.log.debug_level()
    }

    /// No more lines on stderr (the service went to the background).
    pub fn quiet(&self) {
        self.echo.store(false, Ordering::SeqCst);
    }

    pub fn log(&self, level: &str, msg: impl AsRef<[u8]>) {
        let msg = msg.as_ref();
        if self.echo.load(Ordering::SeqCst) && self.log.enabled(level) && level != "CRITICAL" {
            let shown = if level == "DEBUG2" { "DEBUG" } else { level };
            eprintln!("{} {NAME}: {shown}: {}", chrono::Local::now().format("%Y/%m/%d %H:%M:%S"), String::from_utf8_lossy(msg));
        }
        self.log.write(level, msg);
    }
}

// ---------------------------------------------------------------- output files

#[derive(Default)]
struct LogFile {
    out: Option<BufWriter<File>>,
    path: PathBuf,
    counter: i32,
    written: u64,
}

impl LogFile {
    fn write(&mut self, data: &[u8]) {
        if let Some(f) = &mut self.out {
            if f.write_all(data).is_ok() {
                self.written += data.len() as u64;
            }
        }
    }
    fn flush(&mut self) {
        if let Some(f) = &mut self.out {
            let _ = f.flush();
        }
    }
}

/// One output file: `<dir>/<year>/<Mon>/ossec-<tag>-<dd>[-nnn].<ext>` with `link` pointing at
/// it. A file left empty is removed when replaced; `rotate` opens the next numbered one; a
/// day's file over `max_size` continues in the next free number.
#[allow(clippy::too_many_arguments)]
fn open_output(f: &mut LogFile, home: &Path, dir: &str, year: i32, month: &str, tag: &str, day: i32, ext: &str, link: &str, rotate: bool, max_size: i64) -> std::io::Result<()> {
    if let Some(mut old) = f.out.take() {
        let _ = old.flush();
        if f.written == 0 {
            let _ = std::fs::remove_file(&f.path);
        }
    }
    let month_dir = home.join(format!("{dir}/{year}")).join(month);
    std::fs::create_dir_all(&month_dir)?;
    let numbered = |n: i32| month_dir.join(format!("ossec-{tag}-{day:02}-{n:03}.{ext}"));
    let mut path;
    if rotate {
        f.counter += 1;
        path = numbered(f.counter);
    } else {
        path = month_dir.join(format!("ossec-{tag}-{day:02}.{ext}"));
        f.counter = 0;
        loop {
            let too_big = max_size != 0 && std::fs::metadata(&path).map_or(-1, |m| m.len() as i64) > max_size;
            if !(numbered(f.counter + 1).is_file() || too_big) {
                break;
            }
            path = numbered(f.counter + 1);
            f.counter += 1;
        }
    }
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    f.written = file.metadata().map_or(0, |m| m.len());
    f.out = Some(BufWriter::new(file));
    f.path = path.clone();
    let link = home.join(link);
    let _ = std::fs::remove_file(&link);
    std::fs::hard_link(&path, &link)
}

/// archives.log, archives.json, alerts.log, alerts.json, firewall.log.
#[derive(Default)]
pub struct Outputs {
    archives: LogFile,
    archives_json: LogFile,
    alerts: LogFile,
    alerts_json: LogFile,
    firewall: LogFile,
    opened_at: i64,
    /// siem-api's stream carries alerts and events: no files.
    pub stream: bool,
}

type Spec = (&'static str, &'static str, &'static str, &'static str);
const SPECS: [Spec; 5] = [
    ("logs/archives", "archive", "log", "logs/archives/archives.log"),
    ("logs/archives", "archive", "json", "logs/archives/archives.json"),
    ("logs/alerts", "alerts", "log", "logs/alerts/alerts.log"),
    ("logs/alerts", "alerts", "json", "logs/alerts/alerts.json"),
    ("logs/firewall", "firewall", "log", "logs/firewall/firewall.log"),
];

impl Outputs {
    fn all(&mut self) -> [&mut LogFile; 5] {
        [&mut self.archives, &mut self.archives_json, &mut self.alerts, &mut self.alerts_json, &mut self.firewall]
    }

    /// The day's files.
    pub fn open_day(&mut self, home: &Path, g: &crate::config::Global, day: i32, year: i32, mon: &str, now: i64) -> std::io::Result<()> {
        if !self.stream {
            let wanted = [true, g.logall_json, true, g.jsonout_output, true];
            for (i, f) in self.all().into_iter().enumerate() {
                if wanted[i] {
                    let (dir, tag, ext, link) = SPECS[i];
                    open_output(f, home, dir, year, mon, tag, day, ext, link, false, g.max_output_size)?;
                }
            }
        }
        self.opened_at = now;
        Ok(())
    }

    /// Rotation by `<rotate_interval>` or by `<max_output_size>`.
    pub fn rotate(&mut self, home: &Path, g: &crate::config::Global, day: i32, year: i32, mon: &str, now: i64) {
        if self.stream {
            return;
        }
        let max = g.max_output_size;
        if g.rotate_interval != 0 && now - self.opened_at > i64::from(g.rotate_interval) {
            for (i, f) in self.all().into_iter().enumerate() {
                if f.out.is_some() && f.written > 0 {
                    let (dir, tag, ext, link) = SPECS[i];
                    let _ = open_output(f, home, dir, year, mon, tag, day, ext, link, true, max);
                }
            }
            self.opened_at = now;
        } else if max != 0 && now - self.opened_at > i64::from(g.min_rotate_interval) {
            let mut rotated = false;
            for (i, f) in self.all().into_iter().enumerate() {
                if f.out.is_some() && f.written as i64 > max {
                    let (dir, tag, ext, link) = SPECS[i];
                    let _ = open_output(f, home, dir, year, mon, tag, day, ext, link, true, max);
                    rotated = true;
                }
            }
            if rotated {
                self.opened_at = now;
            }
        }
    }

    pub fn flush(&mut self) {
        for f in self.all() {
            f.flush();
        }
    }
}

// ---------------------------------------------------------------- statistics files

const WEEKLY: &str = "stats/weekly-average";
const HOURLY: &str = "stats/hourly-average";
const TOTALS: &str = "stats/totals";

fn read_count(p: &Path) -> i32 {
    std::fs::read_to_string(p).map_or(0, |s| crate::rules::atoi(s.trim_start()).max(0))
}

/// The learned averages from the statistics folders (created when missing).
fn load_averages(home: &Path, st: &mut HourStats) -> std::io::Result<()> {
    for d in [WEEKLY, HOURLY, TOTALS] {
        std::fs::create_dir_all(home.join(d))?;
    }
    for i in 0..=24 {
        st.chour[i] = 0;
        st.rhour[i] = read_count(&home.join(format!("{HOURLY}/{i}")));
    }
    for i in 0..=6 {
        std::fs::create_dir_all(home.join(format!("{WEEKLY}/{i}")))?;
        for j in 0..=24 {
            st.cwhour[i][j] = 0;
            st.rwhour[i][j] = read_count(&home.join(format!("{WEEKLY}/{i}/{j}")));
        }
    }
    Ok(())
}

fn totals_file(home: &Path, year: i32, mon: &str, day: i32) -> std::io::Result<File> {
    let d = home.join(format!("{TOTALS}/{year}/{mon}"));
    std::fs::create_dir_all(&d)?;
    OpenOptions::new().create(true).append(true).open(d.join(format!("ossec-totals-{day:02}.log")))
}

// ---------------------------------------------------------------- labels

/// Agent labels from provigil-db's JSON list: `"key"`, `!"key"` (hidden), `#"key"`
/// (system); a later duplicate does not replace.
pub fn labels_of(json: &Json) -> Vec<Label> {
    let mut out: Vec<Label> = Vec::new();
    for item in json.children() {
        let (Some(Json::String(k)), Some(Json::String(v))) = (item.get_exact("key"), item.get_exact("value")) else { continue };
        let (start, hidden, system) = match (k.first(), k.get(1)) {
            (Some(b'!'), Some(b'"')) => (2, true, false),
            (Some(b'#'), Some(b'"')) => (2, false, true),
            (Some(b'"'), _) => (1, false, false),
            _ => continue,
        };
        let rest = &k[start..];
        let Some(end) = rest.iter().position(|&c| c == b'"') else { continue };
        let key = rest[..end].to_vec();
        if !out.iter().any(|l| l.key == key) {
            out.push(Label { key, value: v.clone(), hidden, system });
        }
    }
    out
}

type LabelMap = Arc<Mutex<HashMap<String, (Vec<Label>, i64)>>>;

/// The agents' labels: a known agent's labels are served even when older than the cache
/// age while a background task reads them again, so events never wait on provigil-db
/// except for an agent seen the first time.
struct LabelCache {
    manager: Vec<Label>,
    cache: LabelMap,
    max_age: i64,
    pending: Arc<Mutex<HashSet<String>>>,
    refresh: Option<tokio::sync::mpsc::UnboundedSender<String>>,
}

impl LabelCache {
    fn new(manager: Vec<Label>, max_age: i64, ctx: Option<&Ctx>) -> LabelCache {
        let cache: LabelMap = Arc::default();
        let pending: Arc<Mutex<HashSet<String>>> = Arc::default();
        let refresh = ctx.map(|ctx| {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let (c, p) = (cache.clone(), pending.clone());
            let db = DbSocket::new(ctx.home.join(DB_SOCKET));
            ctx.rt.spawn(async move {
                while let Some(id) = rx.recv().await {
                    if let Ok(a) = db.query(&format!("global get-labels {}", crate::rules::atoi(&id))).await {
                        if let (Status::Ok, payload) = parse_answer(&a) {
                            if let Some(j) = provigil_json::parse(payload.as_bytes()) {
                                c.lock().expect("labels").insert(id.clone(), (labels_of(&j), Instant::now().sec));
                            }
                        }
                    }
                    p.lock().expect("pending").remove(&id);
                }
            });
            tx
        });
        LabelCache { manager, cache, max_age, pending, refresh }
    }

    fn find(&mut self, ctx: &Ctx, agent: &[u8]) -> Vec<Label> {
        if agent == b"000" {
            return self.manager.clone();
        }
        let id = String::from_utf8_lossy(agent).into_owned();
        let now = Instant::now().sec;
        let cached = self.cache.lock().expect("labels").get(&id).cloned();
        if let Some((l, read)) = cached {
            if now <= read + self.max_age {
                return l;
            }
            if let Some(tx) = &self.refresh {
                if self.pending.lock().expect("pending").insert(id.clone()) {
                    let _ = tx.send(id);
                }
                return l;
            }
        }
        match ctx.db_json(&format!("global get-labels {}", crate::rules::atoi(&id))) {
            Some(j) => {
                let l = labels_of(&j);
                self.cache.lock().expect("labels").insert(id, (l.clone(), now));
                l
            }
            None => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------- the environment

/// Shared handles of the running service.
pub struct Ctx {
    pub home: PathBuf,
    pub rt: tokio::runtime::Handle,
    pub db: Arc<dyn DbQuery>,
    pub log: Arc<ServiceLog>,
}

impl Ctx {
    fn db_text(&self, q: &str) -> Option<String> {
        let (db, q) = (self.db.clone(), q.to_string());
        self.rt.block_on(async move { db.query(&q).await.ok() })
    }

    fn db_json(&self, q: &str) -> Option<Json> {
        match parse_answer(&self.db_text(q)?) {
            (Status::Ok, p) => provigil_json::parse(p.as_bytes()),
            _ => None,
        }
    }
}

/// The live environment: labels cache, response queues (kept connected) and the log.
pub struct LiveHost {
    pub ctx: Ctx,
    labels: LabelCache,
    exec: Option<provigil_ipc::aio::DatagramSender>,
    ar: Option<provigil_ipc::aio::DatagramSender>,
    provigil_ar: Option<provigil_ipc::aio::DatagramSender>,
    node: String,
}

impl LiveHost {
    fn send(&mut self, queue: &str, msg: &[u8]) {
        let path = self.ctx.home.join(queue);
        let slot = match queue {
            "queue/alerts/execq" => &mut self.exec,
            "queue/alerts/ar" => &mut self.ar,
            _ => &mut self.provigil_ar,
        };
        if slot.is_none() {
            let p = path.clone();
            *slot = self.ctx.rt.block_on(async move { provigil_ipc::aio::DatagramSender::connect(p).await.ok() });
            if slot.is_none() {
                self.ctx.log.log("ERROR", format!("(1210): Queue '{}' not accessible: 'connect failed'", queue));
                return;
            }
        }
        // the message with its final zero byte
        let wire = [msg, &[0]].concat();
        let ok = self.ctx.rt.block_on(slot.as_ref().expect("connected").send(&wire)).is_ok();
        if !ok {
            *slot = None;
            self.ctx.log.log("ERROR", format!("(1321): Error communicating with queue '{}'.", queue));
        }
    }

    /// Agents connected now, in pages from provigil-db (`node`: only this node's).
    fn agents(&mut self, mut last: i32, tail: &str) -> Option<Vec<i32>> {
        let mut out = Vec::new();
        loop {
            let a = self.ctx.db_text(&format!("global get-agents-by-connection-status {last} active{tail}"))?;
            let (st, payload) = parse_answer(&a);
            if !matches!(st, Status::Ok | Status::Due) {
                return None;
            }
            let j = provigil_json::parse(payload.as_bytes())?;
            let mut page_last = 0;
            for x in j.children() {
                if let Some(Json::Number { int, .. }) = x.get("id") {
                    out.push(*int);
                    page_last = *int;
                }
            }
            last = page_last;
            if st == Status::Ok {
                return Some(out);
            }
        }
    }
}

impl Host for LiveHost {
    fn labels(&mut self, agent: &[u8]) -> Vec<Label> {
        self.labels.find(&self.ctx, agent)
    }
    fn log(&self, level: &str, msg: &[u8]) {
        self.ctx.log.log(level, msg)
    }
    fn responses(&mut self) -> &mut dyn ResponseSink {
        self
    }
    fn agents_of_node(&mut self, last: i32, limit: i32) -> Option<Vec<i32>> {
        let tail = format!(" {} {limit}", self.node);
        self.agents(last, &tail)
    }
    fn db_query(&mut self, q: &[u8], room: usize) -> Result<Vec<u8>, i32> {
        let (db, q) = (self.ctx.db.clone(), q.to_vec());
        self.ctx.rt.block_on(async move { db.query_bytes(&q, room).await }).map_err(|e| {
            let m = match &e {
                DbError::Connect(_) => format!("Unable to connect to socket '{DB_SOCKET}'."),
                other => other.to_string(),
            };
            self.ctx.log.log("ERROR", m);
            e.code()
        })
    }
    fn send_local(&mut self, path: &str, msg: &[u8]) -> Result<(), (i32, String)> {
        let (p, m) = (self.ctx.home.join(path), msg.to_vec());
        self.ctx.rt.block_on(async move {
            let mut s = provigil_ipc::aio::LocalStream::connect(&p).await.map_err(|e| {
                let (n, t) = crate::messages::os_error(&e);
                (n, t.to_string())
            })?;
            let _ = provigil_ipc::aio::framing::send(&mut s, &m).await;
            Ok(())
        })
    }
    fn send_queue(&mut self, path: &str, msg: &[u8]) -> bool {
        let p = self.ctx.home.join(path);
        let m = [msg, &[0]].concat();
        let r = self.ctx.rt.block_on(async move { provigil_ipc::aio::DatagramSender::connect(&p).await?.send(&m).await });
        if let Err(e) = &r {
            self.ctx.log.log("WARNING", format!("(1210): Queue '{path}' not accessible: '{}'", crate::messages::os_error(e).1));
        }
        r.is_ok()
    }
    fn db_json(&mut self, q: &str) -> Option<Json> {
        let Some(a) = self.ctx.db_text(q) else {
            self.ctx.log.log("ERROR", format!("Unable to connect to socket '{DB_SOCKET}'"));
            return None;
        };
        match parse_answer(&a) {
            (Status::Ok, p) => provigil_json::parse(p.as_bytes()),
            (Status::Error, p) => {
                self.ctx.log.log("ERROR", format!("Bad response from provigil-db: {p}"));
                None
            }
            _ => None,
        }
    }
}

impl ResponseSink for LiveHost {
    fn agent_version(&mut self, agent: i32) -> AgentVersion {
        let labels = self.labels.find(&self.ctx, format!("{agent:03}").as_bytes());
        // the version label agents report under (protocol name)
        if let Some(l) = labels.iter().find(|l| l.key == b"_wazuh_version") {
            return AgentVersion::Found(String::from_utf8_lossy(&l.value).into_owned());
        }
        let Some(j) = self.ctx.db_json(&format!("global get-agent-info {agent}")) else { return AgentVersion::NoInfo };
        match j.children().into_iter().next().and_then(|f| f.get("version")) {
            Some(Json::String(v)) => AgentVersion::Found(String::from_utf8_lossy(v).into_owned()),
            _ => AgentVersion::NoVersion,
        }
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        self.agents(0, "")
    }
    fn node_name(&mut self) -> String {
        self.node.clone()
    }
    fn send_exec(&mut self, msg: &[u8]) {
        self.send("queue/alerts/execq", msg)
    }
    fn send_ar(&mut self, msg: &[u8]) {
        self.send("queue/alerts/ar", msg)
    }
    fn send_provigil_ar(&mut self, msg: &[u8]) {
        self.send(provigil_ipc::queue::AGENT_AR_QUEUE, msg)
    }
}

// ---------------------------------------------------------------- the service

pub struct Service {
    pub cfg: Config,
    pub engine: Engine,
    pub hours: HourStats,
    pub stats_rule: Option<RuleId>,
    pub outputs: Outputs,
    builtin: Builtin,
    whitelist: WhiteList,
    forwarder: Option<Forwarder>,
    stream: Option<Stream>,
    /// the alert id's second part when streaming: the bytes streamed
    streamed: i64,
    fts_file: Option<File>,
    today: i32,
    this_hour: i32,
    year: i32,
    month: String,
    hourly_events: u64,
    hourly_syscheck: u64,
    hourly_firewall: u64,
    node: String,
    pub stats: Stats,
    /// For siem-api's back pressure: [0] datagrams from siem-api, [1] the fullest queue's
    /// usage (f32 bits), [2 + n] datagrams from gateway n.
    pub load: Arc<Vec<AtomicU64>>,
    pub limits: Limits,
    inq: InQueues,
    eps_drop_reported: bool,
    eps_drop_reported_hour: bool,
    state_seconds: i32,
    limits_msg: Option<(&'static str, String)>,
    hostinfo: Option<builtin::small::HostInfo>,
    windows: builtin::windows::Windows,
    db: DbDecoders,
    workers: Option<Workers>,
}

fn engine_settings(c: &Config, short: &[u8], full: &[u8]) -> EngineSettings {
    let g = &c.global;
    EngineSettings {
        rules: RuleSettings {
            order_size: c.internal.decoder_order_size as usize,
            email_level: i32::from(g.mailbylevel),
            log_level: i32::from(g.logbylevel),
            default_timeframe: c.internal.default_timeframe,
            rule_dir: crate::config::RULE_DIR.into(),
            home: c.home.clone(),
        },
        memory_size: g.memory_size,
        fts_list_size: c.internal.fts_list_size as usize,
        fts_min_size_for_str: c.internal.fts_min_size_for_str as usize,
        manager_host: short.to_vec(),
        manager_name: full.to_vec(),
        diff_dir: c.home.join("queue/diff"),
        ignore_file: Some(c.home.join("queue/fts/ig-queue")),
        hide_cluster_info: g.hide_cluster_info,
        cluster_name: g.cluster_name.clone(),
        node_name: g.node_name.clone(),
        show_hidden_labels: g.show_hidden_labels != 0,
        mitre: None,
    }
}

/// The host name and its short form (up to the first dot).
pub fn host_names() -> (Vec<u8>, Vec<u8>) {
    let full = std::env::var("COMPUTERNAME").ok().or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string())).unwrap_or_else(|| "localhost".into());
    let short = full.split('.').next().unwrap_or("").to_string();
    (full.into_bytes(), short.into_bytes())
}

fn config_labels(c: &Config) -> Vec<Label> {
    c.labels.iter().map(|l| Label { key: l.key.as_bytes().to_vec(), value: l.value.as_bytes().to_vec(), hidden: l.hidden, system: l.system }).collect()
}

struct Now {
    sec: i64,
    day: i32,
    year: i32,
    mon: &'static str,
    hour: i32,
    wday: i32,
}

impl Service {
    /// Loads the ruleset: each file's messages are logged as it is read; the first failure
    /// stops with the critical text. `test` is `-t`.
    pub fn new(mut cfg: Config, log: &ServiceLog, test: bool) -> Result<Service, String> {
        let (full, short) = host_names();
        let mut engine = Engine::new(engine_settings(&cfg, &short, &full));
        let home = cfg.home.clone();
        let flush = |m: &mut Messages| -> bool {
            let mut error = false;
            for x in m.take() {
                match x.level {
                    Level::Warning => log.log("WARNING", &x.text),
                    Level::Error => {
                        log.log("ERROR", &x.text);
                        error = true;
                    }
                    Level::Info => {}
                }
            }
            error
        };
        let mut m = Messages::bounded();
        if cfg.ruleset.decoders.is_empty() {
            if let Err(e) = cfg.ruleset.read(&[], &home) {
                m.error(e);
            }
            flush(&mut m);
        }
        let order = engine.settings.rules.order_size;
        for f in &cfg.ruleset.decoders {
            if !test {
                log.log("DEBUG", format!("Reading decoder file {f}."));
            }
            let failed = engine.decoders.load_file(f, order, &home, &mut m) == 0;
            flush(&mut m);
            if failed {
                return Err(format!("(1202): Configuration error at '{f}'."));
            }
        }
        engine.decoders.finish(&mut m);
        if flush(&mut m) {
            return Err("(2105): Error loading decoder options.".into());
        }
        for f in &cfg.ruleset.lists {
            if !test {
                log.log("DEBUG", format!("Reading the lists file: '{f}'"));
            }
            let failed = engine.lists.load(f, &home, &mut m) < 0;
            flush(&mut m);
            if failed {
                return Err(format!("(1221): Error loading the list: '{f}'."));
            }
        }
        log.log("DEBUG", "Building CDB lists.");
        if cfg.ruleset.rules.is_empty() {
            if let Err(e) = cfg.ruleset.read(&[], &home) {
                m.error(e);
            }
            flush(&mut m);
        }
        let responses = cfg.ar.responses.clone();
        for f in &cfg.ruleset.rules {
            if !test {
                log.log("DEBUG", format!("Reading rules file: '{f}'"));
            }
            let failed = engine.rules.load_file(f, &engine.lists, &engine.decoders, &engine.settings.rules, Some(&responses), &mut m) < 0;
            flush(&mut m);
            if failed {
                return Err(format!("(1220): Error loading the rules: '{f}'."));
            }
        }
        engine.rules.set_levels();
        let mut total = 0;
        fn list(set: &crate::rules::RuleSet, nodes: &[crate::rules::RuleNode], depth: i32, log: &ServiceLog, total: &mut i32) {
            for n in nodes {
                let r = &set.rules[n.rule];
                *total += 1;
                log.log("DEBUG", format!("{depth} : rule:{}, level {}, timeout: {}", r.sigid, r.level, r.ignore_time));
                list(set, &n.children, depth + 1, log, total);
            }
        }
        list(&engine.rules, &engine.rules.tree, 0, log, &mut total);
        if !test {
            log.log("INFO", format!("Total rules enabled: '{total}'"));
        }
        let mut h = HashMap::new();
        engine.rules.hash(&mut h);
        for (k, v) in h {
            engine.rules_by_id.entry(k).or_insert(v);
        }
        let builtin = Builtin::add(&mut engine.decoders, order);
        let stats_rule = (cfg.global.stats != 0).then(|| {
            let g = &cfg.global;
            engine.rules.rules.push(Arc::new(stats_rule(i32::from(g.stats), i32::from(g.mailbylevel), i32::from(g.logbylevel))));
            engine.rules.rules.len() - 1
        });
        let whitelist = WhiteList { ips: cfg.global.white_list.clone(), hostnames: cfg.global.hostname_white_list.clone() };
        let forwarder = if cfg.global.forward_to.is_empty() { None } else { cfg.sockets.first().cloned().map(Forwarder::new) };
        let node = cfg.cluster.node_name.clone().unwrap_or_else(|| "undefined".into());
        let mut hours = HourStats { maxdiff: cfg.internal.stats_maxdiff, mindiff: cfg.internal.stats_mindiff, percent_diff: cfg.internal.stats_percent_diff, ..HourStats::default() };
        let _ = load_averages(&cfg.home, &mut hours);
        let (limits, limits_msg) = Limits::new(cfg.global.eps_maximum, cfg.global.eps_timeframe, cfg.global.eps_maximum_found);
        let q = &cfg.internal.queues;
        // Kind order: syscheck, rootcheck, sca, syscollector, hostinfo, winevt, dbsync, upgrade, event
        let sizes: [usize; KINDS] = [q[5], q[7], q[8], q[6], q[9], q[10], q[13], q[14], q[11]];
        let now = engine.clock.now().sec;
        let stream = Stream::from_env(&cfg.home.join("queue/stream-spool/analysisd"));
        let mut s = Service {
            outputs: Outputs { stream: stream.is_some(), ..Outputs::default() },
            cfg,
            engine,
            hours,
            stats_rule,
            builtin,
            whitelist,
            forwarder,
            stream,
            streamed: 0,
            fts_file: None,
            today: 0,
            this_hour: 0,
            year: 0,
            month: String::new(),
            hourly_events: 0,
            hourly_syscheck: 0,
            hourly_firewall: 0,
            node,
            stats: Stats::new(now),
            load: Arc::new((0..2 + 256).map(|_| AtomicU64::new(0)).collect()),
            limits,
            inq: InQueues::new(sizes),
            eps_drop_reported: false,
            eps_drop_reported_hour: false,
            state_seconds: 0,
            limits_msg: Some(limits_msg),
            hostinfo: None,
            windows: Default::default(),
            db: Default::default(),
            workers: None,
        };
        s.open_fts();
        Ok(s)
    }

    pub fn live_host(&self, ctx: Ctx) -> LiveHost {
        let labels = LabelCache::new(config_labels(&self.cfg), i64::from(self.cfg.internal.label_cache_maxage), Some(&ctx));
        LiveHost { ctx, labels, exec: None, ar: None, provigil_ar: None, node: self.node.clone() }
    }

    /// The MITRE table from provigil-db (shared with logtest).
    pub fn load_mitre(&mut self, host: &mut dyn Host) {
        let mut errors = Vec::new();
        let table = crate::mitre::Mitre::load(&mut |q| host.db_json(q), &mut errors);
        for e in errors {
            host.log("ERROR", e.as_bytes());
        }
        self.engine.mitre = table.map(Arc::new);
        self.engine.settings.mitre = self.engine.mitre.clone();
    }

    /// Loads the ruleset of `etc/ossec.conf` again and switches to it; true when it failed
    /// (the current one stays). `msgs` gets the load messages.
    pub fn reload(&mut self, host: &mut dyn Host, msgs: &mut Messages) -> bool {
        self.finish_decoding(host);
        let home = self.cfg.home.clone();
        let Some(rs) = crate::config::ruleset_from_file(&home.join("etc/ossec.conf"), "etc/ossec.conf", &home, false, msgs) else { return true };
        let mut engine = Engine::new(self.engine.settings.clone());
        let responses: Vec<Response> = self.cfg.ar.responses.clone();
        if !engine.load_ruleset(&rs.decoders, &rs.lists, &rs.rules, Some(&responses), msgs) {
            return true;
        }
        let order = engine.settings.rules.order_size;
        self.builtin = Builtin::add(&mut engine.decoders, order);
        if let Ok(d) = std::fs::read(home.join("queue/fts/fts-queue")) {
            engine.preload_fts(&d);
        }
        host.log("INFO", b"Reloading ruleset");
        engine.clock = std::mem::replace(&mut self.engine.clock, Box::new(crate::engine::SystemClock));
        engine.alert_counter = self.engine.alert_counter;
        engine.hourly_alerts = self.engine.hourly_alerts;
        engine.fts_lines = std::mem::take(&mut self.engine.fts_lines);
        engine.mitre = self.engine.mitre.clone();
        if let Some(sr) = self.stats_rule {
            engine.rules.rules.push(self.engine.rules.rules[sr].clone());
            self.stats_rule = Some(engine.rules.rules.len() - 1);
        }
        self.engine = engine;
        self.cfg.ruleset.decoders = rs.decoders;
        self.cfg.ruleset.rules = rs.rules;
        self.cfg.ruleset.lists = rs.lists;
        host.log("INFO", b"Ruleset reloaded successfully");
        false
    }

    pub fn init_decoders(&mut self, host: &mut dyn Host) {
        self.hostinfo = Some(builtin::small::HostInfo::open(&self.cfg.home, host));
    }

    fn now(&self) -> Now {
        let sec = self.engine.clock.now().sec;
        let t = crate::time::local(sec).unwrap_or(crate::time::Tm { year: 1970, mon: 0, mday: 1, hour: 0, min: 0, sec: 0, wday: 4, gmtoff: 0 });
        Now { sec, day: t.mday as i32, year: t.year as i32, mon: crate::time::MONTHS[t.mon as usize], hour: t.hour as i32, wday: t.wday as i32 }
    }

    fn open_fts(&mut self) {
        let dir = self.cfg.home.join("queue/fts");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("fts-queue");
        if let Ok(d) = std::fs::read(&p) {
            self.engine.preload_fts(&d);
        }
        self.fts_file = OpenOptions::new().create(true).append(true).open(&p).ok();
        let ig = dir.join("ig-queue");
        if !ig.exists() {
            let _ = File::create(&ig);
        }
    }

    /// The start time and the day's files.
    pub fn start(&mut self) -> std::io::Result<()> {
        let n = self.now();
        (self.today, self.this_hour, self.year, self.month) = (n.day, n.hour, n.year, n.mon.to_string());
        self.stats.g.uptime = n.sec as u64;
        self.outputs.open_day(&self.cfg.home, &self.cfg.global, n.day, n.year, n.mon, n.sec)
    }

    pub fn queues(&self) -> Queues {
        let q = &self.cfg.internal.queues;
        // the stages after decoding run inline: always empty
        let empty = |size: usize| QueueUse::new(size, 0);
        Queues {
            syscheck: self.inq.usage(Kind::Syscheck),
            syscollector: self.inq.usage(Kind::Syscollector),
            rootcheck: self.inq.usage(Kind::Rootcheck),
            sca: self.inq.usage(Kind::Sca),
            hostinfo: self.inq.usage(Kind::Hostinfo),
            winevt: self.inq.usage(Kind::Winevt),
            dbsync: self.inq.usage(Kind::Dbsync),
            upgrade: self.inq.usage(Kind::Upgrade),
            events: self.inq.usage(Kind::Event),
            processed: empty(q[12]),
            alerts: empty(q[1]),
            archives: empty(q[0]),
            firewall: empty(q[3]),
            fts: empty(q[4]),
            stats: empty(q[2]),
        }
    }

    pub fn write_state(&self, host: &mut dyn Host) {
        if let Err(e) = self.stats.write_file(&self.cfg.home, &self.queues()) {
            for l in e.split('\n') {
                host.log("ERROR", l.as_bytes());
            }
        }
    }

    pub fn stats_json(&self) -> Json {
        let g = &self.cfg.global;
        let eps = (g.eps_maximum > 0 && g.eps_timeframe > 0).then(|| self.limits.reached().1);
        self.stats.json(self.engine.clock.now().sec, &self.queues(), eps)
    }

    /// Once a second: EPS bookkeeping and the state file.
    pub fn second(&mut self, host: &mut dyn Host) {
        let (reached, credits) = self.limits.reached();
        if reached {
            self.stats.g.eps.seconds_over_limit += 1;
        }
        self.stats.g.eps.available_credits_prev = u64::from(credits);
        self.limits.tick();
        let interval = self.cfg.internal.state_interval;
        if interval > 0 {
            self.state_seconds += 1;
            if self.state_seconds >= interval {
                self.state_seconds = 0;
                if !self.stats.agents.is_empty() {
                    if let Some(active) = host.agents_of_node(0, -1) {
                        self.stats.keep_agents(&active);
                    }
                }
                self.write_state(host);
            }
        }
        self.pump(host);
    }

    /// Once a second: flush, hourly totals, the day's change and rotation.
    pub fn tick(&mut self, log: &ServiceLog) {
        let n = self.now();
        self.outputs.flush();
        if let Some(f) = &mut self.fts_file {
            let _ = f.flush();
        }
        if self.this_hour != n.hour {
            self.hour_totals();
            self.this_hour = n.hour;
            if self.eps_drop_reported_hour && !self.eps_drop_reported {
                self.eps_drop_reported_hour = false;
            }
            if self.today != n.day {
                if self.cfg.global.stats != 0 {
                    self.new_day();
                }
                if let Err(e) = self.outputs.open_day(&self.cfg.home, &self.cfg.global, n.day, n.year, n.mon, n.sec) {
                    log.log("CRITICAL", format!("Error allocating log files: {e}"));
                }
                (self.today, self.month, self.year) = (n.day, n.mon.to_string(), n.year);
            }
        }
        self.outputs.rotate(&self.cfg.home, &self.cfg.global, n.day, n.year, n.mon, n.sec);
    }

    /// The hour's rule counts and totals into `stats/totals/<year>/<Mon>/ossec-totals-<dd>.log`.
    fn hour_totals(&mut self) {
        let Ok(mut f) = totals_file(&self.cfg.home, self.year, &self.month, self.today) else { return };
        let mut s: String = self.engine.rule_stats(self.this_hour).into_iter().map(|l| l + "\n").collect();
        s.push_str(&format!("{}--{}--{}--{}--{}\n\n", self.this_hour, self.engine.hourly_alerts, self.hourly_events, self.hourly_syscheck, self.hourly_firewall));
        let _ = f.write_all(s.as_bytes());
        self.engine.hourly_alerts = 0;
        (self.hourly_events, self.hourly_syscheck, self.hourly_firewall) = (0, 0, 0);
    }

    fn new_day(&mut self) {
        let (hourly, weekly, totals) = self.hours.new_day();
        if let Ok(mut f) = totals_file(&self.cfg.home, self.year, &self.month, self.today) {
            let _ = f.write_all((totals.join("\n") + "\n").as_bytes());
        }
        for (i, v) in hourly {
            let _ = std::fs::write(self.cfg.home.join(format!("{HOURLY}/{i}")), v.to_string());
        }
        for (i, j, v) in weekly {
            let _ = std::fs::write(self.cfg.home.join(format!("{WEEKLY}/{i}/{j}")), v.to_string());
        }
    }

    /// The writers for one outcome; messages logged in the order the writers make them.
    fn write(&mut self, host: &mut dyn Host, out: Outcome) {
        let g = self.cfg.global.clone();
        let mut msgs = Messages::default();
        let mut lines: Vec<(&'static str, Vec<u8>)> = Vec::new();
        let drain = |msgs: &mut Messages, lines: &mut Vec<(&'static str, Vec<u8>)>| {
            for m in msgs.take() {
                lines.push((if m.level == Level::Error { "ERROR" } else { "WARNING" }, m.text.into_bytes()));
            }
        };
        let now = self.engine.clock.now().sec;
        if let Some(mut ev) = out.firewall {
            self.stats.firewall_written(ev.agent_id.as_deref(), now);
            let mut buf = Vec::new();
            let _ = crate::text_logs::firewall(&mut ev, &mut buf);
            self.outputs.firewall.write(&buf);
            self.outputs.firewall.flush();
        }
        if let Some(ev) = out.stats_alert {
            self.stats.stats_written();
            self.write_alert(&g, &ev, &mut msgs, false);
        }
        if let Some(ev) = out.alert {
            self.stats.alert_written(ev.agent_id.as_deref(), now);
            self.write_alert(&g, &ev, &mut msgs, true);
        }
        if let (Some(line), Some(p)) = (out.ignore_line, &self.engine.settings.ignore_file) {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
                let _ = f.write_all(&line);
            }
        }
        // response warnings come between the responses run, in order
        let count = out.ar.len();
        for (k, (i, ev)) in out.ar.into_iter().enumerate() {
            drain(&mut msgs, &mut lines);
            lines.extend(out.warnings.iter().filter(|(p, _)| *p == k).map(|(_, w)| ("WARNING", w.clone())));
            let r = self.cfg.ar.responses[i].clone();
            let cmd = self.cfg.ar.commands[r.command_index].clone();
            crate::responses::run(&self.engine, &ev, &r, &cmd, g.ar, &self.whitelist, host.responses(), &mut msgs);
        }
        drain(&mut msgs, &mut lines);
        lines.extend(out.warnings.iter().filter(|(p, _)| *p >= count).map(|(_, w)| ("WARNING", w.clone())));
        if let Some(ev) = out.archive {
            self.stats.archive_written(ev.agent_id.as_deref(), now);
            if let Some(st) = self.stream.as_mut() {
                if let Some(l) = crate::text_logs::json_archive(&self.engine, &ev, &mut msgs) {
                    if let Some(w) = st.send(stream::EVENT, &l) {
                        msgs.warn(w);
                    }
                }
            } else if g.logall {
                let mut buf = Vec::new();
                let _ = crate::text_logs::archive(&ev, &mut buf);
                self.outputs.archives.write(&buf);
            }
            if g.logall_json {
                if let Some(l) = crate::text_logs::json_archive(&self.engine, &ev, &mut msgs) {
                    self.outputs.archives_json.write(&l);
                }
            }
        }
        drain(&mut msgs, &mut lines);
        for (level, m) in lines {
            host.log(level, &m);
        }
        for l in std::mem::take(&mut self.engine.fts_lines) {
            self.stats.fts_written();
            if let Some(f) = &mut self.fts_file {
                let _ = f.write_all(&[l.as_slice(), b"\n"].concat());
            }
        }
    }

    /// One alert to the stream, or to alerts.log (or the custom format) and alerts.json;
    /// `forward`: also to the forwarding socket.
    fn write_alert(&mut self, g: &crate::config::Global, ev: &Event, msgs: &mut Messages, forward: bool) {
        let now = self.engine.clock.now().sec;
        if self.stream.is_some() {
            self.engine.alert_counter = self.streamed;
            let before = msgs.list.len();
            let line = crate::text_logs::json_alert(&self.engine, ev, msgs);
            self.streamed += line.len() as i64;
            if let Some(w) = self.stream.as_mut().and_then(|st| st.send(stream::ALERT, &line)) {
                msgs.warn(w);
            }
            if let Some(fw) = self.forwarder.as_mut().filter(|_| forward) {
                // the alert JSON is made again for the forwarder (its messages twice)
                let again: Vec<_> = msgs.list[before..].to_vec();
                msgs.list.extend(again);
                fw.send(&line[..line.len() - 1], now, msgs);
            }
            return;
        }
        if let Some(fmt) = &g.custom_alert_output {
            self.engine.alert_counter = self.outputs.alerts.written as i64;
            let mut buf = Vec::new();
            let _ = crate::text_logs::custom_alert(&self.engine, ev, fmt.as_bytes(), &mut buf);
            self.outputs.alerts.write(&buf);
        } else if g.alerts_log {
            self.engine.alert_counter = self.outputs.alerts.written as i64;
            let mut buf = Vec::new();
            let _ = crate::text_logs::alert(&self.engine, ev, &mut buf);
            self.outputs.alerts.write(&buf);
        } else if g.jsonout_output {
            self.engine.alert_counter = self.outputs.alerts_json.written as i64;
        }
        if g.jsonout_output {
            let before = msgs.list.len();
            let line = crate::text_logs::json_alert(&self.engine, ev, msgs);
            self.outputs.alerts_json.write(&line);
            if let Some(fw) = self.forwarder.as_mut().filter(|_| forward) {
                let again: Vec<_> = msgs.list[before..].to_vec();
                msgs.list.extend(again);
                fw.send(&line[..line.len() - 1], now, msgs);
            }
        }
    }

    /// One input datagram: checked, counted and queued; then what can be decoded.
    pub fn handle(&mut self, host: &mut dyn Host, msg: &[u8]) {
        self.receive(host, msg);
        self.pump(host);
    }

    pub fn receive(&mut self, host: &mut dyn Host, msg: &[u8]) {
        let msg = match msg {
            [stream::FROM_API, rest @ ..] => {
                self.load[0].fetch_add(1, Ordering::Relaxed);
                rest
            }
            [stream::FROM_GATEWAY, sender, rest @ ..] => {
                self.load[2 + usize::from(*sender)].fetch_add(1, Ordering::Relaxed);
                rest
            }
            _ => msg,
        };
        let text = text_at(msg, 0);
        if text.len() < 4 {
            host.log("ERROR", &[&b"(1222): Invalid msg: "[..], text].concat());
            return;
        }
        self.stats.received(msg.len());
        let kind = Kind::of(text[0]);
        let queued = self.inq.push(kind, text.to_vec());
        if queued {
            self.hourly_events += 1;
            if kind == Kind::Syscheck {
                self.hourly_syscheck += 1;
            }
        } else {
            match kind.dropped_counter() {
                Some(c) => self.stats.dropped(c),
                None => match text[0] {
                    queues::CISCAT => self.stats.dropped(Component::Ciscat),
                    queues::SYSLOG => self.stats.dropped(Component::Syslog),
                    queues::LOCALFILE => match crate::stats::module_of_message(text) {
                        Some(m) => self.stats.dropped(Component::of_module(m)),
                        None => host.log("ERROR", FORMAT_ERROR.as_bytes()),
                    },
                    _ => {}
                },
            }
            let r = &mut self.inq.reported[kind.index()];
            if !*r {
                *r = true;
                host.log("WARNING", kind.full_warning().as_bytes());
            }
        }
        if !queued {
            if self.eps_drop_reported {
                self.stats.g.eps.events_dropped += 1;
            } else if self.limits.reached().0 {
                self.eps_drop_reported = true;
                if !self.eps_drop_reported_hour {
                    host.log("WARNING", b"Queues are full and no EPS credits, dropping events.");
                }
                self.stats.g.eps.events_dropped += 1;
            } else {
                self.stats.g.eps.events_dropped_not_eps += 1;
            }
        } else if self.eps_drop_reported {
            self.eps_drop_reported = false;
            if !self.eps_drop_reported_hour {
                host.log("INFO", b"Queues back to normal and EPS credits, no dropping events.");
                self.eps_drop_reported_hour = true;
            }
        }
    }

    pub fn pump(&mut self, host: &mut dyn Host) {
        self.pump_some(host, usize::MAX);
    }

    /// Decodes up to `max` queued messages while EPS credits last, and matches what the
    /// workers finished.
    pub fn pump_some(&mut self, host: &mut dyn Host, max: usize) {
        while let Some(d) = self.workers.as_ref().and_then(|w| w.done.try_recv().ok()) {
            self.take_decoded(host, d);
        }
        let mut n = 0;
        while n < max && self.inq.has_fast() {
            if !self.limits.take() {
                return;
            }
            let (kind, msg) = self.inq.pop().expect("not empty");
            self.decode(host, kind, &msg);
            n += 1;
        }
        while self.inq.has_slow() && self.worker_room() {
            if !self.limits.take() {
                return;
            }
            let (kind, msg) = self.inq.pop_slow().expect("not empty");
            self.decode(host, kind, &msg);
        }
    }

    fn worker_room(&self) -> bool {
        self.workers.as_ref().is_some_and(|w| w.in_flight < builtin::IN_FLIGHT)
    }

    pub fn start_workers<H: Host + Send + 'static>(&mut self, hosts: Vec<H>) {
        self.workers = Some(Workers::start(hosts));
        self.inq.split = true;
    }

    pub fn finish_decoding(&mut self, host: &mut dyn Host) {
        while self.workers.as_ref().is_some_and(|w| w.in_flight > 0) {
            let Some(Ok(d)) = self.workers.as_ref().map(|w| w.done.recv()) else { return };
            self.take_decoded(host, d);
        }
    }

    fn take_decoded(&mut self, host: &mut dyn Host, d: Decoded) {
        if let Some(w) = &mut self.workers {
            w.in_flight -= 1;
        }
        if let Some((id, name)) = d.integrity {
            let x = &mut self.engine.decoders.decoders[self.builtin.integrity];
            (x.id, x.name) = (id, name);
        }
        if d.keep {
            self.match_rules(host, *d.ev);
        }
    }

    pub fn can_pump(&self) -> bool {
        (self.inq.has_fast() || (self.inq.has_slow() && self.worker_room())) && !self.limits.reached().0
    }

    pub fn pending(&self) -> bool {
        !self.inq.is_empty() || self.workers.as_ref().is_some_and(|w| w.in_flight > 0)
    }

    pub fn input_full(&self) -> bool {
        self.inq.any_full()
    }

    pub fn queue_usage(&self) -> f32 {
        self.inq.max_usage()
    }

    /// siem-api's `getload` answer.
    pub fn load_json(load: &[AtomicU64]) -> Vec<u8> {
        let o = Ordering::Relaxed;
        let senders: Vec<String> = load[2..].iter().enumerate().filter_map(|(n, c)| Some(c.load(o)).filter(|c| *c > 0).map(|c| format!(r#""{n}":{c}"#))).collect();
        format!(r#"{{"error":0,"message":"ok","data":{{"queue_usage":{},"received":{},"senders":{{{}}}}}}}"#, f32::from_bits(load[1].load(o) as u32), load[0].load(o), senders.join(",")).into_bytes()
    }

    fn decode(&mut self, host: &mut dyn Host, kind: Kind, msg: &[u8]) {
        let now = self.engine.clock.now();
        let mut ev = self.engine.new_event();
        let manager = self.engine.settings.manager_host.clone();
        if ev.clean(msg, &manager, now).is_err() {
            host.log("ERROR", FORMAT_ERROR.as_bytes());
            host.log("ERROR", &[&b"(1222): Invalid msg: "[..], msg].concat());
            return;
        }
        let waits = match kind {
            Kind::Dbsync => Some(Component::Dbsync),
            Kind::Upgrade => Some(Component::Upgrade),
            Kind::Syscheck => Some(Component::Syscheck),
            Kind::Syscollector => Some(Component::Syscollector),
            Kind::Sca => Some(Component::Sca),
            Kind::Rootcheck => Some(Component::Rootcheck),
            _ if msg[0] == queues::CISCAT => Some(Component::Ciscat),
            _ => None,
        };
        let order = self.engine.settings.rules.order_size;
        if let Some(c) = waits {
            self.stats.decoded(c, ev.agent_id.as_deref(), now.sec);
            if msg[0] == queues::CISCAT {
                crate::plugins::json(&self.engine.decoders.decoders, &mut ev, order);
            }
            let g = &self.cfg.global;
            let settings = DbSettings {
                builtin: self.builtin,
                order,
                integrity: builtin::integrity::Options { alert_new: g.syscheck_alert_new, auto_ignore: g.syscheck_auto_ignore, ignore_time: i64::from(g.syscheck_ignore_time), ignore_frequency: g.syscheck_ignore_frequency },
            };
            if let Some(w) = &mut self.workers {
                return w.send(kind, settings, ev);
            }
            let fim = &mut self.engine.decoders.decoders[self.builtin.integrity];
            if self.db.decode(host, kind, &settings, fim, &mut ev) {
                self.match_rules(host, ev);
            }
            return;
        }
        match kind {
            Kind::Winevt => {
                self.stats.decoded(Component::Eventchannel, ev.agent_id.as_deref(), now.sec);
                if !self.windows.decode(host, &mut self.engine.decoders, self.builtin.windows, order, &mut ev) {
                    return;
                }
            }
            Kind::Hostinfo => {
                self.stats.decoded(Component::Others, ev.agent_id.as_deref(), now.sec);
                let b = self.builtin;
                let home = self.cfg.home.clone();
                let hi = self.hostinfo.get_or_insert_with(|| builtin::small::HostInfo::open(&home, host));
                if !hi.decode(host, &mut self.engine.decoders, b.hostinfo, b.hostinfo_new, b.hostinfo_changed, &mut ev) {
                    return;
                }
            }
            _ => {
                match msg[0] {
                    queues::SYSLOG => self.stats.decoded(Component::Syslog, None, now.sec),
                    queues::LOCALFILE => {
                        let loc = ev.f[F_LOCATION].clone().unwrap_or_default();
                        self.stats.decoded(Component::of_module(crate::stats::module_of_location(&loc)), ev.agent_id.as_deref(), now.sec);
                    }
                    _ => {}
                }
                self.engine.decode(&mut ev);
            }
        }
        self.match_rules(host, ev);
    }

    fn match_rules(&mut self, host: &mut dyn Host, ev: Event) {
        let n = self.now();
        let opts = Options {
            logfw: self.cfg.internal.log_fw != 0,
            // the stream always carries the events: they are the platform's event store
            logall: self.cfg.global.logall || self.cfg.global.logall_json || self.stream.is_some(),
            stats: i32::from(self.cfg.global.stats),
        };
        let stats = &mut self.stats;
        let mut labels = |ev: &Event| {
            let l = host.labels(ev.agent_id.as_deref().unwrap_or(b""));
            stats.processed(ev.agent_id.as_deref(), n.sec);
            l
        };
        let out = self.engine.process(ev, &opts, &mut self.hours, self.stats_rule, n.hour, n.wday, &mut labels);
        if out.firewall_event {
            self.hourly_firewall += 1;
        }
        self.write(host, out);
    }

    /// getconfig sections.
    pub fn config_section(&self, section: &[u8]) -> Option<Json> {
        use crate::getconfig as g;
        let c = &self.cfg;
        Some(match section {
            b"global" => g::global(c),
            b"active_response" => g::active_response(c),
            b"alerts" => g::alerts(c),
            b"decoders" => g::decoders(&self.engine.decoders, c.internal.decoder_order_size as usize),
            b"rules" => g::rules(&self.engine.rules),
            b"internal" => g::internal(c),
            b"command" => g::commands(c),
            b"labels" => g::labels(c),
            b"rule_test" => g::rule_test(c),
            _ => return None,
        })
    }
}

/// The analysis socket's view of the service.
struct SocketTarget<'a> {
    service: &'a mut Service,
    host: &'a mut dyn Host,
}

impl crate::socket::Service for SocketTarget<'_> {
    fn stats(&mut self) -> Json {
        self.service.stats_json()
    }
    fn agents_stats(&mut self, ids: &[i32]) -> Json {
        self.service.stats.agents_json(self.service.engine.clock.now().sec, ids)
    }
    fn agents_of_node(&mut self, last: i32, limit: i32) -> Option<Vec<i32>> {
        self.host.agents_of_node(last, limit)
    }
    fn config(&mut self, section: &[u8]) -> Option<Json> {
        self.service.config_section(section)
    }
    fn reload(&mut self) -> (bool, Vec<String>) {
        let mut m = Messages::bounded();
        let failed = self.service.reload(self.host, &mut m);
        (failed, m.list.into_iter().map(|x| x.text).collect())
    }
}

// ---------------------------------------------------------------- forwarding

#[cfg(unix)]
enum Connection {
    Datagram(std::os::unix::net::UnixDatagram),
    Stream(std::os::unix::net::UnixStream),
}

/// Sends each alert to the first `<socket>` when `<forward_to>` is set (one connection
/// attempt per second at most).
pub struct Forwarder {
    target: Socket,
    #[cfg(unix)]
    conn: Option<Connection>,
    #[cfg_attr(not(unix), allow(dead_code))]
    last_attempt: i64,
}

impl Forwarder {
    pub fn new(target: Socket) -> Forwarder {
        Forwarder {
            target,
            #[cfg(unix)]
            conn: None,
            last_attempt: 0,
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn mode(&self) -> &'static str {
        if self.target.tcp {
            "tcp"
        } else {
            "udp"
        }
    }

    #[cfg(unix)]
    fn connect(&self) -> Option<Connection> {
        use std::os::unix::net::{UnixDatagram, UnixStream};
        if self.target.tcp {
            UnixStream::connect(&self.target.location).ok().map(Connection::Stream)
        } else {
            let s = UnixDatagram::unbound().ok()?;
            s.connect(&self.target.location).ok()?;
            Some(Connection::Datagram(s))
        }
    }

    /// Err(true) when the socket is busy.
    #[cfg(unix)]
    fn put(c: &mut Connection, msg: &[u8]) -> Result<(), bool> {
        let r = match c {
            Connection::Datagram(s) => s.send(msg).map(|n| n == msg.len()),
            Connection::Stream(s) => s.write(msg).map(|n| n == msg.len()),
        };
        match r {
            Ok(true) => Ok(()),
            Ok(false) => Err(false),
            Err(e) => Err(e.raw_os_error() == Some(105)),
        }
    }

    pub fn send(&mut self, msg: &[u8], now: i64, msgs: &mut Messages) {
        if self.target.name == "agent" {
            return;
        }
        #[cfg(unix)]
        {
            if self.conn.is_none() {
                if now <= self.last_attempt {
                    return;
                }
                match self.connect() {
                    Some(c) => self.conn = Some(c),
                    None => {
                        self.last_attempt = now;
                        msgs.error(format!("Unable to connect to socket '{}': {} ({})", self.target.name, self.target.location, self.mode()));
                        return;
                    }
                }
            }
            let c = self.conn.as_mut().expect("connected");
            if let Err(busy) = Self::put(c, msg) {
                if !busy && now > self.last_attempt {
                    self.conn = None;
                    match self.connect() {
                        None => {
                            msgs.error(format!("Unable to connect to socket '{}': {} ({}).", self.target.name, self.target.location, self.mode()));
                            self.last_attempt = now;
                        }
                        Some(mut c) => {
                            if Self::put(&mut c, msg).is_err() {
                                self.last_attempt = now;
                            }
                            self.conn = Some(c);
                        }
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (msg, now, msgs);
        }
    }
}

// ---------------------------------------------------------------- running

/// The messages logged between loading the ruleset and starting.
fn startup_messages(cfg: &Config, log: &ServiceLog) {
    let g = &cfg.global;
    if g.queue_size != 0 {
        log.log("INFO", "The option <queue_size> is deprecated and won't apply. Set up each queue size in the internal_options file.");
    }
    if g.ar != 0 {
        if g.white_list.is_empty() {
            log.log("INFO", "No IP in the white list for active response.");
        } else {
            for ip in &g.white_list {
                log.log("INFO", format!("White listing IP: '{}'", ip.ip));
            }
            log.log("INFO", format!("{} IPs in the white list for active response.", g.white_list.len()));
        }
        if g.hostname_white_list.is_empty() {
            log.log("INFO", "No Hostname in the white list for active response.");
        } else {
            let mut n = 0;
            for m in &g.hostname_white_list {
                for p in m.patterns() {
                    log.log("INFO", [&b"White listing Hostname: '"[..], p, b"'"].concat());
                    n += 1;
                }
            }
            log.log("INFO", format!("{n} Hostname(s) in the white list for active response."));
        }
    }
    log.log("INFO", format!("Started (pid: {}).", std::process::id()));
}

/// Runs the service until the input queue closes.
pub fn run(mut service: Service, log: Arc<ServiceLog>) -> std::io::Result<()> {
    let home = service.cfg.home.clone();
    startup_messages(&service.cfg, &log);
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let ctx = |db: Arc<dyn DbQuery>| Ctx { home: home.clone(), rt: rt.handle().clone(), db, log: log.clone() };
    let mut host = service.live_host(ctx(Arc::new(DbSocket::new(home.join(DB_SOCKET)))));
    service.load_mitre(&mut host);
    service.start()?;
    service.init_decoders(&mut host);
    if let Some((level, m)) = service.limits_msg.take() {
        log.log(level, m);
    }
    if service.cfg.internal.state_interval == 0 {
        log.log("INFO", "State file is disabled.");
    } else {
        service.write_state(&mut host);
    }

    // logtest
    let lt_cfg = service.cfg.logtest.clone();
    if lt_cfg.enabled {
        let mut lt = Logtest::new(logtest::Settings {
            enabled: true,
            threads: lt_cfg.threads,
            max_sessions: lt_cfg.max_sessions,
            session_timeout: lt_cfg.session_timeout,
            config_file: PathBuf::from("etc/ossec.conf"),
            engine: service.engine.settings.clone(),
        });
        lt.rules_by_id = service.engine.rules_by_id.clone();
        let lt = Arc::new(Mutex::new(lt));
        let path = home.join("queue/sockets/logtest");
        let (l2, lt2) = (log.clone(), lt.clone());
        rt.spawn(async move {
            let _ = std::fs::remove_file(&path);
            let listener = match provigil_ipc::aio::StreamListener::bind(&path).await {
                Ok(l) => l,
                Err(e) => {
                    l2.log("ERROR", format!("(7300): Unable to bind to socket '{}'. Errno: (0) {e}", "queue/sockets/logtest"));
                    return;
                }
            };
            l2.log("INFO", "(7200): Logtest started");
            loop {
                let Ok(mut s) = listener.accept().await else { continue };
                let lt = lt2.clone();
                tokio::spawn(async move {
                    use provigil_ipc::aio::framing;
                    let answer = match framing::recv(&mut s, MAX_MESSAGE - 1).await {
                        Ok(req) => tokio::task::spawn_blocking(move || lt.lock().expect("logtest").request(&req)).await.ok(),
                        Err(framing::FrameError::TooBig(..)) => Some(Logtest::error_answer(logtest::TOO_LARGE)),
                        Err(_) => None,
                    };
                    if let Some(a) = answer {
                        let _ = framing::send(&mut s, &a).await;
                    }
                });
            }
        });
        let every = lt_cfg.session_timeout.max(1) as u64;
        rt.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(every)).await;
                lt.lock().expect("logtest").expire();
            }
        });
    } else {
        log.log("INFO", "(7201): Logtest disabled");
    }

    // the input queue
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(131_072);
    let hosts = (0..DB_WORKERS).map(|_| service.live_host(ctx(Arc::new(DbSocket::new(home.join(DB_SOCKET)))))).collect();
    service.start_workers(hosts);
    let qpath = home.join(provigil_ipc::queue::EVENT_QUEUE);
    let l3 = log.clone();
    rt.spawn(async move {
        let _ = std::fs::remove_file(&qpath);
        let input = match provigil_ipc::aio::DatagramReceiver::bind(&qpath).await {
            Ok(r) => r,
            Err(e) => {
                l3.log("CRITICAL", format!("(1210): Queue '{}' not accessible: '{e}'", provigil_ipc::queue::EVENT_QUEUE));
                return;
            }
        };
        loop {
            if let Ok(m) = input.recv(MAX_MESSAGE).await {
                if tx.send(m).is_err() {
                    break;
                }
            }
        }
    });

    // the analysis socket: answered by the main thread (getload without it)
    type Request = (Vec<u8>, tokio::sync::oneshot::Sender<Vec<u8>>);
    let (atx, arx) = mpsc::channel::<Request>();
    let apath = home.join(crate::socket::PATH);
    let (l4, load) = (log.clone(), service.load.clone());
    rt.spawn(async move {
        let _ = std::fs::remove_file(&apath);
        let listener = match provigil_ipc::aio::StreamListener::bind(&apath).await {
            Ok(l) => l,
            Err(e) => {
                let (n, t) = crate::messages::os_error(&e);
                l4.log("ERROR", format!("Unable to bind to socket '{}': ({n}) '{t}'", crate::socket::PATH));
                return;
            }
        };
        loop {
            let Ok(mut s) = listener.accept().await else { continue };
            let (atx, load, l5) = (atx.clone(), load.clone(), l4.clone());
            tokio::spawn(async move {
                use provigil_ipc::aio::framing;
                match framing::recv(&mut s, MAX_MESSAGE).await {
                    Ok(req) if req.is_empty() => {}
                    Ok(req) if req.starts_with(b"{\"command\":\"getload\"}") => {
                        let _ = framing::send(&mut s, &Service::load_json(&load)).await;
                    }
                    Ok(req) => {
                        let (otx, orx) = tokio::sync::oneshot::channel();
                        if atx.send((req, otx)).is_ok() {
                            if let Ok(a) = orx.await {
                                let _ = framing::send(&mut s, &a).await;
                            }
                        }
                    }
                    Err(framing::FrameError::TooBig(..)) => l5.log("ERROR", "At OS_RecvSecureTCP(): response size is bigger than expected"),
                    Err(e) => l5.log("ERROR", format!("At OS_RecvSecureTCP(): '{e}'")),
                }
            });
        }
    });

    // input, decoding, rules, writers and rotation on this thread
    let mut last_tick = std::time::Instant::now();
    loop {
        // what the queues cannot take waits in the channel, then in the socket: siem-api
        // sees that and holds agents' batches back
        let wait = match (service.can_pump(), service.pending()) {
            (true, _) => Duration::ZERO,
            (false, true) => Duration::from_millis(1),
            (false, false) => Duration::from_millis(50),
        };
        if service.input_full() {
            std::thread::sleep(wait);
        } else {
            match rx.recv_timeout(wait) {
                Ok(m) => {
                    service.receive(&mut host, &m);
                    while !service.input_full() {
                        let Ok(m) = rx.try_recv() else { break };
                        service.receive(&mut host, &m);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        service.load[1].store(u64::from(service.queue_usage().to_bits()), Ordering::Relaxed);
        while let Ok((req, otx)) = arx.try_recv() {
            let a = crate::socket::request(&mut SocketTarget { service: &mut service, host: &mut host }, &req);
            let _ = otx.send(a);
        }
        service.pump_some(&mut host, 256);
        if last_tick.elapsed() >= Duration::from_secs(1) {
            service.tick(&log);
            service.second(&mut host);
            last_tick = std::time::Instant::now();
        }
    }
    service.outputs.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_answer_and_labels() {
        let load: Vec<AtomicU64> = (0..2 + 256).map(|_| AtomicU64::new(0)).collect();
        load[0].store(5, Ordering::Relaxed);
        load[1].store(u64::from(0.25f32.to_bits()), Ordering::Relaxed);
        load[2 + 3].store(70, Ordering::Relaxed);
        assert_eq!(String::from_utf8(Service::load_json(&load)).unwrap(), r#"{"error":0,"message":"ok","data":{"queue_usage":0.25,"received":5,"senders":{"3":70}}}"#);
        let j = provigil_json::parse(br##"[{"key":"\"a\"","value":"1"},{"key":"!\"b\"","value":"2"},{"key":"#\"c\"","value":"3"},{"key":"x","value":"4"},{"key":"\"a\"","value":"5"}]"##).unwrap();
        let l = labels_of(&j);
        assert_eq!(l.len(), 3);
        assert!(l[1].hidden && l[2].system && l[0].value == b"1");
    }
}
