//! The wazuh-analysisd daemon: input queue, rule matching thread, alert /
//! archive / firewall / FTS writers with daily files and rotation
//! (alerts/getloglocation.c), hourly statistics files (stats.c), labels
//! cache (labels.c), active responses and the logtest socket.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{Datelike, Local, TimeZone, Timelike};
use siem_config::active_response::ArConfig;
use siem_config::socket::SocketForwarder;
use siem_ipc::mq::queues::*;
use siem_ipc::wdbc::{parse_result, WdbQuery, WdbcResult, WdbcSocket};

use crate::analysis::{stats_rule, Outcome, ProcessOptions, Stats};
use crate::ar::{os_exec, AgentVersion, ArBackend, ArWhitelist};
use crate::daemon_config::AnalysisdConfig;
use crate::engine::{Engine, EngineConfig};
use crate::event::*;
use crate::labels::{Label, LabelFlags};
use crate::logmsg::{LogLevel, LogList};
use crate::logtest::{Logtest, LogtestConfig};
use crate::input::{InQueues, Kind};
use crate::limits::Limits;
use crate::output;
use crate::state::{Component, EpsReport, QueueStat, QueueStatus, State};
use crate::rules::{ActiveResponse as RuleAr, RuleConfig, RuleId};

pub const OS_MAXSTR: usize = 65536;
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Logging used by the daemon (`minfo` / `mwarn` / `merror`).
pub trait Logger: Send + Sync {
    fn log(&self, level: &str, msg: &str);
    /// A message with arbitrary bytes (C `%s` of event data).
    fn log_bytes(&self, level: &str, msg: &[u8]) {
        self.log(level, &String::from_utf8_lossy(msg))
    }
}

/// Daemon logging to `logs/ossec.log` / `logs/ossec.json` (debug_op.c).
impl Logger for siem_log::WLog {
    fn log(&self, level: &str, msg: &str) {
        self.log_bytes(level, msg.as_bytes())
    }
    #[track_caller]
    fn log_bytes(&self, level: &str, msg: &[u8]) {
        match level {
            "DEBUG" => self.debug1(msg),
            "DEBUG2" => self.debug2(msg),
            _ => self.log_at(siem_log::Level::from_name(level), msg, std::panic::Location::caller()),
        }
    }
}

pub struct StderrLogger;
/// Logs to stderr without the debug levels (tests and tools).
impl Logger for StderrLogger {
    fn log(&self, level: &str, msg: &str) {
        if level.starts_with("DEBUG") {
            return;
        }
        let now = Local::now().format("%Y/%m/%d %H:%M:%S");
        eprintln!("{now} wazuh-analysisd: {level}: {msg}");
    }
    fn log_bytes(&self, level: &str, msg: &[u8]) {
        if level.starts_with("DEBUG") {
            return;
        }
        let now = Local::now().format("%Y/%m/%d %H:%M:%S");
        let mut line = format!("{now} wazuh-analysisd: {level}: ").into_bytes();
        line.extend_from_slice(msg);
        line.push(b'\n');
        let _ = std::io::stderr().write_all(&line);
    }
}

/* ------------------------------------------------------------ log files */

/// One output file of `getloglocation.c`.
#[derive(Default)]
struct LogFile {
    fp: Option<BufWriter<File>>,
    path: PathBuf,
    counter: i32,
    pos: u64,
}

impl LogFile {
    fn write(&mut self, data: &[u8]) {
        if let Some(f) = &mut self.fp {
            if f.write_all(data).is_ok() {
                self.pos += data.len() as u64;
            }
        }
    }
    fn flush(&mut self) {
        if let Some(f) = &mut self.fp {
            let _ = f.flush();
        }
    }
}

fn is_file(p: &Path) -> bool {
    p.is_file()
}

/// `openlog`
#[allow(clippy::too_many_arguments)]
fn openlog(
    lf: &mut LogFile,
    home: &Path,
    logdir: &str,
    year: i32,
    month: &str,
    tag: &str,
    day: i32,
    ext: &str,
    lname: &str,
    rotate: bool,
    max_output_size: i64,
) -> std::io::Result<()> {
    if let Some(mut f) = lf.fp.take() {
        let _ = f.flush();
        if lf.pos == 0 {
            let _ = std::fs::remove_file(&lf.path);
        }
    }
    let ydir = home.join(format!("{logdir}/{year}"));
    std::fs::create_dir_all(&ydir)?;
    let mdir = ydir.join(month);
    std::fs::create_dir_all(&mdir)?;
    let mut path;
    if rotate {
        lf.counter += 1;
        path = mdir.join(format!("ossec-{tag}-{day:02}-{:03}.{ext}", lf.counter));
    } else {
        path = mdir.join(format!("ossec-{tag}-{day:02}.{ext}"));
        lf.counter = 0;
        loop {
            let next = mdir.join(format!("ossec-{tag}-{day:02}-{:03}.{ext}", lf.counter + 1));
            let too_big = max_output_size != 0 && std::fs::metadata(&path).map(|m| m.len() as i64).unwrap_or(-1) > max_output_size;
            if !(is_file(&next) || too_big) {
                break;
            }
            path = next;
            lf.counter += 1;
        }
    }
    let f = OpenOptions::new().create(true).append(true).open(&path)?;
    lf.pos = f.metadata().map(|m| m.len()).unwrap_or(0);
    lf.fp = Some(BufWriter::new(f));
    lf.path = path.clone();
    let link = home.join(lname);
    let _ = std::fs::remove_file(&link);
    std::fs::hard_link(&path, &link)?;
    Ok(())
}

/// `_eflog`, `_ejflog`, `_aflog`, `_jflog`, `_fflog` and their state.
#[derive(Default)]
pub struct LogFiles {
    ef: LogFile,
    ejf: LogFile,
    af: LogFile,
    jf: LogFile,
    ff: LogFile,
    crt_rsec: i64,
}

impl LogFiles {
    /// `OS_GetLogLocation`
    pub fn get_log_location(&mut self, home: &Path, g: &siem_config::global::GlobalConfig, day: i32, year: i32, mon: &str, now: i64) -> std::io::Result<()> {
        let m = g.max_output_size;
        openlog(&mut self.ef, home, "logs/archives", year, mon, "archive", day, "log", "logs/archives/archives.log", false, m)?;
        if g.logall_json != 0 {
            openlog(&mut self.ejf, home, "logs/archives", year, mon, "archive", day, "json", "logs/archives/archives.json", false, m)?;
        }
        openlog(&mut self.af, home, "logs/alerts", year, mon, "alerts", day, "log", "logs/alerts/alerts.log", false, m)?;
        if g.jsonout_output != 0 {
            openlog(&mut self.jf, home, "logs/alerts", year, mon, "alerts", day, "json", "logs/alerts/alerts.json", false, m)?;
        }
        openlog(&mut self.ff, home, "logs/firewall", year, mon, "firewall", day, "log", "logs/firewall/firewall.log", false, m)?;
        self.crt_rsec = now;
        Ok(())
    }

    /// `OS_RotateLogs`
    pub fn rotate(&mut self, home: &Path, g: &siem_config::global::GlobalConfig, day: i32, year: i32, mon: &str, now: i64) {
        let m = g.max_output_size;
        let files: [(&mut LogFile, &str, &str, &str, &str); 5] = [
            (&mut self.ef, "logs/archives", "archive", "log", "logs/archives/archives.log"),
            (&mut self.ejf, "logs/archives", "archive", "json", "logs/archives/archives.json"),
            (&mut self.af, "logs/alerts", "alerts", "log", "logs/alerts/alerts.log"),
            (&mut self.jf, "logs/alerts", "alerts", "json", "logs/alerts/alerts.json"),
            (&mut self.ff, "logs/firewall", "firewall", "log", "logs/firewall/firewall.log"),
        ];
        if g.rotate_interval != 0 && now - self.crt_rsec > g.rotate_interval as i64 {
            for (f, dir, tag, ext, lname) in files {
                if f.fp.is_some() && f.pos > 0 {
                    let _ = openlog(f, home, dir, year, mon, tag, day, ext, lname, true, m);
                }
            }
            self.crt_rsec = now;
        } else if m != 0 && now - self.crt_rsec > g.min_rotate_interval as i64 {
            let mut rotated = false;
            for (f, dir, tag, ext, lname) in files {
                if f.fp.is_some() && f.pos as i64 > m {
                    let _ = openlog(f, home, dir, year, mon, tag, day, ext, lname, true, m);
                    rotated = true;
                }
            }
            if rotated {
                self.crt_rsec = now;
            }
        }
    }

    pub fn flush(&mut self) {
        for f in [&mut self.ef, &mut self.ejf, &mut self.af, &mut self.jf, &mut self.ff] {
            f.flush();
        }
    }
}

/* -------------------------------------------------------------- stats */

const STATWQUEUE: &str = "stats/weekly-average";
const STATQUEUE: &str = "stats/hourly-average";
const STATSAVED: &str = "stats/totals";

fn read_int_file(p: &Path) -> i32 {
    match std::fs::read_to_string(p) {
        Ok(s) => {
            let v = crate::rules::atoi(s.trim_start());
            v.max(0)
        }
        Err(_) => 0,
    }
}

/// `Init_Stats_Directories`
pub fn init_stats(home: &Path, st: &mut Stats) -> std::io::Result<()> {
    std::fs::create_dir_all(home.join(STATWQUEUE))?;
    std::fs::create_dir_all(home.join(STATQUEUE))?;
    std::fs::create_dir_all(home.join(STATSAVED))?;
    for i in 0..=24 {
        st.chour[i] = 0;
        st.rhour[i] = read_int_file(&home.join(format!("{STATQUEUE}/{i}")));
    }
    for i in 0..=6 {
        std::fs::create_dir_all(home.join(format!("{STATWQUEUE}/{i}")))?;
        for j in 0..=24 {
            st.cwhour[i][j] = 0;
            st.rwhour[i][j] = read_int_file(&home.join(format!("{STATWQUEUE}/{i}/{j}")));
        }
    }
    Ok(())
}

fn totals_file(home: &Path, year: i32, mon: &str, day: i32) -> std::io::Result<File> {
    let d = home.join(format!("{STATSAVED}/{year}/{mon}"));
    std::fs::create_dir_all(&d)?;
    OpenOptions::new().create(true).append(true).open(d.join(format!("ossec-totals-{day:02}.log")))
}

/* ------------------------------------------------------------ labels */

struct LabelCache {
    config: Vec<Label>,
    cache: HashMap<String, (Vec<Label>, i64)>,
    maxage: i64,
}

fn to_labels(v: &[siem_config::labels::Label]) -> Vec<Label> {
    v.iter()
        .map(|l| Label {
            key: l.key.as_bytes().to_vec(),
            value: l.value.as_bytes().to_vec(),
            flags: LabelFlags { hidden: l.flags.hidden, system: l.flags.system },
        })
        .collect()
}

/* ------------------------------------------------------------- daemon */

/// Shared handles of the running daemon.
pub struct Ctx {
    pub home: PathBuf,
    pub rt: tokio::runtime::Handle,
    pub wdb: Arc<dyn WdbQuery>,
    pub log: Arc<dyn Logger>,
}

impl Ctx {
    fn wdb_query(&self, q: &str) -> Option<String> {
        let db = self.wdb.clone();
        let q = q.to_string();
        self.rt.block_on(async move { db.query(&q).await.ok() })
    }

    fn wdb_json(&self, q: &str) -> Option<siem_cjson::Json> {
        let r = self.wdb_query(q)?;
        match parse_result(&r) {
            (WdbcResult::Ok, p) => siem_cjson::parse(p.as_bytes()),
            _ => None,
        }
    }
}

/// What the event path needs from outside the ruleset: agent labels,
/// active-response delivery and logging.
pub trait Env {
    /// `labels_find`
    fn labels(&mut self, agent_id: &[u8]) -> Vec<Label>;
    fn log(&self, level: &str, msg: &[u8]);
    fn ar(&mut self) -> &mut dyn ArBackend;
    /// `wdb_get_agents_ids_of_current_node("active", last_id, limit)`
    fn agents_of_node(&mut self, last_id: i32, limit: i32) -> Option<Vec<i32>>;
    /// `wdbc_query_ex(&sock, query, response, len)`: the reply, or the
    /// C return code (-2 connect/send, -1 receive); logs its own errors.
    fn wdb_query_ex(&mut self, query: &[u8], len: usize) -> Result<Vec<u8>, i32> {
        let _ = (query, len);
        Err(-2)
    }
    /// A one-shot `OS_ConnectUnixDomain(path, SOCK_STREAM)` +
    /// `OS_SendSecureTCP(strlen(msg))`; Err((errno, strerror)) when the
    /// connection fails.
    fn send_local(&mut self, path: &str, msg: &[u8]) -> Result<(), (i32, String)> {
        let _ = (path, msg);
        Err((111, "Connection refused".into()))
    }
    /// `StartMQ(path, WRITE, 1)` + `OS_SendUnix(sock, msg, 0)` (one
    /// datagram with the trailing NUL); false when the queue is not
    /// available (the caller decides what to log).
    fn send_mq(&mut self, path: &str, msg: &[u8]) -> bool {
        let _ = (path, msg);
        false
    }
    /// `wdbc_query_parse_json` (logs its own errors).
    fn wdb_json(&mut self, query: &str) -> Option<siem_cjson::Json> {
        let _ = query;
        None
    }
}

/// The running daemon's environment: wazuh-db labels cache, the execd /
/// remoted AR queues (kept connected) and the daemon logger.
pub struct LiveEnv {
    pub ctx: Ctx,
    labels: LabelCache,
    exec: Option<siem_ipc::local::DatagramSender>,
    ar: Option<siem_ipc::local::DatagramSender>,
    node_name: String,
}

impl Env for LiveEnv {
    fn labels(&mut self, agent_id: &[u8]) -> Vec<Label> {
        self.labels.find(&self.ctx, agent_id)
    }
    fn log(&self, level: &str, msg: &[u8]) {
        self.ctx.log.log_bytes(level, msg)
    }
    fn ar(&mut self) -> &mut dyn ArBackend {
        self
    }
    fn send_mq(&mut self, path: &str, msg: &[u8]) -> bool {
        let p = self.ctx.home.join(path);
        let mut m = msg.to_vec();
        m.push(0);
        let ok = self.ctx.rt.block_on(async move {
            let s = siem_ipc::local::DatagramSender::connect(&p).await?;
            s.send(&m).await
        });
        if let Err(e) = &ok {
            let (_, t) = crate::logmsg::errno_text(e);
            self.ctx.log.log("WARNING", &format!("(1210): Queue '{path}' not accessible: '{t}'"));
        }
        ok.is_ok()
    }

    fn send_local(&mut self, path: &str, msg: &[u8]) -> Result<(), (i32, String)> {
        let p = self.ctx.home.join(path);
        let m = msg.to_vec();
        self.ctx.rt.block_on(async move {
            let mut s = siem_ipc::local::LocalStream::connect(&p).await.map_err(|e| {
                let (n, t) = crate::logmsg::errno_text(&e);
                (n, t.to_string())
            })?;
            let _ = siem_ipc::framing::send(&mut s, &m).await;
            Ok(())
        })
    }

    fn wdb_query_ex(&mut self, query: &[u8], len: usize) -> Result<Vec<u8>, i32> {
        let db = self.ctx.wdb.clone();
        let q = query.to_vec();
        match self.ctx.rt.block_on(async move { db.query_bytes(&q, len).await }) {
            Ok(r) => Ok(r),
            Err(e) => {
                let m = match &e {
                    siem_ipc::wdbc::WdbcError::Connect(_) => format!("Unable to connect to socket '{}'.", siem_ipc::wdbc::WDB_LOCAL_SOCK),
                    other => other.to_string(),
                };
                self.ctx.log.log("ERROR", &m);
                Err(e.code())
            }
        }
    }

    fn wdb_json(&mut self, query: &str) -> Option<siem_cjson::Json> {
        let Some(r) = self.ctx.wdb_query(query) else {
            self.ctx.log.log("ERROR", &format!("Unable to connect to socket '{}'", siem_ipc::wdbc::WDB_LOCAL_SOCK));
            return None;
        };
        match parse_result(&r) {
            (WdbcResult::Ok, p) => siem_cjson::parse(p.as_bytes()),
            (WdbcResult::Error, p) => {
                self.ctx.log.log("ERROR", &format!("Bad response from wazuh-db: {p}"));
                None
            }
            _ => None,
        }
    }

    fn agents_of_node(&mut self, mut last_id: i32, limit: i32) -> Option<Vec<i32>> {
        let mut out = Vec::new();
        loop {
            let q = format!("global get-agents-by-connection-status {last_id} active {} {limit}", self.node_name);
            let r = self.ctx.wdb_query(&q)?;
            let (st, payload) = parse_result(&r);
            match st {
                WdbcResult::Ok | WdbcResult::Due => {
                    let j = siem_cjson::parse(payload.as_bytes())?;
                    // wdb_parse_chunk_to_int: last_id is the last id of this chunk (0 if none)
                    let mut last = 0;
                    for a in j.children() {
                        if let Some(siem_cjson::Json::Number { int, .. }) = a.get("id") {
                            out.push(*int);
                            last = *int;
                        }
                    }
                    last_id = last;
                    if st == WdbcResult::Ok {
                        return Some(out);
                    }
                }
                _ => return None,
            }
        }
    }
}

impl LiveEnv {
    fn send(&mut self, which: bool, msg: &[u8]) {
        let path = self.ctx.home.join(if which { "queue/alerts/execq" } else { "queue/alerts/ar" });
        let slot = if which { &mut self.exec } else { &mut self.ar };
        if slot.is_none() {
            let p = path.clone();
            *slot = self.ctx.rt.block_on(async move { siem_ipc::local::DatagramSender::connect(p).await.ok() });
            if slot.is_none() {
                self.ctx.log.log("ERROR", &format!("(1210): Queue '{}' not accessible: 'connect failed'", path.display()));
                return;
            }
        }
        let s = slot.as_ref().unwrap();
        // OS_SendUnix(socket, exec_msg, 0): strlen + 1 bytes
        let mut wire = msg.to_vec();
        wire.push(0);
        let ok = self.ctx.rt.block_on(s.send(&wire)).is_ok();
        if !ok {
            *slot = None;
            self.ctx.log.log("ERROR", &format!("(1321): Error communicating with queue '{}'.", path.display()));
        }
    }
}

impl LabelCache {
    /// `labels_find`
    fn find(&mut self, ctx: &Ctx, agent_id: &[u8]) -> Vec<Label> {
        if agent_id == b"000" {
            return self.config.clone();
        }
        let id = String::from_utf8_lossy(agent_id).into_owned();
        let now = TimeSpec::now().sec;
        if let Some((l, mtime)) = self.cache.get(&id) {
            if now <= mtime + self.maxage {
                return l.clone();
            }
        }
        let q = format!("global get-labels {}", crate::rules::atoi(&id));
        match ctx.wdb_json(&q) {
            Some(j) => {
                let labels = to_labels(&siem_config::labels::labels_parse(&j));
                self.cache.insert(id, (labels.clone(), now));
                labels
            }
            None => Vec::new(),
        }
    }
}

impl ArBackend for LiveEnv {
    fn agent_version(&mut self, agent_id: i32) -> AgentVersion {
        let cid = format!("{agent_id:03}");
        let labels = self.labels.find(&self.ctx, cid.as_bytes());
        if let Some(v) = crate::labels::labels_get(&labels, b"_wazuh_version") {
            return AgentVersion::Found(String::from_utf8_lossy(v).into_owned());
        }
        let Some(j) = self.ctx.wdb_json(&format!("global get-agent-info {agent_id}")) else {
            return AgentVersion::NoInfo;
        };
        // cJSON_GetObjectItem(json->child, "version") as a string
        match j.children().into_iter().next().and_then(|f| f.get("version")) {
            Some(siem_cjson::Json::String(v)) => AgentVersion::Found(String::from_utf8_lossy(v).into_owned()),
            _ => AgentVersion::NoVersion,
        }
    }

    fn active_agents(&mut self) -> Option<Vec<i32>> {
        let mut last = 0;
        let mut out = Vec::new();
        loop {
            let r = self.ctx.wdb_query(&format!("global get-agents-by-connection-status {last} active"))?;
            let (st, payload) = parse_result(&r);
            match st {
                WdbcResult::Ok | WdbcResult::Due => {
                    let j = siem_cjson::parse(payload.as_bytes())?;
                    for a in j.children() {
                        if let Some(siem_cjson::Json::Number { int, .. }) = a.get("id") {
                            out.push(*int);
                            last = *int;
                        }
                    }
                    if st == WdbcResult::Ok {
                        return Some(out);
                    }
                }
                _ => return None,
            }
        }
    }

    fn node_name(&mut self) -> String {
        self.node_name.clone()
    }

    fn send_exec(&mut self, msg: &[u8]) {
        self.send(true, msg)
    }

    fn send_ar(&mut self, msg: &[u8]) {
        self.send(false, msg)
    }
}

/// The rule-matching side of the daemon (decode + rules + writers).
pub struct Analysis {
    pub cfg: AnalysisdConfig,
    pub engine: Engine,
    pub stats: Stats,
    pub stats_rule: Option<RuleId>,
    pub files: LogFiles,
    ar_cfg: ArConfig,
    whitelist: ArWhitelist,
    forwarder: Option<Forwarder>,
    fts_file: Option<File>,
    today: i32,
    thishour: i32,
    prev_year: i32,
    prev_month: String,
    hourly_events: u64,
    hourly_syscheck: u64,
    hourly_firewall: u64,
    node_name: String,
    reported: std::collections::HashSet<u8>,
    /// state.c counters
    pub state: State,
    /// limits.c
    pub limits: Limits,
    inq: InQueues,
    reported_eps_drop: bool,
    reported_eps_drop_hourly: bool,
    state_secs: i32,
    limits_msg: Option<crate::limits::LimitsMsg>,
    /// `HostinfoInit` state (opened when the event loop starts).
    hostinfo: Option<crate::internal::hostinfo::Hostinfo>,
    winevt: crate::internal::winevt::Winevt,
    sca: crate::internal::sca::Sca,
    syscollector: crate::internal::syscollector::Syscollector,
    fim: crate::internal::syscheck::Fim,
}

fn engine_config(cfg: &AnalysisdConfig, shost: &[u8], manager: &[u8]) -> EngineConfig {
    let g = &cfg.global;
    EngineConfig {
        rule: RuleConfig {
            decoder_order_size: cfg.internal.decoder_order_size as usize,
            mailbylevel: g.mailbylevel as i32,
            logbylevel: g.logbylevel as i32,
            default_timeframe: cfg.internal.default_timeframe,
            rulepath: "ruleset/rules".into(),
            home: cfg.home.clone(),
        },
        memorysize: g.memorysize,
        fts_list_size: cfg.internal.fts_list_size as usize,
        fts_min_size_for_str: cfg.internal.fts_min_size_for_str as usize,
        shost: shost.to_vec(),
        manager_name: manager.to_vec(),
        diff_dir: cfg.home.join("queue/diff"),
        ignore_file: Some(cfg.home.join("queue/fts/ig-queue")),
        hide_cluster_info: g.hide_cluster_info != 0,
        cluster_name: g.cluster_name.clone(),
        node_name: g.node_name.clone(),
        show_hidden_labels: g.show_hidden_labels != 0,
        mitre: None,
    }
}

/// The `active_responses` list the rules are bound to
/// (`Rules_OP_ReadRules(.., true)`).
fn rule_ars(cfg: &AnalysisdConfig) -> Vec<RuleAr> {
    cfg.ar
        .responses
        .iter()
        .map(|a| RuleAr {
            name: Some(a.name.clone()),
            command: Some(a.command.clone()),
            agent_id: a.agent_id.clone(),
            rules_id: a.rules_id.clone(),
            rules_group: a.rules_group.clone(),
            level: a.level,
            timeout: a.timeout,
            location: a.location,
            ar_cmd: Some(cfg.ar.commands[a.ar_cmd].name.clone()),
        })
        .collect()
}

/// `gethostname` and the short host (`__shost`, domain removed).
pub fn hostnames() -> (Vec<u8>, Vec<u8>) {
    let full = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "localhost".into());
    let short = full.split('.').next().unwrap_or("").to_string();
    (full.into_bytes(), short.into_bytes())
}

impl Analysis {
    /// Load the ruleset (decoders, lists, rules bound to the active
    /// responses) the way analysisd's `main()` does: each file's messages
    /// are logged as it is read and the first failure stops the load with
    /// the critical message `main()` exits with. `test` is `-t`.
    pub fn new(mut cfg: AnalysisdConfig, log: &dyn Logger, test: bool) -> Result<Self, String> {
        let (full, short) = hostnames();
        let ecfg = engine_config(&cfg, &short, &full);
        let mut engine = Engine::new(ecfg);
        let ars = rule_ars(&cfg);
        let home = cfg.home.clone();
        // the messages of one file (OSList with ERRORLIST_MAXSIZE)
        let flush = |l: &mut LogList| -> bool {
            let mut error = false;
            for m in l.take() {
                match m.level {
                    LogLevel::Warning => log.log("WARNING", &m.msg),
                    LogLevel::Error => {
                        log.log("ERROR", &m.msg);
                        error = true;
                    }
                    LogLevel::Info => {}
                }
            }
            error
        };
        let mut l = LogList::bounded();
        // no decoders configured: the default directories (legacy loading)
        if cfg.ruleset.decoders.is_empty() {
            let _ = crate::ruleset::read_rules(&[], &mut cfg.ruleset, &home, &mut l);
            flush(&mut l);
        }
        let order = engine.cfg.rule.decoder_order_size;
        for f in &cfg.ruleset.decoders {
            if !test {
                log.log("DEBUG", &format!("Reading decoder file {f}."));
            }
            let failed = engine.decoders.read_decode_xml(f, order, &home, &mut l) == 0;
            flush(&mut l);
            if failed {
                return Err(format!("(1202): Configuration error at '{f}'."));
            }
        }
        // SetDecodeXML: its result is not checked, its error messages are
        engine.decoders.set_decode_xml(&mut l);
        if flush(&mut l) {
            return Err("(2105): Error loading decoder options.".into());
        }
        for f in &cfg.ruleset.lists {
            if !test {
                log.log("DEBUG", &format!("Reading the lists file: '{f}'"));
            }
            let failed = engine.lists.load_list(f, &home, &mut l) < 0;
            flush(&mut l);
            if failed {
                return Err(format!("(1221): Error loading the list: '{f}'."));
            }
        }
        log.log("DEBUG", "Building CDB lists.");
        if cfg.ruleset.includes.is_empty() {
            let _ = crate::ruleset::read_rules(&[], &mut cfg.ruleset, &home, &mut l);
            flush(&mut l);
        }
        for f in &cfg.ruleset.includes {
            if !test {
                log.log("DEBUG", &format!("Reading rules file: '{f}'"));
            }
            let failed = engine.rules.read_rules(f, &engine.lists, &engine.decoders, &engine.cfg.rule, Some(&ars), &mut l) < 0;
            flush(&mut l);
            if failed {
                return Err(format!("(1220): Error loading the rules: '{f}'."));
            }
        }
        // _setlevels (printRuleinfo for each rule) and the total
        let mut total = 0;
        fn walk(r: &crate::rules::Rules, nodes: &[crate::rules::RNode], depth: i32, log: &dyn Logger, total: &mut i32) {
            for n in nodes {
                let ri = &r.infos[n.rule];
                *total += 1;
                log.log("DEBUG", &format!("{depth} : rule:{}, level {}, timeout: {}", ri.sigid, ri.level, ri.ignore_time));
                walk(r, &n.children, depth + 1, log, total);
            }
        }
        engine.rules.set_levels();
        walk(&engine.rules, &engine.rules.tree, 0, log, &mut total);
        if !test {
            log.log("INFO", &format!("Total rules enabled: '{total}'"));
        }
        let mut h = HashMap::new();
        engine.rules.rules_hash(&mut h);
        for (k, v) in h {
            engine.g_rules_hash.entry(k).or_insert(v);
        }
        // RootcheckInit, ... (OS_ReadMSG)
        engine.internal = crate::internal::InternalDecoders::init(&mut engine.decoders, order);
        let stats_rule = if cfg.global.stats != 0 {
            engine.rules.infos.push(stats_rule(cfg.global.stats as i32, cfg.global.mailbylevel as i32, cfg.global.logbylevel as i32));
            Some(engine.rules.infos.len() - 1)
        } else {
            None
        };
        let whitelist = ArWhitelist { ips: cfg.global.white_list.clone(), hostnames: cfg.global.hostname_white_list.clone() };
        let forwarder = if !cfg.global.forwarders_list.is_empty() { cfg.sockets.first().cloned().map(Forwarder::new) } else { None };
        let node_name = cfg.cluster.node_name.clone().unwrap_or_else(|| "undefined".into());
        let mut stats = Stats {
            maxdiff: cfg.internal.stats_maxdiff,
            mindiff: cfg.internal.stats_mindiff,
            percent_diff: cfg.internal.stats_percent_diff,
            ..Default::default()
        };
        if init_stats(&cfg.home, &mut stats).is_err() {
            // Config.stats = 0 on failure
        }
        let ar_cfg = cfg.ar.clone();
        // load_limits (logged when the main loop starts, see `start`)
        let (limits, limits_msg) = Limits::load(cfg.global.eps.maximum, cfg.global.eps.timeframe, cfg.global.eps.maximum_found);
        let inq = InQueues::new(&cfg.internal.q);
        let now = engine.clock.now().sec;
        let mut a = Analysis {
            cfg,
            engine,
            stats,
            stats_rule,
            files: LogFiles::default(),
            ar_cfg,
            whitelist,
            forwarder,
            fts_file: None,
            today: 0,
            thishour: 0,
            prev_year: 0,
            prev_month: String::new(),
            hourly_events: 0,
            hourly_syscheck: 0,
            hourly_firewall: 0,
            node_name,
            reported: Default::default(),
            state: State::new(now),
            limits,
            inq,
            reported_eps_drop: false,
            reported_eps_drop_hourly: false,
            state_secs: 0,
            limits_msg: Some(limits_msg),
            hostinfo: None,
            winevt: Default::default(),
            sca: Default::default(),
            syscollector: Default::default(),
            fim: Default::default(),
        };
        a.init_fts();
        Ok(a)
    }

    /// The daemon's environment (labels from wazuh-db, AR queues).
    pub fn live_env(&self, ctx: Ctx) -> LiveEnv {
        let labels = LabelCache {
            config: to_labels(&self.cfg.labels),
            cache: HashMap::new(),
            maxage: self.cfg.internal.label_cache_maxage as i64,
        };
        LiveEnv { ctx, labels, exec: None, ar: None, node_name: self.node_name.clone() }
    }

    /// `mitre_load`: the MITRE table from wazuh-db, shared with logtest.
    pub fn load_mitre(&mut self, env: &mut dyn Env) {
        let mut errs = Vec::new();
        let db = crate::mitre::MitreDb::load(&mut |q| env.wdb_json(q), &mut errs);
        for e in errs {
            env.log("ERROR", e.as_bytes());
        }
        let db = db.map(std::sync::Arc::new);
        self.engine.cfg.mitre = db.clone();
        self.engine.mitre = db;
    }

    /// `w_hotreload_reload`: load the ruleset of `etc/ossec.conf` again and
    /// switch to it (decoders, CDB lists, rules bound to the start-up active
    /// responses, a new event list, FTS reloaded from `queue/fts/fts-queue`
    /// and a new accumulator). Returns true when the new ruleset could not
    /// be loaded (the current one stays); `list` gets the load messages.
    pub fn reload_ruleset(&mut self, env: &mut dyn Env, list: &mut LogList) -> bool {
        let home = self.cfg.home.clone();
        let conf = home.join("etc/ossec.conf");
        let Some(rs) = crate::ruleset::load_ruleset_conf(&conf, "etc/ossec.conf", &home, false, list) else {
            return true;
        };
        let mut engine = Engine::new(self.engine.cfg.clone());
        let ars = rule_ars(&self.cfg);
        if !engine.load_ruleset(&rs.decoders, &rs.lists, &rs.includes, Some(&ars), list) {
            return true;
        }
        // w_hotreload_reload_internal_decoders
        let order = engine.cfg.rule.decoder_order_size;
        engine.internal = crate::internal::InternalDecoders::init(&mut engine.decoders, order);
        // FTS_HotReload
        if let Ok(d) = std::fs::read(home.join("queue/fts/fts-queue")) {
            engine.preload_fts(&d);
        }
        env.log("INFO", b"Reloading ruleset");
        // daemon-wide state outlives the ruleset
        engine.clock = std::mem::replace(&mut self.engine.clock, Box::new(crate::engine::SystemClock));
        engine.alert_second_id = self.engine.alert_second_id;
        engine.hourly_alerts = self.engine.hourly_alerts;
        engine.fts_writes = std::mem::take(&mut self.engine.fts_writes);
        engine.mitre = self.engine.mitre.clone();
        if let Some(sr) = self.stats_rule {
            // the statistics rule belongs to the rule-matching thread
            engine.rules.infos.push(self.engine.rules.infos[sr].clone());
            self.stats_rule = Some(engine.rules.infos.len() - 1);
        }
        self.engine = engine;
        self.cfg.ruleset.decoders = rs.decoders;
        self.cfg.ruleset.includes = rs.includes;
        self.cfg.ruleset.lists = rs.lists;
        env.log("INFO", b"Ruleset reloaded successfully");
        false
    }

    /// `OS_ReadMSG`'s decoder initialisation (`HostinfoInit` opens its file).
    pub fn init_decoders(&mut self, env: &mut dyn Env) {
        self.hostinfo = Some(crate::internal::hostinfo::Hostinfo::init(&self.cfg.home, env));
    }

    /// Local broken-down "now" of the engine clock.
    fn local_now(&self) -> chrono::DateTime<chrono::FixedOffset> {
        crate::localtime::at(self.engine.clock.now().sec)
    }

    fn init_fts(&mut self) {
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

    /// `Start_Time` + the first `OS_GetLogLocation`.
    pub fn start(&mut self) -> std::io::Result<()> {
        let now = self.local_now();
        self.today = now.day() as i32;
        self.thishour = now.hour() as i32;
        self.prev_year = now.year();
        self.prev_month = MONTHS[now.month0() as usize].to_string();
        let m = self.prev_month.clone();
        self.state.g.uptime = now.timestamp() as u64;
        self.files.get_log_location(&self.cfg.home, &self.cfg.global, self.today, self.prev_year, &m, now.timestamp())
    }

    /// The queue figures of the state reports.
    pub fn queue_status(&self) -> QueueStatus {
        let q = &self.cfg.internal.q;
        let empty = |size: usize| QueueStat::new(size, 0);
        QueueStatus {
            syscheck: self.inq.stat(Kind::Syscheck),
            syscollector: self.inq.stat(Kind::Syscollector),
            rootcheck: self.inq.stat(Kind::Rootcheck),
            sca: self.inq.stat(Kind::Sca),
            hostinfo: self.inq.stat(Kind::Hostinfo),
            winevt: self.inq.stat(Kind::Winevt),
            dbsync: self.inq.stat(Kind::Dbsync),
            upgrade: self.inq.stat(Kind::Upgrade),
            events: self.inq.stat(Kind::Event),
            // the stages after decoding run inline: always empty
            processed: empty(q.output),
            alerts: empty(q.alerts),
            archives: empty(q.archives),
            firewall: empty(q.firewall),
            fts: empty(q.fts),
            stats: empty(q.statistical),
        }
    }

    /// `w_analysisd_write_state`
    pub fn write_state(&self, env: &mut dyn Env) {
        if let Err(e) = self.state.write_file(&self.cfg.home, &self.queue_status()) {
            for l in e.split('\n') {
                env.log("ERROR", l.as_bytes());
            }
        }
    }

    /// `asys_create_state_json` (`getstats`)
    pub fn state_json(&self) -> siem_cjson::Json {
        let g = &self.cfg.global.eps;
        let eps = if g.maximum > 0 && g.timeframe > 0 {
            Some(EpsReport { available_credits: self.limits.limit_reached().1 })
        } else {
            None
        };
        self.state.state_json(self.engine.clock.now().sec, &self.queue_status(), eps)
    }

    /// The main thread's once-a-second EPS bookkeeping and the state thread.
    pub fn second(&mut self, env: &mut dyn Env) {
        let (reached, credits) = self.limits.limit_reached();
        if reached {
            self.state.g.eps.seconds_over_limit += 1;
        }
        self.state.g.eps.available_credits_prev = credits as u64;
        self.limits.update();
        let interval = self.cfg.internal.state_interval;
        if interval > 0 {
            self.state_secs += 1;
            if self.state_secs >= interval {
                self.state_secs = 0;
                if !self.state.agents.is_empty() {
                    if let Some(active) = env.agents_of_node(0, -1) {
                        self.state.clean_agents(&active);
                    }
                }
                self.write_state(env);
            }
        }
        self.pump(env);
    }

    /// One iteration of `w_log_rotate_thread` (called every second).
    pub fn tick(&mut self, log: &dyn Logger) {
        let now = self.local_now();
        let (day, year, hour) = (now.day() as i32, now.year(), now.hour() as i32);
        let mon = MONTHS[now.month0() as usize];
        self.files.flush();
        if let Some(f) = &mut self.fts_file {
            let _ = f.flush();
        }
        if self.thishour != hour {
            self.dump_logstats();
            self.thishour = hour;
            // Reset EPS logging flag to avoid flooding
            if self.reported_eps_drop_hourly && !self.reported_eps_drop {
                self.reported_eps_drop_hourly = false;
            }
            if self.today != day {
                if self.cfg.global.stats != 0 {
                    self.update_hour();
                }
                if let Err(e) = self.files.get_log_location(&self.cfg.home, &self.cfg.global, day, year, mon, now.timestamp()) {
                    log.log("CRITICAL", &format!("Error allocating log files: {e}"));
                }
                self.today = day;
                self.prev_month = mon.to_string();
                self.prev_year = year;
            }
        }
        self.files.rotate(&self.cfg.home, &self.cfg.global, day, year, mon, now.timestamp());
    }

    /// `DumpLogstats`
    fn dump_logstats(&mut self) {
        let Ok(mut f) = totals_file(&self.cfg.home, self.prev_year, &self.prev_month, self.today) else {
            return;
        };
        let mut s = String::new();
        for l in self.engine.dump_rule_stats(self.thishour) {
            s.push_str(&l);
            s.push('\n');
        }
        s.push_str(&format!(
            "{}--{}--{}--{}--{}\n\n",
            self.thishour, self.engine.hourly_alerts, self.hourly_events, self.hourly_syscheck, self.hourly_firewall
        ));
        let _ = f.write_all(s.as_bytes());
        self.engine.hourly_alerts = 0;
        self.hourly_events = 0;
        self.hourly_syscheck = 0;
        self.hourly_firewall = 0;
    }

    /// `Update_Hour` + `print_totals`
    fn update_hour(&mut self) {
        let (hourly, weekly, totals) = self.stats.update_hour();
        if let Ok(mut f) = totals_file(&self.cfg.home, self.prev_year, &self.prev_month, self.today) {
            let _ = f.write_all((totals.join("\n") + "\n").as_bytes());
        }
        for (i, v) in hourly {
            let _ = std::fs::write(self.cfg.home.join(format!("{STATQUEUE}/{i}")), v.to_string());
        }
        for (i, j, v) in weekly {
            let _ = std::fs::write(self.cfg.home.join(format!("{STATWQUEUE}/{i}/{j}")), v.to_string());
        }
    }

    /// The writer threads, run inline for one outcome.
    fn write_outcome(&mut self, env: &mut dyn Env, out: Outcome) {
        let g = self.cfg.global.clone();
        // messages in the order the threads emit them
        let mut msgs = LogList::default();
        let mut lines: Vec<(&'static str, Vec<u8>)> = Vec::new();
        let drain = |msgs: &mut LogList, lines: &mut Vec<(&'static str, Vec<u8>)>| {
            for m in msgs.take() {
                lines.push((if m.level == LogLevel::Error { "ERROR" } else { "WARNING" }, m.msg.into_bytes()));
            }
        };
        let now = self.engine.clock.now().sec;
        if let Some(mut ev) = out.firewall {
            self.state.firewall_written(ev.agent_id.as_deref(), now);
            let mut buf = Vec::new();
            let _ = output::fw_log(&mut ev, &mut buf);
            self.files.ff.write(&buf);
            self.files.ff.flush();
        }
        if let Some(ev) = out.stats_alert {
            self.state.stats_written();
            self.write_alert(&g, &ev, &mut msgs, false);
        }
        if let Some(ev) = out.alert {
            self.state.alert_written(ev.agent_id.as_deref(), now);
            self.write_alert(&g, &ev, &mut msgs, true);
        }
        if let Some(line) = out.ignore_line {
            if let Some(p) = &self.engine.cfg.ignore_file {
                if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
                    let _ = f.write_all(&line);
                }
            }
        }
        // AR sanity warnings interleave with OS_Exec in rule order
        let n_ar = out.ar.len();
        for (k, (idx, ev)) in out.ar.into_iter().enumerate() {
            drain(&mut msgs, &mut lines);
            for (_, w) in out.warnings.iter().filter(|(p, _)| *p == k) {
                lines.push(("WARNING", w.clone()));
            }
            let ar = self.ar_cfg.responses[idx].clone();
            let cmd = self.ar_cfg.commands[ar.ar_cmd].clone();
            os_exec(&self.engine, &ev, &ar, &cmd, g.ar, &self.whitelist, env.ar(), &mut msgs);
        }
        drain(&mut msgs, &mut lines);
        for (_, w) in out.warnings.iter().filter(|(p, _)| *p >= n_ar) {
            lines.push(("WARNING", w.clone()));
        }
        if let Some(ev) = out.archive {
            self.state.archive_written(ev.agent_id.as_deref(), now);
            if g.logall != 0 {
                let mut buf = Vec::new();
                let _ = output::os_store(&ev, &mut buf);
                self.files.ef.write(&buf);
            }
            if g.logall_json != 0 {
                if let Some(l) = output::json_archive(&self.engine, &ev, &mut msgs) {
                    self.files.ejf.write(&l);
                }
            }
        }
        drain(&mut msgs, &mut lines);
        for (level, m) in lines {
            env.log(level, &m);
        }
        for l in std::mem::take(&mut self.engine.fts_writes) {
            self.state.fts_written();
            if let Some(f) = &mut self.fts_file {
                let _ = f.write_all(&l);
                let _ = f.write_all(b"\n");
            }
        }
    }

    /// `w_writer_log_thread` / `w_writer_log_statistical_thread` body.
    /// `forward`: `w_writer_log_thread` (sends to the forwarders); the
    /// statistical writer does not.
    fn write_alert(&mut self, g: &siem_config::global::GlobalConfig, ev: &Event, msgs: &mut LogList, forward: bool) {
        if g.custom_alert_output != 0 {
            self.engine.alert_second_id = self.files.af.pos as i64;
            let fmt = g.custom_alert_output_format.clone().unwrap_or_default();
            let mut buf = Vec::new();
            let _ = output::os_custom_log(&self.engine, ev, fmt.as_bytes(), &mut buf);
            self.files.af.write(&buf);
        } else if g.alerts_log != 0 {
            self.engine.alert_second_id = self.files.af.pos as i64;
            let mut buf = Vec::new();
            let _ = output::os_log(&self.engine, ev, &mut buf);
            self.files.af.write(&buf);
        } else if g.jsonout_output != 0 {
            self.engine.alert_second_id = self.files.jf.pos as i64;
        }
        if g.jsonout_output != 0 {
            let before = msgs.msgs.len();
            let line = output::json_alert(&self.engine, ev, msgs);
            self.files.jf.write(&line);
            let now = self.engine.clock.now().sec;
            if let Some(fw) = self.forwarder.as_mut().filter(|_| forward) {
                // Eventinfo_to_jsonstr runs again for the forwarders
                let again: Vec<_> = msgs.msgs[before..].to_vec();
                msgs.msgs.extend(again);
                fw.send(&line[..line.len() - 1], now, msgs);
            }
        }
    }

    /// One message from `queue/sockets/queue`, then whatever the EPS
    /// credits allow to be decoded.
    pub fn handle_message(&mut self, env: &mut dyn Env, msg: &[u8]) {
        self.receive(env, msg);
        self.pump(env);
    }

    /// `ad_input_main` for one datagram: validate, count and queue it.
    pub fn receive(&mut self, env: &mut dyn Env, msg: &[u8]) {
        // buffer[recv] = '\0'; the queued copy is os_strdup(buffer)
        let cmsg = cstr(msg);
        if cmsg.len() < 4 {
            env.log("ERROR", &[&b"(1222): Invalid msg: "[..], cmsg].concat());
            return;
        }
        self.state.received(msg.len());
        let kind = Kind::of(cmsg[0]);
        let pushed = self.inq.push(kind, cmsg.to_vec());
        if pushed {
            self.hourly_events += 1;
            if kind == Kind::Syscheck {
                self.hourly_syscheck += 1;
            }
        } else {
            match kind.dropped_component() {
                Some(c) => self.state.dropped(c),
                None => match cmsg[0] {
                    CISCAT_MQ => self.state.dropped(Component::Ciscat),
                    SYSLOG_MQ => self.state.dropped(Component::Syslog),
                    LOCALFILE_MQ => match crate::state::module_from_message(cmsg) {
                        Some(m) => self.state.dropped(Component::from_module(m)),
                        None => env.log("ERROR", b"(1106): String not correctly formatted."),
                    },
                    _ => {}
                },
            }
            let r = self.inq.reported_mut(kind);
            if !*r {
                *r = true;
                env.log("WARNING", kind.full_warning().as_bytes());
            }
        }
        // EPS accounting of drops
        if !pushed {
            if !self.reported_eps_drop {
                if self.limits.limit_reached().0 {
                    self.reported_eps_drop = true;
                    if !self.reported_eps_drop_hourly {
                        env.log("WARNING", b"Queues are full and no EPS credits, dropping events.");
                    }
                    self.state.g.eps.events_dropped += 1;
                } else {
                    self.state.g.eps.events_dropped_not_eps += 1;
                }
            } else {
                self.state.g.eps.events_dropped += 1;
            }
        } else if self.reported_eps_drop {
            self.reported_eps_drop = false;
            if !self.reported_eps_drop_hourly {
                env.log("INFO", b"Queues back to normal and EPS credits, no dropping events.");
                self.reported_eps_drop_hourly = true;
            }
        }
    }

    /// The decoder threads: decode queued messages while EPS credits last.
    pub fn pump(&mut self, env: &mut dyn Env) {
        self.pump_some(env, usize::MAX);
    }

    /// `pump` for at most `max` messages (the daemon interleaves input).
    pub fn pump_some(&mut self, env: &mut dyn Env, max: usize) {
        let mut n = 0;
        while n < max && !self.inq.is_empty() {
            if !self.limits.try_credit() {
                return;
            }
            let (kind, msg) = self.inq.pop().unwrap();
            self.decode_and_process(env, kind, &msg);
            n += 1;
        }
    }

    /// Messages a decoder could take right now (queued and EPS credits).
    pub fn can_pump(&self) -> bool {
        !self.inq.is_empty() && !self.limits.limit_reached().0
    }

    /// Messages still waiting for a decoder.
    pub fn pending(&self) -> bool {
        !self.inq.is_empty()
    }

    fn decode_and_process(&mut self, env: &mut dyn Env, kind: Kind, msg: &[u8]) {
        let ported = matches!(
            kind,
            Kind::Event | Kind::Rootcheck | Kind::Hostinfo | Kind::Dbsync | Kind::Winevt | Kind::Sca | Kind::Upgrade | Kind::Syscheck | Kind::Syscollector
        );
        if !ported {
            // Internal decoders (syscheck, rootcheck, SCA, syscollector,
            // hostinfo, eventchannel, dbsync, upgrade, CIS-CAT) are handled
            // by their own decoder modules.
            if self.reported.insert(msg[0]) {
                env.log(
                    "WARNING",
                    format!("No decoder for internal message type '{}' yet; message ignored.", msg[0] as char).as_bytes(),
                );
            }
            return;
        }
        let now = self.engine.clock.now();
        let mut ev = self.engine.new_event();
        if ev.clean_msg(msg, &self.engine.cfg.shost.clone(), now).is_err() {
            env.log("ERROR", b"(1106): String not correctly formatted.");
            env.log("ERROR", &[&b"(1222): Invalid msg: "[..], msg].concat());
            return;
        }
        match kind {
            Kind::Dbsync => {
                // w_dispatch_dbsync_thread: no rule matching
                self.state.decoded(Component::Dbsync, ev.agent_id.as_deref(), now.sec);
                let agent = ev.agent_id.clone().unwrap_or_default();
                let log = ev.log().to_vec();
                crate::internal::dbsync::dispatch(env, cstr(&agent), &log);
                return;
            }
            Kind::Syscheck => {
                self.state.decoded(Component::Syscheck, ev.agent_id.as_deref(), now.sec);
                let g = &self.cfg.global;
                let fcfg = crate::internal::syscheck::FimConfig {
                    alert_new: g.syscheck_alert_new != 0,
                    auto_ignore: g.syscheck_auto_ignore != 0,
                    ignore_time: g.syscheck_ignore_time as i64,
                    ignore_frequency: g.syscheck_ignore_frequency,
                };
                let ids = self.engine.internal;
                if !self.fim.decode(env, &mut self.engine.decoders, ids.fim, &ids.fim_ids, &fcfg, &mut ev) {
                    return;
                }
            }
            Kind::Upgrade => {
                // w_dispatch_upgrade_module_thread: no rule matching
                self.state.decoded(Component::Upgrade, ev.agent_id.as_deref(), now.sec);
                let agent = ev.agent_id.clone().unwrap_or_default();
                let log = ev.log().to_vec();
                crate::internal::upgrade::dispatch(env, cstr(&agent), &log);
                return;
            }
            Kind::Syscollector => {
                self.state.decoded(Component::Syscollector, ev.agent_id.as_deref(), now.sec);
                let dec = self.engine.internal.syscollector;
                let order = self.engine.cfg.rule.decoder_order_size;
                if !self.syscollector.decode(env, dec, order, &mut ev) {
                    return;
                }
            }
            Kind::Sca => {
                self.state.decoded(Component::Sca, ev.agent_id.as_deref(), now.sec);
                let dec = self.engine.internal.sca;
                let order = self.engine.cfg.rule.decoder_order_size;
                let keep = self.sca.decode(env, dec, order, &mut ev);
                // RequestDBThread
                self.sca.drain(env);
                if !keep {
                    return;
                }
            }
            Kind::Winevt => {
                self.state.decoded(Component::Eventchannel, ev.agent_id.as_deref(), now.sec);
                let dec = self.engine.internal.winevt;
                let order = self.engine.cfg.rule.decoder_order_size;
                if !self.winevt.decode(env, &mut self.engine.decoders, dec, order, &mut ev) {
                    return;
                }
            }
            Kind::Hostinfo => {
                self.state.decoded(Component::Others, ev.agent_id.as_deref(), now.sec);
                let ids = self.engine.internal;
                let hi = self.hostinfo.get_or_insert_with(|| crate::internal::hostinfo::Hostinfo::init(&self.cfg.home, env));
                if !hi.decode(env, &mut self.engine.decoders, &ids, &mut ev) {
                    return;
                }
            }
            Kind::Rootcheck => {
                self.state.decoded(Component::Rootcheck, ev.agent_id.as_deref(), now.sec);
                let dec = self.engine.internal.rootcheck;
                if !crate::internal::rootcheck::decode(env, dec, &mut ev) {
                    return;
                }
            }
            _ if msg[0] == CISCAT_MQ => {
                self.state.decoded(Component::Ciscat, ev.agent_id.as_deref(), now.sec);
                let dec = self.engine.internal.ciscat;
                let order = self.engine.cfg.rule.decoder_order_size;
                if !crate::internal::ciscat::decode(env, &mut self.engine.decoders, dec, order, &mut ev) {
                    return;
                }
            }
            _ => {
                match msg[0] {
                    SYSLOG_MQ => self.state.decoded(Component::Syslog, None, now.sec),
                    LOCALFILE_MQ => {
                        let loc = ev.f[F_LOCATION].clone().unwrap_or_default();
                        let c = Component::from_module(crate::state::module_from_location(&loc));
                        self.state.decoded(c, ev.agent_id.as_deref(), now.sec);
                    }
                    _ => {}
                }
                self.engine.decode(&mut ev);
            }
        }
        let opts = ProcessOptions {
            logfw: self.cfg.internal.log_fw != 0,
            logall: self.cfg.global.logall != 0 || self.cfg.global.logall_json != 0,
            stats: self.cfg.global.stats as i32,
        };
        let lnow = self.local_now();
        let (hour, wday) = (lnow.hour() as i32, lnow.weekday().num_days_from_sunday() as i32);
        let state = &mut self.state;
        let mut labels = |ev: &Event| {
            let l = env.labels(ev.agent_id.as_deref().unwrap_or(b""));
            state.processed(ev.agent_id.as_deref(), now.sec);
            l
        };
        let out = self.engine.process_event(ev, &opts, &mut self.stats, self.stats_rule, hour, wday, &mut labels);
        if out.firewall_event {
            self.hourly_firewall += 1;
        }
        self.write_outcome(env, out);
    }
}

/// The `%s` view of a buffer (up to the first NUL).
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

#[cfg(unix)]
enum FwdSock {
    Dgram(std::os::unix::net::UnixDatagram),
    Stream(std::os::unix::net::UnixStream),
}

/// A `socket_forwarder` with its connection: `SendJSONtoSCK` sends every
/// alert to the first `<socket>` when `<forward_to>` is configured.
pub struct Forwarder {
    cfg: SocketForwarder,
    #[cfg(unix)]
    sock: Option<FwdSock>,
    #[cfg_attr(not(unix), allow(dead_code))]
    last_attempt: i64,
}

impl Forwarder {
    pub fn new(cfg: SocketForwarder) -> Self {
        Forwarder {
            cfg,
            #[cfg(unix)]
            sock: None,
            last_attempt: 0,
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn mode(&self) -> &'static str {
        match self.cfg.mode {
            siem_config::socket::SocketMode::Udp => "udp",
            siem_config::socket::SocketMode::Tcp => "tcp",
        }
    }

    #[cfg(unix)]
    fn connect(&self) -> Option<FwdSock> {
        use std::os::unix::net::{UnixDatagram, UnixStream};
        match self.cfg.mode {
            siem_config::socket::SocketMode::Udp => {
                let s = UnixDatagram::unbound().ok()?;
                s.connect(&self.cfg.location).ok()?;
                Some(FwdSock::Dgram(s))
            }
            siem_config::socket::SocketMode::Tcp => UnixStream::connect(&self.cfg.location).ok().map(FwdSock::Stream),
        }
    }

    /// `OS_SendUnix(sock, msg, strlen(msg))`: Ok, or Err(true) when busy (ENOBUFS).
    #[cfg(unix)]
    fn send_raw(sock: &mut FwdSock, msg: &[u8]) -> Result<(), bool> {
        let r = match sock {
            FwdSock::Dgram(s) => s.send(msg).map(|n| n == msg.len()),
            FwdSock::Stream(s) => s.write(msg).map(|n| n == msg.len()),
        };
        match r {
            Ok(true) => Ok(()),
            Ok(false) => Err(false),
            Err(e) => Err(e.raw_os_error() == Some(105)),
        }
    }

    /// `SendJSONtoSCK` (`sock_fail_time` is 0 in analysisd: one attempt
    /// per second). Errors go to `msgs`.
    pub fn send(&mut self, msg: &[u8], now: i64, msgs: &mut LogList) {
        if self.cfg.name == "agent" {
            return;
        }
        #[cfg(unix)]
        {
            if self.sock.is_none() {
                if now > self.last_attempt {
                    match self.connect() {
                        Some(s) => self.sock = Some(s),
                        None => {
                            self.last_attempt = now;
                            msgs.error(format!(
                                "Unable to connect to socket '{}': {} ({})",
                                self.cfg.name,
                                self.cfg.location,
                                self.mode()
                            ));
                            return;
                        }
                    }
                } else {
                    // "Discarding event ... due to connection issue" (debug)
                    return;
                }
            }
            let sock = self.sock.as_mut().unwrap();
            if let Err(busy) = Self::send_raw(sock, msg) {
                if !busy && now > self.last_attempt {
                    self.sock = None;
                    match self.connect() {
                        None => {
                            msgs.error(format!(
                                "Unable to connect to socket '{}': {} ({}).",
                                self.cfg.name,
                                self.cfg.location,
                                self.mode()
                            ));
                            self.last_attempt = now;
                        }
                        Some(mut s) => {
                            if Self::send_raw(&mut s, msg).is_err() {
                                self.last_attempt = now;
                            }
                            self.sock = Some(s);
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

/// Run the daemon until the input queue closes.
/// The messages `main()` logs between loading the ruleset and starting.
fn startup_messages(cfg: &AnalysisdConfig, log: &dyn Logger) {
    let g = &cfg.global;
    if g.queue_size != 0 {
        log.log(
            "INFO",
            "The option <queue_size> is deprecated and won't apply. Set up each queue size in the internal_options file.",
        );
    }
    if g.ar != 0 {
        if g.white_list.is_empty() {
            log.log("INFO", "No IP in the white list for active response.");
        } else {
            for ip in &g.white_list {
                log.log("INFO", &format!("White listing IP: '{}'", ip.ip));
            }
            log.log("INFO", &format!("{} IPs in the white list for active response.", g.white_list.len()));
        }
        if g.hostname_white_list.is_empty() {
            log.log("INFO", "No Hostname in the white list for active response.");
        } else {
            let mut n = 0;
            for m in &g.hostname_white_list {
                for p in m.patterns() {
                    log.log_bytes("INFO", &[&b"White listing Hostname: '"[..], p, b"'"].concat());
                    n += 1;
                }
            }
            log.log("INFO", &format!("{n} Hostname(s) in the white list for active response."));
        }
    }
    log.log("INFO", &format!("Started (pid: {}).", std::process::id()));
}

/// Run the daemon (`main()` after the ruleset load, then `OS_ReadMSG`)
/// until the input queue closes.
pub fn run(mut analysis: Analysis, log: Arc<dyn Logger>) -> std::io::Result<()> {
    let home = analysis.cfg.home.clone();
    startup_messages(&analysis.cfg, &*log);
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let wdb: Arc<dyn WdbQuery> = Arc::new(WdbcSocket::new(home.join(siem_ipc::wdbc::WDB_LOCAL_SOCK)));
    let ctx = Ctx { home: home.clone(), rt: rt.handle().clone(), wdb, log: log.clone() };

    let logtest_cfg = analysis.cfg.logtest.clone();
    let mut env = analysis.live_env(ctx);
    // mitre_load (main thread, before the logtest service starts)
    analysis.load_mitre(&mut env);
    // OS_ReadMSG: OS_InitLog / the first OS_GetLogLocation, the internal
    // decoders, load_limits
    analysis.start()?;
    analysis.init_decoders(&mut env);
    if let Some((lvl, m)) = analysis.limits_msg.take() {
        log.log(lvl, &m);
    }
    // w_analysisd_state_main: write right away, then every state_interval
    if analysis.cfg.internal.state_interval == 0 {
        log.log("INFO", "State file is disabled.");
    } else {
        analysis.write_state(&mut env);
    }

    // Logtest service
    if logtest_cfg.enabled {
        let lt = Logtest::new(LogtestConfig {
            enabled: true,
            threads: logtest_cfg.threads,
            max_sessions: logtest_cfg.max_sessions,
            session_timeout: logtest_cfg.session_timeout,
            ossec_conf: PathBuf::from("etc/ossec.conf"),
            engine: analysis.engine.cfg.clone(),
        });
        let lt = Arc::new(Mutex::new(lt));
        let path = home.join("queue/sockets/logtest");
        let l2 = log.clone();
        let lt2 = lt.clone();
        rt.spawn(async move {
            let _ = std::fs::remove_file(&path);
            let listener = match siem_ipc::local::StreamListener::bind(&path).await {
                Ok(l) => l,
                Err(e) => {
                    l2.log("ERROR", &format!("(7300): Unable to bind to socket '{}'. Errno: (0) {e}", path.display()));
                    return;
                }
            };
            l2.log("INFO", "(7200): Logtest started");
            loop {
                let Ok(mut s) = listener.accept().await else { continue };
                let lt = lt2.clone();
                tokio::spawn(async move {
                    let resp = match siem_ipc::framing::recv(&mut s, OS_MAXSTR - 1).await {
                        Ok(req) => {
                            let lt = lt.clone();
                            tokio::task::spawn_blocking(move || lt.lock().unwrap().process_request(&req)).await.ok()
                        }
                        Err(siem_ipc::framing::FrameError::TooBig(..)) => {
                            Some(Logtest::error_response(crate::logtest::LOGTEST_ERROR_RECV_MSG_OVERSIZE))
                        }
                        Err(_) => None,
                    };
                    if let Some(r) = resp {
                        let _ = siem_ipc::framing::send(&mut s, &r).await;
                    }
                });
            }
        });
        let timeout = logtest_cfg.session_timeout.max(1) as u64;
        rt.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(timeout)).await;
                lt.lock().unwrap().expire_sessions();
            }
        });
    } else {
        log.log("INFO", "(7201): Logtest disabled");
    }

    // Input queue
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(131072);
    let qpath = home.join(siem_ipc::mq::DEFAULTQUEUE);
    let l3 = log.clone();
    rt.spawn(async move {
        let _ = std::fs::remove_file(&qpath);
        let rx = match siem_ipc::local::DatagramReceiver::bind(&qpath).await {
            Ok(r) => r,
            Err(e) => {
                l3.log("CRITICAL", &format!("(1210): Queue '{}' not accessible: '{e}'", qpath.display()));
                return;
            }
        };
        loop {
            match rx.recv(OS_MAXSTR).await {
                Ok(m) => {
                    if tx.send(m).is_err() {
                        break;
                    }
                }
                Err(_) => continue,
            }
        }
    });

    // Analysis socket (asyscom_main): requests are answered by this thread
    type AsysReq = (Vec<u8>, tokio::sync::oneshot::Sender<Vec<u8>>);
    let (atx, arx) = mpsc::channel::<AsysReq>();
    let apath = home.join(crate::asyscom::ANLSYS_LOCAL_SOCK);
    let l4 = log.clone();
    rt.spawn(async move {
        let _ = std::fs::remove_file(&apath);
        let listener = match siem_ipc::local::StreamListener::bind(&apath).await {
            Ok(l) => l,
            Err(e) => {
                let (n, t) = crate::logmsg::errno_text(&e);
                l4.log("ERROR", &format!("Unable to bind to socket '{}': ({n}) '{t}'", crate::asyscom::ANLSYS_LOCAL_SOCK));
                return;
            }
        };
        loop {
            let Ok(mut s) = listener.accept().await else { continue };
            let atx = atx.clone();
            let l5 = l4.clone();
            tokio::spawn(async move {
                match siem_ipc::framing::recv(&mut s, OS_MAXSTR).await {
                    Ok(req) if req.is_empty() => {} // "Empty message from local client"
                    Ok(req) => {
                        let (otx, orx) = tokio::sync::oneshot::channel();
                        if atx.send((req, otx)).is_err() {
                            return;
                        }
                        if let Ok(resp) = orx.await {
                            let _ = siem_ipc::framing::send(&mut s, &resp).await;
                        }
                    }
                    Err(siem_ipc::framing::FrameError::TooBig(..)) => {
                        l5.log("ERROR", "At OS_RecvSecureTCP(): response size is bigger than expected");
                    }
                    Err(e) => l5.log("ERROR", &format!("At OS_RecvSecureTCP(): '{e}'")),
                }
            });
        }
    });

    // Input, decoding, rule matching, writers and rotation (this thread)
    let mut last_tick = std::time::Instant::now();
    loop {
        // ad_input_main: queue (or drop) everything that has arrived
        let wait = if analysis.can_pump() { Duration::ZERO } else { Duration::from_millis(50) };
        match rx.recv_timeout(wait) {
            Ok(m) => {
                analysis.receive(&mut env, &m);
                while let Ok(m) = rx.try_recv() {
                    analysis.receive(&mut env, &m);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        while let Ok((req, otx)) = arx.try_recv() {
            let resp = crate::asyscom::dispatch(&mut analysis, &mut env, &req);
            let _ = otx.send(resp);
        }
        // the decoder and rule-matching threads
        analysis.pump_some(&mut env, 256);
        if last_tick.elapsed() >= Duration::from_secs(1) {
            analysis.tick(&*log);
            analysis.second(&mut env);
            last_tick = std::time::Instant::now();
        }
    }
    analysis.files.flush();
    Ok(())
}

/// Convenience used by tests: a timestamp's local (day, year, month).
pub fn local_ymd(sec: i64) -> (i32, i32, &'static str) {
    let t = Local.timestamp_opt(sec, 0).single().unwrap_or_else(Local::now);
    (t.day() as i32, t.year(), MONTHS[t.month0() as usize])
}
