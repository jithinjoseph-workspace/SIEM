//! The stateful part of analysisd for one ruleset: previous events
//! (`EventList`, eventinfo_list.c), the rule matcher (`OS_CheckIfRuleMatch`),
//! the context searches (`Search_LastSids/Groups/Events`), FTS / ignore lists
//! (fts.c), the accumulator (accumulator.c) and `doDiff` (dodiff.c).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use crate::decoders::{decode_event, DecodeCtx, Decoders, NULL_DECODER};
use crate::event::*;
use crate::lists::Lists;
use crate::logmsg::LogList;
use crate::mitre::MitreDb;
use crate::rules::*;

/// Configuration of an engine instance (analysisd `Config` + internal options).
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub rule: RuleConfig,
    /// `memory_size` (EventList max size).
    pub memorysize: i32,
    /// `analysisd.fts_list_size`
    pub fts_list_size: usize,
    /// `analysisd.fts_min_size_for_str`
    pub fts_min_size_for_str: usize,
    /// `__shost`: manager short hostname.
    pub shost: Vec<u8>,
    /// Manager hostname (`gethostname`), used in alerts.
    pub manager_name: Vec<u8>,
    /// Directory of `queue/diff` (doDiff state).
    pub diff_dir: PathBuf,
    /// `queue/fts/ig-queue`, read by `IGnore`.
    pub ignore_file: Option<PathBuf>,
    pub hide_cluster_info: bool,
    pub cluster_name: Option<String>,
    pub node_name: Option<String>,
    pub show_hidden_labels: bool,
    /// The MITRE table loaded at start-up (`mitre_load`), shared by every
    /// engine (analysisd and the logtest sessions).
    pub mitre: Option<std::sync::Arc<MitreDb>>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            rule: RuleConfig::default(),
            memorysize: 8192,
            fts_list_size: 32,
            fts_min_size_for_str: 14,
            shost: b"localhost".to_vec(),
            manager_name: b"localhost".to_vec(),
            diff_dir: PathBuf::from("queue/diff"),
            ignore_file: None,
            hide_cluster_info: true,
            cluster_name: None,
            node_name: None,
            show_hidden_labels: false,
            mitre: None,
        }
    }
}

/// Time source (`w_get_current_time`, `__crt_wday`) — injectable for tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> TimeSpec;
    fn weekday(&self) -> i32 {
        use chrono::Datelike;
        let t = self.now();
        crate::localtime::at(t.sec).weekday().num_days_from_sunday() as i32
    }
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> TimeSpec {
        TimeSpec::now()
    }
}

/// `OS_ACM_Store`
#[derive(Debug, Clone, Default)]
struct AcmStore {
    timestamp: i64,
    dstuser: Option<Bytes>,
    srcuser: Option<Bytes>,
    dstip: Option<Bytes>,
    srcip: Option<Bytes>,
    dstport: Option<Bytes>,
    srcport: Option<Bytes>,
    data: Option<Bytes>,
}

const OS_ACM_EXPIRE_ELM: i64 = 120;
const OS_ACM_PURGE_INTERVAL: i64 = 300;
const OS_ACM_PURGE_COUNT: i32 = 200;
const OS_ACM_MAXELM: usize = 81;
const OS_FLSIZE: usize = 256;

/// `acm_str_replace`
fn acm_str_replace(dst: &mut Option<Bytes>, src: &Option<Bytes>) {
    let Some(src) = src else {
        return;
    };
    if dst.as_ref().map_or(false, |d| !d.is_empty()) {
        return;
    }
    let slen = src.len();
    if slen == 0 || slen > OS_ACM_MAXELM - 1 {
        return;
    }
    *dst = Some(src.clone());
}

/// An analysis engine: one loaded ruleset plus its state (one logtest
/// session, or the analysisd rule-matching state).
pub struct Engine {
    pub cfg: EngineConfig,
    pub decoders: Decoders,
    pub rules: Rules,
    pub lists: Lists,
    /// Stored events (in the EventList and the rules' match lists).
    pub events: HashMap<u64, Event>,
    next_event: u64,
    next_node: u64,
    /// `EventList`: newest first.
    pub last_events: VecDeque<u64>,
    /// `_memoryused`
    memoryused: i32,
    /// FTS state.
    fts_list: VecDeque<Bytes>,
    fts_store: HashSet<Bytes>,
    /// Accumulator state.
    acm_store: HashMap<Bytes, AcmStore>,
    acm_lookups: i32,
    acm_purge_ts: i64,
    /// `decoder_match` / `rule_match` (`regex_matching`).
    pub decoder_match: Vec<Bytes>,
    pub rule_match: Vec<Bytes>,
    /// `Config.g_rules_hash` as seen by the OSSEC alert plugin.
    pub g_rules_hash: HashMap<String, RuleId>,
    pub mitre: Option<std::sync::Arc<MitreDb>>,
    pub clock: Box<dyn Clock>,
    /// `hourly_alerts`
    pub hourly_alerts: u64,
    /// `g_ftell_alerts` (second part of the alert id).
    pub alert_second_id: i64,
    /// FTS lines to append to `queue/fts/fts-queue` (when `save_fts_value`).
    pub fts_writes: Vec<Bytes>,
    /// The built-in decoders (analysisd only).
    pub internal: crate::internal::InternalDecoders,
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> Self {
        let now = TimeSpec::now().sec;
        let mitre = cfg.mitre.clone();
        Engine {
            cfg,
            decoders: Decoders::default(),
            rules: Rules::default(),
            lists: Lists::default(),
            events: HashMap::new(),
            next_event: 1,
            next_node: 1,
            last_events: VecDeque::new(),
            memoryused: 0,
            fts_list: VecDeque::new(),
            fts_store: HashSet::new(),
            acm_store: HashMap::new(),
            acm_lookups: 0,
            acm_purge_ts: now,
            decoder_match: Vec::new(),
            rule_match: Vec::new(),
            g_rules_hash: HashMap::new(),
            mitre,
            clock: Box::new(SystemClock),
            hourly_alerts: 0,
            alert_second_id: 0,
            fts_writes: Vec::new(),
            internal: Default::default(),
        }
    }

    /// A new engine with the same loaded ruleset (as loaded, before any
    /// event) and empty state — equivalent to loading the ruleset again.
    pub fn fork(&self) -> Engine {
        let mut e = Engine::new(self.cfg.clone());
        e.decoders = self.decoders.clone();
        e.rules = self.rules.clone();
        e.lists = self.lists.clone();
        e.g_rules_hash = self.g_rules_hash.clone();
        e.mitre = self.mitre.clone();
        e
    }

    /// `FTS_Init`: load the lines of `queue/fts/fts-queue` into the FTS store
    /// (`fgets` into an OS_FLSIZE + 1 buffer, newline removed).
    pub fn preload_fts(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let rest = &data[pos..];
            let n = rest.iter().position(|&c| c == b'\n').map(|p| p + 1).unwrap_or(rest.len()).min(OS_FLSIZE);
            let mut line = rest[..n].to_vec();
            pos += n;
            if let Some(p) = line.iter().position(|&c| c == b'\n') {
                line.truncate(p);
            }
            let line = cstr(&line, 0).to_vec();
            self.fts_store.insert(line);
        }
    }

    /// `LoopRule` over the whole tree (`DumpLogstats`): "<hour>-<sid>-<level>-<fired>"
    /// for every rule that fired, resetting the counters.
    pub fn dump_rule_stats(&mut self, hour: i32) -> Vec<String> {
        let mut ids = Vec::new();
        crate::rules::collect_dfs(&self.rules.tree, &mut |n| ids.push(n.rule));
        let mut out = Vec::new();
        for r in ids {
            let ri = &mut self.rules.infos[r];
            if ri.firedtimes != 0 {
                out.push(format!("{}-{}-{}-{}", hour, ri.sigid, ri.level, ri.firedtimes));
                ri.firedtimes = 0;
            }
        }
        out
    }

    pub fn new_event(&self) -> Event {
        Event::new(NULL_DECODER)
    }

    /// `w_logtest_initialize_session` / analysisd ruleset loading: decoders,
    /// CDB lists, rules, `_setlevels` and the rules hash.
    pub fn load_ruleset(&mut self, decoders: &[String], lists: &[String], rules: &[String], ars: Option<&[ActiveResponse]>, log: &mut LogList) -> bool {
        let order = self.cfg.rule.decoder_order_size;
        for f in decoders {
            if self.decoders.read_decode_xml(f, order, &self.cfg.rule.home, log) == 0 {
                return false;
            }
        }
        if !self.decoders.set_decode_xml(log) {
            return false;
        }
        for l in lists {
            if self.lists.load_list(l, &self.cfg.rule.home, log) < 0 {
                return false;
            }
        }
        for r in rules {
            if self.rules.read_rules(r, &self.lists, &self.decoders, &self.cfg.rule, ars, log) < 0 {
                return false;
            }
        }
        self.rules.set_levels();
        let mut h = HashMap::new();
        self.rules.rules_hash(&mut h);
        for (k, v) in h {
            self.g_rules_hash.entry(k).or_insert(v);
        }
        true
    }

    fn dec_type(&self, ev: &Event) -> u8 {
        self.decoders.infos[ev.decoder].type_
    }

    /* ------------------------------------------------------- decoding */

    /// `DecodeEvent` on the list chosen by the program name.
    pub fn decode(&mut self, ev: &mut Event) {
        let mut dm = std::mem::take(&mut self.decoder_match);
        let hash = std::mem::take(&mut self.g_rules_hash);
        {
            let ctx = DecodeCtx { order_size: self.cfg.rule.decoder_order_size, rules_hash: &hash };
            let pn = ev.program_name.is_some();
            decode_event(&mut self.decoders, ev, &mut dm, &ctx, pn);
        }
        self.g_rules_hash = hash;
        self.decoder_match = dm;
    }

    /* ---------------------------------------------------- accumulator */

    fn accumulate_cleanup(&mut self) {
        self.acm_lookups += 1;
        let now = self.clock.now().sec;
        if self.acm_lookups < OS_ACM_PURGE_COUNT && self.acm_purge_ts < now + OS_ACM_PURGE_INTERVAL {
            return;
        }
        self.acm_lookups = 0;
        self.acm_purge_ts = now;
        self.acm_store.retain(|_, v| v.timestamp >= now - OS_ACM_EXPIRE_ELM);
    }

    /// `Accumulate`
    pub fn accumulate(&mut self, ev: &mut Event) {
        let Some(id) = ev.f[F_ID].clone() else {
            return;
        };
        let Some(name) = self.decoders.infos[ev.decoder].name.clone() else {
            return;
        };
        self.accumulate_cleanup();
        let now = self.clock.now().sec;
        let mut key: Bytes = ev.hostname.clone().unwrap_or_else(|| b"(null)".to_vec());
        key.push(b' ');
        key.extend_from_slice(name.as_bytes());
        key.push(b' ');
        key.extend_from_slice(&id);
        if key.len() >= OS_FLSIZE {
            return;
        }
        let mut stored = match self.acm_store.get(&key) {
            Some(s) => {
                if s.timestamp > 0 && s.timestamp < now - OS_ACM_EXPIRE_ELM {
                    self.acm_store.remove(&key);
                    AcmStore::default()
                } else {
                    acm_str_replace(&mut ev.f[F_DSTUSER], &s.dstuser);
                    acm_str_replace(&mut ev.f[F_SRCUSER], &s.srcuser);
                    acm_str_replace(&mut ev.f[F_DSTIP], &s.dstip);
                    acm_str_replace(&mut ev.f[F_SRCIP], &s.srcip);
                    acm_str_replace(&mut ev.f[F_DSTPORT], &s.dstport);
                    acm_str_replace(&mut ev.f[F_SRCPORT], &s.srcport);
                    acm_str_replace(&mut ev.f[F_DATA], &s.data);
                    s.clone()
                }
            }
            None => AcmStore::default(),
        };
        stored.timestamp = now;
        acm_str_replace(&mut stored.dstuser, &ev.f[F_DSTUSER]);
        acm_str_replace(&mut stored.srcuser, &ev.f[F_SRCUSER]);
        acm_str_replace(&mut stored.dstip, &ev.f[F_DSTIP]);
        acm_str_replace(&mut stored.srcip, &ev.f[F_SRCIP]);
        acm_str_replace(&mut stored.dstport, &ev.f[F_DSTPORT]);
        acm_str_replace(&mut stored.srcport, &ev.f[F_SRCPORT]);
        acm_str_replace(&mut stored.data, &ev.f[F_DATA]);
        self.acm_store.insert(key, stored);
    }

    /* ------------------------------------------------------------ FTS */

    /// `FTS`: returns the new FTS line, or `None` if already seen.
    fn fts(&mut self, ev: &Event) -> Option<Bytes> {
        let dec = &self.decoders.infos[ev.decoder];
        let pick = |v: &Option<Bytes>, flag: i32| -> Bytes {
            match v {
                Some(x) if dec.fts & flag != 0 => x.clone(),
                _ => Vec::new(),
            }
        };
        let parts: [Bytes; 9] = [
            dec.name.clone().map(|n| n.into_bytes()).unwrap_or_else(|| b"(null)".to_vec()),
            pick(&ev.f[F_ID], FTS_ID),
            pick(&ev.f[F_DSTUSER], FTS_DSTUSER),
            pick(&ev.f[F_SRCUSER], FTS_SRCUSER),
            pick(&ev.f[F_SRCIP], FTS_SRCIP),
            pick(&ev.f[F_DSTIP], FTS_DSTIP),
            pick(&ev.f[F_DATA], FTS_DATA),
            pick(&ev.f[F_SYSTEMNAME], FTS_SYSTEMNAME),
            if dec.fts & FTS_LOCATION != 0 { ev.f[F_LOCATION].clone().unwrap_or_else(|| b"(null)".to_vec()) } else { Vec::new() },
        ];
        let mut line = parts.join(&b' ');
        line.truncate(OS_FLSIZE - 1);
        if let (Some(fts_fields), Some(fields)) = (&dec.fts_fields, &dec.fields) {
            for i in 0..self.cfg.rule.decoder_order_size {
                if fts_fields.get(i).copied().unwrap_or(false) {
                    if let Some(Some(fname)) = fields.get(i) {
                        if let Some(v) = ev.find_field(fname.as_bytes()) {
                            for chunk in [&b" "[..], v] {
                                let room = OS_FLSIZE.saturating_sub(line.len());
                                line.extend_from_slice(&chunk[..chunk.len().min(room)]);
                            }
                        }
                    }
                }
            }
        }
        if self.fts_store.contains(&line) {
            return None;
        }
        let mut list_added = false;
        if dec.type_ == IDS {
            let mut n = 0;
            for prev in self.fts_list.iter().rev() {
                if str_how_closed_match(prev, &line) > self.cfg.fts_min_size_for_str {
                    n += 1;
                    if n > 2 {
                        line.truncate(self.cfg.fts_min_size_for_str);
                        break;
                    }
                }
            }
            self.fts_list.push_back(line.clone());
            if self.fts_list.len() > self.cfg.fts_list_size && self.fts_list.len() > 1 {
                self.fts_list.pop_front();
            }
            list_added = true;
        }
        if !self.fts_store.insert(line.clone()) {
            if list_added {
                self.fts_list.pop_back();
            }
            return None;
        }
        Some(line)
    }

    /// `IGnore`: compares against the lines of the ignore file *including*
    /// their newline, as `fgets` returns them.
    pub fn ignore_check(&self, ev: &Event, rule: RuleId) -> bool {
        let r = &self.rules.infos[rule];
        let dec = &self.decoders.infos[ev.decoder];
        let pick = |v: Option<&Bytes>, cond: bool| -> Bytes {
            match v {
                Some(x) if cond => x.clone(),
                _ => Vec::new(),
            }
        };
        let parts: [Bytes; 8] = [
            match &dec.name {
                Some(n) if r.ckignore & FTS_NAME != 0 => n.clone().into_bytes(),
                _ => Vec::new(),
            },
            pick(ev.f[F_ID].as_ref(), r.ckignore & FTS_ID != 0),
            pick(ev.f[F_DSTUSER].as_ref(), r.ckignore & FTS_DSTUSER != 0),
            pick(ev.f[F_SRCIP].as_ref(), r.ckignore & FTS_SRCIP != 0),
            pick(ev.f[F_DSTIP].as_ref(), r.ckignore & FTS_DSTIP != 0),
            pick(ev.f[F_DATA].as_ref(), r.ignore & FTS_DATA != 0),
            pick(ev.f[F_SYSTEMNAME].as_ref(), r.ignore & FTS_SYSTEMNAME != 0),
            if r.ckignore & FTS_LOCATION != 0 { ev.f[F_LOCATION].clone().unwrap_or_else(|| b"(null)".to_vec()) } else { Vec::new() },
        ];
        let mut line = parts.join(&b' ');
        line.truncate(OS_FLSIZE - 1);
        if r.ckignore & FTS_DYNAMIC != 0 {
            if let Some(fl) = &r.ckignore_fields {
                for f in fl.iter().take(self.cfg.rule.decoder_order_size) {
                    let Some(f) = f else { break };
                    if let Some(v) = ev.find_field(f.as_bytes()) {
                        for chunk in [&b" "[..], v] {
                            let room = OS_FLSIZE.saturating_sub(line.len());
                            line.extend_from_slice(&chunk[..chunk.len().min(room)]);
                        }
                    }
                }
            }
        }
        let Some(path) = &self.cfg.ignore_file else {
            return false;
        };
        let Ok(data) = std::fs::read(path) else {
            return false;
        };
        // fgets(_fline, OS_FLSIZE, fp): chunks of at most 255 bytes
        let mut pos = 0;
        while pos < data.len() {
            let rest = &data[pos..];
            let mut n = rest.iter().position(|&c| c == b'\n').map(|p| p + 1).unwrap_or(rest.len());
            n = n.min(OS_FLSIZE - 1);
            if cstr(&rest[..n], 0) == line.as_slice() && !rest[..n].contains(&0) {
                return true;
            }
            pos += n;
        }
        false
    }

    /// `AddtoIGnore`: the line appended to the ignore file.
    pub fn ignore_line(&self, ev: &Event, rule: RuleId) -> Bytes {
        let r = &self.rules.infos[rule];
        let dec = &self.decoders.infos[ev.decoder];
        let pick = |v: Option<&Bytes>, flag: i32| -> Bytes {
            match v {
                Some(x) if r.ignore & flag != 0 => x.clone(),
                _ => Vec::new(),
            }
        };
        let parts: [Bytes; 8] = [
            match &dec.name {
                Some(n) if r.ignore & FTS_NAME != 0 => n.clone().into_bytes(),
                _ => Vec::new(),
            },
            pick(ev.f[F_ID].as_ref(), FTS_ID),
            pick(ev.f[F_DSTUSER].as_ref(), FTS_DSTUSER),
            pick(ev.f[F_SRCIP].as_ref(), FTS_SRCIP),
            pick(ev.f[F_DSTIP].as_ref(), FTS_DSTIP),
            pick(ev.f[F_DATA].as_ref(), FTS_DATA),
            pick(ev.f[F_SYSTEMNAME].as_ref(), FTS_SYSTEMNAME),
            if r.ignore & FTS_LOCATION != 0 { ev.f[F_LOCATION].clone().unwrap_or_else(|| b"(null)".to_vec()) } else { Vec::new() },
        ];
        let mut out = b"\n".to_vec();
        out.extend_from_slice(&parts.join(&b' '));
        if r.ignore & FTS_DYNAMIC != 0 {
            if let Some(fl) = &r.ignore_fields {
                for f in fl.iter().take(self.cfg.rule.decoder_order_size) {
                    let Some(f) = f else { break };
                    if let Some(v) = ev.find_field(f.as_bytes()) {
                        out.push(b' ');
                        out.extend_from_slice(v);
                    }
                }
            }
        }
        out.push(b'\n');
        out
    }

    /// `AddtoIGnore`
    pub fn add_to_ignore(&self, ev: &Event, rule: RuleId) {
        if let Some(p) = &self.cfg.ignore_file {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = f.write_all(&self.ignore_line(ev, rule));
            }
        }
    }

    /* ---------------------------------------------------------- doDiff */

    /// `doDiff`
    fn do_diff(&self, rule: RuleId, ev: &mut Event) -> bool {
        let sigid = self.rules.infos[rule].sigid;
        let host = ev.hostname.clone().unwrap_or_default();
        let host_part: Bytes = if host.first() == Some(&b'(') {
            let h = &host[1..];
            match h.iter().position(|&c| c == b')') {
                Some(p) => h[..p].to_vec(),
                None => h.to_vec(),
            }
        } else {
            host
        };
        let file = self.cfg.diff_dir.join(String::from_utf8_lossy(&host_part).as_ref()).join(sigid.to_string()).join("last-entry");
        if ev.size >= 65536 {
            return false;
        }
        let log = ev.log().to_vec();
        let write_last = |f: &PathBuf| -> bool {
            if let Some(parent) = f.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut data = log.clone();
            data.push(0);
            std::fs::write(f, data).is_ok()
        };
        let content = match std::fs::metadata(&file) {
            Err(_) => {
                write_last(&file);
                return false;
            }
            Ok(_) => match std::fs::read(&file) {
                Err(_) => return false,
                Ok(d) => {
                    let n = d.len().min(65536);
                    if n == 0 {
                        let _ = std::fs::remove_file(&file);
                        return false;
                    }
                    cstr(&d[..n], 0).to_vec()
                }
            },
        };
        if content == log {
            return false;
        }
        write_last(&file);
        ev.last_events = Some(vec![b"Previous output:".to_vec(), content.clone()]);
        ev.previous = Some(content);
        true
    }

    /* ------------------------------------------- context event searches */

    fn field_eq(a: &Option<Bytes>, b: &Option<Bytes>) -> bool {
        matches!((a, b), (Some(x), Some(y)) if x == y)
    }

    /// `same_loop`
    fn same_loop(r: &RuleInfo, lf: &Event, my: &Event) -> bool {
        if r.same_field & ALL_FIELDS == 0 {
            return true;
        }
        let mut same = r.same_field >> 2;
        let mut i = 2;
        while same != 0 && i < N_FIELDS {
            if same & 1 == 1 && !Self::field_eq(&lf.f[i], &my.f[i]) {
                return false;
            }
            same >>= 1;
            i += 1;
        }
        true
    }

    /// `different_loop`
    fn different_loop(r: &RuleInfo, lf: &Event, my: &Event) -> bool {
        if r.different_field & ALL_FIELDS == 0 {
            return true;
        }
        let mut diff = r.different_field;
        let mut i = 0;
        while diff != 0 && i < N_FIELDS {
            if diff & 1 == 1 && Self::field_eq(&lf.f[i], &my.f[i]) {
                return false;
            }
            diff >>= 1;
            i += 1;
        }
        true
    }

    fn dynamic_same(r: &RuleInfo, lf: &Event, my: &Event) -> bool {
        let mut found = true;
        if let Some(sf) = &r.same_fields {
            for f in sf {
                if !found {
                    break;
                }
                found = false;
                if let Some(mine) = my.find_field(f.as_bytes()) {
                    if lf.find_field(f.as_bytes()) == Some(mine) {
                        found = true;
                    }
                }
            }
        }
        found
    }

    fn dynamic_different_found(r: &RuleInfo, lf: &Event, my: &Event) -> bool {
        let mut found = false;
        if let Some(nf) = &r.not_same_fields {
            for f in nf {
                if found {
                    break;
                }
                if let Some(mine) = my.find_field(f.as_bytes()) {
                    if lf.find_field(f.as_bytes()) == Some(mine) {
                        found = true;
                    }
                }
            }
        }
        found
    }

    fn add_lastevt(my: &mut Event, fc: usize, full_log: &[u8]) {
        let v = my.last_events.get_or_insert_with(Vec::new);
        if fc <= 10 && fc >= v.len() {
            v.truncate(fc);
            if v.len() == fc {
                v.push(full_log.to_vec());
            }
        }
    }

    /// `Search_LastSids` / `Search_LastGroups` (they only differ in the list).
    fn search_list(&mut self, my: &mut Event, rule: RuleId, list: Option<ListId>) -> bool {
        let Some(list) = list else {
            return false;
        };
        let r = self.rules.infos[rule].clone();
        let now = self.clock.now().sec;
        let nodes: Vec<u64> = self.rules.lists[list].nodes.iter().rev().map(|(_, e)| *e).collect();
        let mut frequency_count: i32 = 0;
        let mut first_matched: Option<u64> = None;
        for eid in nodes {
            let Some(lf) = self.events.get(&eid) else {
                continue;
            };
            if now - lf.generate_time > r.timeframe as i64 {
                return false;
            }
            if r.context_opts & FIELD_GFREQUENCY == 0 {
                match (&lf.agent_id, &my.agent_id) {
                    (Some(a), Some(b)) if a == b => {}
                    _ => continue,
                }
            }
            if r.same_field & FIELD_ID != 0 && !Self::field_eq(&lf.f[F_ID], &my.f[F_ID]) {
                continue;
            }
            if r.same_field & FIELD_SRCIP != 0 && !Self::field_eq(&lf.f[F_SRCIP], &my.f[F_SRCIP]) {
                continue;
            }
            if r.same_field & FIELD_DYNAMICS != 0 {
                if my.fields.is_empty() || lf.fields.is_empty() {
                    continue;
                }
                if !Self::dynamic_same(&r, lf, my) {
                    continue;
                }
            }
            if r.different_field & FIELD_DYNAMICS != 0 {
                if my.fields.is_empty() && lf.fields.is_empty() {
                    continue;
                }
                if Self::dynamic_different_found(&r, lf, my) {
                    continue;
                }
            }
            if r.alert_opts & SAME_EXTRAINFO != 0 {
                if !Self::same_loop(&r, lf, my) {
                    continue;
                }
                if !Self::different_loop(&r, lf, my) {
                    continue;
                }
            }
            if lf.matched >= r.level {
                return false;
            }
            let full = lf.full_log().to_vec();
            Self::add_lastevt(my, frequency_count as usize, &full);
            if frequency_count < r.frequency {
                frequency_count += 1;
                if first_matched.is_none() {
                    first_matched = Some(eid);
                }
                continue;
            }
            my.matched = r.level;
            if let Some(f) = first_matched {
                if let Some(e) = self.events.get_mut(&f) {
                    e.matched = r.level;
                }
            }
            return true;
        }
        false
    }

    /// `Search_LastEvents`
    fn search_last_events(&mut self, my: &mut Event, rule: RuleId) -> bool {
        let r = self.rules.infos[rule].clone();
        let now = self.clock.now().sec;
        let my_type = self.dec_type(my);
        let ids: Vec<u64> = self.last_events.iter().copied().collect();
        let mut frequency_count: i32 = 0;
        let mut first_matched: Option<u64> = None;
        let mut rm = std::mem::take(&mut self.rule_match);
        let result = 'outer: {
            for eid in ids {
                let Some(lf) = self.events.get(&eid) else {
                    continue;
                };
                if now - lf.generate_time > r.timeframe as i64 {
                    break 'outer false;
                }
                if r.context_opts & FIELD_GFREQUENCY == 0 {
                    // The C code `continue`s here without advancing the
                    // node (an endless loop); the event is skipped instead.
                    match (&lf.agent_id, &my.agent_id) {
                        (Some(a), Some(b)) if a == b => {}
                        _ => continue,
                    }
                }
                if self.decoders.infos[lf.decoder].type_ != my_type {
                    continue;
                }
                if let Some(re) = &r.if_matched_regex {
                    rm.clear();
                    match re.execute_bytes(lf.log()) {
                        Some(m) => rm = m.sub_bytes,
                        None => continue,
                    }
                }
                if r.same_field & FIELD_ID != 0 && !Self::field_eq(&lf.f[F_ID], &my.f[F_ID]) {
                    continue;
                }
                if r.same_field & FIELD_SRCIP != 0 && !Self::field_eq(&lf.f[F_SRCIP], &my.f[F_SRCIP]) {
                    continue;
                }
                if !Self::same_loop(&r, lf, my) || !Self::different_loop(&r, lf, my) {
                    continue;
                }
                if r.same_field & FIELD_DYNAMICS != 0 {
                    if my.fields.is_empty() || lf.fields.is_empty() {
                        continue;
                    }
                    if !Self::dynamic_same(&r, lf, my) {
                        continue;
                    }
                }
                if r.different_field & FIELD_DYNAMICS != 0 {
                    if my.fields.is_empty() && lf.fields.is_empty() {
                        continue;
                    }
                    if Self::dynamic_different_found(&r, lf, my) {
                        continue;
                    }
                }
                if lf.matched >= r.level {
                    break 'outer false;
                }
                if frequency_count < r.frequency {
                    let full = lf.full_log().to_vec();
                    Self::add_lastevt(my, frequency_count as usize, &full);
                    frequency_count += 1;
                    if first_matched.is_none() {
                        first_matched = Some(eid);
                    }
                    continue;
                }
                my.matched = r.level;
                if let Some(f) = first_matched {
                    if let Some(e) = self.events.get_mut(&f) {
                        e.matched = r.level;
                    }
                }
                break 'outer true;
            }
            false
        };
        self.rule_match = rm;
        result
    }

    /* ------------------------------------------------- rule matching */

    fn expr_ok(&mut self, e: &Option<siem_regex::Expression>, v: &[u8]) -> bool {
        let e = e.as_ref().expect("expression");
        let (m, _) = e.match_bytes(v, Some(&mut self.rule_match));
        m != e.negate
    }

    /// `OS_CheckIfRuleMatch`
    pub fn check_if_rule_match(&mut self, ev: &mut Event, node: &RNode, save_fts: bool, debug: &mut Option<&mut Vec<String>>) -> Option<RuleId> {
        let rid = node.rule;
        let r = self.rules.infos[rid].clone();

        if let Some(d) = debug.as_deref_mut() {
            let mut s = format!("Trying rule: {} - {}", r.sigid, r.comment.as_deref().unwrap_or("(null)"));
            truncate_utf8(&mut s, 1055);
            d.push(s);
        }

        if ev.decoder_syscheck_id != 0 {
            if r.decoded_as != 0 && r.decoded_as != ev.decoder_syscheck_id {
                return None;
            }
        } else if r.decoded_as != 0 && r.decoded_as != self.decoders.infos[ev.decoder].id {
            return None;
        }

        macro_rules! check_field {
            ($expr:expr, $val:expr) => {
                if $expr.is_some() {
                    let Some(v) = $val else {
                        return None;
                    };
                    if !self.expr_ok(&$expr, &v) {
                        return None;
                    }
                }
            };
        }

        check_field!(r.program_name, ev.program_name.clone());
        check_field!(r.id, ev.f[F_ID].clone());
        check_field!(r.system_name, ev.f[F_SYSTEMNAME].clone());
        check_field!(r.protocol, ev.f[F_PROTOCOL].clone());
        check_field!(r.match_, Some(ev.log().to_vec()));
        check_field!(r.regex, Some(ev.log().to_vec()));
        check_field!(r.action, ev.f[F_ACTION].clone());
        check_field!(r.url, ev.f[F_URL].clone());
        check_field!(r.location, ev.f[F_LOCATION].clone());

        for fi in r.fields.iter().take(self.cfg.rule.decoder_order_size) {
            let name = fi.name.clone().unwrap_or_default();
            let Some(v) = ev.find_field(name.as_bytes()).map(|x| x.to_vec()) else {
                return None;
            };
            let (m, _) = fi.regex.match_bytes(&v, Some(&mut self.rule_match));
            if m == fi.regex.negate {
                return None;
            }
        }

        if r.alert_opts & DO_PACKETINFO != 0 {
            check_field!(r.srcip, ev.f[F_SRCIP].clone());
            check_field!(r.dstip, ev.f[F_DSTIP].clone());
            check_field!(r.srcport, ev.f[F_SRCPORT].clone());
            check_field!(r.dstport, ev.f[F_DSTPORT].clone());
        }

        if r.alert_opts & DO_EXTRAINFO != 0 {
            if let Some(c) = r.compiled_rule {
                if !c.eval(ev) {
                    return None;
                }
            }
            if r.user.is_some() {
                if let Some(u) = ev.f[F_DSTUSER].clone() {
                    if !self.expr_ok(&r.user, &u) {
                        return None;
                    }
                } else if let Some(u) = ev.f[F_SRCUSER].clone() {
                    if !self.expr_ok(&r.user, &u) {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            check_field!(r.srcgeoip, ev.f[F_SRCGEOIP].clone());
            check_field!(r.dstgeoip, ev.f[F_DSTGEOIP].clone());
            if r.maxsize != 0 && ev.size < r.maxsize {
                return None;
            }
            if let Some(dt) = &r.day_time {
                if !crate::timeday::os_is_on_time(&ev.hour, dt) {
                    return None;
                }
            }
            if let Some(wd) = &r.week_day {
                if !crate::timeday::os_is_on_day(self.clock.weekday(), wd) {
                    return None;
                }
            }
            check_field!(r.data, ev.f[F_DATA].clone());
            check_field!(r.extra_data, ev.f[F_EXTRA_DATA].clone());
            check_field!(r.hostname, ev.hostname.clone());
            check_field!(r.status, ev.f[F_STATUS].clone());
            if r.context_opts & FIELD_DODIFF != 0 && !self.do_diff(rid, ev) {
                return None;
            }
        }

        if r.alert_opts & DO_FTS != 0 {
            let dec_fts = self.decoders.infos[ev.decoder].fts;
            if dec_fts != 0 || ev.rootcheck_fts != 0 {
                let mut line = None;
                if (dec_fts & FTS_DONE) != 0 || (ev.rootcheck_fts & FTS_DONE) != 0 {
                    // FTS already done
                } else {
                    match self.fts(ev) {
                        None => return None,
                        Some(l) => line = Some(l),
                    }
                }
                if let (Some(l), true) = (line, save_fts) {
                    self.fts_writes.push(l);
                }
            } else {
                return None;
            }
        }

        for lr in &r.lists {
            let key: Option<Bytes> = match lr.field {
                RULE_SRCIP => ev.f[F_SRCIP].clone(),
                RULE_SRCPORT => ev.f[F_SRCPORT].clone(),
                RULE_DSTIP => ev.f[F_DSTIP].clone(),
                RULE_DSTPORT => ev.f[F_DSTPORT].clone(),
                RULE_USER => ev.f[F_SRCUSER].clone().or_else(|| ev.f[F_DSTUSER].clone()),
                RULE_URL => ev.f[F_URL].clone(),
                RULE_ID => ev.f[F_ID].clone(),
                RULE_HOSTNAME => ev.hostname.clone(),
                RULE_PROGRAM_NAME => ev.program_name.clone(),
                RULE_STATUS => ev.f[F_STATUS].clone(),
                RULE_ACTION => ev.f[F_ACTION].clone(),
                RULE_SYSTEMNAME => ev.f[F_SYSTEMNAME].clone(),
                RULE_PROTOCOL => ev.f[F_PROTOCOL].clone(),
                RULE_DATA => ev.f[F_DATA].clone(),
                RULE_EXTRA_DATA => ev.f[F_EXTRA_DATA].clone(),
                RULE_DYNAMIC => lr.dfield.as_ref().and_then(|d| ev.find_field(d.as_bytes()).map(|v| v.to_vec())),
                _ => return None,
            };
            let Some(key) = key else {
                return None;
            };
            if !self.lists.db_search(lr, &key) {
                return None;
            }
        }

        if r.context == 1 && r.context_opts & FIELD_DODIFF == 0 {
            if let Some(search) = r.event_search {
                let ok = match search {
                    EventSearch::LastSids => self.search_list(ev, rid, r.sid_search),
                    EventSearch::LastGroups => self.search_list(ev, rid, r.group_search),
                    EventSearch::LastEvents => self.search_last_events(ev, rid),
                };
                if !ok {
                    if let Some(le) = &mut ev.last_events {
                        le.clear();
                    }
                    return None;
                }
            }
        }

        if let Some(d) = debug.as_deref_mut() {
            let mut s = format!("*Rule {} matched", r.sigid);
            truncate_utf8(&mut s, 31);
            d.push(s);
        }

        if !node.children.is_empty() {
            if let Some(d) = debug.as_deref_mut() {
                d.push("*Trying child rules".to_string());
            }
            for child in &node.children {
                if let Some(cr) = self.check_if_rule_match(ev, child, save_fts, debug) {
                    if ev.prev_rule.is_none() {
                        ev.prev_rule = Some(rid);
                    }
                    return Some(cr);
                }
            }
        }

        if r.alert_opts & NO_ALERT != 0 {
            return None;
        }

        self.hourly_alerts += 1;
        let ri = &mut self.rules.infos[rid];
        ri.firedtimes += 1;
        ev.r_firedtimes = ri.firedtimes;
        Some(rid)
    }

    /* ---------------------------------------------------- event store */

    fn new_node_id(&mut self) -> u64 {
        let n = self.next_node;
        self.next_node += 1;
        n
    }

    /// Store the event in the rule's match lists (sid/group) — the part of
    /// the rule-matching loop before `OS_AddEvent`.
    pub fn add_to_rule_lists(&mut self, ev: &mut Event, eid: u64, rule: RuleId) {
        if let Some(l) = self.rules.infos[rule].sid_prev_matched {
            let n = self.new_node_id();
            self.rules.lists[l].nodes.push((n, eid));
            ev.sid_node_to_delete = Some(n);
        } else if let Some(gl) = self.rules.infos[rule].group_prev_matched.clone() {
            let mut v = Vec::with_capacity(gl.len());
            for l in gl {
                let n = self.new_node_id();
                self.rules.lists[l].nodes.push((n, eid));
                v.push(Some(n));
            }
            ev.group_node_to_delete = Some(v);
        }
    }

    pub fn alloc_event_id(&mut self) -> u64 {
        let id = self.next_event;
        self.next_event += 1;
        id
    }

    /// `Free_Eventinfo` for a stored event: unlink it from the rule lists.
    fn free_event(&mut self, ev: Event) {
        if ev.is_a_copy {
            return;
        }
        let Some(rule) = ev.generated_rule else {
            return;
        };
        if let Some(n) = ev.sid_node_to_delete {
            if let Some(l) = self.rules.infos[rule].sid_prev_matched {
                self.rules.lists[l].nodes.retain(|(id, _)| *id != n);
            }
        } else if let Some(gl) = self.rules.infos[rule].group_prev_matched.clone() {
            if let Some(nodes) = &ev.group_node_to_delete {
                for (i, l) in gl.iter().enumerate() {
                    if let Some(Some(n)) = nodes.get(i) {
                        self.rules.lists[*l].nodes.retain(|(id, _)| id != n);
                    }
                }
            }
        }
    }

    /// `OS_AddEvent`
    pub fn add_event(&mut self, eid: u64, ev: Event) {
        let cur_sec = ev.time.sec;
        self.events.insert(eid, ev);
        self.last_events.push_front(eid);
        self.memoryused += 1;
        if self.last_events.len() > 1 && self.memoryused > self.cfg.memorysize {
            let mut i = 0;
            while self.last_events.len() > 1 {
                let &last = self.last_events.back().unwrap();
                let last_sec = self.events.get(&last).map(|e| e.time.sec).unwrap_or(0);
                if !(i < 10 || (cur_sec - last_sec) > self.rules.max_freq as i64) {
                    break;
                }
                self.last_events.pop_back();
                if let Some(old) = self.events.remove(&last) {
                    self.free_event(old);
                }
                self.memoryused -= 1;
                i += 1;
            }
        }
    }

    /* ------------------------------------------------------- logtest */

    /// `w_logtest_rulesmatching_phase`: returns -1 (no rules), 0 (not
    /// stored) or 1 (stored in the event list).
    pub fn logtest_rules_phase(&mut self, ev: &mut Event, eid: u64, debug: &mut Option<&mut Vec<String>>) -> i32 {
        let tree = std::mem::take(&mut self.rules.tree);
        if tree.is_empty() {
            self.rules.tree = tree;
            return -1;
        }
        let mut added = 0;
        for node in &tree {
            if self.dec_type(ev) == OSSEC_ALERT && ev.generated_rule.is_none() {
                break;
            }
            if self.rules.infos[node.rule].category != self.dec_type(ev) {
                continue;
            }
            let Some(rid) = self.check_if_rule_match(ev, node, false, debug) else {
                continue;
            };
            ev.generated_rule = Some(rid);
            if self.rules.infos[rid].level == 0 {
                break;
            }
            let ri = &mut self.rules.infos[rid];
            if ri.ignore_time != 0 {
                if ri.time_ignored == 0 {
                    ri.time_ignored = ev.generate_time;
                } else if ev.generate_time - ri.time_ignored < ri.ignore_time as i64 {
                    break;
                } else {
                    ri.time_ignored = 0;
                }
            }
            if self.rules.infos[rid].ckignore != 0 && self.ignore_check(ev, rid) {
                break;
            }
            self.add_to_rule_lists(ev, eid, rid);
            added = 1;
            break;
        }
        self.rules.tree = tree;
        added
    }

    /// `w_logtest_process_log` for one event string. Returns the output JSON
    /// and whether an alert was generated.
    pub fn logtest_process(
        &mut self,
        event: &[u8],
        location: &[u8],
        logbylevel: i32,
        debug: Option<&mut Vec<String>>,
        log: &mut LogList,
    ) -> Option<(siem_cjson::Json, bool)> {
        let mut debug = debug;
        let mut ev = self.new_event();
        // w_logtest_preprocessing_phase
        let loc = wstr_escape(location, b'|', b':', 2048 + 1);
        let mut msg = b"1:".to_vec();
        msg.extend_from_slice(&loc);
        msg.push(b':');
        msg.extend_from_slice(event);
        if ev.clean_msg(&msg, &self.cfg.shost, self.clock.now()).is_err() {
            log.error(crate::logmsg::FORMAT_ERROR);
            return None;
        }
        ev.size = ev.log().len();

        self.decode(&mut ev);
        if self.decoders.infos[ev.decoder].accumulate == 1 {
            self.accumulate(&mut ev);
        }

        let eid = self.alloc_event_id();
        let check = self.logtest_rules_phase(&mut ev, eid, &mut debug);
        if check == -1 {
            return None;
        }
        let mut alert = false;
        if let Some(rid) = ev.generated_rule {
            let c = self.rules.infos[rid].comment.clone().unwrap_or_default();
            ev.comment = Some(ev.parse_rule_comment(c.as_bytes()));
            alert = check == 1 && logbylevel <= self.rules.infos[rid].level;
        }
        let out = crate::to_json::eventinfo_to_json(self, &ev, false, log);
        let mut output = siem_cjson::parse(&out).unwrap_or(siem_cjson::Json::Null);
        if let Some(rid) = ev.generated_rule {
            let level = self.rules.infos[rid].level;
            if let Some(rule) = output.get_mut("rule") {
                if rule.get_exact("level").is_none() {
                    rule.add("level", siem_cjson::Json::number(level as f64));
                }
            }
        }
        if check == 1 {
            self.add_event(eid, ev);
        }
        Some((output, alert))
    }
}

/// `OS_StrHowClosedMatch`
pub fn str_how_closed_match(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() > max {
        let mut b = std::mem::take(s).into_bytes();
        b.truncate(max);
        *s = String::from_utf8_lossy(&b).into_owned();
    }
}
