//! One loaded ruleset and its state (spec sections 2.7 and 2.8): earlier events, the rule
//! matcher, context searches, first-time-seen values, ignore lists, the accumulator and the
//! output-change check (`check_diff`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use crate::decoders::{self, DecoderSet, NO_DECODER};
use crate::event::*;
use crate::lists::Lists;
use crate::messages::Messages;
use crate::rules::*;

#[derive(Debug, Clone)]
pub struct EngineSettings {
    pub rules: RuleSettings,
    /// How many earlier events are kept.
    pub memory_size: i32,
    pub fts_list_size: usize,
    pub fts_min_size_for_str: usize,
    /// The manager's short host name (local events).
    pub manager_host: Vec<u8>,
    /// The manager's host name in alerts.
    pub manager_name: Vec<u8>,
    /// Where `check_diff` keeps the last output per host and rule.
    pub diff_dir: PathBuf,
    /// The ignore list file.
    pub ignore_file: Option<PathBuf>,
    pub hide_cluster_info: bool,
    pub cluster_name: Option<String>,
    pub node_name: Option<String>,
    pub show_hidden_labels: bool,
}

impl Default for EngineSettings {
    fn default() -> EngineSettings {
        EngineSettings {
            rules: RuleSettings::default(),
            memory_size: 8192,
            fts_list_size: 32,
            fts_min_size_for_str: 14,
            manager_host: b"localhost".to_vec(),
            manager_name: b"localhost".to_vec(),
            diff_dir: PathBuf::from("queue/diff"),
            ignore_file: None,
            hide_cluster_info: true,
            cluster_name: None,
            node_name: None,
            show_hidden_labels: false,
        }
    }
}

/// The time the engine sees (tests use a fixed one).
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn weekday(&self) -> i32 {
        crate::time::local(self.now().sec).map_or(4, |t| t.wday as i32)
    }
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Values remembered by the accumulator for one host + decoder + id.
#[derive(Debug, Clone, Default)]
struct Accumulated {
    time: i64,
    dstuser: Option<Bytes>,
    srcuser: Option<Bytes>,
    dstip: Option<Bytes>,
    srcip: Option<Bytes>,
    dstport: Option<Bytes>,
    srcport: Option<Bytes>,
    data: Option<Bytes>,
}

const ACCUMULATE_EXPIRE: i64 = 120;
const ACCUMULATE_PURGE_INTERVAL: i64 = 300;
const ACCUMULATE_PURGE_COUNT: i32 = 200;
const ACCUMULATE_MAX: usize = 81;
/// Longest first-time-seen and ignore line, plus one.
const LINE: usize = 256;

/// Fills `to` from `from` when `to` is empty and `from` is 1..80 bytes.
fn fill_empty(to: &mut Option<Bytes>, from: &Option<Bytes>) {
    let Some(v) = from else { return };
    if to.as_ref().is_some_and(|t| !t.is_empty()) || v.is_empty() || v.len() > ACCUMULATE_MAX - 1 {
        return;
    }
    *to = Some(v.clone());
}

/// Common prefix length.
pub fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn cut_text(s: &mut String, max: usize) {
    if s.len() > max {
        let mut b = std::mem::take(s).into_bytes();
        b.truncate(max);
        *s = String::from_utf8_lossy(&b).into_owned();
    }
}

/// Appends " value" while the line has room (256 bytes).
fn append_room(line: &mut Bytes, v: &[u8]) {
    for part in [&b" "[..], v] {
        let room = LINE.saturating_sub(line.len());
        line.extend_from_slice(&part[..part.len().min(room)]);
    }
}

pub struct Engine {
    pub settings: EngineSettings,
    pub decoders: DecoderSet,
    pub rules: RuleSet,
    pub lists: Lists,
    /// Kept events by id.
    pub events: HashMap<u64, Event>,
    next_event: u64,
    next_node: u64,
    /// Kept events, newest first.
    pub recent: VecDeque<u64>,
    kept: i32,
    fts_recent: VecDeque<Bytes>,
    fts_seen: HashSet<Bytes>,
    accumulated: HashMap<Bytes, Accumulated>,
    lookups: i32,
    purged_at: i64,
    pub decoder_groups: Vec<Bytes>,
    pub rule_groups: Vec<Bytes>,
    /// Rule ids by number text, for alerts read back from other managers.
    pub rules_by_id: HashMap<String, RuleId>,
    pub clock: Box<dyn Clock>,
    pub hourly_alerts: u64,
    /// The second part of alert ids.
    pub alert_counter: i64,
    /// First-time-seen lines to save.
    pub fts_lines: Vec<Bytes>,
    /// The MITRE table, shared by all engines.
    pub mitre: Option<Arc<crate::mitre::Mitre>>,
}

impl Engine {
    pub fn new(settings: EngineSettings) -> Engine {
        Engine {
            settings,
            decoders: DecoderSet::default(),
            rules: RuleSet::default(),
            lists: Lists::default(),
            events: HashMap::new(),
            next_event: 1,
            next_node: 1,
            recent: VecDeque::new(),
            kept: 0,
            fts_recent: VecDeque::new(),
            fts_seen: HashSet::new(),
            accumulated: HashMap::new(),
            lookups: 0,
            purged_at: Instant::now().sec,
            decoder_groups: Vec::new(),
            rule_groups: Vec::new(),
            rules_by_id: HashMap::new(),
            clock: Box::new(SystemClock),
            hourly_alerts: 0,
            alert_counter: 0,
            fts_lines: Vec::new(),
            mitre: None,
        }
    }

    /// The same ruleset, as loaded, with no state.
    pub fn fork(&self) -> Engine {
        let mut e = Engine::new(self.settings.clone());
        e.decoders = self.decoders.clone();
        e.rules = self.rules.clone();
        e.lists = self.lists.clone();
        e.rules_by_id = self.rules_by_id.clone();
        e.mitre = self.mitre.clone();
        e
    }

    /// Lines of the saved first-time-seen file (read in pieces of 256 bytes, newline removed).
    pub fn preload_fts(&mut self, data: &[u8]) {
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.iter().position(|&c| c == b'\n').map_or(rest.len(), |p| p + 1).min(LINE);
            let line = &rest[..n];
            rest = &rest[n..];
            let line = &line[..line.iter().position(|&c| c == b'\n').unwrap_or(line.len())];
            self.fts_seen.insert(text_at(line, 0).to_vec());
        }
    }

    /// "<hour>-<id>-<level>-<fired>" for each rule that fired, resetting the counts.
    pub fn rule_stats(&mut self, hour: i32) -> Vec<String> {
        let mut all = Vec::new();
        walk(&self.rules.tree, &mut |n| all.push(n.rule));
        let mut out = Vec::new();
        for r in all {
            let x = Arc::make_mut(&mut self.rules.rules[r]);
            if x.firedtimes != 0 {
                out.push(format!("{hour}-{}-{}-{}", x.sigid, x.level, x.firedtimes));
                x.firedtimes = 0;
            }
        }
        out
    }

    pub fn new_event(&self) -> Event {
        Event::new(NO_DECODER)
    }

    /// Decoders, lists, rules (with active responses), levels and the rule hash.
    pub fn load_ruleset(&mut self, decoders: &[String], lists: &[String], rules: &[String], responses: Option<&[crate::config::Response]>, msgs: &mut Messages) -> bool {
        let (order, home) = (self.settings.rules.order_size, self.settings.rules.home.clone());
        for f in decoders {
            if self.decoders.load_file(f, order, &home, msgs) == 0 {
                return false;
            }
        }
        if !self.decoders.finish(msgs) {
            return false;
        }
        for l in lists {
            if self.lists.load(l, &home, msgs) < 0 {
                return false;
            }
        }
        for r in rules {
            if self.rules.load_file(r, &self.lists, &self.decoders, &self.settings.rules, responses, msgs) < 0 {
                return false;
            }
        }
        self.rules.set_levels();
        let mut h = HashMap::new();
        self.rules.hash(&mut h);
        for (k, v) in h {
            self.rules_by_id.entry(k).or_insert(v);
        }
        true
    }

    fn kind(&self, ev: &Event) -> u8 {
        self.decoders.decoders[ev.decoder].kind
    }

    pub fn decode(&mut self, ev: &mut Event) {
        let mut groups = std::mem::take(&mut self.decoder_groups);
        let cx = decoders::Context { order_size: self.settings.rules.order_size, rules: &self.rules_by_id };
        let pn = ev.program_name.is_some();
        decoders::decode(&mut self.decoders, ev, &mut groups, &cx, pn);
        self.decoder_groups = groups;
    }

    /// Fills empty user, address, port and data fields from earlier events of the same
    /// host, decoder and id (kept two minutes), and remembers this event's values.
    pub fn accumulate(&mut self, ev: &mut Event) {
        let Some(id) = ev.f[F_ID].clone() else { return };
        let Some(name) = self.decoders.decoders[ev.decoder].name.clone() else { return };
        self.lookups += 1;
        let now = self.clock.now().sec;
        if self.lookups >= ACCUMULATE_PURGE_COUNT || self.purged_at >= now + ACCUMULATE_PURGE_INTERVAL {
            self.lookups = 0;
            self.purged_at = now;
            self.accumulated.retain(|_, v| v.time >= now - ACCUMULATE_EXPIRE);
        }
        let key = [ev.hostname.as_deref().unwrap_or(b"(null)"), b" ", name.as_bytes(), b" ", &id].concat();
        if key.len() >= LINE {
            return;
        }
        let mut kept = match self.accumulated.get(&key) {
            Some(s) if s.time > 0 && s.time < now - ACCUMULATE_EXPIRE => {
                self.accumulated.remove(&key);
                Accumulated::default()
            }
            Some(s) => {
                for (f, v) in [(F_DSTUSER, &s.dstuser), (F_SRCUSER, &s.srcuser), (F_DSTIP, &s.dstip), (F_SRCIP, &s.srcip), (F_DSTPORT, &s.dstport), (F_SRCPORT, &s.srcport), (F_DATA, &s.data)] {
                    fill_empty(&mut ev.f[f], v);
                }
                s.clone()
            }
            None => Accumulated::default(),
        };
        kept.time = now;
        for (v, f) in [
            (&mut kept.dstuser, F_DSTUSER),
            (&mut kept.srcuser, F_SRCUSER),
            (&mut kept.dstip, F_DSTIP),
            (&mut kept.srcip, F_SRCIP),
            (&mut kept.dstport, F_DSTPORT),
            (&mut kept.srcport, F_SRCPORT),
            (&mut kept.data, F_DATA),
        ] {
            fill_empty(v, &ev.f[f]);
        }
        self.accumulated.insert(key, kept);
    }

    /// The first-time-seen line of the event; None when seen before.
    fn first_time_seen(&mut self, ev: &Event) -> Option<Bytes> {
        let d = &self.decoders.decoders[ev.decoder];
        let pick = |v: &Option<Bytes>, flag: i32| if d.fts & flag != 0 { v.clone().unwrap_or_default() } else { Vec::new() };
        let parts = [
            d.name.clone().map_or_else(|| b"(null)".to_vec(), String::into_bytes),
            pick(&ev.f[F_ID], FTS_ID),
            pick(&ev.f[F_DSTUSER], FTS_DSTUSER),
            pick(&ev.f[F_SRCUSER], FTS_SRCUSER),
            pick(&ev.f[F_SRCIP], FTS_SRCIP),
            pick(&ev.f[F_DSTIP], FTS_DSTIP),
            pick(&ev.f[F_DATA], FTS_DATA),
            pick(&ev.f[F_SYSTEMNAME], FTS_SYSTEMNAME),
            if d.fts & FTS_LOCATION != 0 { ev.f[F_LOCATION].clone().unwrap_or_else(|| b"(null)".to_vec()) } else { Vec::new() },
        ];
        let mut line = parts.join(&b' ');
        line.truncate(LINE - 1);
        if let (Some(marks), Some(names)) = (&d.fts_fields, &d.field_names) {
            for i in 0..self.settings.rules.order_size {
                if marks.get(i) == Some(&true) {
                    if let Some(v) = names.get(i).and_then(|n| n.as_deref()).and_then(|n| ev.field(n.as_bytes())) {
                        append_room(&mut line, v);
                    }
                }
            }
        }
        if self.fts_seen.contains(&line) {
            return None;
        }
        let mut listed = false;
        if d.kind == IDS {
            // an IDS line close to two others is cut, so similar alerts count as one
            let min = self.settings.fts_min_size_for_str;
            let mut close = 0;
            for prev in self.fts_recent.iter().rev() {
                if common_prefix(prev, &line) > min {
                    close += 1;
                    if close > 2 {
                        line.truncate(min);
                        break;
                    }
                }
            }
            self.fts_recent.push_back(line.clone());
            if self.fts_recent.len() > self.settings.fts_list_size && self.fts_recent.len() > 1 {
                self.fts_recent.pop_front();
            }
            listed = true;
        }
        if !self.fts_seen.insert(line.clone()) {
            if listed {
                self.fts_recent.pop_back();
            }
            return None;
        }
        Some(line)
    }

    /// Whether the event is in the ignore list (the line compared with each line of the file
    /// as read in pieces of 255 bytes, newline included).
    pub fn ignored(&self, ev: &Event, rule: RuleId) -> bool {
        let r = &self.rules.rules[rule];
        let d = &self.decoders.decoders[ev.decoder];
        let pick = |v: &Option<Bytes>, on: bool| if on { v.clone().unwrap_or_default() } else { Vec::new() };
        // data and system name follow the `ignore` options, the rest `check_if_ignored`
        let parts = [
            match &d.name {
                Some(n) if r.ckignore & FTS_NAME != 0 => n.clone().into_bytes(),
                _ => Vec::new(),
            },
            pick(&ev.f[F_ID], r.ckignore & FTS_ID != 0),
            pick(&ev.f[F_DSTUSER], r.ckignore & FTS_DSTUSER != 0),
            pick(&ev.f[F_SRCIP], r.ckignore & FTS_SRCIP != 0),
            pick(&ev.f[F_DSTIP], r.ckignore & FTS_DSTIP != 0),
            pick(&ev.f[F_DATA], r.ignore & FTS_DATA != 0),
            pick(&ev.f[F_SYSTEMNAME], r.ignore & FTS_SYSTEMNAME != 0),
            if r.ckignore & FTS_LOCATION != 0 { ev.f[F_LOCATION].clone().unwrap_or_else(|| b"(null)".to_vec()) } else { Vec::new() },
        ];
        let mut line = parts.join(&b' ');
        line.truncate(LINE - 1);
        if r.ckignore & FTS_DYNAMIC != 0 {
            for f in r.ckignore_fields.iter().flatten().take(self.settings.rules.order_size) {
                let Some(f) = f else { break };
                if let Some(v) = ev.field(f.as_bytes()) {
                    append_room(&mut line, v);
                }
            }
        }
        let Some(data) = self.settings.ignore_file.as_ref().and_then(|p| std::fs::read(p).ok()) else { return false };
        let mut rest = &data[..];
        while !rest.is_empty() {
            let n = rest.iter().position(|&c| c == b'\n').map_or(rest.len(), |p| p + 1).min(LINE - 1);
            let piece = &rest[..n];
            if !piece.contains(&0) && piece == line.as_slice() {
                return true;
            }
            rest = &rest[n..];
        }
        false
    }

    /// The line `ignore` adds to the ignore list.
    pub fn ignore_line(&self, ev: &Event, rule: RuleId) -> Bytes {
        let r = &self.rules.rules[rule];
        let d = &self.decoders.decoders[ev.decoder];
        let pick = |v: &Option<Bytes>, flag: i32| if r.ignore & flag != 0 { v.clone().unwrap_or_default() } else { Vec::new() };
        let parts = [
            match &d.name {
                Some(n) if r.ignore & FTS_NAME != 0 => n.clone().into_bytes(),
                _ => Vec::new(),
            },
            pick(&ev.f[F_ID], FTS_ID),
            pick(&ev.f[F_DSTUSER], FTS_DSTUSER),
            pick(&ev.f[F_SRCIP], FTS_SRCIP),
            pick(&ev.f[F_DSTIP], FTS_DSTIP),
            pick(&ev.f[F_DATA], FTS_DATA),
            pick(&ev.f[F_SYSTEMNAME], FTS_SYSTEMNAME),
            if r.ignore & FTS_LOCATION != 0 { ev.f[F_LOCATION].clone().unwrap_or_else(|| b"(null)".to_vec()) } else { Vec::new() },
        ];
        let mut out = b"\n".to_vec();
        out.extend_from_slice(&parts.join(&b' '));
        if r.ignore & FTS_DYNAMIC != 0 {
            for f in r.ignore_fields.iter().flatten().take(self.settings.rules.order_size) {
                let Some(f) = f else { break };
                if let Some(v) = ev.field(f.as_bytes()) {
                    out.push(b' ');
                    out.extend_from_slice(v);
                }
            }
        }
        out.push(b'\n');
        out
    }

    pub fn add_to_ignore(&self, ev: &Event, rule: RuleId) {
        if let Some(p) = &self.settings.ignore_file {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = f.write_all(&self.ignore_line(ev, rule));
            }
        }
    }

    /// `check_diff`: true when the log differs from the last one kept for this host and
    /// rule (the earlier one becomes `previous`); the new one is kept.
    fn output_changed(&self, rule: RuleId, ev: &mut Event) -> bool {
        let host = ev.hostname.clone().unwrap_or_default();
        let host = match host.strip_prefix(b"(") {
            Some(h) => h[..h.iter().position(|&c| c == b')').unwrap_or(h.len())].to_vec(),
            None => host,
        };
        let file = self.settings.diff_dir.join(String::from_utf8_lossy(&host).as_ref()).join(self.rules.rules[rule].sigid.to_string()).join("last-entry");
        if ev.size >= 65536 {
            return false;
        }
        let log = ev.log().to_vec();
        let keep = || {
            if let Some(d) = file.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::write(&file, [log.as_slice(), &[0]].concat());
        };
        if std::fs::metadata(&file).is_err() {
            keep();
            return false;
        }
        let Ok(d) = std::fs::read(&file) else { return false };
        let d = &d[..d.len().min(65536)];
        if d.is_empty() {
            let _ = std::fs::remove_file(&file);
            return false;
        }
        let before = text_at(d, 0).to_vec();
        if before == log {
            return false;
        }
        keep();
        ev.last_events = Some(vec![b"Previous output:".to_vec(), before.clone()]);
        ev.previous = Some(before);
        true
    }

    fn equal(a: &Option<Bytes>, b: &Option<Bytes>) -> bool {
        matches!((a, b), (Some(x), Some(y)) if x == y)
    }

    /// same_* of the fixed fields (from dstip on).
    fn same_fields(r: &Rule, old: &Event, new: &Event) -> bool {
        r.same_field & ALL_FIELDS == 0 || (2..N_FIELDS).all(|i| (r.same_field >> i) & 1 == 0 || Self::equal(&old.f[i], &new.f[i]))
    }

    /// different_* of the fixed fields.
    fn different_fields(r: &Rule, old: &Event, new: &Event) -> bool {
        r.different_field & ALL_FIELDS == 0 || (0..N_FIELDS).all(|i| (r.different_field >> i) & 1 == 0 || !Self::equal(&old.f[i], &new.f[i]))
    }

    /// same_field: every named field present in the new event and equal in the old one.
    fn same_dynamic(r: &Rule, old: &Event, new: &Event) -> bool {
        r.same_fields.iter().flatten().all(|f| new.field(f.as_bytes()).is_some_and(|v| old.field(f.as_bytes()) == Some(v)))
    }

    /// different_field: some named field equal in both.
    fn equal_dynamic(r: &Rule, old: &Event, new: &Event) -> bool {
        r.not_same_fields.iter().flatten().any(|f| new.field(f.as_bytes()).is_some_and(|v| old.field(f.as_bytes()) == Some(v)))
    }

    /// Keeps up to 11 earlier logs on the event, in order.
    fn note_earlier(ev: &mut Event, n: usize, log: &[u8]) {
        let v = ev.last_events.get_or_insert_with(Vec::new);
        if n <= 10 && n == v.len() {
            v.push(log.to_vec());
        }
    }

    /// Context search in a rule's event list (if_matched_sid / if_matched_group).
    fn search_list(&mut self, ev: &mut Event, rule: RuleId, list: Option<ListId>) -> bool {
        let Some(list) = list else { return false };
        let r = self.rules.rules[rule].clone();
        let now = self.clock.now().sec;
        let ids: Vec<u64> = self.rules.event_lists[list].nodes.iter().rev().map(|&(_, e)| e).collect();
        let (mut count, mut first) = (0, None);
        for id in ids {
            let Some(old) = self.events.get(&id) else { continue };
            if now - old.generate_time > i64::from(r.timeframe) {
                return false;
            }
            if r.context_opts & FIELD_GFREQUENCY == 0 && !Self::equal(&old.agent_id, &ev.agent_id) {
                continue;
            }
            if (r.same_field & FIELD_ID != 0 && !Self::equal(&old.f[F_ID], &ev.f[F_ID])) || (r.same_field & FIELD_SRCIP != 0 && !Self::equal(&old.f[F_SRCIP], &ev.f[F_SRCIP])) {
                continue;
            }
            if r.same_field & FIELD_DYNAMICS != 0 && (ev.fields.is_empty() || old.fields.is_empty() || !Self::same_dynamic(&r, old, ev)) {
                continue;
            }
            if r.different_field & FIELD_DYNAMICS != 0 && ((ev.fields.is_empty() && old.fields.is_empty()) || Self::equal_dynamic(&r, old, ev)) {
                continue;
            }
            if r.alert_opts & SAME_EXTRAINFO != 0 && (!Self::same_fields(&r, old, ev) || !Self::different_fields(&r, old, ev)) {
                continue;
            }
            if old.matched >= r.level {
                return false;
            }
            let log = old.full_log().to_vec();
            Self::note_earlier(ev, count as usize, &log);
            if count < r.frequency {
                count += 1;
                first.get_or_insert(id);
                continue;
            }
            ev.matched = r.level;
            if let Some(e) = first.and_then(|f| self.events.get_mut(&f)) {
                e.matched = r.level;
            }
            return true;
        }
        false
    }

    /// Context search in all recent events (frequency rules with if_matched_regex or none).
    fn search_recent(&mut self, ev: &mut Event, rule: RuleId) -> bool {
        let r = self.rules.rules[rule].clone();
        let now = self.clock.now().sec;
        let kind = self.kind(ev);
        let ids: Vec<u64> = self.recent.iter().copied().collect();
        let (mut count, mut first) = (0, None);
        let mut groups = std::mem::take(&mut self.rule_groups);
        let mut found = false;
        for id in ids {
            let Some(old) = self.events.get(&id) else { continue };
            if now - old.generate_time > i64::from(r.timeframe) {
                break;
            }
            // another agent's event is passed over (the original would loop here for ever)
            if r.context_opts & FIELD_GFREQUENCY == 0 && !Self::equal(&old.agent_id, &ev.agent_id) {
                continue;
            }
            if self.decoders.decoders[old.decoder].kind != kind {
                continue;
            }
            if let Some(re) = &r.if_matched_regex {
                groups.clear();
                match re.execute_bytes(old.log()) {
                    Some(mm) => groups = mm.sub_bytes,
                    None => continue,
                }
            }
            if (r.same_field & FIELD_ID != 0 && !Self::equal(&old.f[F_ID], &ev.f[F_ID])) || (r.same_field & FIELD_SRCIP != 0 && !Self::equal(&old.f[F_SRCIP], &ev.f[F_SRCIP])) {
                continue;
            }
            if !Self::same_fields(&r, old, ev) || !Self::different_fields(&r, old, ev) {
                continue;
            }
            if r.same_field & FIELD_DYNAMICS != 0 && (ev.fields.is_empty() || old.fields.is_empty() || !Self::same_dynamic(&r, old, ev)) {
                continue;
            }
            if r.different_field & FIELD_DYNAMICS != 0 && ((ev.fields.is_empty() && old.fields.is_empty()) || Self::equal_dynamic(&r, old, ev)) {
                continue;
            }
            if old.matched >= r.level {
                break;
            }
            if count < r.frequency {
                let log = old.full_log().to_vec();
                Self::note_earlier(ev, count as usize, &log);
                count += 1;
                first.get_or_insert(id);
                continue;
            }
            ev.matched = r.level;
            if let Some(e) = first.and_then(|f| self.events.get_mut(&f)) {
                e.matched = r.level;
            }
            found = true;
            break;
        }
        self.rule_groups = groups;
        found
    }

    fn passes(&mut self, x: &Option<provigil_regex::Expression>, v: &[u8]) -> bool {
        let Some(x) = x else { return true };
        x.match_bytes(v, Some(&mut self.rule_groups)).0 != x.negate
    }

    /// Whether rule `node` (and then the first matching child, depth first) matches; the
    /// matching rule. `debug` collects the logtest rule trace.
    pub fn match_rule(&mut self, ev: &mut Event, node: &RuleNode, save_fts: bool, debug: &mut Option<&mut Vec<String>>) -> Option<RuleId> {
        let id = node.rule;
        let r = self.rules.rules[id].clone();
        if let Some(d) = debug.as_deref_mut() {
            let mut s = format!("Trying rule: {} - {}", r.sigid, r.comment.as_deref().unwrap_or("(null)"));
            cut_text(&mut s, 1055);
            d.push(s);
        }
        let decoder_id = if ev.decoder_syscheck_id != 0 { ev.decoder_syscheck_id } else { self.decoders.decoders[ev.decoder].id };
        if r.decoded_as != 0 && r.decoded_as != decoder_id {
            return None;
        }

        // each pattern needs its field
        macro_rules! need {
            ($x:expr, $v:expr) => {
                if $x.is_some() {
                    let v = $v?;
                    if !self.passes(&$x, v) {
                        return None;
                    }
                }
            };
        }
        need!(r.program_name, ev.program_name.as_deref());
        need!(r.id, ev.f[F_ID].as_deref());
        need!(r.system_name, ev.f[F_SYSTEMNAME].as_deref());
        need!(r.protocol, ev.f[F_PROTOCOL].as_deref());
        need!(r.match_, Some(ev.log()));
        need!(r.regex, Some(ev.log()));
        need!(r.action, ev.f[F_ACTION].as_deref());
        need!(r.url, ev.f[F_URL].as_deref());
        need!(r.location, ev.f[F_LOCATION].as_deref());
        for f in r.fields.iter().take(self.settings.rules.order_size) {
            let v = ev.field(f.name.as_deref().unwrap_or("").as_bytes())?;
            if f.regex.match_bytes(v, Some(&mut self.rule_groups)).0 == f.regex.negate {
                return None;
            }
        }
        if r.alert_opts & DO_PACKETINFO != 0 {
            need!(r.srcip, ev.f[F_SRCIP].as_deref());
            need!(r.dstip, ev.f[F_DSTIP].as_deref());
            need!(r.srcport, ev.f[F_SRCPORT].as_deref());
            need!(r.dstport, ev.f[F_DSTPORT].as_deref());
        }
        if r.alert_opts & DO_EXTRAINFO != 0 {
            if r.check.is_some_and(|c| !c.passes(ev)) {
                return None;
            }
            // the destination user, else the source user
            need!(r.user, ev.f[F_DSTUSER].as_deref().or(ev.f[F_SRCUSER].as_deref()));
            need!(r.srcgeoip, ev.f[F_SRCGEOIP].as_deref());
            need!(r.dstgeoip, ev.f[F_DSTGEOIP].as_deref());
            if r.maxsize != 0 && ev.size < r.maxsize {
                return None;
            }
            if r.day_time.as_ref().is_some_and(|t| !crate::time::on_time(&ev.hour, t)) {
                return None;
            }
            if r.week_day.as_ref().is_some_and(|d| !crate::time::on_day(self.clock.weekday(), d)) {
                return None;
            }
            need!(r.data, ev.f[F_DATA].as_deref());
            need!(r.extra_data, ev.f[F_EXTRA_DATA].as_deref());
            need!(r.hostname, ev.hostname.as_deref());
            need!(r.status, ev.f[F_STATUS].as_deref());
            if r.context_opts & FIELD_DODIFF != 0 && !self.output_changed(id, ev) {
                return None;
            }
        }
        if r.alert_opts & DO_FTS != 0 {
            let fts = self.decoders.decoders[ev.decoder].fts;
            if fts == 0 && ev.rootcheck_fts == 0 {
                return None;
            }
            if (fts | ev.rootcheck_fts) & FTS_DONE == 0 {
                let line = self.first_time_seen(ev)?;
                if save_fts {
                    self.fts_lines.push(line);
                }
            }
        }
        for c in &r.lists {
            let key = match c.field {
                RULE_SRCIP => ev.f[F_SRCIP].clone(),
                RULE_SRCPORT => ev.f[F_SRCPORT].clone(),
                RULE_DSTIP => ev.f[F_DSTIP].clone(),
                RULE_DSTPORT => ev.f[F_DSTPORT].clone(),
                // the source user, else the destination user
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
                RULE_DYNAMIC => c.dynamic_field.as_ref().and_then(|d| ev.field(d.as_bytes()).map(<[u8]>::to_vec)),
                _ => return None,
            };
            if !self.lists.check(c, &key?) {
                return None;
            }
        }
        if r.context == 1 && r.context_opts & FIELD_DODIFF == 0 {
            if let Some(search) = r.event_search {
                let found = match search {
                    EventSearch::LastSids => self.search_list(ev, id, r.sid_search),
                    EventSearch::LastGroups => self.search_list(ev, id, r.group_search),
                    EventSearch::LastEvents => self.search_recent(ev, id),
                };
                if !found {
                    if let Some(l) = &mut ev.last_events {
                        l.clear();
                    }
                    return None;
                }
            }
        }
        if let Some(d) = debug.as_deref_mut() {
            let mut s = format!("*Rule {} matched", r.sigid);
            cut_text(&mut s, 31);
            d.push(s);
        }
        if !node.children.is_empty() {
            if let Some(d) = debug.as_deref_mut() {
                d.push("*Trying child rules".to_string());
            }
            for child in &node.children {
                if let Some(c) = self.match_rule(ev, child, save_fts, debug) {
                    ev.prev_rule.get_or_insert(id);
                    return Some(c);
                }
            }
        }
        if r.alert_opts & NO_ALERT != 0 {
            return None;
        }
        self.hourly_alerts += 1;
        let x = Arc::make_mut(&mut self.rules.rules[id]);
        x.firedtimes += 1;
        ev.fired_times = x.firedtimes;
        Some(id)
    }

    fn new_node(&mut self) -> u64 {
        self.next_node += 1;
        self.next_node - 1
    }

    /// Puts the event in the event lists of its rule (for if_matched_sid / _group rules).
    pub fn add_to_rule_lists(&mut self, ev: &mut Event, id: u64, rule: RuleId) {
        if let Some(l) = self.rules.rules[rule].sid_prev_matched {
            let n = self.new_node();
            self.rules.event_lists[l].nodes.push((n, id));
            ev.sid_node_to_delete = Some(n);
        } else if let Some(lists) = self.rules.rules[rule].group_prev_matched.clone() {
            let mut nodes = Vec::with_capacity(lists.len());
            for l in lists {
                let n = self.new_node();
                self.rules.event_lists[l].nodes.push((n, id));
                nodes.push(Some(n));
            }
            ev.group_node_to_delete = Some(nodes);
        }
    }

    pub fn new_event_id(&mut self) -> u64 {
        self.next_event += 1;
        self.next_event - 1
    }

    /// Takes a dropped event out of its rule's event lists.
    fn forget(&mut self, ev: Event) {
        let (false, Some(rule)) = (ev.is_a_copy, ev.generated_rule) else { return };
        if let Some(n) = ev.sid_node_to_delete {
            if let Some(l) = self.rules.rules[rule].sid_prev_matched {
                self.rules.event_lists[l].nodes.retain(|&(x, _)| x != n);
            }
        } else if let (Some(lists), Some(nodes)) = (self.rules.rules[rule].group_prev_matched.clone(), &ev.group_node_to_delete) {
            for (i, l) in lists.iter().enumerate() {
                if let Some(Some(n)) = nodes.get(i) {
                    self.rules.event_lists[*l].nodes.retain(|(x, _)| x != n);
                }
            }
        }
    }

    /// Keeps an event; past the memory size, drops the oldest ones (at least ten, then while
    /// older than the highest frequency in seconds).
    pub fn keep(&mut self, id: u64, ev: Event) {
        let sec = ev.time.sec;
        self.events.insert(id, ev);
        self.recent.push_front(id);
        self.kept += 1;
        if self.recent.len() > 1 && self.kept > self.settings.memory_size {
            let mut i = 0;
            while self.recent.len() > 1 {
                let last = *self.recent.back().expect("not empty");
                let last_sec = self.events.get(&last).map_or(0, |e| e.time.sec);
                if !(i < 10 || sec - last_sec > i64::from(self.rules.max_frequency)) {
                    break;
                }
                self.recent.pop_back();
                if let Some(old) = self.events.remove(&last) {
                    self.forget(old);
                }
                self.kept -= 1;
                i += 1;
            }
        }
    }

    /// The logtest rule stage: -1 no rules, 1 the event is kept, 0 not.
    pub fn logtest_rules(&mut self, ev: &mut Event, id: u64, debug: &mut Option<&mut Vec<String>>) -> i32 {
        let tree = std::mem::take(&mut self.rules.tree);
        if tree.is_empty() {
            self.rules.tree = tree;
            return -1;
        }
        let mut kept = 0;
        for node in &tree {
            if self.kind(ev) == OSSEC_ALERT && ev.generated_rule.is_none() {
                break;
            }
            if self.rules.rules[node.rule].category != self.kind(ev) {
                continue;
            }
            let Some(rid) = self.match_rule(ev, node, false, debug) else { continue };
            ev.generated_rule = Some(rid);
            if self.rules.rules[rid].level == 0 {
                break;
            }
            let x = Arc::make_mut(&mut self.rules.rules[rid]);
            if x.ignore_time != 0 {
                if x.time_ignored == 0 {
                    x.time_ignored = ev.generate_time;
                } else if ev.generate_time - x.time_ignored < i64::from(x.ignore_time) {
                    break;
                } else {
                    x.time_ignored = 0;
                }
            }
            if self.rules.rules[rid].ckignore != 0 && self.ignored(ev, rid) {
                break;
            }
            self.add_to_rule_lists(ev, id, rid);
            kept = 1;
            break;
        }
        self.rules.tree = tree;
        kept
    }
}
