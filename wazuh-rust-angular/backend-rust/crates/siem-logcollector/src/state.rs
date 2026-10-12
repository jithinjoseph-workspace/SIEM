//! `logcollector/state.c`: per-file event/byte counts and per-target
//! drops, global and per-interval, the `wazuh-logcollector.state` file and
//! the `getstate` JSON.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

use siem_cjson::Json;

use crate::*;

pub const LC_STATE_GLOBAL: u32 = 1;
pub const LC_STATE_INTERVAL: u32 = 2;

/// `w_lc_state_target_t`
#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub drops: u64,
}

/// `w_lc_state_file_t`
#[derive(Debug, Clone, Default)]
pub struct FileStat {
    pub bytes: u64,
    pub events: u64,
    pub targets: Vec<Target>,
}

/// `w_lc_state_storage_t` (the hash table in insertion order: the C
/// table is randomly seeded, so its order carries no meaning).
#[derive(Debug, Default)]
pub struct Storage {
    pub start: i64,
    pub states: Vec<(String, FileStat)>,
}

impl Storage {
    fn get_mut(&mut self, k: &str) -> &mut FileStat {
        if let Some(p) = self.states.iter().position(|(n, _)| n == k) {
            return &mut self.states[p].1;
        }
        self.states.push((k.to_string(), FileStat::default()));
        &mut self.states.last_mut().unwrap().1
    }
}

#[derive(Default)]
pub struct LcState {
    pub state_type: AtomicU32,
    pub file_enabled: AtomicBool,
    /// `g_lc_raw_stats_mutex` over (global, interval)
    pub raw: Mutex<(Option<Storage>, Option<Storage>)>,
    /// `g_lc_json_stats_mutex` over `g_lc_json_stats`
    pub json: Mutex<Option<Json>>,
}

/// `w_logcollector_state_init`
pub fn init(lc: &Lc, state_type: u32, file_enabled: bool) {
    let mut r = lc.state.raw.lock().unwrap();
    if state_type & LC_STATE_GLOBAL != 0 {
        r.0 = Some(Storage { start: now(), states: Vec::new() });
    }
    if state_type & LC_STATE_INTERVAL != 0 {
        r.1 = Some(Storage { start: now(), states: Vec::new() });
    }
    lc.state.state_type.store(state_type, Ordering::SeqCst);
    lc.state.file_enabled.store(file_enabled, Ordering::SeqCst);
}

fn each(lc: &Lc, f: impl Fn(&mut Storage)) {
    let t = lc.state.state_type.load(Ordering::SeqCst);
    let mut r = lc.state.raw.lock().unwrap();
    if t & LC_STATE_GLOBAL != 0 {
        if let Some(s) = r.0.as_mut() {
            f(s);
        }
    }
    if t & LC_STATE_INTERVAL != 0 {
        if let Some(s) = r.1.as_mut() {
            f(s);
        }
    }
}

/// `w_logcollector_state_update_file` (`w_logcollector_state_add_file` with 0 bytes)
pub fn update_file(lc: &Lc, fpath: &str, bytes: u64) {
    each(lc, |s| {
        let d = s.get_mut(fpath);
        if bytes > 0 {
            d.events += 1;
            d.bytes += bytes;
        }
    });
}

/// `w_logcollector_state_update_target` (`w_logcollector_state_add_target` when not dropped)
pub fn update_target(lc: &Lc, fpath: &str, target: &str, dropped: bool) {
    each(lc, |s| {
        let d = s.get_mut(fpath);
        let t = match d.targets.iter().position(|t| t.name == target) {
            Some(p) => &mut d.targets[p],
            None => {
                d.targets.push(Target { name: target.to_string(), drops: 0 });
                d.targets.last_mut().unwrap()
            }
        };
        if dropped {
            t.drops += 1;
        }
    });
}

/// `w_logcollector_state_delete_file`
pub fn delete_file(lc: &Lc, fpath: &str) {
    each(lc, |s| s.states.retain(|(n, _)| n != fpath));
}

fn fmt_time(t: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(t, 0) {
        chrono::LocalResult::Single(d) | chrono::LocalResult::Ambiguous(d, _) => d.format("%Y-%m-%d %H:%M:%S").to_string(),
        chrono::LocalResult::None => String::new(),
    }
}

/// `_w_logcollector_generate_state`
fn generate(s: &mut Storage, restart: bool) -> Option<Json> {
    if s.states.is_empty() {
        return None;
    }
    let mut files = Json::array();
    for (loc, d) in s.states.iter_mut() {
        let mut targets = Json::array();
        for t in d.targets.iter_mut() {
            let mut o = Json::object();
            o.add("name", Json::string(&t.name));
            o.add("drops", Json::number(t.drops as f64));
            targets.push(o);
            if restart {
                t.drops = 0;
            }
        }
        let mut f = Json::object();
        f.add("location", Json::string(loc));
        f.add("events", Json::number(d.events as f64));
        f.add("bytes", Json::number(d.bytes as f64));
        f.add("targets", targets);
        if restart {
            d.bytes = 0;
            d.events = 0;
        }
        files.push(f);
    }
    let mut root = Json::object();
    root.add("start", Json::string(fmt_time(s.start)));
    root.add("end", Json::string(fmt_time(now())));
    root.add("files", files);
    if restart {
        s.start = now();
    }
    Some(root)
}

/// `w_logcollector_state_generate`
pub fn generate_state(lc: &Lc) {
    let t = lc.state.state_type.load(Ordering::SeqCst);
    let mut js = lc.state.json.lock().unwrap();
    let mut r = lc.state.raw.lock().unwrap();
    let mut root = Json::object();
    if t & LC_STATE_GLOBAL != 0 {
        // cJSON_AddItemToObject with a NULL item adds nothing
        if let Some(g) = r.0.as_mut().and_then(|s| generate(s, false)) {
            root.add("global", g);
        }
    }
    if t & LC_STATE_INTERVAL != 0 {
        if let Some(g) = r.1.as_mut().and_then(|s| generate(s, true)) {
            root.add("interval", g);
        }
    }
    *js = Some(root);
}

/// `w_logcollector_state_get`
pub fn state_get(lc: &Lc) -> Option<Json> {
    let t = lc.state.state_type.load(Ordering::SeqCst);
    if t & LC_STATE_INTERVAL != 0 {
        lc.state.json.lock().unwrap().clone()
    } else if t & LC_STATE_GLOBAL != 0 {
        let mut r = lc.state.raw.lock().unwrap();
        r.0.as_mut().and_then(|s| generate(s, false))
    } else {
        None
    }
}

/// `w_logcollector_state_dump`
fn dump(lc: &Lc) {
    let s = match state_get(lc) {
        Some(j) => j.to_string_formatted(),
        None => return,
    };
    let mut s = s.into_bytes();
    s.push(b'\n');
    match siem_fileop::crt::TextFile::create(LOGCOLLECTOR_STATE) {
        Ok(mut f) => {
            use std::io::Write;
            if f.write_all(&s).is_err() {
                let e = errno();
                lc.log.error(format!(
                    "(1110): Could not write file '{LOGCOLLECTOR_STATE}' due to [({e})-({})].",
                    strerror(e)
                ));
            }
        }
        Err(e) => lc.log.error(fopen_error(LOGCOLLECTOR_STATE, e.raw_os_error().unwrap_or(0))),
    }
}

/// `w_logcollector_state_main`
pub fn state_main(lc: &Lc, interval: i32) {
    if interval > 0 {
        loop {
            sleep_secs(interval as i64);
            generate_state(lc);
            if lc.state.file_enabled.load(Ordering::SeqCst) {
                dump(lc);
            }
        }
    }
}
