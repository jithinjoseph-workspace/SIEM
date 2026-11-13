//! Runs the same requests through the old implementation (siem-wdb) and provigil-agentdb and
//! lists every difference: answer, result code, log lines, router and client messages.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use provigil_agentdb::{Engine, Env, Settings};

pub const NOW: i64 = 1_800_000_000;

#[derive(Default)]
pub struct Seen {
    logs: Mutex<Vec<(String, Vec<u8>)>>,
    router: Mutex<Vec<(i32, Vec<u8>)>>,
    peer: Mutex<Vec<Vec<u8>>>,
}
type Taken = (Vec<(String, Vec<u8>)>, Vec<(i32, Vec<u8>)>, Vec<Vec<u8>>);
impl Seen {
    pub fn take(&self) -> Taken {
        (std::mem::take(&mut *self.logs.lock().unwrap()), std::mem::take(&mut *self.router.lock().unwrap()), std::mem::take(&mut *self.peer.lock().unwrap()))
    }
}

struct OldEnv(Arc<Seen>);
impl siem_wdb::wdb::WdbEnv for OldEnv {
    fn log(&self, level: &str, msg: &[u8]) {
        self.0.logs.lock().unwrap().push((level.into(), msg.to_vec()));
    }
    fn time(&self) -> i64 {
        NOW
    }
    fn timeofday(&self) -> siem_wdb::wdb::state::Tv {
        siem_wdb::wdb::state::Tv { sec: NOW, usec: 0 }
    }
    fn router_send(&self, h: i32, m: &[u8]) {
        self.0.router.lock().unwrap().push((h, m.to_vec()));
    }
    fn send_peer(&self, _: i32, m: &[u8]) -> i32 {
        self.0.peer.lock().unwrap().push(m.to_vec());
        0
    }
    fn is_single_node(&self) -> (i32, i32) {
        (1, 0)
    }
    fn sleep_ms(&self, _: u64) {}
    fn utc_offset(&self, _: i64) -> i64 {
        0
    }
}

struct NewEnv(Arc<Seen>);
impl Env for NewEnv {
    fn log(&self, level: &str, msg: &[u8]) {
        self.0.logs.lock().unwrap().push((level.into(), msg.to_vec()));
    }
    fn time(&self) -> i64 {
        NOW
    }
    fn router_send(&self, h: i32, m: &[u8]) {
        self.0.router.lock().unwrap().push((h, m.to_vec()));
    }
    fn send_peer(&self, _: i32, m: &[u8]) -> i32 {
        self.0.peer.lock().unwrap().push(m.to_vec());
        0
    }
    fn is_single_node(&self) -> (i32, i32) {
        (1, 0)
    }
    fn sleep_ms(&self, _: u64) {}
}

pub fn home() -> tempfile::TempDir {
    let h = tempfile::tempdir().unwrap();
    for d in ["queue/db", "queue/tasks", "backup/db"] {
        std::fs::create_dir_all(h.path().join(d)).unwrap();
    }
    h
}

pub fn show(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

/// The text with the home folder (plain, or JSON-escaped) as `<home>`.
pub fn without_home(v: &[u8], home: &str) -> String {
    let escaped = home.replace('\\', "\\\\");
    show(v).replace(&escaped, "<home>").replace(home, "<home>")
}

/// The old and the new database, each in its own folder with the same fixed clock.
pub struct Pair {
    pub old: siem_wdb::wdb::Wdbd,
    pub new: Engine,
    so: Arc<Seen>,
    pub sn: Arc<Seen>,
    ho: tempfile::TempDir,
    hn: tempfile::TempDir,
}

impl Pair {
    pub fn new() -> Pair {
        Pair::make(false)
    }

    /// Both publish deleted inventory rows on the router.
    pub fn routed() -> Pair {
        Pair::make(true)
    }

    fn make(router: bool) -> Pair {
        let (ho, hn) = (home(), home());
        let (so, sn) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
        let mut old = siem_wdb::wdb::Wdbd::new(siem_wdb::wdb::WdbConfig::default(), ho.path().to_path_buf(), Arc::new(OldEnv(so.clone())));
        old.router_inventory = router;
        let new = Engine::new(hn.path(), Settings { router_inventory: router, ..Settings::default() }, Arc::new(NewEnv(sn.clone())));
        Pair { old, new, so, sn, ho, hn }
    }

    /// The two home folders (old, new).
    pub fn homes(&self) -> [&std::path::Path; 2] {
        [self.ho.path(), self.hn.path()]
    }

    /// Sends each request to both; returns every difference (empty when identical).
    pub fn run(&self, requests: &[String], mask: &dyn Fn(String) -> String) -> Vec<String> {
        let (po, pn) = (self.ho.path().to_string_lossy().into_owned(), self.hn.path().to_string_lossy().into_owned());
        let mut diffs = Vec::new();
        for (n, req) in requests.iter().enumerate() {
            let (ro, ao) = self.old.parse(req.as_bytes(), 7);
            let (rn, an) = self.new.handle(req.as_bytes(), 7);
            let (ao, an) = (mask(without_home(&ao, &po)), mask(without_home(&an, &pn)));
            let (lo, uo, peo) = self.so.take();
            let (ln, un, pen) = self.sn.take();
            let f = |v: Vec<(String, Vec<u8>)>, home: &str| v.into_iter().map(|(l, m)| format!("{l}: {}", mask(without_home(&m, home)))).collect::<Vec<_>>();
            let (lo, ln) = (f(lo, &po), f(ln, &pn));
            if ao != an || ro != rn {
                diffs.push(format!("#{n} {req}\n   answer old {ro} {ao:?}\n   answer new {rn} {an:?}"));
            }
            if lo != ln {
                diffs.push(format!("#{n} {req}\n   logs old:\n      {}\n   logs new:\n      {}", lo.join("\n      "), ln.join("\n      ")));
            }
            if uo != un {
                diffs.push(format!("#{n} {req}\n   router old {uo:?}\n   router new {un:?}"));
            }
            let g = |v: Vec<Vec<u8>>| v.iter().map(|m| mask(show(m))).collect::<Vec<_>>();
            let (peo, pen) = (g(peo), g(pen));
            if peo != pen {
                diffs.push(format!("#{n} {req}\n   to client old {peo:?}\n   to client new {pen:?}"));
            }
        }
        diffs
    }
}
