//! Shared by the wazuh-db differential tests: the injected environment, the
//! line protocol of tools/oracle/wdb_harness.c (Q / T / G) run on the Rust
//! library, the database dumps and the oracle runner.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use siem_sqlite::{Db, SQLITE_FLOAT, SQLITE_INTEGER, SQLITE_NULL, SQLITE_OPEN_READONLY, SQLITE_ROW};
use siem_wdb::wdb::state::Tv;
use siem_wdb::wdb::*;

pub const ORACLE_TIME: i64 = 1759658400;

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        match u8::from_str_radix(&s[i..i + 2], 16) {
            Ok(v) => out.push(v),
            Err(_) => break,
        }
        i += 2;
    }
    out
}

/// The pinned clock and the captured output lines.
pub struct Env {
    pub clock: AtomicI64,
    pub out: Mutex<Vec<String>>,
}

impl WdbEnv for Env {
    fn log(&self, level: &str, msg: &[u8]) {
        if !level.starts_with("DEBUG") {
            self.out.lock().push(format!("M {level} {}", hex(msg)));
        }
    }
    fn time(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }
    fn timeofday(&self) -> Tv {
        Tv { sec: self.time(), usec: 0 }
    }
    fn router_send(&self, handle: i32, msg: &[u8]) {
        self.out.lock().push(format!("E {handle} {}", hex(msg)));
    }
    fn send_peer(&self, _peer: i32, msg: &[u8]) -> i32 {
        self.out.lock().push(format!("S {}", hex(msg)));
        0
    }
    fn is_single_node(&self) -> (i32, i32) {
        // no etc/ossec.conf: OS_ReadXML fails
        (-1, -1)
    }
    fn sleep_ms(&self, _ms: u64) {}
    fn utc_offset(&self, _t: i64) -> i64 {
        // the oracle runs with TZ=UTC
        0
    }
}

fn clear_dir(d: &Path) {
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

pub fn dump_db(base: &Path, rel: &str, out: &mut Vec<String>) {
    out.push(format!("F {rel}"));
    let p = base.join(rel);
    let (rc, db) = Db::open_v2(p.to_string_lossy().as_bytes(), SQLITE_OPEN_READONLY);
    let Some(db) = db.filter(|_| rc == 0) else {
        out.push("X open".into());
        return;
    };
    let (_, tables, _) = db.prepare_v2(b"SELECT type, name, IFNULL(sql, '') FROM sqlite_master ORDER BY type, name;");
    let Some(tables) = tables else {
        out.push("X master".into());
        return;
    };
    while tables.step() == SQLITE_ROW {
        let ty = String::from_utf8_lossy(&tables.column_text(0).unwrap_or_default()).into_owned();
        let name = String::from_utf8_lossy(&tables.column_text(1).unwrap_or_default()).into_owned();
        let sql = tables.column_text(2).unwrap_or_default();
        out.push(format!("D {ty} {name} {}", hex(&sql)));
        if ty != "table" {
            continue;
        }
        let (_, mut rows, _) = db.prepare_v2(format!("SELECT * FROM \"{name}\" ORDER BY rowid;").as_bytes());
        if rows.is_none() {
            rows = db.prepare_v2(format!("SELECT * FROM \"{name}\";").as_bytes()).1;
        }
        let Some(rows) = rows else {
            out.push("X rows".into());
            continue;
        };
        while rows.step() == SQLITE_ROW {
            let mut l = String::from("W");
            for i in 0..rows.column_count() {
                l.push(' ');
                match rows.column_type(i) {
                    SQLITE_INTEGER => l.push_str(&format!("i{}", rows.column_int64(i))),
                    // %.17g
                    SQLITE_FLOAT => l.push_str(&format!("f{}", siem_cjson::fmt_g(rows.column_double(i), 17))),
                    SQLITE_NULL => l.push('n'),
                    _ => {
                        l.push('t');
                        l.push_str(&hex(&rows.column_bytes(i).unwrap_or_default()));
                    }
                }
            }
            out.push(l);
        }
    }
}

pub fn dump_dir(base: &Path, dir: &str, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(base.join(dir)) else {
        return;
    };
    let mut names: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') || n == ".template.db")
        .collect();
    names.sort();
    for n in names {
        let rel = format!("{dir}/{n}");
        if n.len() > 3 && n.ends_with(".db") {
            dump_db(base, &rel, out);
        } else {
            let size = std::fs::metadata(base.join(&rel)).map(|m| m.len()).unwrap_or(0);
            // FNV-1a 64 of the content
            let mut h: u64 = 0xcbf29ce484222325;
            for b in std::fs::read(base.join(&rel)).unwrap_or_default() {
                h = (h ^ b as u64).wrapping_mul(0x100000001b3);
            }
            out.push(format!("L {rel} {size} {h:016x}"));
        }
    }
}

/// The backup selection goes by file mtime (real time): the files that
/// appeared during a request get the pinned clock as mtime (as the oracle
/// harness does) so both sides see the same times.
fn pin_new_backups(home: &Path, seen: &mut Vec<String>, now: i64) {
    let dir = home.join(WDB_BACKUP_FOLDER);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    let names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| !n.starts_with('.')).collect();
    for n in &names {
        if !seen.contains(n) {
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(now as u64);
            if let Ok(f) = std::fs::File::options().write(true).open(dir.join(n)) {
                let _ = f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t));
            }
        }
    }
    *seen = names;
}

/// The Rust side of the harness (`harness_init` / `harness_line` /
/// `harness_finish`).
pub struct Session {
    pub home: PathBuf,
    pub env: Arc<Env>,
    pub d: Arc<Wdbd>,
    n: usize,
    seen_backups: Vec<String>,
}

impl Session {
    pub fn new(home: &Path) -> Session {
        for d in ["queue", WDB2_DIR, WDB_TASK_DIR, "backup", WDB_BACKUP_FOLDER] {
            let _ = std::fs::create_dir_all(home.join(d));
        }
        for d in [WDB2_DIR, WDB_TASK_DIR, WDB_BACKUP_FOLDER] {
            clear_dir(&home.join(d));
        }
        let env = Arc::new(Env { clock: AtomicI64::new(ORACLE_TIME), out: Mutex::new(Vec::new()) });
        siem_sqlite::fix_time(Some(ORACLE_TIME));
        let mut d = Wdbd::new(WdbConfig::default(), home.to_path_buf(), env.clone());
        d.router_agent = true;
        d.router_inventory = true;
        d.state.set_uptime(ORACLE_TIME);
        d.create_profile();
        Session { home: home.to_path_buf(), env, d: Arc::new(d), n: 0, seen_backups: Vec::new() }
    }

    /// One T / G / Q line.
    pub fn line(&mut self, line: &str) {
        let (d, env) = (&self.d, &self.env);
        if let Some(t) = line.strip_prefix("T ") {
            let t: i64 = t.parse().unwrap();
            env.clock.store(t, Ordering::SeqCst);
            siem_sqlite::fix_time(Some(t));
        } else if line == "G" {
            d.commit_old();
            d.check_fragmentation();
            d.close_old();
        } else if let Some(h) = line.strip_prefix("Q ") {
            env.out.lock().push(format!("P {}", self.n));
            self.n += 1;
            let mut req = unhex(h);
            req.truncate(OS_MAXSTR);
            // the NUL-terminated buffer
            if let Some(z) = req.iter().position(|&b| b == 0) {
                req.truncate(z);
            }
            let terminal = req.last() == Some(&b'\n');
            if terminal {
                req.pop();
            }
            let mut response = if req.first() == Some(&b'{') { d.wdbcom_dispatch(&req) } else { d.parse(&req, 7).1 };
            if let Some(z) = response.iter().position(|&b| b == 0) {
                response.truncate(z);
            }
            if !response.is_empty() {
                if terminal && response.len() < OS_MAXSTR - 1 {
                    response.push(b'\n');
                }
                env.out.lock().push(format!("R {}", hex(&response)));
            }
            pin_new_backups(&self.home, &mut self.seen_backups, env.time());
        }
    }

    /// `wdb_close_all` and the dumps; all the output lines.
    pub fn finish(self) -> Vec<String> {
        self.d.close_all();
        let mut out = std::mem::take(&mut *self.env.out.lock());
        for dir in [WDB2_DIR, WDB_TASK_DIR, WDB_BACKUP_FOLDER] {
            dump_dir(&self.home, dir, &mut out);
        }
        out
    }
}

/// Runs the oracle command line (ORACLE_TIME inserted after `env`).
pub fn run_oracle(cmd: &str, input: &str) -> Vec<String> {
    let mut args: Vec<String> = cmd.split_whitespace().map(String::from).collect();
    match args.iter().position(|a| a == "env") {
        Some(p) => args.insert(p + 1, format!("ORACLE_TIME={ORACLE_TIME}")),
        None => {
            args.insert(0, format!("ORACLE_TIME={ORACLE_TIME}"));
            args.insert(0, "env".into());
        }
    }
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn oracle");
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_string();
    let w = std::thread::spawn(move || {
        let _ = stdin.write_all(data.as_bytes());
    });
    let mut s = String::new();
    child.stdout.take().unwrap().read_to_string(&mut s).unwrap();
    w.join().unwrap();
    child.wait().unwrap();
    s.lines().map(|l| l.trim_end_matches('\r').to_string()).collect()
}

/// A readable form of an output line (hex fields decoded).
pub fn decode(l: &str) -> String {
    let p: Vec<&str> = l.split(' ').collect();
    let text = |h: &str| String::from_utf8_lossy(&unhex(h)).chars().take(600).collect::<String>();
    match p.as_slice() {
        ["R", h] | ["S", h] | ["H", h] => format!("{} {:?}", p[0], text(h)),
        ["M", lvl, h] | ["E", lvl, h] => format!("{} {lvl} {:?}", p[0], text(h)),
        ["D", ty, name, h] => format!("D {ty} {name} {:?}", text(h)),
        _ => l.chars().take(400).collect(),
    }
}

/// Compares the two outputs, resynchronising on P / F lines; prints the
/// first differences with the request (looked up in `lines`) and returns
/// their number.
pub fn compare(rust: &[String], oracle: &[String], lines: &[String]) -> usize {
    let mut diffs = 0;
    let mut last_p = String::new();
    let mut i = 0;
    let mut j = 0;
    while i < rust.len() || j < oracle.len() {
        let r = rust.get(i).map(String::as_str).unwrap_or("<eof>");
        let o = oracle.get(j).map(String::as_str).unwrap_or("<eof>");
        if r.starts_with("P ") && r == o {
            last_p = r.to_string();
        }
        if r != o {
            diffs += 1;
            if diffs <= 25 {
                let req = last_p.strip_prefix("P ").and_then(|p| p.parse::<usize>().ok()).and_then(|p| {
                    lines.iter().filter(|l| l.starts_with("Q ")).nth(p).map(|l| String::from_utf8_lossy(&unhex(&l[2..])).into_owned())
                });
                eprintln!("--- diff #{diffs} after {last_p} request {:?}", req.map(|r| r.chars().take(300).collect::<String>()));
                eprintln!("  rust:   {}", decode(r));
                eprintln!("  oracle: {}", decode(o));
            }
            i += 1;
            j += 1;
            while i < rust.len() && !rust[i].starts_with("P ") && !rust[i].starts_with("F ") && !rust[i].starts_with("H ") {
                i += 1;
            }
            while j < oracle.len() && !oracle[j].starts_with("P ") && !oracle[j].starts_with("F ") && !oracle[j].starts_with("H ") {
                j += 1;
            }
            continue;
        }
        i += 1;
        j += 1;
    }
    diffs
}
