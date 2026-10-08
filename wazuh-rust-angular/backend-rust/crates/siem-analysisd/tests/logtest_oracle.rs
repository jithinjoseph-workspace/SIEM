//! Differential test against Wazuh's real logtest pipeline compiled from C
//! (see tools/oracle/README.md).
//!
//! Env:
//!   SIEM_LOGTEST_ORACLE   command line of the oracle, e.g.
//!                         "wsl -d Ubuntu-20.04 --cd /home/u/oracle -- ./logtest_oracle home"
//!   SIEM_TEST_HOME        Rust-side Wazuh home (a separate copy from the oracle's)
//!   SIEM_TEST_CASES       cases.json from tools/make_test_home.py
//!   SIEM_ORACLE_MANAGER   hostname of the oracle machine (manager.name)
//!   SIEM_ORACLE_ROUNDS    number of long sessions (default 2)
//!   SIEM_ORACLE_REPEAT    times the whole event stream is fed in each long session (default 3)
//!   SIEM_ORACLE_FUZZ      number of mutated events (default 20000), in sessions of 40

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use siem_analysisd::engine::{Engine, EngineConfig};
use siem_analysisd::logmsg::{LogLevel, LogList};
use siem_analysisd::ruleset::load_from_ossec_conf;
use siem_cjson::Json;

type Ev = (Vec<u8>, Vec<u8>); // (event, location)

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn level_num(l: LogLevel) -> i32 {
    match l {
        LogLevel::Error => 3,
        LogLevel::Warning => 2,
        LogLevel::Info => 1,
    }
}

/// Remove wall-clock dependent members: root "timestamp" and "id".
fn normalise(j: &mut Json) {
    if let Json::Object(m) = j {
        m.retain(|(k, _)| k != b"timestamp" && k != b"id");
    }
}

fn load_events(path: &str) -> Vec<Vec<String>> {
    let data = std::fs::read(path).unwrap();
    let Json::Array(items) = siem_cjson::parse(&data).unwrap() else { panic!() };
    items
        .iter()
        .map(|o| {
            o.get_exact("events")
                .unwrap()
                .children()
                .iter()
                .map(|e| String::from_utf8(e.as_bytes().unwrap().to_vec()).unwrap())
                .filter(|e| !e.is_empty())
                .collect()
        })
        .collect()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn n(&mut self, m: usize) -> usize {
        if m == 0 {
            0
        } else {
            (self.next() % m as u64) as usize
        }
    }
}

const PREFIXES: &[&str] = &[
    "Dec 29 10:00:01 ",
    "2015 Dec 29 10:00:01 ",
    "2007-06-14T15:48:55-04:00 ",
    "2022-12-19T15:02:53.288+00:00 ",
    "2009-05-22T09:36:46.214994-07:00 ",
    "2015-04-16 21:51:02,805 ",
    "2021-04-21 10:16:09.404756-0700 ",
    "Mon Apr 17 18:27:14 2006 1 64.160.42.130 ",
    "01/28-09:13:16.240702  [**] ",
    "01/28/1979-09:13:16.240702  [**] ",
    "[Fri Feb 11 18:06:35 2004] [warn] ",
    "[Time 2006.12.28 15:53:55 UTC] [Facility auth] [Sender sshd] [PID 483] [Message error: PAM: failure] [Level 3] [Host Hn]",
    "1140804070.368  11623 ",
    "M\u{e4}r 02 17:30:52 ",
    "Jan  1 00:00:00 host prog: ",
    "Jan  1 00:00:00 host prog[12]: [ID 123 auth.info] ",
    "Jan  1 00:00:00 host auth|security:info prog: ",
    "Jan  1 00:00:00 host prog[12x ",
    "Jan  1 00:00:00 host: ",
    "",
];

const LOCATIONS: &[&str] = &[
    "stdin",
    "/var/log/auth.log",
    "[001] (agent1) 192.168.1.10->/var/log/secure",
    "[002] (win) any->EventChannel",
    "(agentless) root@10.0.0.1->ssh_integrity_check",
    "[003] (bad",
    "[004]",
    "[005] x",
    "a|b:c",
    "(x) y->z",
];

fn mutate(r: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    let rounds = 1 + r.n(3);
    for _ in 0..rounds {
        match r.n(7) {
            0 => {
                let p = r.n(v.len() + 1);
                v.truncate(p);
            }
            1 => {
                if !v.is_empty() {
                    let p = r.n(v.len());
                    const SET: &[u8] = b" :[]{}\",.=-|/\\()<>0123456789aZ\t";
                    v[p] = if r.n(4) == 0 { 0x80 + r.n(0x7f) as u8 } else { SET[r.n(SET.len())] };
                }
            }
            2 => {
                let pre = PREFIXES[r.n(PREFIXES.len())].as_bytes();
                let mut nv = pre.to_vec();
                nv.extend_from_slice(&v);
                v = nv;
            }
            3 => {
                if v.len() > 2 {
                    let a = r.n(v.len());
                    let b = (a + 1 + r.n(16)).min(v.len());
                    v.drain(a..b);
                }
            }
            4 => {
                if !v.is_empty() {
                    let a = r.n(v.len());
                    let b = (a + 1 + r.n(24)).min(v.len());
                    let seg = v[a..b].to_vec();
                    let p = r.n(v.len() + 1);
                    v.splice(p..p, seg);
                }
            }
            5 => {
                // swap the syslog header for another one
                if let Some(p) = v.iter().position(|&c| c == b':') {
                    let pre = PREFIXES[r.n(PREFIXES.len())].as_bytes();
                    let mut nv = pre.to_vec();
                    nv.extend_from_slice(&v[(p + 1).min(v.len())..]);
                    v = nv;
                }
            }
            _ => {
                let p = r.n(v.len() + 1);
                v.insert(p, if r.n(2) == 0 { b'\n' } else { 0xc3 });
            }
        }
    }
    v.retain(|&c| c != 0);
    v
}

struct COut {
    json: Vec<u8>,
    alert: String,
    msgs: Vec<Vec<u8>>,
}

struct CSession {
    header: Vec<Vec<u8>>,
    events: Vec<COut>,
    crashed: bool,
}

fn parse_oracle(text: &[u8], sessions: &[Vec<Ev>]) -> Vec<CSession> {
    let mut lines = text
        .split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .peekable();
    let mut out = Vec::new();
    for s in sessions {
        let mut header = Vec::new();
        let mut crashed = false;
        loop {
            let Some(l) = lines.next() else {
                crashed = true;
                break;
            };
            if l == b"READY" {
                break;
            }
            if l.starts_with(b"CRASH") {
                crashed = true;
                break;
            }
            header.push(l.to_vec());
        }
        let mut events = Vec::new();
        if !crashed {
            'ev: for _ in s {
                let mut c = COut { json: Vec::new(), alert: String::new(), msgs: Vec::new() };
                loop {
                    let Some(l) = lines.next() else {
                        crashed = true;
                        break 'ev;
                    };
                    if l == b"END" {
                        break;
                    } else if l.starts_with(b"CRASH") {
                        crashed = true;
                        break 'ev;
                    } else if let Some(o) = l.strip_prefix(b"O ") {
                        c.json = o.to_vec();
                    } else if let Some(a) = l.strip_prefix(b"A ") {
                        c.alert = String::from_utf8_lossy(a).into_owned();
                    } else {
                        c.msgs.push(l.to_vec());
                    }
                }
                events.push(c);
            }
        }
        if !crashed && lines.peek().map_or(false, |l| l.starts_with(b"CRASH")) {
            lines.next();
            crashed = true;
        }
        out.push(CSession { header, events, crashed });
    }
    out
}

#[test]
fn logtest_matches_c() {
    let (Ok(oracle), Ok(home), Ok(cases)) =
        (std::env::var("SIEM_LOGTEST_ORACLE"), std::env::var("SIEM_TEST_HOME"), std::env::var("SIEM_TEST_CASES"))
    else {
        eprintln!("SIEM_LOGTEST_ORACLE / SIEM_TEST_HOME / SIEM_TEST_CASES not set; skipping");
        return;
    };
    let env_n = |k: &str, d: usize| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let home = PathBuf::from(home);
    let manager = std::env::var("SIEM_ORACLE_MANAGER").unwrap_or_else(|_| "localhost".into());
    let rounds = env_n("SIEM_ORACLE_ROUNDS", 2);
    let repeat = env_n("SIEM_ORACLE_REPEAT", 3);
    let fuzz = env_n("SIEM_ORACLE_FUZZ", 20000);
    let _ = std::fs::remove_dir_all(home.join("queue/diff"));

    let stdin_loc = b"stdin".to_vec();
    let per_case = load_events(&cases);
    let mut sessions: Vec<Vec<Ev>> =
        per_case.iter().map(|c| c.iter().map(|e| (e.as_bytes().to_vec(), stdin_loc.clone())).collect()).collect();
    let all: Vec<Vec<u8>> = per_case.iter().flatten().map(|e| e.as_bytes().to_vec()).collect();
    for r in 0..rounds {
        let mut v = Vec::new();
        for k in 0..repeat {
            let off = (r * 97 + k * 31) % all.len().max(1);
            v.extend(all[off..].iter().map(|e| (e.clone(), stdin_loc.clone())));
            v.extend(all[..off].iter().map(|e| (e.clone(), stdin_loc.clone())));
        }
        sessions.push(v);
    }
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut cur: Vec<Ev> = Vec::new();
    for i in 0..fuzz {
        let base = &all[rng.n(all.len())];
        let ev = mutate(&mut rng, base);
        let loc = LOCATIONS[rng.n(LOCATIONS.len())].as_bytes().to_vec();
        cur.push((ev, loc));
        if cur.len() == 40 || i + 1 == fuzz {
            sessions.push(std::mem::take(&mut cur));
        }
    }

    // Optional: only run sessions [a, b) (SIEM_ORACLE_SESSIONS=a:b)
    if let Ok(r) = std::env::var("SIEM_ORACLE_SESSIONS") {
        let (a, b) = r.split_once(':').unwrap();
        let (a, b): (usize, usize) = (a.parse().unwrap(), b.parse().unwrap());
        sessions = sessions[a.min(sessions.len())..b.min(sessions.len())].to_vec();
    }
    // Oracle run
    let mut input = String::new();
    for s in &sessions {
        input.push_str("S\n");
        for (e, l) in s {
            input.push_str("E ");
            input.push_str(&hex(e));
            input.push(' ');
            input.push_str(&hex(l));
            input.push('\n');
        }
    }
    if let Ok(p) = std::env::var("SIEM_ORACLE_INPUT_DUMP") {
        std::fs::write(p, input.as_bytes()).unwrap();
    }
    let parts: Vec<&str> = oracle.split_whitespace().collect();
    let mut child = Command::new(parts[0]).args(&parts[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let t = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let out = child.wait_with_output().unwrap();
    t.join().unwrap();
    if let Ok(p) = std::env::var("SIEM_ORACLE_DUMP") {
        std::fs::write(p, &out.stdout).unwrap();
    }
    let c_sessions = parse_oracle(&out.stdout, &sessions);

    // Rust run
    let mut log = LogList::default();
    let rs = load_from_ossec_conf(&home.join("ossec.conf"), &home, &mut log).expect("ossec.conf");
    let mut cfg = EngineConfig::default();
    cfg.rule.home = home.clone();
    cfg.diff_dir = home.join("queue/diff");
    cfg.manager_name = manager.into_bytes();
    cfg.shost = b"manager".to_vec();
    let mut base = Engine::new(cfg);
    let mut load_log = LogList::default();
    assert!(base.load_ruleset(&rs.decoders, &rs.lists, &rs.includes, None, &mut load_log));
    let logbylevel = rs.logbylevel.map(|v| v as i32).unwrap_or(0);
    let r_load: Vec<Vec<u8>> = load_log.msgs.iter().map(|m| format!("M {} {}", level_num(m.level), m.msg).into_bytes()).collect();

    let mut bad = 0usize;
    let mut checked = 0usize;
    let mut crashes = 0usize;
    for (si, (s, cs)) in sessions.iter().zip(c_sessions.iter()).enumerate() {
        if si == 0 && r_load != cs.header {
            bad += 1;
            eprintln!("LOAD MESSAGES DIFFER (rust {}, c {})", r_load.len(), cs.header.len());
            for (i, (a, b)) in r_load.iter().zip(cs.header.iter()).enumerate() {
                if a != b {
                    eprintln!("  #{i}\n  rust: {}\n  c:    {}", String::from_utf8_lossy(a), String::from_utf8_lossy(b));
                    break;
                }
            }
        }
        if cs.crashed {
            crashes += 1;
            eprintln!("C oracle crashed in session {si} after {} events", cs.events.len());
            if let Some((e, l)) = s.get(cs.events.len()) {
                eprintln!("  crashing event: {:?} location {:?}", String::from_utf8_lossy(e), String::from_utf8_lossy(l));
            }
        }
        let mut eng = base.fork();
        for ((e, loc), c) in s.iter().zip(cs.events.iter()) {
            let mut l = LogList::default();
            let r = eng.logtest_process(e, loc, logbylevel, None, &mut l);
            let (mut r_json, r_alert) = match r {
                Some((j, a)) => (j, a),
                None => (Json::Null, false),
            };
            let mut c_json = siem_cjson::parse(&c.json).unwrap_or(Json::Null);
            normalise(&mut r_json);
            normalise(&mut c_json);
            let r_m: Vec<Vec<u8>> = l.msgs.iter().map(|m| format!("M {} {}", level_num(m.level), m.msg).into_bytes()).collect();
            checked += 1;
            let same = r_json == c_json && (r_alert as u8).to_string() == c.alert && r_m == c.msgs;
            if !same {
                bad += 1;
                if bad <= 15 {
                    eprintln!("DIFF session {si} event {:?} location {:?}", String::from_utf8_lossy(e), String::from_utf8_lossy(loc));
                    let ms = |v: &Vec<Vec<u8>>| v.iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect::<Vec<_>>();
                    eprintln!("  rust: {} alert={} msgs={:?}", r_json.to_string_unformatted(), r_alert as u8, ms(&r_m));
                    eprintln!("  c:    {} alert={} msgs={:?}", c_json.to_string_unformatted(), c.alert, ms(&c.msgs));
                    if r_json != c_json {
                        eprintln!("  (json bytes differ: rust {:?}
                      c    {:?})", String::from_utf8_lossy(&r_json.print_unformatted()).len(), c.json.len());
                    }
                }
            }
        }
    }
    eprintln!("{checked} events compared, {bad} differences, {crashes} C crashes");
    assert_eq!(bad, 0);
}
