//! Built-in decoders, old against new (inventory, configuration assessment, rootcheck,
//! CIS-CAT, host information, database sync, upgrade): generated messages through both, with
//! one recording environment that answers provigil-db from a script; the decoded event, the
//! result and everything sent and logged must be identical.

use std::cell::RefCell;

use provigil_analysisd::builtin::{assessment as na, inventory as ni, small as ns};
use provigil_analysisd::decoders::{Decoder, DecoderSet};
use provigil_analysisd::event::{Event as NewEvent, Instant};
use provigil_analysisd::host::Host;
use provigil_analysisd::responses::{AgentVersion as NV, ResponseSink};
use siem_analysisd::ar::{AgentVersion as OV, ArBackend};
use siem_analysisd::daemon::Env;
use siem_analysisd::decoders::{DecoderInfo, Decoders};
use siem_analysisd::event::{Event as OldEvent, TimeSpec};
use siem_analysisd::internal::{ciscat, dbsync, hostinfo, rootcheck, sca, syscollector, upgrade, InternalDecoders};

/// Records everything; provigil-db answers come from `answers` by the query's hash.
struct Fake {
    seen: RefCell<Vec<String>>,
    answers: Vec<Result<Vec<u8>, i32>>,
    salt: u64,
}

impl Fake {
    fn new(salt: u64) -> Fake {
        let answers = vec![
            Ok(b"ok".to_vec()),
            Ok(b"ok 2".to_vec()),
            Ok(b"ok 1".to_vec()),
            Ok(b"ok found abc def".to_vec()),
            Ok(b"ok found h1".to_vec()),
            Ok(b"ok found p1,p2,,p3".to_vec()),
            Ok(b"ok not found".to_vec()),
            Ok(b"err Agent not found".to_vec()),
            Ok(b"err broken".to_vec()),
            Ok(b"ok [{\"x\":1}]".to_vec()),
            Ok(b"due".to_vec()),
            Err(-1),
            Err(-2),
        ];
        Fake { seen: RefCell::new(Vec::new()), answers, salt }
    }
    fn note(&self, s: String) {
        self.seen.borrow_mut().push(s);
    }
    fn answer(&self, q: &[u8]) -> Result<Vec<u8>, i32> {
        let h = q.iter().fold(self.salt, |h, &b| h.wrapping_mul(31).wrapping_add(u64::from(b)));
        let a = self.answers[(h % self.answers.len() as u64) as usize].clone();
        self.note(format!("db {} -> {:?}", String::from_utf8_lossy(q), a.as_ref().map(|v| String::from_utf8_lossy(v).into_owned())));
        a
    }
}

impl ArBackend for Fake {
    fn agent_version(&mut self, _: i32) -> OV {
        OV::NoInfo
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        None
    }
    fn node_name(&mut self) -> String {
        "n".into()
    }
    fn send_exec(&mut self, m: &[u8]) {
        self.note(format!("exec {}", String::from_utf8_lossy(m)));
    }
    fn send_ar(&mut self, m: &[u8]) {
        self.note(format!("ar {}", String::from_utf8_lossy(m)));
    }
}

impl ResponseSink for Fake {
    fn agent_version(&mut self, _: i32) -> NV {
        NV::NoInfo
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        None
    }
    fn node_name(&mut self) -> String {
        "n".into()
    }
    fn send_exec(&mut self, m: &[u8]) {
        self.note(format!("exec {}", String::from_utf8_lossy(m)));
    }
    fn send_ar(&mut self, m: &[u8]) {
        self.note(format!("ar {}", String::from_utf8_lossy(m)));
    }
}

impl Env for Fake {
    fn labels(&mut self, _: &[u8]) -> Vec<siem_analysisd::labels::Label> {
        Vec::new()
    }
    fn log(&self, level: &str, msg: &[u8]) {
        self.note(format!("{level} {}", String::from_utf8_lossy(msg)));
    }
    fn ar(&mut self) -> &mut dyn ArBackend {
        self
    }
    fn agents_of_node(&mut self, _: i32, _: i32) -> Option<Vec<i32>> {
        None
    }
    fn wdb_query_ex(&mut self, q: &[u8], _: usize) -> Result<Vec<u8>, i32> {
        self.answer(q)
    }
    fn send_local(&mut self, path: &str, msg: &[u8]) -> Result<(), (i32, String)> {
        self.note(format!("local {path} {}", String::from_utf8_lossy(msg)));
        if msg.len() % 3 == 0 {
            Err((111, "Connection refused".into()))
        } else {
            Ok(())
        }
    }
    fn send_mq(&mut self, path: &str, msg: &[u8]) -> bool {
        self.note(format!("mq {path} {}", String::from_utf8_lossy(msg)));
        true
    }
}

impl Host for Fake {
    fn labels(&mut self, _: &[u8]) -> Vec<provigil_analysisd::event::Label> {
        Vec::new()
    }
    fn log(&self, level: &str, msg: &[u8]) {
        self.note(format!("{level} {}", String::from_utf8_lossy(msg)));
    }
    fn responses(&mut self) -> &mut dyn ResponseSink {
        self
    }
    fn agents_of_node(&mut self, _: i32, _: i32) -> Option<Vec<i32>> {
        None
    }
    fn db_query(&mut self, q: &[u8], _: usize) -> Result<Vec<u8>, i32> {
        self.answer(q)
    }
    fn send_local(&mut self, path: &str, msg: &[u8]) -> Result<(), (i32, String)> {
        self.note(format!("local {path} {}", String::from_utf8_lossy(msg)));
        if msg.len() % 3 == 0 {
            Err((111, "Connection refused".into()))
        } else {
            Ok(())
        }
    }
    fn send_queue(&mut self, path: &str, msg: &[u8]) -> bool {
        self.note(format!("mq {path} {}", String::from_utf8_lossy(msg)));
        true
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        v[self.below(v.len())]
    }
    fn chance(&mut self) -> bool {
        self.below(4) != 0
    }
}

fn value(r: &mut Rng) -> String {
    r.pick(&["\"x\"", "\"\"", "1", "2.5", "-3", "true", "null", "[\"a\",\"b\"]", "{\"k\":1}", "\"a,b,,c\"", "\"10.0.0.1\""]).to_string()
}

/// A JSON object with some of `keys` (and sometimes an unknown one).
fn object(r: &mut Rng, keys: &[&str]) -> String {
    let mut parts = Vec::new();
    for k in keys {
        if r.chance() {
            parts.push(format!("\"{k}\":{}", value(r)));
        }
    }
    if r.below(8) == 0 {
        parts.push(format!("\"other\":{}", value(r)));
    }
    format!("{{{}}}", parts.join(","))
}

fn inventory_message(r: &mut Rng) -> String {
    let kind = r.pick(&["port", "port_end", "program", "program_end", "hotfix", "hotfix_end", "hardware", "OS", "network", "network_end", "process", "process_end", "dbsync_packages", "dbsync_network_address", "dbsync_osinfo", "dbsync_", "dbsync_bad", "nope"]);
    let id = r.pick(&["\"ID\":7,", "\"ID\":8,", "\"ID\":\"x\",", ""]);
    let ts = r.pick(&["\"timestamp\":\"2026-01-01\",", ""]);
    let body = match kind {
        "port" => format!("\"port\":{}", object(r, &["protocol", "local_ip", "local_port", "remote_ip", "remote_port", "tx_queue", "rx_queue", "inode", "state", "PID", "process"])),
        "program" => format!("\"program\":{}", object(r, &["format", "name", "priority", "group", "size", "vendor", "install_time", "version", "architecture", "multi-arch", "source", "description", "location"])),
        "process" => format!("\"process\":{}", object(r, &["pid", "name", "state", "ppid", "utime", "stime", "cmd", "argvs", "euser", "ruser", "nice", "size", "tty", "processor"])),
        "hotfix" => format!("\"hotfix\":{}", value(r)),
        "hardware" => format!("\"inventory\":{}", object(r, &["board_serial", "cpu_name", "cpu_cores", "cpu_mhz", "ram_total", "ram_free", "ram_usage"])),
        "OS" => format!("\"inventory\":{}", object(r, &["hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_build", "sysname", "release", "version", "os_patch"])),
        "network" => format!(
            "\"iface\":{{\"name\":\"eth0\",\"MTU\":1500,\"MAC\":\"aa\",\"IPv4\":{{\"address\":[\"10.0.0.1\",\"10.0.0.2\",3],\"netmask\":[\"255.0.0.0\",4],\"broadcast\":{{\"a\":\"x\"}},\"gateway\":\"g\",\"metric\":{}}},\"IPv6\":{{\"address\":[\"fe80::1\"],\"netmask\":[5]}}}}",
            value(r)
        ),
        k if k.starts_with("dbsync_") => format!("\"operation\":{},\"data\":{}", r.pick(&["\"INSERTED\"", "1"]), object(r, &["name", "version", "proto", "scan_time", "checksum", "hostname", "address", "size"])),
        _ => String::new(),
    };
    format!("{{{id}{ts}\"type\":\"{kind}\"{}{body}}}", if body.is_empty() { "" } else { "," })
}

fn assessment_message(r: &mut Rng) -> String {
    // mostly valid: each part is left out or broken now and then
    let rare = |r: &mut Rng| r.below(20) == 0;
    let mut parts: Vec<String> = Vec::new();
    let mut put = |r: &mut Rng, k: &str, v: String| {
        if !rare(r) {
            parts.push(format!("\"{k}\":{}", if rare(r) { "[]".to_string() } else { v }));
        }
    };
    match r.below(5) {
        0 | 1 => {
            let mut check: Vec<String> = Vec::new();
            let mut cput = |r: &mut Rng, k: &str, v: String| {
                if !rare(r) {
                    check.push(format!("\"{k}\":{}", if rare(r) { "7".to_string() } else { v }));
                }
            };
            { let v: String = r.pick(&["1", "2", "3", "4.5"]).into(); cput(r, "id", v); }
            cput(r, "title", "\"Ensure x\"".into());
            for k in ["description", "rationale", "remediation", "references", "file", "directory", "process", "registry", "command", "reason"] {
                if r.below(2) == 0 {
                    { let v: String = r.pick(&["\"a\"", "\"/etc/a,/etc/b\"", "\"\""]).into(); cput(r, k, v); }
                }
            }
            { let v: String = r.pick(&["{\"pci_dss\":\"1.1, 2.2\",\"cis\":3,\"x\":4.5,\"o\":[1]}", "[\"a\",\"b\"]"]).into(); cput(r, "compliance", v); }
            cput(r, "rules", "[\"f:/etc\",\"x:y\",\"c:ls\",4,\"n:1\"]".into());
            if r.below(4) != 0 {
                { let v: String = r.pick(&["\"passed\"", "\"failed\"", "\"not applicable\""]).into(); cput(r, "result", v); }
            }
            { let v: String = r.pick(&["5", "6", "-2"]).into(); put(r, "id", v); }
            put(r, "policy", "\"p\"".into());
            { let v: String = r.pick(&["\"cis\"", "\"p1\""]).into(); put(r, "policy_id", v); }
            put(r, "check", format!("{{{}}}", check.join(",")));
            format!("{{\"type\":\"check\",{}}}", parts.join(","))
        }
        2 => {
            { let v: String = r.pick(&["\"cis\"", "\"p1\"", "\"p3\""]).into(); put(r, "policy_id", v); }
            { let v: String = r.pick(&["7", "8", "-1"]).into(); put(r, "scan_id", v); }
            for k in ["start_time", "end_time", "passed", "failed", "invalid", "total_checks"] {
                { let v: String = r.pick(&["10", "20", "-3", "1.5"]).into(); put(r, k, v); }
            }
            { let v: String = r.pick(&["80", "-1", "2.5"]).into(); put(r, "score", v); }
            { let v: String = r.pick(&["\"abc\"", "\"h1\""]).into(); put(r, "hash", v); }
            { let v: String = r.pick(&["\"h1\"", "\"h2\""]).into(); put(r, "hash_file", v); }
            put(r, "file", "\"cis.yml\"".into());
            put(r, "name", "\"CIS\"".into());
            if r.below(2) == 0 {
                put(r, "description", "\"d\"".into());
                put(r, "references", "\"r\"".into());
            }
            if r.below(3) == 0 {
                put(r, "first_scan", "1".into());
            }
            if r.below(3) == 0 {
                put(r, "force_alert", "\"1\"".into());
            }
            format!("{{\"type\":\"summary\",{}}}", parts.join(","))
        }
        3 => format!("{{\"type\":\"policies\",\"policies\":{}}}", r.pick(&["[\"p1\",\"p3\"]", "[]", "\"x\""])),
        _ => {
            put(r, "elements_sent", "3".into());
            put(r, "policy_id", "\"cis\"".into());
            put(r, "scan_id", "7".into());
            format!("{{\"type\":\"dump_end\",{}}}", parts.join(","))
        }
    }
}

fn events(msg: &str) -> (OldEvent, NewEvent) {
    let mut o = OldEvent::new(0);
    let mut n = NewEvent::new(0);
    o.clean_msg(msg.as_bytes(), b"m", TimeSpec { sec: 1_700_000_000, nsec: 0 }).unwrap();
    n.clean(msg.as_bytes(), b"m", Instant { sec: 1_700_000_000, nsec: 0 }).unwrap();
    (o, n)
}

fn state_old(e: &OldEvent) -> String {
    format!("{} {:?} {:?} {}", e.decoder, e.f, e.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), e.rootcheck_fts)
}

fn state_new(e: &NewEvent) -> String {
    format!("{} {:?} {:?} {}", e.decoder, e.f, e.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), e.rootcheck_fts)
}

#[test]
fn generated_builtin_messages() {
    let dir = tempfile::tempdir().unwrap();
    let (oh, nh) = (dir.path().join("old"), dir.path().join("new"));
    for h in [&oh, &nh] {
        std::fs::create_dir_all(h.join("queue/fts")).unwrap();
    }
    let mut r = Rng(0x9E3779B97F4A7C15);
    let mut oinv = syscollector::Syscollector::default();
    let mut ninv = ni::Inventory::default();
    let mut osca = sca::Sca::default();
    let mut nsca = na::Assessment::default();
    let (mut ofake, mut nfake) = (Fake::new(7), Fake::new(7));
    let mut ohi = hostinfo::Hostinfo::init(&oh, &mut ofake);
    let mut nhi = ns::HostInfo::open(&nh, &mut nfake);
    let mut odec = Decoders::default();
    let mut ndec = DecoderSet::default();
    for _ in 0..3 {
        odec.infos.push(DecoderInfo::default());
        ndec.decoders.push(Decoder::default());
    }
    let ids = InternalDecoders { hostinfo: 2, hostinfo_new_id: 11, hostinfo_mod_id: 12, ..Default::default() };
    let mut decoded = 0;
    let mut actions = std::collections::BTreeMap::<String, usize>::new();
    for round in 0..60_000u64 {
        ofake.salt = round;
        nfake.salt = round;
        let agent = ["000", "001", "002"][r.below(3)];
        let (a, b, ok): (String, String, bool);
        match r.below(7) {
            0 => {
                let loc = r.pick(&["syscollector", "(a) any->syscollector", "(a) any->other", "(bad", "x"]);
                let msg = format!("d:[{agent}] {loc}:{}", inventory_message(&mut r));
                let msg = if agent == "000" { format!("d:{loc}:{}", inventory_message(&mut r)) } else { msg };
                let (mut oe, mut ne) = events(&msg);
                let x = oinv.decode(&mut ofake, 1, 256, &mut oe);
                let y = ninv.decode(&mut nfake, 1, 256, &mut ne);
                (a, b, ok) = (state_old(&oe), state_new(&ne), x == y);
                decoded += usize::from(x);
            }
            1 => {
                let msg = format!("p:[{agent}] (a) any->sca:{}", assessment_message(&mut r));
                let (mut oe, mut ne) = events(&msg);
                let x = osca.decode(&mut ofake, 1, 256, &mut oe);
                osca.drain(&mut ofake);
                let y = nsca.decode(&mut nfake, 1, 256, &mut ne);
                nsca.send_requests(&mut nfake);
                (a, b, ok) = (state_old(&oe), state_new(&ne), x == y);
            }
            2 => {
                let log = r.pick(&[
                    "System Audit: SSH Hardening - 1: Port 22. File: /etc/ssh/sshd_config. Reference: x",
                    "Trojaned version of file '/bin/ls' detected. Signature used: x",
                    " {CIS: 1.1} File: /etc/x.",
                    "File '/a' is owned by root",
                    "anything",
                ]);
                let (mut oe, mut ne) = events(&format!("9:[{agent}] (a) any->rootcheck:{log}"));
                let x = rootcheck::decode(&mut ofake, 1, &mut oe);
                let y = ns::rootcheck(&mut nfake, 1, &mut ne);
                (a, b, ok) = (state_old(&oe), state_new(&ne), x == y);
            }
            3 => {
                let loc = r.pick(&["wodle_cis-cat", "(a) any->wodle_cis-cat", "(a) any->x", "(bad", "y"]);
                let body = format!(
                    "{{\"type\":{},\"scan_id\":{},\"cis\":{}}}",
                    r.pick(&["\"scan_info\"", "\"scan_result\"", "1"]),
                    value(&mut r),
                    object(&mut r, &["timestamp", "benchmark", "profile", "pass", "fail", "error", "notchecked", "unknown", "score"]).replace("\"score\":\"x\"", "\"score\":\"99999999999\"")
                );
                let (mut oe, mut ne) = events(&format!("w:[{agent}] {loc}:{body}"));
                let x = ciscat::decode(&mut ofake, 1, &mut oe);
                let y = ns::ciscat(&mut nfake, 1, &mut ne);
                (a, b, ok) = (state_old(&oe), state_new(&ne), x == y);
            }
            4 => {
                let log = format!("Host: 10.0.0.{}{},{} {}", r.below(4), r.pick(&["", " (x)"]), r.pick(&["", " 22/tcp", " 80/tcp"]), r.pick(&["", "443/tcp"]));
                let log = if r.below(500) == 0 { "Host: ".to_string() } else { log };
                let (mut oe, mut ne) = events(&format!("1:[{agent}] (a) any->nmap:{log}"));
                let x = ohi.decode(&mut ofake, &mut odec, &ids, &mut oe);
                let y = nhi.decode(&mut nfake, &mut ndec, 2, 11, 12, &mut ne);
                (a, b, ok) = (format!("{} {}", state_old(&oe), odec.infos[2].id), format!("{} {}", state_new(&ne), ndec.decoders[2].id), x == y);
            }
            5 => {
                let body = format!(
                    "{{\"component\":{},\"type\":{},\"data\":{}}}",
                    r.pick(&["\"syscollector_packages\"", "\"syscheck\"", "\"fim_file\"", "\"fim_registry\"", "\"bad\"", "1"]),
                    r.pick(&["\"integrity_check_global\"", "\"state\"", "\"integrity_clear\"", "\"other\""]),
                    object(&mut r, &["id", "begin", "end", "tail", "checksum"])
                );
                let body = if r.below(15) == 0 { "{bad".to_string() } else { body };
                dbsync::dispatch(&mut ofake, agent.as_bytes(), body.as_bytes());
                ns::sync(&mut nfake, agent.as_bytes(), body.as_bytes());
                (a, b, ok) = (String::new(), String::new(), true);
            }
            _ => {
                let body = format!("{{\"command\":\"upgrade\",\"parameters\":{}}}", r.pick(&["{\"version\":\"1\"}", "[1]", "3", "{}"]));
                let body = if r.below(10) == 0 { "x".to_string() } else if r.below(10) == 0 { "{\"command\":1}".into() } else { body };
                upgrade::dispatch(&mut ofake, agent.as_bytes(), body.as_bytes());
                ns::upgrade(&mut nfake, agent.as_bytes(), body.as_bytes());
                (a, b, ok) = (String::new(), String::new(), true);
            }
        }
        assert!(ok, "round {round}");
        assert_eq!(a, b, "round {round}");
        let (x, y) = (ofake.seen.take(), nfake.seen.take());
        assert_eq!(x, y, "round {round}");
        for line in &x {
            // "db agent 001 sca insert_scan_info ..." -> "sca insert_scan_info"
            let w: Vec<&str> = line.split(' ').collect();
            let key = if w.first() == Some(&"db") && w.len() > 4 { format!("{} {}", w[3], w[4]) } else { w.iter().take(2).copied().collect::<Vec<_>>().join(" ") };
            *actions.entry(key).or_default() += 1;
        }
    }
    assert!(decoded > 1000, "inventory decoded {decoded}");
    for want in ["sca query", "sca insert", "sca update", "sca query_policy", "sca query_policy_sha256", "INFO Policy", "sca insert_scan_info", "sca update_scan_info_start", "sca insert_compliance", "sca insert_rules", "sca insert_policy", "sca delete_policy", "sca query_policies", "sca delete_check_distinct", "netaddr save", "netproto save", "port del", "package save", "process save", "hotfix save", "dbsync packages", "dbsync network_address", "osinfo set", "hardware save", "rootcheck save", "ciscat save", "mq queue/alerts/cfgarq", "mq queue/alerts/cfgaq", "ar (msg_to_agent)", "local queue/sockets/syscheck", "local queue/tasks/upgrade"] {
        assert!(actions.get(want).copied().unwrap_or(0) > 5, "{want}: {:?}", actions);
    }
    assert_eq!(std::fs::read(oh.join("queue/fts/hostinfo")).unwrap(), std::fs::read(nh.join("queue/fts/hostinfo")).unwrap());
}
