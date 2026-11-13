//! The active-response service, old against new, on the same scenarios: the command table of
//! `ar.conf`, response runs (what the programs receive, the pending list, repeated offenders),
//! timeouts, shutdown, the settings and the requests, and the log lines of each.
//!
//! The old code reads paths relative to the working folder, so everything runs in one test, in
//! turn, with the working folder set to each home.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use provigil_daemon::{Log, Options};

const EXE: &str = if cfg!(windows) { "probe.exe" } else { "probe" };

/// The stand-in response program, built once.
fn probe() -> PathBuf {
    let out = std::env::temp_dir().join(format!("provigil-execd-probe-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let exe = out.join(EXE);
    if !exe.exists() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/probe.rs");
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
        let ok = std::process::Command::new(rustc).arg("-O").arg("-o").arg(&exe).arg(&src).status().unwrap().success();
        assert!(ok, "building the probe");
    }
    exe
}

/// A home with both layouts (the old code ran with the agent layout on this system).
fn home(ar_conf: &str, ossec_conf: &str) -> tempfile::TempDir {
    let h = tempfile::tempdir().unwrap();
    let p = |r: &str| h.path().join(r);
    for d in ["etc/shared", "shared", "active-response/bin", "logs", "var/incoming", "incoming", "queue/sockets"] {
        std::fs::create_dir_all(p(d)).unwrap();
    }
    let probe = probe();
    for name in [EXE, &format!("second-{EXE}")] {
        std::fs::copy(&probe, p(&format!("active-response/bin/{name}"))).unwrap();
    }
    for f in ["etc/shared/ar.conf", "shared/ar.conf"] {
        std::fs::write(p(f), ar_conf).unwrap();
    }
    for f in ["etc/ossec.conf", "ossec.conf"] {
        std::fs::write(p(f), ossec_conf).unwrap();
    }
    std::fs::write(p("etc/internal_options.conf"), "execd.request_timeout=60\nexecd.max_restart_lock=600\nexecd.debug=0\n").unwrap();
    h
}

/// Log lines without the time stamp, the tag and the old logger's debug location.
fn log_lines(home: &Path) -> Vec<String> {
    std::fs::read_to_string(home.join("logs/ossec.log"))
        .unwrap_or_default()
        .lines()
        .map(|l| {
            let l = l.get(20..).unwrap_or(l);
            let l = match (l.find('['), l.find("): ")) {
                (Some(a), Some(b)) if a < b => format!("{}{}", &l[..a], &l[b + 1..]),
                _ => l.to_string(),
            };
            // the level and text only
            l.split_once(": ").map(|(_, rest)| rest.to_string()).unwrap_or(l)
                .replace("incoming\\", "var/incoming/")
                .replace("'shared/ar.conf'", "'etc/shared/ar.conf'")
        })
        // the old Windows start-up code alone logged each command line
        .filter(|l| !l.starts_with("INFO: Started") && !l.contains("ProVigil home") && !l.starts_with("DEBUG: path = '"))
        // the old logger's own start-up lines
        .filter(|l| !l.contains("Logging module auto-initialized") && !l.contains("'log_format' without any option"))
        .collect()
}

fn take(path: &Path) -> String {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    let _ = std::fs::remove_file(path);
    s
}

/// One side of the comparison.
trait Side {
    fn read_table(&self);
    fn table(&self) -> Vec<(String, String, i32)>;
    fn settings(&self, conf: &str) -> i32;
    fn offenders(&self) -> Vec<i32>;
    fn start(&self);
    fn run(&self, msg: &[u8]);
    fn pending(&self) -> Vec<(String, String, String, i32)>;
    fn age_all(&self);
    fn expire(&self);
    fn shutdown(&self);
    fn dispatch(&self, req: &[u8]) -> Vec<u8>;
}

struct Old(siem_execd::Execd);
impl Side for Old {
    fn read_table(&self) {
        siem_execd::exec::read_exec_config(&self.0);
    }
    fn table(&self) -> Vec<(String, String, i32)> {
        let t = self.0.table.lock().unwrap();
        (0..t.names.len()).map(|i| (t.names[i].clone(), t.cmds[i].clone(), t.timeouts[i])).collect()
    }
    fn settings(&self, conf: &str) -> i32 {
        siem_execd::config::execd_config(&self.0, conf)
    }
    fn offenders(&self) -> Vec<i32> {
        self.0.repeated_offenders_timeout.lock().unwrap().iter().copied().take_while(|&v| v != 0).collect()
    }
    fn start(&self) {
        *self.0.timeout_list.lock().unwrap() = Some(Vec::new());
        if self.0.repeated_offenders_timeout.lock().unwrap()[0] != 0 {
            *self.0.repeated_hash.lock().unwrap() = Some(Default::default());
        }
    }
    fn run(&self, msg: &[u8]) {
        siem_execd::execd::execd_run(&self.0, msg);
    }
    fn pending(&self) -> Vec<(String, String, String, i32)> {
        self.0.timeout_list.lock().unwrap().iter().flatten().map(|e| (e.command.clone(), String::from_utf8_lossy(&e.parameters).into_owned(), e.rkey.clone(), e.time_to_block)).collect()
    }
    fn age_all(&self) {
        for e in self.0.timeout_list.lock().unwrap().iter_mut().flatten() {
            e.time_of_addition = 0;
        }
    }
    fn expire(&self) {
        siem_execd::execd::execd_timeout_run(&self.0);
    }
    fn shutdown(&self) {
        siem_execd::execd::execd_shutdown(&self.0);
    }
    fn dispatch(&self, req: &[u8]) -> Vec<u8> {
        siem_execd::wcom::wcom_dispatch(&self.0, req)
    }
}

struct New(provigil_execd::Execd);
impl Side for New {
    fn read_table(&self) {
        self.0.read_table();
    }
    fn table(&self) -> Vec<(String, String, i32)> {
        self.0.table.lock().unwrap().commands.clone()
    }
    fn settings(&self, conf: &str) -> i32 {
        match self.0.read_settings(conf) {
            Ok(provigil_execd::settings::Outcome::Enabled) => 0,
            Ok(provigil_execd::settings::Outcome::Disabled) => 1,
            Ok(provigil_execd::settings::Outcome::Invalid) => -1,
            Err(e) => panic!("{e}"),
        }
    }
    fn offenders(&self) -> Vec<i32> {
        self.0.offender_minutes()
    }
    fn start(&self) {
        self.0.start_counting();
    }
    fn run(&self, msg: &[u8]) {
        self.0.run(msg);
    }
    fn pending(&self) -> Vec<(String, String, String, i32)> {
        self.0.pending.lock().unwrap().iter().map(|e| (e.program.clone(), String::from_utf8_lossy(&e.message).into_owned(), e.key.clone(), e.seconds)).collect()
    }
    fn age_all(&self) {
        for e in self.0.pending.lock().unwrap().iter_mut() {
            e.added = 0;
        }
    }
    fn expire(&self) {
        self.0.expire();
    }
    fn shutdown(&self) {
        self.0.shutdown();
    }
    fn dispatch(&self, req: &[u8]) -> Vec<u8> {
        self.0.dispatch(req)
    }
}

/// What a scenario leaves behind.
#[derive(Debug, PartialEq)]
struct Trace {
    steps: Vec<String>,
    log: Vec<String>,
}

fn old_side(h: &Path) -> Old {
    let log = Arc::new(siem_log::WLog::new_server("provigil-execd", Path::new("")));
    let _ = log.init();
    log.now_daemon();
    log.now_debug();
    log.now_debug();
    let _ = h;
    Old(siem_execd::Execd::new(log, siem_config::internal_options::InternalOptions::from_home(Path::new(""))))
}

fn new_side(h: &Path) -> New {
    let log = Arc::new(Log::open(h, "provigil-execd"));
    log.set_debug(2);
    New(provigil_execd::Execd::new(h, log, Options::read(h)))
}

/// Runs `scenario` on both sides, each in a fresh home, and compares.
fn compare(name: &str, ar_conf: &str, ossec_conf: &str, scenario: &dyn Fn(&dyn Side, &Path) -> Vec<String>) {
    let start = std::env::current_dir().unwrap();
    let ho = home(ar_conf, ossec_conf);
    std::env::set_current_dir(ho.path()).unwrap();
    let old = {
        let s = old_side(ho.path());
        let steps = scenario(&s, ho.path());
        Trace { steps, log: log_lines(ho.path()) }
    };
    std::env::set_current_dir(&start).unwrap();
    let hn = home(ar_conf, ossec_conf);
    // the new code takes its home explicitly; the programs run there
    let new = {
        let s = new_side(hn.path());
        let steps = scenario(&s, hn.path());
        Trace { steps, log: log_lines(hn.path()) }
    };
    for (what, a, b) in [("step", &old.steps, &new.steps), ("log line", &old.log, &new.log)] {
        if let Some(i) = (0..a.len().max(b.len())).find(|&i| a.get(i) != b.get(i)) {
            panic!("scenario {name}: {what} {i} differs
 old: {:?}
 new: {:?}", a.get(i), b.get(i));
        }
    }
}

const AR_CONF: &str = "probe - probe.exe - 60\n\
                       second - second-probe.exe - 0\n\
                       missing - nothere.exe - 30\n\
                       !bad - x.exe - 1\n\
                       noseparator\n\
                       \n\
                       up - ../escape.exe - 5\n\
                       odd - probe.exe -  77junk\r\n\
                       neg - probe.exe - -3\n\
                       missing - probe.exe - 9\n\
                       probe - second-probe.exe - 1\n\
                       half - probe.exe\n";

const CONF: &str = "<ossec_config>\n  <active-response>\n    <disabled>no</disabled>\n    <repeated_offenders>1, 5,10</repeated_offenders>\n  </active-response>\n</ossec_config>\n";

fn msg(command: &str, extra: &str) -> Vec<u8> {
    format!(r#"{{"version":1,"origin":{{"name":"node01","module":"provigil-analysisd"}},"command":"{command}","parameters":{{"extra_args":[],"alert":{{"rule":{{"id":"5712"}}{extra}}}}}}}"#).into_bytes()
}

fn answer(h: &Path, line: &str) {
    std::fs::write(h.join("probe.answer"), line).unwrap();
}

#[test]
fn old_and_new_agree() {
    let ar = |s: &str| s.replace(".exe", if cfg!(windows) { ".exe" } else { "" });
    let ar_conf = ar(AR_CONF);

    // the command table
    compare("table", &ar_conf, CONF, &|s, _| {
        s.read_table();
        s.read_table();
        vec![format!("{:?}", s.table())]
    });

    // long names, too many commands
    let mut big = format!("{} - probe.exe - 1\n", "n".repeat(300));
    for i in 0..70 {
        big.push_str(&format!("c{i} - probe.exe - {i}\n"));
    }
    compare("table limits", &ar(&big), CONF, &|s, _| {
        s.read_table();
        vec![format!("{:?}", s.table())]
    });

    // responses, repeated offenders, timeouts and shutdown
    compare("responses", &ar_conf, CONF, &|s, h| {
        let mut steps = vec![format!("settings {}", s.settings("etc/ossec.conf")), format!("offenders {:?}", s.offenders())];
        s.start();
        s.read_table();
        let long = format!(r#"{{"version":1,"origin":{{}},"command":"check_keys","parameters":{{"keys":["{}","{}"]}}}}"#, "k".repeat(3000), "j".repeat(3000));
        let keys = r#"{"version":1,"origin":{"name":"probe","module":"active-response"},"command":"check_keys","parameters":{"keys":["10.0.0.5"]}}"#;
        let custom = msg(&format!("!{EXE}"), "");
        let msgs: Vec<(Vec<u8>, &str)> = vec![
            (b"not json".to_vec(), ""),
            (br#"{"version":1,"command":5}"#.to_vec(), ""),
            (msg("nosuch", ""), ""),
            (msg("missing", ""), ""),
            (msg("probe", ""), keys),
            (msg("probe", ""), keys),
            (msg("probe", ""), keys),
            (msg("probe", ""), keys),
            (msg("probe", ""), keys),
            (msg("probe", ""), r#"{"version":1,"origin":{},"command":"other","parameters":{}}"#),
            (msg("probe", ""), ""),
            (msg("odd", ""), r#"{"version":1,"origin":{},"command":"check_keys","parameters":{"keys":["a","b",3,"c"]}}"#),
            (msg("neg", ""), keys),
            (msg("second", ""), keys),
            (custom.clone(), keys),
            (br#"{"command":"probe","parameters":{}}"#.to_vec(), keys),
            (br#"{"command":"probe","origin":{"name":"x"},"parameters":"no"}"#.to_vec(), keys),
            (msg("probe", ""), &long),
            (msg("probe", ""), "{broken"),
        ];
        for (m, a) in &msgs {
            answer(h, a);
            s.run(m);
            steps.push(take(&h.join("probe.log")));
            steps.push(format!("{:?}", s.pending()));
        }
        s.age_all();
        s.expire();
        steps.push(take(&h.join("probe.log")));
        steps.push(format!("{:?}", s.pending()));
        answer(h, keys);
        s.run(&msg("probe", ""));
        s.run(&msg("odd", ""));
        steps.push(take(&h.join("probe.log")));
        s.shutdown();
        steps.push(take(&h.join("probe.log")));
        steps.push(format!("{:?}", s.pending()));
        steps
    });

    // settings
    for (i, conf) in [
        "<ossec_config><active-response><disabled>yes</disabled></active-response></ossec_config>",
        "<ossec_config><active-response><disabled> yes</disabled></active-response></ossec_config>",
        "<ossec_config><active-response><repeated_offenders>0,5</repeated_offenders></active-response></ossec_config>",
        "<ossec_config><active-response><repeated_offenders>a,b</repeated_offenders></active-response></ossec_config>",
        "<ossec_config><active-response><repeated_offenders>,,3</repeated_offenders></active-response></ossec_config>",
        "<ossec_config><active-response><repeated_offenders>1,2,3,4,5,6,7,8</repeated_offenders></active-response></ossec_config>",
        "<ossec_config><active-response><command>x</command></active-response><active-response><repeated_offenders>4</repeated_offenders></active-response></ossec_config><ossec_config><active-response><repeated_offenders>9</repeated_offenders></active-response></ossec_config>",
        "<other><active-response><repeated_offenders>7</repeated_offenders></active-response></other>",
        "<ossec_config><active-response><repeated_offenders></repeated_offenders></active-response></ossec_config>",
        "<ossec_config></ossec_config>",
    ]
    .iter()
    .enumerate()
    {
        compare(&format!("settings {i}"), &ar_conf, conf, &|s, _| {
            let r = s.settings("etc/ossec.conf");
            let ar_json = String::from_utf8_lossy(&s.dispatch(b"getconfig active-response")).into_owned();
            vec![format!("{r} {:?} {ar_json}", s.offenders())]
        });
    }

    // requests
    compare("requests", &ar_conf, CONF, &|s, h| {
        s.settings("etc/ossec.conf");
        // a merged bundle: "!<size> <name>\n<content>"
        let bundle = "!5 one.txt\nhello!3 sub/two.txt\nabc";
        for d in ["var/incoming", "incoming"] {
            std::fs::write(h.join(d).join("merged.txt"), bundle).unwrap();
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut gz, b"unpacked data").unwrap();
            std::fs::write(h.join(d).join("pack.gz"), gz.finish().unwrap()).unwrap();
            std::fs::write(h.join(d).join("plain.txt"), b"plain data").unwrap();
        }
        let incoming = |n: &str| {
            let a = std::fs::read_to_string(h.join("var/incoming").join(n));
            let b = std::fs::read_to_string(h.join("incoming").join(n));
            format!("{:?}", a.or(b).ok())
        };
        let mut steps = Vec::new();
        for r in [
            &b"unmerge"[..],
            b"unmerge merged.txt",
            b"unmerge ../x",
            b"unmerge nothere",
            b"uncompress",
            b"uncompress pack.gz",
            b"uncompress pack.gz out.txt",
            b"uncompress plain.txt out2.txt",
            b"uncompress nothere.gz out3.txt",
            b"uncompress ../a b",
            b"lock_restart",
            b"lock_restart -2",
            b"lock_restart abc",
            b"lock_restart 10",
            b"lock_restart -1",
            b"lock_restart 99999",
            b"getconfig",
            b"getconfig active-response",
            // (getconfig cluster: the old code had it on Unix only; see the unit tests)
            b"getconfig nothing",
            b"nonsense",
            b"",
            b"getconfig active-response\0ignored",
        ] {
            steps.push(format!("{:?} -> {:?}", String::from_utf8_lossy(r), String::from_utf8_lossy(&s.dispatch(r))));
        }
        for n in ["one.txt", "sub/two.txt", "out.txt", "out2.txt", "out3.txt", "pack.gz", "plain.txt"] {
            steps.push(format!("{n}: {}", incoming(n)));
        }
        steps
    });
}
