//! Differential test of the wazuh-logtest request protocol
//! (`w_logtest_process_request`) against the C oracle in protocol mode.
//!
//! Env: SIEM_LOGTEST_ORACLE (oracle command line), SIEM_TEST_HOME (Rust home
//! with etc/ossec.conf), SIEM_ORACLE_MANAGER (oracle hostname).
//! The oracle must run with deterministic tokens (tools/oracle/shim/stubs.c).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use siem_analysisd::engine::EngineConfig;
use siem_analysisd::logtest::{Logtest, LogtestConfig};
use siem_cjson::Json;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Drop wall-clock members of `data.output`.
fn normalise(j: &mut Json) {
    if let Some(data) = j.get_mut("data") {
        if let Some(Json::Object(m)) = data.get_mut("output") {
            m.retain(|(k, _)| k != b"timestamp" && k != b"id");
        }
    }
}

fn requests() -> Vec<String> {
    let lp = |params: &str| format!(r#"{{"version":1,"origin":{{"name":"t","module":"t"}},"command":"log_processing","parameters":{params}}}"#);
    let rm = |params: &str| format!(r#"{{"version":1,"command":"remove_session","parameters":{params}}}"#);
    let ev = r#""Feb  9 11:44:56 someserver sshd[1234]: error: Could not stat AuthorizedKeysCommand \"/usr/local/sbin/ssh-ldap-authorized_keys\": No such file or directory""#;
    let ev2 = r#""Jan  8 16:39:33 tp.lan dropbear[14824]: Bad password attempt for 'root' from 193.219.28.149:48629""#;
    vec![
        // parsing / structure errors
        "{bad json".into(),
        "".into(),
        "[1,2]".into(),
        r#"{"command":"log_processing"}"#.into(),
        r#"{"command":"log_processing","parameters":5}"#.into(),
        r#"{"parameters":{}}"#.into(),
        r#"{"command":5,"parameters":{}}"#.into(),
        r#"{"command":"bogus","parameters":{}}"#.into(),
        // log_processing field validation
        lp(r#"{}"#),
        lp(r#"{"location":""}"#),
        lp(r#"{"location":"stdin"}"#),
        lp(r#"{"location":"stdin","log_format":"syslog"}"#),
        lp(r#"{"location":"stdin","log_format":"syslog","event":""}"#),
        lp(r#"{"location":"stdin","log_format":"syslog","event":5}"#),
        lp(r#"{"location":"stdin","log_format":"syslog","event":{}}"#),
        // first real request: new session 00001001
        lp(&format!(r#"{{"location":"stdin","log_format":"syslog","event":{ev}}}"#)),
        // reuse it, with rules_debug
        lp(&format!(r#"{{"token":"00001001","location":"stdin","log_format":"syslog","event":{ev2},"options":{{"rules_debug":true}}}}"#)),
        lp(&format!(r#"{{"token":"00001001","location":"stdin","log_format":"syslog","event":{ev2},"options":{{"rules_debug":"yes"}}}}"#)),
        lp(&format!(r#"{{"token":"00001001","location":"stdin","log_format":"syslog","event":{ev2},"options":7}}"#)),
        // object event
        lp(r#"{"token":"00001001","location":"stdin","log_format":"json","event":{"integration":"github","github":{"actor":"user","action":"repo.archived"}}}"#),
        // invalid tokens
        lp(&format!(r#"{{"token":12,"location":"stdin","log_format":"syslog","event":{ev}}}"#)),
        lp(&format!(r#"{{"token":"short","location":"stdin","log_format":"syslog","event":{ev}}}"#)),
        lp(&format!(r#"{{"token":"deadbeef","location":"[001] (agent) any->x","log_format":"syslog","event":{ev}}}"#)),
        // remove_session
        rm(r#"{}"#),
        rm(r#"{"token":5}"#),
        rm(r#"{"token":"abc"}"#),
        rm(r#"{"token":"ffffffff"}"#),
        rm(r#"{"token":"00001001"}"#),
        rm(r#"{"token":"00001001"}"#),
        // more sessions than max_sessions (oracle started with 2)
        lp(&format!(r#"{{"location":"stdin","log_format":"syslog","event":{ev}}}"#)),
        lp(&format!(r#"{{"location":"stdin","log_format":"syslog","event":{ev}}}"#)),
        lp(&format!(r#"{{"location":"stdin","log_format":"syslog","event":{ev}}}"#)),
        lp(&format!(r#"{{"token":"00001005","location":"stdin","log_format":"syslog","event":{ev}}}"#)),
    ]
}

#[test]
fn logtest_protocol_matches_c() {
    let (Ok(oracle), Ok(home)) = (std::env::var("SIEM_LOGTEST_ORACLE"), std::env::var("SIEM_TEST_HOME")) else {
        eprintln!("SIEM_LOGTEST_ORACLE / SIEM_TEST_HOME not set; skipping");
        return;
    };
    let manager = std::env::var("SIEM_ORACLE_MANAGER").unwrap_or_else(|_| "localhost".into());
    let home = PathBuf::from(home);
    let reqs = requests();

    let mut input = String::new();
    for r in &reqs {
        input.push_str("R ");
        input.push_str(&hex(r.as_bytes()));
        input.push('\n');
    }
    let parts: Vec<&str> = oracle.split_whitespace().collect();
    let mut child = Command::new(parts[0]).args(&parts[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let t = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let out = child.wait_with_output().unwrap();
    t.join().unwrap();
    let c_resps: Vec<Vec<u8>> = out
        .stdout
        .split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter_map(|l| l.strip_prefix(b"P ").map(|p| p.to_vec()))
        .collect();
    assert_eq!(c_resps.len(), reqs.len(), "oracle answered {} of {} requests", c_resps.len(), reqs.len());

    let mut cfg = EngineConfig::default();
    cfg.rule.home = home.clone();
    cfg.diff_dir = home.join("queue/diff");
    cfg.manager_name = manager.into_bytes();
    cfg.shost = b"manager".to_vec();
    let mut counter = 0x1000u32;
    let mut lt = Logtest::new(LogtestConfig {
        enabled: true,
        threads: 1,
        max_sessions: 2,
        session_timeout: 900,
        ossec_conf: PathBuf::from("etc/ossec.conf"),
        engine: cfg,
    });
    lt.token_source = Box::new(move || {
        counter += 1;
        counter
    });

    let mut bad = 0;
    for (i, (r, c)) in reqs.iter().zip(c_resps.iter()).enumerate() {
        let rust = lt.process_request(r.as_bytes());
        let mut rj = siem_cjson::parse(&rust).unwrap_or(Json::Null);
        let mut cj = siem_cjson::parse(c).unwrap_or(Json::Null);
        normalise(&mut rj);
        normalise(&mut cj);
        if rj != cj {
            bad += 1;
            eprintln!("DIFF request #{i}: {r}\n  rust: {}\n  c:    {}", rj.to_string_unformatted(), cj.to_string_unformatted());
        }
    }
    eprintln!("{} requests compared, {bad} differences", reqs.len());
    assert_eq!(bad, 0);
}
