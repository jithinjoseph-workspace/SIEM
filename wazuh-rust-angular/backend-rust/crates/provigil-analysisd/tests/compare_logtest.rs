//! Logtest, old against new: the same requests through both services must give the same
//! answers (the wall-clock timestamp and alert id masked).

use std::path::{Path, PathBuf};

use provigil_analysisd::engine::EngineSettings;
use provigil_analysisd::logtest as nl;
use provigil_analysisd::rules::RuleSettings;
use siem_analysisd::engine::EngineConfig;
use siem_analysisd::logtest as ol;
use siem_analysisd::rules::RuleConfig;

fn manager() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager")
}

fn mask(a: &[u8]) -> String {
    let s = String::from_utf8_lossy(a).into_owned();
    let t = regex::Regex::new(r#""timestamp":"\d{4}-[^"]*""#).unwrap().replace_all(&s, "\"timestamp\":\"T\"").into_owned();
    regex::Regex::new(r#""id":"\d+\.\d+""#).unwrap().replace_all(&t, "\"id\":\"I\"").into_owned()
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
}

fn test_logs() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ruleset/testing/tests");
    let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
    names.sort();
    names.iter().flat_map(|p| std::fs::read_to_string(p).unwrap_or_default().lines().filter_map(|l| l.strip_prefix("log ").and_then(|l| l.split_once(" = ")).map(|(_, v)| v.to_string())).collect::<Vec<_>>()).collect()
}

#[test]
fn requests() {
    let home = manager();
    let mut seq_a = 0x1000_0000u32;
    let mut seq_b = 0x1000_0000u32;
    let mut o = ol::Logtest::new(ol::LogtestConfig {
        enabled: true,
        threads: 1,
        max_sessions: 2,
        session_timeout: 900,
        ossec_conf: PathBuf::from("etc/ossec.conf"),
        engine: EngineConfig { rule: RuleConfig { home: home.clone(), ..RuleConfig::default() }, ..EngineConfig::default() },
    });
    let mut n = nl::Logtest::new(nl::Settings {
        enabled: true,
        threads: 1,
        max_sessions: 2,
        session_timeout: 900,
        config_file: PathBuf::from("etc/ossec.conf"),
        engine: EngineSettings { rules: RuleSettings { home: home.clone(), ..RuleSettings::default() }, ..EngineSettings::default() },
    });
    o.token_source = Box::new(move || {
        seq_a += 0x111;
        seq_a
    });
    n.token_source = Box::new(move || {
        seq_b += 0x111;
        seq_b
    });
    let logs = test_logs();
    let mut r = Rng(0x9E3779B97F4A7C15);
    let mut tokens: Vec<String> = Vec::new();
    let fixed = [
        "{bad json",
        "{}",
        "{\"parameters\":1}",
        "{\"parameters\":{}}",
        "{\"parameters\":{},\"command\":1}",
        "{\"parameters\":{},\"command\":\"x\"}",
        "{\"parameters\":{},\"command\":\"remove_session\"}",
        "{\"parameters\":{\"token\":\"abc\"},\"command\":\"remove_session\"}",
        "{\"parameters\":{\"token\":\"0000abcd\"},\"command\":\"remove_session\"}",
        "{\"parameters\":{\"location\":\"\",\"log_format\":\"syslog\",\"event\":\"x\"},\"command\":\"log_processing\"}",
        "{\"parameters\":{\"location\":\"l\",\"log_format\":1,\"event\":\"x\"},\"command\":\"log_processing\"}",
        "{\"parameters\":{\"location\":\"l\",\"log_format\":\"syslog\"},\"command\":\"log_processing\"}",
        "{\"parameters\":{\"location\":\"l\",\"log_format\":\"syslog\",\"event\":{}},\"command\":\"log_processing\"}",
        "{\"parameters\":{\"location\":\"l\",\"log_format\":\"syslog\",\"event\":\"\"},\"command\":\"log_processing\"}",
    ];
    let mut alerts = 0;
    for round in 0..300 {
        let req = if round < fixed.len() {
            fixed[round].to_string()
        } else {
            let log = &logs[r.below(logs.len())];
            let token = match r.below(5) {
                0 => String::new(),
                1 => ",\"token\":\"zz\"".into(),
                2 => ",\"token\":5".into(),
                _ if !tokens.is_empty() => format!(",\"token\":\"{}\"", tokens[r.below(tokens.len())]),
                _ => String::new(),
            };
            let options = ["", ",\"options\":{\"rules_debug\":true}", ",\"options\":{\"rules_debug\":1}", ",\"options\":[1]"][r.below(4)];
            let event = if log.starts_with('{') && r.below(2) == 0 { log.clone() } else { provigil_json::Json::string(log.as_str()).print_unformatted().into_iter().map(char::from).collect() };
            let location = ["stdin", "/var/log/auth.log", "a:b|c", "EventChannel"][r.below(4)];
            if r.below(40) == 0 && !tokens.is_empty() {
                format!("{{\"parameters\":{{\"token\":\"{}\"}},\"command\":\"remove_session\"}}", tokens[r.below(tokens.len())])
            } else {
                format!("{{\"parameters\":{{\"location\":\"{location}\",\"log_format\":\"syslog\",\"event\":{event}{token}{options}}},\"command\":\"log_processing\"}}")
            }
        };
        let a = o.process_request(req.as_bytes());
        let b = n.request(req.as_bytes());
        assert_eq!(mask(&a), mask(&b), "request {round}: {req}");
        if let Some(t) = provigil_json::parse(&b).and_then(|j| j.get("data").and_then(|d| d.get("token")).and_then(|t| t.as_bytes()).map(|t| String::from_utf8_lossy(t).into_owned())) {
            if !tokens.contains(&t) {
                tokens.push(t);
            }
        }
        alerts += usize::from(String::from_utf8_lossy(&b).contains("\"alert\":true"));
    }
    assert!(alerts > 50, "{alerts} alerts");
    assert_eq!(ol::Logtest::error_response(ol::LOGTEST_ERROR_RECV_MSG_OVERSIZE), nl::Logtest::error_answer(nl::TOO_LARGE));
}
