//! Wazuh's ruleset unit tests (ruleset/testing/tests/*.ini) run through the
//! Rust engine with wazuh-logtest semantics.
//!
//! Prepare the inputs with `tools/make_test_home.py <wazuh-src> <home> <cases.json>`
//! and run with `SIEM_TEST_HOME=<home> SIEM_TEST_CASES=<cases.json>`.

use std::path::PathBuf;

use siem_analysisd::engine::{Engine, EngineConfig};
use siem_analysisd::logmsg::LogList;
use siem_analysisd::ruleset::load_from_ossec_conf;
use siem_cjson::Json;

#[derive(Debug)]
struct Case {
    file: String,
    section: String,
    name: String,
    events: Vec<String>,
    rule: String,
    alert: String,
    decoder: String,
    negate: bool,
}

fn load_cases(path: &str) -> Vec<Case> {
    let data = std::fs::read(path).unwrap();
    let j = siem_cjson::parse(&data).expect("cases json");
    let Json::Array(items) = j else { panic!("array") };
    let st = |o: &Json, k: &str| String::from_utf8(o.get_exact(k).unwrap().as_bytes().unwrap().to_vec()).unwrap();
    items
        .iter()
        .map(|o| Case {
            file: st(o, "file"),
            section: st(o, "section"),
            name: st(o, "name"),
            events: o
                .get_exact("events")
                .unwrap()
                .children()
                .iter()
                .map(|e| String::from_utf8(e.as_bytes().unwrap().to_vec()).unwrap())
                .collect(),
            rule: st(o, "rule"),
            alert: st(o, "alert"),
            decoder: st(o, "decoder"),
            negate: matches!(o.get_exact("negate"), Some(Json::True)),
        })
        .collect()
}

fn ut_of(out: &Json) -> [String; 3] {
    let mut ut = [String::new(), String::new(), String::new()];
    if let Some(rule) = out.get_exact("rule") {
        if let Some(id) = rule.get_exact("id").and_then(|v| v.as_bytes()) {
            ut[0] = String::from_utf8_lossy(id).into_owned();
        }
        if let Some(Json::Number { double, .. }) = rule.get_exact("level") {
            ut[1] = format!("{}", *double as i64);
        }
    }
    if let Some(d) = out.get_exact("decoder") {
        if let Some(n) = d.get_exact("name").and_then(|v| v.as_bytes()) {
            ut[2] = String::from_utf8_lossy(n).into_owned();
        }
    }
    ut
}

#[test]
fn wazuh_ruleset_ini_tests() {
    let (Ok(home), Ok(cases)) = (std::env::var("SIEM_TEST_HOME"), std::env::var("SIEM_TEST_CASES")) else {
        eprintln!("SIEM_TEST_HOME / SIEM_TEST_CASES not set; skipping");
        return;
    };
    let home = PathBuf::from(home);
    let mut log = LogList::default();
    let rs = load_from_ossec_conf(&home.join("ossec.conf"), &home, &mut log).expect("ossec.conf");
    let mut cfg = EngineConfig::default();
    cfg.rule.home = home.clone();
    cfg.diff_dir = home.join("queue/diff");
    let mut base = Engine::new(cfg);
    let loaded = base.load_ruleset(&rs.decoders, &rs.lists, &rs.includes, None, &mut log);
    for m in &log.msgs {
        eprintln!("[load {:?}] {}", m.level, m.msg);
    }
    assert!(loaded, "ruleset failed to load");
    let logbylevel = rs.logbylevel.map(|v| v as i32).unwrap_or(0);

    let filter = std::env::var("SIEM_TEST_FILTER").ok();
    let cases = load_cases(&cases);
    let mut failed = 0;
    let mut total = 0;
    let mut per_file: std::collections::BTreeMap<String, (u32, u32)> = Default::default();
    for c in &cases {
        if let Some(f) = &filter {
            if !c.file.contains(f.as_str()) {
                continue;
            }
        }
        total += 1;
        let mut eng = base.fork();
        let mut last = [String::new(), String::new(), String::new()];
        for ev in &c.events {
            if ev.is_empty() {
                continue;
            }
            let mut l = LogList::default();
            if let Some((out, _)) = eng.logtest_process(ev.as_bytes(), b"stdin", logbylevel, None, &mut l) {
                last = ut_of(&out);
            }
        }
        let expected = [c.rule.clone(), c.alert.clone(), c.decoder.clone()];
        let rc = if expected == last { expected.iter().filter(|s| s.is_empty()).count() } else { 1 };
        let fail = (rc != 0 && !c.negate) || (rc == 0 && c.negate);
        let e = per_file.entry(c.file.clone()).or_default();
        if fail {
            failed += 1;
            e.1 += 1;
            if failed <= 60 {
                eprintln!(
                    "FAIL {} [{}] {}: expected {:?} got {:?}\n    {:?}",
                    c.file, c.section, c.name, expected, last, c.events
                );
            }
        } else {
            e.0 += 1;
        }
    }
    for (f, (p, x)) in &per_file {
        if *x > 0 {
            eprintln!("{f}: {p} passed, {x} failed");
        }
    }
    eprintln!("{} / {} cases passed", total - failed, total);
    assert_eq!(failed, 0, "{failed} ruleset test cases failed");
}
