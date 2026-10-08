//! Minimal wazuh-logtest: `logtest <wazuh-home>`, one event per stdin line,
//! prints the output JSON (and rule debug with `-v`).

use std::io::BufRead;
use std::path::PathBuf;

use siem_analysisd::engine::{Engine, EngineConfig};
use siem_analysisd::logmsg::LogList;
use siem_analysisd::ruleset::load_from_ossec_conf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let home = PathBuf::from(&args[1]);
    let verbose = args.iter().any(|a| a == "-v");
    let mut log = LogList::default();
    let rs = load_from_ossec_conf(&home.join("ossec.conf"), &home, &mut log).expect("ossec.conf");
    let mut cfg = EngineConfig::default();
    cfg.rule.home = home.clone();
    cfg.diff_dir = home.join("queue/diff");
    let mut eng = Engine::new(cfg);
    if !eng.load_ruleset(&rs.decoders, &rs.lists, &rs.includes, None, &mut log) {
        for m in &log.msgs {
            eprintln!("{:?} {}", m.level, m.msg);
        }
        std::process::exit(1);
    }
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.is_empty() {
            continue;
        }
        let mut dbg = Vec::new();
        let mut l = LogList::default();
        let out = eng.logtest_process(line.as_bytes(), b"stdin", 0, if verbose { Some(&mut dbg) } else { None }, &mut l);
        for d in &dbg {
            println!("  {d}");
        }
        for m in &l.msgs {
            println!("  [{:?}] {}", m.level, m.msg);
        }
        match out {
            Some((j, alert)) => println!("{} alert={alert}", j.to_string_unformatted()),
            None => println!("(no output)"),
        }
    }
}
