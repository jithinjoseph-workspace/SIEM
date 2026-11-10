//! The executed actions, audit log and simulation overrides: handed to siem-api only when they
//! changed, read back at start, and moved from an earlier version's file.

use siem_intent_engine::{IntentEngine, IntentExtras};

#[test]
fn extras_are_handed_over_once_and_load_back() {
    let e = IntentEngine::new("no-such-file.json");
    assert!(e.take_extras().is_none(), "nothing changed yet");
    e.save();
    let x = e.take_extras().expect("changed");
    assert!(e.take_extras().is_none(), "handed over once");
    e.extras_store_failed();
    assert!(e.take_extras().is_some(), "a failed store is tried again");

    let mut stored = x.clone();
    stored.executed_actions = vec!["act-1".into()];
    let fresh = IntentEngine::new("no-such-file.json");
    fresh.load_extras(stored.clone());
    fresh.load_extras(stored);
    fresh.save();
    assert_eq!(fresh.take_extras().unwrap().executed_actions, vec!["act-1".to_string()], "loaded once, no duplicates");
}

#[test]
fn an_earlier_versions_file_brings_its_extras() {
    let dir = std::env::temp_dir().join(format!("pv-intent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("intent_engine_config.json");
    std::fs::write(&file, r#"{"dossiers":[],"executed_actions":["act-9"],"action_audit":[],"simulation_overrides":{}}"#).unwrap();
    let e = IntentEngine::new(&file);
    let x: IntentExtras = e.take_extras().expect("a file's extras count as changed");
    assert_eq!(x.executed_actions, vec!["act-9".to_string()]);
    e.stored();
    assert!(!file.exists(), "the file goes once stored");
    let _ = std::fs::remove_dir_all(dir);
}
