//! The purple loop end to end on the real engine and the official ruleset:
//! a technique a built-in rule covers is Defended, an uncovered one is a gap whose
//! drafted rule, once deployed, makes the next round Defended.
use siem_redswarm::*;

fn verdict(eng: &siem_engine::AnalysisEngine, t: &AttackTechnique) -> DetectionVerdict {
    let ev = siem_core::RawEvent::new("043", siem_core::EventSource::WindowsEvent, "redswarm", t.sample_raw_logs[0].clone());
    let alerts: Vec<_> = eng.process_event(&ev, "win-node", "10.0.0.5").into_iter().collect();
    PurpleLoopVerifier::verify_execution(t, "043", ev.timestamp, 15, &alerts).verdict
}

#[test]
fn gap_closes_after_its_draft_is_deployed() {
    std::env::set_var("WAZUH_RULESET_PATH", concat!(env!("CARGO_MANIFEST_DIR"), "/../../ruleset"));
    let eng = siem_engine::AnalysisEngine::new();

    // covered by a built-in rule (a level-0 ruleset match used to hide it)
    assert_eq!(verdict(&eng, &find_technique("T1070.001").unwrap()), DetectionVerdict::Defended);

    let t = find_technique("T1036.005").unwrap();
    assert_ne!(verdict(&eng, &t), DetectionVerdict::Defended);
    let draft = RuleSynthesizer::synthesize_draft_rule(uuid::Uuid::new_v4(), &t, &t.sample_raw_logs[0]);
    assert!(draft.logtest_passed, "{}", draft.logtest_output);

    // deployed through a clone, as siem-api's AppState holds one
    eng.clone().set_custom_rules_xml(&draft.rule_xml);
    assert_eq!(verdict(&eng, &t), DetectionVerdict::Defended);
}
