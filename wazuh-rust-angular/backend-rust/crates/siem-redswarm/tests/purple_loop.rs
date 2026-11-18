//! The purple loop's verdict: only the alerts of a round's own events count (their location
//! names the round), and the ATT&CK id the shipped rules give decides Defended. The attacks
//! themselves go through the real analysis engine in siem-api (`redswarm_engine.rs`).
use siem_core::{AgentAlertInfo, Alert, DecodedFields, MitreAttack, RuleAlertInfo};
use siem_redswarm::*;

fn alert(location: &str, rule: u32, mitre: Option<&str>) -> Alert {
    Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        rule: RuleAlertInfo {
            id: rule,
            level: 10,
            description: "sshd: brute force trying to get access to the system".into(),
            groups: vec!["sshd".into(), "authentication_failed".into()],
            mitre: mitre.map(|m| MitreAttack { id: m.into(), tactic: "Credential Access".into(), technique: "Brute Force".into() }),
        },
        agent: AgentAlertInfo { id: "007".into(), name: "web01".into(), ip: "10.0.0.5".into() },
        manager: None,
        decoder: None,
        full_log: "sshd[4102]: Failed password for root from 203.0.113.50 port 54820 ssh2".into(),
        decoded: DecodedFields::default(),
        location: location.into(),
        data: Default::default(),
    }
}

fn verdict(t: &AttackTechnique, round: &str, alerts: Vec<Alert>) -> DetectionVerdict {
    let own: Vec<Alert> = alerts.into_iter().filter(|a| a.location.starts_with(&format!("redswarm/{round}/"))).collect();
    PurpleLoopVerifier::verify_execution(t, "", chrono::Utc::now(), 60, &own).verdict
}

#[test]
fn only_the_rounds_own_alerts_decide() {
    let t = find_technique_for("T1110.001", "linux").unwrap();
    assert_eq!(verdict(&t, "r1", vec![alert("redswarm/r1/T1110.001", 5763, Some("T1110"))]), DetectionVerdict::Defended);
    // the computer's real brute force at the same time is not this round's detection
    assert_eq!(verdict(&t, "r1", vec![alert("/var/log/auth.log", 5763, Some("T1110"))]), DetectionVerdict::HardGap);
    assert_eq!(verdict(&t, "r1", vec![alert("redswarm/r2/T1110.001", 5763, Some("T1110"))]), DetectionVerdict::HardGap);
    // caught by a low, generic rule, not as the attack it is
    let mut generic = alert("redswarm/r1/T1110.001", 5700, None);
    generic.rule.level = 3;
    assert_eq!(verdict(&t, "r1", vec![generic]), DetectionVerdict::SoftGap);
}

#[test]
fn every_attack_has_events_for_its_system() {
    let c = get_curated_catalog();
    assert!(c.iter().filter(|t| t.platforms == ["windows"]).count() >= 8 && c.iter().filter(|t| t.platforms == ["linux"]).count() >= 7);
    for t in &c {
        assert!(!t.sample_raw_logs.is_empty() && !t.expected_mitre_ids.is_empty(), "{}", t.id);
        let windows = t.sample_raw_logs[0].starts_with("{\"Message\"");
        assert_eq!(windows, t.platforms == ["windows"], "{}: a Windows attack has Windows events", t.id);
    }
    assert_eq!(find_technique_for("T1136.001", "linux").unwrap().platforms, ["linux"]);
    assert_eq!(find_technique_for("T1136.001", "windows").unwrap().platforms, ["windows"]);
}
