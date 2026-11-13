//! The MITRE builder on a small ATT&CK file. (Old vs new on the full enterprise-attack.json:
//! all 19 tables identical, 13 Nov 2026.)

use std::process::Command;

fn query(db: &std::path::Path, sql: &str) -> Vec<Vec<Option<String>>> {
    let mut p = db.to_string_lossy().into_owned().into_bytes();
    p.push(0);
    let (_, d) = siem_sqlite::Db::open_v2(&p, siem_sqlite::SQLITE_OPEN_READWRITE);
    let d = d.unwrap();
    let (_, st, _) = d.prepare_v2(sql.as_bytes());
    let st = st.unwrap();
    let mut out = Vec::new();
    while st.step() == siem_sqlite::SQLITE_ROW {
        out.push((0..st.column_count()).map(|i| st.column_text(i).map(|t| String::from_utf8_lossy(&t).into_owned())).collect());
    }
    out
}

#[test]
fn builds_a_small_attack_file() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("attack.json");
    std::fs::write(
        &json,
        r#"{"spec_version":"2.1","objects":[
        {"type":"x-mitre-tactic","id":"x-mitre-tactic--1","name":"Execution","x_mitre_shortname":"execution","created":"2018-10-17T00:14:20.652Z","modified":"2019-07-19T17:42:06.909Z"},
        {"type":"attack-pattern","id":"attack-pattern--1","name":"Command Line","created":"2017-05-31T21:30:19.735Z","x_mitre_platforms":["Windows","Linux"],
         "x_mitre_data_sources":["Process","Process","Command"],"kill_chain_phases":[{"phase_name":"execution"}],"x_mitre_remote_support":true,
         "external_references":[{"source_name":"mitre-attack","external_id":"T1059","url":"https://attack.mitre.org/techniques/T1059"},{"source_name":"nourl"}]},
        {"type":"attack-pattern","id":"attack-pattern--2","name":"PowerShell"},
        {"type":"intrusion-set","id":"intrusion-set--1","name":"APT1","aliases":["APT1","Comment Crew"],"description":null},
        {"type":"relationship","relationship_type":"subtechnique-of","source_ref":"attack-pattern--2","target_ref":"attack-pattern--1"},
        {"type":"relationship","relationship_type":"uses","id":"relationship--1","source_ref":"intrusion-set--1","target_ref":"attack-pattern--1","description":"uses it"}
    ]}"#,
    )
    .unwrap();
    let db = dir.path().join("mitre.db");
    let st = Command::new(env!("CARGO_BIN_EXE_provigil-mitre")).arg("-d").arg(&db).arg("-j").arg(&json).status().unwrap();
    assert!(st.success());
    let s = |v: &str| Some(v.to_string());
    assert_eq!(query(&db, "SELECT value FROM metadata ORDER BY key"), vec![vec![s("1")], vec![s("2.1")]]);
    assert_eq!(
        query(&db, "SELECT id, created_time, remote_support, network_requirements, subtechnique_of FROM technique ORDER BY id"),
        vec![
            vec![s("attack-pattern--1"), s("2017-05-31 21:30:19.735000"), s("1"), s("0"), None],
            vec![s("attack-pattern--2"), None, s("0"), s("0"), s("attack-pattern--1")],
        ]
    );
    assert_eq!(query(&db, "SELECT source FROM data_source"), vec![vec![s("Command")], vec![s("Process")]]);
    assert_eq!(query(&db, "SELECT tactic_id, tech_id FROM phase"), vec![vec![s("x-mitre-tactic--1"), s("attack-pattern--1")]]);
    assert_eq!(query(&db, "SELECT external_id, type FROM reference"), vec![vec![s("T1059"), s("technique")]]);
    assert_eq!(query(&db, "SELECT alias, type FROM alias ORDER BY alias"), vec![vec![s("APT1"), s("group")], vec![s("Comment Crew"), s("group")]]);
    assert_eq!(query(&db, "SELECT source_type, target_type, description FROM use"), vec![vec![s("group"), s("technique"), s("uses it")]]);

    // a phase with no tactic: refused, the file removed
    std::fs::write(&json, r#"{"spec_version":"2.1","objects":[{"type":"attack-pattern","id":"attack-pattern--9","name":"X","kill_chain_phases":[{"phase_name":"nowhere"}]}]}"#).unwrap();
    let st = Command::new(env!("CARGO_BIN_EXE_provigil-mitre")).arg("-d").arg(&db).arg("-j").arg(&json).output().unwrap();
    assert!(!st.status.success());
    assert!(!db.exists());
}
