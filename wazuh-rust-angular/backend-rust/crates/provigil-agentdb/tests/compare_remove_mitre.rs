//! `wazuhdb remove` and the `mitre` actor: old and new must match.
mod common;

fn requests() -> Vec<String> {
    [
        "wazuhdb",
        "wazuhdb remove",
        "wazuhdb nosuch 1",
        "wazuhdb remove ",
        "wazuhdb remove  ",
        "agent 1 sql SELECT 1",
        "agent 2 sql SELECT 1",
        "agent 3 sql SELECT 1",
        "agent 12 sql SELECT 1",
        "wazuhdb remove 1",
        "wazuhdb remove 1",
        "wazuhdb remove x 2 \"3\" 4x 99999999999999999999 12",
        r#"wazuhdb remove 12 -5 "1 2" a\ b"#,
        "agent 2 sql SELECT 1",
        "wazuhdb remove 2",
        "mitre",
        "mitre sql",
        "mitre nosuch x",
        "mitre sql SELECT * FROM technique ORDER BY id",
        "mitre sql SELECT * FROM nosuch",
        "mitre sql INSERT INTO technique VALUES ('T9', 'x')",
        "mitre sql SELECT count(*) AS n FROM technique",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[test]
fn remove_and_mitre_match_old() {
    // without the MITRE database
    let p = common::Pair::new();
    let diffs = p.run(&["mitre sql SELECT 1".to_string()], &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
    for home in p.homes() {
        std::fs::create_dir_all(home.join("var/db")).unwrap();
        let path = home.join("var/db/mitre.db");
        let (_, db) = provigil_sqlite::Db::open_v2(path.to_string_lossy().as_bytes(), provigil_sqlite::SQLITE_OPEN_READWRITE | provigil_sqlite::SQLITE_OPEN_CREATE);
        let db = db.unwrap();
        db.exec(b"CREATE TABLE technique (id TEXT PRIMARY KEY, name TEXT); INSERT INTO technique VALUES ('T1059', 'Command and Scripting Interpreter'), ('T1003', 'OS Credential Dumping');");
    }
    let p2 = common::Pair::new();
    for (from, to) in p.homes().iter().zip(p2.homes()) {
        std::fs::create_dir_all(to.join("var/db")).unwrap();
        std::fs::copy(from.join("var/db/mitre.db"), to.join("var/db/mitre.db")).unwrap();
    }
    let diffs = p2.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}
