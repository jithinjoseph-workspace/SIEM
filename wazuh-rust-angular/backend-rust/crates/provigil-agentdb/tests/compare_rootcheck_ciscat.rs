//! rootcheck and CIS-CAT commands, and the C-style decimal reader: old and new must match.
mod common;

fn requests() -> Vec<String> {
    let v = [
        r#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#,
        "agent 1 rootcheck nosuch",
        "agent 1 rootcheck save",
        "agent 1 rootcheck save 1700000000",
        "agent 1 rootcheck save -5 log text",
        "agent 1 rootcheck save 99999999999999999999 log",
        "agent 1 rootcheck save 1700000000 Trojaned version of file '/bin/ls' detected. {PCI_DSS: 11.4} {CIS: 1.2}",
        "agent 1 rootcheck save 1700000100 Trojaned version of file '/bin/ls' detected. {PCI_DSS: 11.4} {CIS: 1.2}",
        "agent 1 rootcheck save 1700000200 System audit: SSH root login allowed {PCI_DSS: 2.2",
        "agent 1 rootcheck save 1700000300 escaped\\ space log",
        "agent 1 sql SELECT id, date_first, date_last, log, pci_dss, cis FROM pm_event ORDER BY id",
        "agent 1 rootcheck delete",
        "agent 1 sql SELECT count(*) AS n FROM pm_event",
        "agent 1 ciscat",
        "agent 1 ciscat save",
        "agent 1 ciscat other 1|2",
        "agent 1 ciscat save 11",
        "agent 1 ciscat save 11|2023/01/01",
        "agent 1 ciscat save 11|2023/01/01|bench",
        "agent 1 ciscat save 11|2023/01/01|bench|profile",
        "agent 1 ciscat save 11|2023/01/01|bench|profile|10",
        "agent 1 ciscat save 11|2023/01/01|bench|profile|10|2|3|4",
        "agent 1 ciscat save 11|2023/01/01|bench|profile|10|2|3|4|5|80",
        "agent 1 ciscat save 12|NULL|NULL|profile|NULL|-3|x|4|5|NULL",
        "agent 1 ciscat save 13|t|b|p|1|2|3|4|5|6",
        "agent 1 sql SELECT * FROM ciscat_results ORDER BY id",
    ];
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn rootcheck_and_ciscat_match_old() {
    let p = common::Pair::new();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
fn decimal_reader_matches_old() {
    let parts = ["", " ", "\t", "+", "-", "0", "1", "12", "3.5", ".5", "5.", ".", "e", "e5", "E-3", "x", "0x", "0X1A", "0x1.8p3", "p2", "inf", "INFINITY", "nan", "nan(abc)", "NaN(", "1e309", "9", "_", "00012"];
    let mut seen = 0;
    for a in parts {
        for b in parts {
            for c in ["", "x", "7", "e2", " 3"] {
                let s = format!("{a}{b}{c}");
                let old = siem_wdb::wdb::delta::c_strtod(s.as_bytes());
                let new = provigil_agentdb::text::read_real(s.as_bytes());
                let same = (old.0.is_nan() && new.0.is_nan() || old.0 == new.0) && old.1 == new.1;
                assert!(same, "{s:?}: old {old:?} new {new:?}");
                seen += 1;
            }
        }
    }
    assert!(seen > 4000);
}
