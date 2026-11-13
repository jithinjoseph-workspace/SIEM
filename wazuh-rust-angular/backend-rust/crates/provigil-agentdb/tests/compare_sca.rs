//! `agent <id> sca …`: old and new must match.
mod common;

fn requests() -> Vec<String> {
    let mut r: Vec<String> = vec![r#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#.into()];
    let mut q = |s: &str| r.push(format!("agent 1 sca {s}"));
    r_push_raw(&mut q);
    r
}

fn r_push_raw(q: &mut dyn FnMut(&str)) {
    for s in [
        "query",
        "nosuch x",
        "query 1",
        "insert_policy Win 11|win11.yml|win11|Windows 11 checks|https://example|abc123",
        "insert_policy Win 11|win11.yml|win11|desc",
        "insert_policy Linux|linux.yml|linux|d|r|NULL",
        "query_policies",
        "query_policy win11",
        "query_policy nosuch",
        "query_policy_sha256 win11",
        "query_policy_sha256 linux",
        r#"insert {"id":5,"policy_id":"win11","check":{"id":100,"title":"Password length","description":"d","rationale":"r","remediation":"m","references":"ref","file":"f","condition":"all","directory":"dir","process":"p","registry":"reg","command":"c","result":"failed","reason":"why"}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":101,"title":"Lockout"}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":101,"title":"Lockout again"}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":102,"title":"Audit","result":"passed"}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":103,"title":"Guest","result":"not applicable"}}"#,
        r#"insert {"id":-1,"policy_id":"win11","check":{"id":1,"title":"t"}}"#,
        r#"insert {"id":"5","policy_id":"win11","check":{"id":1,"title":"t"}}"#,
        r#"insert {"policy_id":"win11"}"#,
        r#"insert {"id":5,"check":{}}"#,
        r#"insert {"id":5,"policy_id":7,"check":{}}"#,
        r#"insert {"id":5,"policy_id":"win11"}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"title":"t"}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":"x","title":"t"}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":9}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":9,"title":3}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":9,"title":"t","references":1}}"#,
        r#"insert {"id":5,"policy_id":"win11","check":{"id":9,"title":"t","reason":[]}}"#,
        "insert not json",
        "query 100",
        "query 101",
        "query 999",
        "query_results win11",
        "query_results nosuch",
        "update 101|passed|ok now|6",
        "update 102|failed||NULL",
        "update 999|passed|r|6",
        "update 101|passed",
        "update 101",
        "insert_rules 100|f|C:\\file.txt",
        "insert_rules 100|f|C:\\file.txt",
        "insert_rules 100",
        "insert_rules 100|x",
        "insert_compliance 100|cis|1.1.1",
        "insert_compliance 101|pci_dss|8.2",
        "insert_compliance 999|cis|9",
        "insert_scan_info 1700000000|1700000100|5|win11|10|20|3|33|30|hashA",
        "insert_scan_info 1|2|3|win11",
        "insert_scan_info NULL|2|3|linux|1|2|3|6|33|hashB",
        "insert_scan_info 1|2",
        "query_scan win11",
        "query_scan nosuch",
        "update_scan_info win11|X1700000500",
        "update_scan_info NULL|",
        "update_scan_info nobar",
        "update_scan_info_start win11|ignored|1700000600|7|11|19|4|34|32|hashC",
        "update_scan_info_start win11|ignored|1",
        "update_scan_info_start NULL|x|1|2|3|4|5|6|7|h",
        "query_scan win11",
        "delete_check_distinct win11|6",
        "delete_check_distinct win11",
        "delete_check_distinct linux|NULL",
        "delete_check linux",
        "delete_policy linux",
        "query_policies",
        "delete_check win11",
        "query_results win11",
    ] {
        q(s);
    }
}

#[test]
fn sca_matches_old() {
    let p = common::Pair::new();
    let mut reqs = requests();
    for t in ["sca_policy", "sca_check", "sca_scan_info", "sca_check_rules", "sca_check_compliance"] {
        reqs.push(format!("agent 1 sql SELECT * FROM {t} ORDER BY rowid"));
    }
    let diffs = p.run(&reqs, &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}
