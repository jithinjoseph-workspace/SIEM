//! The `agent <id>` request layer and its generic commands: old and new must match.
mod common;

fn requests() -> Vec<String> {
    let v = [
        r#"global insert-agent {"id":1,"name":"pc1","date_add":1}"#,
        r#"global insert-agent {"id":2,"name":"pc2","date_add":1}"#,
        "agent",
        "agent 1",
        "agent abc sql SELECT 1",
        "agent 1x sql SELECT 1",
        "agent  sql SELECT 1",
        "agent 99 sql SELECT 1",
        "agent -1 sql SELECT 1",
        "agent 1 sql SELECT * FROM metadata ORDER BY key",
        "agent 1 sql SELECT * FROM sync_info ORDER BY component",
        "agent 1 sql SELECT * FROM scan_info ORDER BY module",
        "agent 1 sql SELECT nosuch FROM metadata",
        "agent 1 sql",
        "agent 1 nosuch",
        "agent 1 nosuch arg",
        "agent 0 sql SELECT count(*) AS n FROM sync_info",
        "agent 000 sql SELECT 1 AS one",
        "agent 2 begin",
        "agent 2 begin",
        "agent 2 sql INSERT INTO metadata (key, value) VALUES ('k', 'v')",
        "agent 2 commit",
        "agent 2 commit",
        "agent 2 sql SELECT * FROM metadata WHERE key = 'k'",
        "agent 2 get_fragmentation",
        "agent 2 vacuum",
        "agent 2 sql SELECT key FROM metadata ORDER BY key",
        "agent 2 sleep 1",
        "agent 2 sleep",
        "agent 2 sleep abc",
        "agent 2 close",
        "agent 2 sql SELECT count(*) AS n FROM metadata",
        "agent 2 remove",
        "agent 2 sql SELECT count(*) AS n FROM metadata",
        "agent 1 syscheck",
        "agent 1 fim_registry_key",
        "agent 1 rootcheck",
        "agent 1 syscollector_packages",
        "agent 1 sql SELECT * FROM sca_policy",
    ];
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn agent_base_matches_old() {
    let p = common::Pair::new();
    let diffs = p.run(&requests(), &|s| s);
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}
