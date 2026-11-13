//! Prints the table layout the old implementation creates (run with --nocapture); the new code
//! must create the same layout.
use std::sync::Arc;

struct Quiet;
impl siem_wdb::wdb::WdbEnv for Quiet {
    fn log(&self, _: &str, _: &[u8]) {}
    fn time(&self) -> i64 {
        1_800_000_000
    }
    fn timeofday(&self) -> siem_wdb::wdb::state::Tv {
        siem_wdb::wdb::state::Tv { sec: 1_800_000_000, usec: 0 }
    }
    fn router_send(&self, _: i32, _: &[u8]) {}
    fn send_peer(&self, _: i32, _: &[u8]) -> i32 {
        0
    }
    fn is_single_node(&self) -> (i32, i32) {
        (0, 0)
    }
}

#[test]
fn print_old_schema() {
    let home = tempfile::tempdir().unwrap();
    for d in ["queue/db", "queue/tasks", "backup/db"] {
        std::fs::create_dir_all(home.path().join(d)).unwrap();
    }
    let d = siem_wdb::wdb::Wdbd::new(siem_wdb::wdb::WdbConfig::default(), home.path().to_path_buf(), Arc::new(Quiet));
    d.create_profile();
    let ask = |q: &str| String::from_utf8_lossy(&d.parse(q.as_bytes(), 0).1).into_owned();
    ask(r#"global insert-agent {"id":1,"name":"a","date_add":1}"#);
    for (who, q) in [
        ("GLOBAL", "global sql SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY rowid"),
        ("AGENT", "agent 1 sql SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY rowid"),
        ("TASK", "task sql SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY rowid"),
        ("GLOBAL-META", "global sql SELECT * FROM metadata"),
        ("AGENT-META", "agent 1 sql SELECT * FROM metadata"),
        ("AGENT-ROWS", "agent 1 sql SELECT 'sync_info' t, * FROM sync_info"),
        ("GLOBAL-ROWS", "global sql SELECT * FROM agent"),
    ] {
        println!("=== {who}\n{}", ask(q));
    }
}
