//! Its own test binary: `set_logger` is process-wide and would hide the logs `vectors.rs` captures.

use provigil_fileop::{check_binary_file, merge_append_file, set_logger};
use std::sync::Arc;

#[test]
fn messages_go_to_the_daemon_logger() {
    let dir = std::env::temp_dir().join(format!("pv-fileop-logger-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("etc")).unwrap();
    // WLog::new exits the process without a config file: in the home on Windows, under etc/ on Unix.
    for conf in ["ossec.conf", "etc/ossec.conf"] {
        std::fs::write(dir.join(conf), "<ossec_config></ossec_config>
").unwrap();
    }
    let first = Arc::new(siem_log::WLog::new("test", &dir));
    set_logger(first.clone());
    set_logger(Arc::new(siem_log::WLog::new("second", &dir)));
    assert_eq!(Arc::strong_count(&first), 2, "the first logger stays installed");

    let missing = dir.join("none").to_string_lossy().into_owned();
    assert!(check_binary_file(&missing));
    assert!(!merge_append_file(&mut Vec::new(), &missing, None));
    let _ = std::fs::remove_dir_all(&dir);
}
