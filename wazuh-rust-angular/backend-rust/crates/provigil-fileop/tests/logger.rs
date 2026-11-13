//! Its own test binary: `set_logger` is process-wide and would hide the logs `vectors.rs` captures.

use provigil_fileop::{check_binary_file, merge_append_file, set_logger};
use std::sync::{Arc, Mutex};

#[test]
fn messages_go_to_the_daemon_logger() {
    let got: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let g = got.clone();
    set_logger(Arc::new(move |level: &str, m: &str| g.lock().unwrap().push((level.to_string(), m.to_string()))));
    // the first logger stays installed
    set_logger(Arc::new(|_: &str, _: &str| panic!("second logger used")));

    let dir = std::env::temp_dir().join(format!("pv-fileop-logger-{}", std::process::id()));
    let missing = dir.join("none").to_string_lossy().into_owned();
    assert!(check_binary_file(&missing));
    assert!(!merge_append_file(&mut Vec::new(), &missing, None));
    assert!(!got.lock().unwrap().is_empty(), "messages reached the logger");
}
