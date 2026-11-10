//! Blocks (add) or unblocks (delete) the alert's attacker IP with iptables / ip6tables
//! DROP rules in the INPUT and FORWARD chains. Linux only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use siem_active_response::*;

/// Tries per chain; try `n` that fails pauses `n * PAUSE_MS` (1, 2, 3, 4 s).
const TRIES: u64 = 5;
static PAUSE_MS: AtomicU64 = AtomicU64::new(1000);

/// Runs `cmd` until it succeeds, at most [`TRIES`] times: the tries made and whether the last succeeded.
fn with_retries(mut cmd: impl FnMut() -> bool) -> (u64, bool) {
    for n in 1..=TRIES {
        if cmd() {
            return (n, true);
        }
        if n < TRIES {
            std::thread::sleep(Duration::from_millis(n * PAUSE_MS.load(Ordering::Relaxed)));
        }
    }
    (TRIES, false)
}

fn main() {
    #[cfg(windows)]
    dll_guard::enable();
    std::process::exit(run_main());
}

fn run_main() -> i32 {
    let argv0 = argv0();
    let Some((action, msg)) = setup_and_check_message(&argv0) else { return -1 };
    let Some(ip) = alert_ip(&msg) else {
        write_debug_file(&argv0, b"Cannot read a valid attacker IP from the alert");
        return -1;
    };
    if !cfg!(target_os = "linux") {
        write_debug_file(&argv0, b"Invalid system");
        return -1;
    }
    if action == Action::Add {
        if let Err(code) = check_keys(&argv0, &ip) {
            return code;
        }
    }
    let tool = if ip_version(&ip) == Some(6) { "ip6tables" } else { "iptables" };
    let (found, bin) = get_binary_path(tool);
    if !found {
        write_debug_file(&argv0, format!("The binary '{tool}' is not present in the PATH").as_bytes());
    }
    const LOCK_DIR: &str = "active-response/bin/fw-drop";
    const PID_FILE: &str = "active-response/bin/fw-drop/pid";
    if !lock(LOCK_DIR, PID_FILE, &argv0, "firewall-drop") {
        return -1;
    }
    let op = if action == Action::Add { "-I" } else { "-D" };
    for chain in ["INPUT", "FORWARD"] {
        let args = [op, chain, "-s", ip.as_str(), "-j", "DROP"];
        // a busy firewall lock (another iptables run) fails the command: try again
        let (tries, ok) = with_retries(|| {
            std::process::Command::new(&bin)
                .args(args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        });
        if !ok {
            write_debug_file(&argv0, format!("Unable to run after {tries} tries: {bin} {}", args.join(" ")).as_bytes());
        }
    }
    unlock(LOCK_DIR, &argv0);
    write_debug_file(&argv0, b"Ended");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn failing_command_is_tried_five_times_with_growing_pauses() {
        PAUSE_MS.store(20, Ordering::Relaxed);
        let mut at: Vec<Instant> = Vec::new();
        assert_eq!(
            with_retries(|| {
                at.push(Instant::now());
                false
            }),
            (5, false)
        );
        assert_eq!(at.len(), 5);
        for (i, w) in at.windows(2).enumerate() {
            let pause = w[1] - w[0];
            assert!(pause >= Duration::from_millis(20 * (i as u64 + 1)), "pause {} was {pause:?}", i + 1);
        }
        let mut calls = 0;
        assert_eq!(
            with_retries(|| {
                calls += 1;
                calls == 3
            }),
            (3, true)
        );
    }
}
