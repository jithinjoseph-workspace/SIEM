//! Restarts the agent: the ProVigilSvc service on Windows, `bin/wazuh-control restart` elsewhere.

use siem_active_response::*;

fn main() {
    #[cfg(windows)]
    dll_guard::enable();
    std::process::exit(run_main());
}

fn run_main() -> i32 {
    let argv0 = argv0();
    let Some((action, _)) = setup_and_check_message(&argv0) else { return -1 };
    if action == Action::Add {
        restart(&argv0);
    }
    write_debug_file(&argv0, b"Ended");
    0
}

#[cfg(windows)]
fn restart(argv0: &str) {
    let mut buf = [0u16; 260];
    // SAFETY: the buffer and its length match
    let n = unsafe { windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let dir = if n > 0 && n < buf.len() { String::from_utf16_lossy(&buf[..n]) } else { r"C:\Windows\System32".into() };
    let sc = format!("{dir}\\sc.exe");
    let log = |m: String| write_debug_file(argv0, m.as_bytes());
    let state = || run_output(&sc, &["query", SERVICE]).map(|o| service_state(&String::from_utf8_lossy(&o))).unwrap_or("UNKNOWN");
    // the service's own process ends a moment after it reports stopped: a start before that fails,
    // so wait for STOPPED, then start and check, a few times
    let pid = || run_output(&sc, &["queryex", SERVICE]).and_then(|o| service_pid(&String::from_utf8_lossy(&o)));
    let old = pid();
    let _ = run(&sc, &["stop", SERVICE]);
    if !wait_for(&state, "STOPPED", 60) {
        // a hung agent never stops: end its process so the service can start again
        log(format!("{SERVICE} not stopped after 60 s (state {}); ending process {old:?}", state()));
        if let Some(p) = old {
            let _ = run(&format!("{dir}\\taskkill.exe"), &["/F", "/PID", &p.to_string()]);
        }
        if !wait_for(&state, "STOPPED", 20) {
            log(format!("{SERVICE} still not stopped (state {})", state()));
        }
    }
    for attempt in 1..=5 {
        let _ = run(&sc, &["start", SERVICE]);
        // running with a new process: the old one may still answer RUNNING
        if wait_for(&state, "RUNNING", 30) && pid().is_some_and(|p| Some(p) != old) {
            log(format!("{SERVICE} running again (attempt {attempt}, process {:?})", pid()));
            return;
        }
        log(format!("{SERVICE} start attempt {attempt} failed (state {})", state()));
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    log(format!("Unable to start {SERVICE}; Windows' service recovery will try again"));
}

#[cfg(windows)]
const SERVICE: &str = "ProVigilSvc";

/// The state word of `sc query`'s STATE line (`STATE : 4  RUNNING`).
#[cfg_attr(not(windows), allow(dead_code))]
fn service_state(out: &str) -> &'static str {
    let line = out.lines().find(|l| l.trim_start().starts_with("STATE")).unwrap_or("");
    ["STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING", "PAUSED"].into_iter().find(|s| line.contains(s)).unwrap_or("UNKNOWN")
}

/// The PID line of `sc queryex` (`PID : 9116`); None when stopped (PID 0) or not found.
#[cfg_attr(not(windows), allow(dead_code))]
fn service_pid(out: &str) -> Option<u32> {
    let line = out.lines().find(|l| l.trim_start().starts_with("PID"))?;
    line.split(':').nth(1)?.trim().parse().ok().filter(|p| *p != 0)
}

#[cfg(windows)]
fn wait_for(state: &dyn Fn() -> &'static str, want: &str, secs: u64) -> bool {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if state() == want {
            return true;
        }
        if std::time::Instant::now() >= end {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

#[cfg(not(windows))]
fn restart(argv0: &str) {
    let control = std::env::current_dir().unwrap_or_default().join("bin/wazuh-control");
    let control = control.to_string_lossy();
    if !run(&control, &["restart"]) {
        write_debug_file(argv0, format!("Unable to run {control} restart").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{service_pid, service_state};

    #[test]
    fn reads_the_pid_of_sc_queryex() {
        assert_eq!(service_pid("        STATE              : 4  RUNNING\n        PID                : 9116\n"), Some(9116));
        assert_eq!(service_pid("        PID                : 0\n"), None);
        assert_eq!(service_pid("[SC] OpenService FAILED 1060"), None);
    }

    #[test]
    fn reads_the_state_of_sc_query() {
        let out = "SERVICE_NAME: ProVigilSvc
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
";
        assert_eq!(service_state(out), "STOP_PENDING");
        assert_eq!(service_state("        STATE              : 4  RUNNING "), "RUNNING");
        assert_eq!(service_state("        STATE              : 1  STOPPED "), "STOPPED");
        assert_eq!(service_state("[SC] OpenService FAILED 1060"), "UNKNOWN");
    }
}
