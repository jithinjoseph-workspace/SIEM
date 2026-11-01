//! EDR tamper protection (not in Wazuh): locks the agent service (`tamper::LOCKED_SDDL`,
//! restart on failure) or opens a maintenance window.
//! extra_args: `lock`; `off` (unlocked until locked again); `window=<id>` opens a window:
//! with a timeout, execd runs it again with "delete" when the time is up, which locks again
//! only when that window is still the open one.

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

#[cfg(windows)]
use siem_active_response::{edr::*, tamper::*, *};

fn main() {
    #[cfg(windows)]
    std::process::exit(win_main());
    #[cfg(not(windows))]
    std::process::exit(-1);
}

#[cfg(windows)]
const STATE_FILE: &str = "active-response\\tamper.state";

#[cfg(windows)]
fn win_main() -> i32 {
    // This must be always the first instruction
    dll_verify::enable_dll_verification(&std::sync::Arc::new(siem_log::WLog::new("unset", std::path::Path::new("."))));
    let argv0 = argv0();
    let Some((action, input)) = setup_and_check_message(&argv0) else { return -1 };
    let window = extra_arg(&input, "window").unwrap_or_default();
    let mut st = State::parse(&std::fs::read_to_string(STATE_FILE).unwrap_or_default());
    let r: Result<(&str, String), String> = if action == Action::Delete {
        // the window's timeout: lock again unless a newer window replaced it
        if st.window.as_deref() == Some(window.as_str()) {
            st.window = None;
            lock(&mut st).map(|_| ("locked", "Maintenance window over; agent service locked again".to_string()))
        } else {
            Ok(("unchanged", format!("Window {window} was already closed or replaced")))
        }
    } else if has_extra_flag(&input, "lock") {
        st.window = None;
        lock(&mut st).map(|_| ("locked", "Agent service locked: it cannot be stopped, changed or removed".to_string()))
    } else if has_extra_flag(&input, "off") {
        st.window = None;
        unlock(&st).map(|_| ("off", "Tamper protection off: the agent service has its own permissions again".to_string()))
    } else if valid_window(&window) {
        if let Err(code) = check_keys(&argv0, &window) {
            return code;
        }
        st.window = Some(window.clone());
        unlock(&st).map(|_| ("maintenance", "Maintenance window open: administrators may stop, change or remove the agent".to_string()))
    } else {
        Err("lock, off or window=<id> is required".to_string())
    };
    let _ = std::fs::write(STATE_FILE, st.render());
    let m = match &r {
        Ok((state, m)) => format!("{{\"message\":{},\"state\":\"{state}\",\"window\":{},\"status\":\"success\",\"script\":\"tamper-protect\"}}", json_str(m), json_str(&window)),
        Err(e) => format!("{{\"message\":{},\"window\":{},\"status\":\"failed\",\"script\":\"tamper-protect\"}}", json_str(e), json_str(&window)),
    };
    write_debug_file(&argv0, m.as_bytes());
    write_debug_file(&argv0, b"Ended");
    if r.is_ok() { 0 } else { -1 }
}

/// `sc.exe <args>` from System32: its output, or why it failed.
#[cfg(windows)]
fn sc(args: &[&str]) -> Result<String, String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let out = std::process::Command::new(format!("{root}\\System32\\sc.exe")).args(args).output().map_err(|e| format!("sc.exe: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!("sc.exe {}: {}", args.first().unwrap_or(&""), text.trim()))
    }
}

/// Saves the descriptor to restore (first lock only), then locks and sets the recovery.
#[cfg(windows)]
fn lock(st: &mut State) -> Result<(), String> {
    let current = sc(&["sdshow", SERVICE]).ok().and_then(|o| sddl_of(&o));
    if st.original.is_none() {
        st.original = current.filter(|s| s != LOCKED_SDDL);
        // saved before the change, so a crash cannot lose it
        let _ = std::fs::write(STATE_FILE, st.render());
    }
    sc(&FAILURE_ARGS)?;
    sc(&["sdset", SERVICE, LOCKED_SDDL]).map(|_| ())
}

#[cfg(windows)]
fn unlock(st: &State) -> Result<(), String> {
    sc(&["sdset", SERVICE, st.restore_sddl()]).map(|_| ())
}
