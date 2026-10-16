//! `src/active-response/firewalls/default-firewall-drop.c` (Linux branch):
//! drops an IP with iptables / ip6tables in INPUT and FORWARD.
//!
//! shortcut: the FreeBSD/SunOS/NetBSD (ipf) and AIX (genfilt) branches are
//! not ported; they log "Invalid system" until the agent runs there.

#[cfg(unix)]
use siem_active_response::*;

#[cfg(unix)]
const LOCK_PATH: &str = "active-response/bin/fw-drop";
#[cfg(unix)]
const LOCK_FILE: &str = "active-response/bin/fw-drop/pid";

fn main() {
    #[cfg(unix)]
    std::process::exit(unix_main());
    #[cfg(not(unix))]
    std::process::exit(-1);
}

#[cfg(unix)]
fn unix_main() -> i32 {
    let argv0 = argv0();
    let Some((action, input)) = setup_and_check_message(&argv0) else { return -1 };
    let Some(srcip) = get_srcip_from_json(&input) else {
        write_debug_file(&argv0, b"Cannot read 'srcip' from data or invalid IP format");
        return -1;
    };
    if action == Action::Add {
        if let Err(code) = check_keys(&argv0, &srcip) {
            return code;
        }
    }
    let iptables_tmp = match get_ip_version(&srcip) {
        Some(4) => "iptables",
        Some(6) => "ip6tables",
        _ => {
            write_debug_file(&argv0, format!("Unable to run active response (invalid IP: '{srcip}').").as_bytes());
            return -1;
        }
    };
    // uname(): the system name
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: uname fills the struct.
    if unsafe { libc::uname(&mut u) } < 0 {
        write_debug_file(&argv0, b"Cannot get system name");
        return -1;
    }
    // SAFETY: sysname is NUL-terminated.
    let sysname = unsafe { std::ffi::CStr::from_ptr(u.sysname.as_ptr()) }.to_string_lossy().into_owned();
    if sysname == "Linux" {
        let (found, iptables) = get_binary_path(iptables_tmp);
        if !found {
            let e = std::io::Error::last_os_error();
            write_debug_file(&argv0, format!("The iptables file '{iptables}' is not accessible: {e} ({})", e.raw_os_error().unwrap_or(0)).as_bytes());
            return 0;
        }
        let arg = if action == Action::Add { "-I" } else { "-D" };
        if !lock(LOCK_PATH, LOCK_FILE, &argv0, basename(&argv0)) {
            write_debug_file(&argv0, b"Unable to take lock. End.");
            return -1;
        }
        for chain in ["INPUT", "FORWARD"] {
            let mut count = 0;
            loop {
                if run(&iptables, &[arg, chain, "-s", &srcip, "-j", "DROP"]) {
                    break;
                }
                count += 1;
                if count > 4 {
                    write_debug_file(&argv0, b"Unable to run iptables");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(count));
            }
        }
        unlock(LOCK_PATH, &argv0);
    } else {
        write_debug_file(&argv0, b"Invalid system");
    }
    write_debug_file(&argv0, b"Ended");
    0
}
