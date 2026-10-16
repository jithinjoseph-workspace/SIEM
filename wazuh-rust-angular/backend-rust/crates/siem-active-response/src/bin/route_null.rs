//! `src/active-response/route-null.c` (Windows): blocks an IP with a route
//! to the default gateway (`route -p ADD <ip> MASK 255.255.255.255 <gw>`).

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

#[cfg(windows)]
use siem_active_response::*;

fn main() {
    #[cfg(windows)]
    std::process::exit(win_main());
    #[cfg(not(windows))]
    std::process::exit(-1);
}

/// `IPSIZE` (`INET6_ADDRSTRLEN`, 65 with mingw): the gateway buffer holds 65 bytes.
#[cfg(windows)]
const IPSIZE: usize = 65;

#[cfg(windows)]
fn win_main() -> i32 {
    // This must be always the first instruction
    dll_verify::enable_dll_verification(&std::sync::Arc::new(siem_log::WLog::new("unset", std::path::Path::new("."))));
    let argv0 = argv0();
    let Some((action, input)) = setup_and_check_message(&argv0) else { return -1 };
    let Some(srcip) = get_srcip_from_json(&input) else {
        write_debug_file(&argv0, b"Cannot read 'srcip' from data");
        return -1;
    };
    if action == Action::Add {
        if let Err(code) = check_keys(&argv0, &srcip) {
            return code;
        }
    }
    let (found, route) = get_binary_path("route.exe");
    if !found {
        write_debug_file(&argv0, format!("Binary '{route}' not found in default paths, the full path will not be used.").as_bytes());
    }
    if action == Action::Add {
        let regex = ".*Default Gateway.*[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*";
        let tmp_file = "default-gateway.txt";
        // system(): cmd.exe expands %WINDIR% and runs the pipe
        let cmd = format!("%WINDIR%\\system32\\ipconfig.exe | %WINDIR%\\system32\\findstr.exe /R /C:\"{regex}\" > {tmp_file}");
        let _ = system(&cmd);
        let mut gateway = Vec::new();
        if let Ok(data) = std::fs::read(tmp_file) {
            // text-mode fgets: "\r\n" reads as "\n"; the last matching line wins
            for line in data.split_inclusive(|&c| c == b'\n') {
                let line = if line.ends_with(b"\r\n") { [&line[..line.len() - 2], b"\n"].concat() } else { line.to_vec() };
                if let Some(p) = line.iter().position(|&c| c == b':') {
                    // snprintf(gateway, IPSIZE + 1, "%s", ptr + 2): the newline stays
                    let mut g = line.get(p + 2..).unwrap_or_default().to_vec();
                    g.truncate(IPSIZE);
                    gateway = g;
                }
            }
        }
        let _ = std::fs::remove_file(tmp_file);
        if gateway.is_empty() {
            write_debug_file(&argv0, b"Couldn't get default gateway");
            return -1;
        }
        let gw = String::from_utf8_lossy(&gateway).into_owned();
        if !run(&route, &["-p", "ADD", &srcip, "MASK", "255.255.255.255", &gw]) {
            write_debug_file(&argv0, format!("Unable to run {route}, action: 'ADD'").as_bytes());
        }
    } else if !run(&route, &["DELETE", &srcip]) {
        write_debug_file(&argv0, format!("Unable to run {route}, action: 'DELETE'").as_bytes());
    }
    write_debug_file(&argv0, b"Ended");
    0
}

/// `system(cmd)`: `cmd.exe /c <cmd>`.
#[cfg(windows)]
fn system(cmd: &str) -> i32 {
    use std::os::windows::process::CommandExt;
    let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into());
    std::process::Command::new(comspec).raw_arg(format!("/c {cmd}")).status().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
}
