//! `src/active-response/restart-wazuh.c`: restarts the agent
//! (`wazuh-control restart` on Unix, `net stop/start Wazuh` on Windows).

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

use siem_active_response::*;

fn main() {
    #[cfg(windows)]
    // This must be always the first instruction
    dll_verify::enable_dll_verification(&std::sync::Arc::new(siem_log::WLog::new("unset", std::path::Path::new("."))));
    let argv0 = argv0();
    if setup_and_check_message(&argv0).is_none() {
        std::process::exit(-1);
    }
    #[cfg(unix)]
    {
        let exec = "bin/wazuh-control";
        match std::process::Command::new(exec).arg("restart").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() {
            Ok(mut c) => {
                let _ = c.wait();
            }
            Err(e) => {
                write_debug_file(&argv0, format!("Error executing '{exec}': {e}").as_bytes());
                std::process::exit(-1);
            }
        }
    }
    #[cfg(windows)]
    {
        // system(): cmd.exe expands %WINDIR%
        for verb in ["stop", "start"] {
            let _ = std::process::Command::new("cmd").args(["/C", &format!("%WINDIR%\\system32\\net.exe {verb} Wazuh")]).status();
        }
    }
    write_debug_file(&argv0, b"Ended");
}
