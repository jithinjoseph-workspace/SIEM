//! EDR live response (not in Wazuh): answers one investigation request from the console.
//! extra_args: `id=<request id>`, `action=processes|connections|services|dir|file`,
//! `path=<full path>` for `dir` and `file`. Read-only: it lists and reads, never changes
//! anything. The answer goes to active-responses.log in chunks (`live::result_lines`).

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

use siem_active_response::{edr::*, live, *};

fn main() {
    #[cfg(windows)]
    {
        // This must be always the first instruction
        dll_verify::enable_dll_verification(&std::sync::Arc::new(siem_log::WLog::new("unset", std::path::Path::new("."))));
        // investigation is background work: the user's programs come first
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS};
        unsafe { SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) };
    }
    std::process::exit(run_main());
}

fn run_main() -> i32 {
    let argv0 = argv0();
    let Some((action, input)) = setup_and_check_message(&argv0) else { return -1 };
    if action != Action::Add {
        write_debug_file(&argv0, b"Ended");
        return 0;
    }
    let id = extra_arg(&input, "id").unwrap_or_default();
    let kind = extra_arg(&input, "action").unwrap_or_default();
    if !live::valid_id(&id) {
        write_debug_file(&argv0, live::failed_line("", &kind, "A request id (id=<hex>) is required").as_bytes());
        write_debug_file(&argv0, b"Ended");
        return -1;
    }
    let path = extra_arg(&input, "path").map(|p| p.trim().to_string()).unwrap_or_default();
    let full_path = || match live::path_refusal(&path) {
        Some(why) => Err(why),
        None => Ok(std::path::PathBuf::from(&path)),
    };
    // (payload, more members for the "done" line)
    let r: Result<(Vec<u8>, String), String> = match kind.as_str() {
        "processes" => inventory(Inventory::Processes),
        "connections" => inventory(Inventory::Connections),
        "services" => inventory(Inventory::Services),
        "dir" => full_path().and_then(|p| live::dir_listing(&p)).map(|d| (d, format!(",\"path\":{}", json_str(&path)))),
        "file" => full_path().and_then(|p| live::read_file(&p)).map(|(d, sha)| (d, format!(",\"path\":{},\"file_sha256\":\"{sha}\"", json_str(&path)))),
        _ => Err("Unknown action: processes, connections, services, dir or file".into()),
    };
    let lines = match &r {
        Ok((payload, extra)) => live::result_lines(&id, &kind, payload, extra),
        Err(e) => vec![live::failed_line(&id, &kind, e)],
    };
    for l in &lines {
        write_debug_file(&argv0, l.as_bytes());
    }
    write_debug_file(&argv0, b"Ended");
    if r.is_ok() { 0 } else { -1 }
}

enum Inventory {
    Processes,
    Connections,
    Services,
}

/// The syscollector's own view (siem-sysinfo), as JSON.
#[cfg(windows)]
fn inventory(what: Inventory) -> Result<(Vec<u8>, String), String> {
    let s = siem_sysinfo::SysInfo;
    let v = match what {
        Inventory::Processes => s.processes(),
        Inventory::Connections => s.ports(),
        Inventory::Services => s.services(),
    }
    .map_err(|e| e.to_string())?;
    v.dump().map(|b| (b, String::new())).map_err(|e| String::from_utf8_lossy(&e).into_owned())
}

#[cfg(not(windows))]
fn inventory(_: Inventory) -> Result<(Vec<u8>, String), String> {
    Err("Live response lists processes, connections and services on Windows agents".into())
}
