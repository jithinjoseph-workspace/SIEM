//! EDR live response: answers one investigation request from the console.
//! extra_args: `id=<request id>`, `action=processes|connections|services|dir|file`,
//! `path=<full path>` for `dir` and `file`. Read-only: it lists and reads, never changes
//! anything. The answer goes to active-responses.log in chunks (`live::result_lines`).

use siem_active_response::{edr::*, live, *};

fn main() {
    #[cfg(windows)]
    {
        // This must be always the first instruction
        dll_guard::enable();
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

/// The agent's collectors (`provigil-collect`), as the JSON array the console's live response
/// table reads (its column keys, `LR_COLUMNS` in the agents page).
#[cfg(windows)]
fn inventory(what: Inventory) -> Result<(Vec<u8>, String), String> {
    use provigil_collect::win;
    use serde_json::json;
    let rows: Vec<serde_json::Value> = match what {
        Inventory::Processes => win::processes()?
            .into_iter()
            .map(|p| json!({ "pid": p.pid, "ppid": p.parent_pid, "name": p.name, "cmd": p.command_line }))
            .collect(),
        Inventory::Connections => {
            // every connection, not only listeners; the owner's name when the process list has it
            let names: std::collections::HashMap<u32, String> = win::processes().unwrap_or_default().into_iter().map(|p| (p.pid, p.name)).collect();
            win::ports()?
                .into_iter()
                .map(|c| {
                    let process = c.process.or_else(|| names.get(&c.pid).cloned());
                    json!({ "protocol": c.protocol, "local_ip": c.local_ip, "local_port": c.local_port, "remote_ip": c.remote_ip, "remote_port": c.remote_port, "state": c.state, "pid": c.pid, "process": process })
                })
                .collect()
        }
        Inventory::Services => win::services()?
            .into_iter()
            .map(|s| json!({ "name": s.name, "display_name": s.display_name, "status": s.state, "start_type": s.startup_type, "path": s.path }))
            .collect(),
    };
    serde_json::to_vec(&rows).map(|b| (b, String::new())).map_err(|e| e.to_string())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Each list is a JSON array whose rows carry every key the console's table reads.
    #[test]
    fn lists_have_the_console_shape() {
        for (what, keys) in [
            (Inventory::Processes, &["pid", "ppid", "name", "cmd"][..]),
            (Inventory::Connections, &["protocol", "local_ip", "local_port", "remote_ip", "remote_port", "state", "pid", "process"][..]),
            (Inventory::Services, &["name", "display_name", "status", "start_type", "path"][..]),
        ] {
            let (payload, extra) = inventory(what).unwrap();
            assert!(extra.is_empty());
            let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            let rows = v.as_array().expect("a JSON array");
            assert!(!rows.is_empty(), "{keys:?}: no rows");
            for r in rows {
                for k in keys {
                    assert!(r.get(k).is_some(), "{k} missing in {r}");
                }
            }
            // the agent's own process shows up, with its parent
            if keys[1] == "ppid" {
                assert!(rows.iter().any(|r| r["pid"] == std::process::id() && r["ppid"].as_u64().unwrap() > 0));
            }
        }
    }
}

#[cfg(not(windows))]
fn inventory(_: Inventory) -> Result<(Vec<u8>, String), String> {
    Err("Live response lists processes, connections and services on Windows agents".into())
}
