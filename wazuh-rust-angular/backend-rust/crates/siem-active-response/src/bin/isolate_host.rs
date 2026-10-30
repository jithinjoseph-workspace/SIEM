//! EDR response (not in Wazuh): network isolation of the endpoint with Windows
//! Firewall block rules (`edr::isolation_rules`) that leave only the manager.
//! extra_args: `id=<isolation id>`, `allow=<manager IPv4>[,...]`; `release` lifts it.
//! With a timeout, execd runs it again with "delete" when the time is up: that lifts
//! the isolation only when it is still the same one (`id`), not a newer one.

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

#[cfg(windows)]
use siem_active_response::{edr::*, *};

/// The isolation in force: `id=<id>` and the firewall profiles it turned on (`restore_off=`).
#[cfg(windows)]
const STATE_FILE: &str = "active-response\\isolation.state";
#[cfg(windows)]
const PROFILES: [&str; 3] = ["domainprofile", "privateprofile", "publicprofile"];

fn main() {
    #[cfg(windows)]
    std::process::exit(win_main());
    #[cfg(not(windows))]
    std::process::exit(-1);
}

#[cfg(windows)]
fn win_main() -> i32 {
    // This must be always the first instruction
    dll_verify::enable_dll_verification(&std::sync::Arc::new(siem_log::WLog::new("unset", std::path::Path::new("."))));
    let argv0 = argv0();
    let Some((action, input)) = setup_and_check_message(&argv0) else { return -1 };
    let (netsh_found, netsh) = get_binary_path("netsh.exe");
    if !netsh_found {
        write_debug_file(&argv0, format!("Binary '{netsh}' not found in default paths, the full path will not be used.").as_bytes());
    }
    let id = extra_arg(&input, "id").unwrap_or_default();
    let r = if has_extra_flag(&input, "release") {
        release(&netsh).map(|_| "Host isolation released".to_string())
    } else if action == Action::Delete {
        // the timeout of `id`: only when no newer isolation replaced it
        match state().0 {
            Some(cur) if cur == id => release(&netsh).map(|_| "Host isolation expired and released".to_string()),
            _ => Ok(format!("Isolation {id} was already released or replaced")),
        }
    } else {
        let allow: Vec<std::net::Ipv4Addr> = extra_arg(&input, "allow").unwrap_or_default().split(',').filter_map(|a| a.trim().parse().ok()).collect();
        if id.is_empty() {
            Err("An isolation id (id=<id>) is required".to_string())
        } else if allow.is_empty() {
            // never cut the host off from the manager: it would not hear the release
            Err("No manager address (allow=<IPv4>) to keep reachable; not isolated".to_string())
        } else {
            if let Err(code) = check_keys(&argv0, &id) {
                return code;
            }
            isolate(&netsh, &allow, &id).map(|allow| format!("Host isolated; only {allow} reachable"))
        }
    };
    let m = match &r {
        Ok(m) => format!("{{\"message\":{},\"id\":{},\"status\":\"success\",\"script\":\"isolate-host\"}}", json_str(m), json_str(&id)),
        Err(e) => format!("{{\"message\":{},\"id\":{},\"status\":\"failed\",\"script\":\"isolate-host\"}}", json_str(e), json_str(&id)),
    };
    write_debug_file(&argv0, m.as_bytes());
    write_debug_file(&argv0, b"Ended");
    if r.is_ok() { 0 } else { -1 }
}

/// (the isolation id, the profiles to turn off again on release)
#[cfg(windows)]
fn state() -> (Option<String>, Vec<String>) {
    let t = std::fs::read_to_string(STATE_FILE).unwrap_or_default();
    let get = |k: &str| t.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string()));
    let off = get("restore_off=").map(|v| v.split(',').filter(|p| PROFILES.contains(p)).map(String::from).collect()).unwrap_or_default();
    (get("id=").filter(|v| !v.is_empty()), off)
}

/// The profiles that are off now, from the registry (any Windows language), as netsh.c reads them.
#[cfg(windows)]
fn profiles_off() -> Vec<String> {
    const REG: &str = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\";
    let (_, reg) = get_binary_path("reg.exe");
    // netsh's profile names and their registry keys
    [("domainprofile", "DomainProfile"), ("privateprofile", "StandardProfile"), ("publicprofile", "PublicProfile")]
        .iter()
        .filter(|(_, key)| {
            run_output(&reg, &["query", &format!("{REG}{key}"), "/v", "EnableFirewall"]).is_some_and(|o| firewall_enabled(&String::from_utf8_lossy(&o)) == Some(false))
        })
        .map(|(p, _)| p.to_string())
        .collect()
}

/// The manager addresses kept reachable.
#[cfg(windows)]
fn isolate(netsh: &str, allow: &[std::net::Ipv4Addr], id: &str) -> Result<String, String> {
    let (_, mut restore_off) = state();
    for p in profiles_off() {
        if !restore_off.contains(&p) {
            restore_off.push(p);
        }
    }
    // block rules only act with the firewall on
    if !run(netsh, &["advfirewall", "set", "allprofiles", "state", "on"]) {
        return Err("Unable to turn the Windows firewall on; not isolated".into());
    }
    // an isolation in force is replaced, not stacked
    let name = format!("name=\"{ISOLATION_RULE}\"");
    run(netsh, &["advfirewall", "firewall", "delete", "rule", &name]);
    std::fs::write(STATE_FILE, format!("id={id}\nrestore_off={}\n", restore_off.join(","))).map_err(|e| format!("{STATE_FILE}: {e}"))?;
    for rule in isolation_rules(allow) {
        let args: Vec<&str> = rule.iter().map(|s| s.as_str()).collect();
        if !run(netsh, &args) {
            // half an isolation is worse than none: undo
            let _ = release(netsh);
            return Err(format!("Unable to add the firewall rule ({}); isolation undone", rule[5..].join(" ")));
        }
    }
    Ok(allow.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "))
}

#[cfg(windows)]
fn release(netsh: &str) -> Result<(), String> {
    let name = format!("name=\"{ISOLATION_RULE}\"");
    // "No rules match" when nothing is isolated: not an error
    run(netsh, &["advfirewall", "firewall", "delete", "rule", &name]);
    let (_, off) = state();
    for p in &off {
        run(netsh, &["advfirewall", "set", p, "state", "off"]);
    }
    let _ = std::fs::remove_file(STATE_FILE);
    Ok(())
}
