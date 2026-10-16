//! `src/active-response/netsh.c`: blocks an IP in the Windows firewall
//! (`netsh advfirewall`), warning when a firewall profile is off.

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

#[cfg(windows)]
use siem_active_response::*;

#[cfg(windows)]
const RULE_NAME: &str = "WAZUH ACTIVE RESPONSE BLOCKED IP";
#[cfg(windows)]
const PATH_FIREWALL_PROFILES_REG_DEFAULT: &str = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\";

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
    let Some(srcip) = get_srcip_from_json(&input) else {
        write_debug_file(&argv0, b"Cannot read 'srcip' from data");
        return -1;
    };
    if action == Action::Add {
        if let Err(code) = check_keys(&argv0, &srcip) {
            return code;
        }
    }
    let name = format!("name=\"{RULE_NAME}\"");
    let remoteip = format!("remoteip={srcip}/32");
    let (found, netsh) = get_binary_path("netsh.exe");
    if !found {
        write_debug_file(&argv0, format!("Binary '{netsh}' not found in default paths, the full path will not be used.").as_bytes());
    }
    if action == Action::Add && !all_profiles_status(&argv0) {
        return -1;
    }
    // checkVista(): every Windows this program runs on is Vista or later
    if action == Action::Add {
        for dir in ["dir=in", "dir=out"] {
            if !run(&netsh, &["advfirewall", "firewall", "add", "rule", &name, "interface=any", dir, "action=block", &remoteip]) {
                let d = if dir == "dir=in" { "ADD dir=in" } else { "ADD dir=out" };
                write_debug_file(&argv0, format!("Unable to run netsh, action: '{d}', rule: '{RULE_NAME}'").as_bytes());
            }
        }
    } else if !run(&netsh, &["advfirewall", "firewall", "delete", "rule", &name, &remoteip]) {
        write_debug_file(&argv0, format!("Unable to run netsh, action: 'DELETE', rule: '{RULE_NAME}'").as_bytes());
    }
    write_debug_file(&argv0, b"Ended");
    0
}

/// `getAllProfilesStatus`: logs which profiles are off when one is; false
/// when reg.exe cannot run.
#[cfg(windows)]
fn all_profiles_status(argv0: &str) -> bool {
    const PROFILES_REG: [&str; 3] = ["DomainProfile", "StandardProfile", "PublicProfile"];
    const PROFILE_STR: [&str; 4] = ["FIREWALL_DOMAIN", "FIREWALL_PRIVATE", "FIREWALL_PUBLIC", "FIREWALL_DEFAULT"];
    let (found, reg) = get_binary_path("reg.exe");
    if !found {
        write_debug_file(argv0, format!("Binary '{reg}' not found in default paths, the full path will not be used.").as_bytes());
    }
    let mut global = true;
    let mut aux2 = String::new();
    let mut lengths = [0usize; 3];
    let mut count_active: i32 = 0;
    // firewallData: isThereProfile, isEnabled, profile
    let (mut there, mut profile) = (false, 0usize);
    for (i, p) in PROFILES_REG.iter().enumerate() {
        let path = format!("{PATH_FIREWALL_PROFILES_REG_DEFAULT}{p}");
        let Some(out) = run_output(&reg, &["query", &path, "/v", "EnableFirewall"]) else {
            let e = std::io::Error::last_os_error();
            write_debug_file(argv0, format!("Error executing '{reg}' : {e}").as_bytes());
            return false;
        };
        for line in String::from_utf8_lossy(&out).split_inclusive('\n') {
            if !there {
                // getFirewallProfile
                if let Some(pos) = line.find("FirewallPolicy") {
                    let after = line[pos..].split_once('\\').map(|(_, a)| a).unwrap_or("");
                    if after.contains("DomainProfile") {
                        (profile, there) = (0, true);
                    } else if after.contains("PublicProfile") {
                        (profile, there) = (2, true);
                    } else if after.contains("StandardProfile") {
                        (profile, there) = (1, true);
                    } else {
                        there = false;
                    }
                }
            } else {
                count_active += 1;
                // getStatusFirewallProfile: isEnabledFromPattern(line, "REG_DWORD", "0x1")
                let enabled = line.find("REG_DWORD").is_some_and(|p| {
                    let mut t = line[p..].split_whitespace();
                    t.next();
                    t.next().is_some_and(|v| v.chars().take(3).collect::<String>() == "0x1")
                });
                let m = format!("\"profile{}\":\"{}\",\"status{}\":\"{}\" ", i + 1, PROFILE_STR[profile], i + 1, if enabled { "active" } else { "inactive" });
                global &= enabled;
                lengths[i] = m.len();
                aux2.push_str(&m);
                there = false;
            }
        }
    }
    // the separators between the profiles' entries
    let mut b = aux2.into_bytes();
    let (mut next, mut commas) = (0usize, 0);
    for len in &lengths[..2] {
        next += len;
        if next > 0 && (commas as i32) < count_active - 1 && next <= b.len() {
            b[next - 1] = b',';
            commas += 1;
        }
    }
    if !global {
        let mut m = b"{\"message\":\"Active response may not have an effect\",\"firewall\":{".to_vec();
        m.extend_from_slice(&b);
        m.extend_from_slice(b"},\"status\":\"inactive\",\"script\":\"netsh\"}");
        write_debug_file(argv0, &m);
    }
    true
}
