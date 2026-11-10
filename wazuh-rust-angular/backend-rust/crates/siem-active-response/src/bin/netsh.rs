//! Blocks (add) or unblocks (delete) the alert's attacker IP with two Windows Firewall
//! rules, inbound and outbound. Windows only.

#[cfg(windows)]
use siem_active_response::{edr::firewall_enabled, *};

#[cfg(windows)]
const RULE: &str = "PROVIGIL ACTIVE RESPONSE BLOCKED IP";
/// the rule name of blocks made before ProVigil's own version
#[cfg(windows)]
const OLD_RULE: &str = "WAZUH ACTIVE RESPONSE BLOCKED IP";

fn main() {
    #[cfg(windows)]
    {
        dll_guard::enable();
        std::process::exit(win_main());
    }
    #[cfg(not(windows))]
    std::process::exit(-1);
}

/// Logs each firewall profile that is off: a block has no effect there.
#[cfg(windows)]
fn warn_profiles_off(argv0: &str) {
    const REG: &str = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\";
    let (_, reg) = get_binary_path("reg.exe");
    for (name, key) in [("Domain", "DomainProfile"), ("Private", "StandardProfile"), ("Public", "PublicProfile")] {
        let out = run_output(&reg, &["query", &format!("{REG}{key}"), "/v", "EnableFirewall"]);
        if out.is_some_and(|o| firewall_enabled(&String::from_utf8_lossy(&o)) == Some(false)) {
            write_debug_file(argv0, format!("Warning: the Windows firewall {name} profile is off; the block has no effect there").as_bytes());
        }
    }
}

#[cfg(windows)]
fn win_main() -> i32 {
    let argv0 = argv0();
    let Some((action, msg)) = setup_and_check_message(&argv0) else { return -1 };
    let Some(ip) = alert_ip(&msg) else {
        write_debug_file(&argv0, b"Cannot read a valid attacker IP from the alert");
        return -1;
    };
    if action == Action::Add {
        if let Err(code) = check_keys(&argv0, &ip) {
            return code;
        }
    }
    let (found, netsh) = get_binary_path("netsh.exe");
    if !found {
        write_debug_file(&argv0, format!("Binary '{netsh}' not found in the PATH").as_bytes());
    }
    let remote = format!("remoteip={ip}/{}", if ip_version(&ip) == Some(6) { 128 } else { 32 });
    if action == Action::Add {
        warn_profiles_off(&argv0);
        let name = format!("name=\"{RULE}\"");
        for dir in ["dir=in", "dir=out"] {
            if !run(&netsh, &["advfirewall", "firewall", "add", "rule", &name, "interface=any", dir, "action=block", &remote]) {
                write_debug_file(&argv0, format!("Unable to run netsh to add the {dir} rule").as_bytes());
            }
        }
    } else {
        for rule in [RULE, OLD_RULE] {
            if !run(&netsh, &["advfirewall", "firewall", "delete", "rule", &format!("name=\"{rule}\""), &remote]) {
                write_debug_file(&argv0, b"Unable to run netsh to delete the rules");
            }
        }
    }
    write_debug_file(&argv0, b"Ended");
    0
}
