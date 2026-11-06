//! Blocks (add) or unblocks (delete) the alert's attacker IPv4 address with a persistent
//! host route to the default gateway. Windows only.

#[cfg(windows)]
use siem_active_response::*;

fn main() {
    #[cfg(windows)]
    {
        dll_guard::enable();
        std::process::exit(win_main());
    }
    #[cfg(not(windows))]
    std::process::exit(-1);
}

/// The gateway of a `0.0.0.0` destination in `route print 0.0.0.0` output (the first one).
#[cfg_attr(not(windows), allow(dead_code))]
fn default_gateway(route_print: &str) -> Option<String> {
    route_print.lines().find_map(|l| {
        let t: Vec<&str> = l.split_whitespace().collect();
        (t.len() >= 3 && t[0] == "0.0.0.0" && t[1] == "0.0.0.0" && t[2].parse::<std::net::Ipv4Addr>().is_ok()).then(|| t[2].to_string())
    })
}

#[cfg(windows)]
fn win_main() -> i32 {
    let argv0 = argv0();
    let Some((action, msg)) = setup_and_check_message(&argv0) else { return -1 };
    let Some(ip) = alert_ip(&msg) else {
        write_debug_file(&argv0, b"Cannot read a valid attacker IP from the alert");
        return -1;
    };
    // a 255.255.255.255 host route only exists for IPv4
    if ip_version(&ip) != Some(4) {
        write_debug_file(&argv0, format!("route-null blocks IPv4 addresses only, not {ip}").as_bytes());
        return -1;
    }
    if action == Action::Add {
        if let Err(code) = check_keys(&argv0, &ip) {
            return code;
        }
    }
    let (found, route) = get_binary_path("route.exe");
    if !found {
        write_debug_file(&argv0, format!("Binary '{route}' not found in the PATH").as_bytes());
    }
    if action == Action::Add {
        match run_output(&route, &["print", "0.0.0.0"]).and_then(|o| default_gateway(&String::from_utf8_lossy(&o))) {
            None => write_debug_file(&argv0, b"Unable to find the default gateway"),
            Some(gw) => {
                if !run(&route, &["-p", "ADD", &ip, "MASK", "255.255.255.255", &gw]) {
                    write_debug_file(&argv0, b"Unable to run route.exe to add the route");
                }
            }
        }
    } else if !run(&route, &["DELETE", &ip]) {
        write_debug_file(&argv0, b"Unable to run route.exe to delete the route");
    }
    write_debug_file(&argv0, b"Ended");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_from_the_route_table() {
        let out = "===========================================================================\r\nIPv4 Route Table\r\n===========================================================================\r\nActive Routes:\r\nNetwork Destination        Netmask          Gateway       Interface  Metric\r\n          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.20     25\r\n          0.0.0.0          0.0.0.0         10.0.0.1       10.0.0.9      50\r\n";
        assert_eq!(default_gateway(out).as_deref(), Some("192.168.1.1"));
        assert_eq!(default_gateway("          0.0.0.0          0.0.0.0         On-link     10.0.0.9   50"), None);
        assert_eq!(default_gateway("Persistent Routes:\r\n  None\r\n"), None);
    }
}
