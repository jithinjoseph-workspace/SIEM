//! The endpoint responses the console adds to Wazuh's (not in Wazuh 4.14.7):
//! kill-process, quarantine-file and isolate-host. What they may touch is
//! decided here, apart from the Windows calls, so it is tested on any OS.

use std::net::Ipv4Addr;

use siem_cjson::Json;

/// One `extra_args` item `key=value` (whole, spaces included: a path can hold them).
pub fn extra_arg(input: &Json, key: &str) -> Option<String> {
    let args = input.get("parameters")?.get("extra_args").filter(|a| a.is_array())?;
    let prefix = format!("{key}=");
    args.children().into_iter().find_map(|a| a.as_str().and_then(|s| s.strip_prefix(prefix.as_str()).map(String::from)))
}

/// Whether `extra_args` holds the bare item `flag`.
pub fn has_extra_flag(input: &Json, flag: &str) -> bool {
    let Some(args) = input.get("parameters").and_then(|p| p.get("extra_args")).filter(|a| a.is_array()) else { return false };
    args.children().into_iter().any(|a| a.as_str().is_some_and(|s| *s == *flag))
}

/// A JSON string literal (for the result lines the programs log).
pub fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn norm(p: &str) -> String {
    p.trim().replace('/', "\\").to_lowercase()
}

/// Windows processes whose end crashes or locks the machine (when they run from System32).
const CRITICAL: [&str; 8] = ["smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe"];

/// Why the process must not be killed; None when it may be.
pub fn kill_refusal(pid: u32, image: &str, system_root: &str) -> Option<String> {
    if pid <= 4 {
        return Some(format!("PID {pid} is the system itself"));
    }
    let image = norm(image);
    let (dir, name) = image.rsplit_once('\\').unwrap_or(("", image.as_str()));
    if name == "wazuh-agent.exe" {
        return Some("it is the agent itself".into());
    }
    // a copy elsewhere (an svchost.exe in Temp) is fair game: masquerading malware
    if CRITICAL.contains(&name) && dir == format!("{}\\system32", norm(system_root).trim_end_matches('\\')) {
        return Some(format!("{name} is a critical Windows process"));
    }
    None
}

/// Why the file must not be quarantined; None when it may be.
pub fn quarantine_refusal(path: &str, system_root: &str, agent_home: &str) -> Option<String> {
    let p = norm(path);
    let b = p.as_bytes();
    if !(b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
        return Some("a full path (C:\\...) is required".into());
    }
    if p.split('\\').any(|c| c == ".." || c == ".") {
        return Some("the path has relative parts".into());
    }
    let root = format!("{}\\", norm(system_root).trim_end_matches('\\'));
    if p.starts_with(&root) && !p.starts_with(&format!("{root}temp\\")) {
        return Some("it is inside the Windows directory".into());
    }
    let home = format!("{}\\", norm(agent_home).trim_end_matches('\\'));
    if p.starts_with(&home) {
        return Some("it is one of the agent's own files".into());
    }
    None
}

fn range(a: u32, b: u32) -> String {
    if a == b { Ipv4Addr::from(a).to_string() } else { format!("{}-{}", Ipv4Addr::from(a), Ipv4Addr::from(b)) }
}

/// The IPv4 ranges an isolated host may not reach: all but `allow` (the manager) and loopback.
pub fn isolation_ranges(allow: &[Ipv4Addr]) -> Vec<String> {
    let mut keep: Vec<(u32, u32)> = allow.iter().map(|a| (u32::from(*a), u32::from(*a))).collect();
    keep.push((0x7f00_0000, 0x7fff_ffff));
    keep.sort();
    let mut out = Vec::new();
    let mut next: u64 = 0;
    for (a, b) in keep {
        if a as u64 > next {
            out.push(range(next as u32, a - 1));
        }
        next = next.max(b as u64 + 1);
    }
    if next <= u32::MAX as u64 {
        out.push(range(next as u32, u32::MAX));
    }
    out
}

pub const ISOLATION_RULE: &str = "PROVIGIL EDR HOST ISOLATION";

/// The `netsh advfirewall firewall add rule` arguments of an isolation, both directions:
/// TCP, UDP but DHCP, ICMP, for IPv4 (but `allow`) and IPv6 (but ::1). A block rule
/// wins over every allow rule, so the host keeps only the manager (and an address lease).
pub fn isolation_rules(allow: &[Ipv4Addr]) -> Vec<Vec<String>> {
    let v4 = isolation_ranges(allow).join(",");
    let v6 = "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string();
    let sets = [
        (v4.clone(), "TCP", None),
        (v4.clone(), "UDP", Some("1-66,69-65535")),
        (v4, "ICMPv4", None),
        (v6.clone(), "TCP", None),
        (v6.clone(), "UDP", Some("1-545,548-65535")),
        (v6, "ICMPv6", None),
    ];
    let mut rules = Vec::new();
    for dir in ["in", "out"] {
        for (ips, proto, ports) in &sets {
            let mut r: Vec<String> = ["advfirewall", "firewall", "add", "rule"].map(String::from).to_vec();
            r.push(format!("name=\"{ISOLATION_RULE}\""));
            r.push(format!("dir={dir}"));
            r.push("action=block".into());
            r.push(format!("protocol={proto}"));
            r.push(format!("remoteip={ips}"));
            if let Some(p) = ports {
                r.push(format!("remoteport={p}"));
            }
            rules.push(r);
        }
    }
    rules
}

/// The quarantine record (`quarantine\<id>.json`).
pub fn quarantine_record(id: &str, path: &str, sha256: &str, size: u64, at: &str) -> String {
    format!(
        "{{\"id\":{},\"path\":{},\"sha256\":{},\"size\":{size},\"quarantined_at\":{}}}",
        json_str(id),
        json_str(path),
        json_str(sha256),
        json_str(at)
    )
}

/// `reg query ...\FirewallPolicy\<profile> /v EnableFirewall`: whether the profile is on
/// (None: no value). The registry, unlike `netsh ... show state`, reads the same in every language.
pub fn firewall_enabled(reg_output: &str) -> Option<bool> {
    reg_output.lines().find_map(|l| {
        let mut t = l.split_whitespace();
        (t.next()? == "EnableFirewall" && t.next()? == "REG_DWORD").then(|| t.next().map(|v| v != "0x0"))?
    })
}

/// A quarantine id is ours (a file name in `quarantine\`, never a path).
pub fn valid_quarantine_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(args: &str) -> Json {
        let m = format!(r#"{{"version":1,"origin":{{}},"command":"add","parameters":{{"extra_args":{args}}}}}"#);
        siem_cjson::parse_with_opts(m.as_bytes(), false).unwrap().0
    }

    #[test]
    fn extra_args_keep_spaces() {
        let j = msg(r#"["path=C:\\Program Files\\x y.exe","release","pid=42"]"#);
        assert_eq!(extra_arg(&j, "path").as_deref(), Some(r"C:\Program Files\x y.exe"));
        assert_eq!(extra_arg(&j, "pid").as_deref(), Some("42"));
        assert_eq!(extra_arg(&j, "id"), None);
        assert!(has_extra_flag(&j, "release") && !has_extra_flag(&j, "pid"));
    }

    #[test]
    fn kill_spares_the_system_and_the_agent() {
        let root = r"C:\Windows";
        assert!(kill_refusal(4, r"C:\x.exe", root).is_some());
        assert!(kill_refusal(900, r"C:\Windows\System32\lsass.exe", root).is_some());
        assert!(kill_refusal(900, r"c:\windows\system32\SVCHOST.EXE", root).is_some());
        assert!(kill_refusal(900, r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe", root).is_some());
        // the masquerading copy is killed
        assert!(kill_refusal(900, r"C:\Users\a\AppData\Local\Temp\svchost.exe", root).is_none());
        assert!(kill_refusal(900, r"C:\Users\a\Downloads\mimikatz.exe", root).is_none());
    }

    #[test]
    fn quarantine_spares_windows_and_the_agent() {
        let (root, home) = (r"C:\Windows", r"C:\Program Files (x86)\ossec-agent");
        assert!(quarantine_refusal(r"C:\Windows\System32\kernel32.dll", root, home).is_some());
        assert!(quarantine_refusal(r"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe", root, home).is_some());
        assert!(quarantine_refusal(r"evil.exe", root, home).is_some());
        assert!(quarantine_refusal(r"C:\Users\a\..\..\Windows\System32\x.dll", root, home).is_some());
        assert!(quarantine_refusal(r"C:\Windows\Temp\dropper.exe", root, home).is_none());
        assert!(quarantine_refusal(r"C:\Users\a\Downloads\invoice.pdf.exe", root, home).is_none());
        assert!(valid_quarantine_id("20261027120000123-4242") && !valid_quarantine_id(r"..\x") && !valid_quarantine_id(""));
    }

    #[test]
    fn firewall_state_from_the_registry() {
        let out = |v: &str| format!("\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\...\\PublicProfile\r\n    EnableFirewall    REG_DWORD    {v}\r\n\r\n");
        assert_eq!(firewall_enabled(&out("0x1")), Some(true));
        assert_eq!(firewall_enabled(&out("0x0")), Some(false));
        assert_eq!(firewall_enabled("ERROR: The system was unable to find the specified registry key or value."), None);
    }

    #[test]
    fn isolation_keeps_only_the_manager() {
        let m: Ipv4Addr = "192.168.1.10".parse().unwrap();
        assert_eq!(isolation_ranges(&[m]), ["0.0.0.0-126.255.255.255", "128.0.0.0-192.168.1.9", "192.168.1.11-255.255.255.255"]);
        // the manager on this host, or at the ends of the space
        assert_eq!(isolation_ranges(&["127.0.0.1".parse().unwrap()]), ["0.0.0.0-126.255.255.255", "128.0.0.0-255.255.255.255"]);
        assert_eq!(isolation_ranges(&["0.0.0.0".parse().unwrap(), "255.255.255.255".parse().unwrap()]), ["0.0.0.1-126.255.255.255", "128.0.0.0-255.255.255.254"]);
        let rules = isolation_rules(&[m]);
        assert_eq!(rules.len(), 12);
        assert!(rules.iter().all(|r| r.contains(&"action=block".to_string()) && r.iter().any(|a| a.starts_with("remoteip="))));
        assert!(!rules.iter().any(|r| r.iter().any(|a| a.contains("192.168.1.10,") || a.ends_with("-192.168.1.10"))));
    }
}
