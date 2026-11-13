//! The Windows version (product, display version, build) and the installed updates
//! (hotfixes): what the manager's vulnerability scanner needs to know which CVEs apply.

use serde_json::{json, Value};

/// `name    REG_xx    data` lines of `reg query` output, as (name, data).
fn reg_values(output: &str) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let (name, rest) = l.split_once("    ")?;
            let rest = rest.trim_start();
            let (kind, data) = rest.split_once("    ").unwrap_or((rest, ""));
            kind.starts_with("REG_").then(|| (name.trim().to_string(), data.trim().to_string()))
        })
        .collect()
}

/// A REG_DWORD (`0x1b`) or decimal text as a number.
fn number(v: &str) -> Option<u64> {
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// The OS fields from the `CurrentVersion` key's values.
pub fn os_from(values: &[(String, String)], arch: &str, hostname: &str) -> Value {
    let get = |k: &str| values.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str()).unwrap_or("");
    let build = get("CurrentBuildNumber");
    let build_n: u64 = build.parse().unwrap_or(0);
    let major = number(get("CurrentMajorVersionNumber")).map(|n| n.to_string()).unwrap_or_else(|| get("CurrentVersion").split('.').next().unwrap_or("").to_string());
    let minor = number(get("CurrentMinorVersionNumber")).map(|n| n.to_string()).unwrap_or_else(|| get("CurrentVersion").split('.').nth(1).unwrap_or("").to_string());
    let ubr = number(get("UBR")).unwrap_or(0);
    // Windows 11 still says "Windows 10" in ProductName; build 22000 and later is 11
    let mut product = get("ProductName").to_string();
    if build_n >= 22000 {
        product = product.replace("Windows 10", "Windows 11");
    }
    let name = if product.starts_with("Microsoft") { product.clone() } else { format!("Microsoft {product}") };
    let display = [get("DisplayVersion"), get("ReleaseId")].into_iter().find(|v| !v.is_empty()).unwrap_or("").to_string();
    json!({
        "hostname": hostname,
        "architecture": arch,
        "os_name": name.trim(),
        "os_version": format!("{major}.{minor}.{build}.{ubr}"),
        "os_major": major,
        "os_minor": minor,
        "os_build": build,
        "os_patch": ubr.to_string(),
        "os_display_version": display,
        "os_platform": "windows",
        "sysname": "Windows",
        "release": format!("{build}.{ubr}"),
        "edition": get("EditionID"),
    })
}

/// The KB numbers in a text (`KB` then digits, not inside a word: `-EKB-` is none), upper case.
fn kbs(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    (0..b.len().saturating_sub(2))
        .filter(|&i| b[i].eq_ignore_ascii_case(&b'k') && b[i + 1].eq_ignore_ascii_case(&b'b') && (i == 0 || !b[i - 1].is_ascii_alphanumeric()))
        .filter_map(|i| {
            let n = b[i + 2..].iter().take_while(|c| c.is_ascii_digit()).count();
            (n > 0).then(|| format!("KB{}", &text[i + 2..i + 2 + n]))
        })
        .collect()
}

/// The `Q|<HotFixID>` lines of the PowerShell output (Win32_QuickFixEngineering).
fn qfe_kbs(output: &str) -> Vec<String> {
    output.lines().filter_map(|l| l.trim().strip_prefix("Q|")).flat_map(kbs).collect()
}

/// The `H|<operation>|<result>|<title>` lines of the Windows Update history, newest first: the
/// newest successful entry of a KB decides (operation 1 installed it, 2 removed it).
fn history_kbs(output: &str) -> Vec<String> {
    let (mut seen, mut out) = (std::collections::HashSet::new(), Vec::new());
    for l in output.lines() {
        let Some(rest) = l.trim().strip_prefix("H|") else { continue };
        let mut p = rest.splitn(3, '|');
        let (op, result, title) = (p.next().unwrap_or(""), p.next().unwrap_or(""), p.next().unwrap_or(""));
        // 2 succeeded, 3 succeeded with errors
        if !matches!(result, "2" | "3") {
            continue;
        }
        for kb in kbs(title) {
            if seen.insert(kb.clone()) && op == "1" {
                out.push(kb);
            }
        }
    }
    out
}

/// KB numbers from `reg query <key> /s /v <value>` output: taken from the key's last name
/// (`from_key`) or from the value's data, for the keys `keep(key, data)` accepts.
fn reg_kbs(output: &str, from_key: bool, keep: impl Fn(&str, &str) -> bool) -> Vec<String> {
    let mut key = "";
    let mut out = Vec::new();
    for l in output.lines() {
        if l.starts_with("HKEY_") {
            key = l.trim_end();
        } else if let Some((_, data)) = reg_values(l).pop() {
            if keep(key, &data) {
                out.extend(kbs(if from_key { key.rsplit('\\').next().unwrap_or("") } else { &data }));
            }
        }
    }
    out
}

/// All sources' updates as one sorted list without duplicates.
pub fn merge_hotfixes(sources: &[(&str, Vec<String>)]) -> Vec<String> {
    let mut v: Vec<String> = sources.iter().flat_map(|(_, kbs)| kbs.iter().cloned()).collect();
    v.sort();
    v.dedup();
    v
}

/// The program's output; empty once the agent stops (the program is then ended).
#[cfg(windows)]
fn run(exe: &str, args: &[&str]) -> String {
    use std::io::Read;
    use std::process::{Command, Stdio};
    if !crate::collecting() {
        return String::new();
    }
    let Ok(mut child) = Command::new(exe).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else {
        return String::new();
    };
    let mut out = child.stdout.take().expect("stdout is piped");
    // read meanwhile: a full pipe would hold the program up
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    while matches!(child.try_wait(), Ok(None)) {
        if !crate::collecting() {
            crate::commands::kill_tree(&mut child);
            return String::new();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // a missing key or a partly failed script still leaves usable output
    String::from_utf8_lossy(&reader.join().unwrap_or_default()).into_owned()
}

/// The installed updates per source: WMI, the Windows Update history, the servicing (CBS)
/// packages, the old `HotFix` key, Windows Installer patches and the `Updates` key.
#[cfg(windows)]
pub fn hotfix_sources() -> Vec<(&'static str, Vec<String>)> {
    const SCRIPT: &str = "$ErrorActionPreference='SilentlyContinue'; \
        Get-CimInstance Win32_QuickFixEngineering | ForEach-Object { 'Q|' + $_.HotFixID }; \
        $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $n = $s.GetTotalHistoryCount(); \
        if ($n -gt 0) { $s.QueryHistory(0, $n) | ForEach-Object { 'H|' + [int]$_.Operation + '|' + [int]$_.ResultCode + '|' + $_.Title } }";
    let ps = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", SCRIPT]);
    let reg = |key: &str, value: &str, view: &str| run("reg", &["query", key, "/s", "/v", value, view]);
    let updates = r"HKLM\SOFTWARE\Microsoft\Updates";
    let updates = reg(updates, "ThisVersionInstalled", "/reg:64") + &reg(updates, "ThisVersionInstalled", "/reg:32");
    let cbs = reg(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages", "CurrentState", "/reg:64");
    let hotfix = reg(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix", "Installed", "/reg:64");
    let installer = reg(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products", "DisplayName", "/reg:64");
    vec![
        ("qfe", qfe_kbs(&ps)),
        ("update_history", history_kbs(&ps)),
        // 0x70 installed, 0x80 permanent (0x50 is superseded)
        ("cbs", reg_kbs(&cbs, true, |_, d| matches!(number(d), Some(0x70 | 0x80)))),
        ("hotfix_key", reg_kbs(&hotfix, true, |_, d| number(d) == Some(1))),
        ("installer", reg_kbs(&installer, false, |k, _| k.contains(r"\Patches\"))),
        ("updates_key", reg_kbs(&updates, true, |_, d| d.eq_ignore_ascii_case("Y"))),
    ]
}

#[cfg(windows)]
pub fn collect(arch: &str, hostname: &str) -> (Value, Vec<String>) {
    let cv = run("reg", &["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"]);
    (os_from(&reg_values(&cv), arch, hostname), merge_hotfixes(&hotfix_sources()))
}

/// Human-readable OS summary reported during enrollment.
pub fn enroll_os_string() -> String {
    #[cfg(windows)]
    {
        format!("Windows {}", sysinfo::System::os_version().unwrap_or_default()).trim().to_string()
    }
    #[cfg(not(windows))]
    {
        let os_rel = read_os_release();
        let fields = parse_os_release(&os_rel);
        if let Some(pretty) = fields.iter().find(|(k, _)| k == "PRETTY_NAME").map(|(_, v)| v.clone()).filter(|s| !s.is_empty()) {
            return pretty;
        }
        let name = fields.iter().find(|(k, _)| k == "NAME").map(|(_, v)| v.as_str()).unwrap_or("Linux");
        let ver = fields.iter().find(|(k, _)| k == "VERSION_ID").map(|(_, v)| v.as_str()).unwrap_or("");
        format!("{name} {ver}").trim().to_string()
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn parse_os_release(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, raw_v)) = line.split_once('=') else { continue };
        let v = raw_v.trim().trim_matches('"').trim_matches('\'').to_string();
        out.push((k.trim().to_string(), v));
    }
    out
}

/// Parse Linux `/etc/os-release` and kernel release string into the `sys_osinfo` JSON object.
#[cfg_attr(windows, allow(dead_code))]
pub fn linux_os_from(os_release: &str, kernel_release: &str, arch: &str, hostname: &str) -> Value {
    let pairs = parse_os_release(os_release);
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    let raw_id = get("ID").to_ascii_lowercase();
    let os_name = {
        let n = get("NAME");
        if n.is_empty() {
            let p = get("PRETTY_NAME");
            if p.is_empty() { "Linux".to_string() } else { p }
        } else {
            n
        }
    };
    let os_version = {
        let v = get("VERSION_ID");
        if v.is_empty() { kernel_release.trim().to_string() } else { v }
    };
    let mut ver_parts = os_version.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty());
    let os_major = ver_parts.next().unwrap_or("").to_string();
    let os_minor = ver_parts.next().unwrap_or("").to_string();
    let os_patch = ver_parts.next().unwrap_or("").to_string();

    let os_platform = match raw_id.as_str() {
        "rhel" | "redhat" => "rhel".to_string(),
        "sles" | "sled" | "opensuse-leap" | "opensuse-tumbleweed" | "opensuse" => raw_id.clone(),
        "" => {
            let lower = os_name.to_ascii_lowercase();
            if lower.contains("ubuntu") { "ubuntu".into() }
            else if lower.contains("debian") { "debian".into() }
            else if lower.contains("red hat") { "rhel".into() }
            else if lower.contains("centos") { "centos".into() }
            else if lower.contains("rocky") { "rocky".into() }
            else if lower.contains("alma") { "almalinux".into() }
            else { "linux".into() }
        }
        other => other.to_string(),
    };

    let os_display_version = {
        let codename = get("VERSION_CODENAME");
        if !codename.is_empty() {
            codename
        } else {
            let ver = get("VERSION");
            if !ver.is_empty() { ver } else { get("PRETTY_NAME") }
        }
    };

    let release = kernel_release.trim().to_string();
    json!({
        "hostname": hostname,
        "architecture": arch,
        "os_name": os_name,
        "os_version": os_version,
        "os_major": os_major,
        "os_minor": os_minor,
        "os_patch": os_patch,
        "os_build": release,
        "os_display_version": os_display_version,
        "os_platform": os_platform,
        "sysname": "Linux",
        "release": release,
    })
}

#[cfg(not(windows))]
fn read_os_release() -> String {
    std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default()
}

#[cfg(not(windows))]
pub fn collect(arch: &str, hostname: &str) -> (Value, Vec<String>) {
    let os_rel = read_os_release();
    let kernel_rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    (linux_os_from(&os_rel, &kernel_rel, arch, hostname), Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_11_version_and_updates() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    ProductName    REG_SZ    Windows 10 Pro\r\n    DisplayVersion    REG_SZ    23H2\r\n    CurrentBuildNumber    REG_SZ    22631\r\n    UBR    REG_DWORD    0x10dd\r\n    CurrentMajorVersionNumber    REG_DWORD    0xa\r\n    CurrentMinorVersionNumber    REG_DWORD    0x0\r\n    EditionID    REG_SZ    Professional\r\n";
        let os = os_from(&reg_values(out), "x86_64", "PC1");
        assert_eq!(os["os_name"], "Microsoft Windows 11 Pro");
        assert_eq!(os["os_version"], "10.0.22631.4317");
        assert_eq!((os["os_major"].as_str(), os["os_build"].as_str(), os["os_display_version"].as_str()), (Some("10"), Some("22631"), Some("23H2")));
    }

    #[test]
    fn hotfixes_from_every_source_once() {
        let ps = "Q|KB5031455\r\nQ|kb5032189\r\nQ|File 1\r\n\
            H|1|2|2024-01 Cumulative Update for Windows 11 (KB5034123)\r\n\
            H|2|2|Security Update (KB5000001)\r\nH|1|2|Security Update (KB5000001)\r\n\
            H|1|4|Failed Update (KB5000002)\r\nH|1|3|Defender (KB2267602) with | in title\r\n";
        let cbs = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Packages\\Package_10_for_KB5031455~31bf3856ad364e35~amd64~~10.0.1.1\r\n    CurrentState    REG_DWORD    0x70\r\n\r\n\
            HKEY_LOCAL_MACHINE\\SOFTWARE\\Packages\\Package_for_KB5000003~31bf3856ad364e35~amd64~~10.0.1.1\r\n    CurrentState    REG_DWORD    0x50\r\n\r\n\
            HKEY_LOCAL_MACHINE\\SOFTWARE\\Packages\\Package_for_KB5000004~31bf3856ad364e35~amd64~~10.0.1.1\r\n    CurrentState    REG_DWORD    0x80\r\n\r\n\
            HKEY_LOCAL_MACHINE\\SOFTWARE\\Packages\\Data-26141-EKB-Wrapper-Package~31bf3856ad364e35~amd64~~10.0.1.1\r\n    CurrentState    REG_DWORD    0x70\r\n\r\n\
            End of search: 4 match(es) found.\r\n";
        let installer = "HKEY_LOCAL_MACHINE\\Products\\1926E8\\Patches\\4D5407\r\n    DisplayName    REG_SZ    KB2565063\r\n\
            HKEY_LOCAL_MACHINE\\Products\\1926E8\\InstallProperties\r\n    DisplayName    REG_SZ    Update (KB9999999)\r\n";
        let updates = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Updates\\.NET 4\\KB2468871v2\r\n    ThisVersionInstalled    REG_SZ    Y\r\n\
            HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Updates\\.NET 4\\KB2468872\r\n    ThisVersionInstalled    REG_SZ    N\r\n";
        assert_eq!(qfe_kbs(ps), vec!["KB5031455", "KB5032189"]);
        // KB5000001 was removed after it was installed; KB5000002 failed
        assert_eq!(history_kbs(ps), vec!["KB5034123", "KB2267602"]);
        let sources = vec![
            ("qfe", qfe_kbs(ps)),
            ("update_history", history_kbs(ps)),
            ("cbs", reg_kbs(cbs, true, |_, d| matches!(number(d), Some(0x70 | 0x80)))),
            ("installer", reg_kbs(installer, false, |k, _| k.contains(r"\Patches\"))),
            ("updates_key", reg_kbs(updates, true, |_, d| d.eq_ignore_ascii_case("Y"))),
        ];
        assert_eq!(sources[2].1, vec!["KB5031455", "KB5000004"]);
        assert_eq!(
            merge_hotfixes(&sources),
            vec!["KB2267602", "KB2468871", "KB2565063", "KB5000004", "KB5031455", "KB5032189", "KB5034123"]
        );
    }

    #[test]
    fn linux_os_release_parses_major_distros() {
        let ubuntu = "NAME=\"Ubuntu\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n";
        let u = linux_os_from(ubuntu, "6.8.0-45-generic\n", "x86_64", "web-01");
        assert_eq!(u["os_name"], "Ubuntu");
        assert_eq!(u["os_version"], "24.04");
        assert_eq!(u["os_major"], "24");
        assert_eq!(u["os_minor"], "04");
        assert_eq!(u["os_platform"], "ubuntu");
        assert_eq!(u["os_display_version"], "noble");
        assert_eq!(u["sysname"], "Linux");
        assert_eq!(u["release"], "6.8.0-45-generic");

        let rhel = "NAME=\"Red Hat Enterprise Linux\"\nVERSION=\"9.4 (Plow)\"\nID=\"rhel\"\nVERSION_ID=\"9.4\"\n";
        let r = linux_os_from(rhel, "5.14.0-427.el9.x86_64", "x86_64", "db-01");
        assert_eq!(r["os_platform"], "rhel");
        assert_eq!((r["os_major"].as_str(), r["os_minor"].as_str()), (Some("9"), Some("4")));

        let debian = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\nVERSION_CODENAME=bookworm\n";
        let d = linux_os_from(debian, "6.1.0-25-amd64", "x86_64", "app-01");
        assert_eq!((d["os_platform"].as_str(), d["os_major"].as_str(), d["os_display_version"].as_str()), (Some("debian"), Some("12"), Some("bookworm")));
    }
}
