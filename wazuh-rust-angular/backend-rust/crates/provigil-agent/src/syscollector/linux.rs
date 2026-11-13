//! Linux system inventory collectors matching the Windows `sys::` contract in `syscollector.rs`.
//! Pure file/command parsers sit above the `#[cfg(unix)]` OS calls so they are unit-tested on
//! both Windows and Linux.

use std::collections::HashMap;
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::net::{IpAddr, Ipv6Addr};
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(unix)]
use provigil_collect::{nonempty, PortInfo, ProcessInfo, ServiceInfo};
#[cfg(not(unix))]
use provigil_collect::nonempty;

#[cfg(unix)]
use super::{if_address, npm_packages, python_packages, GroupInfo, Hardware, IfAddress, NetworkAdapter, PackageInfo, Profile, UserInfo};
#[cfg(not(unix))]
use super::{GroupInfo, PackageInfo};

/// Parse `/proc/cpuinfo` -> `(model_name, logical_processors, avg_mhz)`.
pub(crate) fn parse_cpuinfo(content: &str) -> (Option<String>, Option<u32>, Option<u32>) {
    let mut name: Option<String> = None;
    let mut processors = 0u32;
    let mut mhz_sum = 0f64;
    let mut mhz_cnt = 0u32;

    for line in content.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let key = k.trim();
        let val = v.trim();
        match key {
            "processor" => processors += 1,
            "model name" | "Hardware" | "Processor" if name.is_none() => {
                name = nonempty(val);
            }
            "cpu MHz" => {
                if let Ok(m) = val.parse::<f64>() {
                    if m > 0.0 {
                        mhz_sum += m;
                        mhz_cnt += 1;
                    }
                }
            }
            _ => {}
        }
    }
    let avg_mhz = (mhz_cnt > 0).then(|| (mhz_sum / mhz_cnt as f64).round() as u32);
    let cores = (processors > 0).then_some(processors);
    (name, cores, avg_mhz)
}

/// Parse `/proc/meminfo` -> `(ram_total_kb, ram_free_kb, ram_usage_percent)`.
pub(crate) fn parse_meminfo(content: &str) -> (Option<u64>, Option<u64>, Option<u32>) {
    let mut total: Option<u64> = None;
    let mut available: Option<u64> = None;
    let mut free = 0u64;
    let mut buffers = 0u64;
    let mut cached = 0u64;

    for line in content.lines() {
        let Some((k, rest)) = line.split_once(':') else { continue };
        let kb = rest.split_whitespace().next().and_then(|s| s.parse::<u64>().ok());
        let Some(kb) = kb else { continue };
        match k.trim() {
            "MemTotal" => total = Some(kb),
            "MemAvailable" => available = Some(kb),
            "MemFree" => free = kb,
            "Buffers" => buffers = kb,
            "Cached" => cached = kb,
            _ => {}
        }
    }
    let free_kb = total.map(|_| available.unwrap_or(free + buffers + cached));
    let usage = match (total, free_kb) {
        (Some(t), Some(f)) if t > 0 => Some((((t.saturating_sub(f)) * 100) / t) as u32),
        _ => None,
    };
    (total, free_kb, usage)
}

pub(crate) fn clean_dmi_serial(raw: &str) -> Option<String> {
    let s = nonempty(raw)?;
    const PLACEHOLDERS: [&str; 7] = [
        "default string",
        "to be filled by o.e.m.",
        "none",
        "not specified",
        "not applicable",
        "n/a",
        "0",
    ];
    (!PLACEHOLDERS.contains(&s.to_ascii_lowercase().as_str())).then_some(s)
}

/// Parse `/var/lib/dpkg/status` stanzas into installed `PackageInfo` records.
pub(crate) fn parse_dpkg_status(content: &str) -> Vec<PackageInfo> {
    let mut pkgs = Vec::new();
    for stanza in content.split("\n\n") {
        let mut name = None;
        let mut status = None;
        let mut version = None;
        let mut arch = None;
        let mut size_kb: Option<u64> = None;
        let mut maintainer = None;
        let mut desc = None;
        for line in stanza.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            let Some((k, v)) = line.split_once(':') else { continue };
            match k.trim() {
                "Package" => name = nonempty(v),
                "Status" => status = nonempty(v),
                "Version" => version = nonempty(v),
                "Architecture" => arch = nonempty(v),
                "Installed-Size" => size_kb = v.trim().parse::<u64>().ok(),
                "Maintainer" => maintainer = nonempty(v),
                "Description" => desc = nonempty(v),
                _ => {}
            }
        }
        let Some(pkg_name) = name else { continue };
        let is_installed = status
            .as_deref()
            .is_some_and(|s| s.split_whitespace().any(|w| w == "installed"));
        if !is_installed {
            continue;
        }
        pkgs.push(PackageInfo {
            name: pkg_name,
            version,
            publisher: maintainer,
            install_date: None,
            size_bytes: size_kb.map(|k| k * 1024),
            architecture: arch,
            location: None,
            description: desc,
            source: "machine".into(),
            format: "deb".into(),
            user_sid: None,
        });
    }
    pkgs
}

/// Parse lines from `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{VENDOR}\t%{INSTALLTIME}\t%{SUMMARY}\n'`.
pub(crate) fn parse_rpm_lines(content: &str) -> Vec<PackageInfo> {
    let mut pkgs = Vec::new();
    for line in content.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 4 || cols[0].trim().is_empty() {
            continue;
        }
        let raw_ver = cols[1].trim();
        let version = nonempty(raw_ver.strip_prefix("0:").unwrap_or(raw_ver));
        let install_date = cols
            .get(5)
            .and_then(|s| s.trim().parse::<i64>().ok())
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .map(|dt| dt.format("%Y-%m-%d").to_string());
        pkgs.push(PackageInfo {
            name: cols[0].trim().to_string(),
            version,
            publisher: cols.get(4).and_then(|s| nonempty(s)).filter(|v| v != "(none)"),
            install_date,
            size_bytes: cols[3].trim().parse::<u64>().ok(),
            architecture: nonempty(cols[2]).filter(|a| a != "(none)"),
            location: None,
            description: cols.get(6).and_then(|s| nonempty(s)),
            source: "machine".into(),
            format: "rpm".into(),
            user_sid: None,
        });
    }
    pkgs
}

/// Parse Alpine `/lib/apk/db/installed` database stanzas.
pub(crate) fn parse_apk_installed(content: &str) -> Vec<PackageInfo> {
    let mut pkgs = Vec::new();
    for stanza in content.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut arch = None;
        let mut size_bytes = None;
        let mut maintainer = None;
        let mut desc = None;
        for line in stanza.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            match k {
                "P" => name = nonempty(v),
                "V" => version = nonempty(v),
                "A" => arch = nonempty(v),
                "I" => size_bytes = v.trim().parse::<u64>().ok(),
                "m" => maintainer = nonempty(v),
                "T" => desc = nonempty(v),
                _ => {}
            }
        }
        let Some(pkg_name) = name else { continue };
        pkgs.push(PackageInfo {
            name: pkg_name,
            version,
            publisher: maintainer,
            install_date: None,
            size_bytes,
            architecture: arch,
            location: None,
            description: desc,
            source: "machine".into(),
            format: "apk".into(),
            user_sid: None,
        });
    }
    pkgs
}

/// Parse `/proc/net/route` -> map of `iface -> (default_gateway, metric)`.
pub(crate) fn parse_proc_net_route(content: &str) -> HashMap<String, (Option<String>, Option<u32>)> {
    let mut routes: HashMap<String, (Option<String>, Option<u32>)> = HashMap::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let iface = cols[0];
        let dest = cols[1];
        let gw_hex = cols[2];
        let metric = cols[6].parse::<u32>().ok();
        let is_default = dest == "00000000" && gw_hex != "00000000";
        if is_default {
            if let Ok(word) = u32::from_str_radix(gw_hex, 16) {
                let gw = Ipv4Addr::from(word.to_ne_bytes()).to_string();
                routes.entry(iface.to_string()).or_insert((Some(gw), metric));
            }
        } else {
            routes.entry(iface.to_string()).or_insert((None, metric));
        }
    }
    routes
}

pub(crate) struct PasswdRow {
    pub name: String,
    pub uid: String,
    pub gid: String,
    pub full_name: Option<String>,
    pub home: Option<String>,
    pub shell: String,
}

/// Parse `/etc/passwd` entries cleanly.
pub(crate) fn parse_passwd(content: &str) -> Vec<PasswdRow> {
    let mut rows = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split(':').collect();
        if cols.len() < 7 || cols[0].is_empty() {
            continue;
        }
        let gecos = cols[4].split(',').next().unwrap_or("");
        rows.push(PasswdRow {
            name: cols[0].to_string(),
            uid: cols[2].to_string(),
            gid: cols[3].to_string(),
            full_name: nonempty(gecos),
            home: nonempty(cols[5]),
            shell: cols[6].trim().to_string(),
        });
    }
    rows
}

/// Parse `/etc/shadow` locked accounts (`!` / `*` password hash -> disabled).
pub(crate) fn parse_shadow_locked(content: &str) -> HashMap<String, bool> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split(':');
        let Some(name) = parts.next() else { continue };
        let Some(hash) = parts.next() else { continue };
        if !name.is_empty() {
            let locked = hash.is_empty() || hash.starts_with('!') || hash.starts_with('*');
            map.insert(name.to_string(), locked);
        }
    }
    map
}

/// Parse `/etc/group` -> `Vec<GroupInfo>`, also augmenting with primary GID users from `/etc/passwd`.
pub(crate) fn parse_groups_with_passwd(group_content: &str, passwd: &[PasswdRow]) -> (Vec<GroupInfo>, HashMap<String, Vec<String>>) {
    let mut by_gid: HashMap<String, String> = HashMap::new();
    let mut groups = Vec::new();
    let mut user_groups: HashMap<String, Vec<String>> = HashMap::new();

    for line in group_content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split(':').collect();
        if cols.len() < 4 || cols[0].is_empty() {
            continue;
        }
        let name = cols[0].to_string();
        let gid = cols[2].to_string();
        by_gid.insert(gid.clone(), name.clone());
        let members: Vec<String> = cols[3]
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_string)
            .collect();
        for m in &members {
            user_groups.entry(m.clone()).or_default().push(name.clone());
        }
        groups.push(GroupInfo {
            name,
            sid: Some(gid),
            description: None,
            members,
        });
    }

    // Ensure every user's primary group appears in both `user.groups` and `group.members`.
    for row in passwd {
        if let Some(gname) = by_gid.get(&row.gid) {
            let ug = user_groups.entry(row.name.clone()).or_default();
            if !ug.contains(gname) {
                ug.push(gname.clone());
            }
            if let Some(g) = groups.iter_mut().find(|g| g.name == *gname) {
                if !g.members.contains(&row.name) {
                    g.members.push(row.name.clone());
                }
            }
        }
    }
    (groups, user_groups)
}

#[cfg(unix)]
pub fn user_profiles() -> Result<Vec<Profile>, String> {
    let passwd = std::fs::read_to_string("/etc/passwd").map_err(|e| format!("/etc/passwd: {e}"))?;
    let mut out = Vec::new();
    for row in parse_passwd(&passwd) {
        let uid_num = row.uid.parse::<u32>().unwrap_or(65534);
        let nologin = row.shell.ends_with("nologin") || row.shell.ends_with("/false");
        if (uid_num >= 1000 && uid_num < 65534 && !nologin) || row.name == "root" {
            if let Some(home) = row.home {
                let path = PathBuf::from(&home);
                if path.is_dir() {
                    out.push(Profile {
                        sid: row.uid,
                        user: row.name,
                        home: path,
                    });
                }
            }
        }
    }
    Ok(out)
}

#[cfg(unix)]
pub fn hardware() -> (Hardware, Vec<String>) {
    let mut reasons = Vec::new();
    let (cpu_name, cpu_cores, mut cpu_mhz) = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(text) => parse_cpuinfo(&text),
        Err(e) => {
            reasons.push(format!("cpuinfo: {e}"));
            (None, None, None)
        }
    };
    if cpu_mhz.is_none() {
        if let Ok(khz) = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq") {
            if let Ok(v) = khz.trim().parse::<u32>() {
                cpu_mhz = Some(v / 1000);
            }
        }
    }
    let (ram_total_kb, ram_free_kb, ram_usage_percent) = match std::fs::read_to_string("/proc/meminfo") {
        Ok(text) => parse_meminfo(&text),
        Err(e) => {
            reasons.push(format!("meminfo: {e}"));
            (None, None, None)
        }
    };
    let board_serial = std::fs::read_to_string("/sys/class/dmi/id/board_serial")
        .or_else(|_| std::fs::read_to_string("/sys/class/dmi/id/product_serial"))
        .ok()
        .and_then(|s| clean_dmi_serial(&s));

    let hw = Hardware {
        cpu_name,
        cpu_cores,
        cpu_mhz,
        ram_total_kb,
        ram_free_kb,
        ram_usage_percent,
        board_serial,
    };
    (hw, reasons)
}

#[cfg(unix)]
pub fn processes() -> Result<Vec<ProcessInfo>, String> {
    provigil_collect::linux::processes()
}

#[cfg(unix)]
pub fn ports() -> Result<Vec<PortInfo>, String> {
    provigil_collect::linux::ports()
}

#[cfg(unix)]
pub fn services() -> Result<Vec<ServiceInfo>, String> {
    provigil_collect::linux::services()
}

#[cfg(unix)]
fn expand_python_site_dirs(base: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let Ok(rd) = std::fs::read_dir(base) else { return dirs };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("python3") || name.starts_with("python2") {
            let p = entry.path();
            for sub in ["site-packages", "dist-packages"] {
                let candidate = p.join(sub);
                if candidate.is_dir() {
                    dirs.push(candidate);
                }
            }
        }
    }
    dirs
}

#[cfg(unix)]
pub fn packages(profiles: &[Profile]) -> Result<Vec<PackageInfo>, String> {
    let mut pkgs = Vec::new();

    if let Ok(dpkg) = std::fs::read_to_string("/var/lib/dpkg/status") {
        pkgs.extend(parse_dpkg_status(&dpkg));
    } else if Path::new("/var/lib/rpm").is_dir() {
        if let Ok(out) = std::process::Command::new("rpm")
            .args([
                "-qa",
                "--qf",
                "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SIZE}\\t%{VENDOR}\\t%{INSTALLTIME}\\t%{SUMMARY}\\n",
            ])
            .output()
        {
            if out.status.success() {
                pkgs.extend(parse_rpm_lines(&String::from_utf8_lossy(&out.stdout)));
            }
        }
    } else if let Ok(apk) = std::fs::read_to_string("/lib/apk/db/installed") {
        pkgs.extend(parse_apk_installed(&apk));
    }

    // Machine-wide Python & npm packages
    for lib_root in [
        Path::new("/usr/lib"),
        Path::new("/usr/local/lib"),
        Path::new("/usr/lib64"),
    ] {
        for site in expand_python_site_dirs(lib_root) {
            pkgs.extend(python_packages(&site, None));
        }
        let nm = lib_root.join("node_modules");
        if nm.is_dir() {
            pkgs.extend(npm_packages(&nm, None));
        }
    }

    // Per-user Python & npm packages
    for profile in profiles {
        for site in expand_python_site_dirs(&profile.home.join(".local/lib")) {
            pkgs.extend(python_packages(&site, Some(&profile.sid)));
        }
        let user_nm = profile.home.join(".npm-global/lib/node_modules");
        if user_nm.is_dir() {
            pkgs.extend(npm_packages(&user_nm, Some(&profile.sid)));
        }
    }

    Ok(pkgs)
}

#[cfg(unix)]
fn netmask_to_prefix_v4(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

#[cfg(unix)]
fn netmask_to_prefix_v6(mask: Ipv6Addr) -> u8 {
    u128::from(mask).count_ones() as u8
}

#[cfg(unix)]
fn collect_ifaddrs() -> HashMap<String, Vec<(IpAddr, Option<u8>)>> {
    use std::ffi::CStr;
    let mut map: HashMap<String, Vec<(IpAddr, Option<u8>)>> = HashMap::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: Standard POSIX `getifaddrs` followed by `freeifaddrs`.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return map;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
            let sa_family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
            if sa_family == libc::AF_INET {
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let prefix = if !ifa.ifa_netmask.is_null() {
                    let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                    Some(netmask_to_prefix_v4(Ipv4Addr::from(u32::from_be(m.sin_addr.s_addr))))
                } else {
                    None
                };
                map.entry(name).or_default().push((IpAddr::V4(ip), prefix));
            } else if sa_family == libc::AF_INET6 {
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let prefix = if !ifa.ifa_netmask.is_null() {
                    let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
                    Some(netmask_to_prefix_v6(Ipv6Addr::from(m.sin6_addr.s6_addr)))
                } else {
                    None
                };
                map.entry(name).or_default().push((IpAddr::V6(ip), prefix));
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    map
}

#[cfg(unix)]
fn read_u64_file(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(unix)]
pub fn interfaces() -> Result<Vec<NetworkAdapter>, String> {
    let rd = std::fs::read_dir("/sys/class/net").map_err(|e| format!("/sys/class/net: {e}"))?;
    let ifaddrs = collect_ifaddrs();
    let routes = std::fs::read_to_string("/proc/net/route")
        .map(|s| parse_proc_net_route(&s))
        .unwrap_or_default();
    let dhcp_leases_present = Path::new("/run/systemd/netif/leases").is_dir()
        || Path::new("/var/lib/NetworkManager").is_dir()
        || Path::new("/var/lib/dhcp").is_dir();

    let mut adapters = Vec::new();
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = entry.path();
        let mac_address = std::fs::read_to_string(dir.join("address"))
            .ok()
            .and_then(|s| nonempty(&s))
            .filter(|m| m != "00:00:00:00:00:00");
        let mtu = read_u64_file(&dir.join("mtu")) as u32;
        let operstate = std::fs::read_to_string(dir.join("operstate"))
            .ok()
            .and_then(|s| nonempty(&s))
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".into());
        let state = match operstate.as_str() {
            "up" | "unknown" if name == "lo" || operstate == "up" => "up".to_string(),
            "down" => "down".to_string(),
            other => other.to_string(),
        };
        let speed_raw = std::fs::read_to_string(dir.join("speed"))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let speed_mbps = if speed_raw > 0 { speed_raw as u32 } else { 0 };

        let arp_type = read_u64_file(&dir.join("type"));
        let if_type = if arp_type == 772 || name == "lo" {
            Some("loopback".into())
        } else if dir.join("wireless").is_dir() || name.starts_with("wl") {
            Some("wireless".into())
        } else if name.starts_with("tun") || name.starts_with("tap") || name.starts_with("wg") || name.starts_with("veth") || name.starts_with("docker") || name.starts_with("br-") {
            Some("tunnel".into())
        } else if arp_type == 1 {
            Some("ethernet".into())
        } else {
            Some("other".into())
        };

        let stats = dir.join("statistics");
        let rx_bytes = read_u64_file(&stats.join("rx_bytes"));
        let tx_bytes = read_u64_file(&stats.join("tx_bytes"));
        let rx_packets = read_u64_file(&stats.join("rx_packets"));
        let tx_packets = read_u64_file(&stats.join("tx_packets"));
        let rx_errors = Some(read_u64_file(&stats.join("rx_errors")));
        let tx_errors = Some(read_u64_file(&stats.join("tx_errors")));
        let rx_dropped = Some(read_u64_file(&stats.join("rx_dropped")));
        let tx_dropped = Some(read_u64_file(&stats.join("tx_dropped")));

        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        let mut addresses: Vec<IfAddress> = Vec::new();
        if let Some(list) = ifaddrs.get(&name) {
            for (ip, prefix) in list {
                let info = if_address(*ip, *prefix);
                match ip {
                    IpAddr::V4(_) => ipv4.push(info.address.clone()),
                    IpAddr::V6(_) => ipv6.push(info.address.clone()),
                }
                addresses.push(info);
            }
        }
        let (gateway, metric) = routes.get(&name).cloned().unwrap_or((None, None));
        let dhcp = if name != "lo" && dhcp_leases_present && gateway.is_some() {
            Some("enabled".into())
        } else {
            None
        };

        adapters.push(NetworkAdapter {
            name,
            mac_address,
            ipv4,
            ipv6,
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            speed_mbps,
            if_type,
            state: Some(state),
            mtu: (mtu > 0).then_some(mtu),
            rx_errors,
            tx_errors,
            rx_dropped,
            tx_dropped,
            gateway,
            dhcp,
            metric,
            addresses,
        });
    }
    adapters.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(adapters)
}

#[cfg(unix)]
pub fn users(_profiles: &[Profile]) -> Result<Vec<UserInfo>, String> {
    let passwd_text = std::fs::read_to_string("/etc/passwd").map_err(|e| format!("/etc/passwd: {e}"))?;
    let group_text = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let shadow_text = std::fs::read_to_string("/etc/shadow").unwrap_or_default();

    let rows = parse_passwd(&passwd_text);
    let (_groups, user_groups) = parse_groups_with_passwd(&group_text, &rows);
    let shadow = parse_shadow_locked(&shadow_text);

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let shell_disabled = r.shell.ends_with("nologin") || r.shell.ends_with("/false");
        let locked = shadow.get(&r.name).copied().unwrap_or(false);
        out.push(UserInfo {
            name: r.name.clone(),
            full_name: r.full_name,
            sid: Some(r.uid),
            home: r.home,
            disabled: shell_disabled || locked,
            last_logon: None,
            groups: user_groups.get(&r.name).cloned().unwrap_or_default(),
        });
    }
    Ok(out)
}

#[cfg(unix)]
pub fn groups() -> Result<Vec<GroupInfo>, String> {
    let group_text = std::fs::read_to_string("/etc/group").map_err(|e| format!("/etc/group: {e}"))?;
    let passwd_text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let rows = parse_passwd(&passwd_text);
    let (groups, _ug) = parse_groups_with_passwd(&group_text, &rows);
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_cpu_and_meminfo() {
        let cpu = "processor\t: 0\nmodel name\t: AMD EPYC 7763 64-Core Processor\ncpu MHz\t\t: 2445.000\n\nprocessor\t: 1\nmodel name\t: AMD EPYC 7763 64-Core Processor\ncpu MHz\t\t: 2455.000\n";
        let (name, cores, mhz) = parse_cpuinfo(cpu);
        assert_eq!(name.as_deref(), Some("AMD EPYC 7763 64-Core Processor"));
        assert_eq!(cores, Some(2));
        assert_eq!(mhz, Some(2450));

        let mem = "MemTotal:       16384000 kB\nMemFree:         2000000 kB\nMemAvailable:    8192000 kB\n";
        let (tot, free, pct) = parse_meminfo(mem);
        assert_eq!((tot, free, pct), (Some(16384000), Some(8192000), Some(50)));
        assert_eq!(clean_dmi_serial("To be filled by O.E.M."), None);
        assert_eq!(clean_dmi_serial("VMware-42 30 9a").as_deref(), Some("VMware-42 30 9a"));
    }

    #[test]
    fn parses_dpkg_rpm_and_apk_packages() {
        let dpkg = "\
Package: openssl
Status: install ok installed
Architecture: amd64
Maintainer: Ubuntu Developers
Installed-Size: 2048
Version: 3.0.13-0ubuntu3.4
Description: Secure Sockets Layer toolkit

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0
";
        let deb = parse_dpkg_status(dpkg);
        assert_eq!(deb.len(), 1);
        assert_eq!((deb[0].name.as_str(), deb[0].format.as_str(), deb[0].size_bytes), ("openssl", "deb", Some(2048 * 1024)));

        let rpm = "bash\t0:5.1.8-9.el9\tx86_64\t1523400\tRed Hat, Inc.\t1700000000\tThe GNU Bourne Again shell\n";
        let r = parse_rpm_lines(rpm);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].name.as_str(), r[0].version.as_deref(), r[0].format.as_str()), ("bash", Some("5.1.8-9.el9"), "rpm"));

        let apk = "P:musl\nV:1.2.5-r0\nA:x86_64\nI:655360\nT:the musl c library\n\n";
        let a = parse_apk_installed(apk);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].name.as_str(), a[0].format.as_str()), ("musl", "apk"));
    }

    #[test]
    fn parses_route_passwd_and_groups() {
        let route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t01010A0A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        let routes = parse_proc_net_route(route);
        assert_eq!(routes.get("eth0"), Some(&(Some("10.10.1.1".to_string()), Some(100))));

        let passwd = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash\n";
        let grp = "root:x:0:\nsudo:x:27:ubuntu\nubuntu:x:1000:\n";
        let prow = parse_passwd(passwd);
        let (groups, ug) = parse_groups_with_passwd(grp, &prow);
        assert!(ug["ubuntu"].contains(&"sudo".to_string()));
        assert!(ug["ubuntu"].contains(&"ubuntu".to_string()));
        assert_eq!(groups.iter().find(|g| g.name == "sudo").unwrap().sid.as_deref(), Some("27"));
    }
}
