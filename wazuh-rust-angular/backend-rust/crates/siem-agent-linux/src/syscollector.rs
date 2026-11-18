use crate::buffer::AgentBuffer;
use serde::{Deserialize, Serialize};
use siem_core::{EventSource, RawEvent};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Normalized package information matching ProVigil's manager database schema (sys_programs)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub size_bytes: Option<u64>,
    pub architecture: Option<String>,
    pub location: Option<String>,
    pub description: Option<String>,
    /// "machine", "user", "pypi", "npm"
    pub source: String,
    /// "deb", "rpm", "apk", "pacman"
    pub format: String,
    pub user_sid: Option<String>,
}

/// Detailed process information for telemetry and inventory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessItem {
    pub pid: u32,
    pub name: String,
    pub cmd: Option<String>,
    pub ppid: u32,
    pub state: Option<String>,
    pub owner: Option<String>,
    pub memory_mb: u64,
}

/// Detailed network port information for telemetry and inventory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortItem {
    pub protocol: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub state: Option<String>,
    pub pid: u32,
    pub process: Option<String>,
}

/// Normalized hardware information matching manager layout (sys_hwinfo)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub ram_total: u64,
    pub ram_free: u64,
    pub cpu_cores: usize,
    pub cpu_name: Option<String>,
    pub cpu_mhz: Option<u32>,
}

/// Operating system details matching manager layout (sys_osinfo)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetails {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub os_platform: String,
    pub os_codename: Option<String>,
}

/// Complete system inventory structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxSystemInventory {
    pub os_info: OsDetails,
    pub hardware: HardwareInfo,
    pub packages: Vec<PackageInfo>,
    pub processes: Vec<ProcessItem>,
    pub ports: Vec<PortItem>,
    pub services: Vec<String>,
    pub local_users: Vec<String>,
    pub network_adapters: Vec<String>,
}

pub struct LinuxSyscollector {
    _agent_id: String,
}

impl LinuxSyscollector {
    pub fn new(agent_id: String) -> Self {
        Self { _agent_id: agent_id }
    }

    /// Gather full Linux system hardware and software inventory without arbitrary truncations.
    pub fn collect_inventory(&self) -> LinuxSystemInventory {
        let os_info = self.collect_os_details();
        let hardware = self.collect_hardware();
        let packages = self.collect_all_packages();
        let processes = self.collect_processes();
        let ports = self.collect_ports();
        let services = self.collect_services();
        let local_users = self.collect_users();
        let network_adapters = self.collect_network_adapters();

        LinuxSystemInventory {
            os_info,
            hardware,
            packages,
            processes,
            ports,
            services,
            local_users,
            network_adapters,
        }
    }

    fn collect_os_details(&self) -> OsDetails {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| {
                std::fs::read_to_string("/etc/hostname")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "localhost".into())
            });

        let mut os_name = "Linux".to_string();
        let mut os_version = String::new();
        let mut os_codename = None;

        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(name) = trimmed.strip_prefix("NAME=") {
                    os_name = name.trim_matches('"').to_string();
                } else if let Some(ver) = trimmed.strip_prefix("VERSION_ID=") {
                    os_version = ver.trim_matches('"').to_string();
                } else if let Some(code) = trimmed.strip_prefix("VERSION_CODENAME=") {
                    os_codename = Some(code.trim_matches('"').to_string());
                }
            }
        }

        OsDetails {
            hostname,
            os_name,
            os_version,
            architecture: std::env::consts::ARCH.to_string(),
            os_platform: "linux".to_string(),
            os_codename,
        }
    }

    fn collect_hardware(&self) -> HardwareInfo {
        let cpu_cores = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);

        let (ram_total, ram_free) = self.collect_ram_kb();
        let (cpu_name, cpu_mhz) = self.collect_cpu_details();

        HardwareInfo {
            ram_total: ram_total * 1024,
            ram_free: ram_free * 1024,
            cpu_cores,
            cpu_name,
            cpu_mhz,
        }
    }

    fn collect_ram_kb(&self) -> (u64, u64) {
        let mut total = 0u64;
        let mut free = 0u64;
        let mut available = None;

        if let Ok(file) = File::open("/proc/meminfo") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    if let Some(val) = rest.split_whitespace().next().and_then(|s| s.parse().ok()) {
                        total = val;
                    }
                } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    if let Some(val) = rest.split_whitespace().next().and_then(|s| s.parse().ok()) {
                        available = Some(val);
                    }
                } else if let Some(rest) = line.strip_prefix("MemFree:") {
                    if let Some(val) = rest.split_whitespace().next().and_then(|s| s.parse().ok()) {
                        free = val;
                    }
                }
            }
        }
        (total, available.unwrap_or(free))
    }

    fn collect_cpu_details(&self) -> (Option<String>, Option<u32>) {
        let mut model = None;
        let mut mhz = None;

        if let Ok(file) = File::open("/proc/cpuinfo") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if let Some((k, v)) = line.split_once(':') {
                    let key = k.trim();
                    let val = v.trim();
                    if (key == "model name" || key == "Hardware" || key == "Processor") && model.is_none() {
                        if !val.is_empty() {
                            model = Some(val.to_string());
                        }
                    } else if key == "cpu MHz" && mhz.is_none() {
                        if let Ok(m) = val.parse::<f64>() {
                            mhz = Some(m.round() as u32);
                        }
                    }
                }
            }
        }
        (model, mhz)
    }

    /// Complete package collection without arbitrary limit
    pub fn collect_all_packages(&self) -> Vec<PackageInfo> {
        // 1. Check Debian/Ubuntu status database
        if let Ok(dpkg_content) = std::fs::read_to_string("/var/lib/dpkg/status") {
            let pkgs = parse_dpkg_status(&dpkg_content);
            if !pkgs.is_empty() {
                return pkgs;
            }
        }

        // 2. Try rpm on RHEL/CentOS/Rocky/Fedora
        if Path::new("/var/lib/rpm").is_dir() || Path::new("/usr/bin/rpm").exists() {
            if let Ok(output) = Command::new("rpm")
                .args(["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{VENDOR}\t%{INSTALLTIME}\t%{SUMMARY}\n"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let pkgs = parse_rpm_lines(&text);
                    if !pkgs.is_empty() {
                        return pkgs;
                    }
                }
            }
        }

        // 3. Try Alpine apk
        if let Ok(apk_content) = std::fs::read_to_string("/lib/apk/db/installed") {
            let pkgs = parse_apk_installed(&apk_content);
            if !pkgs.is_empty() {
                return pkgs;
            }
        }

        // 4. Try Arch Linux pacman
        if let Ok(output) = Command::new("pacman").args(["-Q"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let pkgs = parse_pacman_lines(&text);
                if !pkgs.is_empty() {
                    return pkgs;
                }
            }
        }

        Vec::new()
    }

    pub(crate) fn collect_processes(&self) -> Vec<ProcessItem> {
        let mut processes = Vec::new();
        let proc_dir = Path::new("/proc");
        if let Ok(entries) = std::fs::read_dir(proc_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(pid) = name.parse::<u32>() {
                    let path = entry.path();
                    let stat_path = path.join("stat");
                    let cmd_path = path.join("cmdline");

                    let cmd = std::fs::read(cmd_path)
                        .ok()
                        .map(|bytes| {
                            bytes
                                .split(|&b| b == 0)
                                .filter(|s| !s.is_empty())
                                .map(|s| String::from_utf8_lossy(s).to_string())
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .filter(|s| !s.is_empty());

                    let mut proc_name = format!("proc_{}", pid);
                    let mut ppid = 0u32;
                    let mut state = None;

                    if let Ok(stat) = std::fs::read_to_string(stat_path) {
                        if let Some(open_p) = stat.find('(') {
                            if let Some(close_p) = stat.rfind(')') {
                                proc_name = stat[open_p + 1..close_p].to_string();
                                let rest = &stat[close_p + 2..];
                                let parts: Vec<&str> = rest.split_whitespace().collect();
                                if !parts.is_empty() {
                                    state = Some(parts[0].to_string());
                                }
                                if parts.len() >= 2 {
                                    ppid = parts[1].parse().unwrap_or(0);
                                }
                            }
                        }
                    }

                    processes.push(ProcessItem {
                        pid,
                        name: proc_name,
                        cmd,
                        ppid,
                        state,
                        owner: None,
                        memory_mb: 0,
                    });
                }
            }
        }
        processes
    }

    pub(crate) fn collect_ports(&self) -> Vec<PortItem> {
        let mut ports = Vec::new();

        let tcp_files = [
            ("/proc/net/tcp", "tcp"),
            ("/proc/net/tcp6", "tcp6"),
            ("/proc/net/udp", "udp"),
            ("/proc/net/udp6", "udp6"),
        ];

        for (path, proto) in &tcp_files {
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        if let Some((ip_hex, port_hex)) = parts[1].split_once(':') {
                            if let Ok(local_port) = u16::from_str_radix(port_hex, 16) {
                                let local_ip = parse_hex_ip(ip_hex);
                                let mut remote_ip = None;
                                let mut remote_port = None;

                                if let Some((rem_ip_hex, rem_port_hex)) = parts[2].split_once(':') {
                                    if let Ok(rp) = u16::from_str_radix(rem_port_hex, 16) {
                                        if rp > 0 {
                                            remote_port = Some(rp);
                                            remote_ip = Some(parse_hex_ip(rem_ip_hex));
                                        }
                                    }
                                }

                                let state = match parts[3] {
                                    "0A" => Some("listening".to_string()),
                                    "01" => Some("established".to_string()),
                                    "02" => Some("syn_sent".to_string()),
                                    "03" => Some("syn_recv".to_string()),
                                    _ => None,
                                };

                                ports.push(PortItem {
                                    protocol: proto.to_string(),
                                    local_ip,
                                    local_port,
                                    remote_ip,
                                    remote_port,
                                    state,
                                    pid: 0,
                                    process: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        ports
    }

    fn collect_services(&self) -> Vec<String> {
        let mut svcs = Vec::new();
        if let Ok(output) = Command::new("systemctl")
            .args(["list-unit-files", "--type=service", "--state=enabled,active"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && !parts[0].ends_with("@.service") {
                        svcs.push(parts[0].to_string());
                    }
                }
                if !svcs.is_empty() {
                    return svcs;
                }
            }
        }

        if let Ok(entries) = std::fs::read_dir("/etc/init.d") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    svcs.push(name);
                }
            }
        }
        svcs
    }

    fn collect_users(&self) -> Vec<String> {
        let mut users = Vec::new();
        if let Ok(file) = File::open("/etc/passwd") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let parts: Vec<&str> = line.split(':').collect();
                if !parts.is_empty() && !parts[0].is_empty() {
                    users.push(parts[0].to_string());
                }
            }
        }
        users
    }

    fn collect_network_adapters(&self) -> Vec<String> {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut adapters = Vec::new();
            for entry in entries.flatten() {
                let iface = entry.file_name().to_string_lossy().to_string();
                let operstate = std::fs::read_to_string(entry.path().join("operstate"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                adapters.push(format!("{iface} ({operstate})"));
            }
            if !adapters.is_empty() {
                return adapters;
            }
        }
        Vec::new()
    }
}

/// Helper to decode IPv4 hex from /proc/net/tcp
fn parse_hex_ip(hex_str: &str) -> String {
    if hex_str.len() == 8 {
        if let Ok(num) = u32::from_str_radix(hex_str, 16) {
            let bytes = num.to_le_bytes();
            return format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
        }
    }
    hex_str.to_string()
}

/// Parse `/var/lib/dpkg/status` stanzas into installed `PackageInfo` records
pub fn parse_dpkg_status(content: &str) -> Vec<PackageInfo> {
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

/// Parse lines from `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{VENDOR}\t%{INSTALLTIME}\t%{SUMMARY}\n'`
pub fn parse_rpm_lines(content: &str) -> Vec<PackageInfo> {
    let mut pkgs = Vec::new();
    for line in content.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 || cols[0].trim().is_empty() {
            continue;
        }
        let raw_ver = cols.get(1).map(|s| s.trim()).unwrap_or("");
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
            size_bytes: cols.get(3).and_then(|s| s.trim().parse::<u64>().ok()),
            architecture: cols.get(2).and_then(|s| nonempty(s)).filter(|a| a != "(none)"),
            location: None,
            description: cols.get(6).and_then(|s| nonempty(s)),
            source: "machine".into(),
            format: "rpm".into(),
            user_sid: None,
        });
    }
    pkgs
}

/// Parse Alpine `/lib/apk/db/installed` stanzas
pub fn parse_apk_installed(content: &str) -> Vec<PackageInfo> {
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

/// Parse Arch Linux `pacman -Q` lines
pub fn parse_pacman_lines(content: &str) -> Vec<PackageInfo> {
    let mut pkgs = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            pkgs.push(PackageInfo {
                name: parts[0].to_string(),
                version: Some(parts[1].to_string()),
                publisher: None,
                install_date: None,
                size_bytes: None,
                architecture: None,
                location: None,
                description: None,
                source: "machine".into(),
                format: "pacman".into(),
                user_sid: None,
            });
        }
    }
    pkgs
}

fn nonempty(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

static LAST_INVENTORY_SEQ: AtomicU64 = AtomicU64::new(0);

/// Spawns the Linux Syscollector worker periodically dispatching hardware/software state to Manager
pub fn spawn_syscollector_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if lifecycle.is_terminated() {
                break;
            }
            if !lifecycle.is_active() {
                continue;
            }
            emit_inventory(&agent_id, &buffer).await;
        }
    })
}

/// Collects full system inventory and sends a normalized `system_inventory` event compatible with manager provigil-db
pub async fn emit_inventory(agent_id: &str, buffer: &AgentBuffer) {
    let collector = LinuxSyscollector::new(agent_id.to_string());
    let inv = collector.collect_inventory();

    let seq = LAST_INVENTORY_SEQ.fetch_add(1, Ordering::SeqCst);
    let event_type = if seq == 0 {
        "system_inventory"
    } else {
        "system_inventory_delta"
    };

    let summary = format!(
        "syscollector: System Inventory: Hostname: '{}', OS: '{}' ({}), CPU Cores: {}, RAM: {} MB, Active Procs: {}, Open Ports: {}, Installed Packages: {}, Services: {}",
        inv.os_info.hostname,
        inv.os_info.os_name,
        inv.os_info.architecture,
        inv.hardware.cpu_cores,
        inv.hardware.ram_total / (1024 * 1024),
        inv.processes.len(),
        inv.ports.len(),
        inv.packages.len(),
        inv.services.len()
    );
    info!("{}", summary);

    let mut event = RawEvent::new(agent_id, EventSource::Syscollector, "syscollector/inventory", summary);
    event.metadata.insert("event_type".into(), event_type.into());
    event.metadata.insert("hostname".into(), inv.os_info.hostname.clone());
    event.metadata.insert("os_type".into(), "linux".into());
    event.metadata.insert("ram_mb".into(), (inv.hardware.ram_total / (1024 * 1024)).to_string());
    event.metadata.insert("cpu_cores".into(), inv.hardware.cpu_cores.to_string());
    event.metadata.insert("processes_count".into(), inv.processes.len().to_string());
    event.metadata.insert("ports_count".into(), inv.ports.len().to_string());
    event.metadata.insert("packages_count".into(), inv.packages.len().to_string());

    if let Ok(os_json) = serde_json::to_string(&inv.os_info) {
        event.metadata.insert("os_info".into(), os_json);
    }

    if let Ok(json_details) = serde_json::to_string(&inv) {
        event.metadata.insert("inventory_json".into(), json_details);
    }

    buffer.push(event).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpkg_parsing_unlimited() {
        let sample = "\
Package: bash
Status: install ok installed
Version: 5.1-6ubuntu1
Architecture: amd64
Installed-Size: 1500
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Description: GNU Bourne Again SHell

Package: curl
Status: install ok installed
Version: 7.81.0-1ubuntu1.16
Architecture: amd64
Installed-Size: 420
Maintainer: Ubuntu Developers
Description: command line tool for transferring data with URL syntax

Package: libssl3
Status: deinstall ok config-files
Version: 3.0.2-0ubuntu1
Architecture: amd64
";

        let pkgs = parse_dpkg_status(sample);
        assert_eq!(pkgs.len(), 2, "Only installed packages should be parsed");
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].version.as_deref(), Some("5.1-6ubuntu1"));
        assert_eq!(pkgs[0].format, "deb");
        assert_eq!(pkgs[0].size_bytes, Some(1500 * 1024));

        assert_eq!(pkgs[1].name, "curl");
        assert_eq!(pkgs[1].version.as_deref(), Some("7.81.0-1ubuntu1.16"));
    }

    #[test]
    fn test_rpm_parsing_unlimited() {
        let sample = "bash\t5.1.8-9.el9\tx86_64\t1523400\tRed Hat, Inc.\t1700000000\tThe GNU Bourne Again shell\nopenssh-server\t8.7p1-38.el9\tx86_64\t980000\tRed Hat, Inc.\t1700001000\tAn implementation of OpenSSH\n";
        let pkgs = parse_rpm_lines(sample);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].version.as_deref(), Some("5.1.8-9.el9"));
        assert_eq!(pkgs[0].format, "rpm");
        assert_eq!(pkgs[1].name, "openssh-server");
    }

    #[test]
    fn test_apk_parsing_unlimited() {
        let sample = "P:busybox\nV:1.36.1-r0\nA:x86_64\nI:892928\nm:S\nT:Size optimized swiss army knife\n\nP:musl\nV:1.2.4-r2\nA:x86_64\nI:614400\nm:Timo\nT:musl c library\n\n";
        let pkgs = parse_apk_installed(sample);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "busybox");
        assert_eq!(pkgs[0].version.as_deref(), Some("1.36.1-r0"));
        assert_eq!(pkgs[0].format, "apk");
    }
}
