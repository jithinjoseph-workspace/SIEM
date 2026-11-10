//! The system inventory: hardware, installed packages, network ports, processes, network
//! interfaces, services, local users and groups, and browser extensions, sent to the manager
//! as one `system_inventory` event, then only as changes (`delta`).
//!
//! Nothing is ever made up: a part that cannot be collected is empty and named in `errors`.
//! The Windows collectors (`win.rs`) use Windows APIs through `windows-sys` and the registry;
//! the external programs a scan runs are the PowerShell and `reg` calls in `osinfo`.

use crate::buffer::EventBuffer;
use crate::sent::{self, Sent};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

pub use provigil_collect::{nonempty, tcp_state, PortInfo, ProcessInfo, ServiceInfo};

pub mod delta;
#[cfg(windows)]
pub mod win;
#[cfg(windows)]
use win as sys;
#[cfg(not(windows))]
use other as sys;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub size_bytes: Option<u64>,
    pub architecture: Option<String>,
    /// `InstallLocation`
    pub location: Option<String>,
    /// `Comments`
    pub description: Option<String>,
    /// `machine`, `machine_x86`, `user`, `appx`, `pypi` or `npm`
    pub source: String,
    /// what the vulnerability scanner matches on: `win` (registry and Store), `pypi`, `npm`, `deb`
    pub format: String,
    /// the owner of a per-user install
    pub user_sid: Option<String>,
}

/// One address of a network interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IfAddress {
    pub address: String,
    pub netmask: Option<String>,
    /// IPv4 only
    pub broadcast: Option<String>,
    /// `ipv4` or `ipv6`
    pub family: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAdapter {
    pub name: String,
    pub mac_address: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub speed_mbps: u32,
    /// `ethernet`, `wireless`, `loopback`, `tunnel` or `other`
    #[serde(rename = "type")]
    pub if_type: Option<String>,
    /// `up` or `down`
    pub state: Option<String>,
    pub mtu: Option<u32>,
    pub rx_errors: Option<u64>,
    pub tx_errors: Option<u64>,
    pub rx_dropped: Option<u64>,
    pub tx_dropped: Option<u64>,
    /// the IPv4 default gateway
    pub gateway: Option<String>,
    /// `enabled` or `disabled`
    pub dhcp: Option<String>,
    pub metric: Option<u32>,
    pub addresses: Vec<IfAddress>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hardware {
    pub cpu_name: Option<String>,
    /// logical processors
    pub cpu_cores: Option<u32>,
    pub cpu_mhz: Option<u32>,
    pub ram_total_kb: Option<u64>,
    pub ram_free_kb: Option<u64>,
    pub ram_usage_percent: Option<u32>,
    pub board_serial: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    pub full_name: Option<String>,
    pub sid: Option<String>,
    pub home: Option<String>,
    pub disabled: bool,
    /// RFC 3339
    pub last_logon: Option<String>,
    /// local groups the user is in
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub sid: Option<String>,
    pub description: Option<String>,
    /// account names
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserExtension {
    /// `chrome`, `edge` or `firefox`
    pub browser: String,
    pub user: String,
    pub profile: String,
    pub id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    /// Firefox says; `None` for Chrome and Edge
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInventory {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub cpu_cores: usize,
    pub ram_mb: u64,
    pub running_processes_count: usize,
    pub open_ports_count: usize,
    pub installed_packages_count: usize,
    pub services_count: usize,
    pub users_count: usize,
    pub listening_ports: Vec<String>,
    pub running_processes: Vec<String>,
    pub installed_software: Vec<String>,
    pub active_services: Vec<String>,
    pub local_users: Vec<String>,
    pub network_adapters: Vec<String>,
    // Enhanced fields
    pub processes: Vec<ProcessInfo>,
    pub packages: Vec<PackageInfo>,
    pub network_interfaces: Vec<NetworkAdapter>,
    pub services: Vec<ServiceInfo>,
    pub hardware: Hardware,
    pub ports: Vec<PortInfo>,
    pub users: Vec<UserInfo>,
    pub groups: Vec<GroupInfo>,
    pub browser_extensions: Vec<BrowserExtension>,
    /// `"<part>: <reason>"` for every part that could not be collected
    pub errors: Vec<String>,
}

/// A user profile on the machine (from the profile list).
#[derive(Debug, Clone)]
pub struct Profile {
    pub sid: String,
    pub user: String,
    pub home: PathBuf,
}

/// What one scan gathered: each part's items, or why it could not be collected.
pub struct Parts {
    /// the hardware, plus a reason for each field that could not be read
    pub hardware: (Hardware, Vec<String>),
    pub processes: Result<Vec<ProcessInfo>, String>,
    pub packages: Result<Vec<PackageInfo>, String>,
    pub ports: Result<Vec<PortInfo>, String>,
    pub network_interfaces: Result<Vec<NetworkAdapter>, String>,
    pub services: Result<Vec<ServiceInfo>, String>,
    pub users: Result<Vec<UserInfo>, String>,
    pub groups: Result<Vec<GroupInfo>, String>,
    pub browser_extensions: Result<Vec<BrowserExtension>, String>,
}

/// The items of a part, or none (and the reason in `errors`).
fn take<T>(part: &str, r: Result<Vec<T>, String>, errors: &mut Vec<String>) -> Vec<T> {
    r.unwrap_or_else(|e| {
        errors.push(format!("{part}: {e}"));
        Vec::new()
    })
}

/// The first `cap` distinct values, in order.
fn distinct_first<'a>(values: impl Iterator<Item = &'a str>, cap: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    values.filter(|v| seen.insert(*v)).take(cap).map(str::to_string).collect()
}

/// The listeners as `ip:port/protocol` (TCP in the listening state and every UDP endpoint).
pub fn listening_summary(ports: &[PortInfo]) -> Vec<String> {
    let mut seen = HashSet::new();
    ports
        .iter()
        .filter(|p| p.protocol.starts_with("udp") || p.state.as_deref() == Some("listening"))
        .map(|p| {
            let ip = if p.local_ip.contains(':') { format!("[{}]", p.local_ip) } else { p.local_ip.clone() };
            format!("{ip}:{}/{}", p.local_port, p.protocol)
        })
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

/// Puts one scan's parts together: the detailed lists, the summaries computed from them,
/// the process names of the ports, and the errors.
pub fn assemble(hostname: String, os: String, arch: String, parts: Parts) -> SystemInventory {
    let (hardware, hw_errors) = parts.hardware;
    let mut errors: Vec<String> = hw_errors.into_iter().map(|e| format!("hardware: {e}")).collect();

    let processes = take("processes", parts.processes, &mut errors);
    let packages = take("packages", parts.packages, &mut errors);
    let mut ports = take("ports", parts.ports, &mut errors);
    let network_interfaces = take("network_interfaces", parts.network_interfaces, &mut errors);
    let services = take("services", parts.services, &mut errors);
    let users = take("users", parts.users, &mut errors);
    let groups = take("groups", parts.groups, &mut errors);
    let browser_extensions = take("browser_extensions", parts.browser_extensions, &mut errors);

    let names: HashMap<u32, &str> = processes.iter().map(|p| (p.pid, p.name.as_str())).collect();
    for p in ports.iter_mut().filter(|p| p.process.is_none()) {
        p.process = names.get(&p.pid).map(|n| n.to_string());
    }
    let listening_ports = listening_summary(&ports);

    let installed: Vec<String> = packages
        .iter()
        .map(|p| match &p.version {
            Some(v) => format!("{}:{v}", p.name),
            None => p.name.clone(),
        })
        .collect();
    let network_adapters = network_interfaces
        .iter()
        .flat_map(|a| a.ipv4.iter().map(move |ip| format!("{}: {ip}", a.name)))
        .collect();

    SystemInventory {
        hostname,
        os,
        arch,
        cpu_cores: hardware.cpu_cores.unwrap_or(0) as usize,
        ram_mb: hardware.ram_total_kb.map(|kb| kb / 1024).unwrap_or(0),
        running_processes_count: processes.len(),
        open_ports_count: listening_ports.len(),
        installed_packages_count: packages.len(),
        services_count: services.len(),
        users_count: users.len(),
        listening_ports,
        running_processes: distinct_first(processes.iter().map(|p| p.name.as_str()), 25),
        installed_software: distinct_first(installed.iter().map(String::as_str), 100),
        active_services: services.iter().take(20).map(|s| s.name.clone()).collect(),
        local_users: users.iter().map(|u| u.name.clone()).collect(),
        network_adapters,
        processes,
        packages,
        network_interfaces,
        services,
        hardware,
        ports,
        users,
        groups,
        browser_extensions,
        errors,
    }
}

// ---------------------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------------------

/// One `Uninstall` subkey as read from the registry.
#[derive(Debug, Clone, Default)]
pub struct RawPackage {
    pub display_name: Option<String>,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub size_kb: Option<u64>,
    pub location: Option<String>,
    pub comments: Option<String>,
    pub system_component: bool,
    pub parent_key_name: Option<String>,
    pub source: String,
    pub user_sid: Option<String>,
    pub architecture: Option<String>,
}

/// The packages to report: entries need a `DisplayName`; system components and updates of
/// another product (`ParentKeyName`) are left out; the same name + version + architecture
/// from two sources is kept once (the first).
pub fn select_packages(raw: Vec<RawPackage>) -> Vec<PackageInfo> {
    let mut seen = HashSet::new();
    raw.into_iter()
        .filter(|r| !r.system_component && r.parent_key_name.as_deref().is_none_or(|p| p.trim().is_empty()))
        .filter_map(|r| {
            let name = r.display_name.as_deref().and_then(nonempty)?;
            // an unresolved resource reference (`@file.dll,-123`) is not a name
            if name.starts_with('@') {
                return None;
            }
            seen.insert((name.clone(), r.version.clone(), r.architecture.clone())).then(|| PackageInfo {
                name,
                version: r.version,
                publisher: r.publisher,
                install_date: r.install_date,
                size_bytes: r.size_kb.map(|kb| kb * 1024),
                architecture: r.architecture,
                location: r.location,
                description: r.comments,
                source: r.source,
                format: "win".into(),
                user_sid: r.user_sid,
            })
        })
        .collect()
}

/// A package found outside the registry.
fn package(name: String, version: Option<String>, source: &str, location: &Path, user_sid: Option<&str>) -> PackageInfo {
    PackageInfo {
        name,
        version,
        publisher: None,
        install_date: None,
        size_bytes: None,
        architecture: None,
        location: Some(location.display().to_string()),
        description: None,
        source: source.into(),
        format: source.into(),
        user_sid: user_sid.map(Into::into),
    }
}

/// A Microsoft Store (AppX / MSIX) package from its full name
/// `Name_Version_Architecture_ResourceId_PublisherId`; `None` for resource packages and
/// bundles (`~`), which repeat a main package.
pub fn appx_package(full_name: &str) -> Option<PackageInfo> {
    let [name, version, arch, "", _publisher] = full_name.split('_').collect::<Vec<_>>()[..] else { return None };
    Some(PackageInfo {
        architecture: Some(arch.into()),
        format: "win".into(),
        location: None,
        ..package(name.into(), Some(version.into()), "appx", Path::new(""), None)
    })
}

/// The `Name:`-style headers of a Python package's `METADATA` / `PKG-INFO` (up to the body).
fn metadata_header(text: &str, key: &str) -> Option<String> {
    text.lines()
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(key))
        .and_then(|(_, v)| nonempty(v))
}

/// The Python packages of a `site-packages` folder: `*.dist-info\METADATA`,
/// `*.egg-info\PKG-INFO` or a `*.egg-info` file.
pub fn python_packages(site: &Path, user_sid: Option<&str>) -> Vec<PackageInfo> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(site).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    entries.sort();
    entries
        .iter()
        .filter_map(|p| {
            let n = file_name(p).to_ascii_lowercase();
            let meta = match () {
                _ if n.ends_with(".dist-info") => p.join("METADATA"),
                _ if n.ends_with(".egg-info") && p.is_dir() => p.join("PKG-INFO"),
                _ if n.ends_with(".egg-info") => p.clone(),
                _ => return None,
            };
            let text = std::fs::read_to_string(meta).ok()?;
            let h = |k| metadata_header(&text, k);
            Some(PackageInfo {
                publisher: h("Author").or_else(|| h("Author-email")),
                description: h("Summary"),
                ..package(h("Name")?, h("Version"), "pypi", p, user_sid)
            })
        })
        .collect()
}

/// The packages of a global `node_modules` folder: `<name>\package.json` and
/// `@scope\<name>\package.json`.
pub fn npm_packages(node_modules: &Path, user_sid: Option<&str>) -> Vec<PackageInfo> {
    let dirs = subdirs(node_modules).into_iter().flat_map(|d| if file_name(&d).starts_with('@') { subdirs(&d) } else { vec![d] });
    dirs.filter_map(|d| {
        let j = read_json(&d.join("package.json"))?;
        let s = |k: &str| j.pointer(k).and_then(Value::as_str).and_then(nonempty);
        Some(PackageInfo {
            publisher: s("/author").or_else(|| s("/author/name")),
            description: s("/description"),
            ..package(s("/name")?, s("/version"), "npm", &d, user_sid)
        })
    })
    .collect()
}

// ---------------------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------------------

/// The IPv4 netmask of a prefix length (more than 32 counts as 32).
pub fn netmask_v4(prefix: u8) -> Ipv4Addr {
    let p = u32::from(prefix.min(32));
    Ipv4Addr::from(if p == 0 { 0 } else { u32::MAX << (32 - p) })
}

/// The IPv6 netmask of a prefix length (more than 128 counts as 128).
pub fn netmask_v6(prefix: u8) -> Ipv6Addr {
    let p = u32::from(prefix.min(128));
    Ipv6Addr::from(if p == 0 { 0 } else { u128::MAX << (128 - p) })
}

/// The IPv4 broadcast address of a network.
pub fn broadcast_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(addr) | !u32::from(netmask_v4(prefix)))
}

/// An interface address with its netmask (and broadcast for IPv4).
pub fn if_address(ip: std::net::IpAddr, prefix: Option<u8>) -> IfAddress {
    match ip {
        std::net::IpAddr::V4(a) => IfAddress {
            address: a.to_string(),
            netmask: prefix.map(|p| netmask_v4(p).to_string()),
            broadcast: prefix.map(|p| broadcast_v4(a, p).to_string()),
            family: "ipv4".into(),
        },
        std::net::IpAddr::V6(a) => IfAddress {
            address: a.to_string(),
            netmask: prefix.map(|p| netmask_v6(p).to_string()),
            broadcast: None,
            family: "ipv6".into(),
        },
    }
}

// ---------------------------------------------------------------------------------------
// Hardware helpers
// ---------------------------------------------------------------------------------------

/// The baseboard serial number from the raw SMBIOS data the firmware-table API returns
/// (an 8-byte header, then the structures). `None` when the board has none or a placeholder.
pub fn board_serial_from_smbios(raw: &[u8]) -> Option<String> {
    let table = raw.get(8..)?;
    let mut i = 0;
    while i + 4 <= table.len() {
        let (kind, len) = (table[i], table[i + 1] as usize);
        if len < 4 {
            return None;
        }
        // the strings follow the formatted area and end with a double NUL
        let strings_at = i + len;
        let mut end = strings_at;
        while end + 1 < table.len() && !(table[end] == 0 && table[end + 1] == 0) {
            end += 1;
        }
        if kind == 2 && len > 7 {
            let index = table[i + 7] as usize;
            if index == 0 {
                return None;
            }
            let area = table.get(strings_at..end)?;
            let s = area.split(|&b| b == 0).nth(index - 1)?;
            let s = nonempty(&String::from_utf8_lossy(s))?;
            const PLACEHOLDERS: [&str; 7] =
                ["default string", "to be filled by o.e.m.", "none", "not specified", "not applicable", "n/a", "base board serial number"];
            return (!PLACEHOLDERS.contains(&s.to_ascii_lowercase().as_str())).then_some(s);
        }
        if kind == 127 {
            return None;
        }
        i = end + 2;
    }
    None
}

// ---------------------------------------------------------------------------------------
// Browser extensions
// ---------------------------------------------------------------------------------------

fn read_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// The numbers of a version text, for comparing (`1.10.2_0` → 1, 10, 2, 0).
fn version_key(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse().unwrap_or(0)).collect()
}

/// A manifest name; a `__MSG_key__` placeholder is looked up in the default locale's messages.
fn chromium_name(manifest: &Value, ext_dir: &Path) -> Option<String> {
    let name = manifest.get("name")?.as_str()?;
    let Some(key) = name.strip_prefix("__MSG_").and_then(|k| k.strip_suffix("__")) else {
        return nonempty(name);
    };
    let resolved = manifest
        .get("default_locale")
        .and_then(Value::as_str)
        .and_then(|loc| read_json(&ext_dir.join("_locales").join(loc).join("messages.json")))
        .and_then(|m| {
            m.as_object()?
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .and_then(|(_, v)| v.get("message")?.as_str().and_then(nonempty))
        });
    // when it cannot be resolved, the placeholder itself (never a made-up name)
    resolved.or_else(|| nonempty(name))
}

/// Chrome / Edge extensions under a `User Data` directory:
/// `<profile>\Extensions\<id>\<version>\manifest.json` (the newest version of each).
pub fn chromium_extensions(user_data: &Path, browser: &str, user: &str) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    for profile in subdirs(user_data) {
        let ext_root = profile.join("Extensions");
        if !ext_root.is_dir() {
            continue;
        }
        for id_dir in subdirs(&ext_root) {
            let newest = subdirs(&id_dir)
                .into_iter()
                .filter(|v| v.join("manifest.json").is_file())
                .max_by_key(|v| version_key(&file_name(v)));
            let Some(ver_dir) = newest else { continue };
            let Some(manifest) = read_json(&ver_dir.join("manifest.json")) else { continue };
            out.push(BrowserExtension {
                browser: browser.into(),
                user: user.into(),
                profile: file_name(&profile),
                id: file_name(&id_dir),
                name: chromium_name(&manifest, &ver_dir),
                version: manifest.get("version").and_then(Value::as_str).and_then(nonempty),
                enabled: None,
            });
        }
    }
    out
}

/// Firefox add-ons under a `Profiles` directory: `<profile>\extensions.json`.
pub fn firefox_extensions(profiles: &Path, user: &str) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    for profile in subdirs(profiles) {
        let Some(doc) = read_json(&profile.join("extensions.json")) else { continue };
        let Some(addons) = doc.get("addons").and_then(Value::as_array) else { continue };
        for a in addons {
            let Some(id) = a.get("id").and_then(Value::as_str) else { continue };
            out.push(BrowserExtension {
                browser: "firefox".into(),
                user: user.into(),
                profile: file_name(&profile),
                id: id.into(),
                name: a.pointer("/defaultLocale/name").and_then(Value::as_str).and_then(nonempty),
                version: a.get("version").and_then(Value::as_str).and_then(nonempty),
                enabled: a.get("active").and_then(Value::as_bool),
            });
        }
    }
    out
}

/// Every Chrome, Edge and Firefox extension in one user's profile directory.
pub fn browser_extensions_for(home: &Path, user: &str) -> Vec<BrowserExtension> {
    let local = home.join("AppData").join("Local");
    let mut out = chromium_extensions(&local.join("Google").join("Chrome").join("User Data"), "chrome", user);
    out.extend(chromium_extensions(&local.join("Microsoft").join("Edge").join("User Data"), "edge", user));
    let ff = home.join("AppData").join("Roaming").join("Mozilla").join("Firefox").join("Profiles");
    out.extend(firefox_extensions(&ff, user));
    out
}

// ---------------------------------------------------------------------------------------
// The collector
// ---------------------------------------------------------------------------------------

/// With nothing to send, the counts and hashes still go this often (seconds).
const HEARTBEAT_EVERY: i64 = 86_400;
/// Process changes go at most hourly; a little less here, as scans do not end to the second.
const PROCESSES_EVERY: i64 = 3_300;

pub struct Syscollector {
    agent_id: String,
    agent_name: String,
    /// Where what was sent is kept.
    state: PathBuf,
    /// `full_send_splay_secs`.
    splay: Option<u64>,
}

impl Syscollector {
    pub fn new(agent_id: String, agent_name: String, splay: Option<u64>) -> Self {
        Self { agent_id, agent_name, state: sent::file(), splay }
    }

    /// Gathers the full hardware and software inventory of the host (blocking work).
    pub fn collect_inventory(&self) -> SystemInventory {
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "localhost".into());
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        let profiles = sys::user_profiles();
        let browser_extensions = profiles
            .as_ref()
            .map(|ps| ps.iter().flat_map(|p| browser_extensions_for(&p.home, &p.user)).collect())
            .map_err(Clone::clone);
        let parts = Parts {
            hardware: sys::hardware(),
            processes: sys::processes(),
            packages: sys::packages(profiles.as_deref().unwrap_or(&[])),
            // like the old agent's default (`ports all="no"`): listening TCP and UDP, not every connection
            ports: sys::ports().map(|v| v.into_iter().filter(|p| p.protocol.starts_with("udp") || p.state.as_deref() == Some("listening")).collect()),
            network_interfaces: sys::interfaces(),
            services: sys::services(),
            users: sys::users(profiles.as_deref().unwrap_or(&[])),
            groups: sys::groups(),
            browser_extensions,
        };
        assemble(hostname, os, arch, parts)
    }

    /// A scan: `full` (or nothing sent yet) sends all of it, else only what changed.
    pub fn scan_and_emit(&self, buffer: &EventBuffer, full: bool) {
        let inv = self.collect_inventory();
        // the OS version and installed updates the vulnerability scanner needs
        let (os_info, hotfixes) = crate::osinfo::collect(&inv.arch, &inv.hostname);
        self.emit(buffer, full, inv, os_info, hotfixes);
    }

    /// Queues what the manager needs of this scan and notes what it now has.
    fn emit(&self, buffer: &EventBuffer, full: bool, inv: SystemInventory, mut os_info: Value, hotfixes: Vec<String>) {
        // stopped meanwhile: the update query was cut short, and no updates would mean false findings
        if !crate::collecting() {
            return;
        }

        let msg = format!(
            "syscollector: System inventory scan completed. Host: {}, OS: {} ({}), RAM: {}MB, CPUs: {}, Processes: {}, Ports: {}, Apps: {}, Services: {}, Users: {}",
            inv.hostname, inv.os, inv.arch, inv.ram_mb, inv.cpu_cores, inv.running_processes_count, inv.open_ports_count, inv.installed_packages_count, inv.services_count, inv.users_count
        );

        info!("Syscollector: {}", msg);
        for e in &inv.errors {
            warn!(error = %e, "Inventory part not collected");
        }

        let mut inv_json = serde_json::to_value(&inv).unwrap_or_default();
        let mut tables = delta::tables(&inv_json, &os_info, &hotfixes);
        let now = Utc::now().timestamp();
        let id = self.agent_id.as_str();
        let sent = Sent::open(&self.state).map_err(|e| warn!(error = %e, "Inventory sent not readable: sending all")).ok();
        if let Some((s, last)) = sent.as_ref().and_then(|s| Some((s, s.at(id, "inventory")?))).filter(|_| !full) {
            if s.at(id, "processes").is_some_and(|at| now - at < PROCESSES_EVERY) {
                tables.retain(|t| t.name != "processes");
            }
            let saved: rusqlite::Result<HashMap<_, _>> = tables.iter().map(|t| Ok((t.name.to_string(), s.items(id, t.name)?))).collect();
            if let Ok(saved) = saved {
                let (changes, n) = delta::changes(&tables, &saved);
                if n == 0 && now - last < HEARTBEAT_EVERY {
                    return;
                }
                buffer.push(delta::event((id, &self.agent_name), changes, n));
                self.note(sent, &tables, now);
                return;
            }
        }
        // the scan ran; only the send of a full one waits
        let first = sent.as_ref().is_none_or(|s| s.at(id, "inventory").is_none());
        if !sent::wait_splay(self.splay, first) {
            return;
        }
        delta::mark_full(&tables, &mut inv_json, &mut os_info);
        let json_data = inv_json.to_string();

        let event = json!({
            "event_type": "system_inventory",
            "timestamp": Utc::now().to_rfc3339(),
            "agent": {
                "id": &self.agent_id,
                "name": &self.agent_name,
            },
            "location": "syscollector/inventory",
            "message": msg,
            "inventory_json": json_data,
            "errors": inv.errors,
            "os_info": os_info,
            "hotfixes": hotfixes,
            "hostname": inv.hostname,
            "os": inv.os,
            "ram_mb": inv.ram_mb.to_string(),
            "processes_count": inv.running_processes_count.to_string(),
            "open_ports_count": inv.open_ports_count.to_string(),
            "listening_ports": inv.listening_ports.join(", "),
            "active_services": inv.active_services.join(", "),
            "local_users": inv.local_users.join(", "),
            "network_adapters": inv.network_adapters.join("; "),
            "system": {
                "os": {
                    "name": "Windows",
                    "version": inv.os,
                    "hostname": inv.hostname,
                },
                "hardware": {
                    "cpu_count": inv.cpu_cores,
                    "total_memory_mb": inv.ram_mb,
                },
                "ports": inv.listening_ports,
                "packages": inv.installed_software,
                "services": inv.active_services,
                "processes": inv.running_processes,
                "networks": inv.network_adapters,
            }
        });

        buffer.push(event);
        self.note(sent, &tables, now);
    }

    /// The manager now has these tables.
    fn note(&self, sent: Option<Sent>, tables: &[delta::Table], now: i64) {
        let Some(mut s) = sent else { return };
        let id = self.agent_id.as_str();
        let parts: BTreeMap<&str, Vec<(&str, &str)>> = tables.iter().map(|t| (t.name, t.items.iter().map(|(k, (h, _))| (k.as_str(), h.as_str())).collect())).collect();
        let saved = s.save_items(id, &parts).and_then(|_| {
            s.set_at(id, "inventory", now)?;
            if parts.contains_key("processes") {
                s.set_at(id, "processes", now)?;
            }
            Ok(())
        });
        if let Err(e) = saved {
            warn!(error = %e, "Inventory sent not saved");
        }
    }
}

pub fn spawn_syscollector_worker(
    agent_id: String,
    agent_name: String,
    buffer: Arc<EventBuffer>,
    interval: Duration,
    full: Arc<Notify>,
    splay: Option<u64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let collector = Arc::new(Syscollector::new(agent_id, agent_name, splay));
        info!("Syscollector inventory daemon initialized (interval: {:?})", interval);

        // the first tick is at once: the first scan right at start
        let mut ticker = tokio::time::interval(interval);
        loop {
            let asked = tokio::select! {
                _ = ticker.tick() => false,
                _ = full.notified() => true,
            };
            debug!("Syscollector: Running scheduled system inventory sync...");
            // API and registry calls: off the async worker threads
            let (c, b) = (collector.clone(), buffer.clone());
            match crate::blocking("inventory scan", move || c.scan_and_emit(&b, asked)).await {
                Ok(_) => crate::scan_done("inventory"),
                Err(e) => warn!(error = %e, "Inventory scan failed"),
            }
        }
    })
}

/// Other platforms: the processes, packages, interfaces and services the old fallbacks read;
/// the rest is empty.
#[cfg(not(windows))]
mod other {
    use super::*;
    use std::process::Command;

    pub fn user_profiles() -> Result<Vec<Profile>, String> {
        Ok(Vec::new())
    }

    pub fn hardware() -> (Hardware, Vec<String>) {
        let cores = std::thread::available_parallelism().ok().map(|n| n.get() as u32);
        (Hardware { cpu_cores: cores, ..Hardware::default() }, Vec::new())
    }

    pub fn ports() -> Result<Vec<PortInfo>, String> {
        Ok(Vec::new())
    }

    pub fn users(_profiles: &[Profile]) -> Result<Vec<UserInfo>, String> {
        Ok(Vec::new())
    }

    pub fn groups() -> Result<Vec<GroupInfo>, String> {
        Ok(Vec::new())
    }

    pub fn processes() -> Result<Vec<ProcessInfo>, String> {
        let entries = std::fs::read_dir("/proc").map_err(|e| e.to_string())?;
        let mut result = Vec::new();
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string();
            let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .ok()
                .map(|s| s.replace('\0', " ").trim().to_string())
                .filter(|s| !s.is_empty());
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let parts: Vec<&str> = stat.split_whitespace().collect();
            let ppid = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let mem_pages = parts.get(23).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            if !comm.is_empty() {
                result.push(ProcessInfo {
                    pid,
                    name: comm,
                    command_line: cmdline,
                    owner: None,
                    parent_pid: ppid,
                    memory_mb: (mem_pages * 4096) / (1024 * 1024),
                    cpu_time_ms: 0,
                    start_time: 0,
                    priority: parts.get(17).and_then(|s| s.parse().ok()).unwrap_or(0),
                    threads: parts.get(19).and_then(|s| s.parse().ok()).unwrap_or(0),
                    virtual_kb: parts.get(22).and_then(|s| s.parse::<u64>().ok()).map(|b| b / 1024),
                    session_id: parts.get(5).and_then(|s| s.parse().ok()),
                });
            }
        }
        Ok(result)
    }

    pub fn packages(_profiles: &[Profile]) -> Result<Vec<PackageInfo>, String> {
        let status = std::fs::read_to_string("/var/lib/dpkg/status").map_err(|e| e.to_string())?;
        let mut packages = Vec::new();
        let (mut name, mut ver, mut arch, mut size, mut desc) = (None, None, None, None, None);
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version: ") {
                ver = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Architecture: ") {
                arch = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Installed-Size: ") {
                size = v.trim().parse::<u64>().ok().map(|kb| kb * 1024);
            } else if let Some(v) = line.strip_prefix("Description: ") {
                desc = Some(v.trim().to_string());
            } else if line.is_empty() {
                if let Some(n) = name.take() {
                    packages.push(PackageInfo {
                        name: n,
                        version: ver.take(),
                        publisher: None,
                        install_date: None,
                        size_bytes: size.take(),
                        architecture: arch.take(),
                        location: None,
                        description: desc.take(),
                        source: "machine".into(),
                        format: "deb".into(),
                        user_sid: None,
                    });
                }
            }
        }
        Ok(packages)
    }

    pub fn interfaces() -> Result<Vec<NetworkAdapter>, String> {
        let entries = std::fs::read_dir("/sys/class/net").map_err(|e| e.to_string())?;
        let mut adapters = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let base = format!("/sys/class/net/{name}");
            let read_str = |f: &str| std::fs::read_to_string(format!("{base}/{f}")).ok().and_then(|s| nonempty(&s));
            let read_u64 = |f: &str| read_str(f).and_then(|s| s.parse::<u64>().ok());
            adapters.push(NetworkAdapter {
                mac_address: read_str("address").filter(|m| m != "00:00:00:00:00:00"),
                ipv4: Vec::new(),
                ipv6: Vec::new(),
                rx_bytes: read_u64("statistics/rx_bytes").unwrap_or(0),
                tx_bytes: read_u64("statistics/tx_bytes").unwrap_or(0),
                rx_packets: read_u64("statistics/rx_packets").unwrap_or(0),
                tx_packets: read_u64("statistics/tx_packets").unwrap_or(0),
                speed_mbps: read_str("speed").and_then(|s| s.parse().ok()).unwrap_or(0),
                if_type: None,
                state: read_str("operstate"),
                mtu: read_str("mtu").and_then(|s| s.parse().ok()),
                rx_errors: read_u64("statistics/rx_errors"),
                tx_errors: read_u64("statistics/tx_errors"),
                rx_dropped: read_u64("statistics/rx_dropped"),
                tx_dropped: read_u64("statistics/tx_dropped"),
                gateway: None,
                dhcp: None,
                metric: None,
                addresses: Vec::new(),
                name,
            });
        }
        Ok(adapters)
    }

    pub fn services() -> Result<Vec<ServiceInfo>, String> {
        let output = Command::new("systemctl")
            .args(["list-units", "--type=service", "--all", "--no-pager", "--no-legend"])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!("systemctl exited with {}", output.status));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(text
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                (parts.len() >= 4).then(|| {
                    let name = parts[0].trim_end_matches(".service").to_string();
                    ServiceInfo {
                        display_name: name.clone(),
                        name,
                        state: if parts[3] == "running" { "running" } else { "stopped" }.into(),
                        startup_type: String::new(),
                        account: None,
                        path: None,
                        pid: None,
                        description: None,
                    }
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_parts() -> Parts {
        Parts {
            hardware: (Hardware::default(), Vec::new()),
            processes: Ok(Vec::new()),
            packages: Ok(Vec::new()),
            ports: Ok(Vec::new()),
            network_interfaces: Ok(Vec::new()),
            services: Ok(Vec::new()),
            users: Ok(Vec::new()),
            groups: Ok(Vec::new()),
            browser_extensions: Ok(Vec::new()),
        }
    }

    fn process(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.into(),
            command_line: None,
            owner: None,
            parent_pid: 0,
            memory_mb: 0,
            cpu_time_ms: 0,
            start_time: 0,
            priority: 8,
            threads: 1,
            virtual_kb: None,
            session_id: None,
        }
    }

    #[test]
    fn no_fake_ports_when_collection_fails() {
        let parts = Parts { ports: Err("GetExtendedTcpTable failed (error 5)".into()), ..empty_parts() };
        let inv = assemble("pc".into(), "windows".into(), "x86_64".into(), parts);
        assert!(inv.ports.is_empty());
        assert!(inv.listening_ports.is_empty());
        assert_eq!(inv.open_ports_count, 0);
        assert_eq!(inv.errors, vec!["ports: GetExtendedTcpTable failed (error 5)".to_string()]);
        // and the event carries it
        let v = serde_json::to_value(&inv).unwrap();
        assert_eq!(v["errors"][0], "ports: GetExtendedTcpTable failed (error 5)");
        assert_eq!(v["ports"], json!([]));
    }

    #[test]
    fn ports_get_process_names_and_summary_has_no_cap() {
        let mut ports: Vec<PortInfo> = (1..=40)
            .map(|n| PortInfo {
                protocol: "tcp".into(),
                local_ip: "0.0.0.0".into(),
                local_port: 1000 + n,
                remote_ip: None,
                remote_port: None,
                state: Some("listening".into()),
                pid: 4,
                process: None,
            })
            .collect();
        ports.push(PortInfo {
            protocol: "udp6".into(),
            local_ip: "::".into(),
            local_port: 500,
            remote_ip: None,
            remote_port: None,
            state: None,
            pid: 900,
            process: None,
        });
        ports.push(PortInfo {
            protocol: "tcp".into(),
            local_ip: "10.0.0.5".into(),
            local_port: 50000,
            remote_ip: Some("10.0.0.1".into()),
            remote_port: Some(443),
            state: Some("established".into()),
            pid: 4,
            process: None,
        });
        let parts = Parts { ports: Ok(ports), processes: Ok(vec![process(4, "System")]), ..empty_parts() };
        let inv = assemble("pc".into(), "windows".into(), "x86_64".into(), parts);
        assert_eq!(inv.open_ports_count, 41);
        assert!(inv.listening_ports.contains(&"0.0.0.0:1040/tcp".to_string()));
        assert!(inv.listening_ports.contains(&"[::]:500/udp6".to_string()));
        assert_eq!(inv.ports[0].process.as_deref(), Some("System"));
        assert_eq!(inv.ports[40].process, None);
        assert!(inv.errors.is_empty());
    }

    fn pkg(name: &str, version: &str) -> PackageInfo {
        PackageInfo { architecture: Some("x64".into()), ..package(name.into(), Some(version.into()), "machine", Path::new(r"C:\p"), None) }
    }

    fn scan_parts() -> Parts {
        let hardware = Hardware { cpu_name: Some("cpu".into()), ram_total_kb: Some(16), ram_free_kb: Some(7), ram_usage_percent: Some(50), ..Hardware::default() };
        Parts { hardware: (hardware, Vec::new()), packages: Ok(vec![pkg("a", "1"), pkg("b", "1"), pkg("c", "1")]), processes: Ok(vec![process(4, "System"), process(9, "svc")]), ..empty_parts() }
    }

    fn os() -> Value {
        json!({ "os_name": "Windows", "os_version": "10.0.1" })
    }

    /// A collector with its own state file, and what one scan of `parts` queues.
    // the folder lives as long as the collector
    struct Sim(Syscollector, EventBuffer, #[allow(dead_code)] tempfile::TempDir);

    impl Sim {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            Sim(Syscollector { agent_id: "058".into(), agent_name: "pc".into(), state: dir.path().join("sent.db"), splay: Some(0) }, EventBuffer::new(100), dir)
        }

        fn scan(&self, full: bool, parts: Parts, hotfixes: &[&str]) -> Vec<Value> {
            let inv = assemble("pc".into(), "windows".into(), "x86_64".into(), parts);
            self.0.emit(&self.1, full, inv, os(), hotfixes.iter().map(|h| h.to_string()).collect());
            self.1.drain_batch(100)
        }

        fn set_at(&self, name: &str, ago: i64) {
            Sent::open(&self.0.state).unwrap().set_at("058", name, Utc::now().timestamp() - ago).unwrap();
        }
    }

    #[test]
    fn inventory_first_full_then_nothing_when_nothing_changed() {
        let s = Sim::new();
        let first = s.scan(false, scan_parts(), &["KB1"]);
        assert_eq!((first.len(), first[0]["event_type"].as_str()), (1, Some("system_inventory")));
        let inv: Value = serde_json::from_str(first[0]["inventory_json"].as_str().unwrap()).unwrap();
        let h = &inv["packages"][0]["_h"];
        assert_eq!((inv["packages"].as_array().unwrap().len(), h.as_str().unwrap().len()), (3, 40), "each item with its hash");
        assert!(inv["hardware"]["_h"].is_string() && first[0]["os_info"]["_h"].is_string());
        assert_eq!(first[0]["hotfixes"], json!(["KB1"]));

        assert!(s.scan(false, scan_parts(), &["KB1"]).is_empty(), "nothing changed: no event");
        // what moves all the time is no change
        let mut busy = scan_parts();
        busy.hardware.0.ram_free_kb = Some(1);
        busy.processes = Ok(vec![ProcessInfo { memory_mb: 900, cpu_time_ms: 5, threads: 80, virtual_kb: Some(1), ..process(4, "System") }, process(9, "svc")]);
        busy.network_interfaces = Ok(Vec::new());
        assert!(s.scan(false, busy, &["KB1"]).is_empty());

        assert_eq!(s.scan(true, scan_parts(), &["KB1"])[0]["event_type"], "system_inventory", "the manager asked");
    }

    #[test]
    fn inventory_delta_sends_exactly_what_changed() {
        let s = Sim::new();
        s.scan(false, scan_parts(), &["KB1", "KB2"]);
        let was: HashMap<String, String> = Sent::open(&s.0.state).unwrap().items("058", "packages").unwrap();
        let parts = Parts { packages: Ok(vec![pkg("a", "1"), pkg("d", "1")]), ..scan_parts() };
        let mut changed = pkg("b", "1");
        changed.publisher = Some("new".into());
        let parts = Parts { packages: parts.packages.map(|mut l| { l.push(changed); l }), ..parts };
        s.set_at("processes", 60);
        let ev = s.scan(false, parts, &["KB1", "KB3"]);
        assert_eq!((ev.len(), ev[0]["event_type"].as_str(), ev[0]["location"].as_str()), (1, Some("system_inventory_delta"), Some("syscollector/inventory")));
        let t = &ev[0]["tables"];
        let p = &t["packages"];
        assert_eq!(p["count"], 3);
        let names = |k: &str| p[k].as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!((names("added"), names("changed")), (vec!["d".to_string()], vec!["b".to_string()]));
        assert_eq!(p["removed"].as_array().unwrap().len(), 1, "c");
        assert!(was.values().any(|h| *h == p["removed"][0].as_str().unwrap()));
        assert!(was.values().any(|h| *h == p["changed"][0]["_was"].as_str().unwrap()));
        assert_eq!(p["changed"][0]["_h"].as_str().unwrap().len(), 40);
        // the updates, and the others only as counts and hashes
        assert_eq!((t["hotfixes"]["added"][0]["hotfix"].as_str(), t["hotfixes"]["removed"][0].as_str()), (Some("KB3"), Some(delta::short_hash("KB2").as_str())));
        assert_eq!(t["hardware"], json!({ "count": 1, "hash": t["hardware"]["hash"] }));
        assert!(t["services"]["count"] == 0 && t["os"]["count"] == 1);
        assert!(t.get("processes").is_none(), "their hour is not up");
        let names: Vec<String> = Sent::open(&s.0.state).unwrap().items("058", "packages").unwrap().keys().cloned().collect();
        assert_eq!(names.len(), 3, "saved");
    }

    #[test]
    fn inventory_processes_hourly_and_a_heartbeat_a_day() {
        let s = Sim::new();
        s.scan(false, scan_parts(), &[]);
        let more = || Parts { processes: Ok(vec![process(4, "System"), process(9, "svc"), process(77, "new")]), ..scan_parts() };
        assert!(s.scan(false, more(), &[]).is_empty(), "a process started: not before the hour is up");
        s.set_at("processes", PROCESSES_EVERY);
        let ev = s.scan(false, more(), &[]);
        assert_eq!(ev[0]["tables"]["processes"]["added"][0]["name"], "new");
        assert_eq!(ev[0]["tables"]["processes"]["count"], 3);
        assert!(s.scan(false, more(), &[]).is_empty(), "sent once");

        s.set_at("inventory", HEARTBEAT_EVERY - 100);
        assert!(s.scan(false, more(), &[]).is_empty());
        s.set_at("inventory", HEARTBEAT_EVERY);
        let beat = s.scan(false, more(), &[]);
        assert_eq!((beat.len(), beat[0]["event_type"].as_str()), (1, Some("system_inventory_delta")));
        assert_eq!((beat[0]["tables"]["packages"]["count"].as_u64(), beat[0]["tables"]["packages"].get("added")), (Some(3), None));
        assert!(serde_json::to_string(&beat[0]).unwrap().len() < 2500, "counts and hashes only");
        assert!(s.scan(false, more(), &[]).is_empty(), "the next a day later");
    }

    #[test]
    fn only_a_full_send_waits_its_splay() {
        let s = Sim::new();
        s.scan(false, scan_parts(), &[]);
        // a day-long splay: a change still goes at once
        let wide = Syscollector { splay: Some(86_400), state: s.0.state.clone(), agent_id: "058".into(), agent_name: "pc".into() };
        let t = std::time::Instant::now();
        let parts = Parts { packages: Ok(vec![pkg("a", "2")]), ..scan_parts() };
        wide.emit(&s.1, false, assemble("pc".into(), "windows".into(), "x86_64".into(), parts), os(), Vec::new());
        assert_eq!(s.1.drain_batch(10)[0]["event_type"], "system_inventory_delta");
        assert!(t.elapsed() < Duration::from_secs(5));
        // a full send with a splay of 2 s takes 0 to 2 s
        let short = Syscollector { splay: Some(2), ..wide };
        let t = std::time::Instant::now();
        short.emit(&s.1, true, assemble("pc".into(), "windows".into(), "x86_64".into(), scan_parts()), os(), Vec::new());
        assert!(t.elapsed() < Duration::from_secs(4));
        assert_eq!(s.1.drain_batch(10)[0]["event_type"], "system_inventory");
    }

    #[test]
    fn inventory_new_agent_id_sends_everything() {
        let s = Sim::new();
        s.scan(false, scan_parts(), &[]);
        let other = Syscollector { agent_id: "059".into(), agent_name: "pc".into(), state: s.0.state.clone(), splay: Some(0) };
        other.emit(&s.1, false, assemble("pc".into(), "windows".into(), "x86_64".into(), scan_parts()), os(), Vec::new());
        assert_eq!(s.1.drain_batch(10)[0]["event_type"], "system_inventory");
    }

    #[test]
    fn inventory_a_part_not_read_removes_nothing() {
        let s = Sim::new();
        s.scan(false, scan_parts(), &["KB1"]);
        let parts = Parts { packages: Err("registry not readable".into()), ..scan_parts() };
        assert!(s.scan(false, parts, &["KB1"]).is_empty(), "no list is not an empty list");
        // no OS name: the update list is not known either
        s.0.emit(&s.1, false, assemble("pc".into(), "windows".into(), "x86_64".into(), scan_parts()), json!({}), Vec::new());
        assert!(s.1.drain_batch(10).is_empty());
        assert_eq!(Sent::open(&s.0.state).unwrap().items("058", "packages").unwrap().len(), 3, "still what the manager has");
        assert_eq!(s.scan(false, Parts { packages: Ok(vec![pkg("a", "1")]), ..scan_parts() }, &["KB1"])[0]["tables"]["packages"]["removed"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn inventory_items_with_one_key_count_once_and_hash_is_order_free() {
        let inv = serde_json::to_value(assemble("pc".into(), "windows".into(), "x86_64".into(), Parts { packages: Ok(vec![pkg("a", "1"), pkg("a", "1"), pkg("", "1")]), ..scan_parts() })).unwrap();
        let t = delta::tables(&inv, &os(), &["KB1".to_string()]);
        assert_eq!(t.iter().find(|t| t.name == "packages").unwrap().items.len(), 1, "the same key once, no name none");
        let names: Vec<&str> = t.iter().map(|t| t.name).collect();
        assert_eq!(names, ["packages", "ports", "processes", "services", "users", "groups", "network", "browser_extensions", "hardware", "os", "hotfixes"]);
        assert_eq!(delta::table_hash(vec!["b".into(), "a".into()]), delta::table_hash(vec!["a".into(), "b".into()]));
    }

    /// What a scan sends on this machine, full and then as a change (read-only), for the sizes:
    /// `cargo test -p provigil-agent live_delta_sizes -- --ignored --nocapture`
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn live_delta_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let c = Syscollector { agent_id: "000".into(), agent_name: "live-test".into(), state: dir.path().join("sent.db"), splay: Some(0) };
        let b = EventBuffer::new(100);
        let size = |b: &EventBuffer| b.drain_batch(10).iter().map(|e| serde_json::to_string(e).unwrap().len()).sum::<usize>();
        c.scan_and_emit(&b, false);
        println!("full inventory: {} bytes", size(&b));
        c.scan_and_emit(&b, false);
        println!("scan right after, processes held back: {} bytes", size(&b));
        Sent::open(&c.state).unwrap().set_at("000", "processes", 0).unwrap();
        std::thread::sleep(Duration::from_secs(60));
        c.scan_and_emit(&b, false);
        println!("a minute later, with process changes: {} bytes", size(&b));
        Sent::open(&c.state).unwrap().set_at("000", "inventory", 0).unwrap();
        c.scan_and_emit(&b, false);
        println!("heartbeat: {} bytes", size(&b));

        let mut s = crate::sca::ScaScanner::new().with_state(dir.path().join("sent.db"), Some(0));
        let bytes = |ev: &[Value]| ev.iter().map(|e| serde_json::to_string(e).unwrap().len()).sum::<usize>();
        let ev = s.scan("000", "live-test");
        println!("configuration assessment, first: {} events, {} bytes", ev.len(), bytes(&ev));
        let ev = s.scan("000", "live-test");
        println!("configuration assessment, second: {} events, {} bytes", ev.len(), bytes(&ev));
    }

    fn raw(name: &str, version: &str, source: &str, arch: Option<&str>) -> RawPackage {
        RawPackage {
            display_name: Some(name.into()),
            version: Some(version.into()),
            source: source.into(),
            architecture: arch.map(Into::into),
            ..RawPackage::default()
        }
    }

    #[test]
    fn package_selection() {
        let list = vec![
            RawPackage { location: Some(r"C:\Program Files\7-Zip".into()), size_kb: Some(5000), ..raw("7-Zip", "23.01", "machine", Some("x64")) },
            raw("7-Zip", "23.01", "machine_x86", Some("x64")),
            raw("7-Zip", "23.01", "machine_x86", Some("x86")),
            raw("7-Zip", "22.00", "machine", Some("x64")),
            RawPackage { system_component: true, ..raw("Hidden runtime", "1.0", "machine", Some("x64")) },
            RawPackage { parent_key_name: Some("Office16.PROPLUS".into()), ..raw("Update for Office", "1", "machine", Some("x64")) },
            RawPackage { parent_key_name: Some("  ".into()), ..raw("Blank parent", "1", "machine", Some("x64")) },
            RawPackage { display_name: None, ..raw("", "1", "machine", None) },
            RawPackage { display_name: Some("   ".into()), ..raw("", "1", "machine", None) },
            RawPackage { user_sid: Some("S-1-5-21-1-2-3-1001".into()), ..raw("Zoom", "6.0", "user", None) },
        ];
        let got = select_packages(list);
        let keys: Vec<(&str, Option<&str>, &str)> =
            got.iter().map(|p| (p.name.as_str(), p.architecture.as_deref(), p.source.as_str())).collect();
        assert_eq!(
            keys,
            vec![
                ("7-Zip", Some("x64"), "machine"),
                ("7-Zip", Some("x86"), "machine_x86"),
                ("7-Zip", Some("x64"), "machine"),
                ("Blank parent", Some("x64"), "machine"),
                ("Zoom", None, "user"),
            ]
        );
        assert_eq!(got[0].size_bytes, Some(5000 * 1024));
        assert_eq!(got[0].location.as_deref(), Some(r"C:\Program Files\7-Zip"));
        assert_eq!(got[2].version.as_deref(), Some("22.00"));
        assert_eq!(got[4].user_sid.as_deref(), Some("S-1-5-21-1-2-3-1001"));
    }

    #[test]
    fn netmask_and_broadcast() {
        assert_eq!(netmask_v4(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(netmask_v4(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(netmask_v4(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(netmask_v4(20), Ipv4Addr::new(255, 255, 240, 0));
        assert_eq!(broadcast_v4(Ipv4Addr::new(192, 168, 1, 37), 24), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(broadcast_v4(Ipv4Addr::new(10, 1, 2, 3), 8), Ipv4Addr::new(10, 255, 255, 255));
        assert_eq!(broadcast_v4(Ipv4Addr::new(10, 1, 2, 3), 32), Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(netmask_v6(64).to_string(), "ffff:ffff:ffff:ffff::");
        assert_eq!(netmask_v6(0).to_string(), "::");
        let a = if_address("192.168.1.37".parse().unwrap(), Some(24));
        assert_eq!((a.netmask.as_deref(), a.broadcast.as_deref(), a.family.as_str()), (Some("255.255.255.0"), Some("192.168.1.255"), "ipv4"));
        let b = if_address("fe80::1".parse().unwrap(), Some(64));
        assert_eq!((b.netmask.as_deref(), b.broadcast, b.family.as_str()), (Some("ffff:ffff:ffff:ffff::"), None, "ipv6"));
    }

    #[test]
    fn tcp_state_names() {
        assert_eq!((tcp_state(2), tcp_state(5), tcp_state(11), tcp_state(99)), ("listening", "established", "time_wait", "unknown"));
    }

    #[test]
    fn board_serial_from_firmware_table() {
        // header, a type 1 structure, a type 2 (serial is string 2), the end structure
        let mut t = vec![0u8, 3, 4, 0, 0, 0, 0, 0];
        t.extend([1, 4, 0, 0]);
        t.extend(b"Sys\0\0");
        t.extend([2, 8, 1, 0, 1, 2, 3, 2]);
        t.extend(b"ACME\0B1\0SN-77 \0\0");
        t.extend([127, 4, 2, 0, 0, 0]);
        assert_eq!(board_serial_from_smbios(&t).as_deref(), Some("B1"));
        // serial index 3 -> "SN-77" (trimmed)
        let mut t3 = t.clone();
        t3[8 + 9 + 7] = 3;
        assert_eq!(board_serial_from_smbios(&t3).as_deref(), Some("SN-77"));
        // no serial / a placeholder
        let mut t0 = t.clone();
        t0[8 + 9 + 7] = 0;
        assert_eq!(board_serial_from_smbios(&t0), None);
        let mut tp = vec![0u8; 8];
        tp.extend([2, 8, 1, 0, 0, 0, 0, 1]);
        tp.extend(b"Default string\0\0");
        assert_eq!(board_serial_from_smbios(&tp), None);
    }

    #[test]
    fn chromium_and_firefox_extensions() {
        let home = tempfile::tempdir().unwrap();
        let ud = home.path().join("AppData").join("Local").join("Google").join("Chrome").join("User Data");
        // a localized name; two versions (the newest wins)
        let ext = ud.join("Default").join("Extensions").join("abcdefghijklmnop");
        for v in ["1.9.0_0", "1.10.0_0"] {
            let d = ext.join(v);
            std::fs::create_dir_all(d.join("_locales").join("en_US")).unwrap();
            std::fs::write(
                d.join("manifest.json"),
                format!("\u{feff}{{\"name\":\"__MSG_appName__\",\"version\":\"{}\",\"default_locale\":\"en_US\"}}", v.trim_end_matches("_0")),
            )
            .unwrap();
            std::fs::write(d.join("_locales").join("en_US").join("messages.json"), r#"{"APPNAME":{"message":"Password Helper"}}"#).unwrap();
        }
        // a plain name in another profile; and a folder without a manifest
        let plain = ud.join("Profile 1").join("Extensions").join("zzzz").join("2.0_0");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::write(plain.join("manifest.json"), r#"{"name":"Dark Reader","version":"2.0"}"#).unwrap();
        std::fs::create_dir_all(ud.join("Default").join("Extensions").join("Temp")).unwrap();

        let ff = home.path().join("AppData").join("Roaming").join("Mozilla").join("Firefox").join("Profiles").join("x1.default-release");
        std::fs::create_dir_all(&ff).unwrap();
        std::fs::write(
            ff.join("extensions.json"),
            r#"{"schemaVersion":36,"addons":[
                {"id":"uBlock0@raymondhill.net","version":"1.57.0","active":true,"defaultLocale":{"name":"uBlock Origin"}},
                {"id":"off@example.org","version":"0.1","active":false,"defaultLocale":{"name":"Turned Off"}}]}"#,
        )
        .unwrap();

        let got = browser_extensions_for(home.path(), "alice");
        assert_eq!(got.len(), 4);
        assert_eq!(
            got[0],
            BrowserExtension {
                browser: "chrome".into(),
                user: "alice".into(),
                profile: "Default".into(),
                id: "abcdefghijklmnop".into(),
                name: Some("Password Helper".into()),
                version: Some("1.10.0".into()),
                enabled: None,
            }
        );
        assert_eq!((got[1].profile.as_str(), got[1].name.as_deref()), ("Profile 1", Some("Dark Reader")));
        assert_eq!(
            (got[2].browser.as_str(), got[2].profile.as_str(), got[2].id.as_str(), got[2].name.as_deref(), got[2].enabled),
            ("firefox", "x1.default-release", "uBlock0@raymondhill.net", Some("uBlock Origin"), Some(true))
        );
        assert_eq!((got[3].version.as_deref(), got[3].enabled), (Some("0.1"), Some(false)));
    }

    #[test]
    fn unresolved_message_keeps_the_placeholder() {
        let d = tempfile::tempdir().unwrap();
        let m = json!({"name": "__MSG_missing__", "default_locale": "fr"});
        assert_eq!(chromium_name(&m, d.path()).as_deref(), Some("__MSG_missing__"));
    }

    #[test]
    fn python_npm_and_store_packages() {
        let d = tempfile::tempdir().unwrap();
        let site = d.path().join("site-packages");
        let dist = site.join("requests-2.31.0.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: Python HTTP for Humans.\nAuthor: Kenneth Reitz\nClassifier: x\n\nName: not-a-header\n",
        )
        .unwrap();
        std::fs::write(site.join("six-1.16.0.egg-info"), "Metadata-Version: 1.0\nName: six\nVersion: 1.16.0\nAuthor-email: b@example.org\n").unwrap();
        std::fs::create_dir_all(site.join("broken.dist-info")).unwrap();
        std::fs::create_dir_all(site.join("requests")).unwrap();
        let py = python_packages(&site, Some("S-1-5-21-1"));
        let got: Vec<_> = py.iter().map(|p| (p.name.as_str(), p.version.as_deref(), p.publisher.as_deref(), p.format.as_str())).collect();
        assert_eq!(got, vec![("requests", Some("2.31.0"), Some("Kenneth Reitz"), "pypi"), ("six", Some("1.16.0"), Some("b@example.org"), "pypi")]);
        assert_eq!((py[0].description.as_deref(), py[0].user_sid.as_deref()), (Some("Python HTTP for Humans."), Some("S-1-5-21-1")));
        assert_eq!(py[0].location.as_deref(), Some(dist.display().to_string().as_str()));

        let nm = d.path().join("node_modules");
        for (dir, json) in [
            ("typescript", r#"{"name":"typescript","version":"5.4.5","author":"Microsoft Corp.","description":"TypeScript"}"#),
            (r"@angular\cli", r#"{"name":"@angular/cli","version":"17.3.0","author":{"name":"Angular Authors"}}"#),
            ("nameless", r#"{"version":"1.0.0"}"#),
        ] {
            std::fs::create_dir_all(nm.join(dir)).unwrap();
            std::fs::write(nm.join(dir).join("package.json"), json).unwrap();
        }
        std::fs::create_dir_all(nm.join(".bin")).unwrap();
        let npm = npm_packages(&nm, None);
        let got: Vec<_> = npm.iter().map(|p| (p.name.as_str(), p.version.as_deref(), p.publisher.as_deref(), p.format.as_str())).collect();
        assert_eq!(got, vec![("@angular/cli", Some("17.3.0"), Some("Angular Authors"), "npm"), ("typescript", Some("5.4.5"), Some("Microsoft Corp."), "npm")]);

        let calc = appx_package("Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe").unwrap();
        assert_eq!(
            (calc.name.as_str(), calc.version.as_deref(), calc.architecture.as_deref(), calc.source.as_str(), calc.format.as_str()),
            ("Microsoft.WindowsCalculator", Some("11.2405.2.0"), Some("x64"), "appx", "win")
        );
        assert!(appx_package("5319275A.WhatsAppDesktop_2.2641.101.0_neutral_split.scale-100_cv1g1gvanyjgm").is_none());
        assert!(appx_package("4DF9E0F8.Netflix_7.0.8.0_neutral_~_mcm4njqhnhss8").is_none());
    }

    /// Counts per package and update source on this machine (Windows only):
    /// `cargo test -p provigil-agent live_sources -- --ignored --nocapture`
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn live_sources() {
        let profiles = sys::user_profiles().unwrap_or_default();
        let pk = sys::packages(&profiles).unwrap();
        for s in ["machine", "machine_x86", "user", "appx", "pypi", "npm"] {
            let of: Vec<_> = pk.iter().filter(|p| p.source == s).collect();
            println!("packages {s}: {}; e.g. {}", of.len(), of.first().map(|p| serde_json::to_string(p).unwrap()).unwrap_or_default());
        }
        let src = crate::osinfo::hotfix_sources();
        for (s, kbs) in &src {
            println!("hotfixes {s}: {}", kbs.len());
        }
        println!("hotfixes merged: {}", crate::osinfo::merge_hotfixes(&src).len());
    }

    /// A real scan of this machine (Windows only):
    /// `cargo test -p provigil-agent live_inventory -- --ignored --nocapture`
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn live_inventory() {
        let started = std::time::Instant::now();
        let inv = Syscollector::new("000".into(), "live-test".into(), None).collect_inventory();
        let size = serde_json::to_string(&inv).unwrap().len();
        println!("scan took {:?}; inventory_json is {size} bytes; errors: {:?}", started.elapsed(), inv.errors);
        println!("hardware: {}", serde_json::to_string(&inv.hardware).unwrap());
        fn show<T: Serialize>(label: &str, n: usize, example: Option<&T>) {
            let e = example.map(|x| serde_json::to_string(x).unwrap()).unwrap_or_else(|| "-".into());
            println!("{label}: {n}; e.g. {e}");
        }
        show("processes", inv.processes.len(), inv.processes.iter().find(|p| p.virtual_kb.is_some()));
        show("packages", inv.packages.len(), inv.packages.iter().find(|p| p.location.is_some()));
        let by_source = |s: &str| inv.packages.iter().filter(|p| p.source == s).count();
        println!("  packages by source: machine {}, machine_x86 {}, user {}", by_source("machine"), by_source("machine_x86"), by_source("user"));
        show("ports", inv.ports.len(), inv.ports.iter().find(|p| p.state.as_deref() == Some("listening")));
        println!("  listening summary: {} entries", inv.open_ports_count);
        show("network_interfaces", inv.network_interfaces.len(), inv.network_interfaces.iter().find(|a| a.gateway.is_some()).or(inv.network_interfaces.first()));
        show("services", inv.services.len(), inv.services.iter().find(|s| s.pid.is_some() && s.description.is_some()));
        show("users", inv.users.len(), inv.users.iter().find(|u| u.home.is_some()).or(inv.users.first()));
        show("groups", inv.groups.len(), inv.groups.iter().find(|g| g.sid.as_deref() == Some("S-1-5-32-544")));
        show("browser_extensions", inv.browser_extensions.len(), inv.browser_extensions.first());

        assert!(inv.ports.iter().any(|p| p.state.as_deref() == Some("listening") && p.pid > 0 && p.process.is_some()));
        assert!(inv.hardware.cpu_name.is_some());
        assert!(inv.users.iter().any(|u| u.sid.is_some()));
        // the Administrators group (its well-known SID; the name is localized)
        assert!(inv.groups.iter().any(|g| g.sid.as_deref() == Some("S-1-5-32-544")));
    }
}
