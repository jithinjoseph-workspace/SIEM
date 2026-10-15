use crate::buffer::AgentBuffer;
use serde::{Deserialize, Serialize};
use siem_core::{EventSource, RawEvent};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxSystemInventory {
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
}

fn get_str(m: &BTreeMap<Vec<u8>, siem_njson::Value>, key: &[u8]) -> Option<String> {
    match m.get(key) {
        Some(siem_njson::Value::Str(bytes)) => Some(String::from_utf8_lossy(bytes).to_string()),
        _ => None,
    }
}

fn get_int(m: &BTreeMap<Vec<u8>, siem_njson::Value>, key: &[u8]) -> Option<i64> {
    match m.get(key) {
        Some(siem_njson::Value::Int(i)) => Some(*i),
        Some(siem_njson::Value::UInt(u)) => Some(*u as i64),
        _ => None,
    }
}

fn get_uint(m: &BTreeMap<Vec<u8>, siem_njson::Value>, key: &[u8]) -> Option<u64> {
    match m.get(key) {
        Some(siem_njson::Value::UInt(u)) => Some(*u),
        Some(siem_njson::Value::Int(i)) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

pub struct LinuxSyscollector {
    _agent_id: String,
    provider: siem_sysinfo::linux::SysInfo,
}

impl LinuxSyscollector {
    pub fn new(agent_id: String) -> Self {
        Self {
            _agent_id: agent_id,
            provider: siem_sysinfo::linux::SysInfo::new(),
        }
    }

    /// Gather full Linux system hardware and software inventory (mirroring syscollector & data_provider)
    pub fn collect_inventory(&self) -> LinuxSystemInventory {
        // 1. Hardware & OS
        let (hostname, os, arch) = match self.provider.os() {
            Ok(siem_njson::Value::Object(map)) => {
                let h = get_str(&map, b"hostname").unwrap_or_else(|| "localhost".into());
                let o = get_str(&map, b"os_display_version")
                    .or_else(|| get_str(&map, b"os_name"))
                    .unwrap_or_else(|| "Linux".into());
                let a = get_str(&map, b"architecture")
                    .unwrap_or_else(|| std::env::consts::ARCH.to_string());
                (h, o, a)
            }
            _ => ("localhost".into(), "Linux".into(), std::env::consts::ARCH.to_string()),
        };

        let (cpu_cores, ram_mb) = match self.provider.hardware() {
            Ok(siem_njson::Value::Object(map)) => {
                let c = get_int(&map, b"cpu_cores").map(|i| i as usize).unwrap_or(4);
                let r = get_uint(&map, b"ram_total").map(|u| u / 1024).unwrap_or(8192);
                (c, r)
            }
            _ => (4, 8192),
        };

        // 2. Processes (native /proc scanning)
        let (running_processes_count, running_processes) = match self.provider.processes() {
            Ok(siem_njson::Value::Array(procs)) => {
                let count = procs.len();
                let samples = procs.iter().take(25).filter_map(|v| {
                    if let siem_njson::Value::Object(m) = v {
                        let pid = get_str(m, b"pid").unwrap_or_else(|| "?".into());
                        let name = get_str(m, b"name").unwrap_or_else(|| "unknown".into());
                        let user = get_str(m, b"ruser").unwrap_or_else(|| "root".into());
                        Some(format!("{} {} {}", pid, user, name))
                    } else {
                        None
                    }
                }).collect();
                (count, samples)
            }
            _ => (0, Vec::new()),
        };

        // 3. Listening Ports (native /proc/net scanning)
        let (open_ports_count, listening_ports) = match self.provider.ports() {
            Ok(siem_njson::Value::Array(ports)) => {
                let count = ports.len();
                let samples = ports.iter().take(25).filter_map(|v| {
                    if let siem_njson::Value::Object(m) = v {
                        let proto = get_str(m, b"protocol").unwrap_or_else(|| "tcp".into());
                        let ip = get_str(m, b"local_ip").unwrap_or_else(|| "0.0.0.0".into());
                        let port = get_int(m, b"local_port").unwrap_or(0);
                        let proc = get_str(m, b"process").unwrap_or_else(|| "-".into());
                        Some(format!("{} {}:{} ({})", proto, ip, port, proc))
                    } else {
                        None
                    }
                }).collect();
                (count, samples)
            }
            _ => (0, Vec::new()),
        };

        // 4. Installed Packages (native /var/lib/dpkg/status & RPM parsing)
        let (installed_packages_count, installed_software) = match self.provider.packages() {
            Ok(siem_njson::Value::Array(pkgs)) => {
                let count = pkgs.len();
                let samples = pkgs.iter().take(30).filter_map(|v| {
                    if let siem_njson::Value::Object(m) = v {
                        let name = get_str(m, b"name").unwrap_or_default();
                        let ver = get_str(m, b"version").unwrap_or_default();
                        if !name.is_empty() {
                            Some(format!("{} ({})", name, ver))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }).collect();
                (count, samples)
            }
            _ => (0, Vec::new()),
        };

        // 5. Services
        let (services_count, active_services) = match self.provider.services() {
            Ok(siem_njson::Value::Array(srvs)) => {
                let count = srvs.len();
                let samples = srvs.iter().take(20).filter_map(|v| {
                    if let siem_njson::Value::Object(m) = v {
                        get_str(m, b"name")
                    } else {
                        None
                    }
                }).collect();
                (count, samples)
            }
            _ => (0, Vec::new()),
        };

        // 6. Users
        let (users_count, local_users) = match self.provider.users() {
            Ok(siem_njson::Value::Array(us)) => {
                let count = us.len();
                let samples = us.iter().take(20).filter_map(|v| {
                    if let siem_njson::Value::Object(m) = v {
                        get_str(m, b"user_name")
                    } else {
                        None
                    }
                }).collect();
                (count, samples)
            }
            _ => (0, Vec::new()),
        };

        // 7. Network Adapters
        let network_adapters = match self.provider.networks() {
            Ok(siem_njson::Value::Array(nets)) => {
                nets.iter().filter_map(|v| {
                    if let siem_njson::Value::Object(m) = v {
                        let name = get_str(m, b"name").unwrap_or_default();
                        let mac = get_str(m, b"mac").unwrap_or_default();
                        let state = get_str(m, b"state").unwrap_or_default();
                        Some(format!("{}: MAC={} State={}", name, mac, state))
                    } else {
                        None
                    }
                }).collect()
            }
            _ => Vec::new(),
        };

        LinuxSystemInventory {
            hostname,
            os,
            arch,
            cpu_cores,
            ram_mb,
            running_processes_count,
            open_ports_count,
            installed_packages_count,
            services_count,
            users_count,
            listening_ports,
            running_processes,
            installed_software,
            active_services,
            local_users,
            network_adapters,
        }
    }
}

/// Spawns the Linux Syscollector worker task
pub fn spawn_syscollector_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let collector = LinuxSyscollector::new(agent_id.clone());

        // Initial inventory publication immediately at boot
        let inv = collector.collect_inventory();
        info!(
            "wazuh-syscollector: Inventory collected (Host: {}, OS: {}, Cores: {}, RAM: {}MB, Packages: {}, Ports: {}, Procs: {})",
            inv.hostname, inv.os, inv.cpu_cores, inv.ram_mb, inv.installed_packages_count, inv.open_ports_count, inv.running_processes_count
        );

        let msg = format!(
            "syscollector: System inventory scan complete. Host: {}, OS: {}, CPU Cores: {}, RAM: {} MB, Installed Packages: {}, Running Processes: {}, Listening Ports: {}",
            inv.hostname, inv.os, inv.cpu_cores, inv.ram_mb, inv.installed_packages_count, inv.running_processes_count, inv.open_ports_count
        );

        let mut event = RawEvent::new(&agent_id, EventSource::Syscollector, "syscollector/inventory", msg);
        event.metadata.insert("hostname".into(), inv.hostname.clone());
        event.metadata.insert("os".into(), inv.os.clone());
        event.metadata.insert("architecture".into(), inv.arch.clone());
        event.metadata.insert("cpu_cores".into(), inv.cpu_cores.to_string());
        event.metadata.insert("ram_mb".into(), inv.ram_mb.to_string());
        event.metadata.insert("processes_count".into(), inv.running_processes_count.to_string());
        event.metadata.insert("ports_count".into(), inv.open_ports_count.to_string());
        event.metadata.insert("packages_count".into(), inv.installed_packages_count.to_string());
        event.metadata.insert("os_type".into(), "linux".into());

        if let Ok(json_str) = serde_json::to_string(&inv) {
            event.metadata.insert("inventory_json".into(), json_str);
        }

        buffer.push(event).await;

        // Periodic resync loop (default every 300s / 5min)
        loop {
            tokio::time::sleep(interval).await;

            let updated_inv = collector.collect_inventory();
            let update_msg = format!(
                "syscollector: Delta sync completed. Tracking {} installed packages, {} active processes, {} open sockets",
                updated_inv.installed_packages_count, updated_inv.running_processes_count, updated_inv.open_ports_count
            );
            info!("{}", update_msg);

            let mut update_event = RawEvent::new(&agent_id, EventSource::Syscollector, "syscollector/delta", update_msg);
            update_event.metadata.insert("processes_count".into(), updated_inv.running_processes_count.to_string());
            update_event.metadata.insert("ports_count".into(), updated_inv.open_ports_count.to_string());
            update_event.metadata.insert("packages_count".into(), updated_inv.installed_packages_count.to_string());
            update_event.metadata.insert("os_type".into(), "linux".into());

            if let Ok(json_str) = serde_json::to_string(&updated_inv) {
                update_event.metadata.insert("inventory_json".into(), json_str);
            }

            buffer.push(update_event).await;
        }
    })
}

/// Explicit on-demand inventory emission (called e.g. from active response commands)
pub async fn emit_inventory(agent_id: &str, buffer: &AgentBuffer) {
    let collector = LinuxSyscollector::new(agent_id.to_string());
    let inv = collector.collect_inventory();

    let msg = format!(
        "syscollector: On-demand inventory scan triggered. Host: {}, Packages: {}, Processes: {}, Ports: {}",
        inv.hostname, inv.installed_packages_count, inv.running_processes_count, inv.open_ports_count
    );
    info!("{}", msg);

    let mut event = RawEvent::new(agent_id, EventSource::Syscollector, "syscollector/inventory", msg);
    event.metadata.insert("hostname".into(), inv.hostname.clone());
    event.metadata.insert("os".into(), inv.os.clone());
    event.metadata.insert("packages_count".into(), inv.installed_packages_count.to_string());
    event.metadata.insert("processes_count".into(), inv.running_processes_count.to_string());
    event.metadata.insert("ports_count".into(), inv.open_ports_count.to_string());
    event.metadata.insert("os_type".into(), "linux".into());

    if let Ok(json_str) = serde_json::to_string(&inv) {
        event.metadata.insert("inventory_json".into(), json_str);
    }

    buffer.push(event).await;
}
