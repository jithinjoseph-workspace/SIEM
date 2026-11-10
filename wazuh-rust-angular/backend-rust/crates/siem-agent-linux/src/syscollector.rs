use crate::buffer::AgentBuffer;
use serde::{Deserialize, Serialize};
use siem_core::{EventSource, RawEvent};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::Command;
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

pub struct LinuxSyscollector {
    _agent_id: String,
}

impl LinuxSyscollector {
    pub fn new(agent_id: String) -> Self {
        Self { _agent_id: agent_id }
    }

    /// Gather full Linux system hardware and software inventory (mirroring syscollector)
    pub fn collect_inventory(&self) -> LinuxSystemInventory {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| {
                std::fs::read_to_string("/etc/hostname")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "localhost".into())
            });

        let os = "Linux".to_string();
        let arch = std::env::consts::ARCH.to_string();
        let cpu_cores = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        let ram_mb = self.collect_ram_mb();

        let (running_processes_count, running_processes) = self.collect_processes();
        let (open_ports_count, listening_ports) = self.collect_listening_ports();
        let (installed_packages_count, installed_software) = self.collect_packages();
        let (services_count, active_services) = self.collect_services();
        let (users_count, local_users) = self.collect_users();
        let network_adapters = self.collect_network_adapters();

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

    fn collect_ram_mb(&self) -> u64 {
        if let Ok(file) = File::open("/proc/meminfo") {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if line.starts_with("MemTotal:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<u64>() {
                            return kb / 1024;
                        }
                    }
                }
            }
        }
        8192
    }

    fn collect_processes(&self) -> (usize, Vec<String>) {
        if let Ok(output) = Command::new("ps").args(["-eo", "pid,user,comm"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut procs = Vec::new();
                let mut count = 0;
                for line in text.lines().skip(1) {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        count += 1;
                        if procs.len() < 25 {
                            procs.push(trimmed.to_string());
                        }
                    }
                }
                if count > 0 {
                    return (count, procs);
                }
            }
        }

        // Direct /proc scan fallback (no ps binary required)
        if let Ok(entries) = std::fs::read_dir("/proc") {
            let mut procs = Vec::new();
            let mut count = 0;
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if file_name.chars().all(|c| c.is_ascii_digit()) {
                        count += 1;
                        if procs.len() < 25 {
                            let comm_path = entry.path().join("comm");
                            let name = std::fs::read_to_string(&comm_path)
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            procs.push(format!("{file_name} {name}"));
                        }
                    }
                }
            }
            if count > 0 {
                return (count, procs);
            }
        }

        (0, Vec::new())
    }

    fn collect_listening_ports(&self) -> (usize, Vec<String>) {
        if let Ok(output) = Command::new("ss").args(["-tulpn"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut ports = Vec::new();
                let mut count = 0;
                for line in text.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        count += 1;
                        if ports.len() < 20 {
                            ports.push(format!("{} -> {}", parts[0], parts[4]));
                        }
                    }
                }
                if count > 0 {
                    return (count, ports);
                }
            }
        }

        // Direct /proc/net/tcp and /proc/net/tcp6 scan (no ss binary required)
        let mut ports = Vec::new();
        let mut count = 0;
        for net_file in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(file) = File::open(net_file) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // "0A" indicates TCP_LISTEN in Linux kernel /proc/net/tcp
                    if parts.len() >= 4 && parts[3] == "0A" {
                        count += 1;
                        if ports.len() < 20 {
                            if let Some(port_hex) = parts[1].split(':').nth(1) {
                                if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                    ports.push(format!("tcp:{}", port));
                                }
                            }
                        }
                    }
                }
            }
        }
        if count > 0 {
            return (count, ports);
        }

        (0, Vec::new())
    }

    fn collect_packages(&self) -> (usize, Vec<String>) {
        // 1. Try dpkg on Debian/Ubuntu
        if let Ok(output) = Command::new("dpkg-query").args(["-W", "-f=${binary:Package} ${Version}\n"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut pkgs = Vec::new();
                let mut count = 0;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        count += 1;
                        if pkgs.len() < 25 {
                            pkgs.push(trimmed.to_string());
                        }
                    }
                }
                if count > 0 {
                    return (count, pkgs);
                }
            }
        }

        // 2. Try rpm on RHEL/CentOS/Rocky/Fedora
        if let Ok(output) = Command::new("rpm").args(["-qa", "--qf", "%{NAME}-%{VERSION}\n"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut pkgs = Vec::new();
                let mut count = 0;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        count += 1;
                        if pkgs.len() < 25 {
                            pkgs.push(trimmed.to_string());
                        }
                    }
                }
                if count > 0 {
                    return (count, pkgs);
                }
            }
        }

        // 3. Try apk on Alpine Linux
        if let Ok(output) = Command::new("apk").args(["info", "-v"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut pkgs = Vec::new();
                let mut count = 0;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        count += 1;
                        if pkgs.len() < 25 {
                            pkgs.push(trimmed.to_string());
                        }
                    }
                }
                if count > 0 {
                    return (count, pkgs);
                }
            }
        }

        // 4. Try pacman on Arch Linux
        if let Ok(output) = Command::new("pacman").args(["-Q"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut pkgs = Vec::new();
                let mut count = 0;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        count += 1;
                        if pkgs.len() < 25 {
                            pkgs.push(trimmed.to_string());
                        }
                    }
                }
                if count > 0 {
                    return (count, pkgs);
                }
            }
        }

        (0, Vec::new())
    }

    fn collect_services(&self) -> (usize, Vec<String>) {
        if let Ok(output) = Command::new("systemctl").args(["list-unit-files", "--type=service", "--state=enabled,active"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut svcs = Vec::new();
                let mut count = 0;
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && parts[0].ends_with(".service") {
                        count += 1;
                        if svcs.len() < 20 {
                            svcs.push(format!("{} ({})", parts[0], parts[1]));
                        }
                    }
                }
                if count > 0 {
                    return (count, svcs);
                }
            }
        }

        // Fallback for non-systemd init (/etc/init.d/)
        if let Ok(entries) = std::fs::read_dir("/etc/init.d") {
            let mut svcs = Vec::new();
            let mut count = 0;
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    count += 1;
                    if svcs.len() < 20 {
                        svcs.push(name);
                    }
                }
            }
            if count > 0 {
                return (count, svcs);
            }
        }

        (0, Vec::new())
    }

    fn collect_users(&self) -> (usize, Vec<String>) {
        if let Ok(file) = File::open("/etc/passwd") {
            let reader = BufReader::new(file);
            let mut users = Vec::new();
            let mut count = 0;
            for line in reader.lines().flatten() {
                let parts: Vec<&str> = line.split(':').collect();
                if !parts.is_empty() && !parts[0].is_empty() {
                    count += 1;
                    if users.len() < 20 {
                        users.push(parts[0].to_string());
                    }
                }
            }
            if count > 0 {
                return (count, users);
            }
        }
        (0, Vec::new())
    }

    fn collect_network_adapters(&self) -> Vec<String> {
        if let Ok(output) = Command::new("ip").args(["-o", "addr"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut adapters = Vec::new();
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        adapters.push(format!("{}: {}", parts[1], parts[3]));
                    }
                }
                if !adapters.is_empty() {
                    return adapters;
                }
            }
        }

        // Direct /sys/class/net lookup
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

/// Collects the inventory once and sends it to the manager.
pub async fn emit_inventory(agent_id: &str, buffer: &AgentBuffer) {
    let collector = LinuxSyscollector::new(agent_id.to_string());
    {
        {
            let inv = collector.collect_inventory();
            let summary = format!(
                "syscollector: System Inventory: Hostname: '{}', OS: '{}' ({}), CPU Cores: {}, RAM: {} MB, Active Procs: {}, Open Ports: {}, Installed Packages: {}, Services: {}",
                inv.hostname, inv.os, inv.arch, inv.cpu_cores, inv.ram_mb, inv.running_processes_count, inv.open_ports_count, inv.installed_packages_count, inv.services_count
            );
            info!("{}", summary);

            let mut event = RawEvent::new(agent_id, EventSource::Syscollector, "syscollector/inventory", summary);
            event.metadata.insert("hostname".into(), inv.hostname.clone());
            event.metadata.insert("os_type".into(), "linux".into());
            event.metadata.insert("ram_mb".into(), inv.ram_mb.to_string());
            event.metadata.insert("cpu_cores".into(), inv.cpu_cores.to_string());
            event.metadata.insert("processes_count".into(), inv.running_processes_count.to_string());
            event.metadata.insert("ports_count".into(), inv.open_ports_count.to_string());
            event.metadata.insert("packages_count".into(), inv.installed_packages_count.to_string());

            if let Ok(json_details) = serde_json::to_string(&inv) {
                event.metadata.insert("inventory_json".into(), json_details);
            }

            buffer.push(event).await;
        }
    }
}
