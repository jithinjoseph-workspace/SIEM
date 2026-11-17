use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// ProVigil Linux Rootcheck Engine
/// Scans `/dev` and `/dev/shm`, detects promiscuous interfaces, checks core system binaries, and inspects `/tmp`.
pub struct RootcheckEngine {
    agent_id: String,
}

impl RootcheckEngine {
    pub fn new(agent_id: String) -> Self {
        Self { agent_id }
    }

    /// Run rootcheck anomaly scan across the Linux host.
    pub async fn run_scan(&self, buffer: &AgentBuffer) {
        info!("provigil-rootcheck: Starting rootkit anomaly and hidden threat scan...");

        let mut issues_found = 0;

        issues_found += self.scan_dev_shm(buffer).await;
        issues_found += self.check_promiscuous_interfaces(buffer).await;
        issues_found += self.check_trojans(buffer).await;
        issues_found += self.scan_tmp_hidden(buffer).await;
        issues_found += self.check_hidden_kernel_modules(buffer).await;
        issues_found += self.check_hidden_processes(buffer).await;
        issues_found += self.check_ld_preload_hijack(buffer).await;

        if issues_found == 0 {
            info!("provigil-rootcheck: Scan completed. System clean. No rootkits, sniffers, or trojans detected.");
        } else {
            warn!("provigil-rootcheck: Scan completed. Flagged {} potential rootkit anomalies!", issues_found);
        }
    }

    /// Detects hidden Loadable Kernel Modules (LKM rootkits) by cross-referencing /proc/modules and /sys/module/
    pub async fn check_hidden_kernel_modules(&self, buffer: &AgentBuffer) -> usize {
        let mut count = 0;
        let proc_modules = Path::new("/proc/modules");
        let sys_modules = Path::new("/sys/module");

        if !proc_modules.exists() || !sys_modules.exists() {
            return 0;
        }

        let mut visible_modules = std::collections::HashSet::new();
        if let Ok(content) = fs::read_to_string(proc_modules) {
            for line in content.lines() {
                if let Some(name) = line.split_whitespace().next() {
                    visible_modules.insert(name.replace('-', "_"));
                }
            }
        }

        if let Ok(entries) = fs::read_dir(sys_modules) {
            for entry in entries.flatten() {
                let mod_name = entry.file_name().to_string_lossy().replace('-', "_");
                let mod_path = entry.path();

                let is_lkm = mod_path.join("initstate").exists() || mod_path.join("sections").exists();
                if is_lkm && !visible_modules.contains(&mod_name) {
                    count += 1;
                    let msg = format!(
                        "rootcheck: HIDDEN KERNEL MODULE DETECTED! Module '{}' present in sysfs (/sys/module/{}) but hidden from /proc/modules (LKM Rootkit behavior)",
                        mod_name, mod_name
                    );
                    warn!("{}", msg);

                    let mut event = RawEvent::new(&self.agent_id, EventSource::Custom("rootcheck".into()), "rootcheck/kernel-rootkit", msg);
                    event.metadata.insert("category".into(), "hidden_kernel_module".into());
                    event.metadata.insert("module_name".into(), mod_name);
                    event.metadata.insert("os_type".into(), "linux".into());
                    event.metadata.insert("severity".into(), "critical".into());
                    buffer.push(event).await;
                }
            }
        }

        count
    }

    /// Detects hidden processes by comparing direct syscall probes against /proc directory enumeration
    pub async fn check_hidden_processes(&self, buffer: &AgentBuffer) -> usize {
        #[allow(unused_mut)]
        let mut count = 0;

        let proc_pids: std::collections::HashSet<u32> = fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .collect();

        #[cfg(not(unix))]
        {
            let _ = buffer;
            let _ = proc_pids;
        }

        #[cfg(unix)]
        {
            let max_pid = fs::read_to_string("/proc/sys/kernel/pid_max")
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(32768)
                .min(65536);

            for pid in 2..max_pid {
                let exists = unsafe {
                    let ret = libc::kill(pid as libc::pid_t, 0);
                    ret == 0 || (ret == -1 && *libc::__errno_location() == libc::EPERM)
                };

                if exists && !proc_pids.contains(&pid) {
                    count += 1;
                    let msg = format!(
                        "rootcheck: HIDDEN PROCESS DETECTED! PID {} responds to syscalls but is unlinked from /proc enumeration (Process Hiding Rootkit)",
                        pid
                    );
                    warn!("{}", msg);

                    let mut event = RawEvent::new(&self.agent_id, EventSource::Custom("rootcheck".into()), "rootcheck/hidden-process", msg);
                    event.metadata.insert("category".into(), "hidden_process".into());
                    event.metadata.insert("hidden_pid".into(), pid.to_string());
                    event.metadata.insert("os_type".into(), "linux".into());
                    event.metadata.insert("severity".into(), "critical".into());
                    buffer.push(event).await;

                    if count >= 20 {
                        break;
                    }
                }
            }
        }

        count
    }

    /// Checks /etc/ld.so.preload and environment for shared library hijacking
    pub async fn check_ld_preload_hijack(&self, buffer: &AgentBuffer) -> usize {
        let mut count = 0;
        let preload_file = Path::new("/etc/ld.so.preload");

        if preload_file.exists() {
            if let Ok(content) = fs::read_to_string(preload_file) {
                let trimmed = content.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    for line in trimmed.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        count += 1;
                        let msg = format!(
                            "rootcheck: SYSTEM LIBRARY HIJACKING DETECTED! /etc/ld.so.preload contains active preload library: '{}'",
                            line
                        );
                        warn!("{}", msg);

                        let mut event = RawEvent::new(&self.agent_id, EventSource::Custom("rootcheck".into()), "rootcheck/ld-preload-hijack", msg);
                        event.metadata.insert("category".into(), "dynamic_linker_hijacking".into());
                        event.metadata.insert("preload_target".into(), line.to_string());
                        event.metadata.insert("os_type".into(), "linux".into());
                        event.metadata.insert("severity".into(), "high".into());
                        buffer.push(event).await;
                    }
                }
            }
        }

        count
    }

    /// Scans /dev and /dev/shm for hidden files (files starting with a dot or suspicious ELF binaries)
    async fn scan_dev_shm(&self, buffer: &AgentBuffer) -> usize {
        let mut count = 0;
        let dev_targets = ["/dev", "/dev/shm", "/run/shm"];

        for dir in dev_targets {
            let p = Path::new(dir);
            if !p.exists() {
                continue;
            }

            if let Ok(entries) = fs::read_dir(p) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    let file_path = entry.path();

                    // Rootkit files in /dev often start with a dot or masquerade as innocent devices
                    if file_name.starts_with('.') && file_name != "." && file_name != ".." {
                        // Whitelist legitimate system entries
                        if file_name == ".udev" || file_name == ".initramfs" {
                            continue;
                        }

                        count += 1;
                        let msg = format!(
                            "rootcheck: Rootkit artifact detected: Hidden file '{}' located in device filesystem '{}'",
                            file_name, dir
                        );
                        warn!("{}", msg);

                        let mut event = RawEvent::new(&self.agent_id, EventSource::Custom("rootcheck".into()), "rootcheck/dev-hidden", msg);
                        event.metadata.insert("category".into(), "rootkit_dev_hidden".into());
                        event.metadata.insert("file_path".into(), file_path.to_string_lossy().to_string());
                        event.metadata.insert("os_type".into(), "linux".into());
                        buffer.push(event).await;
                    }

                    // Check if /dev/shm contains executable files (common shared-memory dropper)
                    if dir.contains("shm") && file_path.is_file() {
                        #[allow(unused_mut)]
                        let mut is_executable = false;

                        #[cfg(unix)]
                        {
                            if let Ok(meta) = file_path.metadata() {
                                use std::os::unix::fs::PermissionsExt;
                                if meta.permissions().mode() & 0o111 != 0 {
                                    is_executable = true;
                                }
                            }
                        }

                        if is_executable {
                            count += 1;
                            let msg = format!(
                                "rootcheck: Suspicious executable payload detected in shared memory: '{}'",
                                file_path.display()
                            );
                            warn!("{}", msg);

                            let mut event = RawEvent::new(&self.agent_id, EventSource::Custom("rootcheck".into()), "rootcheck/shm-executable", msg);
                            event.metadata.insert("category".into(), "rootkit_shm_exec".into());
                            event.metadata.insert("file_path".into(), file_path.to_string_lossy().to_string());
                            event.metadata.insert("os_type".into(), "linux".into());
                            buffer.push(event).await;
                        }
                    }
                }
            }
        }
        count
    }

    /// Check if any network interface is in promiscuous mode (indicating packet sniffing / tcpdump / rogue sniffer)
    async fn check_promiscuous_interfaces(&self, buffer: &AgentBuffer) -> usize {
        let mut count = 0;
        let net_dir = Path::new("/sys/class/net");
        if !net_dir.exists() {
            return 0;
        }

        if let Ok(entries) = fs::read_dir(net_dir) {
            for entry in entries.flatten() {
                let iface_name = entry.file_name().to_string_lossy().to_string();
                let flags_path = entry.path().join("flags");

                if flags_path.exists() {
                    if let Ok(content) = fs::read_to_string(&flags_path) {
                        let trimmed = content.trim();
                        // Flags are written in hex (e.g. 0x1103)
                        let parsed = if trimmed.starts_with("0x") {
                            u32::from_str_radix(trimmed.trim_start_matches("0x"), 16).ok()
                        } else {
                            trimmed.parse::<u32>().ok()
                        };

                        if let Some(flags) = parsed {
                            // IFF_PROMISC = 0x100 (256 in decimal)
                            if (flags & 0x100) != 0 {
                                count += 1;
                                let msg = format!(
                                    "rootcheck: Promiscuous network interface detected: Interface '{}' is running in PROMISC mode (Sniffer / MITM risk) [Flags: {}]",
                                    iface_name, trimmed
                                );
                                warn!("{}", msg);

                                let mut event = RawEvent::new(&self.agent_id, EventSource::Custom("rootcheck".into()), "rootcheck/promisc-iface", msg);
                                event.metadata.insert("category".into(), "sniffer_promisc".into());
                                event.metadata.insert("interface".into(), iface_name);
                                event.metadata.insert("os_type".into(), "linux".into());
                                buffer.push(event).await;
                            }
                        }
                    }
                }
            }
        }
        count
    }

    /// Check for trojanized core binaries (e.g. symlinks or modified scripts replacing /bin/ps, /bin/netstat, /bin/ls)
    async fn check_trojans(&self, buffer: &AgentBuffer) -> usize {
        let mut count = 0;
        let critical_binaries = [
            "/bin/ps",
            "/usr/bin/ps",
            "/bin/netstat",
            "/usr/bin/netstat",
            "/bin/ss",
            "/usr/bin/ss",
            "/bin/ls",
            "/usr/bin/ls",
            "/bin/login",
            "/usr/bin/login",
            "/usr/sbin/sshd",
        ];

        for bin in critical_binaries {
            let p = Path::new(bin);
            if p.exists() {
                // If a critical system binary is a shell script instead of an ELF binary, flag trojan
                if let Ok(mut f) = fs::File::open(p) {
                    use std::io::Read;
                    let mut magic = [0u8; 4];
                    if f.read_exact(&mut magic).is_ok() {
                        // ELF magic is 0x7F 'E' 'L' 'F'
                        if magic[0] != 0x7f || magic[1] != b'E' || magic[2] != b'L' || magic[3] != b'F' {
                            count += 1;
                            let msg = format!(
                                "rootcheck: Trojan anomaly detected: Core binary '{}' does not have valid ELF header (potential shell wrapper or backdoor rootkit)",
                                bin
                            );
                            warn!("{}", msg);

                            let mut event = RawEvent::new(&self.agent_id, EventSource::Custom("rootcheck".into()), "rootcheck/trojan-binary", msg);
                            event.metadata.insert("category".into(), "trojan_binary".into());
                            event.metadata.insert("target_binary".into(), bin.to_string());
                            event.metadata.insert("os_type".into(), "linux".into());
                            buffer.push(event).await;
                        }
                    }
                }
            }
        }
        count
    }

    /// Scan /tmp for hidden directories or suspicious dropper scripts
    async fn scan_tmp_hidden(&self, buffer: &AgentBuffer) -> usize {
        let mut count = 0;
        let tmp_dir = Path::new("/tmp");
        if let Ok(entries) = fs::read_dir(tmp_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') && name != "." && name != ".." {
                    if name.starts_with(".X11") || name.starts_with(".ICE") || name.starts_with(".font") {
                        continue; // Whitelist desktop display sockets
                    }

                    count += 1;
                    let msg = format!(
                        "rootcheck: Hidden entry detected in /tmp directory: '{}'",
                        entry.path().display()
                    );
                    info!("{}", msg);

                    let mut event = RawEvent::new(&self.agent_id, EventSource::Custom("rootcheck".into()), "rootcheck/tmp-hidden", msg);
                    event.metadata.insert("category".into(), "tmp_hidden_file".into());
                    event.metadata.insert("file_path".into(), entry.path().to_string_lossy().to_string());
                    event.metadata.insert("os_type".into(), "linux".into());
                    buffer.push(event).await;
                }
            }
        }
        count
    }
}

/// Spawns the Linux Rootcheck background worker running periodic rootkit assessments
pub fn spawn_rootcheck_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let engine = RootcheckEngine::new(agent_id);

        loop {
            tokio::time::sleep(interval).await;
            if lifecycle.is_terminated() {
                break;
            }
            if !lifecycle.is_active() {
                continue;
            }
            engine.run_scan(&buffer).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rootcheck_engine_initialization() {
        let engine = RootcheckEngine::new("agent-rk-test".into());
        let (buf, _) = AgentBuffer::new(
            "http://127.0.0.1:8088".into(),
            100,
            100,
            Arc::new(crate::lifecycle::LifecycleCoordinator::new("agent-rk-test".into(), "http://127.0.0.1:8088".into())),
        );
        // Clean environment should execute scan safely
        engine.run_scan(&buf).await;
    }
}
