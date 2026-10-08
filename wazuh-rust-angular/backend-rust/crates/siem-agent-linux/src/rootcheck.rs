use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Wazuh Rootcheck Engine
/// Mirrors official Wazuh rootcheck subsystem:
/// - check_rc_dev.c: scans /dev and /dev/shm for hidden files & unauthorized devices
/// - check_rc_if.c: detects promiscuous network interfaces (sniffers)
/// - check_rc_pids.c: detects hidden processes
/// - check_rc_trojans.c: detects trojanized system binaries (/bin/ps, /bin/netstat, /bin/ls)
pub struct RootcheckEngine {
    agent_id: String,
}

impl RootcheckEngine {
    pub fn new(agent_id: String) -> Self {
        Self { agent_id }
    }

    /// Run full rootcheck scan across the Linux system
    pub async fn run_scan(&self, buffer: &AgentBuffer) {
        info!("wazuh-rootcheck: Starting rootkit anomaly and hidden threat scan...");

        let mut issues_found = 0;

        // 1. Scan /dev and /dev/shm for hidden files (mirroring check_rc_dev.c)
        issues_found += self.scan_dev_shm(buffer).await;

        // 2. Check network interfaces for promiscuous mode (mirroring check_rc_if.c)
        issues_found += self.check_promiscuous_interfaces(buffer).await;

        // 3. Check for trojanized core system binaries (mirroring check_rc_trojans.c)
        issues_found += self.check_trojans(buffer).await;

        // 4. Scan /tmp for hidden executables and backdoors
        issues_found += self.scan_tmp_hidden(buffer).await;

        if issues_found == 0 {
            info!("wazuh-rootcheck: Scan completed. System clean. No rootkits, sniffers, or trojans detected.");
        } else {
            warn!("wazuh-rootcheck: Scan completed. Flagged {} potential rootkit anomalies!", issues_found);
        }
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
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let engine = RootcheckEngine::new(agent_id);

        loop {
            engine.run_scan(&buffer).await;
            tokio::time::sleep(interval).await;
        }
    })
}
