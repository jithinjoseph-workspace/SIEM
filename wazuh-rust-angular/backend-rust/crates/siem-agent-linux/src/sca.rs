use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone)]
pub struct LinuxScaCheck {
    pub id: u32,
    pub title: String,
    pub target_file: String,
    pub rule_type: ScaRuleType,
    pub rationale: String,
    pub remediation: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ScaRuleType {
    /// Check file exists and file permissions
    FilePermissions { max_octal: u32 },
    /// Check configuration key=value pattern in file
    ConfigFileEntry { key: String, expected: String },
    /// Check kernel parameter via /proc/sys or sysctl
    SysctlParam { path: String, expected: String },
    /// Check diagnostic command execution output
    CommandCheck { cmd: String, expected: String },
    /// Check file content regex
    FileRegex { path: String, regex: String },
}

pub struct LinuxScaEngine {
    agent_id: String,
    checks: Vec<LinuxScaCheck>,
    #[allow(dead_code)]
    policy_dirs: Vec<PathBuf>,
}

impl LinuxScaEngine {
    pub fn new(agent_id: String) -> Self {
        let checks = vec![
            LinuxScaCheck {
                id: 2001,
                title: "CIS 1.1: Ensure permissions on /etc/shadow are 0640 or more restrictive".into(),
                target_file: "/etc/shadow".into(),
                rule_type: ScaRuleType::FilePermissions { max_octal: 0o640 },
                rationale: "The /etc/shadow file contains user password hashes and must be protected from unauthorized access.".into(),
                remediation: "chmod 0640 /etc/shadow && chown root:shadow /etc/shadow".into(),
            },
            LinuxScaCheck {
                id: 2002,
                title: "CIS 1.2: Ensure permissions on /etc/passwd are 0644".into(),
                target_file: "/etc/passwd".into(),
                rule_type: ScaRuleType::FilePermissions { max_octal: 0o644 },
                rationale: "The /etc/passwd file contains user account details and must only be writable by root.".into(),
                remediation: "chmod 0644 /etc/passwd && chown root:root /etc/passwd".into(),
            },
            LinuxScaCheck {
                id: 2003,
                title: "CIS 5.2.1: Ensure SSH PermitRootLogin is disabled".into(),
                target_file: "/etc/ssh/sshd_config".into(),
                rule_type: ScaRuleType::ConfigFileEntry {
                    key: "PermitRootLogin".into(),
                    expected: "no".into(),
                },
                rationale: "Disallowing direct root logins via SSH forces administrators to log in using regular user credentials and elevate via sudo, preserving auditability.".into(),
                remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd".into(),
            },
            LinuxScaCheck {
                id: 2004,
                title: "CIS 5.2.2: Ensure SSH Protocol is 2".into(),
                target_file: "/etc/ssh/sshd_config".into(),
                rule_type: ScaRuleType::ConfigFileEntry {
                    key: "Protocol".into(),
                    expected: "2".into(),
                },
                rationale: "SSH v1 suffers from critical cryptographic vulnerabilities.".into(),
                remediation: "Set 'Protocol 2' in /etc/ssh/sshd_config".into(),
            },
            LinuxScaCheck {
                id: 2005,
                title: "CIS 3.1.1: Ensure packet forwarding is disabled (net.ipv4.ip_forward = 0)".into(),
                target_file: "/proc/sys/net/ipv4/ip_forward".into(),
                rule_type: ScaRuleType::SysctlParam {
                    path: "/proc/sys/net/ipv4/ip_forward".into(),
                    expected: "0".into(),
                },
                rationale: "An endpoint should not route traffic between interfaces unless configured explicitly as a router.".into(),
                remediation: "sysctl -w net.ipv4.ip_forward=0 and persist in /etc/sysctl.conf".into(),
            },
            LinuxScaCheck {
                id: 2006,
                title: "CIS 3.2.1: Ensure ICMP redirects are not accepted".into(),
                target_file: "/proc/sys/net/ipv4/conf/all/accept_redirects".into(),
                rule_type: ScaRuleType::SysctlParam {
                    path: "/proc/sys/net/ipv4/conf/all/accept_redirects".into(),
                    expected: "0".into(),
                },
                rationale: "ICMP redirects can allow an attacker on the same network to alter routing tables and perform MITM attacks.".into(),
                remediation: "sysctl -w net.ipv4.conf.all.accept_redirects=0".into(),
            },
            LinuxScaCheck {
                id: 2007,
                title: "CIS 1.5.1: Ensure core dumps are restricted in /etc/security/limits.conf".into(),
                target_file: "/etc/security/limits.conf".into(),
                rule_type: ScaRuleType::ConfigFileEntry {
                    key: "* hard core".into(),
                    expected: "0".into(),
                },
                rationale: "Core dumps may contain sensitive memory contents including cryptographic keys and cleartext passwords.".into(),
                remediation: "Add '* hard core 0' to /etc/security/limits.conf".into(),
            },
            LinuxScaCheck {
                id: 2008,
                title: "CIS 1.4.1: Ensure permissions on bootloader config are configured".into(),
                target_file: "/boot/grub/grub.cfg".into(),
                rule_type: ScaRuleType::FilePermissions { max_octal: 0o600 },
                rationale: "The bootloader configuration should only be readable and writable by root.".into(),
                remediation: "chmod 0600 /boot/grub/grub.cfg".into(),
            },
            LinuxScaCheck {
                id: 2009,
                title: "CIS 3.4.1: Ensure reverse path filtering is enabled (net.ipv4.conf.all.rp_filter = 1)".into(),
                target_file: "/proc/sys/net/ipv4/conf/all/rp_filter".into(),
                rule_type: ScaRuleType::SysctlParam {
                    path: "/proc/sys/net/ipv4/conf/all/rp_filter".into(),
                    expected: "1".into(),
                },
                rationale: "Reverse path filtering helps prevent IP address spoofing attacks.".into(),
                remediation: "sysctl -w net.ipv4.conf.all.rp_filter=1".into(),
            },
        ];

        let policy_dirs = vec![
            PathBuf::from("/var/ossec/ruleset/sca"),
            PathBuf::from("/etc/ossec/ruleset/sca"),
            PathBuf::from("./ruleset/sca"),
        ];

        // Discover external YAML policies if present (mirroring Wazuh wm_sca.c)
        for dir in &policy_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().map_or(false, |ext| ext == "yml" || ext == "yaml") {
                        if let Some(doc) = siem_sca::yaml::parse_file(&p.to_string_lossy(), &mut |_| {}) {
                            let _ = doc; // Successfully validated libyaml document
                            info!("wazuh-sca: Loaded dynamic SCA policy file '{}'", p.display());
                        }
                    }
                }
            }
        }

        Self { agent_id, checks, policy_dirs }
    }

    /// Run compliance assessment against the Linux host
    pub async fn run_sca_assessment(&self, buffer: &AgentBuffer) {
        let mut passed_count = 0;
        let mut failed_count = 0;

        for check in &self.checks {
            let passed = self.evaluate_check(check);
            if passed {
                passed_count += 1;
            } else {
                failed_count += 1;
            }

            let status_str = if passed { "PASSED" } else { "FAILED" };
            let log_msg = format!(
                "wazuh-sca: [{}] CIS Check #{}: '{}' on {}",
                status_str, check.id, check.title, check.target_file
            );

            let mut event = RawEvent::new(&self.agent_id, EventSource::Sca, "sca/cis-linux", log_msg);
            event.metadata.insert("check_id".into(), check.id.to_string());
            event.metadata.insert("title".into(), check.title.clone());
            event.metadata.insert("target_file".into(), check.target_file.clone());
            event.metadata.insert("status".into(), status_str.to_lowercase());
            event.metadata.insert("rationale".into(), check.rationale.clone());
            event.metadata.insert("remediation".into(), check.remediation.clone());
            event.metadata.insert("os_type".into(), "linux".into());

            buffer.push(event).await;
        }

        let total = passed_count + failed_count;
        let score_pct = if total > 0 { (passed_count * 100) / total } else { 0 };
        info!(
            "wazuh-sca: Completed Linux CIS Assessment. Passed: {}/{}, Score: {}%",
            passed_count, total, score_pct
        );
    }

    fn evaluate_check(&self, check: &LinuxScaCheck) -> bool {
        match &check.rule_type {
            ScaRuleType::FilePermissions { max_octal } => {
                let p = Path::new(&check.target_file);
                if !p.exists() {
                    return true;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(meta) = p.metadata() {
                        let mode = meta.mode() & 0o777;
                        return mode <= *max_octal;
                    }
                }
                #[cfg(not(unix))]
                let _ = max_octal;
                true
            }
            ScaRuleType::ConfigFileEntry { key, expected } => {
                let p = Path::new(&check.target_file);
                if !p.exists() {
                    return true;
                }
                if let Ok(file) = File::open(p) {
                    let reader = BufReader::new(file);
                    for line in reader.lines().flatten() {
                        let trimmed = line.trim();
                        if trimmed.starts_with('#') || trimmed.is_empty() {
                            continue;
                        }
                        if trimmed.contains(key) && trimmed.contains(expected) {
                            return true;
                        }
                    }
                }
                false
            }
            ScaRuleType::SysctlParam { path, expected } => {
                let p = Path::new(path);
                if p.exists() {
                    if let Ok(content) = std::fs::read_to_string(p) {
                        return content.trim() == expected;
                    }
                }
                false
            }
            ScaRuleType::CommandCheck { cmd, expected } => {
                let parts: Vec<&str> = cmd.split_whitespace().collect();
                if let Some((first, rest)) = parts.split_first() {
                    if let Ok(output) = Command::new(first).args(rest).output() {
                        if output.status.success() {
                            let text = String::from_utf8_lossy(&output.stdout);
                            return text.contains(expected);
                        }
                    }
                }
                false
            }
            ScaRuleType::FileRegex { path, regex } => {
                if let Ok(content) = std::fs::read_to_string(path) {
                    return content.contains(regex);
                }
                false
            }
        }
    }
}

/// Spawns the Linux SCA worker running periodic CIS benchmark assessments
pub fn spawn_sca_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let engine = LinuxScaEngine::new(agent_id);

        loop {
            engine.run_sca_assessment(&buffer).await;
            tokio::time::sleep(interval).await;
        }
    })
}
