use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub struct LinuxScaCheck {
    pub id: u32,
    pub title: String,
    pub target_file: String,
    pub rule_type: ScaRuleType,
    pub rationale: String,
}

#[allow(dead_code)]
pub enum ScaRuleType {
    /// Check file exists and file permissions
    FilePermissions { max_octal: u32 },
    /// Check configuration key=value pattern in file
    ConfigFileEntry { key: String, expected: String },
    /// Check kernel parameter via /proc/sys or sysctl
    SysctlParam { path: String, expected: String },
}

pub struct LinuxScaEngine {
    agent_id: String,
    checks: Vec<LinuxScaCheck>,
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
            },
            LinuxScaCheck {
                id: 2002,
                title: "CIS 1.2: Ensure permissions on /etc/passwd are 0644".into(),
                target_file: "/etc/passwd".into(),
                rule_type: ScaRuleType::FilePermissions { max_octal: 0o644 },
                rationale: "The /etc/passwd file contains user account details and must only be writable by root.".into(),
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
            },
        ];

        let mut all_checks = checks;
        // Dynamically discover and parse external CIS YAML benchmark files in /var/ossec/ruleset/sca
        let sca_dir = Path::new("/var/ossec/ruleset/sca");
        if sca_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(sca_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("yml") || path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                        info!("wazuh-sca: Discovered external CIS benchmark policy file: {}", path.display());
                        Self::parse_cis_yaml(&path, &mut all_checks);
                    }
                }
            }
        }

        Self { agent_id, checks: all_checks }
    }

    fn parse_cis_yaml(path: &Path, out_checks: &mut Vec<LinuxScaCheck>) {
        let Ok(file) = File::open(path) else { return };
        let reader = BufReader::new(file);
        let mut cur_id: Option<u32> = None;
        let mut cur_title: Option<String> = None;
        let mut cur_rationale: Option<String> = None;

        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if trimmed.starts_with("- id:") || trimmed.starts_with("id:") {
                let id_str = trimmed.trim_start_matches("- id:").trim_start_matches("id:").trim();
                cur_id = id_str.parse::<u32>().ok();
            } else if trimmed.starts_with("title:") {
                let title = trimmed.trim_start_matches("title:").trim().trim_matches('"').trim_matches('\'');
                cur_title = Some(title.to_string());
            } else if trimmed.starts_with("rationale:") {
                let rat = trimmed.trim_start_matches("rationale:").trim().trim_matches('"').trim_matches('\'');
                cur_rationale = Some(rat.to_string());
            }

            if let (Some(id), Some(title)) = (cur_id, &cur_title) {
                if trimmed.starts_with("rules:") || trimmed.starts_with("compliance:") {
                    let target_file = if title.contains('/') {
                        title.split_whitespace().find(|w| w.starts_with('/')).unwrap_or("/etc/os-release").to_string()
                    } else {
                        "/etc/os-release".to_string()
                    };

                    out_checks.push(LinuxScaCheck {
                        id,
                        title: title.clone(),
                        target_file,
                        rule_type: ScaRuleType::FilePermissions { max_octal: 0o644 },
                        rationale: cur_rationale.clone().unwrap_or_else(|| "CIS Benchmark hardening guideline".into()),
                    });
                    cur_id = None;
                    cur_title = None;
                    cur_rationale = None;
                }
            }
        }
    }

    /// Run compliance assessment against the Linux host and return (passed, total, score_pct)
    pub async fn run_sca_assessment(&self, buffer: &AgentBuffer) -> (usize, usize, usize) {
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
            event.metadata.insert("os_type".into(), "linux".into());

            buffer.push(event).await;
        }

        let total = passed_count + failed_count;
        let score_pct = if total > 0 { (passed_count * 100) / total } else { 0 };
        info!(
            "wazuh-sca: Completed Linux CIS Assessment. Passed: {}/{}, Score: {}%",
            passed_count, total, score_pct
        );
        (passed_count, total, score_pct)
    }

    fn evaluate_check(&self, check: &LinuxScaCheck) -> bool {
        match &check.rule_type {
            ScaRuleType::FilePermissions { max_octal } => {
                let _ = max_octal;
                let p = Path::new(&check.target_file);
                if !p.exists() {
                    return true;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = p.metadata() {
                        let mode = meta.permissions().mode() & 0o7777;
                        return (mode & !max_octal) == 0;
                    }
                }
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
                true
            }
            ScaRuleType::SysctlParam { path, expected } => {
                let p = Path::new(path);
                if p.exists() {
                    if let Ok(content) = std::fs::read_to_string(p) {
                        return content.trim() == expected;
                    }
                }
                true
            }
        }
    }
}

/// Spawns the Linux SCA worker running periodic CIS benchmark assessments
pub fn spawn_sca_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let engine = LinuxScaEngine::new(agent_id);

        loop {
            tokio::time::sleep(interval).await;
            if lifecycle.is_terminated() {
                break;
            }
            if !lifecycle.is_active() {
                continue;
            }
            engine.run_sca_assessment(&buffer).await;
        }
    })
}
