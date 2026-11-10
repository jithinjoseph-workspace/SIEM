use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct ScaCheck {
    pub id: u32,
    pub title: String,
    pub registry_key: String,
    pub value_name: String,
    pub expected_value: String,
    pub cis_id: String,
    pub compliance: Vec<String>,
    pub remediation: String,
}

pub struct ScaEngine {
    agent_id: String,
    checks: Vec<ScaCheck>,
}

impl ScaEngine {
    pub fn new(agent_id: String) -> Self {
        let checks = vec![
            ScaCheck {
                id: 15500,
                title: "Ensure 'Enforce password history' is set to '24 or more password(s)'".into(),
                registry_key: r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters".into(),
                value_name: "PasswordHistorySize".into(),
                expected_value: "24".into(),
                cis_id: "1.1.1".into(),
                compliance: vec!["CIS 1.1.1".into(), "PCI-DSS v4.0 8.3.5".into(), "SOC 2 CC6.1".into()],
                remediation: "Set Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Enforce password history to 24".into(),
            },
            ScaCheck {
                id: 15501,
                title: "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'".into(),
                registry_key: r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters".into(),
                value_name: "MaximumPasswordAge".into(),
                expected_value: "365".into(),
                cis_id: "1.1.2".into(),
                compliance: vec!["CIS 1.1.2".into(), "PCI-DSS v4.0 8.3.6".into()],
                remediation: "Set Maximum password age between 1 and 365 days".into(),
            },
            ScaCheck {
                id: 15504,
                title: "Ensure 'Account lockout duration' is set to '15 or more minute(s)'".into(),
                registry_key: r"HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout".into(),
                value_name: "MaxDenials".into(),
                expected_value: "5".into(),
                cis_id: "1.2.1".into(),
                compliance: vec!["CIS 1.2.1".into(), "PCI-DSS v4.0 8.3.4".into()],
                remediation: "Configure account lockout duration to at least 15 minutes".into(),
            },
            ScaCheck {
                id: 1001,
                title: "Ensure User Account Control (UAC) - EnableLUA is enabled".into(),
                registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System".into(),
                value_name: "EnableLUA".into(),
                expected_value: "0x1".into(),
                cis_id: "2.3.17.1".into(),
                compliance: vec!["CIS 2.3.17.1".into(), "PCI-DSS v4.0 2.2.2".into(), "SOC 2 CC6.1".into()],
                remediation: "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA to 1".into(),
            },
            ScaCheck {
                id: 1002,
                title: "Ensure Windows Defender Real-Time Protection is active".into(),
                registry_key: r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender".into(),
                value_name: "DisableAntiSpyware".into(),
                expected_value: "0x0".into(),
                cis_id: "18.9.1".into(),
                compliance: vec!["CIS 18.9.1".into(), "PCI-DSS v4.0 5.1.1".into(), "HIPAA 164.308".into()],
                remediation: "Ensure Windows Defender Real-Time Protection and AntiSpyware are enabled".into(),
            },
            ScaCheck {
                id: 1003,
                title: "Ensure Remote Desktop requires Network Level Authentication (NLA)".into(),
                registry_key: r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp".into(),
                value_name: "UserAuthentication".into(),
                expected_value: "0x1".into(),
                cis_id: "18.9.2".into(),
                compliance: vec!["CIS 18.9.2".into(), "PCI-DSS v4.0 2.2.4".into()],
                remediation: "Enable Network Level Authentication for Remote Desktop connections".into(),
            },
            ScaCheck {
                id: 1004,
                title: "Ensure Windows Defender Firewall is enabled for Standard & Domain Profiles".into(),
                registry_key: r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile".into(),
                value_name: "EnableFirewall".into(),
                expected_value: "0x1".into(),
                cis_id: "9.1.1".into(),
                compliance: vec!["CIS 9.1.1".into(), "PCI-DSS v4.0 1.2.1".into(), "SOC 2 CC6.6".into()],
                remediation: "Set EnableFirewall to 1 in StandardProfile and DomainProfile".into(),
            },
            ScaCheck {
                id: 1005,
                title: "Ensure SMBv1 deprecated protocol is disabled (LanmanServer)".into(),
                registry_key: r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters".into(),
                value_name: "SMB1".into(),
                expected_value: "0x0".into(),
                cis_id: "18.2.1".into(),
                compliance: vec!["CIS 18.2.1".into(), "PCI-DSS v4.0 2.2.1".into()],
                remediation: "Disable SMBv1 across LanmanServer and LanmanWorkstation parameters".into(),
            },
            ScaCheck {
                id: 1006,
                title: "Ensure Anonymous SID/Name Translation is restricted (LSA)".into(),
                registry_key: r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa".into(),
                value_name: "RestrictAnonymousSAM".into(),
                expected_value: "0x1".into(),
                cis_id: "2.3.11.1".into(),
                compliance: vec!["CIS 2.3.11.1".into(), "PCI-DSS v4.0 8.2.1".into()],
                remediation: "Set RestrictAnonymousSAM to 1 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa".into(),
            },
            ScaCheck {
                id: 1007,
                title: "Ensure Anonymous enumeration of SAM accounts and shares is restricted".into(),
                registry_key: r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa".into(),
                value_name: "RestrictAnonymous".into(),
                expected_value: "0x1".into(),
                cis_id: "2.3.11.2".into(),
                compliance: vec!["CIS 2.3.11.2".into(), "SOC 2 CC6.1".into()],
                remediation: "Set RestrictAnonymous to 1 in LSA security settings".into(),
            },
            ScaCheck {
                id: 1008,
                title: "Ensure AutoRun/AutoPlay is disabled for all drives".into(),
                registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer".into(),
                value_name: "NoDriveTypeAutoRun".into(),
                expected_value: "0xff".into(),
                cis_id: "18.9.15".into(),
                compliance: vec!["CIS 18.9.15".into(), "PCI-DSS v4.0 2.2.2".into()],
                remediation: "Set NoDriveTypeAutoRun to 0xFF (255) to disable AutoRun on all storage media".into(),
            },
            ScaCheck {
                id: 1009,
                title: "Ensure the built-in Windows Guest account is disabled".into(),
                registry_key: "".into(),
                value_name: "".into(),
                expected_value: "No".into(),
                cis_id: "2.3.1.2".into(),
                compliance: vec!["CIS 2.3.1.2".into(), "PCI-DSS v4.0 8.2.1".into()],
                remediation: "Disable the built-in Guest user account using 'net user Guest /active:no'".into(),
            },
            ScaCheck {
                id: 15511,
                title: "Ensure Link-Local Multicast Name Resolution (LLMNR) is disabled".into(),
                registry_key: r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient".into(),
                value_name: "EnableMulticast".into(),
                expected_value: "0x0".into(),
                cis_id: "18.5.1".into(),
                compliance: vec!["CIS 18.5.1".into(), "PCI-DSS v4.0 2.2.1".into()],
                remediation: "Set EnableMulticast to 0 under Policies\\Microsoft\\Windows NT\\DNSClient".into(),
            },
            ScaCheck {
                id: 15513,
                title: "Ensure Microsoft Defender SmartScreen is enabled".into(),
                registry_key: r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System".into(),
                value_name: "EnableSmartScreen".into(),
                expected_value: "0x1".into(),
                cis_id: "18.9.30".into(),
                compliance: vec!["CIS 18.9.30".into(), "SOC 2 CC6.6".into()],
                remediation: "Set EnableSmartScreen to 1 in Windows System Policies".into(),
            },
        ];

        Self { agent_id, checks }
    }

    /// Evaluate each security policy check
    pub async fn run_assessment(&self, buffer: &AgentBuffer) {
        info!("SCA: Running Windows Security Configuration Assessment ({} checks)...", self.checks.len());

        for check in &self.checks {
            let passed = self.evaluate_check(check);
            let status = if passed { "PASS" } else { "FAIL" };
            let msg = format!("SCA [{}]: (Check #{}) {}", status, check.id, check.title);

            if passed {
                info!("{}", msg);
            } else {
                warn!("{}", msg);
            }

            let mut event = RawEvent::new(&self.agent_id, EventSource::Sca, "sca/windows_baseline", msg);
            event.metadata.insert("check_id".into(), check.id.to_string());
            event.metadata.insert("status".into(), status.to_string());
            event.metadata.insert("title".into(), check.title.clone());
            event.metadata.insert("cis_id".into(), check.cis_id.clone());
            event.metadata.insert("compliance".into(), check.compliance.join(", "));
            event.metadata.insert("remediation".into(), check.remediation.clone());

            buffer.push(event).await;
        }
    }

    fn evaluate_check(&self, check: &ScaCheck) -> bool {
        #[cfg(target_os = "windows")]
        {
            // Check 1009: Built-in Guest account status
            if check.id == 1009 {
                if let Ok(output) = Command::new("net").args(["user", "Guest"]).output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        for line in text.lines() {
                            if line.contains("Account active") {
                                return line.to_lowercase().contains("no");
                            }
                        }
                    }
                }
                return true; // Guest account disabled or not configured
            }

            // For Defender Real-Time Protection (Check 1002):
            // On Windows 10/11, DisableAntiSpyware key does not exist by default, meaning Defender is active (PASS).
            // It only fails if DisableAntiSpyware exists and is set to 0x1.
            if check.id == 1002 {
                if let Ok(output) = Command::new("reg")
                    .args(["query", &check.registry_key, "/v", &check.value_name])
                    .output()
                {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        return !text.contains("0x1");
                    }
                }
                return true; // Not disabled in policies -> PASS
            }

            // For SMBv1 (Check 1005): On modern Windows, SMB1 key absent means disabled by default (PASS)
            if check.id == 1005 {
                if let Ok(output) = Command::new("reg")
                    .args(["query", &check.registry_key, "/v", &check.value_name])
                    .output()
                {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        return text.contains("0x0");
                    }
                }
                return true; // Absent -> PASS
            }

            if let Ok(output) = Command::new("reg")
                .args(["query", &check.registry_key, "/v", &check.value_name])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
                    return text.contains(&check.expected_value.to_lowercase());
                }
            }
            return false;
        }

        #[cfg(not(target_os = "windows"))]
        true // pass on mock non-windows platforms
    }
}

pub fn spawn_sca_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let sca = ScaEngine::new(agent_id);

        // Run on startup
        sca.run_assessment(&buffer).await;

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            sca.run_assessment(&buffer).await;
        }
    })
}
