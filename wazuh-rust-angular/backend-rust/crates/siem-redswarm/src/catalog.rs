use crate::models::{AttackTechnique, CommandPayload, RiskLevel};

/// Returns the curated, high-quality ATT&CK technique catalog.
/// Every live technique is guaranteed to be reversible with an idempotent cleanup payload.
pub fn get_curated_catalog() -> Vec<AttackTechnique> {
    vec![
        // 1. T1110.001 - Password Guessing / SSH Brute Force
        AttackTechnique {
            id: "T1110.001".into(),
            name: "SSH Password Guessing".into(),
            tactic: "Credential Access".into(),
            platforms: vec!["linux".into()],
            risk_level: RiskLevel::Low,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: "for u in admin test root; do ssh -o BatchMode=yes -o StrictHostKeyChecking=no -p 22 $u@127.0.0.1 2>/dev/null || true; done".into(),
                timeout_seconds: 10,
                requires_elevation: false,
            },
            cleanup: CommandPayload {
                command: "true".into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            expected_telemetry: vec![
                "Failed password for".into(),
                "sshd".into(),
                "authentication failure".into(),
            ],
            expected_mitre_ids: vec!["T1110".into(), "T1110.001".into()],
            expected_rule_groups: vec!["syslog".into(), "sshd".into(), "authentication_failed".into()],
            detection_indicators: vec!["Failed password".into(), "ssh2".into(), "sshd".into()],
            banned_in_controlled_live: false,
            sample_raw_logs: vec![
                "sshd[4102]: Failed password for root from 192.168.1.105 port 54820 ssh2".into(),
                "sshd[4103]: Failed password for invalid user admin from 192.168.1.105 port 54822 ssh2".into(),
                "sshd[4104]: Failed password for test from 192.168.1.105 port 54824 ssh2".into(),
            ],
        },

        // 2. T1059.001 - PowerShell Malicious Encoded Execution
        AttackTechnique {
            id: "T1059.001".into(),
            name: "PowerShell Encoded Command Execution".into(),
            tactic: "Execution".into(),
            platforms: vec!["windows".into()],
            risk_level: RiskLevel::Low,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: "powershell.exe -NoProfile -NonInteractive -EncodedCommand V3JpdGUtT3V0cHV0ICdQcm9WaWdpbCBTd2FybSBUZXN0Jw==".into(),
                timeout_seconds: 10,
                requires_elevation: false,
            },
            cleanup: CommandPayload {
                command: "true".into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            expected_telemetry: vec![
                "powershell.exe".into(),
                "-EncodedCommand".into(),
                "EventID: 4104".into(),
                "EventID: 1".into(),
            ],
            expected_mitre_ids: vec!["T1059".into(), "T1059.001".into()],
            expected_rule_groups: vec!["windows".into(), "sysmon".into(), "powershell".into(), "process_creation".into()],
            detection_indicators: vec!["powershell.exe".into(), "-EncodedCommand".into(), "-e ".into()],
            banned_in_controlled_live: false,
            sample_raw_logs: vec![
                "Microsoft-Windows-Sysmon/Operational: EventID 1 - Process Create: powershell.exe -w hidden -EncodedCommand c2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRz (Credential Access test)".into(),
            ],
        },

        // 3. T1547.001 - Registry Run Keys / Startup Folder Persistence
        AttackTechnique {
            id: "T1547.001".into(),
            name: "Registry Run Keys Modification".into(),
            tactic: "Persistence".into(),
            platforms: vec!["windows".into()],
            risk_level: RiskLevel::Medium,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: r#"reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ProVigilRedSwarmProbe" /t REG_SZ /d "C:\Windows\System32\cmd.exe /c echo swarm" /f"#.into(),
                timeout_seconds: 10,
                requires_elevation: false,
            },
            cleanup: CommandPayload {
                command: r#"reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ProVigilRedSwarmProbe" /f >nul 2>&1 || exit 0"#.into(),
                timeout_seconds: 10,
                requires_elevation: false,
            },
            expected_telemetry: vec![
                r"CurrentVersion\Run".into(),
                "ProVigilRedSwarmProbe".into(),
                "EventID: 13".into(),
            ],
            expected_mitre_ids: vec!["T1547".into(), "T1547.001".into()],
            expected_rule_groups: vec!["windows".into(), "sysmon".into(), "registry".into(), "persistence".into()],
            detection_indicators: vec![r"Software\Microsoft\Windows\CurrentVersion\Run".into(), "reg add".into()],
            banned_in_controlled_live: false,
            sample_raw_logs: vec![
                r"Registry 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run' modified: Value 'BackdoorService' added = 'C:\Users\Public\svchost_fake.exe'".into(),
            ],
        },

        // 4. T1082 - System Information Discovery
        AttackTechnique {
            id: "T1082".into(),
            name: "System Information Discovery".into(),
            tactic: "Discovery".into(),
            platforms: vec!["linux".into(), "windows".into()],
            risk_level: RiskLevel::Low,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: "uname -a || systeminfo".into(),
                timeout_seconds: 8,
                requires_elevation: false,
            },
            cleanup: CommandPayload {
                command: "true".into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            expected_telemetry: vec![
                "uname".into(),
                "systeminfo".into(),
                "T1082".into(),
            ],
            expected_mitre_ids: vec!["T1082".into()],
            expected_rule_groups: vec!["discovery".into(), "auditd".into(), "sysmon".into()],
            detection_indicators: vec!["uname".into(), "systeminfo.exe".into()],
            banned_in_controlled_live: false,
            sample_raw_logs: vec![
                "auditd: type=SYSCALL arch=c000003e syscall=63 success=yes exe=\"/usr/bin/uname\" comm=\"uname\"".into(),
            ],
        },

        // 5. T1003.008 - OS Credential Dumping: /etc/shadow
        AttackTechnique {
            id: "T1003.008".into(),
            name: "Access to /etc/shadow".into(),
            tactic: "Credential Access".into(),
            platforms: vec!["linux".into()],
            risk_level: RiskLevel::Medium,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: "head -n 1 /etc/shadow 2>/dev/null || true".into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            cleanup: CommandPayload {
                command: "true".into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            expected_telemetry: vec![
                "/etc/shadow".into(),
                "syscheck".into(),
                "integrity checksum".into(),
            ],
            expected_mitre_ids: vec!["T1003".into(), "T1003.008".into()],
            expected_rule_groups: vec!["fim".into(), "syscheck".into(), "credential_access".into()],
            detection_indicators: vec!["/etc/shadow".into()],
            banned_in_controlled_live: false,
            sample_raw_logs: vec![
                "ossec: File '/etc/shadow' modified (checksum changed from a93f... to d21b...)".into(),
                "auditd: type=PATH name=\"/etc/shadow\" flags=101 mode=0100640 ouid=0 ogid=42".into(),
            ],
        },

        // 6. T1070.001 - Indicator Removal: Clear Windows Event Logs
        AttackTechnique {
            id: "T1070.001".into(),
            name: "Clear Windows Event Logs (Wevtutil)".into(),
            tactic: "Defense Evasion".into(),
            platforms: vec!["windows".into()],
            risk_level: RiskLevel::High,
            reversible: false, // Event log clears cannot be restored!
            cleanup_guaranteed: false,
            execution: CommandPayload {
                command: "wevtutil cl Application".into(),
                timeout_seconds: 10,
                requires_elevation: true,
            },
            cleanup: CommandPayload {
                command: "echo cannot restore cleared logs".into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            expected_telemetry: vec![
                "EventID: 1102".into(),
                "EventID: 104".into(),
                "audit log was cleared".into(),
            ],
            expected_mitre_ids: vec!["T1070".into(), "T1070.001".into()],
            expected_rule_groups: vec!["windows".into(), "security".into(), "defense_evasion".into()],
            detection_indicators: vec!["1102".into(), "audit log was cleared".into(), "wevtutil".into()],
            banned_in_controlled_live: true, // NON-REVERSIBLE: Banned in ControlledLive! SafeTelemetryOnly only.
            sample_raw_logs: vec![
                "Windows-Event [Security] EventID:1102 - The audit log was cleared. Subject: User: Administrator".into(),
            ],
        },

        // 7. T1543.003 - Windows Service Creation (Persistence)
        AttackTechnique {
            id: "T1543.003".into(),
            name: "Windows Service Creation Probe".into(),
            tactic: "Persistence".into(),
            platforms: vec!["windows".into()],
            risk_level: RiskLevel::Medium,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: r#"sc.exe create ProVigilRedSwarm binPath= "cmd.exe /c echo swarm" start= demand"#.into(),
                timeout_seconds: 10,
                requires_elevation: true,
            },
            cleanup: CommandPayload {
                command: r#"sc.exe delete ProVigilRedSwarm >nul 2>&1 || exit 0"#.into(),
                timeout_seconds: 10,
                requires_elevation: true,
            },
            expected_telemetry: vec![
                "EventID: 7045".into(),
                "A service was installed in the system".into(),
                "Service Name: ProVigilRedSwarm".into(),
            ],
            expected_mitre_ids: vec!["T1543".into(), "T1543.003".into()],
            expected_rule_groups: vec!["windows".into(), "system".into(), "service_creation".into(), "persistence".into()],
            detection_indicators: vec!["7045".into(), "service was installed".into(), "sc.exe create".into()],
            banned_in_controlled_live: false,
            sample_raw_logs: vec![
                "Windows-Event [System] EventID:7045 - A service was installed in the system. Service Name: RansomPayloadService, File Name: C:\\Temp\\encrypt.exe".into(),
            ],
        },

        // 8. T1053.003 - Cron Persistence Probe
        AttackTechnique {
            id: "T1053.003".into(),
            name: "Cron Job Creation Probe".into(),
            tactic: "Persistence".into(),
            platforms: vec!["linux".into()],
            risk_level: RiskLevel::Low,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: "echo '# provigil swarm test' > /tmp/redswarm_cron_probe".into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            cleanup: CommandPayload {
                command: "rm -f /tmp/redswarm_cron_probe".into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            expected_telemetry: vec![
                "crontab".into(),
                "/etc/cron".into(),
                "cron".into(),
            ],
            expected_mitre_ids: vec!["T1053".into(), "T1053.003".into()],
            expected_rule_groups: vec!["cron".into(), "syslog".into(), "persistence".into()],
            detection_indicators: vec!["crontab".into(), "/var/spool/cron".into()],
            banned_in_controlled_live: false,
            sample_raw_logs: vec![
                "crontab[9120]: (root) REPLACE (root)".into(),
                "crond[9121]: (root) RELOAD (/var/spool/cron/root)".into(),
            ],
        },

        // 9. T1562.001 - Impair Defenses: Disable Firewall
        AttackTechnique {
            id: "T1562.001".into(),
            name: "Impair Defenses (Firewall Tamper)".into(),
            tactic: "Defense Evasion".into(),
            platforms: vec!["windows".into(), "linux".into()],
            risk_level: RiskLevel::Critical,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: "netsh advfirewall set allprofiles state off || ufw disable".into(),
                timeout_seconds: 10,
                requires_elevation: true,
            },
            cleanup: CommandPayload {
                command: "netsh advfirewall set allprofiles state on || ufw enable".into(),
                timeout_seconds: 10,
                requires_elevation: true,
            },
            expected_telemetry: vec![
                "advfirewall".into(),
                "firewall disabled".into(),
                "EventID: 2003".into(),
            ],
            expected_mitre_ids: vec!["T1562".into(), "T1562.001".into()],
            expected_rule_groups: vec!["windows".into(), "firewall".into(), "defense_evasion".into()],
            detection_indicators: vec!["advfirewall set allprofiles state off".into(), "2003".into(), "ufw disable".into()],
            banned_in_controlled_live: true, // CRITICAL: Never run live in ControlledLive!
            sample_raw_logs: vec![
                "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall: EventID 2003 - A firewall profile state changed. Profile: Domain, State: Disabled".into(),
            ],
        },

        // 10. T1036.005 - Masquerading Legitimate Name
        AttackTechnique {
            id: "T1036.005".into(),
            name: "Masquerading as Windows Service Host".into(),
            tactic: "Defense Evasion".into(),
            platforms: vec!["windows".into()],
            risk_level: RiskLevel::Low,
            reversible: true,
            cleanup_guaranteed: true,
            execution: CommandPayload {
                command: r#"copy /y %SystemRoot%\System32\cmd.exe %TEMP%\svchost.exe && %TEMP%\svchost.exe /c echo test"#.into(),
                timeout_seconds: 10,
                requires_elevation: false,
            },
            cleanup: CommandPayload {
                command: r#"del /f /q %TEMP%\svchost.exe >nul 2>&1 || exit 0"#.into(),
                timeout_seconds: 5,
                requires_elevation: false,
            },
            expected_telemetry: vec![
                "svchost.exe".into(),
                "TEMP".into(),
                "EventID: 1".into(),
            ],
            expected_mitre_ids: vec!["T1036".into(), "T1036.005".into()],
            expected_rule_groups: vec!["windows".into(), "sysmon".into(), "process_creation".into(), "masquerading".into()],
            detection_indicators: vec![r"\Temp\svchost.exe".into(), "svchost.exe".into()],
            banned_in_controlled_live: false,
            sample_raw_logs: vec![
                r"Microsoft-Windows-Sysmon/Operational: EventID 1 - Process Create: ParentImage: cmd.exe, Image: C:\Users\Admin\AppData\Local\Temp\svchost.exe, CommandLine: svchost.exe /c echo".into(),
            ],
        },
    ]
}

/// Look up technique by ID
pub fn find_technique(id: &str) -> Option<AttackTechnique> {
    get_curated_catalog().into_iter().find(|t| t.id == id)
}
