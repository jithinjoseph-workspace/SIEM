use chrono::Utc;
use regex::Regex;
use siem_core::{
    AgentAlertInfo, Alert, DecodedFields, MitreAttack, RawEvent, Rule, RuleAlertInfo,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::info;
use uuid::Uuid;

pub mod accumulator;
pub mod active_response;
pub mod cleanevent;
pub mod dodiff;
pub mod logtest;
pub mod xml_decoder;
pub mod xml_rule;

pub use accumulator::*;
pub use active_response::*;
pub use cleanevent::*;
pub use dodiff::*;
pub use logtest::*;
pub use xml_decoder::*;
pub use xml_rule::*;

pub struct CompiledRule {
    pub rule: Rule,
    pub regex: Regex,
}

pub struct Decoder {
    pub name: String,
    pub regex: Regex,
}

#[derive(Default)]
struct CorrelationState {
    failed_logins: HashMap<String, (u32, chrono::DateTime<Utc>)>, // IP -> (count, first_attempt)
}

#[derive(Clone)]
pub struct AnalysisEngine {
    rules: Arc<Vec<CompiledRule>>,
    decoders: Arc<Vec<Decoder>>,
    pub wazuh_rules: Arc<Vec<CompiledWazuhRule>>,
    pub wazuh_decoders: Arc<Vec<CompiledDecoder>>,
    pub accumulator: Arc<WazuhAccumulator>,
    correlation: Arc<Mutex<CorrelationState>>,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        let decoders = Self::default_decoders();
        let rules = Self::default_rules();

        // Load core Wazuh XML decoders and rules
        let wazuh_decoders = Self::default_wazuh_decoders();
        let wazuh_rules = Self::default_wazuh_rules();
        let accumulator = Arc::new(WazuhAccumulator::new(50_000));

        let mut engine = Self {
            rules: Arc::new(rules),
            decoders: Arc::new(decoders),
            wazuh_rules: Arc::new(wazuh_rules),
            wazuh_decoders: Arc::new(wazuh_decoders),
            accumulator,
            correlation: Arc::new(Mutex::new(CorrelationState::default())),
        };

        // Automatically discover and load official Wazuh ruleset if directory is present
        let mut candidates = Vec::new();
        if let Ok(env_path) = std::env::var("WAZUH_RULESET_PATH") {
            candidates.push(PathBuf::from(env_path));
        }
        candidates.extend([
            PathBuf::from("ruleset"),
            PathBuf::from("../ruleset"),
            PathBuf::from("../../ruleset"),
            PathBuf::from("/var/ossec/ruleset"),
            PathBuf::from(r"C:\Program Files (x86)\ossec-agent\ruleset"),
        ]);

        for cand in &candidates {
            if cand.join("decoders").exists() || cand.join("rules").exists() {
                engine.load_ruleset_directory(cand);
                break;
            }
        }

        engine
    }

    /// Load official Wazuh XML rules and decoders from a directory containing `decoders/` and `rules/`
    pub fn load_ruleset_directory(&mut self, base_path: &Path) {
        let decoders_dir = base_path.join("decoders");
        let rules_dir = base_path.join("rules");

        if decoders_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&decoders_dir) {
                let mut new_decoders = (*self.wazuh_decoders).clone();
                let mut count = 0;
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("xml") {
                        if let Ok(mut decs) = load_decoders_file(&path) {
                            count += decs.len();
                            new_decoders.append(&mut decs);
                        }
                    }
                }
                info!("AnalysisEngine: Loaded {} official decoders from {}", count, decoders_dir.display());
                self.wazuh_decoders = Arc::new(new_decoders);
            }
        }

        if rules_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&rules_dir) {
                let mut new_rules = (*self.wazuh_rules).clone();
                let mut count = 0;
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("xml") {
                        if let Ok(mut rls) = load_rules_file(&path) {
                            count += rls.len();
                            new_rules.append(&mut rls);
                        }
                    }
                }
                info!("AnalysisEngine: Loaded {} official rules from {}", count, rules_dir.display());
                self.wazuh_rules = Arc::new(new_rules);
            }
        }
    }

    /// Return all active detection rules (including Wazuh XML rules converted to core Rule format)
    pub fn list_rules(&self) -> Vec<Rule> {
        let mut all_rules: Vec<Rule> = self.rules.iter().map(|r| r.rule.clone()).collect();
        for wr in self.wazuh_rules.iter() {
            if !wr.noalert {
                all_rules.push(wr.to_core_rule());
            }
        }
        all_rules
    }

    /// Ingest additional Wazuh XML rules dynamically
    pub fn add_wazuh_rules_xml(&mut self, xml: &str) {
        let mut current = (*self.wazuh_rules).clone();
        let mut parsed = parse_rules_xml(xml);
        current.append(&mut parsed);
        self.wazuh_rules = Arc::new(current);
    }

    /// Ingest additional Wazuh XML decoders dynamically
    pub fn add_wazuh_decoders_xml(&mut self, xml: &str) {
        let mut current = (*self.wazuh_decoders).clone();
        let mut parsed = parse_decoders_xml(xml);
        current.append(&mut parsed);
        self.wazuh_decoders = Arc::new(current);
    }

    /// Process a raw ingested log event and return an alert if any rule triggered
    pub fn process_event(&self, event: &RawEvent, agent_name: &str, agent_ip: &str) -> Option<Alert> {
        let mut decoded = self.decode(&event.message);
        let mut event_data: HashMap<String, serde_json::Value> = HashMap::new();

        // 1. Evaluate official Wazuh XML decoders first
        for d in self.wazuh_decoders.iter() {
            if d.try_decode(&event.message, &mut decoded, &mut event_data) {
                break;
            }
        }

        // 2. Evaluate official Wazuh XML rules hierarchically
        let mut active_sids: Vec<u32> = Vec::new();
        let mut active_groups: Vec<String> = Vec::new();
        let mut highest_wazuh_alert: Option<Alert> = None;
        let mut highest_level: u8 = 0;

        let parent_decoder = decoded.extra.get("parent_decoder").map(|s| s.as_str());
        let src_ip = decoded.src_ip.as_deref().or_else(|| {
            event_data.get("srcip").and_then(|v| v.as_str())
        }).or(Some(agent_ip));
        let user = decoded.user.as_deref().or_else(|| {
            event_data.get("dstuser").or_else(|| event_data.get("srcuser")).and_then(|v| v.as_str())
        });

        for w_rule in self.wazuh_rules.iter() {
            if w_rule.matches(
                &event.message,
                &decoded.decoder_name,
                parent_decoder,
                &active_sids,
                &active_groups,
                &event_data,
                Some(&self.accumulator),
                &event.agent_id,
                src_ip,
                user,
            ) {
                active_sids.push(w_rule.id);
                for g in &w_rule.groups {
                    if !active_groups.contains(g) {
                        active_groups.push(g.clone());
                    }
                }

                // Record match into sliding window accumulator
                self.accumulator.record_match(
                    w_rule.id,
                    &event.agent_id,
                    src_ip,
                    decoded.dst_ip.as_deref(),
                    user,
                    &w_rule.groups,
                );

                if !w_rule.noalert && w_rule.level >= highest_level {
                    highest_level = w_rule.level;
                    highest_wazuh_alert = Some(Alert {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        rule: w_rule.to_rule_alert_info(),
                        agent: AgentAlertInfo {
                            id: event.agent_id.clone(),
                            name: agent_name.to_string(),
                            ip: agent_ip.to_string(),
                        },
                        manager: Some(siem_core::ManagerAlertInfo {
                            name: "wazuh-manager-rust".to_string(),
                        }),
                        decoder: Some(siem_core::DecoderAlertInfo {
                            name: decoded.decoder_name.clone(),
                        }),
                        full_log: event.message.clone(),
                        decoded: decoded.clone(),
                        location: event.location.clone(),
                        data: event_data.clone(),
                    });
                }
            }
        }

        if let Some(w_alert) = highest_wazuh_alert {
            return Some(w_alert);
        }

        // 3. Fall back to built-in rules
        for compiled in self.rules.iter() {
            if compiled.regex.is_match(&event.message) {
                let alert = Alert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    rule: RuleAlertInfo {
                        id: compiled.rule.id,
                        level: compiled.rule.level,
                        description: compiled.rule.description.clone(),
                        groups: compiled.rule.groups.clone(),
                        mitre: compiled.rule.mitre.clone(),
                    },
                    agent: AgentAlertInfo {
                        id: event.agent_id.clone(),
                        name: agent_name.to_string(),
                        ip: agent_ip.to_string(),
                    },
                    manager: Some(siem_core::ManagerAlertInfo {
                        name: "wazuh-manager-rust".to_string(),
                    }),
                    decoder: Some(siem_core::DecoderAlertInfo {
                        name: decoded.decoder_name.clone(),
                    }),
                    full_log: event.message.clone(),
                    decoded: decoded.clone(),
                    location: event.location.clone(),
                    data: event_data.clone(),
                };
                return Some(alert);
            }
        }

        // Stateful correlation check for SSH Brute Force
        if let Some(src_ip) = &decoded.src_ip {
            if event.message.to_lowercase().contains("failed password") || event.message.to_lowercase().contains("invalid user") {
                let mut state = self.correlation.lock().unwrap();
                let entry = state.failed_logins.entry(src_ip.clone()).or_insert((0, Utc::now()));
                entry.0 += 1;

                if entry.0 >= 4 {
                    // Trigger Level 10 Brute Force Alert
                    let count = entry.0;
                    entry.0 = 0; // reset window

                    return Some(Alert {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        rule: RuleAlertInfo {
                            id: 5712,
                            level: 10,
                            description: format!("sshd: Multiple failed login attempts ({} attempts detected) - Potential Brute-Force Attack", count),
                            groups: vec!["syslog".into(), "sshd".into(), "authentication_failed".into()],
                            mitre: Some(MitreAttack {
                                id: "T1110".into(),
                                tactic: "Credential Access".into(),
                                technique: "Brute Force".into(),
                            }),
                        },
                        agent: AgentAlertInfo {
                            id: event.agent_id.clone(),
                            name: agent_name.to_string(),
                            ip: agent_ip.to_string(),
                        },
                        manager: Some(siem_core::ManagerAlertInfo {
                            name: "wazuh-manager-rust".to_string(),
                        }),
                        decoder: Some(siem_core::DecoderAlertInfo {
                            name: decoded.decoder_name.clone(),
                        }),
                        full_log: event.message.clone(),
                        decoded: decoded.clone(),
                        location: event.location.clone(),
                        data: event_data.clone(),
                    });
                }
            }
        }

        None
    }

    /// Run decoders against the raw text to extract key fields
    fn decode(&self, message: &str) -> DecodedFields {
        let mut fields = DecodedFields::default();

        for decoder in self.decoders.iter() {
            if let Some(caps) = decoder.regex.captures(message) {
                fields.decoder_name = decoder.name.clone();

                if let Some(ip) = caps.name("ip") {
                    fields.src_ip = Some(ip.as_str().to_string());
                }
                if let Some(user) = caps.name("user") {
                    fields.user = Some(user.as_str().to_string());
                }
                if let Some(port) = caps.name("port") {
                    if let Ok(p) = port.as_str().parse::<u16>() {
                        fields.src_port = Some(p);
                    }
                }
                if let Some(path) = caps.name("path") {
                    fields.file_path = Some(path.as_str().to_string());
                }
                if let Some(action) = caps.name("action") {
                    fields.action = Some(action.as_str().to_string());
                }
                if let Some(prog) = caps.name("prog") {
                    fields.program_name = Some(prog.as_str().to_string());
                }
                return fields;
            }
        }

        // Fallback IP extraction
        let fallback_ip = Regex::new(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b").unwrap();
        if let Some(caps) = fallback_ip.captures(message) {
            if let Some(ip) = caps.name("ip") {
                fields.src_ip = Some(ip.as_str().to_string());
            }
        }

        fields.decoder_name = "generic-syslog".to_string();
        fields
    }

    fn default_decoders() -> Vec<Decoder> {
        vec![
            Decoder {
                name: "sshd-auth".into(),
                regex: Regex::new(r"(?i)(?:Failed|Accepted|Invalid user)\s+(?:password for\s+)?(?P<user>[\w\-]+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(?P<port>\d+)").unwrap(),
            },
            Decoder {
                name: "syscheck-fim".into(),
                regex: Regex::new(r"(?i)File\s+'(?P<path>[^']+)'\s+(?P<action>modified|added|deleted|checksum changed)").unwrap(),
            },
            Decoder {
                name: "windows-registry".into(),
                regex: Regex::new(r"(?i)Registry\s+'(?P<path>[^']+)'\s+(?P<action>modified|added|deleted|value changed)").unwrap(),
            },
            Decoder {
                name: "windows-eventchannel".into(),
                regex: Regex::new(r"(?i)Windows-Event\s+\[(?P<channel>[^\]]+)\]\s+EventID:(?P<eventid>\d+).*User:(?P<user>[^\s]+)").unwrap(),
            },
            Decoder {
                name: "windows-sca".into(),
                regex: Regex::new(r"(?i)SCA\s+\[(?P<status>FAIL|PASS)\]:\s+(?P<check>.+)").unwrap(),
            },
            Decoder {
                name: "sudo-cmd".into(),
                regex: Regex::new(r"(?i)(?P<user>\w+)\s*:\s*COMMAND=(?P<path>[^\s]+)").unwrap(),
            },
            Decoder {
                name: "windows-sysmon".into(),
                regex: Regex::new(r"(?i)Process Create:\s*(?P<path>[^\s]+).*User:\s*(?P<user>[^\s]+)").unwrap(),
            },
        ]
    }

    fn default_rules() -> Vec<CompiledRule> {
        let raw_rules = vec![
            (
                Rule {
                    id: 5710,
                    level: 5,
                    description: "sshd: Attempted login with non-existent or invalid user account".into(),
                    regex_pattern: r"(?i)Invalid user \w+ from \d+".into(),
                    groups: vec!["syslog".into(), "sshd".into(), "invalid_login".into()],
                    mitre: Some(MitreAttack {
                        id: "T1110".into(),
                        tactic: "Credential Access".into(),
                        technique: "Brute Force".into(),
                    }),
                },
                r"(?i)Invalid user \w+ from \d+",
            ),
            (
                Rule {
                    id: 60101,
                    level: 6,
                    description: "windows: Event 4625 - An account failed to log on (Potential Windows credential attack)".into(),
                    regex_pattern: r"(?i)(?:EventID[:=]\s*4625|An account failed to log on)".into(),
                    groups: vec!["windows".into(), "security".into(), "authentication_failed".into()],
                    mitre: Some(MitreAttack {
                        id: "T1110".into(),
                        tactic: "Credential Access".into(),
                        technique: "Brute Force".into(),
                    }),
                },
                r"(?i)(?:EventID[:=]\s*4625|An account failed to log on)",
            ),
            (
                Rule {
                    id: 60102,
                    level: 12,
                    description: "windows: Event 1102 - Security Audit Log was cleared (Defense Evasion)".into(),
                    regex_pattern: r"(?i)(?:EventID[:=]\s*1102|The audit log was cleared)".into(),
                    groups: vec!["windows".into(), "security".into(), "log_cleared".into()],
                    mitre: Some(MitreAttack {
                        id: "T1070.001".into(),
                        tactic: "Defense Evasion".into(),
                        technique: "Clear Windows Event Logs".into(),
                    }),
                },
                r"(?i)(?:EventID[:=]\s*1102|The audit log was cleared)",
            ),
            (
                Rule {
                    id: 60103,
                    level: 10,
                    description: "windows: Event 7045 - A new service was installed in the system (Persistence / Privilege Escalation)".into(),
                    regex_pattern: r"(?i)(?:EventID[:=]\s*7045|A service was installed in the system)".into(),
                    groups: vec!["windows".into(), "system".into(), "persistence".into()],
                    mitre: Some(MitreAttack {
                        id: "T1543.003".into(),
                        tactic: "Persistence".into(),
                        technique: "Windows Service".into(),
                    }),
                },
                r"(?i)(?:EventID[:=]\s*7045|A service was installed in the system)",
            ),
            (
                Rule {
                    id: 60104,
                    level: 13,
                    description: "windows: Suspicious LOLBAS or Shadow Copy deletion command detected (vssadmin / certutil / bitsadmin)".into(),
                    regex_pattern: r"(?i)(?:vssadmin.*delete\s+shadows|certutil.*-urlcache|bitsadmin.*\/transfer)".into(),
                    groups: vec!["windows".into(), "execution".into(), "defense_evasion".into()],
                    mitre: Some(MitreAttack {
                        id: "T1490".into(),
                        tactic: "Impact".into(),
                        technique: "Inhibit System Recovery".into(),
                    }),
                },
                r"(?i)(?:vssadmin.*delete\s+shadows|certutil.*-urlcache|bitsadmin.*\/transfer)",
            ),
            (
                Rule {
                    id: 60200,
                    level: 11,
                    description: "registry: Windows autostart persistence key modified (Run, RunOnce, Winlogon)".into(),
                    regex_pattern: r"(?i)Registry '.*(?:CurrentVersion\\Run|CurrentVersion\\RunOnce|Winlogon).*' (?:modified|added|value changed)".into(),
                    groups: vec!["windows".into(), "registry".into(), "persistence".into()],
                    mitre: Some(MitreAttack {
                        id: "T1547.001".into(),
                        tactic: "Persistence".into(),
                        technique: "Registry Run Keys / Startup Folder".into(),
                    }),
                },
                r"(?i)Registry '.*(?:CurrentVersion\\Run|CurrentVersion\\RunOnce|Winlogon).*' (?:modified|added|value changed)",
            ),
            (
                Rule {
                    id: 60300,
                    level: 8,
                    description: "sca: Security Configuration Assessment check failed (CIS Benchmark violation)".into(),
                    regex_pattern: r"(?i)SCA \[FAIL\]:\s*(?P<rule>.+)".into(),
                    groups: vec!["windows".into(), "sca".into(), "compliance".into()],
                    mitre: Some(MitreAttack {
                        id: "T1082".into(),
                        tactic: "Discovery".into(),
                        technique: "System Information Discovery".into(),
                    }),
                },
                r"(?i)SCA \[FAIL\]:\s*(?P<rule>.+)",
            ),
            (
                Rule {
                    id: 5503,
                    level: 12,
                    description: "syscheck: Critical security configuration file modified (/etc/shadow, /etc/passwd, hosts)".into(),
                    regex_pattern: r"(?i)File '(/etc/(?:shadow|passwd|sudoers)|C:\\Windows\\System32\\drivers\\etc\\hosts)' (?:modified|checksum changed)".into(),
                    groups: vec!["syscheck".into(), "fim".into(), "tampering".into()],
                    mitre: Some(MitreAttack {
                        id: "T1098".into(),
                        tactic: "Persistence".into(),
                        technique: "Account Manipulation".into(),
                    }),
                },
                r"(?i)File '(/etc/(?:shadow|passwd|sudoers)|C:\\Windows\\System32\\drivers\\etc\\hosts)' (?:modified|checksum changed)",
            ),
            (
                Rule {
                    id: 5501,
                    level: 7,
                    description: "syscheck: File integrity monitor detected file modification".into(),
                    regex_pattern: r"(?i)File '.*' (?:modified|added|deleted)".into(),
                    groups: vec!["syscheck".into(), "fim".into()],
                    mitre: Some(MitreAttack {
                        id: "T1565".into(),
                        tactic: "Impact".into(),
                        technique: "Data Manipulation".into(),
                    }),
                },
                r"(?i)File '.*' (?:modified|added|deleted)",
            ),
            (
                Rule {
                    id: 556,
                    level: 3,
                    description: "syscheck: File integrity monitoring scan started (FIM_SCAN_START)".into(),
                    regex_pattern: r"(?i)File integrity monitoring scan started".into(),
                    groups: vec!["syscheck".into(), "fim".into(), "scan_lifecycle".into()],
                    mitre: None,
                },
                r"(?i)File integrity monitoring scan started",
            ),
            (
                Rule {
                    id: 557,
                    level: 3,
                    description: "syscheck: File integrity monitoring scan ended (FIM_SCAN_END)".into(),
                    regex_pattern: r"(?i)File integrity monitoring scan ended".into(),
                    groups: vec!["syscheck".into(), "fim".into(), "scan_lifecycle".into()],
                    mitre: None,
                },
                r"(?i)File integrity monitoring scan ended",
            ),
            (
                Rule {
                    id: 5541,
                    level: 8,
                    description: "syscheck: File permissions altered (mode change / chmod tampering)".into(),
                    regex_pattern: r"(?i)Permissions changed for".into(),
                    groups: vec!["syscheck".into(), "fim".into(), "permission_tampering".into()],
                    mitre: Some(MitreAttack {
                        id: "T1222".into(),
                        tactic: "Defense Evasion".into(),
                        technique: "File and Directory Permissions Modification".into(),
                    }),
                },
                r"(?i)Permissions changed for",
            ),
            (
                Rule {
                    id: 5542,
                    level: 8,
                    description: "syscheck: File ownership altered (UID/GID change / chown tampering)".into(),
                    regex_pattern: r"(?i)Ownership changed for".into(),
                    groups: vec!["syscheck".into(), "fim".into(), "ownership_tampering".into()],
                    mitre: Some(MitreAttack {
                        id: "T1222".into(),
                        tactic: "Defense Evasion".into(),
                        technique: "File and Directory Permissions Modification".into(),
                    }),
                },
                r"(?i)Ownership changed for",
            ),
            (
                Rule {
                    id: 51001,
                    level: 13,
                    description: "rootcheck: Known trojan or rootkit signature detected on filesystem".into(),
                    regex_pattern: r"(?i)rootcheck: Known trojan/rootkit signature detected".into(),
                    groups: vec!["rootcheck".into(), "malware".into()],
                    mitre: Some(MitreAttack {
                        id: "T1014".into(),
                        tactic: "Defense Evasion".into(),
                        technique: "Rootkit".into(),
                    }),
                },
                r"(?i)rootcheck: Known trojan/rootkit signature detected",
            ),
            (
                Rule {
                    id: 51002,
                    level: 11,
                    description: "rootcheck: NTFS Alternate Data Stream detected (Hidden backdoor artifact)".into(),
                    regex_pattern: r"(?i)rootcheck: NTFS Alternate Data Stream found".into(),
                    groups: vec!["rootcheck".into(), "defense_evasion".into()],
                    mitre: Some(MitreAttack {
                        id: "T1564.004".into(),
                        tactic: "Defense Evasion".into(),
                        technique: "NTFS File Attributes".into(),
                    }),
                },
                r"(?i)rootcheck: NTFS Alternate Data Stream found",
            ),
            (
                Rule {
                    id: 60100,
                    level: 14,
                    description: "powershell: Suspicious base64-encoded or in-memory execution payload (Mimikatz / CobaltStrike)".into(),
                    regex_pattern: r"(?i)(?:powershell.*-(?:enc|encodedcommand|nop|w hidden)|mimikatz|sekurlsa::logonpasswords)".into(),
                    groups: vec!["windows".into(), "powershell".into(), "execution".into()],
                    mitre: Some(MitreAttack {
                        id: "T1059.001".into(),
                        tactic: "Execution".into(),
                        technique: "PowerShell".into(),
                    }),
                },
                r"(?i)(?:powershell.*-(?:enc|encodedcommand|nop|w hidden)|mimikatz|sekurlsa::logonpasswords)",
            ),
            (
                Rule {
                    id: 5402,
                    level: 9,
                    description: "sudo: Successful privilege escalation executed by non-root user".into(),
                    regex_pattern: r"(?i)sudo:\s+\w+\s*:\s*COMMAND=(?:/usr/bin/su|/bin/bash|/bin/sh)".into(),
                    groups: vec!["syslog".into(), "sudo".into(), "privilege_escalation".into()],
                    mitre: Some(MitreAttack {
                        id: "T1548".into(),
                        tactic: "Privilege Escalation".into(),
                        technique: "Abuse Elevation Control Mechanism".into(),
                    }),
                },
                r"(?i)sudo:\s+\w+\s*:\s*COMMAND=(?:/usr/bin/su|/bin/bash|/bin/sh)",
            ),
            (
                Rule {
                    id: 70010,
                    level: 15,
                    description: "ransomware: Suspicious high-entropy extension or mass file encryption behavior".into(),
                    regex_pattern: r"(?i)\.(?:locked|crypt|encrypted|crypted|wnry)\b".into(),
                    groups: vec!["malware".into(), "ransomware".into(), "impact".into()],
                    mitre: Some(MitreAttack {
                        id: "T1486".into(),
                        tactic: "Impact".into(),
                        technique: "Data Encrypted for Impact".into(),
                    }),
                },
                r"(?i)\.(?:locked|crypt|encrypted|crypted|wnry)\b",
            ),
        ];

        raw_rules
            .into_iter()
            .map(|(rule, pat)| CompiledRule {
                regex: Regex::new(pat).unwrap(),
                rule,
            })
            .collect()
    }

    fn default_wazuh_decoders() -> Vec<CompiledDecoder> {
        let xml = r#"
<decoders>
  <decoder name="sshd">
    <program_name>^sshd</program_name>
  </decoder>

  <decoder name="sshd-success">
    <parent>sshd</parent>
    <prematch>^Accepted</prematch>
    <regex>^Accepted \S+ for (\S+) from (\S+) port (\d+)</regex>
    <order>user, srcip, srcport</order>
  </decoder>

  <decoder name="sshd-failed">
    <parent>sshd</parent>
    <prematch>^Failed \S+ </prematch>
    <regex>^Failed \S+ for (\S+) from (\S+) port (\d+)</regex>
    <order>user, srcip, srcport</order>
  </decoder>

  <decoder name="sshd-invfailed">
    <parent>sshd</parent>
    <prematch>^Failed \S+ for invalid user|^Failed \S+ for illegal user</prematch>
    <regex>for (?:invalid|illegal) user (\S+) from (\S+) port (\d+)</regex>
    <order>user, srcip, srcport</order>
  </decoder>

  <decoder name="windows-eventchannel">
    <prematch>^Windows-Event</prematch>
    <regex>Windows-Event \[([^\]]+)\] EventID:(\d+).*User:([^\s]+)</regex>
    <order>extra_data, id, user</order>
  </decoder>

  <decoder name="syscheck-fim">
    <prematch>^File '</prematch>
    <regex>File '([^']+)' (modified|added|deleted|checksum changed)</regex>
    <order>path, action</order>
  </decoder>
</decoders>
        "#;
        parse_decoders_xml(xml)
    }

    fn default_wazuh_rules() -> Vec<CompiledWazuhRule> {
        let xml = r#"
<ruleset>
  <!-- OSSEC Base Rules -->
  <group name="ossec,">
    <rule id="500" level="0" noalert="1">
      <category>ossec</category>
      <decoded_as>ossec</decoded_as>
      <description>Grouping of wazuh rules.</description>
    </rule>

    <rule id="501" level="3">
      <if_sid>500</if_sid>
      <match>Agent started</match>
      <description>New wazuh agent connected.</description>
      <group>pci_dss_10.6.1,gdpr_IV_35.7.d</group>
    </rule>

    <rule id="504" level="3">
      <if_sid>500</if_sid>
      <match>Agent disconnected</match>
      <description>Wazuh agent disconnected.</description>
      <mitre><id>T1562.001</id><tactic>Defense Evasion</tactic><technique>Disable or Modify Tools</technique></mitre>
      <group>pci_dss_10.6.1,gdpr_IV_35.7.d</group>
    </rule>
  </group>

  <!-- SSH Rules (from official 0095-sshd_rules.xml) -->
  <group name="syslog,sshd,">
    <rule id="5700" level="0" noalert="1">
      <decoded_as>sshd</decoded_as>
      <description>SSHD messages grouped.</description>
    </rule>

    <rule id="5710" level="5">
      <if_sid>5700</if_sid>
      <match>illegal user|invalid user</match>
      <description>sshd: Attempt to login using a non-existent user.</description>
      <mitre><id>T1110</id><tactic>Credential Access</tactic><technique>Brute Force</technique></mitre>
      <group>invalid_login,authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5</group>
    </rule>

    <rule id="5715" level="3">
      <if_sid>5700</if_sid>
      <match>Accepted</match>
      <description>sshd: Authentication succeeded.</description>
      <mitre><id>T1078</id><tactic>Initial Access</tactic><technique>Valid Accounts</technique></mitre>
      <group>authentication_success,pci_dss_10.2.5</group>
    </rule>

    <rule id="5716" level="5">
      <if_sid>5700</if_sid>
      <match>Failed password|Failed none</match>
      <description>sshd: Authentication failed.</description>
      <mitre><id>T1110</id><tactic>Credential Access</tactic><technique>Brute Force</technique></mitre>
      <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5</group>
    </rule>
  </group>

  <!-- Windows Security Rules (from official 0580-win-security_rules.xml) -->
  <group name="windows,windows_security,">
    <rule id="60100" level="0" noalert="1">
      <category>windows</category>
      <description>Grouping of Windows Security rules.</description>
    </rule>

    <rule id="60101" level="5">
      <if_sid>60100</if_sid>
      <match>4625</match>
      <description>windows: Logon failure - Unknown user name or bad password.</description>
      <mitre><id>T1110</id><tactic>Credential Access</tactic><technique>Brute Force</technique></mitre>
      <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5</group>
    </rule>

    <rule id="60102" level="12">
      <if_sid>60100</if_sid>
      <match>1102</match>
      <description>windows: The audit log was cleared (Defense Evasion).</description>
      <mitre><id>T1070.001</id><tactic>Defense Evasion</tactic><technique>Clear Windows Event Logs</technique></mitre>
      <group>logs_cleared,pci_dss_10.5.2</group>
    </rule>

    <rule id="60103" level="10">
      <if_sid>60100</if_sid>
      <match>7045</match>
      <description>windows: A service was installed in the system (Persistence).</description>
      <mitre><id>T1543.003</id><tactic>Persistence</tactic><technique>Windows Service</technique></mitre>
      <group>service_installed,pci_dss_10.6.1</group>
    </rule>
  </group>
</ruleset>
        "#;
        parse_rules_xml(xml)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siem_core::EventSource;

    #[test]
    fn test_wazuh_xml_decoding_and_rule_evaluation() {
        let engine = AnalysisEngine::new();

        // 1. Test SSH Failed Login log matching Wazuh rule 5716
        let ssh_failed_log = "sshd[1234]: Failed password for root from 192.168.1.50 port 45233 ssh2";
        let event = RawEvent::new("001", EventSource::Syslog, "/var/log/auth.log", ssh_failed_log);

        let alert = engine.process_event(&event, "ubuntu-node", "192.168.1.50");
        assert!(alert.is_some(), "Alert should be generated for ssh failed login");
        let alert = alert.unwrap();
        assert_eq!(alert.rule.id, 5716);
        assert_eq!(alert.decoded.user.as_deref(), Some("root"));
        assert_eq!(alert.decoded.src_ip.as_deref(), Some("192.168.1.50"));
        assert_eq!(alert.decoded.src_port, Some(45233));
        assert!(alert.manager.is_some());
        assert_eq!(alert.manager.as_ref().unwrap().name, "wazuh-manager-rust");

        // 2. Test Windows EventLog 4625 matching Wazuh rule 60101
        let win_event_log = "Windows-Event [Security] EventID:4625 An account failed to log on. User:Administrator";
        let event_win = RawEvent::new("002", EventSource::WindowsEvent, "Security", win_event_log);

        let alert_win = engine.process_event(&event_win, "win-server", "192.168.1.10");
        assert!(alert_win.is_some(), "Alert should be generated for Windows Event 4625");
        let alert_win = alert_win.unwrap();
        assert_eq!(alert_win.rule.id, 60101);
        assert!(alert_win.rule.level >= 5);
        assert_eq!(alert_win.rule.mitre.as_ref().unwrap().id, "T1110");
    }
}
