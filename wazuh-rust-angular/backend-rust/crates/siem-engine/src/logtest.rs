//! Wazuh Logtest Emulation Engine (src/analysisd/logtest.c)
//!
//! Provides the diagnostic test engine simulating Phase 1 (pre-decoding),
//! Phase 2 (decoding), and Phase 3 (rule matching) matching upstream `wazuh-logtest`.

use crate::AnalysisEngine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use siem_core::{EventSource, MitreAttack, RawEvent};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogtestResult {
    pub raw_event: String,
    pub predecoded_timestamp: Option<String>,
    pub predecoded_hostname: Option<String>,
    pub predecoded_program_name: Option<String>,
    pub predecoded_log: String,
    pub decoder_name: String,
    pub extracted_fields: HashMap<String, String>,
    pub matched_rule_id: Option<u32>,
    pub matched_rule_level: Option<u8>,
    pub matched_rule_description: Option<String>,
    pub matched_rule_groups: Vec<String>,
    pub mitre_attack: Option<MitreAttack>,
}

impl LogtestResult {
    /// Formats the result as traditional Wazuh Logtest output
    pub fn format_wazuh_output(&self) -> String {
        let mut out = String::new();

        out.push_str("\n**Phase 1: Completed pre-decoding.\n");
        out.push_str(&format!("    full event: '{}'\n", self.raw_event));
        if let Some(ts) = &self.predecoded_timestamp {
            out.push_str(&format!("    timestamp: '{}'\n", ts));
        }
        if let Some(host) = &self.predecoded_hostname {
            out.push_str(&format!("    hostname: '{}'\n", host));
        }
        if let Some(prog) = &self.predecoded_program_name {
            out.push_str(&format!("    program_name: '{}'\n", prog));
        }
        out.push_str(&format!("    log: '{}'\n", self.predecoded_log));

        out.push_str("\n**Phase 2: Completed decoding.\n");
        out.push_str(&format!("    name: '{}'\n", self.decoder_name));
        let mut sorted_fields: Vec<(&String, &String)> = self.extracted_fields.iter().collect();
        sorted_fields.sort_by_key(|(k, _)| (*k).clone());
        for (k, v) in sorted_fields {
            out.push_str(&format!("    {}: '{}'\n", k, v));
        }

        out.push_str("\n**Phase 3: Completed filtering (rules).\n");
        if let Some(id) = self.matched_rule_id {
            out.push_str(&format!("    id: '{}'\n", id));
            out.push_str(&format!("    level: '{}'\n", self.matched_rule_level.unwrap_or(0)));
            out.push_str(&format!("    description: '{}'\n", self.matched_rule_description.as_deref().unwrap_or("")));
            out.push_str(&format!("    groups: '{:?}'\n", self.matched_rule_groups));
            if let Some(mitre) = &self.mitre_attack {
                out.push_str(&format!("    mitre.id: '{}'\n", mitre.id));
                out.push_str(&format!("    mitre.tactic: '{}'\n", mitre.tactic));
                out.push_str(&format!("    mitre.technique: '{}'\n", mitre.technique));
            }
        } else {
            out.push_str("    No rule matched for this event.\n");
        }

        out
    }
}

pub struct LogtestEngine {
    engine: AnalysisEngine,
    syslog_header_re: Regex,
}

impl Default for LogtestEngine {
    fn default() -> Self {
        Self::new(AnalysisEngine::new())
    }
}

impl LogtestEngine {
    pub fn new(engine: AnalysisEngine) -> Self {
        // Matches standard syslog headers: "Mmm dd hh:mm:ss host prog[pid]: " or "prog: "
        let syslog_header_re = Regex::new(
            r"^(?:(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?(?:(?P<host>[\w\.\-]+)\s+)?(?P<prog>[\w\.\-\(\)]+?)(?:\[\d+\])?: (?P<log>.*)$",
        )
        .unwrap();

        Self {
            engine,
            syslog_header_re,
        }
    }

    /// Analyze a single raw log line through the 3-phase Wazuh pipeline
    pub fn test_log(&self, line: &str) -> LogtestResult {
        let trimmed = line.trim();

        // Phase 1: Pre-decoding
        let (ts, host, prog, log_body) = if let Some(caps) = self.syslog_header_re.captures(trimmed) {
            let ts = caps.name("ts").map(|m| m.as_str().to_string());
            let host = caps.name("host").map(|m| m.as_str().to_string());
            let prog = caps.name("prog").map(|m| m.as_str().to_string());
            let log = caps.name("log").map(|m| m.as_str().to_string()).unwrap_or_else(|| trimmed.to_string());
            (ts, host, prog, log)
        } else {
            (None, None, None, trimmed.to_string())
        };

        // Construct RawEvent and run Phase 2 & 3 through AnalysisEngine
        let event = RawEvent::new("000", EventSource::Syslog, "logtest", trimmed);
        let alert = self.engine.process_event(&event, "logtest-node", "127.0.0.1");

        // Build extracted fields dictionary
        let mut extracted_fields = HashMap::new();
        let decoder_name = if let Some(al) = &alert {
            al.decoder.as_ref().map(|d| d.name.clone()).unwrap_or_else(|| "syslog".to_string())
        } else {
            prog.clone().unwrap_or_else(|| "syslog".to_string())
        };

        if let Some(al) = &alert {
            if let Some(ip) = &al.decoded.src_ip {
                extracted_fields.insert("srcip".to_string(), ip.clone());
            }
            if let Some(port) = al.decoded.src_port {
                extracted_fields.insert("srcport".to_string(), port.to_string());
            }
            if let Some(user) = &al.decoded.user {
                extracted_fields.insert("user".to_string(), user.clone());
            }
            if let Some(action) = &al.decoded.action {
                extracted_fields.insert("action".to_string(), action.clone());
            }
            if let Some(p) = &al.decoded.program_name {
                extracted_fields.insert("program_name".to_string(), p.clone());
            }
            if let Some(path) = &al.decoded.file_path {
                extracted_fields.insert("file_path".to_string(), path.clone());
            }
        }

        let (matched_rule_id, matched_rule_level, matched_rule_description, matched_rule_groups, mitre_attack) =
            if let Some(al) = alert {
                (
                    Some(al.rule.id),
                    Some(al.rule.level),
                    Some(al.rule.description),
                    al.rule.groups,
                    al.rule.mitre,
                )
            } else {
                (None, None, None, Vec::new(), None)
            };

        LogtestResult {
            raw_event: trimmed.to_string(),
            predecoded_timestamp: ts,
            predecoded_hostname: host,
            predecoded_program_name: prog,
            predecoded_log: log_body,
            decoder_name,
            extracted_fields,
            matched_rule_id,
            matched_rule_level,
            matched_rule_description,
            matched_rule_groups,
            mitre_attack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logtest_sshd_failed_login() {
        let logtest = LogtestEngine::default();
        let log = "Oct 03 14:00:00 ubuntu sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 45222 ssh2";

        let res = logtest.test_log(log);
        assert_eq!(res.predecoded_timestamp.as_deref(), Some("Oct 03 14:00:00"));
        assert_eq!(res.predecoded_hostname.as_deref(), Some("ubuntu"));
        assert_eq!(res.predecoded_program_name.as_deref(), Some("sshd"));
        assert_eq!(res.extracted_fields.get("srcip").map(|s| s.as_str()), Some("192.168.1.100"));
        assert!(res.matched_rule_id.is_some());
        assert_eq!(res.matched_rule_id.unwrap(), 5716);

        let output = res.format_wazuh_output();
        assert!(output.contains("**Phase 1: Completed pre-decoding."));
        assert!(output.contains("**Phase 2: Completed decoding."));
        assert!(output.contains("**Phase 3: Completed filtering (rules)."));
        assert!(output.contains("id: '5716'"));
    }
}
