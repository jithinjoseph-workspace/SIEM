//! The console's Logtest page: one line through the engine, with each step shown.

use std::collections::BTreeMap;
use std::fmt::Write;

use serde::Serialize;
use siem_core::{EventSource, MitreAttack, RawEvent};

use crate::{split_syslog, AnalysisEngine};

/// What happened to one test line. Sent to the console as JSON.
#[derive(Debug, Clone, Serialize)]
pub struct LogtestResult {
    pub raw_event: String,
    pub predecoded_timestamp: Option<String>,
    pub predecoded_hostname: Option<String>,
    pub predecoded_program_name: Option<String>,
    pub predecoded_log: String,
    pub decoder_name: String,
    pub extracted_fields: BTreeMap<String, String>,
    pub matched_rule_id: Option<u32>,
    pub matched_rule_level: Option<u8>,
    pub matched_rule_description: Option<String>,
    pub matched_rule_groups: Vec<String>,
    pub mitre_attack: Option<MitreAttack>,
}

pub struct LogtestEngine {
    engine: AnalysisEngine,
}

impl LogtestEngine {
    pub fn new(engine: AnalysisEngine) -> Self {
        LogtestEngine { engine }
    }

    pub fn test_log(&self, line: &str) -> LogtestResult {
        let line = line.trim();
        let header = split_syslog(line);
        let d = self.engine.decode(line).decoded;
        let event = RawEvent::new("000", EventSource::Syslog, "logtest", line);
        let alert = self.engine.process_event(&event, "logtest", "127.0.0.1");

        let decoder_name = if d.decoder_name != "generic-syslog" {
            d.decoder_name.clone()
        } else {
            d.program_name.clone().unwrap_or_else(|| "syslog".into())
        };
        let mut extracted_fields: BTreeMap<String, String> = d.extra.clone().into_iter().collect();
        let named = [
            ("srcip", d.src_ip.clone()),
            ("srcport", d.src_port.map(|p| p.to_string())),
            ("user", d.user.clone()),
            ("action", d.action.clone()),
            ("program_name", d.program_name.clone()),
            ("file_path", d.file_path.clone()),
        ];
        extracted_fields.extend(named.into_iter().filter_map(|(k, v)| Some((k.to_string(), v?))));

        let rule = alert.map(|a| a.rule);
        LogtestResult {
            raw_event: line.to_string(),
            predecoded_timestamp: header.as_ref().map(|h| h.timestamp.to_string()),
            predecoded_hostname: header.as_ref().map(|h| h.host.to_string()),
            predecoded_program_name: header.as_ref().map(|h| h.program.to_string()),
            predecoded_log: header.as_ref().map_or(line, |h| h.log).to_string(),
            decoder_name,
            extracted_fields,
            matched_rule_id: rule.as_ref().map(|r| r.id),
            matched_rule_level: rule.as_ref().map(|r| r.level),
            matched_rule_description: rule.as_ref().map(|r| r.description.clone()),
            matched_rule_groups: rule.as_ref().map(|r| r.groups.clone()).unwrap_or_default(),
            mitre_attack: rule.and_then(|r| r.mitre),
        }
    }
}

impl LogtestResult {
    /// The result as text in three titled parts, one `name: 'value'` per line.
    pub fn format_text(&self) -> String {
        fn line(out: &mut String, k: &str, v: &str) {
            let _ = writeln!(out, "\t{k}: '{v}'");
        }
        let mut out = String::new();
        out.push_str("** Pre-decoding:\n");
        line(&mut out, "full event", &self.raw_event);
        for (k, v) in [
            ("timestamp", &self.predecoded_timestamp),
            ("hostname", &self.predecoded_hostname),
            ("program_name", &self.predecoded_program_name),
        ] {
            if let Some(v) = v {
                line(&mut out, k, v);
            }
        }
        line(&mut out, "log", &self.predecoded_log);

        out.push_str("\n** Decoding:\n");
        line(&mut out, "name", &self.decoder_name);
        for (k, v) in &self.extracted_fields {
            line(&mut out, k, v);
        }

        out.push_str("\n** Rule matching:\n");
        match (self.matched_rule_id, self.matched_rule_level) {
            (Some(id), Some(level)) => {
                line(&mut out, "id", &id.to_string());
                line(&mut out, "level", &level.to_string());
                line(&mut out, "description", self.matched_rule_description.as_deref().unwrap_or(""));
                line(&mut out, "groups", &self.matched_rule_groups.join(", "));
                if let Some(m) = &self.mitre_attack {
                    line(&mut out, "mitre.id", &m.id);
                    line(&mut out, "mitre.tactic", &m.tactic);
                    line(&mut out, "mitre.technique", &m.technique);
                }
            }
            _ => out.push_str("\tNo rule matched.\n"),
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd_line() {
        let lt = LogtestEngine::new(AnalysisEngine::with_ruleset(None));
        let r = lt.test_log("  Oct 12 08:15:01 web01 sshd[2211]: Invalid user oracle from 203.0.113.7 port 40022  ");
        assert_eq!(r.raw_event, "Oct 12 08:15:01 web01 sshd[2211]: Invalid user oracle from 203.0.113.7 port 40022");
        assert_eq!(r.predecoded_timestamp.as_deref(), Some("Oct 12 08:15:01"));
        assert_eq!(r.predecoded_hostname.as_deref(), Some("web01"));
        assert_eq!(r.predecoded_program_name.as_deref(), Some("sshd"));
        assert_eq!(r.predecoded_log, "Invalid user oracle from 203.0.113.7 port 40022");
        assert_eq!(r.decoder_name, "sshd-auth");
        assert_eq!(r.extracted_fields["srcip"], "203.0.113.7");
        assert_eq!(r.extracted_fields["srcport"], "40022");
        assert_eq!(r.extracted_fields["user"], "oracle");
        assert_eq!(r.extracted_fields["program_name"], "sshd");
        assert_eq!((r.matched_rule_id, r.matched_rule_level), (Some(5710), Some(5)));
        assert_eq!(r.matched_rule_groups, ["syslog", "sshd", "invalid_login"]);
        assert_eq!(r.mitre_attack.as_ref().unwrap().id, "T1110");

        let text = r.format_text();
        assert!(text.contains("** Pre-decoding:\n\tfull event: 'Oct 12"));
        assert!(text.contains("\thostname: 'web01'\n"));
        assert!(text.contains("** Decoding:\n\tname: 'sshd-auth'\n"));
        assert!(text.contains("** Rule matching:\n\tid: '5710'\n\tlevel: '5'\n"));
        assert!(text.contains("\tmitre.id: 'T1110'\n"));

        let json = serde_json::to_value(&r).unwrap();
        let mut keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "decoder_name", "extracted_fields", "matched_rule_description", "matched_rule_groups",
                "matched_rule_id", "matched_rule_level", "mitre_attack", "predecoded_hostname", "predecoded_log",
                "predecoded_program_name", "predecoded_timestamp", "raw_event"
            ]
        );

        let none = lt.test_log("2026-11-03T10:00:00Z db01 cron[9]: job done");
        assert_eq!(none.predecoded_program_name.as_deref(), Some("cron"));
        assert_eq!(none.decoder_name, "cron");
        assert!(none.matched_rule_id.is_none());
        assert!(none.format_text().ends_with("** Rule matching:\n\tNo rule matched.\n"));
        assert_eq!(lt.test_log("plain text").decoder_name, "syslog");
    }
}
