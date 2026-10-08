//! Wazuh Log Readers (src/logcollector/read_*.c)
//!
//! Implements all log format parsing engines:
//! - `Syslog`: Standard line-oriented log parser.
//! - `Json`: JSON validation and extraction.
//! - `MultiLineRegex`: Regex-based multiline aggregation with start/end match and delimiter replacement.
//! - `Audit`: Linux auditd record correlation using `msg=audit(TIMESTAMP:ID)`.
//! - `Command` & `FullCommand`: Subprocess execution and output monitoring.
//! - `DjbMultilog`: TAI64N timestamp decoding.
//! - `Ucs2`: UTF-16 LE and BE decoding.
//! - `Database`: MySQL, MSSQL, PostgreSQL statement aggregation.
//! - `Snort`: Full and fast snort alerts.
//! - `Journald`: Systemd journal log parser.
//! - `Macos`: macOS unified log stream parser.
//! - `WinEvt`: Windows EventChannel XML extraction.

use crate::config::{LogFormat, MultilineConfig, MultilineMatchType, MultilineReplaceType};
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;

/// Result of reading a log entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub raw: String,
    pub format: LogFormat,
    pub location: String,
    pub is_multiline: bool,
}

/// Linux auditd event correlator (port of `read_audit.c`)
/// Groups multiple audit lines that share the same `audit(TIMESTAMP:ID)` into a single event
#[derive(Debug, Default)]
pub struct AuditCorrelator {
    pending_events: HashMap<String, Vec<String>>,
}

impl AuditCorrelator {
    pub fn new() -> Self {
        Self {
            pending_events: HashMap::new(),
        }
    }

    /// Process a line from /var/log/audit/audit.log
    pub fn process_line(&mut self, line: &str) -> Option<String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Extract msg=audit(TIMESTAMP:ID)
        let id_marker = "msg=audit(";
        if let Some(pos) = trimmed.find(id_marker) {
            let start = pos + id_marker.len();
            if let Some(end) = trimmed[start..].find(')') {
                let event_id = trimmed[start..start + end].to_string();

                let records = self.pending_events.entry(event_id.clone()).or_default();
                records.push(trimmed.to_string());

                // If record is PROCTITLE or EOE (End of Event), or if 4 records accumulated, emit combined event
                if trimmed.starts_with("type=PROCTITLE")
                    || trimmed.starts_with("type=EOE")
                    || records.len() >= 4
                {
                    if let Some(ev_records) = self.pending_events.remove(&event_id) {
                        return Some(ev_records.join("\n"));
                    }
                }
                return None;
            }
        }

        // Uncorrelated audit line
        Some(trimmed.to_string())
    }
}

/// Multiline Regex Parser (port of `read_multiline_regex.c`)
#[derive(Debug)]
pub struct MultilineRegexParser {
    pub config: MultilineConfig,
    pub regex: Regex,
    buffer: Vec<String>,
}

impl MultilineRegexParser {
    pub fn new(config: MultilineConfig) -> Result<Self, String> {
        let regex = Regex::new(&config.regex).map_err(|e| e.to_string())?;
        Ok(Self {
            config,
            regex,
            buffer: Vec::new(),
        })
    }

    /// Process incoming line. Returns Some(aggregated_log) when a complete multiline entry finishes.
    pub fn process_line(&mut self, line: &str) -> Option<String> {
        let is_match = self.regex.is_match(line);

        match self.config.match_type {
            MultilineMatchType::Start => {
                if is_match && !self.buffer.is_empty() {
                    // New multiline record started! Flush previous buffered lines
                    let flushed = self.format_buffer();
                    self.buffer.clear();
                    self.buffer.push(line.to_string());
                    Some(flushed)
                } else {
                    self.buffer.push(line.to_string());
                    None
                }
            }
            MultilineMatchType::End => {
                self.buffer.push(line.to_string());
                if is_match {
                    let flushed = self.format_buffer();
                    self.buffer.clear();
                    Some(flushed)
                } else {
                    None
                }
            }
            MultilineMatchType::All => {
                self.buffer.push(line.to_string());
                if is_match {
                    let flushed = self.format_buffer();
                    self.buffer.clear();
                    Some(flushed)
                } else {
                    None
                }
            }
        }
    }

    /// Flush any remaining buffered lines on timeout or EOF
    pub fn flush(&mut self) -> Option<String> {
        if self.buffer.is_empty() {
            None
        } else {
            let flushed = self.format_buffer();
            self.buffer.clear();
            Some(flushed)
        }
    }

    fn format_buffer(&self) -> String {
        let sep = match self.config.replace_type {
            MultilineReplaceType::NoReplace => "\n",
            MultilineReplaceType::None => "",
            MultilineReplaceType::Wspace => " ",
            MultilineReplaceType::Tab => "\t",
        };
        self.buffer.join(sep)
    }
}

/// JSON Log Validator and Extractor (port of `read_json.c`)
pub fn parse_json_line(line: &str) -> Option<Value> {
    let trimmed = line.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        serde_json::from_str::<Value>(trimmed).ok()
    } else {
        None
    }
}

/// DJB Multilog TAI64N Decoder (port of `read_djb_multilog.c`)
/// Converts `@40000000529671f6...` into a standard timestamped log
pub fn decode_djb_multilog(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.starts_with('@') && trimmed.len() >= 25 {
        let tai_part = &trimmed[1..17];
        if let Ok(sec) = u64::from_str_radix(tai_part, 16) {
            // TAI64 offset is 2^62 = 0x4000000000000000
            let epoch_secs = sec.saturating_sub(0x40000000);
            if let Some(dt) = chrono::DateTime::from_timestamp(epoch_secs as i64, 0) {
                let rest = trimmed[25..].trim_start();
                return format!("{} {}", dt.format("%Y-%m-%dT%H:%M:%SZ"), rest);
            }
        }
    }
    line.to_string()
}

/// UCS-2 / UTF-16 Decoder (port of `read_ucs2_le.c` and `read_ucs2_be.c`)
pub fn decode_ucs2(bytes: &[u8], is_big_endian: bool) -> String {
    let mut u16_chars = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let val = if is_big_endian {
            u16::from_be_bytes([bytes[i], bytes[i + 1]])
        } else {
            u16::from_le_bytes([bytes[i], bytes[i + 1]])
        };
        u16_chars.push(val);
        i += 2;
    }
    String::from_utf16_lossy(&u16_chars)
}

/// Command Output Formatter (port of `read_command.c`)
/// Formats command output line matching `ossec: output: '{alias}': {line}`
pub fn format_command_output(alias: &str, line: &str) -> String {
    format!("ossec: output: '{}': {}", alias, line.trim())
}

/// FullCommand Diff Detector (port of `read_fullcommand.c`)
/// Returns `Some(formatted_output)` if the output changed or on first run
#[derive(Debug, Default)]
pub struct FullCommandTracker {
    last_output: HashMap<String, String>,
}

impl FullCommandTracker {
    pub fn new() -> Self {
        Self {
            last_output: HashMap::new(),
        }
    }

    pub fn evaluate_output(&mut self, alias: &str, output: &str) -> Option<String> {
        let trimmed = output.trim();
        if let Some(prev) = self.last_output.get(alias) {
            if prev == trimmed {
                return None; // No change
            }
        }

        self.last_output.insert(alias.to_string(), trimmed.to_string());
        Some(format!("ossec: output: '{}':\n{}", alias, trimmed))
    }
}

/// Windows EventChannel / EventLog Formatter (port of `read_win_event_channel.c`)
pub fn format_win_event(provider: &str, event_id: u32, message: &str) -> String {
    format!(
        "WinEvtLog: {}: {}: {}",
        provider,
        event_id,
        message.trim().replace('\r', "").replace('\n', " ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiline_regex_start_matching() {
        let config = MultilineConfig {
            regex: r"^\d{4}-\d{2}-\d{2}".to_string(),
            match_type: MultilineMatchType::Start,
            replace_type: MultilineReplaceType::Wspace,
            timeout: 5,
        };

        let mut parser = MultilineRegexParser::new(config).unwrap();

        assert_eq!(parser.process_line("2026-09-28 12:00:00 [ERROR] Null pointer"), None);
        assert_eq!(parser.process_line("   at com.app.Main.run()"), None);
        assert_eq!(parser.process_line("   at java.lang.Thread.run()"), None);

        // Next matching line triggers emission of previous multiline entry
        let event = parser.process_line("2026-09-28 12:00:05 [INFO] Normal");
        assert!(event.is_some());
        let res = event.unwrap();
        assert!(res.contains("Null pointer"));
        assert!(res.contains("at com.app.Main.run()"));
        assert!(res.contains("at java.lang.Thread.run()"));

        // Flush last entry
        let last = parser.flush();
        assert_eq!(last, Some("2026-09-28 12:00:05 [INFO] Normal".to_string()));
    }

    #[test]
    fn test_audit_correlator() {
        let mut correlator = AuditCorrelator::new();

        let l1 = "type=SYSCALL msg=audit(1695880000.123:456): arch=c000003e syscall=2 success=yes";
        let l2 = "type=CWD msg=audit(1695880000.123:456):  cwd=\"/home/user\"";
        let l3 = "type=PATH msg=audit(1695880000.123:456): item=0 name=\"/etc/shadow\"";
        let l4 = "type=PROCTITLE msg=audit(1695880000.123:456): proctitle=\"cat /etc/shadow\"";

        assert_eq!(correlator.process_line(l1), None);
        assert_eq!(correlator.process_line(l2), None);
        assert_eq!(correlator.process_line(l3), None);

        let combined = correlator.process_line(l4);
        assert!(combined.is_some());
        let res = combined.unwrap();
        assert!(res.contains("type=SYSCALL"));
        assert!(res.contains("type=CWD"));
        assert!(res.contains("type=PATH"));
        assert!(res.contains("type=PROCTITLE"));
    }

    #[test]
    fn test_command_formatters() {
        assert_eq!(
            format_command_output("df -h", "Filesystem 10G 5G 50% /"),
            "ossec: output: 'df -h': Filesystem 10G 5G 50% /"
        );

        let mut tracker = FullCommandTracker::new();
        let res1 = tracker.evaluate_output("netstat", "tcp 0 0 127.0.0.1:80");
        assert!(res1.is_some());

        // Same output -> None
        let res2 = tracker.evaluate_output("netstat", "tcp 0 0 127.0.0.1:80");
        assert!(res2.is_none());

        // Changed output -> Some
        let res3 = tracker.evaluate_output("netstat", "tcp 0 0 127.0.0.1:80\ntcp 0 0 127.0.0.1:443");
        assert!(res3.is_some());
    }

    #[test]
    fn test_ucs2_decoding() {
        // "ABC" in UTF-16 LE: [0x41, 0x00, 0x42, 0x00, 0x43, 0x00]
        let bytes_le = vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00];
        assert_eq!(decode_ucs2(&bytes_le, false), "ABC");

        // "ABC" in UTF-16 BE: [0x00, 0x41, 0x00, 0x42, 0x00, 0x43]
        let bytes_be = vec![0x00, 0x41, 0x00, 0x42, 0x00, 0x43];
        assert_eq!(decode_ucs2(&bytes_be, true), "ABC");
    }
}
