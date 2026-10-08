//! Report Aggregation & Stream Evaluation Engine (`src/reportd/report.c`)

use crate::filter::{AlertRecord, ReportFilter};
use std::collections::HashMap;
use std::io::{BufRead, Write};

#[derive(Debug, Clone, Default)]
pub struct ReportEngine {
    pub total_alerts: usize,
    pub matched_alerts: usize,
    pub field_counts: HashMap<String, usize>,
    pub related_counts: HashMap<(String, String), usize>,
    pub matching_samples: Vec<String>,
}

impl ReportEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses a single line/block into an AlertRecord.
    pub fn parse_line(line: &str) -> Option<AlertRecord> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        if trimmed.starts_with('{') {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let rule_id = val
                    .get("rule")
                    .and_then(|r| r.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string();

                let level = val
                    .get("rule")
                    .and_then(|r| r.get("level"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;

                let mut groups = Vec::new();
                if let Some(arr) = val.get("rule").and_then(|r| r.get("groups")).and_then(|v| v.as_array()) {
                    for g in arr.iter().filter_map(|x| x.as_str()) {
                        groups.push(g.to_string());
                    }
                }

                let location = val
                    .get("location")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let srcip = val
                    .get("data")
                    .and_then(|d| d.get("srcip"))
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);

                let user = val
                    .get("data")
                    .and_then(|d| d.get("dstuser").or_else(|| d.get("user")))
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);

                let filename = val
                    .get("syscheck")
                    .and_then(|s| s.get("path"))
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);

                return Some(AlertRecord {
                    rule_id,
                    level,
                    groups,
                    location,
                    srcip,
                    user,
                    filename,
                    raw: trimmed.to_string(),
                });
            }
        }

        // Fallback for simple space-delimited text or raw alert line
        Some(AlertRecord {
            rule_id: "0".to_string(),
            level: 1,
            groups: Vec::new(),
            location: String::new(),
            srcip: None,
            user: None,
            filename: None,
            raw: trimmed.to_string(),
        })
    }

    /// Evaluates stream of alerts against the filter.
    pub fn process_stream<R: BufRead>(&mut self, reader: R, filter: &ReportFilter) {
        for line in reader.lines().map_while(Result::ok) {
            if let Some(alert) = Self::parse_line(&line) {
                self.total_alerts += 1;
                if filter.matches(&alert) {
                    self.matched_alerts += 1;

                    // Group / primary counting
                    let primary_key = alert.rule_id.clone();
                    *self.field_counts.entry(primary_key).or_default() += 1;

                    // Related field correlation if requested
                    if let (Some(ref f1), Some(ref f2)) = (&filter.related_field, &filter.related_value) {
                        let v1 = filter.extract_field(f1, &alert).unwrap_or("unknown");
                        let v2 = filter.extract_field(f2, &alert).unwrap_or("unknown");
                        *self
                            .related_counts
                            .entry((v1.to_string(), v2.to_string()))
                            .or_default() += 1;
                    }

                    if filter.show_alerts && self.matching_samples.len() < 100 {
                        self.matching_samples.push(alert.raw.clone());
                    }
                }
            }
        }
    }

    /// Writes report output in standard Wazuh reportd text format.
    pub fn write_report<W: Write>(&self, mut out: W, filter: &ReportFilter) -> std::io::Result<()> {
        let name = filter
            .report_name
            .as_deref()
            .unwrap_or("Wazuh Event Report");

        writeln!(out, "Report: {}", name)?;
        writeln!(out, "================================================")?;
        writeln!(out, "Total alerts processed: {}", self.total_alerts)?;
        writeln!(out, "Total alerts matching filter: {}\n", self.matched_alerts)?;

        if !self.related_counts.is_empty() {
            writeln!(out, "Related Event Breakdown:")?;
            writeln!(out, "------------------------------------------------")?;
            let mut entries: Vec<_> = self.related_counts.iter().collect();
            entries.sort_by(|a, b| b.1.cmp(a.1));
            for ((v1, v2), count) in entries {
                writeln!(out, "{:<25} {:<25} : {:>6}", v1, v2, count)?;
            }
            writeln!(out)?;
        } else if !self.field_counts.is_empty() {
            writeln!(out, "Top Matching Rule IDs:")?;
            writeln!(out, "------------------------------------------------")?;
            let mut entries: Vec<_> = self.field_counts.iter().collect();
            entries.sort_by(|a, b| b.1.cmp(a.1));
            for (rule, count) in entries.iter().take(25) {
                writeln!(out, "Rule {:<15} : {:>6} events", rule, count)?;
            }
            writeln!(out)?;
        }

        if filter.show_alerts && !self.matching_samples.is_empty() {
            writeln!(out, "Matching Alert Samples:")?;
            writeln!(out, "------------------------------------------------")?;
            for (idx, alert) in self.matching_samples.iter().enumerate() {
                writeln!(out, "[{:03}] {}", idx + 1, alert)?;
            }
            writeln!(out)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_report_engine_stream() {
        let raw = r#"{"rule":{"id":"5710","level":5,"groups":["sshd"]},"data":{"srcip":"192.168.1.10","user":"root"}}
{"rule":{"id":"5710","level":5,"groups":["sshd"]},"data":{"srcip":"192.168.1.10","user":"root"}}
{"rule":{"id":"5712","level":10,"groups":["sshd"]},"data":{"srcip":"192.168.1.20","user":"admin"}}
"#;

        let mut engine = ReportEngine::new();
        let mut filter = ReportFilter::default();
        filter.group = Some("sshd".to_string());
        filter.related_field = Some("user".to_string());
        filter.related_value = Some("srcip".to_string());

        engine.process_stream(Cursor::new(raw), &filter);

        assert_eq!(engine.total_alerts, 3);
        assert_eq!(engine.matched_alerts, 3);
        assert_eq!(
            engine.related_counts.get(&("root".to_string(), "192.168.1.10".to_string())),
            Some(&2)
        );

        let mut out = Vec::new();
        engine.write_report(&mut out, &filter).unwrap();
        let report_str = String::from_utf8(out).unwrap();
        assert!(report_str.contains("Total alerts matching filter: 3"));
        assert!(report_str.contains("root"));
    }
}
