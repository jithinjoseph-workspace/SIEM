//! Daily Report Generator (`src/monitord/generate_reports.c`)
//!
//! Evaluates daily alerts against user-defined reporting filters and generates summary digests.

use crate::config::ReportConfig;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct ReportSummary {
    pub title: String,
    pub total_alerts_processed: usize,
    pub matched_alerts: usize,
    pub top_rules: HashMap<String, usize>,
    pub top_srcips: HashMap<String, usize>,
    pub top_groups: HashMap<String, usize>,
    pub sample_alerts: Vec<String>,
}

/// Generates a summary report by reading a daily alerts file.
pub fn generate_report_from_file<P: AsRef<Path>>(
    report_cfg: &ReportConfig,
    alerts_file_path: P,
) -> io::Result<ReportSummary> {
    let mut summary = ReportSummary {
        title: report_cfg.title.clone(),
        ..Default::default()
    };

    if !alerts_file_path.as_ref().exists() {
        return Ok(summary);
    }

    let file = File::open(alerts_file_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        summary.total_alerts_processed += 1;

        // Try JSON alert parsing or fallback to text search
        let matched = if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            filter_json_alert(&val, report_cfg)
        } else {
            filter_text_alert(trimmed, report_cfg)
        };

        if matched {
            summary.matched_alerts += 1;
            if report_cfg.filter.show_alerts && summary.sample_alerts.len() < 50 {
                summary.sample_alerts.push(trimmed.to_string());
            }

            // Extract rule / srcip for stats
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(rule_id) = val.get("rule").and_then(|r| r.get("id")).and_then(|v| v.as_str()) {
                    *summary.top_rules.entry(rule_id.to_string()).or_default() += 1;
                }
                if let Some(srcip) = val.get("data").and_then(|d| d.get("srcip")).and_then(|v| v.as_str()) {
                    *summary.top_srcips.entry(srcip.to_string()).or_default() += 1;
                }
            }
        }
    }

    Ok(summary)
}

fn filter_json_alert(val: &serde_json::Value, report: &ReportConfig) -> bool {
    let f = &report.filter;

    if let Some(ref req_rule) = f.rule {
        if let Some(rule_id) = val.get("rule").and_then(|r| r.get("id")).and_then(|v| v.as_str()) {
            if rule_id != req_rule {
                return false;
            }
        } else {
            return false;
        }
    }

    if let Some(ref req_level) = f.level {
        if let Some(lvl) = val.get("rule").and_then(|r| r.get("level")).and_then(|v| v.as_u64()) {
            if let Ok(req_lvl_num) = req_level.parse::<u64>() {
                if lvl < req_lvl_num {
                    return false;
                }
            }
        }
    }

    if let Some(ref req_group) = f.group {
        let mut group_matched = false;
        if let Some(groups) = val.get("rule").and_then(|r| r.get("groups")).and_then(|v| v.as_array()) {
            for g in groups.iter().filter_map(|x| x.as_str()) {
                if req_group.split(',').any(|expected| expected.trim() == g) {
                    group_matched = true;
                    break;
                }
            }
        }
        if !group_matched {
            return false;
        }
    }

    if let Some(ref req_srcip) = f.srcip {
        if let Some(srcip) = val.get("data").and_then(|d| d.get("srcip")).and_then(|v| v.as_str()) {
            if srcip != req_srcip {
                return false;
            }
        } else {
            return false;
        }
    }

    true
}

fn filter_text_alert(line: &str, report: &ReportConfig) -> bool {
    let f = &report.filter;
    if let Some(ref g) = f.group {
        if !line.contains(g) {
            return false;
        }
    }
    if let Some(ref r) = f.rule {
        if !line.contains(r) {
            return false;
        }
    }
    if let Some(ref ip) = f.srcip {
        if !line.contains(ip) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReportFilter;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_report_generation() {
        let temp_file = NamedTempFile::new().unwrap();
        let alerts = r#"{"rule":{"id":"5710","level":5,"groups":["authentication_failed","sshd"]},"data":{"srcip":"192.168.1.100"}}
{"rule":{"id":"5715","level":3,"groups":["sshd","success"]},"data":{"srcip":"192.168.1.50"}}
{"rule":{"id":"5710","level":5,"groups":["authentication_failed"]},"data":{"srcip":"10.0.0.1"}}
"#;
        fs::write(temp_file.path(), alerts).unwrap();

        let mut report = ReportConfig {
            title: "SSH Failed Logins".to_string(),
            report_type: "email".to_string(),
            email_to: vec!["soc@corp.local".to_string()],
            filter: ReportFilter::default(),
        };
        report.filter.rule = Some("5710".to_string());
        report.filter.show_alerts = true;

        let summary = generate_report_from_file(&report, temp_file.path()).unwrap();
        assert_eq!(summary.total_alerts_processed, 3);
        assert_eq!(summary.matched_alerts, 2);
        assert_eq!(summary.top_rules.get("5710"), Some(&2));
        assert_eq!(summary.sample_alerts.len(), 2);
    }
}
