//! Report Filter Definitions & Matching Engine (`src/reportd/report.c`)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReportFilter {
    pub group: Option<String>,
    pub rule: Option<String>,
    pub level: Option<u32>,
    pub location: Option<String>,
    pub srcip: Option<String>,
    pub user: Option<String>,
    pub filename: Option<String>,

    pub related_field: Option<String>,
    pub related_value: Option<String>,

    pub report_name: Option<String>,
    pub show_alerts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlertRecord {
    pub rule_id: String,
    pub level: u32,
    pub groups: Vec<String>,
    pub location: String,
    pub srcip: Option<String>,
    pub user: Option<String>,
    pub filename: Option<String>,
    pub raw: String,
}

impl ReportFilter {
    /// Evaluates if an alert record matches the configured primary filter.
    pub fn matches(&self, alert: &AlertRecord) -> bool {
        if let Some(ref req_rule) = self.rule {
            if alert.rule_id != *req_rule {
                return false;
            }
        }

        if let Some(req_level) = self.level {
            if alert.level < req_level {
                return false;
            }
        }

        if let Some(ref req_group) = self.group {
            let found = alert
                .groups
                .iter()
                .any(|g| g.eq_ignore_ascii_case(req_group));
            if !found {
                return false;
            }
        }

        if let Some(ref req_loc) = self.location {
            if !alert.location.contains(req_loc) {
                return false;
            }
        }

        if let Some(ref req_ip) = self.srcip {
            if alert.srcip.as_deref() != Some(req_ip.as_str()) {
                return false;
            }
        }

        if let Some(ref req_user) = self.user {
            if alert.user.as_deref() != Some(req_user.as_str()) {
                return false;
            }
        }

        if let Some(ref req_file) = self.filename {
            if alert.filename.as_deref() != Some(req_file.as_str()) {
                return false;
            }
        }

        true
    }

    /// Extracts the value of a field for aggregation/correlation.
    pub fn extract_field<'a>(&self, field_name: &str, alert: &'a AlertRecord) -> Option<&'a str> {
        match field_name {
            "rule" => Some(&alert.rule_id),
            "location" => Some(&alert.location),
            "srcip" => alert.srcip.as_deref(),
            "user" => alert.user.as_deref(),
            "filename" => alert.filename.as_deref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_matching() {
        let alert = AlertRecord {
            rule_id: "5710".to_string(),
            level: 10,
            groups: vec!["authentication_failed".to_string(), "sshd".to_string()],
            location: "/var/log/auth.log".to_string(),
            srcip: Some("192.168.1.100".to_string()),
            user: Some("admin".to_string()),
            filename: None,
            raw: "sample alert".to_string(),
        };

        let mut filter = ReportFilter::default();
        filter.rule = Some("5710".to_string());
        filter.level = Some(8);
        filter.group = Some("sshd".to_string());
        assert!(filter.matches(&alert));

        filter.srcip = Some("10.0.0.1".to_string());
        assert!(!filter.matches(&alert));
    }
}
