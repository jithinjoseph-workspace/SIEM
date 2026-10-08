//! Alert Statistical Report Generator (reportd/report.c, shared/report_op.c)
//!
//! Evaluates alert streams, applies filtering criteria, and generates frequency distribution
//! tables and cross-field relationship matrices.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertItem {
    pub rule_id: String,
    pub level: u32,
    pub description: String,
    pub groups: Vec<String>,
    pub location: String,
    pub srcip: Option<String>,
    pub dstip: Option<String>,
    pub user: Option<String>,
    pub filename: Option<String>,
    pub timestamp: String,
}

impl AlertItem {
    /// Parse from JSON alert format (e.g. from alerts.json).
    pub fn from_json(val: &serde_json::Value) -> Option<Self> {
        let rule = val.get("rule")?;
        let rule_id = rule.get("id")?.as_str()?.to_string();
        let level = rule.get("level")?.as_u64()? as u32;
        let description = rule
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let groups = rule
            .get("groups")
            .and_then(|g| g.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let location = val
            .get("location")
            .and_then(|l| l.as_str())
            .unwrap_or("")
            .to_string();

        let srcip = val
            .get("data")
            .and_then(|d| d.get("srcip"))
            .or_else(|| val.get("srcip"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let dstip = val
            .get("data")
            .and_then(|d| d.get("dstip"))
            .or_else(|| val.get("dstip"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let user = val
            .get("data")
            .and_then(|d| d.get("srcuser").or_else(|| d.get("dstuser")))
            .or_else(|| val.get("user"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let filename = val
            .get("syscheck")
            .and_then(|s| s.get("path"))
            .or_else(|| val.get("filename"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let timestamp = val
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();

        Some(Self {
            rule_id,
            level,
            description,
            groups,
            location,
            srcip,
            dstip,
            user,
            filename,
            timestamp,
        })
    }

    /// Extract a named field value.
    pub fn get_field(&self, field_name: &str) -> Option<String> {
        match field_name.to_lowercase().as_str() {
            "rule" | "rule_id" => Some(self.rule_id.clone()),
            "level" => Some(self.level.to_string()),
            "location" => Some(self.location.clone()),
            "srcip" => self.srcip.clone(),
            "dstip" => self.dstip.clone(),
            "user" => self.user.clone(),
            "filename" | "file" => self.filename.clone(),
            _ => None,
        }
    }
}

/// Report filter criteria.
#[derive(Debug, Clone, Default)]
pub struct ReportFilter {
    pub report_name: Option<String>,
    pub group: Option<String>,
    pub rule: Option<String>,
    pub min_level: Option<u32>,
    pub location: Option<String>,
    pub srcip: Option<String>,
    pub user: Option<String>,
    pub filename: Option<String>,
    pub show_alerts: bool,
    pub top_field: Option<String>,
    pub related: Option<(String, String)>, // (primary_field, related_field)
}

impl ReportFilter {
    /// Check if an alert matches all configured filter criteria.
    pub fn matches(&self, alert: &AlertItem) -> bool {
        if let Some(ref grp) = self.group {
            if !alert.groups.iter().any(|g| g.eq_ignore_ascii_case(grp)) {
                return false;
            }
        }

        if let Some(ref r) = self.rule {
            if alert.rule_id != *r {
                return false;
            }
        }

        if let Some(lvl) = self.min_level {
            if alert.level < lvl {
                return false;
            }
        }

        if let Some(ref loc) = self.location {
            if !alert.location.contains(loc) {
                return false;
            }
        }

        if let Some(ref ip) = self.srcip {
            if alert.srcip.as_deref() != Some(ip) {
                return false;
            }
        }

        if let Some(ref u) = self.user {
            if alert.user.as_deref() != Some(u) {
                return false;
            }
        }

        if let Some(ref f) = self.filename {
            if alert.filename.as_deref() != Some(f) {
                return false;
            }
        }

        true
    }
}

/// Statistical report generator aggregating counts.
#[derive(Debug, Clone, Default)]
pub struct ReportGenerator {
    filter: ReportFilter,
    matched_count: usize,
    // Field value -> count
    counts: HashMap<String, usize>,
    // Primary field value -> (Related field value -> count)
    related_counts: HashMap<String, HashMap<String, usize>>,
    raw_alerts: Vec<AlertItem>,
}

impl ReportGenerator {
    pub fn new(filter: ReportFilter) -> Self {
        Self {
            filter,
            matched_count: 0,
            counts: HashMap::new(),
            related_counts: HashMap::new(),
            raw_alerts: Vec::new(),
        }
    }

    /// Ingest and evaluate an alert item.
    pub fn process_alert(&mut self, alert: AlertItem) {
        if !self.filter.matches(&alert) {
            return;
        }

        self.matched_count += 1;

        if let Some((ref primary_field, ref related_field)) = self.filter.related {
            if let Some(p_val) = alert.get_field(primary_field) {
                if let Some(r_val) = alert.get_field(related_field) {
                    let entry = self.related_counts.entry(p_val).or_default();
                    *entry.entry(r_val).or_insert(0) += 1;
                }
            }
        } else if let Some(ref top_field) = self.filter.top_field {
            if let Some(val) = alert.get_field(top_field) {
                *self.counts.entry(val).or_insert(0) += 1;
            }
        } else {
            // Default top field is rule_id
            *self.counts.entry(alert.rule_id.clone()).or_insert(0) += 1;
        }

        if self.filter.show_alerts {
            self.raw_alerts.push(alert);
        }
    }

    /// Render formatted ASCII report text.
    pub fn generate_report(&self) -> String {
        let mut out = String::new();

        if let Some(ref name) = self.filter.report_name {
            out.push_str(&format!("Report: {}\n", name));
            out.push_str("================================================\n");
        }

        out.push_str(&format!("Total alerts processed: {}\n\n", self.matched_count));

        if let Some((ref primary_field, ref related_field)) = self.filter.related {
            out.push_str(&format!(
                "Related entries for '{}' -> '{}':\n",
                primary_field, related_field
            ));
            out.push_str("------------------------------------------------\n");

            let mut sorted_primaries: Vec<(&String, &HashMap<String, usize>)> =
                self.related_counts.iter().collect();
            sorted_primaries.sort_by_key(|(k, _)| (*k).clone());

            for (p_val, rel_map) in sorted_primaries {
                let mut sorted_rel: Vec<(&String, &usize)> = rel_map.iter().collect();
                sorted_rel.sort_by(|a, b| b.1.cmp(a.1));

                out.push_str(&format!("  [{}]:\n", p_val));
                for (r_val, cnt) in sorted_rel {
                    out.push_str(&format!("    {:<40} |{}\n", r_val, cnt));
                }
            }
        } else {
            let field_title = self.filter.top_field.as_deref().unwrap_or("rule");
            out.push_str(&format!("Top entries for '{}':\n", field_title));
            out.push_str("------------------------------------------------\n");

            let mut sorted_counts: Vec<(&String, &usize)> = self.counts.iter().collect();
            sorted_counts.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

            for (val, cnt) in sorted_counts {
                out.push_str(&format!("{:<44} |{}\n", val, cnt));
            }
        }

        if self.filter.show_alerts && !self.raw_alerts.is_empty() {
            out.push_str("\nAlert details:\n");
            out.push_str("------------------------------------------------\n");
            for al in &self.raw_alerts {
                out.push_str(&format!(
                    "[{}] Level: {} Rule: {} ({}) Location: {}\n",
                    al.timestamp, al.level, al.rule_id, al.description, al.location
                ));
            }
        }

        out
    }
}
