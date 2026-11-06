//! Monitord Configuration Engine (`src/monitord/monitord.c`, `reports-config.c`, `global-config.c`)
//!
//! Loads XML configuration for log rotation, agent disconnection thresholds,
//! report definitions, and produces monitoring telemetry JSON.

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DEFAULT_KEEP_LOG_DAYS: u32 = 31;
pub const DEFAULT_DISCONNECTION_TIME: u64 = 900;
pub const DEFAULT_SIZE_ROTATE: u64 = 512 * 1024 * 1024;
pub const DEFAULT_DAILY_ROTATIONS: u32 = 12;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReportFilter {
    pub group: Option<String>,
    pub rule: Option<String>,
    pub level: Option<String>,
    pub location: Option<String>,
    pub srcip: Option<String>,
    pub user: Option<String>,
    pub show_alerts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReportConfig {
    pub title: String,
    pub report_type: String,
    pub email_to: Vec<String>,
    pub filter: ReportFilter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub day_wait: u32,
    pub compress: bool,
    pub sign: bool,
    pub monitor_agents: bool,
    pub rotate_log: bool,
    pub keep_log_days: u32,
    pub size_rotate: u64,
    pub daily_rotations: u32,
    pub delete_old_agents: u32, // In minutes (0 = disabled)
    pub agents_disconnection_time: u64, // In seconds
    pub agents_disconnection_alert_time: u64, // In seconds
    pub smtp_server: Option<String>,
    pub email_from: Option<String>,
    pub email_ids_name: Option<String>,
    pub reports: Vec<ReportConfig>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            day_wait: 0,
            compress: true,
            sign: true,
            monitor_agents: true,
            rotate_log: true,
            keep_log_days: DEFAULT_KEEP_LOG_DAYS,
            size_rotate: DEFAULT_SIZE_ROTATE,
            daily_rotations: DEFAULT_DAILY_ROTATIONS,
            delete_old_agents: 0,
            agents_disconnection_time: DEFAULT_DISCONNECTION_TIME,
            agents_disconnection_alert_time: 0,
            smtp_server: None,
            email_from: None,
            email_ids_name: None,
            reports: Vec::new(),
        }
    }
}

/// Parses time interval string (`s`, `m`, `h`, `d`).
pub fn parse_time_interval(source: &str) -> Option<u64> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (num_str, multiplier) = if let Some(stripped) = trimmed.strip_suffix('d') {
        (stripped, 86400u64)
    } else if let Some(stripped) = trimmed.strip_suffix('h') {
        (stripped, 3600u64)
    } else if let Some(stripped) = trimmed.strip_suffix('m') {
        (stripped, 60u64)
    } else if let Some(stripped) = trimmed.strip_suffix('s') {
        (stripped, 1u64)
    } else {
        (trimmed, 1u64)
    };

    num_str.parse::<u64>().ok().map(|val| val * multiplier)
}

fn eval_bool(s: &str) -> Option<bool> {
    match s.trim().to_lowercase().as_str() {
        "yes" | "true" | "1" => Some(true),
        "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

impl MonitorConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::from_xml(&content)
    }

    pub fn from_xml(xml: &str) -> Result<Self, String> {
        let mut config = MonitorConfig::default();
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut in_global = false;
        let mut in_reports = false;
        let mut current_report: Option<ReportConfig> = None;
        let mut current_tag = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "global" => in_global = true,
                        "reports" => {
                            in_reports = true;
                            current_report = Some(ReportConfig::default());
                        }
                        _ => {
                            current_tag = tag;
                        }
                    }
                }
                Ok(Event::Text(ref e)) => {
                    let text = e.unescape().map_err(|err| err.to_string())?.to_string();
                    if in_global {
                        match current_tag.as_str() {
                            "agents_disconnection_time" => {
                                if let Some(t) = parse_time_interval(&text) {
                                    config.agents_disconnection_time = t;
                                }
                            }
                            "agents_disconnection_alert_time" => {
                                if let Some(t) = parse_time_interval(&text) {
                                    config.agents_disconnection_alert_time = t;
                                }
                            }
                            "smtp_server" => config.smtp_server = Some(text),
                            "email_from" => config.email_from = Some(text),
                            "email_idsname" => config.email_ids_name = Some(text),
                            "delete_old_agents" => {
                                if let Ok(n) = text.parse::<u32>() {
                                    config.delete_old_agents = n;
                                }
                            }
                            _ => {}
                        }
                    } else if in_reports {
                        if let Some(ref mut rep) = current_report {
                            match current_tag.as_str() {
                                "title" => rep.title = text,
                                "type" => rep.report_type = text,
                                "email_to" => rep.email_to.push(text),
                                "group" => rep.filter.group = Some(text),
                                "rule" => rep.filter.rule = Some(text),
                                "level" => rep.filter.level = Some(text),
                                "location" => rep.filter.location = Some(text),
                                "srcip" => rep.filter.srcip = Some(text),
                                "user" => rep.filter.user = Some(text),
                                "showlogs" => {
                                    if let Some(b) = eval_bool(&text) {
                                        rep.filter.show_alerts = b;
                                    }
                                }
                                _ => {}
                            }
                        }
                    } else {
                        // Monitord internal overrides
                        match current_tag.as_str() {
                            "compress" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.compress = b;
                                }
                            }
                            "sign" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.sign = b;
                                }
                            }
                            "rotate_log" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.rotate_log = b;
                                }
                            }
                            "keep_log_days" => {
                                if let Ok(n) = text.parse::<u32>() {
                                    config.keep_log_days = n;
                                }
                            }
                            "daily_rotations" => {
                                if let Ok(n) = text.parse::<u32>() {
                                    config.daily_rotations = n;
                                }
                            }
                            "size_rotate" => {
                                if let Ok(n) = text.parse::<u64>() {
                                    config.size_rotate = n * 1024 * 1024;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "global" => in_global = false,
                        "reports" => {
                            in_reports = false;
                            if let Some(rep) = current_report.take() {
                                if !rep.title.is_empty() {
                                    config.reports.push(rep);
                                }
                            }
                        }
                        _ => {}
                    }
                    current_tag.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(config)
    }

    /// Produces JSON matching `getMonitorInternalOptions` in `monitord.c`.
    pub fn get_monitor_internal_options(&self) -> serde_json::Value {
        serde_json::json!({
            "monitord": {
                "day_wait": self.day_wait,
                "compress": if self.compress { 1 } else { 0 },
                "sign": if self.sign { 1 } else { 0 },
                "monitor_agents": if self.monitor_agents { 1 } else { 0 },
                "keep_log_days": self.keep_log_days,
                "rotate_log": if self.rotate_log { 1 } else { 0 },
                "size_rotate": self.size_rotate,
                "daily_rotations": self.daily_rotations,
                "delete_old_agents": self.delete_old_agents
            }
        })
    }

    /// Produces JSON matching `getMonitorGlobalOptions` in `monitord.c`.
    pub fn get_monitor_global_options(&self) -> serde_json::Value {
        serde_json::json!({
            "monitord": {
                "agents_disconnection_time": self.agents_disconnection_time,
                "agents_disconnection_alert_time": self.agents_disconnection_alert_time
            }
        })
    }

    /// Produces JSON matching `getReportsOptions` in `monitord.c`.
    pub fn get_reports_options(&self) -> serde_json::Value {
        let mut list = Vec::new();
        for rep in &self.reports {
            let mut item = serde_json::Map::new();
            item.insert("title".to_string(), serde_json::json!(rep.title));
            if let Some(ref g) = rep.filter.group {
                item.insert("group".to_string(), serde_json::json!(g));
            }
            if let Some(ref r) = rep.filter.rule {
                item.insert("rule".to_string(), serde_json::json!(r));
            }
            if let Some(ref l) = rep.filter.level {
                item.insert("level".to_string(), serde_json::json!(l));
            }
            if let Some(ref s) = rep.filter.srcip {
                item.insert("srcip".to_string(), serde_json::json!(s));
            }
            if let Some(ref u) = rep.filter.user {
                item.insert("user".to_string(), serde_json::json!(u));
            }
            item.insert(
                "showlogs".to_string(),
                serde_json::json!(if rep.filter.show_alerts { "yes" } else { "no" }),
            );
            if !rep.email_to.is_empty() {
                item.insert("email_to".to_string(), serde_json::json!(rep.email_to));
            }
            list.push(serde_json::Value::Object(item));
        }

        serde_json::json!({ "reports": list })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_intervals() {
        assert_eq!(parse_time_interval("60s"), Some(60));
        assert_eq!(parse_time_interval("15m"), Some(900));
        assert_eq!(parse_time_interval("1h"), Some(3600));
        assert_eq!(parse_time_interval("2d"), Some(172800));
    }

    #[test]
    fn test_xml_config_parse() {
        let xml = r#"
        <ossec_config>
            <global>
                <agents_disconnection_time>10m</agents_disconnection_time>
                <agents_disconnection_alert_time>5m</agents_disconnection_alert_time>
                <delete_old_agents>1440</delete_old_agents>
                <smtp_server>smtp.corp.local</smtp_server>
            </global>
            <reports>
                <title>Daily Web Attack Report</title>
                <type>email</type>
                <email_to>soc@corp.local</email_to>
                <group>web,attack</group>
                <showlogs>yes</showlogs>
            </reports>
        </ossec_config>
        "#;

        let cfg = MonitorConfig::from_xml(xml).unwrap();
        assert_eq!(cfg.agents_disconnection_time, 600);
        assert_eq!(cfg.agents_disconnection_alert_time, 300);
        assert_eq!(cfg.delete_old_agents, 1440);
        assert_eq!(cfg.smtp_server.as_deref().unwrap(), "smtp.corp.local");
        assert_eq!(cfg.reports.len(), 1);
        assert_eq!(cfg.reports[0].title, "Daily Web Attack Report");
        assert!(cfg.reports[0].filter.show_alerts);

        let int_opts = cfg.get_monitor_internal_options();
        assert_eq!(int_opts["monitord"]["compress"], 1);

        let glob_opts = cfg.get_monitor_global_options();
        assert_eq!(glob_opts["monitord"]["agents_disconnection_time"], 600);

        let rep_opts = cfg.get_reports_options();
        assert_eq!(rep_opts["reports"][0]["title"], "Daily Web Attack Report");
    }
}
