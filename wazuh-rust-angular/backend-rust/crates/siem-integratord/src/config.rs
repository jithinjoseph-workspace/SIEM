//! Wazuh External Integration Configuration (src/os_integrator/config.c, integrator-config.h)
//!
//! Handles parsing, validation, and storage for `<integration>` blocks:
//! - Supported native providers: Slack, PagerDuty, VirusTotal, Shuffle, Maltiverse.
//! - Custom integrations with path resolution.
//! - Mandatory validation: Hook URL for Slack/Shuffle/Maltiverse, API Key for PagerDuty/VirusTotal.
//! - Rule ID, severity level, rule group, and location filters.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Alert format matching `json` vs text format in `integrator.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertFormat {
    Json,
    Text,
}

impl Default for AlertFormat {
    fn default() -> Self {
        AlertFormat::Json
    }
}

/// Configuration for a single external integration (`IntegratorConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegratorConfig {
    pub name: String,
    pub hookurl: Option<String>,
    pub apikey: Option<String>,
    pub level: u8,
    pub rule_ids: Vec<u32>,
    pub group: Option<String>,
    pub location: Option<String>,
    pub alert_format: AlertFormat,
    pub options: Option<String>,
    pub timeout: u32,
    pub retries: u32,
    pub max_log: usize,
    pub path: Option<String>,
    pub enabled: bool,
}

impl Default for IntegratorConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            hookurl: None,
            apikey: None,
            level: 0,
            rule_ids: Vec::new(),
            group: None,
            location: None,
            alert_format: AlertFormat::Json,
            options: None,
            timeout: 10,
            retries: 3,
            max_log: 1024,
            path: None,
            enabled: true,
        }
    }
}

impl IntegratorConfig {
    /// Validate configuration requirements according to provider matching `integrator.c` lines 74-139
    pub fn validate(&self) -> Result<(), String> {
        match self.name.as_str() {
            "slack" | "shuffle" => {
                if self.hookurl.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    return Err(format!("Unable to enable integration for: '{}'. Missing hook URL.", self.name));
                }
            }
            "pagerduty" | "virustotal" => {
                if self.apikey.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    return Err(format!("Unable to enable integration for: '{}'. Missing API Key.", self.name));
                }
            }
            "maltiverse" => {
                if self.hookurl.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    return Err(format!("Unable to enable integration for: '{}'. Missing hook URL.", self.name));
                }
                if self.apikey.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    return Err(format!("Unable to enable integration for: '{}'. Missing API Key.", self.name));
                }
            }
            name if name.starts_with("custom-") => {
                if name.len() <= 7 {
                    return Err("Custom integration name must specify a suffix after 'custom-'".to_string());
                }
            }
            name => {
                return Err(format!("Invalid integration: '{}'. Not currently supported.", name));
            }
        }
        Ok(())
    }

    /// Checks if this integration matches an incoming alert (lines 173-275 of `integrator.c`)
    pub fn matches_alert(&self, alert_level: u8, rule_id: u32, groups: &[String], location: &str) -> bool {
        if !self.enabled {
            return false;
        }

        // 1. Location match (lines 184-197)
        if let Some(ref loc) = self.location {
            if !loc.is_empty() && !location.contains(loc) {
                return false;
            }
        }

        // 2. Alert level match (lines 199-211)
        if self.level > 0 && alert_level < self.level {
            return false;
        }

        // 3. Rule group match (lines 213-243)
        // Group in config can be comma-separated: group="pam,sshd"
        if let Some(ref grp_str) = self.group {
            let mut found = false;
            for configured_grp in grp_str.split(',') {
                let trimmed = configured_grp.trim();
                if !trimmed.is_empty() && groups.iter().any(|g| g == trimmed) {
                    found = true;
                    break;
                }
            }
            if !found {
                return false;
            }
        }

        // 4. Rule ID match (lines 245-275)
        if !self.rule_ids.is_empty() && !self.rule_ids.contains(&rule_id) {
            return false;
        }

        true
    }

    /// Generates JSON configuration matching `getIntegratorConfig(void)` in `src/os_integrator/config.c`
    pub fn to_json_config(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("name".to_string(), serde_json::Value::String(self.name.clone()));
        if let Some(ref hook) = self.hookurl {
            map.insert("hook_url".to_string(), serde_json::Value::String(hook.clone()));
        }
        if let Some(ref key) = self.apikey {
            map.insert("api_key".to_string(), serde_json::Value::String(key.clone()));
        }
        map.insert("level".to_string(), serde_json::json!(self.level));
        map.insert("max_log".to_string(), serde_json::json!(self.max_log));
        if !self.rule_ids.is_empty() {
            map.insert("rule_id".to_string(), serde_json::json!(self.rule_ids));
        }
        if let Some(ref g) = self.group {
            map.insert("group".to_string(), serde_json::Value::String(g.clone()));
        }
        let fmt_str = match self.alert_format {
            AlertFormat::Json => "json",
            AlertFormat::Text => "text",
        };
        map.insert("alert_format".to_string(), serde_json::Value::String(fmt_str.to_string()));
        if let Some(ref loc) = self.location {
            map.insert("location".to_string(), serde_json::json!([loc]));
        }
        map.insert("timeout".to_string(), serde_json::json!(self.timeout));
        map.insert("retries".to_string(), serde_json::json!(self.retries));
        serde_json::Value::Object(map)
    }

    /// Parse list of `<integration>` blocks from XML configuration
    pub fn parse_xml(xml: &str) -> Result<Vec<Self>, String> {
        let os_xml = siem_shared::xml::OsXml::parse_str(xml)?;
        let mut integrations = Vec::new();

        let nodes = os_xml.get_elements_by_path(&["ossec_config", "integration"]);
        for elem in nodes {
            let mut config = IntegratorConfig::default();

            if let Some(n) = elem.get_child("name") {
                config.name = n.content.clone();
            }
            if let Some(h) = elem.get_child("hook_url") {
                config.hookurl = Some(h.content.clone());
            }
            if let Some(a) = elem.get_child("api_key") {
                config.apikey = Some(a.content.clone());
            }
            if let Some(lvl) = elem.get_child("level") {
                if let Ok(val) = lvl.content.parse::<u8>() {
                    config.level = val;
                }
            }
            if let Some(r_ids) = elem.get_child("rule_id") {
                for id_str in r_ids.content.split(',') {
                    if let Ok(id) = id_str.trim().parse::<u32>() {
                        config.rule_ids.push(id);
                    }
                }
            }
            if let Some(grp) = elem.get_child("group") {
                config.group = Some(grp.content.clone());
            }
            if let Some(loc) = elem.get_child("location") {
                config.location = Some(loc.content.clone());
            }
            if let Some(fmt) = elem.get_child("alert_format") {
                if fmt.content.eq_ignore_ascii_case("text") {
                    config.alert_format = AlertFormat::Text;
                } else {
                    config.alert_format = AlertFormat::Json;
                }
            }
            if let Some(opt) = elem.get_child("options") {
                config.options = Some(opt.content.clone());
            }
            if let Some(tm) = elem.get_child("timeout") {
                if let Ok(val) = tm.content.parse::<u32>() {
                    config.timeout = val;
                }
            }
            if let Some(ret) = elem.get_child("retries") {
                if let Ok(val) = ret.content.parse::<u32>() {
                    config.retries = val;
                }
            }
            if let Some(ml) = elem.get_child("max_log") {
                if let Ok(val) = ml.content.parse::<usize>() {
                    config.max_log = val;
                }
            }

            // Path defaults to /var/ossec/integrations/<name>
            config.path = Some(format!("/var/ossec/integrations/{}", config.name));

            integrations.push(config);
        }

        Ok(integrations)
    }

    /// Read integrations from file
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Vec<Self>, String> {
        let xml_str = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::parse_xml(&xml_str)
    }
}

/// Helper function matching `getIntegratorConfig(void)` in `src/os_integrator/config.c`
pub fn get_integrator_config_json(integrations: &[IntegratorConfig]) -> serde_json::Value {
    let list: Vec<serde_json::Value> = integrations.iter().map(|c| c.to_json_config()).collect();
    serde_json::json!({
        "integration": list
    })
}
