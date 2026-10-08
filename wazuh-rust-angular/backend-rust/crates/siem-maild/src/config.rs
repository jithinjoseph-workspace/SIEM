//! Wazuh Mail Configuration (src/os_maild/config.c, mail-config.h)
//!
//! Handles parsing and configuration management for `<email_alerts>` and `<global>`:
//! - SMTP server, HELO hostname, sender address, reply-to, and recipient lists.
//! - Granular email routing tables (`email_to`, `rule_id`, `level`, `group`, `location`, `format`).
//! - Anti-flooding rate limiting (`email_maxperhour`).
//! - Alert batching and grouping options (`grouping`, `do_not_delay`, `do_not_group`).

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Format for email notifications matching `FULL_FORMAT`, `SMS_FORMAT`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailFormat {
    Full,
    Sms,
    DoNotDelay,
    DoNotGroup,
}

impl Default for EmailFormat {
    fn default() -> Self {
        EmailFormat::Full
    }
}

/// Granular email alert rule matching `gran_to`, `gran_id`, `gran_level`, `gran_format`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GranularEmailRule {
    pub to: String,
    pub level: Option<u8>,
    pub rule_ids: Vec<u32>,
    pub groups: Vec<String>,
    pub locations: Vec<String>,
    pub format: EmailFormat,
}

impl GranularEmailRule {
    /// Checks if this granular rule matches the given alert parameters
    pub fn matches(&self, level: u8, rule_id: u32, group_list: &[String], location: &str) -> bool {
        // Level check
        if let Some(min_lvl) = self.level {
            if level < min_lvl {
                return false;
            }
        }

        // Rule ID check
        if !self.rule_ids.is_empty() && !self.rule_ids.contains(&rule_id) {
            return false;
        }

        // Group check
        if !self.groups.is_empty() {
            let matches_group = group_list.iter().any(|g| self.groups.contains(g));
            if !matches_group {
                return false;
            }
        }

        // Location check
        if !self.locations.is_empty() && !self.locations.iter().any(|l| location.contains(l)) {
            return false;
        }

        true
    }
}

/// Alert source matching `MAIL_SOURCE_JSON` and `MAIL_SOURCE_LOGS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailSource {
    Json,
    Logs,
}

/// Mail configuration matching `MailConfig` in `mail-config.h`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailConfig {
    pub enabled: bool,
    pub to: Vec<String>,
    pub from: String,
    pub reply_to: Option<String>,
    pub idsname: String,
    pub smtpserver: String,
    pub heloserver: Option<String>,
    pub min_level: u8,
    pub maxperhour: u32,
    pub grouping: bool,
    pub strict_checking: bool,
    pub source: MailSource,
    pub gran_to: Vec<GranularEmailRule>,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            to: Vec::new(),
            from: "wazuh@localhost".to_string(),
            reply_to: None,
            idsname: "Wazuh".to_string(),
            smtpserver: "127.0.0.1".to_string(),
            heloserver: None,
            min_level: 7,
            maxperhour: 12,
            grouping: true,
            strict_checking: false,
            source: MailSource::Json,
            gran_to: Vec::new(),
        }
    }
}

impl MailConfig {
    /// Parse configuration from XML string (`<ossec_config>`)
    pub fn parse_xml(xml: &str) -> Result<Self, String> {
        let os_xml = siem_shared::xml::OsXml::parse_str(xml)?;
        let mut config = Self::default();

        // 1. Parse <global> section
        if let Some(smtp) = os_xml.get_element_content(&["ossec_config", "global", "smtp_server"]) {
            config.smtpserver = smtp;
        }
        if let Some(from) = os_xml.get_element_content(&["ossec_config", "global", "email_from"]) {
            config.from = from;
        }
        if let Some(to) = os_xml.get_element_content(&["ossec_config", "global", "email_to"]) {
            config.to.push(to);
        }
        if let Some(max) = os_xml.get_element_content(&["ossec_config", "global", "email_maxperhour"]) {
            if let Ok(v) = max.parse::<u32>() {
                config.maxperhour = v;
            }
        }
        if let Some(ids) = os_xml.get_element_content(&["ossec_config", "global", "email_idsname"]) {
            config.idsname = ids;
        }

        // 2. Parse <alerts> section
        if let Some(lvl) = os_xml.get_element_content(&["ossec_config", "alerts", "email_alert_level"]) {
            if let Ok(v) = lvl.parse::<u8>() {
                config.min_level = v;
            }
        }

        // 3. Parse <email_alerts> granular routing rules
        let email_alerts = os_xml.get_elements_by_path(&["ossec_config", "email_alerts"]);
        for elem in email_alerts {
            if let Some(to_node) = elem.get_child("email_to") {
                let to_addr = to_node.content.clone();
                let mut level = None;
                if let Some(lvl_node) = elem.get_child("level") {
                    level = lvl_node.content.parse::<u8>().ok();
                }

                let mut rule_ids = Vec::new();
                for r_node in elem.get_children("rule_id") {
                    if let Ok(id) = r_node.content.parse::<u32>() {
                        rule_ids.push(id);
                    }
                }

                let mut groups = Vec::new();
                for g_node in elem.get_children("group") {
                    groups.push(g_node.content.clone());
                }

                let mut format = EmailFormat::Full;
                if let Some(fmt_node) = elem.get_child("format") {
                    match fmt_node.content.as_str() {
                        "sms" => format = EmailFormat::Sms,
                        "do_not_delay" => format = EmailFormat::DoNotDelay,
                        "do_not_group" => format = EmailFormat::DoNotGroup,
                        _ => format = EmailFormat::Full,
                    }
                }

                config.gran_to.push(GranularEmailRule {
                    to: to_addr,
                    level,
                    rule_ids,
                    groups,
                    locations: Vec::new(),
                    format,
                });
            }
        }

        Ok(config)
    }

    /// Read configuration from file
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let xml_str = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::parse_xml(&xml_str)
    }
}
