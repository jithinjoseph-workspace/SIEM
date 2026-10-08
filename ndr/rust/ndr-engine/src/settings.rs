// NDR Engine — Settings Module
// Persistent configuration stored in SQLite key-value table.
// License: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// All configurable settings for the NDR engine.
/// Persisted as key-value pairs in SQLite `ndr_settings` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NdrSettings {
    // ── General ─────────────────────────────────────────────────────────
    pub org_name:     String,
    pub system_name:  String,
    pub timezone:     String,
    pub language:     String,
    pub theme:        String,

    // ── Detection ───────────────────────────────────────────────────────
    pub auto_block_threshold:    u32,
    pub severity_critical:       u32,
    pub severity_high:           u32,
    pub severity_medium:         u32,
    pub severity_low:            u32,
    pub sigma_rules_dir:         String,
    pub hot_reload_interval_min: u32,

    // ── Threat Intelligence ─────────────────────────────────────────────
    pub ti_refresh_interval_min:   u32,
    pub feed_feodo_enabled:        bool,
    pub feed_malwarebazaar_enabled: bool,
    pub feed_urlhaus_enabled:      bool,
    pub custom_ioc_feed_url:       String,
    pub ioc_expiry_days:           u32,
}

impl NdrSettings {
    /// Production defaults matching the user's specification.
    pub fn defaults() -> Self {
        Self {
            // General
            org_name:     "NDR Command".to_string(),
            system_name:  "Tactical Observatory".to_string(),
            timezone:     "UTC".to_string(),
            language:     "en".to_string(),
            theme:        "dark".to_string(),

            // Detection
            auto_block_threshold:    90,
            severity_critical:       90,
            severity_high:           75,
            severity_medium:         50,
            severity_low:            25,
            sigma_rules_dir:         std::env::var("RULES_DIR")
                .unwrap_or_else(|_| "rules".to_string()),
            hot_reload_interval_min: 5,

            // Threat Intelligence
            ti_refresh_interval_min:   60,
            feed_feodo_enabled:        true,
            feed_malwarebazaar_enabled: true,
            feed_urlhaus_enabled:      true,
            custom_ioc_feed_url:       String::new(),
            ioc_expiry_days:           30,
        }
    }

    /// Deserialize from SQLite key-value pairs.
    /// Missing keys fall back to defaults.
    pub fn from_kv(kv: HashMap<String, String>) -> Self {
        let d = Self::defaults();
        Self {
            org_name:     kv.get("org_name").cloned().unwrap_or(d.org_name),
            system_name:  kv.get("system_name").cloned().unwrap_or(d.system_name),
            timezone:     kv.get("timezone").cloned().unwrap_or(d.timezone),
            language:     kv.get("language").cloned().unwrap_or(d.language),
            theme:        kv.get("theme").cloned().unwrap_or(d.theme),

            auto_block_threshold: kv.get("auto_block_threshold")
                .and_then(|v| v.parse().ok()).unwrap_or(d.auto_block_threshold),
            severity_critical: kv.get("severity_critical")
                .and_then(|v| v.parse().ok()).unwrap_or(d.severity_critical),
            severity_high: kv.get("severity_high")
                .and_then(|v| v.parse().ok()).unwrap_or(d.severity_high),
            severity_medium: kv.get("severity_medium")
                .and_then(|v| v.parse().ok()).unwrap_or(d.severity_medium),
            severity_low: kv.get("severity_low")
                .and_then(|v| v.parse().ok()).unwrap_or(d.severity_low),
            sigma_rules_dir: kv.get("sigma_rules_dir").cloned()
                .unwrap_or(d.sigma_rules_dir),
            hot_reload_interval_min: kv.get("hot_reload_interval_min")
                .and_then(|v| v.parse().ok()).unwrap_or(d.hot_reload_interval_min),

            ti_refresh_interval_min: kv.get("ti_refresh_interval_min")
                .and_then(|v| v.parse().ok()).unwrap_or(d.ti_refresh_interval_min),
            feed_feodo_enabled: kv.get("feed_feodo_enabled")
                .map(|v| v == "true").unwrap_or(d.feed_feodo_enabled),
            feed_malwarebazaar_enabled: kv.get("feed_malwarebazaar_enabled")
                .map(|v| v == "true").unwrap_or(d.feed_malwarebazaar_enabled),
            feed_urlhaus_enabled: kv.get("feed_urlhaus_enabled")
                .map(|v| v == "true").unwrap_or(d.feed_urlhaus_enabled),
            custom_ioc_feed_url: kv.get("custom_ioc_feed_url").cloned()
                .unwrap_or(d.custom_ioc_feed_url),
            ioc_expiry_days: kv.get("ioc_expiry_days")
                .and_then(|v| v.parse().ok()).unwrap_or(d.ioc_expiry_days),
        }
    }

    /// Serialize to key-value pairs for SQLite persistence.
    pub fn to_kv(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("org_name".into(),     self.org_name.clone());
        m.insert("system_name".into(),  self.system_name.clone());
        m.insert("timezone".into(),     self.timezone.clone());
        m.insert("language".into(),     self.language.clone());
        m.insert("theme".into(),        self.theme.clone());

        m.insert("auto_block_threshold".into(),    self.auto_block_threshold.to_string());
        m.insert("severity_critical".into(),       self.severity_critical.to_string());
        m.insert("severity_high".into(),           self.severity_high.to_string());
        m.insert("severity_medium".into(),         self.severity_medium.to_string());
        m.insert("severity_low".into(),            self.severity_low.to_string());
        m.insert("sigma_rules_dir".into(),         self.sigma_rules_dir.clone());
        m.insert("hot_reload_interval_min".into(), self.hot_reload_interval_min.to_string());

        m.insert("ti_refresh_interval_min".into(),     self.ti_refresh_interval_min.to_string());
        m.insert("feed_feodo_enabled".into(),          self.feed_feodo_enabled.to_string());
        m.insert("feed_malwarebazaar_enabled".into(),  self.feed_malwarebazaar_enabled.to_string());
        m.insert("feed_urlhaus_enabled".into(),        self.feed_urlhaus_enabled.to_string());
        m.insert("custom_ioc_feed_url".into(),         self.custom_ioc_feed_url.clone());
        m.insert("ioc_expiry_days".into(),             self.ioc_expiry_days.to_string());
        m
    }

    /// Merge a JSON payload into current settings.
    /// Only supplied keys are overwritten; missing keys keep current values.
    pub fn merge_from_json(&mut self, v: &serde_json::Value) {
        if let Some(s) = v.get("org_name").and_then(|x| x.as_str()) {
            self.org_name = s.to_string();
        }
        if let Some(s) = v.get("system_name").and_then(|x| x.as_str()) {
            self.system_name = s.to_string();
        }
        if let Some(s) = v.get("timezone").and_then(|x| x.as_str()) {
            self.timezone = s.to_string();
        }
        if let Some(s) = v.get("language").and_then(|x| x.as_str()) {
            self.language = s.to_string();
        }
        if let Some(s) = v.get("theme").and_then(|x| x.as_str()) {
            self.theme = s.to_string();
        }

        if let Some(n) = v.get("auto_block_threshold").and_then(|x| x.as_u64()) {
            self.auto_block_threshold = (n as u32).min(100);
        }
        if let Some(n) = v.get("severity_critical").and_then(|x| x.as_u64()) {
            self.severity_critical = (n as u32).min(100);
        }
        if let Some(n) = v.get("severity_high").and_then(|x| x.as_u64()) {
            self.severity_high = (n as u32).min(100);
        }
        if let Some(n) = v.get("severity_medium").and_then(|x| x.as_u64()) {
            self.severity_medium = (n as u32).min(100);
        }
        if let Some(n) = v.get("severity_low").and_then(|x| x.as_u64()) {
            self.severity_low = (n as u32).min(100);
        }
        if let Some(s) = v.get("sigma_rules_dir").and_then(|x| x.as_str()) {
            self.sigma_rules_dir = s.to_string();
        }
        if let Some(n) = v.get("hot_reload_interval_min").and_then(|x| x.as_u64()) {
            self.hot_reload_interval_min = (n as u32).max(1);
        }

        if let Some(n) = v.get("ti_refresh_interval_min").and_then(|x| x.as_u64()) {
            self.ti_refresh_interval_min = (n as u32).max(1);
        }
        if let Some(b) = v.get("feed_feodo_enabled").and_then(|x| x.as_bool()) {
            self.feed_feodo_enabled = b;
        }
        if let Some(b) = v.get("feed_malwarebazaar_enabled").and_then(|x| x.as_bool()) {
            self.feed_malwarebazaar_enabled = b;
        }
        if let Some(b) = v.get("feed_urlhaus_enabled").and_then(|x| x.as_bool()) {
            self.feed_urlhaus_enabled = b;
        }
        if let Some(s) = v.get("custom_ioc_feed_url").and_then(|x| x.as_str()) {
            self.custom_ioc_feed_url = s.to_string();
        }
        if let Some(n) = v.get("ioc_expiry_days").and_then(|x| x.as_u64()) {
            self.ioc_expiry_days = (n as u32).max(1);
        }
    }
}
