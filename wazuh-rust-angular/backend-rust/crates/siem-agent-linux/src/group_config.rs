use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

fn default_fim_interval() -> u64 { 15 }
fn default_sca_interval() -> u64 { 60 }
fn default_syscollector_interval() -> u64 { 30 }
fn default_rootcheck_interval() -> u64 { 120 }
fn default_logcollector_interval() -> u64 { 4 }
fn default_eps() -> usize { 500 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicGroupConfig {
    #[serde(default = "default_fim_interval")]
    pub fim_interval_secs: u64,
    #[serde(default = "default_sca_interval")]
    pub sca_interval_secs: u64,
    #[serde(default = "default_syscollector_interval")]
    pub syscollector_interval_secs: u64,
    #[serde(default = "default_rootcheck_interval")]
    pub rootcheck_interval_secs: u64,
    #[serde(default = "default_logcollector_interval")]
    pub logcollector_interval_secs: u64,
    #[serde(default = "default_eps")]
    pub events_per_second: usize,
    #[serde(default)]
    pub manager_urls: Vec<String>,
}

impl Default for DynamicGroupConfig {
    fn default() -> Self {
        Self {
            fim_interval_secs: default_fim_interval(),
            sca_interval_secs: default_sca_interval(),
            syscollector_interval_secs: default_syscollector_interval(),
            rootcheck_interval_secs: default_rootcheck_interval(),
            logcollector_interval_secs: default_logcollector_interval(),
            events_per_second: default_eps(),
            manager_urls: Vec::new(),
        }
    }
}

pub fn group_config_path() -> PathBuf {
    let candidate = Path::new("/opt/provigil-agent/data");
    if candidate.exists() || std::fs::create_dir_all(candidate).is_ok() {
        return candidate.join("group_config.json");
    }
    let local = Path::new("data");
    let _ = std::fs::create_dir_all(local);
    local.join("group_config.json")
}

pub fn load_persisted_group_config() -> DynamicGroupConfig {
    let path = group_config_path();
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<DynamicGroupConfig>(&content) {
                info!("GroupConfig: Loaded persisted group configuration from {}", path.display());
                return cfg;
            }
        }
    }
    DynamicGroupConfig::default()
}

pub fn save_group_config(cfg: &DynamicGroupConfig) {
    let path = group_config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json_str) = serde_json::to_string_pretty(cfg) {
        if let Err(err) = std::fs::write(&path, json_str) {
            warn!("GroupConfig: Failed to write group config to {}: {}", path.display(), err);
        } else {
            info!("GroupConfig: Persisted updated group configuration to {}", path.display());
        }
    }
}

pub fn parse_group_config_value(val: &serde_json::Value) -> Option<DynamicGroupConfig> {
    let config = val.get("config").unwrap_or(val);
    let mut parsed = DynamicGroupConfig::default();

    if let Some(intervals) = config.get("intervals").or_else(|| config.get("scan_intervals")) {
        if let Some(fim) = intervals.get("fim").and_then(|v| v.as_u64()) {
            parsed.fim_interval_secs = fim.max(2);
        }
        if let Some(sca) = intervals.get("sca").and_then(|v| v.as_u64()) {
            parsed.sca_interval_secs = sca.max(10);
        }
        if let Some(sysc) = intervals.get("syscollector").and_then(|v| v.as_u64()) {
            parsed.syscollector_interval_secs = sysc.max(10);
        }
        if let Some(root) = intervals.get("rootcheck").and_then(|v| v.as_u64()) {
            parsed.rootcheck_interval_secs = root.max(30);
        }
        if let Some(logc) = intervals.get("logcollector").and_then(|v| v.as_u64()) {
            parsed.logcollector_interval_secs = logc.max(1);
        }
    }

    if let Some(eps) = config.get("events_per_second").or_else(|| config.get("eps")).and_then(|v| v.as_u64()) {
        parsed.events_per_second = eps as usize;
    }

    if let Some(mgrs) = config.get("manager_urls").and_then(|v| v.as_array()) {
        parsed.manager_urls = mgrs.iter().filter_map(|m| m.as_str().map(|s| s.to_string())).collect();
    }

    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_group_config() {
        let json = serde_json::json!({
            "config": {
                "intervals": {
                    "fim": 30,
                    "sca": 180,
                    "syscollector": 60,
                    "rootcheck": 300,
                    "logcollector": 2
                },
                "events_per_second": 1000,
                "manager_urls": ["https://mgr-a:8443", "https://mgr-b:8443"]
            }
        });

        let parsed = parse_group_config_value(&json).expect("should parse");
        assert_eq!(parsed.fim_interval_secs, 30);
        assert_eq!(parsed.sca_interval_secs, 180);
        assert_eq!(parsed.syscollector_interval_secs, 60);
        assert_eq!(parsed.rootcheck_interval_secs, 300);
        assert_eq!(parsed.logcollector_interval_secs, 2);
        assert_eq!(parsed.events_per_second, 1000);
        assert_eq!(parsed.manager_urls, vec!["https://mgr-a:8443", "https://mgr-b:8443"]);
    }
}
