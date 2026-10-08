// Detection engine shared by ndr-engine and siem-engine.
// NDR-specific rule updater (updater.rs) and multiflow correlator stay in ndr-engine.
// License: Apache-2.0

pub mod sigma;
pub use sigma::{SigmaRule, DetectionMatch, LogSource, ConditionExpr, parse_rule_content};

use crate::normalizer::{NormalizedEvent, EventSource};
use crate::detection::sigma::LogSource as SigmaLogSource;
use std::collections::{HashMap, HashSet};

fn logsource_matches(ls: &SigmaLogSource, event: &NormalizedEvent) -> bool {
    let has_constraint = ls.product.is_some() || ls.category.is_some() || ls.service.is_some();
    if !has_constraint { return true; }

    let product  = ls.product.as_deref().unwrap_or("").to_lowercase();
    let category = ls.category.as_deref().unwrap_or("").to_lowercase();
    let service  = ls.service.as_deref().unwrap_or("").to_lowercase();

    match &event.event_source {
        EventSource::Zeek => {
            if matches!(product.as_str(), "windows" | "macos" | "linux" | "azure" | "okta" | "aws") {
                return false;
            }
            if !service.is_empty() {
                let log_src = event.log_source.as_deref().unwrap_or("");
                return service == log_src || service == "zeek";
            }
            if matches!(category.as_str(), "network_connection" | "dns" | "proxy" | "firewall" | "webserver") {
                return true;
            }
            if category.is_empty() {
                return true;
            }
            false
        }
        EventSource::Suricata => {
            if matches!(product.as_str(), "windows" | "macos" | "linux" | "azure" | "okta" | "aws") {
                return false;
            }
            true
        }
        EventSource::Linux => {
            if product == "windows" || product == "macos" { return false; }
            if product == "linux" || product.is_empty() { return true; }
            if category == "process_creation" || category == "network_connection" { return true; }
            false
        }
        EventSource::WindowsEvent => {
            if matches!(product.as_str(), "linux" | "macos" | "zeek" | "suricata") { return false; }
            if product == "windows" || product.is_empty() { return true; }
            if matches!(category.as_str(), "process_creation" | "network_connection" | "registry_set" | "file_event") {
                return true;
            }
            false
        }
        EventSource::Syslog => {
            if matches!(product.as_str(), "windows" | "macos") { return false; }
            true
        }
        EventSource::CloudTrailAws => {
            product == "aws" || product.is_empty()
        }
        EventSource::AzureAd => {
            product == "azure" || product.is_empty()
        }
        EventSource::Okta => {
            product == "okta" || product.is_empty()
        }
        EventSource::Unknown => true,
    }
}

pub struct DetectionEngine {
    rules: Vec<SigmaRule>,
    disabled_overrides: HashMap<String, HashSet<String>>,
}

impl DetectionEngine {
    pub fn new(_rules_dir: &str) -> Self {
        tracing::info!("Detection engine: starting empty, rules load from ClickHouse");
        Self { rules: Vec::new(), disabled_overrides: HashMap::new() }
    }

    pub fn check(&self, event: &NormalizedEvent) -> Vec<DetectionMatch> {
        self.rules.iter()
            .filter_map(|rule| self.eval(rule, event))
            .collect()
    }

    pub fn check_for_tenant(&self, event: &NormalizedEvent, tenant_id: &str) -> Vec<DetectionMatch> {
        let disabled = self.disabled_overrides.get(tenant_id);
        self.rules.iter()
            .filter(|rule| rule.tenant_id == "*" || rule.tenant_id == tenant_id)
            .filter(|rule| disabled.map_or(true, |d| !d.contains(&rule.id)))
            .filter(|rule| logsource_matches(&rule.logsource, event))
            .filter_map(|rule| self.eval(rule, event))
            .collect()
    }

    fn eval(&self, rule: &SigmaRule, event: &NormalizedEvent) -> Option<DetectionMatch> {
        let matched = rule.condition_expr.eval(&rule.selections, event);
        matched.then(|| DetectionMatch {
            rule_id:  rule.id.clone(),
            title:    rule.title.clone(),
            severity: rule.severity.clone(),
            tags:     rule.tags.clone(),
        })
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
    pub fn get_rules(&self) -> Vec<serde_json::Value> {
        self.rules.iter().map(|r| serde_json::json!({
            "id":        r.id,
            "title":     r.title,
            "severity":  r.severity,
            "tags":      r.tags,
            "tenant_id": r.tenant_id,
            "logsource": {
                "product":  r.logsource.product,
                "category": r.logsource.category,
                "service":  r.logsource.service,
            },
            "conditions": r.conditions.len(),
        })).collect()
    }

    pub fn set_rules(&mut self, rules: Vec<SigmaRule>, disabled: HashMap<String, HashSet<String>>) {
        tracing::info!("Rules updated: {} loaded, {} tenants with overrides", rules.len(), disabled.len());
        self.rules = rules;
        self.disabled_overrides = disabled;
    }
}
