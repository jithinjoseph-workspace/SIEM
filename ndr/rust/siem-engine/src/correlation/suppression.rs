// SIEM Correlation Engine — Alert Suppression
// Evaluates ndr.siem_suppression_rules before creating a new alert.
// Rules are loaded from ClickHouse at startup and refreshed every 5 minutes.
// License: Apache-2.0

use std::sync::Arc;
use tokio::sync::RwLock;
use clickhouse::Client;
use serde::Deserialize;

use crate::correlation::types::{SiemEvent, RuleMatch, SuppressionRule};

/// In-memory cache of suppression rules, refreshed every 5 min.
#[derive(Clone)]
pub struct SuppressionCache {
    rules: Arc<RwLock<Vec<SuppressionRule>>>,
    ch:    Client,
}

// ClickHouse row type for the suppression query
#[derive(Debug, Deserialize, clickhouse::Row)]
struct SuppressionRow {
    id:               String,
    tenant_id:        String,
    rule_id:          String,
    hostname_pattern: String,
    username_pattern: String,
    enabled:          u8,
}

impl SuppressionCache {
    pub fn new(ch: Client) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            ch,
        }
    }

    /// Load suppression rules from ClickHouse.
    /// Called at startup and every 5 minutes.
    pub async fn refresh(&self) {
        let sql = r#"
            SELECT
                id,
                tenant_id,
                rule_id,
                hostname_pattern,
                username_pattern,
                enabled
            FROM ndr.siem_suppression_rules FINAL
            WHERE enabled = 1
        "#;

        match self.ch.query(sql).fetch_all::<SuppressionRow>().await {
            Ok(rows) => {
                let rules: Vec<SuppressionRule> = rows.into_iter().map(|r| SuppressionRule {
                    id:               r.id,
                    tenant_id:        r.tenant_id,
                    rule_id:          if r.rule_id.is_empty() { None } else { Some(r.rule_id) },
                    hostname_pattern: if r.hostname_pattern.is_empty() { None } else { Some(r.hostname_pattern) },
                    username_pattern: if r.username_pattern.is_empty() { None } else { Some(r.username_pattern) },
                    enabled:          r.enabled != 0,
                }).collect();
                let count = rules.len();
                *self.rules.write().await = rules;
                tracing::debug!("Suppression cache refreshed: {} rules loaded", count);
            }
            Err(e) => {
                // Table may not exist yet on first boot — log and continue
                tracing::warn!("Suppression rules refresh failed (table may not exist yet): {}", e);
            }
        }
    }

    /// Returns true if the (event, rule_match) pair should be suppressed.
    /// Suppression logic:
    ///   - tenant_id must match
    ///   - rule_id: None = wildcard, Some(id) = exact match
    ///   - hostname_pattern: None = wildcard, Some(pat) = glob-style prefix match
    ///   - username_pattern: None = wildcard, Some(pat) = glob-style prefix match
    pub async fn is_suppressed(
        &self,
        event: &SiemEvent,
        rule_match: &RuleMatch,
    ) -> bool {
        let rules = self.rules.read().await;
        for rule in rules.iter() {
            // Tenant must match
            if rule.tenant_id != event.tenant_id && rule.tenant_id != "*" {
                continue;
            }

            // Rule ID check (None = match any)
            if let Some(ref rid) = rule.rule_id {
                if rid != &rule_match.rule_id { continue; }
            }

            // Hostname pattern check
            if let Some(ref pat) = rule.hostname_pattern {
                let host = event.hostname.as_deref().unwrap_or("");
                if !glob_match(pat, host) { continue; }
            }

            // Username pattern check
            if let Some(ref pat) = rule.username_pattern {
                let user = event.username.as_deref().unwrap_or("");
                if !glob_match(pat, user) { continue; }
            }

            tracing::debug!(
                "Alert suppressed by rule '{}' for event '{}' on host '{:?}'",
                rule.id, rule_match.rule_id, event.hostname
            );
            return true;
        }
        false
    }

    /// Spawn the 5-minute periodic refresh background task.
    pub fn spawn_refresh_loop(cache: Arc<SuppressionCache>) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(
                tokio::time::Duration::from_secs(300)
            );
            loop {
                ticker.tick().await;
                cache.refresh().await;
            }
        });
    }
}

/// Simple glob matcher: supports `*` as wildcard suffix/prefix.
/// e.g. "web-*" matches "web-server-01", "*-prod" matches "app-prod"
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" { return true; }
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        return value.starts_with(prefix);
    }
    if pattern.starts_with('*') {
        let suffix = &pattern[1..];
        return value.ends_with(suffix);
    }
    // Contains wildcard in middle
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.splitn(2, '*').collect();
        if parts.len() == 2 {
            return value.starts_with(parts[0]) && value.ends_with(parts[1]);
        }
    }
    pattern == value
}
