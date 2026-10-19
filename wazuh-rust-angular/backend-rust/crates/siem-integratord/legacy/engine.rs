//! Wazuh Integrator Engine (src/os_integrator/integrator.c)
//!
//! Evaluates incoming JSON alerts against configured integrations, validates requirements,
//! serializes alert files, and dispatches external integrations.

use crate::config::IntegratorConfig;
use crate::executor::{ExecutorError, IntegrationExecutor, IntegrationInvocation};
use serde_json::Value;

pub struct IntegratorEngine {
    pub integrations: Vec<IntegratorConfig>,
    pub mock_mode: bool,
    pub mock_invocations: Vec<IntegrationInvocation>,
    pub total_dispatched: usize,
}

impl IntegratorEngine {
    pub fn new(integrations: Vec<IntegratorConfig>) -> Self {
        Self {
            integrations,
            mock_mode: true, // Default to mock mode for deterministic safety in test environments
            mock_invocations: Vec::new(),
            total_dispatched: 0,
        }
    }

    /// Process a single incoming JSON alert record matching `OS_IntegratorD`
    pub fn process_alert(&mut self, alert: &Value) -> Result<usize, ExecutorError> {
        let rule_level = alert["rule"]["level"].as_u64().unwrap_or(0) as u8;
        let rule_id = alert["rule"]["id"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .or_else(|| alert["rule"]["id"].as_u64().map(|n| n as u32))
            .unwrap_or(0);
        let location = alert["location"].as_str().unwrap_or("");

        let mut groups = Vec::new();
        if let Some(arr) = alert["rule"]["groups"].as_array() {
            for g in arr {
                if let Some(s) = g.as_str() {
                    groups.push(s.to_string());
                }
            }
        }

        let mut matched_count = 0;

        for config in &self.integrations {
            if !config.matches_alert(rule_level, rule_id, &groups, location) {
                continue;
            }

            // Serialize alert payload
            let alert_content =
                IntegrationExecutor::format_alert(config.alert_format, alert, config.max_log);

            let invocation = IntegrationInvocation {
                integration_name: config.name.clone(),
                script_path: config.path.clone().unwrap_or_default(),
                alert_content,
                options_content: config.options.clone(),
                apikey: config.apikey.clone(),
                hookurl: config.hookurl.clone(),
                timeout: config.timeout,
                retries: config.retries,
            };

            if self.mock_mode {
                self.mock_invocations.push(invocation);
            } else {
                let _ = IntegrationExecutor::execute(config, alert, false);
            }

            matched_count += 1;
            self.total_dispatched += 1;
        }

        Ok(matched_count)
    }

    pub fn active_count(&self) -> usize {
        self.integrations.iter().filter(|i| i.enabled).count()
    }
}
