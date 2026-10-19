//! Integration Subprocess Executor & Alert Serializer (src/os_integrator/integrator.c)
//!
//! Formats alerts into JSON or sanitized key-value files, prepares execution arguments,
//! and invokes integration binaries/scripts with timeout and retries.

use crate::config::{AlertFormat, IntegratorConfig};
use serde_json::Value;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ExecutorError {
    #[error("Failed to write temporary alert file: {0}")]
    TempFileError(String),
    #[error("Subprocess execution failed: {0}")]
    ProcessError(String),
    #[error("Integration timed out after {0} seconds")]
    Timeout(u32),
}

/// Recorded integration invocation (useful for testing and monitoring)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationInvocation {
    pub integration_name: String,
    pub script_path: String,
    pub alert_content: String,
    pub options_content: Option<String>,
    pub apikey: Option<String>,
    pub hookurl: Option<String>,
    pub timeout: u32,
    pub retries: u32,
}

pub struct IntegrationExecutor;

impl IntegrationExecutor {
    /// Serializes an alert according to the integration's format matching `integrator.c`
    pub fn format_alert(format: AlertFormat, alert: &Value, max_log: usize) -> String {
        match format {
            AlertFormat::Json => serde_json::to_string(alert).unwrap_or_default(),
            AlertFormat::Text => {
                let timestamp = alert["timestamp"].as_str().unwrap_or("");
                let location = alert["location"].as_str().unwrap_or("");
                let rule_id = alert["rule"]["id"].as_str().unwrap_or("");
                let level = alert["rule"]["level"].as_u64().unwrap_or(0);
                let desc = alert["rule"]["description"].as_str().unwrap_or("");
                let raw_log = alert["full_log"].as_str().unwrap_or("");
                let srcip = alert["data"]["srcip"]
                    .as_str()
                    .or_else(|| alert["srcip"].as_str())
                    .unwrap_or("");

                // Character sanitization matching lines 303-349 in integrator.c
                let sanitized_log = Self::sanitize_log(raw_log, max_log);
                let sanitized_ip = Self::sanitize_srcip(srcip);

                format!(
                    "alertdate='{}'\nalertlocation='{}'\nruleid='{}'\nalertlevel='{}'\nruledescription='{}'\nalertlog='{}'\nsrcip='{}'",
                    timestamp, location, rule_id, level, desc, sanitized_log, sanitized_ip
                )
            }
        }
    }

    /// Character sanitization matching lines 303-349 in `integrator.c`
    fn sanitize_log(log: &str, max_log: usize) -> String {
        let mut out = String::with_capacity(log.len());
        for c in log.chars() {
            if out.len() >= max_log {
                out.push_str("...");
                break;
            }
            match c {
                '\'' | '`' | '"' | '!' | '$' => out.push(' '),
                '\\' => out.push('/'),
                ';' => out.push(','),
                c if (c as u32) < 32 || (c as u32) > 122 => out.push(' '),
                c => out.push(c),
            }
        }
        out
    }

    /// IP sanitization matching lines 356-381 in `integrator.c`
    fn sanitize_srcip(ip: &str) -> String {
        let mut out = String::with_capacity(ip.len());
        for c in ip.chars() {
            match c {
                '\'' | '\\' | '`' => out.push(' '),
                ' ' => out.push(' '),
                c if (c as u32) < 46 || (c as u32) > 122 => out.push(' '),
                c => out.push(c),
            }
        }
        out
    }

    /// Builds command line arguments matching lines 432-440 of `integrator.c`:
    /// `[script_path, alert_file, apikey, hookurl, debug, options_file, timeout, retries]`
    pub fn build_command_args(
        config: &IntegratorConfig,
        alert_file: &Path,
        options_file: Option<&Path>,
        debug: bool,
    ) -> Vec<String> {
        vec![
            config.path.clone().unwrap_or_default(),
            alert_file.to_string_lossy().to_string(),
            config.apikey.clone().unwrap_or_default(),
            config.hookurl.clone().unwrap_or_default(),
            if debug { "debug".to_string() } else { String::new() },
            options_file
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            config.timeout.to_string(),
            config.retries.to_string(),
        ]
    }

    /// Executes integration command matching lines 278-486 of `integrator.c`
    pub fn execute(
        config: &IntegratorConfig,
        alert: &Value,
        debug: bool,
    ) -> Result<i32, ExecutorError> {
        let temp_dir = std::env::temp_dir();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let rand_val: u32 = rand_u32();

        let alert_path = temp_dir.join(format!("{}-{}-{}.alert", config.name, now, rand_val));
        let alert_content = Self::format_alert(config.alert_format, alert, config.max_log);

        std::fs::write(&alert_path, &alert_content)
            .map_err(|e| ExecutorError::TempFileError(e.to_string()))?;

        let opt_path = if let Some(ref opts) = config.options {
            let path = temp_dir.join(format!("{}-{}-{}.options", config.name, now, rand_val));
            let _ = std::fs::write(&path, opts);
            Some(path)
        } else {
            None
        };

        let script = config.path.as_deref().unwrap_or(&config.name);
        let mut cmd = std::process::Command::new(script);
        cmd.arg(&alert_path);
        cmd.arg(config.apikey.as_deref().unwrap_or(""));
        cmd.arg(config.hookurl.as_deref().unwrap_or(""));
        cmd.arg(if debug { "debug" } else { "" });
        cmd.arg(opt_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default());
        cmd.arg(config.timeout.to_string());
        cmd.arg(config.retries.to_string());

        let output = cmd.output();

        // Always clean up temp files (lines 478-486 of integrator.c)
        let _ = std::fs::remove_file(&alert_path);
        if let Some(ref path) = opt_path {
            let _ = std::fs::remove_file(path);
        }

        match output {
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                if code == 127 {
                    tracing::error!("Couldn't execute command ({}). Check file and permissions.", script);
                    Err(ExecutorError::ProcessError("Exit code 127: file not found or permission denied".to_string()))
                } else if code != 0 {
                    tracing::error!("Unable to run integration for {} -> {}", config.name, script);
                    Err(ExecutorError::ProcessError(format!("Exit status was: {}", code)))
                } else {
                    tracing::debug!("Command ran successfully.");
                    Ok(0)
                }
            }
            Err(e) => {
                tracing::error!("Could not launch command {}: {}", script, e);
                Err(ExecutorError::ProcessError(e.to_string()))
            }
        }
    }
}

fn rand_u32() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (now ^ (std::process::id() as u128)) as u32
}
