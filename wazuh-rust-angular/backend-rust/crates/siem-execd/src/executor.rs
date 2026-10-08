//! Active Response Process Execution (`src/os_execd/exec.c`, `src/os_execd/execd.c`)
//!
//! Handles safe process execution via STDIN / STDOUT pipes matching Wazuh's active response protocol.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use thiserror::Error;
use tracing::warn;

#[derive(Error, Debug)]
pub enum ExecError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Process exited with error code: {0}")]
    ExitStatus(i32),
    #[error("Directory traversal attempt rejected: {0}")]
    Traversal(String),
}

/// Result of initial active response execution containing keys extracted from script STDOUT.
#[derive(Debug, Clone)]
pub struct ArExecutionResult {
    pub rkey: String,
    pub keys: Vec<String>,
}

/// Executes an active response script, writes `initial_params` to STDIN,
/// reads the `check_keys` JSON response from STDOUT, and returns the generated `rkey`.
pub fn execute_ar_handshake(
    program: &str,
    initial_params: &serde_json::Value,
) -> Result<ArExecutionResult, ExecError> {
    // Directory traversal check
    if program.contains("..") {
        return Err(ExecError::Traversal(program.to_string()));
    }

    let prog_name = Path::new(program)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| program.to_string());

    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    // Send initial JSON to child stdin
    let params_str = initial_params.to_string();
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{}", params_str)?;
        stdin.flush()?;
    }

    // Read response from child stdout
    let mut response_line = String::new();
    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        let _ = reader.read_line(&mut response_line);
    }

    let _ = child.wait();

    let mut keys = Vec::new();
    let mut rkey = prog_name.clone();

    let trimmed = response_line.trim();
    if !trimmed.is_empty() {
        if let Ok(keys_json) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(cmd) = keys_json.get("command").and_then(|v| v.as_str()) {
                if cmd == "check_keys" {
                    if let Some(params) = keys_json.get("parameters") {
                        if let Some(k_arr) = params.get("keys").and_then(|v| v.as_array()) {
                            for k in k_arr {
                                if let Some(s) = k.as_str() {
                                    keys.push(s.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !keys.is_empty() {
        rkey.push('-');
        rkey.push_str(&keys.join("-"));
    }

    Ok(ArExecutionResult { rkey, keys })
}

/// Executes an active response script passing JSON parameters to STDIN (for delete, continue, abort).
pub fn execute_ar_action(program: &str, params: &serde_json::Value) -> Result<(), ExecError> {
    if program.contains("..") {
        return Err(ExecError::Traversal(program.to_string()));
    }

    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let params_str = params.to_string();
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{}", params_str)?;
        stdin.flush()?;
    }

    let status = child.wait()?;
    if !status.success() {
        warn!("Active response script '{}' exited with status: {:?}", program, status.code());
    }

    Ok(())
}

/// Extracts or derives an `rkey` from a script name and alert JSON parameters
/// without requiring subprocess execution (useful for deterministic tests and internal queuing).
pub fn derive_rkey(program: &str, alert_keys: &[&str]) -> String {
    let prog_name = Path::new(program)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| program.to_string());

    if alert_keys.is_empty() {
        prog_name
    } else {
        format!("{}-{}", prog_name, alert_keys.join("-"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_rkey() {
        let rkey = derive_rkey("/var/ossec/active-response/bin/firewall-drop.sh", &["192.168.1.5"]);
        assert_eq!(rkey, "firewall-drop.sh-192.168.1.5");

        let rkey_no_keys = derive_rkey("restart-wazuh", &[]);
        assert_eq!(rkey_no_keys, "restart-wazuh");
    }

    #[test]
    fn test_traversal_rejection() {
        let dummy = serde_json::json!({});
        assert!(execute_ar_handshake("../../bin/sh", &dummy).is_err());
        assert!(execute_ar_action("../script.sh", &dummy).is_err());
    }
}
