//! Agentless Command Runner & Stream Dispatcher (`src/agentlessd/agentlessd.c`)
//!
//! Spawns external scripts/commands via pipes and routes streaming messages
//! (`ERROR:`, `INFO:`, `FWD:`, `LOG:`, `STORE:`) into the appropriate queues.

use crate::config::{AgentlessEntry, LESSD_STATE_DIFF};
use crate::diff::{check_diff_file, open_diff_file};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct ScriptOutputMessage {
    pub location: String,
    pub queue_type: String, // "syscheck", "localfile", "alert"
    pub message: String,
}

pub struct AgentlessExecutor {
    pub agentless_dir: PathBuf,
    pub diff_dir: PathBuf,
}

impl AgentlessExecutor {
    pub fn new<P1: AsRef<Path>, P2: AsRef<Path>>(agentless_dir: P1, diff_dir: P2) -> Self {
        Self {
            agentless_dir: agentless_dir.as_ref().to_path_buf(),
            diff_dir: diff_dir.as_ref().to_path_buf(),
        }
    }

    /// Builds command arguments matching `command_args`.
    pub fn build_args(&self, entry: &AgentlessEntry, server_entry: &str) -> (PathBuf, Vec<String>) {
        let script_path = if let Some(ref custom_cmd) = entry.command {
            PathBuf::from(custom_cmd)
        } else {
            self.agentless_dir.join(&entry.script_type)
        };

        let mut args = Vec::new();

        if let Some(prefix) = server_entry.chars().next() {
            match prefix {
                'o' => args.push("use_sudo".to_string()),
                's' => args.push("use_su".to_string()),
                _ => {}
            }
        }

        let raw_host = if server_entry.len() > 1 {
            &server_entry[1..]
        } else {
            server_entry
        };
        args.push(raw_host.to_string());

        if let Some(ref opts) = entry.options {
            for token in opts.split_whitespace() {
                args.push(token.to_string());
            }
        }

        (script_path, args)
    }

    /// Executes a periodic check for a server and processes stdout streams matching `run_periodic_cmd`.
    pub async fn run_periodic_check(
        &self,
        entry: &mut AgentlessEntry,
        server_entry: &str,
    ) -> io::Result<Vec<ScriptOutputMessage>> {
        let (prog, args) = self.build_args(entry, server_entry);
        let raw_host = if server_entry.len() > 1 {
            &server_entry[1..]
        } else {
            server_entry
        };

        info!("Executing agentless check: {} {:?}", prog.display(), args);

        let mut child = match Command::new(&prog)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to spawn {}: {}", prog.display(), e);
                entry.error_flag += 1;
                return Err(e);
            }
        };

        let stdout = child.stdout.take().expect("child stdout");
        let mut reader = BufReader::new(stdout).lines();

        let mut out_messages = Vec::new();
        let mut store_fp: Option<File> = None;

        while let Ok(Some(line)) = reader.next_line().await {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(stripped) = trimmed.strip_prefix("ERROR: ") {
                error!("{}: {}: {}", entry.script_type, raw_host, stripped);
                entry.error_flag += 1;
                break;
            } else if let Some(stripped) = trimmed.strip_prefix("INFO: ") {
                info!("{}: {}: {}", entry.script_type, raw_host, stripped);
            } else if let Some(stripped) = trimmed.strip_prefix("FWD: ") {
                out_messages.push(ScriptOutputMessage {
                    location: format!("({}) {}->syscheck", entry.script_type, raw_host),
                    queue_type: "syscheck".to_string(),
                    message: stripped.to_string(),
                });
            } else if let Some(stripped) = trimmed.strip_prefix("LOG: ") {
                out_messages.push(ScriptOutputMessage {
                    location: format!("({}) {}->syscheck", entry.script_type, raw_host),
                    queue_type: "localfile".to_string(),
                    message: stripped.to_string(),
                });
            } else if (entry.state & LESSD_STATE_DIFF != 0) && trimmed.starts_with("STORE: ") {
                if store_fp.is_none() {
                    if let Ok((_, fp)) = open_diff_file(&self.diff_dir, raw_host, &entry.script_type) {
                        store_fp = Some(fp);
                    }
                }
                if let Some(ref mut fp) = store_fp {
                    let _ = writeln!(fp, "{}", trimmed);
                }
            } else if let Some(ref mut fp) = store_fp {
                let _ = writeln!(fp, "{}", trimmed);
            }
        }

        // Wait for child process
        let status = child.wait().await?;
        if !status.success() {
            warn!("Agentless check {} exited with: {}", prog.display(), status);
        }

        // Flush and check diff if store was active
        if store_fp.is_some() {
            drop(store_fp);
            if let Ok(Some(diff_alert)) = check_diff_file(&self.diff_dir, raw_host, &entry.script_type) {
                out_messages.push(ScriptOutputMessage {
                    location: format!("({}) {}->wazuh-agentlessd", entry.script_type, raw_host),
                    queue_type: "localfile".to_string(),
                    message: diff_alert,
                });
            }
        }

        Ok(out_messages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_build_args() {
        let dir = tempdir().unwrap();
        let executor = AgentlessExecutor::new(dir.path(), dir.path().join("diff"));

        let entry = AgentlessEntry {
            script_type: "ssh_integrity_check_linux".to_string(),
            servers: vec!["oroot@192.168.1.10".to_string()],
            options: Some("/bin /etc".to_string()),
            ..Default::default()
        };

        let (prog, args) = executor.build_args(&entry, &entry.servers[0]);
        assert_eq!(prog, dir.path().join("ssh_integrity_check_linux"));
        assert_eq!(args, vec!["use_sudo", "root@192.168.1.10", "/bin", "/etc"]);
    }
}
