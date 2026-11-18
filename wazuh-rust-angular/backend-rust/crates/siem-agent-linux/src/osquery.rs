use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use siem_core::{EventSource, RawEvent};
use crate::buffer::AgentBuffer;
use crate::lifecycle::LifecycleCoordinator;

const DAEMON_CHECK: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OsqueryConfig {
    pub enabled: bool,
    pub log_path: String,
    pub run_daemon: bool,
    pub bin_path: String,
    pub config_path: Option<String>,
}

impl Default for OsqueryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: "/var/log/osquery/osqueryd.results.log".to_string(),
            run_daemon: true,
            bin_path: "/usr/bin/osqueryd".to_string(),
            config_path: Some("/etc/osquery/osquery.conf".to_string()),
        }
    }
}

pub fn spawn_osquery_worker(
    agent_id: String,
    cfg: OsqueryConfig,
    buffer: Arc<AgentBuffer>,
    lifecycle: Arc<LifecycleCoordinator>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }

    let bin = Path::new(&cfg.bin_path);
    if !bin.exists() {
        info!("provigil-osquery: osqueryd not installed at '{}'. Subsystem inactive.", cfg.bin_path);
        return None;
    }

    info!("provigil-osquery: Initializing osquery supervisor daemon (bin: {}, log: {})", cfg.bin_path, cfg.log_path);

    Some(tokio::spawn(async move {
        let mut last_daemon_check = Instant::now() - DAEMON_CHECK;
        let mut daemon_child: Option<Child> = None;
        let mut last_offset: u64 = 0;

        let log_path = PathBuf::from(&cfg.log_path);
        if let Ok(meta) = std::fs::metadata(&log_path) {
            last_offset = meta.len();
        }

        loop {
            if lifecycle.is_terminated() {
                if let Some(mut child) = daemon_child.take() {
                    let _ = child.kill();
                }
                break;
            }
            if !lifecycle.is_active() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }

            // 1. Ensure osqueryd daemon is running
            if cfg.run_daemon && last_daemon_check.elapsed() >= DAEMON_CHECK {
                last_daemon_check = Instant::now();
                let needs_start = match daemon_child {
                    Some(ref mut child) => match child.try_wait() {
                        Ok(Some(_)) => true, // exited
                        Ok(None) => false,   // still running
                        Err(_) => true,
                    },
                    None => true,
                };

                if needs_start {
                    let mut cmd = Command::new(&cfg.bin_path);
                    if let Some(ref conf) = cfg.config_path {
                        if Path::new(conf).exists() {
                            cmd.arg(format!("--config_path={}", conf));
                        }
                    }
                    cmd.arg("--logger_plugin=filesystem");
                    cmd.arg(format!("--logger_path={}", Path::new(&cfg.log_path).parent().unwrap_or(Path::new("/var/log/osquery")).display()));
                    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());

                    match cmd.spawn() {
                        Ok(c) => {
                            info!("provigil-osquery: Spawned osqueryd supervisor daemon process (PID: {:?})", c.id());
                            daemon_child = Some(c);
                        }
                        Err(e) => {
                            warn!("provigil-osquery: Failed to spawn osqueryd: {}", e);
                        }
                    }
                }
            }

            // 2. Ingest new query result logs
            if log_path.exists() {
                if let Ok(file) = File::open(&log_path) {
                    if let Ok(meta) = file.metadata() {
                        let cur_len = meta.len();
                        if cur_len < last_offset {
                            last_offset = 0; // log rotated
                        }
                        if cur_len > last_offset {
                            let mut reader = BufReader::new(file);
                            if reader.seek(SeekFrom::Start(last_offset)).is_ok() {
                                for line in reader.lines().flatten() {
                                    let trimmed = line.trim();
                                    if !trimmed.is_empty() {
                                        let mut event = RawEvent::new(&agent_id, EventSource::Custom("osquery".into()), "osquery", trimmed.to_string());
                                        event.metadata.insert("source".into(), "osquery".into());
                                        event.metadata.insert("os_type".into(), "linux".into());
                                        buffer.push(event).await;
                                    }
                                }
                                last_offset = cur_len;
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osquery_config_defaults() {
        let cfg = OsqueryConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.bin_path, "/usr/bin/osqueryd");
        assert_eq!(cfg.log_path, "/var/log/osquery/osqueryd.results.log");
    }
}
