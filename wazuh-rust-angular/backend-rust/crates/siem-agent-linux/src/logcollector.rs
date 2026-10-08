use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Tracks the read byte offset for each monitored log file
pub struct LogTracker {
    path: PathBuf,
    offset: u64,
    source: EventSource,
}

impl LogTracker {
    pub fn new(path: impl Into<PathBuf>, source: EventSource) -> Self {
        let p = path.into();
        let offset = if let Ok(meta) = std::fs::metadata(&p) {
            meta.len()
        } else {
            0
        };

        Self {
            path: p,
            offset,
            source,
        }
    }

    /// Read new lines appended to the log file since the previous poll
    pub fn poll_new_lines(&mut self) -> Vec<String> {
        if !self.path.exists() {
            return Vec::new();
        }

        let Ok(file) = File::open(&self.path) else {
            return Vec::new();
        };

        let mut reader = BufReader::new(file);

        // Check if logrotate truncated the file
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() < self.offset {
                self.offset = 0;
            }
        }

        if reader.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }

        let mut lines = Vec::new();
        let mut line = String::new();

        while let Ok(bytes_read) = reader.read_line(&mut line) {
            if bytes_read == 0 {
                break;
            }
            let trimmed = line.trim_end();
            if !trimmed.is_empty() {
                lines.push(trimmed.to_string());
            }
            self.offset += bytes_read as u64;
            line.clear();
        }

        lines
    }
}

/// Spawns the Linux logcollector worker (mirroring Wazuh logcollector daemon)
pub fn spawn_logcollector_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    poll_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("wazuh-logcollector: Initializing target log streams...");

        let mut trackers: Vec<LogTracker> = Vec::new();

        let candidate_logs = [
            ("/var/log/auth.log", EventSource::Auth),
            ("/var/log/secure", EventSource::Auth),
            ("/var/log/audit/audit.log", EventSource::Syslog),
            ("/var/log/syslog", EventSource::Syslog),
            ("/var/log/messages", EventSource::Syslog),
            ("/var/log/cron", EventSource::Syslog),
            ("/var/log/dpkg.log", EventSource::Syslog),
            ("/var/log/apt/history.log", EventSource::Syslog),
            ("/var/log/yum.log", EventSource::Syslog),
            ("/var/log/dnf.log", EventSource::Syslog),
            ("/var/log/nginx/access.log", EventSource::Custom("web-nginx".into())),
            ("/var/log/nginx/error.log", EventSource::Custom("web-nginx".into())),
            ("/var/log/apache2/access.log", EventSource::Custom("web-apache".into())),
            ("/var/log/apache2/error.log", EventSource::Custom("web-apache".into())),
            ("/var/log/httpd/access_log", EventSource::Custom("web-httpd".into())),
            ("./test_linux_logs/auth.log", EventSource::Auth),
            ("./test_linux_logs/audit.log", EventSource::Syslog),
            ("./test_linux_logs/syslog", EventSource::Syslog),
        ];

        for (path_str, src) in &candidate_logs {
            let path = Path::new(path_str);
            if path.exists() {
                info!(" [✓] wazuh-logcollector attached to: {}", path_str);
                trackers.push(LogTracker::new(path, src.clone()));
            }
        }

        if trackers.is_empty() {
            info!("wazuh-logcollector: Standard Linux log paths not detected. Dynamic detection active.");
        }

        loop {
            tokio::time::sleep(poll_interval).await;

            // Dynamically attach if new logs are created or test files created
            for (path_str, src) in &candidate_logs {
                let p = Path::new(path_str);
                if p.exists() && !trackers.iter().any(|t| t.path == p) {
                    info!(" [✓] wazuh-logcollector dynamically attached to: {}", path_str);
                    trackers.push(LogTracker::new(p, src.clone()));
                }
            }

            for tracker in &mut trackers {
                let lines = tracker.poll_new_lines();
                for log_line in lines {
                    let location = tracker.path.to_string_lossy().to_string();
                    let mut event = RawEvent::new(
                        &agent_id,
                        tracker.source.clone(),
                        format!("linux/{}", location),
                        log_line.clone(),
                    );
                    event.metadata.insert("log_file".into(), location);
                    event.metadata.insert("os_type".into(), "linux".into());

                    // Categorize event based on standard Linux security patterns (matching decoders/syslog_rules)
                    if log_line.contains("Failed password") || log_line.contains("authentication failure") {
                        event.metadata.insert("category".into(), "auth_failure".into());
                    } else if log_line.contains("Accepted password") || log_line.contains("Accepted publickey") {
                        event.metadata.insert("category".into(), "auth_success".into());
                    } else if log_line.contains("sudo:") {
                        event.metadata.insert("category".into(), "sudo_execution".into());
                    } else if log_line.contains("type=EXECVE") || log_line.contains("type=SYSCALL") {
                        event.metadata.insert("category".into(), "audit_syscall".into());
                    } else if log_line.contains("status installed") || log_line.contains("Installed:") {
                        event.metadata.insert("category".into(), "package_installed".into());
                    } else if log_line.contains("' OR '") || log_line.contains("UNION SELECT") || log_line.contains("../..") || log_line.contains("<script>") {
                        event.metadata.insert("category".into(), "web_attack".into());
                    }

                    buffer.push(event).await;
                }
            }
        }
    })
}
