use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Default file positions tracking path for Linux
pub fn default_positions_path() -> PathBuf {
    let opt_dir = Path::new("/opt/provigil-agent/data");
    if opt_dir.is_dir() {
        opt_dir.join("file_positions.json")
    } else {
        PathBuf::from("data/file_positions.json")
    }
}

/// Load saved read positions from disk
pub fn load_file_positions(path: &Path) -> HashMap<String, u64> {
    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

/// Save read positions to disk
pub fn save_file_positions(path: &Path, positions: &HashMap<String, u64>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(file) = File::create(path) {
        let _ = serde_json::to_writer_pretty(file, positions);
    }
}

/// Tracks the read byte offset for each monitored log file
pub struct LogTracker {
    pub path: PathBuf,
    pub offset: u64,
    pub source: EventSource,
}

impl LogTracker {
    #[allow(dead_code)]
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

    pub fn with_offset(path: impl Into<PathBuf>, source: EventSource, offset: u64) -> Self {
        Self {
            path: path.into(),
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

/// Tracks systemd-journald logs on modern Linux installations
pub struct JournaldTracker {
    pub last_cursor: Option<String>,
}

impl JournaldTracker {
    pub fn new() -> Self {
        Self { last_cursor: None }
    }

    /// Check if systemd-journald is present on this host
    pub fn is_available() -> bool {
        Path::new("/run/systemd/journal").exists()
            || Path::new("/var/log/journal").exists()
            || Command::new("journalctl").arg("--version").output().is_ok()
    }

    /// Poll new journal messages using cursor tracking
    pub fn poll_new_entries(&mut self) -> Vec<String> {
        let mut cmd = Command::new("journalctl");
        cmd.args(["-n", "50", "--no-pager", "-o", "short-iso"]);

        if let Some(ref cursor) = self.last_cursor {
            cmd.args(["--after-cursor", cursor]);
        } else {
            // Initial poll: fetch only from the last minute to avoid backlog floods
            cmd.args(["--since", "1 minute ago"]);
        }

        cmd.arg("--show-cursor");

        if let Ok(output) = cmd.output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut lines = Vec::new();
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Some(cursor_val) = trimmed.strip_prefix("-- cursor: ") {
                        self.last_cursor = Some(cursor_val.trim().to_string());
                    } else {
                        lines.push(trimmed.to_string());
                    }
                }
                return lines;
            }
        }
        Vec::new()
    }
}

/// Spawns the Linux log collector worker with persistent offsets and journald support.
pub fn spawn_logcollector_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
    poll_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("provigil-logcollector: Initializing target log streams...");

        let positions_path = default_positions_path();
        let mut saved_positions = load_file_positions(&positions_path);
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
        ];

        for (path_str, src) in &candidate_logs {
            let path = Path::new(path_str);
            if path.exists() {
                let offset = saved_positions.get(*path_str).copied().unwrap_or_else(|| {
                    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
                });
                info!("provigil-logcollector attached to: {} (offset: {})", path_str, offset);
                trackers.push(LogTracker::with_offset(path, src.clone(), offset));
            }
        }

        let mut journal_tracker = if JournaldTracker::is_available() {
            info!("provigil-logcollector: Attached to systemd-journald stream.");
            Some(JournaldTracker::new())
        } else {
            None
        };

        let mut loops_count = 0u64;

        loop {
            tokio::time::sleep(poll_interval).await;
            if lifecycle.is_terminated() {
                // Save positions before exiting
                save_file_positions(&positions_path, &saved_positions);
                break;
            }
            if !lifecycle.is_active() {
                continue;
            }

            loops_count += 1;

            // Dynamically attach when watched log files appear
            for (path_str, src) in &candidate_logs {
                let p = Path::new(path_str);
                if p.exists() && !trackers.iter().any(|t| t.path == p) {
                    let offset = saved_positions.get(*path_str).copied().unwrap_or_else(|| {
                        std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
                    });
                    info!("provigil-logcollector dynamically attached to: {} (offset: {})", path_str, offset);
                    trackers.push(LogTracker::with_offset(p, src.clone(), offset));
                }
            }

            // 1. Ingest standard log files
            for tracker in &mut trackers {
                let lines = tracker.poll_new_lines();
                let loc = tracker.path.to_string_lossy().to_string();
                saved_positions.insert(loc.clone(), tracker.offset);

                for log_line in lines {
                    let mut event = RawEvent::new(
                        &agent_id,
                        tracker.source.clone(),
                        format!("linux/{}", loc),
                        log_line.clone(),
                    );
                    event.metadata.insert("log_file".into(), loc.clone());
                    event.metadata.insert("os_type".into(), "linux".into());

                    categorize_log_line(&mut event, &log_line);
                    buffer.push(event).await;
                }
            }

            // 2. Ingest systemd-journald entries on modern distributions
            if let Some(ref mut jt) = journal_tracker {
                let entries = jt.poll_new_entries();
                for entry in entries {
                    let mut event = RawEvent::new(
                        &agent_id,
                        EventSource::Syslog,
                        "linux/journald",
                        entry.clone(),
                    );
                    event.metadata.insert("source".into(), "systemd-journald".into());
                    event.metadata.insert("os_type".into(), "linux".into());

                    categorize_log_line(&mut event, &entry);
                    buffer.push(event).await;
                }
            }

            // Periodically persist positions every 5 iterations (~20s)
            if loops_count % 5 == 0 {
                save_file_positions(&positions_path, &saved_positions);
            }
        }
    })
}

fn categorize_log_line(event: &mut RawEvent, log_line: &str) {
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
    } else if log_line.contains("' OR '")
        || log_line.contains("UNION SELECT")
        || log_line.contains("../..")
        || log_line.contains("<script>")
    {
        event.metadata.insert("category".into(), "web_attack".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_positions_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("test_positions_{}", uuid::Uuid::new_v4()));
        let pos_file = temp_dir.join("file_positions.json");

        let mut positions = HashMap::new();
        positions.insert("/var/log/auth.log".to_string(), 1024u64);
        positions.insert("/var/log/syslog".to_string(), 4096u64);

        save_file_positions(&pos_file, &positions);
        let loaded = load_file_positions(&pos_file);

        assert_eq!(loaded.get("/var/log/auth.log"), Some(&1024u64));
        assert_eq!(loaded.get("/var/log/syslog"), Some(&4096u64));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_log_tracker_polling() {
        let temp_dir = std::env::temp_dir().join(format!("test_tracker_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let log_file = temp_dir.join("test.log");

        std::fs::write(&log_file, "line 1\nline 2\n").unwrap();

        let mut tracker = LogTracker::with_offset(&log_file, EventSource::Syslog, 0);
        let lines = tracker.poll_new_lines();
        assert_eq!(lines, vec!["line 1", "line 2"]);

        // Append more lines
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&log_file).unwrap();
        writeln!(f, "line 3").unwrap();

        let next_lines = tracker.poll_new_lines();
        assert_eq!(next_lines, vec!["line 3"]);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
