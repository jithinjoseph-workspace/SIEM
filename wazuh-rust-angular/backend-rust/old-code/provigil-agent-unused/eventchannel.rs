//! ProVigil Endpoint Agent - Windows Event Log Collection
//!
//! Collects Security, System, Application, PowerShell, Defender, and Sysmon events.
//! 100% clean-room implementation using wevtutil (ships with Windows).

use crate::buffer::EventBuffer;
use chrono::Utc;
use serde_json::json;
use std::collections::HashSet;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

pub struct WindowsEventChannel {
    agent_id: String,
    channels: Vec<String>,
    seen_events: HashSet<String>,
}

impl WindowsEventChannel {
    pub fn new(agent_id: String) -> Self {
        // High-value threat telemetry channels
        let channels = vec![
            "Security".into(),
            "System".into(),
            "Application".into(),
            "Microsoft-Windows-PowerShell/Operational".into(),
            "Microsoft-Windows-Windows Defender/Operational".into(),
            "Microsoft-Windows-Sysmon/Operational".into(),
            "Microsoft-Windows-TaskScheduler/Operational".into(),
        ];

        Self {
            agent_id,
            channels,
            seen_events: HashSet::new(),
        }
    }

    /// Read recent events from a Windows Event Log channel using wevtutil
    fn read_channel(&mut self, channel: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = Command::new("wevtutil")
                .args(["qe", channel, "/c:5", "/rd:true", "/f:text"])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let mut current_event = String::new();
                    let mut event_id = String::new();

                    for line in text.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("Event[") {
                            if !current_event.is_empty() && !event_id.is_empty() {
                                let key = format!("{}:{}:{}", channel, event_id, current_event.len());
                                if !self.seen_events.contains(&key) {
                                    self.seen_events.insert(key);
                                    results.push((event_id.clone(), current_event.clone()));
                                }
                            }
                            current_event.clear();
                            event_id.clear();
                        }

                        if trimmed.starts_with("Event ID:") {
                            if let Some(id) = trimmed.split(':').nth(1) {
                                event_id = id.trim().to_string();
                            }
                        }

                        current_event.push_str(trimmed);
                        current_event.push(' ');
                    }

                    if !current_event.is_empty() && !event_id.is_empty() {
                        let key = format!("{}:{}:{}", channel, event_id, current_event.len());
                        if !self.seen_events.contains(&key) {
                            self.seen_events.insert(key);
                            results.push((event_id, current_event));
                        }
                    }
                }
            }
        }

        // Limit cache size
        if self.seen_events.len() > 10000 {
            self.seen_events.clear();
        }

        results
    }

    pub async fn poll_and_emit(&mut self, buffer: &EventBuffer) {
        let channels = self.channels.clone();
        for channel in channels {
            let events = self.read_channel(&channel);
            for (event_id, text) in events {
                let msg = format!("Windows-Event [{}] EventID:{} - {}", channel, event_id, text);
                info!("Windows Event: {}", msg);

                // Enrich critical security events
                let (severity, threat_type) = match event_id.as_str() {
                    "4625" => ("high", "failed_logon"),
                    "4688" => ("medium", "process_creation"),
                    "7045" => ("high", "service_installation"),
                    "4104" => ("high", "powershell_scriptblock"),
                    "1116" | "1117" => ("critical", "defender_malware_detected"),
                    "106" => ("medium", "scheduled_task_registered"),
                    "1102" => ("critical", "audit_log_cleared"),
                    "4720" => ("high", "user_account_created"),
                    "4728" | "4732" => ("high", "security_group_membership_elevated"),
                    "4738" => ("medium", "user_account_modified"),
                    _ => ("info", "other"),
                };

                let event = json!({
                    "event_type": "windows_event",
                    "timestamp": Utc::now().to_rfc3339(),
                    "agent": {
                        "id": &self.agent_id,
                    },
                    "source": "eventchannel",
                    "channel": channel,
                    "event_id": event_id,
                    "message": msg,
                    "severity": severity,
                    "threat_type": threat_type,
                });

                buffer.push(event);
            }
        }
    }
}

pub fn spawn_eventchannel_worker(
    agent_id: String,
    buffer: Arc<EventBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut collector = WindowsEventChannel::new(agent_id);
        info!("Windows EventChannel collector started");

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            debug!("EventChannel: Polling Windows event logs...");
            collector.poll_and_emit(&buffer).await;
        }
    })
}
