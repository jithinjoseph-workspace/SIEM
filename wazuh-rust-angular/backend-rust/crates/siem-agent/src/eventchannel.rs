use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
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
        // High-value threat telemetry channels mirroring Wazuh Windows EventChannel configuration
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

    /// Read recent events from a Windows Event Log channel using `wevtutil`
    fn read_channel(&mut self, channel: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Query latest 5 events rendered as text.
            // If an optional channel (like Sysmon) is not installed, wevtutil gracefully errors out
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

        // Limit cache size to prevent memory leaks
        if self.seen_events.len() > 10000 {
            self.seen_events.clear();
        }

        results
    }

    pub async fn poll_and_emit(&mut self, buffer: &AgentBuffer) {
        let channels = self.channels.clone();
        for channel in channels {
            let events = self.read_channel(&channel);
            for (event_id, text) in events {
                let msg = format!("Windows-Event [{}] EventID:{} - {}", channel, event_id, text);
                info!("Windows Event Log: {}", msg);

                let mut event = RawEvent::new(&self.agent_id, EventSource::WindowsEvent, &channel, msg);
                event.metadata.insert("channel".into(), channel.clone());
                event.metadata.insert("event_id".into(), event_id.clone());

                // Enrich known critical security events
                match event_id.as_str() {
                    "4625" => {
                        event.metadata.insert("severity".into(), "high".into());
                        event.metadata.insert("threat_type".into(), "failed_logon".into());
                    }
                    "4688" => {
                        event.metadata.insert("severity".into(), "medium".into());
                        event.metadata.insert("threat_type".into(), "process_creation".into());
                    }
                    "7045" => {
                        event.metadata.insert("severity".into(), "high".into());
                        event.metadata.insert("threat_type".into(), "service_installation".into());
                    }
                    "4104" => {
                        event.metadata.insert("severity".into(), "high".into());
                        event.metadata.insert("threat_type".into(), "powershell_scriptblock".into());
                    }
                    "1116" | "1117" => {
                        event.metadata.insert("severity".into(), "critical".into());
                        event.metadata.insert("threat_type".into(), "defender_malware_detected".into());
                    }
                    "106" => {
                        event.metadata.insert("severity".into(), "medium".into());
                        event.metadata.insert("threat_type".into(), "scheduled_task_registered".into());
                    }
                    "1102" => {
                        event.metadata.insert("severity".into(), "critical".into());
                        event.metadata.insert("threat_type".into(), "audit_log_cleared".into());
                    }
                    "4720" => {
                        event.metadata.insert("severity".into(), "high".into());
                        event.metadata.insert("threat_type".into(), "user_account_created".into());
                    }
                    "4728" | "4732" => {
                        event.metadata.insert("severity".into(), "high".into());
                        event.metadata.insert("threat_type".into(), "security_group_membership_elevated".into());
                    }
                    "4738" => {
                        event.metadata.insert("severity".into(), "medium".into());
                        event.metadata.insert("threat_type".into(), "user_account_modified".into());
                    }
                    _ => {}
                }

                buffer.push(event).await;
            }
        }
    }
}

pub fn spawn_eventchannel_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut collector = WindowsEventChannel::new(agent_id);
        info!("Windows EventChannel collector started for Security, System, Application, PowerShell, Defender, and Sysmon channels");

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            debug!("EventChannel: Polling Windows event logs...");
            collector.poll_and_emit(&buffer).await;
        }
    })
}
