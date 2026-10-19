//! Wazuh Mail Daemon Core Engine (src/os_maild/maild.c)
//!
//! Orchestrates alert processing, severity filtering, granular routing,
//! anti-flooding rate limits, aggregation buffers, and delivery execution.

use crate::config::{EmailFormat, MailConfig};
use crate::mail_list::{MailMsg, MailQueue};
use crate::mailer::{AlertMailFormatter, MailerError, SmtpTransport};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Rate limit tracking state for the current hourly window matching `email_maxperhour`.
#[derive(Debug, Clone)]
pub struct HourlyRateTracker {
    max_per_hour: u32,
    current_hour_count: u32,
    dropped_count: u32,
    window_start: Instant,
}

impl HourlyRateTracker {
    pub fn new(max_per_hour: u32) -> Self {
        Self {
            max_per_hour,
            current_hour_count: 0,
            dropped_count: 0,
            window_start: Instant::now(),
        }
    }

    /// Checks if another email is permitted within the current hourly window
    pub fn allow_email(&mut self) -> bool {
        // Reset window if 3600 seconds elapsed
        if self.window_start.elapsed() >= Duration::from_secs(3600) {
            self.current_hour_count = 0;
            self.dropped_count = 0;
            self.window_start = Instant::now();
        }

        if self.current_hour_count < self.max_per_hour {
            self.current_hour_count += 1;
            true
        } else {
            self.dropped_count += 1;
            false
        }
    }

    pub fn dropped_count(&self) -> u32 {
        self.dropped_count
    }

    pub fn current_hour_count(&self) -> u32 {
        self.current_hour_count
    }
}

/// The Wazuh Mail Daemon service matching `maild.c`
pub struct MailDaemon {
    pub config: MailConfig,
    pub queue: MailQueue,
    pub rate_tracker: HourlyRateTracker,
    pub delivered_count: usize,
    pub last_flush: Instant,
    pub mock_mode: bool,
    pub mock_sent_messages: Vec<String>,
}

impl MailDaemon {
    pub fn new(config: MailConfig) -> Self {
        let max_per_hour = config.maxperhour;
        Self {
            config,
            queue: MailQueue::default(),
            rate_tracker: HourlyRateTracker::new(max_per_hour),
            delivered_count: 0,
            last_flush: Instant::now(),
            mock_mode: true, // Default to mock mode in unit tests/embedded runs
            mock_sent_messages: Vec::new(),
        }
    }

    /// Process an alert record in JSON format matching `OS_RecvMailQ_JSON`
    pub fn process_alert_json(&mut self, alert: &Value) -> Result<bool, MailerError> {
        let rule_level = alert["rule"]["level"].as_u64().unwrap_or(0) as u8;
        let rule_id = alert["rule"]["id"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .or_else(|| alert["rule"]["id"].as_u64().map(|n| n as u32))
            .unwrap_or(0);
        let rule_desc = alert["rule"]["description"]
            .as_str()
            .unwrap_or("Unknown alert");
        let agent_name = alert["agent"]["name"].as_str().unwrap_or("manager");
        let agent_id = alert["agent"]["id"].as_str().unwrap_or("000");
        let location = alert["location"].as_str().unwrap_or("unknown");
        let timestamp = alert["timestamp"]
            .as_str()
            .unwrap_or("2026-09-28T00:00:00Z");
        let full_log = alert["full_log"].as_str().unwrap_or("");

        let mut groups = Vec::new();
        if let Some(arr) = alert["rule"]["groups"].as_array() {
            for g in arr {
                if let Some(s) = g.as_str() {
                    groups.push(s.to_string());
                }
            }
        }

        // Determine target recipients
        let mut target_recipients = Vec::new();
        let mut alert_format = EmailFormat::Full;

        // 1. Check granular rules
        for gran in &self.config.gran_to {
            if gran.matches(rule_level, rule_id, &groups, location) {
                target_recipients.push(gran.to.clone());
                alert_format = gran.format;
            }
        }

        // 2. Fallback to default recipients if level >= min_level
        if target_recipients.is_empty() && rule_level >= self.config.min_level {
            target_recipients.extend(self.config.to.clone());
        }

        // If no recipients matched, alert is skipped
        if target_recipients.is_empty() {
            return Ok(false);
        }

        // Format email subject and body
        let subject = AlertMailFormatter::build_subject(
            &self.config.idsname,
            agent_name,
            rule_level,
            rule_desc,
            alert_format,
        );

        let body = AlertMailFormatter::build_body(
            &self.config.idsname,
            timestamp,
            &format!("{} ({}) -> {}", agent_name, agent_id, location),
            rule_id,
            rule_level,
            rule_desc,
            full_log,
        );

        let mut mail_msg = MailMsg::new(&subject, &body, target_recipients.clone());
        mail_msg.rule_level = rule_level;
        mail_msg.rule_id = rule_id;
        mail_msg.agent_name = agent_name.to_string();

        if alert_format == EmailFormat::DoNotDelay || !self.config.grouping {
            // Immediate dispatch without buffering
            self.send_single_message(&mail_msg)?;
        } else {
            // Buffer for grouping
            self.queue.push(mail_msg);
            if self.queue.is_full() {
                self.flush_queue()?;
            }
        }

        Ok(true)
    }

    /// Flushes all pending buffered messages as an aggregated digest email
    pub fn flush_queue(&mut self) -> Result<usize, MailerError> {
        let msgs = self.queue.drain_all();
        if msgs.is_empty() {
            return Ok(0);
        }

        // Check hourly rate limiter
        if !self.rate_tracker.allow_email() {
            return Ok(0);
        }

        // Group messages by recipient set
        let mut recipient_groups: HashMap<Vec<String>, Vec<MailMsg>> = HashMap::new();
        for msg in msgs {
            let key = msg.recipients.clone();
            recipient_groups.entry(key).or_default().push(msg);
        }

        let mut sent_batches = 0;
        for (recipients, batch) in recipient_groups {
            let (subject, body) = AlertMailFormatter::build_aggregated_email(&self.config.idsname, &batch);
            let rfc2822 = AlertMailFormatter::build_rfc2822_message(&self.config, &recipients, &subject, &body);

            if self.mock_mode {
                self.mock_sent_messages.push(rfc2822);
            } else {
                // Real SMTP transmission
                let mut stream = siem_shared::net::connect_tcp(&self.config.smtpserver, 25)
                    .map_err(|e| MailerError::ConnectionFailed(e.to_string()))?;
                SmtpTransport::send(&mut stream, &self.config.from, &recipients, &rfc2822)?;
            }

            self.delivered_count += batch.len();
            sent_batches += 1;
        }

        self.last_flush = Instant::now();
        Ok(sent_batches)
    }

    fn send_single_message(&mut self, msg: &MailMsg) -> Result<(), MailerError> {
        if !self.rate_tracker.allow_email() {
            return Ok(());
        }

        let rfc2822 = AlertMailFormatter::build_rfc2822_message(
            &self.config,
            &msg.recipients,
            &msg.subject,
            &msg.body,
        );

        if self.mock_mode {
            self.mock_sent_messages.push(rfc2822);
        } else {
            let mut stream = siem_shared::net::connect_tcp(&self.config.smtpserver, 25)
                .map_err(|e| MailerError::ConnectionFailed(e.to_string()))?;
            SmtpTransport::send(&mut stream, &self.config.from, &msg.recipients, &rfc2822)?;
        }

        self.delivered_count += 1;
        Ok(())
    }
}
