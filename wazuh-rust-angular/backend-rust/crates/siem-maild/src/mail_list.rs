//! Wazuh Mail List / Alert Aggregation Queue (src/os_maild/mail_list.c, mail_list.h)
//!
//! Provides a bounded FIFO / ring buffer that buffers alert messages for grouping
//! and batch delivery up to `MAIL_LIST_SIZE` (96 alerts).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Default maximum number of alerts buffered matching `MAIL_LIST_SIZE`.
pub const DEFAULT_MAIL_LIST_SIZE: usize = 96;

/// Structure representing an individual email or alert message matching `MailMsg`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailMsg {
    pub subject: String,
    pub body: String,
    pub recipients: Vec<String>,
    pub rule_level: u8,
    pub rule_id: u32,
    pub timestamp: String,
    pub agent_name: String,
}

impl MailMsg {
    pub fn new(subject: &str, body: &str, recipients: Vec<String>) -> Self {
        Self {
            subject: subject.to_string(),
            body: body.to_string(),
            recipients,
            rule_level: 0,
            rule_id: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
            agent_name: "unknown".to_string(),
        }
    }
}

/// Mail queue for buffering alerts prior to delivery (`MailNode` list in `mail_list.c`).
#[derive(Debug, Clone)]
pub struct MailQueue {
    queue: VecDeque<MailMsg>,
    max_size: usize,
}

impl Default for MailQueue {
    fn default() -> Self {
        Self::new(DEFAULT_MAIL_LIST_SIZE)
    }
}

impl MailQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    /// Port of `OS_AddMailtoList`:
    /// Appends an alert message to the queue. If queue is full, oldest item is removed.
    pub fn push(&mut self, msg: MailMsg) {
        if self.queue.len() >= self.max_size {
            self.queue.pop_front();
        }
        self.queue.push_back(msg);
    }

    /// Port of `OS_PopLastMail`:
    /// Pops the oldest message from the queue.
    pub fn pop(&mut self) -> Option<MailMsg> {
        self.queue.pop_front()
    }

    /// Port of `OS_CheckLastMail`:
    /// Inspects the oldest pending message without removing it.
    pub fn peek(&self) -> Option<&MailMsg> {
        self.queue.front()
    }

    /// Drains all buffered messages in order.
    pub fn drain_all(&mut self) -> Vec<MailMsg> {
        self.queue.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.max_size
    }
}
