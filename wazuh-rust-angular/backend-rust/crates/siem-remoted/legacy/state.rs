//! Remoted Daemon State & Performance Metrics (state.c, state.h)
//!
//! Tracks operational statistics, network throughput, active connection counts,
//! and dropped or replayed packet counters.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct RemotedState {
    pub total_messages_received: AtomicU64,
    pub total_bytes_received: AtomicU64,
    pub total_messages_sent: AtomicU64,
    pub dropped_messages: AtomicU64,
    pub discarded_replays: AtomicU64,
    pub invalid_packets: AtomicU64,
    pub active_agents: AtomicUsize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotedMetricsSnapshot {
    pub total_messages_received: u64,
    pub total_bytes_received: u64,
    pub total_messages_sent: u64,
    pub dropped_messages: u64,
    pub discarded_replays: u64,
    pub invalid_packets: u64,
    pub active_agents: usize,
    pub timestamp_rfc3339: String,
}

impl RemotedState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn inc_received(&self, bytes: usize) {
        self.total_messages_received.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn inc_sent(&self) {
        self.total_messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dropped(&self) {
        self.dropped_messages.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_replay(&self) {
        self.discarded_replays.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_invalid(&self) {
        self.invalid_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_active_agents(&self, count: usize) {
        self.active_agents.store(count, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RemotedMetricsSnapshot {
        RemotedMetricsSnapshot {
            total_messages_received: self.total_messages_received.load(Ordering::Relaxed),
            total_bytes_received: self.total_bytes_received.load(Ordering::Relaxed),
            total_messages_sent: self.total_messages_sent.load(Ordering::Relaxed),
            dropped_messages: self.dropped_messages.load(Ordering::Relaxed),
            discarded_replays: self.discarded_replays.load(Ordering::Relaxed),
            invalid_packets: self.invalid_packets.load(Ordering::Relaxed),
            active_agents: self.active_agents.load(Ordering::Relaxed),
            timestamp_rfc3339: chrono::Utc::now().to_rfc3339(),
        }
    }
}
