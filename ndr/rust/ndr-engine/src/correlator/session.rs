// NDR Engine — Correlation Session
// License: Apache-2.0

use crate::normalizer::NormalizedEvent;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// A flow session that accumulates matching Zeek + Suricata events.
/// TTL is protocol-aware: TCP sessions live 600s, others 300s.
/// (Security Onion flow-timeouts: tcp established=600, udp established=300)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Session {
    pub community_id: String,
    pub agent_z:      Option<NormalizedEvent>,
    pub agent_s:      Option<NormalizedEvent>,
    pub first_seen:   u64,
    pub last_seen:    u64,
    /// Transport protocol — determines which TTL to apply
    pub proto:        Option<String>,
}

impl Session {
    pub fn new(community_id: String) -> Self {
        let now = now_secs();
        Self {
            community_id,
            agent_z:    None,
            agent_s:    None,
            first_seen: now,
            last_seen:  now,
            proto:      None,
        }
    }

    /// TTL in seconds. TCP = 600s (10 min), everything else = 300s (5 min).
    pub fn ttl_secs(&self) -> u64 {
        match self.proto.as_deref() {
            Some("tcp") => 600,
            _           => 300,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.last_seen) > self.ttl_secs()
    }
}

/// A fully correlated event pair — Zeek flow + Suricata event for the same community_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationHit {
    pub community_id: String,
    pub agent_z:      NormalizedEvent,
    pub agent_s:      NormalizedEvent,
    pub hit_time:     u64,
    pub source:       String,  // ← NEW

}