// NDR Engine — Real-time Correlation Engine
// Fires immediately from Zeek OR Suricata — no waiting
// Upgrades to full correlation if both arrive
// License: Apache-2.0

pub mod session;
pub use session::{Session, CorrelationHit};

use crate::normalizer::{EventSource, NormalizedEvent};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub struct CorrelationEngine {
    sessions: Arc<DashMap<String, Session>>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    pub fn process(&self, event: NormalizedEvent) -> Option<CorrelationHit> {
        let cid = event.community_id.clone()?;
        let now = now_secs();

        let mut session = self.sessions
            .entry(cid.clone())
            .or_insert_with(|| Session::new(cid.clone()));

        session.last_seen = now;

        match event.event_source {
            EventSource::Zeek => {
                if let Some(p) = &event.proto {
                    session.proto = Some(p.clone());
                }
                session.agent_z = Some(event);

                // Best — both sources present
                if let (Some(z), Some(s)) = (
                    &session.agent_z,
                    &session.agent_s
                ) {
                    return Some(CorrelationHit {
                        community_id: cid,
                        agent_z:      z.clone(),
                        agent_s:      s.clone(),
                        hit_time:     now,
                        source:       "agent-z+agent-s".to_string(),
                    });
                }

                // Fire from Agent-Z alone immediately
                if let Some(z) = &session.agent_z {
                    return Some(CorrelationHit {
                        community_id: cid,
                        agent_z:      z.clone(),
                        agent_s:      z.clone(),
                        hit_time:     now,
                        source:       "agent-z".to_string(),
                    });
                }
            }

            EventSource::Suricata => {
                session.agent_s = Some(event);

                // Best — both sources present
                if let (Some(z), Some(s)) = (
                    &session.agent_z,
                    &session.agent_s
                ) {
                    return Some(CorrelationHit {
                        community_id: cid,
                        agent_z:      z.clone(),
                        agent_s:      s.clone(),
                        hit_time:     now,
                        source:       "agent-z+agent-s".to_string(),
                    });
                }

                // Fire from Agent-S alone immediately
                if let Some(s) = &session.agent_s {
                    return Some(CorrelationHit {
                        community_id: cid,
                        agent_z:      s.clone(),
                        agent_s:      s.clone(),
                        hit_time:     now,
                        source:       "agent-s".to_string(),
                    });
                }
            }

            // Non-network sources are handled at ingest time and never reach the correlator.
            EventSource::Linux
            | EventSource::WindowsEvent
            | EventSource::Syslog
            | EventSource::CloudTrailAws
            | EventSource::AzureAd
            | EventSource::Okta
            | EventSource::Unknown => {}
        }

        None
    }

    pub fn sweep_expired(&self) {
        let now = now_secs();
        self.sessions.retain(|_, s| !s.is_expired(now));
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}