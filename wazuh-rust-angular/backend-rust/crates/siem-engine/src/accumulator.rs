use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::sync::Mutex;

/// Record of an evaluated rule match stored in the sliding window
#[derive(Debug, Clone)]
pub struct MatchedEventRecord {
    pub rule_id: u32,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub user: Option<String>,
    pub groups: Vec<String>,
}

/// Wazuh Stateful Event Accumulator & Correlation Window
/// Direct high-performance Rust port of Wazuh `analysisd/accumulator.c` and `analysisd/eventinfo.c:Search_LastSids()`
pub struct WazuhAccumulator {
    history: Mutex<VecDeque<MatchedEventRecord>>,
    max_history: usize,
}

impl WazuhAccumulator {
    pub fn new(max_history: usize) -> Self {
        Self {
            history: Mutex::new(VecDeque::with_capacity(max_history)),
            max_history,
        }
    }

    /// Record a rule match in the sliding window
    pub fn record_match(
        &self,
        rule_id: u32,
        agent_id: &str,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
        user: Option<&str>,
        groups: &[String],
    ) {
        let mut guard = self.history.lock().unwrap();
        let now = Utc::now();

        // Evict entries older than 10 minutes (600s) to keep memory bounded and O(1)
        while let Some(front) = guard.front() {
            if (now - front.timestamp).num_seconds() > 600 {
                guard.pop_front();
            } else {
                break;
            }
        }

        if guard.len() >= self.max_history {
            guard.pop_front();
        }

        guard.push_back(MatchedEventRecord {
            rule_id,
            timestamp: now,
            agent_id: agent_id.to_string(),
            src_ip: src_ip.map(|s| s.to_string()),
            dst_ip: dst_ip.map(|s| s.to_string()),
            user: user.map(|s| s.to_string()),
            groups: groups.to_vec(),
        });
    }

    /// Search recent matching SIDs within timeframe (mirroring Wazuh Search_LastSids in eventinfo.c)
    pub fn count_matched_sids(
        &self,
        target_sid: u32,
        timeframe_secs: i64,
        same_source_ip: bool,
        current_src_ip: Option<&str>,
        same_user: bool,
        current_user: Option<&str>,
        agent_id: &str,
    ) -> usize {
        let guard = self.history.lock().unwrap();
        let now = Utc::now();
        let mut count = 0;

        for record in guard.iter().rev() {
            // Check timeframe window
            let diff = (now - record.timestamp).num_seconds();
            if diff > timeframe_secs {
                break; // Outside sliding window
            }

            // Must match target rule id
            if record.rule_id != target_sid {
                continue;
            }

            // Same agent check
            if record.agent_id != agent_id {
                continue;
            }

            // Check same_source_ip
            if same_source_ip {
                if record.src_ip.is_none() || current_src_ip.is_none() {
                    continue;
                }
                if record.src_ip.as_deref() != current_src_ip {
                    continue;
                }
            }

            // Check same_user
            if same_user {
                if record.user.is_none() || current_user.is_none() {
                    continue;
                }
                if record.user.as_deref() != current_user {
                    continue;
                }
            }

            count += 1;
        }

        count
    }

    /// Search recent matching groups within timeframe (mirroring Wazuh Search_LastGroups in eventinfo.c)
    pub fn count_matched_groups(
        &self,
        target_group: &str,
        timeframe_secs: i64,
        same_source_ip: bool,
        current_src_ip: Option<&str>,
        same_user: bool,
        current_user: Option<&str>,
        agent_id: &str,
    ) -> usize {
        let guard = self.history.lock().unwrap();
        let now = Utc::now();
        let mut count = 0;

        for record in guard.iter().rev() {
            let diff = (now - record.timestamp).num_seconds();
            if diff > timeframe_secs {
                break;
            }

            if !record.groups.iter().any(|g| g.eq_ignore_ascii_case(target_group)) {
                continue;
            }

            if record.agent_id != agent_id {
                continue;
            }

            if same_source_ip {
                if record.src_ip.is_none() || current_src_ip.is_none() {
                    continue;
                }
                if record.src_ip.as_deref() != current_src_ip {
                    continue;
                }
            }

            if same_user {
                if record.user.is_none() || current_user.is_none() {
                    continue;
                }
                if record.user.as_deref() != current_user {
                    continue;
                }
            }

            count += 1;
        }

        count
    }
}
