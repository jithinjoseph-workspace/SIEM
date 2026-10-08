//! Active Response Timeout and Repeated Offender Management (`src/os_execd/execd.c`)
//!
//! Manages active response expiration schedules, deduplication, repeated offender penalties,
//! and graceful cleanup on daemon shutdown.

use std::collections::HashMap;

/// A tracked active response command scheduled for timeout deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutEntry {
    pub time_of_addition: i64,
    pub time_to_block: u32,
    pub command: String,
    pub parameters: String,
    pub rkey: String,
}

/// Manager tracking active timeouts and repeat offender penalties.
#[derive(Debug, Clone, Default)]
pub struct TimeoutManager {
    pub timeout_list: Vec<TimeoutEntry>,
    pub repeated_offenders: HashMap<String, usize>,
    pub repeated_offenders_table: Vec<u32>,
}

impl TimeoutManager {
    pub fn new(repeated_offenders_table: Vec<u32>) -> Self {
        Self {
            timeout_list: Vec::new(),
            repeated_offenders: HashMap::new(),
            repeated_offenders_table,
        }
    }

    /// Calculates the effective timeout for an `rkey` considering repeated offender multipliers.
    pub fn calculate_timeout(&mut self, rkey: &str, base_timeout: u32) -> u32 {
        if self.repeated_offenders_table.is_empty() || base_timeout == 0 {
            return base_timeout;
        }

        if let Some(count) = self.repeated_offenders.get_mut(rkey) {
            let max_idx = self.repeated_offenders_table.len() - 1;
            let idx = (*count).min(max_idx);
            let penalty_minutes = self.repeated_offenders_table[idx];
            let effective_timeout = penalty_minutes * 60;

            if *count < max_idx {
                *count += 1;
            }

            effective_timeout
        } else {
            // First offense
            self.repeated_offenders.insert(rkey.to_string(), 0);
            base_timeout
        }
    }

    /// Adds a command to the timeout list or updates its timeout if already present.
    /// Returns `(added_before, effective_timeout)`.
    pub fn add_or_update(
        &mut self,
        command: String,
        delete_parameters: String,
        rkey: String,
        base_timeout: u32,
        curr_time: i64,
    ) -> (bool, u32) {
        if base_timeout == 0 {
            return (false, 0);
        }

        let effective_timeout = self.calculate_timeout(&rkey, base_timeout);

        // Check if an entry with this rkey already exists
        for entry in &mut self.timeout_list {
            if entry.rkey == rkey {
                // Command already received: update time of addition to now and refresh timeout
                entry.time_of_addition = curr_time;
                entry.time_to_block = effective_timeout;
                return (true, effective_timeout);
            }
        }

        // New entry
        self.timeout_list.push(TimeoutEntry {
            time_of_addition: curr_time,
            time_to_block: effective_timeout,
            command,
            parameters: delete_parameters,
            rkey,
        });

        (false, effective_timeout)
    }

    /// Checks for expired timeout entries, removes them from the list, and returns them for execution.
    pub fn drain_expired(&mut self, curr_time: i64) -> Vec<TimeoutEntry> {
        let mut expired = Vec::new();
        let mut remaining = Vec::new();

        for entry in self.timeout_list.drain(..) {
            if (curr_time - entry.time_of_addition) >= entry.time_to_block as i64 {
                expired.push(entry);
            } else {
                remaining.push(entry);
            }
        }

        self.timeout_list = remaining;
        expired
    }

    /// Drains all pending timeout entries on daemon shutdown (`ExecdShutdown`).
    pub fn drain_all(&mut self) -> Vec<TimeoutEntry> {
        std::mem::take(&mut self.timeout_list)
    }

    /// Returns the number of currently active timeouts.
    pub fn len(&self) -> usize {
        self.timeout_list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.timeout_list.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_add_and_expiration() {
        let mut manager = TimeoutManager::new(vec![]);

        let now = 1000;
        let (added_before, timeout) = manager.add_or_update(
            "firewall-drop".to_string(),
            r#"{"command":"delete"}"#.to_string(),
            "firewall-drop-192.168.1.1".to_string(),
            30,
            now,
        );
        assert!(!added_before);
        assert_eq!(timeout, 30);
        assert_eq!(manager.len(), 1);

        // Before timeout: no expired
        assert!(manager.drain_expired(now + 20).is_empty());
        assert_eq!(manager.len(), 1);

        // After timeout: expired
        let expired = manager.drain_expired(now + 31);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].rkey, "firewall-drop-192.168.1.1");
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_repeated_offenders_penalties() {
        // Multiplier table: 5 mins (300s), 10 mins (600s), 30 mins (1800s)
        let mut manager = TimeoutManager::new(vec![5, 10, 30]);

        let rkey = "host-deny-10.0.0.99".to_string();

        // Offense 1: base timeout
        let (dup, t1) = manager.add_or_update("host-deny".into(), "{}".into(), rkey.clone(), 60, 1000);
        assert!(!dup);
        assert_eq!(t1, 60);

        // Offense 2: repeated offender penalty 1 (5 mins * 60 = 300s)
        let (dup, t2) = manager.add_or_update("host-deny".into(), "{}".into(), rkey.clone(), 60, 1100);
        assert!(dup); // Already in list
        assert_eq!(t2, 300);

        // Drain to simulate expiration
        manager.drain_expired(2000);

        // Offense 3: repeated offender penalty 2 (10 mins * 60 = 600s)
        let (dup, t3) = manager.add_or_update("host-deny".into(), "{}".into(), rkey.clone(), 60, 2001);
        assert!(!dup);
        assert_eq!(t3, 600);
    }

    #[test]
    fn test_drain_all_on_shutdown() {
        let mut manager = TimeoutManager::new(vec![]);
        manager.add_or_update("cmd1".into(), "{}".into(), "k1".into(), 100, 1000);
        manager.add_or_update("cmd2".into(), "{}".into(), "k2".into(), 200, 1000);

        assert_eq!(manager.len(), 2);
        let drained = manager.drain_all();
        assert_eq!(drained.len(), 2);
        assert_eq!(manager.len(), 0);
    }
}
