//! Monitord Time Control & Periodic Triggers (`src/monitord/monitord.c`)
//!
//! Manages stepping counters, daily boundary detection, and periodic trigger evaluations.

use chrono::{Datelike, Local};

#[derive(Debug, Clone)]
pub struct MonitorTimeControl {
    pub disconnect_counter: u64,
    pub alert_counter: u64,
    pub delete_counter: u64,
    pub today: u32,
    pub this_month: u32,
    pub this_year: i32,
}

impl MonitorTimeControl {
    pub fn new() -> Self {
        let now = Local::now();
        Self {
            disconnect_counter: 0,
            alert_counter: 0,
            delete_counter: 0,
            today: now.day(),
            this_month: now.month(),
            this_year: now.year(),
        }
    }

    /// Steps counters forward by 1 second.
    pub fn step_time(&mut self, monitor_agents: bool, delete_old_agents: u32) {
        self.disconnect_counter += 1;
        if monitor_agents {
            self.alert_counter += 1;
            if delete_old_agents > 0 {
                self.delete_counter += 1;
            }
        }
    }

    /// Updates internal date to current calendar day.
    pub fn update_date(&mut self) {
        let now = Local::now();
        self.today = now.day();
        self.this_month = now.month();
        self.this_year = now.year();
    }

    /// Checks if agent disconnection check interval has elapsed.
    pub fn check_disconnection_trigger(&mut self, disconnection_time: u64) -> bool {
        if self.disconnect_counter >= disconnection_time {
            self.disconnect_counter = 0;
            true
        } else {
            false
        }
    }

    /// Checks if agent alert interval has elapsed.
    pub fn check_alert_trigger(&mut self, monitor_agents: bool, alert_time: u64) -> bool {
        if monitor_agents && self.alert_counter >= alert_time {
            self.alert_counter = 0;
            true
        } else {
            false
        }
    }

    /// Checks if old agent deletion interval has elapsed (time in minutes converted to seconds).
    pub fn check_deletion_trigger(&mut self, monitor_agents: bool, delete_old_agents_min: u32) -> bool {
        if monitor_agents && delete_old_agents_min > 0 {
            let threshold_secs = (delete_old_agents_min as u64) * 60;
            if self.delete_counter >= threshold_secs {
                self.delete_counter = 0;
                return true;
            }
        }
        false
    }

    /// Checks if the day has changed.
    pub fn check_logs_time_trigger(&self) -> bool {
        let now = Local::now();
        now.day() != self.today
    }
}

impl Default for MonitorTimeControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_control_triggers() {
        let mut tc = MonitorTimeControl::new();

        // Step 10 seconds
        for _ in 0..10 {
            tc.step_time(true, 1);
        }

        assert_eq!(tc.disconnect_counter, 10);
        assert_eq!(tc.alert_counter, 10);
        assert_eq!(tc.delete_counter, 10);

        // Disconnection trigger at 10s
        assert!(tc.check_disconnection_trigger(10));
        assert_eq!(tc.disconnect_counter, 0);

        // Alert trigger at 10s
        assert!(tc.check_alert_trigger(true, 10));
        assert_eq!(tc.alert_counter, 0);

        // Deletion trigger at 1 min (60s) -> should be false
        assert!(!tc.check_deletion_trigger(true, 1));
    }
}
