//! Wazuh Recurring Scan Scheduler (schedule_scan.c)
//!
//! Evaluates next scan execution times for FIM, Syscollector, Rootcheck, and Vulnerability Scanner
//! supporting intervals, days of week, days of month, time windows, and anti-burst jitter.

use chrono::{Datelike, Local, NaiveTime, TimeZone};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DayOfWeek {
    Sunday = 0,
    Monday = 1,
    Tuesday = 2,
    Wednesday = 3,
    Thursday = 4,
    Friday = 5,
    Saturday = 6,
}

impl DayOfWeek {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sunday" | "sun" => Some(DayOfWeek::Sunday),
            "monday" | "mon" => Some(DayOfWeek::Monday),
            "tuesday" | "tue" => Some(DayOfWeek::Tuesday),
            "wednesday" | "wed" => Some(DayOfWeek::Wednesday),
            "thursday" | "thu" => Some(DayOfWeek::Thursday),
            "friday" | "fri" => Some(DayOfWeek::Friday),
            "saturday" | "sat" => Some(DayOfWeek::Saturday),
            _ => None,
        }
    }
}

/// Scan scheduling configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSchedule {
    pub interval_secs: u64,
    pub day_of_week: Option<DayOfWeek>,
    pub day_of_month: Option<u32>, // 1..=31
    pub time_of_day: Option<String>, // "HH:MM"
    pub max_jitter_secs: u64,
}

impl Default for ScanSchedule {
    fn default() -> Self {
        Self {
            interval_secs: 43200, // 12 hours
            day_of_week: None,
            day_of_month: None,
            time_of_day: None,
            max_jitter_secs: 0,
        }
    }
}

impl ScanSchedule {
    /// Calculate random jitter in seconds [0, max_jitter_secs].
    pub fn generate_jitter(&self) -> u64 {
        if self.max_jitter_secs == 0 {
            0
        } else {
            let mut rng = rand::thread_rng();
            rng.gen_range(0..=self.max_jitter_secs)
        }
    }

    /// Check if a scan is due to execute given the last run timestamp and current timestamp.
    pub fn is_due(&self, last_run: Option<i64>, current_timestamp: i64) -> bool {
        let last_time = match last_run {
            None | Some(0) => return true,
            Some(t) => t,
        };

        if current_timestamp < last_time {
            return false;
        }

        // 1. If time_of_day is configured ("HH:MM")
        if let Some(ref tod) = self.time_of_day {
            if let Ok(target_time) = NaiveTime::parse_from_str(tod, "%H:%M") {
                let current_dt = Local.timestamp_opt(current_timestamp, 0).single();
                let last_dt = Local.timestamp_opt(last_time, 0).single();

                if let (Some(c_dt), Some(l_dt)) = (current_dt, last_dt) {
                    // Check day of week if configured
                    if let Some(dow) = self.day_of_week {
                        let current_dow = c_dt.weekday().num_days_from_sunday();
                        if current_dow != dow as u32 {
                            return false;
                        }
                    }

                    // Check day of month if configured
                    if let Some(dom) = self.day_of_month {
                        if c_dt.day() != dom {
                            return false;
                        }
                    }

                    // Check if target time reached today and not already run today
                    let reached_time = c_dt.time() >= target_time;
                    let already_run_today = l_dt.date_naive() == c_dt.date_naive();

                    return reached_time && !already_run_today;
                }
            }
        }

        // 2. Interval-based check
        let elapsed = (current_timestamp - last_time) as u64;
        elapsed >= self.interval_secs
    }

    /// Compute next scheduled execution timestamp.
    pub fn next_execution_time(&self, last_run: Option<i64>, current_timestamp: i64) -> i64 {
        let base = match last_run {
            Some(t) if t > 0 => t,
            _ => current_timestamp,
        };

        let jitter = self.generate_jitter() as i64;
        base + (self.interval_secs as i64) + jitter
    }
}
