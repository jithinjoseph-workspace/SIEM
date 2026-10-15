//! `shared/schedule_scan.c` (and the `w_validate_*` helpers it calls): the
//! `<interval>`, `<day>`, `<wday>` and `<time>` options of a module and the
//! wait until its next scan.

use siem_cjson::Json;
use siem_log::WLog;
use siem_xml::XmlNode;

use crate::crt;

/// `WM_DEF_INTERVAL`
pub const WM_DEF_INTERVAL: u32 = 86400;

/// `sched_scan_config`
#[derive(Clone, Debug)]
pub struct SchedScan {
    pub scan_day: i32,
    pub scan_wday: i32,
    pub scan_time: Option<String>,
    pub interval: u32,
    pub month_interval: bool,
    pub time_start: i64,
    pub next_scheduled_scan_time: i64,
    pub daylight: i32,
}

impl Default for SchedScan {
    /// `sched_scan_init`
    fn default() -> Self {
        SchedScan { scan_day: 0, scan_wday: -1, scan_time: None, interval: WM_DEF_INTERVAL, month_interval: false, time_start: 0, next_scheduled_scan_time: 0, daylight: -1 }
    }
}

/// `is_sched_tag`
pub fn is_sched_tag(tag: &str) -> bool {
    matches!(tag, "interval" | "day" | "wday" | "time")
}

/// `XML_VALUEERR`
fn xml_valueerr(el: &str, content: &str) -> String {
    format!("(1235): Invalid value for element '{el}': {content}.")
}

/// `RM_WHITE`
fn rm_white(s: &str) -> &str {
    s.trim_start_matches(' ')
}

/// `w_validate_wday`
pub fn validate_wday(log: &WLog, day: &str) -> i32 {
    const DAYS: [(&str, i32); 14] = [
        ("sunday", 0),
        ("sun", 0),
        ("monday", 1),
        ("mon", 1),
        ("tuesday", 2),
        ("tue", 2),
        ("wednesday", 3),
        ("wed", 3),
        ("thursday", 4),
        ("thu", 4),
        ("friday", 5),
        ("fri", 5),
        ("saturday", 6),
        ("sat", 6),
    ];
    let d = rm_white(day);
    for (name, n) in DAYS {
        if d.len() >= name.len() && d.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes()) {
            return n;
        }
    }
    log.error(format!("(1241): Invalid day format: '{d}'."));
    -1
}

/// `sscanf(s, "%d")`: the value and the rest, None when nothing matches.
fn scan_int(s: &[u8]) -> Option<(i32, &[u8])> {
    let ws = s.iter().take_while(|c| c.is_ascii_whitespace() || **c == 0x0b).count();
    let (v, used, _) = crt::strtol(&s[ws..]);
    (used > 0).then(|| (v as i32, &s[ws + used..]))
}

/// `w_validate_time`: "hh:mm" or None.
pub fn validate_time(log: &WLog, time: &str) -> Option<String> {
    let t = rm_white(time);
    let bad = || {
        log.error(format!("(1240): Invalid time format: '{t}'."));
        None
    };
    if !t.contains(':') {
        return bad();
    }
    // sscanf(time_str, "%d:%d", &hour, &min) with hour = min = -1
    let (mut hour, mut min) = (-1, -1);
    if let Some((h, rest)) = scan_int(t.as_bytes()) {
        hour = h;
        if let Some(rest) = rest.strip_prefix(b":") {
            if let Some((m, _)) = scan_int(rest) {
                min = m;
            }
        }
    } else if t.bytes().all(|c| c.is_ascii_whitespace()) {
        // EOF before the first conversion: sscanf returns -1
        return bad();
    }
    if !(0..24).contains(&hour) || !(0..60).contains(&min) {
        return bad();
    }
    Some(format!("{hour:02}:{min:02}"))
}

/// `w_validate_interval`
fn validate_interval(interval: i32, force: i32) -> i32 {
    match force {
        0 => interval % 86400,
        _ => interval % 604800,
    }
}

impl SchedScan {
    /// `sched_scan_read`: errors are logged here.
    pub fn read(&mut self, log: &WLog, nodes: &[XmlNode], module_name: &str) -> Result<(), ()> {
        for n in nodes {
            let content = n.content.as_deref().unwrap_or("");
            match n.element.as_str() {
                "day" => {
                    if !content.bytes().all(|c| c.is_ascii_digit()) {
                        log.error(xml_valueerr(&n.element, content));
                        return Err(());
                    }
                    self.scan_day = crt::atoi(content.as_bytes());
                    if !(1..=31).contains(&self.scan_day) {
                        log.error(xml_valueerr(&n.element, content));
                        return Err(());
                    }
                }
                "wday" => {
                    self.scan_wday = validate_wday(log, content);
                    if !(0..=6).contains(&self.scan_wday) {
                        log.error(xml_valueerr(&n.element, content));
                        return Err(());
                    }
                }
                "time" => {
                    self.scan_time = validate_time(log, content);
                    if self.scan_time.is_none() {
                        log.error(xml_valueerr(&n.element, content));
                        return Err(());
                    }
                }
                "interval" => {
                    let (v, used) = crt::strtoul0(content.as_bytes());
                    self.interval = v as u32;
                    if self.interval == 0 || self.interval == u32::MAX {
                        log.error(format!("Invalid interval value at module '{module_name}'"));
                        return Err(());
                    }
                    match content.as_bytes().get(used) {
                        Some(b'M') => self.month_interval = true,
                        Some(b'w') => self.interval = self.interval.wrapping_mul(604800),
                        Some(b'd') => self.interval = self.interval.wrapping_mul(86400),
                        Some(b'h') => self.interval = self.interval.wrapping_mul(3600),
                        Some(b'm') => self.interval = self.interval.wrapping_mul(60),
                        Some(b's') | None => {}
                        _ => {
                            log.error(format!("Invalid interval value at module '{module_name}'"));
                            return Err(());
                        }
                    }
                }
                _ => {}
            }
        }
        self.validate_parameters(log)
    }

    /// `_sched_scan_validate_parameters`
    fn validate_parameters(&mut self, log: &WLog) -> Result<(), ()> {
        if self.scan_day != 0 && self.scan_wday >= 0 {
            log.error("Options 'day' and 'wday' are not compatible.");
            return Err(());
        } else if self.scan_day != 0 {
            if !self.month_interval {
                log.warn("Interval must be a multiple of one month. New interval value: 1M");
                self.interval = 1;
                self.month_interval = true;
            }
            if self.scan_time.is_none() {
                self.scan_time = Some("00:00".into());
            }
        } else if self.scan_wday >= 0 {
            if validate_interval(self.interval as i32, 1) != 0 {
                self.interval = 604800;
                log.warn("Interval must be a multiple of one week. New interval value: 1w");
            }
            if self.interval == 0 {
                self.interval = 604800;
            }
            if self.scan_time.is_none() {
                self.scan_time = Some("00:00".into());
            }
        } else if self.scan_time.is_some() {
            if validate_interval(self.interval as i32, 0) != 0 {
                self.interval = WM_DEF_INTERVAL;
                log.warn("Interval must be a multiple of one day. New interval value: 1d");
            }
        } else if self.month_interval {
            log.warn("Interval value is in months. Setting scan day to first day of the month.");
            self.scan_day = 1;
            self.scan_time = Some("00:00".into());
        }
        Ok(())
    }

    /// `sched_scan_get_time_until_next_scan`
    pub fn time_until_next_scan(&mut self, log: &WLog, module_tag: &str, run_on_start: bool) -> i64 {
        let next_time = self.next_time(log, module_tag, run_on_start);
        let mut next_scan_time = crt::now() + next_time;
        self.check_daylight(&mut next_scan_time);
        self.next_scheduled_scan_time = next_scan_time;
        next_time
    }

    /// `_get_next_time`
    fn next_time(&self, log: &WLog, module_tag: &str, run_on_start: bool) -> i64 {
        if run_on_start && self.next_scheduled_scan_time == 0 {
            return 0;
        }
        let first = self.next_scheduled_scan_time == 0;
        if self.scan_day != 0 {
            get_time_to_month_day(self.scan_day, self.scan_time.as_deref().unwrap_or(""), self.interval as i32) as i64
        } else if self.scan_wday >= 0 {
            get_time_to_day(self.scan_wday, self.scan_time.as_deref().unwrap_or(""), self.interval / 604800, first) as i64
        } else if let Some(t) = &self.scan_time {
            get_time_to_hour(t, self.interval / 86400, first) as i64
        } else if self.interval != 0 {
            let last_run_time = crt::now() - self.next_scheduled_scan_time;
            if self.interval as i64 >= last_run_time {
                self.interval as i64 - last_run_time
            } else if first {
                if run_on_start {
                    0
                } else {
                    self.interval as i64
                }
            } else {
                log.tagged(module_tag, "WARNING", "Interval overtaken.");
                0
            }
        } else {
            log.critical(format!("Invalid Scheduling option for module {module_tag}. Exiting."));
            siem_log::cexit::fatal_exit();
        }
    }

    /// `check_daylight(config, next_scan_time, false)`
    fn check_daylight(&mut self, next: &mut i64) {
        let future = crt::localtime(*next).tm_isdst;
        if self.daylight != -1 {
            *next += 3600 * (self.daylight - future) as i64;
        }
        self.daylight = future;
    }

    /// `sched_scan_dump`
    pub fn dump(&self, obj: &mut Json) {
        if self.interval != 0 {
            obj.add("interval", Json::number(self.interval as f64));
        }
        if self.scan_day != 0 {
            obj.add("day", Json::number(self.scan_day as f64));
        }
        const WDAYS: [&str; 7] = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];
        if let Some(d) = usize::try_from(self.scan_wday).ok().and_then(|i| WDAYS.get(i)) {
            obj.add("wday", Json::string(d));
        }
        if let Some(t) = &self.scan_time {
            obj.add("time", Json::string(t));
        }
    }
}

/// `OS_StrBreak(':', hour, 2)` + `atoi` of both parts.
fn hour_min(hour: &str) -> (i32, i32) {
    let p = siem_regex::strings::str_break_bytes(b':', hour.as_bytes(), 2).unwrap_or_default();
    (crt::atoi(p.first().map(|v| v.as_slice()).unwrap_or(b"")), crt::atoi(p.get(1).map(|v| v.as_slice()).unwrap_or(b"")))
}

/// `get_time_to_hour`
pub fn get_time_to_hour(hour: &str, num_days: u32, first_time: bool) -> u64 {
    let curr = crt::now();
    let now = crt::localtime(curr);
    let mut t = now;
    let (h, m) = hour_min(hour);
    t.tm_hour = h;
    t.tm_min = m;
    t.tm_sec = 0;
    let mut tt = t;
    if crt::mktime(&mut tt) - curr <= 0 {
        t.tm_mday += if first_time { 1 } else { num_days as i32 };
    }
    (crt::mktime(&mut t) - curr) as u64
}

/// `get_time_to_day`
pub fn get_time_to_day(wday: i32, hour: &str, num_weeks: u32, first_time: bool) -> u64 {
    let curr = crt::now();
    let mut now = crt::localtime(curr);
    let mut t = now;
    let (h, m) = hour_min(hour);
    t.tm_hour = h;
    t.tm_min = m;
    t.tm_sec = 0;
    let mut tt = t;
    let diff = crt::mktime(&mut tt) - curr;
    if wday == now.tm_wday {
        if diff <= 0 {
            t.tm_mday += if first_time { 7 } else { num_weeks as i32 * 7 };
        }
    } else if wday > now.tm_wday {
        while wday > now.tm_wday {
            t.tm_mday += 1;
            now.tm_wday += 1;
        }
    } else {
        t.tm_mday += 7 - (now.tm_wday - wday);
    }
    (crt::mktime(&mut t) - curr) as u64
}

/// `get_time_to_month_day`
pub fn get_time_to_month_day(month_day: i32, hour: &str, mut num_of_months: i32) -> u64 {
    let curr = crt::now();
    let now = crt::localtime(curr);
    let mut t = now;
    let (h, m) = hour_min(hour);
    t.tm_mday = month_day;
    t.tm_hour = h;
    t.tm_min = m;
    t.tm_sec = 0;
    let mut tt = t;
    let diff = crt::mktime(&mut tt) - curr;
    if now.tm_mday < month_day || (now.tm_mday == month_day && diff > 0) {
        num_of_months = 0;
    }
    if num_of_months >= 12 {
        t.tm_year += num_of_months / 12;
        num_of_months %= 12;
    }
    if t.tm_mon + num_of_months > 11 {
        t.tm_mon = (t.tm_mon + num_of_months) % 12;
        t.tm_year += 1;
    } else {
        t.tm_mon += num_of_months;
    }
    (crt::mktime(&mut t) - curr) as u64
}

/// `w_get_timestamp`
pub fn timestamp(t: i64) -> String {
    let tm = crt::localtime(t);
    format!("{}/{:02}/{:02} {:02}:{:02}:{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// `w_sleep_until`
pub fn sleep_until(abs: i64) {
    while crt::now() < abs {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_and_wday() {
        // only inputs that log nothing: WLog exits without an ossec.conf
        let log = WLog::new("test", std::path::Path::new("."));
        assert_eq!(validate_time(&log, " 1:5x").as_deref(), Some("01:05"));
        assert_eq!(validate_wday(&log, "  Thursdays"), 4);
    }
}
