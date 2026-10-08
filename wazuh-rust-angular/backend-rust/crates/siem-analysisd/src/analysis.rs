//! The analysisd rule-matching stage (`w_process_event_thread`, analysisd.c)
//! and the hourly statistics (`stats.c`). The function returns copies of the
//! event for each writer queue instead of pushing them, so the daemon can
//! do the I/O.

use std::sync::OnceLock;

use crate::engine::Engine;
use crate::event::*;
use crate::rules::*;

/// What `w_process_event_thread` hands to the other threads for one event.
#[derive(Debug, Default)]
pub struct Outcome {
    /// `writer_queue_log` (alerts.log / alerts.json)
    pub alert: Option<Event>,
    /// `writer_queue_log_statistical`
    pub stats_alert: Option<Event>,
    /// `writer_queue_log_firewall`
    pub firewall: Option<Event>,
    /// `writer_queue` (archives), when logall / logall_json
    pub archive: Option<Event>,
    /// Active responses to execute (indices in the AR list) with the event
    /// as it was when they ran.
    pub ar: Vec<(usize, Event)>,
    /// Line to append to the ignore list (`AddtoIGnore`).
    pub ignore_line: Option<Bytes>,
    /// The event was a firewall event (`hourly_firewall`).
    pub firewall_event: bool,
    /// `mwarn` messages of the AR sanity checks, each with the number of
    /// entries of `ar` queued before it (they interleave with `OS_Exec`).
    pub warnings: Vec<(usize, Vec<u8>)>,
}

/// Options of the processing stage.
#[derive(Debug, Clone, Default)]
pub struct ProcessOptions {
    /// `Config.logfw`
    pub logfw: bool,
    /// `Config.logall || Config.logall_json`
    pub logall: bool,
    /// `Config.stats` (0 disables the hourly check)
    pub stats: i32,
}

/// The C string view of a field (up to the first NUL).
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `OS_PRegex` with the two AR sanity patterns.
fn crafted_user_ok(u: &[u8]) -> bool {
    static R: OnceLock<regex::bytes::Regex> = OnceLock::new();
    R.get_or_init(|| regex::bytes::Regex::new(r"(?-u)^[a-zA-Z._0-9@?-]*$").unwrap()).is_match(cstr(u))
}

fn crafted_ip_ok(ip: &[u8]) -> bool {
    static R: OnceLock<regex::bytes::Regex> = OnceLock::new();
    R.get_or_init(|| regex::bytes::Regex::new(r"(?-u)^[a-zA-Z.:_0-9-]*$").unwrap()).is_match(cstr(ip))
}

/// `w_copy_event_for_log`: a detached copy (no list membership).
pub fn copy_for_log(ev: &Event) -> Event {
    let mut c = ev.clone();
    c.is_a_copy = true;
    c
}

/// Hourly/weekly event statistics (`stats.c`).
#[derive(Debug, Clone)]
pub struct Stats {
    pub rhour: [i32; 25],
    pub chour: [i32; 25],
    pub rwhour: [[i32; 25]; 7],
    pub cwhour: [[i32; 25]; 7],
    pub cignorehour: i32,
    pub fired: i32,
    pub daily_errors: i32,
    pub maxdiff: i32,
    pub mindiff: i32,
    pub percent_diff: i32,
    pub comment: String,
}

const WEEKDAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

impl Default for Stats {
    fn default() -> Self {
        Stats {
            rhour: [0; 25],
            chour: [0; 25],
            rwhour: [[0; 25]; 7],
            cwhour: [[0; 25]; 7],
            cignorehour: 0,
            fired: 0,
            daily_errors: 0,
            maxdiff: 0,
            mindiff: 0,
            percent_diff: 20,
            comment: String::new(),
        }
    }
}

impl Stats {
    /// `gethour`
    fn gethour(&self, n: i32) -> i32 {
        let d = (n * self.percent_diff) / 100 + 1;
        if d < self.mindiff {
            n + self.mindiff
        } else if d > self.maxdiff {
            n + self.maxdiff
        } else {
            n + d
        }
    }

    /// `Check_Hour`: true when the current rate is above normal (fires the
    /// statistical alert with `comment`).
    pub fn check_hour(&mut self, hour: i32, wday: i32) -> bool {
        let (h, w) = (hour as usize, wday as usize);
        self.chour[h] += 1;
        self.cwhour[w][h] += 1;
        if self.rhour[24] <= 2 {
            return false;
        }
        if self.daily_errors >= 3 || (self.fired == 1 && self.cignorehour == hour) {
            return false;
        } else if self.cignorehour != hour {
            self.cignorehour = hour;
            self.fired = 0;
        }
        if self.rhour[h] != 0 && self.chour[h] > self.rhour[h] && self.chour[h] > self.gethour(self.rhour[h]) {
            self.comment = format!(
                "The average number of logs between {}:00 and {}:00 is {}. We reached {}.",
                hour,
                hour + 1,
                self.rhour[h],
                self.chour[h]
            );
            self.comment.truncate(190);
            self.fired = 1;
            self.daily_errors += 1;
            return true;
        }
        if self.rwhour[w][24] <= 2 {
            return false;
        }
        if self.rwhour[w][h] != 0 && self.cwhour[w][h] > self.rwhour[w][h] && self.cwhour[w][h] > self.gethour(self.rwhour[w][h]) {
            self.comment = format!(
                "The average number of logs between {}:00 and {}:00 on {} is {}. We reached {}.",
                hour,
                hour + 1,
                WEEKDAYS[w],
                self.rwhour[w][h],
                self.cwhour[w][h]
            );
            self.comment.truncate(190);
            self.fired = 1;
            self.daily_errors += 1;
            return true;
        }
        false
    }

    /// `Update_Hour` (daily): returns the averages to persist
    /// (`stats/hourly-average/<h>` and `stats/weekly-average/<d>/<h>`) and
    /// the totals lines for `stats/totals/...`.
    pub fn update_hour(&mut self) -> (Vec<(usize, i32)>, Vec<(usize, usize, i32)>, Vec<String>) {
        let mut totals = Vec::new();
        let mut sum = 0;
        for i in 0..=23 {
            totals.push(format!("Hour totals - {}:{}", i, self.chour[i]));
            sum += self.chour[i];
        }
        totals.push(format!("Total events for day:{sum}"));

        self.rhour[24] += 1;
        let inter = self.rhour[24].min(7);
        let mut hourly = Vec::new();
        for i in 0..=24 {
            if i != 24 {
                if self.chour[i] == 0 {
                    continue;
                }
                if self.rhour[i] == 0 {
                    self.rhour[i] = self.chour[i] + 20;
                } else if self.daily_errors >= 3 {
                    self.rhour[i] = ((3 * self.chour[i]) + (inter * self.rhour[i])) / (inter + 3) + 25;
                } else {
                    self.rhour[i] = (self.chour[i] + (inter * self.rhour[i])) / (inter + 1) + 5;
                }
            }
            hourly.push((i, self.rhour[i]));
            self.chour[i] = 0;
        }
        let mut weekly = Vec::new();
        for i in 0..=6 {
            self.cwhour[i][24] += 1;
            let inter = self.cwhour[i][24].min(7);
            for j in 0..=24 {
                if j != 24 {
                    if self.cwhour[i][j] == 0 {
                        continue;
                    }
                    if self.rwhour[i][j] == 0 {
                        self.rwhour[i][j] = self.cwhour[i][j] + 20;
                    } else if self.daily_errors >= 3 {
                        self.rwhour[i][j] = ((3 * self.cwhour[i][j]) + (inter * self.rwhour[i][j])) / (inter + 3) + 25;
                    } else {
                        self.rwhour[i][j] = (self.cwhour[i][j] + (inter * self.rwhour[i][j])) / (inter + 1) + 5;
                    }
                }
                weekly.push((i, j, self.rwhour[i][j]));
                self.cwhour[i][j] = 0;
            }
        }
        self.daily_errors = 0;
        (hourly, weekly, totals)
    }
}

/// `zerorulemember(STATS_MODULE, Config.stats, ...)` with group "stats," and
/// the statistical comment.
pub fn stats_rule(level: i32, mailbylevel: i32, logbylevel: i32) -> RuleInfo {
    let mut r = RuleInfo {
        sigid: 11,
        level,
        category: SYSLOG,
        group: Some("stats,".into()),
        comment: Some("Excessive number of events (above normal).".into()),
        ..Default::default()
    };
    if mailbylevel <= level {
        r.alert_opts |= DO_MAILALERT;
    }
    if logbylevel <= level {
        r.alert_opts |= DO_LOGALERT;
    }
    r
}

impl Engine {
    /// `w_process_event_thread` for one decoded event. `stats_rule` is the
    /// id of the statistics pseudo-rule (when stats are enabled), `hour` /
    /// `wday` the current local hour and weekday.
    pub fn process_event(
        &mut self,
        mut ev: Event,
        opts: &ProcessOptions,
        stats: &mut Stats,
        stats_rule: Option<RuleId>,
        hour: i32,
        wday: i32,
        labels: &mut dyn FnMut(&Event) -> Vec<crate::labels::Label>,
    ) -> Outcome {
        let mut out = Outcome::default();
        ev.size = ev.log().len();

        if self.decoders.infos[ev.decoder].accumulate == 1 {
            self.accumulate(&mut ev);
        }

        if self.decoders.infos[ev.decoder].type_ == FIREWALL {
            out.firewall_event = true;
            if opts.logfw {
                let need = [F_ACTION, F_SRCIP, F_DSTIP, F_SRCPORT, F_DSTPORT, F_PROTOCOL];
                if need.iter().any(|&i| ev.f[i].is_none()) {
                    return out;
                }
                out.firewall = Some(copy_for_log(&ev));
            }
        }

        if opts.stats != 0 {
            if let Some(sr) = stats_rule {
                if stats.check_hour(hour, wday) {
                    let saved_rule = ev.generated_rule;
                    let saved_buf = std::mem::take(&mut ev.buf);
                    let saved_log = ev.log;
                    ev.generated_rule = Some(sr);
                    let mut b = stats.comment.as_bytes().to_vec();
                    b.push(0);
                    ev.buf = b;
                    ev.log = 0;
                    if self.rules.infos[sr].alert_opts & DO_LOGALERT != 0 {
                        out.stats_alert = Some(copy_for_log(&ev));
                    }
                    ev.generated_rule = saved_rule;
                    ev.buf = saved_buf;
                    ev.log = saved_log;
                }
            }
        }

        // Insert labels (labels_find) and w_inc_processed_events
        ev.labels = labels(&ev);

        let eid = self.alloc_event_id();
        let tree = std::mem::take(&mut self.rules.tree);
        let mut skip_archive = false;
        let mut no_debug: Option<&mut Vec<String>> = None;
        for node in &tree {
            let t_rule: RuleId;
            if self.decoders.infos[ev.decoder].type_ == OSSEC_ALERT {
                match ev.generated_rule {
                    None => {
                        skip_archive = true;
                        break;
                    }
                    Some(r) => t_rule = r,
                }
            } else if self.rules.infos[node.rule].category != self.decoders.infos[ev.decoder].type_ {
                continue;
            } else {
                match self.check_if_rule_match(&mut ev, node, true, &mut no_debug) {
                    Some(r) => t_rule = r,
                    None => continue,
                }
            }
            let mut t_rule = t_rule;

            if self.rules.infos[t_rule].level == 0 {
                break;
            }

            let ignore_time = self.rules.infos[t_rule].ignore_time;
            if ignore_time != 0 {
                let ti = self.rules.infos[t_rule].time_ignored;
                if ti == 0 {
                    self.rules.infos[t_rule].time_ignored = ev.generate_time;
                } else if ev.generate_time - ti < ignore_time as i64 {
                    match ev.prev_rule {
                        Some(p) => {
                            t_rule = p;
                            if let Some(le) = &mut ev.last_events {
                                le.clear();
                            }
                        }
                        None => break,
                    }
                } else {
                    self.rules.infos[t_rule].time_ignored = ev.generate_time;
                }
            }

            ev.generated_rule = Some(t_rule);

            if self.rules.infos[t_rule].ckignore != 0 && self.ignore_check(&ev, t_rule) {
                ev.generated_rule = None;
                break;
            }
            if self.rules.infos[t_rule].ignore != 0 {
                out.ignore_line = Some(self.ignore_line(&ev, t_rule));
            }

            let c = self.rules.infos[t_rule].comment.clone().unwrap_or_default();
            ev.comment = Some(ev.parse_rule_comment(c.as_bytes()));

            if self.rules.infos[t_rule].alert_opts & DO_LOGALERT != 0 {
                out.alert = Some(copy_for_log(&ev));
            }

            if let Some(ars) = self.rules.infos[t_rule].ar.clone() {
                for a in ars {
                    let mut do_ar = true;
                    if let Some(u) = &ev.f[F_DSTUSER] {
                        if !crafted_user_ok(u) {
                            out.warnings.push((out.ar.len(), [&b"(1272): Invalid username '"[..], cstr(u), b"'. Possible logging attack."].concat()));
                            do_ar = false;
                        }
                    }
                    if let Some(ip) = &ev.f[F_SRCIP] {
                        if !crafted_ip_ok(ip) {
                            out.warnings.push((out.ar.len(), [&b"(1271): Invalid IP Address '"[..], cstr(ip), b"'. Possible logging attack."].concat()));
                            do_ar = false;
                        }
                    }
                    if do_ar {
                        out.ar.push((a, copy_for_log(&ev)));
                    }
                }
            }

            self.add_to_rule_lists(&mut ev, eid, t_rule);
            ev.queue_added = true;
            out.archive = Some(copy_for_log(&ev));
            // w_free_event_info: the stored event drops its last_events
            ev.last_events = None;
            self.rules.tree = tree;
            self.add_event(eid, ev);
            if !opts.logall {
                out.archive = None;
            }
            return out;
        }
        self.rules.tree = tree;
        if skip_archive {
            return out;
        }
        if opts.logall {
            out.archive = Some(copy_for_log(&ev));
        }
        out
    }
}
