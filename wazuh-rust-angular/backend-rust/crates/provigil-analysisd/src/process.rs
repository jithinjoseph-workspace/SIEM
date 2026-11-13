//! The rule stage of the service for one decoded event (spec section 2.8): firewall and
//! statistics copies, labels, the first matching rule, ignore times and lists, the alert,
//! active responses and the archive copy. It returns what the writers need.

use std::sync::{Arc, OnceLock};

use crate::engine::Engine;
use crate::event::*;
use crate::rules::*;

#[derive(Debug, Default)]
pub struct Outcome {
    pub alert: Option<Event>,
    pub stats_alert: Option<Event>,
    pub firewall: Option<Event>,
    pub archive: Option<Event>,
    /// Active responses to run (their index) with the event as it was.
    pub ar: Vec<(usize, Event)>,
    pub ignore_line: Option<Bytes>,
    pub firewall_event: bool,
    /// Warnings of the response checks, each after this many responses.
    pub warnings: Vec<(usize, Vec<u8>)>,
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub logfw: bool,
    pub logall: bool,
    /// The level of statistics alerts (0: off).
    pub stats: i32,
}

fn safe_user(u: &[u8]) -> bool {
    static R: OnceLock<regex::bytes::Regex> = OnceLock::new();
    R.get_or_init(|| regex::bytes::Regex::new(r"(?-u)^[a-zA-Z._0-9@?-]*$").expect("pattern")).is_match(text_at(u, 0))
}

fn safe_ip(ip: &[u8]) -> bool {
    static R: OnceLock<regex::bytes::Regex> = OnceLock::new();
    R.get_or_init(|| regex::bytes::Regex::new(r"(?-u)^[a-zA-Z.:_0-9-]*$").expect("pattern")).is_match(text_at(ip, 0))
}

/// A copy for a writer: not part of any event list.
pub fn writer_copy(ev: &Event) -> Event {
    Event { is_a_copy: true, ..ev.clone() }
}

const WEEKDAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/// Events per hour against the learned averages (spec section 2.8, statistics).
#[derive(Debug, Clone)]
pub struct Stats {
    /// learned per hour; [24] counts the days learned
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

impl Default for Stats {
    fn default() -> Stats {
        Stats { rhour: [0; 25], chour: [0; 25], rwhour: [[0; 25]; 7], cwhour: [[0; 25]; 7], cignorehour: 0, fired: 0, daily_errors: 0, maxdiff: 0, mindiff: 0, percent_diff: 20, comment: String::new() }
    }
}

impl Stats {
    /// The count that is "above normal" for an average: the average plus `percent_diff`
    /// percent and one, but at least `mindiff` and at most `maxdiff` more.
    fn limit(&self, n: i32) -> i32 {
        let d = n * self.percent_diff / 100 + 1;
        n + if d < self.mindiff {
            self.mindiff
        } else if d > self.maxdiff {
            self.maxdiff
        } else {
            d
        }
    }

    /// Counts an event; true (with [`Stats::comment`]) when the hour or the week day hour is
    /// above normal, at most once per hour and three times a day.
    pub fn count(&mut self, hour: i32, wday: i32) -> bool {
        let (h, w) = (hour as usize, wday as usize);
        self.chour[h] += 1;
        self.cwhour[w][h] += 1;
        if self.rhour[24] <= 2 {
            return false;
        }
        if self.daily_errors >= 3 || (self.fired == 1 && self.cignorehour == hour) {
            return false;
        }
        if self.cignorehour != hour {
            self.cignorehour = hour;
            self.fired = 0;
        }
        let fire = |s: &mut Stats, text: String| {
            s.comment = text;
            s.comment.truncate(190);
            s.fired = 1;
            s.daily_errors += 1;
            true
        };
        if self.rhour[h] != 0 && self.chour[h] > self.rhour[h] && self.chour[h] > self.limit(self.rhour[h]) {
            let t = format!("The average number of logs between {}:00 and {}:00 is {}. We reached {}.", hour, hour + 1, self.rhour[h], self.chour[h]);
            return fire(self, t);
        }
        if self.rwhour[w][24] <= 2 {
            return false;
        }
        if self.rwhour[w][h] != 0 && self.cwhour[w][h] > self.rwhour[w][h] && self.cwhour[w][h] > self.limit(self.rwhour[w][h]) {
            let t = format!("The average number of logs between {}:00 and {}:00 on {} is {}. We reached {}.", hour, hour + 1, WEEKDAYS[w], self.rwhour[w][h], self.cwhour[w][h]);
            return fire(self, t);
        }
        false
    }

    /// The daily update: the new averages per hour and per week day hour, and the totals
    /// lines. The counts start again.
    pub fn new_day(&mut self) -> (Vec<(usize, i32)>, Vec<(usize, usize, i32)>, Vec<String>) {
        let mut totals: Vec<String> = (0..24).map(|i| format!("Hour totals - {}:{}", i, self.chour[i])).collect();
        totals.push(format!("Total events for day:{}", self.chour[..24].iter().sum::<i32>()));
        let errors = self.daily_errors;
        let learn = |avg: &mut i32, count: i32, days: i32| {
            *avg = if *avg == 0 {
                count + 20
            } else if errors >= 3 {
                (3 * count + days * *avg) / (days + 3) + 25
            } else {
                (count + days * *avg) / (days + 1) + 5
            };
        };
        self.rhour[24] += 1;
        let days = self.rhour[24].min(7);
        let mut hourly = Vec::new();
        for i in 0..=24 {
            if i != 24 {
                if self.chour[i] == 0 {
                    continue;
                }
                learn(&mut self.rhour[i], self.chour[i], days);
            }
            hourly.push((i, self.rhour[i]));
            self.chour[i] = 0;
        }
        let mut weekly = Vec::new();
        for d in 0..7 {
            self.cwhour[d][24] += 1;
            let days = self.cwhour[d][24].min(7);
            for j in 0..=24 {
                if j != 24 {
                    if self.cwhour[d][j] == 0 {
                        continue;
                    }
                    learn(&mut self.rwhour[d][j], self.cwhour[d][j], days);
                }
                weekly.push((d, j, self.rwhour[d][j]));
                self.cwhour[d][j] = 0;
            }
        }
        self.daily_errors = 0;
        (hourly, weekly, totals)
    }
}

/// The statistics alert's rule (id 11, group `stats,`).
pub fn stats_rule(level: i32, email_level: i32, log_level: i32) -> Rule {
    let mut r = Rule { sigid: 11, level, category: SYSLOG, group: Some("stats,".into()), comment: Some("Excessive number of events (above normal).".into()), ..Rule::default() };
    if email_level <= level {
        r.alert_opts |= DO_MAILALERT;
    }
    if log_level <= level {
        r.alert_opts |= DO_LOGALERT;
    }
    r
}

impl Engine {
    /// The rule stage for one decoded event. `stats_rule`: the statistics rule's id when
    /// statistics are on; `hour` / `wday`: the local hour and week day; `labels`: the
    /// agent's labels.
    #[allow(clippy::too_many_arguments)]
    pub fn process(&mut self, mut ev: Event, opts: &Options, stats: &mut Stats, stats_rule: Option<RuleId>, hour: i32, wday: i32, labels: &mut dyn FnMut(&Event) -> Vec<Label>) -> Outcome {
        let mut out = Outcome::default();
        ev.size = ev.log().len();
        if self.decoders.decoders[ev.decoder].accumulate == 1 {
            self.accumulate(&mut ev);
        }
        if self.decoders.decoders[ev.decoder].kind == FIREWALL {
            out.firewall_event = true;
            if opts.logfw {
                if [F_ACTION, F_SRCIP, F_DSTIP, F_SRCPORT, F_DSTPORT, F_PROTOCOL].iter().any(|&f| ev.f[f].is_none()) {
                    return out;
                }
                out.firewall = Some(writer_copy(&ev));
            }
        }
        if let (true, Some(sr)) = (opts.stats != 0, stats_rule) {
            if stats.count(hour, wday) && self.rules.rules[sr].alert_opts & DO_LOGALERT != 0 {
                // the statistics alert carries its text as the log
                let mut s = writer_copy(&ev);
                s.generated_rule = Some(sr);
                s.buf = [stats.comment.as_bytes(), &[0]].concat();
                s.log_start = 0;
                out.stats_alert = Some(s);
            }
        }
        ev.labels = labels(&ev);

        let id = self.new_event_id();
        let tree = std::mem::take(&mut self.rules.tree);
        let mut no_debug = None;
        let mut no_archive = false;
        for node in &tree {
            let kind = self.decoders.decoders[ev.decoder].kind;
            let mut rule = if kind == OSSEC_ALERT {
                match ev.generated_rule {
                    Some(r) => r,
                    None => {
                        no_archive = true;
                        break;
                    }
                }
            } else if self.rules.rules[node.rule].category != kind {
                continue;
            } else {
                match self.match_rule(&mut ev, node, true, &mut no_debug) {
                    Some(r) => r,
                    None => continue,
                }
            };
            if self.rules.rules[rule].level == 0 {
                break;
            }
            let (ignore_time, ignored_at) = (self.rules.rules[rule].ignore_time, self.rules.rules[rule].time_ignored);
            if ignore_time != 0 {
                if ignored_at == 0 {
                    Arc::make_mut(&mut self.rules.rules[rule]).time_ignored = ev.generate_time;
                } else if ev.generate_time - ignored_at < i64::from(ignore_time) {
                    // inside the ignore time: the parent rule alerts instead, if any
                    match ev.prev_rule {
                        Some(p) => {
                            rule = p;
                            if let Some(l) = &mut ev.last_events {
                                l.clear();
                            }
                        }
                        None => break,
                    }
                } else {
                    Arc::make_mut(&mut self.rules.rules[rule]).time_ignored = ev.generate_time;
                }
            }
            ev.generated_rule = Some(rule);
            if self.rules.rules[rule].ckignore != 0 && self.ignored(&ev, rule) {
                ev.generated_rule = None;
                break;
            }
            if self.rules.rules[rule].ignore != 0 {
                out.ignore_line = Some(self.ignore_line(&ev, rule));
            }
            let comment = self.rules.rules[rule].comment.clone().unwrap_or_default();
            ev.comment = Some(ev.expand_comment(comment.as_bytes()));
            if self.rules.rules[rule].alert_opts & DO_LOGALERT != 0 {
                out.alert = Some(writer_copy(&ev));
            }
            for a in self.rules.rules[rule].ar.clone().unwrap_or_default() {
                let mut run = true;
                if let Some(u) = ev.f[F_DSTUSER].as_deref().filter(|u| !safe_user(u)) {
                    out.warnings.push((out.ar.len(), [&b"(1272): Invalid username '"[..], text_at(u, 0), b"'. Possible logging attack."].concat()));
                    run = false;
                }
                if let Some(ip) = ev.f[F_SRCIP].as_deref().filter(|ip| !safe_ip(ip)) {
                    out.warnings.push((out.ar.len(), [&b"(1271): Invalid IP Address '"[..], text_at(ip, 0), b"'. Possible logging attack."].concat()));
                    run = false;
                }
                if run {
                    out.ar.push((a, writer_copy(&ev)));
                }
            }
            self.add_to_rule_lists(&mut ev, id, rule);
            ev.queue_added = true;
            if opts.logall {
                out.archive = Some(writer_copy(&ev));
            }
            ev.last_events = None;
            self.rules.tree = tree;
            self.keep(id, ev);
            return out;
        }
        self.rules.tree = tree;
        if opts.logall && !no_archive {
            out.archive = Some(writer_copy(&ev));
        }
        out
    }
}
