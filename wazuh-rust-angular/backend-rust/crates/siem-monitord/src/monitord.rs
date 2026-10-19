//! `monitord/monitord.c`: the main loop, its time control and the
//! `getconfig` JSON.

use std::sync::Arc;

use chrono::{DateTime, Datelike, Local};
use siem_cjson::Json;
use siem_ipc::mq::queues::LOCALFILE_MQ;
use siem_log::WLog;

use crate::config::MonitorConfig;
use crate::mq::{self, Queue};
use crate::wdb::Wdb;
use crate::{fatal, ARGV0, DEFAULTQUEUE, QUEUE_SEND};

/// `OS_MG_STARTED`
const OS_MG_STARTED: &str = "ossec: Manager started.";

/// `monitor_time_control`
pub struct TimeControl {
    pub disconnect_counter: i64,
    pub alert_counter: i64,
    pub delete_counter: i64,
    pub current_time: DateTime<Local>,
    pub today: u32,
    pub thismonth: usize,
    pub thisyear: i32,
}

impl TimeControl {
    /// `monitor_init_time_control`
    pub fn new(now: DateTime<Local>) -> Self {
        Self { disconnect_counter: 0, alert_counter: 0, delete_counter: 0, current_time: now, today: now.day(), thismonth: now.month0() as usize, thisyear: now.year() }
    }

    /// `monitor_step_time`
    pub fn step(&mut self, now: DateTime<Local>, m: &MonitorConfig) {
        self.current_time = now;
        self.disconnect_counter += 1;
        if m.monitor_agents != 0 {
            self.alert_counter += 1;
        }
        if m.delete_old_agents != 0 && m.monitor_agents != 0 {
            self.delete_counter += 1;
        }
    }

    /// `monitor_update_date`
    pub fn update_date(&mut self) {
        self.today = self.current_time.day();
        self.thismonth = self.current_time.month0() as usize;
        self.thisyear = self.current_time.year();
    }

    /// `check_disconnection_trigger`
    pub fn disconnection_trigger(&mut self, m: &MonitorConfig) -> bool {
        if self.disconnect_counter >= m.global.agents_disconnection_time {
            self.disconnect_counter = 0;
            return true;
        }
        false
    }

    /// `check_alert_trigger`
    pub fn alert_trigger(&mut self, m: &MonitorConfig) -> bool {
        if m.monitor_agents != 0 && self.alert_counter >= m.global.agents_disconnection_alert_time {
            self.alert_counter = 0;
            return true;
        }
        false
    }

    /// `check_deletion_trigger`
    pub fn deletion_trigger(&mut self, m: &MonitorConfig) -> bool {
        if m.monitor_agents != 0 && m.delete_old_agents != 0 && self.delete_counter >= m.delete_old_agents as i64 * 60 {
            self.delete_counter = 0;
            return true;
        }
        false
    }

    /// `check_logs_time_trigger`
    pub fn logs_time_trigger(&self) -> bool {
        self.today != self.current_time.day()
    }
}

/// The daemon state (`mond`, `agents_to_alert_hash`, the wazuh-db socket).
pub struct Monitor {
    pub mond: MonitorConfig,
    pub log: Arc<WLog>,
    pub rt: tokio::runtime::Handle,
    pub wdb: Wdb,
    pub queue: Option<Queue>,
    /// `agents_to_alert_hash`: agent id -> time it was marked disconnected.
    pub to_alert: Vec<(String, i64)>,
}

impl Monitor {
    pub fn new(mond: MonitorConfig, log: Arc<WLog>, rt: tokio::runtime::Handle) -> Self {
        let wdb = Wdb::new(rt.clone());
        Self { mond, log, rt, wdb, queue: None, to_alert: Vec::new() }
    }

    /// `monitor_queue_connect`
    pub fn queue_connect(&mut self) {
        self.queue = Queue::start();
        if self.queue.is_some() && mq::send(&self.queue, OS_MG_STARTED.as_bytes(), ARGV0, LOCALFILE_MQ) < 0 {
            // We keep trying to reconnect next time.
            self.queue = None;
            self.log.debug1(QUEUE_SEND);
        }
    }

    /// `Monitord`
    pub fn run(mut self) -> ! {
        // Wait a few seconds to settle
        std::thread::sleep(std::time::Duration::from_secs(10));

        self.queue_connect();
        if self.queue.is_none() {
            fatal(&self.log, &format!("(1211): Unable to access queue: '{DEFAULTQUEUE}'. Giving up."));
        }
        crate::moncom::start(&self.rt, Arc::new(self.mond.clone()), self.log.clone());

        let mut tc = TimeControl::new(Local::now());
        loop {
            tc.step(Local::now(), &self.mond);

            if self.queue.is_none() {
                self.queue_connect();
            }
            if tc.disconnection_trigger(&self.mond) {
                self.agents_disconnection();
            }
            if tc.alert_trigger(&self.mond) {
                self.agents_alert();
            }
            if tc.deletion_trigger(&self.mond) {
                self.agents_deletion();
            }

            if tc.logs_time_trigger() {
                self.monitor_logs(false);
                self.generate_reports(tc.today, tc.thismonth, tc.thisyear, tc.current_time);
                crate::manage_files::manage_files(&self.log, self.mond.compress != 0, tc.today, tc.thismonth, tc.thisyear);
                tc.update_date();
            } else {
                self.monitor_logs(true);
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    /// `generate_reports`: one worker per report with recipients (C forks
    /// children), 20 s apart, then waits for them like C.
    pub fn generate_reports(&self, cday: u32, cmon: usize, cyear: i32, p: DateTime<Local>) {
        let Some(smtp) = self.mond.smtpserver.clone() else { return };
        let mut children = Vec::new();
        for r in self.mond.reports.iter().filter(|r| !r.emailto.is_empty()) {
            let (r, smtp, from, ids, log) = (r.clone(), smtp.clone(), self.mond.emailfrom.clone().unwrap_or_default(), self.mond.emailidsname.clone(), self.log.clone());
            children.push(std::thread::spawn(move || run_report(&log, &r, &smtp, &from, ids.as_deref(), cday, cmon, cyear, &p)));
            // Sleep between each report. Time is not important in here.
            std::thread::sleep(std::time::Duration::from_secs(20));
        }
        self.log.debug1(format!("Waiting for {} child processes to finish", children.len()));
        let mut twait = 0;
        while !children.is_empty() {
            if let Some(i) = children.iter().position(|h| h.is_finished()) {
                let _ = children.remove(i).join();
                self.log.debug1(format!("Child process {} finished", std::process::id()));
                continue;
            }
            // If there is still any report left, sleep 5 and try again
            std::thread::sleep(std::time::Duration::from_secs(5));
            twait += 1;
            if twait > 2 {
                self.log.warn("Report taking too long to complete. Waiting for it to finish...");
                std::thread::sleep(std::time::Duration::from_secs(10));
                if twait > 10 {
                    self.log.warn("Report took too long. Moving on...");
                    break;
                }
            }
        }
    }
}

/// The child of `generate_reports`: the day's alerts file and its rotations.
#[allow(clippy::too_many_arguments)]
fn run_report(log: &WLog, r: &crate::config::ReportConfig, smtp: &str, from: &str, ids: Option<&str>, cday: u32, cmon: usize, cyear: i32, p: &DateTime<Local>) {
    let title = r.title.clone().unwrap_or_default();
    log.info(format!("Starting daily reporting for '{title}'"));
    log.debug1(format!("Generating report from PID {}", std::process::id()));
    let base = format!("logs/alerts/{cyear}/{}/ossec-alerts-{cday:02}", crate::MONTHS[cmon]);
    let mut aname = format!("{base}.log");
    let mut i = 1;
    while crate::is_file(&aname) {
        let text = match siem_maild::cfile::CFile::open(&aname) {
            Ok(fp) => siem_maild::report::os_reportd_start(&r.r_filter, fp),
            Err(_) => {
                log.error("Unable to open alerts file to generate report.");
                Vec::new()
            }
        };
        if text.len() < 10 {
            log.debug1(format!("Report '{title}' empty for '{aname}'."));
        } else if siem_maild::smtp::os_send_custom_email(&r.emailto, &title, smtp, from, ids, &text, p) != 0 {
            log.warn(format!("Unable to send report email for '{title}'."));
        } else {
            log.debug1(format!("Report '{title}' for '{aname}' sent."));
        }
        aname = format!("{base}-{i:03}.log");
        i += 1;
    }
}

fn num(o: &mut Json, k: &str, v: f64) {
    o.add(k, Json::number(v));
}

/// `getMonitorInternalOptions`
pub fn internal_options(m: &MonitorConfig) -> Json {
    let mut c = Json::object();
    num(&mut c, "day_wait", m.day_wait as f64);
    num(&mut c, "compress", m.compress as f64);
    num(&mut c, "sign", m.sign as f64);
    num(&mut c, "monitor_agents", m.monitor_agents as f64);
    num(&mut c, "keep_log_days", m.keep_log_days as f64);
    num(&mut c, "rotate_log", m.rotate_log as f64);
    num(&mut c, "size_rotate", m.size_rotate as f64);
    num(&mut c, "daily_rotations", m.daily_rotations as f64);
    num(&mut c, "delete_old_agents", m.delete_old_agents as f64);
    let mut root = Json::object();
    root.add("monitord", c);
    root
}

/// `getMonitorGlobalOptions`
pub fn global_options(m: &MonitorConfig) -> Json {
    let mut c = Json::object();
    num(&mut c, "agents_disconnection_time", m.global.agents_disconnection_time as f64);
    num(&mut c, "agents_disconnection_alert_time", m.global.agents_disconnection_alert_time as f64);
    let mut root = Json::object();
    root.add("monitord", c);
    root
}

/// `getReportsOptions`
pub fn reports_options(m: &MonitorConfig) -> Json {
    let mut root = Json::object();
    if !m.reports.is_empty() {
        let mut arr = Json::array();
        for r in &m.reports {
            let mut rep = Json::object();
            let f = &r.r_filter;
            for (k, v) in [("title", &r.title), ("group", &f.group), ("rule", &f.rule), ("level", &f.level), ("srcip", &f.srcip), ("user", &f.user)] {
                if let Some(v) = v {
                    rep.add(k, Json::string(v));
                }
            }
            rep.add("showlogs", Json::string(if f.show_alerts != 0 { "yes" } else { "no" }));
            if !r.emailto.is_empty() {
                let mut e = Json::array();
                for t in &r.emailto {
                    e.push(Json::string(t));
                }
                rep.add("email_to", e);
            }
            arr.push(rep);
        }
        root.add("reports", arr);
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers() {
        let mut m = MonitorConfig { monitor_agents: 1, delete_old_agents: 1, ..Default::default() };
        m.global.agents_disconnection_time = 3;
        m.global.agents_disconnection_alert_time = 0;
        let now = Local::now();
        let mut tc = TimeControl::new(now);
        let mut fired = Vec::new();
        for _ in 0..6 {
            tc.step(now, &m);
            fired.push((tc.disconnection_trigger(&m), tc.alert_trigger(&m)));
        }
        assert_eq!(fired.iter().filter(|f| f.0).count(), 2);
        assert!(fired.iter().all(|f| f.1)); // alert time 0: every second
        for _ in 0..60 {
            tc.step(now, &m);
        }
        assert!(tc.deletion_trigger(&m) && !tc.deletion_trigger(&m));
        assert!(!tc.logs_time_trigger());
    }

    #[test]
    fn getconfig_json() {
        let mut m = MonitorConfig { day_wait: 10, compress: 1, size_rotate: 512 * 1024 * 1024, daily_rotations: 12, ..Default::default() };
        m.global.agents_disconnection_time = 900;
        assert_eq!(
            internal_options(&m).to_string_unformatted(),
            r#"{"monitord":{"day_wait":10,"compress":1,"sign":0,"monitor_agents":0,"keep_log_days":0,"rotate_log":0,"size_rotate":536870912,"daily_rotations":12,"delete_old_agents":0}}"#
        );
        assert_eq!(global_options(&m).to_string_unformatted(), r#"{"monitord":{"agents_disconnection_time":900,"agents_disconnection_alert_time":0}}"#);
        assert_eq!(reports_options(&m).to_string_unformatted(), "{}");
    }
}
