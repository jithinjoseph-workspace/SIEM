//! The Rust side of the maild oracle (tests/oracle `harness.c`): the same
//! commands on stdin, run in a Wazuh home (the cwd). Logs go to
//! `$MON_RLOG/logs/ossec.log`.

use std::io::BufRead;
use std::sync::Arc;

use chrono::TimeZone;
use siem_config::LogLevel;
use siem_log::WLog;
use siem_maild::alert::{FileQueue, JQueue, CRALERT_MAIL_SET, CRALERT_READ_ALL};
use siem_maild::client::{mail_from_json, mail_from_log, MailMsg, Subject};
use siem_maild::config::{mail_conf, Conf, Mail};
use siem_maild::maild::{mailcom_dispatch, MailList, MAIL_LIST_SIZE};
use siem_maild::report::{os_report_configfilter, os_reportd_start, ReportFilter, REPORT_FILTER, REPORT_RELATED, REPORT_TYPE_DAILY};
use siem_maild::smtp::{os_send_custom_email, os_sendmail, os_sendsms, Envelope};

fn esc(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b {
        match c {
            b'\r' => s.push_str("\\r"),
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            b'\\' => s.push_str("\\\\"),
            0 => break,
            _ => s.push(c as char),
        }
    }
    s
}

fn outb(tag: &str, b: &[u8]) {
    println!("{tag} {}", esc(b));
}

fn show(m: &Mail, g: &Subject, msg: &MailMsg, sms: &Option<MailMsg>) {
    outb("subject", &msg.subject);
    outb("body", &msg.body);
    if let Some(s) = sms {
        outb("sms_subject", &s.subject);
        outb("sms_body", &s.body);
    }
    println!("priority {} g_level {}", m.priority, g.level);
    outb("g_subject", &g.text);
    let sets: String = (0..m.gran_to.len()).map(|i| format!(" {}", m.gran_set.get(i).copied().unwrap_or(0))).collect();
    println!("gran_set{sets}");
}

fn main() {
    let log = Arc::new(WLog::new_server("wazuh-maild", std::path::Path::new(&std::env::var("MON_RLOG").expect("MON_RLOG"))));
    log.now_debug();
    log.now_debug();
    log.now_daemon();
    siem_maild::set_logger(log.clone());
    let mut m = Mail::default();
    let mut g = Subject::default();
    let mut list = MailList::new(MAIL_LIST_SIZE);
    let mut jq: Option<JQueue> = None;
    let mut lq: Option<FileQueue> = None;
    let mut last_sms: Option<MailMsg> = None;
    let t = chrono::Local.timestamp_opt(1_700_000_000, 0).unwrap();
    let nosleep = |s: u64| std::thread::sleep(std::time::Duration::from_secs(s));
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let (cmd, arg) = line.split_once(' ').unwrap_or((&line, ""));
        match cmd {
            "config" => {
                let mut msgs = Vec::new();
                let r = mail_conf(std::path::Path::new(""), arg, false, &mut msgs);
                for (lvl, s) in msgs {
                    match lvl {
                        LogLevel::Debug1 => log.debug1(s),
                        LogLevel::Debug2 => log.debug2(s),
                        LogLevel::Info => log.info(s),
                        LogLevel::Warn => log.warn(s),
                        LogLevel::Error => log.error(s),
                    }
                }
                match r {
                    Conf::Ok(c) => {
                        m = c;
                        let o = siem_config::internal_options::InternalOptions::from_home("");
                        m.strict_checking = o.get_int("maild", "strict_checking", 0, 1).unwrap();
                        m.grouping = o.get_int("maild", "grouping", 0, 1).unwrap();
                        m.subject_full = o.get_int("maild", "full_subject", 0, 1).unwrap();
                        println!("config child exit 2");
                    }
                    Conf::Disabled => println!("config child exit 0"),
                    Conf::Err => println!("config child exit 1"),
                }
            }
            "getconfig" => {
                let c = if arg.is_empty() { "getconfig".to_string() } else { format!("getconfig {arg}") };
                outb("getconfig", mailcom_dispatch(&m, c.as_bytes()).as_bytes())
            }
            "set" => {
                let n: Vec<i32> = arg.split_whitespace().map(|x| x.parse().unwrap()).collect();
                (m.strict_checking, m.grouping, m.subject_full) = (n[0], n[1], n[2]);
            }
            "json" => {
                let q = jq.get_or_insert_with(|| {
                    let mut q = JQueue::default();
                    q.open(false);
                    q
                });
                let got = match q.next(&nosleep) {
                    Some(al) => mail_from_json(al, &mut m, &mut g),
                    None => {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        None
                    }
                };
                match got {
                    Some((msg, sms)) => {
                        show(&m, &g, &msg, &sms);
                        list.add(msg);
                        if sms.is_some() {
                            last_sms = sms;
                        }
                    }
                    None => println!("json none"),
                }
            }
            "log" => {
                let q = lq.get_or_insert_with(|| FileQueue::init(None, CRALERT_MAIL_SET | CRALERT_READ_ALL));
                match q.read_filemon(DEFAULT_TIMEOUT_FOR_HARNESS, &nosleep).map(|al| mail_from_log(al, &mut m, &mut g)) {
                    Some((msg, sms)) => {
                        show(&m, &g, &msg, &sms);
                        list.add(msg);
                        if sms.is_some() {
                            last_sms = sms;
                        }
                    }
                    None => println!("log none"),
                }
            }
            "sendmail" => {
                if !list.has_mail() {
                    println!("sendmail empty");
                    continue;
                }
                let r = os_sendmail(&Envelope::of(&m), &t, &list.snapshot(), &g);
                while list.pop().is_some() {}
                g = Subject::default();
                println!("sendmail {}", (r < 0) as i32);
            }
            "sms" => match &last_sms {
                Some(s) => println!("sms {}", (os_sendsms(&Envelope::of(&m), &t, s) < 0) as i32),
                None => println!("sms none"),
            },
            "custom" => {
                let body = std::fs::read(arg).unwrap();
                let r = os_send_custom_email(&m.to, "Daily report: test", m.smtpserver.as_deref().unwrap_or(""), m.from.as_deref().unwrap_or("(null)"), m.idsname.as_deref(), &body, &t);
                println!("custom {}", (r < 0) as i32);
            }
            "report" => {
                let mut it = arg.split(' ');
                let (file, name) = (it.next().unwrap(), it.next().unwrap());
                let mut f = ReportFilter { report_type: REPORT_TYPE_DAILY, report_name: (name != "-").then(|| name.to_string()), ..Default::default() };
                for tok in it {
                    if tok == "showlogs" {
                        f.show_alerts = 1;
                        continue;
                    }
                    let (k, v) = tok.split_once('=').unwrap();
                    let mut e = |s: String| log.error(s);
                    match k.strip_prefix("rel:") {
                        Some(k) => os_report_configfilter(k, v, &mut f, REPORT_RELATED, &mut e),
                        None => os_report_configfilter(k, v, &mut f, REPORT_FILTER, &mut e),
                    };
                }
                let out = match siem_maild::cfile::CFile::open(file) {
                    Ok(fp) => os_reportd_start(&f, fp),
                    Err(_) => {
                        log.error("Unable to open alerts file to generate report.");
                        Vec::new()
                    }
                };
                outb("report", &out);
            }
            "" => {}
            _ => println!("unknown {cmd}"),
        }
    }
}

/// The C harness reads `alerts.log` with `mail_timeout` = 0 (no waiting).
const DEFAULT_TIMEOUT_FOR_HARNESS: u32 = 0;
