//! `os_maild/maild.c` (`OS_Run`), `os_maild/mail_list.c` and
//! `os_maild/mailcom.c`.
//!
//! C forks one child per e-mail; here a thread gets a copy of the same state
//! (the alerts to send, the subject, the granular flags) at that moment.

use std::collections::VecDeque;
use std::sync::Arc;
use std::thread::JoinHandle;

use chrono::{Local, Timelike};
use siem_ipc::framing::{self, FrameError};
use siem_ipc::local::StreamListener;
use siem_log::WLog;

use crate::alert::{FileQueue, JQueue, CRALERT_MAIL_SET};
use crate::client::{mail_from_json, mail_from_log, MailMsg, Subject};
use crate::config::{mail_alerts_json, mail_config_json, mail_internal_json, Mail, DONOTGROUP, FULL_FORMAT, MAIL_SOURCE_LOGS};
use crate::smtp::{os_sendmail, os_sendsms, Envelope};
use crate::log;

/// `MAIL_LIST_SIZE`, `MAXCHILDPROCESS`, `NEXTMAIL_TIMEOUT`, `DEFAULT_TIMEOUT`
pub const MAIL_LIST_SIZE: i64 = 96;
const MAXCHILDPROCESS: usize = 6;
pub const NEXTMAIL_TIMEOUT: u32 = 2;
pub const DEFAULT_TIMEOUT: u32 = 18;
/// `MAIL_LOCAL_SOCK`
pub const MAIL_LOCAL_SOCK: &str = "queue/sockets/mail";

/// `mail_list.c`: newest at the front, `OS_PopLastMail` takes the oldest.
/// The C counter skips the first node of an empty list, so it drifts by one
/// per drained batch; kept as is.
#[derive(Default)]
pub struct MailList {
    nodes: VecDeque<MailMsg>,
    used: i64,
    max: i64,
}

impl MailList {
    /// `OS_CreateMailList`
    pub fn new(max: i64) -> Self {
        MailList { nodes: VecDeque::new(), used: 0, max }
    }

    /// `OS_AddMailtoList`
    pub fn add(&mut self, m: MailMsg) {
        if self.nodes.is_empty() {
            self.nodes.push_front(m);
            return;
        }
        self.nodes.push_front(m);
        self.used += 1;
        if self.used > self.max {
            self.nodes.pop_back();
            self.used -= 1;
        }
    }

    /// `OS_PopLastMail`
    pub fn pop(&mut self) -> Option<MailMsg> {
        let m = self.nodes.pop_back()?;
        self.used -= 1;
        Some(m)
    }

    /// `OS_CheckLastMail`
    pub fn has_mail(&self) -> bool {
        !self.nodes.is_empty()
    }

    /// The queued alerts in the order `OS_Sendmail` pops them.
    pub fn snapshot(&self) -> Vec<MailMsg> {
        self.nodes.iter().rev().cloned().collect()
    }
}

/// `OS_Run`
pub fn os_run(mut m: Mail) -> ! {
    let mut tm = Local::now();
    let mut thishour = tm.hour();
    let mut fileq = None;
    let mut jq = JQueue::default();
    if m.source == MAIL_SOURCE_LOGS {
        log().info("Getting alerts in log format.");
        fileq = Some(FileQueue::init(None, CRALERT_MAIL_SET));
    } else {
        log().info("Getting alerts in JSON format.");
        if jq.open(true) < 0 {
            log().error("Could not open JSON alerts file.");
        }
    }
    let mut list = MailList::new(MAIL_LIST_SIZE);
    let mut mail_timeout = DEFAULT_TIMEOUT;
    let mut g = Subject::default();
    let mut s_msg: Option<MailMsg> = None;
    let mut msg_sms: Option<MailMsg> = None;
    let mut mailtosend: i32 = 0;
    let mut children: Vec<JoinHandle<()>> = Vec::new();
    let sleep = |s: u64| std::thread::sleep(std::time::Duration::from_secs(s));

    loop {
        tm = Local::now();

        // SMS messages are sent without delay
        if let Some(sms) = msg_sms.take() {
            let env = Envelope::of(&m);
            let t = tm;
            children.push(std::thread::spawn(move || {
                if os_sendsms(&env, &t, &sms) < 0 {
                    log().error(format!("(1263): Error Sending email to {} (smtp server)", env.smtpserver));
                }
            }));
        }

        if mail_timeout == NEXTMAIL_TIMEOUT && tm.hour() == thishour {
            // Get more messages
        } else if (mailtosend < m.maxperhour && mailtosend != 0) || (tm.hour() != thishour && children.len() < MAXCHILDPROCESS) {
            if list.has_mail() {
                let env = Envelope::of(&m);
                let mails = list.snapshot();
                let subject = g.clone();
                let t = tm;
                children.push(std::thread::spawn(move || {
                    if os_sendmail(&env, &t, &mails, &subject) < 0 {
                        log().error(format!("(1263): Error Sending email to {} (smtp server)", env.smtpserver));
                    }
                }));
                while list.pop().is_some() {}
                g = Subject::default();
                for i in 0..m.gran_to.len().min(m.gran_set.len()) {
                    m.gran_set[i] = if s_msg.is_some() && m.gran_set[i] == DONOTGROUP { FULL_FORMAT } else { 0 };
                }
            }
            // snd_check_hour: if we sent everything
            if tm.hour() != thishour {
                thishour = tm.hour();
                mailtosend = 0;
            }
        }

        // Saved message for the do_not_group option
        if let Some(sm) = s_msg.take() {
            for i in 0..m.gran_to.len().min(m.gran_set.len()) {
                if m.gran_set[i] == DONOTGROUP {
                    m.gran_set[i] = FULL_FORMAT;
                }
            }
            list.add(sm);
            mailtosend += 1;
            continue;
        }

        let got = match fileq.as_mut() {
            Some(fq) => fq.read_filemon(mail_timeout, &sleep).map(|al| mail_from_log(al, &mut m, &mut g)),
            None => match jq.next(&sleep) {
                Some(al) => mail_from_json(al, &mut m, &mut g),
                None => {
                    sleep(1);
                    None
                }
            },
        };
        if let Some((msg, sms)) = got {
            msg_sms = sms;
            if m.priority == DONOTGROUP {
                s_msg = Some(msg);
            } else {
                list.add(msg);
            }
            if m.grouping != 0 {
                if m.priority != 0 {
                    mail_timeout = DEFAULT_TIMEOUT;
                    if m.priority != DONOTGROUP {
                        mailtosend += 1;
                    }
                } else {
                    mail_timeout = NEXTMAIL_TIMEOUT;
                }
            } else {
                mailtosend += 1;
            }
        } else if mail_timeout == NEXTMAIL_TIMEOUT {
            mailtosend += 1;
            mail_timeout = DEFAULT_TIMEOUT;
        }

        // Wait for the children
        children.retain(|h| !h.is_finished());
    }
}

/// `mailcom_dispatch`
pub fn mailcom_dispatch(m: &Mail, command: &[u8]) -> String {
    let command = &command[..command.iter().position(|&c| c == 0).unwrap_or(command.len())];
    let command = String::from_utf8_lossy(command);
    let (cmd, args) = match command.split_once(' ') {
        Some((c, a)) => (c, Some(a)),
        None => (command.as_ref(), None),
    };
    if cmd != "getconfig" {
        log().debug1(format!("MAILCOM Unrecognized command '{cmd}'."));
        return "err Unrecognized command".into();
    }
    let Some(section) = args else {
        log().debug1("MAILCOM getconfig needs arguments.");
        return "err MAILCOM getconfig needs arguments".into();
    };
    let j = match section {
        "global" => mail_config_json(m),
        "alerts" => mail_alerts_json(m),
        "internal" => mail_internal_json(m),
        _ => {
            log().debug1(format!("At MAILCOM getconfig: Could not get '{section}' section"));
            return "err Could not get requested section".into();
        }
    };
    format!("ok {}", j.to_string_unformatted())
}

/// `mailcom_main` on its own runtime thread.
pub fn mailcom_start(m: Arc<Mail>, log: Arc<WLog>) {
    crate::log_thread_start(&log);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        rt.block_on(async move {
            log.debug1("Local requests thread ready");
            let l = match StreamListener::bind(MAIL_LOCAL_SOCK).await {
                Ok(l) => l,
                Err(e) => {
                    log.error(format!("Unable to bind to socket '{MAIL_LOCAL_SOCK}': ({}) {}.", e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
                    return;
                }
            };
            loop {
                let mut peer = match l.accept().await {
                    Ok(p) => p,
                    Err(e) => {
                        log.error(format!("At mailcom_main(): accept(): {}", crate::strerror(&e)));
                        continue;
                    }
                };
                match framing::recv(&mut peer, siem_ipc::OS_MAXSTR).await {
                    Ok(b) if b.is_empty() => log.debug1("Empty message from local client."),
                    Ok(b) => {
                        let r = mailcom_dispatch(&m, &b);
                        let _ = framing::send(&mut peer, r.as_bytes()).await;
                    }
                    Err(FrameError::Closed) => log.debug1("Empty message from local client."),
                    Err(FrameError::TooBig(..)) => log.error("At mailcom_main(): OS_RecvSecureTCP(): response size is bigger than expected"),
                    Err(FrameError::Io(e)) => log.error(format!("At mailcom_main(): OS_RecvSecureTCP(): {}", crate::strerror(&e))),
                }
            }
        });
    });
}


#[cfg(test)]
mod tests {
    use super::*;

    fn mm(s: &str) -> MailMsg {
        MailMsg { subject: s.into(), body: s.into() }
    }

    #[test]
    fn list_order_and_cap() {
        let mut l = MailList::new(2);
        for s in ["a", "b", "c", "d"] {
            l.add(mm(s));
        }
        // the first node is not counted: max + 1 kept, oldest dropped
        assert_eq!(l.snapshot().iter().map(|m| m.subject[0]).collect::<Vec<_>>(), b"bcd");
        while l.pop().is_some() {}
        // the counter is now -1: one more fits next time
        for s in ["a", "b", "c", "d", "e"] {
            l.add(mm(s));
        }
        assert_eq!(l.snapshot().len(), 4);
    }
}
