//! `<rule_test>` (config/logtest-config.c, `Read_Logtest`).

use crate::messages;
use crate::util::{parse_time, strtol};
use crate::{ConfigContext, ConfigError, Result};
use siem_xml::XmlNode;

pub const LOGTEST_THREAD: u16 = 1;
pub const LOGTEST_LIMIT_THREAD: u16 = 128;
pub const LOGTEST_MAX_SESSIONS: u16 = 64;
pub const LOGTEST_LIMIT_MAX_SESSIONS: u16 = 500;
pub const LOGTEST_SESSION_TIMEOUT: i64 = 900;
pub const LOGTEST_LIMIT_SESSION_TIMEOUT: i64 = 31536000;

/// `w_logtest_conf_t` (defaults of `w_logtest_init_parameters`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogtestConfig {
    pub enabled: bool,
    pub threads: u16,
    pub max_sessions: u16,
    pub session_timeout: i64,
}

impl Default for LogtestConfig {
    fn default() -> Self {
        LogtestConfig {
            enabled: true,
            threads: LOGTEST_THREAD,
            max_sessions: LOGTEST_MAX_SESSIONS,
            session_timeout: LOGTEST_SESSION_TIMEOUT,
        }
    }
}

/// `Read_Logtest`. `nproc` is `get_nproc()` for `threads=auto`.
pub fn read_logtest(ctx: &mut ConfigContext, nodes: &[XmlNode], cfg: &mut LogtestConfig, nproc: u16) -> Result<()> {
    for n in nodes {
        let Some(c) = n.content.as_deref() else {
            return Err(ConfigError::new(messages::xml_valuenull(&n.element)));
        };
        let num = |c: &str| -> Option<i64> {
            let (v, end) = strtol(c);
            if v < 0 || v > 65534 || end != c.len() {
                None
            } else {
                Some(v)
            }
        };
        match n.element.as_str() {
            "enabled" => {
                cfg.enabled = match c {
                    "no" => false,
                    "yes" => true,
                    _ => return Err(ConfigError::new(messages::xml_valueerr(&n.element, c))),
                }
            }
            "threads" => {
                if c == "auto" {
                    cfg.threads = nproc;
                    continue;
                }
                let Some(v) = num(c) else {
                    return Err(ConfigError::new(messages::xml_valueerr(&n.element, c)));
                };
                if v > LOGTEST_LIMIT_THREAD as i64 {
                    ctx.warn(format!("(7000): Number of logtest threads too high. Only creates {LOGTEST_LIMIT_THREAD} threads"));
                    cfg.threads = LOGTEST_LIMIT_THREAD;
                } else {
                    cfg.threads = v as u16;
                }
            }
            "max_sessions" => {
                let Some(v) = num(c) else {
                    return Err(ConfigError::new(messages::xml_valueerr(&n.element, c)));
                };
                if v > LOGTEST_LIMIT_MAX_SESSIONS as i64 {
                    ctx.warn(format!(
                        "(7001): Number of maximum users connected in logtest too high. Only allows {LOGTEST_LIMIT_MAX_SESSIONS} users"
                    ));
                    cfg.max_sessions = LOGTEST_LIMIT_MAX_SESSIONS;
                } else {
                    cfg.max_sessions = v as u16;
                }
            }
            "session_timeout" => {
                let v = parse_time(c);
                if v <= 0 {
                    return Err(ConfigError::new(messages::xml_valueerr(&n.element, c)));
                } else if v > LOGTEST_LIMIT_SESSION_TIMEOUT {
                    ctx.warn(format!(
                        "(7002): Number of maximum user timeouts in logtest too high. Only allows {LOGTEST_LIMIT_SESSION_TIMEOUT}s maximum timeouts"
                    ));
                    cfg.session_timeout = LOGTEST_LIMIT_SESSION_TIMEOUT;
                } else {
                    cfg.session_timeout = v;
                }
            }
            e => return Err(ConfigError::new(messages::xml_invelem(e))),
        }
    }
    Ok(())
}
