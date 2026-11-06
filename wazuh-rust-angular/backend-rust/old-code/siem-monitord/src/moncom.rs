//! `monitord/moncom.c`: `getconfig <internal|reports|global>` on
//! `queue/sockets/monitor`.

use std::sync::Arc;

use siem_ipc::framing::{self, FrameError};
use siem_ipc::local::StreamListener;
use siem_log::WLog;

use crate::config::MonitorConfig;
use crate::monitord::{global_options, internal_options, reports_options};
use crate::MON_LOCAL_SOCK;

/// `moncom_dispatch`
pub fn dispatch(log: &WLog, m: &MonitorConfig, command: &[u8]) -> String {
    let command = &command[..command.iter().position(|&c| c == 0).unwrap_or(command.len())];
    let command = String::from_utf8_lossy(command);
    let (cmd, args) = match command.split_once(' ') {
        Some((c, a)) => (c, Some(a)),
        None => (command.as_ref(), None),
    };
    if cmd == "getconfig" {
        let Some(section) = args else {
            log.debug1("MONCOM getconfig needs arguments.");
            return "err MONCOM getconfig needs arguments".into();
        };
        let cfg = match section {
            "internal" => internal_options(m),
            "reports" => reports_options(m),
            "global" => global_options(m),
            _ => {
                log.debug1(format!("At MONCOM getconfig: Could not get '{section}' section"));
                return "err Could not get requested section".into();
            }
        };
        format!("ok {}", cfg.to_string_unformatted())
    } else {
        log.debug1(format!("MONCOM Unrecognized command '{cmd}'."));
        "err Unrecognized command".into()
    }
}

/// `moncom_main`, as a task on `rt`.
pub fn start(rt: &tokio::runtime::Handle, m: Arc<MonitorConfig>, log: Arc<WLog>) {
    siem_maild::log_thread_start(&log);
    rt.spawn(async move {
        log.debug1("Local requests thread ready");
        let l = match StreamListener::bind(MON_LOCAL_SOCK).await {
            Ok(l) => l,
            Err(e) => {
                log.error(format!("Unable to bind to socket '{MON_LOCAL_SOCK}': ({}) {}.", e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
                return;
            }
        };
        loop {
            let mut peer = match l.accept().await {
                Ok(p) => p,
                Err(e) => {
                    log.error(format!("At moncom_main(): accept(): {}", crate::strerror(&e)));
                    continue;
                }
            };
            match framing::recv(&mut peer, siem_ipc::OS_MAXSTR).await {
                Ok(b) if b.is_empty() => log.debug1("Empty message from local client."),
                Ok(b) => {
                    let r = dispatch(&log, &m, &b);
                    let _ = framing::send(&mut peer, r.as_bytes()).await;
                }
                Err(FrameError::Closed) => log.debug1("Empty message from local client."),
                Err(FrameError::TooBig(..)) => log.error("At moncom_main(): OS_RecvSecureTCP(): response size is bigger than expected"),
                Err(FrameError::Io(e)) => log.error(format!("At moncom_main(): OS_RecvSecureTCP(): {}", crate::strerror(&e))),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        let log = WLog::new_server("t", std::path::Path::new("."));
        let m = MonitorConfig::default();
        assert!(dispatch(&log, &m, b"getconfig global\0").starts_with("ok {\"monitord\":{\"agents_disconnection_time\":0"));
        assert_eq!(dispatch(&log, &m, b"getconfig"), "err MONCOM getconfig needs arguments");
        assert_eq!(dispatch(&log, &m, b"getconfig x"), "err Could not get requested section");
        assert_eq!(dispatch(&log, &m, b"foo bar"), "err Unrecognized command");
    }
}
