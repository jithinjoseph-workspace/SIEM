//! The Rust side of the monitord oracle (tests/oracle: `harness.c`): the same
//! commands on stdin, run in a Wazuh home (the cwd). Logs go to
//! `$MON_RLOG/logs/ossec.log`.

use std::io::BufRead;
use std::sync::Arc;

use siem_config::LogLevel;
use siem_log::WLog;
use siem_monitord::config::{monitord_config, MonitorConfig};
use siem_monitord::monitord::Monitor;

fn main() {
    let log = Arc::new(WLog::new_server("wazuh-monitord", std::path::Path::new(&std::env::var("MON_RLOG").expect("MON_RLOG"))));
    log.now_debug();
    log.now_debug();
    log.now_daemon();
    siem_ipc::os_net::set_logger(log.clone());
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let mut m = Monitor::new(MonitorConfig::default(), log.clone(), rt.handle().clone());
    let out = |s: &str| println!("{s}");
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let (cmd, arg) = line.split_once(' ').unwrap_or((&line, ""));
        let n: Vec<i64> = arg.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        match cmd {
            "config" => {
                let a: Vec<&str> = arg.split_whitespace().collect();
                let (r, msgs) = monitord_config(std::path::Path::new(""), a[0], a.get(1) == Some(&"1"), a.get(2).and_then(|x| x.parse().ok()).unwrap_or(-1));
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
                    Ok(c) => m.mond = c,
                    Err(c) => siem_monitord::fatal(&log, &c),
                }
                out("config ok");
            }
            "moncom" => out(&siem_monitord::moncom::dispatch(&log, &m.mond, arg.as_bytes())),
            "queue" => {
                m.queue_connect();
                out(if m.queue.is_some() { "queue up" } else { "queue down" });
            }
            "disconnect" => {
                m.agents_disconnection();
                out("disconnect done");
            }
            "alert" => {
                m.agents_alert();
                out("alert done");
            }
            "delete" => {
                m.agents_deletion();
                out("delete done");
            }
            "rotate" => {
                siem_monitord::rotate_log::w_rotate_log(&log, n[2] != 0, n[3] as i32, n[0] != 0, n[1] != 0, n[4] as i32);
                out("rotate done");
            }
            "manage" => {
                siem_monitord::manage_files::manage_files(&log, true, n[0] as u32, n[1] as usize, n[2] as i32);
                out("manage done");
            }
            "logs" => {
                m.mond.day_wait = 0;
                m.monitor_logs(n[0] != 0);
                out("logs done");
            }
            "set" => {
                let c = &mut m.mond;
                c.rotate_log = n[0] as u32;
                c.size_rotate = n[1] as u64;
                c.compress = n[2] as u32;
                c.keep_log_days = n[3] as i32;
                c.daily_rotations = n[4] as i32;
                c.monitor_agents = n[5] as u32;
                c.delete_old_agents = n[6] as u32;
                c.global.agents_disconnection_time = n[7];
                c.global.agents_disconnection_alert_time = n[8];
                out("set ok");
            }
            "pending" => out(&format!("pending {}", m.to_alert.len())),
            "" => {}
            _ => out(&format!("unknown {cmd}")),
        }
    }
}
