//! `syscheckd/src/run_check.c` (`start_daemon`) and `fim_initialize` of `syscheck.c`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::cfmt::{cfmt, A};
use super::create_db::{Fim, DIFF_DIR};
use super::fimdb::{self, FimDbError, LogLevel};
use super::{mdebug1, mdebug2, merror, minfo, msgs, mwarn};

/// `os_restart.syscheck` (`os_set_restart_syscheck` / `os_check_restart_syscheck`)
pub static RESTART_SYSCHECK: AtomicBool = AtomicBool::new(false);

/// `loggingFunction`
pub fn logging_function(l: LogLevel, m: &str) {
    match l {
        LogLevel::Error => merror(m),
        LogLevel::ErrorExit => {
            merror(m);
            std::process::exit(1);
        }
        LogLevel::Info => minfo(m),
        LogLevel::Warning => mwarn(m),
        LogLevel::Debug => mdebug1(m),
        LogLevel::DebugVerbose => mdebug2(m),
    }
}

/// `fim_initialize`: false when the module is disabled.
pub fn fim_initialize(fim: &Arc<Fim>) -> bool {
    let c = fim.sk.cfg.read_recursive();
    let f2 = fim.clone();
    let sync_cb: Arc<dyn Fn(&str, &[u8]) + Send + Sync> = Arc::new(move |loc: &str, msg: &[u8]| f2.send_sync_state(loc, msg));
    let error_log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|m: &str| merror(m));
    let r = fimdb::fim_db_init(
        c.database_store,
        c.sync_interval,
        c.sync_max_interval,
        c.sync_response_timeout,
        sync_cb,
        Arc::new(logging_function),
        c.file_entry_limit,
        if cfg!(windows) { c.db_entry_registry_limit } else { 0 },
        cfg!(windows) && c.enable_registry_synchronization,
        c.sync_thread_pool,
        c.sync_queue_size,
        if cfg!(windows) { Some(error_log) } else { None },
    );
    drop(c);
    if r != FimDbError::Ok {
        merror("Unable to initialize database. FIM module will be disabled.");
        fim.sk.cfg.write().disabled = 1;
        return false;
    }
    true
}

/// `set_priority_windows_thread`
#[cfg(windows)]
pub(super) fn set_priority_windows_thread(prio: i32) {
    use windows_sys::Win32::System::Threading::*;
    let p = match prio {
        i32::MIN..=-10 => THREAD_PRIORITY_HIGHEST,
        -9..=-5 => THREAD_PRIORITY_ABOVE_NORMAL,
        -4..=0 => THREAD_PRIORITY_NORMAL,
        1..=5 => THREAD_PRIORITY_BELOW_NORMAL,
        6..=10 => THREAD_PRIORITY_LOWEST,
        _ => THREAD_PRIORITY_IDLE,
    };
    mdebug1(cfmt(msgs::FIM_PROCESS_PRIORITY, &[A::I(prio as i64)]));
    // SAFETY: the pseudo handle of this thread.
    unsafe {
        if SetThreadPriority(GetCurrentThread(), p) == 0 {
            merror(format!("Can't set thread priority: {}", windows_sys::Win32::Foundation::GetLastError() as i32));
        }
    }
}

/// `cldir_ex` of a diff directory, logging unless it does not exist.
fn clear_diff_dir(sub: &str) {
    let d = format!("{DIFF_DIR}/{sub}/");
    if let Err(e) = siem_fileop::cldir_ex_ignore(&d, &[]) {
        if e.kind() != std::io::ErrorKind::NotFound {
            let errno = e.raw_os_error().unwrap_or(0);
            merror(format!("Unable to clear directory '{d}': {} ({errno})", siem_ipc::os_net::strerror(errno)));
        }
    }
}

/// `"%02d:%02d:%02d"` of the local time, and the month and week days.
fn local_now() -> (String, i32, i32) {
    use chrono::{Datelike, Timelike};
    let t = chrono::Local::now();
    (format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second()), t.day() as i32, t.weekday().num_days_from_sunday() as i32)
}

/// The scan_time/scan_day check of `start_daemon`.
fn scheduled(scan_time: Option<&str>, scan_day: Option<&[u8]>, hour: &str, wday: i32) -> bool {
    use siem_config::timeday::os_is_on_day;
    match (scan_time, scan_day) {
        (Some(t), Some(d)) => os_is_after_time(hour, t) && os_is_on_day(wday, d),
        (Some(t), None) => os_is_after_time(hour, t),
        (None, Some(d)) => os_is_on_day(wday, d),
        (None, None) => false,
    }
}

/// `start_daemon`: never returns unless the module is disabled.
#[cfg(windows)]
pub fn start_daemon(fim: &Arc<Fim>) {
    let (prio, has_sched) = {
        let c = fim.sk.cfg.read_recursive();
        (c.process_priority, c.scan_time.is_some() || c.scan_day.is_some())
    };
    set_priority_windows_thread(prio);
    // shortcut: rootcheck (w_rootcheck_thread) is not ported yet.
    if has_sched {
        fim.sk.cfg.write().time = 604800;
    }
    clear_diff_dir("file");
    clear_diff_dir("registry");
    clear_diff_dir("local");
    let c = fim.sk.cfg.read_recursive();
    if c.disabled != 0 {
        return;
    }
    minfo(msgs::FIM_DAEMON_STARTED);
    if c.file_limit_enabled {
        mdebug2(cfmt(msgs::FIM_FILE_LIMIT_VALUE, &[A::I(c.file_entry_limit as i64)]));
    } else {
        mdebug2(cfmt(msgs::FIM_LIMIT_UNLIMITED, &[A::S("file")]));
    }
    if c.registry_limit_enabled {
        mdebug2(cfmt(msgs::FIM_REGISTRY_LIMIT_VALUE, &[A::I(c.db_entry_registry_limit as i64)]));
    } else {
        mdebug2(cfmt(msgs::FIM_LIMIT_UNLIMITED, &[A::S("registry")]));
    }
    minfo(cfmt(msgs::FIM_FREQUENCY_TIME, &[A::I(c.time as i64)]));
    let (sync, whodata) = (c.enable_synchronization, c.enable_whodata);
    drop(c);
    fim.fim_scan();
    if sync {
        if let Some(db) = fimdb::instance() {
            db.run_integrity();
        }
    }
    super::realtime::start_realtime_thread(fim);
    if whodata {
        super::whodata::fim_whodata_initialize(fim);
    }
    let mut prev = now();
    let (mut day_scanned, mut curr_day) = (false, 0);
    if has_sched {
        let (hour, mday, wday) = local_now();
        curr_day = mday;
        let c = fim.sk.cfg.read_recursive();
        day_scanned = scheduled(c.scan_time.as_deref(), c.scan_day.as_deref(), &hour, wday);
    }
    loop {
        let curr = now();
        let mut run_now = RESTART_SYSCHECK.swap(false, Ordering::SeqCst);
        let c = fim.sk.cfg.read_recursive();
        if has_sched {
            let (hour, mday, wday) = local_now();
            if curr_day != mday {
                day_scanned = false;
                curr_day = mday;
            }
            if !day_scanned && scheduled(c.scan_time.as_deref(), c.scan_day.as_deref(), &hour, wday) {
                day_scanned = true;
                run_now = true;
            }
        }
        let time = c.time as i64;
        drop(c);
        if curr - prev > time || run_now {
            prev = fim.fim_scan();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `OS_IsAfterTime`
fn os_is_after_time(time_str: &str, ossec_time: &str) -> bool {
    let o = ossec_time.as_bytes();
    if o.first() == Some(&b'!') {
        return false;
    }
    // strncmp(time_str, ossec_time + 1, 5) >= 0 (both NUL-terminated)
    let pad = |b: &[u8]| -> [u8; 5] {
        let mut a = [0u8; 5];
        for (i, &c) in b.iter().take_while(|&&c| c != 0).take(5).enumerate() {
            a[i] = c;
        }
        a
    };
    pad(time_str.as_bytes()) >= pad(o.get(1..).unwrap_or(b""))
}

#[cfg(test)]
mod tests {
    #[test]
    fn after_time() {
        assert!(super::os_is_after_time("10:30:00", "x10:30"));
        assert!(!super::os_is_after_time("10:29:59", "x10:30"));
        assert!(!super::os_is_after_time("23:00:00", "!10:30"));
    }
}
