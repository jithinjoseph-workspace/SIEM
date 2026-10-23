//! Port of `wazuh-agentlessd` (`src/agentlessd`, Wazuh 4.14.7): runs the
//! `agentless/` expect scripts against hosts without an agent and forwards
//! their integrity (`FWD:`), log (`LOG:`) and diff (`STORE:`) output to analysisd.

pub mod config;

use std::io::{Read, Write};

use siem_execd::wfd::{self, Wfd, W_BIND_STDERR, W_BIND_STDOUT};
use siem_ipc::mq::queues::{LOCALFILE_MQ, SYSCHECK_MQ};
use siem_maild::{log, strerror};
use siem_monitord::mq::{self, Queue};

pub use config::{Entry, LESSD_STATE_CONNECTED, LESSD_STATE_DIFF, LESSD_STATE_PERIODIC};
use config::trunc1023;

pub const ARGV0: &str = "wazuh-agentlessd";
pub const AGENTLESSDIR: &str = "agentless";
pub const AGENTLESS_ENTRYDIR: &str = "queue/agentless";
pub const DIFF_DIR: &str = "queue/diff";
const DIFF_NEW_FILE: &str = "new-entry";
const DIFF_LAST_FILE: &str = "last-entry";
const SYSCHECK: &str = "syscheck";
/// `OS_MAXSTR - (OS_LOG_HEADER * 2)`
const BUFFER_SIZE: usize = 65536 - 256 * 2;
/// `sizeof(diff_alert) - 1` (`OS_MAXSTR - OS_LOG_HEADER`)
const DIFF_ALERT_MAX: usize = 65536 - 256;
const STR_MORE_CHANGES: &str = "More changes...";

fn errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// A C string: the bytes up to the first NUL.
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `lessdc`: the analysisd queue and the configured entries.
pub struct Lessd {
    pub queue: Option<Queue>,
    pub entries: Vec<Entry>,
}

impl Lessd {
    /// `SendMSG`, reconnecting once on failure (`QUEUE_FATAL` never happens: StartMQ waits forever).
    fn send(&mut self, msg: &[u8], location: &str, loc: u8) {
        if mq::send(&self.queue, msg, location, loc) < 0 {
            log().debug1("(1224): Error sending message to queue.");
            self.queue = Queue::start();
            mq::send(&self.queue, msg, location, loc);
        }
    }

    /// `send_intcheck_msg` / `send_log_msg`
    fn send_script_msg(&mut self, script: &str, host: &str, msg: &[u8], loc: u8) {
        let location = trunc1023(format!("({script}) {host}->{SYSCHECK}"));
        self.send(msg, &location, loc);
    }

    /// `gen_diff_alert`
    fn gen_diff_alert(&mut self, host: &str, script: &str, alert_diff_time: i64) {
        let path = format!("{DIFF_DIR}/{host}->{script}/diff.{}", alert_diff_time as i32);
        let Ok(mut fp) = std::fs::File::open(&path) else {
            log().error("Unable to generate diff alert.");
            return;
        };
        let mut buf = Vec::with_capacity(BUFFER_SIZE);
        let _ = (&mut fp).take(BUFFER_SIZE as u64).read_to_end(&mut buf);
        match buf.len() {
            0 => {
                log().error("Unable to generate diff alert (fread).");
                return;
            }
            BUFFER_SIZE => {
                let mut n = BUFFER_SIZE - STR_MORE_CHANGES.len();
                while n > 0 && buf[n - 1] != b'\n' {
                    n -= 1;
                }
                buf.truncate(n);
                buf.extend_from_slice(STR_MORE_CHANGES.as_bytes());
            }
            _ => {}
        }
        let mut alert = b"ossec: agentless: Change detected:\n".to_vec();
        alert.extend_from_slice(cstr(&buf));
        alert.truncate(DIFF_ALERT_MAX);
        let location = trunc1023(format!("({script}) {host}->{ARGV0}"));
        self.send(&alert, &location, LOCALFILE_MQ);
        save_agentless_entry(host, script, "diff");
    }

    /// `check_diff_file`
    fn check_diff_file(&mut self, host: &str, script: &str) {
        let dir = format!("{DIFF_DIR}/{host}->{script}");
        let new_location = trunc1023(format!("{dir}/{DIFF_NEW_FILE}"));
        let old_location = trunc1023(format!("{dir}/{DIFF_LAST_FILE}"));
        let rename_err = |a: &str, b: &str, e: std::io::Error| log().error(format!("(1124): Could not rename file '{a}' to '{b}' due to [({})-({})].", errno(&e), strerror(&e)));

        // First run: the new entry becomes the last one
        let Some(md5_old) = siem_fileop::md5_file(&old_location) else {
            if let Err(e) = std::fs::rename(&new_location, &old_location) {
                rename_err(&new_location, &old_location, e);
            }
            return;
        };
        let Some(md5_new) = siem_fileop::md5_file(&new_location) else {
            log().error(format!("Invalid internal state (missing '{new_location}')."));
            return;
        };
        if md5_new == md5_old {
            let _ = std::fs::remove_file(&new_location);
            return;
        }

        // Keep the old state at its timestamp and run diff against the new one
        let date_of_change = siem_fileop::mtime(&old_location).unwrap_or(-1);
        let tmp_location = trunc1023(format!("{dir}/state.{}", date_of_change as i32));
        if let Err(e) = std::fs::rename(&old_location, &tmp_location) {
            return rename_err(&old_location, &tmp_location, e);
        }
        if let Err(e) = std::fs::rename(&new_location, &old_location) {
            return rename_err(&new_location, &old_location, e);
        }
        let date_of_change = siem_fileop::mtime(&old_location).unwrap_or(-1);
        let wl = log();
        let Some(mut w) = wfd::wpopenv(wl, "diff", &["diff", &tmp_location, &old_location], W_BIND_STDOUT) else {
            let e = std::io::Error::last_os_error();
            log().error(format!("Unable to run diff for {host}->{script}: {} ({})", strerror(&e), errno(&e)));
            return;
        };
        let diff_location = trunc1023(format!("{dir}/diff.{}", date_of_change as i32));
        let mut fp = match std::fs::File::create(&diff_location) {
            Ok(f) => f,
            Err(e) => {
                log().error(format!("Unable to open diff file '{diff_location}': {} ({})", strerror(&e), errno(&e)));
                wfd::wpclose(wl, w);
                return;
            }
        };
        let mut out = Vec::new();
        if let Some(r) = w.file_out.as_mut() {
            let _ = r.read_to_end(&mut out);
        }
        if let Err(e) = fp.write_all(&out) {
            log().error(format!("Unable to write diff file '{diff_location}': {} ({})", strerror(&e), errno(&e)));
        }
        drop(fp);
        if wfd::wpclose(wl, w) != 256 {
            log().error(format!("Unable to run diff for {host}->{script}"));
            return;
        }
        self.gen_diff_alert(host, script, date_of_change);
    }

    /// `run_periodic_cmd`
    pub fn run_periodic_cmd(&mut self, idx: usize, test_it: bool) -> i32 {
        let servers = self.entries[idx].server.clone();
        let (type_, state) = (self.entries[idx].type_.clone(), self.entries[idx].state);
        for server in &servers {
            if server.is_empty() {
                continue;
            }
            // Only the first server entry is tested
            if test_it {
                let command = trunc1023(format!("{AGENTLESSDIR}/{type_}"));
                let ret_code = match popen_checked(&[command.as_str(), "test", "test"], 0) {
                    Some(p) => p.close(),
                    None => 0,
                };
                if ret_code != 0 {
                    if ret_code == 32512 {
                        log().error(format!("Expect command not found (or bad arguments) for '{type_}'."));
                    }
                    log().error(format!("Test failed for '{type_}' ({}). Ignoring.", ret_code / 256));
                    self.entries[idx].error_flag = 99;
                    return -1;
                }
                log().info(format!("Test passed for '{type_}'."));
                return 0;
            }

            let host = &server[1..];
            let argv = command_args(&type_, server, &self.entries[idx].options);
            let argv: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            let Some(mut p) = popen_checked(&argv, W_BIND_STDOUT | W_BIND_STDERR) else {
                log().error(format!("Subprocess failed on '{type_}' for '{host}'."));
                self.entries[idx].error_flag += 1;
                continue;
            };
            let mut fp_store: Option<std::fs::File> = None;
            while let Some(line) = p.fgets(2048) {
                let mut buf = cstr(&line);
                if let Some(i) = buf.iter().position(|&c| c == b'\r') {
                    buf = &buf[..i];
                }
                if let Some(i) = buf.iter().position(|&c| c == b'\n') {
                    buf = &buf[..i];
                }
                // `buf + 5` after a 4-byte match: past the end on a bare "FWD:"
                let after5 = buf.get(5..).unwrap_or(b"");
                if let Some(m) = buf.strip_prefix(b"ERROR: ") {
                    log().error(format!("{type_}: {host}: {}", String::from_utf8_lossy(m)));
                    self.entries[idx].error_flag += 1;
                    break;
                } else if let Some(m) = buf.strip_prefix(b"INFO: ") {
                    log().info(format!("{type_}: {host}: {}", String::from_utf8_lossy(m)));
                } else if buf.starts_with(b"FWD:") {
                    self.send_script_msg(&type_, host, after5, SYSCHECK_MQ);
                } else if buf.starts_with(b"LOG:") {
                    self.send_script_msg(&type_, host, after5, LOCALFILE_MQ);
                } else if state & LESSD_STATE_DIFF != 0 && buf.starts_with(b"STORE: ") {
                    fp_store = open_diff_file(host, &type_);
                } else if let Some(f) = fp_store.as_mut() {
                    let _ = f.write_all(buf);
                    let _ = f.write_all(b"\n");
                } else {
                    log().debug1(format!("Buffer: {}", String::from_utf8_lossy(buf)));
                }
            }
            if fp_store.take().is_some() {
                self.check_diff_file(host, &type_);
            } else {
                save_agentless_entry(host, &type_, "syscheck");
            }
            p.close();
        }
        0
    }

    /// `Agentlessd`: the main loop (the queue is connected by the caller).
    pub fn run(&mut self) -> ! {
        let mut test_it = true;
        loop {
            let tm = now();
            for i in 0..self.entries.len() {
                let e = &mut self.entries[i];
                if e.error_flag >= 10 {
                    if e.error_flag != 99 {
                        log().error(format!("Too many failures for '{}'. Ignoring it.", e.type_));
                        e.error_flag = 99;
                    }
                    sleep(i as u64 + 1);
                    continue;
                }
                if e.state & LESSD_STATE_PERIODIC != 0 && e.current_state + (e.frequency as i64) < tm {
                    self.run_periodic_cmd(i, test_it);
                    if !test_it {
                        self.entries[i].current_state = tm;
                    }
                }
                sleep(i as u64 + 1);
            }
            // We only check every minute
            test_it = false;
            sleep(60);
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn sleep(s: u64) {
    std::thread::sleep(std::time::Duration::from_secs(s));
}

/// `save_agentless_entry`: the host list the control tools read.
pub fn save_agentless_entry(host: &str, script: &str, agttype: &str) {
    let path = trunc1023(format!("{AGENTLESS_ENTRYDIR}/({script}) {host}"));
    if let Err(e) = std::fs::write(&path, format!("type: {agttype}\n")) {
        log().error(format!("(1103): Could not open file '{path}' due to [({})-({})].", errno(&e), strerror(&e)));
    }
}

/// `open_diff_file`: `new-entry`, creating its directory if needed.
pub fn open_diff_file(host: &str, script: &str) -> Option<std::fs::File> {
    let path = trunc1023(format!("{DIFF_DIR}/{host}->{script}/{DIFF_NEW_FILE}"));
    if let Ok(f) = std::fs::File::create(&path) {
        return Some(f);
    }
    let dir = trunc1023(format!("{DIFF_DIR}/{host}->{script}"));
    if !std::path::Path::new(&dir).is_dir() {
        #[allow(unused_mut)]
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o770);
        if let Err(e) = b.create(&dir) {
            log().error(format!("(1107): Could not create directory '{dir}' due to [({})-({})].", errno(&e), strerror(&e)));
            return None;
        }
    }
    match std::fs::File::create(&path) {
        Ok(f) => Some(f),
        Err(e) => {
            log().error(format!("(1103): Could not open file '{path}' due to [({})-({})].", errno(&e), strerror(&e)));
            None
        }
    }
}

/// `command_args`: `agentless/<type> [use_sudo|use_su] <host> <arguments...>`.
pub fn command_args(type_: &str, server: &str, options: &str) -> Vec<String> {
    let mut argv = vec![trunc1023(format!("{AGENTLESSDIR}/{type_}"))];
    match server.as_bytes().first() {
        Some(b'o') => argv.push("use_sudo".into()),
        Some(b's') => argv.push("use_su".into()),
        _ => {}
    }
    argv.push(server[1..].to_string());
    argv.extend(options.split(' ').filter(|t| !t.is_empty()).map(String::from));
    argv
}

/// `wpopenv(..., W_CHECK_WRITE)`: the C child refuses a script its user can
/// write and exits 127, so that case reads nothing and closes with 32512.
pub enum Proc {
    Run(Wfd),
    Refused,
}

impl Proc {
    pub fn fgets(&mut self, size: usize) -> Option<Vec<u8>> {
        match self {
            Proc::Run(w) => w.fgets(size),
            Proc::Refused => None,
        }
    }

    pub fn close(self) -> i32 {
        match self {
            Proc::Run(w) => wfd::wpclose(log(), w),
            Proc::Refused => 127 << 8,
        }
    }
}

pub fn popen_checked(argv: &[&str], flags: i32) -> Option<Proc> {
    #[cfg(unix)]
    {
        let c = std::ffi::CString::new(argv[0]).unwrap_or_default();
        // SAFETY: a NUL-terminated path.
        if unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0 {
            log().error(format!("At wpopenv(): file '{}' has write permissions.", argv[0]));
            return Some(Proc::Refused);
        }
    }
    wfd::wpopenv(log(), argv[0], argv, flags).map(Proc::Run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_args_like_c() {
        assert_eq!(command_args("ssh_generic_diff", " root@h", ""), ["agentless/ssh_generic_diff", "root@h"]);
        assert_eq!(command_args("t", "oadmin@h", "ls  -la /etc"), ["agentless/t", "use_sudo", "admin@h", "ls", "-la", "/etc"]);
        assert_eq!(command_args("t", "sadmin@h", "x"), ["agentless/t", "use_su", "admin@h", "x"]);
    }
}
