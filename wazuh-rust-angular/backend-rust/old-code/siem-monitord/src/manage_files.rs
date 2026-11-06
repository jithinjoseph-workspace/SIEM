//! `monitord/manage_files.c`: signs and compresses the previous day's
//! alerts, archives and firewall logs.

use chrono::{Datelike, Duration, Local};

use crate::compress_log::os_compress_log;
use crate::sign_log::os_sign_log;
use crate::{file_size, is_file, MONTHS};
use siem_log::WLog;

/// `EVENTS`, `ALERTS`, `FWLOGS`
const EVENTS: &str = "logs/archives";
const ALERTS: &str = "logs/alerts";
const FWLOGS: &str = "logs/firewall";

/// `manage_files`: `cmon` is 0-based.
pub fn manage_files(log: &WLog, compress: bool, cday: u32, cmon: usize, cyear: i32) {
    // Time from the day before (for log signing)
    let old = Local::now() - Duration::seconds(93500);
    let old = (old.year(), old.month0() as usize, old.day());
    for (dir, tag, ext) in [(EVENTS, "archive", "log"), (EVENTS, "archive", "json"), (ALERTS, "alerts", "log"), (ALERTS, "alerts", "json"), (FWLOGS, "firewall", "log")] {
        manage_log(log, compress, dir, cday, cmon, cyear, old, tag, ext);
    }
}

#[allow(clippy::too_many_arguments)]
fn manage_log(log: &WLog, compress: bool, dir: &str, cday: u32, cmon: usize, cyear: i32, old: (i32, usize, u32), tag: &str, ext: &str) {
    let logfile = format!("{dir}/{cyear}/{}/ossec-{tag}-{cday:02}", MONTHS[cmon]);
    let logfile_old = format!("{dir}/{}/{}/ossec-{tag}-{:02}", old.0, MONTHS[old.1], old.2);
    os_sign_log(log, &logfile, &logfile_old, ext);
    if compress {
        let mut logfile_r = format!("{logfile}.{ext}");
        os_compress_log(log, &logfile_r);
        // C checks the file it just compressed (now removed), so this only
        // runs when that compression failed.
        let mut i = 1;
        while is_file(&logfile_r) && file_size(&logfile_r) > 0 {
            logfile_r = format!("{logfile}-{i:03}.{ext}");
            os_compress_log(log, &logfile_r);
            i += 1;
        }
    }
}
