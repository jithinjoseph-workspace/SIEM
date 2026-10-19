//! `monitord/compress_log.c`: gzip a log file and remove the original.

use std::io::{Read, Write};

use crate::strerror;
use siem_log::WLog;

/// `OS_MAXSTR`
const OS_MAXSTR: usize = 65536;

/// `OS_CompressLog`
pub fn os_compress_log(log: &WLog, logfile: &str) {
    let gz = format!("{logfile}.gz");
    // Do not warn in here, since the alert file may not exist
    let Ok(mut src) = std::fs::File::open(logfile) else { return };
    let out = match std::fs::File::create(&gz) {
        Ok(f) => f,
        Err(e) => {
            log.error(format!("(1103): Could not open file '{gz}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), strerror(&e)));
            return;
        }
    };
    let mut z = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    let mut buf = vec![0u8; OS_MAXSTR];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Err(e) = z.write_all(&buf[..n]) {
            log.error(format!("Compression error: {e}"));
        }
    }
    drop(src);
    let _ = z.finish();
    if let Err(e) = std::fs::remove_file(logfile) {
        log.error(format!("Unable to delete '{logfile}' due to '{}'", strerror(&e)));
    }
}
