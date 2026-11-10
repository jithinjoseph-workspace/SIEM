//! `monitord/sign_log.c`: MD5/SHA1/SHA256 of a day's log (plus its rotated
//! parts), chained with the previous day's checksum file.

use md5::Digest;

use crate::{file_size, is_file, strerror};
use siem_log::WLog;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `OS_MD5_File` / `OS_SHA1_File` / `OS_SHA256_File` of the old sum file.
fn file_sums(path: &str) -> Option<(String, String, String)> {
    let d = std::fs::read(path).ok()?;
    Some((hex(&md5::Md5::digest(&d)), hex(&sha1::Sha1::digest(&d)), hex(&sha2::Sha256::digest(&d))))
}

/// `OS_SignLog`
pub fn os_sign_log(log: &WLog, logfile: &str, logfile_old: &str, ext: &str) {
    let logfile_r = format!("{logfile}.{ext}");
    let logfilesum = format!("{logfile_r}.sum");
    let logfilesum_old = format!("{logfile_old}.{ext}.sum");

    let none = || ("none".to_string(), "none".to_string(), "none".to_string());
    let old = file_sums(&logfilesum_old).unwrap_or_else(|| {
        log.debug1(format!("Checksum for previous log file is missing: '{logfilesum_old}'. Starting new sequence."));
        none()
    });

    let cur = match std::fs::read(&logfile_r) {
        Ok(first) => {
            let (mut m, mut s, mut s2) = (md5::Md5::new(), sha1::Sha1::new(), sha2::Sha256::new());
            let mut feed = |d: &[u8]| {
                m.update(d);
                s.update(d);
                s2.update(d);
            };
            feed(&first);
            // Include rotated files
            let mut i = 1;
            loop {
                let r = format!("{logfile}-{i:03}.{ext}");
                if !(is_file(&r) && file_size(&r) > 0) {
                    break;
                }
                match std::fs::read(&r) {
                    Ok(d) => feed(&d),
                    Err(e) => {
                        log.error(format!("(1103): Could not open file '{r}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), strerror(&e)));
                        break;
                    }
                }
                i += 1;
            }
            (hex(&m.finalize()), hex(&s.finalize()), hex(&s2.finalize()))
        }
        Err(_) => none(),
    };

    let body = format!(
        "Current checksum:\nMD5  ({logfile}) = {}\nSHA1 ({logfile}) = {}\nSHA256 ({logfile}) = {}\n\n\
         Chained checksum:\nMD5  ({logfilesum_old}) = {}\nSHA1 ({logfilesum_old}) = {}\nSHA256 ({logfilesum_old}) = {}\n\n",
        cur.0, cur.1, cur.2, old.0, old.1, old.2
    );
    if let Err(e) = std::fs::write(&logfilesum, body) {
        log.error(format!("(1103): Could not open file '{logfilesum}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), strerror(&e)));
    }
}
