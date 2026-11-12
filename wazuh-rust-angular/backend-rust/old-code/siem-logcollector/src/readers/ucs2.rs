//! `read_ucs2_le` / `read_ucs2_be` (Windows): UTF-16 log files.
//!
//! The C readers keep their quirks and so do these:
//! * LE reads 16-bit units with msvcrt `fgetws`; the hash, the samples in the
//!   debug messages and `OS_SHA1_Stream` see the buffer as a `char *`, so they
//!   stop at the first zero byte (the high byte of an ASCII character).
//! * BE reads bytes with `fgets` (a line ends at the 0x0A byte), checks
//!   `str[1]` for comments, does not strip the CR (its `strrchr` sees an empty
//!   C string), and swaps every byte pair of the whole buffer before the
//!   UTF-8 conversion.
//! * The large-message loop of LE indexes the wide buffer with a byte count.

use crate::readers::{push, take_fp};
use crate::status::{get_hash_context, sha1_stream, update_file_status};
use crate::*;

/// `UCS2_LE`
const UCS2_LE: i32 = 1;
/// `OS_MAXSTR_BE`
const OS_MAXSTR_BE: usize = OS_MAXSTR * 2;

fn dots(rbytes: i64, n: i32) -> &'static str {
    if rbytes > n as i64 {
        "..."
    } else {
        ""
    }
}

/// `wcslen`
fn wcslen(s: &[u16]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// `wcsrchr(s, c)`
fn wcsrchr(s: &[u16], c: u16) -> Option<usize> {
    s[..wcslen(s)].iter().rposition(|&x| x == c)
}

/// `(char *) str`: the little-endian bytes up to the first zero byte.
fn as_cstr(s: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    for &u in s {
        let (lo, hi) = (u as u8, (u >> 8) as u8);
        if lo == 0 {
            break;
        }
        out.push(lo);
        if hi == 0 {
            break;
        }
        out.push(hi);
    }
    out
}

/// `WideCharToMultiByte(CP_UTF8, 0, str, -1, ...)`: the UTF-8 string and
/// its size with the terminating NUL.
fn to_utf8(wide: &[u16]) -> (Vec<u8>, usize) {
    let s = String::from_utf16_lossy(&wide[..wcslen(wide)]).into_bytes();
    let n = s.len() + 1;
    (s, n)
}

fn send(lc: &Lc, lf: &Reader, wide: &[u16]) {
    let (utf8, utf8_bytes) = to_utf8(wide);
    lc.log.debug2(format!("Line converted to UTF-8 is {utf8_bytes} bytes"));
    if !crate::collector::check_ignore_and_restrict(lc, &lf.c.regex_ignore, &lf.c.regex_restrict, &utf8) {
        push(lc, lf, &utf8, utf8_bytes, LOCALFILE_MQ);
    }
}

fn large(lc: &Lc, lf: &Reader, rbytes: i64, sample: &[u8], reported: &mut bool) {
    let sl = lc.sample_len();
    let m = format!(
        "Large message size from file '{}' (length = {rbytes}): '{}'...",
        lf.file(),
        crate::sample(sample, sl)
    );
    if !*reported {
        lc.log.error(m);
        *reported = true;
    } else {
        lc.log.debug2(m);
    }
}

/// `read_ucs2_le`
pub fn read_ucs2_le(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    let mut ms = false;
    let mut ms_reported = false;
    let mut s = vec![0u16; OS_MAXSTR + 1];
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let mut current_position = fp.ftell();
    let mut ctx = get_hash_context(lc, lf, current_position);
    let maxl = lc.max_lines();
    let sl = lc.sample_len();
    let mut lines = 0;
    let mut offset = fp.ftell();
    let mut rbytes: i64;
    loop {
        if !(lc.can_read() && (maxl == 0 || lines < maxl) && offset >= 0 && fp.fgetws(&mut s, OS_MAXSTR - OS_LOG_HEADER)) {
            break;
        }
        rbytes = fp.ftell() - offset;
        lines += 1;
        lc.log.debug2(format!("Bytes read from '{}': {rbytes} bytes", lf.file()));
        if rbytes <= 0 {
            break;
        }
        if let Some(n) = wcsrchr(&s, 0x0A) {
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &as_cstr(&s));
            }
            s[n] = 0;
        }
        if rbytes == (OS_MAXSTR - OS_LOG_HEADER - 1) as i64 {
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &as_cstr(&s));
            }
            ms = true;
            s[rbytes as usize - 1] = 0;
        } else if lf.c.ucs2 == UCS2_LE && fp.feof() {
            lc.log.debug2(format!(
                "Message not complete from '{}'. Trying again: '{}'{}",
                lf.file(),
                crate::sample(&as_cstr(&s), sl),
                dots(rbytes, sl)
            ));
            fp.fseek(current_position, 0);
            break;
        }
        if let Some(p) = wcsrchr(&s, 0x0D) {
            s[p] = 0;
        }
        // Empty strings and "#" comments
        if rbytes <= 4 || s[0] == b'#' as u16 {
            current_position = fp.ftell();
            offset += rbytes;
            continue;
        }
        lc.log.debug2(format!("Reading syslog message: '{}'{}", crate::sample(&as_cstr(&s), sl), dots(rbytes, sl)));
        if drop_it == 0 {
            send(lc, lf, &s);
        }
        if ms {
            large(lc, lf, rbytes, &as_cstr(&s), &mut ms_reported);
            offset += rbytes;
            while fp.fgetws(&mut s, OS_MAXSTR - 2) {
                rbytes = fp.ftell() - offset;
                if rbytes <= 1 {
                    break;
                }
                if let Some(c) = ctx.as_mut() {
                    sha1_stream(c, &as_cstr(&s));
                }
                // str[rbytes - 2]: a byte count used as a wide index
                if s.get(rbytes as usize - 2).copied() == Some(0x0A) {
                    break;
                }
                offset += rbytes;
            }
            ms = false;
        }
        current_position = fp.ftell();
        offset += rbytes;
    }
    if let Some(c) = ctx {
        update_file_status(lc, lf.file(), current_position, c);
    }
    lc.log.debug2(format!("Read {lines} lines from {}", lf.file()));
    lf.fp = Some(fp);
}

/// `read_ucs2_be`
pub fn read_ucs2_be(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    let mut ms = false;
    let mut ms_reported = false;
    let mut s = vec![0u8; OS_MAXSTR_BE + 1];
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let mut current_position = fp.ftell();
    let mut ctx = get_hash_context(lc, lf, current_position);
    let maxl = lc.max_lines();
    let sl = lc.sample_len();
    let mut lines = 0;
    let mut offset = fp.ftell();
    let mut rbytes: i64;
    loop {
        if !(lc.can_read() && (maxl == 0 || lines < maxl) && offset >= 0 && fp.fgets(&mut s, OS_MAXSTR_BE - OS_LOG_HEADER)) {
            break;
        }
        rbytes = fp.ftell() - offset;
        lines += 1;
        lc.log.debug2(format!("Bytes read from '{}': {rbytes} bytes", lf.file()));
        if rbytes <= 0 {
            break;
        }
        let ru = rbytes as usize;
        if s[ru - 1] == b'\n' {
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &s);
            }
            s[ru - 1] = 0;
        } else if ru == OS_MAXSTR_BE - OS_LOG_HEADER - 1 {
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &s);
            }
            ms = true;
            s[ru - 1] = 0;
        } else if lf.c.ucs2 == UCS2_LE && fp.feof() {
            lc.log.debug2(format!(
                "Message not complete from '{}'. Trying again: '{}'{}",
                lf.file(),
                crate::sample(&s, sl),
                dots(rbytes, sl)
            ));
            fp.fseek(current_position, 0);
            break;
        }
        // strrchr(str, '\r') within the C string
        if let Some(p) = cstr(&s).iter().rposition(|&c| c == b'\r') {
            s[p] = 0;
        }
        if rbytes <= 4 || s[1] == b'#' {
            current_position = fp.ftell();
            offset += rbytes;
            continue;
        }
        lc.log.debug2(format!("Reading syslog message: '{}'{}", crate::sample(&s, sl), dots(rbytes, sl)));
        if drop_it == 0 {
            // If the file is Big Endian, swap every byte
            let mut j = 0;
            for _ in 0..OS_MAXSTR_BE / 2 {
                s.swap(j, j + 1);
                j += 2;
            }
            let wide: Vec<u16> = s[..OS_MAXSTR_BE].chunks(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
            send(lc, lf, &wide);
        }
        if ms {
            large(lc, lf, rbytes, &s, &mut ms_reported);
            offset += rbytes;
            while fp.fgets(&mut s, OS_MAXSTR_BE - 2) {
                rbytes = fp.ftell() - offset;
                if rbytes <= 0 {
                    break;
                }
                if let Some(c) = ctx.as_mut() {
                    sha1_stream(c, &s);
                }
                if s[rbytes as usize - 1] == b'\n' {
                    break;
                }
                offset += rbytes;
            }
            ms = false;
        }
        current_position = fp.ftell();
        offset += rbytes;
    }
    if let Some(c) = ctx {
        update_file_status(lc, lf.file(), current_position, c);
    }
    lc.log.debug2(format!("Read {lines} lines from {}", lf.file()));
    lf.fp = Some(fp);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn char_view_of_wide_buffer() {
        let w: Vec<u16> = "Ab".encode_utf16().chain([0]).collect();
        assert_eq!(as_cstr(&w), b"A");
        assert_eq!(wcsrchr(&w, b'b' as u16), Some(1));
        assert_eq!(to_utf8(&w), (b"Ab".to_vec(), 3));
    }
}
