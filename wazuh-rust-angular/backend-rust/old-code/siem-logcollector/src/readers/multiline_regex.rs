//! `logcollector/read_multiline_regex.c`: logs spanning several lines,
//! split by a PCRE2 expression matching their start, end or whole text,
//! with a context kept between reads for logs still being written.

use siem_config::localfile::{MlMatch, MlReplace, MultilineConfig, MultilineCtxt};

use super::{ign, push};
use crate::status::{get_hash_context, sha1_stream, update_file_status};
use crate::*;

/// `multiline_replace` on the C string at the start of `s`.
fn multiline_replace(s: &mut [u8], t: MlReplace) {
    let len = strlen(s);
    if len == 0 || s[len - 1] != b'\n' {
        return;
    }
    let nl = len - 1;
    let cr = if len > 1 && s[nl - 1] == b'\r' { Some(nl - 1) } else { None };
    match t {
        MlReplace::Wspace | MlReplace::Tab => {
            let c = if t == MlReplace::Wspace { b' ' } else { b'\t' };
            match cr {
                Some(p) => {
                    s[p] = c;
                    s[nl] = 0;
                }
                None => s[nl] = c,
            }
        }
        MlReplace::None => match cr {
            Some(p) => s[p] = 0,
            None => s[nl] = 0,
        },
        MlReplace::NoReplace => {}
    }
}

/// `multiline_ctxt_backup`
fn ctxt_backup(buf: &[u8], lines: i32, ctxt: &mut Option<MultilineCtxt>) {
    let cur = cstr(buf);
    match ctxt {
        None => {}
        Some(c) if c.buffer.len() == cur.len() => return, // size unchanged: nothing updated
        Some(_) => {}
    }
    let c = ctxt.get_or_insert_with(MultilineCtxt::default);
    c.buffer = cur.to_vec();
    c.lines_count = lines;
    c.timestamp = now();
}

/// `multiline_ctxt_is_expired`
fn ctxt_expired(timeout: u32, ctxt: &Option<MultilineCtxt>) -> bool {
    match ctxt {
        None => true,
        Some(c) => now() - c.timestamp > timeout as i64,
    }
}

/// `multiline_getlog_{start,end,all}`: lines of the next log in `buf`.
fn getlog(lc: &Lc, buf: &mut [u8], length: usize, fp: &mut CFile, ml: &mut MultilineConfig) -> i32 {
    let mut off = 0usize;
    let mut collecting = false;
    let mut readed = 0;
    let mut retstr = false;
    buf[0] = 0;
    let mut pos = fp.ftell();

    if let Some(c) = &ml.ctxt {
        let n = c.buffer.len().min(buf.len() - 1);
        buf[..n].copy_from_slice(&c.buffer[..n]);
        buf[n] = 0;
        readed = c.lines_count;
        off = strlen(buf);
        collecting = true;
        if ctxt_expired(ml.timeout, &ml.ctxt) {
            ml.ctxt = None;
            multiline_replace(buf, MlReplace::None);
            return readed;
        }
    }

    loop {
        if !lc.can_read() {
            break;
        }
        if !fp.fgets(&mut buf[off..], length - off) {
            retstr = false;
            break;
        }
        retstr = true;
        match ml.match_type {
            MlMatch::Start => {
                if collecting && ml.regex.match_bytes(cstr(&buf[off..]), None).0 {
                    buf[off] = 0;
                    multiline_replace(buf, MlReplace::None);
                    fp.fseek(pos, 0);
                    break;
                }
                multiline_replace(&mut buf[off..], ml.replace_type);
                off += strlen(&buf[off..]);
                readed += 1;
                pos = fp.ftell();
            }
            MlMatch::End | MlMatch::All => {
                readed += 1;
                let hay = if ml.match_type == MlMatch::End { cstr(&buf[off..]) } else { cstr(buf) };
                if ml.regex.match_bytes(hay, None).0 {
                    multiline_replace(buf, MlReplace::None);
                    collecting = false;
                    break;
                }
                multiline_replace(&mut buf[off..], ml.replace_type);
                off += strlen(&buf[off..]);
            }
        }
        collecting = true;
        retstr = false;
        if off == length - 1 {
            break;
        }
    }

    if collecting && !retstr && length > off + 1 {
        ctxt_backup(buf, readed, &mut ml.ctxt);
        readed = 0;
    } else if length == off + 1 {
        loop {
            let c = fp.fgetc();
            if c == b'\n' as i32 || c == 0 || c == -1 {
                break;
            }
        }
    }
    if ml.ctxt.is_some() && readed > 0 {
        ml.ctxt = None;
    }
    readed
}

/// `get_file_chunk`
fn get_file_chunk(fp: &mut CFile, initial: i64, fin: i64) -> Option<Vec<u8>> {
    let len = fin - initial;
    if len <= 0 || fp.fseek(initial, 0) != 0 {
        return None;
    }
    let mut b = vec![0u8; len as usize];
    if fp.fread(&mut b) as i64 != len {
        return None;
    }
    Some(b)
}

/// `read_multiline_regex`
pub fn read_multiline_regex(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    let length = OS_MAXSTR - OS_LOG_HEADER;
    let mut buf = vec![0u8; OS_MAXSTR + 1];
    if !lc.can_read() {
        return;
    }
    let Some(mut ml) = lf.c.multiline.take() else { return };
    let Some(mut fp) = lf.fp.take() else {
        lf.c.multiline = Some(ml);
        return;
    };
    let t = fp.ftell();
    if ml.offset_last_read == 0 || t < ml.offset_last_read {
        ml.offset_last_read = t;
    }
    let mut ctx = get_hash_context(lc, lf, ml.offset_last_read);
    *rc = 0;
    let maxl = lc.max_lines();
    let mut count = 0;
    loop {
        if !(maxl == 0 || count < maxl) {
            break;
        }
        let rlines = getlog(lc, &mut buf, length, &mut fp, &mut ml);
        if rlines <= 0 {
            break;
        }
        if drop_it == 0 && !ign(lc, lf, &buf) {
            push(lc, lf, &buf, strlen(&buf) + 1, LOCALFILE_MQ);
        }
        count += rlines;
        let initial = ml.offset_last_read;
        ml.offset_last_read = fp.ftell();
        let Some(raw) = get_file_chunk(&mut fp, initial, ml.offset_last_read) else { continue };
        if let Some(c) = ctx.as_mut() {
            sha1_stream(c, &raw);
        }
    }
    if let Some(c) = ctx {
        update_file_status(lc, lf.file(), ml.offset_last_read, c);
    }
    lf.fp = Some(fp);
    lf.c.multiline = Some(ml);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_like_c() {
        let mut b = *b"ab\r\n\0x";
        multiline_replace(&mut b, MlReplace::Wspace);
        assert_eq!(cstr(&b), b"ab ");
        let mut b = *b"ab\n\0";
        multiline_replace(&mut b, MlReplace::Tab);
        assert_eq!(cstr(&b), b"ab\t");
        let mut b = *b"ab\n\0";
        multiline_replace(&mut b, MlReplace::None);
        assert_eq!(cstr(&b), b"ab");
    }
}
