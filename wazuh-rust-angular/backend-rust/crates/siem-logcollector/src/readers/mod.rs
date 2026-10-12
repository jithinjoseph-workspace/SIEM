//! The format readers (`logcollector/read_*.c`). Each one keeps the loop
//! structure, buffers and quirks of its C function: the fixed buffers keep
//! their old bytes between lines, the `offset`/`rbytes` arithmetic and the
//! `continue` points are the same, and lines are hashed with
//! `OS_SHA1_Stream` (up to the first NUL).

pub mod multiline_regex;
pub mod ucs2;

use sha1::Sha1;
use siem_cjson::Json;

use crate::collector::check_ignore_and_restrict;
use crate::output;
use crate::status::{get_hash_context, sha1_stream, update_file_status};
use crate::*;

pub use multiline_regex::read_multiline_regex;

/// `w_msg_hash_queues_push(str, lf->file, size, lf->log_target, mq)`
pub(crate) fn push(lc: &Lc, lf: &Reader, msg: &[u8], size: usize, mq: u8) {
    let file = lf.file().to_string();
    output::push(lc, msg, &file, size, &lf.targets(), mq);
}

fn ign(lc: &Lc, lf: &Reader, line: &[u8]) -> bool {
    check_ignore_and_restrict(lc, &lf.c.regex_ignore, &lf.c.regex_restrict, line)
}

fn dots(rbytes: i64, n: i32) -> &'static str {
    if rbytes > n as i64 {
        "..."
    } else {
        ""
    }
}

/// `snprintf(dst, size, "%s", src)`: bytes copied (truncated) + NUL;
/// returns the full length of `src`.
fn snprintf_s(dst: &mut [u8], src: &[u8]) -> usize {
    let src = cstr(src);
    if dst.is_empty() {
        return src.len();
    }
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
    src.len()
}

/// `strrchr(s, c)` within the C string.
fn strrchr(b: &[u8], c: u8) -> Option<usize> {
    cstr(b).iter().rposition(|&x| x == c)
}

fn strchr(b: &[u8], c: u8) -> Option<usize> {
    cstr(b).iter().position(|&x| x == c)
}

fn isdigit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn isalnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Take the open file of the entry for the duration of a read.
fn take_fp(lf: &mut Reader) -> Option<CFile> {
    lf.fp.take()
}

/// The skeleton shared by `read_syslog` and `read_json`.
fn read_lines(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32, json: bool) {
    let mut ms = false;
    let mut ms_reported = false;
    let mut s = vec![0u8; OS_MAXSTR + 1];
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let mut current_position = fp.ftell();
    let mut ctx: Option<Sha1> = get_hash_context(lc, lf, current_position);
    let maxl = lc.max_lines();
    let sl = lc.sample_len();
    let mut lines = 0;
    let mut offset = fp.ftell();
    let mut rbytes: i64;
    loop {
        if !(lc.can_read() && (maxl == 0 || lines < maxl) && offset >= 0 && fp.fgets(&mut s, OS_MAXSTR - OS_LOG_HEADER)) {
            break;
        }
        rbytes = fp.ftell() - offset;
        lines += 1;
        if rbytes <= 0 {
            break;
        }
        let ru = rbytes as usize;
        if s[ru - 1] == b'\n' {
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &s);
            }
            s[ru - 1] = 0;
            if strlen(&s) as i64 != rbytes - 1 {
                lc.log.debug2(format!(
                    "Line in '{}' contains some zero-bytes (valid={}{} total={}). Dropping line.",
                    lf.file(),
                    strlen(&s),
                    if json { " /" } else { "/" },
                    rbytes - 1
                ));
                offset += rbytes;
                continue;
            }
        } else if ru == OS_MAXSTR - OS_LOG_HEADER - 1 {
            ms = true;
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &s);
            }
            if !json {
                s[ru - 1] = 0;
            }
        } else if fp.feof() {
            lc.log.debug2(format!(
                "Message not complete from '{}'. Trying again: '{}'{}",
                lf.file(),
                sample(&s, sl),
                dots(rbytes, sl)
            ));
            if current_position >= 0 {
                fp.fseek(current_position, 0);
            }
            break;
        }

        // Windows: drop the last CR, empty lines and "#" comments
        #[cfg(windows)]
        {
            if let Some(p) = strrchr(&s, b'\r') {
                s[p] = 0;
            }
            if rbytes <= 2 || s[0] == b'#' {
                current_position = fp.ftell();
                offset += rbytes;
                continue;
            }
        }

        if !json {
            lc.log.debug2(format!("Reading syslog message: '{}'{}", sample(&s, sl), dots(rbytes, sl)));
            if drop_it == 0 && !ign(lc, lf, &s) {
                push(lc, lf, &s, ru, LOCALFILE_MQ);
            }
        } else {
            if ign(lc, lf, &s) {
                offset += rbytes;
                continue;
            }
            let parsed = match siem_cjson::parse_with_opts(cstr(&s), false) {
                Ok((mut obj, _)) if obj.is_object() => {
                    if let Some(l) = lf.c.labels.clone() {
                        for x in l.iter() {
                            w_json_add_field(&mut obj, &x.key, &x.value);
                        }
                    }
                    obj.print_unformatted()
                }
                _ => {
                    lc.log.debug1(format!(
                        "Line '{}'{} read from '{}' is not a JSON object.",
                        sample(&s, sl),
                        dots(rbytes, sl),
                        lf.file()
                    ));
                    offset += rbytes;
                    continue;
                }
            };
            lc.log.debug2(format!(
                "Reading json message: '{}'{}",
                sample(&parsed, sl),
                if parsed.len() > sl as usize { "..." } else { "" }
            ));
            if drop_it == 0 {
                push(lc, lf, &parsed, parsed.len() + 1, LOCALFILE_MQ);
            }
        }

        if ms {
            if !ms_reported {
                lc.log.error(format!(
                    "Large message size from file '{}' (length = {rbytes}): '{}'...",
                    lf.file(),
                    sample(&s, sl)
                ));
                ms_reported = true;
            } else {
                lc.log.debug2(format!(
                    "Large message size from file '{}' (length = {rbytes}): '{}'...",
                    lf.file(),
                    sample(&s, sl)
                ));
            }
            offset += rbytes;
            while fp.fgets(&mut s, OS_MAXSTR - 2) {
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

/// `read_syslog`
pub fn read_syslog(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    read_lines(lc, lf, rc, drop_it, false);
}

/// `read_json`
pub fn read_json(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    read_lines(lc, lf, rc, drop_it, true);
}

/// `W_JSON_AddField`: dotted keys make nested objects; values starting
/// with '[' that parse completely are added as arrays.
pub fn w_json_add_field(root: &mut Json, key: &str, value: &str) {
    if let Some(dot) = key.find('.') {
        let cur = &key[..dot];
        let rest = &key[dot + 1..];
        match root.get_mut(cur) {
            Some(o) => {
                if o.is_object() {
                    w_json_add_field(o, rest, value);
                }
            }
            None => {
                let mut o = Json::object();
                w_json_add_field(&mut o, rest, value);
                root.add(cur, o);
            }
        }
    } else if root.get(key).is_none() {
        if value.starts_with('[') {
            if let Ok((j, used)) = siem_cjson::parse_with_opts(value.as_bytes(), false) {
                if used >= value.len() {
                    root.add(key, j);
                    return;
                }
            }
        }
        root.add(key, Json::string(value));
    }
}

/// `read_multiline` (`multi-line:<n>`)
pub fn read_multiline(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    let mut ms = false;
    let mut ms_reported = false;
    let mut linesgot = 0i64;
    let mut s = vec![0u8; OS_MAX_LOG_SIZE];
    let mut buffer = vec![0u8; OS_MAX_LOG_SIZE];
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
        if !(lc.can_read() && (maxl == 0 || lines < maxl) && offset >= 0 && fp.fgets(&mut s, OS_MAX_LOG_SIZE)) {
            break;
        }
        rbytes = fp.ftell() - offset;
        lines += 1;
        linesgot += 1;
        if rbytes <= 0 {
            break;
        }
        let ru = rbytes as usize;
        if s[ru - 1] == b'\n' {
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &s);
            }
            s[ru - 1] = 0;
            if strlen(&s) as i64 != rbytes - 1 {
                lc.log.debug2(format!(
                    "Line in '{}' contains some zero-bytes (valid={} / total={}). Dropping line.",
                    lf.file(),
                    strlen(&s),
                    rbytes - 1
                ));
                offset += rbytes;
                continue;
            }
        } else if ru == OS_MAX_LOG_SIZE - 1 {
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &s);
            }
            ms = true;
        } else if fp.feof() {
            lc.log.debug2(format!(
                "Message not complete from '{}'. Trying again: '{}'{}",
                lf.file(),
                sample(&s, sl),
                dots(rbytes, sl)
            ));
            if current_position >= 0 {
                fp.fseek(current_position, 0);
            }
            break;
        }

        #[cfg(windows)]
        if let Some(p) = strrchr(&s, b'\r') {
            s[p] = 0;
        }

        let mut bsize = strlen(&buffer);
        if buffer[0] != 0 && bsize < buffer.len() - 1 {
            buffer[bsize] = b' ';
            bsize += 1;
        }
        let avail = buffer.len() - bsize;
        let size = snprintf_s(&mut buffer[bsize..], &s);
        if size >= avail {
            ms = true;
        }
        if linesgot < lf.c.linecount {
            offset += rbytes;
            continue;
        }
        linesgot = 0;
        if drop_it == 0 && !ign(lc, lf, &buffer) {
            lc.log.debug2(format!(
                "Reading message: '{}'{}",
                sample(&buffer, sl),
                if strlen(&buffer) > sl as usize { "..." } else { "" }
            ));
            push(lc, lf, &buffer, strlen(&buffer) + 1, LOCALFILE_MQ);
        }
        buffer[0] = 0;

        if ms {
            if !ms_reported {
                lc.log.error(format!(
                    "Large message size from file '{}' (length = {rbytes}): '{}'...",
                    lf.file(),
                    sample(&s, sl)
                ));
                ms_reported = true;
            } else {
                lc.log.debug2(format!(
                    "Large message size from file '{}' (length = {rbytes}): '{}'...",
                    lf.file(),
                    sample(&s, sl)
                ));
            }
            offset += rbytes;
            let n = s.len();
            while fp.fgets(&mut s, n) {
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

/// `read_snortfull` (C never selects it: `set_read` overrides it with
/// `read_syslog`; kept for completeness).
pub fn read_snortfull(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    const LABEL: &[u8] = b"[Classification: Preprocessor] [Priority: 3] ";
    #[derive(PartialEq)]
    enum P {
        None,
        One,
        Two,
    }
    let mut f_msg_size: i64 = OS_MAX_LOG_SIZE as i64 - 1;
    let mut p = P::None;
    let mut s = vec![0u8; OS_MAX_LOG_SIZE];
    let mut f_msg = vec![0u8; OS_MAX_LOG_SIZE];
    let mut lines = 0;
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let mut current_position = fp.ftell();
    let mut ctx = get_hash_context(lc, lf, current_position);
    let maxl = lc.max_lines();
    // strncat(dst, src, n)
    let strncat = |dst: &mut Vec<u8>, src: &[u8], n: i64| {
        let l = strlen(dst);
        let src = cstr(src);
        let k = src.len().min(n.max(0) as usize).min(dst.len() - l - 1);
        dst[l..l + k].copy_from_slice(&src[..k]);
        dst[l + k] = 0;
    };
    while lc.can_read() && (maxl == 0 || lines < maxl) && fp.fgets(&mut s, OS_MAX_LOG_SIZE) {
        lines += 1;
        if let Some(c) = ctx.as_mut() {
            sha1_stream(c, &s);
        }
        let Some(q) = strrchr(&s, b'\n') else {
            lc.log.error("Bad formated snort full file.");
            *rc = -1;
            lf.fp = Some(fp);
            return;
        };
        s[q] = 0;
        let bad = |lc: &Lc| lc.log.error("Bad formated snort full file.");
        match p {
            P::None => {
                if s.starts_with(b"[**] [") {
                    snprintf_s(&mut f_msg, &s);
                    f_msg_size -= strlen(&s) as i64;
                    p = P::One;
                }
            }
            P::One => {
                if s.starts_with(b"[Classification: ") {
                    strncat(&mut f_msg, &s.clone(), f_msg_size);
                    f_msg_size -= strlen(&s) as i64;
                    p = P::Two;
                } else if s.starts_with(b"[Priority: ") {
                    strncat(&mut f_msg, LABEL, f_msg_size);
                    f_msg_size -= LABEL.len() as i64;
                    p = P::Two;
                } else if s[2] == b'/' && s[5] == b'-' && strchr(&s, b' ').is_some() {
                    let q = strchr(&s, b' ').unwrap();
                    strncat(&mut f_msg, LABEL, f_msg_size);
                    f_msg_size -= LABEL.len() as i64;
                    let tail = s[q + 1..].to_vec();
                    strncat(&mut f_msg, &tail, f_msg_size - 40);
                    p = P::None;
                    if drop_it == 0 && !ign(lc, lf, &s) {
                        push(lc, lf, &s, strlen(&f_msg), LOCALFILE_MQ);
                    }
                    f_msg[0] = 0;
                    f_msg_size = OS_MAX_LOG_SIZE as i64 - 1;
                    s[0] = 0;
                } else {
                    bad(lc);
                    *rc = -1;
                    lf.fp = Some(fp);
                    return;
                }
            }
            P::Two => {
                if s[2] == b'/' && s[5] == b'-' && strchr(&s, b' ').is_some() {
                    let q = strchr(&s, b' ').unwrap();
                    let tail = s[q + 1..].to_vec();
                    strncat(&mut f_msg, &tail, f_msg_size);
                    p = P::None;
                    if drop_it == 0 && !ign(lc, lf, &s) {
                        push(lc, lf, &s, strlen(&s) + 1, LOCALFILE_MQ);
                    }
                    f_msg[0] = 0;
                    f_msg_size = OS_MAX_LOG_SIZE as i64 - 1;
                    s[0] = 0;
                } else {
                    bad(lc);
                    *rc = -1;
                    lf.fp = Some(fp);
                    return;
                }
            }
        }
    }
    current_position = fp.ftell();
    if let Some(c) = ctx {
        update_file_status(lc, lf.file(), current_position, c);
    }
    lc.log.debug2(format!("Read {lines} lines from {}", lf.file()));
    lf.fp = Some(fp);
}

/// `read_ossecalert`
pub fn read_ossecalert(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let al = crate::read_alert::get_alert_data(lc, 0, &mut fp);
    let Some(al) = al else {
        lf.fp = Some(fp);
        return;
    };
    let pos = fp.ftell();
    let ctx = match crate::status::sha1_file_nbytes(lc, lf.file(), pos, 0) {
        Ok(c) => c,
        Err(_) => {
            lc.log.error(format!("(1969): Failure to generate the SHA1 hash from file '{}'", lf.file()));
            <Sha1 as sha1::Digest>::new()
        }
    };
    update_file_status(lc, lf.file(), pos, ctx);
    let none = |v: &Option<String>| match v {
        None => true,
        Some(x) => x.as_bytes().starts_with(b"(no"),
    };
    let srcip_msg = if none(&al.srcip) {
        String::new()
    } else {
        trunc254(format!(" srcip: {};", al.srcip.as_deref().unwrap()))
    };
    let user_msg = if none(&al.user) {
        String::new()
    } else {
        trunc254(format!(" user: {};", al.user.as_deref().unwrap()))
    };
    let body = if al.log.len() <= 1 {
        // printf("%s", NULL) prints "(null)" with glibc
        al.log.first().cloned().unwrap_or_else(|| "(null)".to_string())
    } else {
        let mut t = String::new();
        for l in &al.log {
            t.push_str(l);
            t.push('\n');
        }
        let mut b = t.into_bytes();
        if b.len() > 1596 {
            b[1594] = b'.';
            b[1595] = b'.';
            b[1596] = b'.';
            b.truncate(1597);
        }
        String::from_utf8_lossy(&b).into_owned()
    };
    let msg = format!(
        "ossec: Alert Level: {}; Rule: {} - {}; Location: {};{}{}  {}",
        al.level,
        al.rule,
        al.comment.as_deref().unwrap_or("(null)"),
        al.location.as_deref().unwrap_or("(null)"),
        srcip_msg,
        user_msg,
        body
    );
    let mut m = msg.into_bytes();
    m.truncate(OS_SIZE_2048 - 1);
    if drop_it == 0 && !ign(lc, lf, &m) {
        push(lc, lf, &m, m.len() + 1, LOCALFILE_MQ);
    }
    lf.fp = Some(fp);
}

/// `snprintf(buf, 255, ...)`
fn trunc254(s: String) -> String {
    let mut b = s.into_bytes();
    b.truncate(254);
    String::from_utf8_lossy(&b).into_owned()
}

/// `__go_after`
fn go_after(x: &[u8], y: &[u8]) -> Option<usize> {
    let xs = strlen(x);
    if xs <= y.len() || &x[..y.len()] != y {
        return None;
    }
    Some(y.len())
}

/// `__get_port`: returns the index (in `s`) of the next field, or None.
fn get_port(s: &mut [u8], start: usize, proto: &mut Vec<u8>, port: &mut Vec<u8>, msize: usize) -> Option<usize> {
    let mut st = start;
    let mut filtered = false;
    while s.get(st) == Some(&b' ') {
        st += 1;
    }
    let p = st + strchr(&s[st..], b'/')?;
    s[p] = 0;
    let mut p = p + 1;
    // strncpy(port, str, msize); port[msize - 1] = '\0'
    let sp = cstr(&s[st..]);
    let n = sp.len().min(msize - 1);
    *port = sp[..n].to_vec();
    let q = go_after(&s[p..], b"open/");
    match q {
        None => {
            filtered = true;
            let q = p;
            p = q + strchr(&s[q..], b'/')? + 1;
        }
        Some(off) => p += off,
    }
    let st = p;
    let p2 = st + strchr(&s[st..], b'/')?;
    s[p2] = 0;
    let p = p2 + 1;
    let pr = cstr(&s[st..]);
    let n = pr.len().min(msize - 1);
    *proto = pr[..n].to_vec();
    if filtered {
        proto.clear();
    }
    if s.get(p) == Some(&b'/') {
        let p = p + 1;
        let q = p;
        return match strchr(&s[p..], b',') {
            Some(c) => Some(p + c),
            None => Some(q),
        };
    }
    None
}

/// `read_nmapg`
pub fn read_nmapg(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    let mut need_clear = false;
    let mut s = vec![0u8; OS_MAX_LOG_SIZE];
    let mut lines = 0;
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let mut current_position = fp.ftell();
    let mut ctx = get_hash_context(lc, lf, current_position);
    let maxl = lc.max_lines();
    while lc.can_read() && (maxl == 0 || lines < maxl) && fp.fgets(&mut s, OS_MAX_LOG_SIZE) {
        lines += 1;
        if let Some(c) = ctx.as_mut() {
            sha1_stream(c, &s);
        }
        if need_clear {
            if strchr(&s, b'\n').is_some() {
                need_clear = false;
            }
            continue;
        }
        match strchr(&s, b'\n') {
            Some(q) => s[q] = 0,
            None => need_clear = true,
        }
        if s[0] == b'#' || s[0] == 0 {
            continue;
        }
        let file_error = |lc: &Lc| lc.log.error("Bad formated nmap grepable file.");
        let Some(q) = go_after(&s, b"Host: ") else {
            file_error(lc);
            *rc = -1;
            lf.fp = Some(fp);
            return;
        };
        let Some(p) = strchr(&s[q..], b')').map(|x| q + x) else {
            file_error(lc);
            *rc = -1;
            lf.fp = Some(fp);
            return;
        };
        let ip_start = q;
        let Some(tab) = strchr(&s[p..], b'\t').map(|x| p + x) else {
            file_error(lc);
            *rc = -1;
            lf.fp = Some(fp);
            return;
        };
        let q = tab + 1;
        s[p + 1] = 0;
        let ip = cstr(&s[ip_start..]).to_vec();
        let pp = match go_after(&s[q..], b"Ports:") {
            Some(off) => q + off,
            None => {
                if go_after(&s[q..], b"Status:").is_some() {
                    continue;
                }
                file_error(lc);
                *rc = -1;
                lf.fp = Some(fp);
                return;
            }
        };
        let mut final_msg = format!("Host: {}, open ports:", String::from_utf8_lossy(&ip)).into_bytes();
        let mut final_msg_s: i64;
        if final_msg.len() < OS_MAX_LOG_SIZE {
            final_msg_s = (OS_MAX_LOG_SIZE - final_msg.len()) as i64;
        } else {
            final_msg.truncate(OS_MAX_LOG_SIZE - 1);
            final_msg_s = 0;
            lc.log.error(format!(
                "Large message size from file '{}' (length = {}): '{}'...",
                lf.file(),
                final_msg.len(),
                String::from_utf8_lossy(&final_msg)
            ));
        }
        let mut p = pp;
        let mut proto = Vec::new();
        let mut port = Vec::new();
        loop {
            if final_msg_s < 27 {
                break;
            }
            match get_port(&mut s, p, &mut proto, &mut port, 9) {
                None => {
                    lc.log.debug1("Bad formated nmap grepable file (port).");
                    break;
                }
                Some(np) => p = np,
            }
            if !proto.is_empty() {
                let add = format!(" {}({})", String::from_utf8_lossy(&port), String::from_utf8_lossy(&proto)).into_bytes();
                let room = (final_msg_s as usize).saturating_sub(1);
                final_msg.extend_from_slice(&add[..add.len().min(room)]);
                final_msg_s -= add.len() as i64;
            }
            if s.get(p) == Some(&b',') {
                p += 1;
            } else {
                break;
            }
        }
        if drop_it == 0 && !ign(lc, lf, &final_msg) {
            push(lc, lf, &final_msg, final_msg.len() + 1, HOSTINFO_MQ);
        }
    }
    current_position = fp.ftell();
    if let Some(c) = ctx {
        update_file_status(lc, lf.file(), current_position, c);
    }
    lc.log.debug2(format!("Read {lines} lines from {}", lf.file()));
    lf.fp = Some(fp);
}

/// `read_mysql_log`
pub fn read_mysql_log(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    let mut need_clear = false;
    let mut s = vec![0u8; OS_MAX_LOG_SIZE];
    let mut buffer: Vec<u8>;
    let mut lines = 0;
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let mut current_position = fp.ftell();
    let mut ctx = get_hash_context(lc, lf, current_position);
    let maxl = lc.max_lines();
    let mut last = lc.statics.lock().unwrap().get("mysql_last_time").cloned().unwrap_or_else(|| vec![0u8; 36]);
    while lc.can_read() && (maxl == 0 || lines < maxl) && fp.fgets(&mut s, OS_MAX_LOG_SIZE) {
        lines += 1;
        let str_len = strlen(&s);
        if let Some(c) = ctx.as_mut() {
            sha1_stream(c, &s);
        }
        match strrchr(&s, b'\n') {
            Some(p) => {
                s[p] = 0;
                if need_clear {
                    need_clear = false;
                    continue;
                }
            }
            None => need_clear = true,
        }
        // Windows: drop the last CR, empty lines and "#" comments
        #[cfg(windows)]
        {
            if let Some(p) = strrchr(&s, b'\r') {
                s[p] = 0;
            }
            if str_len <= 2 || s[0] == b'#' {
                continue;
            }
        }
        let d = |i: usize| isdigit(s[i]);
        let rest_after = |st: usize| -> Vec<u8> {
            let mut p = st;
            while s[p] == b' ' || s[p] == b'\t' {
                p += 1;
            }
            cstr(&s[p..]).to_vec()
        };
        let save = |last: &mut Vec<u8>, n: usize, keep: usize| {
            // strncpy(__mysql_last_time, str, n); __mysql_last_time[keep] = '\0'
            let src = cstr(&s);
            for k in 0..n {
                last[k] = if k < src.len() { src[k] } else { 0 };
            }
            last[keep] = 0;
        };
        let msg: Vec<u8>;
        if str_len > 18 && s[6] == b' ' && s[9] == b':' && s[12] == b':' && (0..6).all(d) && d(7) && d(8) {
            save(&mut last, 16, 15);
            msg = rest_after(15);
        } else if str_len > 35
            && s[4] == b'-'
            && s[7] == b'-'
            && s[10] == b'T'
            && s[13] == b':'
            && s[16] == b':'
            && s[19] == b'.'
            && (s[26] == b'-' || s[26] == b'+')
            && s[29] == b':'
            && s[32] == b' '
            && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25, 27, 28, 30, 31].iter().all(|&i| d(i))
        {
            save(&mut last, 33, 32);
            msg = rest_after(32);
        } else if str_len > 30
            && s[4] == b'-'
            && s[7] == b'-'
            && s[10] == b'T'
            && s[13] == b':'
            && s[16] == b':'
            && s[19] == b'.'
            && s[26] == b'Z'
            && s[27] == b' '
            && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25].iter().all(|&i| d(i))
        {
            save(&mut last, 28, 27);
            msg = rest_after(27);
        } else if str_len > 10 && last[0] != 0 && s[0] == 0x09 && s[1] == 0x09 && s[2..8].iter().all(|&c| c == 0x20) {
            msg = rest_after(2);
        } else {
            continue;
        }
        let full = format!("MySQL log: {} {}", String::from_utf8_lossy(cstr(&last)), String::from_utf8_lossy(&msg)).into_bytes();
        buffer = full.clone();
        if full.len() >= OS_MAX_LOG_SIZE {
            buffer.truncate(OS_MAX_LOG_SIZE - 1);
            lc.log.error(format!(
                "Message size too big on file '{}' (length = {}): '{}'...",
                lf.file(),
                full.len(),
                String::from_utf8_lossy(&buffer)
            ));
        }
        lc.log.debug2(format!("Reading mysql messages: '{}'", String::from_utf8_lossy(&buffer)));
        if drop_it == 0 && !ign(lc, lf, &buffer) {
            push(lc, lf, &buffer, buffer.len() + 1, LOCALFILE_MQ);
        }
    }
    lc.statics.lock().unwrap().insert("mysql_last_time", last);
    current_position = fp.ftell();
    if let Some(c) = ctx {
        update_file_status(lc, lf.file(), current_position, c);
    }
    lc.log.debug2(format!("Read {lines} lines from {}", lf.file()));
    lf.fp = Some(fp);
}

/// The common body of `read_mssql_log` and `read_postgresql_log`.
fn read_sql_log(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32, pg: bool) {
    let mut need_clear = false;
    let mut s = vec![0u8; OS_MAX_LOG_SIZE];
    let mut buffer = vec![0u8; OS_MAX_LOG_SIZE];
    let mut lines = 0;
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let mut current_position = fp.ftell();
    let mut ctx = get_hash_context(lc, lf, current_position);
    let maxl = lc.max_lines();
    let send = |lc: &Lc, lf: &Reader, b: &[u8]| {
        lc.log.debug2(format!(
            "Reading {} message: '{}'",
            if pg { "PostgreSQL" } else { "MSSQL" },
            String::from_utf8_lossy(cstr(b))
        ));
        if drop_it == 0 && !ign(lc, lf, b) {
            push(lc, lf, b, strlen(b) + 1, LOCALFILE_MQ);
        }
    };
    while lc.can_read() && (maxl == 0 || lines < maxl) && fp.fgets(&mut s, OS_MAX_LOG_SIZE) {
        lines += 1;
        let mut str_len = strlen(&s);
        if let Some(c) = ctx.as_mut() {
            sha1_stream(c, &s);
        }
        if str_len >= buffer.len() - 2 {
            str_len = buffer.len() - 10;
        }
        match strrchr(&s, b'\n') {
            Some(p) => {
                s[p] = 0;
                if need_clear {
                    need_clear = false;
                    continue;
                }
            }
            None => need_clear = true,
        }
        // Windows: drop the last CR, empty lines and "#" comments
        #[cfg(windows)]
        {
            if let Some(p) = strrchr(&s, b'\r') {
                s[p] = 0;
            }
            if str_len <= 1 || s[0] == b'#' {
                continue;
            }
        }
        let header = if pg {
            str_len > 32
                && s[0] == b'['
                && s[5] == b'-'
                && s[8] == b'-'
                && s[11] == b' '
                && s[14] == b':'
                && s[17] == b':'
                && isdigit(s[1])
                && isdigit(s[12])
        } else {
            str_len > 19
                && s[4] == b'-'
                && s[7] == b'-'
                && s[10] == b' '
                && s[13] == b':'
                && s[16] == b':'
                && (0..4).all(|i| isdigit(s[i]))
        };
        if header {
            if buffer[0] == 0 {
                snprintf_s(&mut buffer, &s);
                continue;
            } else {
                send(lc, lf, &buffer);
                snprintf_s(&mut buffer, &s);
            }
        } else if str_len > 2 && buffer[0] != 0 && (!pg || s[0] == b'\t') {
            let blen = strlen(&buffer);
            if buffer.len() - blen > str_len {
                buffer[blen] = b' ';
                buffer[blen + 1] = 0;
                // strncat(buffer, str, str_len + 3): the whole line
                let src = cstr(&s).to_vec();
                let k = src.len().min(str_len + 3).min(buffer.len() - (blen + 1) - 1);
                buffer[blen + 1..blen + 1 + k].copy_from_slice(&src[..k]);
                buffer[blen + 1 + k] = 0;
            }
        }
    }
    if pg {
        if buffer[0] != 0 {
            send(lc, lf, &buffer);
        }
        current_position = fp.ftell();
        if let Some(c) = ctx {
            update_file_status(lc, lf.file(), current_position, c);
        }
    } else {
        current_position = fp.ftell();
        if let Some(c) = ctx {
            update_file_status(lc, lf.file(), current_position, c);
        }
        if buffer[0] != 0 {
            send(lc, lf, &buffer);
        }
    }
    lc.log.debug2(format!("Read {lines} lines from {}", lf.file()));
    lf.fp = Some(fp);
}

/// `read_mssql_log`
pub fn read_mssql_log(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    read_sql_log(lc, lf, rc, drop_it, false);
}

/// `read_postgresql_log`
pub fn read_postgresql_log(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    read_sql_log(lc, lf, rc, drop_it, true);
}

/// `init_djbmultilog`
pub fn init_djbmultilog(lc: &Lc, lf: &mut Reader) -> bool {
    lf.c.djb_program_name = None;
    #[cfg(unix)]
    let h = {
        let mut host = vec![0u8; 513];
        // SAFETY: gethostname into a 512-byte buffer.
        let ok = unsafe { libc::gethostname(host.as_mut_ptr().cast(), 511) } == 0;
        let mut h = if ok { cstr(&host).to_vec() } else { b"unknown".to_vec() };
        if ok {
            if let Some(d) = h.iter().position(|&c| c == b'.') {
                h.truncate(d);
            }
        }
        h
    };
    #[cfg(windows)]
    let h = b"win32".to_vec();
    lc.statics.lock().unwrap().insert("djb_host", h);
    let file = lf.file().to_string();
    let Some(slash) = file.rfind('/') else { return false };
    if &file[slash..] != "/current" || slash == 0 {
        return false;
    }
    let dir = &file[..slash];
    let Some(s2) = dir.rfind('/') else {
        // strrchr returns NULL: os_strdup(NULL + 1) would crash in C
        return false;
    };
    if s2 == 0 {
        return false;
    }
    let name = dir[s2 + 1..].to_string();
    lc.log.info(format!("Using program name '{name}' for DJB multilog file: '{file}'."));
    lf.c.djb_program_name = Some(name);
    true
}

/// `read_djbmultilog`
pub fn read_djbmultilog(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mut need_clear = false;
    let mut s = vec![0u8; OS_MAX_LOG_SIZE];
    let mut buffer = vec![0u8; OS_MAX_LOG_SIZE];
    let mut lines = 0;
    *rc = 0;
    let Some(prog) = lf.c.djb_program_name.clone() else { return };
    let Some(mut fp) = take_fp(lf) else { return };
    let mut current_position = fp.ftell();
    let mut ctx = get_hash_context(lc, lf, current_position);
    let maxl = lc.max_lines();
    let host = lc.statics.lock().unwrap().get("djb_host").cloned().unwrap_or_default();
    while lc.can_read() && (maxl == 0 || lines < maxl) && fp.fgets(&mut s, OS_MAX_LOG_SIZE) {
        if let Some(c) = ctx.as_mut() {
            sha1_stream(c, &s);
        }
        lines += 1;
        let str_len = strlen(&s);
        match strrchr(&s, b'\n') {
            Some(p) => {
                s[p] = 0;
                if need_clear {
                    need_clear = false;
                    continue;
                }
            }
            None => need_clear = true,
        }
        if str_len > 26 && s[0] == b'@' && isalnum(s[1]) && isalnum(s[2]) && isalnum(s[3]) && isalnum(s[24]) && s[25] == b' ' {
            let mut p = 26;
            while s[p] == b' ' || s[p] == b'\t' {
                p += 1;
            }
            let at = |k: usize| s.get(p + k).copied().unwrap_or(0);
            if str_len > 44 && at(3) == b' ' && at(6) == b' ' && at(9) == b':' && at(12) == b':' && at(15) == b' ' {
                let tail = s[p + 16..].to_vec();
                snprintf_s(&mut buffer, &tail);
            } else {
                let tm = crate::local_tm_now();
                let full = format!(
                    "{} {:02} {:02}:{:02}:{:02} {} {}: {}",
                    MONTHS[tm.tm_mon as usize],
                    tm.tm_mday,
                    tm.tm_hour,
                    tm.tm_min,
                    tm.tm_sec,
                    String::from_utf8_lossy(&host),
                    prog,
                    String::from_utf8_lossy(cstr(&s[p..]))
                )
                .into_bytes();
                snprintf_s(&mut buffer, &full);
                if full.len() >= buffer.len() {
                    lc.log.error(format!(
                        "Message size too big on file '{}' (length = {}): '{}'...",
                        lf.file(),
                        full.len(),
                        String::from_utf8_lossy(cstr(&buffer))
                    ));
                }
            }
        } else {
            lc.log.debug2(format!("Invalid DJB log: '{}'", String::from_utf8_lossy(cstr(&s))));
            continue;
        }
        if ign(lc, lf, &s) {
            continue;
        }
        lc.log.debug2(format!("Reading DJB multilog message: '{}'", String::from_utf8_lossy(cstr(&buffer))));
        if drop_it == 0 {
            push(lc, lf, &buffer, strlen(&buffer) + 1, LOCALFILE_MQ);
        }
    }
    current_position = fp.ftell();
    if let Some(c) = ctx {
        update_file_status(lc, lf.file(), current_position, c);
    }
    lc.log.debug2(format!("Read {lines} lines from {}", lf.file()));
    lf.fp = Some(fp);
}

/// `read_audit`
pub fn read_audit(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    const MAX_CACHE: usize = 64;
    const MAX_HEADER: usize = 64;
    let mut cache: Vec<Vec<u8>> = Vec::new();
    let mut header = [0u8; MAX_HEADER];
    let mut buffer = vec![0u8; OS_MAX_LOG_SIZE];
    let mut lines = 0;
    *rc = 0;
    let Some(mut fp) = take_fp(lf) else { return };
    let mut offset = fp.ftell();
    let mut ctx = get_hash_context(lc, lf, offset);
    let maxl = lc.max_lines();
    let send = |lc: &Lc, lf: &Reader, cache: &mut Vec<Vec<u8>>| {
        let mut message: Vec<u8> = Vec::new();
        for c in cache.drain(..) {
            let z = c.len();
            if message.len() + z + 1 < OS_MAX_LOG_SIZE {
                if !message.is_empty() {
                    message.push(b' ');
                }
                message.extend_from_slice(&c);
            }
        }
        if drop_it == 0 && !ign(lc, lf, &message) {
            push(lc, lf, &message, message.len() + 1, LOCALFILE_MQ);
        }
    };
    offset = fp.ftell();
    let mut rbytes: i64;
    loop {
        if !(lc.can_read() && (maxl == 0 || lines < maxl) && offset >= 0 && fp.fgets(&mut buffer, OS_MAX_LOG_SIZE)) {
            break;
        }
        rbytes = fp.ftell() - offset;
        if rbytes <= 0 {
            break;
        }
        lines += 1;
        let ru = rbytes as usize;
        if buffer[ru - 1] == b'\n' {
            if let Some(c) = ctx.as_mut() {
                sha1_stream(c, &buffer);
            }
            buffer[ru - 1] = 0;
            if strlen(&buffer) as i64 != rbytes - 1 {
                lc.log.debug2(format!(
                    "Line in '{}' contains some zero-bytes (valid={} / total={}). Dropping line.",
                    lf.file(),
                    strlen(&buffer),
                    rbytes - 1
                ));
                offset += rbytes;
                continue;
            }
        } else {
            if ru == OS_MAX_LOG_SIZE - 1 {
                offset += rbytes;
                while fp.fgets(&mut buffer, OS_MAX_LOG_SIZE) {
                    rbytes = fp.ftell() - offset;
                    if rbytes <= 0 {
                        break;
                    }
                    if let Some(c) = ctx.as_mut() {
                        sha1_stream(c, &buffer);
                    }
                    if buffer[rbytes as usize - 1] == b'\n' {
                        break;
                    }
                    offset += rbytes;
                }
            } else if fp.feof() {
                lc.log.debug2(format!("Message not complete. Trying again: '{}'", String::from_utf8_lossy(cstr(&buffer))));
                if fp.fseek(offset, 0) < 0 {
                    let e = errno();
                    lc.log.error(format!(
                        "(1116): Could not set position in file '{}' due to [({e})-({})].",
                        lf.file(),
                        strerror(e)
                    ));
                }
            }
            break;
        }
        if strlen(&buffer) == 0 {
            lc.log.debug2("audit reader: empty line, skipping.");
            break;
        }
        let b = cstr(&buffer).to_vec();
        let find = |h: &[u8], n: &[u8], from: usize| h[from..].windows(n.len()).position(|w| w == n).map(|p| p + from);
        let id = find(&b, b"type=", 0)
            .and_then(|t| find(&b, b" msg=audit(", t + 5))
            .map(|m| m + 11)
            .and_then(|id| find(&b, b"):", id).map(|p| (id, p)));
        let Some((id, p)) = id else {
            lc.log.warn("Discarding audit message because of invalid syntax.");
            break;
        };
        let z = p - id;
        // strncmp(id, header, z)
        let hcmp = (0..z).find_map(|k| {
            let a = b[id + k];
            let h = if k < MAX_HEADER { header[k] } else { 0 };
            if a != h {
                Some(true)
            } else if a == 0 {
                Some(false)
            } else {
                None
            }
        });
        if hcmp.unwrap_or(false) {
            if !cache.is_empty() {
                send(lc, lf, &mut cache);
            }
            cache.push(b.clone());
            // strncpy(header, id, z < MAX_HEADER ? z : MAX_HEADER - 1): no NUL added
            let n = if z < MAX_HEADER { z } else { MAX_HEADER - 1 };
            header[..n].copy_from_slice(&b[id..id + n]);
        } else if cache.len() == MAX_CACHE {
            lc.log.error("Discarding audit message because cache is full.");
        } else {
            cache.push(b.clone());
        }
        offset += rbytes;
    }
    if !cache.is_empty() {
        send(lc, lf, &mut cache);
    }
    if let Some(c) = ctx {
        update_file_status(lc, lf.file(), offset, c);
    }
    lc.log.debug2(format!("Read {lines} lines from {}", lf.file()));
    lf.fp = Some(fp);
}

/// `read_command`
pub fn read_command(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    *rc = 0;
    let Some(cmd) = lf.c.command.clone() else { return };
    lc.log.debug2(format!("Running command '{cmd}'"));
    let Ok(mut out) = CFile::popen(&cmd) else {
        lc.log.error(format!("Unable to execute command: '{cmd}'."));
        lf.c.command = None;
        return;
    };
    let mut s = vec![0u8; OS_MAXSTR + 1];
    let label = lf.c.alias.clone().unwrap_or_else(|| cmd.clone());
    let prefix = format!("ossec: output: '{label}': ").into_bytes();
    let cmd_size = snprintf_s(&mut s[..256], &prefix).min(255);
    let maxl = lc.max_lines();
    let mut lines = 0;
    while lc.can_read() && (maxl == 0 || lines < maxl) && out.fgets(&mut s[cmd_size..], OS_MAXSTR - OS_LOG_HEADER - 256) {
        lines += 1;
        if let Some(p) = strrchr(&s, b'\n') {
            s[p] = 0;
        }
        if s[0] == 0 {
            continue;
        }
        if ign(lc, lf, &s) {
            continue;
        }
        lc.log.debug2(format!("Reading command message: '{}'", String::from_utf8_lossy(cstr(&s))));
        if drop_it == 0 {
            let loc = lf.c.alias.clone().unwrap_or_else(|| cmd.clone());
            output::push(lc, &s, &loc, strlen(&s) + 1, &lf.targets(), LOCALFILE_MQ);
        }
    }
    out.pclose();
    lc.log.debug2(format!("Read {lines} lines from command '{cmd}'"));
}

/// `read_fullcommand`
pub fn read_fullcommand(lc: &Lc, lf: &mut Reader, rc: &mut i32, drop_it: i32) {
    *rc = 0;
    let Some(cmd) = lf.c.command.clone() else { return };
    lc.log.debug2(format!("Running full command '{cmd}'"));
    let Ok(mut out) = CFile::popen(&cmd) else {
        lc.log.error(format!("Unable to execute command: '{cmd}'."));
        lf.c.command = None;
        return;
    };
    let mut s = vec![0u8; OS_MAXSTR + 1];
    let label = lf.c.alias.clone().unwrap_or_else(|| cmd.clone());
    let prefix = format!("ossec: output: '{label}':\n").into_bytes();
    let cmd_size = snprintf_s(&mut s[..256], &prefix).min(255);
    let n = out.fread(&mut s[cmd_size..cmd_size + OS_MAXSTR - OS_LOG_HEADER - 256]);
    if n > 0 {
        s[cmd_size + n] = 0;
        if let Some(p) = strrchr(&s, b'\n') {
            s[p] = 0;
        }
        lc.log.debug2(format!("Reading command message: '{}'", String::from_utf8_lossy(cstr(&s))));
        let src = cstr(&s);
        let mut fin: Vec<u8> = Vec::with_capacity(src.len());
        let mut k = 0;
        while k < src.len() {
            if src[k] == b'\r' {
                k += 1;
                continue;
            }
            if src[k] == b'\n' && src.get(k + 1) == Some(&b'\n') {
                k += 1;
            }
            fin.push(src[k]);
            k += 1;
        }
        if drop_it == 0 && !ign(lc, lf, &fin) {
            let loc = lf.c.alias.clone().unwrap_or_else(|| cmd.clone());
            output::push(lc, &fin, &loc, fin.len() + 1, &lf.targets(), LOCALFILE_MQ);
        }
    }
    out.pclose();
}

/// `read_journald`
pub fn read_journald(lc: &Lc, lf: &mut Reader, rc: &mut i32, _drop_it: i32) {
    crate::journal::read_journald(lc, lf, rc);
}
