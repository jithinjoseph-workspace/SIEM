//! `Eventinfo` (analysisd/eventinfo.h) and `OS_CleanMSG` (cleanevent.c).
//!
//! The C code parses the event in place inside one buffer that holds two
//! copies of the log (`full_log` and `log`) and cuts it with NUL bytes; the
//! decoders then keep pointers into that buffer (`log`, `log_after_parent`,
//! `log_after_prematch`, the regex offsets). The port keeps exactly that
//! buffer and expresses every pointer as an offset into it, so that the
//! pointer arithmetic of the decoders (including the `end - 1` cases and the
//! NUL terminators) behaves byte for byte like the original.

use crate::decoders::DecId;
use crate::rules::RuleId;

pub type Bytes = Vec<u8>;

/* Types of events (from decoders) */
pub const UNKNOWN: u8 = 0;
pub const SYSLOG: u8 = 1;
pub const IDS: u8 = 2;
pub const FIREWALL: u8 = 3;
pub const WEBLOG: u8 = 7;
pub const SQUID: u8 = 8;
pub const DECODER_WINDOWS: u8 = 9;
pub const HOST_INFO: u8 = 10;
pub const OSSEC_RL: u8 = 11;
pub const OSSEC_ALERT: u8 = 12;

/* FTS allowed values */
pub const FTS_NAME: i32 = 0o001000;
pub const FTS_SRCUSER: i32 = 0o002000;
pub const FTS_DSTUSER: i32 = 0o004000;
pub const FTS_SRCIP: i32 = 0o000100;
pub const FTS_DSTIP: i32 = 0o000200;
pub const FTS_LOCATION: i32 = 0o000400;
pub const FTS_ID: i32 = 0o000010;
pub const FTS_DATA: i32 = 0o000020;
pub const FTS_SYSTEMNAME: i32 = 0o000040;
pub const FTS_DONE: i32 = 0o010000;
pub const FTS_DYNAMIC: i32 = 0o020000;

/// Static event fields, in the order of `field_offset[]` (eventinfo.c), which
/// is also the bit order of `FIELD_*` in rules.h.
pub const F_SRCIP: usize = 0;
pub const F_ID: usize = 1;
pub const F_DSTIP: usize = 2;
pub const F_SRCPORT: usize = 3;
pub const F_DSTPORT: usize = 4;
pub const F_SRCUSER: usize = 5;
pub const F_DSTUSER: usize = 6;
pub const F_PROTOCOL: usize = 7;
pub const F_ACTION: usize = 8;
pub const F_URL: usize = 9;
pub const F_DATA: usize = 10;
pub const F_EXTRA_DATA: usize = 11;
pub const F_STATUS: usize = 12;
pub const F_SYSTEMNAME: usize = 13;
pub const F_SRCGEOIP: usize = 14;
pub const F_DSTGEOIP: usize = 15;
pub const F_LOCATION: usize = 16;
pub const N_FIELDS: usize = 17;

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// `DynamicField`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicField {
    pub key: Bytes,
    /// `NULL` values exist (the syscheck decoders leave unset fields NULL).
    pub value: Option<Bytes>,
}

/// Wall-clock instant (`struct timespec`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeSpec {
    pub sec: i64,
    pub nsec: i64,
}

impl TimeSpec {
    pub fn now() -> Self {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        TimeSpec { sec: d.as_secs() as i64, nsec: d.subsec_nanos() as i64 }
    }
}

/// `Eventinfo`
#[derive(Debug, Clone, Default)]
pub struct Event {
    /// The `full_log` allocation: `full_log` starts at 0 and the working copy
    /// (`log`) at `loglen`. Always NUL terminated.
    pub buf: Bytes,
    /// Offset of `lf->log` in `buf`.
    pub log: usize,
    /// `log_after_parent` / `log_after_prematch` (offsets in `buf`).
    pub log_after_parent: Option<isize>,
    pub log_after_prematch: Option<isize>,
    pub agent_id: Option<Bytes>,
    pub hostname: Option<Bytes>,
    pub program_name: Option<Bytes>,
    pub comment: Option<Bytes>,
    pub dec_timestamp: Option<Bytes>,
    /// Static fields (`srcip` .. `location`), indexed by `F_*`.
    pub f: [Option<Bytes>; N_FIELDS],
    pub fields: Vec<DynamicField>,

    pub generated_rule: Option<RuleId>,
    pub decoder: DecId,
    pub sid_node_to_delete: Option<u64>,
    pub group_node_to_delete: Option<Vec<Option<u64>>>,

    pub size: usize,
    pub p_name_size: usize,
    pub matched: i32,
    pub generate_time: i64,
    pub time: TimeSpec,
    pub day: i32,
    pub year: i32,
    pub hour: String,
    pub mon: String,

    pub previous: Option<Bytes>,
    pub labels: Vec<crate::labels::Label>,
    pub decoder_syscheck_id: u16,
    pub rootcheck_fts: i32,
    pub is_a_copy: bool,
    pub last_events: Option<Vec<Bytes>>,
    pub r_firedtimes: i32,
    pub queue_added: bool,
    pub tid: i32,
    pub prev_rule: Option<RuleId>,
}

/// The C string starting at `off` (up to the first NUL).
pub fn cstr(buf: &[u8], off: usize) -> &[u8] {
    let s = buf.get(off..).unwrap_or(&[]);
    match s.iter().position(|&b| b == 0) {
        Some(n) => &s[..n],
        None => s,
    }
}

/// Byte at `off`, 0 when out of range (the C buffers are NUL padded).
#[inline]
pub fn byte_at(buf: &[u8], off: isize) -> u8 {
    if off < 0 {
        return 0;
    }
    buf.get(off as usize).copied().unwrap_or(0)
}

fn isdigit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// `isValidChar(c) == 1` (the map holds the character itself for invalid
/// ones, so only the value 1 means "valid").
fn is_valid_char(c: u8) -> bool {
    siem_regex::maps::HOSTNAME_MAP[c as usize] == 1
}

/// `wstr_chr_escape`
pub fn wstr_chr_escape(s: &[u8], character: u8, escape: u8) -> Option<usize> {
    let mut escaped = false;
    for (i, &c) in s.iter().enumerate() {
        if c == 0 {
            break;
        }
        if !escaped {
            if c == character {
                return Some(i);
            }
            if c == escape {
                escaped = true;
            }
        } else {
            escaped = false;
        }
    }
    None
}

/// `wstr_unescape` into a buffer of `dst_size` bytes.
pub fn wstr_unescape(s: &[u8], escape: u8, dst_size: usize) -> Bytes {
    let s = cstr(s, 0);
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    loop {
        let mut z = s[i.min(s.len())..].iter().position(|&c| c == escape).unwrap_or(s.len() - i.min(s.len()));
        z = if z + j <= dst_size - 1 { z } else { dst_size - j - 1 };
        out.extend_from_slice(&s[i..i + z]);
        j += z;
        i += z;
        if at(i) != 0 && j < dst_size - 1 {
            if at(i + 1) == escape {
                out.push(at(i));
                j += 1;
                i += 1;
            } else if at(i + 1) == 0 {
                out.push(at(i));
                j += 1;
            }
            i += 1;
        }
        if !(at(i) != 0 && j < dst_size - 1) {
            break;
        }
    }
    out
}

/// `wstr_escape` (escape `match` and the escape char itself).
pub fn wstr_escape(s: &[u8], escape: u8, matchc: u8, dst_size: usize) -> Bytes {
    let s = cstr(s, 0);
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut dst = vec![0u8; dst_size];
    let mut i = 0usize;
    let mut j = 0usize;
    loop {
        let z0 = s[i..].iter().position(|&c| c == escape || c == matchc).unwrap_or(s.len() - i);
        let mut z = z0;
        if at(i + z) == 0 || (j + z) >= (dst_size - 2) {
            z = if z + j <= dst_size - 1 { z } else { dst_size - j - 1 };
            dst[j..j + z].copy_from_slice(&s[i..i + z]);
        } else {
            dst[j..j + z].copy_from_slice(&s[i..i + z]);
            dst[j + z] = escape;
            dst[j + z + 1] = if at(i + z) == escape { escape } else { matchc };
            z += 1;
            j += 1;
        }
        j += z;
        i += z;
        if !(at(i) != 0 && j < dst_size - 2) {
            break;
        }
    }
    dst.truncate(j);
    dst
}

impl Event {
    /// `Zero_Eventinfo`
    pub fn new(null_decoder: DecId) -> Self {
        Event { decoder: null_decoder, r_firedtimes: -1, tid: -1, ..Default::default() }
    }

    pub fn full_log(&self) -> &[u8] {
        cstr(&self.buf, 0)
    }

    pub fn log(&self) -> &[u8] {
        cstr(&self.buf, self.log)
    }

    pub fn location(&self) -> Option<&[u8]> {
        self.f[F_LOCATION].as_deref()
    }

    /// `FindField`: case-insensitive key lookup among the dynamic fields.
    pub fn find_field(&self, key: &[u8]) -> Option<&[u8]> {
        self.fields.iter().find(|f| f.key.eq_ignore_ascii_case(key)).and_then(|f| f.value.as_deref())
    }

    /// `OS_CleanMSG`: parse `"<q>:<location>:<log>"`. `shost` is the manager
    /// short hostname (`__shost`), used as hostname for local events.
    pub fn clean_msg(&mut self, msg: &[u8], shost: &[u8], now: TimeSpec) -> Result<(), &'static str> {
        let msg = cstr(msg, 0);
        // Ignore the id of the message
        let msg = msg.get(2..).unwrap_or(&[]);

        let colon = wstr_chr_escape(msg, b':', b'|').ok_or(crate::logmsg::FORMAT_ERROR)?;
        let location = wstr_unescape(&msg[..colon], b'|', 8192 + 256 + 3);
        self.f[F_LOCATION] = Some(location);

        let pieces_src = &msg[colon + 1..];
        let loglen = pieces_src.len() + 1;

        // full_log and log: two copies in one (2 * loglen + 1) buffer.
        let mut buf = vec![0u8; 2 * loglen + 1];
        buf[..loglen - 1].copy_from_slice(pieces_src);
        buf[loglen..2 * loglen - 1].copy_from_slice(pieces_src);
        let mut log = loglen;

        // `pieces` still points at the original message (not the buffer).
        let mut p: Vec<u8> = pieces_src.to_vec();
        p.resize(p.len() + 64, 0);
        let mut pi = 0usize;

        // Umlaut in the month name (e.g. "Mär"): repaired in the message only.
        if loglen >= 3 && p[1] == 195 && p[2] == 164 {
            p[0] = 0;
            p[1] = b'M';
            p[2] = b'a';
            pi = 1;
        }
        let pc = |i: usize| p[pi + i];

        let mut syslog_ts = false;
        if loglen > 17 && pc(3) == b' ' && pc(6) == b' ' && pc(9) == b':' && pc(12) == b':' && pc(15) == b' ' {
            log += 16;
            syslog_ts = true;
        } else if loglen > 24
            && pc(4) == b'-'
            && pc(7) == b'-'
            && pc(10) == b' '
            && pc(13) == b':'
            && pc(16) == b':'
            && pc(19) == b','
        {
            log += 24;
            syslog_ts = true;
        } else if loglen > 33
            && pc(4) == b'-'
            && pc(7) == b'-'
            && pc(10) == b'T'
            && pc(13) == b':'
            && pc(16) == b':'
            && ((pc(22) == b':' && pc(25) == b' ') || pc(19) == b'.')
        {
            if pc(22) == b':' && pc(25) == b' ' {
                log += 26;
            } else if pc(26) == b':' {
                log += 30;
            } else if pc(29) == b':' {
                log += 33;
            } else {
                log += 32;
            }
            syslog_ts = true;
        } else if loglen > 21
            && isdigit(pc(0))
            && pc(4) == b' '
            && pc(8) == b' '
            && pc(11) == b' '
            && pc(14) == b':'
            && pc(17) == b':'
            && pc(20) == b' '
        {
            log += 21;
            syslog_ts = true;
        } else if loglen > 33
            && isdigit(pc(0))
            && pc(4) == b'-'
            && pc(7) == b'-'
            && pc(10) == b' '
            && pc(13) == b':'
            && pc(16) == b':'
            && pc(19) == b'.'
            && (pc(26) == b'-' || pc(26) == b'+')
            && pc(31) == b' '
        {
            log += 32;
            syslog_ts = true;
        }

        let mut dec_ts: Option<usize> = None;
        let mut hostname: Option<usize> = None;
        let mut program_name: Option<usize> = None;
        let mut owned_program_name: Option<Bytes> = None;

        if syslog_ts {
            dec_ts = Some(loglen);
            buf[log - 1] = 0;

            if buf[log] == b' ' {
                log += 1;
            }

            // Hostname
            hostname = Some(log);
            let mut q = log;
            while is_valid_char(buf[q]) {
                q += 1;
            }
            let pieces: Option<usize>;

            if buf[q] == b':' && byte_at(&buf, q as isize + 1) == b' ' {
                // Syslog without hostname (Solaris 8/9)
                program_name = hostname;
                hostname = None;
                buf[q] = 0;
                q += 2;
                log = q;
                pieces = Some(q);
            } else if buf[q] != b' ' {
                hostname = None;
                pieces = None;
            } else {
                buf[q] = 0;
                q += 1;
                log = q;
                program_name = Some(q);

                while is_valid_char(buf[q]) {
                    q += 1;
                }

                if buf[q] == b':' {
                    buf[q] = 0;
                    q += 1;
                    if buf[q] == b' ' {
                        q += 1;
                    }
                    pieces = Some(q);
                } else if buf[q] == b'[' && isdigit(byte_at(&buf, q as isize + 1)) {
                    buf[q] = 0;
                    q += 2;
                    while isdigit(buf[q]) {
                        q += 1;
                    }
                    if buf[q] == b']' && byte_at(&buf, q as isize + 1) == b':' {
                        q += 2;
                        if buf[q] == b' ' {
                            q += 1;
                        }
                        pieces = Some(q);
                    } else if buf[q] == b']' && byte_at(&buf, q as isize + 1) == b' ' {
                        q += 2;
                        pieces = Some(q);
                    } else {
                        // Fix for some weird log formats
                        q -= 1;
                        while isdigit(buf[q]) {
                            q -= 1;
                        }
                        if buf[q] == 0 {
                            buf[q] = b'[';
                        }
                        pieces = None;
                        program_name = None;
                    }
                } else if buf[q] == b'|' && byte_at(&buf, q as isize + 1).is_ascii_lowercase() {
                    // AIX syslog
                    q += 2;
                    while buf[q].is_ascii_alphanumeric() {
                        q += 1;
                    }
                    if buf[q] == b':' {
                        q += 1;
                        while buf[q].is_ascii_alphanumeric() {
                            q += 1;
                        }
                        if buf[q] == b' ' {
                            q += 1;
                            program_name = Some(q);
                            while is_valid_char(buf[q]) {
                                q += 1;
                            }
                            if buf[q] == b':' && byte_at(&buf, q as isize + 1) == b' ' {
                                buf[q] = 0;
                                q += 2;
                                pieces = Some(q);
                            } else if buf[q] == b'[' && isdigit(byte_at(&buf, q as isize + 1)) {
                                buf[q] = 0;
                                q += 2;
                                while isdigit(buf[q]) {
                                    q += 1;
                                }
                                if buf[q] == b']'
                                    && byte_at(&buf, q as isize + 1) == b':'
                                    && byte_at(&buf, q as isize + 2) == b' '
                                {
                                    q += 3;
                                    pieces = Some(q);
                                } else {
                                    pieces = None;
                                }
                            } else {
                                pieces = Some(q);
                            }
                        } else {
                            pieces = None;
                            program_name = None;
                        }
                    } else {
                        pieces = None;
                        program_name = None;
                    }
                } else {
                    pieces = None;
                    program_name = None;
                }
            }

            // Remove [ID xx facility.severity]
            if let Some(mut q) = pieces {
                log = q;
                if byte_at(&buf, q as isize) == b'['
                    && byte_at(&buf, q as isize + 1) == b'I'
                    && byte_at(&buf, q as isize + 2) == b'D'
                    && byte_at(&buf, q as isize + 3) == b' '
                {
                    q += 4;
                    let rest = cstr(&buf, q);
                    if let Some(r) = rest.iter().position(|&c| c == b']') {
                        log = q + r + 2;
                    }
                }
            }

            if let Some(pn) = program_name {
                self.p_name_size = cstr(&buf, pn).len();
            }
        } else if loglen > 28
            && pc(3) == b' '
            && pc(7) == b' '
            && pc(10) == b' '
            && pc(13) == b':'
            && pc(16) == b':'
            && pc(19) == b' '
            && pc(24) == b' '
            && pc(26) == b' '
        {
            // xferlog date format
            log += 25;
            dec_ts = Some(loglen);
            buf[log - 1] = 0;
        } else if loglen > 24
            && pc(2) == b'/'
            && pc(5) == b'-'
            && pc(8) == b':'
            && pc(11) == b':'
            && pc(14) == b'.'
            && pc(21) == b' '
        {
            // snort date format
            log += 23;
            dec_ts = Some(loglen);
            buf[log - 2] = 0;
        } else if loglen > 28
            && pc(2) == b'/'
            && pc(5) == b'/'
            && pc(10) == b'-'
            && pc(13) == b':'
            && pc(16) == b':'
            && pc(19) == b'.'
            && pc(26) == b' '
        {
            // suricata (new) date format
            log += 28;
            dec_ts = Some(loglen);
            buf[log - 2] = 0;
        } else if loglen > 27
            && pc(0) == b'['
            && pc(4) == b' '
            && pc(8) == b' '
            && pc(11) == b' '
            && pc(14) == b':'
            && pc(17) == b':'
            && pc(20) == b' '
            && pc(25) == b']'
        {
            // apache log format
            log += 27;
            dec_ts = Some(loglen + 1);
            buf[log - 2] = 0;
        } else if loglen > 26
            && pc(0) == b'['
            && pc(1) == b'T'
            && pc(5) == b' '
            && pc(10) == b'.'
            && pc(13) == b'.'
            && pc(16) == b' '
            && pc(19) == b':'
        {
            // osx asl log format
            let mut done_message = false;
            log += 25;
            let mut pieces = cstr(&buf, log).iter().position(|&c| c == b'[').map(|r| log + r);
            while let Some(mut q) = pieces {
                q += 1;
                let rest = cstr(&buf, q);
                if rest.starts_with(b"Sender ") && program_name.is_none() && owned_program_name.is_none() {
                    q += 7;
                    program_name = Some(q);
                    match cstr(&buf, q).iter().position(|&c| c == b']') {
                        Some(r) => {
                            buf[q + r] = 0;
                            self.p_name_size = r;
                            q = q + r + 1;
                        }
                        None => {
                            program_name = None;
                            break;
                        }
                    }
                } else if rest.starts_with(b"Message ") && !done_message {
                    q += 8;
                    done_message = true;
                    log = q;
                    match cstr(&buf, q).iter().position(|&c| c == b']') {
                        Some(r) => {
                            buf[q + r] = 0;
                            q = q + r + 1;
                        }
                        None => break,
                    }
                } else if rest.starts_with(b"Host ") {
                    q += 5;
                    hostname = Some(q);
                    match cstr(&buf, q).iter().position(|&c| c == b']') {
                        Some(r) => {
                            buf[q + r] = 0;
                        }
                        None => hostname = None,
                    }
                    break;
                }
                pieces = cstr(&buf, q).iter().position(|&c| c == b'[').map(|r| q + r);
            }
        } else if loglen > 32
            && pc(0) == b'1'
            && isdigit(pc(1))
            && isdigit(pc(2))
            && isdigit(pc(3))
            && pc(10) == b'.'
            && isdigit(pc(13))
            && pc(14) == b' '
            && (pc(21) == b' ' || pc(22) == b' ')
        {
            // squid date format
            log += 14;
            while buf[log] == b' ' {
                log += 1;
            }
            dec_ts = Some(loglen);
            buf[log - 1] = 0;
        }

        let _ = &mut owned_program_name;
        self.dec_timestamp = dec_ts.map(|o| cstr(&buf, o).to_vec());
        self.program_name = program_name.map(|o| cstr(&buf, o).to_vec());
        let hostname_v = hostname.map(|o| cstr(&buf, o).to_vec());
        self.buf = buf;
        self.log = log;

        // Every message must be "hostname->location" or "[id] (agent) ip->location".
        let loc = self.f[F_LOCATION].take().unwrap_or_default();
        if loc.first() == Some(&b'[') {
            let after = &loc[1..];
            let close = match after.iter().position(|&c| c == b']') {
                Some(c) => c,
                None => {
                    self.f[F_LOCATION] = Some(loc);
                    self.agent_id = None;
                    self.hostname = None;
                    return Err(crate::logmsg::FORMAT_ERROR);
                }
            };
            let agent_id = after[..close].to_vec();
            let rest = &after[close..]; // starts at ']'
            let new_loc = if rest.len() > 1 { rest[2.min(rest.len())..].to_vec() } else { Vec::new() };
            let hostname = if new_loc.first() == Some(&b'(') {
                let mut h = new_loc[1..].to_vec();
                match h.iter().position(|&c| c == b')') {
                    Some(e) => h.truncate(e),
                    None => h.clear(),
                }
                h
            } else {
                Vec::new()
            };
            self.agent_id = Some(agent_id);
            self.f[F_LOCATION] = Some(new_loc);
            self.hostname = Some(hostname);
        } else {
            self.f[F_LOCATION] = Some(loc);
            self.hostname = Some(hostname_v.unwrap_or_else(|| shost.to_vec()));
            self.agent_id = Some(b"000".to_vec());
        }

        self.set_time(now);
        Ok(())
    }

    /// The time-related part of `OS_CleanMSG`.
    pub fn set_time(&mut self, now: TimeSpec) {
        use chrono::{Datelike, Timelike};
        self.generate_time = now.sec;
        self.time = now;
        let lt = crate::localtime::at(now.sec);
        self.day = lt.day() as i32;
        self.year = lt.year();
        self.mon = MONTHS[lt.month0() as usize].to_string();
        self.hour = format!("{:02}:{:02}:{:02}", lt.hour(), lt.minute(), lt.second());
    }

    /// `ParseRuleComment`: expand `$(field)` in the rule description.
    pub fn parse_rule_comment(&self, comment: &[u8]) -> Bytes {
        const MAX: usize = 1024;
        let orig: Vec<u8> = cstr(comment, 0)[..cstr(comment, 0).len().min(MAX)].to_vec();
        let mut fin: Vec<u8> = Vec::new();
        let mut n = 0usize;
        let mut pos = 0usize;
        loop {
            let tok = match find_sub(&orig[pos..], b"$(") {
                Some(t) => pos + t,
                None => break,
            };
            let s = &orig[pos..tok];
            let z = s.len();
            if n + z >= MAX {
                return comment.to_vec();
            }
            fin.extend_from_slice(s);
            n += z;
            let var_start = tok + 2;
            let end = match orig[var_start..].iter().position(|&c| c == b')') {
                Some(e) => var_start + e,
                None => {
                    // `*tok = '$'; str = tok;` -> the rest is appended as is
                    pos = tok;
                    break;
                }
            };
            let var = &orig[var_start..end];
            pos = end + 1;
            let field: Option<&[u8]> = match var {
                b"dstuser" => self.f[F_DSTUSER].as_deref(),
                b"srcuser" => self.f[F_SRCUSER].as_deref(),
                b"srcip" => self.f[F_SRCIP].as_deref(),
                b"dstip" => self.f[F_DSTIP].as_deref(),
                b"srcgeoip" if crate::GEOIP_ENABLED => self.f[F_SRCGEOIP].as_deref(),
                b"dstgeoip" if crate::GEOIP_ENABLED => self.f[F_DSTGEOIP].as_deref(),
                b"srcport" => self.f[F_SRCPORT].as_deref(),
                b"dstport" => self.f[F_DSTPORT].as_deref(),
                b"protocol" => self.f[F_PROTOCOL].as_deref(),
                b"action" => self.f[F_ACTION].as_deref(),
                b"id" => self.f[F_ID].as_deref(),
                b"url" => self.f[F_URL].as_deref(),
                b"data" => self.f[F_DATA].as_deref(),
                b"status" => self.f[F_STATUS].as_deref(),
                b"extra_data" => self.f[F_EXTRA_DATA].as_deref(),
                b"system_name" => self.f[F_SYSTEMNAME].as_deref(),
                b"program_name" => self.program_name.as_deref(),
                b"hostname" => self.hostname.as_deref(),
                _ => self.find_field(var),
            };
            if let Some(f) = field {
                let z = f.len();
                if n + z >= MAX {
                    return comment.to_vec();
                }
                fin.extend_from_slice(f);
                n += z;
            }
        }
        let s = &orig[pos..];
        if n + s.len() >= MAX {
            return comment.to_vec();
        }
        fin.extend_from_slice(s);
        fin
    }
}

pub fn find_sub(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() {
        return Some(0);
    }
    h.windows(n.len()).position(|w| w == n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(m: &str) -> Event {
        let mut e = Event::new(0);
        e.clean_msg(m.as_bytes(), b"manager", TimeSpec { sec: 1_700_000_000, nsec: 0 }).unwrap();
        e
    }

    #[test]
    fn syslog_header() {
        let e = clean("1:stdin:Dec 29 10:00:01 myhost sshd[123]: Accepted password");
        assert_eq!(e.hostname.as_deref(), Some(&b"myhost"[..]));
        assert_eq!(e.program_name.as_deref(), Some(&b"sshd"[..]));
        assert_eq!(e.log(), b"Accepted password");
        assert_eq!(e.dec_timestamp.as_deref(), Some(&b"Dec 29 10:00:01"[..]));
        assert_eq!(e.full_log(), b"Dec 29 10:00:01 myhost sshd[123]: Accepted password");
        assert_eq!(e.agent_id.as_deref(), Some(&b"000"[..]));
    }

    #[test]
    fn agent_location() {
        let e = clean("1:[001] (agent1) 10.0.0.1->/var/log/auth.log:hello world");
        assert_eq!(e.agent_id.as_deref(), Some(&b"001"[..]));
        assert_eq!(e.location(), Some(&b"(agent1) 10.0.0.1->/var/log/auth.log"[..]));
        assert_eq!(e.hostname.as_deref(), Some(&b"agent1"[..]));
        assert_eq!(e.log(), b"hello world");
        assert_eq!(e.hostname.as_deref(), Some(&b"agent1"[..]));
    }

    #[test]
    fn escape_roundtrip() {
        let esc = wstr_escape(b"a:b|c", b'|', b':', 100);
        assert_eq!(esc, b"a|:b||c");
        assert_eq!(wstr_unescape(&esc, b'|', 100), b"a:b|c");
    }
}
