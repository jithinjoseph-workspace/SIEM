//! An event: the cleaned message (location, agent, syslog header) and everything the decoders
//! and rules add to it (spec section 2.4).
//!
//! The log is kept twice in one buffer, `full_log` at 0 and the working copy at `log_start`
//! (the length of the log plus one). Header parsing ends texts by writing zero bytes into the
//! working copy, and the decoders keep positions into it (`log`, after the parent, after the
//! prematch), so positions are offsets into [`Event::buf`] and every text ends at a zero byte.

pub type Bytes = Vec<u8>;
pub type DecoderId = usize;
pub type RuleId = usize;

// Event types a decoder may set.
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

// First-time-seen field flags.
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

// The fixed fields, in this order everywhere (also the bit order of the rule field flags).
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

/// GeoIP lookups are not built in: `$(srcgeoip)` and `$(dstgeoip)` stay empty.
pub const GEOIP: bool = false;

pub const FORMAT_ERROR: &str = "(1106): String not correctly formatted.";

/// A named field set by a decoder; the file integrity decoder leaves some without value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicField {
    pub key: Bytes,
    pub value: Option<Bytes>,
}

/// An agent label attached to the event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Label {
    pub key: Bytes,
    pub value: Bytes,
    pub hidden: bool,
    pub system: bool,
}

/// Seconds and nanoseconds since 1970.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Instant {
    pub sec: i64,
    pub nsec: i64,
}

impl Instant {
    pub fn now() -> Instant {
        let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        Instant { sec: d.as_secs() as i64, nsec: i64::from(d.subsec_nanos()) }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Event {
    /// `full_log`, a zero, the working copy, a zero, a zero.
    pub buf: Bytes,
    /// Where the log the decoders read starts.
    pub log_start: usize,
    pub after_parent: Option<isize>,
    pub after_prematch: Option<isize>,
    pub agent_id: Option<Bytes>,
    pub hostname: Option<Bytes>,
    pub program_name: Option<Bytes>,
    pub comment: Option<Bytes>,
    pub dec_timestamp: Option<Bytes>,
    /// The fixed fields, by `F_*`.
    pub f: [Option<Bytes>; N_FIELDS],
    pub fields: Vec<DynamicField>,

    pub generated_rule: Option<RuleId>,
    pub decoder: DecoderId,
    pub sid_node_to_delete: Option<u64>,
    pub group_node_to_delete: Option<Vec<Option<u64>>>,

    pub size: usize,
    pub program_name_size: usize,
    pub matched: i32,
    pub generate_time: i64,
    pub time: Instant,
    pub day: i32,
    pub year: i32,
    pub hour: String,
    pub mon: String,

    pub previous: Option<Bytes>,
    pub labels: Vec<Label>,
    pub decoder_syscheck_id: u16,
    pub rootcheck_fts: i32,
    pub is_a_copy: bool,
    pub last_events: Option<Vec<Bytes>>,
    pub fired_times: i32,
    pub queue_added: bool,
    pub tid: i32,
    pub prev_rule: Option<RuleId>,
}

/// The text at `at` up to the first zero byte.
pub fn text_at(buf: &[u8], at: usize) -> &[u8] {
    let s = buf.get(at..).unwrap_or(&[]);
    &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
}

/// The byte at `at`; zero outside the buffer.
#[inline]
pub fn byte(buf: &[u8], at: isize) -> u8 {
    if at < 0 {
        0
    } else {
        buf.get(at as usize).copied().unwrap_or(0)
    }
}

fn host_char(c: u8) -> bool {
    provigil_regex::maps::HOSTNAME_MAP[c as usize] == 1
}

/// The first `c` not escaped by `escape`, before any zero byte.
pub fn find_unescaped(s: &[u8], c: u8, escape: u8) -> Option<usize> {
    let mut escaped = false;
    for (i, &b) in s.iter().enumerate() {
        if b == 0 {
            return None;
        }
        if escaped {
            escaped = false;
        } else if b == c {
            return Some(i);
        } else if b == escape {
            escaped = true;
        }
    }
    None
}

/// Removes one `escape` before each byte, keeping at most `room - 1` bytes; an `escape` at
/// the very end stays.
pub fn unescape(s: &[u8], escape: u8, room: usize) -> Bytes {
    let s = text_at(s, 0);
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() && out.len() < room - 1 {
        if s[i] == escape && i + 1 < s.len() {
            i += 1;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Puts `escape` before each `c` and each `escape`, in at most `room - 1` bytes; a pair that
/// would not fit in `room - 2` bytes ends the text (the rest copied without escapes, cut).
pub fn escape(s: &[u8], escape: u8, c: u8, room: usize) -> Bytes {
    let s = text_at(s, 0);
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let run = s[i..].iter().position(|&b| b == escape || b == c).unwrap_or(s.len() - i);
        if i + run == s.len() || out.len() + run >= room - 2 {
            let n = run.min(room - 1 - out.len());
            out.extend_from_slice(&s[i..i + n]);
            break;
        }
        out.extend_from_slice(&s[i..i + run]);
        out.extend_from_slice(&[escape, s[i + run]]);
        i += run + 1;
        if i >= s.len() || out.len() >= room - 2 {
            break;
        }
    }
    out
}

pub fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() {
        return Some(0);
    }
    h.windows(n.len()).position(|w| w == n)
}

/// The known log headers, by their fixed characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Header {
    /// a syslog-style time stamp of this many bytes, then host and program
    Syslog(usize),
    Xferlog,
    Snort,
    Suricata,
    Apache,
    MacAsl,
    Squid,
    None,
}

/// `at(i)`: the i-th byte of the log (zero past its end).
fn header(at: impl Fn(usize) -> u8, len: usize) -> Header {
    let is = |i: usize, c: u8| at(i) == c;
    let digit = |i: usize| at(i).is_ascii_digit();
    let marks = |m: &[(usize, u8)]| m.iter().all(|&(i, c)| is(i, c));
    if len > 17 && marks(&[(3, b' '), (6, b' '), (9, b':'), (12, b':'), (15, b' ')]) {
        // Dec 29 10:00:01
        return Header::Syslog(16);
    }
    if len > 24 && marks(&[(4, b'-'), (7, b'-'), (10, b' '), (13, b':'), (16, b':'), (19, b',')]) {
        // 2007-06-14 15:48:55,123
        return Header::Syslog(24);
    }
    if len > 33 && marks(&[(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')]) && (marks(&[(22, b':'), (25, b' ')]) || is(19, b'.')) {
        // ISO 8601 with a zone, with or without fractions
        return Header::Syslog(if marks(&[(22, b':'), (25, b' ')]) {
            26
        } else if is(26, b':') {
            30
        } else if is(29, b':') {
            33
        } else {
            32
        });
    }
    if len > 21 && digit(0) && marks(&[(4, b' '), (8, b' '), (11, b' '), (14, b':'), (17, b':'), (20, b' ')]) {
        // 2007 Jun 14 15:48:55
        return Header::Syslog(21);
    }
    if len > 33 && digit(0) && marks(&[(4, b'-'), (7, b'-'), (10, b' '), (13, b':'), (16, b':'), (19, b'.'), (31, b' ')]) && (is(26, b'-') || is(26, b'+')) {
        // 2007-06-14 15:48:55.123456+02:00
        return Header::Syslog(32);
    }
    if len > 28 && marks(&[(3, b' '), (7, b' '), (10, b' '), (13, b':'), (16, b':'), (19, b' '), (24, b' '), (26, b' ')]) {
        return Header::Xferlog;
    }
    if len > 24 && marks(&[(2, b'/'), (5, b'-'), (8, b':'), (11, b':'), (14, b'.'), (21, b' ')]) {
        return Header::Snort;
    }
    if len > 28 && marks(&[(2, b'/'), (5, b'/'), (10, b'-'), (13, b':'), (16, b':'), (19, b'.'), (26, b' ')]) {
        return Header::Suricata;
    }
    if len > 27 && marks(&[(0, b'['), (4, b' '), (8, b' '), (11, b' '), (14, b':'), (17, b':'), (20, b' '), (25, b']')]) {
        return Header::Apache;
    }
    if len > 26 && marks(&[(0, b'['), (1, b'T'), (5, b' '), (10, b'.'), (13, b'.'), (16, b' '), (19, b':')]) {
        return Header::MacAsl;
    }
    if len > 32 && is(0, b'1') && digit(1) && digit(2) && digit(3) && is(10, b'.') && digit(13) && is(14, b' ') && (is(21, b' ') || is(22, b' ')) {
        return Header::Squid;
    }
    Header::None
}

impl Event {
    pub fn new(null_decoder: DecoderId) -> Event {
        Event { decoder: null_decoder, fired_times: -1, tid: -1, ..Event::default() }
    }

    pub fn full_log(&self) -> &[u8] {
        text_at(&self.buf, 0)
    }

    pub fn log(&self) -> &[u8] {
        text_at(&self.buf, self.log_start)
    }

    pub fn location(&self) -> Option<&[u8]> {
        self.f[F_LOCATION].as_deref()
    }

    /// A dynamic field by name, without case.
    pub fn field(&self, key: &[u8]) -> Option<&[u8]> {
        self.fields.iter().find(|f| f.key.eq_ignore_ascii_case(key)).and_then(|f| f.value.as_deref())
    }

    /// Reads `<queue>:<location>:<log>`: the location (with `|` escapes), the agent from
    /// `[id] (name) ip->...` locations, and a known header at the start of the log.
    /// `manager` is the host name of local events.
    pub fn clean(&mut self, msg: &[u8], manager: &[u8], now: Instant) -> Result<(), &'static str> {
        let msg = text_at(msg, 0).get(2..).unwrap_or(&[]);
        let colon = find_unescaped(msg, b':', b'|').ok_or(FORMAT_ERROR)?;
        let location = unescape(&msg[..colon], b'|', 8192 + 256 + 3);
        let src = &msg[colon + 1..];
        let len = src.len() + 1;
        let mut buf = vec![0u8; 2 * len + 1];
        buf[..len - 1].copy_from_slice(src);
        buf[len..2 * len - 1].copy_from_slice(src);
        let mut log = len;

        // The header is recognised on the message, where a two-byte "ä" in the month
        // ("Mär") is read as "Mar" one byte further on; the positions stay those of the buffer.
        let shifted = len >= 3 && src.get(1) == Some(&195) && src.get(2) == Some(&164);
        let at = |i: usize| -> u8 {
            if shifted {
                match i {
                    0 => b'M',
                    1 => b'a',
                    _ => src.get(i + 1).copied().unwrap_or(0),
                }
            } else {
                src.get(i).copied().unwrap_or(0)
            }
        };

        let mut stamp = None;
        let mut host = None;
        let mut program = None;
        match header(at, len) {
            Header::Syslog(skip) => {
                log += skip;
                stamp = Some(len);
                buf[log - 1] = 0;
                if buf[log] == b' ' {
                    log += 1;
                }
                let (h, p, rest) = syslog_host_program(&mut buf, log);
                host = h;
                program = p;
                log = match rest {
                    Some(q) => skip_id(&buf, q),
                    None => syslog_log_start(&buf, log, h),
                };
                if let Some(p) = program {
                    self.program_name_size = text_at(&buf, p).len();
                }
            }
            Header::Xferlog => {
                log += 25;
                stamp = Some(len);
                buf[log - 1] = 0;
            }
            Header::Snort => {
                log += 23;
                stamp = Some(len);
                buf[log - 2] = 0;
            }
            Header::Suricata => {
                log += 28;
                stamp = Some(len);
                buf[log - 2] = 0;
            }
            Header::Apache => {
                log += 27;
                stamp = Some(len + 1);
                buf[log - 2] = 0;
            }
            Header::MacAsl => {
                log += 25;
                let (h, p, l) = mac_asl(&mut buf, log, &mut self.program_name_size);
                host = h;
                program = p;
                log = l;
            }
            Header::Squid => {
                log += 14;
                while buf[log] == b' ' {
                    log += 1;
                }
                stamp = Some(len);
                buf[log - 1] = 0;
            }
            Header::None => {}
        }

        self.dec_timestamp = stamp.map(|o| text_at(&buf, o).to_vec());
        self.program_name = program.map(|o| text_at(&buf, o).to_vec());
        let host = host.map(|o| text_at(&buf, o).to_vec());
        self.buf = buf;
        self.log_start = log;

        // "[id] (name) ip->where" from agents; anything else is local
        if location.first() == Some(&b'[') {
            let Some(close) = location.iter().position(|&c| c == b']') else {
                self.f[F_LOCATION] = Some(location);
                self.agent_id = None;
                self.hostname = None;
                return Err(FORMAT_ERROR);
            };
            let rest = location.get(close + 2..).unwrap_or(&[]).to_vec();
            let name = match rest.strip_prefix(b"(") {
                Some(r) => r[..r.iter().position(|&c| c == b')').unwrap_or(0)].to_vec(),
                None => Vec::new(),
            };
            self.agent_id = Some(location[1..close].to_vec());
            self.f[F_LOCATION] = Some(rest);
            self.hostname = Some(name);
        } else {
            self.f[F_LOCATION] = Some(location);
            self.hostname = Some(host.unwrap_or_else(|| manager.to_vec()));
            self.agent_id = Some(b"000".to_vec());
        }
        self.set_time(now);
        Ok(())
    }

    /// The event time and its local day, year, month and hour texts.
    pub fn set_time(&mut self, now: Instant) {
        self.generate_time = now.sec;
        self.time = now;
        let t = crate::time::local(now.sec).unwrap_or(crate::time::Tm { year: 1970, mon: 0, mday: 1, hour: 0, min: 0, sec: 0, wday: 4, gmtoff: 0 });
        self.day = t.mday as i32;
        self.year = t.year as i32;
        self.mon = crate::time::MONTHS[t.mon as usize].to_string();
        self.hour = format!("{:02}:{:02}:{:02}", t.hour, t.min, t.sec);
    }

    /// The rule description with each `$(name)` replaced by the field's value (unknown or
    /// unset: nothing); the description as written when the result would reach 1,024 bytes
    /// or more.
    pub fn expand_comment(&self, comment: &[u8]) -> Bytes {
        const MAX: usize = 1024;
        let c = text_at(comment, 0);
        let src = &c[..c.len().min(MAX)];
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some(t) = find(&src[pos..], b"$(") {
            let t = pos + t;
            out.extend_from_slice(&src[pos..t]);
            if out.len() >= MAX {
                return comment.to_vec();
            }
            let Some(e) = src[t + 2..].iter().position(|&b| b == b')') else {
                pos = t;
                break;
            };
            let name = &src[t + 2..t + 2 + e];
            pos = t + 3 + e;
            if let Some(v) = self.named(name) {
                out.extend_from_slice(v);
                if out.len() >= MAX {
                    return comment.to_vec();
                }
            }
        }
        out.extend_from_slice(&src[pos..]);
        if out.len() >= MAX {
            return comment.to_vec();
        }
        out
    }

    /// A field by the name rules use for it.
    fn named(&self, name: &[u8]) -> Option<&[u8]> {
        let fixed = match name {
            b"dstuser" => F_DSTUSER,
            b"srcuser" => F_SRCUSER,
            b"srcip" => F_SRCIP,
            b"dstip" => F_DSTIP,
            b"srcgeoip" if GEOIP => F_SRCGEOIP,
            b"dstgeoip" if GEOIP => F_DSTGEOIP,
            b"srcport" => F_SRCPORT,
            b"dstport" => F_DSTPORT,
            b"protocol" => F_PROTOCOL,
            b"action" => F_ACTION,
            b"id" => F_ID,
            b"url" => F_URL,
            b"data" => F_DATA,
            b"status" => F_STATUS,
            b"extra_data" => F_EXTRA_DATA,
            b"system_name" => F_SYSTEMNAME,
            b"program_name" => return self.program_name.as_deref(),
            b"hostname" => return self.hostname.as_deref(),
            _ => return self.field(name),
        };
        self.f[fixed].as_deref()
    }
}

/// After a syslog time stamp at `start`: (host, program, where the message starts). Zero
/// bytes end the host and the program in `buf`. No message start: the header did not end
/// as expected.
fn syslog_host_program(buf: &mut [u8], start: usize) -> (Option<usize>, Option<usize>, Option<usize>) {
    let at = |buf: &[u8], i: usize| byte(buf, i as isize);
    let mut q = start;
    while host_char(buf[q]) {
        q += 1;
    }
    if buf[q] == b':' && at(buf, q + 1) == b' ' {
        // no host (Solaris 8/9): what was read is the program
        buf[q] = 0;
        return (None, Some(start), Some(q + 2));
    }
    if buf[q] != b' ' {
        return (None, None, None);
    }
    let host = Some(start);
    buf[q] = 0;
    q += 1;
    let program = q;
    while host_char(buf[q]) {
        q += 1;
    }
    match buf[q] {
        b':' => {
            buf[q] = 0;
            q += 1;
            if buf[q] == b' ' {
                q += 1;
            }
            (host, Some(program), Some(q))
        }
        b'[' if at(buf, q + 1).is_ascii_digit() => {
            buf[q] = 0;
            q += 2;
            while buf[q].is_ascii_digit() {
                q += 1;
            }
            if buf[q] == b']' && at(buf, q + 1) == b':' {
                q += 2;
                if buf[q] == b' ' {
                    q += 1;
                }
                (host, Some(program), Some(q))
            } else if buf[q] == b']' && at(buf, q + 1) == b' ' {
                (host, Some(program), Some(q + 2))
            } else {
                // not a pid after all: put the bracket back
                q -= 1;
                while buf[q].is_ascii_digit() {
                    q -= 1;
                }
                if buf[q] == 0 {
                    buf[q] = b'[';
                }
                (host, None, None)
            }
        }
        b'|' if at(buf, q + 1).is_ascii_lowercase() => {
            // AIX: host|facility:level program...
            q += 2;
            while buf[q].is_ascii_alphanumeric() {
                q += 1;
            }
            if buf[q] != b':' {
                return (host, None, None);
            }
            q += 1;
            while buf[q].is_ascii_alphanumeric() {
                q += 1;
            }
            if buf[q] != b' ' {
                return (host, None, None);
            }
            q += 1;
            let program = q;
            while host_char(buf[q]) {
                q += 1;
            }
            if buf[q] == b':' && at(buf, q + 1) == b' ' {
                buf[q] = 0;
                (host, Some(program), Some(q + 2))
            } else if buf[q] == b'[' && at(buf, q + 1).is_ascii_digit() {
                buf[q] = 0;
                q += 2;
                while buf[q].is_ascii_digit() {
                    q += 1;
                }
                if buf[q] == b']' && at(buf, q + 1) == b':' && at(buf, q + 2) == b' ' {
                    (host, Some(program), Some(q + 3))
                } else {
                    (host, Some(program), None)
                }
            } else {
                (host, Some(program), Some(q))
            }
        }
        _ => (host, None, None),
    }
}

/// After `[ID nnn facility.severity] ` when the message starts with it.
fn skip_id(buf: &[u8], q: usize) -> usize {
    if text_at(buf, q).starts_with(b"[ID ") {
        if let Some(r) = text_at(buf, q + 4).iter().position(|&c| c == b']') {
            return q + 4 + r + 2;
        }
    }
    q
}

/// Where the log starts when the syslog header did not end as expected: after the host when
/// one was read, else where it was.
fn syslog_log_start(buf: &[u8], log: usize, host: Option<usize>) -> usize {
    match host {
        Some(h) => h + text_at(buf, h).len() + 1,
        None => log,
    }
}

/// The macOS system log header after its time: `[Sender x]`, `[Message y]` and `[Host z]`
/// parts. Returns (host, program, log start).
fn mac_asl(buf: &mut [u8], mut log: usize, program_size: &mut usize) -> (Option<usize>, Option<usize>, usize) {
    let (mut host, mut program) = (None, None);
    let mut message_seen = false;
    let mut next = text_at(buf, log).iter().position(|&c| c == b'[').map(|r| log + r);
    while let Some(open) = next {
        let mut q = open + 1;
        let rest = text_at(buf, q);
        if rest.starts_with(b"Sender ") && program.is_none() {
            q += 7;
            match text_at(buf, q).iter().position(|&c| c == b']') {
                Some(r) => {
                    program = Some(q);
                    buf[q + r] = 0;
                    *program_size = r;
                    q += r + 1;
                }
                None => break,
            }
        } else if rest.starts_with(b"Message ") && !message_seen {
            q += 8;
            message_seen = true;
            log = q;
            match text_at(buf, q).iter().position(|&c| c == b']') {
                Some(r) => {
                    buf[q + r] = 0;
                    q += r + 1;
                }
                None => break,
            }
        } else if rest.starts_with(b"Host ") {
            q += 5;
            if let Some(r) = text_at(buf, q).iter().position(|&c| c == b']') {
                buf[q + r] = 0;
                host = Some(q);
            }
            break;
        }
        next = text_at(buf, q).iter().position(|&c| c == b'[').map(|r| q + r);
    }
    (host, program, log)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(m: &str) -> Event {
        let mut e = Event::new(0);
        e.clean(m.as_bytes(), b"manager", Instant { sec: 1_700_000_000, nsec: 0 }).unwrap();
        e
    }

    #[test]
    fn headers_and_locations() {
        let e = clean("1:stdin:Dec 29 10:00:01 myhost sshd[123]: Accepted password");
        assert_eq!((e.hostname.as_deref(), e.program_name.as_deref()), (Some(&b"myhost"[..]), Some(&b"sshd"[..])));
        assert_eq!((e.log(), e.dec_timestamp.as_deref()), (&b"Accepted password"[..], Some(&b"Dec 29 10:00:01"[..])));
        let e = clean("1:[001] (agent1) 10.0.0.1->/var/log/auth.log:hello world");
        assert_eq!((e.agent_id.as_deref(), e.hostname.as_deref()), (Some(&b"001"[..]), Some(&b"agent1"[..])));
        assert_eq!(e.location(), Some(&b"(agent1) 10.0.0.1->/var/log/auth.log"[..]));
        assert_eq!(escape(b"a:b|c", b'|', b':', 100), b"a|:b||c");
        assert_eq!(unescape(b"a|:b||c", b'|', 100), b"a:b|c");
    }
}
