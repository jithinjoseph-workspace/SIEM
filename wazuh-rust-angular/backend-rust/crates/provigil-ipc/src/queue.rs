//! Messages to the detection engine's event queue (`queue/sockets/queue`): `<queue>:<location>:
//! <message>`, the location's `|` and `:` written as `||` and `|:`. Messages relayed from an
//! agent carry their own queue and location: `<queue>:<agent>-><location>:<message>`.

/// Queue identifiers: what kind of event a message is.
pub mod ids {
    pub const LOCALFILE: u8 = b'1';
    pub const SYSLOG: u8 = b'2';
    pub const HOSTINFO: u8 = b'3';
    pub const SECURE: u8 = b'4';
    pub const DBSYNC: u8 = b'5';
    pub const SYSCHECK: u8 = b'8';
    pub const ROOTCHECK: u8 = b'9';
    pub const SYSCOLLECTOR: u8 = b'd';
    pub const CISCAT: u8 = b'e';
    pub const WIN_EVT: u8 = b'f';
    pub const SCA: u8 = b'p';
    pub const UPGRADE: u8 = b'u';
}

/// The engine's event queue (relative to the home folder).
pub const EVENT_QUEUE: &str = "queue/sockets/queue";
/// Active responses for ProVigil agents, which siem-api reads and hands to their keepalive.
pub const AGENT_AR_QUEUE: &str = "queue/alerts/provigil-ar";
/// Room for an escaped location (the result has at most `LOCATION_ROOM - 1` bytes).
pub const LOCATION_ROOM: usize = 8193;

/// `|` and `:` of `s` written as `||` and `|:` (the text ends at a NUL byte). The result fits in
/// `room - 1` bytes: a run of plain bytes is cut at that size, and an escape pair is written only
/// while at least three bytes are left; once a pair leaves fewer than three, writing stops.
pub fn escape(s: &[u8], room: usize) -> Vec<u8> {
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    let special = |c: u8| c == b'|' || c == b':';
    let mut out = Vec::with_capacity(s.len().min(room));
    let mut i = 0;
    loop {
        let run = s[i..].iter().take_while(|&&c| !special(c)).count();
        let at_end = i + run == s.len();
        if at_end || out.len() + run + 2 >= room {
            // the last run, or no room for another pair: plain bytes up to the limit, then stop
            let take = run.min(room.saturating_sub(1).saturating_sub(out.len()));
            out.extend_from_slice(&s[i..i + take]);
            break;
        }
        out.extend_from_slice(&s[i..i + run]);
        out.push(b'|');
        out.push(s[i + run]);
        i += run + 1;
        if i == s.len() || out.len() + 2 >= room {
            break;
        }
    }
    out
}

/// One event message. `location` is escaped. For [`ids::SECURE`] the message is an agent's own
/// `<queue>:<location>:<text>` and the result `<queue>:<location escaped>-><agent location>:
/// <text>`; it is None when that message is malformed or a keepalive. At most 65,535 bytes.
pub fn message(text: &[u8], location: &str, queue: u8) -> Option<Vec<u8>> {
    let loc = escape(location.as_bytes(), LOCATION_ROOM);
    let mut out = Vec::with_capacity(text.len() + loc.len() + 8);
    if queue == ids::SECURE {
        let q = *text.first()?;
        if text.get(1) != Some(&b':') {
            return None;
        }
        let rest = &text[2..];
        if rest.starts_with(b"keepalive") {
            return None;
        }
        out.push(q);
        out.push(b':');
        out.extend_from_slice(&loc);
        out.extend_from_slice(b"->");
        out.extend_from_slice(rest);
    } else {
        out.push(queue);
        out.push(b':');
        out.extend_from_slice(&loc);
        out.push(b':');
        out.extend_from_slice(text);
    }
    out.truncate(crate::MAX_MESSAGE - 1);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_formats() {
        assert_eq!(escape(b"[001] (agent) any->/var/log", LOCATION_ROOM), b"[001] (agent) any->/var/log");
        assert_eq!(escape(b"C:\\Windows|x", LOCATION_ROOM), b"C|:\\Windows||x");
        assert_eq!(escape(b"::", LOCATION_ROOM), b"|:|:");
        assert_eq!(escape(b"a\0:b", LOCATION_ROOM), b"a");
        let m = message(b"1:/var/log/syslog:Oct  5 sshd: x", "[001] (web01) 10.0.0.5", ids::SECURE).unwrap();
        assert_eq!(m, b"1:[001] (web01) 10.0.0.5->/var/log/syslog:Oct  5 sshd: x");
        assert!(message(b"1:keepalive:x", "[001] (a) any", ids::SECURE).is_none());
        assert!(message(b"1x", "a", ids::SECURE).is_none());
        assert_eq!(message(b"<13>hello", "10.0.0.1", ids::SYSLOG).unwrap(), b"2:10.0.0.1:<13>hello");
    }

    /// 20,000 cases recorded from the original escaping (room, input, length and hex of the result).
    #[test]
    fn escape_matches_recorded_cases() {
        for line in include_str!("../tests/data/escape_cases.tsv").lines() {
            let mut it = line.split('\t');
            let room: usize = it.next().unwrap().parse().unwrap();
            let input = it.next().unwrap();
            let expected = it.next().unwrap();
            let out = escape(input.as_bytes(), room);
            let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(format!("{} {}", out.len(), hex), expected, "room={room} input={input:?}");
        }
    }
}
