//! `SendMSG` (`src/shared/mq_op.c`): the message format every daemon uses to
//! feed analysisd through `queue/sockets/queue`.

/// Queue identifiers (`mq_op.h`).
pub mod queues {
    pub const LOCALFILE_MQ: u8 = b'1';
    pub const SYSLOG_MQ: u8 = b'2';
    pub const HOSTINFO_MQ: u8 = b'3';
    pub const SECURE_MQ: u8 = b'4';
    pub const DBSYNC_MQ: u8 = b'5';
    pub const SYSCHECK_MQ: u8 = b'8';
    pub const ROOTCHECK_MQ: u8 = b'9';
    pub const SYSCOLLECTOR_MQ: u8 = b'd';
    pub const CISCAT_MQ: u8 = b'e';
    pub const WIN_EVT_MQ: u8 = b'f';
    pub const SCA_MQ: u8 = b'p';
    pub const UPGRADE_MQ: u8 = b'u';
}

/// Default analysisd queue path relative to the Wazuh home (`DEFAULTQUEUE`).
pub const DEFAULTQUEUE: &str = "queue/sockets/queue";

/// `wstr_escape(dst, size, str, escape, match)`: prefixes `escape` and `match`
/// characters with `escape`. Output is bounded to `dst_size - 1` bytes.
pub fn wstr_escape(s: &[u8], escape: u8, matchc: u8, dst_size: usize) -> Vec<u8> {
    let at = |k: usize| s.get(k).copied().unwrap_or(0);
    let mut dst = vec![0u8; dst_size];
    let (mut i, mut j) = (0usize, 0usize);
    loop {
        // z = strcspn(str + i, {escape, match})
        let mut z = 0usize;
        while at(i + z) != 0 && at(i + z) != escape && at(i + z) != matchc {
            z += 1;
        }
        if at(i + z) == 0 || j + z >= dst_size - 2 {
            z = if z + j <= dst_size - 1 { z } else { dst_size - j - 1 };
            // strncpy stops at NUL
            for k in 0..z {
                dst[j + k] = at(i + k);
            }
        } else {
            for k in 0..z {
                dst[j + k] = at(i + k);
            }
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

/// `SendMSGAction` formatting. Returns `None` when Wazuh would drop the
/// message (keepalive locations, or a malformed `SECURE_MQ` payload).
///
/// * `SECURE_MQ`: `message` is `"<q>:<location>:<msg>"` from an agent; the
///   result is `"<q>:<locmsg>-><location>:<msg>"`.
/// * otherwise: `"<loc>:<locmsg>:<message>"`.
///
/// `locmsg` has `|` and `:` escaped with `|`.
pub fn format_msg(message: &[u8], locmsg: &str, loc: u8) -> Option<Vec<u8>> {
    let loc_buff = wstr_escape(locmsg.as_bytes(), b'|', b':', 8193);
    let mut out = Vec::with_capacity(message.len() + loc_buff.len() + 8);
    if loc == queues::SECURE_MQ {
        let q = *message.first()?;
        if message.get(1) != Some(&b':') {
            return None;
        }
        let rest = &message[2..];
        if rest.starts_with(b"keepalive") {
            return None;
        }
        out.push(q);
        out.push(b':');
        out.extend_from_slice(&loc_buff);
        out.extend_from_slice(b"->");
        out.extend_from_slice(rest);
    } else {
        out.push(loc);
        out.push(b':');
        out.extend_from_slice(&loc_buff);
        out.push(b':');
        out.extend_from_slice(message);
    }
    // snprintf(tmpstr, OS_MAXSTR, ...)
    out.truncate(crate::OS_MAXSTR - 1);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_like_wazuh() {
        assert_eq!(wstr_escape(b"[001] (agent) any->/var/log", b'|', b':', 8193), b"[001] (agent) any->/var/log");
        assert_eq!(wstr_escape(b"C:\\Windows|x", b'|', b':', 8193), b"C|:\\Windows||x");
        assert_eq!(wstr_escape(b"::", b'|', b':', 8193), b"|:|:");
    }

    #[test]
    fn secure_mq_format() {
        let m = format_msg(b"1:/var/log/syslog:Oct  5 sshd: x", "[001] (web01) 10.0.0.5", queues::SECURE_MQ).unwrap();
        assert_eq!(m, b"1:[001] (web01) 10.0.0.5->/var/log/syslog:Oct  5 sshd: x");
        assert!(format_msg(b"1:keepalive:x", "[001] (a) any", queues::SECURE_MQ).is_none());
        assert!(format_msg(b"1x", "a", queues::SECURE_MQ).is_none());
        let s = format_msg(b"<13>hello", "10.0.0.1", queues::SYSLOG_MQ).unwrap();
        assert_eq!(s, b"2:10.0.0.1:<13>hello");
    }
}

#[cfg(test)]
mod oracle {
    /// 20,000 cases produced by the C `wstr_escape` (size, input, return, output).
    #[test]
    fn wstr_escape_matches_c() {
        for line in include_str!("esc_cases.tsv").lines() {
            let mut it = line.split('\t');
            let size: usize = it.next().unwrap().parse().unwrap();
            let input = it.next().unwrap();
            let expected = it.next().unwrap();
            let out = super::wstr_escape(input.as_bytes(), b'|', b':', size);
            let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(format!("{} {}", out.len(), hex), expected, "size={size} input={input:?}");
        }
    }
}
