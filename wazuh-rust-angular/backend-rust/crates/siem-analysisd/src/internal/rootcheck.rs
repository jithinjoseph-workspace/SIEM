//! Rootcheck decoder (analysisd/decoders/rootcheck.c, shared/rootcheck_op.c):
//! the event is stored in the agent's database (`rootcheck save`), the reply
//! tells whether it is new (then the FTS check is already satisfied), and the
//! title and file are extracted from the log.

use crate::daemon::Env;
use crate::event::{DynamicField, Event, FTS_DONE};

/// `ROOTCHECK_MOD`
pub const ROOTCHECK_MOD: &str = "rootcheck";
/// `OS_SIZE_6144`
const OS_SIZE_6144: usize = 6144;

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// `rk_get_title`
pub fn rk_get_title(log: &[u8]) -> Option<Vec<u8>> {
    let mut t = log.to_vec();
    if let Some(c) = find(&t, b" {") {
        if c == 0 {
            return None;
        }
        t.truncate(c);
    }
    if let Some(c) = find(&t, b"System Audit: ") {
        if find(&t, b" - ").map_or(true, |d| c < d) {
            t = t[c + 14..].to_vec();
        }
    }
    // Remove "\. .*"
    if let Some(c) = find(&t, b". ") {
        t.truncate(c + 1);
    }
    // Remove "File: ('.*') "
    if let Some(c) = find(&t, b"File '").or_else(|| find(&t, b"file '")) {
        if let Some(d) = find(&t[c + 6..], b"' ") {
            let d = c + 6 + d;
            let tail = t[d + 2..].to_vec();
            t.truncate(c + 5);
            t.extend_from_slice(&tail);
        }
    }
    Some(t)
}

/// `rk_get_file`
pub fn rk_get_file(log: &[u8]) -> Option<Vec<u8>> {
    if let Some(f) = find(log, b"File: ") {
        let file = &log[f + 6..];
        if let Some(c) = find(file, b". ") {
            return Some(file[..c].to_vec());
        }
        if file.last() == Some(&b'.') {
            return Some(file[..file.len() - 1].to_vec());
        }
        return None;
    }
    if let Some(f) = find(log, b"File '").or_else(|| find(log, b"file '")) {
        let file = &log[f + 6..];
        if let Some(c) = find(file, b"' ") {
            return Some(file[..c].to_vec());
        }
        if file.last() == Some(&b'\'') {
            return Some(file[..file.len() - 1].to_vec());
        }
        return None;
    }
    None
}

/// `wstr_chr`: first `c` not escaped by a backslash.
pub fn wstr_chr(s: &[u8], c: u8) -> Option<usize> {
    let mut escaped = false;
    for (i, &b) in s.iter().enumerate() {
        if !escaped {
            if b == c {
                return Some(i);
            }
            if b == b'\\' {
                escaped = true;
            }
        } else {
            escaped = false;
        }
    }
    None
}

/// `strtol(s, NULL, 10)` for small values (leading spaces, sign, digits).
pub fn strtol(s: &[u8]) -> i64 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    // accumulate the magnitude; out of range gives LONG_MIN / LONG_MAX
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((s[i] - b'0') as u64)) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if neg {
        if overflow || v > i64::MAX as u64 + 1 {
            i64::MIN
        } else {
            (v as i64).wrapping_neg()
        }
    } else if overflow || v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

/// `DecodeRootcheck`: false when the event goes no further.
pub fn decode(env: &mut dyn Env, dec: usize, ev: &mut Event) -> bool {
    let agent = ev.agent_id.clone().unwrap_or_default();
    let log = ev.log().to_vec();
    // send_rootcheck_log: snprintf(query, OS_SIZE_6144, "agent %s rootcheck save %li %s")
    let mut q = b"agent ".to_vec();
    q.extend_from_slice(&agent);
    q.extend_from_slice(format!(" rootcheck save {} ", ev.time.sec).as_bytes());
    q.extend_from_slice(&log);
    q.truncate(OS_SIZE_6144 - 1);
    let response = match env.wdb_query_ex(&q, OS_SIZE_6144) {
        Ok(r) => r,
        Err(code) => {
            if code == -2 {
                env.log("ERROR", &[&b"Bad load query: '"[..], &q, b"'."].concat());
            }
            // the response buffer is still empty
            env.log("ERROR", b"Rootcheck decoder unexpected result: ''");
            return false;
        }
    };
    env.log("DEBUG", &[&b"Rootcheck decoder response: '"[..], &response, b"'"].concat());
    ev.decoder = dec;
    if let Some(p) = wstr_chr(&response, b' ') {
        if strtol(&response[p + 1..]) == 2 {
            // Entry was inserted
            ev.rootcheck_fts = FTS_DONE;
        }
    }
    ev.fields = vec![
        DynamicField { key: b"title".to_vec(), value: rk_get_title(&log) },
        DynamicField { key: b"file".to_vec(), value: rk_get_file(&log) },
    ];
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_and_files() {
        assert_eq!(
            rk_get_title(b"System Audit: SSH Hardening - 1: Port 22. File: /etc/ssh/sshd_config. Reference: x").unwrap(),
            b"SSH Hardening - 1: Port 22."
        );
        assert_eq!(rk_get_title(b" {x}"), None);
        assert_eq!(rk_get_title(b"Trojaned version of file '/bin/ls' detected. x").unwrap(), b"Trojaned version of file detected.");
        assert_eq!(rk_get_file(b"a. File: /etc/x. b").unwrap(), b"/etc/x");
        assert_eq!(rk_get_file(b"File: /etc/x").as_deref(), None);
        assert_eq!(rk_get_file(b"Trojaned file '/bin/ls' detected").unwrap(), b"/bin/ls");
        assert_eq!(rk_get_file(b"x file '/bin/ls'").unwrap(), b"/bin/ls");
        assert_eq!(wstr_chr(b"ok\\ 1 2", b' '), Some(5));
        assert_eq!(strtol(b"2 x"), 2);
    }
}
