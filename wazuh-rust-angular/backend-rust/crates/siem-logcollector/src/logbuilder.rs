//! `shared/log_builder.c`: the `<out_format>` patterns (`$(log)`,
//! `$(location)`, `$(timestamp[ fmt])`, `$(hostname)`, `$(host_ip)`,
//! `$(json_escaped_log)`, `$(base64_log)`).

use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::sync::{Mutex, RwLock};

use crate::*;

/// `LOG_BUILDER_HOSTNAME_LEN`
const HOSTNAME_LEN: usize = 512;
const IPSIZE: usize = 46;
#[cfg(unix)]
const CONTROL_SOCK: &str = "queue/sockets/control";

#[derive(Default)]
pub struct LogBuilder {
    /// (`host_name`, `host_ip`) behind `rwlock`
    pub hosts: RwLock<(String, String)>,
    /// `g_ip_update_interval`
    pub ip_update_interval: AtomicI32,
    /// statics of `log_builder_update_host_ip`
    host_ip: Mutex<String>,
    last_update: AtomicI64,
}

/// `wstr_escape_json`
pub fn wstr_escape_json(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        let e = match c {
            0x08 => Some(b'b'),
            b'\t' => Some(b't'),
            b'\n' => Some(b'n'),
            0x0c => Some(b'f'),
            b'\r' => Some(b'r'),
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            _ => None,
        };
        match e {
            Some(e) => {
                out.push(b'\\');
                out.push(e);
            }
            None => out.push(c),
        }
    }
    out
}

/// `encode_base64`
pub fn encode_base64(src: &[u8]) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for c in src.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63]);
        out.push(T[(n >> 12) as usize & 63]);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] } else { b'=' });
        out.push(if c.len() > 2 { T[n as usize & 63] } else { b'=' });
    }
    out
}

/// `strftime` of the local time `t` (msvcrt on Windows).
#[cfg(windows)]
fn strftime_local(fmt: &[u8], t: i64, size: usize) -> Option<Vec<u8>> {
    let f = std::str::from_utf8(fmt).ok()?;
    siem_config::localfile::win::strftime_at(f, size, t).map(String::into_bytes)
}

/// The RFC 3164 timestamp: strftime "%b %e %T", or on Windows (no `%e`
/// there) "%s %s%d %02d:%02d:%02d" of the local time.
fn rfc3164(t: i64) -> Option<Vec<u8>> {
    #[cfg(unix)]
    return strftime_local(b"%b %e %T", t, 64);
    #[cfg(windows)]
    {
        use chrono::{Datelike, TimeZone, Timelike};
        const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let tm = chrono::Local.timestamp_opt(t, 0).single()?;
        let d = tm.day();
        Some(
            format!(
                "{} {}{} {:02}:{:02}:{:02}",
                MONTHS[tm.month0() as usize],
                if d < 10 { " " } else { "" },
                d,
                tm.hour(),
                tm.minute(),
                tm.second()
            )
            .into_bytes(),
        )
    }
}

/// `strftime` of the local time `t` (empty on failure, as `strftime` == 0).
#[cfg(unix)]
fn strftime_local(fmt: &[u8], t: i64, size: usize) -> Option<Vec<u8>> {
    let c = std::ffi::CString::new(fmt.to_vec()).ok()?;
    let mut buf = vec![0u8; size];
    // SAFETY: localtime_r/strftime on valid buffers.
    let n = unsafe {
        let tt = t as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&tt, &mut tm);
        libc::strftime(buf.as_mut_ptr().cast(), size, c.as_ptr(), &tm)
    };
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

/// `log_builder_init`
pub fn init(lc: &Lc, update: bool) {
    let v = lc.define_int("logcollector", "ip_update_interval", 0, 3600);
    lc.builder.ip_update_interval.store(v, Ordering::SeqCst);
    if update {
        update_all(lc);
    } else {
        *lc.builder.hosts.write().unwrap() = ("localhost".into(), "0.0.0.0".into());
    }
}

/// `log_builder_update`: 0, or -1 when the hostname could not be read.
pub fn update_all(lc: &Lc) -> i32 {
    let mut r = 0;
    if update_hostname(lc) != 0 {
        r = -1;
    }
    update_host_ip(lc);
    r
}

fn update_hostname(lc: &Lc) -> i32 {
    let name = siem_ipc::os_net::gethostname(HOSTNAME_LEN);
    let mut h = lc.builder.hosts.write().unwrap();
    if let Some(n) = name {
        h.0 = String::from_utf8_lossy(&n).into_owned();
        0
    } else {
        h.0 = "localhost".into();
        -1
    }
}

fn update_host_ip(lc: &Lc) {
    let interval = lc.builder.ip_update_interval.load(Ordering::SeqCst) as i64;
    let now = now();
    let mut host_ip = lc.builder.host_ip.lock().unwrap();
    #[cfg(windows)]
    if interval > 0 && now - lc.builder.last_update.load(Ordering::SeqCst) >= interval {
        lc.builder.last_update.store(now, Ordering::SeqCst);
        // get_agent_ip_legacy_win32() never returns NULL
        let ip = crate::win::get_agent_ip_legacy_win32(lc);
        *host_ip = ip.chars().take(IPSIZE - 1).collect();
    }
    #[cfg(unix)]
    if interval > 0 && now - lc.builder.last_update.load(Ordering::SeqCst) >= interval {
        lc.builder.last_update.store(now, Ordering::SeqCst);
        let sock = siem_ipc::os_net::connect_unix_domain(CONTROL_SOCK, siem_ipc::os_net::SOCK_STREAM, 128);
        if sock < 0 {
            let e = errno();
            lc.log.debug1(format!(
                "Cannot update host IP: The control module is not available: {} ({e})",
                strerror(e)
            ));
            lc.builder.last_update.store(0, Ordering::SeqCst);
        } else {
            let req = b"host_ip";
            // SAFETY: send/recv on our own socket.
            unsafe {
                if libc::send(sock, req.as_ptr().cast(), req.len(), 0) > 0 {
                    let mut b = vec![0u8; IPSIZE];
                    // recv into the static: it keeps the old tail when shorter
                    let mut old = host_ip.clone().into_bytes();
                    old.resize(IPSIZE, 0);
                    let r = libc::recv(sock, b.as_mut_ptr().cast(), IPSIZE - 1, 0);
                    if r < 0 {
                        let e = errno();
                        lc.log.debug1(format!("The control module did not respond: {} ({e}).", strerror(e)));
                        host_ip.clear();
                    } else {
                        old[..r as usize].copy_from_slice(&b[..r as usize]);
                        *host_ip = String::from_utf8_lossy(cstr(&old)).into_owned();
                    }
                }
                libc::close(sock);
            }
        }
    }
    let mut h = lc.builder.hosts.write().unwrap();
    if !host_ip.is_empty() && *host_ip != "Err" {
        h.1 = host_ip.chars().take(IPSIZE - 1).collect();
    } else {
        h.1 = "0.0.0.0".into();
    }
}

/// `log_builder_build`
pub fn build(lc: &Lc, pattern: Option<&str>, logmsg: &[u8], location: &[u8]) -> Vec<u8> {
    let logmsg = cstr(logmsg);
    let Some(pattern) = pattern else { return logmsg.to_vec() };
    let timestamp = now();
    let pat = pattern.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let hosts = lc.builder.hosts.read().unwrap().clone();
    let fail = |lc: &Lc| {
        lc.log.debug1("Too long message format");
        let mut v = logmsg.to_vec();
        v.truncate(OS_MAXSTR - 1);
        v
    };
    let mut cur = 0usize;
    loop {
        let Some(tok) = find(&pat[cur..], b"$(").map(|p| cur + p) else { break };
        let z = tok - cur;
        if out.len() + z >= OS_MAXSTR {
            return fail(lc);
        }
        out.extend_from_slice(&pat[cur..tok]);
        let param_start = tok + 2;
        let Some(end) = pat[param_start..].iter().position(|&c| c == b')').map(|p| param_start + p) else {
            // Token not closed: the rest (from "$(") is copied below
            cur = tok;
            break;
        };
        let param = &pat[param_start..end];
        cur = end + 1;
        let field: Option<Vec<u8>> = if param == b"log" || param == b"output" {
            Some(logmsg.to_vec())
        } else if param == b"location" || param == b"command" {
            Some(cstr(location).to_vec())
        } else if param.starts_with(b"timestamp") {
            match param.iter().position(|&c| c == b' ') {
                Some(sp) => match strftime_local(&param[sp + 1..], timestamp, 64) {
                    Some(t) => Some(t),
                    None => {
                        let e = errno();
                        lc.log.debug1(format!(
                            "Cannot format time '{}': {} ({e})",
                            String::from_utf8_lossy(&param[sp..]),
                            strerror(e)
                        ));
                        None
                    }
                },
                None => rfc3164(timestamp),
            }
        } else if param == b"hostname" {
            Some(hosts.0.clone().into_bytes())
        } else if param == b"host_ip" {
            Some(hosts.1.clone().into_bytes())
        } else if param == b"json_escaped_log" {
            Some(wstr_escape_json(logmsg))
        } else if param == b"base64_log" {
            Some(encode_base64(logmsg))
        } else {
            lc.log.debug1(format!("Invalid parameter '{}' for log format.", String::from_utf8_lossy(param)));
            continue;
        };
        if let Some(f) = field {
            let f = cstr(&f).to_vec();
            if out.len() + f.len() >= OS_MAXSTR {
                return fail(lc);
            }
            out.extend_from_slice(&f);
        }
    }
    let rest = &pat[cur..];
    if out.len() + rest.len() >= OS_MAXSTR {
        return fail(lc);
    }
    out.extend_from_slice(rest);
    out
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(encode_base64(b"ab"), b"YWI=");
        assert_eq!(wstr_escape_json(b"a\"b\n"), b"a\\\"b\\n");
    }
}
