//! `logcollector/lccom.c`: the `queue/sockets/logcollector` requests
//! (`getconfig <section>`, `getstate [next]`), including the 64 KB paging
//! of large state answers, ported byte for byte on offsets instead of the C
//! pointers.

use std::sync::Mutex;

use siem_cjson::Json;
#[cfg(unix)]
use siem_ipc::os_net;

use crate::*;

const LEN_LOCATION: usize = 10;
const OFFSET_HEADER_TAGS: usize = 3;
const OFFSET_CLOSING_TAGS: usize = 2;
const TAG_ERROR: &[u8] = b"{\"error\"";
const TAG_DATA: &[u8] = b"\"data\"";
const TAG_GLOBAL: &[u8] = b"\"global\"";
const TAG_FILES: &[u8] = b"\"files\"";
const TAG_INTERVAL: &[u8] = b"\"interval\"";
const TAG_LOCATION: &[u8] = b"\"location\"";
const MAX_LEN_HEADER: usize = 150;

/// The statics of lccom.c.
struct Paging {
    flag_interval: bool,
    flag_global: bool,
    api_latest_index: u16,
    mtime_prev: i64,
}

static PAGING: Mutex<Paging> = Mutex::new(Paging { flag_interval: false, flag_global: false, api_latest_index: 0, mtime_prev: 0 });

fn strstr(h: &[u8], n: &[u8]) -> Option<usize> {
    let h = cstr(h);
    h.windows(n.len()).position(|w| w == n)
}

/// `lccom_dispatch`
pub fn lccom_dispatch(lc: &Lc, command: &[u8]) -> Vec<u8> {
    let command = cstr(command);
    let (comm, args) = match command.iter().position(|&c| c == b' ') {
        Some(p) => (&command[..p], Some(&command[p + 1..])),
        None => (command, None),
    };
    match comm {
        b"getconfig" => match args {
            None => {
                lc.log.debug1("LCCOM getconfig needs arguments.");
                b"err LCCOM getconfig needs arguments".to_vec()
            }
            Some(a) => lccom_getconfig(lc, &String::from_utf8_lossy(a)),
        },
        b"getstate" => lccom_getstate(lc, args.map(|a| a.starts_with(b"next")).unwrap_or(false)),
        _ => {
            lc.log.debug1(format!("LCCOM Unrecognized command '{}'.", String::from_utf8_lossy(comm)));
            b"err Unrecognized command".to_vec()
        }
    }
}

/// `lccom_getconfig`
pub fn lccom_getconfig(lc: &Lc, section: &str) -> Vec<u8> {
    let cfg = match section {
        "localfile" => crate::config::get_localfile_config(lc),
        "socket" => crate::config::get_socket_config(lc),
        "internal" => Some(crate::config::get_internal_options(lc)),
        _ => None,
    };
    match cfg {
        Some(j) => format!("ok {}", j.to_string_unformatted()).into_bytes(),
        None => {
            lc.log.debug1(format!("At LCCOM getconfig: Could not get '{section}' section"));
            b"err Could not get requested section".to_vec()
        }
    }
}

/// `getObjectIndexFromJsonStats`: offsets of each `"location"`, after a 0.
fn object_index(out: &[u8]) -> Vec<usize> {
    let mut ptrs = vec![0usize];
    let mut from = 0;
    while let Some(p) = strstr(&out[from..], TAG_LOCATION) {
        ptrs.push(from + p);
        from += p + LEN_LOCATION;
    }
    ptrs
}

/// `checkJson64k`
fn check_json_64k(out: &[u8], initial: u16, amount: u16, ptrs: &[usize], output: &mut Vec<u8>, size_out: &mut usize) -> u16 {
    let mut counter = 0usize;
    let mut cur: u16 = if initial == 0 { 1 } else { initial };
    let mut last: u16 = 0;
    while cur < amount {
        let len = ptrs[cur as usize] - ptrs[cur as usize - 1];
        counter += len;
        if counter < OS_MAXSTR - OS_SIZE_1024 {
            cur += 1;
        } else {
            *output = vec![0u8; OS_MAXSTR];
            let a = ptrs[initial as usize];
            let b = ptrs[cur as usize - 1];
            output[..b - a].copy_from_slice(&out[a..b]);
            last = cur - 1;
            counter = 0;
            cur = 1;
            break;
        }
    }
    if cur != 1 && counter < OS_MAXSTR - OS_SIZE_1024 {
        *output = vec![0u8; OS_MAXSTR];
        let start = ptrs[initial as usize];
        let prev = ptrs[if initial == 0 { 0 } else { initial as usize - 1 }];
        let n = ptrs[cur as usize - 1] - prev + strlen(&out[ptrs[cur as usize - 1]..]);
        let src = cstr(&out[start..]);
        let k = src.len().min(n).min(OS_MAXSTR);
        output[..k].copy_from_slice(&src[..k]);
    }
    *size_out = counter;
    if cur == 1 {
        last
    } else {
        cur
    }
}

/// `addHeader`
fn add_header(s: &mut Vec<u8>, header_data: &[u8], header: &[u8]) {
    let mut tmp = vec![0u8; OS_MAXSTR];
    let ld = header_data.len();
    let lh = header.len();
    tmp[..ld].copy_from_slice(header_data);
    tmp[ld..ld + lh].copy_from_slice(header);
    let n = OS_MAXSTR - ld - lh - 1;
    tmp[ld + lh..ld + lh + n].copy_from_slice(&s[..n]);
    *s = vec![0u8; OS_MAXSTR];
    s[..OS_MAXSTR - 1].copy_from_slice(&tmp[..OS_MAXSTR - 1]);
}

/// `addClosingTags`
fn add_closing_tags(s: &mut Vec<u8>) {
    let l = strlen(s);
    let at = l - OFFSET_CLOSING_TAGS;
    if s.len() < at + 4 {
        s.resize(at + 4, 0);
    }
    s[at..at + 4].copy_from_slice(b"]}}}");
}

/// `extractHeadersFromJson`: (global, interval, data) headers.
fn extract_headers(b: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut g = Vec::new();
    let mut i = Vec::new();
    let mut d = Vec::new();
    if let Some(pg) = strstr(b, TAG_GLOBAL) {
        if let Some(pf) = strstr(&b[pg..], TAG_FILES) {
            let len = (pf + TAG_FILES.len() + OFFSET_HEADER_TAGS).min(MAX_LEN_HEADER);
            g = b[pg..pg + len].to_vec();
        }
    }
    if let Some(pi) = strstr(b, TAG_INTERVAL) {
        if let Some(pf) = strstr(&b[pi..], TAG_FILES) {
            let len = (pf + TAG_FILES.len() + OFFSET_HEADER_TAGS).min(MAX_LEN_HEADER);
            i = b[pi..pi + len].to_vec();
        }
    }
    if let Some(pd) = strstr(b, TAG_DATA) {
        // ptrData + strlen(TAG_FILES) - buffJson + 1
        let len = (pd + TAG_FILES.len() + 1).min(MAX_LEN_HEADER);
        d = b[..len].to_vec();
    }
    (g, i, d)
}

/// `addStartandEndTagsToJsonStrBlock`
fn add_tags(buf: &mut Vec<u8>, hg: &[u8], hi: &[u8], hd: &[u8], counter: usize, next: bool, lc: &Lc) {
    let mut st = PAGING.lock().unwrap();
    if !next {
        st.flag_interval = false;
        st.flag_global = false;
    }
    if !st.flag_global {
        if strstr(buf, TAG_ERROR).is_some() && strstr(buf, TAG_DATA).is_some() {
            if strstr(buf, TAG_GLOBAL).is_some() {
                st.flag_global = true;
                if strstr(buf, TAG_FILES).is_some() {
                    if strstr(buf, TAG_INTERVAL).is_some() {
                        st.flag_interval = true;
                        if counter == 0 {
                            add_closing_tags(buf);
                        } else {
                            st.flag_interval = false;
                            st.flag_global = false;
                        }
                    } else {
                        add_closing_tags(buf);
                        st.flag_interval = false;
                    }
                }
            } else {
                st.flag_global = false;
                lc.log.warn("'global' tag no found in logcollector JSON stats");
            }
        }
    } else if !st.flag_interval && st.flag_global {
        if strstr(buf, TAG_INTERVAL).is_some() {
            st.flag_interval = true;
            if counter == 0 {
                add_closing_tags(buf);
                add_header(buf, hd, hg);
            } else {
                add_header(buf, hd, hg);
                st.flag_interval = false;
            }
        } else {
            add_closing_tags(buf);
            add_header(buf, hd, hg);
            st.flag_interval = false;
        }
    } else if st.flag_interval && st.flag_global {
        if counter == 0 {
            add_closing_tags(buf);
            add_header(buf, hd, hi);
        } else {
            add_header(buf, hd, hi);
            st.flag_interval = false;
            st.flag_global = false;
        }
    }
}

/// `isJsonUpdated`
fn is_json_updated(lc: &Lc) -> bool {
    let mut current = 0i64;
    if let Ok(m) = std::fs::metadata(LOGCOLLECTOR_STATE) {
        #[cfg(unix)]
        let buf = {
            use std::os::unix::fs::MetadataExt;
            current = m.mtime();
            let mut buf = vec![0u8; 256];
            // SAFETY: localtime_r/strftime on valid buffers.
            let n = unsafe {
                let t = current as libc::time_t;
                let mut tm: libc::tm = std::mem::zeroed();
                libc::localtime_r(&t, &mut tm);
                libc::strftime(buf.as_mut_ptr().cast(), 256, c"%c".as_ptr(), &tm)
            };
            buf.truncate(n);
            buf
        };
        #[cfg(windows)]
        let buf = {
            current = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            siem_config::localfile::win::strftime_at("%c", 256, current).unwrap_or_default().into_bytes()
        };
        lc.log.debug2(format!(" {} {LOGCOLLECTOR_STATE}", String::from_utf8_lossy(&buf)));
    }
    let mut st = PAGING.lock().unwrap();
    let updated = current != st.mtime_prev && st.mtime_prev != 0;
    if updated {
        lc.log.debug2("Logcollector JSON stats have been updated.");
    }
    st.mtime_prev = current;
    updated
}

/// `getJsonStr64kBlockFromLatestIndex`
fn json_block(lc: &Lc, output: &mut Vec<u8>, next: bool) {
    let ptrs = object_index(output);
    let amount = ptrs.len() as u16;
    let mut idx = {
        let mut st = PAGING.lock().unwrap();
        if !next {
            st.api_latest_index = 0;
        }
        st.api_latest_index
    };
    let (hg, hi, hd) = extract_headers(output);
    let mut buffer = vec![0u8; OS_MAXSTR];
    let mut counter = 0;
    idx = check_json_64k(output, idx, amount, &ptrs, &mut buffer, &mut counter);
    add_tags(&mut buffer, &hg, &hi, &hd, counter, next, lc);
    if idx == amount {
        idx = 0;
    }
    PAGING.lock().unwrap().api_latest_index = idx;
    *output = cstr(&buffer).to_vec();
}

/// `replaceBoolToStr`
fn replace_bool(buf: &mut Vec<u8>, m: &[u8], v: bool) {
    if let Some(p) = strstr(buf, m) {
        let at = p + m.len();
        if buf.len() < at + 5 {
            buf.resize(at + 5, 0);
        }
        buf[at..at + 5].copy_from_slice(if v { b"true " } else { b"false" });
    }
}

/// `lccom_getstate`
pub fn lccom_getstate(lc: &Lc, next: bool) -> Vec<u8> {
    let mut w = Json::object();
    match crate::state::state_get(lc) {
        None => {
            w.add("error", Json::number(1.0));
            w.add("data", Json::object());
            w.add("message", Json::string("Statistics unavailable"));
            lc.log.debug1("At LCCOM getstate: Statistics unavailable");
        }
        Some(s) => {
            w.add("error", Json::number(0.0));
            w.add("remaining", Json::bool(false));
            w.add("json_updated", Json::bool(false));
            w.add("data", s);
        }
    }
    let mut out = w.print_unformatted();
    if out.len() >= OS_MAXSTR {
        json_block(lc, &mut out, next);
        let remaining = strlen(&out) >= OS_MAXSTR - 2 * OS_SIZE_1024;
        replace_bool(&mut out, b"\"remaining\":", remaining);
        let upd = is_json_updated(lc);
        replace_bool(&mut out, b"\"json_updated\":", upd);
        out.truncate(strlen(&out));
    }
    out
}

/// `lccom_main` (not on Windows, where agentd calls `lccom_dispatch`)
#[cfg(unix)]
pub fn lccom_main(lc: &Lc) {
    lc.log.debug1("Local requests thread ready");
    let sock = os_net::bind_unix_domain(LC_LOCAL_SOCK, libc::SOCK_STREAM, OS_MAXSTR as i32);
    if sock < 0 {
        let e = errno();
        lc.log.error(format!("Unable to bind to socket '{LC_LOCAL_SOCK}': ({e}) {}.", strerror(e)));
        return;
    }
    loop {
        // SAFETY: select/accept on our own socket.
        let rc = unsafe {
            let mut set: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut set);
            libc::FD_SET(sock, &mut set);
            libc::select(sock + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        if rc == -1 {
            let e = errno();
            if e != libc::EINTR {
                lc.exit_critical(format!("At lccom_main(): select(): {}", strerror(e)));
            }
            continue;
        } else if rc == 0 {
            continue;
        }
        // SAFETY: accept on our listening socket.
        let peer = unsafe { libc::accept(sock, std::ptr::null_mut(), std::ptr::null_mut()) };
        if peer < 0 {
            let e = errno();
            if e != libc::EINTR {
                lc.log.error(format!("At lccom_main(): accept(): {}", strerror(e)));
            }
            continue;
        }
        let mut buf = Vec::new();
        match os_net::recv_secure_tcp(peer, &mut buf, OS_MAXSTR as u32) {
            r if r == os_net::OS_SOCKTERR as isize => {
                lc.log.error("At lccom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
            }
            -1 => {
                let e = errno();
                lc.log.error(format!("At lccom_main(): OS_RecvSecureTCP(): {}", strerror(e)));
            }
            0 => {
                lc.log.debug1("Empty message from local client.");
                // SAFETY: closing the peer.
                unsafe { libc::close(peer) };
            }
            _ => {
                let resp = lccom_dispatch(lc, &buf);
                os_net::send_secure_tcp(peer, &resp);
                // SAFETY: closing the peer.
                unsafe { libc::close(peer) };
            }
        }
    }
}
