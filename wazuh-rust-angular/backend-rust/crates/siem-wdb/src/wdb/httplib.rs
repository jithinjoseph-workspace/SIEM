//! The server half of cpp-httplib 0.14.2 (Wazuh's deps/54 build: no zlib,
//! brotli or OpenSSL support, select() based) as the router uses it: a
//! unix socket listener, a thread pool, keep-alive handling, request
//! parsing, routing with regex (literal) and `:param` matchers, ranges and
//! the response writer. Linux only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const KEEPALIVE_TIMEOUT_SECOND: i64 = 5;
pub const KEEPALIVE_MAX_COUNT: usize = 5;
pub const READ_TIMEOUT_SECOND: i64 = 5;
pub const WRITE_TIMEOUT_SECOND: i64 = 5;
pub const REQUEST_URI_MAX_LENGTH: usize = 8192;
pub const HEADER_MAX_LENGTH: usize = 8192;
pub const RECV_BUFSIZ: usize = 4096;
pub const LISTEN_BACKLOG: i32 = 5;
pub const MULTIPART_FORM_DATA_FILE_MAX_COUNT: usize = 1024;
pub const FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH: usize = 8192;

/// `std::multimap<std::string, std::string, detail::ci>`
#[derive(Debug, Clone, Default)]
pub struct Headers(pub Vec<(Vec<u8>, Vec<u8>)>);

/// `detail::ci`: lexicographic on `tolower` of unsigned bytes.
fn ci_less(a: &[u8], b: &[u8]) -> bool {
    let n = a.len().min(b.len());
    for i in 0..n {
        let (x, y) = (a[i].to_ascii_lowercase(), b[i].to_ascii_lowercase());
        if x != y {
            return x < y;
        }
    }
    a.len() < b.len()
}

fn ci_eq(a: &[u8], b: &[u8]) -> bool {
    !ci_less(a, b) && !ci_less(b, a)
}

impl Headers {
    /// `emplace` (after the equal keys).
    pub fn emplace(&mut self, k: &[u8], v: &[u8]) {
        let pos = self.0.iter().position(|(x, _)| ci_less(k, x)).unwrap_or(self.0.len());
        self.0.insert(pos, (k.to_vec(), v.to_vec()));
    }

    pub fn has(&self, k: &str) -> bool {
        self.0.iter().any(|(x, _)| ci_eq(x, k.as_bytes()))
    }

    /// `get_header_value(key, 0)` ("" when missing).
    pub fn get(&self, k: &str) -> &[u8] {
        self.0.iter().find(|(x, _)| ci_eq(x, k.as_bytes())).map(|(_, v)| v.as_slice()).unwrap_or(b"")
    }

    pub fn erase(&mut self, k: &str) {
        self.0.retain(|(x, _)| !ci_eq(x, k.as_bytes()));
    }
}

/// `has_crlf` (on the C string).
fn has_crlf(s: &[u8]) -> bool {
    s.iter().take_while(|&&c| c != 0).any(|&c| c == b'\r' || c == b'\n')
}

#[derive(Debug, Default)]
pub struct Request {
    pub method: Vec<u8>,
    pub target: Vec<u8>,
    pub version: Vec<u8>,
    pub path: Vec<u8>,
    pub params: Vec<(Vec<u8>, Vec<u8>)>,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub path_params: HashMap<String, Vec<u8>>,
    /// `Ranges` (-1 for a missing bound)
    pub ranges: Vec<(i64, i64)>,
    /// `req.files` (only counted: no endpoint reads them)
    pub files: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Request {
    pub fn set_header(&mut self, k: &[u8], v: &[u8]) {
        if !has_crlf(k) && !has_crlf(v) {
            self.headers.emplace(k, v);
        }
    }

    fn is_multipart_form_data(&self) -> bool {
        self.headers.get("Content-Type").starts_with(b"multipart/form-data")
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: i32,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Default for Response {
    fn default() -> Self {
        Response { status: -1, headers: Headers::default(), body: Vec::new() }
    }
}

impl Response {
    pub fn set_header(&mut self, k: &str, v: &[u8]) {
        if !has_crlf(k.as_bytes()) && !has_crlf(v) {
            self.headers.emplace(k.as_bytes(), v);
        }
    }

    pub fn set_content(&mut self, s: Vec<u8>, content_type: &str) {
        self.body = s;
        self.headers.erase("Content-Type");
        self.set_header("Content-Type", content_type.as_bytes());
    }
}

/// A handler; `Err` is the `what()` of the exception it throws.
pub type Handler = Arc<dyn Fn(&mut Request, &mut Response) -> Result<(), Vec<u8>> + Send + Sync>;
/// The exception handler (`set_exception_handler`).
pub type ExceptionHandler = Arc<dyn Fn(&Request, &mut Response, &[u8]) + Send + Sync>;

enum Matcher {
    /// `RegexMatcher` (the router's patterns have no metacharacters).
    Literal(Vec<u8>),
    /// `PathParamsMatcher`
    Params { fragments: Vec<Vec<u8>>, names: Vec<String> },
}

impl Matcher {
    /// `make_matcher`
    fn new(pattern: &str) -> Matcher {
        if !pattern.contains("/:") {
            return Matcher::Literal(pattern.as_bytes().to_vec());
        }
        let p = pattern.as_bytes();
        let mut fragments = Vec::new();
        let mut names = Vec::new();
        let mut last = 0usize;
        loop {
            let Some(m) = p[last.min(p.len())..].iter().position(|&c| c == b':').map(|x| x + last) else {
                break;
            };
            fragments.push(p[last..m].to_vec());
            let start = m + 1;
            let sep = p[start.min(p.len())..].iter().position(|&c| c == b'/').map(|x| x + start).unwrap_or(p.len());
            names.push(String::from_utf8_lossy(&p[start..sep]).into_owned());
            last = sep + 1;
        }
        if last < p.len() {
            fragments.push(p[last..].to_vec());
        }
        Matcher::Params { fragments, names }
    }

    fn matches(&self, req: &mut Request) -> bool {
        req.path_params.clear();
        match self {
            // std::regex_match on the whole path
            Matcher::Literal(l) => &req.path == l,
            Matcher::Params { fragments, names } => {
                let path = &req.path;
                let mut starting_pos = 0usize;
                for (i, fragment) in fragments.iter().enumerate() {
                    if starting_pos + fragment.len() > path.len() {
                        return false;
                    }
                    // strncmp on the C strings
                    let a = &path[starting_pos..];
                    for (k, &f) in fragment.iter().enumerate() {
                        let c = a.get(k).copied().unwrap_or(0);
                        if c != f {
                            return false;
                        }
                        if c == 0 {
                            break;
                        }
                    }
                    starting_pos += fragment.len();
                    if i >= names.len() {
                        continue;
                    }
                    let sep = path[starting_pos..].iter().position(|&c| c == b'/').map(|x| x + starting_pos).unwrap_or(path.len());
                    let v = path[starting_pos..sep].to_vec();
                    req.path_params.entry(names[i].clone()).or_insert(v);
                    starting_pos = sep + 1;
                }
                starting_pos >= req.path.len()
            }
        }
    }
}

// ------------------------------------------------------------- detail::

fn is_hex(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'A'..=b'F' => Some((c - b'A' + 10) as u32),
        b'a'..=b'f' => Some((c - b'a' + 10) as u32),
        _ => None,
    }
}

fn from_hex_to_i(s: &[u8], i: usize, cnt: usize) -> Option<u32> {
    if i >= s.len() {
        return None;
    }
    let mut val = 0u32;
    for k in 0..cnt {
        let c = *s.get(i + k).unwrap_or(&0);
        if c == 0 {
            return None;
        }
        val = val * 16 + is_hex(c)?;
    }
    Some(val)
}

fn to_utf8(code: u32, out: &mut Vec<u8>) {
    if code < 0x80 {
        out.push((code & 0x7F) as u8);
    } else if code < 0x800 {
        out.push((0xC0 | ((code >> 6) & 0x1F)) as u8);
        out.push((0x80 | (code & 0x3F)) as u8);
    } else if code < 0xD800 {
        out.push((0xE0 | ((code >> 12) & 0xF)) as u8);
        out.push((0x80 | ((code >> 6) & 0x3F)) as u8);
        out.push((0x80 | (code & 0x3F)) as u8);
    } else if code < 0xE000 {
        // invalid: nothing
    } else if code < 0x10000 {
        out.push((0xE0 | ((code >> 12) & 0xF)) as u8);
        out.push((0x80 | ((code >> 6) & 0x3F)) as u8);
        out.push((0x80 | (code & 0x3F)) as u8);
    } else if code < 0x110000 {
        out.push((0xF0 | ((code >> 18) & 0x7)) as u8);
        out.push((0x80 | ((code >> 12) & 0x3F)) as u8);
        out.push((0x80 | ((code >> 6) & 0x3F)) as u8);
        out.push((0x80 | (code & 0x3F)) as u8);
    }
}

/// `decode_url`
pub fn decode_url(s: &[u8], convert_plus_to_space: bool) -> Vec<u8> {
    let mut r = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 1 < s.len() {
            if s[i + 1] == b'u' {
                match from_hex_to_i(s, i + 2, 4) {
                    Some(v) => {
                        to_utf8(v, &mut r);
                        i += 5;
                    }
                    None => r.push(s[i]),
                }
            } else {
                match from_hex_to_i(s, i + 1, 2) {
                    Some(v) => {
                        r.push(v as u8);
                        i += 2;
                    }
                    None => r.push(s[i]),
                }
            }
        } else if convert_plus_to_space && s[i] == b'+' {
            r.push(b' ');
        } else {
            r.push(s[i]);
        }
        i += 1;
    }
    r
}

fn is_space_or_tab(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn trim(b: &[u8], mut left: usize, mut right: usize) -> (usize, usize) {
    while left < b.len() && is_space_or_tab(b[left]) {
        left += 1;
    }
    while right > 0 && is_space_or_tab(b[right - 1]) {
        right -= 1;
    }
    (left, right)
}

/// `split(b, e, d, fn)`
fn split(b: &[u8], d: u8, mut f: impl FnMut(&[u8])) {
    let mut beg = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == d {
            let (l, r) = trim(b, beg, i);
            if l < r {
                f(&b[l..r]);
            }
            beg = i + 1;
        }
        i += 1;
    }
    if i > 0 {
        let (l, r) = trim(b, beg, i);
        if l < r {
            f(&b[l..r]);
        }
    }
}

/// `parse_query_text`
fn parse_query_text(s: &[u8], params: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    let mut cache: Vec<Vec<u8>> = Vec::new();
    split(s, b'&', |kv| {
        if cache.iter().any(|c| c == kv) {
            return;
        }
        cache.push(kv.to_vec());
        let mut key: Vec<u8> = Vec::new();
        let mut val: Vec<u8> = Vec::new();
        split(kv, b'=', |x| {
            if key.is_empty() {
                key = x.to_vec();
            } else {
                val = x.to_vec();
            }
        });
        if !key.is_empty() {
            params.push((decode_url(&key, true), decode_url(&val, true)));
        }
    });
}

/// `parse_header` (the value goes through decode_url but for Location).
fn parse_header(line: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut end = line.len();
    while end > 0 && is_space_or_tab(line[end - 1]) {
        end -= 1;
    }
    let line = &line[..end];
    let colon = line.iter().position(|&c| c == b':')?;
    let key = &line[..colon];
    let mut p = colon + 1;
    while p < line.len() && is_space_or_tab(line[p]) {
        p += 1;
    }
    if p < line.len() {
        let v = &line[p..];
        let val = if ci_eq(key, b"Location") { v.to_vec() } else { decode_url(v, false) };
        Some((key.to_vec(), val))
    } else {
        None
    }
}

/// `strtoull(s, NULL, 10)` (on the C string).
fn strtoull(s: &[u8]) -> u64 {
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: u64 = 0;
    let mut over = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((s[i] - b'0') as u64)) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    if over {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    }
}

/// `strtoul(s, &end, 16)`: (value, digits consumed).
fn strtoul_hex(s: &[u8]) -> (u64, usize) {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    // optional 0x prefix
    if i + 1 < s.len() && s[i] == b'0' && (s[i + 1] == b'x' || s[i + 1] == b'X') && s.get(i + 2).and_then(|&c| is_hex(c)).is_some() {
        i += 2;
    }
    let start = i;
    let mut v: u64 = 0;
    let mut over = false;
    while i < s.len() {
        let Some(d) = is_hex(s[i]) else { break };
        match v.checked_mul(16).and_then(|x| x.checked_add(d as u64)) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    let v = if over {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    };
    (v, i)
}

/// `parse_range_header`
fn parse_range_header(s: &[u8], ranges: &mut Vec<(i64, i64)>) -> bool {
    // ^bytes=(\d*-\d*(?:,\s*\d*-\d*)*)$
    let Some(spec) = s.strip_prefix(b"bytes=") else {
        return false;
    };
    let is_ws = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    // validate the whole spec
    {
        let mut i = 0;
        let mut first = true;
        loop {
            if !first {
                if i >= spec.len() {
                    break;
                }
                if spec[i] != b',' {
                    return false;
                }
                i += 1;
                while i < spec.len() && is_ws(spec[i]) {
                    i += 1;
                }
            }
            first = false;
            while i < spec.len() && spec[i].is_ascii_digit() {
                i += 1;
            }
            if i >= spec.len() || spec[i] != b'-' {
                return false;
            }
            i += 1;
            while i < spec.len() && spec[i].is_ascii_digit() {
                i += 1;
            }
            if i >= spec.len() {
                break;
            }
        }
    }
    let mut all_valid = true;
    let mut failed = false;
    split(spec, b',', |item| {
        if !all_valid || failed {
            return;
        }
        // \s*(\d*)-(\d*)
        let mut i = 0;
        while i < item.len() && is_ws(item[i]) {
            i += 1;
        }
        let a0 = i;
        while i < item.len() && item[i].is_ascii_digit() {
            i += 1;
        }
        let a = &item[a0..i];
        if i >= item.len() || item[i] != b'-' {
            return;
        }
        i += 1;
        let b0 = i;
        while i < item.len() && item[i].is_ascii_digit() {
            i += 1;
        }
        if i != item.len() {
            return;
        }
        let b = &item[b0..i];
        // std::stoll throws out_of_range on overflow: the whole parse fails
        let conv = |d: &[u8]| -> Option<i64> { std::str::from_utf8(d).ok()?.parse::<i64>().ok() };
        let first = if a.is_empty() {
            -1
        } else {
            match conv(a) {
                Some(v) => v,
                None => {
                    failed = true;
                    return;
                }
            }
        };
        let last = if b.is_empty() {
            -1
        } else {
            match conv(b) {
                Some(v) => v,
                None => {
                    failed = true;
                    return;
                }
            }
        };
        if first != -1 && last != -1 && first > last {
            all_valid = false;
            return;
        }
        ranges.push((first, last));
    });
    if failed {
        return false;
    }
    all_valid
}

/// `status_message`
pub fn status_message(status: i32) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocol",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choice",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        306 => "unused",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "Internal Server Error",
    }
}

// ------------------------------------------------------------- sockets

fn handle_eintr(mut f: impl FnMut() -> isize) -> isize {
    loop {
        let r = f();
        // SAFETY: reading errno.
        if r < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
            continue;
        }
        return r;
    }
}

fn select_fd(sock: i32, sec: i64, usec: i64, write: bool) -> isize {
    if sock >= libc::FD_SETSIZE as i32 {
        return 1;
    }
    handle_eintr(|| {
        // SAFETY: a valid fd_set for one descriptor below FD_SETSIZE.
        unsafe {
            let mut fds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut fds);
            libc::FD_SET(sock, &mut fds);
            let mut tv = libc::timeval { tv_sec: sec as libc::time_t, tv_usec: usec as libc::suseconds_t };
            if write {
                libc::select(sock + 1, std::ptr::null_mut(), &mut fds, std::ptr::null_mut(), &mut tv) as isize
            } else {
                libc::select(sock + 1, &mut fds, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv) as isize
            }
        }
    })
}

fn select_read(sock: i32, sec: i64, usec: i64) -> isize {
    select_fd(sock, sec, usec, false)
}

fn select_write(sock: i32, sec: i64, usec: i64) -> isize {
    select_fd(sock, sec, usec, true)
}

fn read_socket(sock: i32, buf: &mut [u8], flags: i32) -> isize {
    handle_eintr(|| {
        // SAFETY: the slice bounds the write.
        unsafe { libc::recv(sock, buf.as_mut_ptr().cast(), buf.len(), flags) as isize }
    })
}

fn send_socket(sock: i32, buf: &[u8]) -> isize {
    handle_eintr(|| {
        // SAFETY: the slice bounds the read.
        unsafe { libc::send(sock, buf.as_ptr().cast(), buf.len(), 0) as isize }
    })
}

/// `is_socket_alive`
fn is_socket_alive(sock: i32) -> bool {
    let val = select_read(sock, 0, 0);
    if val == 0 {
        return true;
    }
    // SAFETY: reading errno.
    if val < 0 && unsafe { *libc::__errno_location() } == libc::EBADF {
        return false;
    }
    let mut b = [0u8; 1];
    read_socket(sock, &mut b, libc::MSG_PEEK) > 0
}

/// `keep_alive`
fn keep_alive(sock: i32, timeout_sec: i64) -> bool {
    let start = Instant::now();
    loop {
        let val = select_read(sock, 0, 10000);
        if val < 0 {
            return false;
        } else if val == 0 {
            if start.elapsed().as_millis() as i64 > timeout_sec * 1000 {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        } else {
            return true;
        }
    }
}

/// `SocketStream`: a 4 KiB read buffer per request.
struct SocketStream {
    sock: i32,
    buf: Vec<u8>,
    off: usize,
    size: usize,
}

impl SocketStream {
    fn new(sock: i32) -> Self {
        SocketStream { sock, buf: vec![0; RECV_BUFSIZ], off: 0, size: 0 }
    }

    fn is_readable(&self) -> bool {
        select_read(self.sock, READ_TIMEOUT_SECOND, 0) > 0
    }

    fn is_writable(&self) -> bool {
        select_write(self.sock, WRITE_TIMEOUT_SECOND, 0) > 0 && is_socket_alive(self.sock)
    }

    fn read(&mut self, out: &mut [u8]) -> isize {
        let size = out.len();
        if self.off < self.size {
            let remaining = self.size - self.off;
            let n = size.min(remaining);
            out[..n].copy_from_slice(&self.buf[self.off..self.off + n]);
            self.off += n;
            return n as isize;
        }
        if !self.is_readable() {
            return -1;
        }
        self.off = 0;
        self.size = 0;
        if size < RECV_BUFSIZ {
            let n = read_socket(self.sock, &mut self.buf, 0);
            if n <= 0 {
                n
            } else if n as usize <= size {
                out[..n as usize].copy_from_slice(&self.buf[..n as usize]);
                n
            } else {
                out.copy_from_slice(&self.buf[..size]);
                self.off = size;
                self.size = n as usize;
                size as isize
            }
        } else {
            read_socket(self.sock, out, 0)
        }
    }

    fn write(&mut self, data: &[u8]) -> isize {
        if !self.is_writable() {
            return -1;
        }
        send_socket(self.sock, data)
    }

    /// `write_data`
    fn write_data(&mut self, d: &[u8]) -> bool {
        let mut offset = 0;
        while offset < d.len() {
            let n = self.write(&d[offset..]);
            if n < 0 {
                return false;
            }
            offset += n as usize;
        }
        true
    }
}

/// `stream_line_reader` (the fixed buffer only matters for the C string
/// view: `ptr()` stops at a NUL).
struct LineReader {
    line: Vec<u8>,
}

impl LineReader {
    fn new() -> Self {
        LineReader { line: Vec::new() }
    }

    fn getline(&mut self, strm: &mut SocketStream) -> bool {
        self.line.clear();
        let mut i = 0;
        loop {
            let mut b = [0u8; 1];
            let n = strm.read(&mut b);
            if n < 0 {
                return false;
            } else if n == 0 {
                if i == 0 {
                    return false;
                }
                break;
            }
            self.line.push(b[0]);
            i += 1;
            if b[0] == b'\n' {
                break;
            }
        }
        true
    }

    fn size(&self) -> usize {
        self.line.len()
    }

    /// `ptr()` as a C string
    fn cstr(&self) -> &[u8] {
        &self.line[..self.line.iter().position(|&c| c == 0).unwrap_or(self.line.len())]
    }

    fn end_with_crlf(&self) -> bool {
        self.line.ends_with(b"\r\n")
    }
}

/// `read_headers`
fn read_headers(strm: &mut SocketStream, headers: &mut Headers) -> bool {
    let mut lr = LineReader::new();
    loop {
        if !lr.getline(strm) {
            return false;
        }
        if lr.end_with_crlf() {
            if lr.size() == 2 {
                break;
            }
        } else {
            continue;
        }
        if lr.size() > HEADER_MAX_LENGTH {
            return false;
        }
        // the C works on ptr() .. ptr()+size-2 (bytes past a NUL included)
        let line = &lr.line[..lr.size() - 2];
        if let Some((k, v)) = parse_header(line) {
            headers.emplace(&k, &v);
        }
    }
    true
}

/// `read_content_with_length`
fn read_content_with_length(strm: &mut SocketStream, len: u64, out: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    let mut buf = vec![0u8; RECV_BUFSIZ];
    let mut r: u64 = 0;
    while r < len {
        let read_len = (len - r).min(RECV_BUFSIZ as u64) as usize;
        let n = strm.read(&mut buf[..read_len]);
        if n <= 0 {
            return false;
        }
        if !out(&buf[..n as usize]) {
            return false;
        }
        r += n as u64;
    }
    true
}

fn skip_content_with_length(strm: &mut SocketStream, len: u64) {
    let mut buf = vec![0u8; RECV_BUFSIZ];
    let mut r: u64 = 0;
    while r < len {
        let read_len = (len - r).min(RECV_BUFSIZ as u64) as usize;
        let n = strm.read(&mut buf[..read_len]);
        if n <= 0 {
            return;
        }
        r += n as u64;
    }
}

fn read_content_without_length(strm: &mut SocketStream, out: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    let mut buf = vec![0u8; RECV_BUFSIZ];
    loop {
        let n = strm.read(&mut buf);
        if n < 0 {
            return false;
        } else if n == 0 {
            return true;
        }
        if !out(&buf[..n as usize]) {
            return false;
        }
    }
}

/// `read_content_chunked` (its line reader has a 16 byte fixed buffer;
/// `ptr()` is still the whole line)
fn read_content_chunked(strm: &mut SocketStream, req: &mut Request, out: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    let mut lr = LineReader::new();
    if !lr.getline(strm) {
        return false;
    }
    loop {
        let (chunk_len, consumed) = strtoul_hex(lr.cstr());
        if consumed == 0 {
            return false;
        }
        if chunk_len == u64::MAX {
            return false;
        }
        if chunk_len == 0 {
            break;
        }
        if !read_content_with_length(strm, chunk_len, out) {
            return false;
        }
        if !lr.getline(strm) {
            return false;
        }
        if lr.cstr() != b"\r\n" {
            return false;
        }
        if !lr.getline(strm) {
            return false;
        }
    }
    // Trailer
    if !lr.getline(strm) {
        return false;
    }
    while lr.cstr() != b"\r\n" {
        if lr.size() > HEADER_MAX_LENGTH {
            return false;
        }
        let end = lr.size().saturating_sub(2);
        if let Some((k, v)) = parse_header(&lr.line[..end]) {
            req.headers.emplace(&k, &v);
        }
        if !lr.getline(strm) {
            return false;
        }
    }
    true
}

/// `MultipartFormDataParser` (validation; the parts land in `req.files`).
struct MultipartParser {
    boundary: Vec<u8>,
    dash_boundary_crlf: Vec<u8>,
    crlf_dash_boundary: Vec<u8>,
    state: usize,
    is_valid: bool,
    buf: Vec<u8>,
    spos: usize,
    name: Vec<u8>,
}

fn find(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let c = needle[0];
    let mut off = 0;
    while off < hay.len() {
        let mut pos = off;
        loop {
            if pos == hay.len() {
                return hay.len();
            }
            if hay[pos] == c {
                break;
            }
            pos += 1;
        }
        if needle.len() > hay.len() - pos {
            return hay.len();
        }
        if hay[pos..].starts_with(needle) {
            return pos;
        }
        off = pos + 1;
    }
    hay.len()
}

impl MultipartParser {
    fn new(boundary: Vec<u8>) -> Self {
        let mut dbc = b"--".to_vec();
        dbc.extend_from_slice(&boundary);
        dbc.extend_from_slice(b"\r\n");
        let mut cdb = b"\r\n--".to_vec();
        cdb.extend_from_slice(&boundary);
        MultipartParser { boundary, dash_boundary_crlf: dbc, crlf_dash_boundary: cdb, state: 0, is_valid: false, buf: Vec::new(), spos: 0, name: Vec::new() }
    }

    fn data(&self) -> &[u8] {
        &self.buf[self.spos..]
    }

    fn erase(&mut self, n: usize) {
        self.spos += n;
    }

    fn parse(&mut self, input: &[u8], req: &mut Request, file_count: &mut usize) -> bool {
        let _ = &self.boundary;
        self.buf.drain(..self.spos);
        self.spos = 0;
        self.buf.extend_from_slice(input);
        while !self.data().is_empty() {
            match self.state {
                0 => {
                    let p = find(self.data(), &self.dash_boundary_crlf.clone());
                    self.erase(p);
                    if self.dash_boundary_crlf.len() > self.data().len() {
                        return true;
                    }
                    if !self.data().starts_with(&self.dash_boundary_crlf.clone()) {
                        return false;
                    }
                    let n = self.dash_boundary_crlf.len();
                    self.erase(n);
                    self.state = 1;
                }
                1 => {
                    self.name.clear();
                    self.state = 2;
                }
                2 => {
                    let mut pos = find(self.data(), b"\r\n");
                    if pos > HEADER_MAX_LENGTH {
                        return false;
                    }
                    while pos < self.data().len() {
                        if pos == 0 {
                            // header_callback
                            if *file_count == MULTIPART_FORM_DATA_FILE_MAX_COUNT {
                                *file_count += 1;
                                self.is_valid = false;
                                return false;
                            }
                            *file_count += 1;
                            req.files.push((self.name.clone(), Vec::new()));
                            self.erase(2);
                            self.state = 3;
                            break;
                        }
                        let header = self.data()[..pos].to_vec();
                        let lower: Vec<u8> = header.iter().map(|c| c.to_ascii_lowercase()).collect();
                        if lower.starts_with(b"content-type:") {
                            // file_.content_type: unused
                        } else {
                            // ^Content-Disposition:\s*form-data;\s*(.*)$ (icase)
                            let ok = (|| -> Option<Vec<u8>> {
                                let rest = lower.strip_prefix(b"content-disposition:")?;
                                let off = header.len() - rest.len();
                                let mut i = off;
                                while i < header.len() && is_regex_space(header[i]) {
                                    i += 1;
                                }
                                if !header[i..].to_ascii_lowercase().starts_with(b"form-data;") {
                                    return None;
                                }
                                i += 10;
                                while i < header.len() && is_regex_space(header[i]) {
                                    i += 1;
                                }
                                let tail = &header[i..];
                                if tail.iter().any(|&c| c == b'\r' || c == b'\n') {
                                    return None;
                                }
                                Some(tail.to_vec())
                            })();
                            let Some(params_text) = ok else {
                                self.is_valid = false;
                                return false;
                            };
                            // parse_disposition_params
                            let mut params: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                            let mut cache: Vec<Vec<u8>> = Vec::new();
                            let dq = |s: &[u8]| -> Vec<u8> {
                                if s.len() >= 2 && s[0] == b'"' && s[s.len() - 1] == b'"' {
                                    s[1..s.len() - 1].to_vec()
                                } else {
                                    s.to_vec()
                                }
                            };
                            split(&params_text, b';', |kv| {
                                if cache.iter().any(|c| c == kv) {
                                    return;
                                }
                                cache.push(kv.to_vec());
                                let mut key = Vec::new();
                                let mut val = Vec::new();
                                split(kv, b'=', |x| {
                                    if key.is_empty() {
                                        key = x.to_vec();
                                    } else {
                                        val = x.to_vec();
                                    }
                                });
                                if !key.is_empty() {
                                    params.push((dq(&key), dq(&val)));
                                }
                            });
                            let get = |k: &[u8]| params.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
                            match get(b"name") {
                                Some(n) => self.name = n,
                                None => {
                                    self.is_valid = false;
                                    return false;
                                }
                            }
                            if let Some(f) = get(b"filename*") {
                                // ^UTF-8''(.+?)$ (icase)
                                let l = f.to_ascii_lowercase();
                                if !(l.starts_with(b"utf-8''") && f.len() > 7 && !f[7..].iter().any(|&c| c == b'\r' || c == b'\n')) {
                                    self.is_valid = false;
                                    return false;
                                }
                            }
                        }
                        self.erase(pos + 2);
                        pos = find(self.data(), b"\r\n");
                    }
                    if self.state != 3 {
                        return true;
                    }
                }
                3 => {
                    let cdb = self.crlf_dash_boundary.clone();
                    if cdb.len() > self.data().len() {
                        return true;
                    }
                    let pos = find(self.data(), &cdb);
                    if pos < self.data().len() {
                        let chunk = self.data()[..pos].to_vec();
                        if let Some(f) = req.files.last_mut() {
                            f.1.extend_from_slice(&chunk);
                        }
                        self.erase(pos + cdb.len());
                        self.state = 4;
                    } else {
                        let len = self.data().len() - cdb.len();
                        if len > 0 {
                            let chunk = self.data()[..len].to_vec();
                            if let Some(f) = req.files.last_mut() {
                                f.1.extend_from_slice(&chunk);
                            }
                            self.erase(len);
                        }
                        return true;
                    }
                }
                _ => {
                    if 2 > self.data().len() {
                        return true;
                    }
                    if self.data().starts_with(b"\r\n") {
                        self.erase(2);
                        self.state = 1;
                    } else {
                        if 2 > self.data().len() {
                            return true;
                        }
                        if self.data().starts_with(b"--") {
                            self.erase(2);
                            self.is_valid = true;
                            let n = self.data().len();
                            self.erase(n);
                        } else {
                            return true;
                        }
                    }
                }
            }
        }
        true
    }
}

/// `parse_multipart_boundary`
fn parse_multipart_boundary(content_type: &[u8]) -> Option<Vec<u8>> {
    let kw = b"boundary=";
    let pos = content_type.windows(kw.len()).position(|w| w == kw)?;
    let beg = pos + kw.len();
    let end = content_type[beg..].iter().position(|&c| c == b';').map(|x| x + beg).unwrap_or(content_type.len());
    let b = &content_type[beg..end];
    let b = if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' { &b[1..b.len() - 1] } else { b };
    (!b.is_empty()).then(|| b.to_vec())
}

// ------------------------------------------------------------- Server

struct Pool {
    jobs: Mutex<(std::collections::VecDeque<i32>, bool)>,
    cond: Condvar,
}

pub struct Server {
    get_handlers: Mutex<Vec<(Matcher, Handler)>>,
    post_handlers: Mutex<Vec<(Matcher, Handler)>>,
    exception_handler: Mutex<Option<ExceptionHandler>>,
    svr_sock: AtomicI32,
    is_running: AtomicBool,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Server {
        Server {
            get_handlers: Mutex::new(Vec::new()),
            post_handlers: Mutex::new(Vec::new()),
            exception_handler: Mutex::new(None),
            svr_sock: AtomicI32::new(-1),
            is_running: AtomicBool::new(false),
        }
    }

    pub fn get(&self, pattern: &str, h: Handler) {
        self.get_handlers.lock().unwrap_or_else(|e| e.into_inner()).push((Matcher::new(pattern), h));
    }

    pub fn post(&self, pattern: &str, h: Handler) {
        self.post_handlers.lock().unwrap_or_else(|e| e.into_inner()).push((Matcher::new(pattern), h));
    }

    pub fn set_exception_handler(&self, h: ExceptionHandler) {
        *self.exception_handler.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// `listen(path, port)` with AF_UNIX: blocks until `stop`.
    pub fn listen_unix(self: &Arc<Self>, path: &str) -> bool {
        if path.len() > 108 {
            return false;
        }
        // SAFETY: plain socket calls with valid arguments.
        let sock = unsafe {
            let sock = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            if sock < 0 {
                return false;
            }
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            for (i, b) in path.bytes().enumerate().take(addr.sun_path.len()) {
                addr.sun_path[i] = b as libc::c_char;
            }
            let addrlen = (std::mem::size_of::<libc::sockaddr_un>() - addr.sun_path.len() + path.len()) as libc::socklen_t;
            libc::fcntl(sock, libc::F_SETFD, libc::FD_CLOEXEC);
            // default_socket_options: SO_REUSEADDR, SO_REUSEPORT
            let yes: libc::c_int = 1;
            libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_REUSEADDR, (&yes as *const libc::c_int).cast(), 4);
            libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_REUSEPORT, (&yes as *const libc::c_int).cast(), 4);
            if libc::bind(sock, (&addr as *const libc::sockaddr_un).cast(), addrlen) != 0 || libc::listen(sock, LISTEN_BACKLOG) != 0 {
                libc::close(sock);
                return false;
            }
            sock
        };
        self.svr_sock.store(sock, Ordering::SeqCst);
        self.listen_internal()
    }

    /// `listen_internal`
    fn listen_internal(self: &Arc<Self>) -> bool {
        let mut ret = true;
        self.is_running.store(true, Ordering::SeqCst);
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
        let count = std::cmp::max(8, if n > 0 { n - 1 } else { 0 });
        let pool = Arc::new(Pool { jobs: Mutex::new((std::collections::VecDeque::new(), false)), cond: Condvar::new() });
        let mut workers = Vec::new();
        for _ in 0..count {
            let (p, s) = (pool.clone(), self.clone());
            workers.push(std::thread::spawn(move || loop {
                let job = {
                    let mut g = p.jobs.lock().unwrap_or_else(|e| e.into_inner());
                    loop {
                        if let Some(j) = g.0.pop_front() {
                            break Some(j);
                        }
                        if g.1 {
                            break None;
                        }
                        g = p.cond.wait(g).unwrap_or_else(|e| e.into_inner());
                    }
                };
                match job {
                    Some(sock) => s.process_and_close_socket(sock),
                    None => break,
                }
            }));
        }
        loop {
            let svr = self.svr_sock.load(Ordering::SeqCst);
            if svr < 0 {
                break;
            }
            // SAFETY: accept on the listening socket.
            let sock = unsafe { libc::accept(svr, std::ptr::null_mut(), std::ptr::null_mut()) };
            if sock < 0 {
                // SAFETY: reading errno.
                let e = unsafe { *libc::__errno_location() };
                if e == libc::EMFILE {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                } else if e == libc::EINTR || e == libc::EAGAIN {
                    continue;
                }
                let svr = self.svr_sock.load(Ordering::SeqCst);
                if svr >= 0 {
                    // SAFETY: closing our socket.
                    unsafe { libc::close(svr) };
                    ret = false;
                }
                break;
            }
            // SAFETY: setting the timeouts of the accepted socket.
            unsafe {
                let tv = libc::timeval { tv_sec: READ_TIMEOUT_SECOND as libc::time_t, tv_usec: 0 };
                libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&tv as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as u32);
                let tv = libc::timeval { tv_sec: WRITE_TIMEOUT_SECOND as libc::time_t, tv_usec: 0 };
                libc::setsockopt(sock, libc::SOL_SOCKET, libc::SO_SNDTIMEO, (&tv as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as u32);
            }
            let mut g = pool.jobs.lock().unwrap_or_else(|e| e.into_inner());
            g.0.push_back(sock);
            drop(g);
            pool.cond.notify_one();
        }
        // task_queue->shutdown(): the queued connections are still served
        pool.jobs.lock().unwrap_or_else(|e| e.into_inner()).1 = true;
        pool.cond.notify_all();
        for w in workers {
            let _ = w.join();
        }
        self.is_running.store(false, Ordering::SeqCst);
        ret
    }

    /// `stop`
    pub fn stop(&self) {
        if self.is_running() {
            let sock = self.svr_sock.swap(-1, Ordering::SeqCst);
            if sock >= 0 {
                // SAFETY: shutting down and closing our listening socket.
                unsafe {
                    libc::shutdown(sock, libc::SHUT_RDWR);
                    libc::close(sock);
                }
            }
        }
    }

    /// `process_and_close_socket` + `process_server_socket_core`
    fn process_and_close_socket(&self, sock: i32) {
        let mut count = KEEPALIVE_MAX_COUNT;
        while self.svr_sock.load(Ordering::SeqCst) >= 0 && count > 0 && keep_alive(sock, KEEPALIVE_TIMEOUT_SECOND) {
            let close_connection = count == 1;
            let mut connection_closed = false;
            let mut strm = SocketStream::new(sock);
            let ret = self.process_request(&mut strm, close_connection, &mut connection_closed);
            if !ret || connection_closed {
                break;
            }
            count -= 1;
        }
        // SAFETY: shutting down and closing the peer.
        unsafe {
            libc::shutdown(sock, libc::SHUT_RDWR);
            libc::close(sock);
        }
    }

    /// `parse_request_line`
    fn parse_request_line(s: &[u8], req: &mut Request) -> bool {
        if s.len() < 2 || !s.ends_with(b"\r\n") {
            return false;
        }
        let s = &s[..s.len() - 2];
        let mut count = 0;
        split(s, b' ', |p| {
            match count {
                0 => req.method = p.to_vec(),
                1 => req.target = p.to_vec(),
                2 => req.version = p.to_vec(),
                _ => {}
            }
            count += 1;
        });
        if count != 3 {
            return false;
        }
        const METHODS: [&[u8]; 10] = [b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH", b"PRI"];
        if !METHODS.contains(&req.method.as_slice()) {
            return false;
        }
        if req.version != b"HTTP/1.1" && req.version != b"HTTP/1.0" {
            return false;
        }
        if let Some(i) = req.target.iter().position(|&c| c == b'#') {
            req.target.truncate(i);
        }
        let target = req.target.clone();
        let mut count = 0;
        let mut path = Vec::new();
        let mut params = Vec::new();
        split(&target, b'?', |p| {
            match count {
                0 => path = decode_url(p, false),
                1 => {
                    if !p.is_empty() {
                        parse_query_text(p, &mut params);
                    }
                }
                _ => {}
            }
            count += 1;
        });
        req.path = path;
        req.params = params;
        count <= 2
    }

    /// `process_request`
    fn process_request(&self, strm: &mut SocketStream, close_connection: bool, connection_closed: &mut bool) -> bool {
        let mut lr = LineReader::new();
        if !lr.getline(strm) {
            return false;
        }
        let mut req = Request::default();
        let mut res = Response::default();

        if strm.sock >= libc::FD_SETSIZE as i32 {
            let mut dummy = Headers::default();
            read_headers(strm, &mut dummy);
            res.status = 500;
            return self.write_response(strm, close_connection, &req, &mut res, false);
        }
        if lr.size() > REQUEST_URI_MAX_LENGTH {
            let mut dummy = Headers::default();
            read_headers(strm, &mut dummy);
            res.status = 414;
            return self.write_response(strm, close_connection, &req, &mut res, false);
        }
        if !Self::parse_request_line(lr.cstr(), &mut req) || !read_headers(strm, &mut req.headers) {
            res.status = 400;
            return self.write_response(strm, close_connection, &req, &mut res, false);
        }
        if req.headers.get("Connection") == b"close" {
            *connection_closed = true;
        }
        if req.version == b"HTTP/1.0" && req.headers.get("Connection") != b"Keep-Alive" {
            *connection_closed = true;
        }
        // REMOTE_ADDR / REMOTE_PORT / LOCAL_ADDR / LOCAL_PORT
        let peer_pid = peer_pid(strm.sock);
        req.set_header(b"REMOTE_ADDR", b"");
        req.set_header(b"REMOTE_PORT", peer_pid.to_string().as_bytes());
        req.set_header(b"LOCAL_ADDR", b"");
        req.set_header(b"LOCAL_PORT", b"0");

        if req.headers.has("Range") {
            let v = req.headers.get("Range").to_vec();
            if !parse_range_header(&v, &mut req.ranges) {
                res.status = 416;
                return self.write_response(strm, close_connection, &req, &mut res, false);
            }
        }
        if req.headers.get("Expect") == b"100-continue" {
            let line = format!("HTTP/1.1 {} {}\r\n\r\n", 100, status_message(100));
            strm.write(line.as_bytes());
        }

        // Routing
        let routed = match self.routing(&mut req, &mut res, strm) {
            Ok(r) => r,
            Err(what) => {
                let h = self.exception_handler.lock().unwrap_or_else(|e| e.into_inner()).clone();
                match h {
                    Some(h) => {
                        h(&req, &mut res, &what);
                        true
                    }
                    None => {
                        res.status = 500;
                        let mut val = Vec::new();
                        for &c in what.iter().take_while(|&&c| c != 0) {
                            match c {
                                b'\r' => val.extend_from_slice(b"\\r"),
                                b'\n' => val.extend_from_slice(b"\\n"),
                                _ => val.push(c),
                            }
                        }
                        res.set_header("EXCEPTION_WHAT", &val);
                        false
                    }
                }
            }
        };
        if routed {
            if res.status == -1 {
                res.status = if req.ranges.is_empty() { 200 } else { 206 };
            }
            self.write_response(strm, close_connection, &req, &mut res, true)
        } else {
            if res.status == -1 {
                res.status = 404;
            }
            self.write_response(strm, close_connection, &req, &mut res, false)
        }
    }

    /// `routing`: Ok(routed) or the exception of a handler.
    fn routing(&self, req: &mut Request, res: &mut Response, strm: &mut SocketStream) -> Result<bool, Vec<u8>> {
        let m = req.method.clone();
        // expect_content
        if matches!(m.as_slice(), b"POST" | b"PUT" | b"PATCH" | b"PRI" | b"DELETE") && !self.read_content(strm, req, res) {
            return Ok(false);
        }
        let handlers = match m.as_slice() {
            b"GET" | b"HEAD" => &self.get_handlers,
            b"POST" => &self.post_handlers,
            b"PUT" | b"DELETE" | b"OPTIONS" | b"PATCH" => return Ok(false),
            _ => {
                res.status = 400;
                return Ok(false);
            }
        };
        let handler = {
            let g = handlers.lock().unwrap_or_else(|e| e.into_inner());
            let mut found = None;
            for (matcher, h) in g.iter() {
                if matcher.matches(req) {
                    found = Some(h.clone());
                    break;
                }
            }
            found
        };
        match handler {
            Some(h) => {
                h(req, res)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// `Server::read_content` / `read_content_core`
    fn read_content(&self, strm: &mut SocketStream, req: &mut Request, res: &mut Response) -> bool {
        let multipart = req.is_multipart_form_data();
        let mut parser = None;
        if multipart {
            match parse_multipart_boundary(req.headers.get("Content-Type")) {
                Some(b) => parser = Some(MultipartParser::new(b)),
                None => {
                    res.status = 400;
                    return false;
                }
            }
        }
        if req.method == b"DELETE" && !req.headers.has("Content-Length") {
            return true;
        }
        // prepare_content_receiver: no decompressors in this build
        let encoding = req.headers.get("Content-Encoding").to_vec();
        if encoding == b"gzip" || encoding == b"deflate" || encoding.windows(2).any(|w| w == b"br") {
            res.status = 415;
            return false;
        }
        let mut body = std::mem::take(&mut req.body);
        let mut files: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut file_count = 0usize;
        let mut exceed = false;
        let ret = {
            let mut tmp = Request::default();
            let mut out = |b: &[u8]| -> bool {
                match parser.as_mut() {
                    Some(p) => {
                        tmp.files = std::mem::take(&mut files);
                        let ok = p.parse(b, &mut tmp, &mut file_count);
                        files = std::mem::take(&mut tmp.files);
                        ok
                    }
                    None => {
                        body.extend_from_slice(b);
                        true
                    }
                }
            };
            if req.headers.get("Transfer-Encoding").eq_ignore_ascii_case(b"chunked") {
                let mut hdrs = Request::default();
                let r = read_content_chunked(strm, &mut hdrs, &mut out);
                for (k, v) in hdrs.headers.0 {
                    req.headers.emplace(&k, &v);
                }
                r
            } else if !req.headers.has("Content-Length") {
                read_content_without_length(strm, &mut out)
            } else {
                let len = strtoull(req.headers.get("Content-Length"));
                // payload_max_length_ is SIZE_MAX
                if len > u64::MAX {
                    exceed = true;
                    skip_content_with_length(strm, len);
                    false
                } else if len > 0 {
                    read_content_with_length(strm, len, &mut out)
                } else {
                    true
                }
            }
        };
        req.body = body;
        req.files = files;
        if !ret {
            res.status = if exceed { 413 } else { 400 };
            return false;
        }
        if multipart {
            if !parser.map(|p| p.is_valid).unwrap_or(false) {
                res.status = 400;
                return false;
            }
        } else if req.headers.get("Content-Type").starts_with(b"application/x-www-form-urlencoded") {
            if req.body.len() > FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH {
                res.status = 413;
                return false;
            }
            let b = req.body.clone();
            parse_query_text(&b, &mut req.params);
        }
        true
    }

    /// `write_response_core`
    fn write_response(&self, strm: &mut SocketStream, close_connection: bool, req: &Request, res: &mut Response, need_apply_ranges: bool) -> bool {
        if need_apply_ranges {
            Self::apply_ranges(req, res);
        }
        if close_connection || req.headers.get("Connection") == b"close" {
            res.set_header("Connection", b"close");
        } else {
            res.set_header("Keep-Alive", format!("timeout={KEEPALIVE_TIMEOUT_SECOND}, max={KEEPALIVE_MAX_COUNT}").as_bytes());
        }
        if !res.headers.has("Content-Type") && !res.body.is_empty() {
            res.set_header("Content-Type", b"text/plain");
        }
        if !res.headers.has("Content-Length") && res.body.is_empty() {
            res.set_header("Content-Length", b"0");
        }
        if !res.headers.has("Accept-Ranges") && req.method == b"HEAD" {
            res.set_header("Accept-Ranges", b"bytes");
        }
        let mut head = format!("HTTP/1.1 {} {}\r\n", res.status, status_message(res.status)).into_bytes();
        for (k, v) in &res.headers.0 {
            // "%s: %s\r\n" on the C strings
            head.extend_from_slice(&k[..k.iter().position(|&c| c == 0).unwrap_or(k.len())]);
            head.extend_from_slice(b": ");
            head.extend_from_slice(&v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())]);
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");
        strm.write_data(&head);
        let mut ret = true;
        if req.method != b"HEAD" && !res.body.is_empty() && !strm.write_data(&res.body) {
            ret = false;
        }
        ret
    }

    /// `apply_ranges` (body responses; the content provider paths are
    /// unused by the endpoints)
    fn apply_ranges(req: &Request, res: &mut Response) {
        let mut boundary = Vec::new();
        let mut content_type = Vec::new();
        if req.ranges.len() > 1 {
            boundary = make_multipart_data_boundary();
            if res.headers.has("Content-Type") {
                content_type = res.headers.get("Content-Type").to_vec();
                // erase the first one
                if let Some(i) = res.headers.0.iter().position(|(k, _)| ci_eq(k, b"Content-Type")) {
                    res.headers.0.remove(i);
                }
            }
            let mut v = b"multipart/byteranges; boundary=".to_vec();
            v.extend_from_slice(&boundary);
            res.set_header("Content-Type", &v);
        }
        if res.body.is_empty() {
            // content_length_ == 0, no provider: nothing
            return;
        }
        if req.ranges.is_empty() {
        } else if req.ranges.len() == 1 {
            let cr = make_content_range_header_field(req.ranges[0], res.body.len());
            res.set_header("Content-Range", cr.as_bytes());
            let (offset, length) = get_range_offset_and_length(req.ranges[0], res.body.len());
            if offset < res.body.len() {
                let end = offset.saturating_add(length).min(res.body.len());
                res.body = res.body[offset..end].to_vec();
            } else {
                res.body.clear();
                res.status = 416;
            }
        } else {
            // make_multipart_ranges_data uses res.content_length_ (0 here)
            let mut data = Vec::new();
            let mut ok = true;
            for r in &req.ranges {
                data.extend_from_slice(b"--");
                data.extend_from_slice(&boundary);
                data.extend_from_slice(b"\r\n");
                if !content_type.is_empty() {
                    data.extend_from_slice(b"Content-Type: ");
                    data.extend_from_slice(&content_type);
                    data.extend_from_slice(b"\r\n");
                }
                data.extend_from_slice(b"Content-Range: ");
                data.extend_from_slice(make_content_range_header_field(*r, 0).as_bytes());
                data.extend_from_slice(b"\r\n\r\n");
                let (offset, length) = get_range_offset_and_length(*r, 0);
                if offset < res.body.len() {
                    let end = offset.saturating_add(length).min(res.body.len());
                    data.extend_from_slice(&res.body[offset..end]);
                } else {
                    ok = false;
                    break;
                }
                data.extend_from_slice(b"\r\n");
            }
            if ok {
                data.extend_from_slice(b"--");
                data.extend_from_slice(&boundary);
                data.extend_from_slice(b"--");
                res.body = data;
            } else {
                res.body.clear();
                res.status = 416;
            }
        }
        let len = res.body.len().to_string();
        res.set_header("Content-Length", len.as_bytes());
    }
}

/// The peer pid (`get_remote_ip_and_port` for AF_UNIX: SO_PEERCRED).
fn peer_pid(sock: i32) -> i32 {
    // SAFETY: valid ucred buffer.
    unsafe {
        let mut ucred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(sock, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut ucred as *mut libc::ucred).cast(), &mut len) == 0 {
            ucred.pid
        } else {
            0
        }
    }
}

/// `get_range_offset_and_length(req, content_length, index)`
fn get_range_offset_and_length(r: (i64, i64), content_length: usize) -> (usize, usize) {
    let (mut first, mut second) = r;
    if first == -1 && second == -1 {
        return (0, content_length);
    }
    let slen = content_length as i64;
    if first == -1 {
        first = std::cmp::max(0, slen - second);
        second = slen - 1;
    }
    if second == -1 {
        second = slen - 1;
    }
    (first as usize, ((second - first) as usize).wrapping_add(1))
}

/// ECMAScript `\s` of std::regex (`isspace`)
fn is_regex_space(c: u8) -> bool {
    matches!(c, b' ' | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d)
}

/// `make_content_range_header_field`
fn make_content_range_header_field(r: (i64, i64), content_length: usize) -> String {
    let mut f = String::from("bytes ");
    if r.0 != -1 {
        f.push_str(&r.0.to_string());
    }
    f.push('-');
    if r.1 != -1 {
        f.push_str(&r.1.to_string());
    }
    f.push('/');
    f.push_str(&content_length.to_string());
    f
}

/// `make_multipart_data_boundary` (random: 16 characters of the charset)
fn make_multipart_data_boundary() -> Vec<u8> {
    const DATA: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut r = b"--cpp-httplib-multipart-data-".to_vec();
    let mut seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1) | 1;
    for _ in 0..16 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        r.push(DATA[(seed % DATA.len() as u64) as usize]);
    }
    r
}
