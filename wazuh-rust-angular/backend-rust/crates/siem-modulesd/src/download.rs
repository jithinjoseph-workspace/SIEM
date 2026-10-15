//! The download module (`wazuh_modules/wm_download.c`) and the `shared/url.c`
//! helpers that use it or curl: `wurl_request`, `wurl_get`, `wurl_http_get`.
//!
//! shortcut: HTTP goes through reqwest (rustls + webpki roots) instead of curl
//! with the system CA list; curl's error-buffer text is reproduced for HTTP
//! status errors only (connection/TLS errors carry reqwest's text). Switch to
//! libcurl if those must match too.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use siem_ipc::local::{LocalStream, StreamListener};
use siem_log::WLog;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::task_general::{cat, cstr, OS_MAXSTR};

/// `WM_DOWNLOAD_SOCK`
pub const WM_DOWNLOAD_SOCK: &str = "queue/sockets/download";
/// `WM_DOWNLOAD_LOGTAG`
const LOGTAG: &str = "wazuh-modulesd:download";
/// `PATH_MAX`
const PATH_MAX: usize = 4096;
pub const OS_FILERR: i32 = -3;
pub const OS_CONNERR: i32 = -8;
pub const OS_TIMEOUT: i32 = -13;

/// `wstr_chr`: the first unescaped `c`.
fn wstr_chr(s: &[u8], c: u8) -> Option<usize> {
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

/// `wstr_replace`
fn replace(s: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

pub struct Download {
    enabled: bool,
    log: Arc<WLog>,
}

impl Download {
    /// `wm_download_read`: `wazuh_download.enabled`.
    pub fn new(enabled: bool, log: Arc<WLog>) -> Self {
        Download { enabled, log }
    }

    fn tlog(&self, level: &str, m: impl AsRef<[u8]>) {
        self.log.tagged(LOGTAG, level, m);
    }

    /// `wm_download_main`
    pub async fn main(self: Arc<Self>) {
        if self.enabled {
            self.tlog("INFO", "Module started.");
        } else {
            self.tlog("INFO", "Module disabled. Exiting.");
            return;
        }
        let mut seconds = 60u64;
        let listener = loop {
            match StreamListener::bind(WM_DOWNLOAD_SOCK).await {
                Ok(l) => break l,
                Err(_) => {
                    self.tlog("WARNING", format!("Unable to bind to socket '{WM_DOWNLOAD_SOCK}', retrying in {seconds} secs."));
                    tokio::time::sleep(Duration::from_secs(seconds)).await;
                    seconds += if seconds < 600 { 60 } else { 0 };
                }
            }
        };
        loop {
            let mut peer = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    self.tlog("ERROR", format!("accept(): {}", crate::wdb::errno_text(&e)));
                    continue;
                }
            };
            let mut buf = vec![0u8; OS_MAXSTR];
            match peer.read(&mut buf).await {
                Err(e) => self.tlog("ERROR", format!("recv(): {} ({})", crate::wdb::errno_text(&e), e.raw_os_error().unwrap_or(0))),
                Ok(0) => self.tlog("DEBUG", "Client disconnected. This may be a healthcheck."),
                Ok(n) => {
                    let out = self.dispatch(cstr(&buf[..n])).await;
                    if let Err(e) = peer.write_all(&out).await {
                        self.tlog("ERROR", format!("send(): {} ({})", crate::wdb::errno_text(&e), e.raw_os_error().unwrap_or(0)));
                    }
                }
            }
        }
    }

    /// `wm_download_dispatch`: the answer to one request.
    async fn dispatch(&self, req: &[u8]) -> Vec<u8> {
        let fail = |dbg: &str, ans: &str| {
            self.tlog("DEBUG", cat(&[dbg.as_bytes(), b": '", req, b"'"]));
            ans.as_bytes().to_vec()
        };
        // Get command
        let Some(sp) = req.iter().position(|&c| c == b' ') else {
            return fail("Empty request command", "err empty command");
        };
        if &req[..sp] != b"download" {
            return fail("Invalid request command", "err invalid command");
        }
        let mut rest = &req[sp + 1..];
        // url | file | header | data | timeout |
        let field = |rest: &mut &[u8]| -> Option<Vec<u8>> {
            let p = wstr_chr(rest, b'|')?;
            let f = rest[..p].to_vec();
            *rest = &rest[p + 1..];
            Some(f)
        };
        let Some(url) = field(&mut rest) else {
            return fail("Empty request URL", "err empty url");
        };
        let Some(fpath) = field(&mut rest) else {
            return fail("Empty request file", "err empty file name");
        };
        let (mut header, mut data, mut timeout) = (None, None, 0i64);
        match field(&mut rest) {
            None => self.tlog("DEBUG2", cat(&[b"Empty request header: '", req, b"'"])),
            Some(h) => {
                header = Some(h);
                match field(&mut rest) {
                    None => self.tlog("DEBUG2", cat(&[b"Empty request data: '", req, b"'"])),
                    Some(d) => {
                        data = Some(d);
                        match field(&mut rest) {
                            None => self.tlog("DEBUG2", cat(&[b"Empty request timeout: '", req, b"'"])),
                            Some(t) => timeout = siem_config::util::strtol(&String::from_utf8_lossy(&t)).0,
                        }
                    }
                }
            }
        }
        // Unescape
        let unsc_fpath = replace(&fpath, b"\\|", b"|");
        let header = header.filter(|h| !h.is_empty()).map(|h| replace(&h, b"\\|", b"|"));
        let data = data.filter(|d| !d.is_empty()).map(|d| replace(&d, b"\\|", b"|"));
        // Jail path
        if unsc_fpath.len() >= PATH_MAX {
            return fail("Path too long", "err path too long");
        }
        let jpath = String::from_utf8_lossy(&unsc_fpath).into_owned();
        if siem_fileop::ref_parent_folder(&jpath) {
            return fail("Path references parent folder", "err parent folder reference");
        }
        let url_s = String::from_utf8_lossy(&url).into_owned();
        self.tlog("DEBUG", format!("Downloading '{url_s}' to '{jpath}'"));
        let h = header.map(|h| String::from_utf8_lossy(&h).into_owned());
        let d = data.map(|d| String::from_utf8_lossy(&d).into_owned());
        match wurl_get(&self.log, &url_s, &jpath, h.as_deref(), d.as_deref(), timeout).await {
            OS_CONNERR => {
                self.tlog("DEBUG", format!("Cannot download file '{jpath}' from URL: '{url_s}'"));
                b"err connecting to url".to_vec()
            }
            OS_FILERR => {
                self.tlog("DEBUG", format!("Cannot open file '{jpath}'"));
                b"err writing file".to_vec()
            }
            OS_TIMEOUT => {
                self.tlog("DEBUG", format!("Timeout reached when downloading file '{jpath}' from URL: '{url_s}'"));
                b"err timeout".to_vec()
            }
            _ => {
                self.tlog("DEBUG2", format!("Download of '{url_s}' finished."));
                b"ok".to_vec()
            }
        }
    }
}

/// curl's error buffer for a failed transfer.
fn curl_error(e: &reqwest::Error) -> String {
    match e.status() {
        // CURLE_HTTP_RETURNED_ERROR with CURLOPT_FAILONERROR
        Some(st) => format!("The requested URL returned error: {}", st.as_u16()),
        None => e.to_string(),
    }
}

fn client(timeout: i64) -> Option<reqwest::Client> {
    let mut b = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
    if timeout > 0 {
        b = b.timeout(Duration::from_secs(timeout as u64));
    }
    b.build().ok()
}

/// `wurl_get`: download `url` (POST when `data`) into `dest`; 0 or OS_*ERR.
pub async fn wurl_get(log: &WLog, url: &str, dest: &str, header: Option<&str>, data: Option<&str>, timeout: i64) -> i32 {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    // umask(0006)
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o660);
    let mut fp = match opts.open(dest) {
        Ok(f) => f,
        Err(e) => {
            let n = e.raw_os_error().unwrap_or(0);
            log.debug1(format!("(1103): Could not open file '{dest}' due to [({n})-({})].", crate::wdb::errno_text(&e)));
            return OS_FILERR;
        }
    };
    let Some(c) = client(timeout) else {
        log.debug1("Parameter setup error at CURL");
        drop(fp);
        let _ = std::fs::remove_file(dest);
        return OS_CONNERR;
    };
    let mut req = match data {
        Some(d) => c.post(url).body(d.to_string()),
        None => c.get(url),
    };
    if let Some(h) = header {
        if let Some((k, v)) = h.split_once(':') {
            req = req.header(k.trim(), v.trim());
        }
    }
    let res = async {
        let r = req.send().await?.error_for_status()?;
        r.bytes().await
    }
    .await;
    match res {
        Ok(body) => {
            if fp.write_all(&body).is_err() {
                drop(fp);
                let _ = std::fs::remove_file(dest);
                return OS_FILERR;
            }
            0
        }
        Err(e) => {
            log.debug1(format!("CURL ERROR: {}", curl_error(&e)));
            drop(fp);
            let _ = std::fs::remove_file(dest);
            if e.is_timeout() {
                OS_TIMEOUT
            } else {
                OS_CONNERR
            }
        }
    }
}

/// `wurl_http_get`: the body (at most `max_size` bytes) or None.
pub async fn wurl_http_get(log: &WLog, url: &str, max_size: usize, timeout: i64) -> Option<Vec<u8>> {
    let Some(c) = client(timeout) else {
        log.debug1("Parameter setup error at CURL");
        return None;
    };
    let res = async {
        let r = c.get(url).send().await?.error_for_status()?;
        r.bytes().await
    }
    .await;
    match res {
        Ok(b) if b.len() > max_size => {
            log.warn("Response buffer size limit reached.");
            log.debug1("CURL ERROR Failure writing output to destination");
            None
        }
        Ok(b) => Some(b.to_vec()),
        Err(e) => {
            log.debug1(format!("CURL ERROR {}", curl_error(&e)));
            None
        }
    }
}

/// `wurl_request`: ask the download module to fetch `url` into `dest`.
pub async fn wurl_request(log: &WLog, url: &str, dest: &str, header: Option<&str>, data: Option<&str>, timeout: i64) -> i32 {
    let u = url.replace(' ', "%20");
    let d = dest.replace('|', "\\|");
    let h = header.map(|h| h.replace('|', "\\|"));
    let da = data.map(|x| x.replace('|', "\\|"));
    // zrequest = the lengths + sizeof(long) + 7; snprintf fills it and send() sends zrequest - 1 bytes
    let zrequest = u.len() + d.len() + "download".len() + h.as_ref().map_or(0, |s| s.len()) + da.as_ref().map_or(0, |s| s.len()) + 8 + 7;
    let mut req = format!("download {u}|{d}|{}|{}|{timeout}|", h.as_deref().unwrap_or(""), da.as_deref().unwrap_or("")).into_bytes();
    req.truncate(zrequest - 1);
    req.resize(zrequest - 1, 0);
    let mut sock = match LocalStream::connect(WM_DOWNLOAD_SOCK).await {
        Ok(s) => s,
        Err(_) => {
            log.warn(format!("Couldn't connect to download module socket '{WM_DOWNLOAD_SOCK}'"));
            return -1;
        }
    };
    if sock.write_all(&req).await.is_err() {
        log.error("Couldn't send request to download module.");
        return -1;
    }
    let mut resp = [0u8; 63];
    match sock.read(&mut resp).await {
        Err(_) => {
            log.error("Couldn't receive URL response from download module.");
            -1
        }
        Ok(0) => {
            log.error("Couldn't receive URL response from download module (closed unexpectedly).");
            -1
        }
        Ok(n) => match cstr(&resp[..n]) {
            b"ok" => 0,
            b"err connecting to url" => OS_CONNERR,
            b"err writing file" => OS_FILERR,
            b"err timeout" => OS_TIMEOUT,
            r => {
                log.debug1(cat(&[b"Couldn't download from '", u.as_bytes(), b"': ", r]));
                -1
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatch_errors_like_c() {
        let d = Download::new(true, crate::task_general::test_log());
        assert_eq!(d.dispatch(b"nospace").await, b"err empty command");
        assert_eq!(d.dispatch(b"upload x|y|").await, b"err invalid command");
        assert_eq!(d.dispatch(b"download http://x").await, b"err empty url");
        assert_eq!(d.dispatch(b"download http://x|file").await, b"err empty file name");
        assert_eq!(d.dispatch(b"download http://x|../f|").await, b"err parent folder reference");
        assert_eq!(wstr_chr(b"a\\|b|c", b'|'), Some(4));
    }
}
