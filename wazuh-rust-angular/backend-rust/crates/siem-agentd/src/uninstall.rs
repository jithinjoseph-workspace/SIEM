//! The anti-tampering check of `client-agent/agentd.c`
//! (`package_uninstall_validation`, `check_uninstall_permission`,
//! `authenticate_and_get_token`): before the package is removed, the
//! installer asks the Wazuh API whether the uninstall is allowed. The
//! HTTPS requests mirror `wurl_http_request` (shared/url.c).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

use siem_log::WLog;

/// `certs_list` (shared/url.c)
const CERTS_LIST: [&str; 5] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/usr/share/ssl/certs/ca-bundle.crt",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/etc/ssl/cert.pem",
];
/// `OS_SIZE_8192`: the response size limit given to `wurl_http_request`.
const MAX_SIZE: usize = 8192;

/// `curl_response`
pub struct Response {
    pub status_code: i64,
    pub body: Vec<u8>,
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Decode a `Transfer-Encoding: chunked` body.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(eol) = b.windows(2).position(|w| w == b"\r\n") else { break };
        let size_str = String::from_utf8_lossy(&b[..eol]);
        let Ok(size) = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16) else { break };
        b = &b[eol + 2..];
        if size == 0 || b.len() < size {
            out.extend_from_slice(&b[..size.min(b.len())]);
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = b.get(size + 2..).unwrap_or(&[]);
    }
    out
}

/// `wurl_http_request(method, headers, url, NULL, OS_SIZE_8192, 30, userpass, ssl_verify)`
pub fn http_request(method: &str, headers: &[String], url: &str, userpass: Option<&str>, ssl_verify: bool) -> Option<Response> {
    let rest = url.strip_prefix("https://")?;
    let (hostport, path) = match rest.find('/') {
        Some(p) => (&rest[..p], &rest[p..]),
        None => (rest, "/"),
    };
    let host = match hostport.rfind(':') {
        Some(p) if !hostport.starts_with('[') || hostport[..p].ends_with(']') => &hostport[..p],
        _ => hostport,
    }
    .trim_start_matches('[')
    .trim_end_matches(']');
    let addr = if hostport.contains(':') && !hostport.ends_with(']') { hostport.to_string() } else { format!("{hostport}:443") };

    let timeout = Duration::from_secs(30);
    let sa = addr.to_socket_addrs().ok()?.next()?;
    let tcp = TcpStream::connect_timeout(&sa, timeout).ok()?;
    tcp.set_read_timeout(Some(timeout)).ok()?;
    tcp.set_write_timeout(Some(timeout)).ok()?;

    let mut b = SslConnector::builder(SslMethod::tls()).ok()?;
    if ssl_verify {
        if let Some(cert) = CERTS_LIST.iter().find(|p| std::path::Path::new(p).exists()) {
            b.set_ca_file(cert).ok()?;
        }
    } else {
        b.set_verify(SslVerifyMode::NONE);
    }
    let mut cfg = b.build().configure().ok()?;
    if !ssl_verify {
        cfg.set_verify_hostname(false);
    }
    let mut tls = cfg.connect(host, tcp).ok()?;

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {hostport}\r\n");
    if let Some(up) = userpass {
        req.push_str(&format!("Authorization: Basic {}\r\n", base64(up.as_bytes())));
    }
    req.push_str("Accept: */*\r\nUser-Agent: curl/7.58.0\r\n");
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).ok()?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let hdr_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..hdr_end]).into_owned();
    let status_code = head.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;
    let mut body = raw[hdr_end + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    body.truncate(MAX_SIZE);
    Some(Response { status_code, body })
}

/// `check_uninstall_permission`: `false` when the uninstall is granted.
pub fn check_uninstall_permission(log: &WLog, token: &str, host: &str, ssl_verify: bool) -> bool {
    let url = format!("https://{host}/agents/uninstall");
    let headers = vec![format!("Authorization: Bearer {token}")];
    match http_request("GET", &headers, &url, None, ssl_verify) {
        Some(r) => {
            if r.status_code == 200 {
                log.info("(9501): Validation of the uninstallation of the Wazuh agent package granted.");
                return false;
            } else if r.status_code == 403 {
                log.info("(9502): Validation of the uninstallation of the Wazuh agent package denied.");
            } else {
                log.error(format!(
                    "(4116): Unexpected status code in Wazuh agent package uninstallation request: {}\n",
                    r.status_code
                ));
            }
        }
        None => log.error("(4117): Failed validation request to uninstall Wazuh agent package."),
    }
    true
}

/// `authenticate_and_get_token`
pub fn authenticate_and_get_token(log: &WLog, userpass: &str, host: &str, ssl_verify: bool) -> Option<String> {
    let url = format!("https://{host}/security/user/authenticate?raw=true");
    match http_request("POST", &[], &url, Some(userpass), ssl_verify) {
        Some(r) if r.status_code == 200 => Some(String::from_utf8_lossy(&r.body).into_owned()),
        Some(r) => {
            log.error(format!(
                "(4116): Unexpected status code in Wazuh agent package uninstallation request: {}\n",
                r.status_code
            ));
            None
        }
        None => {
            log.error("(4117): Failed validation request to uninstall Wazuh agent package.");
            None
        }
    }
}

/// `package_uninstall_validation`: the exit code (0 = granted).
pub fn package_uninstall_validation(
    log: &WLog,
    token: Option<&str>,
    login: Option<&str>,
    host: &str,
    ssl_verify: bool,
) -> bool {
    let mut result = true;
    log.info("(9500): Starting user validation to uninstall the Wazuh agent package.");
    if let Some(t) = token {
        result = check_uninstall_permission(log, t, host, ssl_verify);
        if result {
            return result;
        }
    }
    if let Some(l) = login {
        match authenticate_and_get_token(log, l, host, ssl_verify) {
            Some(t) => result = check_uninstall_permission(log, &t, host, ssl_verify),
            None => log.error(format!("(4115): Error trying to get API token with login: {l}")),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_chunks() {
        assert_eq!(base64(b"wazuh:wazuh"), "d2F6dWg6d2F6dWg=");
        assert_eq!(dechunk(b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n"), b"abcdef");
    }
}
