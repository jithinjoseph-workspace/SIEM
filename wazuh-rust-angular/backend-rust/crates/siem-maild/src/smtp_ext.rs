//! Extension, not in Wazuh 4.14.7: authenticated SMTP over TLS.
//!
//! Wazuh's maild speaks plain SMTP on port 25 without login, so providers
//! like Gmail or Office 365 need a local relay. When `etc/smtp_auth.conf`
//! exists (written by siem-api from the platform's SMTP settings), every
//! e-mail maild/monitord sends goes through it instead:
//!
//! ```text
//! host=smtp.gmail.com
//! port=587
//! security=starttls      # starttls | tls | none
//! user=alerts@example.com
//! password=<app password>
//! ```
//!
//! The dialog is then EHLO, STARTTLS (or implicit TLS on 465), AUTH PLAIN,
//! followed by the same MAIL FROM / RCPT TO / DATA as Wazuh. In this mode the
//! message text is sent with CRLF line ends and dot-stuffing.

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::smtp::{new_session, reply_ok, Conn, Envelope, Session};

pub const SMTP_AUTH_FILE: &str = "etc/smtp_auth.conf";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SmtpAuth {
    pub host: String,
    pub port: u16,
    /// "starttls", "tls" or "none"
    pub security: String,
    pub user: String,
    pub password: String,
}

/// Parses `smtp_auth.conf` text.
pub fn parse(text: &str) -> Option<SmtpAuth> {
    let mut a = SmtpAuth { port: 587, security: "starttls".into(), ..Default::default() };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim().to_string();
        match k.trim() {
            "host" => a.host = v,
            "port" => a.port = v.parse().ok()?,
            "security" => a.security = v.to_ascii_lowercase(),
            "user" => a.user = v,
            "password" => a.password = v,
            _ => {}
        }
    }
    (!a.host.is_empty() && matches!(a.security.as_str(), "starttls" | "tls" | "none")).then_some(a)
}

/// The settings, when the extension is configured.
pub fn load() -> Option<SmtpAuth> {
    parse(&std::fs::read_to_string(SMTP_AUTH_FILE).ok()?)
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let c = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(c)
    })
    .clone()
}

fn wrap(host: &str, tcp: TcpStream) -> Result<Conn, String> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("SMTP TLS: invalid server name '{host}': {e}"))?;
    let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| format!("SMTP TLS: {e}"))?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    // finish the handshake now so certificate errors are reported here
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).map_err(|e| format!("SMTP TLS handshake with '{host}' failed: {e}"))?;
    }
    Ok(Conn::Tls(Box::new(s)))
}

/// A whole SMTP reply: lines until one whose 4th byte is not '-'.
pub fn read_reply(ss: &mut Session) -> Option<Vec<u8>> {
    let mut all = Vec::new();
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match ss.read_raw(&mut b) {
            Ok(1) => {
                line.push(b[0]);
                if b[0] == b'\n' {
                    let done = line.len() < 4 || line[3] != b'-';
                    all.append(&mut line);
                    if done || all.len() > 65536 {
                        return Some(all);
                    }
                }
            }
            _ => {
                all.append(&mut line);
                return (!all.is_empty()).then_some(all);
            }
        }
    }
}

fn expect(ss: &mut Session, code: &str, what: &str) -> Result<(), String> {
    let r = ss.recv();
    if reply_ok(code, &r) && r.as_ref().is_some_and(|m| m.starts_with(code.as_bytes())) {
        return Ok(());
    }
    let text = r.map(|m| String::from_utf8_lossy(&m).trim().to_string()).unwrap_or_else(|| "null".into());
    Err(format!("{what}: {text}"))
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Connects, secures and authenticates; the session then continues with
/// `Mail From` exactly like the plain dialog.
pub fn open(a: &SmtpAuth, env: &Envelope) -> Result<Session, String> {
    let tcp = TcpStream::connect((a.host.as_str(), a.port)).map_err(|e| format!("Unable to connect to SMTP server {}:{}: {e}", a.host, a.port))?;
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(300)));
    let conn = if a.security == "tls" { wrap(&a.host, tcp)? } else { Conn::Tcp(tcp) };
    let mut ss = new_session(conn);
    expect(&mut ss, "220", "(1762): Banner not received from server")?;
    let helo = env.heloserver.clone().unwrap_or_else(|| "notify.ossec.net".into());
    ss.send(format!("EHLO {helo}\r\n").as_bytes());
    expect(&mut ss, "250", "(1763): Hello not accepted by server")?;
    if a.security == "starttls" {
        ss.send(b"STARTTLS\r\n");
        expect(&mut ss, "220", "SMTP server refused STARTTLS")?;
        let Conn::Tcp(tcp) = ss.conn else { return Err("SMTP STARTTLS on a TLS connection".into()) };
        ss = new_session(wrap(&a.host, tcp)?);
        ss.send(format!("EHLO {helo}\r\n").as_bytes());
        expect(&mut ss, "250", "(1763): Hello not accepted by server")?;
    }
    if !a.user.is_empty() {
        let token = b64(format!("\0{}\0{}", a.user, a.password).as_bytes());
        ss.send(format!("AUTH PLAIN {token}\r\n").as_bytes());
        expect(&mut ss, "235", "SMTP authentication failed")?;
    }
    Ok(ss)
}

/// DATA text for strict servers: bare LF -> CRLF, and a '.' starting a line doubled.
pub fn normalize_data(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() + 16);
    let mut bol = true;
    for (i, &c) in b.iter().enumerate() {
        if bol && c == b'.' {
            out.push(b'.');
        }
        if c == b'\n' && (i == 0 || b[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(c);
        bol = c == b'\n';
    }
    out
}

/// Sends one test message through the configured server (siem-api's "Send test email").
pub fn send_test(a: &SmtpAuth, from: &str, to: &str) -> Result<(), String> {
    let env = Envelope { from: from.into(), ..Default::default() };
    let mut ss = open(a, &env)?;
    ss.send(format!("MAIL FROM:<{from}>\r\n").as_bytes());
    expect(&mut ss, "250", "(1764): Mail from not accepted by server")?;
    ss.send(format!("RCPT TO:<{to}>\r\n").as_bytes());
    expect(&mut ss, "250", &format!("(1765): RCPT TO not accepted by server - '{to}'."))?;
    ss.send(b"DATA\r\n");
    expect(&mut ss, "354", "(1766): DATA not accepted by server")?;
    let date = chrono::Local::now().format("%a, %d %b %Y %T %z");
    let msg = format!("From: Wazuh <{from}>\r\nTo: <{to}>\r\nDate: {date}\r\nSubject: Wazuh notification - test e-mail\r\n\r\nThis is a test e-mail from the SIEM manager. Alert e-mails will use these settings.\r\n");
    ss.send(&normalize_data(msg.as_bytes()));
    ss.send(b"\r\n.\r\n");
    expect(&mut ss, "250", "(1767): End of DATA not accepted by server")?;
    ss.send(b"QUIT\r\n");
    if let Conn::Tcp(s) = &mut ss.conn {
        let _ = s.flush();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_settings() {
        let a = parse("# x\nhost = smtp.gmail.com\nport=465\nsecurity=TLS\nuser=a@b\npassword=p=q\n").unwrap();
        assert_eq!((a.host.as_str(), a.port, a.security.as_str(), a.password.as_str()), ("smtp.gmail.com", 465, "tls", "p=q"));
        assert!(parse("port=25").is_none());
        assert!(parse("host=h\nsecurity=ssl").is_none());
    }

    #[test]
    fn data_normalized() {
        assert_eq!(normalize_data(b".a\nb\r\n.c"), b"..a\r\nb\r\n..c");
    }
}
