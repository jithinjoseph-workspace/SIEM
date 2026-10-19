//! `os_maild/sendmail.c` (`OS_Sendmail`, `OS_Sendsms`) and
//! `os_maild/sendcustomemail.c` (`OS_SendCustomEmail`): the SMTP dialog,
//! or a local sendmail program when the server is a path.
//!
//! Extension (not in Wazuh): when `etc/smtp_auth.conf` exists the dialog runs
//! over STARTTLS or implicit TLS with SMTP AUTH, so providers such as Gmail or
//! Office 365 can be used directly; see [`crate::smtp_ext`].

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::client::{MailMsg, Subject};
use crate::config::{Mail, FULL_FORMAT, SMS_FORMAT};
use crate::log;
use crate::smtp_ext;

const SMTP_DEFAULT_PORT: u16 = 25;
const OS_SIZE_1024: usize = 1024;
/// `SOCK_RECV_TIME0`
const SOCK_RECV_TIME0: u64 = 300;

const BANNER_ERROR: &str = "(1762): Banner not received from server";
const HELO_ERROR: &str = "(1763): Hello not accepted by server";
const FROM_ERROR: &str = "(1764): Mail from not accepted by server";
const DATA_ERROR: &str = "(1766): DATA not accepted by server";
const END_DATA_ERROR: &str = "(1767): End of DATA not accepted by server";

/// What a send needs from `MailConfig` (copied, like the forked child's view).
#[derive(Debug, Clone, Default)]
pub struct Envelope {
    pub smtpserver: String,
    pub heloserver: Option<String>,
    pub from: String,
    pub reply_to: Option<String>,
    pub idsname: Option<String>,
    pub to: Vec<String>,
    pub gran_to: Vec<String>,
    pub gran_set: Vec<i32>,
    pub strict_checking: bool,
}

impl Envelope {
    pub fn of(m: &Mail) -> Envelope {
        Envelope {
            smtpserver: m.smtpserver.clone().unwrap_or_default(),
            heloserver: m.heloserver.clone(),
            from: m.from.clone().unwrap_or_else(|| "(null)".into()),
            reply_to: m.reply_to.clone(),
            idsname: m.idsname.clone(),
            to: m.to.clone(),
            gran_to: m.gran_to.clone(),
            gran_set: m.gran_set.clone(),
            strict_checking: m.strict_checking != 0,
        }
    }
}

/// `snprintf(buf, n, ...)`
fn cut(s: String, n: usize) -> Vec<u8> {
    let mut b = s.into_bytes();
    b.truncate(n.saturating_sub(1));
    b
}

/// The connection: SMTP socket (plain or TLS) or a sendmail program's stdin.
pub enum Conn {
    Tcp(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    Pipe(std::process::Child),
}

pub struct Session {
    pub conn: Conn,
    /// Extension mode: replies are read whole and DATA is normalized.
    ext: bool,
}

impl Session {
    /// `OS_SendTCP` / `fprintf(sendmail->file_in, ...)`
    pub fn send(&mut self, b: &[u8]) {
        let _ = match &mut self.conn {
            Conn::Tcp(s) => s.write_all(b),
            Conn::Tls(s) => s.write_all(b).and_then(|_| s.flush()),
            Conn::Pipe(c) => c.stdin.as_mut().map(|i| i.write_all(b)).unwrap_or(Ok(())),
        };
    }

    /// `OS_RecvTCP(socket, OS_SIZE_1024)`: one `recv`; `None` on EOF or error.
    /// In extension mode: a whole (possibly multi-line) reply.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        if self.ext {
            return smtp_ext::read_reply(self);
        }
        let mut buf = vec![0u8; OS_SIZE_1024 - 1];
        let n = match &mut self.conn {
            Conn::Tcp(s) => s.read(&mut buf),
            Conn::Tls(s) => s.read(&mut buf),
            Conn::Pipe(_) => return None,
        };
        match n {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                // C treats the reply as a string
                if let Some(z) = buf.iter().position(|&c| c == 0) {
                    buf.truncate(z);
                }
                Some(buf)
            }
            _ => None,
        }
    }

    pub fn read_raw(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.conn {
            Conn::Tcp(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
            Conn::Pipe(_) => Ok(0),
        }
    }

    /// Body text: verbatim in Wazuh mode; CRLF line ends and dot-stuffing in
    /// extension mode (strict servers such as Gmail need both).
    fn send_body(&mut self, b: &[u8]) {
        if self.ext && !matches!(self.conn, Conn::Pipe(_)) {
            let n = smtp_ext::normalize_data(b);
            self.send(&n);
        } else {
            self.send(b);
        }
    }

    fn is_pipe(&self) -> bool {
        matches!(self.conn, Conn::Pipe(_))
    }

    /// `close(socket)` / `wpclose(sendmail)`
    fn close(self) {
        if let Conn::Pipe(mut c) = self.conn {
            drop(c.stdin.take());
            if let Err(e) = c.wait() {
                log().error(format!("(1111): Error during waitpid()-call due to [({})-({})].", e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
            }
        }
    }
}

/// `OS_Match(pattern, msg)`
fn ok(pattern: &str, msg: &Option<Vec<u8>>) -> bool {
    msg.as_ref().is_some_and(|m| siem_regex::os_word_match(pattern, &String::from_utf8_lossy(m)))
}

fn msg_text(m: &Option<Vec<u8>>) -> String {
    m.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_else(|| "null".into())
}

/// Opens the connection and runs the dialog up to (not including) `Mail From`.
/// `Err(code)` is what the C function returns.
fn open(env: &Envelope, helo_custom: bool, recv_timeout: bool) -> Result<Session, i32> {
    if env.smtpserver.starts_with('/') {
        // wpopenv(smtpserver, [smtpserver], W_BIND_STDIN)
        return std::process::Command::new(&env.smtpserver)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map(|c| Session { conn: Conn::Pipe(c), ext: false })
            .map_err(|_| -1);
    }
    if let Some(auth) = smtp_ext::load() {
        return smtp_ext::open(&auth, env).map_err(|e| {
            log().error(e);
            -1
        });
    }
    let s = match TcpStream::connect((env.smtpserver.as_str(), SMTP_DEFAULT_PORT)) {
        Ok(s) => s,
        Err(_) => return Err(-1),
    };
    if recv_timeout && s.set_read_timeout(Some(Duration::from_secs(SOCK_RECV_TIME0))).is_err() {
        log().error("Couldn't set receiving timeout for socket.");
    }
    let mut ss = Session { conn: Conn::Tcp(s), ext: false };
    let msg = ss.recv();
    if !ok("220", &msg) {
        log().error(BANNER_ERROR);
        return Err(-1);
    }
    let helo = if helo_custom { env.heloserver.clone().unwrap_or_else(|| "notify.ossec.net".into()) } else { "notify.ossec.net".into() };
    ss.send(&cut(format!("Helo {helo}\r\n"), 256));
    let mut msg = ss.recv();
    if !ok("250", &msg) {
        match &msg {
            // Some servers (virus scans in the middle) send two banners
            Some(_) if ok("220", &msg) => {
                msg = ss.recv();
                if !ok("250", &msg) {
                    log().error(format!("{HELO_ERROR}:{}", msg_text(&msg)));
                    return Err(-1);
                }
            }
            Some(_) => {
                log().error(format!("{HELO_ERROR}:{}", msg_text(&msg)));
                return Err(-1);
            }
            None => {
                log().error(format!("{HELO_ERROR}:null"));
                return Err(-1);
            }
        }
    }
    Ok(ss)
}

/// `Mail From` + one `Rcpt To` (with its error handling done by the caller).
fn mail_from(ss: &mut Session, from: &str, n: usize) -> bool {
    ss.send(&cut(format!("Mail From: <{from}>\r\n"), n));
    let msg = ss.recv();
    if !ok("250", &msg) {
        log().error(FROM_ERROR);
        return false;
    }
    true
}

fn rcpt(ss: &mut Session, to: &str, n: usize) -> bool {
    ss.send(&cut(format!("Rcpt To: <{to}>\r\n"), n));
    ok("250", &ss.recv())
}

fn data(ss: &mut Session) -> bool {
    ss.send(b"DATA\r\n");
    if !ok("354", &ss.recv()) {
        log().error(DATA_ERROR);
        return false;
    }
    true
}

/// `append_mailbox` loop: "<a>, <b>" bounded by `cap` bytes.
fn mailbox_list<'a>(addrs: impl Iterator<Item = &'a String>, cap: usize) -> String {
    let mut out = String::new();
    let mut rem = cap;
    for (i, a) in addrs.enumerate() {
        let piece = if i == 0 { format!("<{a}>") } else { format!(", <{a}>") };
        if piece.len() >= rem {
            break;
        }
        rem -= piece.len();
        out.push_str(&piece);
    }
    out
}

fn date_header(t: &chrono::DateTime<chrono::Local>, n: usize) -> Vec<u8> {
    cut(t.format("Date: %a, %d %b %Y %T %z\r\n").to_string(), n)
}

/// End of DATA, QUIT, close. Returns 0, or -1 when strict checking fails.
fn finish(mut ss: Session, strict: bool) -> i32 {
    if ss.is_pipe() {
        ss.close();
        return 0;
    }
    ss.send(b"\r\n.\r\n");
    let msg = ss.recv();
    if strict && !ok("250", &msg) {
        log().error(END_DATA_ERROR);
        return -1;
    }
    ss.send(b"QUIT\r\n");
    let _ = ss.recv();
    ss.close();
    0
}

/// `OS_Sendmail`: one e-mail with every queued alert (oldest first).
pub fn os_sendmail(env: &Envelope, t: &chrono::DateTime<chrono::Local>, mails: &[MailMsg], g: &Subject) -> i32 {
    let Some(first) = mails.first() else {
        log().error("No email to be sent. Inconsistent state.");
        return -1;
    };
    let mut ss = match open(env, true, true) {
        Ok(s) => s,
        Err(c) => return c,
    };
    if !ss.is_pipe() {
        if !mail_from(&mut ss, &env.from, 256) {
            return -1;
        }
        for to in &env.to {
            if !rcpt(&mut ss, to, 256) {
                log().error(format!("(1765): RCPT TO not accepted by server - '{to}'."));
                return -1;
            }
        }
        for (i, to) in env.gran_to.iter().enumerate() {
            if env.gran_set.get(i) != Some(&FULL_FORMAT) {
                continue;
            }
            if !rcpt(&mut ss, to, 256) {
                log().error(format!("(1765): RCPT TO not accepted by server - '{to}'."));
            }
        }
        if !data(&mut ss) {
            return -1;
        }
    }
    ss.send(&cut(format!("From: Wazuh <{}>\r\n", env.from), 255));
    if let Some(r) = &env.reply_to {
        ss.send(&cut(format!("Reply-To: Wazuh <{r}>\r\n"), 256));
    }
    if !env.to.is_empty() || !env.gran_to.is_empty() {
        let full: Vec<&String> = env.gran_to.iter().enumerate().filter(|(i, _)| env.gran_set.get(*i) == Some(&FULL_FORMAT)).map(|(_, t)| t).collect();
        let list = mailbox_list(env.to.iter().chain(full), 1024);
        if !list.is_empty() {
            let hdr = format!("To: {list}\r\n");
            if !ss.is_pipe() && hdr.len() >= 255 {
                log().error("Error formatting 'To' header: snprintf failed or output truncated.");
                return -1;
            }
            ss.send(hdr.as_bytes());
        }
    }
    ss.send(&date_header(t, 255));
    if let Some(i) = &env.idsname {
        ss.send(&cut(format!("X-IDS-OSSEC: {i}\r\n"), 256));
    }
    let subject = if g.level != 0 && !g.text.is_empty() { &g.text } else { &first.subject };
    let mut h = b"Subject: ".to_vec();
    h.extend_from_slice(subject);
    h.extend_from_slice(b"\r\n");
    h.truncate(255);
    ss.send(&h);
    ss.send(b"\r\n");
    for m in mails {
        ss.send_body(&m.body);
    }
    finish(ss, env.strict_checking)
}

/// `OS_Sendsms`
pub fn os_sendsms(env: &Envelope, t: &chrono::DateTime<chrono::Local>, sms: &MailMsg) -> i32 {
    let mut ss = match open(env, true, true) {
        Ok(s) => s,
        Err(c) => return c,
    };
    if !ss.is_pipe() {
        if !mail_from(&mut ss, &env.from, 127) {
            return -1;
        }
        let mut final_to = String::new();
        let mut first = true;
        for (i, to) in env.gran_to.iter().enumerate() {
            if env.gran_set.get(i) != Some(&SMS_FORMAT) {
                continue;
            }
            if !rcpt(&mut ss, to, 127) {
                log().error(format!("(1765): RCPT TO not accepted by server - '{to}'."));
                return -1;
            }
            let piece = if first { format!("<{to}>") } else { format!(", <{to}>") };
            if final_to.len() + piece.len() < 510 {
                final_to.push_str(&piece);
                first = false;
            }
        }
        if !data(&mut ss) {
            return -1;
        }
        if !final_to.is_empty() {
            let hdr = format!("To: {final_to}\r\n");
            if hdr.len() >= 127 {
                log().error("Error formatting 'To' header: snprintf failed or output truncated.");
                return -1;
            }
            ss.send(hdr.as_bytes());
        }
    }
    ss.send(&cut(format!("From: Wazuh <{}>\r\n", env.from), 127));
    if let Some(r) = &env.reply_to {
        ss.send(&cut(format!("Reply-To: Wazuh <{r}>\r\n"), 127));
    }
    ss.send(&date_header(t, 127));
    let mut h = b"Subject: ".to_vec();
    h.extend_from_slice(&sms.subject);
    h.extend_from_slice(b"\r\n");
    h.truncate(126);
    ss.send(&h);
    ss.send(b"\r\n");
    ss.send_body(&sms.body);
    finish(ss, env.strict_checking)
}

/// `OS_SendCustomEmail` (the daily reports): the body is the report file.
pub fn os_send_custom_email(to: &[String], subject: &str, smtpserver: &str, from: &str, idsname: Option<&str>, body: &[u8], t: &chrono::DateTime<chrono::Local>) -> i32 {
    let env = Envelope { smtpserver: smtpserver.into(), from: from.into(), ..Default::default() };
    let mut ss = match open(&env, false, false) {
        Ok(s) => s,
        Err(c) => return c,
    };
    if !ss.is_pipe() {
        if !mail_from(&mut ss, from, 127) {
            return -1;
        }
        for t in to {
            if !rcpt(&mut ss, t, 127) {
                log().error(format!("(1765): RCPT TO not accepted by server - '{t}'."));
                return -1;
            }
        }
        if !data(&mut ss) {
            return -1;
        }
    }
    ss.send(&cut(format!("From: Wazuh <{from}>\r\n"), 127));
    let hdr = format!("To: {}\r\n", mailbox_list(to.iter(), 1024));
    if hdr.len() >= 127 {
        log().error("Error formatting 'To' header: snprintf failed or output truncated.");
        return -1;
    }
    ss.send(hdr.as_bytes());
    ss.send(&date_header(t, 127));
    if let Some(i) = idsname {
        ss.send(&cut(format!("X-IDS-OSSEC: {i}\r\n"), 127));
    }
    ss.send(&cut(format!("Subject: {subject}\r\n"), 127));
    ss.send(b"\r\n");
    // fgets(buffer, 2048): the file in pieces of at most 2047 bytes, each sent alone
    let mut rest = body;
    while !rest.is_empty() {
        let n = rest.iter().take(2047).position(|&c| c == b'\n').map(|p| p + 1).unwrap_or(rest.len().min(2047));
        ss.send_body(&rest[..n]);
        rest = &rest[n..];
    }
    if ss.is_pipe() {
        ss.close();
        return 0;
    }
    ss.send(b"\r\n.\r\n");
    let _ = ss.recv();
    ss.send(b"QUIT\r\n");
    let _ = ss.recv();
    ss.close();
    0
}

/// Exposed for the extension (it shares the plain-mode reply check).
pub(crate) fn reply_ok(code: &str, m: &Option<Vec<u8>>) -> bool {
    ok(code, m)
}

pub(crate) fn new_session(conn: Conn) -> Session {
    Session { conn, ext: true }
}
