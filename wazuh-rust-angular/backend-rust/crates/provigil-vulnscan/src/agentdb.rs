//! Agent database (provigil-db) client: socket `queue/db/wdb`, length-prefixed frames, query
//! texts and answer parsing. The query texts and formats are provigil-db's protocol.

use serde_json::Value;
use std::io::{Read, Write};
use std::sync::Mutex;

const MAX_ANSWER: usize = 64 << 20;

#[derive(Debug, Clone, PartialEq)]
pub enum DbError {
    /// `ok {"status":"NOT_SYNCED"}`: the agent's data is not in the database yet.
    NotSynced,
    Failed(String),
}

impl DbError {
    pub fn text(&self) -> String {
        match self {
            DbError::NotSynced => NOT_SYNCED_TEXT.into(),
            DbError::Failed(s) => s.clone(),
        }
    }
}

pub const NOT_SYNCED_TEXT: &str = "DB query not synced";

/// Answers queries; the host gives the socket client, tests give a fake.
pub trait AgentDb: Send + Sync {
    fn query(&self, q: &str) -> Result<Vec<Value>, DbError>;
}

fn agent_id(id: &str) -> Result<&str, DbError> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DbError::Failed("Invalid agent id".into()));
    }
    Ok(id)
}

pub fn q_osinfo(id: &str) -> Result<String, DbError> {
    Ok(format!("agent {} osinfo get ", agent_id(id)?))
}
pub fn q_hotfixes(id: &str) -> Result<String, DbError> {
    Ok(format!("agent {} hotfix get ", agent_id(id)?))
}
pub fn q_packages(id: &str) -> Result<String, DbError> {
    Ok(format!("agent {} package get ", agent_id(id)?))
}
pub fn q_all_agents() -> String {
    "global get-all-agents context ".into()
}
pub fn q_agent_info(id: &str) -> String {
    format!("global get-agent-info {id} ")
}

fn parse_body(body: &str) -> Result<Value, DbError> {
    serde_json::from_str(body).map_err(|e| DbError::Failed(format!("Error parsing JSON response: {body}. Exception id: 101. {e}")))
}

/// Interprets the frames of one query: zero or more `due` parts, then the final answer.
pub fn interpret(frames: &[String]) -> Result<Vec<Value>, DbError> {
    let mut parts = Vec::new();
    for f in frames {
        // The kind is decided by how the text starts; the body follows the code and one character.
        let code = ["due", "ok", "err", "ign", "unk"].into_iter().find(|c| f.starts_with(c));
        let body = code.map_or("", |c| f.get(c.len() + 1..).unwrap_or(""));
        match code {
            Some("due") => parts.push(parse_body(body)?),
            Some("ok") => {
                // After `due` parts any `ok` closes the answer; its body is ignored.
                if !parts.is_empty() {
                    return Ok(parts);
                }
                return match parse_body(body)? {
                    Value::Array(a) => Ok(a),
                    v if v.get("status").and_then(Value::as_str) == Some("NOT_SYNCED") => Err(DbError::NotSynced),
                    v => Ok(vec![v]),
                };
            }
            Some("err") => return Err(DbError::Failed(format!("DB query error: {body}"))),
            Some("ign") => return Err(DbError::Failed(format!("DB query ignored: {body}"))),
            Some("unk") => return Err(DbError::Failed(format!("DB query unknown response: {body}"))),
            _ if f.is_empty() => return Err(DbError::Failed("Empty DB response".into())),
            _ => return Err(DbError::Failed(format!("DB query invalid response: {f}"))),
        }
    }
    Err(DbError::Failed("Empty DB response".into()))
}

/// Port of a loopback socket: decimal text in `<socket>.port`. A missing file or bad text is a
/// connection failure, like a refused connection.
pub fn read_port(socket: &std::path::Path) -> std::io::Result<u16> {
    let mut p = socket.as_os_str().to_owned();
    p.push(".port");
    let text = std::fs::read_to_string(&p)?;
    text.trim()
        .parse::<u16>()
        .ok()
        .filter(|n| *n != 0)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "invalid port file"))
}

/// A connected byte stream to provigil-db.
pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

pub type Connector = Box<dyn Fn() -> std::io::Result<Box<dyn Stream>> + Send + Sync>;

/// Socket client: one connection, one query at a time, one reconnect on transport errors.
pub struct SocketAgentDb {
    connect: Connector,
    conn: Mutex<Option<Box<dyn Stream>>>,
}

impl SocketAgentDb {
    pub fn new(connect: Connector) -> Self {
        SocketAgentDb { connect, conn: Mutex::new(None) }
    }

    /// The Unix socket `<home>/queue/db/wdb`.
    #[cfg(unix)]
    pub fn unix(home: &std::path::Path) -> Self {
        let path = home.join("queue/db/wdb");
        Self::new(Box::new(move || Ok(Box::new(std::os::unix::net::UnixStream::connect(&path)?) as Box<dyn Stream>)))
    }

    /// TCP to `127.0.0.1:<port from <socket>.port>`; the port file is read on every attempt.
    pub fn loopback(socket: &std::path::Path) -> Self {
        let socket = socket.to_path_buf();
        Self::new(Box::new(move || {
            let port = read_port(&socket)?;
            Ok(Box::new(std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))?) as Box<dyn Stream>)
        }))
    }

    /// The platform's local socket to provigil-db (`<home>/queue/db/wdb`).
    #[cfg(unix)]
    pub fn local(home: &std::path::Path) -> Self {
        Self::unix(home)
    }

    /// The platform's local socket to provigil-db (`<home>/queue/db/wdb`).
    #[cfg(not(unix))]
    pub fn local(home: &std::path::Path) -> Self {
        Self::loopback(&home.join("queue/db/wdb"))
    }

    fn exchange(s: &mut dyn Stream, q: &str) -> std::io::Result<Vec<String>> {
        s.write_all(&(q.len() as u32).to_le_bytes())?;
        s.write_all(q.as_bytes())?;
        let mut frames = Vec::new();
        loop {
            let mut len = [0u8; 4];
            s.read_exact(&mut len)?;
            let n = u32::from_le_bytes(len) as usize;
            if n > MAX_ANSWER {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "answer too large"));
            }
            let mut buf = vec![0u8; n];
            s.read_exact(&mut buf)?;
            let t = String::from_utf8_lossy(&buf).into_owned();
            let done = !t.starts_with("due");
            frames.push(t);
            if done {
                return Ok(frames);
            }
        }
    }
}

impl AgentDb for SocketAgentDb {
    /// One connect attempt per query attempt: a connect failure ends the query with the system
    /// error text; an exchange error drops the connection and retries once.
    fn query(&self, q: &str) -> Result<Vec<Value>, DbError> {
        let mut g = self.conn.lock().unwrap();
        for _ in 0..2 {
            if g.is_none() {
                *g = Some((self.connect)().map_err(|e| DbError::Failed(e.to_string()))?);
            }
            let Some(s) = g.as_mut() else { continue };
            match Self::exchange(s.as_mut(), q) {
                Ok(frames) => return interpret(&frames),
                Err(_) => *g = None,
            }
        }
        Err(DbError::Failed("Connection with provigil-db lost.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn f(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn answers() {
        assert_eq!(interpret(&f(&["ok [{\"a\":1}]"])).unwrap(), vec![json!({"a":1})]);
        assert_eq!(interpret(&f(&["due {\"a\":1}", "due {\"a\":2}", "ok"])).unwrap().len(), 2);
        assert_eq!(interpret(&f(&["ok {\"b\":2}"])).unwrap(), vec![json!({"b":2})]);
        assert_eq!(interpret(&f(&["ok {\"status\":\"NOT_SYNCED\"}"])).unwrap_err(), DbError::NotSynced);
        assert_eq!(interpret(&f(&["err No such table"])).unwrap_err(), DbError::Failed("DB query error: No such table".into()));
        assert_eq!(interpret(&f(&[""])).unwrap_err(), DbError::Failed("Empty DB response".into()));
        assert_eq!(interpret(&f(&["ign x"])).unwrap_err(), DbError::Failed("DB query ignored: x".into()));
        assert_eq!(interpret(&f(&["what"])).unwrap_err(), DbError::Failed("DB query invalid response: what".into()));
        assert!(interpret(&f(&["ok {x"])).unwrap_err().text().starts_with("Error parsing JSON response: {x. Exception id: 101. "));
        // D56: after `due` parts any `ok` ends the answer with exactly the parts.
        let rows = |v: &[&str]| interpret(&f(v)).unwrap();
        assert_eq!(rows(&["due {\"name\":\"a\"}", "due {\"name\":\"b\"}", "ok {\"status\":\"SUCCESS\"}"]), vec![json!({"name":"a"}), json!({"name":"b"})]);
        assert_eq!(rows(&["due {\"id\":1}", "ok []"]), vec![json!({"id":1})]);
        assert_eq!(rows(&["due {\"hotfix\":\"KB1\"}", "ok {\"status\":\"NOT_SYNCED\"}"]), vec![json!({"hotfix":"KB1"})]);
        assert_eq!(rows(&["ok {\"status\":\"SUCCESS\"}"]), vec![json!({"status":"SUCCESS"})]);
        // D13: a bare `ok` without parts is a parse error; the kind is decided by the start.
        assert!(interpret(&f(&["ok"])).unwrap_err().text().starts_with("Error parsing JSON response: . Exception id: 101. "));
        assert!(interpret(&f(&["okay"])).unwrap_err().text().starts_with("Error parsing JSON response: y. Exception id: 101. "));
        assert_eq!(interpret(&f(&["errX"])).unwrap_err(), DbError::Failed("DB query error: ".into()));
    }

    #[test]
    fn query_texts() {
        assert_eq!(q_osinfo("001").unwrap(), "agent 001 osinfo get ");
        assert_eq!(q_hotfixes("001").unwrap(), "agent 001 hotfix get ");
        assert_eq!(q_packages("001").unwrap(), "agent 001 package get ");
        assert_eq!(q_all_agents(), "global get-all-agents context ");
        assert_eq!(q_agent_info("001"), "global get-agent-info 001 ");
        assert_eq!(q_osinfo("1a").unwrap_err(), DbError::Failed("Invalid agent id".into()));
    }

    /// Fake provigil-db on a loopback port: each connection answers one query with `answer`,
    /// then closes.
    fn fake_db(answer: &'static str) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut len = [0u8; 4];
                if s.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut q = vec![0u8; u32::from_le_bytes(len) as usize];
                let _ = s.read_exact(&mut q);
                let _ = s.write_all(&(answer.len() as u32).to_le_bytes());
                let _ = s.write_all(answer.as_bytes());
            }
        });
        port
    }

    #[test]
    fn loopback_port_file() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("queue/db")).unwrap();
        let port_file = home.path().join("queue/db/wdb.port");
        let db = SocketAgentDb::local(home.path());
        #[cfg(not(unix))]
        {
            // Missing port file: handled like a refused connection.
            // D12: a connect failure ends the query with the system error text.
            let e = db.query("global get-all-agents context ").unwrap_err().text();
            assert!(!e.is_empty() && e != "Connection with provigil-db lost.", "{e}");
            std::fs::write(&port_file, format!(" {}\n", fake_db("ok [{\"id\":1}]"))).unwrap();
            assert_eq!(db.query("global get-all-agents context ").unwrap(), vec![json!({"id":1})]);
            // The old server closed the connection; the reconnect reads the new port.
            std::fs::write(&port_file, fake_db("ok [{\"id\":2}]").to_string()).unwrap();
            assert_eq!(db.query("global get-all-agents context ").unwrap(), vec![json!({"id":2})]);
            std::fs::write(&port_file, "not a port").unwrap();
            assert_eq!(db.query("x ").unwrap_err(), DbError::Failed("invalid port file".into()));
        }
        let _ = (db, port_file);
        // The loopback client works on every platform.
        let path = home.path().join("other");
        std::fs::write(home.path().join("other.port"), fake_db("ok {\"b\":2}").to_string()).unwrap();
        assert_eq!(SocketAgentDb::loopback(&path).query("q ").unwrap(), vec![json!({"b":2})]);
    }

    #[test]
    fn socket_framing_and_reconnect() {
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            // First connection is dropped at once; the second answers.
            let (s, _) = l.accept().unwrap();
            drop(s);
            let (mut s, _) = l.accept().unwrap();
            let mut len = [0u8; 4];
            s.read_exact(&mut len).unwrap();
            let mut q = vec![0u8; u32::from_le_bytes(len) as usize];
            s.read_exact(&mut q).unwrap();
            assert_eq!(q, b"global get-all-agents context ");
            for a in ["due {\"id\":0}", "ok"] {
                s.write_all(&(a.len() as u32).to_le_bytes()).unwrap();
                s.write_all(a.as_bytes()).unwrap();
            }
        });
        let db = SocketAgentDb::new(Box::new(move || Ok(Box::new(TcpStream::connect(addr)?) as Box<dyn Stream>)));
        assert_eq!(db.query(&q_all_agents()).unwrap(), vec![json!({"id":0})]);
    }
}
