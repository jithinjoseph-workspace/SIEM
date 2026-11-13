//! The agent-database client: one request, one answer, on `queue/db/wdb`. The connection is kept
//! and opened again (once per request) when it was lost.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::local::{self, Stream};
use crate::{framing, MAX_MESSAGE};

/// The status word an answer starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Error,
    Ignore,
    Due,
    Unknown,
}

/// The status of an answer and what follows its first space (the whole answer without one).
pub fn parse_answer(answer: &str) -> (Status, &str) {
    let (head, rest) = answer.split_once(' ').unwrap_or((answer, answer));
    let st = match head {
        "ok" => Status::Ok,
        "err" => Status::Error,
        "ign" => Status::Ignore,
        "due" => Status::Due,
        _ => Status::Unknown,
    };
    (st, rest)
}

/// Why a request got no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// The socket could not be reached or written (code -2).
    Connect(String),
    /// No answer, or one over the size limit (code -1).
    Answer(String),
}

impl DbError {
    /// -2 for a connection failure, -1 otherwise.
    pub fn code(&self) -> i32 {
        match self {
            DbError::Connect(_) => -2,
            DbError::Answer(_) => -1,
        }
    }
}

/// What answers agent-database requests (the socket client, or a stand-in in tests).
pub trait AgentDb: Send + Sync {
    fn query(&self, q: &str) -> Result<String, DbError>;
}

/// The client of the service's socket.
pub struct DbClient {
    path: PathBuf,
    conn: Mutex<Option<Stream>>,
}

impl DbClient {
    /// A client of the socket at `home/queue/db/wdb`.
    pub fn new(home: &Path) -> DbClient {
        DbClient { path: home.join("queue/db/wdb"), conn: Mutex::new(None) }
    }

    fn connect(&self) -> Result<Stream, DbError> {
        local::connect(&self.path).map_err(|e| DbError::Connect(e.to_string()))
    }

    fn round_trip(s: &mut Stream, q: &str) -> std::io::Result<String> {
        framing::send(s, q.as_bytes())?;
        match framing::recv(s, MAX_MESSAGE)? {
            Some(a) => Ok(String::from_utf8_lossy(&a).into_owned()),
            None => Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed")),
        }
    }
}

impl AgentDb for DbClient {
    fn query(&self, q: &str) -> Result<String, DbError> {
        let mut g = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(self.connect()?);
        }
        let first = Self::round_trip(g.as_mut().unwrap(), q);
        let answer = match first {
            Ok(a) => Ok(a),
            Err(_) => {
                // the service was restarted or the connection dropped: open it again once
                *g = Some(self.connect()?);
                Self::round_trip(g.as_mut().unwrap(), q).map_err(|e| DbError::Answer(e.to_string()))
            }
        };
        if answer.is_err() {
            *g = None;
        }
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_and_reconnects() {
        assert_eq!(parse_answer("ok [1]"), (Status::Ok, "[1]"));
        assert_eq!(parse_answer("due {}"), (Status::Due, "{}"));
        assert_eq!(parse_answer("err"), (Status::Error, "err"));
        assert_eq!(parse_answer("what"), (Status::Unknown, "what"));

        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("queue/db/wdb");
        let c = DbClient::new(home.path());
        assert_eq!(c.query("x").unwrap_err().code(), -2);
        // a server that answers one request per connection: the client opens it again
        let l = local::bind(&path).unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().take(2) {
                let mut s = s.unwrap();
                let q = framing::recv(&mut s, MAX_MESSAGE).unwrap().unwrap();
                framing::send(&mut s, &[b"ok ".as_slice(), &q].concat()).unwrap();
            }
        });
        assert_eq!(c.query("one").unwrap(), "ok one");
        assert_eq!(c.query("two").unwrap(), "ok two");
    }
}
