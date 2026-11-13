//! The agent-database clients: one request, one answer, on `queue/db/wdb`. A request is sent
//! with a trailing zero byte; an answer is text up to its first zero byte, at most
//! [`MAX_ANSWER`]` - 1` bytes. Answers start with `ok`, `err`, `due` or `ign`.
//!
//! Both clients keep one connection. Connecting is tried 5 times, waiting 1, 2, 3, 4 and 5
//! seconds between tries; a request that fails on a kept connection is sent again once on a new
//! one (the service was restarted).
//!
//! * [`DbClient`]: blocking ([`AgentDb`]).
//! * [`DbSocket`]: async ([`DbQuery`]).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use crate::local::{self, Stream};
use crate::{framing, MAX_MESSAGE};

/// The service's socket (relative to the home folder).
pub const DB_SOCKET: &str = "queue/db/wdb";
/// The size limit of an answer.
pub const MAX_ANSWER: usize = 65536;
/// Connection attempts before giving up.
const ATTEMPTS: u64 = 5;

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
    /// No answer (code -1).
    Answer(String),
    /// The answer is over the caller's size limit (code -1).
    TooBig,
}

impl DbError {
    /// -2 for a connection failure, -1 otherwise.
    pub fn code(&self) -> i32 {
        match self {
            DbError::Connect(_) => -2,
            _ => -1,
        }
    }
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Connect(e) => write!(f, "unable to connect to provigil-db: {e}"),
            DbError::Answer(e) => write!(f, "no response from provigil-db: {e}"),
            DbError::TooBig => write!(f, "Cannot receive message: response size is bigger than expected"),
        }
    }
}

impl std::error::Error for DbError {}

/// The text of an answer: up to its first zero byte, at most `limit - 1` bytes.
fn answer_text(a: &[u8], limit: usize) -> Vec<u8> {
    let end = a.iter().position(|&b| b == 0).unwrap_or(a.len()).min(limit.saturating_sub(1));
    a[..end].to_vec()
}

/// The request as sent: up to its first zero byte, then one zero byte.
fn request_bytes(q: &[u8]) -> Vec<u8> {
    let mut v = q[..q.iter().position(|&b| b == 0).unwrap_or(q.len())].to_vec();
    v.push(0);
    v
}

// ------------------------------------------------------------------ blocking

/// What answers agent-database requests, blocking (the socket client, or a stand-in in tests).
pub trait AgentDb: Send + Sync {
    fn query(&self, q: &str) -> Result<String, DbError>;
}

/// The blocking client of the service's socket.
pub struct DbClient {
    path: PathBuf,
    conn: Mutex<Option<Stream>>,
    attempts: u64,
}

impl DbClient {
    /// A client of the socket at `home/queue/db/wdb`.
    pub fn new(home: &Path) -> DbClient {
        DbClient { path: home.join(DB_SOCKET), conn: Mutex::new(None), attempts: ATTEMPTS }
    }

    /// The same with another number of connection attempts (tests: 1).
    pub fn with_attempts(mut self, n: u64) -> DbClient {
        self.attempts = n.max(1);
        self
    }

    fn connect(&self) -> Result<Stream, DbError> {
        let mut last = String::new();
        for attempt in 1..=self.attempts {
            match local::connect(&self.path) {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last = e.to_string();
                    if attempt < self.attempts {
                        std::thread::sleep(Duration::from_secs(attempt));
                    }
                }
            }
        }
        Err(DbError::Connect(last))
    }

    fn round_trip(s: &mut Stream, q: &[u8]) -> std::io::Result<Vec<u8>> {
        framing::send(s, &request_bytes(q))?;
        framing::recv(s, MAX_MESSAGE)?.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed"))
    }
}

impl AgentDb for DbClient {
    fn query(&self, q: &str) -> Result<String, DbError> {
        let mut g = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(self.connect()?);
        }
        let answer = match Self::round_trip(g.as_mut().unwrap(), q.as_bytes()) {
            Ok(a) => Ok(a),
            Err(_) => {
                // the service was restarted or the connection dropped: open it again once
                *g = Some(self.connect()?);
                Self::round_trip(g.as_mut().unwrap(), q.as_bytes()).map_err(|e| DbError::Answer(e.to_string()))
            }
        };
        match answer {
            Ok(a) => Ok(String::from_utf8_lossy(&answer_text(&a, MAX_ANSWER)).into_owned()),
            Err(e) => {
                *g = None;
                Err(e)
            }
        }
    }
}

// ------------------------------------------------------------------ async

/// What answers agent-database requests, async (the socket client, or an in-process database).
#[async_trait::async_trait]
pub trait DbQuery: Send + Sync {
    /// The answer to `q` (text up to its first zero byte).
    async fn query(&self, q: &str) -> Result<String, DbError>;

    /// The answer to the request `q` (up to its first zero byte) when it fits `limit` bytes;
    /// [`DbError::TooBig`] otherwise. The result has at most `limit - 1` bytes.
    async fn query_bytes(&self, q: &[u8], limit: usize) -> Result<Vec<u8>, DbError> {
        let q = &q[..q.iter().position(|&b| b == 0).unwrap_or(q.len())];
        let a = self.query(&String::from_utf8_lossy(q)).await?;
        if a.len() > limit {
            return Err(DbError::TooBig);
        }
        Ok(answer_text(a.as_bytes(), limit))
    }
}

/// The async client of the service's socket.
pub struct DbSocket {
    path: PathBuf,
    conn: tokio::sync::Mutex<Option<crate::aio::LocalStream>>,
}

enum TripError {
    Io(String),
    TooBig,
}

impl DbSocket {
    /// A client of the socket at `path` (normally `<home>/queue/db/wdb`).
    pub fn new(path: impl Into<PathBuf>) -> DbSocket {
        DbSocket { path: path.into(), conn: tokio::sync::Mutex::new(None) }
    }

    async fn connect(&self) -> Result<crate::aio::LocalStream, DbError> {
        let mut last = String::new();
        for attempt in 1..=ATTEMPTS {
            match crate::aio::LocalStream::connect(&self.path).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last = e.to_string();
                    tracing::info!("Cannot connect to '{}': {}. Waiting {} seconds to reconnect.", self.path.display(), e, attempt);
                    tokio::time::sleep(Duration::from_secs(attempt)).await;
                }
            }
        }
        tracing::error!("Unable to connect to socket '{}'.", self.path.display());
        Err(DbError::Connect(last))
    }

    async fn round_trip(s: &mut crate::aio::LocalStream, q: &[u8], limit: usize) -> Result<Vec<u8>, TripError> {
        use crate::aio::framing;
        framing::send(s, &request_bytes(q)).await.map_err(|e| TripError::Io(e.to_string()))?;
        match framing::recv(s, limit).await {
            Ok(a) => Ok(a),
            Err(framing::FrameError::TooBig(..)) => Err(TripError::TooBig),
            Err(e) => Err(TripError::Io(e.to_string())),
        }
    }

    /// One request with the reconnect-once rule; the raw answer.
    async fn ask(&self, q: &[u8], limit: usize) -> Result<Vec<u8>, DbError> {
        let mut g = self.conn.lock().await;
        if g.is_none() {
            *g = Some(self.connect().await?);
        }
        match Self::round_trip(g.as_mut().unwrap(), q, limit).await {
            Ok(a) => Ok(a),
            Err(TripError::TooBig) => {
                // the rest of that answer is still on the connection: start a new one next time
                *g = None;
                Err(DbError::TooBig)
            }
            Err(TripError::Io(_)) => {
                tracing::error!("Connection with provigil-db lost. Reconnecting.");
                *g = Some(self.connect().await?);
                match Self::round_trip(g.as_mut().unwrap(), q, limit).await {
                    Ok(a) => Ok(a),
                    Err(e) => {
                        *g = None;
                        Err(match e {
                            TripError::TooBig => DbError::TooBig,
                            TripError::Io(e) => DbError::Answer(e),
                        })
                    }
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl DbQuery for DbSocket {
    async fn query(&self, q: &str) -> Result<String, DbError> {
        let a = self.ask(q.as_bytes(), MAX_ANSWER).await?;
        Ok(String::from_utf8_lossy(&answer_text(&a, MAX_ANSWER)).into_owned())
    }

    async fn query_bytes(&self, q: &[u8], limit: usize) -> Result<Vec<u8>, DbError> {
        let a = self.ask(q, limit).await?;
        Ok(answer_text(&a, limit))
    }
}

/// The JSON of an `ok` answer (None otherwise; errors are logged).
pub async fn query_json(db: &dyn DbQuery, q: &str) -> Option<serde_json::Value> {
    let a = match db.query(q).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("{e}");
            return None;
        }
    };
    match parse_answer(&a) {
        (Status::Ok, rest) => serde_json::from_str(rest).ok(),
        (Status::Error, rest) => {
            tracing::error!("Bad response from provigil-db: {rest}");
            None
        }
        _ => None,
    }
}

/// Whether a request was answered `ok`.
pub async fn query_ok(db: &dyn DbQuery, q: &str) -> bool {
    match db.query(q).await {
        Ok(a) if parse_answer(&a).0 == Status::Ok => true,
        Ok(_) => {
            tracing::debug!("Global DB Error reported in the result of the query");
            false
        }
        Err(e) => {
            tracing::debug!("Global DB Error in the response from socket: {e}");
            tracing::trace!("Global DB SQL query: {q}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server answering `ok <request>` to one request per connection (zero byte removed).
    fn one_per_connection(path: &Path, n: usize) {
        let l = local::bind(path).unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().take(n) {
                let mut s = s.unwrap();
                let q = framing::recv(&mut s, MAX_MESSAGE).unwrap().unwrap();
                assert_eq!(q.last(), Some(&0), "requests end with a zero byte");
                framing::send(&mut s, &[b"ok ".as_slice(), &q[..q.len() - 1]].concat()).unwrap();
            }
        });
    }

    #[test]
    fn blocking_client_answers_and_reconnects() {
        assert_eq!(parse_answer("ok [1]"), (Status::Ok, "[1]"));
        assert_eq!(parse_answer("due {}"), (Status::Due, "{}"));
        assert_eq!(parse_answer("err"), (Status::Error, "err"));
        assert_eq!(parse_answer("what"), (Status::Unknown, "what"));

        let home = tempfile::tempdir().unwrap();
        let c = DbClient::new(home.path()).with_attempts(1);
        assert_eq!(c.query("x").unwrap_err().code(), -2);
        one_per_connection(&home.path().join(DB_SOCKET), 2);
        assert_eq!(c.query("one").unwrap(), "ok one");
        assert_eq!(c.query("two").unwrap(), "ok two");
    }

    #[tokio::test]
    async fn async_client_answers_reconnects_and_limits() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(DB_SOCKET);
        one_per_connection(&path, 3);
        let c = DbSocket::new(&path);
        assert_eq!(c.query("one").await.unwrap(), "ok one");
        // the server closed that connection: the client opens a new one and asks again
        assert_eq!(c.query("two").await.unwrap(), "ok two");
        assert_eq!(c.query_bytes(b"three\0ignored", 6).await.unwrap_err(), DbError::TooBig);
        assert_eq!(DbError::Connect("x".into()).code(), -2);
        assert_eq!(DbError::TooBig.code(), -1);
    }
}
