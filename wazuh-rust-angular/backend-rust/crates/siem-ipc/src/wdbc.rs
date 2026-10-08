//! wazuh-db client (`src/shared/wazuhdb_op.c`): queries go over the
//! `queue/db/wdb` stream socket, framed with `OS_SendSecureTCP`, and include
//! the trailing NUL (`size + 1`). Replies look like `"ok <payload>"`,
//! `"err <msg>"`, `"due <payload>"` or `"ign <msg>"`.

use crate::framing;
use crate::local::LocalStream;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::Mutex;

/// `WDB_LOCAL_SOCK`
pub const WDB_LOCAL_SOCK: &str = "queue/db/wdb";
/// `WDBOUTPUT_SIZE` (OS_MAXSTR)
pub const WDBOUTPUT_SIZE: usize = 65536;

/// `wdbc_result`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdbcResult {
    Ok,
    Error,
    Ignore,
    Due,
    Unknown,
}

/// `wdbc_parse_result`: status and the payload after the first space
/// (the whole string when there is no space).
pub fn parse_result(response: &str) -> (WdbcResult, &str) {
    let (head, payload) = match response.find(' ') {
        Some(p) => (&response[..p], &response[p + 1..]),
        None => (response, response),
    };
    let st = match head {
        "ok" => WdbcResult::Ok,
        "err" => WdbcResult::Error,
        "ign" => WdbcResult::Ignore,
        "due" => WdbcResult::Due,
        _ => WdbcResult::Unknown,
    };
    (st, payload)
}

#[derive(Debug, thiserror::Error)]
pub enum WdbcError {
    /// -2: cannot connect / send.
    #[error("unable to connect to wazuh-db: {0}")]
    Connect(String),
    /// -1: no or bad response.
    #[error("no response from wazuh-db: {0}")]
    Response(String),
    /// -1: the reply does not fit the caller's buffer.
    #[error("Cannot receive message: response size is bigger than expected")]
    TooBig,
}

impl WdbcError {
    /// The `wdbc_query_ex` return code (-2 connect/send, -1 receive).
    pub fn code(&self) -> i32 {
        match self {
            WdbcError::Connect(_) => -2,
            _ => -1,
        }
    }
}

/// Anything that can answer wazuh-db queries: the socket client below, or
/// an in-process `siem-wdb` instance.
#[async_trait::async_trait]
pub trait WdbQuery: Send + Sync {
    /// `wdbc_query_ex`: send `query`, return the raw response string.
    async fn query(&self, query: &str) -> Result<String, WdbcError>;

    /// `wdbc_query_ex` with a C caller's buffer: the query is sent up to its
    /// first NUL, a reply longer than `len` bytes is an error ("response
    /// size is bigger than expected") and the reply is a C string of at
    /// most `len - 1` bytes.
    async fn query_bytes(&self, query: &[u8], len: usize) -> Result<Vec<u8>, WdbcError> {
        let q = &query[..query.iter().position(|&b| b == 0).unwrap_or(query.len())];
        let r = self.query(&String::from_utf8_lossy(q)).await?;
        if r.len() > len {
            return Err(WdbcError::TooBig);
        }
        Ok(cstr_reply(r.into_bytes(), len))
    }
}

/// `response[len - 1] = '\0'` and the C string view of a reply.
fn cstr_reply(mut r: Vec<u8>, len: usize) -> Vec<u8> {
    let end = r.iter().position(|&b| b == 0).unwrap_or(r.len()).min(len.saturating_sub(1));
    r.truncate(end);
    r
}

/// Socket client with reconnection (`wdbc_query_ex`).
pub struct WdbcSocket {
    path: PathBuf,
    conn: Mutex<Option<LocalStream>>,
}

impl WdbcSocket {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), conn: Mutex::new(None) }
    }

    /// `wdbc_connect_with_attempts(5)`
    async fn connect(&self) -> Result<LocalStream, WdbcError> {
        let mut last = String::new();
        for attempt in 1..=5u64 {
            match LocalStream::connect(&self.path).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last = e.to_string();
                    tracing::info!("Cannot connect to '{}': {}. Waiting {} seconds to reconnect.", self.path.display(), e, attempt);
                    tokio::time::sleep(Duration::from_secs(attempt)).await;
                }
            }
        }
        tracing::error!("Unable to connect to socket '{}'.", self.path.display());
        Err(WdbcError::Connect(last))
    }

    async fn roundtrip(s: &mut LocalStream, query: &str) -> std::io::Result<Vec<u8>> {
        Self::roundtrip_bytes(s, query.as_bytes(), WDBOUTPUT_SIZE).await.map_err(|e| match e {
            RtError::Io(e) => e,
            RtError::TooBig => std::io::Error::other("response too big"),
        })
    }

    async fn roundtrip_bytes(s: &mut LocalStream, query: &[u8], len: usize) -> Result<Vec<u8>, RtError> {
        let mut q = query.to_vec();
        q.push(0);
        framing::send(s, &q).await.map_err(|e| RtError::Io(std::io::Error::other(e.to_string())))?;
        match framing::recv(s, len).await {
            Ok(r) => Ok(r),
            Err(framing::FrameError::TooBig(..)) => Err(RtError::TooBig),
            Err(e) => Err(RtError::Io(std::io::Error::other(e.to_string()))),
        }
    }
}

enum RtError {
    Io(std::io::Error),
    TooBig,
}

#[async_trait::async_trait]
impl WdbQuery for WdbcSocket {
    async fn query(&self, query: &str) -> Result<String, WdbcError> {
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            *guard = Some(self.connect().await?);
        }
        let s = guard.as_mut().unwrap();
        let resp = match Self::roundtrip(s, query).await {
            Ok(r) => r,
            Err(_) => {
                // EPIPE: reconnect once and retry.
                tracing::error!("Connection with wazuh-db lost. Reconnecting.");
                *guard = Some(self.connect().await?);
                let s = guard.as_mut().unwrap();
                Self::roundtrip(s, query).await.map_err(|e| WdbcError::Response(e.to_string()))?
            }
        };
        // response[len - 1] = '\0' and the payload is a C string.
        let end = resp.iter().position(|&b| b == 0).unwrap_or(resp.len()).min(WDBOUTPUT_SIZE - 1);
        Ok(String::from_utf8_lossy(&resp[..end]).into_owned())
    }

    async fn query_bytes(&self, query: &[u8], len: usize) -> Result<Vec<u8>, WdbcError> {
        let q = &query[..query.iter().position(|&b| b == 0).unwrap_or(query.len())];
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            *guard = Some(self.connect().await?);
        }
        let s = guard.as_mut().unwrap();
        let resp = match Self::roundtrip_bytes(s, q, len).await {
            Ok(r) => r,
            Err(RtError::TooBig) => return Err(WdbcError::TooBig),
            Err(RtError::Io(_)) => {
                tracing::error!("Connection with wazuh-db lost. Reconnecting.");
                *guard = Some(self.connect().await?);
                let s = guard.as_mut().unwrap();
                match Self::roundtrip_bytes(s, q, len).await {
                    Ok(r) => r,
                    Err(RtError::TooBig) => return Err(WdbcError::TooBig),
                    Err(RtError::Io(e)) => return Err(WdbcError::Response(e.to_string())),
                }
            }
        };
        Ok(cstr_reply(resp, len))
    }
}

/// `wdbc_query_parse_json`: `Some(json)` only for an `ok` reply with valid JSON.
pub async fn query_parse_json(db: &dyn WdbQuery, query: &str) -> Option<serde_json::Value> {
    let resp = match db.query(query).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("{e}");
            return None;
        }
    };
    match parse_result(&resp) {
        (WdbcResult::Ok, p) => serde_json::from_str(p).ok(),
        (WdbcResult::Error, p) => {
            tracing::error!("Bad response from wazuh-db: {p}");
            None
        }
        _ => None,
    }
}

/// Run a query whose reply must be `ok` (the `wdb_update_*` helpers).
pub async fn query_ok(db: &dyn WdbQuery, query: &str) -> bool {
    match db.query(query).await {
        Ok(r) => {
            if parse_result(&r).0 != WdbcResult::Ok {
                tracing::debug!("Global DB Error reported in the result of the query");
                false
            } else {
                true
            }
        }
        Err(e) => {
            tracing::debug!("Global DB Error in the response from socket: {e}");
            tracing::trace!("Global DB SQL query: {query}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_results() {
        assert_eq!(parse_result("ok [{\"id\":1}]"), (WdbcResult::Ok, "[{\"id\":1}]"));
        assert_eq!(parse_result("due [1]"), (WdbcResult::Due, "[1]"));
        assert_eq!(parse_result("err Invalid"), (WdbcResult::Error, "Invalid"));
        assert_eq!(parse_result("ok"), (WdbcResult::Ok, "ok"));
        assert_eq!(parse_result("weird x"), (WdbcResult::Unknown, "x"));
    }
}
