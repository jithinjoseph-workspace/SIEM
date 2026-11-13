//! What the service's parts need from outside: logging, provigil-db, local sockets and
//! queues, agent labels and the active response targets. The daemon implements it; tests
//! use a recording one.

use provigil_json::Json;

use crate::event::Label;
use crate::responses::ResponseSink;

pub trait Host {
    fn labels(&mut self, agent: &[u8]) -> Vec<Label>;
    /// `level`: ERROR, WARNING, INFO, DEBUG, DEBUG2.
    fn log(&self, level: &str, msg: &[u8]);
    fn responses(&mut self) -> &mut dyn ResponseSink;
    /// Active agents of this node after `last` (at most `limit`).
    fn agents_of_node(&mut self, last: i32, limit: i32) -> Option<Vec<i32>>;
    /// A provigil-db query: the answer (at most `room` bytes), or -2 (could not send) / -1
    /// (no answer). It logs its own errors.
    fn db_query(&mut self, query: &[u8], room: usize) -> Result<Vec<u8>, i32> {
        let _ = (query, room);
        Err(-2)
    }
    /// One message to a local stream socket; Err((errno, text)) when it cannot connect.
    fn send_local(&mut self, path: &str, msg: &[u8]) -> Result<(), (i32, String)> {
        let _ = (path, msg);
        Err((111, "Connection refused".into()))
    }
    /// One datagram (with a final zero byte) to a local queue; false when it is not there.
    fn send_queue(&mut self, path: &str, msg: &[u8]) -> bool {
        let _ = (path, msg);
        false
    }
    /// A provigil-db query answered as JSON (`ok <json>`); it logs its own errors.
    fn db_json(&mut self, query: &str) -> Option<Json> {
        let _ = query;
        None
    }
}
