//! The `wdb_global_helpers.c` / `wazuhdb_op.c` calls monitord makes.

use siem_cjson::Json;
use siem_ipc::wdbc::{parse_result, WdbQuery, WdbcError, WdbcResult, WdbcSocket, WDB_LOCAL_SOCK};
use siem_log::WLog;

/// A blocking wazuh-db client over the async `WdbcSocket`.
pub struct Wdb {
    sock: WdbcSocket,
    rt: tokio::runtime::Handle,
}

impl Wdb {
    pub fn new(rt: tokio::runtime::Handle) -> Self {
        Self { sock: WdbcSocket::new(WDB_LOCAL_SOCK), rt }
    }

    /// `wdbc_query_ex`: the response, or -2 (no connection) / -1.
    pub fn query_ex(&self, log: &WLog, q: &str) -> Result<String, i32> {
        match self.rt.block_on(self.sock.query(q)) {
            Ok(r) => Ok(r),
            Err(WdbcError::Connect(_)) => {
                log.error(format!("Unable to connect to socket '{WDB_LOCAL_SOCK}'."));
                Err(-2)
            }
            Err(_) => Err(-1),
        }
    }

    /// `wdbc_query_parse_json`
    pub fn query_parse_json(&self, log: &WLog, q: &str) -> Option<Json> {
        let r = match self.query_ex(log, q) {
            Ok(r) => r,
            Err(-2) => {
                log.error(format!("Unable to connect to socket '{WDB_LOCAL_SOCK}'"));
                return None;
            }
            Err(_) => {
                log.error("No response from wazuh-db.");
                return None;
            }
        };
        match parse_result(&r) {
            (WdbcResult::Ok, arg) => siem_cjson::parse_str(arg),
            (WdbcResult::Error, arg) => {
                log.error(format!("Bad response from wazuh-db: {arg}"));
                None
            }
            _ => None,
        }
    }

    /// The paged `int*` queries (`wdb_parse_chunk_to_int` loop); empty on error.
    fn chunk_ids(&self, log: &WLog, mk: impl Fn(i32) -> String) -> Vec<i32> {
        let mut out = Vec::new();
        let mut last = 0;
        loop {
            let Ok(r) = self.query_ex(log, &mk(last)) else { return Vec::new() };
            let (st, payload) = parse_result(&r);
            match st {
                WdbcResult::Ok | WdbcResult::Due => {
                    let Some(j) = siem_cjson::parse_str(payload) else { return Vec::new() };
                    last = 0;
                    for a in j.children() {
                        if let Some(id) = a.get("id").filter(|v| v.is_number()).and_then(Json::as_i32) {
                            out.push(id);
                            last = id;
                        }
                    }
                    if st == WdbcResult::Ok {
                        return out;
                    }
                }
                WdbcResult::Error => return Vec::new(),
                _ => return out,
            }
        }
    }

    /// `wdb_disconnect_agents`
    pub fn disconnect_agents(&self, log: &WLog, keepalive: i64, sync_status: &str) -> Vec<i32> {
        self.chunk_ids(log, |last| format!("global disconnect-agents {last} {} {sync_status}", keepalive as i32))
    }

    /// `wdb_get_agents_by_connection_status`
    pub fn agents_by_connection_status(&self, log: &WLog, status: &str) -> Vec<i32> {
        self.chunk_ids(log, |last| format!("global get-agents-by-connection-status {last} {status}"))
    }

    /// `wdb_get_agent_info`
    pub fn get_agent_info(&self, log: &WLog, id: i32) -> Option<Json> {
        let r = self.query_parse_json(log, &format!("global get-agent-info {id}"));
        if r.is_none() {
            log.error(format!("Error querying Wazuh DB to get the agent's {id} information."));
        }
        r
    }

    /// `wdb_find_agent`: the id, -2 when not found, -1 on error.
    pub fn find_agent(&self, log: &WLog, name: &str, ip: &str) -> i32 {
        let mut d = Json::object();
        d.add("name", Json::string(name));
        d.add("ip", Json::string(ip));
        let q = format!("global find-agent {}", d.to_string_unformatted());
        let Some(root) = self.query_parse_json(log, &q) else {
            log.error("Error querying Wazuh DB for agent ID.");
            return -1;
        };
        match root.children().first().and_then(|c| c.get("id")).filter(|v| v.is_number()) {
            Some(v) => v.as_i32().unwrap_or(-2),
            None => -2,
        }
    }

    /// `wdbc_query_ex` on a new connection (`auth_remove_agent`): 0 or the error.
    pub fn query_once(&self, log: &WLog, q: &str) -> i32 {
        let s = WdbcSocket::new(WDB_LOCAL_SOCK);
        match self.rt.block_on(s.query(q)) {
            Ok(_) => 0,
            Err(WdbcError::Connect(_)) => {
                log.error(format!("Unable to connect to socket '{WDB_LOCAL_SOCK}'."));
                -2
            }
            Err(_) => -1,
        }
    }
}
