//! The wazuh-db global helpers remoted uses (`wdb_global_helpers.c`), sending
//! exactly the query strings a C remoted sends.

use crate::agent_info::AgentInfoData;
use serde_json::{json, Value};
use siem_ipc::wdbc::{parse_result, query_ok, query_parse_json, WdbQuery, WdbcResult};

pub const AGENT_CS_NEVER_CONNECTED: &str = "never_connected";
pub const AGENT_CS_PENDING: &str = "pending";
pub const AGENT_CS_ACTIVE: &str = "active";
pub const AGENT_CS_DISCONNECTED: &str = "disconnected";

/// `agent_status_code_t`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStatusCode {
    InvalidVersion = 1,
    ErrVersionRecv = 2,
    HcShutdownRecv = 3,
    NoKeepalive = 4,
    ResetByManager = 5,
}

/// `WDB_GROUP_MODE_EMPTY_ONLY`
pub const WDB_GROUP_MODE_EMPTY_ONLY: &str = "empty_only";

/// `wdb_update_agent_data`
pub async fn update_agent_data(db: &dyn WdbQuery, d: &AgentInfoData) -> bool {
    query_ok(db, &format!("global update-agent-data {}", d.to_wdb_json())).await
}

/// `wdb_update_agent_keepalive`
pub async fn update_agent_keepalive(db: &dyn WdbQuery, id: i64, connection_status: &str, sync_status: &str) -> bool {
    let data = format!(
        "{{\"id\":{id},\"connection_status\":{},\"sync_status\":{}}}",
        serde_json::to_string(connection_status).unwrap(),
        serde_json::to_string(sync_status).unwrap()
    );
    query_ok(db, &format!("global update-keepalive {data}")).await
}

/// `wdb_update_agent_connection_status`
pub async fn update_agent_connection_status(
    db: &dyn WdbQuery,
    id: i64,
    connection_status: &str,
    sync_status: &str,
    status_code: AgentStatusCode,
) -> bool {
    let data = format!(
        "{{\"id\":{id},\"connection_status\":{},\"sync_status\":{},\"status_code\":{}}}",
        serde_json::to_string(connection_status).unwrap(),
        serde_json::to_string(sync_status).unwrap(),
        status_code as i32
    );
    query_ok(db, &format!("global update-connection-status {data}")).await
}

/// `wdb_update_agent_status_code`
pub async fn update_agent_status_code(
    db: &dyn WdbQuery,
    id: i64,
    status_code: AgentStatusCode,
    version: Option<&str>,
    sync_status: &str,
) -> bool {
    let mut data = format!("{{\"id\":{id},\"status_code\":{}", status_code as i32);
    if let Some(v) = version {
        // snprintf(wazuh_version, OS_SIZE_128, "%s %s", __ossec_name, version)
        let mut wv = format!("Wazuh {v}");
        wv.truncate(127);
        data.push_str(&format!(",\"version\":{}", serde_json::to_string(&wv).unwrap()));
    }
    data.push_str(&format!(",\"sync_status\":{}}}", serde_json::to_string(sync_status).unwrap()));
    query_ok(db, &format!("global update-status-code {data}")).await
}

/// `wdb_get_agent_group`
pub async fn get_agent_group(db: &dyn WdbQuery, id: i64) -> Option<String> {
    let root = query_parse_json(db, &format!("global select-agent-group {id}")).await;
    let Some(root) = root else {
        tracing::error!("Error querying Wazuh DB to get the agent's {id} group.");
        return None;
    };
    // cJSON_GetObjectItem(root->child, "group")
    let first = match &root {
        Value::Array(a) => a.first().cloned(),
        Value::Object(o) => o.values().next().cloned(),
        _ => None,
    }?;
    first.get("group").and_then(|g| g.as_str()).map(String::from)
}

/// `wdb_set_agent_groups_csv`
pub async fn set_agent_groups_csv(db: &dyn WdbQuery, id: i64, groups_csv: &str, mode: &str, sync_status: Option<&str>) -> bool {
    let groups: Vec<&str> = groups_csv.split(',').collect();
    let mut s = format!("{{\"mode\":{}", serde_json::to_string(mode).unwrap());
    if let Some(ss) = sync_status {
        s.push_str(&format!(",\"sync_status\":{}", serde_json::to_string(ss).unwrap()));
    }
    s.push_str(&format!(",\"data\":[{{\"id\":{id},\"groups\":{}}}]}}", serde_json::to_string(&groups).unwrap()));
    query_ok(db, &format!("global set-agent-groups {s}")).await
}

/// `wdb_reset_agents_connection`
pub async fn reset_agents_connection(db: &dyn WdbQuery, sync_status: &str) -> bool {
    query_ok(db, &format!("global reset-agents-connection {sync_status}")).await
}

/// `wdb_parse_chunk_to_int` loop driver for `get-agents-by-connection-status`.
async fn collect_ids(db: &dyn WdbQuery, mut make: impl FnMut(i64) -> String) -> Option<Vec<i64>> {
    let mut ids = Vec::new();
    let mut last_id: i64 = 0;
    loop {
        let resp = db.query(&make(last_id)).await.ok()?;
        let (st, payload) = parse_result(&resp);
        match st {
            WdbcResult::Ok | WdbcResult::Due => {
                let v: Value = serde_json::from_str(payload).ok()?;
                let mut last = 0;
                for a in v.as_array().into_iter().flatten() {
                    if let Some(n) = a.get("id").and_then(|x| x.as_i64()) {
                        ids.push(n);
                        last = n;
                    }
                }
                last_id = last;
                if st == WdbcResult::Ok {
                    return Some(ids);
                }
            }
            _ => return None,
        }
    }
}

/// `wdb_get_agents_ids_of_current_node`
pub async fn get_agents_ids_of_current_node(
    db: &dyn WdbQuery,
    connection_status: &str,
    node_name: &str,
    last_id: i64,
    limit: i64,
) -> Option<Vec<i64>> {
    let mut first = Some(last_id);
    collect_ids(db, |l| {
        let start = first.take().unwrap_or(l);
        format!("global get-agents-by-connection-status {start} {connection_status} {node_name} {limit}")
    })
    .await
}

/// `wdb_get_distinct_agent_groups`: every `{group, group_hash}` row.
pub async fn get_distinct_agent_groups(db: &dyn WdbQuery) -> Option<Vec<Value>> {
    let mut rows = Vec::new();
    let mut last_hash = String::new();
    loop {
        let resp = db.query(&format!("global get-distinct-groups {last_hash}")).await.ok();
        let Some(resp) = resp else {
            tracing::error!("Error querying Wazuh DB to get agent's groups.");
            return None;
        };
        let (st, payload) = parse_result(&resp);
        match st {
            WdbcResult::Ok | WdbcResult::Due => {
                let Ok(Value::Array(a)) = serde_json::from_str::<Value>(payload) else {
                    tracing::error!("Error querying Wazuh DB to get agent's groups.");
                    return None;
                };
                if let Some(h) = a.last().and_then(|x| x.get("group_hash")).and_then(|h| h.as_str()) {
                    last_hash = h.to_string();
                }
                rows.extend(a);
                if st == WdbcResult::Ok {
                    return Some(rows);
                }
            }
            _ => {
                tracing::error!("Error querying Wazuh DB to get agent's groups.");
                return None;
            }
        }
    }
}

/// Convenience used by the cluster-less `assign_group_to_agent` result.
pub fn group_json(group: &str) -> Value {
    json!({ "group": group })
}

#[cfg(test)]
mod tests {
    use super::*;
    use siem_ipc::wdbc::WdbcError;
    use std::sync::Mutex;

    struct Mock {
        log: Mutex<Vec<String>>,
        replies: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl WdbQuery for Mock {
        async fn query(&self, q: &str) -> Result<String, WdbcError> {
            self.log.lock().unwrap().push(q.to_string());
            Ok(self.replies.lock().unwrap().pop().unwrap_or_else(|| "ok".into()))
        }
    }

    #[tokio::test]
    async fn query_strings_match_c() {
        let m = Mock { log: Mutex::new(vec![]), replies: Mutex::new(vec![]) };
        update_agent_keepalive(&m, 1, AGENT_CS_ACTIVE, "synced").await;
        update_agent_connection_status(&m, 2, AGENT_CS_DISCONNECTED, "synced", AgentStatusCode::HcShutdownRecv).await;
        update_agent_status_code(&m, 3, AgentStatusCode::InvalidVersion, Some("v4.15.0"), "synced").await;
        set_agent_groups_csv(&m, 4, "default,linux", WDB_GROUP_MODE_EMPTY_ONLY, Some("synced")).await;
        reset_agents_connection(&m, "synced").await;
        let log = m.log.lock().unwrap();
        assert_eq!(log[0], r#"global update-keepalive {"id":1,"connection_status":"active","sync_status":"synced"}"#);
        assert_eq!(log[1], r#"global update-connection-status {"id":2,"connection_status":"disconnected","sync_status":"synced","status_code":3}"#);
        assert_eq!(log[2], r#"global update-status-code {"id":3,"status_code":1,"version":"Wazuh v4.15.0","sync_status":"synced"}"#);
        assert_eq!(log[3], r#"global set-agent-groups {"mode":"empty_only","sync_status":"synced","data":[{"id":4,"groups":["default","linux"]}]}"#);
        assert_eq!(log[4], "global reset-agents-connection synced");
    }

    #[tokio::test]
    async fn chunked_ids() {
        let m = Mock {
            log: Mutex::new(vec![]),
            replies: Mutex::new(vec!["ok [{\"id\":3}]".into(), "due [{\"id\":1},{\"id\":2}]".into()]),
        };
        let ids = get_agents_ids_of_current_node(&m, AGENT_CS_ACTIVE, "node01", 0, -1).await.unwrap();
        assert_eq!(ids, vec![1, 2, 3]);
        let log = m.log.lock().unwrap();
        assert_eq!(log[0], "global get-agents-by-connection-status 0 active node01 -1");
        assert_eq!(log[1], "global get-agents-by-connection-status 2 active node01 -1");
    }
}
