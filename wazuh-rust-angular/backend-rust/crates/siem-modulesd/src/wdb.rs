//! The wazuh-db global helpers the database module uses
//! (`wazuh_db/helpers/wdb_global_helpers.c`, `shared/wazuhdb_op.c`), with
//! the C log messages.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use siem_ipc::wdbc::{parse_result, WdbQuery, WdbcError, WdbcResult};
use siem_log::WLog;

/// `WDB_LOCAL_SOCK`
pub const WDB_LOCAL_SOCK: &str = "queue/db/wdb";
const OS_INVALID: i32 = -1;

/// `wdbc_query_ex`: the response, or the C return code (-2 / -1).
pub async fn query_ex(db: &dyn WdbQuery, log: &WLog, query: &str) -> Result<String, i32> {
    match db.query(query).await {
        Ok(r) => Ok(r),
        Err(WdbcError::Connect(_)) => {
            log.error(format!("Unable to connect to socket '{WDB_LOCAL_SOCK}'."));
            Err(-2)
        }
        Err(e) => Err(e.code()),
    }
}

/// `wdbc_query_parse_json`
pub async fn query_parse_json(db: &dyn WdbQuery, log: &WLog, query: &str) -> Option<Value> {
    let resp = match query_ex(db, log, query).await {
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
    match parse_result(&resp) {
        (WdbcResult::Ok, arg) => serde_json::from_str(arg).ok(),
        (WdbcResult::Error, arg) => {
            log.error(format!("Bad response from wazuh-db: {arg}"));
            None
        }
        _ => None,
    }
}

/// The result handling shared by the "ok or error" helpers.
async fn query_status(db: &dyn WdbQuery, log: &WLog, query: &str) -> i32 {
    match query_ex(db, log, query).await {
        Ok(r) => {
            if parse_result(&r).0 != WdbcResult::Ok {
                log.debug1("Global DB Error reported in the result of the query");
                OS_INVALID
            } else {
                0
            }
        }
        Err(-1) => {
            log.debug1("Global DB Error in the response from socket");
            log.debug2(format!("Global DB SQL query: {query}"));
            OS_INVALID
        }
        Err(_) => {
            log.debug1("Global DB Cannot execute SQL query; err database queue/db/global.db");
            log.debug2(format!("Global DB SQL query: {query}"));
            OS_INVALID
        }
    }
}

/// `wdb_insert_agent(id, name, NULL, register_ip, raw_key, group, keep_date)`
pub async fn insert_agent(
    db: &dyn WdbQuery,
    log: &WLog,
    id: i32,
    name: &str,
    register_ip: &str,
    internal_key: &str,
    group: Option<&str>,
    date_add: i64,
) -> i32 {
    let data = json!({
        "id": id,
        "name": name,
        "ip": Value::Null,
        "register_ip": register_ip,
        "internal_key": internal_key,
        "group": group,
        "date_add": date_add,
    });
    query_status(db, log, &format!("global insert-agent {data}")).await
}

/// `wdb_update_agent_name`
pub async fn update_agent_name(db: &dyn WdbQuery, log: &WLog, id: i32, name: &str) -> i32 {
    let data = json!({ "id": id, "name": name });
    query_status(db, log, &format!("global update-agent-name {data}")).await
}

/// `wdb_remove_agent`
pub async fn remove_agent(db: &dyn WdbQuery, log: &WLog, id: i32) -> i32 {
    query_status(db, log, &format!("global delete-agent {id}")).await
}

/// `wdb_get_agent_name`: the name, "" when the agent is not in the DB,
/// None on error.
pub async fn get_agent_name(db: &dyn WdbQuery, log: &WLog, id: i32) -> Option<String> {
    let Some(root) = query_parse_json(db, log, &format!("global select-agent-name {id}")).await else {
        log.error(format!("Error querying Wazuh DB to get the agent's {id} name."));
        return None;
    };
    Some(root.get(0).and_then(|a| a.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string())
}

/// `wdb_get_all_agents_rbtree`: the ids as `%03d` strings, in order.
pub async fn get_all_agents(db: &dyn WdbQuery, log: &WLog, include_manager: bool) -> Option<BTreeSet<String>> {
    let mut last_id: i64 = if include_manager { -1 } else { 0 };
    let mut tree = BTreeSet::new();
    loop {
        let q = format!("global get-all-agents last_id {last_id}");
        let status = match query_ex(db, log, &q).await {
            Ok(r) => {
                // wdb_parse_chunk_to_rbtree
                let (st, payload) = parse_result(&r);
                if st == WdbcResult::Ok || st == WdbcResult::Due {
                    match serde_json::from_str::<Value>(payload) {
                        Ok(Value::Array(a)) => {
                            let mut last = 0;
                            for agent in a {
                                if let Some(n) = agent.get("id").and_then(|i| i.as_i64()) {
                                    tree.insert(format!("{n:03}"));
                                    last = n;
                                }
                            }
                            last_id = last;
                            st
                        }
                        Ok(_) => {
                            last_id = 0;
                            st
                        }
                        Err(_) => WdbcResult::Error,
                    }
                } else {
                    last_id = 0;
                    st
                }
            }
            Err(_) => WdbcResult::Error,
        };
        match status {
            WdbcResult::Due => continue,
            WdbcResult::Error => {
                log.error("Error querying Wazuh DB to get agent's IDs.");
                return None;
            }
            _ => return Some(tree),
        }
    }
}

/// `wdb_find_group`: the group id, or -1.
pub async fn find_group(db: &dyn WdbQuery, log: &WLog, name: &str) -> i32 {
    let Some(root) = query_parse_json(db, log, &format!("global find-group {name}")).await else {
        log.error("Error querying Wazuh DB to get the agent group id.");
        return OS_INVALID;
    };
    root.get(0).and_then(|g| g.get("id")).and_then(|i| i.as_i64()).map(|i| i as i32).unwrap_or(OS_INVALID)
}

/// `wdb_insert_group`
pub async fn insert_group(db: &dyn WdbQuery, log: &WLog, name: &str) -> i32 {
    query_status(db, log, &format!("global insert-agent-group {name}")).await
}

/// `wdb_remove_group_db`
pub async fn remove_group_db(db: &dyn WdbQuery, log: &WLog, name: &str) -> i32 {
    query_status(db, log, &format!("global delete-group {name}")).await
}

/// `wdb_set_agent_groups`
pub async fn set_agent_groups(db: &dyn WdbQuery, log: &WLog, id: i32, groups: &[String], mode: &str, sync_status: &str) -> i32 {
    let data = json!({ "mode": mode, "sync_status": sync_status, "data": [{ "id": id, "groups": groups }] });
    let q = format!("global set-agent-groups {data}");
    match query_ex(db, log, &q).await {
        Ok(r) => {
            if parse_result(&r).0 != WdbcResult::Ok {
                log.debug1("Global DB Error reported in the result of the query");
                OS_INVALID
            } else {
                0
            }
        }
        Err(_) => {
            log.debug1("Global DB Error in the response from socket");
            log.debug2(format!("Global DB SQL query: {q}"));
            OS_INVALID
        }
    }
}

/// `wdb_update_groups`: drops the groups whose `etc/shared` folder is
/// gone and inserts the folders the DB does not have.
pub async fn update_groups(db: &dyn WdbQuery, log: &WLog, dirname: &str) -> i32 {
    let Some(root) = query_parse_json(db, log, "global select-groups").await else {
        log.error("Error querying Wazuh DB to update groups.");
        return OS_INVALID;
    };
    if let Some(a) = root.as_array() {
        for item in a {
            if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                let group_path = format!("{dirname}/{name}");
                if std::fs::read_dir(&group_path).is_err() {
                    // Group doesn't exists anymore, delete it
                    remove_group_db(db, log, name).await;
                }
            }
        }
    }
    // Add new groups from the folder /etc/shared if they dont exists on database
    let rd = match std::fs::read_dir(dirname) {
        Ok(r) => r,
        Err(e) => {
            log.error(format!("Couldn't open directory '{dirname}': {}.", errno_text(&e)));
            return OS_INVALID;
        }
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = format!("{dirname}/{name}");
        // C: `if (!IsDir(path))` -- IsDir returns 0 for a directory
        if std::fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false) && find_group(db, log, &name).await <= 0 {
            insert_group(db, log, &name).await;
        }
    }
    0
}

/// `strerror(errno)`
pub fn errno_text(e: &std::io::Error) -> String {
    let t = e.to_string();
    t.split(" (os error").next().unwrap_or("").to_string()
}

/// `TIMESTAMP_FILE`
pub const TIMESTAMP_FILE: &str = "queue/agents-timestamp";

/// `get_agent_date_added`: the registration date in `queue/agents-timestamp`
/// (local time), 0 when it is not there.
pub fn get_agent_date_added(log: &WLog, agent_id: i32) -> i64 {
    use chrono::TimeZone;
    let Ok(data) = std::fs::read(TIMESTAMP_FILE) else { return 0 };
    let text = String::from_utf8_lossy(&data);
    for line in text.split_inclusive('\n') {
        let Some(sep) = line.find(' ') else { continue };
        if siem_regex::os_ip::atoi(&line[..sep]) != agent_id {
            continue;
        }
        // OS_StrBreak(' ', line, 5): the date is fields 3 and 4
        let parts: Vec<&str> = line.splitn(5, ' ').collect();
        if parts.len() < 5 {
            return 0;
        }
        let date = format!("{} {}", parts[3], parts[4]);
        let date = date.split('\n').next().unwrap_or("");
        let parsed = chrono::NaiveDateTime::parse_from_str(date.trim_end(), "%Y-%m-%d %H:%M:%S");
        return match parsed.ok().and_then(|d| chrono::Local.from_local_datetime(&d).earliest()) {
            Some(t) => t.timestamp(),
            None => {
                log.error(format!("Invalid date format in file '{TIMESTAMP_FILE}' for agent '{agent_id}'"));
                0
            }
        };
    }
    0
}
