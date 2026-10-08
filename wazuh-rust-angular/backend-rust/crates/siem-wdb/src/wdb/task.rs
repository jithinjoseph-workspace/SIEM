//! The task manager database (wazuh_db/wdb_task.c) and the JSON commands
//! on the wazuh-db socket (wazuh_db/wdb_com.c).

use siem_cjson::Json;

use super::*;

pub const WM_TASK_STATUS_PENDING: &str = "Pending";
pub const WM_TASK_STATUS_IN_PROGRESS: &str = "In progress";
pub const WM_TASK_STATUS_DONE: &str = "Done";
pub const WM_TASK_STATUS_FAILED: &str = "Failed";
pub const WM_TASK_STATUS_CANCELLED: &str = "Cancelled";
pub const WM_TASK_STATUS_TIMEOUT: &str = "Timeout";
pub const WM_TASK_STATUS_LEGACY: &str = "Legacy";

fn sql_error(d: &Wdbd, wdb: &Wdb) {
    d.merror(&msg!("(5211): SQL error: '", wdb.errmsg(), "'"));
}

/// The upgrade task row of `SELECT *, MAX(CREATE_TIME) ...`.
pub struct TaskRow {
    pub node: Option<B>,
    pub module: Option<B>,
    pub command: Option<B>,
    pub status: Option<B>,
    pub error: Option<B>,
    pub create_time: i32,
    pub last_update_time: i32,
}

impl Wdbd {
    fn task_prep(&self, wdb: &mut Wdb, idx: usize) -> Option<std::sync::Arc<siem_sqlite::Stmt>> {
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.mdebug1(b"(5212): Cannot begin transaction.");
            return None;
        }
        if self.stmt_cache(wdb, idx) < 0 {
            self.mdebug1(b"(5213): Cannot cache statement.");
            return None;
        }
        Some(wdb.st(idx))
    }

    fn task_cache(&self, wdb: &mut Wdb, idx: usize) -> Option<std::sync::Arc<siem_sqlite::Stmt>> {
        if self.stmt_cache(wdb, idx) < 0 {
            self.mdebug1(b"(5213): Cannot cache statement.");
            return None;
        }
        Some(wdb.st(idx))
    }

    /// `wdb_task_insert_task`: the task id or OS_INVALID.
    pub fn task_insert_task(&self, wdb: &mut Wdb, agent_id: i32, node: &[u8], module: &[u8], command: &[u8]) -> i32 {
        let Some(st) = self.task_prep(wdb, WDB_STMT_TASK_INSERT_TASK) else {
            return OS_INVALID;
        };
        st.bind_int(1, agent_id);
        st.bind_text(2, Some(node));
        st.bind_text(3, Some(module));
        st.bind_text(4, Some(command));
        st.bind_int(5, self.time() as i32);
        st.bind_text(7, Some(WM_TASK_STATUS_PENDING.as_bytes()));
        let r = self.step(&st);
        if r != SQLITE_DONE && r != SQLITE_CONSTRAINT {
            sql_error(self, wdb);
            return OS_INVALID;
        }
        let Some(st) = self.task_cache(wdb, WDB_STMT_TASK_GET_LAST_AGENT_TASK) else {
            return OS_INVALID;
        };
        st.bind_int(1, agent_id);
        if self.step(&st) != SQLITE_ROW {
            sql_error(self, wdb);
            return OS_INVALID;
        }
        let task_id = st.column_int(0);
        if task_id == 0 {
            return OS_INVALID;
        }
        task_id
    }

    /// `wdb_task_get_upgrade_task_status`
    pub fn task_get_upgrade_task_status(&self, wdb: &mut Wdb, agent_id: i32, node: &[u8], status: &mut Option<B>) -> i32 {
        let Some(st) = self.task_prep(wdb, WDB_STMT_TASK_GET_LAST_AGENT_UPGRADE_TASK) else {
            return OS_INVALID;
        };
        st.bind_int(1, agent_id);
        if self.step(&st) != SQLITE_ROW {
            sql_error(self, wdb);
            return OS_INVALID;
        }
        let task_id = st.column_int(0);
        if task_id == 0 {
            return OS_SUCCESS;
        }
        let task_node = st.column_text(2).unwrap_or_default();
        let task_status = st.column_text(7).unwrap_or_default();
        if task_status == WM_TASK_STATUS_PENDING.as_bytes() && task_node != cstr(node) {
            let Some(del) = self.task_cache(wdb, WDB_STMT_TASK_DELETE_TASK) else {
                return OS_INVALID;
            };
            del.bind_int(1, task_id);
            if self.step(&del) != SQLITE_DONE {
                sql_error(self, wdb);
                return OS_INVALID;
            }
        } else {
            *status = Some(task_status);
        }
        OS_SUCCESS
    }

    /// `wdb_task_update_upgrade_task_status`
    pub fn task_update_upgrade_task_status(&self, wdb: &mut Wdb, agent_id: i32, node: &[u8], status: &[u8], error: Option<&[u8]>) -> i32 {
        let status = cstr(status);
        let is = |s: &str| status == s.as_bytes();
        if !is(WM_TASK_STATUS_IN_PROGRESS) && !is(WM_TASK_STATUS_DONE) && !is(WM_TASK_STATUS_FAILED) && !is(WM_TASK_STATUS_LEGACY) {
            return OS_INVALID;
        }
        let Some(st) = self.task_prep(wdb, WDB_STMT_TASK_GET_LAST_AGENT_UPGRADE_TASK) else {
            return OS_INVALID;
        };
        st.bind_int(1, agent_id);
        if self.step(&st) != SQLITE_ROW {
            sql_error(self, wdb);
            return OS_INVALID;
        }
        let task_id = st.column_int(0);
        if task_id == 0 {
            return OS_NOTFOUND;
        }
        let old_node = st.column_text(2).unwrap_or_default();
        let old_status = st.column_text(7).unwrap_or_default();
        let node = cstr(node);
        let old_is = |s: &str| old_status == s.as_bytes();
        if (is(WM_TASK_STATUS_IN_PROGRESS) && (!old_is(WM_TASK_STATUS_PENDING) || old_node != node))
            || (is(WM_TASK_STATUS_LEGACY) && (!old_is(WM_TASK_STATUS_IN_PROGRESS) || old_node != node))
            || (is(WM_TASK_STATUS_DONE) && !old_is(WM_TASK_STATUS_IN_PROGRESS))
            || (is(WM_TASK_STATUS_FAILED) && !old_is(WM_TASK_STATUS_IN_PROGRESS))
        {
            return OS_NOTFOUND;
        }
        let Some(upd) = self.task_cache(wdb, WDB_STMT_TASK_UPDATE_TASK_STATUS) else {
            return OS_INVALID;
        };
        upd.bind_text(1, Some(status));
        upd.bind_int(2, self.time() as i32);
        if let Some(e) = error {
            upd.bind_text(3, Some(e));
        }
        upd.bind_int(4, task_id);
        let r = self.step(&upd);
        if r != SQLITE_DONE && r != SQLITE_CONSTRAINT {
            sql_error(self, wdb);
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdb_task_get_upgrade_task_by_agent_id`: the task id, OS_NOTFOUND or
    /// OS_INVALID, and the row.
    pub fn task_get_upgrade_task_by_agent_id(&self, wdb: &mut Wdb, agent_id: i32) -> (i32, Option<TaskRow>) {
        let Some(st) = self.task_prep(wdb, WDB_STMT_TASK_GET_LAST_AGENT_UPGRADE_TASK) else {
            return (OS_INVALID, None);
        };
        st.bind_int(1, agent_id);
        if self.step(&st) != SQLITE_ROW {
            sql_error(self, wdb);
            return (OS_INVALID, None);
        }
        let task_id = st.column_int(0);
        if task_id == 0 {
            return (OS_NOTFOUND, None);
        }
        let row = TaskRow {
            node: st.column_text(2),
            module: st.column_text(3),
            command: st.column_text(4),
            create_time: st.column_int(5),
            last_update_time: st.column_int(6),
            status: st.column_text(7),
            error: st.column_text(8),
        };
        (task_id, Some(row))
    }

    /// `wdb_task_cancel_upgrade_tasks`
    pub fn task_cancel_upgrade_tasks(&self, wdb: &mut Wdb, node: &[u8]) -> i32 {
        let Some(st) = self.task_prep(wdb, WDB_STMT_TASK_CANCEL_PENDING_UPGRADE_TASKS) else {
            return OS_INVALID;
        };
        st.bind_int(1, self.time() as i32);
        st.bind_text(2, Some(node));
        let r = self.step(&st);
        if r != SQLITE_DONE && r != SQLITE_CONSTRAINT {
            sql_error(self, wdb);
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdb_task_set_timeout_status`
    pub fn task_set_timeout_status(&self, wdb: &mut Wdb, now: i64, interval: i32, next_timeout: &mut i64) -> i32 {
        let Some(st) = self.task_prep(wdb, WDB_STMT_TASK_GET_TASK_BY_STATUS) else {
            return OS_INVALID;
        };
        st.bind_text(1, Some(WM_TASK_STATUS_IN_PROGRESS.as_bytes()));
        while self.step(&st) == SQLITE_ROW {
            let task_id = st.column_int(0);
            let last_update_time = st.column_int(6);
            let limit = last_update_time.wrapping_add(interval) as i64;
            if now >= limit {
                let Some(upd) = self.task_cache(wdb, WDB_STMT_TASK_UPDATE_TASK_STATUS) else {
                    return OS_INVALID;
                };
                upd.bind_text(1, Some(WM_TASK_STATUS_TIMEOUT.as_bytes()));
                upd.bind_int(2, self.time() as i32);
                upd.bind_int(4, task_id);
                let r = self.step(&upd);
                if r != SQLITE_DONE && r != SQLITE_CONSTRAINT {
                    sql_error(self, wdb);
                    return OS_INVALID;
                }
            } else if *next_timeout > limit {
                *next_timeout = limit;
            }
        }
        OS_SUCCESS
    }

    /// `wdb_task_delete_old_entries`
    pub fn task_delete_old_entries(&self, wdb: &mut Wdb, timestamp: i32) -> i32 {
        let Some(st) = self.task_prep(wdb, WDB_STMT_TASK_DELETE_OLD_TASKS) else {
            return OS_INVALID;
        };
        st.bind_int(1, timestamp);
        if self.step(&st) != SQLITE_DONE {
            sql_error(self, wdb);
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdbcom_dispatch`: the JSON commands (getstats, getconfig).
    pub fn wdbcom_dispatch(&self, request: &[u8]) -> B {
        const MESSAGES: [&str; 7] = [
            "ok",
            "Invalid JSON input",
            "Empty command",
            "Unrecognized command",
            "Empty parameters",
            "Empty section",
            "Unrecognized or not configured section",
        ];
        let build = |code: usize, data: Option<Json>| {
            let mut root = Json::object();
            root.add("error", Json::number(code as f64));
            root.add("message", Json::string(MESSAGES[code]));
            root.add("data", data.unwrap_or_else(Json::object));
            out(root.print_unformatted())
        };
        let Ok((req, _)) = siem_cjson::parse_with_opts(cstr(request), false) else {
            return build(1, None);
        };
        match req.get("command") {
            Some(Json::String(c)) => match cstr(c) {
                b"getstats" => build(0, Some(self.state.create_state_json(self.time()))),
                b"getconfig" => match req.get("parameters") {
                    Some(p @ Json::Object(_)) => match p.get("section") {
                        Some(Json::String(s)) => match cstr(s) {
                            b"internal" => build(0, Some(self.get_internal_config())),
                            b"wdb" => build(0, Some(self.get_config())),
                            _ => build(6, None),
                        },
                        _ => build(5, None),
                    },
                    _ => build(4, None),
                },
                _ => build(3, None),
            },
            _ => build(2, None),
        }
    }
}
