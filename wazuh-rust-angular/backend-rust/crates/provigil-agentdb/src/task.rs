//! The `task` actor (spec § 1.5, § 5): agent upgrade tasks in `queue/tasks/tasks.db`.

use std::sync::Arc;

use provigil_json::Json;
use provigil_sqlite::{Stmt, SQLITE_CONSTRAINT, SQLITE_DONE, SQLITE_OK, SQLITE_ROW};

use crate::text::{answer, near, split_word, until_nul};
use crate::{layout, Answer, Engine, Handle, Locked, INVALID, OK, TASK_DIR, TASK_NAME};

const NOT_FOUND: i32 = -2;

const PENDING: &[u8] = b"Pending";
const IN_PROGRESS: &[u8] = b"In progress";
const DONE: &[u8] = b"Done";
const FAILED: &[u8] = b"Failed";
const TIMEOUT: &[u8] = b"Timeout";
const LEGACY: &[u8] = b"Legacy";

const LAST_UPGRADE_TASK: &str =
    "SELECT *, MAX(CREATE_TIME) FROM TASKS WHERE AGENT_ID = ? AND (COMMAND = 'upgrade' OR COMMAND = 'upgrade_custom');";
const UPDATE_STATUS: &str = "UPDATE TASKS SET STATUS = ?, LAST_UPDATE_TIME = ?, ERROR_MESSAGE = ? WHERE TASK_ID = ?;";

/// A task row (columns 2–8 of the table).
struct Row {
    node: Option<Vec<u8>>,
    module: Option<Vec<u8>>,
    command: Option<Vec<u8>>,
    create_time: i32,
    update_time: i32,
    status: Option<Vec<u8>>,
    error: Option<Vec<u8>>,
}

fn result(code: i32) -> Json {
    let mut r = Json::object();
    r.add("error", Json::number(code as f64));
    r
}
fn ok_json(j: &Json) -> Vec<u8> {
    answer(cat!("ok ", j.print_unformatted()))
}
fn number(j: Option<&Json>) -> Option<i32> {
    match j {
        Some(Json::Number { int, .. }) => Some(*int),
        _ => None,
    }
}
fn text(j: Option<&Json>) -> Option<&[u8]> {
    match j {
        Some(Json::String(s)) => Some(until_nul(s)),
        _ => None,
    }
}

impl Engine {
    /// The tasks database, created when missing.
    pub fn open_tasks(&self) -> Option<Locked> {
        let mut h = self.cached(TASK_NAME);
        if h.db.is_none() {
            let rel = format!("{TASK_DIR}/{TASK_NAME}.db");
            if !self.open_into(&mut h, &rel) {
                self.debug(b"Tasks database not found, creating.".to_vec());
                h.db = None;
                if !self.create_file(&rel, layout::TASKS) {
                    self.error(cat!("Couldn't create SQLite database '", rel.clone(), "'"));
                    return None;
                }
                if !self.open_into(&mut h, &rel) {
                    self.error(cat!("Can't open SQLite database '", rel.clone(), "': ", h.errmsg()));
                    h.db = None;
                    return None;
                }
            }
        }
        Some(h)
    }

    pub(crate) fn task_actor(&self, rest: &[u8], peer: i32) -> Answer {
        self.debug2(cat!("Task query: ", rest));
        let Some(mut h) = self.open_tasks() else {
            self.debug2(cat!("Couldn't open DB task: ", TASK_DIR, "/", TASK_NAME, ".db"));
            return (INVALID, b"err Couldn't open DB task".to_vec());
        };
        h.peer = peer;
        let (cmd, args) = split_word(rest);
        let Some(args) = args else {
            self.debug(b"Invalid DB query syntax.".to_vec());
            self.debug2(cat!("DB query error near: ", cmd));
            return (INVALID, near("err Invalid DB query syntax", cmd));
        };
        let json = || provigil_json::parse_with_opts(until_nul(args), false).map(|(j, _)| j);
        let with_params = |f: &dyn Fn(&mut Handle, &Json) -> Answer, h: &mut Handle| match json() {
            Err(_) => (INVALID, near("err Invalid command parameters", until_nul(args))),
            Ok(p) => f(h, &p),
        };
        match cmd {
            b"upgrade" => with_params(&|h, p| self.task_upgrade(h, p, b"upgrade"), &mut h),
            b"upgrade_custom" => with_params(&|h, p| self.task_upgrade(h, p, b"upgrade_custom"), &mut h),
            b"upgrade_get_status" => with_params(&|h, p| self.task_get_status(h, p), &mut h),
            b"upgrade_update_status" => with_params(&|h, p| self.task_update_status(h, p), &mut h),
            b"upgrade_result" => with_params(&|h, p| self.task_result(h, p), &mut h),
            b"upgrade_cancel_tasks" => with_params(&|h, p| self.task_cancel(h, p), &mut h),
            b"set_timeout" => with_params(&|h, p| self.task_set_timeout(h, p), &mut h),
            b"delete_old" => with_params(&|h, p| self.task_delete_old(h, p), &mut h),
            b"sql" => match self.sql(&h, until_nul(args)) {
                Some(d) => (OK, ok_json(&d)),
                None => {
                    let e = h.errmsg();
                    self.debug(cat!("Tasks DB Cannot execute SQL query; err database ", TASK_DIR, "/", TASK_NAME, ".db: ", e.clone()));
                    self.debug2(cat!("Tasks DB SQL query: ", until_nul(args)));
                    (INVALID, answer(cat!("err Cannot execute Tasks database query; ", e)))
                }
            },
            _ => {
                self.debug(b"Invalid DB query syntax.".to_vec());
                self.debug2(cat!("Task DB query error near: ", cmd));
                (INVALID, near("err Invalid DB query syntax", cmd))
            }
        }
    }

    // ------------------------------------------------------------------ statements

    /// A task statement: inside a transaction when `begin`, reused when cached.
    fn task_stmt(&self, h: &mut Handle, sql: &str, begin: bool) -> Option<Arc<Stmt>> {
        if begin && !h.transaction && !self.begin(h) {
            self.debug(b"(5212): Cannot begin transaction.".to_vec());
            return None;
        }
        if let Some(st) = h.stmts.get(sql) {
            let st = st.clone();
            st.reset();
            st.clear_bindings();
            return Some(st);
        }
        let (rc, st, _) = h.db().prepare_v2(sql.as_bytes());
        match st.filter(|_| rc == SQLITE_OK) {
            Some(st) => {
                let st = Arc::new(st);
                h.stmts.insert(sql.to_string(), st.clone());
                Some(st)
            }
            None => {
                self.error(cat!("DB(", h.id.clone(), ") sqlite3_prepare_v2() stmt(", sql, "): ", h.errmsg()));
                self.debug(b"(5213): Cannot cache statement.".to_vec());
                None
            }
        }
    }

    fn sql_error(&self, h: &Handle) {
        self.error(cat!("(5211): SQL error: '", h.errmsg(), "'"));
    }

    fn written(&self, h: &Handle, st: &Stmt) -> bool {
        let r = self.step(st);
        if r != SQLITE_DONE && r != SQLITE_CONSTRAINT {
            self.sql_error(h);
            return false;
        }
        true
    }

    // ------------------------------------------------------------------ operations

    /// Inserts a pending task; its id, or INVALID.
    fn insert_task(&self, h: &mut Handle, agent: i32, node: &[u8], module: &[u8], command: &[u8]) -> i32 {
        let Some(st) = self.task_stmt(h, "INSERT INTO TASKS VALUES(NULL,?,?,?,?,?,?,?,?);", true) else { return INVALID };
        st.bind_int(1, agent);
        st.bind_text(2, Some(node));
        st.bind_text(3, Some(module));
        st.bind_text(4, Some(command));
        st.bind_int(5, self.time() as i32);
        st.bind_text(7, Some(PENDING));
        if !self.written(h, &st) {
            return INVALID;
        }
        let Some(st) = self.task_stmt(h, "SELECT *, MAX(CREATE_TIME) FROM TASKS WHERE AGENT_ID = ?;", false) else { return INVALID };
        st.bind_int(1, agent);
        if self.step(&st) != SQLITE_ROW {
            self.sql_error(h);
            return INVALID;
        }
        match st.column_int(0) {
            0 => INVALID,
            id => id,
        }
    }

    /// The agent's last upgrade task: (task id or 0, row) or None on error.
    fn last_upgrade_task(&self, h: &mut Handle, agent: i32) -> Option<(i32, Row)> {
        let st = self.task_stmt(h, LAST_UPGRADE_TASK, true)?;
        st.bind_int(1, agent);
        if self.step(&st) != SQLITE_ROW {
            self.sql_error(h);
            return None;
        }
        Some((
            st.column_int(0),
            Row {
                node: st.column_text(2),
                module: st.column_text(3),
                command: st.column_text(4),
                create_time: st.column_int(5),
                update_time: st.column_int(6),
                status: st.column_text(7),
                error: st.column_text(8),
            },
        ))
    }

    fn task_upgrade(&self, h: &mut Handle, p: &Json, command: &[u8]) -> Answer {
        let Some(agent) = number(p.get("agent")) else {
            return (INVALID, b"err Error insert task: 'parsing agent error'".to_vec());
        };
        let Some(node) = text(p.get("node")) else {
            return (INVALID, b"err Error insert task: 'parsing node error'".to_vec());
        };
        let Some(module) = text(p.get("module")) else {
            return (INVALID, b"err Error insert task: 'parsing module error'".to_vec());
        };
        let id = self.insert_task(h, agent, node, module, command);
        if id >= 0 {
            let mut r = result(OK);
            r.add("task_id", Json::number(id as f64));
            (OK, ok_json(&r))
        } else {
            (id, ok_json(&result(id)))
        }
    }

    fn task_get_status(&self, h: &mut Handle, p: &Json) -> Answer {
        let Some(agent) = number(p.get("agent")) else {
            return (INVALID, b"err Error get upgrade task status: 'parsing agent error'".to_vec());
        };
        let Some(node) = text(p.get("node")) else {
            return (INVALID, b"err Error get upgrade task status: 'parsing node error'".to_vec());
        };
        let (code, status) = match self.last_upgrade_task(h, agent) {
            None => (INVALID, None),
            Some((0, _)) => (OK, None),
            Some((id, row)) => {
                let st = row.status.unwrap_or_default();
                // a pending task of another node is dropped
                if st == PENDING && row.node.unwrap_or_default() != node {
                    match self.task_stmt(h, "DELETE FROM TASKS WHERE TASK_ID = ?;", false) {
                        None => (INVALID, None),
                        Some(del) => {
                            del.bind_int(1, id);
                            if self.step(&del) != SQLITE_DONE {
                                self.sql_error(h);
                                (INVALID, None)
                            } else {
                                (OK, None)
                            }
                        }
                    }
                } else {
                    (OK, Some(st))
                }
            }
        };
        let mut r = result(code);
        if code == OK {
            if let Some(s) = status {
                r.add("status", Json::string(until_nul(&s)));
            }
        }
        (code, ok_json(&r))
    }

    fn task_update_status(&self, h: &mut Handle, p: &Json) -> Answer {
        let Some(agent) = number(p.get("agent")) else {
            return (INVALID, b"err Error upgrade update status task: 'parsing agent error'".to_vec());
        };
        let Some(node) = text(p.get("node")) else {
            return (INVALID, b"err Error upgrade update status task: 'parsing node error'".to_vec());
        };
        let Some(status) = text(p.get("status")) else {
            return (INVALID, b"err Error upgrade update status task: 'parsing status error'".to_vec());
        };
        let code = self.update_status(h, agent, node, status, text(p.get("error_msg")));
        (code, ok_json(&result(code)))
    }

    fn update_status(&self, h: &mut Handle, agent: i32, node: &[u8], status: &[u8], error: Option<&[u8]>) -> i32 {
        if ![IN_PROGRESS, DONE, FAILED, LEGACY].contains(&status) {
            return INVALID;
        }
        let Some((id, row)) = self.last_upgrade_task(h, agent) else { return INVALID };
        if id == 0 {
            return NOT_FOUND;
        }
        let (old_node, old) = (row.node.unwrap_or_default(), row.status.unwrap_or_default());
        // allowed moves: Pending→In progress (same node), In progress→Legacy (same node),
        // In progress→Done / Failed
        if (status == IN_PROGRESS && (old != PENDING || old_node != node))
            || (status == LEGACY && (old != IN_PROGRESS || old_node != node))
            || ((status == DONE || status == FAILED) && old != IN_PROGRESS)
        {
            return NOT_FOUND;
        }
        let Some(upd) = self.task_stmt(h, UPDATE_STATUS, false) else { return INVALID };
        upd.bind_text(1, Some(status));
        upd.bind_int(2, self.time() as i32);
        if let Some(e) = error {
            upd.bind_text(3, Some(e));
        }
        upd.bind_int(4, id);
        if self.written(h, &upd) {
            OK
        } else {
            INVALID
        }
    }

    fn task_result(&self, h: &mut Handle, p: &Json) -> Answer {
        let Some(agent) = number(p.get("agent")) else {
            return (INVALID, b"err Error upgrade result task: 'parsing agent error'".to_vec());
        };
        match self.last_upgrade_task(h, agent) {
            Some((id, row)) if id > 0 => {
                let mut r = result(OK);
                r.add("task_id", Json::number(id as f64));
                for (k, v) in [("node", &row.node), ("module", &row.module), ("command", &row.command), ("status", &row.status), ("error_msg", &row.error)] {
                    if let Some(v) = v {
                        r.add(k, Json::string(until_nul(v)));
                    }
                }
                r.add("create_time", Json::number(row.create_time as f64));
                r.add("update_time", Json::number(row.update_time as f64));
                (OK, ok_json(&r))
            }
            Some((0, _)) => (NOT_FOUND, ok_json(&result(NOT_FOUND))),
            _ => (INVALID, ok_json(&result(INVALID))),
        }
    }

    fn task_cancel(&self, h: &mut Handle, p: &Json) -> Answer {
        let Some(node) = text(p.get("node")) else {
            return (INVALID, b"err Error upgrade cancel task: 'parsing node error'".to_vec());
        };
        let code = match self.task_stmt(
            h,
            "UPDATE TASKS SET STATUS = 'Cancelled', LAST_UPDATE_TIME = ? WHERE NODE = ? AND STATUS = 'Pending' AND (COMMAND = 'upgrade' OR COMMAND = 'upgrade_custom');",
            true,
        ) {
            None => INVALID,
            Some(st) => {
                st.bind_int(1, self.time() as i32);
                st.bind_text(2, Some(node));
                if self.written(h, &st) {
                    OK
                } else {
                    INVALID
                }
            }
        };
        (code, ok_json(&result(code)))
    }

    fn task_set_timeout(&self, h: &mut Handle, p: &Json) -> Answer {
        let Some(now) = number(p.get("now")) else {
            return (INVALID, b"err Error set timeout task: 'parsing now error'".to_vec());
        };
        let Some(interval) = number(p.get("interval")) else {
            return (INVALID, b"err Error set timeout task: 'parsing interval error'".to_vec());
        };
        let mut next = now.wrapping_add(interval) as i64;
        let code = self.time_out_tasks(h, now as i64, interval, &mut next);
        let mut r = result(code);
        if code == OK {
            r.add("timestamp", Json::number(next as f64));
        }
        (code, ok_json(&r))
    }

    /// Tasks in progress longer than `interval` become timed out; `next` gets the earliest
    /// coming time-out.
    fn time_out_tasks(&self, h: &mut Handle, now: i64, interval: i32, next: &mut i64) -> i32 {
        let Some(st) = self.task_stmt(h, "SELECT * FROM TASKS WHERE STATUS = ?;", true) else { return INVALID };
        st.bind_text(1, Some(IN_PROGRESS));
        while self.step(&st) == SQLITE_ROW {
            let id = st.column_int(0);
            let limit = st.column_int(6).wrapping_add(interval) as i64;
            if now >= limit {
                let Some(upd) = self.task_stmt(h, UPDATE_STATUS, false) else { return INVALID };
                upd.bind_text(1, Some(TIMEOUT));
                upd.bind_int(2, self.time() as i32);
                upd.bind_int(4, id);
                if !self.written(h, &upd) {
                    return INVALID;
                }
            } else if *next > limit {
                *next = limit;
            }
        }
        OK
    }

    fn task_delete_old(&self, h: &mut Handle, p: &Json) -> Answer {
        let Some(ts) = number(p.get("timestamp")) else {
            return (INVALID, b"err Error delete old task: 'parsing timestamp error'".to_vec());
        };
        let code = match self.task_stmt(h, "DELETE FROM TASKS WHERE CREATE_TIME <= ?;", true) {
            None => INVALID,
            Some(st) => {
                st.bind_int(1, ts);
                if self.step(&st) != SQLITE_DONE {
                    self.sql_error(h);
                    INVALID
                } else {
                    OK
                }
            }
        };
        (code, ok_json(&result(code)))
    }
}
