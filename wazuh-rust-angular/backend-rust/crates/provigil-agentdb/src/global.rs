//! The `global` actor (spec § 1.4, § 3, § 7): the agent list, labels, groups, sync and backups.

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use provigil_json::Json;
use provigil_sqlite::{Stmt, SQLITE_DONE, SQLITE_ERROR, SQLITE_ROW};

use crate::rows::Columns;
use crate::text::{answer, id3, near, read_int, split_word, tokens, until_nul};
use crate::{Answer, Engine, Handle, GLOBAL_NAME, DB_DIR, INVALID, MAX_RESPONSE, OK, ST_DUE, ST_ERROR, ST_OK, ST_UNKNOWN, STATUS_WORDS, TOPIC_AGENT};

/// Codes of the "set groups" and "insert link" steps.
const NOT_FOUND: i32 = -2;
const UNDEFINED: i32 = -9;
/// Status codes written with a connection change.
const NO_KEEPALIVE: i32 = 4;
const RESET_BY_MANAGER: i32 = 5;
/// Group limits (spec § 7.7).
const MAX_GROUP_NAME: usize = 255;
const MAX_GROUPS_PER_AGENT: i32 = 128;
/// Characters of the agent group hash.
const GROUP_HASH_SIZE: usize = 8;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Override,
    Append,
    EmptyOnly,
    Remove,
}

fn text_of(j: Option<&Json>) -> Option<&[u8]> {
    match j {
        Some(Json::String(s)) => Some(until_nul(s)),
        _ => None,
    }
}
fn is_number(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::Number { .. }))
}
fn is_text(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::String(_)))
}
fn is_bool(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::True | Json::False))
}
fn int_of(j: Option<&Json>) -> i32 {
    match j {
        Some(Json::Number { int, .. }) => *int,
        Some(Json::True) => 1,
        _ => 0,
    }
}
fn first(j: &Json) -> Option<&Json> {
    match j {
        Json::Array(a) => a.first(),
        Json::Object(o) => o.first().map(|(_, v)| v),
        _ => None,
    }
}
fn ok_json(j: &Json) -> Vec<u8> {
    answer(cat!("ok ", j.print_unformatted()))
}
fn status_json(status: i32, j: &Json) -> Vec<u8> {
    answer(cat!(STATUS_WORDS[status as usize], " ", j.print_unformatted()))
}
fn ok() -> Vec<u8> {
    b"ok".to_vec()
}
/// The first `size` hex digits of SHA-256.
fn sha256_hex(s: &[u8], size: usize) -> Vec<u8> {
    let d = Sha256::digest(until_nul(s));
    d.iter().take(size / 2).flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}
fn hex(d: &[u8]) -> Vec<u8> {
    d.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

/// Local time `YYYY/MM/DD hh:mm:ss`.
fn local_stamp(t: i64, utc_offset: i64) -> String {
    let secs = t + utc_offset;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil from days (proleptic Gregorian)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y}/{m:02}/{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

impl Engine {
    pub(crate) fn global_actor(&self, rest: &[u8], peer: i32) -> Answer {
        self.debug2(cat!("Global query: ", rest));
        let Some(mut h) = self.open_global() else {
            self.debug2(cat!("Couldn't open DB global: ", DB_DIR, "/", GLOBAL_NAME, ".db"));
            return (INVALID, b"err Couldn't open DB global".to_vec());
        };
        if !h.enabled {
            self.debug2(cat!("Database disabled: ", DB_DIR, "/", GLOBAL_NAME, ".db."));
            return (INVALID, b"err DB global disabled.".to_vec());
        }
        h.peer = peer;
        let (cmd, args) = split_word(rest);
        let r = self.global_command(&mut h, cmd, args);
        if r.0 == INVALID {
            self.check_file(&mut h);
        }
        r
    }

    fn global_sql_err(&self, h: &Handle) -> Answer {
        let e = h.errmsg();
        self.debug(cat!("Global DB Cannot execute SQL query; err database ", DB_DIR, "/", GLOBAL_NAME, ".db: ", e.clone()));
        (INVALID, answer(cat!("err Cannot execute Global database query; ", e)))
    }

    /// Strict JSON (nothing may follow it).
    fn global_json(&self, input: &[u8], m1: &str) -> Result<Json, Answer> {
        match provigil_json::parse_with_opts(input, true) {
            Ok((j, _)) => Ok(j),
            Err(off) => {
                self.debug(m1.as_bytes().to_vec());
                self.debug2(cat!("Global DB JSON error near: ", until_nul(&input[off.min(input.len())..])));
                Err((INVALID, near("err Invalid JSON syntax", input)))
            }
        }
    }

    fn global_command(&self, h: &mut Handle, cmd: &[u8], args: Option<&[u8]>) -> Answer {
        // a command that needs arguments and got none
        macro_rules! need {
            (|$a:ident| $body:expr) => {
                match args {
                    Some($a) => $body,
                    None => {
                        self.debug(cat!("Global DB Invalid DB query syntax for ", cmd, "."));
                        self.debug2(cat!("Global DB query error near: ", cmd));
                        (INVALID, near("err Invalid DB query syntax", cmd))
                    }
                }
            };
        }
        match cmd {
            b"sql" => match args {
                None => {
                    self.debug(b"Global DB Invalid DB query syntax.".to_vec());
                    self.debug2(cat!("Global DB query error near: ", cmd));
                    (INVALID, near("err Invalid DB query syntax", cmd))
                }
                Some(sql) => match self.sql(h, sql) {
                    Some(d) => (OK, ok_json(&d)),
                    None => {
                        let e = h.errmsg();
                        self.debug(cat!("Global DB Cannot execute SQL query; err database ", DB_DIR, "/", GLOBAL_NAME, ".db: ", e.clone()));
                        self.debug2(cat!("Global DB SQL query: ", until_nul(sql)));
                        (INVALID, answer(cat!("err Cannot execute Global database query; ", e)))
                    }
                },
            },
            b"insert-agent" => need!(|a| self.cmd_insert_agent(h, a)),
            b"update-agent-name" => need!(|a| self.cmd_update_agent_name(h, a)),
            b"update-agent-data" => need!(|a| self.cmd_update_agent_data(h, a)),
            b"get-labels" => need!(|a| match self.labels_get(h, read_int(a)) {
                None => {
                    self.debug(b"Error getting agent labels from global.db.".to_vec());
                    (INVALID, b"err Error getting agent labels from global.db.".to_vec())
                }
                Some(l) => (OK, ok_json(&l)),
            }),
            b"update-keepalive" => need!(|a| self.cmd_update_keepalive(h, a)),
            b"update-connection-status" => need!(|a| self.cmd_update_connection_status(h, a)),
            b"update-status-code" => need!(|a| self.cmd_update_status_code(h, a)),
            b"delete-agent" => need!(|a| self.cmd_delete_agent(h, a)),
            b"select-agent-name" => need!(|a| {
                self.one_json(h, "SELECT name FROM agent WHERE id = ?;", read_int(a), "Error getting agent name from global.db.")
            }),
            b"select-agent-group" => need!(|a| {
                self.one_json(h, "SELECT `group` from agent where id = ?;", read_int(a), "Error getting agent group from global.db.")
            }),
            b"find-agent" => need!(|a| self.cmd_find_agent(h, a)),
            b"find-group" => need!(|a| match self.find_group(h, a) {
                None => {
                    self.debug(b"Error getting group id from global.db.".to_vec());
                    (INVALID, b"err Error getting group id from global.db.".to_vec())
                }
                Some(j) => (OK, ok_json(&j)),
            }),
            b"insert-agent-group" => need!(|a| {
                if self.insert_group(h, a) {
                    (OK, ok())
                } else {
                    self.debug(b"Error inserting group in global.db.".to_vec());
                    (INVALID, b"err Error inserting group in global.db.".to_vec())
                }
            }),
            b"select-group-belong" => need!(|a| match self.agent_groups(h, read_int(a)) {
                None => {
                    self.debug(b"Error getting agent groups information from global.db.".to_vec());
                    (INVALID, b"err Error getting agent groups information from global.db.".to_vec())
                }
                Some(j) => (OK, ok_json(&j)),
            }),
            b"get-group-agents" => need!(|a| self.cmd_get_group_agents(h, a)),
            b"delete-group" => need!(|a| {
                if self.delete_group(h, a) {
                    (OK, ok())
                } else {
                    self.debug(b"Error deleting group in global.db.".to_vec());
                    (INVALID, b"err Error deleting group in global.db.".to_vec())
                }
            }),
            b"select-groups" => match self.select_groups(h) {
                None => {
                    self.debug(b"Error getting groups from global.db.".to_vec());
                    (INVALID, b"err Error getting groups from global.db.".to_vec())
                }
                Some(j) => (OK, ok_json(&j)),
            },
            b"sync-agent-groups-get" => need!(|a| self.cmd_sync_agent_groups_get(h, a)),
            b"set-agent-groups" => need!(|a| self.cmd_set_agent_groups(h, a)),
            b"sync-agent-info-get" => self.cmd_sync_agent_info_get(h, args),
            b"sync-agent-info-set" => need!(|a| self.cmd_sync_agent_info_set(h, a)),
            b"get-groups-integrity" => need!(|a| self.cmd_groups_integrity(h, a)),
            b"recalculate-agent-group-hashes" => {
                if self.recalculate_all_group_hashes(h) {
                    (OK, ok())
                } else {
                    self.warn(b"Error recalculating group hash of agents in global.db.".to_vec());
                    (INVALID, b"err Error recalculating group hash of agents in global.db".to_vec())
                }
            }
            b"disconnect-agents" => need!(|a| self.cmd_disconnect_agents(h, a)),
            b"get-all-agents" => need!(|a| self.cmd_get_all_agents(h, a)),
            b"get-distinct-groups" => {
                let mut status = ST_UNKNOWN;
                match self.distinct_groups(h, args, &mut status) {
                    None => {
                        self.debug(b"Error getting agent groups from global.db.".to_vec());
                        (INVALID, b"err Error getting agent groups from global.db.".to_vec())
                    }
                    Some(j) => (OK, status_json(status, &j)),
                }
            }
            b"get-agent-info" => need!(|a| {
                self.one_json(h, "SELECT * FROM agent WHERE id = ?;", read_int(a), "Error getting agent information from global.db.")
            }),
            b"reset-agents-connection" => need!(|a| {
                if self.reset_connections(h, a) {
                    (OK, ok())
                } else {
                    self.global_sql_err(h)
                }
            }),
            b"get-agents-by-connection-status" => need!(|a| self.cmd_agents_by_status(h, a)),
            b"backup" => need!(|a| self.cmd_backup(h, a)),
            b"vacuum" => self.vacuum_command(h, "Global DB"),
            b"get_fragmentation" => self.fragmentation_command(h, "Global DB"),
            b"sleep" => self.sleep_command(args, cmd, "Global DB"),
            _ => {
                self.debug(b"Invalid DB query syntax.".to_vec());
                self.debug2(cat!("Global DB query error near: ", cmd));
                (INVALID, near("err Invalid DB query syntax", cmd))
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    fn stmt(&self, h: &mut Handle, sql: &str) -> Option<std::sync::Arc<Stmt>> {
        self.prepare(h, sql)
    }

    /// All rows of a one-int-parameter query, with the usual failure log.
    fn rows_of(&self, h: &mut Handle, sql: &str, id: i32) -> Option<Json> {
        let st = self.stmt(h, sql)?;
        st.bind_int(1, id);
        let r = self.rows(&st);
        if r.is_none() {
            self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
        }
        r
    }

    fn one_json(&self, h: &mut Handle, sql: &str, id: i32, err: &str) -> Answer {
        match self.rows_of(h, sql, id) {
            None => {
                self.debug(err.as_bytes().to_vec());
                (INVALID, cat!("err ", err))
            }
            Some(j) => (OK, ok_json(&j)),
        }
    }

    fn exec_binds(&self, h: &mut Handle, sql: &str, bind: impl FnOnce(&Stmt)) -> bool {
        let Some(st) = self.stmt(h, sql) else { return false };
        bind(&st);
        self.run(&st)
    }

    fn sync_status(&self, h: &mut Handle, id: i32) -> Option<Vec<u8>> {
        let st = self.stmt(h, "SELECT sync_status FROM agent WHERE id = ?;")?;
        st.bind_int(1, id);
        match self.step(&st) {
            SQLITE_ROW => st.column_text(0),
            SQLITE_DONE => None,
            _ => {
                self.debug(cat!("sqlite3_step(): ", h.errmsg()));
                None
            }
        }
    }

    /// The requested sync status, unless the current one does not allow it (§ 7.1).
    fn validated_sync(&self, h: &mut Handle, id: i32, requested: &[u8]) -> Vec<u8> {
        let requested = until_nul(requested);
        let Some(old) = self.sync_status(h, id) else {
            self.warn(cat!("Failed to get old sync_status for agent '", id, "'"));
            return requested.to_vec();
        };
        let allowed = match &old[..] {
            b"synced" | b"syncreq_keepalive" => true,
            b"syncreq_status" => requested != b"syncreq_keepalive",
            b"syncreq" => requested != b"syncreq_keepalive" && requested != b"syncreq_status",
            _ => false,
        };
        if allowed {
            requested.to_vec()
        } else {
            old
        }
    }

    pub(crate) fn group_hash_clear(&self) {
        self.group_hash.lock().clear();
    }

    // ------------------------------------------------------------------ agents

    fn valid_group_name(&self, g: &[u8]) -> bool {
        let g = until_nul(g);
        if g.len() > MAX_GROUP_NAME {
            self.warn(cat!("Invalid group name. The group '", g, "' exceeds the maximum length of ", MAX_GROUP_NAME, " characters permitted"));
            return false;
        }
        // the old pattern accepts backslashes as well (kept, spec § 7.7)
        if g.is_empty() || !g.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'\\' | b'.' | b'-')) {
            self.warn(cat!("Invalid group name. '", g, "' contains invalid characters"));
            return false;
        }
        if g == b"." {
            self.warn(b"Invalid group name. '.' represents the current directory in unix systems".to_vec());
            return false;
        }
        if g == b".." {
            self.warn(b"Invalid group name. '..' represents the parent directory in unix systems".to_vec());
            return false;
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_agent(&self, h: &mut Handle, id: i32, name: Option<&[u8]>, ip: Option<&[u8]>, register_ip: Option<&[u8]>, key: Option<&[u8]>, group: Option<&[u8]>, date_add: i32) -> bool {
        if let Some(g) = group.map(until_nul).filter(|g| !g.is_empty()) {
            for name in g.split(|&c| c == b',').filter(|s| !s.is_empty()) {
                if !self.valid_group_name(name) {
                    self.error(cat!("Invalid group name '", name, "' in multigroup '", g, "' for agent ", id));
                    return false;
                }
            }
        }
        self.exec_binds(h, "INSERT INTO agent (id, name, ip, register_ip, internal_key, date_add, `group`) VALUES (?,?,?,?,?,?,?);", |st| {
            st.bind_int(1, id);
            st.bind_text(2, name);
            st.bind_text(3, ip);
            st.bind_text(4, register_ip);
            st.bind_text(5, key);
            st.bind_int(6, date_add);
            st.bind_text(7, group);
        })
    }

    fn cmd_insert_agent(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let d = match self.global_json(input, "Global DB Invalid JSON syntax when inserting agent.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let (id, name, date) = (d.get("id"), d.get("name"), d.get("date_add"));
        if !(is_number(id) && is_text(name) && is_number(date)) {
            self.debug(b"Global DB Invalid JSON data when inserting agent. Not compliant with constraints defined in the database.".to_vec());
            return (INVALID, near("err Invalid JSON data", input));
        }
        let s = |k: &str| text_of(d.get(k));
        if !self.insert_agent(h, int_of(id), text_of(name), s("ip"), s("register_ip"), s("internal_key"), s("group"), int_of(date)) {
            return self.global_sql_err(h);
        }
        self.group_hash_clear();
        (OK, ok())
    }

    fn cmd_update_agent_name(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let d = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent name.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        if !(is_number(d.get("id")) && is_text(d.get("name"))) {
            self.debug(b"Global DB Invalid JSON data when updating agent name.".to_vec());
            return (INVALID, near("err Invalid JSON data", input));
        }
        let (id, name) = (int_of(d.get("id")), text_of(d.get("name")));
        if !self.exec_binds(h, "UPDATE agent SET name = ? WHERE id = ?;", |st| {
            st.bind_text(1, name);
            st.bind_int(2, id);
        }) {
            return self.global_sql_err(h);
        }
        (OK, ok())
    }

    fn cmd_update_agent_data(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let d = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent version.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        if !is_number(d.get("id")) {
            self.debug(b"Global DB Invalid JSON data when updating agent version.".to_vec());
            return (INVALID, near("err Invalid JSON data", input));
        }
        let id = int_of(d.get("id"));
        let s = |k: &str| text_of(d.get(k));
        const COLS: [&str; 14] = [
            "os_name", "os_version", "os_major", "os_minor", "os_codename", "os_platform", "os_build", "os_uname", "os_arch", "version",
            "config_sum", "merged_sum", "manager_host", "node_name",
        ];
        let validated = self.validated_sync(h, id, s("sync_status").unwrap_or(b"synced"));
        let ip = s("agent_ip");
        // the manager (id 0) keeps its "never expires" keep-alive
        let keepalive = "last_keepalive = (CASE WHEN id = 0 THEN 253402300799 ELSE STRFTIME('%s', 'NOW') END)";
        let sql = format!(
            "UPDATE agent SET {}, {keepalive}{}, connection_status = :connection_status, sync_status = :sync_status, group_config_status = :group_config_status WHERE id = :id;",
            COLS.iter().map(|c| format!("{c} = :{c}")).collect::<Vec<_>>().join(", "),
            if ip.is_some() { ", ip = :agent_ip" } else { "" }
        );
        let ok_ = self.exec_binds(h, &sql, |st| {
            for c in COLS {
                st.bind_text(st.bind_parameter_index(format!(":{c}").as_bytes()), s(c));
            }
            if ip.is_some() {
                st.bind_text(st.bind_parameter_index(b":agent_ip"), ip);
            }
            st.bind_text(st.bind_parameter_index(b":connection_status"), s("connection_status"));
            st.bind_text(st.bind_parameter_index(b":sync_status"), Some(&validated));
            st.bind_text(st.bind_parameter_index(b":group_config_status"), s("group_config_status"));
            st.bind_int(st.bind_parameter_index(b":id"), id);
        });
        if !ok_ {
            return self.global_sql_err(h);
        }
        // the labels are replaced only when the agent was updated; no labels removes them all
        let mut labels = id.to_string().into_bytes();
        if let Some(l) = s("labels") {
            labels.push(b' ');
            labels.extend_from_slice(l);
        }
        self.set_labels_text(h, &labels)
    }

    fn labels_get(&self, h: &mut Handle, id: i32) -> Option<Json> {
        self.rows_of(h, "SELECT * FROM labels WHERE id = ?;", id)
    }

    fn labels_delete(&self, h: &mut Handle, id: i32) -> bool {
        self.exec_binds(h, "DELETE FROM labels WHERE id = ?;", |st| {
            st.bind_int(1, id);
        })
    }

    fn label_set(&self, h: &mut Handle, id: i32, key: &[u8], value: &[u8]) -> bool {
        self.exec_binds(h, "INSERT INTO labels (id, key, value) VALUES (?,?,?);", |st| {
            st.bind_int(1, id);
            st.bind_text(2, Some(key));
            st.bind_text(3, Some(value));
        })
    }

    /// `<id> k1:v1\nk2:v2`: replaces the agent's labels.
    fn set_labels_text(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let input = until_nul(input);
        let start = input.iter().position(|&c| c != b' ');
        let Some(start) = start else {
            self.debug(b"Invalid DB query syntax.".to_vec());
            self.debug2(cat!("DB query error near: ", input));
            return (INVALID, near("err Invalid DB query syntax", input));
        };
        let rest = &input[start..];
        let (idt, labels) = match rest.iter().position(|&c| c == b' ') {
            Some(p) => (&rest[..p], &rest[p + 1..]),
            None => (rest, &b""[..]),
        };
        let id = read_int(idt);
        if !self.labels_delete(h, id) {
            return self.global_sql_err(h);
        }
        for line in labels.split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
            let Some(c) = line.iter().position(|&x| x == b':') else { continue };
            if !self.label_set(h, id, &line[..c], &line[c + 1..]) {
                return self.global_sql_err(h);
            }
        }
        (OK, ok())
    }

    fn cmd_update_keepalive(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let d = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent keepalive.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        if !(is_number(d.get("id")) && is_text(d.get("connection_status")) && is_text(d.get("sync_status"))) {
            self.debug(b"Global DB Invalid JSON data when updating agent keepalive.".to_vec());
            return (INVALID, near("err Invalid JSON data", input));
        }
        let id = int_of(d.get("id"));
        let v = self.validated_sync(h, id, text_of(d.get("sync_status")).unwrap_or_default());
        let conn = text_of(d.get("connection_status"));
        if !self.exec_binds(
            h,
            "UPDATE agent SET last_keepalive = STRFTIME('%s', 'NOW'), connection_status = ?, sync_status = ?, disconnection_time = 0, status_code = 0 WHERE id = ?;",
            |st| {
                st.bind_text(1, conn);
                st.bind_text(2, Some(&v));
                st.bind_int(3, id);
            },
        ) {
            return self.global_sql_err(h);
        }
        (OK, ok())
    }

    fn set_connection(&self, h: &mut Handle, id: i32, conn: &[u8], sync: Option<&[u8]>, code: i32) -> bool {
        let disconnected = if until_nul(conn) == b"disconnected" { self.time() } else { 0 };
        self.exec_binds(h, "UPDATE agent SET connection_status = ?, sync_status = ?, disconnection_time = ?, status_code = ? WHERE id = ?;", |st| {
            st.bind_text(1, Some(conn));
            st.bind_text(2, sync);
            st.bind_int(3, disconnected as i32);
            st.bind_int(4, code);
            st.bind_int(5, id);
        })
    }

    fn cmd_update_connection_status(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let d = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent connection status.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        if !(is_number(d.get("id")) && is_text(d.get("connection_status")) && is_text(d.get("sync_status")) && is_number(d.get("status_code"))) {
            self.debug(b"Global DB Invalid JSON data when updating agent connection status.".to_vec());
            return (INVALID, near("err Invalid JSON data", input));
        }
        let id = int_of(d.get("id"));
        let v = self.validated_sync(h, id, text_of(d.get("sync_status")).unwrap_or_default());
        if !self.set_connection(h, id, text_of(d.get("connection_status")).unwrap_or_default(), Some(&v), int_of(d.get("status_code"))) {
            return self.global_sql_err(h);
        }
        (OK, ok())
    }

    fn cmd_update_status_code(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let d = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent status code.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let version = d.get("version");
        if !(is_number(d.get("id")) && is_number(d.get("status_code")) && (version.is_none() || is_text(version)) && is_text(d.get("sync_status"))) {
            self.debug(b"Global DB Invalid JSON data when updating agent status code.".to_vec());
            return (INVALID, near("err Invalid JSON data", input));
        }
        let id = int_of(d.get("id"));
        let v = self.validated_sync(h, id, text_of(d.get("sync_status")).unwrap_or_default());
        let (code, ver) = (int_of(d.get("status_code")), text_of(version));
        if !self.exec_binds(h, "UPDATE agent SET status_code = ?, version = ?, sync_status = ? WHERE id = ?;", |st| {
            st.bind_int(1, code);
            st.bind_text(2, ver);
            st.bind_text(3, Some(&v));
            st.bind_int(4, id);
        }) {
            return self.global_sql_err(h);
        }
        (OK, ok())
    }

    fn cmd_delete_agent(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let id = read_int(input);
        if !self.exec_binds(h, "DELETE FROM agent WHERE id = ?;", |st| {
            st.bind_int(1, id);
        }) {
            self.debug(b"Error deleting agent from agent table in global.db.".to_vec());
            return (INVALID, b"err Error deleting agent from agent table in global.db.".to_vec());
        }
        if self.settings.router_agent {
            let mut info = Json::object();
            info.add("agent_id", Json::string(id3(id)));
            let mut m = Json::object();
            m.add("agent_info", info);
            m.add("action", Json::string("deleteAgent"));
            self.env.router_send(TOPIC_AGENT, &m.print_unformatted());
        }
        self.group_hash_clear();
        (OK, ok())
    }

    fn cmd_find_agent(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let d = match self.global_json(input, "Global DB Invalid JSON syntax when finding agent id.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        if !(is_text(d.get("name")) && is_text(d.get("ip"))) {
            self.debug(b"Global DB Invalid JSON data when finding agent id.".to_vec());
            return (INVALID, near("err Invalid JSON data", input));
        }
        let (name, ip) = (text_of(d.get("name")), text_of(d.get("ip")));
        let r = self.stmt(h, "SELECT id FROM agent WHERE name = ? AND (register_ip = ? OR register_ip LIKE ? || '/_%');").and_then(|st| {
            st.bind_text(1, name);
            st.bind_text(2, ip);
            st.bind_text(3, ip);
            let r = self.rows(&st);
            if r.is_none() {
                self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
            }
            r
        });
        match r {
            None => self.global_sql_err(h),
            Some(j) => (OK, ok_json(&j)),
        }
    }

    pub(crate) fn agent_exists_in(&self, h: &mut Handle, id: i32) -> i32 {
        let Some(st) = self.stmt(h, "SELECT EXISTS(SELECT 1 FROM agent WHERE id=?);") else { return INVALID };
        st.bind_int(1, id);
        match self.step(&st) {
            SQLITE_ROW => st.column_int(0),
            SQLITE_DONE => 0,
            _ => {
                self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
                INVALID
            }
        }
    }

    // ------------------------------------------------------------------ groups

    fn find_group(&self, h: &mut Handle, name: &[u8]) -> Option<Json> {
        let st = self.stmt(h, "SELECT id FROM `group` WHERE name = ?;")?;
        st.bind_text(1, Some(name));
        let r = self.rows(&st);
        if r.is_none() {
            self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
        }
        r
    }

    fn insert_group(&self, h: &mut Handle, name: &[u8]) -> bool {
        if !self.valid_group_name(name) {
            self.debug(cat!("Cannot insert '", until_nul(name), "'"));
            return false;
        }
        self.exec_binds(h, "INSERT INTO `group` (name) VALUES(?);", |st| {
            st.bind_text(1, Some(name));
        })
    }

    /// The agent's group names in priority order (one column, sized).
    fn agent_groups(&self, h: &mut Handle, id: i32) -> Option<Json> {
        let st = self.stmt(h, "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority;")?;
        st.bind_int(1, id);
        let mut status = SQLITE_ERROR;
        let r = self.rows_sized(&st, MAX_RESPONSE, &mut status, Columns::First);
        if status == SQLITE_ROW {
            self.warn(b"The agent's groups exceed the socket maximum response size.".to_vec());
        } else if status != SQLITE_DONE {
            self.debug(cat!("Failed to get agent groups: ", h.errmsg(), "."));
        }
        r
    }

    fn insert_link(&self, h: &mut Handle, group: i32, agent: i32, priority: i32) -> i32 {
        if !h.transaction && !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
            return UNDEFINED;
        }
        let Some(st) = self.prepare(h, "INSERT OR REPLACE INTO belongs (id_group, id_agent, priority) VALUES(?,?,?);") else { return UNDEFINED };
        st.bind_int(1, group);
        st.bind_int(2, agent);
        st.bind_int(3, priority);
        if self.run(&st) {
            OK
        } else {
            INVALID
        }
    }

    fn cmd_get_group_agents(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let mut t = tokens(input);
        let Some(group) = t.next() else {
            self.debug(b"Invalid arguments, group name not found.".to_vec());
            return (INVALID, b"err Invalid arguments, group name not found.".to_vec());
        };
        if t.next() != Some(b"last_id") {
            self.debug(b"Invalid arguments, 'last_id' not found.".to_vec());
            return (INVALID, b"err Invalid arguments, 'last_id' not found.".to_vec());
        }
        let Some(last) = t.next() else {
            self.debug(b"Invalid arguments, last agent id not found.".to_vec());
            return (INVALID, b"err Invalid arguments, last agent id not found.".to_vec());
        };
        let last = read_int(last);
        let fail = || {
            self.debug(b"Error getting group agents from global.db.".to_vec());
            (INVALID, b"err Error getting group agents from global.db.".to_vec())
        };
        let Some(st) = self.stmt(h, "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > ?;") else {
            return fail();
        };
        st.bind_text(1, Some(group));
        st.bind_int(2, last);
        let mut sql = SQLITE_ERROR;
        match self.rows_sized(&st, MAX_RESPONSE, &mut sql, Columns::First) {
            None => fail(),
            Some(j) => (OK, status_json(sql_status(sql), &j)),
        }
    }

    fn delete_group(&self, h: &mut Handle, name: &[u8]) -> bool {
        let agents = self.stmt(h, "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?);").and_then(|st| {
            st.bind_text(1, Some(name));
            let r = self.rows(&st);
            if r.is_none() {
                self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
            }
            r
        });
        let Some(st) = self.stmt(h, "DELETE FROM `group` WHERE name = ?;") else { return false };
        st.bind_text(1, Some(name));
        if !self.run(&st) {
            self.debug(cat!("SQLite: ", h.errmsg()));
            return false;
        }
        let (single, worker) = self.env.is_single_node();
        let sync: &[u8] = if single != 0 || worker != 0 { b"synced" } else { b"syncreq" };
        if let Some(Json::Array(items)) = agents {
            for item in items {
                if let Some(Json::Number { int: agent, .. }) = item.get("id_agent") {
                    if !self.default_group_if_empty(h, *agent) || !self.recalculate_group_hash(h, *agent, Some(sync)) {
                        self.error(cat!("Couldn't recalculate hash group for agent: '", id3(*agent), "'"));
                        return false;
                    }
                }
            }
        }
        true
    }

    fn select_groups(&self, h: &mut Handle) -> Option<Json> {
        let st = self.stmt(h, "SELECT name FROM `group`;")?;
        let mut status = SQLITE_ERROR;
        let r = self.rows_sized(&st, MAX_RESPONSE, &mut status, Columns::All);
        if status == SQLITE_ROW {
            self.warn(b"The groups exceed the socket maximum response size.".to_vec());
        } else if status != SQLITE_DONE {
            self.debug(cat!("Failed to get groups: ", h.errmsg(), "."));
        }
        r
    }

    fn max_priority(&self, h: &mut Handle, id: i32) -> i32 {
        self.single_int(h, "SELECT MAX(priority) FROM belongs WHERE id_agent=?;", id)
    }

    fn groups_number(&self, h: &mut Handle, id: i32) -> i32 {
        self.single_int(h, "SELECT count(id_group) groups_number from belongs WHERE id_agent = ?;", id)
    }

    /// The first column of the first row as an int, or INVALID when there is none.
    fn single_int(&self, h: &mut Handle, sql: &str, id: i32) -> i32 {
        let Some(st) = self.stmt(h, sql) else { return INVALID };
        st.bind_int(1, id);
        match self.rows(&st) {
            Some(r) => match first(&r).and_then(first) {
                Some(j) => int_of(Some(j)),
                None => INVALID,
            },
            None => {
                self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
                INVALID
            }
        }
    }

    fn group_id(&self, h: &mut Handle, name: &[u8]) -> Result<i32, ()> {
        match self.find_group(h, name) {
            Some(f) if !f.children().is_empty() => match first(&f).and_then(|c| c.get("id")) {
                Some(Json::Number { int, .. }) => Ok(*int),
                _ => {
                    self.warn(b"Invalid response from wdb_global_find_group.".to_vec());
                    Err(())
                }
            },
            _ => {
                self.warn(cat!("Unable to find the id of the group '", name, "'"));
                Err(())
            }
        }
    }

    fn assign_groups(&self, h: &mut Handle, id: i32, groups: &Json, mut priority: i32, create_name: Option<&[u8]>) -> bool {
        let mut good = true;
        for g in groups.children() {
            let Json::String(name) = g else {
                self.debug(b"Invalid groups set information".to_vec());
                good = false;
                continue;
            };
            let name = until_nul(name);
            let Ok(gid) = self.group_id(h, name) else {
                good = false;
                continue;
            };
            let mut r = self.insert_link(h, gid, id, priority);
            if create_name.is_none() && r == INVALID {
                // without a name the agent is not created
                r = NOT_FOUND;
            }
            if r == INVALID {
                if self.agent_exists_in(h, id) == 0 {
                    let ip: &[u8] = b"0.0.0.0";
                    let now = self.time() as i32;
                    if !self.insert_agent(h, id, create_name, Some(ip), Some(ip), None, None, now) {
                        self.debug(cat!("Unable to create agent '", id, "' in never_connected state"));
                        good = false;
                    } else {
                        r = self.insert_link(h, gid, id, priority);
                        if r == INVALID || r == UNDEFINED {
                            self.debug(cat!(
                                "Unable to insert group '", name, "' for agent '", id,
                                "', retry failed after creating agent in never_connected state."
                            ));
                            good = false;
                        } else {
                            priority += 1;
                        }
                    }
                } else {
                    self.debug(cat!("Unable to insert group '", name, "' for agent '", id, "', agent already exists, groups not synced."));
                    good = false;
                }
            } else if r == UNDEFINED {
                self.debug(cat!("Unable to insert group '", name, "' for agent '", id, "', undefined error."));
                good = false;
            } else if r == NOT_FOUND {
                self.debug(cat!("Unable to insert group '", name, "' for agent '", id, "', agent not found."));
                good = false;
            } else {
                priority += 1;
            }
        }
        good
    }

    fn unassign_groups(&self, h: &mut Handle, id: i32, groups: &Json) -> bool {
        let mut good = true;
        for g in groups.children() {
            let Json::String(name) = g else {
                self.debug(b"Invalid groups remove information".to_vec());
                good = false;
                continue;
            };
            let name = until_nul(name);
            let Ok(gid) = self.group_id(h, name) else {
                good = false;
                continue;
            };
            let deleted = self.exec_binds(h, "DELETE FROM belongs WHERE id_group = ? and id_agent = ?;", |st| {
                st.bind_int(1, gid);
                st.bind_int(2, id);
            });
            if deleted {
                if !self.default_group_if_empty(h, id) {
                    good = false;
                }
            } else {
                self.debug(cat!("Unable to delete group '", name, "' for agent '", id, "'"));
                good = false;
            }
        }
        good
    }

    fn default_group_if_empty(&self, h: &mut Handle, id: i32) -> bool {
        if self.max_priority(h, id) != INVALID {
            return true;
        }
        if self.assign_groups(h, id, &Json::Array(vec![Json::string("default")]), 0, None) {
            self.debug(cat!("Agent '", id3(id), "' reassigned to 'default' group"));
            true
        } else {
            self.error(cat!("There was an error assigning the agent '", id3(id), "' to default group"));
            false
        }
    }

    fn valid_groups(&self, h: &mut Handle, groups: &Json, id: i32) -> bool {
        let existing = self.groups_number(h, id);
        if existing == INVALID {
            return false;
        }
        let mut counter = 0;
        for g in groups.children() {
            if let Json::String(name) = g {
                counter += 1;
                if counter + existing > MAX_GROUPS_PER_AGENT {
                    self.warn(cat!("The groups assigned to agent ", id3(id), " exceed the maximum of ", MAX_GROUPS_PER_AGENT, " permitted."));
                    return false;
                }
                if !self.valid_group_name(name) {
                    return false;
                }
            }
        }
        true
    }

    /// The agent's groups joined with `,` in priority order (None when it has none).
    fn group_text(&self, h: &mut Handle, id: i32) -> Option<Vec<u8>> {
        let st = self.stmt(h, "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority;")?;
        st.bind_int(1, id);
        let mut out: Option<Vec<u8>> = None;
        let mut s;
        loop {
            s = self.step(&st);
            if s != SQLITE_ROW {
                break;
            }
            let Some(g) = st.column_text(0) else {
                self.debug(b"Group hash is NULL".to_vec());
                continue;
            };
            if let Some(o) = &out {
                if MAX_RESPONSE < o.len() + g.len() + 1 {
                    self.debug(b"The agent's groups exceed the socket maximum response size.".to_vec());
                    break;
                }
            }
            match &mut out {
                Some(o) => {
                    o.push(b',');
                    o.extend_from_slice(&g);
                }
                None => out = Some(g),
            }
        }
        if s != SQLITE_DONE {
            self.debug(b"SQL statement execution failed".to_vec());
        }
        out
    }

    fn recalculate_group_hash(&self, h: &mut Handle, id: i32, sync: Option<&[u8]>) -> bool {
        let text = self.group_text(h, id);
        let hash = match &text {
            Some(t) => Some(sha256_hex(t, GROUP_HASH_SIZE)),
            None => {
                self.warn(cat!("The groups were empty right after the set for agent '", id3(id), "'"));
                None
            }
        };
        let mut good = true;
        let set = self.exec_binds(h, "UPDATE agent SET 'group' = ?, group_hash = ?, group_sync_status = ? WHERE id = ?;", |st| {
            st.bind_text(1, text.as_deref());
            st.bind_text(2, hash.as_deref());
            st.bind_text(3, sync);
            st.bind_int(4, id);
        });
        if !set {
            self.debug(cat!("Error executing setting the agent group context: ", h.errmsg()));
            good = false;
            self.error(cat!("There was an error assigning the groups context to agent '", id3(id), "'"));
        }
        self.group_hash_clear();
        good
    }

    fn recalculate_group_hash_quiet(&self, h: &mut Handle, id: i32, stored: Option<&[u8]>) -> bool {
        let text = self.group_text(h, id);
        let hash = match &text {
            Some(t) => Some(sha256_hex(t, GROUP_HASH_SIZE)),
            None => {
                self.debug(cat!("No groups in belongs table for agent '", id3(id), "'"));
                None
            }
        };
        let changed = match (stored, &text) {
            (Some(_), None) | (None, Some(_)) => true,
            (Some(g), Some(t)) => until_nul(g) != &t[..],
            (None, None) => false,
        };
        let mut good = true;
        if changed {
            let set = self.exec_binds(h, "UPDATE agent SET 'group' = ?, group_hash = ? WHERE id = ?;", |st| {
                st.bind_text(1, text.as_deref());
                st.bind_text(2, hash.as_deref());
                st.bind_int(3, id);
            });
            if !set {
                self.debug(cat!("Error executing setting the agent group hash: ", h.errmsg()));
                good = false;
                self.error(cat!("There was an error assigning the groups hash to agent '", id3(id), "'"));
            }
        }
        self.group_hash_clear();
        good
    }

    fn recalculate_all_group_hashes(&self, h: &mut Handle) -> bool {
        let Some(st) = self.stmt(h, "SELECT id, `group` FROM agent WHERE id > ?;") else { return false };
        st.bind_int(1, 0);
        let mut s;
        loop {
            s = self.step(&st);
            if s != SQLITE_ROW {
                break;
            }
            let id = st.column_int(0);
            let group = st.column_text(1);
            if !self.recalculate_group_hash_quiet(h, id, group.as_deref()) {
                self.error(cat!("Couldn't recalculate hash group for agent: '", id3(id), "'"));
                return false;
            }
        }
        if s != SQLITE_DONE {
            self.debug(b"SQL statement execution failed".to_vec());
        }
        true
    }

    fn cmd_set_agent_groups(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let args = match provigil_json::parse_with_opts(input, true) {
            Ok((j, _)) => j,
            Err(off) => {
                self.debug(b"Global DB Invalid JSON syntax when parsing set_agent_groups".to_vec());
                self.debug2(cat!("Global DB JSON error near: ", until_nul(&input[off.min(input.len())..])));
                return (INVALID, near("err Invalid JSON syntax", input));
            }
        };
        let (Some(data @ Json::Array(_)), Some(mode_s)) = (args.get("data"), text_of(args.get("mode"))) else {
            self.debug(b"Missing mandatory fields in set_agent_groups command.".to_vec());
            return (INVALID, b"err Invalid JSON data, missing required fields".to_vec());
        };
        let mode = match mode_s {
            b"override" => Mode::Override,
            b"append" => Mode::Append,
            b"empty_only" => Mode::EmptyOnly,
            b"remove" => Mode::Remove,
            _ => {
                self.debug(cat!("Invalid mode '", mode_s, "' in set_agent_groups command."));
                return (INVALID, answer(cat!("err Invalid mode '", mode_s, "' in set_agent_groups command")));
            }
        };
        let sync = text_of(args.get("sync_status")).unwrap_or(b"synced");
        if self.set_agent_groups(h, mode, sync, data) {
            (OK, b"ok".to_vec())
        } else {
            (INVALID, cat!(STATUS_WORDS[ST_ERROR as usize], " An error occurred during the set of the groups"))
        }
    }

    fn set_agent_groups(&self, h: &mut Handle, mode: Mode, sync: &[u8], items: &Json) -> bool {
        let mut good = true;
        let mut valid = true;
        for item in items.children() {
            let (Some(Json::Number { int: id, .. }), Some(groups @ Json::Array(_))) = (item.get("id"), item.get("groups")) else {
                good = false;
                self.debug(b"Invalid groups set information".to_vec());
                continue;
            };
            let id = *id;
            let mut priority = 0;
            if mode == Mode::Remove {
                if !self.unassign_groups(h, id, groups) {
                    good = false;
                    self.error(cat!("There was an error un-assigning the groups to agent '", id3(id), "'"));
                }
            } else {
                if mode == Mode::Override {
                    if !self.exec_binds(h, "DELETE FROM belongs WHERE id_agent = ?;", |st| {
                        st.bind_int(1, id);
                    }) {
                        good = false;
                        self.error(b"There was an error cleaning the previous agent groups".to_vec());
                    }
                } else {
                    let last = self.max_priority(h, id);
                    if last >= 0 {
                        if mode == Mode::EmptyOnly {
                            self.debug(b"Agent group set in empty_only mode ignored because the agent already contains groups".to_vec());
                            continue;
                        }
                        priority = last + 1;
                    }
                }
                valid = self.valid_groups(h, groups, id);
                if valid {
                    let mut name: Option<Vec<u8>> = None;
                    if mode == Mode::Override {
                        match item.get("name") {
                            Some(Json::String(n)) => name = Some(until_nul(n).to_vec()),
                            _ if self.settings.is_worker_node => {
                                self.error(cat!("Agent name is required when overriding groups for agent '", id3(id), "'"));
                                good = false;
                                continue;
                            }
                            _ => self.debug(cat!(
                                "Agent name is not provided for agent '", id3(id),
                                "', the agent not will not be created if it does not exist"
                            )),
                        }
                    }
                    if !self.assign_groups(h, id, groups, priority, name.as_deref()) {
                        good = false;
                        self.error(cat!("There was an error assigning the groups to agent '", id3(id), "'"));
                    }
                } else {
                    good = false;
                }
            }
            if valid && !self.recalculate_group_hash(h, id, Some(sync)) {
                good = false;
                self.error(cat!("Couldn't recalculate hash group for agent: '", id3(id), "'"));
            }
        }
        good
    }

    /// SHA-1 of every agent's group hash in id order (empty when there is none); cached.
    fn global_group_hash(&self, h: &mut Handle) -> Option<Vec<u8>> {
        {
            let c = self.group_hash.lock();
            if !c.is_empty() {
                self.debug2(b"Using global group hash from cache".to_vec());
                return Some(c.clone());
            }
        }
        let st = self.stmt(h, "SELECT group_hash FROM agent WHERE id > 0 AND group_hash IS NOT NULL ORDER BY id;")?;
        let mut s = self.step(&st);
        if s != SQLITE_ROW {
            self.debug2(b"No group hash was found to calculate the global group hash.".to_vec());
            return Some(Vec::new());
        }
        let mut ctx = Sha1::new();
        while s == SQLITE_ROW {
            match st.column_text(0) {
                None => self.debug(cat!("DB(", h.id.clone(), ") has a NULL  checksum.")),
                Some(c) => ctx.update(&c),
            }
            s = self.step(&st);
        }
        let digest = hex(&ctx.finalize());
        *self.group_hash.lock() = digest.clone();
        self.debug2(b"New global group hash calculated and stored in cache.".to_vec());
        Some(digest)
    }

    fn cmd_groups_integrity(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let input = until_nul(input);
        if input.len() < 40 {
            let m = cat!("Hash hex-digest does not have the expected length. Expected (40) got (", input.len(), ")");
            self.debug(m.clone());
            return (INVALID, cat!("err ", m));
        }
        let want = &input[..40];
        let fail = || {
            self.debug(b"Error getting groups integrity information from global.db.".to_vec());
            (INVALID, b"err Error getting groups integrity information from global.db.".to_vec())
        };
        let Some(st) = self.stmt(h, "SELECT 1 FROM agent WHERE group_sync_status = 'syncreq';") else { return fail() };
        let word = match self.step(&st) {
            SQLITE_ROW => "syncreq",
            SQLITE_DONE => match self.global_group_hash(h) {
                Some(g) if g == want => "synced",
                _ => "hash_mismatch",
            },
            _ => {
                self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
                return fail();
            }
        };
        (OK, ok_json(&Json::Array(vec![Json::string(word)])))
    }

    fn distinct_groups(&self, h: &mut Handle, after: Option<&[u8]>, status: &mut i32) -> Option<Json> {
        let Some(st) = self.stmt(h, "SELECT DISTINCT `group`, group_hash from agent WHERE id > 0 AND group_hash > ? ORDER BY group_hash;") else {
            *status = ST_ERROR;
            return None;
        };
        st.bind_text(1, Some(after.unwrap_or(b"")));
        let mut sql = SQLITE_ERROR;
        let r = self.rows_sized(&st, MAX_RESPONSE, &mut sql, Columns::All);
        *status = sql_status(sql);
        r
    }

    // ------------------------------------------------------------------ sync

    fn cmd_sync_agent_groups_get(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let args = match provigil_json::parse_with_opts(input, true) {
            Ok((j, _)) => j,
            Err(off) => {
                self.debug(b"Global DB Invalid JSON syntax when parsing sync-agent-groups-get".to_vec());
                self.debug2(cat!("Global DB JSON error near: ", until_nul(&input[off.min(input.len())..])));
                return (INVALID, near("err Invalid JSON syntax", input));
            }
        };
        let (cond, last, set_synced, get_hash, delta) =
            (args.get("condition"), args.get("last_id"), args.get("set_synced"), args.get("get_global_hash"), args.get("agent_registration_delta"));
        if (cond.is_some() && !is_text(cond))
            || (last.is_some() && (!is_number(last) || int_of(last) < 0))
            || (set_synced.is_some() && !is_bool(set_synced))
            || (get_hash.is_some() && !is_bool(get_hash))
            || (delta.is_some() && (!is_number(delta) || int_of(delta) < 0))
        {
            self.debug(b"Invalid alternative fields data in sync-agent-groups-get command.".to_vec());
            return (INVALID, b"err Invalid JSON data, invalid alternative fields data".to_vec());
        }
        // Some(true) = only agents needing sync, Some(false) = all, None = no condition
        let condition = match text_of(cond) {
            Some(b"sync_status") => Some(Some(true)),
            Some(b"all") => Some(Some(false)),
            Some(_) => None,
            None => Some(None),
        };
        let r = match condition {
            None => {
                self.debug(b"Invalid groups sync condition".to_vec());
                (ST_ERROR, None)
            }
            Some(c) => self.sync_agent_groups_get(
                h,
                c,
                if last.is_some() { int_of(last) } else { 0 },
                matches!(set_synced, Some(Json::True)),
                matches!(get_hash, Some(Json::True)),
                if delta.is_some() { int_of(delta) } else { 0 },
            ),
        };
        match r {
            (status, Some(j)) => {
                let p = j.print_unformatted();
                if p.len() <= MAX_RESPONSE {
                    (OK, answer(cat!(STATUS_WORDS[status as usize], " ", p)))
                } else {
                    (INVALID, b"err Invalid response from wdb_global_sync_agent_groups_get".to_vec())
                }
            }
            (_, None) => (INVALID, b"err Could not obtain a response from wdb_global_sync_agent_groups_get".to_vec()),
        }
    }

    fn sync_agent_groups_get(&self, h: &mut Handle, cond: Option<bool>, mut last: i32, set_synced: bool, get_hash: bool, delta: i32) -> (i32, Option<Json>) {
        let mut response = Json::object();
        let mut data: Vec<Json> = Vec::new();
        let mut size = 13usize;
        let mut status = ST_UNKNOWN;
        let Some(only_syncreq) = cond else {
            if get_hash {
                response.add("data", Json::Array(data));
                let s = self.add_global_hash(h, &mut response, size);
                return (s, Some(Json::Array(vec![response])));
            }
            response.add("data", Json::Array(data));
            return (ST_OK, Some(Json::Array(vec![response])));
        };
        if !h.transaction && !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
            response.add("data", Json::Array(data));
            return (ST_ERROR, Some(Json::Array(vec![response])));
        }
        let registered_before = self.time() - delta as i64;
        let sql = if only_syncreq {
            "SELECT id, name FROM agent WHERE id > ? AND group_sync_status = 'syncreq' AND date_add < ? LIMIT 1;"
        } else {
            "SELECT id, name FROM agent WHERE id > ? AND date_add < ? LIMIT 1;"
        };
        while status == ST_UNKNOWN {
            let Some(st) = self.stmt(h, sql) else {
                self.debug(b"Cannot cache statement".to_vec());
                status = ST_ERROR;
                break;
            };
            st.bind_int(1, last);
            st.bind_int(2, registered_before as i32);
            match self.rows(&st).as_ref().and_then(first).cloned() {
                Some(mut agent) => {
                    if let Some(Json::Number { int: id, .. }) = agent.get("id") {
                        last = *id;
                        match self.agent_groups(h, last) {
                            Some(g) if first(&g).is_some() => agent.add("groups", g),
                            _ => agent.add("groups", Json::array()),
                        };
                        let len = agent.print_unformatted().len();
                        if size + len + 1 < MAX_RESPONSE {
                            data.push(agent);
                            size += len + 1;
                            if set_synced
                                && !self.exec_binds(h, "UPDATE agent SET group_sync_status = ? WHERE id = ?;", |st| {
                                    st.bind_text(1, Some(b"synced"));
                                    st.bind_int(2, last);
                                })
                            {
                                self.error(cat!("Cannot set group_sync_status for agent ", last));
                                status = ST_ERROR;
                            }
                        } else {
                            status = ST_DUE;
                        }
                    } else {
                        last += 1;
                    }
                }
                None => {
                    if get_hash {
                        response.add("data", Json::Array(std::mem::take(&mut data)));
                        let s = self.add_global_hash(h, &mut response, size);
                        return (s, Some(Json::Array(vec![response])));
                    }
                    status = ST_OK;
                }
            }
        }
        response.add("data", Json::Array(data));
        (status, Some(Json::Array(vec![response])))
    }

    fn add_global_hash(&self, h: &mut Handle, response: &mut Json, size: usize) -> i32 {
        if size + 7 + 41 + 1 < MAX_RESPONSE {
            match self.global_group_hash(h) {
                Some(hash) => {
                    response.add("hash", if hash.is_empty() { Json::Null } else { Json::String(hash) });
                    ST_OK
                }
                None => {
                    self.error(b"Cannot obtain the global group hash".to_vec());
                    ST_ERROR
                }
            }
        } else {
            ST_DUE
        }
    }

    fn cmd_sync_agent_info_get(&self, h: &mut Handle, args: Option<&[u8]>) -> Answer {
        let mut last = self.sync_last_id.lock();
        if let Some(a) = args {
            if let (b"last_id", Some(v)) = split_word(a) {
                *last = read_int(v);
            }
        }
        let (status, body) = self.sync_agent_info_get(h, &mut last);
        let o = answer(cat!(STATUS_WORDS[status as usize], " ", body));
        if status != ST_DUE {
            *last = 0;
        }
        (OK, o)
    }

    fn sync_agent_info_get(&self, h: &mut Handle, last: &mut i32) -> (i32, Vec<u8>) {
        if !h.transaction && !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
            return (ST_ERROR, b"Cannot begin transaction".to_vec());
        }
        let mut out = b"[".to_vec();
        let mut size = 2usize;
        let initial = *last;
        let mut status = ST_UNKNOWN;
        let passes = [
            "SELECT id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, last_keepalive, connection_status, disconnection_time, group_config_status, status_code FROM agent WHERE id > ? AND sync_status = 'syncreq' LIMIT 1;",
            "SELECT id, last_keepalive, connection_status, disconnection_time, status_code FROM agent WHERE id > ? AND sync_status = 'syncreq_status' LIMIT 1;",
            "SELECT id, last_keepalive FROM agent WHERE id > ? AND sync_status = 'syncreq_keepalive' LIMIT 1;",
        ];
        for (n, sql) in passes.iter().enumerate() {
            *last = initial;
            status = ST_UNKNOWN;
            while status == ST_UNKNOWN {
                let Some(st) = self.stmt(h, sql) else {
                    self.debug(b"Cannot cache statement".to_vec());
                    return (ST_ERROR, b"Cannot cache statement".to_vec());
                };
                st.bind_int(1, *last);
                match self.rows(&st).as_ref().and_then(first).cloned() {
                    Some(mut agent) => {
                        if let Some(Json::Number { int: id, .. }) = agent.get("id").cloned() {
                            if n == 0 {
                                if let Some(labels) = self.labels_get(h, id) {
                                    if first(&labels).is_some() {
                                        agent.add("labels", labels);
                                    }
                                }
                            }
                            let p = agent.print_unformatted();
                            if size + p.len() + 1 < MAX_RESPONSE {
                                out.extend_from_slice(&p);
                                out.push(b',');
                                size += p.len() + 1;
                                *last = id;
                                if !self.exec_binds(h, "UPDATE agent SET sync_status = ? WHERE id = ?;", |st| {
                                    st.bind_text(1, Some(b"synced"));
                                    st.bind_int(2, id);
                                }) {
                                    self.error(cat!("Cannot set sync_status for agent ", id));
                                    return (ST_ERROR, cat!("Cannot set sync_status for agent ", id));
                                }
                            } else {
                                status = ST_DUE;
                            }
                        } else {
                            *last += 1;
                        }
                    }
                    None => status = ST_OK,
                }
            }
            if status == ST_DUE {
                break;
            }
        }
        if size > 2 {
            out.pop();
        }
        out.push(b']');
        (status, out)
    }

    fn cmd_sync_agent_info_set(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let root = match provigil_json::parse_with_opts(input, true) {
            Ok((j, _)) => j,
            Err(off) => {
                self.debug(b"Global DB Invalid JSON syntax updating unsynced agents.".to_vec());
                self.debug2(cat!("Global DB JSON error near: ", until_nul(&input[off.min(input.len())..])));
                return (INVALID, near("err Invalid JSON syntax", input));
            }
        };
        for agent in root.children() {
            if !self.sync_agent_info_set(h, agent) {
                return self.global_sql_err(h);
            }
            let Some(labels @ Json::Array(_)) = agent.get("labels") else { continue };
            let id = if is_number(agent.get("id")) { int_of(agent.get("id")) } else { INVALID };
            if id == INVALID {
                self.debug(b"Global DB Cannot execute SQL query; incorrect agent id in labels array.".to_vec());
                return (INVALID, b"err Cannot update labels due to invalid id.".to_vec());
            }
            if !self.labels_delete(h, id) {
                return self.global_sql_err(h);
            }
            for l in labels.children() {
                let (k, v, i) = (l.get("key"), l.get("value"), l.get("id"));
                if is_text(k) && is_text(v) && is_number(i) && !self.label_set(h, int_of(i), text_of(k).unwrap_or_default(), text_of(v).unwrap_or_default()) {
                    return self.global_sql_err(h);
                }
            }
        }
        (OK, ok())
    }

    fn sync_agent_info_set(&self, h: &mut Handle, agent: &Json) -> bool {
        const COLS: [&str; 22] = [
            "config_sum", "ip", "manager_host", "merged_sum", "name", "node_name", "os_arch", "os_build", "os_codename", "os_major", "os_minor",
            "os_name", "os_platform", "os_uname", "os_version", "version", "last_keepalive", "connection_status", "disconnection_time", "id",
            "group_config_status", "status_code",
        ];
        let sql = "UPDATE agent SET config_sum = :config_sum, ip = :ip, manager_host = :manager_host, merged_sum = :merged_sum, name = :name, node_name = :node_name, os_arch = :os_arch, os_build = :os_build, os_codename = :os_codename, os_major = :os_major, os_minor = :os_minor, os_name = :os_name, os_platform = :os_platform, os_uname = :os_uname, os_version = :os_version, version = :version, last_keepalive = :last_keepalive, connection_status = :connection_status, disconnection_time = :disconnection_time, group_config_status = :group_config_status, status_code = :status_code, sync_status = :sync_status WHERE id = :id;";
        self.exec_binds(h, sql, |st| {
            for c in COLS {
                let i = st.bind_parameter_index(format!(":{c}").as_bytes());
                if i == 0 {
                    continue;
                }
                match agent.get(c) {
                    Some(Json::Number { int, .. }) => {
                        st.bind_int(i, *int);
                    }
                    Some(Json::String(s)) => {
                        st.bind_text(i, Some(s));
                    }
                    _ => {}
                }
            }
            st.bind_text(st.bind_parameter_index(b":sync_status"), Some(b"synced"));
        })
    }

    // ------------------------------------------------------------------ connections

    fn cmd_disconnect_agents(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let mut t = tokens(input);
        let Some(last) = t.next() else {
            self.debug(b"Invalid arguments last id not found.".to_vec());
            return (INVALID, b"err Invalid arguments last id not found".to_vec());
        };
        let Some(keepalive) = t.next() else {
            self.debug(b"Invalid arguments keepalive not found.".to_vec());
            return (INVALID, b"err Invalid arguments keepalive not found".to_vec());
        };
        let Some(sync) = t.next() else {
            self.debug(b"Invalid arguments sync_status not found.".to_vec());
            return (INVALID, b"err Invalid arguments sync_status not found".to_vec());
        };
        let fail = || {
            self.debug(b"Error getting agents to be disconnected from global.db.".to_vec());
            (INVALID, b"err Error getting agents to be disconnected from global.db.".to_vec())
        };
        let Some(st) = self.stmt(
            h,
            "SELECT id FROM agent WHERE id > ? AND (connection_status = 'active' OR connection_status = 'pending') AND last_keepalive < ?;",
        ) else {
            return fail();
        };
        st.bind_int(1, read_int(last));
        st.bind_int(2, read_int(keepalive));
        let mut sql = SQLITE_ERROR;
        let Some(r) = self.rows_sized(&st, MAX_RESPONSE, &mut sql, Columns::All) else { return fail() };
        let mut status = sql_status(sql);
        drop(st);
        for agent in r.children() {
            match agent.get("id") {
                Some(Json::Number { int: id, .. }) => {
                    if !self.set_connection(h, *id, b"disconnected", Some(sync), NO_KEEPALIVE) {
                        self.error(cat!("Cannot set connection_status for agent ", *id));
                        status = ST_ERROR;
                    }
                }
                _ => {
                    self.error(b"Invalid element returned by disconnect query".to_vec());
                    status = ST_ERROR;
                }
            }
        }
        (OK, status_json(status, &r))
    }

    fn cmd_get_all_agents(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let mut t = tokens(input);
        match t.next() {
            Some(b"context") => {
                let Some(st) = self.stmt(h, "SELECT id,version,name,ip FROM agent;") else {
                    return (INVALID, b"err Error getting agents from global.db.".to_vec());
                };
                let r = self.rows_send(&st, h.peer);
                if r != OK {
                    return (r, b"err Error getting agents from global.db.".to_vec());
                }
                (OK, b"ok []".to_vec())
            }
            Some(b"last_id") => {
                let Some(last) = t.next() else {
                    self.debug(b"Invalid arguments 'last_id' not found.".to_vec());
                    return (INVALID, b"err Invalid arguments 'last_id' not found".to_vec());
                };
                let fail = || {
                    self.debug(b"Error getting agents from global.db.".to_vec());
                    (INVALID, b"err Error getting agents from global.db.".to_vec())
                };
                let Some(st) = self.stmt(h, "SELECT id FROM agent WHERE id > ?;") else { return fail() };
                st.bind_int(1, read_int(last));
                let mut sql = SQLITE_ERROR;
                match self.rows_sized(&st, MAX_RESPONSE, &mut sql, Columns::All) {
                    None => fail(),
                    Some(j) => (OK, status_json(sql_status(sql), &j)),
                }
            }
            _ => {
                self.debug(b"Invalid arguments 'last_id' or 'context' not found.".to_vec());
                (INVALID, b"err Invalid arguments 'last_id' or 'context' not found".to_vec())
            }
        }
    }

    fn reset_connections(&self, h: &mut Handle, sync: &[u8]) -> bool {
        self.exec_binds(
            h,
            "UPDATE agent SET connection_status = 'disconnected', status_code = ?, sync_status = ?, disconnection_time = STRFTIME('%s', 'NOW') where connection_status != 'disconnected' AND connection_status != 'never_connected' AND id != 0;",
            |st| {
                st.bind_int(1, RESET_BY_MANAGER);
                st.bind_text(2, Some(sync));
            },
        )
    }

    fn cmd_agents_by_status(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let mut t = tokens(input);
        let Some(last) = t.next() else {
            self.debug(b"Invalid arguments 'last_id' not found.".to_vec());
            return (INVALID, b"err Invalid arguments 'last_id' not found".to_vec());
        };
        let Some(conn) = t.next() else {
            self.debug(b"Invalid arguments 'connection_status' not found.".to_vec());
            return (INVALID, b"err Invalid arguments 'connection_status' not found".to_vec());
        };
        let mut node = None;
        let mut limit = 0;
        if let Some(n) = t.next() {
            node = Some(n);
            let Some(l) = t.next() else {
                self.debug(b"Invalid arguments 'limit' not found.".to_vec());
                return (INVALID, b"err Invalid arguments 'limit' not found".to_vec());
            };
            limit = read_int(l);
        }
        let fail = || {
            self.debug(b"Error getting agents by connection status from global.db.".to_vec());
            (INVALID, b"err Error getting agents by connection status from global.db.".to_vec())
        };
        if !h.transaction && !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
            return fail();
        }
        let sql = if node.is_none() {
            "SELECT id FROM agent WHERE id > ? AND connection_status = ?;"
        } else {
            "SELECT id FROM agent WHERE id > ? AND connection_status = ? AND node_name = ? ORDER BY id LIMIT ?;"
        };
        let Some(st) = self.stmt(h, sql) else { return fail() };
        st.bind_int(1, read_int(last));
        st.bind_text(2, Some(conn));
        if let Some(n) = node {
            st.bind_text(3, Some(n));
            st.bind_int(4, limit);
        }
        let mut sql = SQLITE_ERROR;
        match self.rows_sized(&st, MAX_RESPONSE, &mut sql, Columns::All) {
            None => fail(),
            Some(j) => (OK, status_json(sql_status(sql), &j)),
        }
    }

    // ------------------------------------------------------------------ backups

    fn cmd_backup(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let (action, rest) = match input.iter().position(|&c| c != b' ') {
            None => return (INVALID, b"err Missing backup action".to_vec()),
            Some(s) => {
                let t = &input[s..];
                match t.iter().position(|&c| c == b' ') {
                    Some(p) => (&t[..p], &t[p + 1..]),
                    None => (t, &b""[..]),
                }
            }
        };
        match action {
            b"create" => {
                let (r, out) = self.create_backup(h, "");
                if r != OK {
                    self.error(cat!("Creating Global DB snapshot on demand failed: ", until_nul(&out)));
                }
                (r, out)
            }
            b"get" => match self.backup_names() {
                Some(names) => (OK, ok_json(&Json::Array(names.into_iter().map(|(n, _)| Json::string(n)).collect()))),
                None => {
                    self.debug(cat!("Unable to open backup directory '", crate::BACKUP_DIR, "'"));
                    (INVALID, answer(cat!("err Cannot execute backup get command, unable to open '", crate::BACKUP_DIR, "' folder")))
                }
            },
            b"restore" => {
                let input = until_nul(rest);
                let params = provigil_json::parse_with_opts(input, true);
                if let Err(off) = &params {
                    if !input.is_empty() {
                        self.debug(b"Invalid backup JSON syntax when restoring snapshot.".to_vec());
                        self.debug2(cat!("JSON error near: ", until_nul(&input[(*off).min(input.len())..])));
                        return (INVALID, near("err Invalid JSON syntax", input));
                    }
                }
                let params = params.ok().map(|(j, _)| j);
                let snapshot = params.as_ref().and_then(|p| text_of(p.get("snapshot"))).map(|s| s.to_vec());
                let save = matches!(params.as_ref().and_then(|p| p.get("save_pre_restore_state")), Some(Json::True));
                self.restore_backup(h, snapshot.as_deref(), save)
            }
            _ => (INVALID, answer(cat!("err Invalid backup action: ", action))),
        }
    }

    /// Backups of the global database: (name, modification time).
    pub(crate) fn backup_names(&self) -> Option<Vec<(String, Option<i64>)>> {
        let dir = std::fs::read_dir(self.path(crate::BACKUP_DIR)).ok()?;
        let mut v = Vec::new();
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(BACKUP_NAME) {
                continue;
            }
            let t = e.metadata().ok().and_then(|m| m.modified().ok()).map(|t| match t.duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(e) => -(e.duration().as_secs() as i64),
            });
            v.push((name, t));
        }
        Some(v)
    }

    pub(crate) fn create_backup(&self, h: &mut Handle, tag: &str) -> Answer {
        let now = self.time();
        let stamp = local_stamp(now, self.env.utc_offset(now)).replace([' ', '/'], "-");
        // Windows file names cannot hold ':' (decision D-4: the old code's backups always failed there)
        #[cfg(windows)]
        let stamp = stamp.replace(':', "-");
        let rel = format!("{}/{BACKUP_NAME}-{stamp}{tag}", crate::BACKUP_DIR);
        if !self.commit(h) {
            return (INVALID, b"err Cannot commit current transaction to create backup".to_vec());
        }
        h.drop_statements();
        let full = self.path(&rel);
        let (rc, st, _) = h.db().prepare_v2(b"VACUUM INTO ?;");
        let Some(st) = st.filter(|_| rc == provigil_sqlite::SQLITE_OK) else {
            return (INVALID, answer(cat!("err DB(", h.id.clone(), ") sqlite3_prepare_v2(): ", h.errmsg())));
        };
        st.bind_text(1, Some(full.to_string_lossy().as_bytes()));
        if !self.run(&st) {
            return (INVALID, answer(cat!("err SQLite: ", h.errmsg())));
        }
        drop(st);
        let gz = format!("{rel}.gz");
        let compressed = match gzip_file(&full, &self.path(&gz)) {
            Ok(()) => true,
            Err(e) => {
                self.error(cat!("Global database backup compression failed: ", e));
                false
            }
        };
        let _ = std::fs::remove_file(&full);
        if !compressed {
            return (INVALID, b"err Failed during database backup compression".to_vec());
        }
        self.info(cat!("Created Global database backup \"", gz.clone(), "\""));
        self.remove_old_backups();
        (OK, ok_json(&Json::Array(vec![Json::string(gz)])))
    }

    fn remove_old_backups(&self) {
        let Some(names) = self.backup_names() else {
            self.debug(cat!("Unable to open backup directory '", crate::BACKUP_DIR, "'"));
            return;
        };
        let extra = names.len() as i64 - self.settings.backup_max_files as i64;
        for _ in 0..extra.max(0) {
            if let Some(n) = self.oldest_backup() {
                let rel = format!("{}/{n}", crate::BACKUP_DIR);
                let _ = std::fs::remove_file(self.path(&rel));
                self.info(cat!("Deleted Global database backup: \"", rel, "\""));
            }
        }
    }

    fn newest_backup(&self) -> Option<String> {
        let Some(names) = self.backup_names() else {
            self.debug(cat!("Unable to open backup directory '", crate::BACKUP_DIR, "'"));
            return None;
        };
        let mut best: (i64, Option<String>) = (INVALID as i64, None);
        for (n, t) in names {
            if let Some(t) = t {
                if t >= best.0 {
                    best = (t, Some(n));
                }
            }
        }
        best.1
    }

    fn oldest_backup(&self) -> Option<String> {
        let Some(names) = self.backup_names() else {
            self.debug(cat!("Unable to open backup directory '", crate::BACKUP_DIR, "'"));
            return None;
        };
        let now = self.time();
        let mut best: (i64, Option<String>) = (INVALID as i64, None);
        for (n, t) in names {
            if let Some(t) = t {
                if now - t >= best.0 {
                    best = (now - t, Some(n));
                }
            }
        }
        best.1
    }

    fn restore_backup(&self, h: &mut Handle, snapshot: Option<&[u8]>, save_first: bool) -> Answer {
        let chosen: Option<Vec<u8>> = match snapshot {
            Some(s) => Some(until_nul(s).to_vec()),
            None => self.newest_backup().map(String::into_bytes),
        };
        if save_first {
            let (r, out) = self.create_backup(h, "-pre_restore");
            if r != OK {
                self.error(cat!("Creating pre-restore Global DB snapshot failed. Backup restore stopped: ", until_nul(&out)));
                return (INVALID, out);
            }
        }
        let Some(b) = chosen else {
            self.debug(b"Unable to found a snapshot to restore".to_vec());
            return (INVALID, b"err Unable to found a snapshot to restore".to_vec());
        };
        let global = format!("{DB_DIR}/{GLOBAL_NAME}.db");
        let tmp = format!("{DB_DIR}/{GLOBAL_NAME}.db.back");
        let src = format!("{}/{}", crate::BACKUP_DIR, String::from_utf8_lossy(&b));
        if let Err(e) = gunzip_file(&self.path(&src), &self.path(&tmp)) {
            self.error(cat!("Global database backup decompression failed: ", e));
            self.debug(b"Failed during backup decompression".to_vec());
            return (INVALID, b"err Failed during backup decompression".to_vec());
        }
        self.close(h, true);
        let _ = std::fs::remove_file(self.path(&global));
        match std::fs::rename(self.path(&tmp), self.path(&global)) {
            Err(e) => {
                self.error(cat!("Renaming ", tmp, " to ", global, ": ", e.to_string()));
                (INVALID, Vec::new())
            }
            Ok(()) => (OK, ok()),
        }
    }
}

/// Backup file name prefix in `backup/db`.
const BACKUP_NAME: &str = "global.db-backup";

/// ok / due / err from the last step of a sized read.
fn sql_status(s: i32) -> i32 {
    match s {
        SQLITE_DONE => ST_OK,
        SQLITE_ROW => ST_DUE,
        _ => ST_ERROR,
    }
}

/// Compresses a file; the reason when it fails.
fn gzip_file(src: &std::path::Path, dst: &std::path::Path) -> Result<(), String> {
    use std::io::Write;
    let data = std::fs::read(src).map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    let f = std::fs::File::create(dst).map_err(|e| format!("cannot create {}: {e}", dst.display()))?;
    let mut e = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    e.write_all(&data).and_then(|_| e.finish().map(|_| ())).map_err(|e| format!("compressing into {}: {e}", dst.display()))
}

/// Decompresses a file; the reason when it fails.
fn gunzip_file(src: &std::path::Path, dst: &std::path::Path) -> Result<(), String> {
    use std::io::Read;
    let f = std::fs::File::open(src).map_err(|e| format!("cannot open {}: {e}", src.display()))?;
    let mut v = Vec::new();
    flate2::read::GzDecoder::new(f).read_to_end(&mut v).map_err(|e| format!("decompressing {}: {e}", src.display()))?;
    std::fs::write(dst, v).map_err(|e| format!("cannot write {}: {e}", dst.display()))
}
