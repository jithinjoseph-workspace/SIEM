//! The `global` and `task` commands of wazuh_db/wdb_parser.c: the command
//! dispatch of the global actor (with its counters and timings), every
//! `wdb_parse_global_*` handler and the task manager JSON commands.

use siem_cjson::Json;

use super::global::*;
use super::parser::{near, CBuf, WDBC_RESULT};
use super::state::Tv;
use super::*;

type R = (i32, B);

/// `cJSON_IsString(j) ? j->valuestring : NULL`
fn str_of(j: Option<&Json>) -> Option<&[u8]> {
    match j {
        Some(Json::String(s)) => Some(cstr(s)),
        _ => None,
    }
}

fn is_number(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::Number { .. }))
}

fn is_string(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::String(_)))
}

fn is_bool(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::True | Json::False))
}

/// `valueint` of a number (0 otherwise, never read by the C then).
fn int_of(j: Option<&Json>) -> i32 {
    match j {
        Some(Json::Number { int, .. }) => *int,
        Some(Json::True) => 1,
        _ => 0,
    }
}

/// The error pointer of `cJSON_ParseWithOpts`.
fn json_err_at(input: &[u8], off: usize) -> &[u8] {
    cstr(&input[off.min(input.len())..])
}

impl Wdbd {
    /// The common "Cannot execute SQL query" error of the global handlers.
    fn global_sql_err(&self, wdb: &Wdb) -> R {
        let e = wdb.errmsg();
        self.mdebug1(&msg!("Global DB Cannot execute SQL query; err database ", WDB2_DIR, "/", WDB_GLOB_NAME, ".db: ", e));
        (OS_INVALID, out(msg!("err Cannot execute Global database query; ", e)))
    }

    /// `cJSON_ParseWithOpts(input, &error, TRUE)` with the handlers' error.
    fn global_json(&self, input: &[u8], m1: &str) -> Result<Json, R> {
        match siem_cjson::parse_with_opts(input, true) {
            Ok((j, _)) => Ok(j),
            Err(off) => {
                self.mdebug1(m1.as_bytes());
                self.mdebug2(&msg!("Global DB JSON error near: ", json_err_at(input, off)));
                Err((OS_INVALID, near("err Invalid JSON syntax", input)))
            }
        }
    }

    /// The command dispatch of the `global` actor.
    pub fn parse_global_command(&self, wdb: &mut Wdb, buf: &mut CBuf, q: &[u8], next: Option<usize>) -> R {
        let no_args = |d: &Self| -> R {
            d.mdebug1(&msg!("Global DB Invalid DB query syntax for ", q, "."));
            d.mdebug2(&msg!("Global DB query error near: ", q));
            (OS_INVALID, near("err Invalid DB query syntax", q))
        };
        macro_rules! timed {
            ($inc:ident, $time:ident, $body:expr) => {{
                self.state.$inc();
                match next {
                    None => no_args(self),
                    Some(n) => {
                        let b = self.tv();
                        let r = ($body)(n);
                        self.state.$time(Tv::diff(self.tv(), b));
                        r
                    }
                }
            }};
        }
        macro_rules! timed_opt {
            ($inc:ident, $time:ident, $body:expr) => {{
                self.state.$inc();
                let b = self.tv();
                let r = ($body)(next);
                self.state.$time(Tv::diff(self.tv(), b));
                r
            }};
        }
        match q {
            b"sql" => {
                self.state.w_inc_global_sql();
                match next {
                    None => {
                        self.mdebug1(b"Global DB Invalid DB query syntax.");
                        self.mdebug2(&msg!("Global DB query error near: ", q));
                        (OS_INVALID, near("err Invalid DB query syntax", q))
                    }
                    Some(n) => {
                        let sql = buf.owned(n);
                        let b = self.tv();
                        let data = self.exec(wdb.db(), &sql);
                        self.state.w_inc_global_sql_time(Tv::diff(self.tv(), b));
                        match data {
                            Some(d) => (0, out(msg!("ok ", d.print_unformatted()))),
                            None => {
                                let e = wdb.errmsg();
                                self.mdebug1(&msg!("Global DB Cannot execute SQL query; err database ", WDB2_DIR, "/", WDB_GLOB_NAME, ".db: ", e));
                                self.mdebug2(&msg!("Global DB SQL query: ", sql));
                                (OS_INVALID, out(msg!("err Cannot execute Global database query; ", e)))
                            }
                        }
                    }
                }
            }
            b"insert-agent" => timed!(w_inc_global_agent_insert_agent, w_inc_global_agent_insert_agent_time, |n| self
                .parse_global_insert_agent(wdb, buf.at(n))),
            b"update-agent-name" => timed!(w_inc_global_agent_update_agent_name, w_inc_global_agent_update_agent_name_time, |n| self
                .parse_global_update_agent_name(wdb, buf.at(n))),
            b"update-agent-data" => timed!(w_inc_global_agent_update_agent_data, w_inc_global_agent_update_agent_data_time, |n| self
                .parse_global_update_agent_data(wdb, buf.at(n))),
            b"get-labels" => timed!(w_inc_global_labels_get_labels, w_inc_global_labels_get_labels_time, |n| self
                .parse_global_get_agent_labels(wdb, buf.at(n))),
            b"update-keepalive" => timed!(w_inc_global_agent_update_keepalive, w_inc_global_agent_update_keepalive_time, |n| self
                .parse_global_update_agent_keepalive(wdb, buf.at(n))),
            b"update-connection-status" => timed!(
                w_inc_global_agent_update_connection_status,
                w_inc_global_agent_update_connection_status_time,
                |n| self.parse_global_update_connection_status(wdb, buf.at(n))
            ),
            b"update-status-code" => timed!(w_inc_global_agent_update_status_code, w_inc_global_agent_update_status_code_time, |n| self
                .parse_global_update_status_code(wdb, buf.at(n))),
            b"delete-agent" => timed!(w_inc_global_agent_delete_agent, w_inc_global_agent_delete_agent_time, |n| self
                .parse_global_delete_agent(wdb, buf.at(n))),
            b"select-agent-name" => timed!(w_inc_global_agent_select_agent_name, w_inc_global_agent_select_agent_name_time, |n| self
                .parse_global_select_agent_name(wdb, buf.at(n))),
            b"select-agent-group" => timed!(w_inc_global_agent_select_agent_group, w_inc_global_agent_select_agent_group_time, |n| self
                .parse_global_select_agent_group(wdb, buf.at(n))),
            b"find-agent" => timed!(w_inc_global_agent_find_agent, w_inc_global_agent_find_agent_time, |n| self
                .parse_global_find_agent(wdb, buf.at(n))),
            b"find-group" => timed!(w_inc_global_group_find_group, w_inc_global_group_find_group_time, |n| self
                .parse_global_find_group(wdb, buf.at(n))),
            b"insert-agent-group" => timed!(w_inc_global_group_insert_agent_group, w_inc_global_group_insert_agent_group_time, |n| self
                .parse_global_insert_agent_group(wdb, buf.at(n))),
            b"select-group-belong" => timed!(w_inc_global_belongs_select_group_belong, w_inc_global_belongs_select_group_belong_time, |n| self
                .parse_global_select_group_belong(wdb, buf.at(n))),
            b"get-group-agents" => timed!(w_inc_global_belongs_get_group_agent, w_inc_global_belongs_get_group_agent_time, |n| self
                .parse_global_get_group_agents(wdb, buf, n)),
            b"delete-group" => timed!(w_inc_global_group_delete_group, w_inc_global_group_delete_group_time, |n| self
                .parse_global_delete_group(wdb, buf.at(n))),
            b"select-groups" => timed_opt!(w_inc_global_group_select_groups, w_inc_global_group_select_groups_time, |_| self
                .parse_global_select_groups(wdb)),
            b"sync-agent-groups-get" => timed!(w_inc_global_agent_sync_agent_groups_get, w_inc_global_agent_sync_agent_groups_get_time, |n| self
                .parse_global_sync_agent_groups_get(wdb, buf.at(n))),
            b"set-agent-groups" => timed!(w_inc_global_agent_set_agent_groups, w_inc_global_agent_set_agent_groups_time, |n| self
                .parse_global_set_agent_groups(wdb, buf.at(n))),
            b"sync-agent-info-get" => timed_opt!(w_inc_global_agent_sync_agent_info_get, w_inc_global_agent_sync_agent_info_get_time, |n| self
                .parse_global_sync_agent_info_get(wdb, buf, n)),
            b"sync-agent-info-set" => timed!(w_inc_global_agent_sync_agent_info_set, w_inc_global_agent_sync_agent_info_set_time, |n| self
                .parse_global_sync_agent_info_set(wdb, buf.at(n))),
            b"get-groups-integrity" => timed!(w_inc_global_agent_get_groups_integrity, w_inc_global_agent_get_groups_integrity_time, |n| self
                .parse_get_groups_integrity(wdb, buf.at(n))),
            b"recalculate-agent-group-hashes" => timed_opt!(
                w_inc_global_agent_recalculate_agent_group_hashes,
                w_inc_global_agent_recalculate_agent_group_hashes_time,
                |_| self.parse_global_recalculate_agent_group_hashes(wdb)
            ),
            b"disconnect-agents" => timed!(w_inc_global_agent_disconnect_agents, w_inc_global_agent_disconnect_agents_time, |n| self
                .parse_global_disconnect_agents(wdb, buf, n)),
            b"get-all-agents" => timed!(w_inc_global_agent_get_all_agents, w_inc_global_agent_get_all_agents_time, |n| self
                .parse_global_get_all_agents(wdb, buf, n)),
            b"get-distinct-groups" => timed_opt!(w_inc_global_agent_get_distinct_groups, w_inc_global_agent_get_distinct_groups_time, |n: Option<usize>| {
                let input = n.map(|n| buf.owned(n));
                self.parse_global_get_distinct_agent_groups(wdb, input.as_deref())
            }),
            b"get-agent-info" => timed!(w_inc_global_agent_get_agent_info, w_inc_global_agent_get_agent_info_time, |n| self
                .parse_global_get_agent_info(wdb, buf.at(n))),
            b"reset-agents-connection" => timed!(w_inc_global_agent_reset_agents_connection, w_inc_global_agent_reset_agents_connection_time, |n| self
                .parse_reset_agents_connection(wdb, buf.at(n))),
            b"get-agents-by-connection-status" => timed!(
                w_inc_global_agent_get_agents_by_connection_status,
                w_inc_global_agent_get_agents_by_connection_status_time,
                |n| self.parse_global_get_agents_by_connection_status(wdb, buf, n)
            ),
            b"backup" => timed!(w_inc_global_backup, w_inc_global_backup_time, |n| self.parse_global_backup(wdb, buf, n)),
            b"vacuum" => {
                self.state.w_inc_global_vacuum();
                let b = self.tv();
                let r = self.vacuum_command(wdb, "Global DB");
                self.state.w_inc_global_vacuum_time(Tv::diff(self.tv(), b));
                r
            }
            b"get_fragmentation" => {
                self.state.w_inc_global_get_fragmentation();
                let b = self.tv();
                let r = self.fragmentation_command(wdb, "Global DB");
                self.state.w_inc_global_get_fragmentation_time(Tv::diff(self.tv(), b));
                r
            }
            b"sleep" => {
                self.state.w_inc_global_sleep();
                let b = self.tv();
                let r = self.sleep_command(buf, next, q, "Global DB");
                self.state.w_inc_global_sleep_time(Tv::diff(self.tv(), b));
                r
            }
            _ => {
                self.mdebug1(b"Invalid DB query syntax.");
                self.mdebug2(&msg!("Global DB query error near: ", q));
                (OS_INVALID, near("err Invalid DB query syntax", q))
            }
        }
    }

    /// `wdb_parse_global_insert_agent`
    fn parse_global_insert_agent(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let data = match self.global_json(input, "Global DB Invalid JSON syntax when inserting agent.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let j_id = data.get("id");
        let j_name = data.get("name");
        let j_date_add = data.get("date_add");
        // These are the only constraints defined in the database for this
        // set of parameters. All the other parameters could be NULL.
        if is_number(j_id) && is_string(j_name) && is_number(j_date_add) {
            let r = self.global_insert_agent(
                wdb,
                int_of(j_id),
                str_of(j_name),
                str_of(data.get("ip")),
                str_of(data.get("register_ip")),
                str_of(data.get("internal_key")),
                str_of(data.get("group")),
                int_of(j_date_add),
            );
            if r != OS_SUCCESS {
                return self.global_sql_err(wdb);
            }
        } else {
            self.mdebug1(b"Global DB Invalid JSON data when inserting agent. Not compliant with constraints defined in the database.");
            return (OS_INVALID, near("err Invalid JSON data", input));
        }
        self.group_hash_cache_clear();
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_update_agent_name`
    fn parse_global_update_agent_name(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let data = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent name.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let j_id = data.get("id");
        let j_name = data.get("name");
        if is_number(j_id) && is_string(j_name) {
            if self.global_update_agent_name(wdb, int_of(j_id), str_of(j_name)) != OS_SUCCESS {
                return self.global_sql_err(wdb);
            }
        } else {
            self.mdebug1(b"Global DB Invalid JSON data when updating agent name.");
            return (OS_INVALID, near("err Invalid JSON data", input));
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_update_agent_data`
    fn parse_global_update_agent_data(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let data = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent version.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let j_id = data.get("id");
        if !is_number(j_id) {
            self.mdebug1(b"Global DB Invalid JSON data when updating agent version.");
            return (OS_INVALID, near("err Invalid JSON data", input));
        }
        let id = int_of(j_id);
        let s = |k: &str| str_of(data.get(k));
        let f: [Option<&[u8]>; 14] = [
            s("os_name"),
            s("os_version"),
            s("os_major"),
            s("os_minor"),
            s("os_codename"),
            s("os_platform"),
            s("os_build"),
            s("os_uname"),
            s("os_arch"),
            s("version"),
            s("config_sum"),
            s("merged_sum"),
            s("manager_host"),
            s("node_name"),
        ];
        let sync_status = s("sync_status").unwrap_or(b"synced");
        let labels = s("labels");
        let validated = self.global_validate_sync_status(wdb, id, sync_status);
        if self.global_update_agent_version(wdb, id, &f, s("agent_ip"), s("connection_status"), Some(&validated), s("group_config_status")) != OS_SUCCESS {
            return self.global_sql_err(wdb);
        }
        // The labels are replaced only when the agent was updated; NULL
        // labels remove the current ones.
        let mut labels_data = Some(trunc(id.to_string().into_bytes(), OS_MAXSTR - 1));
        if let Some(l) = labels {
            wm_strcat(&mut labels_data, l, b' ');
        }
        let mut lb = CBuf::new(&labels_data.unwrap_or_default());
        self.parse_global_set_agent_labels(wdb, &mut lb, 0)
    }

    /// `wdb_parse_global_get_agent_labels`
    fn parse_global_get_agent_labels(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        match self.global_get_agent_labels(wdb, atoi(input)) {
            None => {
                self.mdebug1(b"Error getting agent labels from global.db.");
                (OS_INVALID, out(b"err Error getting agent labels from global.db.".to_vec()))
            }
            Some(l) => (OS_SUCCESS, out(msg!("ok ", l.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_set_agent_labels`
    fn parse_global_set_agent_labels(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut saved = 0;
        // "agent_id key1:value1\nkey2:value2" or "agent_id"
        let Some(id) = buf.strtok(Some(input), &mut saved, b" ") else {
            self.mdebug1(b"Invalid DB query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(input)));
            return (OS_INVALID, near("err Invalid DB query syntax", buf.at(input)));
        };
        let agent_id = atoi(buf.at(id));
        if self.global_del_agent_labels(wdb, agent_id) != OS_SUCCESS {
            return self.global_sql_err(wdb);
        }
        while let Some(label) = buf.strtok(None, &mut saved, b"\n") {
            let Some(colon) = buf.chr(label, b':') else {
                continue;
            };
            buf.nul(colon);
            let key = buf.owned(label);
            let value = buf.owned(colon + 1);
            if self.global_set_agent_label(wdb, agent_id, &key, &value) != OS_SUCCESS {
                return self.global_sql_err(wdb);
            }
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_update_agent_keepalive`
    fn parse_global_update_agent_keepalive(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let data = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent keepalive.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let j_id = data.get("id");
        let j_conn = data.get("connection_status");
        let j_sync = data.get("sync_status");
        if is_number(j_id) && is_string(j_conn) && is_string(j_sync) {
            let id = int_of(j_id);
            let validated = self.global_validate_sync_status(wdb, id, str_of(j_sync).unwrap_or_default());
            if self.global_update_agent_keepalive(wdb, id, str_of(j_conn), Some(&validated)) != OS_SUCCESS {
                return self.global_sql_err(wdb);
            }
        } else {
            self.mdebug1(b"Global DB Invalid JSON data when updating agent keepalive.");
            return (OS_INVALID, near("err Invalid JSON data", input));
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_update_connection_status`
    fn parse_global_update_connection_status(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let data = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent connection status.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let j_id = data.get("id");
        let j_conn = data.get("connection_status");
        let j_sync = data.get("sync_status");
        let j_code = data.get("status_code");
        if is_number(j_id) && is_string(j_conn) && is_string(j_sync) && is_number(j_code) {
            let id = int_of(j_id);
            let validated = self.global_validate_sync_status(wdb, id, str_of(j_sync).unwrap_or_default());
            let conn = str_of(j_conn).unwrap_or_default();
            if self.global_update_agent_connection_status(wdb, id, conn, Some(&validated), int_of(j_code)) != OS_SUCCESS {
                return self.global_sql_err(wdb);
            }
        } else {
            self.mdebug1(b"Global DB Invalid JSON data when updating agent connection status.");
            return (OS_INVALID, near("err Invalid JSON data", input));
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_update_status_code`
    fn parse_global_update_status_code(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let data = match self.global_json(input, "Global DB Invalid JSON syntax when updating agent status code.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let j_id = data.get("id");
        let j_code = data.get("status_code");
        let j_version = data.get("version");
        let j_sync = data.get("sync_status");
        if is_number(j_id) && is_number(j_code) && (j_version.is_none() || is_string(j_version)) && is_string(j_sync) {
            let id = int_of(j_id);
            let validated = self.global_validate_sync_status(wdb, id, str_of(j_sync).unwrap_or_default());
            if self.global_update_agent_status_code(wdb, id, int_of(j_code), str_of(j_version), Some(&validated)) != OS_SUCCESS {
                return self.global_sql_err(wdb);
            }
        } else {
            self.mdebug1(b"Global DB Invalid JSON data when updating agent status code.");
            return (OS_INVALID, near("err Invalid JSON data", input));
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_delete_agent`
    fn parse_global_delete_agent(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let agent_id = atoi(input);
        let padded = format!("{agent_id:03}");
        if self.global_delete_agent(wdb, agent_id) != OS_SUCCESS {
            self.mdebug1(b"Error deleting agent from agent table in global.db.");
            return (OS_INVALID, out(b"err Error deleting agent from agent table in global.db.".to_vec()));
        }
        if self.router_agent {
            let mut info = Json::object();
            info.add("agent_id", Json::string(&padded));
            let mut m = Json::object();
            m.add("agent_info", info);
            m.add("action", Json::string("deleteAgent"));
            self.env.router_send(1, &m.print_unformatted());
        }
        self.group_hash_cache_clear();
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_select_agent_name`
    fn parse_global_select_agent_name(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        match self.global_select_agent_name(wdb, atoi(input)) {
            None => {
                self.mdebug1(b"Error getting agent name from global.db.");
                (OS_INVALID, out(b"err Error getting agent name from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_select_agent_group`
    fn parse_global_select_agent_group(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        match self.global_select_agent_group(wdb, atoi(input)) {
            None => {
                self.mdebug1(b"Error getting agent group from global.db.");
                (OS_INVALID, out(b"err Error getting agent group from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_find_agent`
    fn parse_global_find_agent(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let data = match self.global_json(input, "Global DB Invalid JSON syntax when finding agent id.") {
            Ok(d) => d,
            Err(r) => return r,
        };
        let j_name = data.get("name");
        let j_ip = data.get("ip");
        if !(is_string(j_name) && is_string(j_ip)) {
            self.mdebug1(b"Global DB Invalid JSON data when finding agent id.");
            return (OS_INVALID, near("err Invalid JSON data", input));
        }
        match self.global_find_agent(wdb, str_of(j_name), str_of(j_ip)) {
            None => self.global_sql_err(wdb),
            Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_find_group`
    fn parse_global_find_group(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        match self.global_find_group(wdb, Some(input)) {
            None => {
                self.mdebug1(b"Error getting group id from global.db.");
                (OS_INVALID, out(b"err Error getting group id from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_insert_agent_group`
    fn parse_global_insert_agent_group(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        if self.global_insert_agent_group(wdb, input) != OS_SUCCESS {
            self.mdebug1(b"Error inserting group in global.db.");
            return (OS_INVALID, out(b"err Error inserting group in global.db.".to_vec()));
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_select_group_belong`
    fn parse_global_select_group_belong(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        match self.global_select_group_belong(wdb, atoi(input)) {
            None => {
                self.mdebug1(b"Error getting agent groups information from global.db.");
                (OS_INVALID, out(b"err Error getting agent groups information from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_get_group_agents`
    fn parse_global_get_group_agents(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut saved = 0;
        let Some(group) = buf.strtok(Some(input), &mut saved, b" ") else {
            self.mdebug1(b"Invalid arguments, group name not found.");
            return (OS_INVALID, out(b"err Invalid arguments, group name not found.".to_vec()));
        };
        match buf.strtok(None, &mut saved, b" ") {
            Some(t) if buf.eq(t, "last_id") => {}
            _ => {
                self.mdebug1(b"Invalid arguments, 'last_id' not found.");
                return (OS_INVALID, out(b"err Invalid arguments, 'last_id' not found.".to_vec()));
            }
        }
        let Some(last) = buf.strtok(None, &mut saved, b" ") else {
            self.mdebug1(b"Invalid arguments, last agent id not found.");
            return (OS_INVALID, out(b"err Invalid arguments, last agent id not found.".to_vec()));
        };
        let last_agent_id = atoi(buf.at(last));
        let group = buf.owned(group);
        let mut status = WDBC_UNKNOWN;
        match self.global_get_group_agents(wdb, &mut status, &group, last_agent_id) {
            None => {
                self.mdebug1(b"Error getting group agents from global.db.");
                (OS_INVALID, out(b"err Error getting group agents from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!(WDBC_RESULT[status as usize], " ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_delete_group`
    fn parse_global_delete_group(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        if self.global_delete_group(wdb, input) != OS_SUCCESS {
            self.mdebug1(b"Error deleting group in global.db.");
            return (OS_INVALID, out(b"err Error deleting group in global.db.".to_vec()));
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_select_groups`
    fn parse_global_select_groups(&self, wdb: &mut Wdb) -> R {
        match self.global_select_groups(wdb) {
            None => {
                self.mdebug1(b"Error getting groups from global.db.");
                (OS_INVALID, out(b"err Error getting groups from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_set_agent_groups`
    fn parse_global_set_agent_groups(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let args = match siem_cjson::parse_with_opts(input, true) {
            Ok((j, _)) => j,
            Err(off) => {
                self.mdebug1(b"Global DB Invalid JSON syntax when parsing set_agent_groups");
                self.mdebug2(&msg!("Global DB JSON error near: ", json_err_at(input, off)));
                return (OS_INVALID, near("err Invalid JSON syntax", input));
            }
        };
        let j_mode = args.get("mode");
        let j_sync = args.get("sync_status");
        let j_data = args.get("data");
        let (Some(data @ Json::Array(_)), Some(mode_s)) = (j_data, str_of(j_mode)) else {
            self.mdebug1(b"Missing mandatory fields in set_agent_groups command.");
            return (OS_INVALID, out(b"err Invalid JSON data, missing required fields".to_vec()));
        };
        let mode = match mode_s {
            b"override" => WDB_GROUP_OVERRIDE,
            b"append" => WDB_GROUP_APPEND,
            b"empty_only" => WDB_GROUP_EMPTY_ONLY,
            b"remove" => WDB_GROUP_REMOVE,
            _ => WDB_GROUP_INVALID_MODE,
        };
        if mode == WDB_GROUP_INVALID_MODE {
            self.mdebug1(&msg!("Invalid mode '", mode_s, "' in set_agent_groups command."));
            return (OS_INVALID, out(msg!("err Invalid mode '", mode_s, "' in set_agent_groups command")));
        }
        let sync_status = str_of(j_sync).unwrap_or(b"synced");
        let status = self.global_set_agent_groups(wdb, mode, Some(sync_status), data);
        if status == WDBC_OK {
            (OS_SUCCESS, out(WDBC_RESULT[status as usize].as_bytes().to_vec()))
        } else {
            (OS_INVALID, out(msg!(WDBC_RESULT[status as usize], " An error occurred during the set of the groups")))
        }
    }

    /// `wdb_parse_global_sync_agent_groups_get`
    fn parse_global_sync_agent_groups_get(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let args = match siem_cjson::parse_with_opts(input, true) {
            Ok((j, _)) => j,
            Err(off) => {
                self.mdebug1(b"Global DB Invalid JSON syntax when parsing sync-agent-groups-get");
                self.mdebug2(&msg!("Global DB JSON error near: ", json_err_at(input, off)));
                return (OS_INVALID, near("err Invalid JSON syntax", input));
            }
        };
        let j_cond = args.get("condition");
        let j_last_id = args.get("last_id");
        let j_set_synced = args.get("set_synced");
        let j_get_hash = args.get("get_global_hash");
        let j_delta = args.get("agent_registration_delta");
        // The data types of the alternative parameters, when present
        if (j_cond.is_some() && !is_string(j_cond))
            || (j_last_id.is_some() && (!is_number(j_last_id) || int_of(j_last_id) < 0))
            || (j_set_synced.is_some() && !is_bool(j_set_synced))
            || (j_get_hash.is_some() && !is_bool(j_get_hash))
            || (j_delta.is_some() && (!is_number(j_delta) || int_of(j_delta) < 0))
        {
            self.mdebug1(b"Invalid alternative fields data in sync-agent-groups-get command.");
            return (OS_INVALID, out(b"err Invalid JSON data, invalid alternative fields data".to_vec()));
        }
        let condition = match str_of(j_cond) {
            Some(b"sync_status") => WDB_GROUP_SYNC_STATUS,
            Some(b"all") => WDB_GROUP_ALL,
            Some(_) => WDB_GROUP_INVALID_CONDITION,
            None => WDB_GROUP_NO_CONDITION,
        };
        let last_id = if j_last_id.is_some() { int_of(j_last_id) } else { 0 };
        let set_synced = matches!(j_set_synced, Some(Json::True));
        let get_hash = matches!(j_get_hash, Some(Json::True));
        let delta = if j_delta.is_some() { int_of(j_delta) } else { 0 };
        let (status, sync) = self.global_sync_agent_groups_get(wdb, condition, last_id, set_synced, get_hash, delta);
        match sync {
            Some(j) => {
                let response = j.print_unformatted();
                if response.len() <= WDB_MAX_RESPONSE_SIZE {
                    (OS_SUCCESS, out(msg!(WDBC_RESULT[status as usize], " ", response)))
                } else {
                    (OS_INVALID, out(b"err Invalid response from wdb_global_sync_agent_groups_get".to_vec()))
                }
            }
            None => (OS_INVALID, out(b"err Could not obtain a response from wdb_global_sync_agent_groups_get".to_vec())),
        }
    }

    /// `wdb_parse_global_sync_agent_info_get`
    fn parse_global_sync_agent_info_get(&self, wdb: &mut Wdb, buf: &mut CBuf, input: Option<usize>) -> R {
        let mut last_id = self.sync_last_id.lock();
        if let Some(input) = input {
            if let Some(sp) = buf.wchr(input, b' ') {
                buf.nul(sp);
                if buf.eq(input, "last_id") {
                    *last_id = atoi(buf.at(sp + 1));
                }
            }
        }
        let (status, info) = self.global_sync_agent_info_get(wdb, &mut last_id);
        let o = out(msg!(WDBC_RESULT[status as usize], " ", info));
        if status != WDBC_DUE {
            *last_id = 0;
        }
        (OS_SUCCESS, o)
    }

    /// `wdb_parse_global_sync_agent_info_set`
    fn parse_global_sync_agent_info_set(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        let root = match siem_cjson::parse_with_opts(input, true) {
            Ok((j, _)) => j,
            Err(off) => {
                self.mdebug1(b"Global DB Invalid JSON syntax updating unsynced agents.");
                self.mdebug2(&msg!("Global DB JSON error near: ", json_err_at(input, off)));
                return (OS_INVALID, near("err Invalid JSON syntax", input));
            }
        };
        for agent in root.children() {
            if self.global_sync_agent_info_set(wdb, agent) != OS_SUCCESS {
                return self.global_sql_err(wdb);
            }
            let labels = agent.get("labels");
            let Some(labels @ Json::Array(_)) = labels else {
                continue;
            };
            let j_id = agent.get("id");
            let agent_id = if is_number(j_id) { int_of(j_id) } else { OS_INVALID };
            if agent_id == OS_INVALID {
                self.mdebug1(b"Global DB Cannot execute SQL query; incorrect agent id in labels array.");
                return (OS_INVALID, out(b"err Cannot update labels due to invalid id.".to_vec()));
            } else if self.global_del_agent_labels(wdb, agent_id) != OS_SUCCESS {
                return self.global_sql_err(wdb);
            }
            for label in labels.children() {
                let key = label.get("key");
                let value = label.get("value");
                let id = label.get("id");
                if is_string(key) && is_string(value) && is_number(id) {
                    let (k, v) = (str_of(key).unwrap_or_default(), str_of(value).unwrap_or_default());
                    if self.global_set_agent_label(wdb, int_of(id), k, v) != OS_SUCCESS {
                        return self.global_sql_err(wdb);
                    }
                }
            }
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_get_groups_integrity`
    fn parse_get_groups_integrity(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        const OS_SHA1_HEXDIGEST_SIZE: usize = 40;
        let input_len = input.len() as i32;
        if input.len() < OS_SHA1_HEXDIGEST_SIZE {
            self.mdebug1(&msg!("Hash hex-digest does not have the expected length. Expected (", OS_SHA1_HEXDIGEST_SIZE, ") got (", input_len, ")"));
            return (
                OS_INVALID,
                out(msg!("err Hash hex-digest does not have the expected length. Expected (", OS_SHA1_HEXDIGEST_SIZE, ") got (", input_len, ")")),
            );
        }
        let hash = &input[..OS_SHA1_HEXDIGEST_SIZE];
        match self.global_get_groups_integrity(wdb, hash) {
            None => {
                self.mdebug1(b"Error getting groups integrity information from global.db.");
                (OS_INVALID, out(b"err Error getting groups integrity information from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_recalculate_agent_group_hashes`
    fn parse_global_recalculate_agent_group_hashes(&self, wdb: &mut Wdb) -> R {
        if self.global_recalculate_all_agent_groups_hash(wdb) != OS_SUCCESS {
            self.mwarn(b"Error recalculating group hash of agents in global.db.");
            return (OS_INVALID, out(b"err Error recalculating group hash of agents in global.db".to_vec()));
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_get_agent_info`
    fn parse_global_get_agent_info(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        match self.global_get_agent_info(wdb, atoi(input)) {
            None => {
                self.mdebug1(b"Error getting agent information from global.db.");
                (OS_INVALID, out(b"err Error getting agent information from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_get_agents_by_connection_status`
    fn parse_global_get_agents_by_connection_status(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut saved = 0;
        let Some(t) = buf.strtok(Some(input), &mut saved, b" ") else {
            self.mdebug1(b"Invalid arguments 'last_id' not found.");
            return (OS_INVALID, out(b"err Invalid arguments 'last_id' not found".to_vec()));
        };
        let last_id = atoi(buf.at(t));
        let Some(conn) = buf.strtok(None, &mut saved, b" ") else {
            self.mdebug1(b"Invalid arguments 'connection_status' not found.");
            return (OS_INVALID, out(b"err Invalid arguments 'connection_status' not found".to_vec()));
        };
        let mut node_name = None;
        let mut limit = 0;
        if let Some(node) = buf.strtok(None, &mut saved, b" ") {
            node_name = Some(buf.owned(node));
            let Some(l) = buf.strtok(None, &mut saved, b" ") else {
                self.mdebug1(b"Invalid arguments 'limit' not found.");
                return (OS_INVALID, out(b"err Invalid arguments 'limit' not found".to_vec()));
            };
            limit = atoi(buf.at(l));
        }
        let conn = buf.owned(conn);
        let mut status = WDBC_UNKNOWN;
        match self.global_get_agents_by_connection_status(wdb, last_id, &conn, node_name.as_deref(), limit, &mut status) {
            None => {
                self.mdebug1(b"Error getting agents by connection status from global.db.");
                (OS_INVALID, out(b"err Error getting agents by connection status from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!(WDBC_RESULT[status as usize], " ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_get_all_agents`
    fn parse_global_get_all_agents(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut saved = 0;
        let first = buf.strtok(Some(input), &mut saved, b" ");
        let Some(first) = first.filter(|&t| buf.eq(t, "last_id") || buf.eq(t, "context")) else {
            self.mdebug1(b"Invalid arguments 'last_id' or 'context' not found.");
            return (OS_INVALID, out(b"err Invalid arguments 'last_id' or 'context' not found".to_vec()));
        };
        if buf.eq(first, "context") {
            let status = self.global_get_all_agents_context(wdb);
            if status != OS_SUCCESS {
                return (status, out(b"err Error getting agents from global.db.".to_vec()));
            }
            return (status, out(b"ok []".to_vec()));
        }
        let Some(t) = buf.strtok(None, &mut saved, b" ") else {
            self.mdebug1(b"Invalid arguments 'last_id' not found.");
            return (OS_INVALID, out(b"err Invalid arguments 'last_id' not found".to_vec()));
        };
        let last_id = atoi(buf.at(t));
        let mut status = WDBC_UNKNOWN;
        match self.global_get_all_agents(wdb, last_id, &mut status) {
            None => {
                self.mdebug1(b"Error getting agents from global.db.");
                (OS_INVALID, out(b"err Error getting agents from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!(WDBC_RESULT[status as usize], " ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_get_distinct_agent_groups`
    fn parse_global_get_distinct_agent_groups(&self, wdb: &mut Wdb, input: Option<&[u8]>) -> R {
        let mut status = WDBC_UNKNOWN;
        match self.global_get_distinct_agent_groups(wdb, input, &mut status) {
            None => {
                self.mdebug1(b"Error getting agent groups from global.db.");
                (OS_INVALID, out(b"err Error getting agent groups from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!(WDBC_RESULT[status as usize], " ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_reset_agents_connection`
    fn parse_reset_agents_connection(&self, wdb: &mut Wdb, input: &[u8]) -> R {
        if self.global_reset_agents_connection(wdb, Some(input)) != OS_SUCCESS {
            return self.global_sql_err(wdb);
        }
        (OS_SUCCESS, out(b"ok".to_vec()))
    }

    /// `wdb_parse_global_disconnect_agents`
    fn parse_global_disconnect_agents(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut saved = 0;
        let Some(t) = buf.strtok(Some(input), &mut saved, b" ") else {
            self.mdebug1(b"Invalid arguments last id not found.");
            return (OS_INVALID, out(b"err Invalid arguments last id not found".to_vec()));
        };
        let last_id = atoi(buf.at(t));
        let Some(t) = buf.strtok(None, &mut saved, b" ") else {
            self.mdebug1(b"Invalid arguments keepalive not found.");
            return (OS_INVALID, out(b"err Invalid arguments keepalive not found".to_vec()));
        };
        let keep_alive = atoi(buf.at(t));
        let Some(t) = buf.strtok(None, &mut saved, b" ") else {
            self.mdebug1(b"Invalid arguments sync_status not found.");
            return (OS_INVALID, out(b"err Invalid arguments sync_status not found".to_vec()));
        };
        let sync_status = buf.owned(t);
        let mut status = WDBC_UNKNOWN;
        match self.global_get_agents_to_disconnect(wdb, last_id, keep_alive, Some(&sync_status), &mut status) {
            None => {
                self.mdebug1(b"Error getting agents to be disconnected from global.db.");
                (OS_INVALID, out(b"err Error getting agents to be disconnected from global.db.".to_vec()))
            }
            Some(j) => (OS_SUCCESS, out(msg!(WDBC_RESULT[status as usize], " ", j.print_unformatted()))),
        }
    }

    /// `wdb_parse_global_backup`
    fn parse_global_backup(&self, wdb: &mut Wdb, buf: &mut CBuf, input: usize) -> R {
        let mut tail = 0;
        let mut output: B = Vec::new();
        let Some(action) = buf.strtok(Some(input), &mut tail, b" ") else {
            return (OS_INVALID, out(b"err Missing backup action".to_vec()));
        };
        if buf.eq(action, "create") {
            let result = self.global_create_backup(wdb, &mut output, None);
            if result != OS_SUCCESS {
                self.merror(&msg!("Creating Global DB snapshot on demand failed: ", cstr(&output)));
            }
            (result, output)
        } else if buf.eq(action, "get") {
            match self.global_get_backups() {
                Some(j) => (OS_SUCCESS, out(msg!("ok ", j.print_unformatted()))),
                None => (OS_INVALID, out(msg!("err Cannot execute backup get command, unable to open '", WDB_BACKUP_FOLDER, "' folder"))),
            }
        } else if buf.eq(action, "restore") {
            // wdb_parse_global_restore_backup
            let input = buf.owned(tail);
            let params = siem_cjson::parse_with_opts(&input, true);
            if let Err(off) = params {
                if !input.is_empty() {
                    self.mdebug1(b"Invalid backup JSON syntax when restoring snapshot.");
                    self.mdebug2(&msg!("JSON error near: ", json_err_at(&input, off)));
                    return (OS_INVALID, near("err Invalid JSON syntax", &input));
                }
            }
            let params = params.ok().map(|(j, _)| j);
            let snapshot = params.as_ref().and_then(|p| str_of(p.get("snapshot"))).map(|s| s.to_vec());
            let save = params.as_ref().map(|p| p.get("save_pre_restore_state"));
            let save_pre_restore_state = match save {
                Some(j) if is_bool(j) => int_of(j) != 0,
                _ => false,
            };
            let result = self.global_restore_backup(wdb, snapshot.as_deref(), save_pre_restore_state, &mut output);
            (result, output)
        } else {
            (OS_INVALID, out(msg!("err Invalid backup action: ", buf.at(action))))
        }
    }

    /// The command dispatch of the `task` actor.
    pub fn parse_task_command(&self, wdb: &mut Wdb, buf: &mut CBuf, q: &[u8], next: usize) -> R {
        macro_rules! task {
            ($inc:ident, $time:ident, $body:expr) => {{
                self.state.$inc();
                let n = buf.owned(next);
                match siem_cjson::parse_with_opts(&n, false) {
                    Err(_) => (OS_INVALID, near("err Invalid command parameters", &n)),
                    Ok((params, _)) => {
                        let b = self.tv();
                        let r = ($body)(&params);
                        self.state.$time(Tv::diff(self.tv(), b));
                        r
                    }
                }
            }};
        }
        match q {
            b"upgrade" => task!(w_inc_task_upgrade, w_inc_task_upgrade_time, |p: &Json| self.parse_task_upgrade(wdb, p, b"upgrade")),
            b"upgrade_custom" => task!(w_inc_task_upgrade_custom, w_inc_task_upgrade_custom_time, |p: &Json| self
                .parse_task_upgrade(wdb, p, b"upgrade_custom")),
            b"upgrade_get_status" => task!(w_inc_task_upgrade_get_status, w_inc_task_upgrade_get_status_time, |p: &Json| self
                .parse_task_upgrade_get_status(wdb, p)),
            b"upgrade_update_status" => task!(w_inc_task_upgrade_update_status, w_inc_task_upgrade_update_status_time, |p: &Json| self
                .parse_task_upgrade_update_status(wdb, p)),
            b"upgrade_result" => task!(w_inc_task_upgrade_result, w_inc_task_upgrade_result_time, |p: &Json| self
                .parse_task_upgrade_result(wdb, p)),
            b"upgrade_cancel_tasks" => task!(w_inc_task_upgrade_cancel_tasks, w_inc_task_upgrade_cancel_tasks_time, |p: &Json| self
                .parse_task_upgrade_cancel_tasks(wdb, p)),
            b"set_timeout" => task!(w_inc_task_set_timeout, w_inc_task_set_timeout_time, |p: &Json| self.parse_task_set_timeout(wdb, p)),
            b"delete_old" => task!(w_inc_task_delete_old, w_inc_task_delete_old_time, |p: &Json| self.parse_task_delete_old(wdb, p)),
            b"sql" => {
                self.state.w_inc_task_sql();
                let sql = buf.owned(next);
                let b = self.tv();
                let data = self.exec(wdb.db(), &sql);
                self.state.w_inc_task_sql_time(Tv::diff(self.tv(), b));
                match data {
                    Some(d) => (0, out(msg!("ok ", d.print_unformatted()))),
                    None => {
                        let e = wdb.errmsg();
                        self.mdebug1(&msg!("Tasks DB Cannot execute SQL query; err database ", WDB_TASK_DIR, "/", WDB_TASK_NAME, ".db: ", e));
                        self.mdebug2(&msg!("Tasks DB SQL query: ", sql));
                        (OS_INVALID, out(msg!("err Cannot execute Tasks database query; ", e)))
                    }
                }
            }
            _ => {
                self.mdebug1(b"Invalid DB query syntax.");
                self.mdebug2(&msg!("Task DB query error near: ", q));
                (OS_INVALID, near("err Invalid DB query syntax", q))
            }
        }
    }

    /// `wdb_parse_task_upgrade`
    fn parse_task_upgrade(&self, wdb: &mut Wdb, p: &Json, command: &[u8]) -> R {
        let Some(Json::Number { int: agent_id, .. }) = p.get("agent") else {
            return (OS_INVALID, out(b"err Error insert task: 'parsing agent error'".to_vec()));
        };
        let Some(node) = str_of(p.get("node")) else {
            return (OS_INVALID, out(b"err Error insert task: 'parsing node error'".to_vec()));
        };
        let Some(module) = str_of(p.get("module")) else {
            return (OS_INVALID, out(b"err Error insert task: 'parsing module error'".to_vec()));
        };
        let mut result = self.task_insert_task(wdb, *agent_id, node, module, command);
        let mut response = Json::object();
        if result >= 0 {
            response.add("error", Json::number(OS_SUCCESS as f64));
            response.add("task_id", Json::number(result as f64));
            result = OS_SUCCESS;
        } else {
            response.add("error", Json::number(result as f64));
        }
        (result, out(msg!("ok ", response.print_unformatted())))
    }

    /// `wdb_parse_task_upgrade_get_status`
    fn parse_task_upgrade_get_status(&self, wdb: &mut Wdb, p: &Json) -> R {
        let Some(Json::Number { int: agent_id, .. }) = p.get("agent") else {
            return (OS_INVALID, out(b"err Error get upgrade task status: 'parsing agent error'".to_vec()));
        };
        let Some(node) = str_of(p.get("node")) else {
            return (OS_INVALID, out(b"err Error get upgrade task status: 'parsing node error'".to_vec()));
        };
        let mut status = None;
        let result = self.task_get_upgrade_task_status(wdb, *agent_id, node, &mut status);
        let mut response = Json::object();
        response.add("error", Json::number(result as f64));
        if result == OS_SUCCESS {
            // cJSON_AddStringToObject with a NULL string adds nothing
            if let Some(s) = status {
                response.add("status", Json::string(cstr(&s)));
            }
        }
        (result, out(msg!("ok ", response.print_unformatted())))
    }

    /// `wdb_parse_task_upgrade_update_status`
    fn parse_task_upgrade_update_status(&self, wdb: &mut Wdb, p: &Json) -> R {
        let Some(Json::Number { int: agent_id, .. }) = p.get("agent") else {
            return (OS_INVALID, out(b"err Error upgrade update status task: 'parsing agent error'".to_vec()));
        };
        let Some(node) = str_of(p.get("node")) else {
            return (OS_INVALID, out(b"err Error upgrade update status task: 'parsing node error'".to_vec()));
        };
        let Some(status) = str_of(p.get("status")) else {
            return (OS_INVALID, out(b"err Error upgrade update status task: 'parsing status error'".to_vec()));
        };
        let error = str_of(p.get("error_msg"));
        let result = self.task_update_upgrade_task_status(wdb, *agent_id, node, status, error);
        let mut response = Json::object();
        response.add("error", Json::number(result as f64));
        (result, out(msg!("ok ", response.print_unformatted())))
    }

    /// `wdb_parse_task_upgrade_result`
    fn parse_task_upgrade_result(&self, wdb: &mut Wdb, p: &Json) -> R {
        let Some(Json::Number { int: agent_id, .. }) = p.get("agent") else {
            return (OS_INVALID, out(b"err Error upgrade result task: 'parsing agent error'".to_vec()));
        };
        let (mut result, row) = self.task_get_upgrade_task_by_agent_id(wdb, *agent_id);
        let mut response = Json::object();
        match row {
            Some(row) if result >= 0 => {
                response.add("error", Json::number(OS_SUCCESS as f64));
                response.add("task_id", Json::number(result as f64));
                // cJSON_AddStringToObject with a NULL string adds nothing
                for (k, v) in [
                    ("node", &row.node),
                    ("module", &row.module),
                    ("command", &row.command),
                    ("status", &row.status),
                    ("error_msg", &row.error),
                ] {
                    if let Some(v) = v {
                        response.add(k, Json::string(cstr(v)));
                    }
                }
                response.add("create_time", Json::number(row.create_time as f64));
                response.add("update_time", Json::number(row.last_update_time as f64));
                result = OS_SUCCESS;
            }
            _ => {
                response.add("error", Json::number(result as f64));
            }
        }
        (result, out(msg!("ok ", response.print_unformatted())))
    }

    /// `wdb_parse_task_upgrade_cancel_tasks`
    fn parse_task_upgrade_cancel_tasks(&self, wdb: &mut Wdb, p: &Json) -> R {
        let Some(node) = str_of(p.get("node")) else {
            return (OS_INVALID, out(b"err Error upgrade cancel task: 'parsing node error'".to_vec()));
        };
        let result = self.task_cancel_upgrade_tasks(wdb, node);
        let mut response = Json::object();
        response.add("error", Json::number(result as f64));
        (result, out(msg!("ok ", response.print_unformatted())))
    }

    /// `wdb_parse_task_set_timeout`
    fn parse_task_set_timeout(&self, wdb: &mut Wdb, p: &Json) -> R {
        let Some(Json::Number { int: now, .. }) = p.get("now") else {
            return (OS_INVALID, out(b"err Error set timeout task: 'parsing now error'".to_vec()));
        };
        let Some(Json::Number { int: interval, .. }) = p.get("interval") else {
            return (OS_INVALID, out(b"err Error set timeout task: 'parsing interval error'".to_vec()));
        };
        let mut next_timeout = now.wrapping_add(*interval) as i64;
        let result = self.task_set_timeout_status(wdb, *now as i64, *interval, &mut next_timeout);
        let mut response = Json::object();
        response.add("error", Json::number(result as f64));
        if result == OS_SUCCESS {
            response.add("timestamp", Json::number(next_timeout as f64));
        }
        (result, out(msg!("ok ", response.print_unformatted())))
    }

    /// `wdb_parse_task_delete_old`
    fn parse_task_delete_old(&self, wdb: &mut Wdb, p: &Json) -> R {
        let Some(Json::Number { int: timestamp, .. }) = p.get("timestamp") else {
            return (OS_INVALID, out(b"err Error delete old task: 'parsing timestamp error'".to_vec()));
        };
        let result = self.task_delete_old_entries(wdb, *timestamp);
        let mut response = Json::object();
        response.add("error", Json::number(result as f64));
        (result, out(msg!("ok ", response.print_unformatted())))
    }
}
