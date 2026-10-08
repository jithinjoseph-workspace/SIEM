//! The query parser (wazuh_db/wdb_parser.c, `wdb_parse`): the actor and
//! command dispatch with the usage counters and timings. The per-domain
//! parsers live in parser_agent.rs and parser_global.rs.
//!
//! The C parses the request in place (cutting it with NULs). [`CBuf`]
//! emulates that buffer so every `strchr` / `strtok_r` / "`*next++ = '\0'`"
//! keeps its exact effect, including the cases where the C reads past a
//! field it has already cut.

use siem_cjson::Json;

use super::state::Tv;
use super::*;

/// The request buffer: the bytes, a NUL and zero padding (the daemon's
/// buffer holds older requests there; zeros read as the end of string).
pub struct CBuf {
    pub b: Vec<u8>,
}

impl CBuf {
    pub fn new(s: &[u8]) -> CBuf {
        let mut b = cstr(s).to_vec();
        b.extend(std::iter::repeat_n(0u8, 64));
        CBuf { b }
    }

    fn ensure(&mut self, i: usize) {
        if i >= self.b.len() {
            self.b.resize(i + 64, 0);
        }
    }

    /// The C string at `i`.
    pub fn at(&self, i: usize) -> &[u8] {
        if i >= self.b.len() {
            return b"";
        }
        cstr(&self.b[i..])
    }

    pub fn owned(&self, i: usize) -> B {
        self.at(i).to_vec()
    }

    /// `strchr(at(i), c)`
    pub fn chr(&self, i: usize, c: u8) -> Option<usize> {
        self.at(i).iter().position(|&x| x == c).map(|p| i + p)
    }

    /// `wstr_chr(at(i), c)`
    pub fn wchr(&self, i: usize, c: u8) -> Option<usize> {
        wstr_chr(self.at(i), c).map(|p| i + p)
    }

    /// `*p = '\0'`
    pub fn nul(&mut self, i: usize) {
        self.ensure(i);
        self.b[i] = 0;
    }

    /// `strcmp(at(i), s) == 0`
    pub fn eq(&self, i: usize, s: &str) -> bool {
        self.at(i) == s.as_bytes()
    }

    /// `strncmp(at(i), s, strlen(s)) == 0`
    pub fn starts(&self, i: usize, s: &str) -> bool {
        self.at(i).starts_with(s.as_bytes())
    }

    /// `strtol(at(i), NULL, 10)`
    pub fn strtol(&self, i: usize) -> i64 {
        strtol(self.at(i))
    }

    /// `strtok_r(start or NULL, delim, &save)`: the token start.
    pub fn strtok(&mut self, start: Option<usize>, save: &mut usize, delim: &[u8]) -> Option<usize> {
        let mut p = start.unwrap_or(*save);
        self.ensure(p);
        while self.b[p] != 0 && delim.contains(&self.b[p]) {
            p += 1;
            self.ensure(p);
        }
        if self.b[p] == 0 {
            *save = p;
            return None;
        }
        let tok = p;
        loop {
            self.ensure(p);
            let c = self.b[p];
            if c == 0 {
                *save = p;
                return Some(tok);
            }
            if delim.contains(&c) {
                self.b[p] = 0;
                *save = p + 1;
                return Some(tok);
            }
            p += 1;
        }
    }
}

/// `snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", s)`
pub fn near(prefix: &str, s: &[u8]) -> B {
    out(msg!(prefix, ", near '", s32(s), "'"))
}

/// `WDBC_RESULT`
pub const WDBC_RESULT: [&str; 5] = ["ok", "due", "err", "ign", "unk"];

impl Wdbd {
    pub fn tv(&self) -> Tv {
        self.env.timeofday()
    }

    /// `wdb_parse`: the result and the response (a C string).
    pub fn parse(&self, input: &[u8], peer: i32) -> (i32, B) {
        self.state.w_inc_queries_total();
        let mut buf = CBuf::new(input);
        // Clean string
        let mut i = 0;
        while buf.b[i] == b' ' || buf.b[i] == b'\n' {
            i += 1;
        }
        let Some(sp) = buf.wchr(i, b' ') else {
            self.mdebug1(b"Invalid DB query syntax.");
            self.mdebug2(&msg!("DB query: ", buf.at(i)));
            return (OS_INVALID, near("err Invalid DB query syntax", buf.at(i)));
        };
        let actor = i;
        buf.nul(sp);
        let next = sp + 1;
        if buf.eq(actor, "agent") {
            self.parse_agent(&mut buf, next, peer)
        } else if buf.eq(actor, "wazuhdb") {
            self.parse_wazuhdb(&mut buf, next)
        } else if buf.eq(actor, "mitre") {
            self.parse_mitre(&mut buf, next, peer)
        } else if buf.eq(actor, "global") {
            self.parse_global_actor(&mut buf, next, peer)
        } else if buf.eq(actor, "task") {
            self.parse_task_actor(&mut buf, next, peer)
        } else {
            self.mdebug1(&msg!("DB(000) Invalid DB query actor: ", buf.at(actor)));
            (OS_INVALID, out(msg!("err Invalid DB query actor: '", s32(buf.at(actor)), "'")))
        }
    }

    /// The `agent` actor.
    fn parse_agent(&self, buf: &mut CBuf, id: usize, peer: i32) -> (i32, B) {
        self.state.w_inc_agent();
        let Some(sp) = buf.wchr(id, b' ') else {
            self.mdebug1(b"Invalid DB query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(id)));
            return (OS_INVALID, near("err Invalid DB query syntax", buf.at(id)));
        };
        buf.nul(sp);
        let query = sp + 1;
        let id_s = buf.owned(id);
        let (agent_id_l, end) = strtol_end(&id_s);
        // strtol leaves `next` at the start when there are no digits
        let rest_ok = if end == 0 { id_s.is_empty() } else { end == id_s.len() };
        if !rest_ok {
            self.mdebug1(&msg!("Invalid agent ID '", id_s, "'"));
            return (OS_INVALID, out(msg!("err Invalid agent ID '", s32(&id_s), "'")));
        }
        let agent_id = agent_id_l as i32;
        let sagent_id = format!("{agent_id:03}");
        self.mdebug2(&msg!("Agent ", sagent_id, " query: ", buf.at(query)));

        if agent_id != 0 {
            let Some(mut g) = self.open_global() else {
                self.mdebug2(&msg!("Couldn't open DB global: ", WDB2_DIR, "/", WDB_GLOB_NAME, ".db"));
                return (OS_INVALID, out(b"err Couldn't open DB global".to_vec()));
            };
            if !g.enabled {
                self.mdebug2(&msg!("Database disabled: ", WDB2_DIR, "/", WDB_GLOB_NAME, ".db."));
                self.leave(g);
                return (OS_INVALID, out(b"err DB global disabled.".to_vec()));
            }
            if self.global_agent_exists(&mut g, agent_id) <= 0 {
                self.mdebug2(&msg!("No agent with id ", sagent_id, " found."));
                self.leave(g);
                return (OS_INVALID, out(b"err Agent not found".to_vec()));
            }
            self.leave(g);
        }

        let begin = self.tv();
        let Some(mut wdb) = self.open_agent2(agent_id) else {
            self.merror(&msg!("Couldn't open DB for agent '", sagent_id, "'"));
            self.state.w_inc_agent_open_time(Tv::diff(self.tv(), begin));
            return (OS_INVALID, out(msg!("err Couldn't open DB for agent ", agent_id)));
        };
        self.state.w_inc_agent_open_time(Tv::diff(self.tv(), begin));
        wdb.peer = peer;

        let next = buf.wchr(query, b' ').map(|p| {
            buf.nul(p);
            p + 1
        });
        let q = buf.owned(query);
        let mut output: B;
        let mut result = 0;

        // the "no arguments" error of most commands
        let no_args = |d: &Self, msg: &str| -> (i32, B) {
            d.mdebug1(&msg!("DB(", sagent_id, ") ", msg));
            d.mdebug2(&msg!("DB(", sagent_id, ") query error near: ", q));
            (OS_INVALID, near("err Invalid DB query syntax", &q))
        };
        macro_rules! timed {
            ($inc:ident, $time:ident, $body:expr) => {{
                self.state.$inc();
                match next {
                    None => no_args(self, "Invalid DB query syntax."),
                    Some(n) => {
                        let b = self.tv();
                        let r = ($body)(n);
                        self.state.$time(Tv::diff(self.tv(), b));
                        r
                    }
                }
            }};
        }
        macro_rules! fim {
            ($inc:ident, $time:ident, $component:expr, $what:expr) => {{
                self.state.$inc();
                match next {
                    None => {
                        self.mdebug1(&msg!("DB(", sagent_id, ") Invalid ", $what, " query syntax."));
                        self.mdebug2(&msg!("DB(", sagent_id, ") ", $what, " query error near: ", q));
                        (OS_INVALID, near("err Invalid Syscheck query syntax", &q))
                    }
                    Some(n) => {
                        let b = self.tv();
                        let r = self.parse_syscheck(&mut wdb, $component, buf, n);
                        self.state.$time(Tv::diff(self.tv(), b));
                        r
                    }
                }
            }};
        }

        match &q[..] {
            b"syscheck" => (result, output) = fim!(w_inc_agent_syscheck, w_inc_agent_syscheck_time, WDB_FIM, "FIM"),
            b"fim_file" => (result, output) = fim!(w_inc_agent_fim_file, w_inc_agent_fim_file_time, WDB_FIM_FILE, "FIM file"),
            b"fim_registry" => {
                (result, output) = fim!(w_inc_agent_fim_registry, w_inc_agent_fim_registry_time, WDB_FIM_REGISTRY, "FIM registry")
            }
            b"fim_registry_key" => {
                (result, output) =
                    fim!(w_inc_agent_fim_registry_key, w_inc_agent_fim_registry_key_time, WDB_FIM_REGISTRY_KEY, "FIM registry key")
            }
            b"fim_registry_value" => {
                (result, output) = fim!(
                    w_inc_agent_fim_registry_value,
                    w_inc_agent_fim_registry_value_time,
                    WDB_FIM_REGISTRY_VALUE,
                    "FIM registry value"
                )
            }
            b"sca" => (result, output) = timed!(w_inc_agent_sca, w_inc_agent_sca_time, |n| self.parse_sca(&mut wdb, buf, n)),
            b"netinfo" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_network_info,
                    w_inc_agent_syscollector_deprecated_network_info_time,
                    |n| self.parse_netinfo(&mut wdb, buf, n)
                )
            }
            b"netproto" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_network_protocol,
                    w_inc_agent_syscollector_deprecated_network_protocol_time,
                    |n| self.parse_netproto(&mut wdb, buf, n)
                )
            }
            b"netaddr" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_network_address,
                    w_inc_agent_syscollector_deprecated_network_address_time,
                    |n| self.parse_netaddr(&mut wdb, buf, n)
                )
            }
            b"osinfo" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_osinfo,
                    w_inc_agent_syscollector_deprecated_osinfo_time,
                    |n| self.parse_osinfo(&mut wdb, buf, n)
                )
            }
            b"hardware" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_hardware,
                    w_inc_agent_syscollector_deprecated_hardware_time,
                    |n| self.parse_hardware(&mut wdb, buf, n)
                )
            }
            b"port" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_ports,
                    w_inc_agent_syscollector_deprecated_ports_time,
                    |n| self.parse_ports(&mut wdb, buf, n)
                )
            }
            b"package" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_packages,
                    w_inc_agent_syscollector_deprecated_packages_time,
                    |n| self.parse_packages(&mut wdb, buf, n)
                )
            }
            b"hotfix" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_hotfixes,
                    w_inc_agent_syscollector_deprecated_hotfixes_time,
                    |n| self.parse_hotfixes(&mut wdb, buf, n)
                )
            }
            b"process" => {
                (result, output) = timed!(
                    w_inc_agent_syscollector_deprecated_process,
                    w_inc_agent_syscollector_deprecated_process_time,
                    |n| self.parse_processes(&mut wdb, buf, n)
                )
            }
            b"dbsync" => (result, output) = timed!(w_inc_agent_dbsync, w_inc_agent_dbsync_time, |n| self.parse_dbsync(&mut wdb, buf, n)),
            b"ciscat" => (result, output) = timed!(w_inc_agent_ciscat, w_inc_agent_ciscat_time, |n| self.parse_ciscat(&mut wdb, buf, n)),
            b"rootcheck" => {
                self.state.w_inc_agent_rootcheck();
                (result, output) = match next {
                    None => {
                        self.mdebug1(&msg!("DB(", sagent_id, ") Invalid rootcheck query syntax."));
                        self.mdebug2(&msg!("DB(", sagent_id, ") rootcheck query error near: ", q));
                        (OS_INVALID, near("err Invalid Rootcheck query syntax", &q))
                    }
                    Some(n) => {
                        let b = self.tv();
                        let r = self.parse_rootcheck(&mut wdb, buf, n);
                        self.state.w_inc_agent_rootcheck_time(Tv::diff(self.tv(), b));
                        r
                    }
                }
            }
            b"sql" => {
                self.state.w_inc_agent_sql();
                (result, output) = match next {
                    None => no_args(self, "Invalid DB query syntax."),
                    Some(n) => {
                        let sql = buf.owned(n);
                        let b = self.tv();
                        let data = self.exec(wdb.db(), &sql);
                        self.state.w_inc_agent_sql_time(Tv::diff(self.tv(), b));
                        match data {
                            Some(d) => (0, out(msg!("ok ", d.print_unformatted()))),
                            None => {
                                self.mdebug1(&msg!("DB(", sagent_id, ") Cannot execute SQL query."));
                                self.mdebug2(&msg!("DB(", sagent_id, ") SQL query: ", sql));
                                (OS_INVALID, out(b"err Cannot execute SQL query".to_vec()))
                            }
                        }
                    }
                }
            }
            b"remove" => {
                self.state.w_inc_agent_remove();
                output = out(b"ok".to_vec());
                let b = self.tv();
                if self.close(&mut wdb, false) < 0 {
                    self.mdebug1(&msg!("DB(", sagent_id, ") Cannot close database."));
                    output = out(b"err Cannot close database".to_vec());
                    result = OS_INVALID;
                }
                self.leave(wdb);
                if self.remove_database(&sagent_id) < 0 {
                    output = out(b"err Cannot remove database".to_vec());
                    result = OS_INVALID;
                }
                self.state.w_inc_agent_remove_time(Tv::diff(self.tv(), b));
                return (result, output);
            }
            b"begin" => {
                self.state.w_inc_agent_begin();
                let b = self.tv();
                if self.begin2(&mut wdb) < 0 {
                    self.mdebug1(&msg!("DB(", sagent_id, ") Cannot begin transaction."));
                    output = out(b"err Cannot begin transaction".to_vec());
                    result = OS_INVALID;
                } else {
                    output = out(b"ok".to_vec());
                }
                self.state.w_inc_agent_begin_time(Tv::diff(self.tv(), b));
            }
            b"commit" => {
                self.state.w_inc_agent_commit();
                let b = self.tv();
                if self.commit2(&mut wdb) < 0 {
                    self.mdebug1(&msg!("DB(", sagent_id, ") Cannot end transaction."));
                    output = out(b"err Cannot end transaction".to_vec());
                    result = OS_INVALID;
                } else {
                    output = out(b"ok".to_vec());
                }
                self.state.w_inc_agent_commit_time(Tv::diff(self.tv(), b));
            }
            b"close" => {
                self.state.w_inc_agent_close();
                output = out(b"ok".to_vec());
                let b = self.tv();
                if self.close(&mut wdb, true) < 0 {
                    self.mdebug1(&msg!("DB(", sagent_id, ") Cannot close database."));
                    output = out(b"err Cannot close database".to_vec());
                    result = OS_INVALID;
                }
                self.leave(wdb);
                self.state.w_inc_agent_close_time(Tv::diff(self.tv(), b));
                return (result, output);
            }
            _ if q.starts_with(b"syscoll") => {
                // strncmp(query, "syscollector_", 7)
                (result, output) = match next {
                    None => {
                        self.mdebug1(&msg!("DB(", sagent_id, ") Invalid Syscollector query syntax."));
                        self.mdebug2(&msg!("DB(", sagent_id, ") Syscollector query error near: ", q));
                        (OS_INVALID, near("err Invalid Syscollector query syntax", &q))
                    }
                    Some(n) => {
                        let b = self.tv();
                        let r = self.parse_syscollector(&mut wdb, &q, buf, n);
                        self.state.w_inc_agent_syscollector_times(Tv::diff(self.tv(), b), r.0);
                        r
                    }
                }
            }
            b"vacuum" => {
                self.state.w_inc_agent_vacuum();
                let b = self.tv();
                (result, output) = self.vacuum_command(&mut wdb, &format!("DB({sagent_id})"));
                self.state.w_inc_agent_vacuum_time(Tv::diff(self.tv(), b));
            }
            b"get_fragmentation" => {
                self.state.w_inc_agent_get_fragmentation();
                let b = self.tv();
                (result, output) = self.fragmentation_command(&wdb, &format!("DB({sagent_id})"));
                self.state.w_inc_agent_get_fragmentation_time(Tv::diff(self.tv(), b));
            }
            b"sleep" => {
                self.state.w_inc_agent_sleep();
                let b = self.tv();
                (result, output) = self.sleep_command(buf, next, &q, &format!("DB({sagent_id})"));
                self.state.w_inc_agent_sleep_time(Tv::diff(self.tv(), b));
            }
            _ => {
                self.mdebug1(&msg!("DB(", sagent_id, ") Invalid DB query syntax."));
                self.mdebug2(&msg!("DB(", sagent_id, ") query error near: ", q));
                output = near("err Invalid DB query syntax", &q);
                result = OS_INVALID;
            }
        }
        if result == OS_INVALID {
            self.check_db_file(&mut wdb);
        }
        self.leave(wdb);
        (result, output)
    }

    /// The "DB not found" recovery of an invalid result: `w_is_file` of the
    /// database, closing it when it vanished.
    fn check_db_file(&self, wdb: &mut Wdb) {
        let rel = format!("{WDB2_DIR}/{}.db", wdb.id);
        if std::fs::File::open(self.path(&rel)).is_err() {
            self.mwarn(&msg!("DB(", rel, ") not found. This behavior is unexpected, the database will be recreated."));
            self.close(wdb, false);
        }
    }

    /// The `vacuum` command (agent and global).
    pub(crate) fn vacuum_command(&self, wdb: &mut Wdb, who: &str) -> (i32, B) {
        let mut result = 0;
        let mut output = Vec::new();
        if self.commit2(wdb) < 0 {
            self.mdebug1(&msg!(who, " Cannot end transaction."));
            output = out(b"err Cannot end transaction".to_vec());
            result = -1;
        }
        self.finalize_all_statements(wdb);
        if result != -1 {
            if self.vacuum(wdb) < 0 {
                self.mdebug1(&msg!(who, " Cannot vacuum database."));
                output = out(b"err Cannot vacuum database".to_vec());
                result = -1;
            } else {
                let after = self.get_db_state(wdb);
                if after == OS_INVALID {
                    self.mdebug1(&msg!(who, " Couldn't get fragmentation after vacuum for the database."));
                    output = out(b"err Vacuum performed, but couldn't get fragmentation information after vacuum".to_vec());
                    result = -1;
                } else {
                    let t = self.time().to_string();
                    let v = after.to_string();
                    if self.update_last_vacuum_data(wdb, t.as_bytes(), v.as_bytes()) != OS_SUCCESS {
                        self.mdebug1(&msg!(who, " Couldn't update last vacuum info for the database."));
                        output = out(
                            b"err Vacuum performed, but last vacuum information couldn't be updated in the metadata table".to_vec(),
                        );
                        result = -1;
                    } else {
                        let mut j = Json::object();
                        j.add("fragmentation_after_vacuum", Json::number(after as f64));
                        output = out(msg!("ok ", j.print_unformatted()));
                        result = 0;
                    }
                }
            }
        }
        (result, output)
    }

    /// The `get_fragmentation` command.
    pub(crate) fn fragmentation_command(&self, wdb: &Wdb, who: &str) -> (i32, B) {
        let state = self.get_db_state(wdb);
        let free_pages = self.get_db_free_pages_percentage(wdb);
        if state < 0 || free_pages < 0 {
            self.mdebug1(&msg!(who, " Cannot get database fragmentation."));
            return (-1, out(b"err Cannot get database fragmentation".to_vec()));
        }
        let mut j = Json::object();
        j.add("fragmentation", Json::number(state as f64));
        j.add("free_pages_percentage", Json::number(free_pages as f64));
        (0, out(msg!("ok ", j.print_unformatted())))
    }

    /// The `sleep` command (`w_time_delay`).
    pub(crate) fn sleep_command(&self, buf: &CBuf, next: Option<usize>, q: &[u8], who: &str) -> (i32, B) {
        // strtoul(next, NULL, 10) == ULONG_MAX
        let delay = next.map(|n| strtoul(buf.at(n)));
        match delay {
            Some(d) if d != u64::MAX => {
                self.env.sleep_ms(d);
                (0, out(b"ok ".to_vec()))
            }
            _ => {
                self.mdebug1(&msg!(who, " Invalid DB query syntax."));
                self.mdebug2(&msg!(who, " query error near: ", q));
                (OS_INVALID, near("err Invalid DB query syntax", q))
            }
        }
    }

    /// The `wazuhdb` actor.
    fn parse_wazuhdb(&self, buf: &mut CBuf, query: usize) -> (i32, B) {
        self.state.w_inc_wazuhdb();
        let Some(sp) = buf.wchr(query, b' ') else {
            self.mdebug1(b"Invalid DB query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(query)));
            return (OS_INVALID, near("err Invalid DB query syntax", buf.at(query)));
        };
        buf.nul(sp);
        let next = sp + 1;
        if buf.eq(query, "remove") {
            self.state.w_inc_wazuhdb_remove();
            let b = self.tv();
            let data = self.remove_multiple_agents(buf.at(next));
            self.state.w_inc_wazuhdb_remove_time(Tv::diff(self.tv(), b));
            // cJSON_PrintUnformatted(NULL) is NULL: "%s" prints "(null)"
            let printed = data.map(|d| d.print_unformatted()).unwrap_or_else(|| b"(null)".to_vec());
            (0, out(msg!("ok ", printed)))
        } else {
            self.mdebug1(b"Invalid DB query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(query)));
            (OS_INVALID, out(b"err No agents id provided".to_vec()))
        }
    }

    /// The `mitre` actor.
    fn parse_mitre(&self, buf: &mut CBuf, query: usize, peer: i32) -> (i32, B) {
        self.state.w_inc_mitre();
        self.mdebug2(&msg!("Mitre query: ", buf.at(query)));
        let Some(mut wdb) = self.open_mitre() else {
            self.mdebug2(&msg!("Couldn't open DB mitre: ", WDB_DIR, "/", WDB_MITRE_NAME, ".db"));
            return (OS_INVALID, out(b"err Couldn't open DB mitre".to_vec()));
        };
        wdb.peer = peer;
        let Some(sp) = buf.wchr(query, b' ') else {
            self.mdebug1(b"Invalid DB query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(query)));
            let r = near("err Invalid DB query syntax", buf.at(query));
            self.leave(wdb);
            return (OS_INVALID, r);
        };
        buf.nul(sp);
        let next = sp + 1;
        let r = if buf.eq(query, "sql") {
            self.state.w_inc_mitre_sql();
            let sql = buf.owned(next);
            let b = self.tv();
            let data = self.exec(wdb.db(), &sql);
            self.state.w_inc_mitre_sql_time(Tv::diff(self.tv(), b));
            match data {
                Some(d) => (0, out(msg!("ok ", d.print_unformatted()))),
                None => {
                    let e = wdb.errmsg();
                    self.mdebug1(&msg!(
                        "Mitre DB Cannot execute SQL query; err database ",
                        WDB_DIR,
                        "/",
                        WDB_MITRE_NAME,
                        ".db: ",
                        e
                    ));
                    self.mdebug2(&msg!("Mitre DB SQL query: ", sql));
                    (OS_INVALID, out(msg!("err Cannot execute Mitre database query; ", e)))
                }
            }
        } else {
            self.mdebug1(b"Invalid DB query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(query)));
            (OS_INVALID, near("err Invalid DB query syntax", buf.at(query)))
        };
        self.leave(wdb);
        r
    }

    /// The `global` actor.
    fn parse_global_actor(&self, buf: &mut CBuf, query: usize, peer: i32) -> (i32, B) {
        self.state.w_inc_global();
        self.mdebug2(&msg!("Global query: ", buf.at(query)));
        let b = self.tv();
        let Some(mut wdb) = self.open_global() else {
            self.mdebug2(&msg!("Couldn't open DB global: ", WDB2_DIR, "/", WDB_GLOB_NAME, ".db"));
            self.state.w_inc_global_open_time(Tv::diff(self.tv(), b));
            return (OS_INVALID, out(b"err Couldn't open DB global".to_vec()));
        };
        if !wdb.enabled {
            self.mdebug2(&msg!("Database disabled: ", WDB2_DIR, "/", WDB_GLOB_NAME, ".db."));
            self.leave(wdb);
            self.state.w_inc_global_open_time(Tv::diff(self.tv(), b));
            return (OS_INVALID, out(b"err DB global disabled.".to_vec()));
        }
        self.state.w_inc_global_open_time(Tv::diff(self.tv(), b));
        wdb.peer = peer;
        let next = buf.wchr(query, b' ').map(|p| {
            buf.nul(p);
            p + 1
        });
        let q = buf.owned(query);
        let (result, output) = self.parse_global_command(&mut wdb, buf, &q, next);
        if result == OS_INVALID {
            self.check_db_file(&mut wdb);
        }
        self.leave(wdb);
        (result, output)
    }

    /// The `task` actor.
    fn parse_task_actor(&self, buf: &mut CBuf, query: usize, peer: i32) -> (i32, B) {
        self.state.w_inc_task();
        self.mdebug2(&msg!("Task query: ", buf.at(query)));
        let Some(mut wdb) = self.open_tasks() else {
            self.mdebug2(&msg!("Couldn't open DB task: ", WDB_TASK_DIR, "/", WDB_TASK_NAME, ".db"));
            return (OS_INVALID, out(b"err Couldn't open DB task".to_vec()));
        };
        wdb.peer = peer;
        let Some(sp) = buf.wchr(query, b' ') else {
            self.mdebug1(b"Invalid DB query syntax.");
            self.mdebug2(&msg!("DB query error near: ", buf.at(query)));
            let r = near("err Invalid DB query syntax", buf.at(query));
            self.leave(wdb);
            return (OS_INVALID, r);
        };
        buf.nul(sp);
        let next = sp + 1;
        let q = buf.owned(query);
        let r = self.parse_task_command(&mut wdb, buf, &q, next);
        self.leave(wdb);
        r
    }
}

/// `strtoul(s, NULL, 10)` (glibc: a leading '-' negates modulo 2^64,
/// overflow is ULONG_MAX).
pub fn strtoul(s: &[u8]) -> u64 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: u64 = 0;
    let mut over = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((s[i] - b'0') as u64)) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    if over {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    }
}
