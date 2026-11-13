//! The `agent <id>` actor (spec § 1.1, § 2): opening agent databases and the command dispatch.

use crate::text::{answer, id3, near, read_long, split_word, until_nul};
use crate::{layout, Answer, Engine, Handle, Locked, DB_DIR, INVALID, OK};

/// The template every new agent database is copied from.
pub const TEMPLATE: &str = "queue/db/.template.db";

impl Engine {
    /// Creates the template file from the agent layout.
    pub fn create_template(&self) -> bool {
        self.create_file(TEMPLATE, layout::AGENT)
    }

    /// A new agent database, copied from the template (created first when missing).
    fn create_agent_db(&self, id: &str) -> bool {
        let source = match std::fs::read(self.path(TEMPLATE)) {
            Ok(d) => d,
            Err(_) => {
                self.debug(b"Profile database not found, creating.".to_vec());
                if !self.create_template() {
                    return false;
                }
                match std::fs::read(self.path(TEMPLATE)) {
                    Ok(d) => d,
                    Err(_) => {
                        self.error(cat!("Couldn't open profile '", TEMPLATE, "'."));
                        return false;
                    }
                }
            }
        };
        let rel = format!("{DB_DIR}/{id}.db");
        let tmp = format!("{rel}.new");
        if let Err(e) = std::fs::write(self.path(&tmp), &source) {
            self.error(cat!("Couldn't create database '", rel, "': ", os_text(&e), " (", e.raw_os_error().unwrap_or(0), ")"));
            return false;
        }
        if let Err(e) = std::fs::rename(self.path(&tmp), self.path(&rel)) {
            self.error(cat!(
                "(1124): Could not rename file '", tmp.clone(), "' to '", rel, "' due to [(", e.raw_os_error().unwrap_or(0), ")-(", os_text(&e), ")]."
            ));
            let _ = std::fs::remove_file(self.path(&tmp));
            return false;
        }
        true
    }

    /// The agent's database, created when missing.
    pub fn open_agent(&self, agent: i32) -> Option<Locked> {
        let id = id3(agent);
        let mut h = self.cached(&id);
        if h.db.is_some() {
            return Some(h);
        }
        let rel = format!("{DB_DIR}/{id}.db");
        if !self.open_into(&mut h, &rel) {
            self.debug(cat!("No SQLite database found for agent '", id.clone(), "', creating."));
            h.db = None;
            if !self.create_agent_db(&id) {
                self.error(cat!("Couldn't create SQLite database '", rel.clone(), "'"));
                return None;
            }
            if !self.open_into(&mut h, &rel) {
                self.error(cat!("Can't open SQLite database '", rel.clone(), "': ", h.errmsg()));
                h.db = None;
                return None;
            }
        } else {
            self.check_version(&mut h, &rel, "metadata", layout::AGENT_VERSION);
        }
        Some(h)
    }

    pub(crate) fn agent_actor(&self, rest: &[u8], peer: i32) -> Answer {
        let (idt, query) = split_word(rest);
        let Some(query) = query else {
            self.debug(b"Invalid DB query syntax.".to_vec());
            self.debug2(cat!("DB query error near: ", idt));
            return (INVALID, near("err Invalid DB query syntax", idt));
        };
        let (n, end) = read_long(idt);
        // only digits (or nothing): the id
        if !(if end == 0 { idt.is_empty() } else { end == idt.len() }) {
            self.debug(cat!("Invalid agent ID '", idt, "'"));
            return (INVALID, answer(cat!("err Invalid agent ID '", crate::text::first32(idt), "'")));
        }
        let agent = n as i32;
        let sid = id3(agent);
        self.debug2(cat!("Agent ", sid.clone(), " query: ", query));
        if agent != 0 {
            let Some(mut g) = self.open_global() else {
                self.debug2(cat!("Couldn't open DB global: ", DB_DIR, "/global.db"));
                return (INVALID, b"err Couldn't open DB global".to_vec());
            };
            if !g.enabled {
                self.debug2(cat!("Database disabled: ", DB_DIR, "/global.db."));
                return (INVALID, b"err DB global disabled.".to_vec());
            }
            if self.agent_exists_in(&mut g, agent) <= 0 {
                self.debug2(cat!("No agent with id ", sid.clone(), " found."));
                return (INVALID, b"err Agent not found".to_vec());
            }
        }
        let Some(mut h) = self.open_agent(agent) else {
            self.error(cat!("Couldn't open DB for agent '", sid.clone(), "'"));
            return (INVALID, answer(cat!("err Couldn't open DB for agent ", agent)));
        };
        h.peer = peer;
        let (cmd, args) = split_word(query);
        let who = format!("DB({sid})");
        let no_args = |what: &str, prefix: &str| -> Answer {
            match what {
                "" => {
                    self.debug(cat!(who.clone(), " Invalid DB query syntax."));
                    self.debug2(cat!(who.clone(), " query error near: ", cmd));
                }
                w => {
                    self.debug(cat!(who.clone(), " Invalid ", w, " query syntax."));
                    self.debug2(cat!(who.clone(), " ", w, " query error near: ", cmd));
                }
            }
            (INVALID, near(prefix, cmd))
        };
        let r: Answer = match cmd {
            b"syscheck" | b"fim_file" | b"fim_registry" | b"fim_registry_key" | b"fim_registry_value" => {
                let what = match cmd {
                    b"syscheck" => "FIM",
                    b"fim_file" => "FIM file",
                    b"fim_registry" => "FIM registry",
                    b"fim_registry_key" => "FIM registry key",
                    _ => "FIM registry value",
                };
                match args {
                    None => no_args(what, "err Invalid Syscheck query syntax"),
                    Some(a) => self.fim_command(&mut h, cmd, a),
                }
            }
            b"rootcheck" => match args {
                None => {
                    self.debug(cat!(who.clone(), " Invalid rootcheck query syntax."));
                    self.debug2(cat!(who.clone(), " rootcheck query error near: ", cmd));
                    (INVALID, near("err Invalid Rootcheck query syntax", cmd))
                }
                Some(a) => self.rootcheck_command(&mut h, a),
            },
            b"sql" => match args {
                None => no_args("", "err Invalid DB query syntax"),
                Some(sql) => match self.sql(&h, sql) {
                    Some(d) => (OK, answer(cat!("ok ", d.print_unformatted()))),
                    None => {
                        self.debug(cat!(who.clone(), " Cannot execute SQL query."));
                        self.debug2(cat!(who.clone(), " SQL query: ", until_nul(sql)));
                        (INVALID, b"err Cannot execute SQL query".to_vec())
                    }
                },
            },
            b"remove" => {
                let mut r = (OK, b"ok".to_vec());
                self.close(&mut h, false);
                drop(h);
                let rel = format!("{DB_DIR}/{sid}.db");
                if let Err(e) = std::fs::remove_file(self.path(&rel)) {
                    self.debug(cat!("(1129): Could not unlink file '", rel, "' due to [(", e.raw_os_error().unwrap_or(0), ")-(", os_text(&e), ")]."));
                    r = (INVALID, b"err Cannot remove database".to_vec());
                }
                return r;
            }
            b"begin" => {
                if self.begin(&mut h) {
                    (OK, b"ok".to_vec())
                } else {
                    self.debug(cat!(who.clone(), " Cannot begin transaction."));
                    (INVALID, b"err Cannot begin transaction".to_vec())
                }
            }
            b"commit" => {
                if self.commit(&mut h) {
                    (OK, b"ok".to_vec())
                } else {
                    self.debug(cat!(who.clone(), " Cannot end transaction."));
                    (INVALID, b"err Cannot end transaction".to_vec())
                }
            }
            b"close" => {
                self.close(&mut h, true);
                return (OK, b"ok".to_vec());
            }
            b"vacuum" => self.vacuum_command(&mut h, &who),
            b"get_fragmentation" => self.fragmentation_command(&h, &who),
            b"sleep" => self.sleep_command(args, cmd, &who),
            c if c.starts_with(b"syscoll") => match args {
                None => {
                    self.debug(cat!(who.clone(), " Invalid Syscollector query syntax."));
                    self.debug2(cat!(who.clone(), " Syscollector query error near: ", cmd));
                    (INVALID, near("err Invalid Syscollector query syntax", cmd))
                }
                Some(a) => self.syscollector_command(&mut h, cmd, a),
            },
            _ => match (self.legacy_command(&mut h, cmd, args), args) {
                (Some(r), _) => r,
                (None, _) => {
                    self.debug(cat!(who.clone(), " Invalid DB query syntax."));
                    self.debug2(cat!(who.clone(), " query error near: ", cmd));
                    (INVALID, near("err Invalid DB query syntax", cmd))
                }
            },
        };
        if r.0 == INVALID {
            self.check_file(&mut h);
        }
        r
    }

    /// The legacy commands; None = unknown command.
    fn legacy_command(&self, h: &mut Handle, cmd: &[u8], args: Option<&[u8]>) -> Option<Answer> {
        let who = format!("DB({})", h.id);
        const NEEDS_ARGS: [&[u8]; 12] =
            [b"sca", b"netinfo", b"netproto", b"netaddr", b"osinfo", b"hardware", b"port", b"package", b"hotfix", b"process", b"dbsync", b"ciscat"];
        let Some(a) = args else {
            return match cmd {
                c if NEEDS_ARGS.contains(&c) => {
                    self.debug(cat!(who.clone(), " Invalid DB query syntax."));
                    self.debug2(cat!(who, " query error near: ", cmd));
                    Some((INVALID, near("err Invalid DB query syntax", cmd)))
                }
                _ => None,
            };
        };
        match cmd {
            b"ciscat" => Some(self.ciscat_command(h, a)),
            b"sca" => Some(self.sca_command(h, a)),
            b"dbsync" => Some(self.dbsync_command(h, a)),
            b"netinfo" | b"netproto" | b"netaddr" | b"osinfo" | b"hardware" | b"port" | b"package" | b"hotfix" | b"process" => self.inventory_command(h, cmd, a),
            _ => None,
        }
    }

}

/// The operating system's text for an I/O error (without Rust's "(os error N)" suffix).
pub fn os_text(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(p) => s[..p].to_string(),
        None => s,
    }
}
