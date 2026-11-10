//! Database schema upgrades (wazuh_db/wdb_upgrade.c).

use siem_cjson::Json;

use super::*;

/// `decode_win_attributes` (shared/syscheck_op.c)
pub fn decode_win_attributes(attrs: u32) -> B {
    const A: &[(u32, &str)] = &[
        (0x20, "ARCHIVE, "),
        (0x800, "COMPRESSED, "),
        (0x40, "DEVICE, "),
        (0x10, "DIRECTORY, "),
        (0x4000, "ENCRYPTED, "),
        (0x2, "HIDDEN, "),
        (0x8000, "INTEGRITY_STREAM, "),
        (0x80, "NORMAL, "),
        (0x2000, "NOT_CONTENT_INDEXED, "),
        (0x20000, "NO_SCRUB_DATA, "),
        (0x1000, "OFFLINE, "),
        (0x1, "READONLY, "),
        (0x400000, "RECALL_ON_DATA_ACCESS, "),
        (0x40000, "RECALL_ON_OPEN, "),
        (0x400, "REPARSE_POINT, "),
        (0x200, "SPARSE_FILE, "),
        (0x4, "SYSTEM, "),
        (0x100, "TEMPORARY, "),
        (0x10000, "VIRTUAL, "),
    ];
    let mut s: B = A.iter().filter(|(b, _)| attrs & b != 0).flat_map(|(_, n)| n.bytes()).collect();
    let size = s.len();
    s.truncate(255);
    if size > 2 {
        s.truncate(size - 2);
    }
    s
}

fn agent_updates() -> [&'static str; 16] {
    [
        schema::upgrade_v1(),
        schema::upgrade_v2(),
        schema::upgrade_v3(),
        schema::upgrade_v4(),
        schema::upgrade_v5(),
        schema::upgrade_v6(),
        schema::upgrade_v7(),
        schema::upgrade_v8(),
        schema::upgrade_v9(),
        schema::upgrade_v10(),
        schema::upgrade_v11(),
        schema::upgrade_v12(),
        schema::upgrade_v13(),
        schema::upgrade_v14(),
        schema::upgrade_v15(),
        schema::upgrade_v16(),
    ]
}

fn global_updates() -> [&'static str; 7] {
    [
        schema::global_upgrade_v1(),
        schema::global_upgrade_v2(),
        schema::global_upgrade_v3(),
        schema::global_upgrade_v4(),
        schema::global_upgrade_v5(),
        schema::global_upgrade_v6(),
        schema::global_upgrade_v7(),
    ]
}

impl Wdbd {
    /// `wdb_upgrade`: false when the database could not be recreated
    /// (`wdb_upgrade` returning NULL).
    pub fn upgrade(&self, wdb: &mut Wdb) -> bool {
        let updates = agent_updates();
        let mut database_updated = false;
        let mut version = 0;
        let (ret, db_version) = self.metadata_get_entry(wdb, b"db_version");
        if ret == OS_SUCCESS || ret == OS_NOTFOUND {
            version = atoi(&db_version);
            if version < 0 {
                self.merror(&msg!("DB(", wdb.id, "): Incorrect database version: ", version));
                return false;
            }
            for i in version as usize..updates.len() {
                self.mdebug2(&msg!("Updating database '", wdb.id, "' to version ", i + 1));
                database_updated = false;
                if self.sql_exec(wdb, updates[i]) == -1 || self.adjust_upgrade(wdb, i) != 0 {
                    if !self.backup(wdb, version) {
                        return false;
                    }
                    break;
                }
                database_updated = true;
            }
        }
        if self.router_agent && database_updated {
            let mut agent_info = Json::object();
            agent_info.add("agent_id", Json::string(&wdb.id));
            let mut m = Json::object();
            m.add("agent_info", agent_info);
            m.add("action", Json::string("upgradeAgentDB"));
            let mut data = Json::object();
            data.add("db_version", Json::number(version as f64));
            data.add("new_db_version", Json::number(updates.len() as f64));
            m.add("data", data);
            self.env.router_send(1, &m.print_unformatted());
        }
        true
    }

    /// `wdb_upgrade_global`: false when it returns NULL.
    pub fn upgrade_global(&self, wdb: &mut Wdb) -> bool {
        let updates = global_updates();
        let mut output: B = Vec::new();
        let mut version = 0;
        match self.count_tables_with_name(wdb, b"metadata") {
            Some(count) => {
                if count > 0 {
                    let (r, v) = self.metadata_get_entry(wdb, b"db_version");
                    if r == OS_SUCCESS {
                        version = atoi(&v);
                    } else {
                        self.mwarn(&msg!("DB(", wdb.id, "): Error trying to get DB version"));
                        wdb.enabled = false;
                    }
                } else if self.is_older_than_v310(wdb) {
                    if self.global_create_backup(wdb, &mut output, Some("-pre_upgrade")) != OS_SUCCESS {
                        self.merror(&msg!("Creating pre-upgrade Global DB snapshot failed: ", cstr(&output)));
                        wdb.enabled = false;
                        return true;
                    }
                    return self.recreate_global(wdb);
                }
            }
            None => {
                self.merror(&msg!("DB(", wdb.id, ") Error trying to find metadata table"));
                wdb.enabled = false;
                return true;
            }
        }
        if (version as usize) < updates.len() || version < 0 {
            if self.global_create_backup(wdb, &mut output, Some("-pre_upgrade")) != OS_SUCCESS {
                self.merror(&msg!("Creating pre-upgrade Global DB snapshot failed: ", cstr(&output)));
                wdb.enabled = false;
            } else {
                let mut i = version;
                while (i as i64) < updates.len() as i64 {
                    self.mdebug2(&msg!("Updating database '", wdb.id, "' to version ", i + 1));
                    let script = if i >= 0 { updates[i as usize] } else { "" };
                    if self.sql_exec(wdb, script) == OS_INVALID || self.adjust_global_upgrade(wdb, i) != 0 {
                        if self.global_restore_backup(wdb, None, false, &mut output) != OS_INVALID {
                            self.merror(&msg!(
                                "Failed to update global.db to version ",
                                i + 1,
                                ". The global.db was restored to the original state."
                            ));
                        } else {
                            self.merror(&msg!("Failed to update global.db to version ", i + 1, "."));
                            wdb.enabled = false;
                        }
                        break;
                    }
                    i += 1;
                }
            }
        }
        true
    }

    /// `wdb_backup`: back the agent database up and recreate it. False when
    /// `wdb_backup` returns NULL.
    pub fn backup(&self, wdb: &mut Wdb, version: i32) -> bool {
        let sagent_id = wdb.id.clone();
        let rel = format!("{WDB2_DIR}/{sagent_id}.db");
        if self.close(wdb, true) != -1 {
            if self.create_backup(&sagent_id, version) != -1 {
                self.mwarn(&msg!("Creating DB backup and create clear DB for agent: '", sagent_id, "'"));
                let _ = std::fs::remove_file(self.path(&rel));
                if self.create_agent_db2(&sagent_id) < 0 {
                    self.merror(&msg!("Couldn't create SQLite database for agent '", sagent_id, "'"));
                    return false;
                }
                let (rc, db) = siem_sqlite::Db::open_v2(self.path(&rel).to_string_lossy().as_bytes(), SQLITE_OPEN_READWRITE);
                if rc != SQLITE_OK {
                    let e = db.as_ref().map(|d| d.errmsg()).unwrap_or_else(|| b"out of memory".to_vec());
                    self.merror(&msg!("Can't open SQLite backup database '", rel, "': ", e));
                    wdb.db = None;
                    return false;
                }
                wdb.db = db;
            }
        } else {
            self.merror(&msg!("Couldn't create SQLite database backup for agent '", sagent_id, "'"));
        }
        true
    }

    /// `wdb_recreate_global`: false when it returns NULL.
    pub fn recreate_global(&self, wdb: &mut Wdb) -> bool {
        let rel = format!("{WDB2_DIR}/{WDB_GLOB_NAME}.db");
        let path = self.path(&rel);
        if self.close(wdb, true) != OS_INVALID {
            let _ = std::fs::remove_file(&path);
            if self.create_global(&path) != OS_SUCCESS {
                self.merror(&msg!("Couldn't create SQLite database '", rel, "'"));
                return false;
            }
            let (rc, db) = siem_sqlite::Db::open_v2(path.to_string_lossy().as_bytes(), SQLITE_OPEN_READWRITE);
            if rc != SQLITE_OK {
                let e = db.as_ref().map(|d| d.errmsg()).unwrap_or_else(|| b"out of memory".to_vec());
                self.merror(&msg!("Can't open SQLite backup database '", rel, "': ", e));
                wdb.db = None;
                return false;
            }
            wdb.db = db;
        }
        true
    }

    /// `wdb_create_backup`: copy the agent database to `<id>.db-oldv<v>-<t>`.
    pub fn create_backup(&self, agent_id: &str, version: i32) -> i32 {
        let src_rel = trunc(format!("{WDB2_DIR}/{agent_id}.db").into_bytes(), OS_FLSIZE);
        let src_rel = String::from_utf8_lossy(&src_rel).into_owned();
        let data = match std::fs::read(self.path(&src_rel)) {
            Ok(d) => d,
            Err(e) => {
                let (n, t) = errno_text(&e);
                self.merror(&msg!("Couldn't open source '", src_rel, "': ", t, " (", n, ")"));
                return -1;
            }
        };
        let dst_rel = trunc(format!("{WDB2_DIR}/{agent_id}.db-oldv{version}-{}", self.time() as u64).into_bytes(), OS_FLSIZE);
        let dst_rel = String::from_utf8_lossy(&dst_rel).into_owned();
        if let Err(e) = std::fs::write(self.path(&dst_rel), &data) {
            let (n, t) = errno_text(&e);
            self.merror(&msg!("Couldn't open dest '", dst_rel, "': ", t, " (", n, ")"));
            return -1;
        }
        set_mode(&self.path(&dst_rel), 0o640);
        0
    }

    /// `wdb_adjust_upgrade`
    fn adjust_upgrade(&self, wdb: &mut Wdb, step: usize) -> i32 {
        match step {
            3 => self.adjust_v4(wdb),
            _ => 0,
        }
    }

    /// `wdb_adjust_global_upgrade`
    fn adjust_global_upgrade(&self, wdb: &mut Wdb, step: i32) -> i32 {
        match step {
            3 => self.global_adjust_v4(wdb),
            _ => 0,
        }
    }

    /// `wdb_adjust_v4`: decode the numeric Windows attributes of fim_entry.
    fn adjust_v4(&self, wdb: &mut Wdb) -> i32 {
        if self.begin2(wdb) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") The begin statement could not be executed."));
            return -1;
        }
        if self.stmt_cache(wdb, WDB_STMT_FIM_GET_ATTRIBUTES) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") Can't cache statement: get_attributes."));
            return -1;
        }
        let get = wdb.st(WDB_STMT_FIM_GET_ATTRIBUTES);
        while self.step(&get) == SQLITE_ROW {
            let (Some(file), Some(attrs)) = (get.column_text(0), get.column_text(1)) else {
                continue;
            };
            if !attrs.first().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }
            let decoded = decode_win_attributes(atoi(&attrs) as u32);
            if self.stmt_cache(wdb, WDB_STMT_FIM_UPDATE_ATTRIBUTES) < 0 {
                self.merror(&msg!("DB(", wdb.id, ") Can't cache statement: update_attributes."));
                return -1;
            }
            let upd = wdb.st(WDB_STMT_FIM_UPDATE_ATTRIBUTES);
            upd.bind_text(1, Some(&decoded));
            upd.bind_text(2, Some(&file));
            if self.step(&upd) != SQLITE_DONE {
                self.mdebug1(&msg!("DB(", wdb.id, ") The attribute coded as ", attrs, " could not be updated."));
            }
        }
        if self.commit2(wdb) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") The commit statement could not be executed."));
            return -1;
        }
        0
    }

    /// `wdb_is_older_than_v310`
    pub fn is_older_than_v310(&self, wdb: &Wdb) -> bool {
        let (rc, st, _) = wdb.db().prepare_v2(b"SELECT COUNT(*) FROM agent WHERE id=0 AND last_keepalive=253402300799;");
        let result = match st.filter(|_| rc == SQLITE_OK) {
            None => {
                self.merror(&msg!("DB(", wdb.id, ") sqlite3_prepare_v2(): ", wdb.errmsg()));
                OS_INVALID
            }
            Some(st) => match self.step(&st) {
                SQLITE_ROW => st.column_int(0),
                SQLITE_DONE => OS_SUCCESS,
                _ => OS_INVALID,
            },
        };
        result != 1
    }
}
