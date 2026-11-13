//! Background work of the database service (spec § 1.6–1.8): idle commits, fragmentation
//! checks with vacuum, closing databases beyond the open limit, the scheduled global backup and
//! opening every agent database once at start (which applies the layout check).

use std::sync::Arc;

use siem_cjson::Json;
use siem_sqlite::{SQLITE_DONE, SQLITE_OK};

use crate::text::read_long;
use crate::{Engine, Handle, DB_DIR, GLOBAL_NAME, INVALID};

impl Engine {
    /// The open handles, in name order.
    fn handles(&self) -> Vec<(String, Arc<parking_lot::Mutex<Handle>>)> {
        let mut v: Vec<_> = self.dbs.lock().iter().map(|(k, h)| (k.clone(), h.clone())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// One second of the maintenance loop. `countdown` counts the seconds to the next
    /// fragmentation check.
    pub fn maintenance_tick(&self, countdown: &mut i64) {
        self.commit_old();
        if *countdown <= 0 {
            self.check_fragmentation();
            *countdown = self.settings.check_fragmentation_interval;
        } else {
            *countdown -= 1;
        }
        self.close_old();
    }

    /// Vacuums databases that are fragmented enough (and have enough free pages).
    pub fn check_fragmentation(&self) {
        let s = &self.settings;
        for (_, h) in self.handles() {
            let mut h = h.lock();
            if h.db.is_none() {
                continue;
            }
            let id = h.id.clone();
            let (frag, free) = (self.fragmentation(&h), self.free_pages_percentage(&h));
            if frag == INVALID || free == INVALID {
                self.error(cat!("Couldn't get current state for the database '", id, "'"));
                continue;
            }
            let Some((last_time, last_value)) = self.last_vacuum(&h) else {
                self.error(cat!("Couldn't get last vacuum info for the database '", id, "'"));
                continue;
            };
            let due = free >= s.free_pages_percentage
                && (frag > s.max_fragmentation || (frag > s.fragmentation_threshold && (last_time == 0 || (last_time > 0 && frag > last_value + s.fragmentation_delta))));
            if !due {
                continue;
            }
            if !self.commit(&mut h) {
                self.error(cat!("Couldn't execute commit statement, before vacuum, for the database '", id, "'"));
                continue;
            }
            h.drop_statements();
            let vacuumed = {
                let (rc, st, _) = h.db().prepare_v2(b"VACUUM;");
                match st.filter(|_| rc == SQLITE_OK) {
                    Some(st) => self.step(&st) == SQLITE_DONE,
                    None => {
                        self.debug(cat!("SQLite: ", h.errmsg()));
                        false
                    }
                }
            };
            if !vacuumed {
                self.error(cat!("Couldn't execute vacuum for the database '", id, "'"));
                continue;
            }
            // shortcut: the time is not measured (always 0.000 ms), add a clock to Env if it is needed
            self.debug(cat!("Vacuum executed on the '", id.clone(), "' database. Time: 0.000 ms."));
            let after = self.fragmentation(&h);
            if after == INVALID {
                self.error(cat!("Couldn't get fragmentation after vacuum for the database '", id, "'"));
                continue;
            }
            let (t, v) = (self.time().to_string(), after.to_string());
            if !self.store_vacuum(&h, t.as_bytes(), v.as_bytes()) {
                self.error(cat!("Couldn't update last vacuum info for the database '", id.clone(), "'"));
            }
            if after >= frag {
                self.warn(cat!("After vacuum, the database '", id, "' has become just as fragmented or worse"));
            }
        }
    }

    /// (time, fragmentation) of the last vacuum; (0, 0) when there was none.
    fn last_vacuum(&self, h: &Handle) -> Option<(i32, i32)> {
        let data = self.sql(h, b"SELECT key, value FROM metadata WHERE key in ('last_vacuum_time', 'last_vacuum_value');")?;
        let Json::Array(items) = &data else { return None };
        if items.is_empty() {
            self.debug2(b"No vacuum data in metadata table.".to_vec());
            return Some((0, 0));
        }
        let (mut t, mut v) = (-1, -1);
        for item in items {
            match (item.get("key"), item.get("value")) {
                (Some(k), Some(val)) => {
                    let n = read_long(val.as_bytes().unwrap_or(b"")).0 as i32;
                    match k.as_bytes().unwrap_or(b"") {
                        b"last_vacuum_time" => t = n,
                        b"last_vacuum_value" => v = n,
                        _ => {}
                    }
                }
                _ => self.error(b"It was not possible to get key or value from database response.".to_vec()),
            }
        }
        if t != -1 && v != -1 {
            Some((t, v))
        } else {
            self.error(b"Missing field last_vacuum_time or last_vacuum_value from metadata table.".to_vec());
            None
        }
    }

    /// Closes idle databases while more than the open limit are kept (never the global one),
    /// then forgets closed handles nobody uses.
    pub fn close_old(&self) {
        let mut dbs = self.handles();
        let total = dbs.len();
        let mut closed = 0usize;
        for (_, h) in &dbs {
            if total - closed <= self.settings.open_db_limit {
                break;
            }
            let mut g = h.lock();
            // in use: the list, this loop and any request holding it
            let idle = Arc::strong_count(h) == 2;
            if g.db.is_some() && idle && g.id != GLOBAL_NAME {
                self.debug2(cat!("Closing database for agent ", g.id.clone()));
                self.close(&mut g, true);
                closed += 1;
            }
        }
        dbs.clear();
        self.dbs.lock().retain(|_, h| Arc::strong_count(h) > 1 || h.try_lock().is_none_or(|g| g.db.is_some()));
    }

    /// The modification time of the newest global backup (-1 when none or unreadable).
    pub fn newest_backup_time(&self) -> i64 {
        match self.backup_names() {
            None => {
                self.debug(cat!("Unable to open backup directory '", crate::BACKUP_DIR, "'"));
                -1
            }
            Some(v) => v.into_iter().filter_map(|(_, t)| t).fold(-1, i64::max),
        }
    }

    /// One second of the backup loop: a global backup when `backup_interval` has passed since
    /// `last` (start it with [`Engine::newest_backup_time`]).
    pub fn backup_tick(&self, last: &mut i64) {
        if !self.settings.backup_enabled {
            return;
        }
        let now = self.time();
        if now - *last < self.settings.backup_interval {
            return;
        }
        if let Some(mut h) = self.open_global() {
            if h.enabled {
                let (r, out) = self.create_backup(&mut h, "");
                if r != crate::OK {
                    self.error(cat!("Creating Global DB snapshot by interval failed: ", crate::text::until_nul(&out)));
                }
            }
        }
        *last = now;
    }

    /// Opens every agent database once, one per second, while `running` says so.
    pub fn open_all_agents(&self, running: &dyn Fn() -> bool) {
        let dir = match std::fs::read_dir(self.path(DB_DIR)) {
            Ok(d) => d,
            Err(e) => {
                self.debug(cat!("Opening directory: '", DB_DIR, "': ", crate::agent::os_text(&e)));
                return;
            }
        };
        for e in dir.flatten() {
            if !running() {
                break;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            if name == ".template.db" || name == "000.db" || name.contains('-') {
                continue;
            }
            let Some(dot) = name.find('.') else { continue };
            // removed since the listing: not created again empty
            if !self.path(&format!("{DB_DIR}/{name}")).exists() {
                continue;
            }
            let id = read_long(&name.as_bytes()[..dot]).0 as i32;
            drop(self.open_agent(id));
            self.env.sleep_ms(1000);
        }
    }
}
