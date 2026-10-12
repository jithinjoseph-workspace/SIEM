//! The threads of wazuh-db's main (wazuh_db/main.c) that do not touch the
//! local socket: gc, backup and the database upgrade, with the `running`
//! flag the signal handler clears.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::*;

/// `running`, cleared by the signal handler.
pub static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// `run_gc`
pub fn run_gc(d: Arc<Wdbd>) {
    let mut fragmentation_interval = d.cfg.check_fragmentation_interval;
    while running() {
        d.commit_old();
        if fragmentation_interval <= 0 {
            d.check_fragmentation();
            fragmentation_interval = d.cfg.check_fragmentation_interval;
        } else {
            fragmentation_interval -= 1;
        }
        d.close_old();
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// `run_backup`
pub fn run_backup(d: Arc<Wdbd>) {
    let mut last_global_backup_time = d.global_get_most_recent_backup().0;
    let global_interval = d.cfg.backup[WDB_GLOBAL_BACKUP].interval;
    let global_enabled = d.cfg.backup[WDB_GLOBAL_BACKUP].enabled;
    d.mdebug2(b"Database backup thread started.");
    while running() {
        for i in 0..WDB_LAST_BACKUP {
            if i == WDB_GLOBAL_BACKUP && global_enabled {
                let current_time = d.time();
                if current_time - last_global_backup_time >= global_interval {
                    let mut output: B = Vec::new();
                    if let Some(mut wdb) = d.open_global() {
                        if wdb.enabled && d.global_create_backup(&mut wdb, &mut output, None) != OS_SUCCESS {
                            d.merror(&msg!("Creating Global DB snapshot by interval failed: ", cstr(&output)));
                        }
                        last_global_backup_time = current_time;
                        d.leave(wdb);
                    } else {
                        last_global_backup_time = current_time;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// `run_up`: open (and upgrade) every agent database, one per second.
pub fn run_up(d: Arc<Wdbd>) {
    let db_folder = WDB2_DIR;
    let rd = match std::fs::read_dir(d.path(db_folder)) {
        Ok(r) => r,
        Err(e) => {
            let (_, t) = errno_text(&e);
            d.mdebug1(&msg!("Opening directory: '", db_folder, "': ", t));
            return;
        }
    };
    for e in rd.flatten() {
        if !running() {
            break;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name == ".template.db" || name == "000.db" || name.contains('-') {
            continue;
        }
        let Some(dot) = name.find('.') else {
            continue;
        };
        if let Some(wdb) = d.open_agent2(super::atoi(name[..dot].as_bytes())) {
            d.leave(wdb);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
