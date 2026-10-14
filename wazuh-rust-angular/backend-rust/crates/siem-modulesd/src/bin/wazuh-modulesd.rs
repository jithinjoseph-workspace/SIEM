//! `wazuh-modulesd` (wazuh_modules/main.c): `wazuh-modulesd -[dfht]`.
//!
//! Runs the ported manager modules: `database` (from the `wazuh_database.*`
//! internal options).

use std::path::PathBuf;
use std::sync::Arc;

use siem_log::WLog;
use siem_modulesd::database::{wm_database_read, Database};

const ARGV0: &str = "wazuh-modulesd";

fn print_out(s: &str) {
    eprintln!("{s}");
}

/// `wm_help`
fn wm_help() -> ! {
    print_out(" ");
    print_out("Wazuh v4.14.7 - Wazuh Inc. (info@wazuh.com)");
    print_out("http://www.wazuh.com");
    print_out(&format!("  {ARGV0}: -[Vhdtf]"));
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -f          Run in foreground");
    print_out("    -h          This help message");
    print_out("    -t          Test configuration");
    print_out(" ");
    std::process::exit(1);
}

fn early_exit(msg: &str) -> ! {
    let ts = siem_log::timestamp(chrono::Local::now());
    eprintln!("{ts} {ARGV0}: CRITICAL: {msg}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    // Define current working directory
    let home_path = match siem_daemon::homedir(&argv0) {
        Ok(h) => h,
        Err(e) => early_exit(e),
    };
    if let Err(e) = std::env::set_current_dir(&home_path) {
        let n = e.raw_os_error().unwrap_or(0);
        early_exit(&format!(
            "(1133): Unable to chdir to directory '{}' due to [({n})-({})].",
            home_path.display(),
            siem_modulesd::wdb::errno_text(&e)
        ));
    }
    let base = PathBuf::new();
    let log = Arc::new(WLog::new_server(ARGV0, &base));
    let opts = siem_config::internal_options::InternalOptions::from_home(&base);
    let wm_debug_level = match opts.get_int("wazuh_modules", "debug", 0, 2) {
        Ok(v) => v,
        Err(e) => {
            log.critical(e.0.as_bytes());
            std::process::exit(1);
        }
    };

    // getopt(argc, argv, "dfht")
    let mut wm_debug = 0;
    let mut test_config = false;
    let mut foreground = false;
    for a in std::env::args().skip(1) {
        if !a.starts_with('-') || a == "-" || a == "--" {
            break;
        }
        for c in a[1..].chars() {
            match c {
                'd' => {
                    log.now_debug();
                    wm_debug = 1;
                }
                'f' => foreground = true,
                'h' => wm_help(),
                't' => {
                    test_config = true;
                    foreground = true;
                }
                _ => {
                    print_out(" ");
                    wm_help();
                }
            }
        }
    }
    if wm_debug == 0 {
        for _ in 0..wm_debug_level {
            log.now_debug();
        }
    }
    log.debug1(format!("Wazuh home directory: {}", home_path.display()));

    let nofile = match opts.get_int("wazuh_modules", "rlimit_nofile", 8192, 1048576) {
        Ok(v) => v,
        Err(e) => {
            log.critical(e.0.as_bytes());
            std::process::exit(1);
        }
    };
    if let Err(m) = siem_daemon::set_nofile(nofile as u64) {
        log.error(m.as_bytes());
    }

    // wm_setup: wm_config (the database module on the manager)
    let database = match wm_database_read(&opts) {
        Ok(d) => d,
        Err(e) => {
            log.critical(e.as_bytes());
            std::process::exit(1);
        }
    };
    if !foreground {
        siem_daemon::go_daemon(&log);
        log.now_daemon();
    }
    let Some(database) = database else {
        log.info("No configuration defined. Exiting...");
        std::process::exit(0);
    };
    if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
        log.critical("Couldn't create PID file: (Permission denied)");
        std::process::exit(1);
    }
    if test_config {
        std::process::exit(0);
    }
    log.info(format!("Started (pid: {}).", std::process::id()));

    let db: Arc<dyn siem_ipc::wdbc::WdbQuery> = Arc::new(siem_ipc::wdbc::WdbcSocket::new(siem_modulesd::wdb::WDB_LOCAL_SOCK));
    log.debug2("Created new thread for the 'database' module.");
    Database::new(database, log.clone(), db).main().await;
    siem_daemon::delete_pid(ARGV0, &log);
}
