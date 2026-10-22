//! `wazuh-db` (wazuh_db/main.c `main`): `wazuh-db -[Vhdtf]`.

#[cfg(not(target_os = "linux"))]
fn main() {
    portable::main()
}

/// The manager on other hosts: the same start-up without the router, the
/// HTTP API, privilege separation or epoll (see `daemon_portable`).
#[cfg(not(target_os = "linux"))]
mod portable {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use siem_log::WLog;
    use siem_wdb::wdb::config::{LoadError, WdbDaemonConfig};
    use siem_wdb::wdb::daemon_portable::*;
    use siem_wdb::wdb::threads::{run_backup, run_gc, run_up};
    use siem_wdb::wdb::*;

    const ARGV0: &str = "wazuh-db";
    const OSSECCONF: &str = "etc/ossec.conf";

    fn early_exit(msg: &str) -> ! {
        let ts = siem_log::timestamp(chrono::Local::now());
        eprintln!("{ts} {ARGV0}: CRITICAL: {msg}");
        std::process::exit(1);
    }

    pub fn main() {
        let argv0 = std::env::args().next().unwrap_or_default();
        let home_path = match siem_daemon::homedir(&argv0) {
            Ok(h) => h,
            Err(e) => early_exit(e),
        };
        if let Err(e) = std::env::set_current_dir(&home_path) {
            let (n, t) = errno_text(&e);
            early_exit(&format!("(1133): Unable to chdir to directory '{}' due to [({n})-({t})].", home_path.display()));
        }
        let base = PathBuf::new();
        let wlog = Arc::new(WLog::new_server(ARGV0, &base));
        let mut test_config = false;
        for a in std::env::args().skip(1) {
            if !a.starts_with('-') || a == "-" || a == "--" {
                break;
            }
            for c in a[1..].chars() {
                match c {
                    'd' => wlog.now_debug(),
                    't' => test_config = true,
                    'f' => {}
                    _ => {
                        eprintln!("{ARGV0}: invalid option -- '{c}'");
                        std::process::exit(1);
                    }
                }
            }
        }
        let conf = match WdbDaemonConfig::load(&base, Path::new(OSSECCONF)) {
            Ok(c) => c,
            Err(LoadError::Internal(e)) => {
                wlog.critical(e.0.as_bytes());
                std::process::exit(1);
            }
            Err(LoadError::Config(e)) => {
                wlog.error(e.0.as_bytes());
                wlog.critical("Invalid configuration block for Wazuh-DB.");
                std::process::exit(1);
            }
        };
        for w in &conf.warnings {
            wlog.warn(w.as_bytes());
        }
        if wlog.is_debug() == 0 {
            for _ in 0..conf.debug {
                wlog.now_debug();
            }
        }
        wlog.debug1(format!("Wazuh home directory: {}", home_path.display()));
        if test_config {
            std::process::exit(0);
        }
        let path_template = home_path.join(WDB2_DIR).join(WDB_PROF_NAME);
        let _ = std::fs::remove_file(&path_template);
        wlog.debug1(format!("Template file removed: {}", path_template.display()));
        if siem_daemon::create_pid(ARGV0, std::process::id(), &wlog).is_err() {
            wlog.critical("(1212): Unable to create PID file.");
            std::process::exit(1);
        }
        wlog.info(format!("Started (pid: {}).", std::process::id()));

        #[cfg(windows)]
        siem_wdb::wdb::router::router_initialize(wlog.clone());
        let env = Arc::new(PortableEnv::new(wlog.clone(), PathBuf::from(OSSECCONF)));
        #[allow(unused_mut)]
        let mut d = Wdbd::new(conf.wdb.clone(), base.clone(), env.clone());
        // Router providers (the Linux daemon does the same)
        #[cfg(windows)]
        {
            use siem_wdb::wdb::router::{WDB_AGENT_EVENTS_TOPIC, WDB_INVENTORY_EVENTS_TOPIC};
            d.router_agent = env.router.create(WDB_AGENT_EVENTS_TOPIC);
            if !d.router_agent {
                wlog.debug2("Failed to create router handle for 'wdb-agent-events'.");
            }
            d.router_inventory = env.router.create(WDB_INVENTORY_EVENTS_TOPIC);
            if !d.router_inventory {
                wlog.debug2("Failed to create router handle for 'wdb-inventory-events'.");
            }
        }
        d.state.set_uptime(d.time());
        d.create_profile();
        let d = Arc::new(d);

        let dealer = {
            let (d, e) = (d.clone(), env.clone());
            std::thread::Builder::new().name("run_dealer".into()).spawn(move || run_dealer(d, e))
        };
        let gc = {
            let dd = d.clone();
            std::thread::Builder::new().name("run_gc".into()).spawn(move || run_gc(dd))
        };
        let up = {
            let dd = d.clone();
            std::thread::Builder::new().name("run_up".into()).spawn(move || run_up(dd))
        };
        let (Ok(dealer), Ok(gc), Ok(up)) = (dealer, gc, up) else {
            wlog.error("Couldn't create threads: Resource temporarily unavailable");
            siem_daemon::delete_pid(ARGV0, &wlog);
            std::process::exit(1);
        };
        let backup = d.check_backup_enabled().then(|| {
            let dd = d.clone();
            std::thread::spawn(move || run_backup(dd))
        });
        let _ = dealer.join();
        let _ = up.join();
        let _ = gc.join();
        if let Some(b) = backup {
            let _ = b.join();
        }
        d.close_all();
        wlog.info("Graceful process shutdown.");
        siem_daemon::delete_pid(ARGV0, &wlog);
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use parking_lot::Mutex;
    use siem_log::WLog;
    use siem_wdb::wdb::config::{LoadError, WdbDaemonConfig};
    use siem_wdb::wdb::daemon::*;
    use siem_wdb::wdb::*;

    const ARGV0: &str = "wazuh-db";
    const USER: &str = "wazuh";
    const GROUPGLOBAL: &str = "wazuh";
    const OSSECCONF: &str = "etc/ossec.conf";

    fn print_out(s: &str) {
        eprintln!("{s}");
    }

    /// `print_header`
    fn print_header() {
        print_out("");
        print_out("Wazuh v4.14.7 - Wazuh Inc. (info@wazuh.com)");
        print_out("http://www.wazuh.com");
        print_out("");
    }

    /// `print_version`
    fn print_version() -> ! {
        print_out("");
        print_out("Wazuh v4.14.7 - Wazuh Inc.");
        print_out("");
        print_out(
            "This program is free software; you can redistribute it and/or modify\n\
             it under the terms of the GNU General Public License (version 2) as \n\
             published by the Free Software Foundation. For more details, go to \n\
             https://www.gnu.org/licenses/gpl.html\n",
        );
        std::process::exit(0);
    }

    /// `wdb_help`
    fn wdb_help() -> ! {
        print_header();
        print_out(&format!("  {ARGV0}: -[Vhdtf]"));
        print_out("    -V          Version and license message.");
        print_out("    -h          This help message.");
        print_out("    -d          Debug mode. Use this parameter multiple times to increase the debug level.");
        print_out("    -t          Test configuration.");
        print_out("    -f          Run in foreground.");
        std::process::exit(0);
    }

    /// `merror_exit` before the logger exists.
    fn early_exit(msg: &str) -> ! {
        let ts = siem_log::timestamp(chrono::Local::now());
        eprintln!("{ts} {ARGV0}: CRITICAL: {msg}");
        std::process::exit(1);
    }

    pub fn main() {
        let argv0 = std::env::args().next().unwrap_or_default();
        // Define current working directory
        let home_path = match siem_daemon::homedir(&argv0) {
            Ok(h) => h,
            Err(e) => early_exit(e),
        };
        if let Err(e) = std::env::set_current_dir(&home_path) {
            let (n, t) = errno_text(&e);
            early_exit(&format!("(1133): Unable to chdir to directory '{}' due to [({n})-({t})].", home_path.display()));
        }
        let base = PathBuf::new();
        let wlog = Arc::new(WLog::new(ARGV0, &base));

        // Get options: getopt(argc, argv, "Vdhtf")
        let mut test_config = false;
        let mut run_foreground = false;
        for a in std::env::args().skip(1) {
            if !a.starts_with('-') || a == "-" {
                break;
            }
            if a == "--" {
                break;
            }
            for c in a[1..].chars() {
                match c {
                    'V' => print_version(),
                    'h' => wdb_help(),
                    'd' => wlog.now_debug(),
                    't' => test_config = true,
                    'f' => run_foreground = true,
                    _ => {
                        eprintln!("{ARGV0}: invalid option -- '{c}'");
                        wdb_help();
                    }
                }
            }
        }

        // Read internal options, wdb_init_conf and ossec.conf
        let conf = match WdbDaemonConfig::load(&base, Path::new(OSSECCONF)) {
            Ok(c) => c,
            Err(LoadError::Internal(e)) => {
                wlog.critical(e.0.as_bytes());
                std::process::exit(1);
            }
            Err(LoadError::Config(e)) => {
                wlog.error(e.0.as_bytes());
                wlog.critical("Invalid configuration block for Wazuh-DB.");
                std::process::exit(1);
            }
        };
        for w in &conf.warnings {
            wlog.warn(w.as_bytes());
        }
        if wlog.is_debug() == 0 {
            for _ in 0..conf.debug {
                wlog.now_debug();
            }
        }
        wlog.debug1(format!("Wazuh home directory: {}", home_path.display()));
        if test_config {
            std::process::exit(0);
        }

        // Initialize variables (wdb_pool_init is the Wdbd pool)
        if !run_foreground {
            siem_daemon::go_daemon(&wlog);
            wlog.now_daemon();
        }

        // Reset template: remove queue/db/.template.db (not yet chrooted)
        let path_template = home_path.join(WDB2_DIR).join(WDB_PROF_NAME);
        let _ = std::fs::remove_file(&path_template);
        wlog.debug1(format!("Template file removed: {}", path_template.display()));

        // Set max open files limit
        if let Err(m) = siem_daemon::set_nofile(conf.nofile as u64) {
            wlog.error(m.as_bytes());
        }

        // Set user and group, change root
        if let Err(m) = siem_daemon::privsep(USER, GROUPGLOBAL, &home_path, true) {
            wlog.critical(m.as_bytes());
            std::process::exit(1);
        }

        // Signal manipulation
        install_signals(wlog.clone());

        // Create PID file
        if siem_daemon::create_pid(ARGV0, std::process::id(), &wlog).is_err() {
            wlog.critical("(1212): Unable to create PID file.");
            std::process::exit(1);
        }
        let exit_log = wlog.clone();
        let cleanup = move || siem_daemon::delete_pid(ARGV0, &exit_log);

        wlog.info(format!("Started (pid: {}).", std::process::id()));

        // Router module logging initialization and providers
        router_initialize(wlog.clone());
        let router: Arc<dyn RouterSink> = Arc::new(WazuhRouter::default());
        let env = Arc::new(DaemonEnv { log: wlog.clone(), router: router.clone(), ossecconf: PathBuf::from(OSSECCONF) });
        let mut d = Wdbd::new(conf.wdb.clone(), base.clone(), env);
        d.router_agent = router.create(WDB_AGENT_EVENTS_TOPIC);
        if !d.router_agent {
            wlog.debug2("Failed to create router handle for 'wdb-agent-events'.");
        }
        d.router_inventory = router.create(WDB_INVENTORY_EVENTS_TOPIC);
        if !d.router_inventory {
            wlog.debug2("Failed to create router handle for 'wdb-inventory-events'.");
        }

        let Some(notify) = Notify::init() else {
            let e = std::io::Error::last_os_error();
            let (n, t) = errno_text(&e);
            wlog.critical(format!("at run_dealer(): wnotify_init(): {t} ({n})"));
            cleanup();
            std::process::exit(1);
        };
        let notify = Arc::new(notify);

        // Global stats uptime
        d.state.set_uptime(d.time());
        // Create template
        d.create_profile();
        let d = Arc::new(d);

        // Start threads
        let dealer = {
            let (d, n) = (d.clone(), notify.clone());
            std::thread::Builder::new().name("run_dealer".into()).spawn(move || run_dealer(d, n))
        };
        let Ok(dealer) = dealer else {
            wlog.error("Couldn't create 'run_dealer' thread: Resource temporarily unavailable");
            cleanup();
            std::process::exit(1);
        };

        let api = siem_wdb::wdb::http::start_api(d.clone(), wlog.clone() as Arc<dyn siem_wdb::wdb::http::ApiLog>);

        let queue_mutex = Arc::new(Mutex::new(()));
        let mut workers = Vec::new();
        for i in 0..d.cfg.worker_pool_size {
            let (dd, n, q) = (d.clone(), notify.clone(), queue_mutex.clone());
            match std::thread::Builder::new().name("run_worker".into()).spawn(move || run_worker(dd, n, q)) {
                Ok(h) => workers.push(h),
                Err(e) => {
                    wlog.error(format!("Couldn't create 'run_worker' {} thread: {e}", i + 1));
                    cleanup();
                    std::process::exit(1);
                }
            }
        }
        let gc = {
            let dd = d.clone();
            std::thread::Builder::new().name("run_gc".into()).spawn(move || run_gc(dd))
        };
        let up = {
            let dd = d.clone();
            std::thread::Builder::new().name("run_up".into()).spawn(move || run_up(dd))
        };
        let (Ok(gc), Ok(up)) = (gc, up) else {
            wlog.error("Couldn't create 'run_gc' thread: Resource temporarily unavailable");
            cleanup();
            std::process::exit(1);
        };
        let backups_enabled = d.check_backup_enabled();
        let backup = if backups_enabled {
            let dd = d.clone();
            match std::thread::Builder::new().name("run_backup".into()).spawn(move || run_backup(dd)) {
                Ok(h) => Some(h),
                Err(e) => {
                    wlog.error(format!("Couldn't create 'run_backup' thread: {e}"));
                    cleanup();
                    std::process::exit(1);
                }
            }
        } else {
            None
        };

        // Join threads
        let _ = dealer.join();
        for w in workers {
            let _ = w.join();
        }
        if let Some(api) = api {
            api.stop();
        }
        drop(notify);
        let _ = up.join();
        let _ = gc.join();
        if let Some(b) = backup {
            let _ = b.join();
        }
        d.close_all();

        // Reset template again (chrooted now)
        let path_template = format!("{WDB2_DIR}/{WDB_PROF_NAME}");
        let _ = std::fs::remove_file(&path_template);
        wlog.debug1(format!("Template file removed again: {path_template}"));
        wlog.info("Graceful process shutdown.");
        cleanup();
    }
}
