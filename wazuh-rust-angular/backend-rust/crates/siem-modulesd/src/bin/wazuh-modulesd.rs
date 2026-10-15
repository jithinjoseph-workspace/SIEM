//! `wazuh-modulesd` (wazuh_modules/main.c): `wazuh-modulesd -[dfht]`.
//!
//! Runs the ported manager modules, in the C list order: `agent-upgrade` and
//! `task-manager` (default modules, read again from `<agent-upgrade>` /
//! `<task-manager>` in ossec.conf), `database` and `download` (internal
//! options).

use std::path::PathBuf;
use std::sync::Arc;

use siem_config::{read_config, ConfigContext, ConfigError, ConfigHandler, Platform, Section};
use siem_log::WLog;
use siem_modulesd::database::{wm_database_read, Database};
use siem_modulesd::{agent_upgrade, download, task_manager};
use siem_xml::{OsXml, XmlNode};

/// The `<agent-upgrade>` and `<task-manager>` sections (`Read_AgentUpgrade`, `Read_TaskManager`).
/// shortcut: the other wodles of a manager ossec.conf are not read until their modules are ported.
struct Handler<'a> {
    up: &'a mut agent_upgrade::Config,
    tm: &'a mut task_manager::Config,
}

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, _xml: &OsXml, section: Section, node: &XmlNode, children: Option<&[XmlNode]>) -> siem_config::Result<()> {
        if !matches!(section, Section::AgentUpgrade | Section::TaskManager) {
            return Ok(());
        }
        if children.is_none() {
            ctx.debug1(format!("Empty configuration for module '{}'", node.element));
        }
        let r = if section == Section::AgentUpgrade { agent_upgrade::read(ctx, children, self.up) } else { task_manager::read(ctx, children, self.tm) };
        r.map_err(|_| ConfigError::new(""))
    }
}

/// The configuration readers' messages, in order.
fn flush(log: &WLog, ctx: &mut ConfigContext) {
    for (lv, m) in ctx.log.drain(..) {
        match lv {
            siem_config::LogLevel::Debug1 => log.debug1(m),
            siem_config::LogLevel::Debug2 => log.debug2(m),
            siem_config::LogLevel::Info => log.info(m),
            siem_config::LogLevel::Warn => log.warn(m),
            siem_config::LogLevel::Error => log.error(m),
        }
    }
}

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

    // wm_setup: wm_config. wm_initialize_default_modules: agent-upgrade, task-manager
    let mut up = agent_upgrade::Config::default();
    let mut tm = task_manager::Config::default();
    let mut ctx = ConfigContext::new(Platform::MANAGER);
    let r = read_config(&mut ctx, siem_config::modules::CWMODULE, "etc/ossec.conf", None, &mut Handler { up: &mut up, tm: &mut tm });
    flush(&log, &mut ctx);
    if r.is_err() {
        std::process::exit(1);
    }
    let database = match wm_database_read(&opts) {
        Ok(d) => d,
        Err(e) => {
            log.critical(e.as_bytes());
            std::process::exit(1);
        }
    };
    let download_enabled = match opts.get_int("wazuh_download", "enabled", 0, 1) {
        Ok(v) => v != 0,
        Err(e) => {
            log.critical(e.0.as_bytes());
            std::process::exit(1);
        }
    };
    if !foreground {
        siem_daemon::go_daemon(&log);
        log.now_daemon();
    }
    if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
        log.critical("Couldn't create PID file: (Permission denied)");
        std::process::exit(1);
    }
    if test_config {
        std::process::exit(0);
    }
    log.info(format!("Started (pid: {}).", std::process::id()));

    let db: Arc<dyn siem_ipc::wdbc::WdbQuery> = Arc::new(siem_ipc::wdbc::WdbcSocket::new(siem_modulesd::wdb::WDB_LOCAL_SOCK));
    let mut threads = Vec::new();
    let m = Arc::new(agent_upgrade::UpgradeManager::new(up, log.clone(), db.clone()));
    threads.push(tokio::spawn(m.main()));
    log.debug2(format!("Created new thread for the '{}' module.", agent_upgrade::NAME));
    let m = Arc::new(task_manager::TaskManager::new(tm, log.clone(), db.clone()));
    threads.push(tokio::spawn(m.main()));
    log.debug2(format!("Created new thread for the '{}' module.", task_manager::NAME));
    if let Some(database) = database {
        let d = Database::new(database, log.clone(), db.clone());
        threads.push(tokio::spawn(async move { d.main().await }));
        log.debug2("Created new thread for the 'database' module.");
    }
    let m = Arc::new(download::Download::new(download_enabled, log.clone()));
    threads.push(tokio::spawn(m.main()));
    log.debug2("Created new thread for the 'download' module.");
    // pthread_join of every module thread
    for t in threads {
        let _ = t.await;
    }
    siem_daemon::delete_pid(ARGV0, &log);
}
