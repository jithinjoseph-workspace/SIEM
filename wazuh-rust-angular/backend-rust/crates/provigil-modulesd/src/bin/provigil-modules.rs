//! `provigil-modulesd [-d] [-f] [-t] [-h]` (named `provigil-modules` until the old service is
//! retired): the router, the vulnerability scanner and the database module, run by siem-api from
//! the manager home folder. `-d` more logging (twice for the most), `-f` foreground (always),
//! `-t` check the settings and stop, `-h` help.

use std::path::PathBuf;
use std::sync::Arc;

use provigil_daemon::{Log, Options};
use provigil_ipc::agentdb::{AgentDb, DbClient};
use provigil_modulesd::{database, host, router};

const NAME: &str = "provigil-modulesd";

fn help() -> ! {
    eprintln!(" ");
    eprintln!("  {NAME}: -[dfht]");
    eprintln!("    -d          More logging; give it twice for the most.");
    eprintln!("    -f          Run in the foreground (always).");
    eprintln!("    -h          This help.");
    eprintln!("    -t          Check the settings and stop.");
    eprintln!(" ");
    std::process::exit(1);
}

/// Raises the open-files limit (Unix; Windows has no such limit).
#[cfg(unix)]
fn set_nofile(n: u64) -> Result<(), String> {
    let lim = libc::rlimit { rlim_cur: n as libc::rlim_t, rlim_max: n as libc::rlim_t };
    // SAFETY: a plain system call on a local value.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } == 0 {
        Ok(())
    } else {
        Err(format!("Could not set resource limit for file descriptors to {n}: {}", std::io::Error::last_os_error()))
    }
}
#[cfg(not(unix))]
fn set_nofile(_: u64) -> Result<(), String> {
    Ok(())
}

fn main() {
    let (mut debug, mut test_only) = (0u8, false);
    for a in std::env::args().skip(1) {
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty() && *f != "-") else { break };
        for c in flags.chars() {
            match c {
                'd' => debug += 1,
                'f' => {}
                't' => test_only = true,
                _ => help(),
            }
        }
    }
    let home = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let log = Arc::new(Log::open(&home, NAME));
    let opts = Options::read(&home);
    let fail = |e: String| -> ! {
        log.critical(e);
        std::process::exit(1);
    };
    let level = opts.int("provigil_modules", "debug", 0, 0, 2).unwrap_or_else(|e| fail(e));
    log.set_debug(if debug > 0 { debug } else { level as u8 });
    log.debug(format!("ProVigil home directory: {}", home.display()));
    let nofile = opts.int("provigil_modules", "rlimit_nofile", 8192, 8192, 1_048_576).unwrap_or_else(|e| fail(e));
    if let Err(e) = set_nofile(nofile as u64) {
        log.error(e);
    }
    let db_settings = database::Settings::read(&opts).unwrap_or_else(|e| fail(e));
    // the scanner reads max_eps itself; a bad value stops the service
    opts.int("provigil_modules", "max_eps", 100, 1, 1000).unwrap_or_else(|e| fail(e));
    if test_only {
        std::process::exit(0);
    }
    let _pid_file = provigil_daemon::create_pid(&home, NAME).unwrap_or_else(|e| fail(format!("Couldn't create PID file: ({e})")));
    log.info(format!("Started (pid: {}).", std::process::id()));

    let router = router::Router::new(&home, log.clone());
    log.tagged(router::TAG, "INFO", "Loaded router module.");
    log.tagged(router::TAG, "INFO", "Starting router module.");
    if let Err(e) = router.start() {
        log.tagged(router::TAG, "ERROR", format!("Couldn't open the router's registration socket: {e}"));
    }
    let _scanner = host::start(&home, log.clone(), router.clone());

    let db: Arc<dyn AgentDb> = Arc::new(DbClient::new(&home));
    let database = db_settings.map(|s| {
        let d = database::Database::new(s, log.clone(), db.clone(), &home);
        log.debug2("Created new thread for the 'database' module.");
        std::thread::Builder::new().name("database".into()).spawn(move || d.run())
    });
    match database {
        Some(Ok(t)) => {
            let _ = t.join();
        }
        Some(Err(e)) => log.error(format!("Couldn't create the database module's thread: {e}")),
        None => {}
    }
    // the router and the scanner run on their own threads until siem-api ends the process
    loop {
        std::thread::park();
    }
}
