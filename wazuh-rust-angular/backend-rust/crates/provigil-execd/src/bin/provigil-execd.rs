//! `provigil-execd -[Vhdtf] [-g group] [-c config] [-D home]`: the manager's active responses
//! (see the crate notes). siem-api runs it on Linux with `-f -D <home>`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use provigil_daemon::{privs, Log, Options};
use provigil_execd::settings::Outcome;
use provigil_execd::{Execd, CONF, DISABLED, EXEC_QUEUE, NAME};

const GROUP: &str = "provigil";

fn help() -> ! {
    for l in [
        " ".to_string(),
        format!("  {NAME}: -[Vhdtf] [-g group] [-c config] [-D home]"),
        "    -V          Version".into(),
        "    -h          This help".into(),
        "    -d          More logging; give it twice for the most".into(),
        "    -t          Check the settings and stop".into(),
        "    -f          Run in the foreground".into(),
        format!("    -g <group>  Group to run as when started as root (default: {GROUP})"),
        format!("    -c <config> Settings file (default: {CONF})"),
        "    -D <home>   Manager home folder (default: the current folder)".into(),
        " ".into(),
    ] {
        eprintln!("{l}");
    }
    std::process::exit(1);
}

struct Args {
    debug: u8,
    test: bool,
    foreground: bool,
    group: String,
    conf: String,
    home: Option<PathBuf>,
}

fn args() -> Args {
    let mut a = Args { debug: 0, test: false, foreground: false, group: GROUP.into(), conf: CONF.into(), home: None };
    let list: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < list.len() {
        let Some(flags) = list[i].strip_prefix('-').filter(|f| !f.is_empty() && *f != "-") else { break };
        let chars: Vec<char> = flags.chars().collect();
        for (k, c) in chars.iter().enumerate() {
            match c {
                'V' => {
                    eprintln!("\nProVigil {NAME} {}\n", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                'h' => help(),
                'd' => a.debug += 1,
                't' => a.test = true,
                'f' => a.foreground = true,
                'g' | 'c' | 'D' => {
                    let rest: String = chars[k + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        list.get(i).cloned().unwrap_or_else(|| help())
                    };
                    match c {
                        'g' => a.group = v,
                        'c' => a.conf = v,
                        _ => a.home = Some(v.into()),
                    }
                    break;
                }
                _ => help(),
            }
        }
        i += 1;
    }
    a
}

fn main() {
    let a = args();
    let home = a.home.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    if let Err(e) = std::env::set_current_dir(&home) {
        eprintln!("{NAME}: CRITICAL: (1133): Unable to chdir to directory '{}' due to [({})-({})].", home.display(), provigil_execd::errno(&e), provigil_execd::strerror(&e));
        std::process::exit(1);
    }
    let log = Arc::new(Log::open(&home, NAME));
    let fail = |m: String| -> ! {
        log.critical(m);
        std::process::exit(1);
    };
    let opts = Options::read(&home);
    let level = opts.int("execd", "debug", 0, 0, 2).unwrap_or_else(|e| fail(e));
    log.set_debug(if a.debug > 0 { a.debug } else { level as u8 });
    log.debug(format!("ProVigil home directory: {}", home.display()));
    {
        let l = log.clone();
        provigil_fileop::set_logger(Arc::new(move |level: &str, m: &str| match level {
            "ERROR" => l.error(m),
            "WARNING" => l.warn(m),
            _ => l.debug2(m),
        }));
    }

    // root keeps its user (responses change the firewall) and takes the service group
    #[cfg(unix)]
    if privs::is_root() {
        match privs::group_id(&a.group) {
            Some(gid) => {
                if let Err(e) = privs::set_group(gid) {
                    fail(format!("(1130): Unable to switch to group '{}' due to [({})-({})].", a.group, provigil_execd::errno(&e), provigil_execd::strerror(&e)));
                }
            }
            None => log.warn(format!("(1203): Invalid group '{}' given: keeping the current group.", a.group)),
        }
    }

    let ex = Arc::new(Execd::new(&home, log.clone(), opts));
    let outcome = ex.read_settings(&a.conf).unwrap_or_else(|e| fail(e));
    if outcome == Outcome::Invalid {
        log.error(format!("(1202): Configuration error at '{}'.", a.conf));
        std::process::exit(1);
    }
    ex.read_options().unwrap_or_else(|e| fail(e));
    if a.test {
        std::process::exit(0);
    }
    if !a.foreground {
        if let Err(e) = privs::daemonize() {
            fail(format!("Could not go to the background: {e}"));
        }
    }
    if outcome == Outcome::Disabled {
        log.info(DISABLED);
    }
    let pid_file = provigil_daemon::create_pid(&home, NAME).unwrap_or_else(|_| fail("(1212): Unable to create PID file.".into()));
    {
        let ex = ex.clone();
        std::thread::Builder::new().name("com".into()).spawn(move || ex.serve()).unwrap_or_else(|e| fail(format!("Could not start the request thread: {e}")));
    }
    log.info(format!("Started (pid: {}).", std::process::id()));

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap_or_else(|e| fail(format!("Could not start: {e}")));
    rt.block_on(async {
        let stop = stop_signal();
        tokio::pin!(stop);
        if outcome == Outcome::Disabled {
            // only the requests are served
            let sig = (&mut stop).await;
            leave(&ex, &log, &pid_file, sig, false);
        }
        ex.start_counting();
        let queue = match provigil_ipc::aio::DatagramReceiver::bind(home.join(EXEC_QUEUE)).await {
            Ok(q) => q,
            Err(e) => fail(format!("(1210): Queue '{EXEC_QUEUE}' not accessible: '{}'", provigil_execd::strerror(&e))),
        };
        loop {
            ex.reap();
            ex.expire();
            tokio::select! {
                sig = &mut stop => leave(&ex, &log, &pid_file, sig, true),
                r = tokio::time::timeout(Duration::from_secs(1), queue.recv(provigil_ipc::MAX_MESSAGE)) => match r {
                    Err(_) => continue,
                    Ok(Err(e)) => log.error(format!("(1210): Queue '{EXEC_QUEUE}' not accessible: '{}'", provigil_execd::strerror(&e))),
                    Ok(Ok(m)) => {
                        let m = &m[..m.iter().position(|&c| c == 0).unwrap_or(m.len())];
                        log.debug2(format!("Received message: '{}'", String::from_utf8_lossy(m)));
                        // a response program runs to its end before the next message
                        let (ex2, m2) = (ex.clone(), m.to_vec());
                        let _ = tokio::task::spawn_blocking(move || ex2.run(&m2)).await;
                    }
                },
            }
        }
    });
}

/// Undoes the pending responses (when they run), logs the signal, removes the PID file, exits.
fn leave(ex: &Execd, log: &Log, pid_file: &std::path::Path, sig: i32, undo: bool) -> ! {
    if undo {
        ex.shutdown();
    }
    log.info(format!("(1225): SIGNAL [({sig})-({})] Received. Exit Cleaning...", privs::signal_name(sig)));
    let _ = std::fs::remove_file(pid_file);
    std::process::exit(1);
}

/// The first stop signal (INT, QUIT, TERM, ALRM); HUP is ignored.
async fn stop_signal() -> i32 {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut hup = signal(SignalKind::hangup()).ok();
        let mut int = signal(SignalKind::interrupt()).ok();
        let mut quit = signal(SignalKind::quit()).ok();
        let mut term = signal(SignalKind::terminate()).ok();
        let mut alrm = signal(SignalKind::alarm()).ok();
        async fn on(s: &mut Option<tokio::signal::unix::Signal>) {
            match s {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending().await,
            }
        }
        loop {
            tokio::select! {
                _ = on(&mut hup) => continue,
                _ = on(&mut int) => return libc::SIGINT,
                _ = on(&mut quit) => return libc::SIGQUIT,
                _ = on(&mut term) => return libc::SIGTERM,
                _ = on(&mut alrm) => return libc::SIGALRM,
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        2
    }
}
