//! `provigil-analysisd -[Vhdtf] [-u user] [-g group] [-c config] [-D home]`: the manager's
//! analysis (see the crate notes). siem-api runs it with `-f -D <home>`, and checks rule
//! changes with `-t -c etc/ossec.staging.conf -D <home>` (it reads ERROR and CRITICAL lines
//! from the output).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use provigil_analysisd::config::Config;
use provigil_analysisd::daemon::{run, Service, ServiceLog, NAME};
use provigil_daemon::{privs, Log, Options};

const USER: &str = "provigil";
const GROUP: &str = "provigil";
const CONF: &str = "etc/ossec.conf";

fn help() -> ! {
    for l in [
        " ".to_string(),
        format!("  {NAME}: -[Vhdtf] [-u user] [-g group] [-c config] [-D home]"),
        "    -V          Version".into(),
        "    -h          This help".into(),
        "    -d          More logging; give it twice for the most".into(),
        "    -t          Check the settings and the ruleset, then stop".into(),
        "    -f          Run in the foreground".into(),
        format!("    -u <user>   User to run as when started as root (default: {USER})"),
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
    user: String,
    group: String,
    conf: String,
    home: Option<PathBuf>,
}

fn args() -> Args {
    let mut a = Args { debug: 0, test: false, foreground: false, user: USER.into(), group: GROUP.into(), conf: CONF.into(), home: None };
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
                'u' | 'g' | 'c' | 'D' => {
                    let rest: String = chars[k + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        list.get(i).cloned().unwrap_or_else(|| {
                            eprintln!("{NAME}: option requires an argument -- '{c}'");
                            help()
                        })
                    };
                    match c {
                        'u' => a.user = v,
                        'g' => a.group = v,
                        'c' => a.conf = v,
                        _ => a.home = Some(v.into()),
                    }
                    break;
                }
                _ => {
                    eprintln!("{NAME}: invalid option -- '{c}'");
                    help()
                }
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
        eprintln!("{} {NAME}: CRITICAL: (1133): Unable to chdir to directory '{}' due to [({})-({e})].", chrono::Local::now().format("%Y/%m/%d %H:%M:%S"), home.display(), e.raw_os_error().unwrap_or(0));
        std::process::exit(1);
    }
    // absolute from here: every path of the service hangs off it
    let home = std::env::current_dir().unwrap_or(home);
    let log = Arc::new(ServiceLog::new(Log::open(&home, NAME), true));
    let fail = |m: String| -> ! {
        log.log("CRITICAL", m);
        std::process::exit(1);
    };
    // the internal option counts when -d was not given
    let level = Options::read(&home).int("analysisd", "debug", 0, 0, 2).unwrap_or_else(|e| fail(e));
    log.set_debug(if a.debug > 0 { a.debug } else { level as u8 });
    log.log("DEBUG", format!("ProVigil home directory: {}", home.display()));

    let cfg = match Config::load(&home, Path::new(&a.conf), true) {
        Ok(c) => c,
        Err(e) => {
            log.log("ERROR", e);
            fail(format!("(1202): Configuration error at '{}'.", a.conf));
        }
    };
    log.log("DEBUG", "Active response initialized ...");
    log.log("DEBUG", "Read configuration ...");
    for w in &cfg.warnings {
        log.log("WARNING", w);
    }
    let g = &cfg.global;
    if !g.alerts_log && !g.jsonout_output {
        log.log("WARNING", "All alert formats are disabled. Mail reporting, Syslog client and Integrator won't work properly.");
    }
    if !cfg.sockets.is_empty() && !g.forward_to.is_empty() {
        for s in &cfg.sockets {
            log.log("DEBUG", format!("Socket '{}' ({}) added. Location: {}", s.name, if s.tcp { "tcp" } else { "udp" }, s.location));
        }
        for target in &g.forward_to {
            // a warning for every socket before the matching one (kept as it was)
            for _ in cfg.sockets.iter().take_while(|s| &s.name != target) {
                log.log("WARNING", format!("Socket for target '{target}' is not defined."));
            }
        }
    }
    if let Err(m) = privs::set_nofile(cfg.internal.rlimit_nofile as u64) {
        log.log("ERROR", m);
    }

    if !a.test && !a.foreground {
        if let Err(e) = privs::daemonize() {
            fail(format!("Could not go to the background: {e}"));
        }
        log.quiet();
    }

    // started as root: the service user and group (no chroot: paths are absolute)
    #[cfg(unix)]
    if privs::is_root() {
        let (Some(uid), Some(gid)) = (privs::user_id(&a.user), privs::group_id(&a.group)) else {
            fail(format!("(1203): Invalid user '{}' or group '{}' given.", a.user, a.group));
        };
        if let Err(e) = privs::set_group(gid) {
            fail(format!("(1130): Unable to switch to group '{}' due to [({})-({e})].", a.group, e.raw_os_error().unwrap_or(0)));
        }
        if let Err(e) = privs::set_user(uid) {
            fail(format!("(1131): Unable to switch to user '{}' due to [({})-({e})].", a.user, e.raw_os_error().unwrap_or(0)));
        }
        log.log("DEBUG", format!("Running as user: {}", a.user));
    }

    let pid_file = if a.test {
        None
    } else {
        let p = provigil_daemon::create_pid(&home, NAME).unwrap_or_else(|_| fail("(1212): Unable to create PID file.".into()));
        let (l, p2) = (log.clone(), p.clone());
        std::thread::Builder::new()
            .name("signals".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
                let sig = rt.block_on(stop_signal());
                provigil_ipc::platform_stream::flush_at_exit();
                l.log("INFO", format!("(1225): SIGNAL [({sig})-({})] Received. Exit Cleaning...", privs::signal_name(sig)));
                let _ = std::fs::remove_file(&p2);
                std::process::exit(1);
            })
            .unwrap_or_else(|e| fail(format!("Could not start the signal thread: {e}")));
        Some(p)
    };
    let leave = |code: i32| -> ! {
        if let Some(p) = &pid_file {
            let _ = std::fs::remove_file(p);
        }
        std::process::exit(code);
    };

    let service = match Service::new(cfg, &log, a.test) {
        Ok(s) => s,
        Err(crit) => {
            log.log("CRITICAL", crit);
            leave(1);
        }
    };
    if a.test {
        leave(0);
    }
    if let Err(e) = run(service, log.clone()) {
        log.log("CRITICAL", e.to_string());
        leave(1);
    }
    leave(0);
}

/// The first stop signal (INT, QUIT, TERM, ALRM); HUP and PIPE are ignored.
async fn stop_signal() -> i32 {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut hup = signal(SignalKind::hangup()).ok();
        let mut pipe = signal(SignalKind::pipe()).ok();
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
                _ = on(&mut pipe) => continue,
                _ = on(&mut int) => return 2,
                _ = on(&mut quit) => return 3,
                _ = on(&mut term) => return 15,
                _ = on(&mut alrm) => return 14,
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        2
    }
}
