//! `provigil-agentlessd -[Vhdtf] [-u user] [-g group] [-c config] [-D home]`: agentless
//! monitoring (see the crate notes). siem-api runs it on Linux with `-f -D <home>`.

use std::path::PathBuf;
use std::sync::Arc;

use provigil_agentlessd::{config, Lessd, Queue, NAME, SOCKET};
use provigil_daemon::{privs, Log};

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
        "    -t          Check the settings and stop".into(),
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

fn main() {
    let (mut debug, mut foreground, mut test) = (0u8, false, false);
    let (mut user, mut group, mut conf, mut home) = (USER.to_string(), GROUP.to_string(), CONF.to_string(), None::<PathBuf>);
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
                'd' => debug += 1,
                'f' => foreground = true,
                't' => test = true,
                'u' | 'g' | 'c' | 'D' => {
                    let rest: String = chars[k + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        list.get(i).cloned().unwrap_or_else(|| help())
                    };
                    match c {
                        'u' => user = v,
                        'g' => group = v,
                        'c' => conf = v,
                        _ => home = Some(v.into()),
                    }
                    break;
                }
                _ => help(),
            }
        }
        i += 1;
    }
    let home = home.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    if let Err(e) = std::env::set_current_dir(&home) {
        eprintln!("{NAME}: CRITICAL: (1133): Unable to chdir to directory '{}' due to [({})-({})].", home.display(), e.raw_os_error().unwrap_or(0), provigil_agentlessd::strerror(&e));
        std::process::exit(1);
    }
    let log = Arc::new(Log::open(&home, NAME));
    log.set_debug(debug);
    let fail = |m: String| -> ! {
        log.critical(m);
        std::process::exit(1);
    };
    log.debug(format!("ProVigil home directory: {}", home.display()));

    let mut notes = Vec::new();
    let entries = config::read(&home, &conf, &mut notes);
    for (level, m) in notes {
        log.write(level, m);
    }
    let Some(entries) = entries else { fail("(7101): Invalid agentless configuration.".into()) };
    if test {
        std::process::exit(0);
    }
    if !foreground {
        if let Err(e) = privs::daemonize() {
            fail(format!("Could not go to the background: {e}"));
        }
    }
    if entries.is_empty() {
        log.info("Not configured. Exiting.");
        std::process::exit(0);
    }

    // root runs the scripts as the service user, never as itself
    #[cfg(unix)]
    if privs::is_root() {
        let (Some(uid), Some(gid)) = (privs::user_id(&user), privs::group_id(&group)) else {
            let e = std::io::Error::last_os_error();
            fail(format!("(1203): Invalid user '{user}' or group '{group}' given: {} ({})", provigil_agentlessd::strerror(&e), e.raw_os_error().unwrap_or(0)));
        };
        if let Err(e) = privs::set_group(gid) {
            fail(format!("(1130): Unable to switch to group '{group}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), provigil_agentlessd::strerror(&e)));
        }
        if let Err(e) = privs::set_user(uid) {
            fail(format!("(1131): Unable to switch to user '{user}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), provigil_agentlessd::strerror(&e)));
        }
        log.debug(format!("Running as user: {user}"));
    }
    #[cfg(not(unix))]
    let _ = (&user, &group);

    let pid_file = provigil_daemon::create_pid(&home, NAME).unwrap_or_else(|_| fail("(1212): Unable to create PID file.".into()));
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap_or_else(|e| fail(format!("Could not start: {e}")));
    {
        let (log, pid_file) = (log.clone(), pid_file.clone());
        rt.spawn(async move {
            let sig = stop_signal().await;
            log.info(format!("(1225): SIGNAL [({sig})-({})] Received. Exit Cleaning...", privs::signal_name(sig)));
            let _ = std::fs::remove_file(&pid_file);
            std::process::exit(1);
        });
    }
    log.info(format!("Started (pid: {}).", std::process::id()));

    // let the other services settle
    std::thread::sleep(std::time::Duration::from_secs(2));
    let queue = Queue::open(&home, rt.handle().clone(), log.clone());
    {
        let (entries, log, home) = (entries.clone(), log.clone(), home.clone());
        std::thread::Builder::new().name("lessdcom".into()).spawn(move || serve(&home, &entries, &log)).unwrap_or_else(|e| fail(format!("Could not start the request thread: {e}")));
    }
    Lessd { home, log, events: queue, entries }.run();
}

/// Serves `queue/sockets/agentless`, one request per connection.
fn serve(home: &std::path::Path, entries: &[config::Entry], log: &Log) {
    log.debug("Local requests thread ready");
    let listener = match provigil_ipc::local::bind(&home.join(SOCKET)) {
        Ok(l) => l,
        Err(e) => {
            log.error(format!("Unable to bind to socket '{SOCKET}': ({}) {}.", e.raw_os_error().unwrap_or(0), provigil_agentlessd::strerror(&e)));
            return;
        }
    };
    for peer in listener.incoming() {
        let Ok(mut peer) = peer else { continue };
        let _ = peer.set_read_timeout(Some(std::time::Duration::from_secs(30)));
        match provigil_ipc::framing::recv(&mut peer, provigil_ipc::MAX_MESSAGE) {
            Ok(Some(m)) if !m.is_empty() => {
                let answer = config::dispatch(entries, &m, &|t| log.debug(t));
                let _ = provigil_ipc::framing::send(&mut peer, answer.as_bytes());
            }
            Ok(_) => log.debug("Empty message from local client."),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => log.error("At lessdcom_main(): OS_RecvSecureTCP(): response size is bigger than expected"),
            Err(e) => log.error(format!("At lessdcom_main(): OS_RecvSecureTCP(): {}", provigil_agentlessd::strerror(&e))),
        }
    }
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
