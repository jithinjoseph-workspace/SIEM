//! `wazuh-agentlessd` (agentlessd/main.c):
//! `wazuh-agentlessd -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use siem_agentlessd::{config, Entry, Lessd, ARGV0};
use siem_config::LogLevel;
use siem_log::WLog;

const USER: &str = "wazuh";
const GROUPGLOBAL: &str = "wazuh";
const OSSECCONF: &str = "etc/ossec.conf";
/// `LESSD_LOCAL_SOCK`
const LESSD_LOCAL_SOCK: &str = "queue/sockets/agentless";

fn help(home: &str) -> ! {
    for l in [
        " ".to_string(),
        "Wazuh v4.14.7 - Wazuh Inc. (info@wazuh.com)".into(),
        "http://www.wazuh.com".into(),
        format!("  {ARGV0}: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]"),
        "    -V          Version and license message".into(),
        "    -h          This help message".into(),
        "    -d          Execute in debug mode. This parameter".into(),
        "                can be specified multiple times".into(),
        "                to increase the debug level.".into(),
        "    -t          Test configuration".into(),
        "    -f          Run in foreground".into(),
        format!("    -u <user>   User to run as (default: {USER})"),
        format!("    -g <group>  Group to run as (default: {GROUPGLOBAL})"),
        format!("    -c <config> Configuration file to use (default: {OSSECCONF})"),
        format!("    -D <dir>    Directory to chdir and chroot into (default: {home})"),
        " ".into(),
    ] {
        eprintln!("{l}");
    }
    std::process::exit(1);
}

fn fatal(log: &WLog, msg: &str) -> ! {
    log.critical(msg);
    siem_daemon::handle_exit();
    std::process::exit(1);
}

/// `lessdcom_main`
fn lessdcom_start(list: Vec<Entry>, log: Arc<WLog>) {
    use siem_ipc::framing::{self, FrameError};
    siem_maild::log_thread_start(&log);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        rt.block_on(async move {
            log.debug1("Local requests thread ready");
            let l = match siem_ipc::local::StreamListener::bind(LESSD_LOCAL_SOCK).await {
                Ok(l) => l,
                Err(e) => {
                    log.error(format!("Unable to bind to socket '{LESSD_LOCAL_SOCK}': ({}) {}.", e.raw_os_error().unwrap_or(0), siem_maild::strerror(&e)));
                    return;
                }
            };
            loop {
                let Ok(mut peer) = l.accept().await else { continue };
                match framing::recv(&mut peer, siem_ipc::OS_MAXSTR).await {
                    Ok(b) if !b.is_empty() => {
                        let r = config::lessdcom_dispatch(&list, &b);
                        let _ = framing::send(&mut peer, r.as_bytes()).await;
                    }
                    Ok(_) | Err(FrameError::Closed) => log.debug1("Empty message from local client."),
                    Err(FrameError::TooBig(..)) => log.error("At lessdcom_main(): OS_RecvSecureTCP(): response size is bigger than expected"),
                    Err(FrameError::Io(e)) => log.error(format!("At lessdcom_main(): OS_RecvSecureTCP(): {}", siem_maild::strerror(&e))),
                }
            }
        });
    });
}

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let mut home = match siem_daemon::homedir(&argv0) {
        Ok(h) => h.to_string_lossy().into_owned(),
        Err(e) => {
            eprintln!("{ARGV0}: CRITICAL: {e}");
            std::process::exit(1);
        }
    };
    let (mut debug, mut foreground, mut test) = (0, false, false);
    let (mut user, mut group, mut cfg) = (USER.to_string(), GROUPGLOBAL.to_string(), OSSECCONF.to_string());
    // getopt(argc, argv, "Vdhtfu:g:D:c:")
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" || !a.starts_with('-') || a == "-" {
            break;
        }
        let chars: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            match chars[j] {
                'V' => {
                    eprintln!("\nWazuh v4.14.7 - Wazuh Inc.\n");
                    std::process::exit(0);
                }
                'h' => help(&home),
                'd' => debug += 1,
                'f' => foreground = true,
                't' => test = true,
                c @ ('u' | 'g' | 'D' | 'c') => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        args.get(i).cloned().unwrap_or_else(|| help(&home))
                    };
                    match c {
                        'u' => user = v,
                        'g' => group = v,
                        'D' => home = v,
                        _ => cfg = v,
                    }
                    j = chars.len();
                    continue;
                }
                _ => help(&home),
            }
            j += 1;
        }
        i += 1;
    }
    if std::env::set_current_dir(&home).is_err() {
        let e = std::io::Error::last_os_error();
        eprintln!("{ARGV0}: CRITICAL: (1133): Unable to chdir to directory '{home}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), siem_maild::strerror(&e));
        std::process::exit(1);
    }
    let base = PathBuf::new();
    let log = Arc::new(WLog::new_server(ARGV0, &base));
    siem_maild::set_logger(log.clone());
    for _ in 0..debug {
        log.now_debug();
    }
    log.debug1(format!("Wazuh home directory: {home}"));
    #[cfg(unix)]
    if siem_daemon::get_user(&user).is_none() || siem_daemon::get_group(&group).is_none() {
        let e = std::io::Error::last_os_error();
        fatal(&log, &format!("(1203): Invalid user '{user}' or group '{group}' given: {} ({})", siem_maild::strerror(&e), e.raw_os_error().unwrap_or(0)));
    }
    let mut msgs = Vec::new();
    let r = config::read_agentless_conf(&base, &cfg, &mut msgs);
    for (lvl, m) in msgs {
        match lvl {
            LogLevel::Debug1 => log.debug1(m),
            LogLevel::Debug2 => log.debug2(m),
            LogLevel::Info => log.info(m),
            LogLevel::Warn => log.warn(m),
            LogLevel::Error => log.error(m),
        }
    }
    let Some(entries) = r else { fatal(&log, "(7101): Invalid agentless configuration.") };
    if test {
        std::process::exit(0);
    }
    if !foreground {
        siem_daemon::go_daemon(&log);
    }
    if entries.is_empty() {
        log.info("Not configured. Exiting.");
        std::process::exit(0);
    }
    if let Err(m) = siem_daemon::privsep(&user, &group, Path::new(&home), false) {
        fatal(&log, &m);
    }
    log.debug1(format!("Chrooted to directory: {home}, using user: {user}"));
    siem_daemon::start_sig(ARGV0, log.clone());
    if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
        fatal(&log, "(1212): Unable to create PID file.");
    }
    log.info(format!("Started (pid: {}).", std::process::id()));

    // Wait a few seconds to settle
    std::thread::sleep(std::time::Duration::from_secs(2));
    let queue = siem_monitord::mq::Queue::start();
    lessdcom_start(entries.clone(), log.clone());
    Lessd { queue, entries }.run();
}
