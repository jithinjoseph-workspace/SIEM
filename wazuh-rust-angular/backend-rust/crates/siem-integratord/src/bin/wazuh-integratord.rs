//! `wazuh-integratord` (os_integrator/main.c):
//! `wazuh-integratord -[Vhdtf] [-u user] [-g group]`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use siem_config::LogLevel;
use siem_log::WLog;

const ARGV0: &str = "wazuh-integratord";
const USER: &str = "wazuh";
const GROUPGLOBAL: &str = "wazuh";
const OSSECCONF: &str = "etc/ossec.conf";
/// `INTG_LOCAL_SOCK`
const INTG_LOCAL_SOCK: &str = "queue/sockets/integrator";

fn help() -> ! {
    for l in [
        " ".to_string(),
        "Wazuh v4.14.7 - Wazuh Inc. (info@wazuh.com)".into(),
        "http://www.wazuh.com".into(),
        format!("  {ARGV0}: -[Vhdtf] [-u user] [-g group]"),
        "    -V          Version and license message".into(),
        "    -h          This help message".into(),
        "    -d          Execute in debug mode. This parameter".into(),
        "                can be specified multiple times".into(),
        "                to increase the debug level.".into(),
        "    -t          Test configuration".into(),
        "    -f          Run in foreground".into(),
        format!("    -u <user>   User to run as (default: {USER})"),
        format!("    -g <group>  Group to run as (default: {GROUPGLOBAL})"),
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

/// `intgcom_main`
fn intgcom_start(list: Arc<Vec<siem_integratord::config::Integration>>, log: Arc<WLog>) {
    use siem_ipc::framing::{self, FrameError};
    siem_maild::log_thread_start(&log);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        rt.block_on(async move {
            log.debug1("Local requests thread ready");
            let l = match siem_ipc::local::StreamListener::bind(INTG_LOCAL_SOCK).await {
                Ok(l) => l,
                Err(e) => {
                    log.error(format!("Unable to bind to socket '{INTG_LOCAL_SOCK}': ({}) {}.", e.raw_os_error().unwrap_or(0), siem_integratord::strerror(&e)));
                    return;
                }
            };
            loop {
                let Ok(mut peer) = l.accept().await else { continue };
                match framing::recv(&mut peer, siem_ipc::OS_MAXSTR).await {
                    Ok(b) if !b.is_empty() => {
                        let r = siem_integratord::config::intgcom_dispatch(&list, &b);
                        let _ = framing::send(&mut peer, r.as_bytes()).await;
                    }
                    Ok(_) | Err(FrameError::Closed) => log.debug1("Empty message from local client."),
                    Err(FrameError::TooBig(..)) => log.error("At intgcom_main(): OS_RecvSecureTCP(): response size is bigger than expected"),
                    Err(FrameError::Io(e)) => log.error(format!("At intgcom_main(): OS_RecvSecureTCP(): {}", siem_integratord::strerror(&e))),
                }
            }
        });
    });
}

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let home = match siem_daemon::homedir(&argv0) {
        Ok(h) => h.to_string_lossy().into_owned(),
        Err(e) => {
            eprintln!("{ARGV0}: CRITICAL: {e}");
            std::process::exit(1);
        }
    };
    // C changes to the home before reading the options
    if std::env::set_current_dir(&home).is_err() {
        eprintln!("{ARGV0}: ERROR: (1133): Unable to chdir to directory '{home}'.");
        std::process::exit(1);
    }
    let base = PathBuf::new();
    let log = Arc::new(WLog::new_server(ARGV0, &base));
    siem_maild::set_logger(log.clone());
    let (mut debug, mut foreground, mut test) = (0, false, false);
    let (mut user, mut group) = (USER.to_string(), GROUPGLOBAL.to_string());
    // getopt(argc, argv, "Vdhtfu:g:")
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
                'h' => help(),
                'd' => debug += 1,
                'f' => foreground = true,
                't' => test = true,
                c @ ('u' | 'g') => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        args.get(i).cloned().unwrap_or_else(|| help())
                    };
                    if c == 'u' {
                        user = v;
                    } else {
                        group = v;
                    }
                    j = chars.len();
                    continue;
                }
                _ => help(),
            }
            j += 1;
        }
        i += 1;
    }
    for _ in 0..debug {
        log.now_debug();
    }
    if debug == 0 {
        let opts = siem_config::internal_options::InternalOptions::from_home(&base);
        match opts.get_int("integrator", "debug", 0, 2) {
            Ok(n) => (0..n).for_each(|_| log.now_debug()),
            Err(e) => fatal(&log, &e.0),
        }
    }
    #[cfg(unix)]
    if siem_daemon::get_user(&user).is_none() || siem_daemon::get_group(&group).is_none() {
        let e = std::io::Error::last_os_error();
        fatal(&log, &format!("(1203): Invalid user '{user}' or group '{group}' given: {} ({})", siem_integratord::strerror(&e), e.raw_os_error().unwrap_or(0)));
    }

    let mut msgs = Vec::new();
    let r = siem_integratord::config::read_integrator_conf(&base, OSSECCONF, &mut msgs);
    for (lvl, m) in msgs {
        match lvl {
            LogLevel::Debug1 => log.debug1(m),
            LogLevel::Debug2 => log.debug2(m),
            LogLevel::Info => log.info(m),
            LogLevel::Warn => log.warn(m),
            LogLevel::Error => log.error(m),
        }
    }
    let Some(list) = r else { fatal(&log, &format!("(1202): Configuration error at '{OSSECCONF}'.")) };
    if list.is_empty() {
        if !test {
            log.info("Remote integrations not configured. Clean exit.");
        }
        std::process::exit(0);
    }
    if test {
        std::process::exit(0);
    }
    if !foreground {
        siem_daemon::go_daemon(&log);
    }
    if let Err(m) = siem_daemon::privsep(&user, &group, Path::new(&home), false) {
        fatal(&log, &m);
    }
    intgcom_start(Arc::new(list.clone()), log.clone());
    log.debug1(format!("Chrooted to directory: {home}, using user: {user}"));
    siem_daemon::start_sig(ARGV0, log.clone());
    if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
        fatal(&log, "(1212): Unable to create PID file.");
    }
    log.info(format!("Started (pid: {}).", std::process::id()));
    siem_integratord::integrator::os_integratord(list);
}
