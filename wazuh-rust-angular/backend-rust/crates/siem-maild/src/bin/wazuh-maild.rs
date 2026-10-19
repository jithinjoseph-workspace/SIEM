//! `wazuh-maild` (os_maild/maild.c `main`):
//! `wazuh-maild -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use siem_config::LogLevel;
use siem_log::WLog;
use siem_maild::config::{mail_conf, Conf};

const ARGV0: &str = "wazuh-maild";
const USER: &str = "wazuh";
const GROUPGLOBAL: &str = "wazuh";
const OSSECCONF: &str = "etc/ossec.conf";

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
        format!("    -D <dir>    Directory to chroot and chdir into (default: {home})"),
        " ".into(),
    ] {
        eprintln!("{l}");
    }
    std::process::exit(1);
}

fn early_exit(msg: &str) -> ! {
    eprintln!("{} {ARGV0}: CRITICAL: {msg}", siem_log::timestamp(chrono::Local::now()));
    std::process::exit(1);
}

fn fatal(log: &WLog, msg: &str) -> ! {
    log.critical(msg);
    siem_daemon::handle_exit();
    std::process::exit(1);
}

/// `OS_GetHost(host, 5)`
fn get_host(host: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    for _ in 0..5 {
        if let Some(a) = (host, 0).to_socket_addrs().ok().and_then(|mut a| a.next()) {
            return Some(a.ip().to_string());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    None
}

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let default_home = match siem_daemon::homedir(&argv0) {
        Ok(h) => h.to_string_lossy().into_owned(),
        Err(e) => early_exit(e),
    };
    let (mut debug, mut foreground, mut test) = (0, false, false);
    let (mut user, mut group, mut home, mut cfg) = (USER.to_string(), GROUPGLOBAL.to_string(), None::<String>, OSSECCONF.to_string());
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
                'h' => help(&default_home),
                'd' => debug += 1,
                'f' => foreground = true,
                't' => test = true,
                c @ ('u' | 'g' | 'D' | 'c') => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        args.get(i).cloned().unwrap_or_else(|| help(&default_home))
                    };
                    match c {
                        'u' => user = v,
                        'g' => group = v,
                        'D' => home = Some(v),
                        _ => cfg = v,
                    }
                    j = chars.len();
                    continue;
                }
                _ => help(&default_home),
            }
            j += 1;
        }
        i += 1;
    }
    let home = home.unwrap_or(default_home);
    if let Err(e) = std::env::set_current_dir(&home) {
        early_exit(&format!("(1133): Unable to chdir to directory '{home}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), siem_maild::strerror(&e)));
    }
    let base = PathBuf::new();
    let log = Arc::new(WLog::new_server(ARGV0, &base));
    for _ in 0..debug {
        log.now_debug();
    }
    siem_maild::set_logger(log.clone());
    siem_ipc::os_net::set_logger(log.clone());

    #[cfg(unix)]
    if siem_daemon::get_user(&user).is_none() || siem_daemon::get_group(&group).is_none() {
        let e = std::io::Error::last_os_error();
        fatal(&log, &format!("(1203): Invalid user '{user}' or group '{group}' given: {} ({})", siem_maild::strerror(&e), e.raw_os_error().unwrap_or(0)));
    }

    // Read configuration
    let mut msgs = Vec::new();
    let r = mail_conf(&base, &cfg, test, &mut msgs);
    for (lvl, m) in msgs {
        match lvl {
            LogLevel::Debug1 => log.debug1(m),
            LogLevel::Debug2 => log.debug2(m),
            LogLevel::Info => log.info(m),
            LogLevel::Warn => log.warn(m),
            LogLevel::Error => log.error(m),
        }
    }
    let mut mail = match r {
        Conf::Ok(m) => m,
        Conf::Disabled => std::process::exit(0),
        Conf::Err => fatal(&log, &format!("(1202): Configuration error at '{OSSECCONF}'.")),
    };
    // Internal options
    let opts = siem_config::internal_options::InternalOptions::from_home(&base);
    let get = |k: &str| opts.get_int("maild", k, 0, 1).unwrap_or_else(|e| fatal(&log, &e.0));
    mail.strict_checking = get("strict_checking");
    mail.grouping = get("grouping");
    mail.subject_full = get("full_subject");

    if test {
        std::process::exit(0);
    }
    if !foreground {
        siem_daemon::go_daemon(&log);
    }
    let Some(server) = mail.smtpserver.clone() else { fatal(&log, "SMTP server not set. Exiting.") };
    if !server.starts_with('/') {
        match get_host(&server) {
            Some(ip) => mail.smtpserver = Some(ip),
            None => fatal(&log, &format!("(1265): Invalid SMTP Server: {server}")),
        }
    }
    if let Err(m) = siem_daemon::privsep(&user, &group, Path::new(&home), !server.starts_with('/')) {
        fatal(&log, &m);
    }
    log.debug1(format!("Chrooted to directory: {home}, using user: {user}"));
    if siem_maild::smtp_ext::load().is_some() {
        log.info("SMTP TLS/authentication settings found in etc/smtp_auth.conf; using them for every e-mail.");
    }

    siem_maild::maild::mailcom_start(Arc::new(mail.clone()), log.clone());
    siem_daemon::start_sig(ARGV0, log.clone());
    if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
        fatal(&log, "(1212): Unable to create PID file.");
    }
    log.info(format!("Started (pid: {}).", std::process::id()));
    siem_maild::maild::os_run(mail);
}
