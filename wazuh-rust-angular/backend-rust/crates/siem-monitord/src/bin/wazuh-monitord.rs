//! `wazuh-monitord` (monitord/main.c):
//! `wazuh-monitord -[Vhdtf] [-u user] [-g group] [-c config] [-D dir] [-n] [-w sec]`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use siem_config::LogLevel;
use siem_log::WLog;
use siem_monitord::config::{monitord_config, MAX_DAY_WAIT};
use siem_monitord::monitord::Monitor;
use siem_monitord::{fatal, ARGV0};

const USER: &str = "wazuh";
const GROUPGLOBAL: &str = "wazuh";
const OSSECCONF: &str = "etc/ossec.conf";

fn print_version() -> ! {
    eprintln!(" ");
    eprintln!("Wazuh v4.14.7 - Wazuh Inc.");
    eprintln!(" ");
    eprintln!(
        "This program is free software; you can redistribute it and/or modify\n\
         it under the terms of the GNU General Public License (version 2) as \n\
         published by the Free Software Foundation. For more details, go to \n\
         https://www.gnu.org/licenses/gpl.html\n"
    );
    std::process::exit(0);
}

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
        "    -n          Disable agent monitoring.".into(),
        "    -w <sec>    Time (sec.) to wait before rotating logs and alerts.".into(),
        " ".into(),
    ] {
        eprintln!("{l}");
    }
    std::process::exit(1);
}

/// `merror_exit` before the logger is set up.
fn early_exit(msg: &str) -> ! {
    let ts = siem_log::timestamp(chrono::Local::now());
    eprintln!("{ts} {ARGV0}: CRITICAL: {msg}");
    std::process::exit(1);
}

struct Opts {
    debug: i32,
    foreground: bool,
    test: bool,
    no_agents: bool,
    day_wait: i16,
    user: String,
    group: String,
    home: Option<String>,
    cfg: String,
}

/// getopt(argc, argv, "Vdhtfu:g:D:c:nw:")
fn parse_args(home: &str) -> Opts {
    let mut o = Opts { debug: 0, foreground: false, test: false, no_agents: false, day_wait: -1, user: USER.into(), group: GROUPGLOBAL.into(), home: None, cfg: OSSECCONF.into() };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" || !a.starts_with('-') || a == "-" {
            break; // getopt stops at the first non-option
        }
        let chars: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            match c {
                'V' => print_version(),
                'h' => help(home),
                'd' => o.debug += 1,
                'f' => o.foreground = true,
                't' => o.test = true,
                'n' => o.no_agents = true,
                'u' | 'g' | 'D' | 'c' | 'w' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let val = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => {
                                eprintln!("{ARGV0}: option requires an argument -- '{c}'");
                                help(home);
                            }
                        }
                    };
                    match c {
                        'u' => o.user = val,
                        'g' => o.group = val,
                        'D' => o.home = Some(val),
                        'c' => o.cfg = val,
                        _ => {
                            // strtol: the whole argument must be a number in [0, MAX_DAY_WAIT]
                            match val.parse::<i64>() {
                                Ok(v) if (0..=MAX_DAY_WAIT as i64).contains(&v) && !val.starts_with('+') => o.day_wait = v as i16,
                                _ => early_exit(&format!("Invalid value for option -{c}.")),
                            }
                        }
                    }
                    j = chars.len();
                    continue;
                }
                _ => {
                    eprintln!("{ARGV0}: invalid option -- '{c}'");
                    help(home);
                }
            }
            j += 1;
        }
        i += 1;
    }
    o
}

/// `OS_GetHost(host, 5)`: the address the name resolves to.
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
    let o = parse_args(&default_home);
    let home = o.home.clone().unwrap_or(default_home);

    // Change working directory
    if let Err(e) = std::env::set_current_dir(&home) {
        early_exit(&format!("(1133): Unable to chdir to directory '{home}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), siem_monitord::strerror(&e)));
    }
    let base = PathBuf::new();
    let log = Arc::new(WLog::new_server(ARGV0, &base));
    siem_ipc::os_net::set_logger(log.clone());
    siem_maild::set_logger(log.clone());
    for _ in 0..o.debug {
        log.now_debug();
    }
    if o.debug == 0 {
        let opts = siem_config::internal_options::InternalOptions::from_home(&base);
        match opts.get_int("monitord", "debug", 0, 2) {
            Ok(n) => (0..n).for_each(|_| log.now_debug()),
            Err(e) => fatal(&log, &e.0),
        }
    }
    log.debug1(format!("Wazuh home directory: {home}"));

    #[cfg(unix)]
    if siem_daemon::get_user(&o.user).is_none() || siem_daemon::get_group(&o.group).is_none() {
        let e = std::io::Error::last_os_error();
        fatal(&log, &format!("(1203): Invalid user '{}' or group '{}' given: {} ({})", o.user, o.group, siem_monitord::strerror(&e), e.raw_os_error().unwrap_or(0)));
    }

    // Reading configuration
    let (r, msgs) = monitord_config(&base, &o.cfg, o.no_agents, o.day_wait);
    for (lvl, m) in msgs {
        match lvl {
            LogLevel::Debug1 => log.debug1(m),
            LogLevel::Debug2 => log.debug2(m),
            LogLevel::Info => log.info(m),
            LogLevel::Warn => log.warn(m),
            LogLevel::Error => log.error(m),
        }
    }
    let mut mond = match r {
        Ok(m) => m,
        Err(crit) => fatal(&log, &crit),
    };

    // If we have any reports configured, read smtp/emailfrom
    if !mond.reports.is_empty() {
        let mut xml = match siem_xml::OsXml::read_file(Path::new(&o.cfg), false) {
            Ok(x) => x,
            Err(_) => fatal(&log, &format!("(1202): Configuration error at '{}'.", o.cfg)),
        };
        let smtp = xml.get_one_content_for_element(&["ossec_config", "global", "smtp_server"]);
        mond.emailfrom = xml.get_one_content_for_element(&["ossec_config", "global", "email_from"]);
        mond.emailidsname = xml.get_one_content_for_element(&["ossec_config", "global", "email_idsname"]);
        match (smtp, mond.emailfrom.is_some()) {
            (Some(s), true) => {
                if s.starts_with('/') {
                    mond.smtpserver = Some(s);
                } else {
                    mond.smtpserver = get_host(&s);
                    if mond.smtpserver.is_none() {
                        log.error(format!("(1265): Invalid SMTP Server: {s}"));
                        mond.emailfrom = None;
                        log.error("Invalid SMTP server.  Disabling email reports.");
                    }
                }
            }
            _ => {
                mond.emailfrom = None;
                log.error("SMTP server or 'email from' missing. Disabling email reports.");
            }
        }
    }

    // Do not monitor agents in client/worker nodes
    if siem_config::cluster::is_worker(Path::new(OSSECCONF)) == Some(true) {
        log.debug1("Cluster client node: Disabled the agent monitoring");
        mond.monitor_agents = 0;
    }

    if o.test {
        std::process::exit(0);
    }
    if !o.foreground {
        siem_daemon::go_daemon(&log);
    }
    if let Err(m) = siem_daemon::privsep(&o.user, &o.group, Path::new(&home), true) {
        fatal(&log, &m);
    }
    log.debug1(format!("Chrooted to directory: {home}, using user: {}", o.user));
    siem_daemon::start_sig(ARGV0, log.clone());
    if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
        fatal(&log, "(1212): Unable to create PID file.");
    }
    log.info(format!("Started (pid: {}).", std::process::id()));

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap_or_else(|e| fatal(&log, &e.to_string()));
    Monitor::new(mond, log, rt.handle().clone()).run();
}
