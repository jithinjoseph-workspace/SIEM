//! `wazuh-analysisd` (analysisd.c `main`):
//! `wazuh-analysisd -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use siem_analysisd::daemon::{run, Analysis, Logger};
use siem_analysisd::daemon_config::AnalysisdConfig;
use siem_log::WLog;

const ARGV0: &str = "wazuh-analysisd";
const USER: &str = "wazuh";
const GROUPGLOBAL: &str = "wazuh";
const OSSECCONF: &str = "etc/ossec.conf";

fn print_out(s: &str) {
    eprintln!("{s}");
}

/// `print_version`
fn print_version() -> ! {
    print_out(" ");
    print_out("Wazuh v4.14.7 - Wazuh Inc.");
    print_out(" ");
    print_out(
        "This program is free software; you can redistribute it and/or modify\n\
         it under the terms of the GNU General Public License (version 2) as \n\
         published by the Free Software Foundation. For more details, go to \n\
         https://www.gnu.org/licenses/gpl.html\n",
    );
    std::process::exit(0);
}

/// `help_analysisd`
fn help(home: &str) -> ! {
    print_out(" ");
    print_out("Wazuh v4.14.7 - Wazuh Inc. (info@wazuh.com)");
    print_out("http://www.wazuh.com");
    print_out(&format!("  {ARGV0}: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]"));
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out(&format!("    -u <user>   User to run as (default: {USER})"));
    print_out(&format!("    -g <group>  Group to run as (default: {GROUPGLOBAL})"));
    print_out(&format!("    -c <config> Configuration file to use (default: {OSSECCONF})"));
    print_out(&format!("    -D <dir>    Directory to chroot and chdir into (default: {home})"));
    print_out(" ");
    std::process::exit(1);
}

/// `merror_exit` before the logger can read the configuration.
fn early_exit(msg: &str) -> ! {
    let ts = siem_log::timestamp(chrono::Local::now());
    eprintln!("{ts} {ARGV0}: CRITICAL: {msg}");
    std::process::exit(1);
}

struct Opts {
    debug: i32,
    foreground: bool,
    test: bool,
    user: String,
    group: String,
    home: Option<String>,
    cfg: String,
}

/// getopt(argc, argv, "Vtdhfu:g:D:c:")
fn parse_args(home: &str) -> Opts {
    let mut o = Opts {
        debug: 0,
        foreground: false,
        test: false,
        user: USER.into(),
        group: GROUPGLOBAL.into(),
        home: None,
        cfg: OSSECCONF.into(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            break;
        }
        if !a.starts_with('-') || a == "-" {
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
                'u' | 'g' | 'D' | 'c' => {
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
                        _ => o.cfg = val,
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

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    // w_homedir
    let default_home = match siem_daemon::homedir(&argv0) {
        Ok(h) => h.to_string_lossy().into_owned(),
        Err(e) => early_exit(e),
    };
    let o = parse_args(&default_home);
    let home = o.home.clone().unwrap_or(default_home);

    // Change working directory: every path below is relative to it
    if let Err(e) = std::env::set_current_dir(&home) {
        let n = e.raw_os_error().unwrap_or(0);
        early_exit(&format!("(1133): Unable to chdir to directory '{home}' due to [({n})-({e})]."));
    }
    let base = PathBuf::new();
    let wlog = Arc::new(WLog::new_server(ARGV0, &base));
    for _ in 0..o.debug {
        wlog.now_debug();
    }
    // the internal option takes effect when -d was not given
    let opts = siem_config::internal_options::InternalOptions::from_home(&base);
    let sys_debug = match opts.get_int("analysisd", "debug", 0, 2) {
        Ok(v) => v,
        Err(e) => {
            wlog.critical(e.0.as_bytes());
            std::process::exit(1);
        }
    };
    if o.debug == 0 {
        for _ in 0..sys_debug {
            wlog.now_debug();
        }
    }
    let log: Arc<dyn Logger> = wlog.clone();
    log.log("DEBUG", &format!("Wazuh home directory: {home}"));

    // Check if the user/group given are valid
    #[cfg(unix)]
    if siem_daemon::get_user(&o.user).is_none() || siem_daemon::get_group(&o.group).is_none() {
        let e = std::io::Error::last_os_error();
        log.log(
            "CRITICAL",
            &format!(
                "(1203): Invalid user '{}' or group '{}' given: {} ({})",
                o.user,
                o.group,
                e.to_string().split(" (os error").next().unwrap_or(""),
                e.raw_os_error().unwrap_or(0)
            ),
        );
        std::process::exit(1);
    }
    log.log("DEBUG", "Found user/group ...");

    // AR_ReadConfig + GlobalConf (+ labels, logtest)
    let conf = match AnalysisdConfig::load(&base, Path::new(&o.cfg), true) {
        Ok(c) => c,
        Err(e) => {
            log.log("ERROR", &e.0);
            log.log("CRITICAL", &format!("(1202): Configuration error at '{}'.", o.cfg));
            std::process::exit(1);
        }
    };
    log.log("DEBUG", "Active response initialized ...");
    log.log("DEBUG", "Read configuration ...");
    for w in &conf.warnings {
        log.log("WARNING", w);
    }
    let g = &conf.global;
    if g.alerts_log == 0 && g.jsonout_output == 0 {
        log.log("WARNING", "All alert formats are disabled. Mail reporting, Syslog client and Integrator won't work properly.");
    }
    // Check sockets
    if !conf.sockets.is_empty() && !g.forwarders_list.is_empty() {
        for s in &conf.sockets {
            let mode = match s.mode {
                siem_config::socket::SocketMode::Udp => "udp",
                siem_config::socket::SocketMode::Tcp => "tcp",
            };
            log.log("DEBUG", &format!("Socket '{}' ({mode}) added. Location: {}", s.name, s.location));
        }
        for target in &g.forwarders_list {
            // (the C loop warns for every socket before the matching one)
            for s in &conf.sockets {
                if &s.name == target {
                    break;
                }
                log.log("WARNING", &format!("Socket for target '{target}' is not defined."));
            }
        }
    }
    // Set resource limit for file descriptors
    if let Err(m) = siem_daemon::set_nofile(conf.internal.rlimit_nofile as u64) {
        log.log("ERROR", &m);
    }

    // Continuing in daemon mode
    if !o.test && !o.foreground {
        siem_daemon::go_daemon(&wlog);
    }

    // Set the group, chroot, set the user
    if let Err(m) = siem_daemon::privsep(&o.user, &o.group, Path::new(&home), true) {
        log.log("CRITICAL", &m);
        std::process::exit(1);
    }
    log.log("DEBUG", &format!("Chrooted to directory: {home}, using user: {}", o.user));

    if !o.test {
        siem_daemon::start_sig(ARGV0, wlog.clone());
        if siem_daemon::create_pid(ARGV0, std::process::id(), &wlog).is_err() {
            log.log("CRITICAL", "(1212): Unable to create PID file.");
            std::process::exit(1);
        }
    }

    let analysis = match Analysis::new(conf, &*log, o.test) {
        Ok(a) => a,
        Err(crit) => {
            log.log("CRITICAL", &crit);
            siem_daemon::handle_exit();
            std::process::exit(1);
        }
    };
    // Success on the configuration test
    if o.test {
        std::process::exit(0);
    }
    if let Err(e) = run(analysis, log.clone()) {
        log.log("CRITICAL", &e.to_string());
        siem_daemon::handle_exit();
        std::process::exit(1);
    }
    siem_daemon::handle_exit();
}
