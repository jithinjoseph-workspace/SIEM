//! `client-agent/main.c`: the `wazuh-agentd` command line.

#[cfg(not(unix))]
fn main() {
    eprintln!("wazuh-agentd: the agent daemon runs on Unix only (Windows uses wazuh-agent).");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    unix::main();
}

#[cfg(unix)]
mod unix {
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use siem_agentd::*;
    use siem_config::client::validate_address;
    use siem_config::internal_options::InternalOptions;
    use siem_log::WLog;

    /// `print_out`: a line on stderr.
    fn print_out(s: &str) {
        eprintln!("{s}");
    }

    fn help_agentd() -> ! {
        print_out(" ");
        print_out(&format!("{OSSEC_NAME} {OSSEC_VERSION} - Wazuh Inc. (info@wazuh.com)"));
        print_out("http://www.wazuh.com");
        print_out(&format!("  {ARGV0}: -[Vhdtf] [-u user] [-g group] [-c config]"));
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
        print_out(" ");
        std::process::exit(1);
    }

    fn print_version() -> ! {
        print_out(" ");
        print_out(&format!("{OSSEC_NAME} {OSSEC_VERSION} - Wazuh Inc."));
        print_out(" ");
        print_out(
            "This program is free software; you can redistribute it and/or modify\n\
             it under the terms of the GNU General Public License (version 2) as \n\
             published by the Free Software Foundation. For more details, go to \n\
             https://www.gnu.org/licenses/gpl.html\n",
        );
        std::process::exit(0);
    }

    /// One parsed option (`getopt_long` with "Vtdfhu:g:D:c:").
    enum Opt {
        Flag(char),
        Arg(char, Option<String>),
        Long(u8, Option<String>),
        Unknown,
    }

    fn getopt(args: &[String]) -> Vec<Opt> {
        const WITH_ARG: &str = "ugDc";
        const FLAGS: &str = "Vtdfh";
        let mut out = Vec::new();
        let mut i = 1;
        while i < args.len() {
            let a = &args[i];
            if a == "--" {
                break;
            }
            if let Some(long) = a.strip_prefix("--") {
                let (name, val) = match long.find('=') {
                    Some(p) => (&long[..p], Some(long[p + 1..].to_string())),
                    None => (long, None),
                };
                let id = match name {
                    "uninstall-auth-login" => 1,
                    "uninstall-auth-token" => 2,
                    "uninstall-auth-host" => 3,
                    "uninstall-ssl-verify" => 4,
                    _ => {
                        out.push(Opt::Unknown);
                        i += 1;
                        continue;
                    }
                };
                // 1-3: required_argument; 4: optional_argument (only with '=')
                let val = if id != 4 && val.is_none() {
                    i += 1;
                    args.get(i).cloned()
                } else {
                    val
                };
                out.push(Opt::Long(id, val));
                i += 1;
                continue;
            }
            if !a.starts_with('-') || a.len() == 1 {
                // non-option arguments are permuted to the end by GNU getopt
                i += 1;
                continue;
            }
            let chars: Vec<char> = a[1..].chars().collect();
            let mut k = 0;
            while k < chars.len() {
                let c = chars[k];
                if WITH_ARG.contains(c) {
                    let rest: String = chars[k + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        Some(rest)
                    } else {
                        i += 1;
                        args.get(i).cloned()
                    };
                    out.push(Opt::Arg(c, v));
                    break;
                } else if FLAGS.contains(c) {
                    out.push(Opt::Flag(c));
                } else {
                    eprintln!("{}: invalid option -- '{c}'", args[0]);
                    out.push(Opt::Unknown);
                }
                k += 1;
            }
            i += 1;
        }
        out
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        let home = match siem_daemon::homedir(&args[0]) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        };
        let log = Arc::new(WLog::new(ARGV0, &home));
        siem_ipc::os_net::set_logger(Arc::clone(&log));

        if let Err(e) = std::env::set_current_dir(&home) {
            let n = e.raw_os_error().unwrap_or(0);
            log.error(format!(
                "(1133): Unable to chdir to directory '{}' due to [({n})-({})].",
                home.display(),
                strerror(n)
            ));
            std::process::exit(1);
        }

        let ag = Arc::new(Agentd::new(Arc::clone(&log), InternalOptions::from_home(Path::new(""))));
        let agent_debug_level = ag.define_int("agent", "debug", 0, 2);
        ag.ints.agent_debug_level.store(agent_debug_level, Ordering::SeqCst);

        let mut test_config = false;
        let mut debug_level = 0;
        let mut run_foreground = false;
        let mut user = USER.to_string();
        let mut group = GROUPGLOBAL.to_string();
        let mut cfg = OSSECCONF.to_string();
        let (mut login, mut token, mut host): (Option<String>, Option<String>, Option<String>) = (None, None, None);
        let mut ssl_verify = true;

        for o in getopt(&args) {
            match o {
                Opt::Flag('V') => print_version(),
                Opt::Flag('h') => help_agentd(),
                Opt::Flag('d') => {
                    log.now_debug();
                    debug_level = 1;
                }
                Opt::Flag('f') => run_foreground = true,
                Opt::Flag('t') => test_config = true,
                Opt::Arg('u', v) => user = v.unwrap_or_else(|| ag.exit_critical("-u needs an argument")),
                Opt::Arg('g', v) => group = v.unwrap_or_else(|| ag.exit_critical("-g needs an argument")),
                Opt::Arg('D', v) => {
                    if v.is_none() {
                        ag.exit_critical("-D needs an argument");
                    }
                    log.warn("-D is deprecated.");
                }
                Opt::Arg('c', v) => cfg = v.unwrap_or_else(|| ag.exit_critical("-c needs an argument.")),
                Opt::Long(1, v) => {
                    login = Some(v.unwrap_or_else(|| ag.exit_critical("--uninstall-auth-login needs an argument")))
                }
                Opt::Long(2, v) => {
                    token = Some(v.unwrap_or_else(|| ag.exit_critical("--uninstall-auth-token needs an argument")))
                }
                Opt::Long(3, v) => {
                    host = Some(v.unwrap_or_else(|| ag.exit_critical("--uninstall-auth-host needs an argument")))
                }
                Opt::Long(4, v) => match v.as_deref() {
                    None | Some("") | Some("true") | Some("TRUE") | Some("1") => ssl_verify = true,
                    Some("false") | Some("FALSE") | Some("0") => ssl_verify = false,
                    _ => ag.exit_critical("--uninstall-ssl-verify accepts 'true'/'false' or '1'/'0' as arguments"),
                },
                _ => help_agentd(),
            }
        }

        // Anti tampering functionality
        if (token.is_some() || login.is_some()) && host.is_some() {
            let denied = uninstall::package_uninstall_validation(
                &log,
                token.as_deref(),
                login.as_deref(),
                host.as_deref().unwrap(),
                ssl_verify,
            );
            std::process::exit(i32::from(denied));
        }

        // Command line setting takes precedence
        if debug_level == 0 {
            for _ in 0..agent_debug_level {
                log.now_debug();
            }
        }

        log.debug1(format!("Wazuh home directory: {}", home.display()));
        log.debug1(startup_msg(std::process::id()));

        if config::client_conf(&ag, &cfg).is_err() {
            ag.exit_error(CLIENT_ERROR);
        }

        let servers = ag.cfg.read().unwrap().server.clone();
        if servers.first().map(|s| s.rip.is_empty()).unwrap_or(true) {
            log.error(AG_INV_IP);
            ag.exit_error(CLIENT_ERROR);
        }
        if !validate_address(&servers) {
            log.error(format!("(4112): Invalid server address found: '{}'", servers[0].rip));
            ag.exit_error(CLIENT_ERROR);
        }
        if !config::validate_ipv6_link_local_interface(&ag, &servers) {
            log.error(AG_INV_INT);
            ag.exit_error(CLIENT_ERROR);
        }

        {
            let mut c = ag.cfg.write().unwrap();
            if c.notify_time == 0 {
                c.notify_time = NOTIFY_TIME;
            }
            if c.max_time_reconnect_try == 0 {
                c.max_time_reconnect_try = RECONNECT_TIME;
            }
            if c.max_time_reconnect_try <= c.notify_time {
                c.max_time_reconnect_try = c.notify_time * 3;
                log.info(format!(
                    "Max time to reconnect can't be less than notify_time({}), using notify_time*3 ({})",
                    c.notify_time, c.max_time_reconnect_try
                ));
            }
        }

        if siem_daemon::get_user(&user).is_none() || siem_daemon::get_group(&group).is_none() {
            let e = errno();
            ag.exit_critical(format!("(1203): Invalid user '{user}' or group '{group}' given: {} ({e})", strerror(e)));
        }

        if test_config {
            std::process::exit(0);
        }

        siem_daemon::start_sig(ARGV0, Arc::clone(&log));

        agentd::agentd_start(ag, &home, &user, &group, run_foreground);
    }
}
