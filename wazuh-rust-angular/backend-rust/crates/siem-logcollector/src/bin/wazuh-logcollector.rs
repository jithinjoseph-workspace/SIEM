//! `logcollector/main.c`: the `wazuh-logcollector` command line.

#[cfg(not(unix))]
fn main() {
    eprintln!("wazuh-logcollector: this build runs on Unix only.");
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

    use siem_config::internal_options::InternalOptions;
    use siem_ipc::mq_op::{start_mq, INFINITE_OPENQ_ATTEMPTS, WRITE};
    use siem_log::WLog;
    use siem_logcollector::*;

    fn print_out(s: &str) {
        eprintln!("{s}");
    }

    fn help() -> ! {
        print_out(" ");
        print_out("Wazuh v4.14.7 - Wazuh Inc. (info@wazuh.com)");
        print_out("http://www.wazuh.com");
        print_out(&format!("  {ARGV0}: -[Vhdtf] [-c config]"));
        print_out("    -V          Version and license message");
        print_out("    -h          This help message");
        print_out("    -d          Execute in debug mode. This parameter");
        print_out("                can be specified multiple times");
        print_out("                to increase the debug level.");
        print_out("    -t          Test configuration");
        print_out("    -f          Run in foreground");
        print_out(&format!("    -c <config> Configuration file to use (default: {OSSECCONF})"));
        print_out(" ");
        std::process::exit(1);
    }

    fn version() -> ! {
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
            log.critical(format!(
                "(1133): Unable to chdir to directory '{}' due to [({n})-({})].",
                home.display(),
                strerror(n)
            ));
            std::process::exit(1);
        }
        let lc = Arc::new(Lc::new(Arc::clone(&log), InternalOptions::from_home(Path::new(""))));
        let dbg = lc.define_int("logcollector", "debug", 0, 2);
        lc.ints.lc_debug_level.store(dbg, Ordering::SeqCst);

        // getopt "Vtdhfc:"
        let (mut debug_level, mut test_config, mut foreground) = (0, false, false);
        let mut cfg = OSSECCONF.to_string();
        let mut i = 1;
        while i < args.len() {
            let a = &args[i];
            if a == "--" {
                break;
            }
            if !a.starts_with('-') || a.len() == 1 {
                i += 1;
                continue;
            }
            let chars: Vec<char> = a[1..].chars().collect();
            let mut k = 0;
            while k < chars.len() {
                match chars[k] {
                    'V' => version(),
                    'h' => help(),
                    'd' => {
                        log.now_debug();
                        debug_level = 1;
                    }
                    'f' => foreground = true,
                    't' => test_config = true,
                    'c' => {
                        let rest: String = chars[k + 1..].iter().collect();
                        cfg = if !rest.is_empty() {
                            rest
                        } else {
                            i += 1;
                            match args.get(i) {
                                Some(v) => v.clone(),
                                None => lc.exit_critical("-c needs an argument"),
                            }
                        };
                        break;
                    }
                    c => {
                        eprintln!("{}: invalid option -- '{c}'", args[0]);
                        help();
                    }
                }
                k += 1;
            }
            i += 1;
        }

        let Some(gid) = siem_daemon::get_group(GROUPGLOBAL) else {
            let e = errno();
            lc.exit_critical(format!("(1203): Invalid user '' or group '{GROUPGLOBAL}' given: {} ({e})", strerror(e)));
        };
        // Privsep_SetGroup
        // SAFETY: plain libc calls.
        unsafe {
            let g = gid as libc::gid_t;
            if libc::setgroups(1, &g) == -1 || libc::setegid(g) < 0 || libc::setgid(g) < 0 {
                let e = errno();
                lc.exit_critical(format!(
                    "(1130): Unable to switch to group '{GROUPGLOBAL}' due to [({e})-({})].",
                    strerror(e)
                ));
            }
        }

        if debug_level == 0 {
            for _ in 0..dbg {
                log.now_debug();
            }
        }
        log.debug1(format!("Wazuh home directory: {}", home.display()));

        output::hash_queues_init(&lc);
        if config::log_collector_config(&lc, &cfg) < 0 {
            log.error(format!("(1202): Configuration error at '{cfg}'."));
            std::process::exit(1);
        }
        if test_config {
            std::process::exit(0);
        }
        if lc.files.read().unwrap().logff.is_empty() {
            log.info("(1905): No file configured to monitor.");
        }

        siem_daemon::start_sig(ARGV0, Arc::clone(&log));

        let nofile = get(&lc.ints.nofile);
        if let Err(e) = siem_daemon::set_nofile(nofile as u64) {
            log.error(e);
        }
        if !foreground {
            log.now_daemon();
            siem_daemon::go_daemon(&log);
        }
        if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
            lc.exit_critical("(1212): Unable to create PID file.");
        }
        let q = start_mq(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
        if q < 0 {
            lc.exit_critical(format!("(1211): Unable to access queue: '{DEFAULTQUEUE}'. Giving up."));
        }
        lc.logr_queue.store(q, Ordering::SeqCst);

        collector::log_collector_start(lc);
    }
}
