//! `os_execd/main.c`: the `wazuh-execd` command line (Unix; on Windows
//! execd runs inside `wazuh-agent.exe`).

#[cfg(not(unix))]
fn main() {
    eprintln!("wazuh-execd: runs inside wazuh-agent.exe on Windows.");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    unix::main();
}

#[cfg(unix)]
mod unix {
    use std::path::Path;
    use std::sync::{Arc, OnceLock};

    use siem_config::internal_options::InternalOptions;
    use siem_execd::*;
    use siem_log::WLog;

    static EX: OnceLock<Arc<Execd>> = OnceLock::new();

    fn print_out(s: &str) {
        eprintln!("{s}");
    }

    fn help() -> ! {
        print_out(" ");
        print_out("Wazuh v4.14.7 - Wazuh Inc. (info@wazuh.com)");
        print_out("http://www.wazuh.com");
        print_out(&format!("  {ARGV0}: -[Vhdtf] [-g group] [-c config]"));
        print_out("    -V          Version and license message");
        print_out("    -h          This help message");
        print_out("    -d          Execute in debug mode. This parameter");
        print_out("                can be specified multiple times");
        print_out("                to increase the debug level.");
        print_out("    -t          Test configuration");
        print_out("    -f          Run in foreground");
        print_out(&format!("    -g <group>  Group to run as (default: {GROUPGLOBAL})"));
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

    /// `ExecdShutdown(sig)` before `HandleSIG`
    fn shutdown() {
        if let Some(ex) = EX.get() {
            execd::execd_shutdown(ex);
        }
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
        siem_fileop::set_logger(Arc::clone(&log));
        if let Err(e) = std::env::set_current_dir(&home) {
            let n = e.raw_os_error().unwrap_or(0);
            log.critical(format!("(1133): Unable to chdir to directory '{}' due to [({n})-({})].", home.display(), strerror(n)));
            std::process::exit(1);
        }
        let ex = Arc::new(Execd::new(Arc::clone(&log), InternalOptions::from_home(Path::new(""))));
        let _ = EX.set(Arc::clone(&ex));

        // getopt "Vtdhfg:c:"
        let (mut test_config, mut foreground, mut debug_level) = (false, false, 0);
        let mut group = GROUPGLOBAL.to_string();
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
                        debug_level = 1;
                        log.now_debug();
                    }
                    'f' => foreground = true,
                    't' => test_config = true,
                    c @ ('g' | 'c') => {
                        let rest: String = chars[k + 1..].iter().collect();
                        let v = if !rest.is_empty() {
                            rest
                        } else {
                            i += 1;
                            match args.get(i) {
                                Some(v) => v.clone(),
                                None => help(),
                            }
                        };
                        if c == 'g' {
                            group = v;
                        } else {
                            cfg = v;
                        }
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

        if debug_level == 0 {
            for _ in 0..ex.define_int("execd", "debug", 0, 2) {
                log.now_debug();
            }
        }
        log.debug1(format!("Wazuh home directory: {}", home.display()));

        let Some(gid) = siem_daemon::get_group(&group) else {
            let e = errno();
            ex.exit_critical(format!("(1203): Invalid user '' or group '{group}' given: {} ({e})", strerror(e)));
        };
        // Privsep_SetGroup
        // SAFETY: plain libc calls.
        unsafe {
            let g = gid as libc::gid_t;
            if libc::setgroups(1, &g) == -1 || libc::setegid(g) < 0 || libc::setgid(g) < 0 {
                let e = errno();
                ex.exit_critical(format!("(1130): Unable to switch to group '{group}' due to [({e})-({})].", strerror(e)));
            }
        }

        let c = config::execd_config(&ex, &cfg);
        if c < 0 {
            ex.exit_error(format!("(1202): Configuration error at '{cfg}'."));
        }
        if test_config {
            std::process::exit(0);
        }

        siem_daemon::start_sig2(ARGV0, Arc::clone(&log), shutdown);

        if !foreground {
            log.now_daemon();
            siem_daemon::go_daemon(&log);
        }

        if c == 1 {
            log.info(EXEC_DISABLED);
        }

        if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
            ex.exit_critical("(1212): Unable to create PID file.");
        }

        // Start com request thread (CreateThreadJoinable logs the stack size; a missing option is fatal)
        match siem_config::internal_options::InternalOptions::from_home("").get_int("wazuh", "thread_stack_size", 2048, 65536) {
            Ok(kib) => log.debug2(format!("Thread stack size set to: {kib} KiB")),
            Err(err) => ex.exit_critical(&err.0),
        }
        let e = Arc::clone(&ex);
        let wcom = std::thread::spawn(move || wcom::wcom_main(&e));

        log.info(format!("Started (pid: {}).", std::process::id()));

        // If AR is disabled, do not continue
        if c == 1 {
            let _ = wcom.join();
            std::process::exit(0);
        }

        let q = siem_ipc::mq_op::start_mq(EXECQUEUE, siem_ipc::mq_op::READ, 0);
        if q < 0 {
            ex.exit_critical(format!("(1210): Queue '{EXECQUEUE}' not accessible: '{}'", strerror(errno())));
        }
        execd::execd_start(&ex, q);
    }
}
