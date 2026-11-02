//! `wazuh-reportd` (reportd/report.c `main`): reads alerts on stdin and
//! prints the report (`os_ReportdStart`, ported in `siem_maild::report`) to
//! stderr. `wazuh-reportd -[Vhdtns] [-u user] [-g group] [-D dir] [-f filter value] [-r filter value]`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use siem_log::WLog;
use siem_maild::cfile::CFile;
use siem_maild::report::{os_report_configfilter, os_reportd_start, ReportFilter, REPORT_FILTER, REPORT_RELATED};

const ARGV0: &str = "wazuh-reportd";
const USER: &str = "wazuh";
const GROUPGLOBAL: &str = "wazuh";

/// `help_reportd`
fn help(home: &str) -> ! {
    for l in [
        " ".to_string(),
        "Wazuh v4.14.7 - Wazuh Inc. (info@wazuh.com)".into(),
        "http://www.wazuh.com".into(),
        "  Generate reports (via stdin)".into(),
        format!("  {ARGV0}: -[Vhdtns] [-u user] [-g group] [-D dir] [-f filter value] [-r filter value]"),
        "    -V          Version and license message".into(),
        "    -h          This help message".into(),
        "    -d          Execute in debug mode. This parameter".into(),
        "                can be specified multiple times".into(),
        "                to increase the debug level.".into(),
        "    -t          Test configuration".into(),
        "    -n          Create description for the report".into(),
        "    -s          Show the alert dump".into(),
        format!("    -u <user>   User to run as (default: {USER})"),
        format!("    -g <group>  Group to run as (default: {GROUPGLOBAL})"),
        format!("    -D <dir>    Directory to chroot and chdir into (default: {home})"),
        "    -f <filter> <value> Filter the results".into(),
        "    -r <filter> <value> Show related entries".into(),
        "    Filters allowed: group, rule, level, location,".into(),
        "                     user, srcip, filename".into(),
        "  Examples:".into(),
        "     -f group authentication_success (to filter on login success)".into(),
        "     -f level 10 (to filter on level >= 10)".into(),
        "     -f group authentication -r user srcip (to show srcip for all users)".into(),
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

/// stdin as the alerts "file" (`fileq->fp = stdin`)
fn stdin_file() -> std::fs::File {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned().expect("stdin"))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        std::fs::File::from(std::io::stdin().as_handle().try_clone_to_owned().expect("stdin"))
    }
}

fn main() {
    let argv0 = std::env::args().next().unwrap_or_default();
    let default_home = match siem_daemon::homedir(&argv0) {
        Ok(h) => h.to_string_lossy().into_owned(),
        Err(e) => early_exit(e),
    };
    let mut home = default_home.clone();
    let (mut user, mut group) = (USER.to_string(), GROUPGLOBAL.to_string());
    let (mut debug, mut test) = (0, false);
    let mut filter = ReportFilter::default();
    // the filter errors happen before the logger knows the home: collected, then logged
    let log0 = Arc::new(WLog::new_server(ARGV0, &PathBuf::new()));
    // getopt(argc, argv, "Vdhstu:g:D:f:v:n:r:"); -f / -r also take the next argument (argv[optind])
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
                    eprintln!(
                        "This program is free software; you can redistribute it and/or modify\n\
                         it under the terms of the GNU General Public License (version 2) as \n\
                         published by the Free Software Foundation. For more details, go to \n\
                         https://www.gnu.org/licenses/gpl.html\n"
                    );
                    std::process::exit(0);
                }
                'h' => help(&default_home),
                'd' => debug += 1,
                't' => test = true,
                's' => filter.show_alerts = 1,
                c @ ('u' | 'g' | 'D' | 'n' | 'f' | 'r' | 'v') => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => {
                                eprintln!("{argv0}: option requires an argument -- '{c}'");
                                help(&default_home)
                            }
                        }
                    };
                    match c {
                        'u' => user = v,
                        'g' => group = v,
                        'D' => home = v,
                        'n' => filter.report_name = Some(v),
                        'v' => help(&default_home),
                        _ => {
                            // the value is argv[optind], consumed by optind++
                            i += 1;
                            let Some(value) = args.get(i).cloned() else {
                                fatal(&log0, if c == 'f' { "-f needs two argument" } else { "-r needs two argument" });
                            };
                            let kind = if c == 'f' { REPORT_FILTER } else { REPORT_RELATED };
                            let mut errs = Vec::new();
                            if os_report_configfilter(&v, &value, &mut filter, kind, &mut |m| errs.push(m)) != 0 {
                                for m in errs {
                                    log0.error(m);
                                }
                                fatal(&log0, "(1202): Configuration error at 'user argument'.");
                            }
                        }
                    }
                    j = chars.len();
                    continue;
                }
                o => {
                    eprintln!("{argv0}: invalid option -- '{o}'");
                    help(&default_home)
                }
            }
            j += 1;
        }
        i += 1;
    }
    if let Err(e) = std::env::set_current_dir(&home) {
        early_exit(&format!("(1133): Unable to chdir to directory '{home}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), siem_maild::strerror(&e)));
    }
    let log = Arc::new(WLog::new_server(ARGV0, &PathBuf::new()));
    for _ in 0..debug {
        log.now_debug();
    }
    siem_maild::set_logger(log.clone());
    log.debug1(format!("Wazuh home directory: {home}"));

    #[cfg(unix)]
    if siem_daemon::get_user(&user).is_none() || siem_daemon::get_group(&group).is_none() {
        let e = std::io::Error::last_os_error();
        fatal(&log, &format!("(1203): Invalid user '{user}' or group '{group}' given: {} ({})", siem_maild::strerror(&e), e.raw_os_error().unwrap_or(0)));
    }
    if test {
        std::process::exit(0);
    }
    if let Err(m) = siem_daemon::privsep(&user, &group, Path::new(&home), true) {
        fatal(&log, &m);
    }
    log.debug1(format!("Chrooted to directory: {home}, using user: {user}"));
    siem_daemon::start_sig(ARGV0, log.clone());
    if siem_daemon::create_pid(ARGV0, std::process::id(), &log).is_err() {
        fatal(&log, "(1212): Unable to create PID file.");
    }
    log.info(format!("Started (pid: {}).", std::process::id()));

    // l_print_out: every report line to stderr
    let report = os_reportd_start(&filter, CFile::from_file(stdin_file()));
    use std::io::Write;
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(&report);
    let _ = err.flush();
    // exit(0) runs the atexit HandleExit: PID file removed
    siem_daemon::handle_exit();
    std::process::exit(0);
}
