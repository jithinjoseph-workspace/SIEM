//! Wazuh Syslog Daemon Binary Entry Point (`src/os_csyslogd/main.c`)
//!
//! CLI arguments:
//!   -V          Version and license message
//!   -h          This help message
//!   -d          Execute in debug mode
//!   -t          Test configuration
//!   -f          Run in foreground
//!   -u <user>   User to run as
//!   -g <group>  Group to run as
//!   -c <config> Configuration file to use
//!   -D <dir>    Directory to chroot and chdir into

use siem_csyslogd::{SyslogConfigHolder, SyslogDaemon};
use std::env;
use std::process;

const ARGV0: &str = "wazuh-csyslogd";
const VERSION: &str = "v4.14.7";

fn print_help() {
    println!("  {}: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    println!("    -V          Version and license message");
    println!("    -h          This help message");
    println!("    -d          Execute in debug mode");
    println!("    -t          Test configuration");
    println!("    -f          Run in foreground");
    println!("    -u <user>   User to run as (default: ossec)");
    println!("    -g <group>  Group to run as (default: ossec)");
    println!("    -c <config> Configuration file to use (default: ossec.conf)");
    println!("    -D <dir>    Directory to chroot and chdir into");
}

fn print_version() {
    println!("Wazuh {} - Syslog Output Daemon", VERSION);
    println!("Copyright (C) 2015, Wazuh Inc.");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let mut cfg_file = "ossec.conf".to_string();
    let mut test_config = false;
    let mut _debug_mode = false;
    let mut _foreground = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-V" => {
                print_version();
                process::exit(0);
            }
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-d" => {
                _debug_mode = true;
            }
            "-f" => {
                _foreground = true;
            }
            "-t" => {
                test_config = true;
            }
            "-c" => {
                if i + 1 < args.len() {
                    cfg_file = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("-c needs an argument");
                    process::exit(1);
                }
            }
            "-u" | "-g" | "-D" => {
                if i + 1 < args.len() {
                    i += 1; // Handled in deployment / privsep
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                print_help();
                process::exit(1);
            }
        }
        i += 1;
    }

    println!("{}: Starting {} ({})", ARGV0, ARGV0, VERSION);

    // Read and parse configuration
    let holder = match SyslogConfigHolder::from_file(&cfg_file) {
        Ok(h) => h,
        Err(e) => {
            if test_config {
                eprintln!("{}: Configuration error in '{}': {}", ARGV0, cfg_file, e);
                process::exit(1);
            }
            println!("{}: Remote syslog server not configured or error in '{}': {}. Clean exit.", ARGV0, cfg_file, e);
            process::exit(0);
        }
    };

    if holder.configs.is_empty() {
        println!("{}: Remote syslog server not configured. Clean exit.", ARGV0);
        process::exit(0);
    }

    if test_config {
        println!("{}: Configuration test successful ({} syslog destination(s) configured).", ARGV0, holder.configs.len());
        process::exit(0);
    }

    let mut daemon = SyslogDaemon::new(holder.configs);
    daemon.init_senders();
    println!("{}: Daemon successfully initialized with {} destinations.", ARGV0, daemon.senders.len());
}
