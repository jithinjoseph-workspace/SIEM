//! Wazuh Active Response Execution Daemon CLI Binary (`src/os_execd/main.c`)
//!
//! CLI arguments:
//!   -V          Version and license message
//!   -h          This help message
//!   -d          Execute in debug mode
//!   -t          Test configuration
//!   -f          Run in foreground
//!   -g <group>  Group to run as
//!   -c <config> Configuration file to use

use siem_execd::{ActiveResponseEngine, CommandCatalog, ExecdConfig};
use std::env;
use std::path::PathBuf;
use std::process;

const ARGV0: &str = "wazuh-execd";
const VERSION: &str = "v4.14.7";

fn print_help() {
    println!("  {}: -[Vhdtf] [-g group] [-c config]", ARGV0);
    println!("    -V          Version and license message");
    println!("    -h          This help message");
    println!("    -d          Execute in debug mode");
    println!("    -t          Test configuration");
    println!("    -f          Run in foreground");
    println!("    -g <group>  Group to run as (default: ossec)");
    println!("    -c <config> Configuration file to use (default: ossec.conf)");
}

fn print_version() {
    println!("Wazuh {} - Active Response Execution Daemon", VERSION);
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
            "-g" => {
                if i + 1 < args.len() {
                    i += 1;
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

    // Read config
    let config = match ExecdConfig::from_file(&cfg_file) {
        Ok(c) => c,
        Err(e) => {
            if test_config {
                eprintln!("{}: Configuration error in '{}': {}", ARGV0, cfg_file, e);
                process::exit(1);
            }
            println!("{}: Active response configuration error or disabled: {}. Clean exit.", ARGV0, e);
            process::exit(0);
        }
    };

    if test_config {
        println!("{}: Configuration test successful.", ARGV0);
        process::exit(0);
    }

    if config.disabled {
        println!("{}: Active response disabled. Clean exit.", ARGV0);
        process::exit(0);
    }

    let catalog = CommandCatalog::new(PathBuf::from("active-response/bin"));
    let mut engine = ActiveResponseEngine::new(config, catalog);
    println!("{}: Active response daemon initialized.", ARGV0);

    // Periodic timeout checker would run in main loop
    let _ = engine.check_timeouts();
}
