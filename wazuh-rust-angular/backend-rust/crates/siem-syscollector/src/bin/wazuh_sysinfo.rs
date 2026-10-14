//! Wazuh SysInfo Test Tool / CLI (mirroring src/data_provider/testtool/main.cpp)
//!
//! Provides the sysinfo diagnostic CLI tool matching sysinfo_test_tool.
//! Supports:
//!   --hardware
//!   --networks
//!   --packages
//!   --processes
//!   --ports
//!   --os
//!   --hotfixes
//!   --groups
//!   --users
//!   --services
//!   --browser-extensions

use siem_syscollector::provider::SysInfoProvider;
use std::env;

fn print_usage() {
    eprintln!("Usage: wazuh-sysinfo [options]");
    eprintln!();
    eprintln!("Optional arguments:");
    eprintln!("  --hardware            Prints the current Operating System hardware information.");
    eprintln!("  --networks            Prints the current Operating System networks information.");
    eprintln!("  --packages            Prints the current Operating System packages information.");
    eprintln!("  --processes           Prints the current Operating System processes information.");
    eprintln!("  --ports               Prints the current Operating System ports information.");
    eprintln!("  --os                  Prints the current Operating System information.");
    eprintln!("  --hotfixes            Prints the current Operating System hotfixes information.");
    eprintln!("  --groups              Prints the current Operating System groups information.");
    eprintln!("  --users               Prints the current Operating System users information.");
    eprintln!("  --services            Prints the current Operating System services information.");
    eprintln!("  --browser-extensions  Prints the current Operating System browser extensions.");
    eprintln!("  --all                 Prints all inventory categories.");
    eprintln!("  -h, --help            Prints this help message.");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        print_usage();
        return;
    }

    let mut printed = false;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--hardware" => {
                let hw = SysInfoProvider::get_hardware();
                println!("{}", serde_json::to_string_pretty(&hw).unwrap_or_default());
                printed = true;
            }
            "--networks" => {
                let (ifaces, protocols, addrs) = SysInfoProvider::get_networks();
                let output = serde_json::json!({
                    "interfaces": ifaces,
                    "protocols": protocols,
                    "addresses": addrs,
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
                printed = true;
            }
            "--packages" | "--packages-cb" => {
                let pkgs = SysInfoProvider::get_packages();
                println!("{}", serde_json::to_string_pretty(&pkgs).unwrap_or_default());
                printed = true;
            }
            "--processes" | "--processes-cb" => {
                let procs = SysInfoProvider::get_processes();
                println!("{}", serde_json::to_string_pretty(&procs).unwrap_or_default());
                printed = true;
            }
            "--ports" => {
                let ports = SysInfoProvider::get_ports();
                println!("{}", serde_json::to_string_pretty(&ports).unwrap_or_default());
                printed = true;
            }
            "--os" => {
                let os = SysInfoProvider::get_os();
                println!("{}", serde_json::to_string_pretty(&os).unwrap_or_default());
                printed = true;
            }
            "--hotfixes" => {
                let hotfixes = SysInfoProvider::get_hotfixes();
                println!("{}", serde_json::to_string_pretty(&hotfixes).unwrap_or_default());
                printed = true;
            }
            "--groups" => {
                let groups = SysInfoProvider::get_groups();
                println!("{}", serde_json::to_string_pretty(&groups).unwrap_or_default());
                printed = true;
            }
            "--users" => {
                let users = SysInfoProvider::get_users();
                println!("{}", serde_json::to_string_pretty(&users).unwrap_or_default());
                printed = true;
            }
            "--services" => {
                let services = SysInfoProvider::get_services();
                println!("{}", serde_json::to_string_pretty(&services).unwrap_or_default());
                printed = true;
            }
            "--browser-extensions" => {
                let ext = SysInfoProvider::get_browser_extensions();
                println!("{}", serde_json::to_string_pretty(&ext).unwrap_or_default());
                printed = true;
            }
            "--all" => {
                let (ifaces, protocols, addrs) = SysInfoProvider::get_networks();
                let full = serde_json::json!({
                    "hardware": SysInfoProvider::get_hardware(),
                    "os": SysInfoProvider::get_os(),
                    "network_interfaces": ifaces,
                    "network_protocols": protocols,
                    "network_addresses": addrs,
                    "packages": SysInfoProvider::get_packages(),
                    "ports": SysInfoProvider::get_ports(),
                    "processes": SysInfoProvider::get_processes(),
                    "hotfixes": SysInfoProvider::get_hotfixes(),
                    "groups": SysInfoProvider::get_groups(),
                    "users": SysInfoProvider::get_users(),
                    "services": SysInfoProvider::get_services(),
                    "browser_extensions": SysInfoProvider::get_browser_extensions(),
                });
                println!("{}", serde_json::to_string_pretty(&full).unwrap_or_default());
                printed = true;
            }
            "-h" | "--help" => {
                print_usage();
                return;
            }
            other => {
                eprintln!("Unknown option: {}", other);
                print_usage();
                std::process::exit(1);
            }
        }
    }

    if !printed {
        print_usage();
    }
}
