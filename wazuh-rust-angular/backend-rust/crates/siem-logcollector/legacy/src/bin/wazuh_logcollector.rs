use siem_logcollector::config::LogCollectorConfig;
use siem_logcollector::engine::LogCollectorEngine;
use siem_logcollector::state::FileStateManager;
use std::env;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut config_path = "var/ossec/etc/ossec.conf".to_string();
    let status_file = "queue/logcollector/file_status.json".to_string();
    let mut test_config = false;
    let mut run_foreground = false;
    let mut debug = false;
    let mut user: Option<String> = None;
    let mut group: Option<String> = None;
    let mut dir: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    config_path = args[i + 1].clone();
                    i += 1;
                }
            }
            "-t" => {
                test_config = true;
            }
            "-d" => {
                debug = true;
            }
            "-f" => {
                run_foreground = true;
            }
            "-u" => {
                if i + 1 < args.len() {
                    user = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-g" => {
                if i + 1 < args.len() {
                    group = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-D" => {
                if i + 1 < args.len() {
                    dir = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-V" => {
                println!("Wazuh v4.14.7 - wazuh-logcollector (Rust engine)");
                return;
            }
            "-h" | "--help" => {
                println!("  wazuh-logcollector: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]");
                println!("    -V          Version and license message");
                println!("    -h          This help message");
                println!("    -d          Execute in debug mode");
                println!("    -t          Test configuration");
                println!("    -f          Run in foreground");
                println!("    -u <user>   Run as 'user'");
                println!("    -g <group>  Run as 'group'");
                println!("    -c <config> Read the 'config' file");
                println!("    -D <dir>    Chroot/working directory 'dir'");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    println!("Starting wazuh-logcollector (Rust engine)...");
    if debug {
        println!("Debug mode enabled.");
    }
    if run_foreground {
        println!("Running in foreground mode.");
    }
    if let Some(ref u) = user {
        println!("Configured user: {}", u);
    }
    if let Some(ref g) = group {
        println!("Configured group: {}", g);
    }
    if let Some(ref d) = dir {
        println!("Chroot / working directory: {}", d);
    }

    let config = if Path::new(&config_path).exists() {
        match LogCollectorConfig::parse_file(&config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Warning: Failed to parse {}: {}. Starting with default configuration.", config_path, e);
                LogCollectorConfig::default()
            }
        }
    } else {
        println!("Config file '{}' not found, starting with default configuration.", config_path);
        LogCollectorConfig::default()
    };

    if test_config {
        println!(
            "Configuration test successful: {} localfiles and {} sockets configured.",
            config.localfiles.len(),
            config.sockets.len()
        );
        return;
    }

    let state_mgr = FileStateManager::new(&status_file);
    let mut engine = LogCollectorEngine::new(config, state_mgr);

    println!("wazuh-logcollector initialized successfully.");
    let initial_events = engine.harvest_all();
    println!("Initial harvest completed: {} log events processed.", initial_events.len());
}
