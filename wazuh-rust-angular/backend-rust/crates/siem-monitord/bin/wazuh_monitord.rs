//! Wazuh Monitord CLI Binary (`src/monitord/main.c`)

use siem_monitord::config::MonitorConfig;
use siem_monitord::daemon::MonitorDaemon;
use std::env;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let args: Vec<String> = env::args().collect();
    let mut config_path: Option<String> = None;
    let mut base_dir: PathBuf = PathBuf::from(".");
    let mut no_agents = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    config_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-D" => {
                if i + 1 < args.len() {
                    base_dir = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
            }
            "-n" => {
                no_agents = true;
            }
            "-h" | "--help" => {
                println!("Usage: wazuh-monitord [-c <config_path>] [-D <dir>] [-n]");
                println!("  -c <config>  Path to ossec.conf configuration");
                println!("  -D <dir>     Base working directory");
                println!("  -n           Disable agent monitoring");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let mut config = if let Some(ref path) = config_path {
        MonitorConfig::from_file(path).unwrap_or_else(|e| {
            eprintln!("Warning: could not read {}: {}. Using default config.", path, e);
            MonitorConfig::default()
        })
    } else {
        MonitorConfig::default()
    };

    if no_agents {
        config.monitor_agents = false;
    }

    info!("Starting wazuh-monitord daemon in {}...", base_dir.display());
    let mut daemon = MonitorDaemon::new(config, &base_dir);
    daemon.run().await;

    Ok(())
}
