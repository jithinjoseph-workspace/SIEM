//! Wazuh Agentless Daemon CLI Binary (`src/agentlessd/main.c`)

use siem_agentlessd::config::AgentlessConfig;
use siem_agentlessd::daemon::AgentlessDaemon;
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
            "-h" | "--help" => {
                println!("Usage: wazuh-agentlessd [-c <config_path>] [-D <dir>]");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let config = if let Some(ref path) = config_path {
        AgentlessConfig::from_file(path).unwrap_or_else(|e| {
            eprintln!("Warning: could not read {}: {}. Starting with empty config.", path, e);
            AgentlessConfig::default()
        })
    } else {
        AgentlessConfig::default()
    };

    info!("Starting wazuh-agentlessd in {}...", base_dir.display());
    let daemon = AgentlessDaemon::new(config, &base_dir);
    daemon.run().await;

    Ok(())
}
