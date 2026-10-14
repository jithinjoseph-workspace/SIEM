//! Wazuh Authd CLI Binary (`src/os_auth/main-server.c`)

use siem_authd::config::AuthdConfig;
use siem_authd::server::AuthDaemon;
use std::env;
use std::path::Path;
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
    let mut port: Option<u16> = None;
    let mut password: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if i + 1 < args.len() {
                    config_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-p" | "--port" => {
                if i + 1 < args.len() {
                    if let Ok(p) = args[i + 1].parse::<u16>() {
                        port = Some(p);
                    }
                    i += 1;
                }
            }
            "-P" | "--password" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-h" | "--help" => {
                println!("Usage: wazuh-authd [-c <config_path>] [-p <port>] [-P <password>]");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let mut config = if let Some(ref path) = config_path {
        AuthdConfig::from_file(path).unwrap_or_else(|e| {
            eprintln!("Warning: could not read {}: {}. Using default config.", path, e);
            AuthdConfig::default()
        })
    } else {
        AuthdConfig::default()
    };

    if let Some(p) = port {
        config.port = p;
    }
    if let Some(pw) = password {
        config.use_password = true;
        config.password = Some(pw);
    }

    info!("Starting wazuh-authd daemon on port {}...", config.port);
    let daemon = AuthDaemon::new(config, Some(Path::new("etc/client.keys")));
    daemon.run_server().await?;

    Ok(())
}
