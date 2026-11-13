use std::fs;
use std::path::Path;
use std::process::Command;

pub const SERVICE_NAME: &str = "provigil-agent.service";
pub const SYSTEMD_PATH: &str = "/etc/systemd/system/provigil-agent.service";

pub fn print_banner() {
    println!(r#"
  ____             __     ___       _ _ 
 |  _ \ _ __ ___   \ \   / (_) __ _(_) |
 | |_) | '__/ _ \   \ \ / /| |/ _` | | |
 |  __/| | | (_) |   \ V / | | (_| | | |
 |_|   |_|  \___/     \_/  |_|\__, |_|_|
                              |___/     
        ProVigil Linux Endpoint Security Agent
"#);
}

/// Generate and install the systemd service unit.
pub fn install_service() {
    let current_exe = std::env::current_exe()
        .unwrap_or_else(|_| Path::new("/opt/provigil-agent/bin/siem-agent-linux").to_path_buf());
    let exe_str = current_exe.to_string_lossy();

    let service_content = format!(
        r#"[Unit]
Description=ProVigil Linux Endpoint Security Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/provigil-agent
EnvironmentFile=-/opt/provigil-agent/etc/agent.env
EnvironmentFile=-/etc/provigil-agent/agent.env
ExecStart={} --daemon
Restart=always
RestartSec=10
RestartPreventExitStatus=42
KillMode=process
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"#,
        exe_str
    );

    if Path::new("/etc/systemd/system").exists() {
        if let Err(e) = fs::write(SYSTEMD_PATH, &service_content) {
            eprintln!("Failed to write systemd service file: {}", e);
            return;
        }
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        let _ = Command::new("systemctl").args(["enable", SERVICE_NAME]).status();
        println!(" [OK] Installed and enabled systemd service: {}", SYSTEMD_PATH);
    } else {
        println!(" [INFO] Non-systemd environment detected. Generated service unit:");
        println!("{}", service_content);
    }
}

/// Uninstall systemd service.
pub fn uninstall_service() {
    if Path::new(SYSTEMD_PATH).exists() {
        let _ = Command::new("systemctl").args(["stop", SERVICE_NAME]).status();
        let _ = Command::new("systemctl").args(["disable", SERVICE_NAME]).status();
        let _ = fs::remove_file(SYSTEMD_PATH);
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        println!(" [OK] Uninstalled systemd service: {}", SERVICE_NAME);
    } else {
        println!(" [WARN] Systemd service file {} not found.", SYSTEMD_PATH);
    }
}

pub fn start_service() {
    let _ = Command::new("systemctl").args(["start", SERVICE_NAME]).status();
    println!(" [OK] Triggered systemctl start {}", SERVICE_NAME);
}

pub fn stop_service() {
    let _ = Command::new("systemctl").args(["stop", SERVICE_NAME]).status();
    println!(" [OK] Triggered systemctl stop {}", SERVICE_NAME);
}

pub fn restart_service() {
    let _ = Command::new("systemctl").args(["restart", SERVICE_NAME]).status();
    println!(" [OK] Triggered systemctl restart {}", SERVICE_NAME);
}

pub fn query_status() {
    let output = Command::new("systemctl")
        .args(["status", SERVICE_NAME])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!("--- Systemd Status for {} ---", SERVICE_NAME);
            if !stdout.is_empty() {
                println!("{}", stdout);
            }
            if !stderr.is_empty() {
                eprintln!("{}", stderr);
            }
        }
        Err(e) => {
            eprintln!("Failed to query systemctl: {}", e);
        }
    }
}

pub fn print_help() {
    print_banner();
    println!(r#"
USAGE:
    siem-agent-linux [COMMAND | FLAGS]

COMMANDS:
    start                Run the agent in console foreground
    start-service        Start the systemd agent service
    stop-service         Stop the systemd agent service
    restart-service      Restart the agent service
    status-service       Check the systemd daemon status
    install-service      Install and register /etc/systemd/system/provigil-agent.service
    uninstall-service    Disable and remove the systemd service

FLAGS:
    --daemon             Run continuously as systemd daemon
    --console            Run interactively in foreground
    -h, --help           Show this help information

ENVIRONMENT VARIABLES:
    SIEM_MANAGER_URL     Target manager endpoint (default: https://127.0.0.1:8443)
    SIEM_AGENT_ID        Agent ID override
    HOSTNAME             Host name override
"#);
}
