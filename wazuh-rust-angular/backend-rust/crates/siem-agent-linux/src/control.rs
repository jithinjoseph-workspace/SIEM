use std::fs;
use std::path::Path;
use std::process::Command;

pub const SERVICE_NAME: &str = "wazuh-rust-agent.service";
pub const SYSTEMD_PATH: &str = "/etc/systemd/system/wazuh-rust-agent.service";

pub fn print_banner() {
    println!(r#"
 __          __                 _        _____              _     
 \ \        / /                | |      |  __ \            | |    
  \ \  /\  / /__ _  _____   _  | |__    | |__) | _   _ ___ | |_   
   \ \/  \/ / _` ||_  / | | | | '_ \   |  _  / | | | / __|| __|  
    \  /\  / (_| | / /| |_| | | | | |  | | \ \ | |_| \__ \| |_   
     \/  \/ \__,_|/___|\__,_| |_| |_|  |_|  \_\ \__,_|___/ \__|  
             Wazuh Next-Gen Linux Endpoint Agent (Rust)
"#);
}

/// Generate and install the systemd service file
pub fn install_service() {
    let current_exe = std::env::current_exe().unwrap_or_else(|_| Path::new("/usr/local/bin/siem-agent-linux").to_path_buf());
    let exe_str = current_exe.to_string_lossy();

    let service_content = format!(
        r#"[Unit]
Description=Wazuh Next-Gen Endpoint Security Agent (Rust)
Documentation=https://wazuh.com
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/ossec
ExecStart={} --daemon
Restart=always
RestartSec=10
KillMode=process
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"#,
        exe_str
    );

    // On Linux systems, write to /etc/systemd/system/
    if Path::new("/etc/systemd/system").exists() {
        if let Err(e) = fs::write(SYSTEMD_PATH, &service_content) {
            eprintln!("Failed to write systemd service file: {}", e);
            return;
        }
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        let _ = Command::new("systemctl").args(["enable", SERVICE_NAME]).status();
        println!(" [✓] Successfully installed and enabled systemd service: {}", SYSTEMD_PATH);
    } else {
        println!(" [i] Non-systemd system detected or test environment. Generated service template:");
        println!("{}", service_content);
    }
}

/// Uninstall systemd service
pub fn uninstall_service() {
    if Path::new(SYSTEMD_PATH).exists() {
        let _ = Command::new("systemctl").args(["stop", SERVICE_NAME]).status();
        let _ = Command::new("systemctl").args(["disable", SERVICE_NAME]).status();
        let _ = fs::remove_file(SYSTEMD_PATH);
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        println!(" [✓] Successfully uninstalled systemd service: {}", SERVICE_NAME);
    } else {
        println!(" [!] Systemd service file {} not found.", SYSTEMD_PATH);
    }
}

pub fn start_service() {
    let _ = Command::new("systemctl").args(["start", SERVICE_NAME]).status();
    println!(" [✓] Triggered systemctl start {}", SERVICE_NAME);
}

pub fn stop_service() {
    let _ = Command::new("systemctl").args(["stop", SERVICE_NAME]).status();
    println!(" [✓] Triggered systemctl stop {}", SERVICE_NAME);
}

pub fn restart_service() {
    let _ = Command::new("systemctl").args(["restart", SERVICE_NAME]).status();
    println!(" [✓] Triggered systemctl restart {}", SERVICE_NAME);
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

COMMANDS (wazuh-control equivalent):
    start                Run the agent in console foreground
    start-service        Start the systemd agent service (systemctl start)
    stop-service         Stop the systemd agent service (systemctl stop)
    restart-service      Restart the agent service
    status-service       Check the systemd daemon status
    install-service      Install and register /etc/systemd/system/wazuh-rust-agent.service
    uninstall-service    Disable and remove the systemd service

FLAGS:
    --daemon             Run continuously as systemd daemon
    --console            Run interactively in foreground
    -h, --help           Show this help information

ENVIRONMENT VARIABLES:
    SIEM_MANAGER_URL     Target SIEM manager endpoint (default: http://127.0.0.1:8088)
    SIEM_AGENT_ID        Agent ID (default: 002)
    HOSTNAME             Host name override
"#);
}
