mod agcom;
mod buffer;
mod client_agent;
mod control;
mod execd;
mod logcollector;
mod rootcheck;
mod sca;
mod syscheck;
mod syscollector;

use buffer::AgentBuffer;
use client_agent::ClientAgent;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "install-service" | "--install" => {
                control::install_service();
                return;
            }
            "uninstall-service" | "--uninstall" => {
                control::uninstall_service();
                return;
            }
            "start-service" | "--start" => {
                control::start_service();
                return;
            }
            "stop-service" | "--stop" => {
                control::stop_service();
                return;
            }
            "restart-service" | "--restart" => {
                control::restart_service();
                return;
            }
            "status-service" | "--status" => {
                control::query_status();
                return;
            }
            "--help" | "-h" | "help" => {
                control::print_help();
                return;
            }
            _ => {}
        }
    }

    control::print_banner();
    run_linux_agent().await;
}

async fn run_linux_agent() {
    let config = ClientAgent::load_config();
    let client = ClientAgent { config: config.clone() };

    info!("===============================================================");
    info!("Starting Wazuh Next-Gen Linux Endpoint Agent in Rust");
    info!("Agent ID:        {}", config.agent_id);
    info!("Agent Hostname:  {}", config.agent_name);
    info!("Target Manager:  {}", config.manager_url);
    info!("Distribution:    {}", ClientAgent::detect_linux_distro());
    info!("Platform:        {} ({})", std::env::consts::OS, std::env::consts::ARCH);
    info!("===============================================================");

    // 1. Initialize Resilient Agent Buffer (capacity: 5000 events, 500 eps)
    let (buffer, _buffer_worker) = AgentBuffer::new(
        config.manager_url.clone(),
        config.buffer_capacity,
        config.events_per_second,
    );
    let buffer = Arc::new(buffer);

    // 2. Perform Agent Registration with Manager
    client.register(&buffer).await;

    // 3. Spawn Keepalive Heartbeat Worker (every 10s)
    let _keepalive_handle = ClientAgent::spawn_keepalive_worker(
        config.agent_id.clone(),
        config.agent_name.clone(),
        config.manager_url.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(10),
    );

    // 4. Configure Monitored Directories for Linux Syscheck (FIM)
    let mut fim_paths = Vec::new();
    let linux_fim_targets = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/ssh/sshd_config",
        "/etc/pam.d",
        "/etc/crontab",
        "/etc/cron.d",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/boot",
        "./test_fim_linux",
    ];

    for target in linux_fim_targets {
        let p = PathBuf::from(target);
        if p.exists() {
            fim_paths.push(p);
        }
    }

    // 5. Spawn Core Wazuh Subsystems:
    info!("Spawning Wazuh Linux Subsystem Daemons:");

    // Module 1: wazuh-logcollector (auth.log, secure, audit.log, syslog)
    info!(" [✓] wazuh-logcollector (tailing /var/log/auth.log, audit.log, syslog)");
    let _logcollector_handle = logcollector::spawn_logcollector_worker(
        config.agent_id.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(4),
    );

    // Module 2: wazuh-syscheckd (FIM)
    info!(" [✓] wazuh-syscheckd (monitoring Linux critical files & directories)");
    let _syscheck_handle = syscheck::spawn_syscheck_worker(
        config.agent_id.clone(),
        fim_paths,
        Arc::clone(&buffer),
        Duration::from_secs(15),
    );

    // Module 3: wazuh-syscollector (System Inventory & Package Auditing)
    info!(" [✓] wazuh-syscollector (hardware, processes, listening ports, packages, services)");
    let _syscollector_handle = syscollector::spawn_syscollector_worker(
        config.agent_id.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(30),
    );

    // Module 4: wazuh-sca (Security Configuration Assessment - CIS Linux Benchmarks)
    info!(" [✓] wazuh-sca (evaluating CIS Linux Benchmarks & system hardening)");
    let _sca_handle = sca::spawn_sca_worker(
        config.agent_id.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(60),
    );

    // Module 5: wazuh-execd (Active Response / Remediation Dispatcher)
    info!(" [✓] wazuh-execd (active response: iptables/ufw drop, process termination, quarantine)");
    let _execd_handle = execd::spawn_active_response_worker(
        config.agent_id.clone(),
        config.manager_url.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(5),
    );

    // Module 6: wazuh-rootcheck (Rootkit Anomaly, Promiscuous Sniffers & Hidden Threat Detector)
    info!(" [✓] wazuh-rootcheck (scanning /dev/shm hidden files, promiscuous sniffers, trojan binaries)");
    let _rootcheck_handle = rootcheck::spawn_rootcheck_worker(
        config.agent_id.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(120),
    );

    info!("===============================================================");
    info!("Wazuh Linux Agent is RUNNING. Press Ctrl+C to stop.");
    info!("===============================================================");

    // Wait for termination signal
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Termination signal received. Shutting down Wazuh Linux Agent cleanly...");
        }
        Err(err) => {
            tracing::error!("Error listening for termination signal: {}", err);
        }
    }
}
