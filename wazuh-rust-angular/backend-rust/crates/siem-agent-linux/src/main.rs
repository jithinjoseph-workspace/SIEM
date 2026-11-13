mod agcom;
mod buffer;
mod client_agent;
#[allow(dead_code)]
mod config_parser;
mod control;
mod enroll;
mod execd;
pub mod inotify_watcher;
mod lifecycle;
mod logcollector;
mod rootcheck;
mod sca;
mod syscheck;
mod syscollector;
pub mod whodata;

use buffer::AgentBuffer;
use client_agent::ClientAgent;
use lifecycle::LifecycleCoordinator;
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
    if lifecycle::is_decommissioned() {
        tracing::warn!("provigil-agentd: Endpoint decommissioned by manager. Exiting cleanly (status 42).");
        std::process::exit(42);
    }

    let mut config = ClientAgent::load_config();
    enroll::export_tenant_key(config.tenant_key.as_deref());

    if config.agent_id.is_empty() {
        let e = enroll::enroll_until_done(
            &config.manager_url,
            &config.agent_name,
            &config.agent_group,
            "linux",
            config.tenant_key.as_deref(),
        )
        .await;
        let keys_path = ["/opt/provigil-agent/etc/client.keys", "/etc/provigil-agent/client.keys"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.parent().map(|d| d.exists()).unwrap_or(false))
            .unwrap_or_else(|| std::path::PathBuf::from("client.keys"));
        if let Err(err) = enroll::write_client_keys(&keys_path, &e) {
            tracing::warn!("Could not store client.keys at {}: {}", keys_path.display(), err);
        }
        enroll::export_agent_key(&e.raw_key);
        config.agent_id = e.agent_id;
        config.agent_name = e.agent_name;
        config.agent_key = e.raw_key;
    }

    if !config.agent_id.trim().is_empty() {
        std::env::set_var("SIEM_AGENT_ID", config.agent_id.trim());
    }

    let lifecycle = Arc::new(LifecycleCoordinator::new(config.agent_id.clone(), config.manager_url.clone()));
    if let Some(state) = lifecycle.fetch_state().await {
        lifecycle.set_state(state);
    }
    let _lifecycle_poller = Arc::clone(&lifecycle).spawn_poll_worker(Duration::from_secs(15));
    let client = ClientAgent { config: config.clone() };

    info!("===============================================================");
    info!("Starting ProVigil Linux Endpoint Agent");
    info!("Agent ID:        {}", config.agent_id);
    info!("Agent Hostname:  {}", config.agent_name);
    info!("Target Manager:  {}", config.manager_url);
    info!("Distribution:    {}", ClientAgent::detect_linux_distro());
    info!("Platform:        {} ({})", std::env::consts::OS, std::env::consts::ARCH);
    info!("===============================================================");

    let (buffer, _buffer_worker) = AgentBuffer::new(
        config.manager_url.clone(),
        config.buffer_capacity,
        config.events_per_second,
        Arc::clone(&lifecycle),
    );
    let buffer = Arc::new(buffer);

    client.register(&buffer).await;

    let _keepalive_handle = ClientAgent::spawn_keepalive_worker(
        config.agent_id.clone(),
        config.agent_name.clone(),
        config.manager_url.clone(),
        Arc::clone(&buffer),
        Arc::clone(&lifecycle),
        Duration::from_secs(10),
    );

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
    ];

    for target in linux_fim_targets {
        let p = PathBuf::from(target);
        if p.exists() {
            fim_paths.push(p);
        }
    }

    info!("Starting ProVigil endpoint telemetry modules:");

    info!(" - provigil-logcollector (auth.log, audit.log, syslog)");
    let _logcollector_handle = logcollector::spawn_logcollector_worker(
        config.agent_id.clone(),
        Arc::clone(&buffer),
        Arc::clone(&lifecycle),
        Duration::from_secs(4),
    );

    info!(" - provigil-syscheckd (file integrity monitoring)");
    let _syscheck_handle = syscheck::spawn_syscheck_worker(
        config.agent_id.clone(),
        fim_paths,
        Arc::clone(&buffer),
        Arc::clone(&lifecycle),
        Duration::from_secs(15),
    );

    info!(" - provigil-syscollector (system inventory & packages)");
    let _syscollector_handle = syscollector::spawn_syscollector_worker(
        config.agent_id.clone(),
        Arc::clone(&buffer),
        Arc::clone(&lifecycle),
        Duration::from_secs(30),
    );

    info!(" - provigil-sca (CIS Linux security configuration assessment)");
    let _sca_handle = sca::spawn_sca_worker(
        config.agent_id.clone(),
        Arc::clone(&buffer),
        Arc::clone(&lifecycle),
        Duration::from_secs(60),
    );

    info!(" - provigil-execd (active response dispatcher)");
    let _execd_handle = execd::spawn_active_response_worker(
        config.agent_id.clone(),
        config.agent_key.clone(),
        config.manager_url.clone(),
        Arc::clone(&buffer),
        Arc::clone(&lifecycle),
        Duration::from_secs(5),
    );

    info!(" - provigil-rootcheck (anomaly & rootkit scanner)");
    let _rootcheck_handle = rootcheck::spawn_rootcheck_worker(
        config.agent_id.clone(),
        Arc::clone(&buffer),
        Arc::clone(&lifecycle),
        Duration::from_secs(120),
    );

    info!("===============================================================");
    info!("ProVigil Linux Agent is RUNNING.");
    info!("===============================================================");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Termination signal received. Shutting down ProVigil Linux Agent cleanly...");
        }
        _ = async {
            while !lifecycle.is_terminated() {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        } => {
            info!("Lifecycle coordinator triggered agent termination. Process exiting cleanly.");
        }
    }
}
