mod active_response;
mod buffer;
mod eventchannel;
mod fim;
mod registry;
mod sca;
mod syscollector;
#[cfg(windows)]
pub mod win_service;

use buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Core asynchronous agent loop that spawns and manages all Wazuh telemetry workers.
pub async fn run_agent_loop() {
    // 0. Enable DLL verification (matching Wazuh win_utils.c: enable_dll_verification to prevent DLL hijacking)
    #[cfg(windows)]
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetDllDirectoryW(lpPathName: *const u16) -> i32;
        }
        let empty: [u16; 1] = [0];
        let _ = SetDllDirectoryW(empty.as_ptr());
    }

    // 0. Load credentials from client.keys (if present)
    let (keys_id, keys_name) = {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()));
        let client_keys_candidates = [
            exe_dir.as_ref().map(|d| d.join("client.keys")),
            Some(std::path::PathBuf::from(r"C:\Program Files (x86)\ossec-agent\client.keys")),
            Some(std::path::PathBuf::from(r"C:\Program Files\ossec-agent\client.keys")),
            Some(std::path::PathBuf::from("client.keys")),
        ];
        let mut creds = (None, None);
        for cand in client_keys_candidates.into_iter().flatten() {
            if let Some((id, name, _, _)) = siem_core::parse_client_keys(&cand) {
                creds = (Some(id), Some(name));
                break;
            }
        }
        creds
    };

    // Load official ossec.conf XML
    let ossec_conf = siem_core::OssecConfig::find_and_load();
    let ossec_url = ossec_conf.get_manager_address();
    let (buf_cap, buf_eps) = if let Some(buf) = &ossec_conf.client_buffer {
        (buf.queue_size, buf.events_per_second)
    } else {
        (5000, 500)
    };

    // Fallback or override from agent-config.json
    let (file_url, file_id) = {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()));
        let config_candidates = [
            exe_dir.map(|d| d.join("agent-config.json")),
            Some(std::path::PathBuf::from(r"C:\Program Files\Wazuh-Agent\agent-config.json")),
        ];
        let mut found = (None, None);
        for cand in config_candidates.into_iter().flatten() {
            if cand.exists() {
                if let Ok(content) = std::fs::read_to_string(&cand) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        let u = val.get("manager_url").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let i = val.get("agent_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                        found = (u, i);
                        break;
                    }
                }
            }
        }
        found
    };

    let manager_url = std::env::var("SIEM_MANAGER_URL")
        .ok()
        .or(file_url)
        .or_else(|| if ossec_url != "http://127.0.0.1:8088" { Some(ossec_url) } else { None })
        .unwrap_or_else(|| "http://127.0.0.1:8088".into());
    let agent_id = std::env::var("SIEM_AGENT_ID")
        .ok()
        .or(keys_id)
        .or(file_id)
        .unwrap_or_else(|| "001".into());
    let agent_name = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or(keys_name)
        .unwrap_or_else(|| "wazuh-win-agent".into());

    info!("===============================================================");
    info!("Starting Next-Gen Wazuh Windows Agent in Rust");
    info!("Agent ID:        {}", agent_id);
    info!("Agent Hostname:  {}", agent_name);
    info!("Target Manager:  {}", manager_url);
    info!("Platform:        {} ({})", std::env::consts::OS, std::env::consts::ARCH);
    info!("===============================================================");

    // 1. Initialize Resilient Client Buffer (matching ossec.conf client_buffer settings)
    let (buffer, buffer_worker) = AgentBuffer::new(manager_url.clone(), buf_cap, buf_eps as u32);
    let buffer = Arc::new(buffer);

    // 2. Send Registration & Initial Keepalive
    let register_msg = format!(
        "wazuh-agent[{}]: Windows Agent successfully started on host '{}' (OS: {}, ARCH: {}). Registered with SIEM Manager.",
        agent_id, agent_name, std::env::consts::OS, std::env::consts::ARCH
    );
    let mut reg_event = RawEvent::new(&agent_id, EventSource::WindowsEvent, "agent/lifecycle", register_msg);
    reg_event.metadata.insert("status".into(), "active".into());
    reg_event.metadata.insert("hostname".into(), agent_name.clone());
    reg_event.metadata.insert("os_type".into(), "windows".into());
    buffer.push(reg_event).await;

    // 3. Configure Monitored Directories for FIM (File Integrity Monitoring - mirroring Wazuh ossec.conf)
    let mut fim_paths = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let win_dir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        // 1. Critical network configuration & hosts
        fim_paths.push(PathBuf::from(format!(r"{}\System32\drivers\etc\hosts", win_dir)));
        fim_paths.push(PathBuf::from(format!(r"{}\System32\drivers\etc\networks", win_dir)));
        
        // 2. PowerShell profiles (persistence & command execution)
        let ps_profile = PathBuf::from(format!(r"{}\System32\WindowsPowerShell\v1.0\profile.ps1", win_dir));
        if ps_profile.exists() {
            fim_paths.push(ps_profile);
        }

        // 3. User & Global Startup directories (persistence)
        if let Ok(app_data) = std::env::var("APPDATA") {
            let startup = PathBuf::from(format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", app_data));
            if startup.exists() {
                fim_paths.push(startup);
            }
        }
        if let Ok(prog_data) = std::env::var("ProgramData") {
            let global_startup = PathBuf::from(format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", prog_data));
            if global_startup.exists() {
                fim_paths.push(global_startup);
            }
        }
    }

    // Also monitor test directories if present
    let test_dirs = [
        PathBuf::from(r"C:\test_fim"),
        PathBuf::from(r"C:\ProgramData\Wazuh-Agent\monitored"),
        PathBuf::from("./test_fim"),
    ];
    for td in test_dirs {
        if td.exists() {
            fim_paths.push(td);
        }
    }

    // 4. Spawn Subsystem Workers
    info!("Spawning Wazuh Windows Agent Core Subsystems:");

    // Worker 1: Windows EventChannel Collector (Security, System, Application, PowerShell, Defender, Sysmon)
    info!(" [✓] EventChannel Collector (polling Security, System, App, PowerShell, Defender, Sysmon)");
    let eventchannel_handle = eventchannel::spawn_eventchannel_worker(
        agent_id.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(5),
    );

    // Worker 2: File Integrity Monitor (FIM / syscheck)
    info!(" [✓] Syscheck / FIM Engine (tracking critical paths and SHA-256 baselines)");
    let fim_handle = fim::spawn_fim_worker(
        agent_id.clone(),
        fim_paths,
        Arc::clone(&buffer),
        Duration::from_secs(15),
    );

    // Worker 3: Windows Registry Persistence Monitor
    info!(" [✓] Windows Registry Monitor (tracking Run, RunOnce, Winlogon, KnownDLLs, Policies)");
    let registry_handle = registry::spawn_registry_worker(
        agent_id.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(15),
    );

    // Worker 4: Syscollector (System Hardware, Processes, Ports, Packages, Services)
    info!(" [✓] Syscollector (hardware, network, open ports, running processes, services)");
    let syscollector_handle = syscollector::spawn_syscollector_worker(
        agent_id.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(60),
    );

    // Worker 5: Security Configuration Assessment (SCA / CIS baseline)
    info!(" [✓] SCA Engine (CIS benchmarks, UAC, Defender, RDP policies)");
    let sca_handle = sca::spawn_sca_worker(
        agent_id.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(120),
    );

    // Worker 6: Periodic Keepalive / Heartbeat (Wazuh notify_time = 20s)
    let heartbeat_buffer = Arc::clone(&buffer);
    let hb_agent_id = agent_id.clone();
    let hb_hostname = agent_name.clone();
    let heartbeat_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(20));
        let mut count = 0u64;

        loop {
            ticker.tick().await;
            count += 1;

            let msg = format!("wazuh-agent[{}]: Keepalive heartbeat #{} from host '{}' (status: healthy)", hb_agent_id, count, hb_hostname);
            let mut event = RawEvent::new(&hb_agent_id, EventSource::WindowsEvent, "agent/keepalive", msg);
            event.metadata.insert("heartbeat_seq".into(), count.to_string());
            event.metadata.insert("health".into(), "ok".into());
            heartbeat_buffer.push(event).await;

            // Write local Wazuh Agent state file (matching client-agent/state.c)
            let state_content = format!(
                "# Wazuh Rust Agent State\nstatus='active'\nagent_id='{}'\nhostname='{}'\nheartbeat_seq='{}'\nlast_keepalive='{}'\nhealth='ok'\n",
                hb_agent_id, hb_hostname, count, chrono::Utc::now().to_rfc3339()
            );
            let _ = tokio::fs::write("wazuh-agent.state", state_content).await;
        }
    });

    // Worker 7: Active Response Daemon (win_execd: remote command execution)
    info!(" [✓] Active Response Daemon (win_execd: automated IP block, process termination)");
    let active_response_handle = active_response::spawn_active_response_worker(
        agent_id.clone(),
        manager_url.clone(),
        Arc::clone(&buffer),
        Duration::from_secs(5),
    );

    info!("All Wazuh Windows Agent core modules are running successfully!");

    // Await all workers
    let _ = tokio::join!(
        buffer_worker,
        eventchannel_handle,
        fim_handle,
        registry_handle,
        syscollector_handle,
        sca_handle,
        heartbeat_handle,
        active_response_handle
    );
}

fn print_usage() {
    println!("Wazuh Rust Endpoint Agent (Next-Gen SIEM & XDR)");
    println!("Usage:");
    println!("  siem-agent.exe                          Run agent (auto-detects service vs console)");
    println!("  siem-agent.exe --console                Run interactively in foreground console");
    println!("  siem-agent.exe --ui                     Launch Desktop Management Console (win32ui GUI)");
    println!("  siem-agent.exe install-service          Install as automatic background Windows Service (auto-start on boot)");
    println!("  siem-agent.exe uninstall-service        Uninstall the background Windows Service");
    println!("  siem-agent.exe start-service            Start the background Windows Service");
    println!("  siem-agent.exe stop-service             Stop the background Windows Service");
    println!("  siem-agent.exe status-service           Query current Windows Service status");
    println!();
    println!("Optional installation arguments:");
    println!("  siem-agent.exe install-service [MANAGER_URL] [AGENT_ID]");
    println!("  Example: siem-agent.exe install-service http://127.0.0.1:8088 001");
}

fn main() {
    let _ = tracing_subscriber::fmt().try_init();

    let args: Vec<String> = std::env::args().collect();

    // Check CLI commands
    if args.len() > 1 {
        let cmd = args[1].to_lowercase();
        match cmd.as_str() {
            "--ui" | "ui" | "gui" | "-g" => {
                #[cfg(windows)]
                {
                    println!("[*] Launching Wazuh Agent Desktop Management Console...");
                    let script_path = std::env::current_exe()
                        .ok()
                        .and_then(|p| p.parent().map(|d| d.join("wazuh-agent-ui.ps1")))
                        .unwrap_or_else(|| std::path::PathBuf::from("wazuh-agent-ui.ps1"));
                    
                    let target = if script_path.exists() {
                        script_path.to_string_lossy().to_string()
                    } else {
                        "wazuh-agent-ui.ps1".to_string()
                    };

                    let _ = std::process::Command::new("powershell")
                        .args(["-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", &target])
                        .spawn();
                    return;
                }
                #[cfg(not(windows))]
                {
                    eprintln!("Desktop GUI is only supported on Windows.");
                    return;
                }
            }
            "install-service" | "--install" | "-i" => {
                #[cfg(windows)]
                {
                    let url = args.get(2).map(|s| s.as_str());
                    let id = args.get(3).map(|s| s.as_str());
                    win_service::manager::install_service(url, id);
                    return;
                }
                #[cfg(not(windows))]
                {
                    eprintln!("Windows Service installation is only supported on Windows.");
                    return;
                }
            }
            "uninstall-service" | "--uninstall" | "-u" => {
                #[cfg(windows)]
                {
                    win_service::manager::uninstall_service();
                    return;
                }
                #[cfg(not(windows))]
                {
                    eprintln!("Windows Service uninstallation is only supported on Windows.");
                    return;
                }
            }
            "start-service" | "--start" => {
                #[cfg(windows)]
                {
                    win_service::manager::start_service();
                    return;
                }
                #[cfg(not(windows))]
                {
                    eprintln!("Windows Service management is only supported on Windows.");
                    return;
                }
            }
            "stop-service" | "--stop" => {
                #[cfg(windows)]
                {
                    win_service::manager::stop_service();
                    return;
                }
                #[cfg(not(windows))]
                {
                    eprintln!("Windows Service management is only supported on Windows.");
                    return;
                }
            }
            "status-service" | "--status" => {
                #[cfg(windows)]
                {
                    win_service::manager::query_status();
                    return;
                }
                #[cfg(not(windows))]
                {
                    eprintln!("Windows Service management is only supported on Windows.");
                    return;
                }
            }
            "--service" => {
                #[cfg(windows)]
                {
                    if let Err(e) = win_service::run_service_dispatcher() {
                        eprintln!("Failed to start service dispatcher: {:?}", e);
                    }
                    return;
                }
            }
            "--help" | "-h" | "/?" | "help" => {
                print_usage();
                return;
            }
            "start" | "--console" | "--foreground" => {
                // Run directly in console (matching Wazuh win_agent.c: start)
                run_in_console();
                return;
            }
            _ => {}
        }
    }

    // Default invocation without specific flags:
    // If started by Windows Service Control Manager (at PC boot or via net start),
    // run_service_dispatcher will succeed and run as background service!
    #[cfg(windows)]
    {
        if let Err(_dispatcher_err) = win_service::run_service_dispatcher() {
            // Error 1063 (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) means the program
            // was executed interactively from a terminal/explorer rather than by the SCM.
            // Fall back seamlessly to foreground console execution!
            run_in_console();
        }
    }

    #[cfg(not(windows))]
    {
        run_in_console();
    }
}

fn run_in_console() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to initialize Tokio runtime");

    rt.block_on(async {
        run_agent_loop().await;
    });
}
