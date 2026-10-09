#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use tracing::{error, info};
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

pub const SERVICE_NAME: &str = "WazuhRustSvc";
pub const SERVICE_DISPLAY_NAME: &str = "Wazuh Rust Endpoint Agent";
pub const SERVICE_DESCRIPTION: &str =
    "Next-Generation Wazuh SIEM Endpoint Telemetry & Threat Defense Agent written in Rust";

#[cfg(windows)]
define_windows_service!(ffi_service_main, win_service_main);

#[cfg(windows)]
pub fn run_service_dispatcher() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

#[cfg(windows)]
pub fn win_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service_internal() {
        error!("Windows Service encountered error: {:?}", e);
    }
}

#[cfg(windows)]
fn run_service_internal() -> Result<(), windows_service::Error> {
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_signal = Arc::clone(&stop_requested);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("Windows Service Stop/Shutdown received. Flagging graceful termination.");
                stop_signal.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report RUNNING to Windows Service Control Manager
    let running_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running_status)?;

    info!("Wazuh Windows Agent service is now in RUNNING state.");

    // Create Tokio multi-threaded runtime for the service
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to initialize Tokio runtime for Windows Service");

    rt.block_on(async {
        let stop_clone = Arc::clone(&stop_requested);
        tokio::select! {
            _ = crate::run_agent_loop() => {
                info!("Agent core loop exited.");
            }
            _ = async {
                while !stop_clone.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            } => {
                info!("Graceful shutdown requested by Windows SCM.");
            }
        }
    });

    // Report STOPPED to Windows Service Control Manager
    let stopped_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(stopped_status)?;

    info!("Wazuh Windows Agent service successfully stopped.");
    Ok(())
}

/// Service management CLI functions (Install, Uninstall, Start, Stop, Status)
#[cfg(windows)]
pub mod manager {
    use super::*;
    use std::process::Command;

    pub fn install_service(
        custom_manager_url: Option<&str>,
        agent_name: Option<&str>,
        agent_group: Option<&str>,
        tenant_key: Option<&str>,
    ) -> bool {
        let current_exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[!] Could not determine current executable path: {}", e);
                return false;
            }
        };

        // 1. Permanent installation directory (matching Wazuh standard: %ProgramFiles%\Wazuh-Agent\)
        let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
        let target_dir = std::path::PathBuf::from(format!(r"{}\Wazuh-Agent", program_files));
        let target_exe = target_dir.join("siem-agent.exe");

        let exe_to_register = if current_exe != target_exe {
            let _ = std::fs::create_dir_all(&target_dir);
            match std::fs::copy(&current_exe, &target_exe) {
                Ok(_) => {
                    println!("[✓] Deployed agent binary to permanent system path: {:?}", target_exe);
                    target_exe
                }
                Err(e) => {
                    eprintln!("[!] Note: Could not copy to {:?} ({}), using {:?}", target_exe, e, current_exe);
                    current_exe.clone()
                }
            }
        } else {
            current_exe.clone()
        };

        let exe_str = exe_to_register.to_string_lossy();
        println!("[*] Registering Windows Service '{}'...", SERVICE_NAME);
        println!("    Binary Path: {}", exe_str);

        // 2. Clean up any existing service entry first (mirroring Wazuh win_service.c: UninstallService())
        let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
        std::thread::sleep(Duration::from_millis(300));
        let _ = Command::new("sc.exe").args(["delete", SERVICE_NAME]).output();
        std::thread::sleep(Duration::from_millis(300));

        // 3. Create service with Automatic startup (matching Wazuh standard)
        let bin_path_arg = format!("'\"{}\" --service'", exe_str);
        let ps_cmd = format!(
            "New-Service -Name '{}' -BinaryPathName {} -DisplayName '{}' -Description '{}' -StartupType Automatic",
            SERVICE_NAME, bin_path_arg, SERVICE_DISPLAY_NAME, SERVICE_DESCRIPTION
        );
        let ps_create = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .output();

        let mut success = match ps_create {
            Ok(ref out) if out.status.success() => {
                println!("[✓] Service '{}' successfully registered in Windows SCM!", SERVICE_NAME);
                true
            }
            _ => false,
        };

        if !success {
            // Fallback to cmd.exe sc create (preserves exact space-after-equals formatting)
            let cmd_str = format!(
                "sc create {} binPath= \"\\\"{}\\\" --service\" DisplayName= \"{}\" start= auto",
                SERVICE_NAME, exe_str, SERVICE_DISPLAY_NAME
            );
            let sc_create = Command::new("cmd.exe").args(["/c", &cmd_str]).output();
            match sc_create {
                Ok(out) if out.status.success() => {
                    println!("[✓] Service '{}' registered via SCM fallback!", SERVICE_NAME);
                    success = true;
                }
                Ok(out) => {
                    let err_str = String::from_utf8_lossy(&out.stderr);
                    let out_str = String::from_utf8_lossy(&out.stdout);
                    eprintln!("[!] Service creation failed:\n{}{}", out_str, err_str);
                }
                Err(e) => {
                    eprintln!("[!] Failed to invoke service creation: {}", e);
                }
            }
        }

        if !success {
            return false;
        }

        // 4. Set service description
        let _ = Command::new("sc.exe")
            .args(["description", SERVICE_NAME, SERVICE_DESCRIPTION])
            .output();

        // 5. Configure failure recovery actions (restart on failure after 5s/10s/30s - matching Wazuh supervisor)
        let _ = Command::new("sc.exe")
            .args([
                "failure",
                SERVICE_NAME,
                "reset= 86400",
                "actions= restart/5000/restart/10000/restart/30000",
            ])
            .output();

        // 6. Write permanent local agent-config.json in installation folder (matches Wazuh ossec.conf).
        // No agent_id: the agent enrolls on first start and keeps its id in client.keys.
        let manager_url = custom_manager_url.unwrap_or("http://127.0.0.1:8088");
        let config_path = target_dir.join("agent-config.json");
        let mut cfg = serde_json::json!({ "manager_url": manager_url });
        if let Some(n) = agent_name.filter(|s| !s.trim().is_empty()) {
            cfg["agent_name"] = serde_json::Value::String(n.trim().to_string());
        }
        if let Some(g) = agent_group.filter(|s| !s.trim().is_empty()) {
            cfg["agent_group"] = serde_json::Value::String(g.trim().to_string());
        }
        if let Some(k) = tenant_key.filter(|s| !s.trim().is_empty()) {
            cfg["tenant_key"] = serde_json::Value::String(k.trim().to_string());
        }
        let config_json = serde_json::to_string_pretty(&cfg).unwrap_or_default();
        if let Err(e) = std::fs::write(&config_path, config_json) {
            eprintln!("[!] Warning: Could not write {:?}: {}", config_path, e);
        } else {
            println!("[✓] Saved permanent agent configuration: {:?}", config_path);
        }

        // 7. Configure System Environment variables via setx /M
        if let Some(url) = custom_manager_url {
            let _ = Command::new("setx")
                .args(["/M", "SIEM_MANAGER_URL", url])
                .output();
            println!("    Configured System Environment: SIEM_MANAGER_URL = {}", url);
        }
        // A machine-wide SIEM_AGENT_ID from older installers would pin every
        // host to the same id: remove it so the agent enrolls.
        let _ = Command::new("reg")
            .args(["delete", r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "/v", "SIEM_AGENT_ID", "/f"])
            .output();

        println!("[✓] Service configured to start automatically on Windows boot!");
        println!("[*] Starting service now...");
        start_service();
        true
    }

    pub fn uninstall_service() -> bool {
        println!("[*] Stopping Windows Service '{}'...", SERVICE_NAME);
        let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();

        std::thread::sleep(Duration::from_millis(500));

        println!("[*] Deleting service from Windows SCM database...");
        let sc_delete = Command::new("sc.exe").args(["delete", SERVICE_NAME]).output();

        match sc_delete {
            Ok(out) if out.status.success() => {
                println!("[✓] Service '{}' successfully removed from Windows.", SERVICE_NAME);
                true
            }
            Ok(out) => {
                let err_str = String::from_utf8_lossy(&out.stderr);
                let out_str = String::from_utf8_lossy(&out.stdout);
                eprintln!("[!] sc delete failed:\n{}{}", out_str, err_str);
                false
            }
            Err(e) => {
                eprintln!("[!] Failed to invoke sc.exe: {}", e);
                false
            }
        }
    }

    pub fn start_service() -> bool {
        println!("[*] Starting service '{}'...", SERVICE_NAME);
        let out = Command::new("sc.exe").args(["start", SERVICE_NAME]).output();
        match out {
            Ok(o) if o.status.success() => {
                println!("[✓] Windows Service '{}' is now RUNNING in the background.", SERVICE_NAME);
                true
            }
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.contains("already running") || s.contains("1056") {
                    println!("[i] Service '{}' is already running.", SERVICE_NAME);
                    true
                } else {
                    eprintln!("[!] sc start output:\n{}", s);
                    false
                }
            }
            Err(e) => {
                eprintln!("[!] Failed to start service: {}", e);
                false
            }
        }
    }

    pub fn stop_service() -> bool {
        println!("[*] Stopping service '{}'...", SERVICE_NAME);
        let out = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
        match out {
            Ok(o) if o.status.success() => {
                println!("[✓] Service '{}' stopped.", SERVICE_NAME);
                true
            }
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                println!("{}", s);
                true
            }
            Err(e) => {
                eprintln!("[!] Failed to stop service: {}", e);
                false
            }
        }
    }

    pub fn query_status() {
        println!("[*] Querying status for '{}'...", SERVICE_NAME);
        let out = Command::new("sc.exe").args(["query", SERVICE_NAME]).output();
        match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                println!("{}", s);
            }
            Err(e) => {
                eprintln!("[!] Failed to query status: {}", e);
            }
        }
    }
}
