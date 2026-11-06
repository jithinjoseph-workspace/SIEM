//! Native Windows Service Integration.
//!
//! Provides Windows Service registration, lifecycle control, and SCM
//! (Service Control Manager) dispatching using `windows-service`.
//!
//! 100% clean-room Rust implementation (zero GPL derivation).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{error, info};

#[cfg(windows)]
use std::ffi::OsString;
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

pub const SERVICE_NAME: &str = "ProVigilSvc";
pub const SERVICE_DISPLAY_NAME: &str = "ProVigil Security Agent";
pub const SERVICE_DESCRIPTION: &str = "ProVigil Endpoint Detection, Response, and Telemetry Agent";

pub static RUNNING: AtomicBool = AtomicBool::new(true);

/// Windows starts the agent again 5 s, 10 s, then 60 s after it crashes or stops on its own
/// (not on a requested stop); the count resets after a day.
#[cfg(windows)]
const RECOVERY_ACTIONS: &str = "restart/5000/restart/10000/restart/60000";

#[cfg(windows)]
define_windows_service!(ffi_service_main, win_service_main);

#[cfg(windows)]
pub fn run_service_dispatcher() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

#[cfg(windows)]
pub fn win_service_main(_arguments: Vec<OsString>) {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let _ = std::env::set_current_dir(parent);
        }
    }
    if let Err(e) = run_service_internal() {
        error!("Windows Service encountered error: {:?}", e);
    }
}

#[cfg(windows)]
fn run_service_internal() -> Result<(), windows_service::Error> {
    // the handle is set once registered; the handler reports STOP_PENDING through it
    let handle: std::sync::Arc<std::sync::OnceLock<service_control_handler::ServiceStatusHandle>> = Default::default();
    let h = handle.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("Windows Service Stop/Shutdown received. Flagging graceful termination.");
                if let Some(h) = h.get() {
                    let _ = h.set_service_status(stop_pending());
                }
                request_stop();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    let _ = handle.set(status_handle);

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

    info!("ProVigil Windows Agent service is now in RUNNING state.");

    // Run the agent async loop in a dedicated multi-threaded runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();

    if let Ok(runtime) = rt {
        runtime.block_on(async {
            if let Err(e) = crate::run_agent_pipeline().await {
                error!("Agent pipeline error: {:?}", e);
            }
        });
        // a plain drop waits forever for a task blocked in a system call (an event channel read):
        // the service then never stops and a restart hangs
        let t = std::time::Instant::now();
        runtime.shutdown_timeout(Duration::from_secs(10));
        if t.elapsed() >= Duration::from_secs(10) {
            tracing::warn!(running = ?crate::still_running(), "Stop: work still running after 10 s, ended with the process");
        }
    }

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
    let _ = status_handle.set_service_status(stopped_status);

    info!("ProVigil Windows Agent service stopped.");
    // threads still blocked must not keep the process (and its handles) alive after STOPPED
    std::process::exit(0)
}

#[cfg(not(windows))]
pub fn run_service_dispatcher() -> Result<(), String> {
    Err("Windows Service can only run on Windows".into())
}

#[cfg(windows)]
pub fn install_service() -> Result<(), String> {
    use std::process::Command;
    let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
    let bin_path = format!("\"{}\" --service", exe_path.display());

    info!("Installing ProVigil Windows Service...");

    // sc.exe directly (no cmd.exe): Rust quotes each argument, so the quoted path survives
    let sc = |verb: &str| {
        Command::new("sc.exe")
            .args([verb, SERVICE_NAME, "binPath=", &bin_path, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", SERVICE_DISPLAY_NAME])
            .output()
            .map_err(|e| format!("Failed to execute sc {verb}: {e}"))
    };
    let mut output = sc("create")?;
    // 1073: the service exists (a re-install): point it at this exe instead
    if output.status.code() == Some(1073) {
        let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
        output = sc("config")?;
    }

    let out_str = String::from_utf8_lossy(&output.stdout).to_string();
    let err_str = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        info!("ProVigil Windows Service registered successfully.");
        let _ = Command::new("sc.exe").args(["description", SERVICE_NAME, SERVICE_DESCRIPTION]).output();
        let _ = Command::new("sc.exe").args(["failure", SERVICE_NAME, "reset=", "86400", "actions=", RECOVERY_ACTIONS]).output();
        let _ = Command::new("sc.exe").args(["failureflag", SERVICE_NAME, "1"]).output();
        return Ok(());
    }

    // 2. Fallback: PowerShell New-Service
    let ps_cmd = format!(
        "New-Service -Name '{}' -BinaryPathName '{}' -DisplayName '{}' -Description '{}' -StartupType Automatic",
        SERVICE_NAME,
        bin_path.replace('"', "`\""),
        SERVICE_DISPLAY_NAME,
        SERVICE_DESCRIPTION,
    );

    let ps_res = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .output();

    if let Ok(ref out) = ps_res {
        if out.status.success() {
            info!("ProVigil Windows Service installed successfully via New-Service.");
            return Ok(());
        }
    }

    Err(format!("{err_str} {out_str}").trim().to_string())
}

#[cfg(not(windows))]
pub fn install_service() -> Result<(), String> {
    Err("Windows Service can only be installed on Windows".into())
}

#[cfg(windows)]
pub fn uninstall_service() -> Result<(), String> {
    use std::process::Command;
    info!("Uninstalling ProVigil Windows Service...");

    let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &format!("Stop-Service -Name '{}' -Force -ErrorAction SilentlyContinue; Remove-Service -Name '{}' -ErrorAction SilentlyContinue", SERVICE_NAME, SERVICE_NAME)])
        .output();
    let _ = Command::new("sc.exe").args(["delete", SERVICE_NAME]).output();

    info!("ProVigil Windows Service uninstalled successfully.");
    Ok(())
}

#[cfg(not(windows))]
pub fn uninstall_service() -> Result<(), String> {
    Err("Windows Service can only be uninstalled on Windows".into())
}

#[cfg(windows)]
pub fn query_service_status() -> Result<String, String> {
    use std::process::Command;
    let output = Command::new("sc")
        .args(["query", SERVICE_NAME])
        .output()
        .map_err(|e| format!("Failed to query service: {e}"))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(not(windows))]
pub fn query_service_status() -> Result<String, String> {
    Ok("Status: Not applicable (Non-Windows host)".into())
}

/// STOP_PENDING with time for the pipeline (up to ~15 s) and the runtime (10 s) to end.
#[cfg(windows)]
fn stop_pending() -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    }
}

pub fn request_stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    /// The installed service has the recovery actions `install_service` sets, read back with
    /// `sc qfailure` (needs the agent installed; changes nothing).
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn installed_service_restarts_on_failure() {
        use super::*;
        let sc = |verb: &str| String::from_utf8_lossy(&std::process::Command::new("sc.exe").args([verb, SERVICE_NAME]).output().unwrap().stdout).into_owned();
        let failure = sc("qfailure");
        assert!(failure.contains("RESET_PERIOD (in seconds)    : 86400"), "{failure}");
        for delay in RECOVERY_ACTIONS.split('/').skip(1).step_by(2) {
            assert!(failure.contains(&format!("RESTART -- Delay = {delay} milliseconds")), "{failure}");
        }
        let flag = sc("qfailureflag");
        assert!(flag.contains("FAILURE_ACTIONS_ON_NONCRASH_FAILURES:  TRUE"), "{flag}");
    }
}
