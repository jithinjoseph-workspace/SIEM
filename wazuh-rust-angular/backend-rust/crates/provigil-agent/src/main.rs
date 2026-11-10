//! ProVigil Unified Windows Endpoint Agent Main Entry Point.

use tracing::info;
use provigil_agent::service;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set current directory to the executable's directory (essential when started via SCM)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let _ = std::env::set_current_dir(parent);
        }
    }
    // every DLL the agent loads must be signed, like the response programs
    #[cfg(windows)]
    siem_active_response::dll_guard::enable();

    // logs: RUST_LOG, else the configured log_level; to logs/provigil-agent.log (a service has
    // no console), else stderr
    let level = provigil_agent::config::AgentConfig::load_or_default(None).log_level;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new(&level))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = std::fs::create_dir_all("logs");
    match RotatingLog::open("logs/provigil-agent.log".into()) {
        Ok(f) => tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(std::sync::Mutex::new(f)).init(),
        Err(_) => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }

    let args: Vec<String> = std::env::args().collect();

    // 1. Service Manager commands
    if args.iter().any(|a| a == "--install" || a == "install-service") {
        match service::install_service() {
            Ok(()) => println!("ProVigil Agent Windows service installed successfully."),
            Err(e) => eprintln!("Service installation error: {e}"),
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "--uninstall" || a == "uninstall-service") {
        match service::uninstall_service() {
            Ok(()) => println!("ProVigil Agent Windows service uninstalled successfully."),
            Err(e) => eprintln!("Service uninstallation error: {e}"),
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "--status") {
        match service::query_service_status() {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("Status query error: {e}"),
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "-h" || a == "--help" || a == "/?") {
        println!("ProVigil Unified Endpoint Agent v{}", env!("CARGO_PKG_VERSION"));
        println!("Usage: provigil-agent [OPTIONS]");
        println!();
        println!("Options:");
        println!("  --run               Run agent in foreground (console mode)");
        println!("  --service           Run agent as Windows Service (invoked by SCM)");
        println!("  --install           Install agent as Windows Service (ProVigilSvc)");
        println!("  --uninstall         Uninstall agent Windows Service");
        println!("  --status            Check Windows Service status");
        println!("  -h, --help          Print this help menu");
        return Ok(());
    }

    // 2. Windows Service Control Manager (SCM) Dispatcher
    if args.iter().any(|a| a == "--service") {
        #[cfg(windows)]
        {
            info!("Starting ProVigil Agent in Windows Service Mode via SCM Dispatcher");
            if let Err(e) = service::run_service_dispatcher() {
                eprintln!("Windows Service Control Manager error: {e:?}");
            }
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            eprintln!("Windows Service mode is only supported on Windows.");
            return Ok(());
        }
    }

    // 3. Foreground / Console Mode
    info!("Starting ProVigil Unified Windows Endpoint Agent (Console Mode)");
    
    // Spawn Ctrl+C listener for graceful stop
    tokio::spawn(async {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Ctrl+C received; stopping ProVigil Agent gracefully...");
            service::request_stop();
        }
    });

    provigil_agent::run_agent_pipeline().await
}

/// The agent log: at 10 MB renamed to `.1` (`.1` to `.2`, ... `.5` dropped) and started again.
struct RotatingLog {
    path: std::path::PathBuf,
    file: std::fs::File,
    size: u64,
    limit: u64,
}

impl RotatingLog {
    const KEEP: u32 = 5;

    fn open(path: std::path::PathBuf) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self { path, file, size, limit: 10 * 1024 * 1024 })
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let old = |n: u32| std::path::PathBuf::from(format!("{}.{n}", self.path.display()));
        for n in (1..Self::KEEP).rev() {
            let _ = std::fs::rename(old(n), old(n + 1));
        }
        // the open file is renamed under it (Rust opens with FILE_SHARE_DELETE), then reopened
        std::fs::rename(&self.path, old(1))?;
        self.file = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

impl std::io::Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.size > 0 && self.size + buf.len() as u64 > self.limit {
            let _ = self.rotate();
        }
        let n = std::io::Write::write(&mut self.file, buf)?;
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn log_rotates_and_keeps_five() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provigil-agent.log");
        std::fs::write(&path, "x".repeat(90)).unwrap();
        let mut log = RotatingLog::open(path.clone()).unwrap();
        log.limit = 100;
        for i in 0..8 {
            log.write_all(format!("{i}{}", "y".repeat(59)).as_bytes()).unwrap();
        }
        let read = |s: &str| std::fs::read_to_string(dir.path().join(format!("provigil-agent.log{s}"))).unwrap();
        assert!(read("").starts_with('7'), "the current file has the last line");
        assert!(read(".1").starts_with('6') && read(".5").starts_with('2'));
        assert!(!dir.path().join("provigil-agent.log.6").exists(), "five kept");
        assert!(std::fs::read_dir(dir.path()).unwrap().count() == 6);
    }
}
