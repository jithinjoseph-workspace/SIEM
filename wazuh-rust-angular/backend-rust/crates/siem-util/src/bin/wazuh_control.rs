//! Wazuh Control CLI (src/init/wazuh-server.sh, wazuh-client.sh)
//!
//! Native cross-platform implementation of `wazuh-control`:
//! - Commands: `start`, `stop`, `restart`, `status`, `info`
//! - JSON output support via `-j` flag matching Wazuh REST API expectations.
//! - Checks daemon PID files and process liveness across Linux and Windows.

use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const VERSION: &str = "v4.14.7";
const REVISION: &str = "rc1";
const TYPE: &str = "server";

const DAEMONS: &[&str] = &[
    "wazuh-db",
    "wazuh-authd",
    "wazuh-execd",
    "wazuh-analysisd",
    "wazuh-syscheckd",
    "wazuh-remoted",
    "wazuh-logcollector",
    "wazuh-monitord",
    "wazuh-modulesd",
    "wazuh-maild",
    "wazuh-agentlessd",
    "wazuh-integratord",
    "wazuh-csyslogd",
    "wazuh-apid",
];

fn find_run_dir() -> PathBuf {
    let candidates = [
        PathBuf::from("/var/ossec/var/run"),
        PathBuf::from("var/run"),
        PathBuf::from("run"),
    ];

    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }

    PathBuf::from("var/run")
}

fn is_process_running(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH"])
            .output();
        if let Ok(out) = output {
            let s = String::from_utf8_lossy(&out.stdout);
            s.contains(&pid.to_string())
        } else {
            false
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
}

fn get_daemon_pid(run_dir: &Path, daemon: &str) -> Option<u32> {
    if let Ok(entries) = fs::read_dir(run_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(daemon) && name.ends_with(".pid") {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    if let Ok(pid) = content.trim().parse::<u32>() {
                        if is_process_running(pid) {
                            return Some(pid);
                        } else {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
    None
}

fn status(use_json: bool) {
    let run_dir = find_run_dir();
    let mut data = Vec::new();

    for daemon in DAEMONS {
        let is_running = get_daemon_pid(&run_dir, daemon).is_some();
        let status_str = if is_running { "running" } else { "stopped" };

        if use_json {
            data.push(json!({
                "daemon": daemon,
                "status": status_str
            }));
        } else {
            if is_running {
                println!("{} is running...", daemon);
            } else {
                println!("{} not running...", daemon);
            }
        }
    }

    if use_json {
        let res = json!({
            "error": 0,
            "data": data
        });
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
    }
}

fn info(use_json: bool, arg: Option<&str>) {
    if use_json {
        let res = json!({
            "error": 0,
            "data": [
                { "WAZUH_VERSION": VERSION },
                { "WAZUH_REVISION": REVISION },
                { "WAZUH_TYPE": TYPE }
            ]
        });
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
    } else {
        match arg {
            Some("-v") => println!("{}", VERSION),
            Some("-r") => println!("{}", REVISION),
            Some("-t") => println!("{}", TYPE),
            _ => {
                println!("WAZUH_VERSION=\"{}\"", VERSION);
                println!("WAZUH_REVISION=\"{}\"", REVISION);
                println!("WAZUH_TYPE=\"{}\"", TYPE);
            }
        }
    }
}

fn stop_daemons(use_json: bool) {
    let run_dir = find_run_dir();
    let mut data = Vec::new();

    for daemon in DAEMONS.iter().rev() {
        if let Some(pid) = get_daemon_pid(&run_dir, daemon) {
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output();
            }
            #[cfg(not(target_os = "windows"))]
            {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }

            if use_json {
                data.push(json!({
                    "daemon": daemon,
                    "status": "stopped"
                }));
            } else {
                println!("Killing {}...", daemon);
            }
        } else {
            if use_json {
                data.push(json!({
                    "daemon": daemon,
                    "status": "stopped"
                }));
            } else {
                println!("{} not running...", daemon);
            }
        }
    }

    if use_json {
        let res = json!({
            "error": 0,
            "data": data
        });
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
    } else {
        println!("Wazuh {} Stopped", VERSION);
    }
}

fn start_daemons(use_json: bool) {
    if !use_json {
        println!("Starting Wazuh {}...", VERSION);
    }

    let run_dir = find_run_dir();
    let _ = fs::create_dir_all(&run_dir);
    let mut data = Vec::new();

    for daemon in DAEMONS {
        if get_daemon_pid(&run_dir, daemon).is_some() {
            if use_json {
                data.push(json!({
                    "daemon": daemon,
                    "status": "running"
                }));
            } else {
                println!("{} already running...", daemon);
            }
            continue;
        }

        // Check if executable exists in current directory or target/release or /var/ossec/bin
        let bin_candidates = [
            PathBuf::from(format!("./{}", daemon)),
            PathBuf::from(format!("target/release/{}", daemon)),
            PathBuf::from(format!("target/debug/{}", daemon)),
            PathBuf::from(format!("/var/ossec/bin/{}", daemon)),
        ];

        let mut launched = false;
        for c in &bin_candidates {
            if c.exists() {
                if let Ok(child) = std::process::Command::new(c).spawn() {
                    let pid = child.id();
                    let pid_file = run_dir.join(format!("{}-{}.pid", daemon, pid));
                    let _ = fs::write(&pid_file, pid.to_string());
                    launched = true;
                    break;
                }
            }
        }

        if launched {
            if use_json {
                data.push(json!({
                    "daemon": daemon,
                    "status": "running"
                }));
            } else {
                println!("Started {}...", daemon);
            }
        } else {
            if use_json {
                data.push(json!({
                    "daemon": daemon,
                    "status": "stopped"
                }));
            } else {
                println!("{} not installed or binary not found", daemon);
            }
        }
    }

    if use_json {
        let res = json!({
            "error": 0,
            "data": data
        });
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
    } else {
        println!("Completed.");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut use_json = false;
    let mut action = String::new();
    let mut extra_arg: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-j" => {
                use_json = true;
            }
            act if action.is_empty() => {
                action = act.to_string();
            }
            extra if extra_arg.is_none() => {
                extra_arg = Some(extra.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    match action.as_str() {
        "status" => status(use_json),
        "start" => start_daemons(use_json),
        "stop" => stop_daemons(use_json),
        "restart" => {
            stop_daemons(use_json);
            std::thread::sleep(std::time::Duration::from_millis(500));
            start_daemons(use_json);
        }
        "info" => info(use_json, extra_arg.as_deref()),
        "help" | "-h" | "--help" | "" => {
            println!("Usage: wazuh-control [-j] {{start|stop|restart|status|info [-v -r -t]}}");
            println!("    -j    Use JSON output matching Wazuh API.");
            if action.is_empty() {
                std::process::exit(1);
            }
        }
        unknown => {
            eprintln!("Unknown command: {}", unknown);
            println!("Usage: wazuh-control [-j] {{start|stop|restart|status|info [-v -r -t]}}");
            std::process::exit(1);
        }
    }
}
