//! What the host daemon does before starting the scanner (2.1): read the configuration file and
//! internal options, find the host name, create the agent-database client, then start.

use crate::agentdb::AgentDb;
use crate::config::{self, ModuleConfig};
use crate::legacy_names::CONFIG_FILE;
use crate::log::Log;
use crate::scanner::{Router, Scanner, StartOptions};
use crate::sink::StreamSpool;
use std::path::Path;
use std::sync::Arc;

/// Host name from the system call `gethostname` (at most 255 bytes); `undefined` when it fails.
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    if !sys_hostname(&mut buf) {
        return "undefined".into();
    }
    let n = buf.iter().position(|b| *b == 0).unwrap_or(255);
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[cfg(unix)]
fn sys_hostname(buf: &mut [u8; 256]) -> bool {
    // SAFETY: the buffer is valid for 255 bytes plus a terminator.
    unsafe { libc::gethostname(buf.as_mut_ptr().cast(), 255) == 0 }
}

#[cfg(windows)]
#[link(name = "ws2_32")]
extern "system" {
    fn gethostname(name: *mut u8, namelen: i32) -> i32;
}

#[cfg(windows)]
fn sys_hostname(buf: &mut [u8; 256]) -> bool {
    // Opening any socket makes the standard library start the socket layer the call needs.
    let _ = std::net::UdpSocket::bind("127.0.0.1:0");
    // SAFETY: the buffer is valid for 255 bytes plus a terminator.
    unsafe { gethostname(buf.as_mut_ptr(), 255) == 0 }
}

#[cfg(not(any(unix, windows)))]
fn sys_hostname(_: &mut [u8; 256]) -> bool {
    false
}

pub struct HostAdapters {
    /// Agent-database client; `None` uses the local socket `queue/db/wdb` (Unix socket, or TCP
    /// loopback with its `.port` file on Windows).
    pub agent_db: Option<Arc<dyn AgentDb>>,
    pub router: Option<Arc<dyn Router>>,
    pub stream: Option<Arc<dyn StreamSpool>>,
    pub content_updater: bool,
}

/// Starts the scanner the way the manager daemon does. `None` when no scanner section exists,
/// when the start failed or the module is disabled.
pub fn launch(home: &Path, log: Log, is_manager: bool, adapters: HostAdapters) -> Option<Scanner> {
    let text = std::fs::read_to_string(home.join(CONFIG_FILE)).ok()?;
    let vd = config::read_section(&text, is_manager, &log)?;
    let read = |f: &str| std::fs::read_to_string(home.join(f)).unwrap_or_default();
    let (a, b) = (read("etc/internal_options.conf"), read("etc/local_internal_options.conf"));
    let opts = match config::internal_options(&[&a, &b]) {
        Ok(o) => o,
        Err(e) => {
            // An invalid max-eps option is fatal for the host.
            host!(log, Critical, "{e}");
            std::process::exit(1);
        }
    };
    let name = hostname();
    // The local client connects lazily, so creating it cannot fail.
    let agent_db: Arc<dyn AgentDb> = adapters.agent_db.unwrap_or_else(|| Arc::new(crate::agentdb::SocketAgentDb::local(home)));
    host!(log, Debug2, "Created new thread for the 'vulnerability_scanner' module.");
    let cfg = ModuleConfig::new(vd, &opts, &name);
    Scanner::start(
        home,
        log,
        cfg,
        StartOptions {
            agent_db,
            report_sink: None,
            report_socket: None,
            manager_name: name,
            content_updater: adapters.content_updater,
            router: adapters.router,
            stream: adapters.stream,
            threads: true,
        },
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn hostname_is_the_system_name() {
        // D18: the system host-name call on every platform.
        let out = std::process::Command::new("hostname").output().unwrap();
        assert_eq!(super::hostname(), String::from_utf8_lossy(&out.stdout).trim());
    }
}
