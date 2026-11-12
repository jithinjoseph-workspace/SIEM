//! Starts ProVigil's own vulnerability scanner (`provigil-vulnscan`) inside this daemon and
//! connects it to the daemon's log, the local message router and siem-api's stream.

use std::path::Path;
use std::sync::{Arc, Mutex};

use provigil_vulnscan::host::{launch, HostAdapters};
use provigil_vulnscan::log::{Level, Log, Logger};
use provigil_vulnscan::sink::StreamSpool;
use provigil_vulnscan::{Router, Scanner};
use serde_json::Value;
use siem_log::WLog;

/// The scanner's log lines go to this daemon's log with the scanner's own tags.
struct DaemonLog(Arc<WLog>);

impl Logger for DaemonLog {
    fn log(&self, tag: &str, level: Level, msg: &str) {
        let lv = match level {
            Level::Debug => "DEBUG",
            Level::Debug2 => "DEBUG2",
            Level::Info => "INFO",
            Level::Warning => "WARNING",
            Level::Error => "ERROR",
            Level::Critical => "CRITICAL",
        };
        // an empty tag: the daemon's own lines
        let tag = if tag.is_empty() { "provigil-modulesd" } else { tag };
        self.0.tagged(tag, lv, msg);
    }
    fn enabled(&self, level: Level) -> bool {
        match level {
            Level::Debug => self.0.is_debug() >= 1,
            Level::Debug2 => self.0.is_debug() >= 2,
            _ => true,
        }
    }
}

/// Router topics: inventory deltas and sync messages arrive in the router's binary form and are
/// handed over as JSON; the database topics already carry JSON.
#[cfg(any(target_os = "linux", windows))]
struct LocalRouter {
    subs: Mutex<Vec<siem_router::RouterSubscriber>>,
}

#[cfg(any(target_os = "linux", windows))]
impl Router for LocalRouter {
    fn subscribe(&self, topic: &str, subscriber_id: &str, cb: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String> {
        let schema = match topic {
            "deltas-syscollector" => Some(siem_router::schemas::SYSCOLLECTOR_DELTAS_SCHEMA),
            "rsync" => Some(siem_router::schemas::RSYNC_SCHEMA),
            _ => None,
        };
        let parser = schema.map(|s| {
            let mut p = siem_router::fb::Parser::new();
            p.parse(s.as_bytes());
            p
        });
        let f: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |m: &[u8]| {
            let v = match &parser {
                // malformed buffers are dropped here
                Some(p) => p.buffer_to_json(m).and_then(|j| serde_json::from_str::<Value>(&j).ok()),
                None => serde_json::from_slice::<Value>(m).ok(),
            };
            if let Some(v) = v {
                cb(v);
            }
        });
        let s = siem_router::RouterSubscriber::new(topic, subscriber_id, false);
        s.subscribe(f, Arc::new(|| {}))?;
        self.subs.lock().unwrap().push(s);
        Ok(())
    }
}

/// siem-api's stream (spool `queue/stream-spool/vulnerability`).
struct ApiStream(Mutex<siem_ipc::platform_stream::Stream>);

impl StreamSpool for ApiStream {
    fn send(&self, kind: u8, body: &str) -> Result<Option<String>, String> {
        Ok(self.0.lock().unwrap().send(kind, body.as_bytes()))
    }
}

/// Starts the scanner from `etc/ossec.conf` (None: no section, disabled, or the start failed).
pub fn start(home: &Path, log: Arc<WLog>) -> Option<Scanner> {
    let stream = siem_ipc::platform_stream::Stream::from_env(&home.join("queue/stream-spool/vulnerability"))
        .map(|s| Arc::new(ApiStream(Mutex::new(s))) as Arc<dyn StreamSpool>);
    // the running scanner keeps the router (and its subscriptions) until it stops
    #[cfg(any(target_os = "linux", windows))]
    let router: Option<Arc<dyn Router>> = Some(Arc::new(LocalRouter { subs: Mutex::new(Vec::new()) }));
    #[cfg(not(any(target_os = "linux", windows)))]
    let router: Option<Arc<dyn Router>> = None;
    launch(home, Log::new(Arc::new(DaemonLog(log))), true, HostAdapters { agent_db: None, router, stream, content_updater: true })
}
