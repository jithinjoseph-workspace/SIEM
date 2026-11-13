//! Starts the own vulnerability scanner (`provigil-vulnscan`) in this service, with the service's
//! log (the scanner's own tags), the router and siem-api's stream.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use provigil_daemon::Log;
use provigil_vulnscan::host::{launch, HostAdapters};
use provigil_vulnscan::log::{Level, Logger};
use provigil_vulnscan::sink::StreamSpool;
use provigil_vulnscan::Scanner;
use serde_json::Value;

use crate::router::Router;

struct ScannerLog(Arc<Log>);

impl Logger for ScannerLog {
    fn log(&self, tag: &str, level: Level, msg: &str) {
        let lv = match level {
            Level::Debug => "DEBUG",
            Level::Debug2 => "DEBUG2",
            Level::Info => "INFO",
            Level::Warning => "WARNING",
            Level::Error => "ERROR",
            Level::Critical => "CRITICAL",
        };
        // no tag: the service's own lines
        let tag = if tag.is_empty() { "provigil-modulesd" } else { tag };
        self.0.tagged(tag, lv, msg);
    }
    fn enabled(&self, level: Level) -> bool {
        match level {
            Level::Debug => self.0.enabled("DEBUG"),
            Level::Debug2 => self.0.enabled("DEBUG2"),
            _ => true,
        }
    }
}

/// The router as the scanner subscribes to it: messages are JSON; anything else (the binary
/// topics of the retired agent receiver, spec M-2) is dropped and counted.
struct ScannerRouter {
    router: Arc<Router>,
    log: Arc<Log>,
}

impl provigil_vulnscan::Router for ScannerRouter {
    fn subscribe(&self, topic: &str, id: &str, cb: Box<dyn Fn(Value) + Send + Sync>) -> Result<(), String> {
        let dropped = Arc::new(AtomicU64::new(0));
        let (log, name) = (self.log.clone(), topic.to_string());
        self.router.subscribe(
            topic,
            id,
            Arc::new(move |m: &[u8]| match serde_json::from_slice::<Value>(m) {
                Ok(v) => cb(v),
                Err(_) => {
                    let n = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                    // the first one, then every thousandth
                    if n == 1 || n % 1000 == 0 {
                        log.tagged(crate::router::TAG, "WARNING", format!("Topic '{name}': {n} message(s) that are not JSON dropped."));
                    }
                }
            }),
        )
    }
}

/// siem-api's stream (spool `queue/stream-spool/vulnerability`).
struct ApiStream(Mutex<provigil_ipc::platform_stream::Stream>);

impl StreamSpool for ApiStream {
    fn send(&self, kind: u8, body: &str) -> Result<Option<String>, String> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).send(kind, body.as_bytes()))
    }
}

/// Starts the scanner from `etc/ossec.conf` (None: no section, disabled, or the start failed).
pub fn start(home: &Path, log: Arc<Log>, router: Arc<Router>) -> Option<Scanner> {
    let stream = provigil_ipc::platform_stream::Stream::from_env(&home.join("queue/stream-spool/vulnerability"))
        .map(|s| Arc::new(ApiStream(Mutex::new(s))) as Arc<dyn StreamSpool>);
    let router: Arc<dyn provigil_vulnscan::Router> = Arc::new(ScannerRouter { router, log: log.clone() });
    launch(home, provigil_vulnscan::log::Log::new(Arc::new(ScannerLog(log))), true, HostAdapters { agent_db: None, router: Some(router), stream, content_updater: true })
}
