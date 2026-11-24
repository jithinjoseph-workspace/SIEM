// Simple per-IP sliding-window rate limiter using dashmap.
// Limits: 300 req/60s for general API, 20 req/60s for /api/login.
// Uses token bucket approximation via request timestamp deque.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

const WINDOW:       Duration = Duration::from_secs(60);
const LIMIT_API:    usize    = 300;
const LIMIT_LOGIN:  usize    = 20;

/// Events per sensor per 60 s. 0 (the default) means unlimited. Set
/// INGEST_RATE_LIMIT=<n> to cap a runaway sensor again. (It used to default to
/// 50,000 - about 833 events/s - and a sensor over that lost the excess silently.)
fn ingest_event_limit() -> usize {
    std::env::var("INGEST_RATE_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

struct Bucket {
    timestamps: VecDeque<Instant>,
}

impl Bucket {
    fn new() -> Self { Self { timestamps: VecDeque::new() } }

    fn allow(&mut self, limit: usize) -> bool {
        let now = Instant::now();
        // Evict expired entries
        while self.timestamps.front().map(|t| now.duration_since(*t) > WINDOW).unwrap_or(false) {
            self.timestamps.pop_front();
        }
        if self.timestamps.len() >= limit {
            return false;
        }
        self.timestamps.push_back(now);
        true
    }
}

static BUCKETS: LazyLock<Arc<DashMap<String, Bucket>>> =
    LazyLock::new(|| Arc::new(DashMap::new()));

// ── Per-sensor ingest event-volume rate limit ─────────────────────────────
// Tracks cumulative event count per sensor key over a fixed 60s window.
// This is intentionally a simple tumbling window (not sliding) — cheap and
// sufficient for burst protection.

struct CountBucket {
    count:        usize,
    window_start: Instant,
}

impl CountBucket {
    fn new() -> Self { Self { count: 0, window_start: Instant::now() } }

    fn allow_n(&mut self, n: usize, limit: usize) -> bool {
        if Instant::now().duration_since(self.window_start) > WINDOW {
            self.count = 0;
            self.window_start = Instant::now();
        }
        if self.count + n > limit {
            return false;
        }
        self.count += n;
        true
    }
}

static INGEST_BUCKETS: LazyLock<Arc<DashMap<String, CountBucket>>> =
    LazyLock::new(|| Arc::new(DashMap::new()));

/// Returns false if `sensor_key` has sent more than INGEST_RATE_LIMIT events in
/// the last 60 seconds. Always true when the limit is 0 (unlimited, the default).
pub fn check_ingest_rate(sensor_key: &str, event_count: usize) -> bool {
    let limit = ingest_event_limit();
    if limit == 0 {
        return true;
    }
    INGEST_BUCKETS
        .entry(sensor_key.to_string())
        .or_insert_with(CountBucket::new)
        .allow_n(event_count, limit)
}

/// Endpoints that sensors (machines) call. They are NOT limited here: with thousands
/// of sensors a shared per-IP counter only throttles healthy ones. Keys are
/// validated by each handler, and the optional per-sensor INGEST_RATE_LIMIT still applies.
pub fn is_sensor_path(path: &str) -> bool {
    path == "/api/ingest"
        || path.starts_with("/api/sensor/")
        || matches!(path, "/api/pcap/pending" | "/api/pcap/upload" | "/api/pcap/upload-failed")
}

pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path  = req.uri().path().to_string();
    if is_sensor_path(&path) {
        return Ok(next.run(req).await);
    }
    // Count per real client. The connection address is always nginx's container IP, so
    // keying on it made every browser and sensor share ONE 300-per-minute budget.
    // nginx sets X-Real-IP to the real client (it is the only way in to the engines).
    let ip = req.headers().get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
        .unwrap_or_else(|| addr.ip())
        .to_string();
    let limit = if path.contains("/login") { LIMIT_LOGIN } else { LIMIT_API };

    let key = format!("{}:{}", ip, if path.contains("/login") { "login" } else { "api" });

    let allowed = {
        let mut bucket = BUCKETS.entry(key).or_insert_with(Bucket::new);
        bucket.allow(limit)
    };

    if !allowed {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod ingest_limit_tests {
    use super::*;

    #[test]
    fn sensor_paths_are_exempt_from_the_shared_ip_limit() {
        for p in ["/api/ingest", "/api/sensor/checkin", "/api/sensor/heartbeat", "/api/sensor/register",
                  "/api/sensor/command", "/api/pcap/pending", "/api/pcap/upload", "/api/pcap/upload-failed"] {
            assert!(is_sensor_path(p), "{p} should be exempt");
        }
        // UI routes stay limited - including look-alikes
        for p in ["/api/sensors/assign", "/api/sensor-keys", "/api/sensor-keys/recent-ips", "/api/stats",
                  "/api/ingest-stats", "/api/auth/login", "/api/pcap/download"] {
            assert!(!is_sensor_path(p), "{p} must stay limited");
        }
    }

    // One test: it changes a process-wide env var, so it must not run in parallel with another.
    #[test]
    fn unlimited_by_default_and_capped_when_set() {
        std::env::remove_var("INGEST_RATE_LIMIT");
        assert!(check_ingest_rate("t-unlimited", 10_000_000), "no limit set: everything passes");
        std::env::set_var("INGEST_RATE_LIMIT", "0");
        assert!(check_ingest_rate("t-unlimited", 10_000_000), "0 means unlimited");
        std::env::set_var("INGEST_RATE_LIMIT", "1000");
        assert!(check_ingest_rate("t-capped", 600));
        assert!(!check_ingest_rate("t-capped", 600), "second batch would pass 1000 in the window");
        assert!(check_ingest_rate("t-other", 900), "another sensor has its own budget");
        std::env::remove_var("INGEST_RATE_LIMIT");
    }
}
