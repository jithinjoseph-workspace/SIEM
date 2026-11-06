//! Counters: atomics only, so counting never takes a lock on the hot path. Logs of refusals are
//! rate-limited: the first, then a summary every minute.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use tracing::warn;

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        #[derive(Default)]
        pub struct Counters { $(pub $name: AtomicU64,)* }
        impl Counters {
            pub fn all(&self) -> Vec<(&'static str, u64)> {
                vec![$((stringify!($name), self.$name.load(Relaxed)),)*]
            }
        }
    };
}

counters!(
    connections_opened, connections_refused, connections_closed_over_limit, handshakes_limited,
    tls_ok, tls_failed, tls_timed_out, bytes_in, bytes_out, accept_errors,
    keepalives_received, keepalives_coalesced, keepalive_rows_flushed, keepalive_flush_failures,
    events_received, events_too_large, events_unusable, batches_repeated, events_forwarded,
    baseline_rows_stored, inventories_queued, full_sends_asked,
    engine_datagrams_sent, engine_restarts_seen, engine_datagrams_possibly_lost,
    commands_handed_out, commands_offered_again, commands_expired, commands_no_result, commands_queued,
    results_stored, results_unknown, command_marks_written, command_mark_failures,
    engine_responses_received, engine_responses_invalid, engine_responses_queued, engine_all_agents_expansions,
    key_reloads, cache_poll_failures, cloned_identities, state_jobs_dropped, time_limits,
);

/// Kinds of call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Enroll,
    Keepalive,
    Events,
    Result,
    Config,
    Yara,
    Upgrade,
    Download,
    Legacy,
    AgentState,
    Other,
}

pub const KINDS: [&str; 11] = ["enroll", "keepalive", "events", "result", "config", "yara", "upgrade", "download", "legacy", "agent_state", "other"];
pub const OUTCOMES: [u16; 12] = [200, 400, 401, 403, 404, 408, 409, 410, 413, 429, 503, 500];

/// Why a call was refused: 429 and 503 by reason.
pub const REASONS: [&str; 14] = ["engine_behind", "engine_down", "engine_send", "keepalive_rate", "events_in_flight", "agent_eps", "enroll_rate", "address_rate", "download_slots", "not_ready", "api_down", "provigil_db", "backlog", "time_limit"];

#[derive(Default)]
pub struct Stats {
    pub c: Counters,
    /// By kind and outcome.
    calls: [[AtomicU64; OUTCOMES.len()]; KINDS.len()],
    reasons: [AtomicU64; REASONS.len()],
    logged: [LogLimit; REASONS.len()],
}

/// The first, then a summary every minute.
#[derive(Default)]
pub struct LogLimit {
    next_ms: AtomicU64,
    held: AtomicU64,
}

impl LogLimit {
    pub fn warn(&self, now_ms: u64, what: &str) {
        let next = self.next_ms.load(Relaxed);
        if now_ms >= next && self.next_ms.compare_exchange(next, now_ms + 60_000, Relaxed, Relaxed).is_ok() {
            let held = self.held.swap(0, Relaxed);
            warn!("{what} (and {held} more in the last minute)");
        } else {
            self.held.fetch_add(1, Relaxed);
        }
    }
}

impl Stats {
    pub fn call(&self, kind: Kind, code: u16) {
        let o = OUTCOMES.iter().position(|c| *c == code).unwrap_or(OUTCOMES.len() - 1);
        self.calls[kind as usize][o].fetch_add(1, Relaxed);
    }

    pub fn refused(&self, reason: &'static str, now_ms: u64) {
        let i = REASONS.iter().position(|r| *r == reason).unwrap_or(0);
        self.reasons[i].fetch_add(1, Relaxed);
        self.logged[i].warn(now_ms, &format!("refused: {reason}"));
    }

    /// Prometheus text; `extra` are gauges.
    pub fn metrics(&self, extra: &[(&str, f64)]) -> String {
        let mut o = String::with_capacity(8192);
        for (k, v) in self.c.all() {
            o.push_str(&format!("provigil_gateway_{k}_total {v}\n"));
        }
        for (i, kind) in KINDS.iter().enumerate() {
            for (j, code) in OUTCOMES.iter().enumerate() {
                let n = self.calls[i][j].load(Relaxed);
                if n > 0 {
                    o.push_str(&format!("provigil_gateway_calls_total{{kind=\"{kind}\",outcome=\"{code}\"}} {n}\n"));
                }
            }
        }
        for (i, r) in REASONS.iter().enumerate() {
            o.push_str(&format!("provigil_gateway_refusals_total{{reason=\"{r}\"}} {}\n", self.reasons[i].load(Relaxed)));
        }
        for (k, v) in extra {
            o.push_str(&format!("provigil_gateway_{k} {v}\n"));
        }
        o
    }

    pub fn json(&self) -> serde_json::Value {
        let calls: serde_json::Map<String, serde_json::Value> = KINDS
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let by: serde_json::Map<String, serde_json::Value> = OUTCOMES.iter().enumerate().filter_map(|(j, c)| Some((c.to_string(), self.calls[i][j].load(Relaxed)))).filter(|(_, n)| *n > 0).map(|(c, n)| (c, n.into())).collect();
                (k.to_string(), by.into())
            })
            .collect();
        let reasons: serde_json::Map<String, serde_json::Value> = REASONS.iter().enumerate().map(|(i, r)| (r.to_string(), self.reasons[i].load(Relaxed).into())).collect();
        let counters: serde_json::Map<String, serde_json::Value> = self.c.all().into_iter().map(|(k, v)| (k.to_string(), v.into())).collect();
        serde_json::json!({ "counters": counters, "calls": calls, "refusals": reasons })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_text() {
        let s = Stats::default();
        s.c.tls_ok.fetch_add(3, Relaxed);
        s.call(Kind::Events, 429);
        s.refused("engine_behind", 1);
        let t = s.metrics(&[("engine_lag", 7.0)]);
        assert!(t.contains("provigil_gateway_tls_ok_total 3\n"), "{t}");
        assert!(t.contains("provigil_gateway_calls_total{kind=\"events\",outcome=\"429\"} 1\n"), "{t}");
        assert!(t.contains("provigil_gateway_refusals_total{reason=\"engine_behind\"} 1\n"), "{t}");
        assert!(t.contains("provigil_gateway_engine_lag 7\n"), "{t}");
    }

    #[test]
    fn log_limit_holds_the_rest() {
        let l = LogLimit::default();
        l.warn(1000, "x");
        l.warn(1001, "x");
        l.warn(1002, "x");
        assert_eq!(l.held.load(Relaxed), 2);
        l.warn(62_000, "x");
        assert_eq!(l.held.load(Relaxed), 0);
    }
}
