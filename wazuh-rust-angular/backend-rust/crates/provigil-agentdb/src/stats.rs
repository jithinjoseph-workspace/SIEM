//! Service statistics and the JSON commands (spec § 1.9, decision D-6): every request is
//! counted and timed by actor and command; `{"command":"getstats"}` reports them and
//! `{"command":"getconfig","parameters":{"section":"internal"|"wdb"}}` the settings.

use std::collections::BTreeMap;
use std::time::Duration;

use provigil_json::Json;

use crate::text::{split_word, until_nul};
use crate::Engine;

#[derive(Default)]
pub struct Stats {
    total: u64,
    /// actor → (count, time); "actor command" → (count, time)
    by: BTreeMap<String, (u64, Duration)>,
}

impl Stats {
    pub(crate) fn record(&mut self, request: &[u8], took: Duration) {
        self.total += 1;
        let (actor, command) = classify(request);
        for key in [actor.clone(), format!("{actor} {command}")] {
            let e = self.by.entry(key).or_default();
            e.0 += 1;
            e.1 += took;
        }
    }
}

/// (actor, command) of a request: the agent actor's command is the word after the id.
fn classify(request: &[u8]) -> (String, String) {
    let req = until_nul(request);
    let req = &req[req.iter().position(|&c| c != b' ' && c != b'\n').unwrap_or(req.len())..];
    let (actor, rest) = split_word(req);
    let rest = rest.unwrap_or(b"");
    let command = match actor {
        b"agent" => split_word(rest).1.map(|r| split_word(r).0).unwrap_or(b""),
        _ => split_word(rest).0,
    };
    let text = |b: &[u8]| String::from_utf8_lossy(&b[..b.len().min(64)]).into_owned();
    match actor {
        b"agent" | b"global" | b"task" | b"wazuhdb" | b"mitre" => (text(actor), text(command)),
        _ => ("unknown".into(), String::new()),
    }
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0
}

impl Engine {
    /// The statistics as JSON.
    pub fn stats_json(&self) -> Json {
        let s = self.stats.lock();
        let now = self.time();
        let (mut received, mut execution) = (Json::object(), Json::object());
        let mut breakdown: BTreeMap<&str, (Json, Json)> = BTreeMap::new();
        for (key, (count, took)) in &s.by {
            match key.split_once(' ') {
                None => {
                    received.add(key.as_str(), Json::number(*count as f64));
                    execution.add(key.as_str(), Json::number(ms(*took)));
                }
                Some((actor, command)) => {
                    let e = breakdown.entry(actor).or_insert_with(|| (Json::object(), Json::object()));
                    let name = if command.is_empty() { "(none)" } else { command };
                    e.0.add(name, Json::number(*count as f64));
                    e.1.add(name, Json::number(ms(*took)));
                }
            }
        }
        for (actor, (r, t)) in breakdown {
            received.add(format!("{actor}_breakdown").as_str(), r);
            execution.add(format!("{actor}_breakdown").as_str(), t);
        }
        let total_time: Duration = s.by.iter().filter(|(k, _)| !k.contains(' ')).map(|(_, v)| v.1).sum();
        let mut queries = Json::object();
        queries.add("received", Json::number(s.total as f64));
        queries.add("received_breakdown", received);
        let mut time = Json::object();
        time.add("execution", Json::number(ms(total_time)));
        time.add("execution_breakdown", execution);
        let mut metrics = Json::object();
        metrics.add("queries", queries);
        metrics.add("time", time);
        let mut root = Json::object();
        root.add("uptime", Json::number(self.started as f64));
        root.add("timestamp", Json::number(now as f64));
        root.add("name", Json::string("provigil-db"));
        root.add("metrics", metrics);
        root
    }

    fn internal_config(&self) -> Json {
        let s = &self.settings;
        let mut w = Json::object();
        for (k, v) in [
            ("commit_time_max", s.commit_time_max),
            ("commit_time_min", s.commit_time_min),
            ("open_db_limit", s.open_db_limit as i64),
            ("fragmentation_threshold", s.fragmentation_threshold as i64),
            ("fragmentation_delta", s.fragmentation_delta as i64),
            ("free_pages_percentage", s.free_pages_percentage as i64),
            ("max_fragmentation", s.max_fragmentation as i64),
            ("check_fragmentation_interval", s.check_fragmentation_interval),
        ] {
            w.add(k, Json::number(v as f64));
        }
        let mut root = Json::object();
        root.add("provigil_db", w);
        root
    }

    fn backup_config(&self) -> Json {
        let s = &self.settings;
        let mut n = Json::object();
        n.add("database", Json::string("global"));
        n.add("enabled", Json::bool(s.backup_enabled));
        n.add("interval", Json::number(s.backup_interval as f64));
        n.add("max_files", Json::number(s.backup_max_files as f64));
        let mut wdb = Json::object();
        wdb.add("backup", Json::Array(vec![n]));
        let mut root = Json::object();
        root.add("wdb", wdb);
        root
    }

    /// A JSON command: `{"error":<code>,"message":"…","data":{…}}`.
    pub fn json_command(&self, request: &[u8]) -> Vec<u8> {
        const MESSAGES: [&str; 7] =
            ["ok", "Invalid JSON input", "Empty command", "Unrecognized command", "Empty parameters", "Empty section", "Unrecognized or not configured section"];
        let reply = |code: usize, data: Option<Json>| {
            let mut root = Json::object();
            root.add("error", Json::number(code as f64));
            root.add("message", Json::string(MESSAGES[code]));
            root.add("data", data.unwrap_or_else(Json::object));
            root.print_unformatted()
        };
        let Ok((req, _)) = provigil_json::parse_with_opts(until_nul(request), false) else { return reply(1, None) };
        let text = |j: Option<&Json>| match j {
            Some(Json::String(s)) => Some(until_nul(s).to_vec()),
            _ => None,
        };
        match text(req.get("command")).as_deref() {
            None => reply(2, None),
            Some(b"getstats") => reply(0, Some(self.stats_json())),
            Some(b"getconfig") => match req.get("parameters") {
                Some(p @ Json::Object(_)) => match text(p.get("section")).as_deref() {
                    None => reply(5, None),
                    Some(b"internal") => reply(0, Some(self.internal_config())),
                    Some(b"wdb") => reply(0, Some(self.backup_config())),
                    Some(_) => reply(6, None),
                },
                _ => reply(4, None),
            },
            Some(_) => reply(3, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_requests() {
        assert_eq!(classify(b"agent 1 syscollector_osinfo save2 {}"), ("agent".into(), "syscollector_osinfo".into()));
        assert_eq!(classify(b" global get-agent-info {}"), ("global".into(), "get-agent-info".into()));
        assert_eq!(classify(b"nonsense"), ("unknown".into(), String::new()));
        let mut s = Stats::default();
        s.record(b"task upgrade {}", Duration::from_millis(2));
        s.record(b"task upgrade {}", Duration::from_millis(3));
        assert_eq!(s.total, 2);
        assert_eq!(s.by["task upgrade"].0, 2);
    }
}
