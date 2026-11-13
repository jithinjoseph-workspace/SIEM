//! Service statistics (spec section 2.22): global and per-agent counters, the state file
//! and the `getstats` / `getagentsstats` JSON.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use provigil_json::Json;

pub const NAME: &str = "provigil-analysisd";
/// Agents per `getagentsstats` answer.
pub const AGENTS_PER_ANSWER: usize = 75;

/// Where an event came from: one counter of [`Counts`]. The order is the counters' order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    Agent,
    Agentless,
    Dbsync,
    Monitor,
    Remote,
    Syslog,
    Virustotal,
    Aws,
    Azure,
    Ciscat,
    Command,
    Docker,
    Gcp,
    Github,
    Office365,
    MsGraph,
    Oscap,
    Osquery,
    Rootcheck,
    Sca,
    Syscheck,
    Syscollector,
    Upgrade,
    Vulnerability,
    Eventchannel,
    Eventlog,
    Macos,
    Others,
}

const COMPONENTS: usize = 28;

impl Component {
    /// By the module name in a location (the names agents and modules send, old and new).
    pub fn of_module(m: &[u8]) -> Component {
        use Component::*;
        match m {
            b"wazuh-agent" => Agent,
            b"provigil-agentlessd" | b"wazuh-agentlessd" => Agentless,
            b"provigil-monitord" | b"wazuh-monitord" => Monitor,
            b"provigil-remoted" | b"wazuh-remoted" => Remote,
            b"virustotal" => Virustotal,
            b"aws-s3" | b"Wazuh-AWS" => Aws,
            b"azure-logs" | b"Azure" => Azure,
            b"cis-cat" | b"wodle_cis-cat" => Ciscat,
            _ if m == b"command" || m.starts_with(b"command_") => Command,
            b"docker-listener" | b"Wazuh-Docker" => Docker,
            b"gcp-pubsub" | b"gcp-bucket" | b"Wazuh-GCloud" => Gcp,
            b"github" => Github,
            b"office365" => Office365,
            b"ms-graph" => MsGraph,
            b"open-scap" | b"wodle_open-scap" => Oscap,
            b"osquery" => Osquery,
            b"rootcheck" => Rootcheck,
            b"sca" => Sca,
            b"syscheck" => Syscheck,
            b"syscollector" => Syscollector,
            b"agent-upgrade" => Upgrade,
            b"vulnerability-detector" => Vulnerability,
            b"macos" => Macos,
            b"WinEvtLog" => Eventlog,
            _ => Others,
        }
    }

    /// Agentless and syslog events are not counted per agent.
    fn per_agent(self) -> bool {
        !matches!(self, Component::Agentless | Component::Syslog)
    }
}

/// The module after `->` in a location (the location itself when there is none).
pub fn module_of_location(location: &[u8]) -> &[u8] {
    match crate::event::find(location, b"->") {
        Some(p) => &location[p + 2..],
        None => location,
    }
}

/// The module of a raw message `q:[id] (name) ip->module:log` or `q:module:log`.
pub fn module_of_message(msg: &[u8]) -> Option<&[u8]> {
    let m = msg.get(2..).unwrap_or(b"");
    let start = if m.first() == Some(&b'[') { &m[crate::event::find(m, b"->")? + 2..] } else { m };
    Some(&start[..start.iter().position(|&c| c == b':')?])
}

/// One counter per component.
#[derive(Debug, Clone, Copy)]
pub struct Counts([u64; COMPONENTS]);

impl Default for Counts {
    fn default() -> Counts {
        Counts([0; COMPONENTS])
    }
}

impl Counts {
    pub fn get(&self, c: Component) -> u64 {
        self.0[c as usize]
    }
    fn bump(&mut self, c: Component) {
        self.0[c as usize] += 1;
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Eps {
    pub available_credits_prev: u64,
    pub events_dropped: u64,
    pub events_dropped_not_eps: u64,
    pub seconds_over_limit: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Global {
    pub uptime: u64,
    pub received_bytes: u64,
    pub events_received: u64,
    pub events_processed: u64,
    pub decoded: Counts,
    pub dropped: Counts,
    pub alerts: u64,
    pub archives: u64,
    pub firewall: u32,
    pub fts: u32,
    pub stats: u32,
    pub eps: Eps,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Agent {
    pub uptime: u64,
    pub processed: u64,
    pub alerts: u64,
    pub archives: u64,
    pub firewall: u32,
    pub decoded: Counts,
}

/// A queue's size and how full it is (elements / (size - 1), as a 32-bit float).
#[derive(Debug, Clone, Copy, Default)]
pub struct QueueUse {
    pub size: usize,
    pub usage: f32,
}

impl QueueUse {
    pub fn new(size: usize, elements: usize) -> QueueUse {
        QueueUse { size, usage: elements as f32 / (size as f32 - 1.0) }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Queues {
    pub syscheck: QueueUse,
    pub syscollector: QueueUse,
    pub rootcheck: QueueUse,
    pub sca: QueueUse,
    pub hostinfo: QueueUse,
    pub winevt: QueueUse,
    pub dbsync: QueueUse,
    pub upgrade: QueueUse,
    pub events: QueueUse,
    pub processed: QueueUse,
    pub alerts: QueueUse,
    pub archives: QueueUse,
    pub firewall: QueueUse,
    pub fts: QueueUse,
    pub stats: QueueUse,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub g: Global,
    pub agents: HashMap<String, Agent>,
}

/// An agent id other than the manager's.
fn agent_key(id: Option<&[u8]>) -> Option<String> {
    let id = crate::event::text_at(id?, 0);
    (id != b"000").then(|| String::from_utf8_lossy(id).into_owned())
}

impl Stats {
    pub fn new(now: i64) -> Stats {
        Stats { g: Global { uptime: now as u64, ..Global::default() }, agents: HashMap::new() }
    }

    fn agent(&mut self, id: String, now: i64) -> &mut Agent {
        self.agents.entry(id).or_insert_with(|| Agent { uptime: now as u64, ..Agent::default() })
    }

    pub fn received(&mut self, bytes: usize) {
        self.g.received_bytes += bytes as u64;
        self.g.events_received += 1;
    }

    pub fn decoded(&mut self, c: Component, agent: Option<&[u8]>, now: i64) {
        self.g.decoded.bump(c);
        if let (true, Some(id)) = (c.per_agent(), agent_key(agent)) {
            self.agent(id, now).decoded.bump(c);
        }
    }

    pub fn dropped(&mut self, c: Component) {
        self.g.dropped.bump(c);
    }

    pub fn processed(&mut self, agent: Option<&[u8]>, now: i64) {
        self.g.events_processed += 1;
        if let Some(id) = agent_key(agent) {
            self.agent(id, now).processed += 1;
        }
    }

    pub fn alert_written(&mut self, agent: Option<&[u8]>, now: i64) {
        self.g.alerts += 1;
        if let Some(id) = agent_key(agent) {
            self.agent(id, now).alerts += 1;
        }
    }

    pub fn archive_written(&mut self, agent: Option<&[u8]>, now: i64) {
        self.g.archives += 1;
        if let Some(id) = agent_key(agent) {
            self.agent(id, now).archives += 1;
        }
    }

    pub fn firewall_written(&mut self, agent: Option<&[u8]>, now: i64) {
        self.g.firewall = self.g.firewall.wrapping_add(1);
        if let Some(id) = agent_key(agent) {
            let a = self.agent(id, now);
            a.firewall = a.firewall.wrapping_add(1);
        }
    }

    pub fn fts_written(&mut self) {
        self.g.fts = self.g.fts.wrapping_add(1);
    }

    pub fn stats_written(&mut self) {
        self.g.stats = self.g.stats.wrapping_add(1);
    }

    /// Only the active agents stay.
    pub fn keep_agents(&mut self, active: &[i32]) {
        self.agents.retain(|id, _| active.contains(&crate::rules::atoi(id)));
    }

    /// The text of `var/run/provigil-analysisd.state`.
    pub fn file_text(&self, q: &Queues) -> String {
        use Component::*;
        let other = |c: &Counts| c.get(Upgrade) + c.get(Ciscat) + c.get(Syslog) + c.get(Others);
        let total = |c: &Counts| c.get(Syscheck) + c.get(Syscollector) + c.get(Rootcheck) + c.get(Sca) + c.get(Eventchannel) + c.get(Dbsync) + other(c);
        let (d, s) = (&self.g.decoded, &self.g);
        let mut out = format!("# State file for {NAME}\n# THIS FILE WILL BE DEPRECATED IN FUTURE VERSIONS\n\n");
        let mut item = |title: &str, key: &str, v: String| out.push_str(&format!("# {title}\n{key}='{v}'\n\n"));
        for (title, key, v) in [
            ("Total events decoded", "total_events_decoded", total(d)),
            ("Syscheck events decoded", "syscheck_events_decoded", d.get(Syscheck)),
            ("Syscollector events decoded", "syscollector_events_decoded", d.get(Syscollector)),
            ("Rootcheck events decoded", "rootcheck_events_decoded", d.get(Rootcheck)),
            ("Security configuration assessment events decoded", "sca_events_decoded", d.get(Sca)),
            ("Winevt events decoded", "winevt_events_decoded", d.get(Eventchannel)),
            ("Database synchronization messages dispatched", "dbsync_messages_dispatched", d.get(Dbsync)),
            ("Other events decoded", "other_events_decoded", other(d)),
            ("Events processed (Rule matching)", "events_processed", s.events_processed),
            ("Events received", "events_received", s.events_received),
            ("Events dropped", "events_dropped", total(&s.dropped)),
            ("Alerts written to disk", "alerts_written", s.alerts),
            ("Firewall alerts written to disk", "firewall_written", u64::from(s.firewall)),
            ("FTS alerts written to disk", "fts_written", u64::from(s.fts)),
        ] {
            item(title, key, v.to_string());
        }
        for (title, key, u) in [
            ("Syscheck queue", "syscheck_queue", q.syscheck),
            ("Syscollector queue", "syscollector_queue", q.syscollector),
            ("Rootcheck queue", "rootcheck_queue", q.rootcheck),
            ("Security configuration assessment queue", "sca_queue", q.sca),
            ("Hostinfo queue", "hostinfo_queue", q.hostinfo),
            ("Winevt queue", "winevt_queue", q.winevt),
            ("Database synchronization message queue", "dbsync_queue", q.dbsync),
            ("Upgrade module message queue", "upgrade_queue", q.upgrade),
            ("Event queue", "event_queue", q.events),
            ("Rule matching queue", "rule_matching_queue", q.processed),
            ("Alerts log queue", "alerts_queue", q.alerts),
            ("Firewall log queue", "firewall_queue", q.firewall),
            ("Statistical log queue", "statistical_queue", q.stats),
            ("Archives log queue", "archives_queue", q.archives),
        ] {
            item(title, &format!("{key}_usage"), format!("{:.2}", f64::from(u.usage)));
            item(&format!("{title} size"), &format!("{key}_size"), u.size.to_string());
        }
        out
    }

    /// Writes the state file (through a `.temp` file); the error text to log.
    pub fn write_file(&self, home: &Path, q: &Queues) -> Result<(), String> {
        let rel = format!("var/run/{NAME}.state");
        let (path, tmp) = (home.join(&rel), home.join(format!("{rel}.temp")));
        if let Err(e) = std::fs::File::create(&tmp).and_then(|mut f| f.write_all(self.file_text(q).as_bytes())) {
            let (n, t) = crate::messages::os_error(&e);
            return Err(format!("(1103): Could not open file '{rel}.temp' due to [({n})-({t})]."));
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let mut m = format!("Renaming {rel}.temp to {rel}: {}", crate::messages::os_error(&e).1);
            if let Err(e2) = std::fs::remove_file(&tmp) {
                m.push_str(&format!("\nDeleting {rel}.temp: {}", crate::messages::os_error(&e2).1));
            }
            return Err(m);
        }
        Ok(())
    }

    /// The `getstats` data (`eps`: the credits left, when the limit is on).
    pub fn json(&self, now: i64, q: &Queues, eps: Option<u32>) -> Json {
        let s = &self.g;
        let mut root = Json::object();
        root.add("uptime", num(s.uptime));
        root.add("timestamp", num(now));
        root.add("name", Json::string(NAME));
        let mut metrics = Json::object();
        let mut bytes = Json::object();
        bytes.add("received", num(s.received_bytes));
        metrics.add("bytes", bytes);
        if let Some(credits) = eps {
            let mut e = Json::object();
            e.add("available_credits", num(credits));
            e.add("available_credits_prev", num(s.eps.available_credits_prev));
            e.add("events_dropped", num(s.eps.events_dropped));
            e.add("events_dropped_not_eps", num(s.eps.events_dropped_not_eps));
            e.add("seconds_over_limit", num(s.eps.seconds_over_limit));
            metrics.add("eps", e);
        }
        let mut events = Json::object();
        events.add("processed", num(s.events_processed));
        events.add("received", num(s.events_received));
        let mut received = Json::object();
        received.add("decoded_breakdown", counts_json(&s.decoded, true));
        received.add("dropped_breakdown", counts_json(&s.dropped, true));
        events.add("received_breakdown", received);
        let mut written = Json::object();
        for (k, v) in [("alerts", s.alerts), ("archives", s.archives), ("firewall", u64::from(s.firewall)), ("fts", u64::from(s.fts)), ("stats", u64::from(s.stats))] {
            written.add(k, num(v));
        }
        events.add("written_breakdown", written);
        metrics.add("events", events);
        let mut queues = Json::object();
        for (k, u) in [
            ("alerts", q.alerts),
            ("archives", q.archives),
            ("dbsync", q.dbsync),
            ("eventchannel", q.winevt),
            ("firewall", q.firewall),
            ("fts", q.fts),
            ("hostinfo", q.hostinfo),
            ("others", q.events),
            ("processed", q.processed),
            ("rootcheck", q.rootcheck),
            ("sca", q.sca),
            ("stats", q.stats),
            ("syscheck", q.syscheck),
            ("syscollector", q.syscollector),
            ("upgrade", q.upgrade),
        ] {
            let mut j = Json::object();
            j.add("size", num(u.size));
            j.add("usage", Json::number(f64::from(u.usage)));
            queues.add(k, j);
        }
        metrics.add("queues", queues);
        root.add("metrics", metrics);
        root
    }

    /// The `getagentsstats` data of the listed agents that have counters.
    pub fn agents_json(&self, now: i64, ids: &[i32]) -> Json {
        let mut root = Json::object();
        root.add("timestamp", num(now));
        root.add("name", Json::string(NAME));
        let mut list = Vec::new();
        for &id in ids {
            let Some(a) = self.agents.get(&format!("{id:03}")) else { continue };
            let mut item = Json::object();
            item.add("uptime", num(a.uptime));
            item.add("id", num(id));
            let mut events = Json::object();
            events.add("processed", num(a.processed));
            let mut received = Json::object();
            received.add("decoded_breakdown", counts_json(&a.decoded, false));
            events.add("received_breakdown", received);
            let mut written = Json::object();
            for (k, v) in [("alerts", a.alerts), ("archives", a.archives), ("firewall", u64::from(a.firewall))] {
                written.add(k, num(v));
            }
            events.add("written_breakdown", written);
            let mut metrics = Json::object();
            metrics.add("events", events);
            item.add("metrics", metrics);
            list.push(item);
        }
        root.add("agents", Json::Array(list));
        root
    }
}

/// Counters of any width as JSON numbers.
trait Number {
    fn wide(self) -> f64;
}
macro_rules! number {
    ($($t:ty),*) => {$(impl Number for $t {
        fn wide(self) -> f64 {
            self as f64
        }
    })*};
}
number!(u64, u32, i64, i32, usize);

fn num(v: impl Number) -> Json {
    Json::number(v.wide())
}

/// The counters as the breakdown objects (`global`: with agentless and syslog).
fn counts_json(c: &Counts, global: bool) -> Json {
    use Component::*;
    let n = |x: Component| num(c.get(x));
    let mut d = Json::object();
    d.add("agent", n(Agent));
    if global {
        d.add("agentless", n(Agentless));
    }
    d.add("dbsync", n(Dbsync));
    let mut integrations = Json::object();
    integrations.add("virustotal", n(Virustotal));
    d.add("integrations_breakdown", integrations);
    let mut m = Json::object();
    for (k, x) in [("aws", Aws), ("azure", Azure), ("ciscat", Ciscat), ("command", Command), ("docker", Docker), ("gcp", Gcp), ("github", Github)] {
        m.add(k, n(x));
    }
    let mut lc = Json::object();
    for (k, x) in [("eventchannel", Eventchannel), ("eventlog", Eventlog), ("macos", Macos), ("others", Others)] {
        lc.add(k, n(x));
    }
    m.add("logcollector_breakdown", lc);
    for (k, x) in [
        ("office365", Office365),
        ("ms-graph", MsGraph),
        ("oscap", Oscap),
        ("osquery", Osquery),
        ("rootcheck", Rootcheck),
        ("sca", Sca),
        ("syscheck", Syscheck),
        ("syscollector", Syscollector),
        ("upgrade", Upgrade),
        ("vulnerability", Vulnerability),
    ] {
        m.add(k, n(x));
    }
    d.add("modules_breakdown", m);
    d.add("monitor", n(Monitor));
    d.add("remote", n(Remote));
    if global {
        d.add("syslog", n(Syslog));
    }
    d
}
