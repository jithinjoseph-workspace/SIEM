//! Daemon statistics (analysisd/state.c): global and per-agent counters,
//! the `var/run/wazuh-analysisd.state` file and the `getstats` /
//! `getagentsstats` JSON.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use siem_cjson::Json;

pub const ARGV0: &str = "wazuh-analysisd";
/// `ASYS_MAX_NUM_AGENTS_STATS`
pub const ASYS_MAX_NUM_AGENTS_STATS: usize = 75;

/// `logcollector_t`
#[derive(Debug, Clone, Copy, Default)]
pub struct Logcollector {
    pub eventchannel: u64,
    pub eventlog: u64,
    pub macos: u64,
    pub others: u64,
}

/// `modules_t`
#[derive(Debug, Clone, Copy, Default)]
pub struct Modules {
    pub aws: u64,
    pub azure: u64,
    pub ciscat: u64,
    pub command: u64,
    pub docker: u64,
    pub gcp: u64,
    pub github: u64,
    pub office365: u64,
    pub ms_graph: u64,
    pub oscap: u64,
    pub osquery: u64,
    pub rootcheck: u64,
    pub sca: u64,
    pub syscheck: u64,
    pub syscollector: u64,
    pub upgrade: u64,
    pub vulnerability: u64,
    pub logcollector: Logcollector,
}

/// `events_t`
#[derive(Debug, Clone, Copy, Default)]
pub struct Events {
    pub agent: u64,
    pub agentless: u64,
    pub dbsync: u64,
    pub monitor: u64,
    pub remote: u64,
    pub syslog: u64,
    pub virustotal: u64,
    pub modules: Modules,
}

/// `written_t`
#[derive(Debug, Clone, Copy, Default)]
pub struct Written {
    pub alerts: u64,
    pub archives: u64,
    pub firewall: u32,
    pub fts: u32,
    pub stats: u32,
}

/// `eps_state_t`
#[derive(Debug, Clone, Copy, Default)]
pub struct EpsState {
    pub available_credits_prev: u64,
    pub events_dropped: u64,
    pub events_dropped_not_eps: u64,
    pub seconds_over_limit: u64,
}

/// `analysisd_state_t`
#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalState {
    pub uptime: u64,
    pub received_bytes: u64,
    pub events_received: u64,
    pub events_processed: u64,
    pub decoded: Events,
    pub dropped: Events,
    pub written: Written,
    pub eps: EpsState,
}

/// `analysisd_agent_state_t`
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentState {
    pub uptime: u64,
    pub events_processed: u64,
    pub alerts_written: u64,
    pub archives_written: u64,
    pub firewall_written: u32,
    pub decoded: Events,
}

/// One queue's (size, usage) for the reports.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueueStat {
    pub size: usize,
    /// `queue_get_percentage_ex` (a C float)
    pub usage: f32,
}

impl QueueStat {
    /// `queue_get_percentage_ex`: elements / (size - 1)
    pub fn new(size: usize, elements: usize) -> Self {
        QueueStat { size, usage: elements as f32 / (size as f32 - 1.0) }
    }
}

/// `queue_status_t`
#[derive(Debug, Clone, Copy, Default)]
pub struct QueueStatus {
    pub syscheck: QueueStat,
    pub syscollector: QueueStat,
    pub rootcheck: QueueStat,
    pub sca: QueueStat,
    pub hostinfo: QueueStat,
    pub winevt: QueueStat,
    pub dbsync: QueueStat,
    pub upgrade: QueueStat,
    pub events: QueueStat,
    pub processed: QueueStat,
    pub alerts: QueueStat,
    pub archives: QueueStat,
    pub firewall: QueueStat,
    pub fts: QueueStat,
    pub stats: QueueStat,
}

/// Which counter of `events_t` a decoded/dropped event goes to.
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

impl Component {
    /// `w_inc_decoded_by_component_events` / `w_inc_dropped_by_component_events`
    pub fn from_module(m: &[u8]) -> Component {
        use Component::*;
        match m {
            b"wazuh-agent" => Agent,
            b"wazuh-agentlessd" => Agentless,
            b"wazuh-monitord" => Monitor,
            b"wazuh-remoted" => Remote,
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

    /// Agentless and syslog have no per-agent counter.
    fn per_agent(self) -> bool {
        !matches!(self, Component::Agentless | Component::Syslog)
    }
}

impl Events {
    fn slot(&mut self, c: Component) -> &mut u64 {
        use Component::*;
        match c {
            Agent => &mut self.agent,
            Agentless => &mut self.agentless,
            Dbsync => &mut self.dbsync,
            Monitor => &mut self.monitor,
            Remote => &mut self.remote,
            Syslog => &mut self.syslog,
            Virustotal => &mut self.virustotal,
            Aws => &mut self.modules.aws,
            Azure => &mut self.modules.azure,
            Ciscat => &mut self.modules.ciscat,
            Command => &mut self.modules.command,
            Docker => &mut self.modules.docker,
            Gcp => &mut self.modules.gcp,
            Github => &mut self.modules.github,
            Office365 => &mut self.modules.office365,
            MsGraph => &mut self.modules.ms_graph,
            Oscap => &mut self.modules.oscap,
            Osquery => &mut self.modules.osquery,
            Rootcheck => &mut self.modules.rootcheck,
            Sca => &mut self.modules.sca,
            Syscheck => &mut self.modules.syscheck,
            Syscollector => &mut self.modules.syscollector,
            Upgrade => &mut self.modules.upgrade,
            Vulnerability => &mut self.modules.vulnerability,
            Eventchannel => &mut self.modules.logcollector.eventchannel,
            Eventlog => &mut self.modules.logcollector.eventlog,
            Macos => &mut self.modules.logcollector.macos,
            Others => &mut self.modules.logcollector.others,
        }
    }
}

/// `extract_module_from_location`
pub fn module_from_location(location: &[u8]) -> &[u8] {
    match location.windows(2).position(|w| w == b"->") {
        Some(p) => &location[p + 2..],
        None => location,
    }
}

/// `extract_module_from_message` (None on a format error).
pub fn module_from_message(msg: &[u8]) -> Option<&[u8]> {
    let m = msg.get(2..).unwrap_or(b"");
    let start = if m.first() == Some(&b'[') {
        let p = m.windows(2).position(|w| w == b"->")?;
        &m[p + 2..]
    } else {
        m
    };
    let end = start.iter().position(|&c| c == b':')?;
    Some(&start[..end])
}

/// All of state.c's counters.
#[derive(Debug, Default)]
pub struct State {
    pub g: GlobalState,
    pub agents: HashMap<String, AgentState>,
}

fn real_agent(agent_id: Option<&[u8]>) -> Option<String> {
    let id = agent_id?;
    let id = &id[..id.iter().position(|&c| c == 0).unwrap_or(id.len())];
    if id == b"000" {
        return None;
    }
    Some(String::from_utf8_lossy(id).into_owned())
}

impl State {
    pub fn new(now: i64) -> Self {
        State { g: GlobalState { uptime: now as u64, ..Default::default() }, agents: HashMap::new() }
    }

    /// `get_node`
    fn agent(&mut self, id: String, now: i64) -> &mut AgentState {
        self.agents.entry(id).or_insert_with(|| AgentState { uptime: now as u64, ..Default::default() })
    }

    /// `w_add_recv` + `w_inc_received_events`
    pub fn received(&mut self, bytes: usize) {
        self.g.received_bytes += bytes as u64;
        self.g.events_received += 1;
    }

    /// `w_inc_*_decoded_events(agent_id)`
    pub fn decoded(&mut self, c: Component, agent_id: Option<&[u8]>, now: i64) {
        *self.g.decoded.slot(c) += 1;
        if c.per_agent() {
            if let Some(id) = real_agent(agent_id) {
                *self.agent(id, now).decoded.slot(c) += 1;
            }
        }
    }

    /// `w_inc_*_dropped_events()`
    pub fn dropped(&mut self, c: Component) {
        *self.g.dropped.slot(c) += 1;
    }

    /// `w_inc_processed_events`
    pub fn processed(&mut self, agent_id: Option<&[u8]>, now: i64) {
        self.g.events_processed += 1;
        if let Some(id) = real_agent(agent_id) {
            self.agent(id, now).events_processed += 1;
        }
    }

    /// `w_inc_alerts_written`
    pub fn alert_written(&mut self, agent_id: Option<&[u8]>, now: i64) {
        self.g.written.alerts += 1;
        if let Some(id) = real_agent(agent_id) {
            self.agent(id, now).alerts_written += 1;
        }
    }

    /// `w_inc_archives_written`
    pub fn archive_written(&mut self, agent_id: Option<&[u8]>, now: i64) {
        self.g.written.archives += 1;
        if let Some(id) = real_agent(agent_id) {
            self.agent(id, now).archives_written += 1;
        }
    }

    /// `w_inc_firewall_written`
    pub fn firewall_written(&mut self, agent_id: Option<&[u8]>, now: i64) {
        self.g.written.firewall = self.g.written.firewall.wrapping_add(1);
        if let Some(id) = real_agent(agent_id) {
            let a = self.agent(id, now);
            a.firewall_written = a.firewall_written.wrapping_add(1);
        }
    }

    pub fn fts_written(&mut self) {
        self.g.written.fts = self.g.written.fts.wrapping_add(1);
    }

    pub fn stats_written(&mut self) {
        self.g.written.stats = self.g.written.stats.wrapping_add(1);
    }

    /// `w_analysisd_clean_agents_state`: keep only the active agents.
    pub fn clean_agents(&mut self, active: &[i32]) {
        if self.agents.is_empty() {
            return;
        }
        self.agents.retain(|id, _| active.contains(&crate::rules::atoi(id)));
    }

    /// The state file text (`w_analysisd_write_state`).
    pub fn file_text(&self, q: &QueueStatus) -> String {
        let s = &self.g;
        let d = &s.decoded;
        let x = &s.dropped;
        let other = |e: &Events| e.modules.upgrade + e.modules.ciscat + e.syslog + e.modules.logcollector.others;
        let total = |e: &Events| {
            e.modules.syscheck
                + e.modules.syscollector
                + e.modules.rootcheck
                + e.modules.sca
                + e.modules.logcollector.eventchannel
                + e.dbsync
                + other(e)
        };
        let u = |v: f32| format!("{:.2}", v as f64);
        format!(
            "# State file for {ARGV0}\n\
             # THIS FILE WILL BE DEPRECATED IN FUTURE VERSIONS\n\
             \n\
             # Total events decoded\n\
             total_events_decoded='{}'\n\
             \n\
             # Syscheck events decoded\n\
             syscheck_events_decoded='{}'\n\
             \n\
             # Syscollector events decoded\n\
             syscollector_events_decoded='{}'\n\
             \n\
             # Rootcheck events decoded\n\
             rootcheck_events_decoded='{}'\n\
             \n\
             # Security configuration assessment events decoded\n\
             sca_events_decoded='{}'\n\
             \n\
             # Winevt events decoded\n\
             winevt_events_decoded='{}'\n\
             \n\
             # Database synchronization messages dispatched\n\
             dbsync_messages_dispatched='{}'\n\
             \n\
             # Other events decoded\n\
             other_events_decoded='{}'\n\
             \n\
             # Events processed (Rule matching)\n\
             events_processed='{}'\n\
             \n\
             # Events received\n\
             events_received='{}'\n\
             \n\
             # Events dropped\n\
             events_dropped='{}'\n\
             \n\
             # Alerts written to disk\n\
             alerts_written='{}'\n\
             \n\
             # Firewall alerts written to disk\n\
             firewall_written='{}'\n\
             \n\
             # FTS alerts written to disk\n\
             fts_written='{}'\n\
             \n\
             # Syscheck queue\n\
             syscheck_queue_usage='{}'\n\
             \n\
             # Syscheck queue size\n\
             syscheck_queue_size='{}'\n\
             \n\
             # Syscollector queue\n\
             syscollector_queue_usage='{}'\n\
             \n\
             # Syscollector queue size\n\
             syscollector_queue_size='{}'\n\
             \n\
             # Rootcheck queue\n\
             rootcheck_queue_usage='{}'\n\
             \n\
             # Rootcheck queue size\n\
             rootcheck_queue_size='{}'\n\
             \n\
             # Security configuration assessment queue\n\
             sca_queue_usage='{}'\n\
             \n\
             # Security configuration assessment queue size\n\
             sca_queue_size='{}'\n\
             \n\
             # Hostinfo queue\n\
             hostinfo_queue_usage='{}'\n\
             \n\
             # Hostinfo queue size\n\
             hostinfo_queue_size='{}'\n\
             \n\
             # Winevt queue\n\
             winevt_queue_usage='{}'\n\
             \n\
             # Winevt queue size\n\
             winevt_queue_size='{}'\n\
             \n\
             # Database synchronization message queue\n\
             dbsync_queue_usage='{}'\n\
             \n\
             # Database synchronization message queue size\n\
             dbsync_queue_size='{}'\n\
             \n\
             # Upgrade module message queue\n\
             upgrade_queue_usage='{}'\n\
             \n\
             # Upgrade module message queue size\n\
             upgrade_queue_size='{}'\n\
             \n\
             # Event queue\n\
             event_queue_usage='{}'\n\
             \n\
             # Event queue size\n\
             event_queue_size='{}'\n\
             \n\
             # Rule matching queue\n\
             rule_matching_queue_usage='{}'\n\
             \n\
             # Rule matching queue size\n\
             rule_matching_queue_size='{}'\n\
             \n\
             # Alerts log queue\n\
             alerts_queue_usage='{}'\n\
             \n\
             # Alerts log queue size\n\
             alerts_queue_size='{}'\n\
             \n\
             # Firewall log queue\n\
             firewall_queue_usage='{}'\n\
             \n\
             # Firewall log queue size\n\
             firewall_queue_size='{}'\n\
             \n\
             # Statistical log queue\n\
             statistical_queue_usage='{}'\n\
             \n\
             # Statistical log queue size\n\
             statistical_queue_size='{}'\n\
             \n\
             # Archives log queue\n\
             archives_queue_usage='{}'\n\
             \n\
             # Archives log queue size\n\
             archives_queue_size='{}'\n\
             \n",
            total(d),
            d.modules.syscheck,
            d.modules.syscollector,
            d.modules.rootcheck,
            d.modules.sca,
            d.modules.logcollector.eventchannel,
            d.dbsync,
            other(d),
            s.events_processed,
            s.events_received,
            total(x),
            s.written.alerts,
            s.written.firewall,
            s.written.fts,
            u(q.syscheck.usage),
            q.syscheck.size,
            u(q.syscollector.usage),
            q.syscollector.size,
            u(q.rootcheck.usage),
            q.rootcheck.size,
            u(q.sca.usage),
            q.sca.size,
            u(q.hostinfo.usage),
            q.hostinfo.size,
            u(q.winevt.usage),
            q.winevt.size,
            u(q.dbsync.usage),
            q.dbsync.size,
            u(q.upgrade.usage),
            q.upgrade.size,
            u(q.events.usage),
            q.events.size,
            u(q.processed.usage),
            q.processed.size,
            u(q.alerts.usage),
            q.alerts.size,
            u(q.firewall.usage),
            q.firewall.size,
            u(q.stats.usage),
            q.stats.size,
            u(q.archives.usage),
            q.archives.size,
        )
    }

    /// `w_analysisd_write_state`: write `<home>/var/run/wazuh-analysisd.state`
    /// through a `.temp` file and a rename. Returns the error to log.
    pub fn write_file(&self, home: &Path, q: &QueueStatus) -> Result<(), String> {
        let path = home.join(format!("var/run/{ARGV0}.state"));
        let tmp = home.join(format!("var/run/{ARGV0}.state.temp"));
        let text = self.file_text(q);
        let r = std::fs::File::create(&tmp).and_then(|mut f| f.write_all(text.as_bytes()));
        // messages name the paths relative to the home (analysisd chroots)
        let rel = format!("var/run/{ARGV0}.state");
        if let Err(e) = r {
            let (n, t) = crate::logmsg::errno_text(&e);
            return Err(format!("(1103): Could not open file '{rel}.temp' due to [({n})-({t})]."));
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let mut m = format!("Renaming {rel}.temp to {rel}: {}", crate::logmsg::errno_text(&e).1);
            if let Err(e2) = std::fs::remove_file(&tmp) {
                m.push('\n');
                m.push_str(&format!("Deleting {rel}.temp: {}", crate::logmsg::errno_text(&e2).1));
            }
            return Err(m);
        }
        Ok(())
    }
}

fn num(v: impl Into<f64>) -> Json {
    Json::number(v.into())
}

fn events_json(e: &Events, global: bool) -> Json {
    let mut d = Json::object();
    d.add("agent", num(e.agent as f64));
    if global {
        d.add("agentless", num(e.agentless as f64));
    }
    d.add("dbsync", num(e.dbsync as f64));
    let mut integ = Json::object();
    integ.add("virustotal", num(e.virustotal as f64));
    d.add("integrations_breakdown", integ);
    let m = &e.modules;
    let mut mj = Json::object();
    mj.add("aws", num(m.aws as f64));
    mj.add("azure", num(m.azure as f64));
    mj.add("ciscat", num(m.ciscat as f64));
    mj.add("command", num(m.command as f64));
    mj.add("docker", num(m.docker as f64));
    mj.add("gcp", num(m.gcp as f64));
    mj.add("github", num(m.github as f64));
    let mut lc = Json::object();
    lc.add("eventchannel", num(m.logcollector.eventchannel as f64));
    lc.add("eventlog", num(m.logcollector.eventlog as f64));
    lc.add("macos", num(m.logcollector.macos as f64));
    lc.add("others", num(m.logcollector.others as f64));
    mj.add("logcollector_breakdown", lc);
    mj.add("office365", num(m.office365 as f64));
    mj.add("ms-graph", num(m.ms_graph as f64));
    mj.add("oscap", num(m.oscap as f64));
    mj.add("osquery", num(m.osquery as f64));
    mj.add("rootcheck", num(m.rootcheck as f64));
    mj.add("sca", num(m.sca as f64));
    mj.add("syscheck", num(m.syscheck as f64));
    mj.add("syscollector", num(m.syscollector as f64));
    mj.add("upgrade", num(m.upgrade as f64));
    mj.add("vulnerability", num(m.vulnerability as f64));
    d.add("modules_breakdown", mj);
    d.add("monitor", num(e.monitor as f64));
    d.add("remote", num(e.remote as f64));
    if global {
        d.add("syslog", num(e.syslog as f64));
    }
    d
}

/// EPS figures for `getstats` (`limit_reached` credits).
#[derive(Debug, Clone, Copy)]
pub struct EpsReport {
    pub available_credits: u32,
}

impl State {
    /// `asys_create_state_json`
    pub fn state_json(&self, now: i64, q: &QueueStatus, eps: Option<EpsReport>) -> Json {
        let s = &self.g;
        let mut root = Json::object();
        root.add("uptime", num(s.uptime as f64));
        root.add("timestamp", num(now as f64));
        root.add("name", Json::string(ARGV0));
        let mut metrics = Json::object();
        let mut bytes = Json::object();
        bytes.add("received", num(s.received_bytes as f64));
        metrics.add("bytes", bytes);
        if let Some(e) = eps {
            let mut ej = Json::object();
            ej.add("available_credits", num(e.available_credits as f64));
            ej.add("available_credits_prev", num(s.eps.available_credits_prev as f64));
            ej.add("events_dropped", num(s.eps.events_dropped as f64));
            ej.add("events_dropped_not_eps", num(s.eps.events_dropped_not_eps as f64));
            ej.add("seconds_over_limit", num(s.eps.seconds_over_limit as f64));
            metrics.add("eps", ej);
        }
        let mut events = Json::object();
        events.add("processed", num(s.events_processed as f64));
        events.add("received", num(s.events_received as f64));
        let mut rb = Json::object();
        rb.add("decoded_breakdown", events_json(&s.decoded, true));
        rb.add("dropped_breakdown", events_json(&s.dropped, true));
        events.add("received_breakdown", rb);
        let mut wb = Json::object();
        wb.add("alerts", num(s.written.alerts as f64));
        wb.add("archives", num(s.written.archives as f64));
        wb.add("firewall", num(s.written.firewall));
        wb.add("fts", num(s.written.fts));
        wb.add("stats", num(s.written.stats));
        events.add("written_breakdown", wb);
        metrics.add("events", events);
        let mut queues = Json::object();
        for (name, st) in [
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
            j.add("size", num(st.size as f64));
            j.add("usage", num(st.usage as f64));
            queues.add(name, j);
        }
        metrics.add("queues", queues);
        root.add("metrics", metrics);
        root
    }

    /// `asys_create_agents_state_json`
    pub fn agents_json(&self, now: i64, ids: &[i32]) -> Json {
        let mut root = Json::object();
        root.add("timestamp", num(now as f64));
        root.add("name", Json::string(ARGV0));
        let mut arr = Vec::new();
        for &id in ids {
            let key = format!("{id:03}");
            let Some(a) = self.agents.get(&key) else { continue };
            let mut item = Json::object();
            item.add("uptime", num(a.uptime as f64));
            item.add("id", num(id));
            let mut metrics = Json::object();
            let mut events = Json::object();
            events.add("processed", num(a.events_processed as f64));
            let mut rb = Json::object();
            rb.add("decoded_breakdown", events_json(&a.decoded, false));
            events.add("received_breakdown", rb);
            let mut wb = Json::object();
            wb.add("alerts", num(a.alerts_written as f64));
            wb.add("archives", num(a.archives_written as f64));
            wb.add("firewall", num(a.firewall_written));
            events.add("written_breakdown", wb);
            metrics.add("events", events);
            item.add("metrics", metrics);
            arr.push(item);
        }
        root.add("agents", Json::Array(arr));
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modules() {
        assert_eq!(module_from_location(b"[001] (a) any->syscheck"), b"syscheck");
        assert_eq!(module_from_location(b"/var/log/syslog"), b"/var/log/syslog");
        assert_eq!(module_from_message(b"1:[001] (a) any->sca:log"), Some(&b"sca"[..]));
        assert_eq!(module_from_message(b"1:rootcheck:log"), Some(&b"rootcheck"[..]));
        assert_eq!(module_from_message(b"1:[001] (a) x:log"), None);
        assert_eq!(Component::from_module(b"command_x"), Component::Command);
        assert_eq!(Component::from_module(b"/var/log/syslog"), Component::Others);
    }

    #[test]
    fn per_agent_counters() {
        let mut s = State::new(100);
        s.decoded(Component::Syscheck, Some(b"001"), 200);
        s.decoded(Component::Syscheck, Some(b"000"), 200);
        s.decoded(Component::Syslog, Some(b"001"), 200);
        assert_eq!(s.g.decoded.modules.syscheck, 2);
        assert_eq!(s.agents["001"].decoded.modules.syscheck, 1);
        assert_eq!(s.agents["001"].decoded.syslog, 0);
        assert_eq!(s.agents["001"].uptime, 200);
        s.clean_agents(&[2]);
        assert!(s.agents.is_empty());
    }

    #[test]
    fn usage_is_a_float() {
        let q = QueueStat::new(16384, 1);
        assert_eq!(q.usage, 1f32 / 16383f32);
    }
}
