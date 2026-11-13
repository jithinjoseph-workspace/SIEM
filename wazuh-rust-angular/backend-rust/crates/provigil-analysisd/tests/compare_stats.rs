//! Statistics, old against new: random counter sequences give the same state file and
//! `getstats` / `getagentsstats` JSON.

use provigil_analysisd::stats as ns;
use siem_analysisd::state as os;

const OLD: [os::Component; 28] = {
    use os::Component::*;
    [Agent, Agentless, Dbsync, Monitor, Remote, Syslog, Virustotal, Aws, Azure, Ciscat, Command, Docker, Gcp, Github, Office365, MsGraph, Oscap, Osquery, Rootcheck, Sca, Syscheck, Syscollector, Upgrade, Vulnerability, Eventchannel, Eventlog, Macos, Others]
};
const NEW: [ns::Component; 28] = {
    use ns::Component::*;
    [Agent, Agentless, Dbsync, Monitor, Remote, Syslog, Virustotal, Aws, Azure, Ciscat, Command, Docker, Gcp, Github, Office365, MsGraph, Oscap, Osquery, Rootcheck, Sca, Syscheck, Syscollector, Upgrade, Vulnerability, Eventchannel, Eventlog, Macos, Others]
};

#[test]
fn counters() {
    let mut r: u64 = 0x9E3779B97F4A7C15;
    let mut next = |n: u64| {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r % n
    };
    for _ in 0..200 {
        let (mut o, mut n) = (os::State::new(100), ns::Stats::new(100));
        for _ in 0..next(400) {
            let agent: Option<&[u8]> = [Some(&b"001"[..]), Some(b"002"), Some(b"000"), None, Some(b"010\0x")][next(5) as usize];
            let now = 100 + next(50) as i64;
            match next(9) {
                0 => {
                    let b = next(1000) as usize;
                    o.received(b);
                    n.received(b);
                }
                1 => {
                    let c = next(28) as usize;
                    o.decoded(OLD[c], agent, now);
                    n.decoded(NEW[c], agent, now);
                }
                2 => {
                    let c = next(28) as usize;
                    o.dropped(OLD[c]);
                    n.dropped(NEW[c]);
                }
                3 => {
                    o.processed(agent, now);
                    n.processed(agent, now);
                }
                4 => {
                    o.alert_written(agent, now);
                    n.alert_written(agent, now);
                }
                5 => {
                    o.archive_written(agent, now);
                    n.archive_written(agent, now);
                }
                6 => {
                    o.firewall_written(agent, now);
                    n.firewall_written(agent, now);
                }
                7 => {
                    o.fts_written();
                    n.fts_written();
                    o.stats_written();
                    n.stats_written();
                }
                _ => {
                    if next(20) == 0 {
                        o.clean_agents(&[1]);
                        n.keep_agents(&[1]);
                    }
                }
            }
        }
        let sizes: Vec<(usize, usize)> = (0..15).map(|_| (128 + next(3000) as usize, next(128) as usize)).collect();
        let oq = |i: usize| os::QueueStat::new(sizes[i].0, sizes[i].1);
        let nq = |i: usize| ns::QueueUse::new(sizes[i].0, sizes[i].1);
        let oqs = os::QueueStatus { syscheck: oq(0), syscollector: oq(1), rootcheck: oq(2), sca: oq(3), hostinfo: oq(4), winevt: oq(5), dbsync: oq(6), upgrade: oq(7), events: oq(8), processed: oq(9), alerts: oq(10), archives: oq(11), firewall: oq(12), fts: oq(13), stats: oq(14) };
        let nqs = ns::Queues { syscheck: nq(0), syscollector: nq(1), rootcheck: nq(2), sca: nq(3), hostinfo: nq(4), winevt: nq(5), dbsync: nq(6), upgrade: nq(7), events: nq(8), processed: nq(9), alerts: nq(10), archives: nq(11), firewall: nq(12), fts: nq(13), stats: nq(14) };
        assert_eq!(o.file_text(&oqs), n.file_text(&nqs));
        let eps = if next(2) == 0 { Some(next(100) as u32) } else { None };
        assert_eq!(o.state_json(500, &oqs, eps.map(|c| os::EpsReport { available_credits: c })).print_unformatted(), n.json(500, &nqs, eps).print_unformatted());
        assert_eq!(o.agents_json(500, &[1, 2, 10, 3]).print_unformatted(), n.agents_json(500, &[1, 2, 10, 3]).print_unformatted());
    }
    for m in ["[001] (a) any->syscheck", "x", "a->b->c", ""] {
        assert_eq!(os::module_from_location(m.as_bytes()), ns::module_of_location(m.as_bytes()));
    }
    for m in ["1:[001] (a) any->sca:log", "1:rootcheck:log", "1:[001] (a) x:log", "", "1:x"] {
        assert_eq!(os::module_from_message(m.as_bytes()), ns::module_of_message(m.as_bytes()));
    }
    for m in ["wazuh-agent", "command_x", "Wazuh-AWS", "WinEvtLog", "zzz", "provigil-remoted"] {
        assert_eq!(OLD.iter().position(|c| *c == os::Component::from_module(m.as_bytes())), NEW.iter().position(|c| *c == ns::Component::of_module(m.as_bytes())));
    }
}
