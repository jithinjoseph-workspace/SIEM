//! The internal decoders that wait on provigil-db or a local socket: inline when no worker
//! runs (tests, tools), otherwise on worker threads so the analysis thread never waits. A
//! worker takes the event after `OS_CleanMSG` and hands it back decoded; the analysis thread
//! matches the rules. An agent always has the same worker, so its messages keep their order.

use std::sync::mpsc::{channel, Receiver, Sender};

use crate::daemon::Env;
use crate::decoders::DecoderInfo;
use crate::event::Event;
use crate::input::Kind;
use crate::internal::syscheck::{Fim, FimConfig};
use crate::internal::{ciscat, dbsync, rootcheck, sca::Sca, syscollector::Syscollector, upgrade, InternalDecoders};

/// Messages at the workers at one time: the rest stays counted in its input queue.
pub const WINDOW: usize = 256;

/// What the decoders need from the ruleset and configuration.
#[derive(Debug, Clone, Copy)]
pub struct DbCfg {
    pub ids: InternalDecoders,
    pub order_size: usize,
    pub fim: FimConfig,
}

/// The decoders' own state.
#[derive(Default)]
pub struct DbDecoders {
    fim: Fim,
    sca: Sca,
    syscollector: Syscollector,
}

impl DbDecoders {
    /// One message of a queue that `Kind::waits`: true when the event goes on to the rules.
    /// `fim`: the FIM decoder's entry, which it renames for each event.
    pub fn decode(&mut self, env: &mut dyn Env, kind: Kind, cfg: &DbCfg, fim: &mut DecoderInfo, ev: &mut Event) -> bool {
        let (ids, order) = (&cfg.ids, cfg.order_size);
        match kind {
            Kind::Dbsync | Kind::Upgrade => {
                let agent = ev.agent_id.clone().unwrap_or_default();
                let agent = &agent[..agent.iter().position(|&c| c == 0).unwrap_or(agent.len())];
                let log = ev.log().to_vec();
                if kind == Kind::Dbsync {
                    dbsync::dispatch(env, agent, &log);
                } else {
                    upgrade::dispatch(env, agent, &log);
                }
                false
            }
            Kind::Syscheck => self.fim.decode(env, fim, ids.fim, &ids.fim_ids, &cfg.fim, ev),
            Kind::Syscollector => self.syscollector.decode(env, ids.syscollector, order, ev),
            Kind::Sca => {
                let keep = self.sca.decode(env, ids.sca, order, ev);
                // RequestDBThread
                self.sca.drain(env);
                keep
            }
            Kind::Rootcheck => rootcheck::decode(env, ids.rootcheck, ev),
            _ => ciscat::decode(env, ids.ciscat, ev),
        }
    }
}

struct Job {
    kind: Kind,
    cfg: DbCfg,
    ev: Box<Event>,
}

/// A decoded event: for the rules when `keep`.
pub struct Decoded {
    pub ev: Box<Event>,
    pub keep: bool,
    /// The FIM decoder's id and name for this event.
    pub fim: Option<(u16, Option<String>)>,
}

/// The worker threads, each with its own `Env` (its own provigil-db connection).
pub struct DbWorkers {
    jobs: Vec<Sender<Job>>,
    pub done: Receiver<Decoded>,
    pub in_flight: usize,
}

impl DbWorkers {
    pub fn start<E: Env + Send + 'static>(envs: Vec<E>) -> DbWorkers {
        let (done_tx, done) = channel();
        let jobs = envs
            .into_iter()
            .enumerate()
            .map(|(i, mut env)| {
                let (tx, rx) = channel::<Job>();
                let done_tx = done_tx.clone();
                std::thread::Builder::new()
                    .name(format!("decode-db-{i}"))
                    .spawn(move || {
                        let mut db = DbDecoders::default();
                        while let Ok(mut j) = rx.recv() {
                            let mut info = DecoderInfo::default();
                            let keep = db.decode(&mut env, j.kind, &j.cfg, &mut info, &mut j.ev);
                            let fim = (j.kind == Kind::Syscheck).then_some((info.id, info.name));
                            if done_tx.send(Decoded { ev: j.ev, keep, fim }).is_err() {
                                return;
                            }
                        }
                    })
                    .expect("decoder thread");
                tx
            })
            .collect();
        DbWorkers { jobs, done, in_flight: 0 }
    }

    pub fn send(&mut self, kind: Kind, cfg: DbCfg, ev: Event) {
        let hash = ev.agent_id.iter().flatten().fold(0usize, |h, &b| h.wrapping_mul(31).wrapping_add(b as usize));
        let i = hash % self.jobs.len();
        self.in_flight += 1;
        let _ = self.jobs[i].send(Job { kind, cfg, ev: Box::new(ev) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ar::{AgentVersion, ArBackend};
    use crate::labels::Label;
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<(String, String)>>>;

    /// Records which thread saw each provigil-db query.
    struct DbEnv(Seen);

    impl ArBackend for DbEnv {
        fn agent_version(&mut self, _: i32) -> AgentVersion {
            AgentVersion::NoInfo
        }
        fn active_agents(&mut self) -> Option<Vec<i32>> {
            None
        }
        fn node_name(&mut self) -> String {
            String::new()
        }
        fn send_exec(&mut self, _: &[u8]) {}
        fn send_ar(&mut self, _: &[u8]) {}
    }

    impl Env for DbEnv {
        fn labels(&mut self, _: &[u8]) -> Vec<Label> {
            Vec::new()
        }
        fn log(&self, _: &str, _: &[u8]) {}
        fn ar(&mut self) -> &mut dyn ArBackend {
            self
        }
        fn agents_of_node(&mut self, _: i32, _: i32) -> Option<Vec<i32>> {
            None
        }
        fn wdb_query_ex(&mut self, q: &[u8], _: usize) -> Result<Vec<u8>, i32> {
            let thread = std::thread::current().name().unwrap_or("").to_string();
            self.0.lock().unwrap().push((thread, String::from_utf8_lossy(q).into_owned()));
            Ok(b"ok not found".to_vec())
        }
    }

    fn sca_event(agent: &str, check: u32) -> Event {
        let mut ev = Event::new(crate::decoders::NULL_DECODER);
        let msg = format!(r#"p:[{agent}] (a) any->sca:{{"type":"check","id":1,"policy":"p","policy_id":"pid","check":{{"id":{check},"title":"t","result":"failed"}}}}"#);
        ev.clean_msg(msg.as_bytes(), b"h", Default::default()).unwrap();
        ev
    }

    #[test]
    fn workers_do_the_database_work_and_keep_each_agents_order() {
        let seen = Seen::default();
        let mut w = DbWorkers::start(vec![DbEnv(seen.clone()), DbEnv(seen.clone())]);
        let cfg = DbCfg { ids: Default::default(), order_size: 64, fim: FimConfig { alert_new: false, auto_ignore: false, ignore_time: 0, ignore_frequency: 0 } };
        for check in 0..50 {
            for agent in ["101", "102", "103"] {
                w.send(Kind::Sca, cfg, sca_event(agent, check));
            }
        }
        for _ in 0..150 {
            let d = w.done.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            assert!(d.keep);
            w.in_flight -= 1;
        }
        let seen = seen.lock().unwrap();
        assert!(seen.iter().all(|(t, _)| t.starts_with("decode-db-")), "provigil-db is never asked from this thread");
        for agent in ["101", "102", "103"] {
            let checks: Vec<u32> = seen.iter().filter_map(|(_, q)| q.strip_prefix(&format!("agent {agent} sca query "))?.parse().ok()).collect();
            assert_eq!(checks, (0..50).collect::<Vec<_>>());
        }
    }
}
