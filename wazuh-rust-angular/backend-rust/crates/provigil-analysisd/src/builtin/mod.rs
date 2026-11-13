//! The built-in decoders (spec sections 2.23 to 2.28): not in the decoder files; their
//! entries are added to the decoder set at start and again on a ruleset reload.

pub mod assessment;
pub mod integrity;
pub mod inventory;
pub mod small;
pub mod windows;

use std::sync::mpsc::{channel, Receiver, Sender};

use crate::decoders::{Decoder, DecoderSet};
use crate::event::*;
use crate::host::Host;
use crate::queues::Kind;

/// The built-in decoders' entries in a decoder set.
#[derive(Debug, Clone, Copy, Default)]
pub struct Builtin {
    pub rootcheck: DecoderId,
    pub hostinfo: DecoderId,
    pub hostinfo_new: u16,
    pub hostinfo_changed: u16,
    pub ciscat: DecoderId,
    pub windows: DecoderId,
    pub assessment: DecoderId,
    pub inventory: DecoderId,
    /// The integrity decoder (its name and id change with each event).
    pub integrity: DecoderId,
    pub integrity_ids: integrity::Ids,
}

/// An entry with dynamic field names at some `order` positions (None: no names).
fn entry(set: &DecoderSet, name: &str, order: usize, fields: Option<&[(usize, &str)]>) -> Decoder {
    let field_names = fields.map(|f| {
        let mut v = vec![None; order];
        for &(i, n) in f {
            if i < order {
                v[i] = Some(n.to_string());
            }
        }
        v
    });
    Decoder { id: set.id_of(name), kind: OSSEC_RL, name: Some(name.to_string()), field_names, ..Decoder::default() }
}

impl Builtin {
    /// Adds the entries to `set` (after its files are loaded).
    pub fn add(set: &mut DecoderSet, order: usize) -> Builtin {
        let push = |set: &mut DecoderSet, d: Decoder| {
            set.decoders.push(d);
            set.decoders.len() - 1
        };
        let d = entry(set, small::ROOTCHECK_NAME, order, Some(&[(0, "title"), (1, "file")]));
        let rootcheck = push(set, d);
        let d = entry(set, small::HOSTINFO_CHANGED, order, None);
        let hostinfo = push(set, d);
        let d = entry(set, small::CISCAT_NAME, order, None);
        let ciscat = push(set, d);
        let d = entry(set, windows::NAME, order, None);
        let windows = push(set, d);
        let d = entry(set, assessment::NAME, order, None);
        let assessment = push(set, d);
        let d = entry(set, inventory::NAME, order, None);
        let inventory = push(set, d);
        let names: Vec<(usize, &str)> = integrity::FIELD_NAMES.iter().copied().enumerate().collect();
        let d = entry(set, integrity::CHANGED, order, Some(&names));
        let integrity = push(set, d);
        Builtin {
            rootcheck,
            hostinfo,
            hostinfo_new: set.id_of(small::HOSTINFO_NEW),
            hostinfo_changed: set.id_of(small::HOSTINFO_CHANGED),
            ciscat,
            windows,
            assessment,
            inventory,
            integrity,
            integrity_ids: integrity::Ids::of(set),
        }
    }
}

/// What the database decoders need from the ruleset and settings.
#[derive(Debug, Clone, Copy)]
pub struct DbSettings {
    pub builtin: Builtin,
    pub order: usize,
    pub integrity: integrity::Options,
}

/// The state of the decoders that wait on provigil-db.
#[derive(Default)]
pub struct DbDecoders {
    integrity: integrity::Integrity,
    assessment: assessment::Assessment,
    inventory: inventory::Inventory,
}

impl DbDecoders {
    /// One message of a queue that waits: true when it goes on to the rules. `fim` is the
    /// integrity decoder's entry, which this renames per event.
    pub fn decode(&mut self, host: &mut dyn Host, kind: Kind, s: &DbSettings, fim: &mut Decoder, ev: &mut Event) -> bool {
        let b = &s.builtin;
        match kind {
            Kind::Dbsync | Kind::Upgrade => {
                let agent = ev.agent_id.clone().unwrap_or_default();
                let agent = text_at(&agent, 0).to_vec();
                let log = ev.log().to_vec();
                if kind == Kind::Dbsync {
                    small::sync(host, &agent, &log);
                } else {
                    small::upgrade(host, &agent, &log);
                }
                false
            }
            Kind::Syscheck => self.integrity.decode(host, fim, b.integrity, &b.integrity_ids, &s.integrity, ev),
            Kind::Syscollector => self.inventory.decode(host, b.inventory, s.order, ev),
            Kind::Sca => {
                let keep = self.assessment.decode(host, b.assessment, s.order, ev);
                self.assessment.send_requests(host);
                keep
            }
            Kind::Rootcheck => small::rootcheck(host, b.rootcheck, ev),
            _ => small::ciscat(host, b.ciscat, ev),
        }
    }
}

/// Messages at the workers at one time; the rest waits in its input queue.
pub const IN_FLIGHT: usize = 256;

struct Job {
    kind: Kind,
    settings: DbSettings,
    ev: Box<Event>,
}

/// A decoded event, for the rules when `keep`.
pub struct Decoded {
    pub ev: Box<Event>,
    pub keep: bool,
    /// The integrity decoder's id and name for this event.
    pub integrity: Option<(u16, Option<String>)>,
}

/// Worker threads (each with its own host and provigil-db connection). An agent always
/// goes to the same worker, so its messages stay in order.
pub struct Workers {
    jobs: Vec<Sender<Job>>,
    pub done: Receiver<Decoded>,
    pub in_flight: usize,
}

impl Workers {
    pub fn start<H: Host + Send + 'static>(hosts: Vec<H>) -> Workers {
        let (done_tx, done) = channel();
        let jobs = hosts
            .into_iter()
            .enumerate()
            .map(|(i, mut host)| {
                let (tx, rx) = channel::<Job>();
                let done_tx = done_tx.clone();
                std::thread::Builder::new()
                    .name(format!("decode-db-{i}"))
                    .spawn(move || {
                        let mut state = DbDecoders::default();
                        while let Ok(mut j) = rx.recv() {
                            let mut fim = Decoder::default();
                            let keep = state.decode(&mut host, j.kind, &j.settings, &mut fim, &mut j.ev);
                            let integrity = (j.kind == Kind::Syscheck).then_some((fim.id, fim.name));
                            if done_tx.send(Decoded { ev: j.ev, keep, integrity }).is_err() {
                                return;
                            }
                        }
                    })
                    .expect("a decoder thread");
                tx
            })
            .collect();
        Workers { jobs, done, in_flight: 0 }
    }

    pub fn send(&mut self, kind: Kind, settings: DbSettings, ev: Event) {
        let h = ev.agent_id.iter().flatten().fold(0usize, |h, &b| h.wrapping_mul(31).wrapping_add(usize::from(b)));
        let i = h % self.jobs.len();
        self.in_flight += 1;
        let _ = self.jobs[i].send(Job { kind, settings, ev: Box::new(ev) });
    }
}
