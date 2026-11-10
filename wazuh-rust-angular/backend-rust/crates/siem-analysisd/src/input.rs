//! analysisd's decoder input queues (`decode_queue_*_input`,
//! `dispatch_dbsync_input`, `upgrade_module_input`): bounded FIFOs filled by
//! `ad_input_main` and drained by the decoder threads. Here one arrival
//! ordered FIFO with per-queue occupancy, so `queue_full_ex` /
//! `queue_get_percentage_ex` behave like the C queues of `queue_init(size)`
//! (which hold `size - 1` elements).

use std::collections::VecDeque;

use siem_ipc::mq::queues::*;

use crate::daemon_config::QueueSizes;
use crate::state::{Component, QueueStat};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Syscheck,
    Rootcheck,
    Sca,
    Syscollector,
    Hostinfo,
    Winevt,
    Dbsync,
    Upgrade,
    /// `decode_queue_event_input` (everything else, CIS-CAT included)
    Event,
}

const KINDS: usize = 9;

impl Kind {
    /// The `ad_input_main` dispatch on the queue character.
    pub fn of(c: u8) -> Kind {
        match c {
            SYSCHECK_MQ => Kind::Syscheck,
            ROOTCHECK_MQ => Kind::Rootcheck,
            SCA_MQ => Kind::Sca,
            SYSCOLLECTOR_MQ => Kind::Syscollector,
            HOSTINFO_MQ => Kind::Hostinfo,
            WIN_EVT_MQ => Kind::Winevt,
            DBSYNC_MQ => Kind::Dbsync,
            UPGRADE_MQ => Kind::Upgrade,
            _ => Kind::Event,
        }
    }

    fn idx(self) -> usize {
        self as usize
    }

    /// Whether decoding a message of queue character `c` waits on provigil-db or a local
    /// socket: such a message belongs on a worker thread (internal/db_worker.rs).
    pub fn waits(c: u8) -> bool {
        c == CISCAT_MQ || matches!(Kind::of(c), Kind::Syscheck | Kind::Rootcheck | Kind::Sca | Kind::Syscollector | Kind::Dbsync | Kind::Upgrade)
    }

    /// The warning logged (once) when the queue is full.
    pub fn full_warning(self) -> &'static str {
        match self {
            Kind::Syscheck => "Syscheck decoder queue is full.",
            Kind::Rootcheck => "Rootcheck decoder queue is full.",
            Kind::Sca => "Security Configuration Assessment decoder queue is full.",
            Kind::Syscollector => "Syscollector decoder queue is full.",
            Kind::Hostinfo => "Hostinfo decoder queue is full.",
            Kind::Winevt => "Windows eventchannel decoder queue is full.",
            Kind::Dbsync => "Database synchronization decoder queue is full.",
            Kind::Upgrade => "Upgrade module decoder queue is full.",
            Kind::Event => "Input queue is full.",
        }
    }

    /// The dropped-events counter of a fixed queue (`Event` depends on
    /// the message, see `Analysis::receive`).
    pub fn dropped_component(self) -> Option<Component> {
        match self {
            Kind::Syscheck => Some(Component::Syscheck),
            Kind::Rootcheck => Some(Component::Rootcheck),
            Kind::Sca => Some(Component::Sca),
            Kind::Syscollector => Some(Component::Syscollector),
            Kind::Hostinfo => Some(Component::Others),
            Kind::Winevt => Some(Component::Eventchannel),
            Kind::Dbsync => Some(Component::Dbsync),
            Kind::Upgrade => Some(Component::Upgrade),
            Kind::Event => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct InQueues {
    fifo: VecDeque<(Kind, Vec<u8>)>,
    /// What `Kind::waits` when workers take it (`split`), so it never holds up the rest.
    slow: VecDeque<(Kind, Vec<u8>)>,
    pub split: bool,
    count: [usize; KINDS],
    size: [usize; KINDS],
    /// `reported_<queue>`: the full warning was logged.
    pub reported: [bool; KINDS],
}

impl InQueues {
    pub fn new(q: &QueueSizes) -> Self {
        let mut size = [0; KINDS];
        size[Kind::Syscheck.idx()] = q.syscheck;
        size[Kind::Rootcheck.idx()] = q.rootcheck;
        size[Kind::Sca.idx()] = q.sca;
        size[Kind::Syscollector.idx()] = q.syscollector;
        size[Kind::Hostinfo.idx()] = q.hostinfo;
        size[Kind::Winevt.idx()] = q.winevt;
        size[Kind::Dbsync.idx()] = q.dbsync;
        size[Kind::Upgrade.idx()] = q.upgrade;
        size[Kind::Event.idx()] = q.event;
        InQueues { size, ..Default::default() }
    }

    /// `queue_full_ex`
    pub fn full(&self, k: Kind) -> bool {
        self.count[k.idx()] + 1 >= self.size[k.idx()]
    }

    /// `queue_push_ex` (false when full).
    pub fn push(&mut self, k: Kind, msg: Vec<u8>) -> bool {
        if self.full(k) {
            return false;
        }
        self.count[k.idx()] += 1;
        let q = if self.split && Kind::waits(msg[0]) { &mut self.slow } else { &mut self.fifo };
        q.push_back((k, msg));
        true
    }

    pub fn front(&self) -> Option<&(Kind, Vec<u8>)> {
        self.fifo.front()
    }

    pub fn pop(&mut self) -> Option<(Kind, Vec<u8>)> {
        let (k, m) = self.fifo.pop_front()?;
        self.count[k.idx()] -= 1;
        Some((k, m))
    }

    /// The next message for a worker thread.
    pub fn pop_slow(&mut self) -> Option<(Kind, Vec<u8>)> {
        let (k, m) = self.slow.pop_front()?;
        self.count[k.idx()] -= 1;
        Some((k, m))
    }

    pub fn is_empty(&self) -> bool {
        self.fifo.is_empty() && self.slow.is_empty()
    }

    pub fn has_fast(&self) -> bool {
        !self.fifo.is_empty()
    }

    pub fn has_slow(&self) -> bool {
        !self.slow.is_empty()
    }

    /// A queue that cannot take another message.
    pub fn any_full(&self) -> bool {
        (0..KINDS).any(|i| self.count[i] + 1 >= self.size[i])
    }

    /// How full the fullest queue is, 0 to 1.
    pub fn max_usage(&self) -> f32 {
        (0..KINDS).map(|i| self.count[i] as f32 / (self.size[i] as f32 - 1.0).max(1.0)).fold(0.0, f32::max)
    }

    pub fn stat(&self, k: Kind) -> QueueStat {
        QueueStat::new(self.size[k.idx()], self.count[k.idx()])
    }

    pub fn reported_mut(&mut self, k: Kind) -> &mut bool {
        &mut self.reported[k.idx()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_is_size_minus_one() {
        let q = QueueSizes { event: 3, syscheck: 128, ..Default::default() };
        let mut iq = InQueues::new(&q);
        assert!(iq.push(Kind::Event, b"a".to_vec()));
        assert!(iq.push(Kind::Event, b"b".to_vec()));
        assert!(!iq.push(Kind::Event, b"c".to_vec()));
        assert!(iq.push(Kind::Syscheck, b"s".to_vec()));
        assert_eq!(iq.stat(Kind::Event).usage, 1.0);
        assert_eq!(iq.pop().unwrap().1, b"a");
        assert!(iq.push(Kind::Event, b"c".to_vec()));
    }
}
