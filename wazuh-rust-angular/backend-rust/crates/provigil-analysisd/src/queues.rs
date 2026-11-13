//! The input queues (spec section 2.3): each message's first byte says which agent module
//! sent it, and so which decoder queue it goes to.

pub const LOCALFILE: u8 = b'1';
pub const SYSLOG: u8 = b'2';
pub const HOSTINFO: u8 = b'3';
pub const SECURE: u8 = b'4';
pub const DBSYNC: u8 = b'5';
pub const SYSCHECK: u8 = b'8';
pub const ROOTCHECK: u8 = b'9';
pub const SYSCOLLECTOR: u8 = b'd';
pub const CISCAT: u8 = b'e';
pub const WINEVT: u8 = b'f';
pub const SCA: u8 = b'p';
pub const UPGRADE: u8 = b'u';

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
    /// everything else (CIS-CAT included)
    Event,
}

pub const KINDS: usize = 9;

impl Kind {
    pub fn of(c: u8) -> Kind {
        match c {
            SYSCHECK => Kind::Syscheck,
            ROOTCHECK => Kind::Rootcheck,
            SCA => Kind::Sca,
            SYSCOLLECTOR => Kind::Syscollector,
            HOSTINFO => Kind::Hostinfo,
            WINEVT => Kind::Winevt,
            DBSYNC => Kind::Dbsync,
            UPGRADE => Kind::Upgrade,
            _ => Kind::Event,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }

    /// Messages that wait on provigil-db or a local socket while decoded: they go to the
    /// database workers.
    pub fn waits(c: u8) -> bool {
        c == CISCAT || matches!(Kind::of(c), Kind::Syscheck | Kind::Rootcheck | Kind::Sca | Kind::Syscollector | Kind::Dbsync | Kind::Upgrade)
    }

    /// The warning logged once when the queue is full.
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
}

impl Kind {
    /// The dropped-events counter of a fixed queue (the event queue's depends on the message).
    pub fn dropped_counter(self) -> Option<crate::stats::Component> {
        use crate::stats::Component as C;
        Some(match self {
            Kind::Syscheck => C::Syscheck,
            Kind::Rootcheck => C::Rootcheck,
            Kind::Sca => C::Sca,
            Kind::Syscollector => C::Syscollector,
            Kind::Hostinfo => C::Others,
            Kind::Winevt => C::Eventchannel,
            Kind::Dbsync => C::Dbsync,
            Kind::Upgrade => C::Upgrade,
            Kind::Event => return None,
        })
    }
}

/// The decoder input queues: one arrival-ordered list with a count per queue (a queue of
/// size n holds n - 1 messages); with `split`, messages that wait on provigil-db have their
/// own list so they never hold up the rest.
#[derive(Debug, Default)]
pub struct InQueues {
    fast: std::collections::VecDeque<(Kind, Vec<u8>)>,
    slow: std::collections::VecDeque<(Kind, Vec<u8>)>,
    pub split: bool,
    count: [usize; KINDS],
    size: [usize; KINDS],
    /// The full warning was logged.
    pub reported: [bool; KINDS],
}

impl InQueues {
    /// Sizes per kind (in `Kind` order).
    pub fn new(sizes: [usize; KINDS]) -> InQueues {
        InQueues { size: sizes, ..InQueues::default() }
    }

    pub fn full(&self, k: Kind) -> bool {
        self.count[k.index()] + 1 >= self.size[k.index()]
    }

    /// False when full.
    pub fn push(&mut self, k: Kind, msg: Vec<u8>) -> bool {
        if self.full(k) {
            return false;
        }
        self.count[k.index()] += 1;
        let q = if self.split && Kind::waits(msg[0]) { &mut self.slow } else { &mut self.fast };
        q.push_back((k, msg));
        true
    }

    pub fn pop(&mut self) -> Option<(Kind, Vec<u8>)> {
        let (k, m) = self.fast.pop_front()?;
        self.count[k.index()] -= 1;
        Some((k, m))
    }

    pub fn pop_slow(&mut self) -> Option<(Kind, Vec<u8>)> {
        let (k, m) = self.slow.pop_front()?;
        self.count[k.index()] -= 1;
        Some((k, m))
    }

    pub fn is_empty(&self) -> bool {
        self.fast.is_empty() && self.slow.is_empty()
    }

    pub fn has_fast(&self) -> bool {
        !self.fast.is_empty()
    }

    pub fn has_slow(&self) -> bool {
        !self.slow.is_empty()
    }

    pub fn any_full(&self) -> bool {
        (0..KINDS).any(|i| self.count[i] + 1 >= self.size[i])
    }

    /// How full the fullest queue is, 0 to 1.
    pub fn max_usage(&self) -> f32 {
        (0..KINDS).map(|i| self.count[i] as f32 / (self.size[i] as f32 - 1.0).max(1.0)).fold(0.0, f32::max)
    }

    pub fn usage(&self, k: Kind) -> crate::stats::QueueUse {
        crate::stats::QueueUse::new(self.size[k.index()], self.count[k.index()])
    }
}
