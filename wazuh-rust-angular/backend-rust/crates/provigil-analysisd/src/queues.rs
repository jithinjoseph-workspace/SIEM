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
