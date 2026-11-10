//! The limits of the three public routes, by source address. Each map is small (the addresses
//! active in the last minute) and locked only on those rare routes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

/// At most `limit` per `window_ms` per address.
pub struct PerAddr {
    limit: u32,
    window_ms: u64,
    seen: Mutex<HashMap<IpAddr, (u64, u32)>>,
}

impl PerAddr {
    pub fn new(limit: u32, window_ms: u64) -> Self {
        Self { limit, window_ms, seen: Mutex::default() }
    }

    pub fn allow(&self, addr: IpAddr, now_ms: u64) -> bool {
        let window = now_ms / self.window_ms;
        let mut m = self.seen.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, (w, _)| *w == window);
        }
        let e = m.entry(addr).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        e.1 += 1;
        e.1 <= self.limit
    }
}

/// At most `limit` per second in total.
pub struct PerSecond {
    limit: u64,
    /// second << 32 | count
    now: AtomicU64,
}

impl PerSecond {
    pub fn new(limit: u32) -> Self {
        Self { limit: limit as u64, now: AtomicU64::new(0) }
    }

    pub fn allow(&self, now_ms: u64) -> bool {
        let second = (now_ms / 1000) & 0xFFFF_FFFF;
        let v = self.now.fetch_add(1, Relaxed);
        if v >> 32 != second {
            self.now.store(second << 32 | 1, Relaxed);
            return true;
        }
        (v & 0xFFFF_FFFF) < self.limit
    }
}

/// At most `limit` at a time per address: the slot is held until dropped.
pub struct Slots {
    limit: u32,
    held: Mutex<HashMap<IpAddr, u32>>,
}

pub struct Slot(Arc<Slots>, IpAddr);

impl Slots {
    pub fn new(limit: u32) -> Arc<Self> {
        Arc::new(Self { limit, held: Mutex::default() })
    }

    pub fn take(self: &Arc<Self>, addr: IpAddr) -> Option<Slot> {
        let mut m = self.held.lock().unwrap();
        let n = m.entry(addr).or_default();
        if *n >= self.limit {
            return None;
        }
        *n += 1;
        Some(Slot(self.clone(), addr))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut m = self.0.held.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

pub struct Limits {
    pub enroll_addr: PerAddr,
    pub enroll_total: PerSecond,
    pub state_addr: PerAddr,
    pub downloads: Arc<Slots>,
}

impl Limits {
    pub fn new(enroll_per_minute: u32, enroll_per_second: u32) -> Self {
        Self { enroll_addr: PerAddr::new(enroll_per_minute, 60_000), enroll_total: PerSecond::new(enroll_per_second), state_addr: PerAddr::new(60, 60_000), downloads: Slots::new(2) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

    #[test]
    fn per_address_window() {
        let l = PerAddr::new(2, 60_000);
        assert!(l.allow(A, 1) && l.allow(A, 2));
        assert!(!l.allow(A, 3));
        assert!(l.allow(B, 3), "another address");
        assert!(l.allow(A, 60_000), "the next minute");
    }

    #[test]
    fn per_second_total() {
        let l = PerSecond::new(2);
        assert!(l.allow(5_000) && l.allow(5_100));
        assert!(!l.allow(5_200));
        assert!(l.allow(6_000));
    }

    #[test]
    fn slots_held_until_dropped() {
        let s = Slots::new(2);
        let (a, _b) = (s.take(A).unwrap(), s.take(A).unwrap());
        assert!(s.take(A).is_none());
        assert!(s.take(B).is_some());
        drop(a);
        assert!(s.take(A).is_some());
    }
}
