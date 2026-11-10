//! The lists siem-api checks: malicious IPs, file hashes and domains, shared between threads.

use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::matcher::{ip_key, mask, normalize_domain, normalize_hash, parse_ip, parse_range, url_host, List};

pub const IP_LIST: &str = "malicious_ips";
pub const HASH_LIST: &str = "malicious_hashes";
pub const DOMAIN_LIST: &str = "malicious_domains";

/// Size of one list, as returned by [`ThreatIntelManager::get_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListInfo {
    pub name: String,
    entries: usize,
}

impl ListInfo {
    pub fn total_entries(&self) -> usize {
        self.entries
    }
}

/// All lists, shared between threads behind an `Arc`.
#[derive(Default)]
pub struct ThreatIntelManager {
    lists: RwLock<HashMap<String, List>>,
}

impl ThreatIntelManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `value` to `list` (or replaces its description). Returns false when the
    /// value is not valid for that list.
    pub fn insert_entry(&self, list: &str, value: &str, description: &str) -> bool {
        let desc = description.to_string();
        if list == IP_LIST {
            if let Some((net, width, prefix)) = parse_range(value) {
                let mut lists = self.write();
                let l = lists.entry(list.to_string()).or_default();
                if prefix == width {
                    l.exact.insert(ip_key(net, width), desc);
                } else {
                    l.ranges.insert((net, width, prefix), desc);
                }
                return true;
            }
            return false;
        }
        let key = match list {
            HASH_LIST => normalize_hash(value),
            DOMAIN_LIST => normalize_domain(value),
            // lists without a known kind take any non-empty value as written
            _ => Some(value.trim().to_string()).filter(|v| !v.is_empty()),
        };
        match key {
            Some(key) => {
                self.write().entry(list.to_string()).or_default().exact.insert(key, desc);
                true
            }
            None => false,
        }
    }

    /// Adds one `value[:description]` per line; blank and `#` lines are skipped.
    /// Returns (added, refused).
    pub fn load_from_text(&self, list: &str, text: &str) -> (usize, usize) {
        let (mut added, mut refused) = (0, 0);
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (value, desc) = split_line(list, line);
            let desc = desc.map(str::trim).filter(|d| !d.is_empty()).unwrap_or("imported");
            if self.insert_entry(list, value, desc) {
                added += 1;
            } else {
                refused += 1;
            }
        }
        (added, refused)
    }

    /// Every entry as (value, description), ranges as `network/prefix`, sorted by value.
    pub fn entries(&self, list: &str) -> Vec<(String, String)> {
        let lists = self.read();
        let Some(l) = lists.get(list) else { return Vec::new() };
        let mut out: Vec<(String, String)> = l
            .exact
            .iter()
            .map(|(v, d)| (v.clone(), d.clone()))
            .chain(l.ranges.iter().map(|((net, w, p), d)| (format!("{}/{p}", ip_key(*net, *w)), d.clone())))
            .collect();
        out.sort();
        out
    }

    pub fn get_list(&self, name: &str) -> Option<ListInfo> {
        self.read().get(name).map(|l| ListInfo {
            name: name.to_string(),
            entries: l.exact.len() + l.ranges.len(),
        })
    }

    pub fn check_ip(&self, value: &str) -> Option<(String, String)> {
        let (ip, width) = parse_ip(value)?;
        let lists = self.read();
        let l = lists.get(IP_LIST)?;
        let desc = l.exact.get(&ip_key(ip, width)).or_else(|| {
            l.ranges
                .iter()
                .find(|((net, w, prefix), _)| *w == width && ip & mask(width, *prefix) == *net)
                .map(|(_, d)| d)
        })?;
        Some((IP_LIST.to_string(), desc.clone()))
    }

    pub fn check_hash(&self, value: &str) -> Option<(String, String)> {
        let key = normalize_hash(value)?;
        let desc = self.read().get(HASH_LIST)?.exact.get(&key)?.clone();
        Some((HASH_LIST.to_string(), desc))
    }

    /// Matches the domain itself or any listed parent domain; a URL is checked by its host.
    pub fn check_domain(&self, value: &str) -> Option<(String, String)> {
        let host = match value.trim().split_once("://") {
            Some((_, rest)) => url_host(rest),
            None => value,
        };
        let key = normalize_domain(host)?;
        let lists = self.read();
        let l = lists.get(DOMAIN_LIST)?;
        let mut candidate = key.as_str();
        loop {
            if let Some(desc) = l.exact.get(candidate) {
                return Some((DOMAIN_LIST.to_string(), desc.clone()));
            }
            candidate = candidate.split_once('.')?.1;
        }
    }

    // A panic in another thread must not take the lists down with it.
    fn read(&self) -> RwLockReadGuard<'_, HashMap<String, List>> {
        self.lists.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<String, List>> {
        self.lists.write().unwrap_or_else(|e| e.into_inner())
    }
}

/// Splits a text line into value and optional description. IPv6 values contain ':',
/// so in the IP list a line that is a valid IP or range as a whole is all value, and
/// otherwise it splits after the longest valid IP or range before a ':' (the leftmost
/// one would cut `::ffff:192.0.2.9:x` at `::ffff`).
fn split_line<'a>(list: &str, line: &'a str) -> (&'a str, Option<&'a str>) {
    if list != IP_LIST {
        return match line.split_once(':') {
            Some((v, d)) => (v, Some(d)),
            None => (line, None),
        };
    }
    if parse_range(line).is_some() {
        return (line, None);
    }
    line.rmatch_indices(':')
        .map(|(i, _)| (&line[..i], &line[i + 1..]))
        .find(|(v, _)| parse_range(v).is_some())
        .map_or((line, None), |(v, d)| (v, Some(d)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn desc(r: Option<(String, String)>) -> Option<String> {
        r.map(|(_, d)| d)
    }

    #[test]
    fn same_value_counts_once_and_keeps_newer_description() {
        let m = ThreatIntelManager::new();
        assert!(m.get_list(IP_LIST).is_none());
        assert!(m.insert_entry(IP_LIST, "203.0.113.5", "old"));
        assert!(m.insert_entry(IP_LIST, " 203.0.113.5 ", "new"));
        assert!(m.insert_entry(IP_LIST, "::ffff:203.0.113.5", "newest"));
        assert_eq!(m.get_list(IP_LIST).unwrap().total_entries(), 1);
        assert_eq!(desc(m.check_ip("203.0.113.5")).as_deref(), Some("newest"));

        assert!(m.insert_entry(HASH_LIST, &"AB".repeat(16), "a"));
        assert!(m.insert_entry(HASH_LIST, &"ab".repeat(16), "b"));
        assert_eq!(m.get_list(HASH_LIST).unwrap().total_entries(), 1);

        assert!(m.insert_entry(DOMAIN_LIST, "Evil.Example.", "a"));
        assert!(m.insert_entry(DOMAIN_LIST, "evil.example", "b"));
        assert_eq!(m.get_list(DOMAIN_LIST).unwrap().total_entries(), 1);
        assert_eq!(desc(m.check_domain("evil.example")).as_deref(), Some("b"));

        assert!(m.insert_entry("custom", "anything", "x"));
        assert_eq!(m.get_list("custom").unwrap().total_entries(), 1);
    }

    #[test]
    fn invalid_values_are_refused_per_list() {
        let m = ThreatIntelManager::new();
        for bad in ["", "not-an-ip", "300.1.1.1", "10.0.0.0/33", "10.0.0.0/", "10.0.0.0/x", "10.0.0.0/255", "::1/129", "evil.example"] {
            assert!(!m.insert_entry(IP_LIST, bad, "x"), "ip {bad:?}");
        }
        for bad in ["", "abc", &"g".repeat(32), &"a".repeat(33), &"a".repeat(63), "evil.example"] {
            assert!(!m.insert_entry(HASH_LIST, bad, "x"), "hash {bad:?}");
        }
        for bad in ["", "localhost", "203.0.113.5", "http://evil.example/x", "-evil.example", "evil..example", "ev il.example"] {
            assert!(!m.insert_entry(DOMAIN_LIST, bad, "x"), "domain {bad:?}");
        }
        assert!(!m.insert_entry("custom", "   ", "x"));
        assert!(m.get_list(IP_LIST).is_none());
        assert!(m.get_list(HASH_LIST).is_none());
        assert!(m.get_list(DOMAIN_LIST).is_none());

        assert!(m.insert_entry(IP_LIST, "2001:db8::1", "x"));
        assert!(m.insert_entry(IP_LIST, "2001:db8:1::/48", "x"));
        assert!(m.insert_entry(HASH_LIST, &"a".repeat(40), "x"));
        assert!(m.insert_entry(HASH_LIST, &"a".repeat(64), "x"));
    }

    #[test]
    fn ranges_and_ipv4_in_ipv6() {
        let m = ThreatIntelManager::new();
        m.insert_entry(IP_LIST, "203.0.113.0/24", "range");
        m.insert_entry(IP_LIST, "2001:db8:1::/48", "v6 range");
        m.insert_entry(IP_LIST, "::ffff:198.51.100.0/120", "mapped range");
        assert_eq!(desc(m.check_ip("203.0.113.200")).as_deref(), Some("range"));
        assert_eq!(desc(m.check_ip("::ffff:203.0.113.5")).as_deref(), Some("range"));
        assert_eq!(desc(m.check_ip("2001:db8:1:ffff::1")).as_deref(), Some("v6 range"));
        assert_eq!(desc(m.check_ip("198.51.100.7")).as_deref(), Some("mapped range"));
        assert!(m.check_ip("203.0.114.1").is_none());
        assert!(m.check_ip("2001:db8:2::1").is_none());
        assert!(m.check_ip("garbage").is_none());

        m.insert_entry(IP_LIST, "0.0.0.0/0", "everything v4");
        assert_eq!(desc(m.check_ip("8.8.8.8")).as_deref(), Some("everything v4"));
        assert!(m.check_ip("2001:db8:2::1").is_none());
    }

    #[test]
    fn hash_case_insensitive() {
        let m = ThreatIntelManager::new();
        let h = "d41d8cd98f00b204e9800998ecf8427e";
        m.insert_entry(HASH_LIST, h, "empty file");
        let (list, d) = m.check_hash(&format!("  {}  ", h.to_uppercase())).unwrap();
        assert_eq!((list.as_str(), d.as_str()), (HASH_LIST, "empty file"));
        assert!(m.check_hash(&"0".repeat(32)).is_none());
    }

    #[test]
    fn domain_matching() {
        let m = ThreatIntelManager::new();
        m.insert_entry(DOMAIN_LIST, "evil.example", "c2");
        for hit in ["EVIL.example", " evil.example. ", "cdn.evil.example", "a.b.Evil.Example.", "http://evil.example/path", "https://user@cdn.evil.example:8443/x?y=1", "hxxp://evil.example"] {
            assert_eq!(desc(m.check_domain(hit)).as_deref(), Some("c2"), "{hit:?}");
        }
        for miss in ["notevil.example", "evil.example.org", "example", "http://notevil.example/evil.example", ""] {
            assert!(m.check_domain(miss).is_none(), "{miss:?}");
        }
    }

    #[test]
    fn exact_ip_wins_over_range() {
        let m = ThreatIntelManager::new();
        m.insert_entry(IP_LIST, "203.0.113.0/24", "range");
        m.insert_entry(IP_LIST, "203.0.113.5", "exact");
        m.insert_entry(IP_LIST, "203.0.113.6/32", "exact /32");
        assert_eq!(desc(m.check_ip("203.0.113.5")).as_deref(), Some("exact"));
        assert_eq!(desc(m.check_ip("203.0.113.6")).as_deref(), Some("exact /32"));
        assert_eq!(desc(m.check_ip("203.0.113.7")).as_deref(), Some("range"));
        assert_eq!(m.get_list(IP_LIST).unwrap().total_entries(), 3);
    }

    #[test]
    fn load_from_text_lines() {
        let m = ThreatIntelManager::new();
        let text = "# Feodo export\n\n  \n203.0.113.5:Emotet C2\n198.51.100.0/24\n  # indented comment\n\
                    2001:db8::1\n2001:db8::2:Dridex: tier 2\n2001:db8:1::/48:v6 range\n::ffff:192.0.2.9:mapped\n\
                    not-an-ip:bad\n300.1.1.1\n10.0.0.0/33:bad prefix\n";
        assert_eq!(m.load_from_text(IP_LIST, text), (6, 3));
        assert_eq!(desc(m.check_ip("203.0.113.5")).as_deref(), Some("Emotet C2"));
        assert_eq!(desc(m.check_ip("198.51.100.9")).as_deref(), Some("imported"));
        assert_eq!(desc(m.check_ip("2001:db8::1")).as_deref(), Some("imported"));
        assert_eq!(desc(m.check_ip("2001:db8::2")).as_deref(), Some("Dridex: tier 2"));
        assert_eq!(desc(m.check_ip("2001:db8:1::5")).as_deref(), Some("v6 range"));
        assert_eq!(desc(m.check_ip("192.0.2.9")).as_deref(), Some("mapped"));

        let hashes = format!("{}:Mimikatz\n{}\nxyz:bad\n", "A".repeat(32), "b".repeat(64));
        assert_eq!(m.load_from_text(HASH_LIST, &hashes), (2, 1));
        assert_eq!(desc(m.check_hash(&"b".repeat(64))).as_deref(), Some("imported"));

        assert_eq!(m.load_from_text(DOMAIN_LIST, "Evil.Example:phishing\nc2.example\nlocalhost\n#x.example\n"), (2, 1));
        assert_eq!(desc(m.check_domain("cdn.evil.example")).as_deref(), Some("phishing"));
        assert_eq!(m.load_from_text(DOMAIN_LIST, "# only comments\n\n"), (0, 0));
    }

    #[test]
    fn entries_lists_values_and_ranges() {
        let m = ThreatIntelManager::new();
        assert!(m.entries(IP_LIST).is_empty());
        m.insert_entry(IP_LIST, "203.0.113.5", "exact");
        m.insert_entry(IP_LIST, "198.51.100.77/24", "range");
        m.insert_entry(IP_LIST, "2001:DB8:1::/48", "v6");
        m.insert_entry(IP_LIST, "::ffff:192.0.2.0/120", "mapped");
        let want = [
            ("192.0.2.0/24", "mapped"),
            ("198.51.100.0/24", "range"),
            ("2001:db8:1::/48", "v6"),
            ("203.0.113.5", "exact"),
        ];
        let got = m.entries(IP_LIST);
        assert_eq!(got.iter().map(|(v, d)| (v.as_str(), d.as_str())).collect::<Vec<_>>(), want);

        m.insert_entry(DOMAIN_LIST, "Evil.Example.", "c2");
        assert_eq!(m.entries(DOMAIN_LIST), vec![("evil.example".to_string(), "c2".to_string())]);
        assert!(m.entries("no_such_list").is_empty());
    }

    #[test]
    fn concurrent_reads_and_writes() {
        let m = Arc::new(ThreatIntelManager::new());
        let handles: Vec<_> = (0..8u32)
            .map(|t| {
                let m = Arc::clone(&m);
                std::thread::spawn(move || {
                    for i in 0..500u32 {
                        let ip = format!("10.{t}.{}.{}", i / 256, i % 256);
                        assert!(m.insert_entry(IP_LIST, &ip, "feed"));
                        assert!(m.check_ip(&ip).is_some());
                        m.check_domain("cdn.evil.example");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.get_list(IP_LIST).unwrap().total_entries(), 8 * 500);
    }
}
