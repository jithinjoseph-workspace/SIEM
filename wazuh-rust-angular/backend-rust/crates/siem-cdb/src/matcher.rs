//! High-performance indicator parsing, normalization, and network subnet matching
//! for threat intelligence feeds (IPs, CIDR ranges, file hashes, domains).

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default)]
pub(crate) struct List {
    /// Normalized exact value -> description
    pub(crate) exact: HashMap<String, String>,
    /// (masked network bits, family width in bits, prefix length) -> description
    pub(crate) ranges: HashMap<(u128, u8, u8), String>,
}

/// Parses an IPv4 or IPv6 address into a bit representation and width (32 or 128).
/// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are normalized as IPv4.
pub(crate) fn parse_ip(value: &str) -> Option<(u128, u8)> {
    let ip: IpAddr = value.trim().parse().ok()?;
    Some(match ip {
        IpAddr::V4(v4) => (u32::from(v4) as u128, 32),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (u32::from(v4) as u128, 32),
            None => (u128::from(v6), 128),
        },
    })
}

/// Parses a standalone IP or CIDR notation (`address/prefix`) into (masked network bits, width, prefix).
pub(crate) fn parse_range(value: &str) -> Option<(u128, u8, u8)> {
    let value = value.trim();
    let (addr, prefix) = match value.split_once('/') {
        Some((a, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (a, Some(p.parse::<u8>().ok()?))
        }
        Some(_) => return None,
        None => (value, None),
    };
    let (ip, width) = parse_ip(addr)?;
    let Some(prefix) = prefix else {
        return Some((ip, width, width));
    };
    let prefix = if width == 32 && addr.contains(':') {
        // ::ffff:a.b.c.d/N covers the IPv4 range /N-96
        prefix.checked_sub(96).filter(|p| *p <= 32)?
    } else if prefix <= width {
        prefix
    } else {
        return None;
    };
    Some((ip & mask(width, prefix), width, prefix))
}

/// Computes bitmask for the given family width and prefix length.
pub(crate) fn mask(width: u8, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        (u128::MAX << (128 - prefix as u32)) >> (128 - width as u32)
    }
}

/// Formats raw address bits back into a canonical IP string.
pub(crate) fn ip_key(bits: u128, width: u8) -> String {
    if width == 32 {
        std::net::Ipv4Addr::from(bits as u32).to_string()
    } else {
        std::net::Ipv6Addr::from(bits).to_string()
    }
}

/// Normalizes cryptographic hashes (MD5 = 32 hex chars, SHA-1 = 40, SHA-256 = 64).
pub(crate) fn normalize_hash(value: &str) -> Option<String> {
    let v = value.trim();
    (matches!(v.len(), 32 | 40 | 64) && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| v.to_ascii_lowercase())
}

/// Normalizes domain names (lowercase, stripped trailing dot, valid label format).
pub(crate) fn normalize_domain(value: &str) -> Option<String> {
    let v = value.trim();
    let v = v.strip_suffix('.').unwrap_or(v).to_ascii_lowercase();
    let labels_ok = v.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    (labels_ok && v.len() <= 253 && v.contains('.') && v.parse::<IpAddr>().is_err()).then_some(v)
}

/// Extracts hostname from a URL string, stripping scheme, path, query, user, and port.
pub(crate) fn url_host(rest: &str) -> &str {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    host.split(':').next().unwrap_or("")
}

