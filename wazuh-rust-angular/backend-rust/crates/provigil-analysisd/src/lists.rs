//! Lists (spec section 2.15): `key:value` text files used by rules. Lookups return the first
//! record of a key; [`write_cdb`] writes the constant-database file format for other tools.

use std::collections::HashMap;
use std::path::Path;

use provigil_regex::OsMatch;

use crate::messages::{self as m, Messages};

pub const MATCH_KEY: i32 = 0;
pub const NOT_MATCH_KEY: i32 = 1;
pub const MATCH_KEY_VALUE: i32 = 2;
pub const ADDRESS_MATCH_KEY: i32 = 10;
pub const NOT_ADDRESS_MATCH_KEY: i32 = 11;
pub const ADDRESS_MATCH_KEY_VALUE: i32 = 12;

#[derive(Debug, Clone, Default)]
pub struct List {
    /// The name rules use: the text file ...
    pub text_name: String,
    /// ... or its `.cdb` name.
    pub cdb_name: String,
    pub records: Vec<(Vec<u8>, Vec<u8>)>,
    /// The first record of each key.
    pub first: HashMap<Vec<u8>, usize>,
    pub loaded: bool,
}

impl List {
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.first.get(key).map(|&i| self.records[i].1.as_slice())
    }

    /// The key, then the key cut after each `.` from the end (`10.1.2.` .. `10.`).
    fn get_address(&self, key: &[u8]) -> Option<&[u8]> {
        self.get(key).or_else(|| (1..key.len()).rev().filter(|&n| key[n - 1] == b'.').find_map(|n| self.get(&key[..n])))
    }
}

/// A list condition of a rule.
#[derive(Debug, Clone)]
pub struct ListCheck {
    pub field: i32,
    pub lookup: i32,
    pub value_pattern: Option<OsMatch>,
    pub dynamic_field: Option<String>,
    pub file: String,
    pub list: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Lists {
    pub lists: Vec<List>,
}

/// The records of a list text: one per line (lines read in pieces of 65,534 bytes, ending
/// at a zero byte, `\r` or `\n`). `key:value`, `"key":value`, `key:"value"`; a line without
/// `:` or with an unclosed quote is skipped. A quoted key is only taken when its quote comes
/// before the first `:`.
pub fn parse_text(data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let n = rest.iter().position(|&c| c == b'\n').map_or(rest.len(), |p| p + 1).min(65534);
        let mut s = &rest[..n];
        rest = &rest[n..];
        for stop in [0, b'\r', b'\n'] {
            if let Some(p) = s.iter().position(|&c| c == stop) {
                s = &s[..p];
            }
        }
        let first_colon = s.iter().position(|&c| c == b':');
        let mut key = None;
        let mut search_from = 0;
        if let (Some(q), Some(c)) = (s.iter().position(|&c| c == b'"'), first_colon) {
            if c > q {
                let Some(e) = s[q + 1..].iter().position(|&c| c == b'"') else { continue };
                key = Some(s[q + 1..q + 1 + e].to_vec());
                search_from = q + e + 2;
            }
        }
        let Some(colon) = s.get(search_from..).and_then(|t| t.iter().position(|&c| c == b':')).map(|c| search_from + c) else { continue };
        let after = &s[colon + 1..];
        let value = match after.iter().position(|&c| c == b'"') {
            Some(q) => match after[q + 1..].iter().position(|&c| c == b'"') {
                Some(e) => after[q + 1..q + 1 + e].to_vec(),
                None => continue,
            },
            None => after.to_vec(),
        };
        out.push((key.unwrap_or_else(|| s[..colon].to_vec()), value));
    }
    out
}

impl Lists {
    /// Reads a list file (`name` as configured; without `/` it is under `ruleset/rules`).
    pub fn load(&mut self, name: &str, home: &Path, msgs: &mut Messages) -> i32 {
        let mut text = if name.contains('/') { name.to_string() } else { format!("ruleset/rules/{name}") };
        if let Some(p) = text.find(".cdb") {
            text.truncate(p);
        }
        let data = match std::fs::read(crate::config::resolve(home, &text)) {
            Ok(d) => d,
            Err(e) => {
                msgs.warn(m::open_failed(&text, e.raw_os_error().unwrap_or(2), &e.to_string()));
                return 0;
            }
        };
        let records = parse_text(&data);
        let mut first = HashMap::new();
        for (i, (k, _)) in records.iter().enumerate() {
            first.entry(k.clone()).or_insert(i);
        }
        let cdb_name = format!("{text}.cdb");
        self.lists.push(List { text_name: text, cdb_name, records, first, loaded: true });
        0
    }

    pub fn find(&self, name: &str) -> Option<usize> {
        self.lists.iter().position(|l| l.text_name == name || l.cdb_name == name)
    }

    /// Whether `key` passes the rule's list condition.
    pub fn check(&self, c: &ListCheck, key: &[u8]) -> bool {
        let list = c.list.and_then(|i| self.lists.get(i));
        let value_ok = |v: &[u8]| c.value_pattern.as_ref().is_some_and(|p| p.is_match_bytes(v));
        match c.lookup {
            MATCH_KEY => list.is_some_and(|l| l.get(key).is_some()),
            NOT_MATCH_KEY => !list.is_some_and(|l| l.get(key).is_some()),
            MATCH_KEY_VALUE => list.and_then(|l| l.get(key)).is_some_and(value_ok),
            ADDRESS_MATCH_KEY => list.is_some_and(|l| l.get_address(key).is_some()),
            NOT_ADDRESS_MATCH_KEY => !list.is_some_and(|l| l.get_address(key).is_some()),
            // inverted in the original and kept: rules in the field depend on it
            ADDRESS_MATCH_KEY_VALUE => !list.and_then(|l| l.get_address(key)).is_some_and(value_ok),
            _ => false,
        }
    }
}

/// The hash of the constant-database format.
pub fn cdb_hash(key: &[u8]) -> u32 {
    key.iter().fold(5381u32, |h, &c| h.wrapping_add(h << 5) ^ u32::from(c))
}

/// The records in the constant-database file format: a 2,048-byte table of 256 (position,
/// slots) pairs, the records, then 256 hash tables twice as long as their entries.
pub fn write_cdb(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0u8; 2048];
    let mut entries = Vec::new();
    for (k, v) in records {
        entries.push((cdb_hash(k), out.len() as u32));
        for n in [k.len() as u32, v.len() as u32] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    for t in 0..256u32 {
        let bucket: Vec<(u32, u32)> = entries.iter().copied().filter(|(h, _)| h & 255 == t).collect();
        let slots = bucket.len() * 2;
        let at = (t * 8) as usize;
        let start = out.len() as u32;
        out[at..at + 4].copy_from_slice(&start.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&(slots as u32).to_le_bytes());
        let mut table = vec![(0u32, 0u32); slots];
        for (h, p) in bucket {
            let mut w = (h >> 8) as usize % slots;
            while table[w].1 != 0 {
                w = (w + 1) % slots;
            }
            table[w] = (h, p);
        }
        for (h, p) in table {
            out.extend_from_slice(&h.to_le_bytes());
            out.extend_from_slice(&p.to_le_bytes());
        }
    }
    out
}
