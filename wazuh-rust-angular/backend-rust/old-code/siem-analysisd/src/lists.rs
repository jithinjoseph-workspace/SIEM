//! CDB lists: `lists.c`, `lists_list.c`, `lists_make.c`.
//!
//! analysisd compiles each text list into a constant database (`.cdb`) and
//! answers lookups with `cdb_find`, which returns the *first* record stored
//! under a key. The port parses the text file with the exact `lists_make.c`
//! rules and keeps the records in memory with the same first-wins semantics;
//! [`write_cdb`] produces the on-disk `.cdb` (D. J. Bernstein format) for
//! other tools.

use std::collections::HashMap;

use siem_regex::OsMatch;

use crate::logmsg::{self, LogList};

pub const LR_STRING_MATCH: i32 = 0;
pub const LR_STRING_NOT_MATCH: i32 = 1;
pub const LR_STRING_MATCH_VALUE: i32 = 2;
pub const LR_ADDRESS_MATCH: i32 = 10;
pub const LR_ADDRESS_NOT_MATCH: i32 = 11;
pub const LR_ADDRESS_MATCH_VALUE: i32 = 12;

const OS_MAXSTR: usize = 65536;

/// `ListNode`
#[derive(Debug, Clone, Default)]
pub struct ListNode {
    pub txt_filename: String,
    pub cdb_filename: String,
    /// Records in insertion order.
    pub records: Vec<(Vec<u8>, Vec<u8>)>,
    /// key -> index of the first record.
    pub index: HashMap<Vec<u8>, usize>,
    pub loaded: bool,
}

impl ListNode {
    /// `cdb_find` + `cdb_read`: value of the first record with `key`.
    pub fn find(&self, key: &[u8]) -> Option<&[u8]> {
        self.index.get(key).map(|&i| self.records[i].1.as_slice())
    }
}

/// `ListRule`
#[derive(Debug, Clone)]
pub struct ListRule {
    pub field: i32,
    pub lookup_type: i32,
    pub matcher: Option<OsMatch>,
    pub dfield: Option<String>,
    pub filename: String,
    pub db: Option<usize>,
}

/// The `ListNode` chain of a ruleset.
#[derive(Debug, Clone, Default)]
pub struct Lists {
    pub nodes: Vec<ListNode>,
}

/// Parse the text list exactly like `Lists_OP_MakeCDB`.
pub fn parse_list_text(data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    // fgets(str, OS_MAXSTR - 1, fd): at most OS_MAXSTR - 2 bytes per read.
    let max = OS_MAXSTR - 2;
    let mut pos = 0;
    while pos < data.len() {
        let rest = &data[pos..];
        let mut n = rest.iter().position(|&c| c == b'\n').map(|p| p + 1).unwrap_or(rest.len());
        if n > max {
            n = max;
        }
        let mut line: Vec<u8> = rest[..n].to_vec();
        pos += n;
        // fgets stops at NUL only implicitly: strchr below sees a C string
        if let Some(z) = line.iter().position(|&c| c == 0) {
            line.truncate(z);
        }
        if let Some(r) = line.iter().position(|&c| c == b'\r') {
            line.truncate(r);
        }
        if let Some(r) = line.iter().position(|&c| c == b'\n') {
            line.truncate(r);
        }
        let s = line;
        let mut key: Option<(usize, usize)> = None;
        let mut key_quotes: Option<usize> = None;
        if let Some(q) = s.iter().position(|&c| c == b'"') {
            if let Some(colon) = s.iter().position(|&c| c == b':') {
                if colon > q {
                    let kstart = q + 1;
                    match s[kstart..].iter().position(|&c| c == b'"') {
                        Some(e) => {
                            key = Some((kstart, kstart + e));
                            key_quotes = Some(kstart + e + 1);
                        }
                        None => continue,
                    }
                }
            }
        }
        let value_begin = key_quotes.unwrap_or(0);
        let Some(colon) = s[value_begin.min(s.len())..].iter().position(|&c| c == b':').map(|c| value_begin + c) else {
            continue;
        };
        // When the key is not quoted it ends at the ':'.
        let key_range = key.unwrap_or((0, colon));
        let val_start = colon + 1;
        let val: Vec<u8> = match s[val_start..].iter().position(|&c| c == b'"') {
            Some(q) => {
                let vs = val_start + q + 1;
                match s[vs..].iter().position(|&c| c == b'"') {
                    Some(e) => s[vs..vs + e].to_vec(),
                    None => continue,
                }
            }
            None => s[val_start..].to_vec(),
        };
        // An unquoted key is `str` cut at the first NUL written: the ':' (or
        // the opening quote of a value).
        let mut k = s[key_range.0..key_range.1].to_vec();
        if key.is_none() {
            if let Some(q) = k.iter().position(|&c| c == 0) {
                k.truncate(q);
            }
        }
        out.push((k, val));
    }
    out
}

impl Lists {
    /// `Lists_OP_LoadList` (+ `Lists_OP_MakeCDB` contents).
    pub fn load_list(&mut self, listfile: &str, home: &std::path::Path, log: &mut LogList) -> i32 {
        let mut a = listfile.to_string();
        if !a.contains('/') {
            a = format!("ruleset/rules/{a}");
        }
        if let Some(h) = a.find(".cdb") {
            a.truncate(h);
        }
        let b = format!("{a}.cdb");
        let data = match std::fs::read(crate::rules::resolve(home, &a)) {
            Ok(d) => d,
            Err(e) => {
                log.warn(logmsg::fopen_error(&a, e.raw_os_error().unwrap_or(2), &e.to_string()));
                return 0;
            }
        };
        let records = parse_list_text(&data);
        let mut index = HashMap::new();
        for (i, (k, _)) in records.iter().enumerate() {
            index.entry(k.clone()).or_insert(i);
        }
        self.nodes.push(ListNode { txt_filename: a, cdb_filename: b, records, index, loaded: true });
        0
    }

    /// `OS_FindList`
    pub fn find_list(&self, name: &str) -> Option<usize> {
        self.nodes.iter().position(|n| n.txt_filename == name || n.cdb_filename == name)
    }

    fn key_address(node: &ListNode, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(v) = node.find(key) {
            return Some(v.to_vec());
        }
        let mut tmp = key.to_vec();
        while !tmp.is_empty() {
            if *tmp.last().unwrap() == b'.' {
                if let Some(v) = node.find(&tmp) {
                    return Some(v.to_vec());
                }
            }
            tmp.pop();
        }
        None
    }

    /// `OS_DBSearch`
    pub fn db_search(&self, lrule: &ListRule, key: &[u8]) -> bool {
        let node = lrule.db.and_then(|d| self.nodes.get(d));
        let matcher_ok = |v: &[u8]| -> bool {
            match &lrule.matcher {
                Some(m) => m.is_match_bytes(v),
                // OSMatch_Execute with a NULL pattern returns 0
                None => false,
            }
        };
        match lrule.lookup_type {
            LR_STRING_MATCH => node.map_or(false, |n| n.find(key).is_some()),
            LR_STRING_NOT_MATCH => !node.map_or(false, |n| n.find(key).is_some()),
            LR_STRING_MATCH_VALUE => node.and_then(|n| n.find(key)).map_or(false, matcher_ok),
            LR_ADDRESS_MATCH => node.map_or(false, |n| Self::key_address(n, key).is_some()),
            LR_ADDRESS_NOT_MATCH => !node.map_or(false, |n| Self::key_address(n, key).is_some()),
            // OS_DBSearch returns 1 when OS_DBSearchKeyAddressValue returned 0.
            LR_ADDRESS_MATCH_VALUE => {
                let r = node.and_then(|n| Self::key_address(n, key)).map_or(false, |v| matcher_ok(&v));
                !r
            }
            _ => false,
        }
    }
}

/// `cdb_hash`
pub fn cdb_hash(key: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &c in key {
        h = (h.wrapping_add(h << 5)) ^ (c as u32);
    }
    h
}

/// Serialise records in the `cdb_make` format.
pub fn write_cdb(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0u8; 2048];
    let mut entries: Vec<(u32, u32)> = Vec::new();
    for (k, v) in records {
        let pos = out.len() as u32;
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(v);
        entries.push((cdb_hash(k), pos));
    }
    let mut header = vec![0u8; 2048];
    for t in 0..256u32 {
        let bucket: Vec<(u32, u32)> = entries.iter().copied().filter(|(h, _)| h & 255 == t).collect();
        let len = (bucket.len() * 2) as u32;
        let tpos = out.len() as u32;
        header[(t * 8) as usize..(t * 8 + 4) as usize].copy_from_slice(&tpos.to_le_bytes());
        header[(t * 8 + 4) as usize..(t * 8 + 8) as usize].copy_from_slice(&len.to_le_bytes());
        let mut slots = vec![(0u32, 0u32); len as usize];
        for (h, p) in bucket {
            let mut w = ((h >> 8) % len) as usize;
            while slots[w].1 != 0 {
                w = (w + 1) % len as usize;
            }
            slots[w] = (h, p);
        }
        for (h, p) in slots {
            out.extend_from_slice(&h.to_le_bytes());
            out.extend_from_slice(&p.to_le_bytes());
        }
    }
    out[..2048].copy_from_slice(&header);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_formats() {
        let r = parse_list_text(b"a:b\n\"k:1\":v\nx:\"quoted\"\nnovalue\n\"bad:1\nkey:\r\n");
        assert_eq!(
            r,
            vec![
                (b"a".to_vec(), b"b".to_vec()),
                (b"k:1".to_vec(), b"v".to_vec()),
                (b"x".to_vec(), b"quoted".to_vec()),
                (b"key".to_vec(), b"".to_vec()),
            ]
        );
    }
}
