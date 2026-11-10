//! `SysNormalizer` (syscollectorNormalizer.cpp): the dictionary and the
//! exclusions of `norm_config.json` for one target ("windows", "linux",
//! "macos"). The patterns are ECMAScript `std::regex`es; `regex_match` is a
//! whole-string match and `regex_replace` replaces every match.

use std::collections::BTreeMap;

use siem_njson::Value;

pub struct SysNormalizer {
    exclusions: BTreeMap<Vec<u8>, Vec<Value>>,
    dictionary: BTreeMap<Vec<u8>, Vec<Value>>,
}

fn s(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Str(b) => Some(b),
        _ => None,
    }
}

/// `std::regex` (ECMAScript) as a whole-string matcher.
fn full(pattern: &[u8]) -> Option<regex::bytes::Regex> {
    let p = String::from_utf8_lossy(pattern);
    regex::bytes::Regex::new(&format!("^(?:{p})$")).ok()
}

fn search(pattern: &[u8]) -> Option<regex::bytes::Regex> {
    regex::bytes::Regex::new(&String::from_utf8_lossy(pattern)).ok()
}

/// The ECMAScript format string of `regex_replace` (`$&`, `$n`, `$$`) in
/// the `regex` crate's syntax.
fn ecma_format(fmt: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] == b'$' && i + 1 < fmt.len() {
            match fmt[i + 1] {
                b'&' => {
                    out.extend_from_slice(b"${0}");
                    i += 2;
                    continue;
                }
                b'$' => {
                    out.extend_from_slice(b"$$");
                    i += 2;
                    continue;
                }
                c if c.is_ascii_digit() => {
                    let mut j = i + 1;
                    while j < fmt.len() && j < i + 3 && fmt[j].is_ascii_digit() {
                        j += 1;
                    }
                    out.extend_from_slice(b"${");
                    out.extend_from_slice(&fmt[i + 1..j]);
                    out.push(b'}');
                    i = j;
                    continue;
                }
                _ => {}
            }
        }
        if fmt[i] == b'$' {
            out.extend_from_slice(b"$$");
        } else {
            out.push(fmt[i]);
        }
        i += 1;
    }
    out
}

impl SysNormalizer {
    /// `SysNormalizer(configFile, target)`
    pub fn new(config_file: &str, target: &str) -> SysNormalizer {
        SysNormalizer { exclusions: type_values(config_file, target, "exclusions"), dictionary: type_values(config_file, target, "dictionary") }
    }

    /// `removeExcluded(type, data)`
    pub fn remove_excluded(&self, ty: &str, data: &mut Value) {
        let Some(items) = self.exclusions.get(ty.as_bytes()) else { return };
        for ex in items {
            let (Some(pattern), Some(field)) = (ex.find(b"pattern").and_then(s), ex.find(b"field_name").and_then(s)) else {
                continue;
            };
            let Some(re) = full(pattern) else { continue };
            match data {
                Value::Array(a) => {
                    // (the C++ erases while iterating: every matching element goes)
                    a.retain(|item| !item.find(field).and_then(s).is_some_and(|v| re.is_match(v)));
                }
                _ => {
                    if data.find(field).and_then(s).is_some_and(|v| re.is_match(v)) {
                        data.clear();
                    }
                }
            }
        }
    }

    /// `normalize(type, data)`
    pub fn normalize(&self, ty: &str, data: &mut Value) {
        let Some(dict) = self.dictionary.get(ty.as_bytes()) else { return };
        match data {
            Value::Array(a) => {
                for item in a.iter_mut() {
                    normalize_item(dict, item);
                }
            }
            _ => normalize_item(dict, data),
        }
    }
}

/// `normalizeItem`
fn normalize_item(dictionary: &[Value], item: &mut Value) {
    for d in dictionary {
        let find_pattern = d.find(b"find_pattern");
        let find_field = d.find(b"find_field");
        match (find_pattern, find_field) {
            (Some(p), Some(f)) => {
                let (Some(p), Some(f)) = (s(p), s(f)) else { continue };
                let Some(re) = full(p) else { continue };
                if !item.find(f).and_then(s).is_some_and(|v| re.is_match(v)) {
                    continue;
                }
            }
            (None, None) => {}
            _ => continue,
        }
        if let (Some(rp), Some(rf), Some(rv)) = (d.find(b"replace_pattern"), d.find(b"replace_field"), d.find(b"replace_value")) {
            if let (Some(rp), Some(rf), Some(rv)) = (s(rp), s(rf), s(rv)) {
                if let Some(re) = search(rp) {
                    if let Some(Value::Str(cur)) = item.find(rf).cloned() {
                        let fmt = ecma_format(rv);
                        let new = re.replace_all(&cur, fmt.as_slice()).into_owned();
                        let _ = item.set(rf, Value::Str(new));
                    }
                }
            }
        }
        if let (Some(af), Some(av)) = (d.find(b"add_field"), d.find(b"add_value")) {
            if let (Some(af), Some(av)) = (s(af), s(av)) {
                let _ = item.set(af, Value::Str(av.to_vec()));
            }
        }
    }
}

/// `getTypeValues(configFile, target, type)`
fn type_values(config_file: &str, target: &str, ty: &str) -> BTreeMap<Vec<u8>, Vec<Value>> {
    let mut ret: BTreeMap<Vec<u8>, Vec<Value>> = BTreeMap::new();
    let Ok(raw) = std::fs::read(config_file) else { return ret };
    // std::ifstream (text mode)
    let text: Vec<u8> = raw.iter().copied().filter(|&c| c != b'\r').collect();
    let Ok(cfg) = siem_njson::parse(&text) else { return ret };
    let Some(list) = cfg.find(ty.as_bytes()) else { return ret };
    for item in list.iter() {
        if item.find(b"target").and_then(s) == Some(target.as_bytes()) {
            let key = item.find(b"data_type").and_then(s).unwrap_or(b"").to_vec();
            ret.entry(key).or_default().push(item.clone());
        }
    }
    ret
}
