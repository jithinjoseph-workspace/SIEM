//! Windows registry monitoring.
//!
//! Each configured key (`HKLM\...` or `HKEY_LOCAL_MACHINE\...`, ` [x32]` for the 32-bit view) is
//! walked with the Win32 registry API down to the recursion level, skipping ignored keys. Per
//! key: last write time, owner and permissions (SDDL); per value: type, size, MD5, SHA-1 and
//! SHA-256 of the data. Compared with the baseline in `data\fim.db` (table `registry`).
//! Restrict regexes narrow what is monitored; value data goes out only for `report_changes` keys.

use std::collections::HashMap;
use std::path::Path;
use chrono::Utc;
use regex::{Regex, RegexBuilder};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::buffer::EventBuffer;
use crate::fim;
use crate::fim_db::FimDb;

/// One key (`value_type` empty) or one value as last seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegEntry {
    pub value_type: String,
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    /// Keys: last write time (Unix seconds).
    pub mtime: i64,
    /// Keys: owner SID and permissions (DACL as SDDL).
    pub owner: String,
    pub perms: String,
    /// Values: the data as text (REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ).
    pub data: Option<String>,
}

/// (full key path, `[x64]` / `[x32]`, value name; `None` for the key itself).
pub type RegId = (String, String, Option<String>);

/// Longest `value_data` sent, in characters.
const MAX_DATA_CHARS: usize = 1024;

pub struct RegistryMonitor {
    /// (full key path, 32-bit view)
    keys: Vec<(String, bool)>,
    /// Lower-case full key paths.
    ignore: Vec<String>,
    max_depth: u32,
    baseline: HashMap<RegId, RegEntry>,
    db: Option<FimDb>,
    /// No baseline yet: the first scan records it without reporting.
    first_scan_quiet: bool,
    /// When not empty, only keys matching one are monitored.
    restrict_key: Vec<Regex>,
    /// When not empty, only values matching one are monitored.
    restrict_value: Vec<Regex>,
    /// Lower-case full key paths whose value data is sent; `None`: every key's.
    report_changes: Option<Vec<String>>,
}

/// `HKLM\Software\X [x32]` → (`HKEY_LOCAL_MACHINE\Software\X`, true); `None` for an unknown hive.
pub fn parse_key(entry: &str) -> Option<(String, bool)> {
    let t = entry.trim();
    let lower = t.to_ascii_lowercase();
    let (t, x32) = if lower.ends_with("[x32]") {
        (t[..t.len() - 5].trim_end(), true)
    } else if lower.ends_with("[x64]") {
        (t[..t.len() - 5].trim_end(), false)
    } else {
        (t, false)
    };
    let t = t.trim_end_matches('\\');
    let (hive, rest) = t.split_once('\\').unwrap_or((t, ""));
    let full = match hive.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => "HKEY_LOCAL_MACHINE",
        "HKCU" | "HKEY_CURRENT_USER" => "HKEY_CURRENT_USER",
        "HKCR" | "HKEY_CLASSES_ROOT" => "HKEY_CLASSES_ROOT",
        "HKU" | "HKEY_USERS" => "HKEY_USERS",
        "HKCC" | "HKEY_CURRENT_CONFIG" => "HKEY_CURRENT_CONFIG",
        _ => return None,
    };
    Some((if rest.is_empty() { full.to_string() } else { format!("{full}\\{rest}") }, x32))
}

pub fn type_name(t: u32) -> &'static str {
    match t {
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

fn utf16(data: &[u8]) -> Vec<u16> {
    data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect()
}

/// The data as text for the text and number types, at most [`MAX_DATA_CHARS`] characters.
fn data_text(t: u32, data: &[u8]) -> Option<String> {
    let text = match t {
        1 | 2 => {
            let w = utf16(data);
            let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
            String::from_utf16_lossy(&w[..end])
        }
        7 => utf16(data)
            .split(|&c| c == 0)
            .filter(|s| !s.is_empty())
            .map(String::from_utf16_lossy)
            .collect::<Vec<_>>()
            .join("\n"),
        4 => u32::from_le_bytes(data.get(..4)?.try_into().ok()?).to_string(),
        11 => u64::from_le_bytes(data.get(..8)?.try_into().ok()?).to_string(),
        _ => return None,
    };
    Some(text.chars().take(MAX_DATA_CHARS).collect())
}

pub fn value_entry(t: u32, data: &[u8]) -> RegEntry {
    RegEntry {
        value_type: type_name(t).into(),
        size: data.len() as u64,
        md5: format!("{:x}", md5::Md5::digest(data)),
        sha1: format!("{:x}", sha1::Sha1::digest(data)),
        sha256: format!("{:x}", Sha256::digest(data)),
        data: data_text(t, data),
        ..Default::default()
    }
}

/// What differs; a key's last write time alone is no change (it moves with every value change).
fn changed_attributes(old: &RegEntry, new: &RegEntry, is_key: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    if is_key {
        if old.owner != new.owner {
            out.push("owner");
        }
        if old.perms != new.perms {
            out.push("perm");
        }
        if !out.is_empty() && old.mtime != new.mtime {
            out.push("mtime");
        }
        return out;
    }
    for (name, differs) in [
        ("type", old.value_type != new.value_type),
        ("size", old.size != new.size),
        ("md5", old.md5 != new.md5),
        ("sha1", old.sha1 != new.sha1),
        ("sha256", old.sha256 != new.sha256),
    ] {
        if differs {
            out.push(name);
        }
    }
    out
}

/// The patterns, case-insensitive like the registry.
fn patterns(list: &[String]) -> Vec<Regex> {
    list.iter()
        .filter_map(|p| RegexBuilder::new(p).case_insensitive(true).build().map_err(|e| warn!(regex = %p, error = %e, "Invalid registry restrict expression: not used")).ok())
        .collect()
}

/// Whether this key's value data may leave the agent: it is at or below a listed key.
fn reports_data(report: &Option<Vec<String>>, key: &str) -> bool {
    let lower = key.to_lowercase();
    report.as_ref().is_none_or(|list| list.iter().any(|k| lower.strip_prefix(k.as_str()).is_some_and(|r| r.is_empty() || r.starts_with('\\'))))
}

impl RegistryMonitor {
    pub fn new(monitored_keys: Vec<String>) -> Self {
        let keys = monitored_keys
            .iter()
            .filter_map(|k| {
                let parsed = parse_key(k);
                if parsed.is_none() {
                    warn!(key = %k, "Registry key with an unknown hive; not monitored");
                }
                parsed
            })
            .collect();
        Self {
            keys,
            ignore: Vec::new(),
            max_depth: 512,
            baseline: HashMap::new(),
            db: None,
            first_scan_quiet: true,
            restrict_key: Vec::new(),
            restrict_value: Vec::new(),
            report_changes: None,
        }
    }

    /// Keys starting with one of `prefixes` (either hive spelling, case-insensitive) are skipped.
    pub fn with_ignore(mut self, prefixes: &[String]) -> Self {
        self.ignore = prefixes.iter().filter_map(|p| parse_key(p)).map(|(k, _)| k.to_lowercase()).collect();
        self
    }

    /// Depth walked below each configured key (0: the key itself only).
    pub fn with_recursion_level(mut self, level: u32) -> Self {
        self.max_depth = level;
        self
    }

    /// `registry_restrict_key` / `registry_restrict_value`.
    pub fn with_restrict(mut self, keys: &[String], values: &[String]) -> Self {
        self.restrict_key = patterns(keys);
        self.restrict_value = patterns(values);
        self
    }

    /// Only keys at or below one of `prefixes` send their value data.
    pub fn with_report_changes(mut self, prefixes: &[String]) -> Self {
        self.report_changes = Some(prefixes.iter().filter_map(|p| parse_key(p)).map(|(k, _)| k.to_lowercase()).collect());
        self
    }

    /// Whether the restrict lists let this key or value be monitored.
    fn wanted(&self, id: &RegId) -> bool {
        let any = |list: &[Regex], text: &str| list.is_empty() || list.iter().any(|r| r.is_match(text));
        any(&self.restrict_key, &id.0) && id.2.as_ref().is_none_or(|v| any(&self.restrict_value, v))
    }

    /// Keeps the baseline in `path` (SQLite) and starts from what it holds.
    pub fn with_database(mut self, path: &Path) -> Self {
        match FimDb::open(path).and_then(|db| db.load_registry().map(|b| (db, b))) {
            Ok((db, base)) => {
                info!(entries = base.len(), db = %path.display(), "Registry baseline loaded");
                self.first_scan_quiet = base.is_empty();
                self.baseline = base;
                self.db = Some(db);
            }
            Err(e) => tracing::error!(error = %e, db = %path.display(), "Registry database not usable; baseline kept in memory only"),
        }
        self
    }

    /// Walks the configured keys and reports what was added, modified or deleted since the
    /// last scan. A deleted key is one event with one per value it held (the manager keeps a
    /// row per value); its subkeys go with it.
    pub fn scan(&mut self, agent_id: &str, agent_name: &str) -> Vec<Value> {
        let current = self.read_all();
        // a walk cut short by the stop would take what it did not reach as deleted
        if !crate::collecting() {
            return Vec::new();
        }
        self.compare(agent_id, agent_name, current)
    }

    fn compare(&mut self, agent_id: &str, agent_name: &str, mut current: HashMap<RegId, RegEntry>) -> Vec<Value> {
        current.retain(|id, _| self.wanted(id));
        // the baseline too: one from before these settings must not send old data with a change
        let report = &self.report_changes;
        current.iter_mut().chain(self.baseline.iter_mut()).filter(|(id, _)| !reports_data(report, &id.0)).for_each(|(_, e)| e.data = None);
        let mut events = Vec::new();

        for (id, new) in &current {
            match self.baseline.get(id) {
                None => events.push(event(agent_id, agent_name, id, "added", Some(new), None, Vec::new())),
                Some(old) => {
                    let changed = changed_attributes(old, new, id.2.is_none());
                    if !changed.is_empty() {
                        events.push(event(agent_id, agent_name, id, "modified", Some(new), Some(old), changed));
                    }
                }
            }
        }

        // every entry under a deleted key too, so the manager keeps no stale rows
        let deleted: Vec<&RegId> = self.baseline.keys().filter(|id| !current.contains_key(*id)).collect();
        for id in &deleted {
            // restricted away by new settings: it leaves the baseline without a report
            if !self.wanted(id) {
                continue;
            }
            events.push(event(agent_id, agent_name, id, "deleted", None, self.baseline.get(*id), Vec::new()));
        }

        if let Some(db) = self.db.as_mut() {
            let changed: Vec<(&RegId, &RegEntry)> = current.iter().filter(|(id, e)| self.baseline.get(*id) != Some(*e)).collect();
            if let Err(e) = db.apply_registry(&changed, &deleted) {
                tracing::error!(error = %e, "Registry baseline not saved");
            }
        }
        self.baseline = current;
        if std::mem::take(&mut self.first_scan_quiet) {
            info!(entries = self.baseline.len(), "Registry baseline built (first scan: nothing reported)");
            events.clear();
        }
        for ev in &events {
            info!(key = %ev["registry"]["key"], value = %ev["registry"]["value_name"], event = %ev["registry"]["event"], "Registry change");
        }
        events
    }

    /// The registry values to the manager once per agent id, as a change event describes them,
    /// without their data (`fim_entry` has no column for it). Called by the thread that scans,
    /// so the baseline holds still meanwhile.
    pub fn sync_state(&self, buffer: &EventBuffer, agent: &(String, String), synced: &Path, running: fn() -> bool, allowed: fn() -> bool) {
        if fim::state_sent(synced, "registry", &agent.0) {
            return;
        }
        let values: Vec<(&RegId, &RegEntry)> = self.baseline.iter().filter(|(id, _)| id.2.is_some()).collect();
        fim::send_state(buffer, agent, synced, "registry", &values, running, allowed, |batch| {
            let entry = |(id, e): &(&RegId, &RegEntry)| event("", "", id, "added", Some(&RegEntry { data: None, ..(*e).clone() }), None, Vec::new())["registry"].clone();
            batch.iter().map(entry).collect()
        });
    }

    #[cfg(windows)]
    fn read_all(&self) -> HashMap<RegId, RegEntry> {
        let mut out = HashMap::new();
        for (path, x32) in &self.keys {
            win::walk_root(path, *x32, self.max_depth, &self.ignore, &mut out);
        }
        out
    }

    #[cfg(not(windows))]
    fn read_all(&self) -> HashMap<RegId, RegEntry> {
        HashMap::new()
    }
}

fn event(
    agent_id: &str,
    agent_name: &str,
    id: &RegId,
    kind: &str,
    new: Option<&RegEntry>,
    old: Option<&RegEntry>,
    changed: Vec<&str>,
) -> Value {
    let (key, arch, value) = id;
    let mut r = json!({ "key": key, "arch": arch, "event": kind, "changed_attributes": changed });
    if let Some(name) = value {
        r["value_name"] = json!(name);
        if let Some(e) = new.or(old) {
            r["value_type"] = json!(e.value_type);
        }
        if let Some(n) = new {
            r["size_after"] = json!(n.size);
            r["sha256_after"] = json!(n.sha256);
            if let Some(d) = &n.data {
                r["value_data"] = json!(d);
            }
        }
        if let Some(o) = old {
            r["sha256_before"] = json!(o.sha256);
        }
        // the fields of the earlier autostart events, kept for compatibility
        let text = |e: Option<&RegEntry>| json!(e.and_then(|e| e.data.clone()).unwrap_or_default());
        match kind {
            "added" => r["value"] = text(new),
            "modified" => {
                r["old_value"] = text(old);
                r["new_value"] = text(new);
            }
            _ => r["old_value"] = text(old),
        }
    }
    json!({
        "type": "registry",
        "timestamp": Utc::now().to_rfc3339(),
        "agent": { "id": agent_id, "name": agent_name },
        "registry": r
    })
}

#[cfg(windows)]
pub(crate) mod win {
    use super::*;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorOwner, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegGetKeySecurity, RegOpenKeyExW, RegQueryInfoKeyW, HKEY,
        HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ,
        KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// A NUL-terminated wide string allocated by the system, freed after reading.
    unsafe fn take_local_wstr(p: *mut u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        LocalFree(p.cast());
        s
    }

    /// (owner SID, DACL as SDDL) of a security descriptor read with owner and DACL (also
    /// used for files by `fim.rs`).
    pub(crate) unsafe fn owner_and_dacl(sd: PSECURITY_DESCRIPTOR) -> (String, String) {
        let mut owner = String::new();
        let (mut sid, mut defaulted): (PSID, _) = (null_mut(), 0);
        if GetSecurityDescriptorOwner(sd, &mut sid, &mut defaulted) != 0 && !sid.is_null() {
            let mut p = null_mut();
            if ConvertSidToStringSidW(sid, &mut p) != 0 {
                owner = take_local_wstr(p);
            }
        }
        let mut p = null_mut();
        let perms = if ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut p, null_mut()) != 0 {
            take_local_wstr(p)
        } else {
            String::new()
        };
        (owner, perms)
    }

    struct Key {
        h: HKEY,
        view: u32,
    }

    impl Drop for Key {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.h) };
        }
    }

    impl Key {
        fn open(parent: HKEY, sub: &str, view: u32) -> Option<Key> {
            let mut h: HKEY = null_mut();
            let rc = unsafe { RegOpenKeyExW(parent, wide(sub).as_ptr(), 0, KEY_READ | view, &mut h) };
            (rc == ERROR_SUCCESS).then_some(Key { h, view })
        }

        /// Last write time as Unix seconds.
        fn mtime(&self) -> i64 {
            let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let rc = unsafe {
                RegQueryInfoKeyW(
                    self.h, null_mut(), null_mut(), null(), null_mut(), null_mut(), null_mut(), null_mut(), null_mut(),
                    null_mut(), null_mut(), &mut ft,
                )
            };
            if rc != ERROR_SUCCESS {
                return 0;
            }
            let t = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
            (t / 10_000_000) as i64 - 11_644_473_600
        }

        /// (owner SID, DACL as SDDL).
        fn security(&self) -> (String, String) {
            let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            let mut len = 0u32;
            let rc = unsafe { RegGetKeySecurity(self.h, info, null_mut(), &mut len) };
            if rc != ERROR_INSUFFICIENT_BUFFER || len == 0 {
                return Default::default();
            }
            let mut sd = vec![0u64; (len as usize).div_ceil(8)];
            if unsafe { RegGetKeySecurity(self.h, info, sd.as_mut_ptr().cast(), &mut len) } != ERROR_SUCCESS {
                return Default::default();
            }
            unsafe { owner_and_dacl(sd.as_mut_ptr().cast()) }
        }

        fn subkeys(&self) -> Vec<String> {
            let mut out = Vec::new();
            let mut buf = [0u16; 256]; // key names are at most 255 characters
            for i in 0.. {
                let mut len = buf.len() as u32;
                let rc = unsafe {
                    RegEnumKeyExW(self.h, i, buf.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut())
                };
                match rc {
                    ERROR_SUCCESS => out.push(String::from_utf16_lossy(&buf[..len as usize])),
                    ERROR_NO_MORE_ITEMS => break,
                    _ => {} // skip a name that cannot be read
                }
            }
            out
        }

        /// (name, type, data) of every value.
        fn values(&self) -> Vec<(String, u32, Vec<u8>)> {
            let mut out = Vec::new();
            // value names are at most 16383 characters
            let mut name = vec![0u16; 16384];
            let mut data = vec![0u8; 4096];
            let mut i = 0;
            loop {
                let (mut nlen, mut dlen, mut ty) = (name.len() as u32, data.len() as u32, 0u32);
                let rc = unsafe {
                    RegEnumValueW(self.h, i, name.as_mut_ptr(), &mut nlen, null(), &mut ty, data.as_mut_ptr(), &mut dlen)
                };
                match rc {
                    ERROR_SUCCESS => {
                        out.push((String::from_utf16_lossy(&name[..nlen as usize]), ty, data[..dlen as usize].to_vec()));
                        i += 1;
                    }
                    // the data does not fit: grow and read the same value again
                    ERROR_MORE_DATA if (dlen as usize) > data.len() => data.resize(dlen as usize, 0),
                    ERROR_NO_MORE_ITEMS => break,
                    _ => i += 1,
                }
            }
            out
        }
    }

    fn hive(name: &str) -> Option<HKEY> {
        Some(match name {
            "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
            "HKEY_USERS" => HKEY_USERS,
            "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
            _ => return None,
        })
    }

    pub(super) fn walk_root(path: &str, x32: bool, max_depth: u32, ignore: &[String], out: &mut HashMap<RegId, RegEntry>) {
        let (h, sub) = path.split_once('\\').unwrap_or((path, ""));
        let view = if x32 { KEY_WOW64_32KEY } else { KEY_WOW64_64KEY };
        if let Some(key) = hive(h).and_then(|h| Key::open(h, sub, view)) {
            walk(&key, path, if x32 { "[x32]" } else { "[x64]" }, 0, max_depth, ignore, out);
        }
    }

    fn walk(key: &Key, path: &str, arch: &str, depth: u32, max_depth: u32, ignore: &[String], out: &mut HashMap<RegId, RegEntry>) {
        let lower = path.to_lowercase();
        if !crate::collecting() || ignore.iter().any(|i| lower.starts_with(i)) {
            return;
        }
        let (owner, perms) = key.security();
        let entry = RegEntry { mtime: key.mtime(), owner, perms, ..Default::default() };
        out.insert((path.to_string(), arch.to_string(), None), entry);
        for (name, ty, data) in key.values() {
            out.insert((path.to_string(), arch.to_string(), Some(name)), value_entry(ty, &data));
        }
        if depth >= max_depth {
            return;
        }
        for sub in key.subkeys() {
            if let Some(child) = Key::open(key.h, &sub, key.view) {
                walk(&child, &format!("{path}\\{sub}"), arch, depth + 1, max_depth, ignore, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_monitor_baseline() {
        let mut mon = RegistryMonitor::new(vec!["HKLM\\Software\\ProVigilNoSuchKey".into()]);
        let ev = mon.scan("001", "win-dev");
        assert!(ev.is_empty());
    }

    #[test]
    fn deleted_key_sends_its_values() {
        let mut mon = RegistryMonitor::new(Vec::new());
        mon.first_scan_quiet = false;
        let x64 = "[x64]".to_string();
        let all = [("K", None), ("K", Some("v1")), ("K", Some("v2")), (r"K\Sub", None), (r"K\Sub", Some("s")), (r"K\Sub\Deep", Some("d"))];
        for (key, value) in all {
            mon.baseline.insert((key.into(), x64.clone(), value.map(String::from)), RegEntry::default());
        }
        let mut got: Vec<(String, Option<String>)> = mon
            .scan("1", "t")
            .iter()
            .map(|e| (e["registry"]["key"].as_str().unwrap().into(), e["registry"]["value_name"].as_str().map(String::from)))
            .collect();
        got.sort();
        let want: Vec<(String, Option<String>)> = all.iter().map(|(k, v)| (k.to_string(), v.map(String::from))).collect();
        assert_eq!(got, want, "every subkey and value below K too");
    }

    #[test]
    fn key_spellings_and_views() {
        assert_eq!(parse_key(r"HKLM\Software\X"), Some((r"HKEY_LOCAL_MACHINE\Software\X".into(), false)));
        assert_eq!(parse_key(r"hkey_current_user\A\ [x32]"), Some((r"HKEY_CURRENT_USER\A".into(), true)));
        assert_eq!(parse_key(r"HKU [X64]"), Some(("HKEY_USERS".into(), false)));
        assert_eq!(parse_key(r"HKXX\A"), None);
    }

    #[test]
    fn value_types_text_and_hashes() {
        let sz: Vec<u8> = "hi\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let e = value_entry(1, &sz);
        assert_eq!((e.value_type.as_str(), e.size, e.data.as_deref()), ("REG_SZ", 6, Some("hi")));
        assert_eq!(e.sha256.len(), 64);
        assert_eq!(e.sha1.len(), 40);
        assert_eq!(e.md5.len(), 32);
        assert_eq!(value_entry(4, &42u32.to_le_bytes()).data.as_deref(), Some("42"));
        assert_eq!(value_entry(11, &7u64.to_le_bytes()).data.as_deref(), Some("7"));
        let multi: Vec<u8> = "a\0b\0\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(value_entry(7, &multi).data.as_deref(), Some("a\nb"));
        assert_eq!(value_entry(3, &[1, 2]).data, None);
        assert_eq!(value_entry(0, &[]).value_type, "REG_UNKNOWN");
        assert_eq!(type_name(10), "REG_RESOURCE_REQUIREMENTS_LIST");
        let long: Vec<u8> = "x".repeat(2000).encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(value_entry(2, &long).data.unwrap().len(), MAX_DATA_CHARS);
    }

    fn id(key: &str, value: Option<&str>) -> RegId {
        (key.into(), "[x64]".into(), value.map(String::from))
    }

    fn with_data(text: &str) -> RegEntry {
        RegEntry { value_type: "REG_SZ".into(), sha256: text.into(), data: Some(text.into()), ..Default::default() }
    }

    #[test]
    fn restrict_regexes_narrow_keys_and_values() {
        let run = r"HKEY_LOCAL_MACHINE\Software\Run";
        let other = r"HKEY_LOCAL_MACHINE\Software\Other";
        let mon = RegistryMonitor::new(Vec::new()).with_restrict(&[r"\\run$".into()], &["^evil".into()]);
        assert!(mon.wanted(&id(run, None)) && mon.wanted(&id(&run.to_uppercase(), None)), "any case");
        assert!(!mon.wanted(&id(other, None)));
        assert!(mon.wanted(&id(run, Some("Evil1"))));
        assert!(!mon.wanted(&id(run, Some("good"))));
        assert!(!mon.wanted(&id(other, Some("evil"))), "a value needs its key to match too");
        assert!(RegistryMonitor::new(Vec::new()).wanted(&id("K", Some("v"))), "no lists: everything");
        let broken = RegistryMonitor::new(Vec::new()).with_restrict(&["(".into()], &[]);
        assert!(broken.wanted(&id("K", None)), "an invalid expression is not used, as in log files");
    }

    #[test]
    fn scan_leaves_restricted_entries_out_without_a_report() {
        let mut mon = RegistryMonitor::new(Vec::new()).with_restrict(&["keep".into()], &[]);
        mon.first_scan_quiet = false;
        mon.baseline.insert(id("Other", Some("v")), with_data("old"));
        let current = HashMap::from([(id("Other", Some("v")), with_data("new")), (id("Keep", Some("v")), with_data("x"))]);
        let ev = mon.compare("1", "t", current);
        assert_eq!(ev.len(), 1, "{ev:#?}");
        assert_eq!((ev[0]["registry"]["key"].as_str(), ev[0]["registry"]["event"].as_str()), (Some("Keep"), Some("added")));
        assert!(!mon.baseline.contains_key(&id("Other", Some("v"))));
    }

    #[test]
    fn value_data_only_for_report_changes_keys() {
        let reported = r"HKEY_LOCAL_MACHINE\Software\Run";
        let below = r"HKEY_LOCAL_MACHINE\Software\Run\Sub";
        let silent = r"HKEY_LOCAL_MACHINE\Software\Runner";
        let mut mon = RegistryMonitor::new(Vec::new()).with_report_changes(&[r"HKLM\software\run".into()]);
        mon.first_scan_quiet = false;
        let keys = [reported, below, silent];
        keys.iter().for_each(|k| drop(mon.baseline.insert(id(k, Some("v")), with_data("before-data"))));
        let ev = mon.compare("1", "t", keys.iter().map(|k| (id(k, Some("v")), with_data("after-data"))).collect());
        let of = |k: &str| ev.iter().find(|e| e["registry"]["key"] == k).unwrap()["registry"].clone();
        for k in [reported, below] {
            assert_eq!((of(k)["value_data"].as_str(), of(k)["old_value"].as_str()), (Some("after-data"), Some("before-data")));
        }
        let hidden = of(silent);
        assert_eq!(hidden["sha256_after"], "after-data", "the hash still goes");
        assert!(hidden.get("value_data").is_none());
        assert_eq!((hidden["old_value"].as_str(), hidden["new_value"].as_str()), (Some(""), Some("")));
        assert!(!hidden["changed_attributes"].as_array().unwrap().is_empty(), "the change is still reported");
        assert!(reports_data(&None, "Any"), "without the setting: every key");
    }

    #[test]
    fn values_sent_once_per_agent_id_without_their_data() {
        let tmp = tempfile::tempdir().unwrap();
        let synced = tmp.path().join("fim_synced.json");
        let mut mon = RegistryMonitor::new(Vec::new());
        let e = RegEntry { size: 4, ..with_data("secret") };
        mon.baseline.extend([(id(r"HKEY_LOCAL_MACHINE\Run", None), RegEntry::default()), (id(r"HKEY_LOCAL_MACHINE\Run", Some("v")), e)]);
        let buffer = EventBuffer::new(10);
        let agent = ("7".to_string(), "pc".to_string());
        mon.sync_state(&buffer, &agent, &synced, || true, || true);
        let sent = buffer.drain_batch(10);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["event_type"], "fim_state");
        let entries = sent[0]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "values, not keys");
        let r = &entries[0];
        assert_eq!((r["key"].as_str(), r["arch"].as_str(), r["value_name"].as_str(), r["value_type"].as_str()), (Some(r"HKEY_LOCAL_MACHINE\Run"), Some("[x64]"), Some("v"), Some("REG_SZ")));
        assert_eq!((&r["size_after"], r["sha256_after"].as_str()), (&json!(4), Some("secret")));
        assert!(r.get("value_data").is_none() && r["value"] == "", "{r}");

        mon.sync_state(&buffer, &agent, &synced, || true, || true);
        assert!(buffer.is_empty(), "not again");
        mon.sync_state(&buffer, &("8".into(), "pc".into()), &synced, || true, || true);
        assert_eq!(buffer.len(), 1, "a new id: again");
    }

    /// Live: `HKCU\Software\ProVigilTest`, changed with reg.exe.
    #[cfg(windows)]
    #[test]
    fn registry_live_hkcu() {
        const ROOT: &str = r"HKCU\Software\ProVigilTest";
        let _turn = crate::HKCU_TEST_KEY.lock().unwrap_or_else(|e| e.into_inner());
        let reg = |args: &[&str]| {
            let out = std::process::Command::new("reg").args(args).output().unwrap();
            assert!(out.status.success() || args[0] == "delete", "reg {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        };
        let _ = std::process::Command::new("reg").args(["delete", ROOT, "/f"]).output();
        reg(&["add", ROOT, "/f"]);
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("fim.db");
        let open = || {
            RegistryMonitor::new(vec![ROOT.into()])
                .with_ignore(&[r"HKEY_CURRENT_USER\software\provigiltest\skip".into()])
                .with_recursion_level(2)
                .with_database(&db)
        };
        let mut mon = open();
        assert!(mon.scan("1", "t").is_empty(), "fresh baseline is quiet");
        let full = r"HKEY_CURRENT_USER\Software\ProVigilTest";
        let k = format!(r"{ROOT}\K");
        let one = |mon: &mut RegistryMonitor| {
            let ev = mon.scan("1", "t");
            assert_eq!(ev.len(), 1, "{ev:#?}");
            ev[0]["registry"].clone()
        };

        reg(&["add", &k, "/f"]);
        // reg.exe also writes an empty default value to a key it creates: removed
        reg(&["delete", &k, "/ve", "/f"]);
        let r = one(&mut mon);
        assert_eq!((r["event"].as_str(), r["key"].as_str(), r["arch"].as_str()), (Some("added"), Some(&*format!(r"{full}\K")), Some("[x64]")));
        assert!(r.get("value_name").is_none());

        reg(&["add", &k, "/v", "D", "/t", "REG_DWORD", "/d", "42", "/f"]);
        let r = one(&mut mon);
        assert_eq!((r["event"].as_str(), r["value_name"].as_str(), r["value_type"].as_str(), r["value_data"].as_str()), (Some("added"), Some("D"), Some("REG_DWORD"), Some("42")));
        assert_eq!(r["size_after"], 4);

        reg(&["add", &k, "/v", "S", "/t", "REG_SZ", "/d", "hello", "/f"]);
        let r = one(&mut mon);
        assert_eq!((r["event"].as_str(), r["value_type"].as_str(), r["value_data"].as_str(), r["value"].as_str()), (Some("added"), Some("REG_SZ"), Some("hello"), Some("hello")));

        reg(&["add", &k, "/v", "D", "/t", "REG_DWORD", "/d", "7", "/f"]);
        let r = one(&mut mon);
        assert_eq!((r["event"].as_str(), r["value_name"].as_str(), r["value_data"].as_str()), (Some("modified"), Some("D"), Some("7")));
        assert_eq!((r["old_value"].as_str(), r["new_value"].as_str()), (Some("42"), Some("7")));
        assert!(r["changed_attributes"].as_array().unwrap().contains(&json!("sha256")));
        assert_ne!(r["sha256_before"], r["sha256_after"]);

        reg(&["delete", &k, "/v", "S", "/f"]);
        let r = one(&mut mon);
        assert_eq!((r["event"].as_str(), r["value_name"].as_str(), r["old_value"].as_str()), (Some("deleted"), Some("S"), Some("hello")));

        // ignored (prefix, other case and hive spelling) and below the recursion level: nothing
        reg(&["add", &format!(r"{ROOT}\Skip\Inner"), "/v", "X", "/d", "1", "/f"]);
        reg(&["add", &format!(r"{ROOT}\A\B\C"), "/v", "V", "/d", "1", "/f"]);
        let ev = mon.scan("1", "t");
        let keys: Vec<&str> = ev.iter().map(|e| e["registry"]["key"].as_str().unwrap()).collect();
        assert_eq!(ev.len(), 2, "{ev:#?}");
        assert!(keys.contains(&&*format!(r"{full}\A")) && keys.contains(&&*format!(r"{full}\A\B")), "{keys:?}");

        // restart: the baseline is on disk, nothing new
        drop(mon);
        let mut mon = open();
        assert!(mon.scan("1", "t").is_empty());

        // the key with its remaining value: the key and the value
        reg(&["delete", &k, "/f"]);
        let mut ev = mon.scan("1", "t");
        ev.sort_by_key(|e| e["registry"]["value_name"].as_str().map(String::from));
        let got: Vec<(&str, &str, Option<&str>)> = ev.iter().map(|e| (e["registry"]["event"].as_str().unwrap(), e["registry"]["key"].as_str().unwrap(), e["registry"]["value_name"].as_str())).collect();
        assert_eq!(got, [("deleted", &*format!(r"{full}\K"), None), ("deleted", &*format!(r"{full}\K"), Some("D"))]);

        reg(&["delete", ROOT, "/f"]);
    }
}
