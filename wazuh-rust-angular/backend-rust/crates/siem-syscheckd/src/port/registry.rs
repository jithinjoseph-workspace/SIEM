//! `syscheckd/src/registry/registry.c` and `registry/events.c` (the registry scan).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use siem_cjson::Json;
use siem_dbsync::ReturnTypeCallback;
use siem_njson::Value;
use windows_sys::Win32::System::Registry::*;

use super::cfmt::{cfmt, A};
use super::config::*;
use super::create_db::{fim_check_restrict, Fim, FIM_ADD, FIM_DELETE, FIM_MODIFICATION};
use super::fimdb::{self, RegKey, RegValue};
use super::{mdebug1, mdebug2, merror, msgs};

const MAX_KEY_LENGTH: usize = 260;
const REG_UNKNOWN: u32 = 12;
const EVENT_TYPES: [&str; 3] = ["added", "deleted", "modified"];
/// The registry scan has its own `_base_line`.
static BASE_LINE: AtomicBool = AtomicBool::new(false);

/// `VALUE_TYPE[t]`
fn value_type(t: i32) -> Option<&'static str> {
    fimdb::registry_type_text(t as u32)
}

fn arch_str(arch: i32) -> &'static str {
    if arch == ARCH_32BIT {
        "[x32]"
    } else {
        "[x64]"
    }
}

/// `OS_SHA1_strings`
fn sha1_strings(parts: &[&[u8]]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

/// `cJSON_AddStringToObject(o, k, v)`: nothing is added for a NULL string.
fn add_s(o: &mut Json, k: &str, v: Option<&[u8]>) {
    if let Some(v) = v {
        o.add(k, Json::string(v));
    }
}

/// `cJSON_AddItemToObject(o, k, cJSON_Parse(v))`
fn add_parsed(o: &mut Json, k: &str, v: Option<&[u8]>) {
    if let Some(j) = v.and_then(siem_cjson::parse) {
        o.add(k, j);
    }
}

/// `cJSON_GetStringValue(cJSON_GetObjectItem(j, k))`
fn gs<'a>(j: &'a Json, k: &str) -> Option<&'a [u8]> {
    j.get(k).and_then(|v| v.as_bytes())
}

/// `item->valueint`
fn vi(j: &Json) -> i32 {
    j.as_i32().unwrap_or(0)
}

/// `fim_registry_configuration`
fn fim_registry_configuration(cfg: &SyscheckConfig, key: &[u8], arch: i32) -> Option<usize> {
    let mut top = 0usize;
    let mut ret = None;
    for (i, r) in cfg.registry.iter().flatten().enumerate() {
        if r.arch != arch {
            continue;
        }
        let e = r.entry.as_bytes();
        // w_compare_str
        if !e.is_empty() && e.len() <= key.len() && key.starts_with(e) && top < e.len() {
            ret = Some(i);
            top = e.len();
        }
    }
    if ret.is_none() {
        mdebug2(cfmt(msgs::FIM_CONFIGURATION_NOTFOUND, &[A::S("registry"), A::B(key)]));
    }
    ret
}

fn reg_at(cfg: &SyscheckConfig, i: usize) -> &Registry {
    &cfg.registry.as_ref().expect("registry list")[i]
}

/// `fim_set_root_key`: the root handle and the sub key.
fn fim_set_root_key(full_key: &[u8]) -> Option<(HKEY, &[u8])> {
    let roots: [(&[u8], HKEY); 4] = [
        (b"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE),
        (b"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT),
        (b"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG),
        (b"HKEY_USERS", HKEY_USERS),
    ];
    let (name, h) = roots.into_iter().find(|(n, _)| full_key.starts_with(n))?;
    if full_key.get(name.len()) != Some(&b'\\') {
        return None;
    }
    Some((h, &full_key[name.len() + 1..]))
}

/// `fim_registry_validate_recursion_level`: true when excluded.
fn validate_recursion_level(key: &[u8], c: &Registry) -> bool {
    let parent = c.entry.len();
    if parent > key.len() {
        return true;
    }
    let depth = key[parent..].iter().filter(|&&b| b == PATH_SEP).count() as i32;
    if depth > c.recursion_level {
        mdebug2(cfmt(msgs::FIM_MAX_RECURSION_LEVEL, &[A::I(depth as i64), A::I(c.recursion_level as i64), A::B(key)]));
        return true;
    }
    false
}

/// `fim_registry_validate_ignore`: true when excluded.
fn validate_ignore(cfg: &SyscheckConfig, entry: &[u8], c: &Registry, key: bool) -> bool {
    let (list, regex) = if key { (&cfg.key_ignore, &cfg.key_ignore_regex) } else { (&cfg.value_ignore, &cfg.value_ignore_regex) };
    let kind = if key { "registry" } else { "value" };
    for i in list.iter().flatten() {
        if i.arch != c.arch {
            continue;
        }
        let ib = i.entry.as_bytes();
        // strncasecmp(ignore, entry, strlen(ignore))
        if entry.len() >= ib.len() && entry[..ib.len()].eq_ignore_ascii_case(ib) {
            mdebug2(cfmt(msgs::FIM_REG_IGNORE_ENTRY, &[A::S(kind), A::S(arch_str(i.arch)), A::B(entry), A::S(&i.entry)]));
            return true;
        }
    }
    for r in regex.iter().flatten() {
        if r.arch != c.arch {
            continue;
        }
        if r.regex.is_match_bytes(entry) {
            mdebug2(cfmt(msgs::FIM_REG_IGNORE_SREGEX, &[A::S(kind), A::S(arch_str(r.arch)), A::B(entry), A::S(r.regex.raw())]));
            return true;
        }
    }
    false
}

/// `fim_registry_get_checksum_key`: the size is computed without `:%d`, so the arch is cut off.
fn checksum_key(k: &mut RegKey) {
    let e = |o: &Option<Vec<u8>>| o.clone().unwrap_or_default();
    let s = [e(&k.perm), e(&k.uid), e(&k.gid), e(&k.user_name), e(&k.group_name), (k.mtime as u32).to_string().into_bytes()].join(&b':');
    k.checksum = sha1_strings(&[&s]);
}

/// `fim_registry_get_checksum_value`
fn checksum_value(v: &mut RegValue) {
    let s = format!("{}:{}:{}:{}:{}", v.type_, v.size, v.hash_md5, v.hash_sha1, v.hash_sha256);
    v.checksum = sha1_strings(&[s.as_bytes()]);
}

/// `fim_registry_calculate_hashes`
fn calculate_hashes(v: &mut RegValue, opts: i32, data: &[u8]) {
    use md5::Digest;
    v.hash_md5.clear();
    v.hash_sha1.clear();
    v.hash_sha256.clear();
    if opts & (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM) == 0 {
        return;
    }
    let mut buf: Vec<u8> = Vec::new();
    let wide = |off: usize| -> Vec<u16> { data[off.min(data.len())..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect() };
    match v.type_ {
        1 | 2 => match super::win::wide_to_utf8(&wide(0)) {
            Some(u) => buf = u,
            None => {
                mdebug1("Error converting registry value data to UTF-8.");
                return;
            }
        },
        7 => {
            let w = wide(0);
            let mut i = 0;
            while i < w.len() && w[i] != 0 {
                match super::win::wide_to_utf8(&w[i..]) {
                    Some(u) => buf.extend_from_slice(&u),
                    None => {
                        mdebug1("Error converting registry value data to UTF-8.");
                        return;
                    }
                }
                i += w[i..].iter().position(|&c| c == 0).unwrap_or(w.len() - i) + 1;
            }
        }
        4 => buf = format!("{:08x}", u32::from_le_bytes([data[0], data[1], data[2], data[3]])).into_bytes(),
        _ => {
            for b in data.iter().take(v.size as usize) {
                buf.extend_from_slice(format!("{b:02x}").as_bytes());
            }
        }
    }
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    if opts & CHECK_MD5SUM != 0 {
        v.hash_md5 = hex(&md5::Md5::digest(&buf));
    }
    if opts & CHECK_SHA1SUM != 0 {
        v.hash_sha1 = hex(&sha1::Sha1::digest(&buf));
    }
    if opts & CHECK_SHA256SUM != 0 {
        v.hash_sha256 = hex(&sha2::Sha256::digest(&buf));
    }
}

/// `fim_registry_get_key_data`
fn get_key_data(h: HKEY, path: &[u8], c: &Registry) -> Option<RegKey> {
    let mut k = RegKey { path: path.to_vec(), arch: c.arch, ..Default::default() };
    if c.opts & CHECK_OWNER != 0 {
        let (name, sid) = super::win::get_user(&String::from_utf8_lossy(path), h as _, windows_sys::Win32::Security::Authorization::SE_REGISTRY_KEY);
        k.user_name = Some(name.into_bytes());
        k.uid = Some(sid.into_bytes());
    }
    if c.opts & CHECK_GROUP != 0 {
        let (name, sid) = super::win::get_registry_group(h as _);
        k.group_name = Some(name.into_bytes());
        k.gid = Some(sid.into_bytes());
    }
    if c.opts & CHECK_PERM != 0 {
        match super::win::get_registry_permissions(h) {
            Ok(mut acl) => {
                super::win::decode_win_acl_json(&mut acl);
                k.perm = Some(acl.print_unformatted());
                k.perm_json = Some(acl);
            }
            Err(e) => {
                mdebug1(cfmt(msgs::FIM_EXTRACT_PERM_FAIL, &[A::B(path), A::I(e as i64)]));
                return None;
            }
        }
    }
    if c.opts & CHECK_MTIME != 0 {
        k.mtime = super::win::get_registry_mtime(h) as i64;
    }
    k.last_event = now();
    checksum_key(&mut k);
    Some(k)
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `fim_registry_key_attributes_json`
fn key_attributes_json(ev: &Json, k: Option<&RegKey>, c: &Registry) -> Json {
    let mut a = Json::object();
    a.add("type", Json::string("registry_key"));
    match k {
        Some(k) => {
            if c.opts & CHECK_PERM != 0 {
                add_parsed(&mut a, "perm", k.perm.as_deref());
            }
            if c.opts & CHECK_OWNER != 0 {
                add_s(&mut a, "uid", k.uid.as_deref());
                add_s(&mut a, "user_name", k.user_name.as_deref());
            }
            if c.opts & CHECK_GROUP != 0 {
                add_s(&mut a, "gid", k.gid.as_deref());
                add_s(&mut a, "group_name", k.group_name.as_deref());
            }
            if c.opts & CHECK_MTIME != 0 {
                a.add("mtime", Json::number(k.mtime as f64));
            }
            if !k.checksum.is_empty() {
                a.add("checksum", Json::string(&k.checksum));
            }
        }
        None => {
            if c.opts & CHECK_PERM != 0 && ev.get("perm").is_some() {
                add_parsed(&mut a, "perm", gs(ev, "perm"));
            }
            if c.opts & CHECK_OWNER != 0 {
                add_s(&mut a, "uid", gs(ev, "uid"));
                add_s(&mut a, "user_name", gs(ev, "user_name"));
            }
            if c.opts & CHECK_GROUP != 0 {
                add_s(&mut a, "gid", gs(ev, "gid"));
                add_s(&mut a, "group_name", gs(ev, "group_name"));
            }
            if c.opts & CHECK_MTIME != 0 {
                if let Some(m) = ev.get("mtime") {
                    a.add("mtime", Json::number(vi(m) as f64));
                }
            }
            if ev.get("checksum").is_some() {
                add_s(&mut a, "checksum", gs(ev, "checksum"));
            }
        }
    }
    a
}

/// `fim_registry_value_attributes_json`
fn value_attributes_json(ev: &Json, v: Option<&RegValue>, c: &Registry) -> Json {
    let mut a = Json::object();
    a.add("type", Json::string("registry_value"));
    match v {
        Some(v) => {
            if c.opts & CHECK_TYPE != 0 {
                add_s(&mut a, "value_type", value_type(v.type_ as i32).map(str::as_bytes));
            }
            if c.opts & CHECK_SIZE != 0 {
                a.add("size", Json::number(v.size as f64));
            }
            for (bit, k, h) in [(CHECK_MD5SUM, "hash_md5", &v.hash_md5), (CHECK_SHA1SUM, "hash_sha1", &v.hash_sha1), (CHECK_SHA256SUM, "hash_sha256", &v.hash_sha256)] {
                if c.opts & bit != 0 {
                    a.add(k, Json::string(h));
                }
            }
            if !v.checksum.is_empty() {
                a.add("checksum", Json::string(&v.checksum));
            }
        }
        None => {
            if let Some(t) = ev.get("type") {
                if c.opts & CHECK_TYPE != 0 {
                    add_s(&mut a, "value_type", value_type(vi(t)).map(str::as_bytes));
                }
            }
            if c.opts & CHECK_SIZE != 0 {
                if let Some(s) = ev.get("size") {
                    a.add("size", Json::number(vi(s) as f64));
                }
            }
            for (bit, k) in [(CHECK_MD5SUM, "hash_md5"), (CHECK_SHA1SUM, "hash_sha1"), (CHECK_SHA256SUM, "hash_sha256")] {
                if c.opts & bit != 0 && ev.get(k).is_some() {
                    add_s(&mut a, k, gs(ev, k));
                }
            }
            if ev.get("checksum").is_some() {
                add_s(&mut a, "checksum", gs(ev, "checksum"));
            }
        }
    }
    a
}

/// `fim_calculate_dbsync_difference_key`
fn difference_key(k: &RegKey, c: &Registry, old: &Json, ca: &mut Json, oa: &mut Json) {
    let push = |ca: &mut Json, s: &str| {
        ca.push(Json::string(s));
    };
    oa.add("type", Json::string("registry_key"));
    if c.opts & CHECK_PERM != 0 {
        if old.get("perm").is_some() {
            add_parsed(oa, "perm", gs(old, "perm"));
            push(ca, "permission");
        } else {
            add_parsed(oa, "perm", k.perm.as_deref());
        }
    }
    if c.opts & CHECK_OWNER != 0 {
        if old.get("uid").is_some() {
            add_s(oa, "uid", gs(old, "uid"));
            push(ca, "uid");
        } else {
            add_s(oa, "uid", k.uid.as_deref());
        }
        if old.get("user_name").is_some() {
            let u = gs(old, "user_name");
            add_s(oa, "user_name", u);
            // AD might fail to solve the user name
            if u.is_some_and(|u| !u.is_empty()) {
                push(ca, "user_name");
            }
        } else {
            add_s(oa, "user_name", k.user_name.as_deref());
        }
    }
    if c.opts & CHECK_GROUP != 0 {
        if old.get("gid").is_some() {
            add_s(oa, "gid", gs(old, "gid"));
            push(ca, "gid");
        } else {
            // the C adds the uid here
            add_s(oa, "gid", k.uid.as_deref());
        }
        if old.get("group_name").is_some() {
            add_s(oa, "group_name", gs(old, "group_name"));
            push(ca, "group_name");
        } else {
            add_s(oa, "group_name", k.group_name.as_deref());
        }
    }
    if c.opts & CHECK_MTIME != 0 {
        match old.get("mtime") {
            Some(m) => {
                oa.add("mtime", Json::number(vi(m) as f64));
                push(ca, "mtime");
            }
            None => {
                oa.add("mtime", Json::number(k.mtime as f64));
            }
        }
    }
    if !k.checksum.is_empty() {
        oa.add("checksum", Json::string(&k.checksum));
    }
}

/// `fim_calculate_dbsync_difference_value`
fn difference_value(v: &RegValue, c: &Registry, old: &Json, ca: &mut Json, oa: &mut Json) {
    let push = |ca: &mut Json, s: &str| {
        ca.push(Json::string(s));
    };
    oa.add("type", Json::string("registry_value"));
    if c.opts & CHECK_SIZE != 0 {
        match old.get("size") {
            Some(s) => {
                oa.add("size", Json::number(vi(s) as f64));
                push(ca, "size");
            }
            None => {
                oa.add("size", Json::number(v.size as f64));
            }
        }
    }
    if c.opts & CHECK_TYPE != 0 {
        match old.get("value_type") {
            Some(t) => {
                add_s(oa, "value_type", value_type(vi(t)).map(str::as_bytes));
                push(ca, "value_type");
            }
            None => add_s(oa, "value_type", value_type(v.type_ as i32).map(str::as_bytes)),
        }
    }
    for (bit, k, label, h) in [
        (CHECK_MD5SUM, "hash_md5", "md5", &v.hash_md5),
        (CHECK_SHA1SUM, "hash_sha1", "sha1", &v.hash_sha1),
        (CHECK_SHA256SUM, "hash_sha256", "sha256", &v.hash_sha256),
    ] {
        if c.opts & bit != 0 {
            if old.get(k).is_some() {
                add_s(oa, k, gs(old, k));
                push(ca, label);
            } else {
                oa.add(k, Json::string(h));
            }
        }
    }
}

/// A queued transaction callback and the entry being written.
enum Pending {
    Key(ReturnTypeCallback, Json, Option<RegKey>),
    Value(ReturnTypeCallback, Json, Option<(RegValue, Option<Vec<u8>>)>),
}

struct Scan<'a> {
    fim: &'a Fim,
    cfg: &'a SyscheckConfig,
    key_txn: Option<siem_dbsync::DBSyncTxn>,
    val_txn: Option<siem_dbsync::DBSyncTxn>,
    cur_key: Arc<Mutex<Option<RegKey>>>,
    cur_val: Arc<Mutex<Option<(RegValue, Option<Vec<u8>>)>>>,
    pending: Arc<Mutex<Vec<Pending>>>,
    key_type: i32,
    val_type: i32,
}

impl Scan<'_> {
    /// Runs the queued callbacks (the C runs them inside dbsync's call).
    fn drain(&mut self) {
        let items = std::mem::take(&mut *self.pending.lock().unwrap());
        for p in items {
            match p {
                Pending::Key(t, j, k) => self.key_callback(t, &j, k.as_ref()),
                Pending::Value(t, j, v) => self.value_callback(t, &j, v),
            }
        }
    }

    /// `registry_key_transaction_callback`
    fn key_callback(&mut self, t: ReturnTypeCallback, res: &Json, key: Option<&RegKey>) {
        if !BASE_LINE.load(Ordering::SeqCst) {
            return;
        }
        let (path, arch, hash): (Vec<u8>, i32, Vec<u8>) = match key {
            None => {
                let (Some(p), Some(a), Some(h)) = (res.get("path"), res.get("arch"), res.get("hash_full_path")) else { return };
                let a = if a.as_bytes() == Some(b"[x32]") { ARCH_32BIT } else { ARCH_64BIT };
                (p.as_bytes().unwrap_or(b"").to_vec(), a, h.as_bytes().unwrap_or(b"").to_vec())
            }
            Some(k) => (k.path.clone(), k.arch, k.hash_full_path.clone().into_bytes()),
        };
        let Some(ci) = fim_registry_configuration(self.cfg, &path, arch) else { return };
        let c = reg_at(self.cfg, ci);
        self.key_type = match t {
            ReturnTypeCallback::Inserted => FIM_ADD,
            ReturnTypeCallback::Modified => FIM_MODIFICATION,
            ReturnTypeCallback::Deleted => {
                if c.opts & CHECK_SEECHANGES != 0 {
                    self.fim.fim_diff_process_delete_registry(&path, arch);
                }
                FIM_DELETE
            }
            ReturnTypeCallback::MaxRows => {
                mdebug1(cfmt("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", &[A::B(&path)]));
                return;
            }
            _ => return,
        };
        let mut data = Json::object();
        data.add("path", Json::string(&path));
        data.add("index", Json::string(&hash));
        data.add("version", Json::number(3.0));
        data.add("mode", Json::string("scheduled"));
        data.add("type", Json::string(EVENT_TYPES[self.key_type as usize]));
        data.add("arch", Json::string(arch_str(arch)));
        match res.get("last_event") {
            Some(ts) => data.add("timestamp", Json::number(vi(ts) as f64)),
            None => data.add("timestamp", Json::number(key.map(|k| k.last_event).unwrap_or(0) as f64)),
        };
        data.add("attributes", key_attributes_json(res, key, c));
        if let (Some(old), Some(k)) = (res.get("old"), key) {
            let mut oa = Json::object();
            let mut ca = Json::array();
            difference_key(k, c, old, &mut ca, &mut oa);
            let empty = ca.len() == 0;
            data.add("old_attributes", oa);
            data.add("changed_attributes", ca);
            if empty {
                mdebug2(cfmt(msgs::FIM_EMPTY_CHANGED_ATTRIBUTES, &[A::B(&path)]));
                return;
            }
        }
        if let Some(tag) = &c.tag {
            data.add("tags", Json::string(tag));
        }
        let mut ev = Json::object();
        ev.add("type", Json::string("event"));
        ev.add("data", data);
        self.fim.send_syscheck_msg(&ev);
    }

    /// `registry_value_transaction_callback`
    fn value_callback(&mut self, t: ReturnTypeCallback, res: &Json, val: Option<(RegValue, Option<Vec<u8>>)>) {
        if !BASE_LINE.load(Ordering::SeqCst) {
            return;
        }
        let (value, diff) = match val {
            Some((v, d)) => (Some(v), d),
            None => (None, None),
        };
        let (path, arch, name, hash): (Vec<u8>, i32, Vec<u8>, Vec<u8>) = match &value {
            None => {
                let (Some(p), Some(a), Some(n), Some(h)) = (res.get("path"), res.get("arch"), res.get("name"), res.get("hash_full_path")) else { return };
                let a = if a.as_bytes() == Some(b"[x32]") { ARCH_32BIT } else { ARCH_64BIT };
                (p.as_bytes().unwrap_or(b"").to_vec(), a, n.as_bytes().unwrap_or(b"").to_vec(), h.as_bytes().unwrap_or(b"").to_vec())
            }
            Some(v) => (v.path.clone(), v.arch, v.name.clone(), v.hash_full_path.clone().into_bytes()),
        };
        let Some(ci) = fim_registry_configuration(self.cfg, &path, arch) else { return };
        let c = reg_at(self.cfg, ci);
        self.val_type = match t {
            ReturnTypeCallback::Inserted => FIM_ADD,
            ReturnTypeCallback::Modified => FIM_MODIFICATION,
            ReturnTypeCallback::Deleted => {
                if c.opts & CHECK_SEECHANGES != 0 {
                    self.fim.fim_diff_process_delete_value(&path, &name, arch);
                }
                FIM_DELETE
            }
            ReturnTypeCallback::MaxRows => {
                mdebug1(cfmt("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", &[A::B(&path)]));
                return;
            }
            _ => return,
        };
        let mut data = Json::object();
        data.add("path", Json::string(&path));
        data.add("index", Json::string(&hash));
        data.add("version", Json::number(3.0));
        data.add("mode", Json::string("scheduled"));
        data.add("type", Json::string(EVENT_TYPES[self.val_type as usize]));
        data.add("arch", Json::string(arch_str(arch)));
        data.add("value_name", Json::string(&name));
        match res.get("last_event") {
            Some(ts) => data.add("timestamp", Json::number(vi(ts) as f64)),
            None => data.add("timestamp", Json::number(value.as_ref().map(|v| v.last_event).unwrap_or(0) as f64)),
        };
        data.add("attributes", value_attributes_json(res, value.as_ref(), c));
        if let (Some(old), Some(v)) = (res.get("old"), &value) {
            let mut oa = Json::object();
            let mut ca = Json::array();
            difference_value(v, c, old, &mut ca, &mut oa);
            let empty = ca.len() == 0;
            data.add("old_attributes", oa);
            data.add("changed_attributes", ca);
            if empty {
                mdebug2(cfmt(msgs::FIM_EMPTY_CHANGED_ATTRIBUTES, &[A::B(&path)]));
                return;
            }
        }
        if let Some(tag) = &c.tag {
            data.add("tags", Json::string(tag));
        }
        if let (Some(d), ReturnTypeCallback::Modified) = (&diff, t) {
            data.add("content_changes", Json::string(d));
        }
        let mut ev = Json::object();
        ev.add("type", Json::string("event"));
        ev.add("data", data);
        self.fim.send_syscheck_msg(&ev);
    }

    /// `fim_db_transaction_sync_row` of a key or a value, then its callbacks.
    fn sync_row(&mut self, item: &Value, is_key: bool) {
        let Some(db) = fimdb::instance() else { return };
        let txn = if is_key { &self.key_txn } else { &self.val_txn };
        let r = match txn {
            Some(t) => db.transaction_sync_row(t, item),
            // DBSyncTxn(NULL).syncTxnRow throws
            None => {
                db.log(fimdb::LogLevel::Error, "Invalid handle value.");
                fimdb::FimDbError::Err
            }
        };
        if r != fimdb::FimDbError::Ok {
            if is_key {
                merror(format!("Dbsync registry transaction failed due to {}", r as i32));
            } else {
                mdebug2(format!("dbsync transaction failed due to {}", r as i32));
            }
        }
        self.drain();
    }

    /// `fim_read_values`
    fn read_values(&mut self, h: HKEY, path: &[u8], arch: i32, count: u32, max_name: u32, max_data: u32) {
        let mut name_buf = vec![0u16; max_name as usize + 1];
        // reused for every value, as in the C (os_calloc(max_value_data_length + 4))
        let mut data_buf = vec![0u8; max_data as usize + 4];
        for i in 0..count {
            let mut name_size = max_name + 1;
            let mut data_size = max_data;
            let mut data_type = 0u32;
            let Some(ci) = fim_registry_configuration(self.cfg, path, arch) else { return };
            // SAFETY: buffers of the sizes passed.
            let rc = unsafe { RegEnumValueW(h, i, name_buf.as_mut_ptr(), &mut name_size, std::ptr::null(), &mut data_type, data_buf.as_mut_ptr(), &mut data_size) };
            if rc != 0 {
                break;
            }
            let Some(name) = super::win::wide_to_utf8(&name_buf) else {
                mdebug1("Failed to convert value name to UTF-8");
                continue;
            };
            let c = reg_at(self.cfg, ci);
            let mut v = RegValue {
                path: path.to_vec(),
                arch,
                name,
                type_: if data_type <= 11 { data_type } else { REG_UNKNOWN },
                size: data_size as u64,
                last_event: now(),
                ..Default::default()
            };
            let mut value_path = path.to_vec();
            value_path.push(b'\\');
            value_path.extend_from_slice(&v.name);
            if validate_ignore(self.cfg, &value_path, c, false) {
                continue;
            }
            if fim_check_restrict(&v.name, c.restrict_value.as_ref()) {
                continue;
            }
            v.hash_full_path = sha1_strings(&[b"value", arch_str(arch).as_bytes(), &v.path, &v.name]);
            calculate_hashes(&mut v, c.opts, &data_buf);
            checksum_value(&mut v);
            let diff = if c.opts & CHECK_SEECHANGES != 0 { self.fim.fim_registry_value_diff(self.cfg, &v.path, &v.name, &data_buf, v.type_, c) } else { None };
            let item = fimdb::reg_value_json(&v, true);
            *self.cur_val.lock().unwrap() = Some((v, diff));
            self.sync_row(&item, false);
            *self.cur_val.lock().unwrap() = None;
        }
    }

    /// `fim_open_key`
    fn open_key(&mut self, root: HKEY, full_key: &[u8], sub_key: &[u8], arch: i32, parent: Option<usize>) {
        let Some(ci) = fim_registry_configuration(self.cfg, full_key, arch) else { return };
        if parent.is_some_and(|p| p != ci) {
            return;
        }
        let c = reg_at(self.cfg, ci);
        if validate_recursion_level(full_key, c) || validate_ignore(self.cfg, full_key, c, true) {
            return;
        }
        let access = KEY_READ | if arch == ARCH_32BIT { KEY_WOW64_32KEY } else { KEY_WOW64_64KEY };
        let Some(w) = super::win::auto_to_wide(sub_key) else {
            mdebug1(cfmt("Failed to convert registry key to wide character: '%s'", &[A::B(sub_key)]));
            return;
        };
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated wide sub key.
        let rc = unsafe { RegOpenKeyExW(root, w.as_ptr(), 0, access, &mut h) };
        if rc != 0 {
            mdebug1(cfmt(msgs::FIM_REG_OPEN, &[A::B(sub_key), A::S(arch_str(arch)), A::I(rc as i64)]));
            return;
        }
        let (mut subkeys, mut values, mut max_name, mut max_data) = (0u32, 0u32, 0u32, 0u32);
        let n = std::ptr::null_mut();
        // SAFETY: the counts and sizes of an open key.
        let rc = unsafe { RegQueryInfoKeyA(h, std::ptr::null_mut(), n, n, &mut subkeys, n, n, &mut values, &mut max_name, &mut max_data, n, std::ptr::null_mut()) };
        if rc != 0 {
            // SAFETY: opened above.
            unsafe { RegCloseKey(h) };
            return;
        }
        for i in 0..subkeys {
            let mut name = [0u16; MAX_KEY_LENGTH + 1];
            let mut size = (MAX_KEY_LENGTH + 1) as u32;
            // SAFETY: a buffer of `size` wide chars.
            let rc = unsafe { RegEnumKeyExW(h, i, name.as_mut_ptr(), &mut size, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
            if rc != 0 {
                continue;
            }
            let Some(sub) = super::win::wide_to_utf8(&name) else {
                mdebug1("Failed to convert sub key name to UTF-8");
                continue;
            };
            let mut new_full = full_key.to_vec();
            new_full.push(b'\\');
            new_full.extend_from_slice(&sub);
            let at = new_full.iter().position(|&b| b == b'\\').map(|p| p + 1).unwrap_or(new_full.len());
            let new_sub = new_full[at..].to_vec();
            self.open_key(root, &new_full, &new_sub, arch, Some(ci));
        }
        let c = reg_at(self.cfg, ci);
        if fim_check_restrict(full_key, c.restrict_key.as_ref()) {
            // the C leaks the handle here
            // SAFETY: opened above.
            unsafe { RegCloseKey(h) };
            return;
        }
        let Some(mut k) = get_key_data(h, full_key, c) else {
            // SAFETY: opened above (the C leaks it).
            unsafe { RegCloseKey(h) };
            return;
        };
        k.hash_full_path = sha1_strings(&[b"key", arch_str(arch).as_bytes(), &k.path]);
        let item = fimdb::reg_key_json(&k, true);
        let (kpath, karch) = (k.path.clone(), k.arch);
        *self.cur_key.lock().unwrap() = Some(k);
        self.sync_row(&item, true);
        if values != 0 {
            self.read_values(h, &kpath, karch, values, max_name, max_data);
        }
        // SAFETY: opened above.
        unsafe { RegCloseKey(h) };
    }
}

/// `fim_registry_scan`
pub fn fim_registry_scan(fim: &Fim) {
    let Some(db) = fimdb::instance() else { return };
    let cur_key: Arc<Mutex<Option<RegKey>>> = Arc::new(Mutex::new(None));
    let cur_val: Arc<Mutex<Option<(RegValue, Option<Vec<u8>>)>>> = Arc::new(Mutex::new(None));
    let pending: Arc<Mutex<Vec<Pending>>> = Arc::new(Mutex::new(Vec::new()));
    let (k2, p2) = (cur_key.clone(), pending.clone());
    let kcb: siem_dbsync::ResultCallback = Arc::new(move |t: ReturnTypeCallback, j: &Value| {
        if let Some(cj) = fimdb::to_cjson(j) {
            p2.lock().unwrap().push(Pending::Key(t, cj, k2.lock().unwrap().clone()));
        }
        Ok(())
    });
    let (v2, p3) = (cur_val.clone(), pending.clone());
    let vcb: siem_dbsync::ResultCallback = Arc::new(move |t: ReturnTypeCallback, j: &Value| {
        if let Some(cj) = fimdb::to_cjson(j) {
            p3.lock().unwrap().push(Pending::Value(t, cj, v2.lock().unwrap().clone()));
        }
        Ok(())
    });
    let key_txn = db.transaction_start(fimdb::FIMDB_REGISTRY_KEY_TXN_TABLE, kcb);
    let val_txn = db.transaction_start(fimdb::FIMDB_REGISTRY_VALUE_TXN_TABLE, vcb);
    mdebug1(msgs::FIM_WINREGISTRY_START);
    let mut invalid = Vec::new();
    {
        let cfg = fim.sk.cfg.read_recursive();
        let mut s = Scan { fim, cfg: &cfg, key_txn, val_txn, cur_key, cur_val, pending, key_type: 0, val_type: 0 };
        for (i, r) in cfg.registry.iter().flatten().enumerate() {
            if r.entry.is_empty() {
                continue;
            }
            mdebug2(cfmt(msgs::FIM_READING_REGISTRY, &[A::S(if r.arch == ARCH_64BIT { "[x64] " } else { "[x32] " }), A::S(&r.entry)]));
            let Some((root, sub)) = fim_set_root_key(r.entry.as_bytes()) else {
                mdebug1(cfmt(msgs::FIM_INV_REG, &[A::S(&r.entry), A::S(if r.arch == ARCH_64BIT { "[x64] " } else { "[x32]" })]));
                invalid.push(i);
                continue;
            };
            s.open_key(root, r.entry.as_bytes(), sub, r.arch, None);
        }
        // deleted values first, then keys (no current entry)
        let (kt, vt) = (s.key_txn.take(), s.val_txn.take());
        let p = s.pending.clone();
        let del = |is_key: bool| {
            let p = p.clone();
            move |t: ReturnTypeCallback, j: &Value| -> siem_dbsync::R {
                if let Some(cj) = fimdb::to_cjson(j) {
                    p.lock().unwrap().push(if is_key { Pending::Key(t, cj, None) } else { Pending::Value(t, cj, None) });
                }
                Ok(())
            }
        };
        if let Some(vt) = vt {
            db.transaction_deleted_rows(vt, &mut del(false));
        }
        s.drain();
        if let Some(kt) = kt {
            db.transaction_deleted_rows(kt, &mut del(true));
        }
        s.drain();
    }
    if !invalid.is_empty() {
        // "Ignored entries are zeroed"
        let mut cfg = fim.sk.cfg.write();
        if let Some(reg) = cfg.registry.as_mut() {
            for i in invalid {
                reg[i].entry.clear();
            }
        }
    }
    mdebug1(msgs::FIM_WINREGISTRY_ENDED);
    BASE_LINE.store(true, Ordering::SeqCst);
}
