//! `syscheckd/src/create_db.c` (the file scan: `fim_scan`, `fim_checker`,
//! `fim_directory`, `fim_file`, `fim_get_data`, the event JSON, the DB
//! state alerts) and the message helpers of `run_check.c`.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use siem_cjson::Json;
use siem_dbsync::ReturnTypeCallback;
use siem_njson::Value;

use super::cfmt::{cfmt, A};
use super::config::*;
use super::fimdb::{self, FileData, FimDbError, FIM_REALTIME, FIM_SCHEDULED, FIM_WHODATA};
use super::{is_debug, mdebug1, mdebug2, merror, minfo, msgs, mwarn};

pub const FIM_ADD: i32 = 0;
pub const FIM_DELETE: i32 = 1;
pub const FIM_MODIFICATION: i32 = 2;
const EVENT_TYPES: [&str; 3] = ["added", "deleted", "modified"];
const EVENT_MODES: [&str; 3] = ["scheduled", "realtime", "whodata"];

pub const SYSCHECK_MQ: u8 = b'8';
pub const DBSYNC_MQ: u8 = b'5';
pub const LOCALFILE_MQ: u8 = b'1';
/// `SYSCHECK` location
pub const SYSCHECK: &str = "syscheck";
#[cfg(windows)]
pub const DIFF_DIR: &str = "queue/diff";
#[cfg(unix)]
pub const DIFF_DIR: &str = "queue/diff";

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

/// `whodata_evt` (Windows fields)
#[derive(Clone, Debug, Default)]
pub struct WhodataEvt {
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub process_name: Option<String>,
    pub path: Vec<u8>,
    pub process_id: u64,
    pub mask: u32,
    pub scan_directory: u8,
}

/// `event_data_t`
#[derive(Clone, Debug, Default)]
pub struct EventData {
    pub mode: i32,
    pub type_: i32,
    pub report_event: bool,
    pub w_evt: Option<WhodataEvt>,
    #[cfg(windows)]
    pub statbuf: super::win::Stat,
}

/// `fim_state_db`
#[derive(Clone, Copy, PartialEq, Eq)]
enum DbState {
    Empty,
    Normal,
    P80,
    P90,
    Full,
}

/// The module state the scan shares with the other threads.
pub struct Fim {
    pub sk: Arc<super::syscheck::Syscheck>,
    base_line: AtomicBool,
    scan_mutex: Mutex<()>,
    db_states: Mutex<[DbState; 3]>,
    fps: Mutex<(u32, i64)>,
    n_msg_sent: AtomicI32,
    sync_eps: Mutex<i64>,
    pub shutdown: AtomicBool,
    /// `SendMSGPredicated(queue, msg, location, mq, fim_shutdown_process_on)`: < 0 on error.
    pub send: Box<dyn Fn(u8, &str, &[u8]) -> i32 + Send + Sync>,
    /// `syscheck.diff_folder_size`, `comp_estimation_perc`, `disk_quota_full_msg`
    pub diff: Mutex<super::diff::DiffState>,
}

/// `os_sha1` of a string
fn sha1_hex(b: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn bstr(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `fim_get_checksum`
pub fn fim_get_checksum(d: &mut FileData) {
    let e = |o: &Option<Vec<u8>>| o.as_deref().unwrap_or(b"").to_vec();
    let s = [
        d.size.to_string().into_bytes(),
        e(&d.perm),
        e(&d.attributes),
        e(&d.uid),
        e(&d.gid),
        e(&d.user_name),
        e(&d.group_name),
        d.mtime.to_string().into_bytes(),
        d.inode.to_string().into_bytes(),
        d.hash_md5.clone().into_bytes(),
        d.hash_sha1.clone().into_bytes(),
        d.hash_sha256.clone().into_bytes(),
    ]
    .join(&b':');
    d.checksum = sha1_hex(&s);
}

/// The perm string as cJSON (Windows stores the ACL JSON as text).
fn perm_value(perm: Option<&[u8]>) -> Json {
    #[cfg(windows)]
    {
        return perm.and_then(siem_cjson::parse).unwrap_or(Json::Null);
    }
    #[cfg(unix)]
    Json::string(perm.unwrap_or(b""))
}

/// `fim_attributes_json`
pub fn fim_attributes_json(d: &FileData) -> Json {
    let mut a = Json::object();
    a.add("type", Json::string("file"));
    if d.options & CHECK_SIZE != 0 {
        a.add("size", Json::number(d.size as f64));
    }
    if d.options & CHECK_PERM != 0 {
        a.add("perm", perm_value(d.perm.as_deref()));
    }
    let nz = |o: &Option<Vec<u8>>| o.as_ref().filter(|v| !v.is_empty()).cloned();
    if d.options & CHECK_OWNER != 0 {
        if let Some(u) = nz(&d.uid) {
            a.add("uid", Json::string(u));
        }
    }
    if d.options & CHECK_GROUP != 0 {
        if let Some(g) = nz(&d.gid) {
            a.add("gid", Json::string(g));
        }
    }
    if let Some(u) = nz(&d.user_name) {
        a.add("user_name", Json::string(u));
    }
    if let Some(g) = nz(&d.group_name) {
        a.add("group_name", Json::string(g));
    }
    if d.options & CHECK_INODE != 0 {
        a.add("inode", Json::string(d.inode.to_string()));
    }
    if d.options & CHECK_MTIME != 0 {
        a.add("mtime", Json::number(d.mtime as f64));
    }
    if d.options & CHECK_MD5SUM != 0 {
        a.add("hash_md5", Json::string(&d.hash_md5));
    }
    if d.options & CHECK_SHA1SUM != 0 {
        a.add("hash_sha1", Json::string(&d.hash_sha1));
    }
    if d.options & CHECK_SHA256SUM != 0 {
        a.add("hash_sha256", Json::string(&d.hash_sha256));
    }
    if cfg!(windows) && d.options & CHECK_ATTRS != 0 {
        a.add("attributes", Json::string(d.attributes.as_deref().unwrap_or(b"")));
    }
    if !d.checksum.is_empty() {
        a.add("checksum", Json::string(&d.checksum));
    }
    a
}

/// `fim_calculate_dbsync_difference`
fn fim_calculate_dbsync_difference(d: &FileData, changed: &Json, old: &mut Json, ca: &mut Json) {
    old.add("type", Json::string("file"));
    let gs = |k: &str| changed.get(k).and_then(|v| v.as_bytes()).map(|b| b.to_vec());
    let push = |ca: &mut Json, n: &str| {
        ca.push(Json::string(n));
    };
    if d.options & CHECK_SIZE != 0 {
        match changed.get("size") {
            Some(v) => {
                old.add("size", Json::number(v.as_i32().unwrap_or(0) as f64));
                push(ca, "size");
            }
            None => {
                old.add("size", Json::number(d.size as f64));
            }
        }
    }
    if d.options & CHECK_PERM != 0 {
        match changed.get("perm") {
            Some(v) => {
                old.add("perm", perm_value(v.as_bytes()));
                push(ca, "permission");
            }
            None => {
                old.add("perm", perm_value(d.perm.as_deref()));
            }
        }
    }
    for (bit, k, label, val) in [(CHECK_OWNER, "uid", "uid", &d.uid), (CHECK_GROUP, "gid", "gid", &d.gid)] {
        if d.options & bit != 0 {
            if changed.get(k).is_some() {
                old.add_str(k, gs(k).as_deref().map(|b| std::str::from_utf8(b).unwrap_or("")));
                push(ca, label);
            } else {
                old.add_str(k, val.as_deref().map(|b| std::str::from_utf8(b).unwrap_or("")));
            }
        }
    }
    for (k, val) in [("user_name", &d.user_name), ("group_name", &d.group_name)] {
        if val.is_some() {
            if changed.get(k).is_some() {
                if let Some(v) = gs(k) {
                    old.add(k, Json::string(v));
                }
                push(ca, k);
            } else if let Some(v) = val {
                old.add(k, Json::string(v));
            }
        }
    }
    if d.options & CHECK_INODE != 0 {
        match changed.get("inode") {
            Some(v) if v.is_string() => {
                old.add("inode", v.clone());
                push(ca, "inode");
            }
            Some(_) => mwarn(msgs::FIM_WARN_INODE_WRONG_TYPE),
            None => {
                old.add("inode", Json::string(d.inode.to_string()));
            }
        }
    }
    if d.options & CHECK_MTIME != 0 {
        match changed.get("mtime") {
            Some(v) => {
                old.add("mtime", Json::number(v.as_i32().unwrap_or(0) as f64));
                push(ca, "mtime");
            }
            None => {
                old.add("mtime", Json::number(d.mtime as f64));
            }
        }
    }
    for (bit, k, label, val) in [
        (CHECK_MD5SUM, "hash_md5", "md5", &d.hash_md5),
        (CHECK_SHA1SUM, "hash_sha1", "sha1", &d.hash_sha1),
        (CHECK_SHA256SUM, "hash_sha256", "sha256", &d.hash_sha256),
    ] {
        if d.options & bit != 0 {
            if let Some(v) = changed.get(k) {
                if let Some(b) = v.as_bytes() {
                    old.add(k, Json::string(b));
                }
                push(ca, label);
            } else {
                old.add(k, Json::string(val));
            }
        }
    }
    if cfg!(windows) && d.options & CHECK_ATTRS != 0 {
        if let Some(v) = changed.get("attributes") {
            if let Some(b) = v.as_bytes() {
                old.add("attributes", Json::string(b));
            }
            push(ca, "attributes");
        } else if let Some(a) = &d.attributes {
            old.add("attributes", Json::string(a));
        }
    }
    if !d.checksum.is_empty() {
        match changed.get("checksum").and_then(|v| v.as_bytes()) {
            Some(b) => {
                old.add("checksum", Json::string(b));
            }
            None => {
                old.add("checksum", Json::string(&d.checksum));
            }
        }
    }
}

/// `dbsync_attributes_json`
fn dbsync_attributes_json(ev: &Json, options: i32) -> Json {
    let mut a = Json::object();
    a.add("type", Json::string("file"));
    let nz = |k: &str| ev.get(k).and_then(|v| v.as_bytes()).filter(|b| !b.is_empty()).map(|b| b.to_vec());
    if options & CHECK_SIZE != 0 {
        if let Some(v) = ev.get("size") {
            a.add("size", Json::number(v.as_i32().unwrap_or(0) as f64));
        }
    }
    if options & CHECK_PERM != 0 {
        if let Some(v) = ev.get("perm") {
            a.add("perm", perm_value(v.as_bytes()));
        }
    }
    if options & CHECK_OWNER != 0 {
        if let Some(u) = nz("uid") {
            a.add("uid", Json::string(u));
        }
    }
    if options & CHECK_GROUP != 0 {
        if let Some(g) = nz("gid") {
            a.add("gid", Json::string(g));
        }
    }
    if let Some(u) = nz("user_name") {
        a.add("user_name", Json::string(u));
    }
    if let Some(g) = nz("group_name") {
        a.add("group_name", Json::string(g));
    }
    if options & CHECK_INODE != 0 {
        match ev.get("inode") {
            Some(v) if v.is_string() => {
                a.add("inode", v.clone());
            }
            Some(_) => mwarn(msgs::FIM_WARN_INODE_WRONG_TYPE),
            None => {}
        }
    }
    if options & CHECK_MTIME != 0 {
        if let Some(v) = ev.get("mtime") {
            a.add("mtime", Json::number(v.as_i32().unwrap_or(0) as f64));
        }
    }
    for (bit, k) in [(CHECK_MD5SUM, "hash_md5"), (CHECK_SHA1SUM, "hash_sha1"), (CHECK_SHA256SUM, "hash_sha256")] {
        if options & bit != 0 {
            if let Some(b) = ev.get(k).and_then(|v| v.as_bytes()) {
                a.add(k, Json::string(b));
            }
        }
    }
    if cfg!(windows) && options & CHECK_ATTRS != 0 {
        if let Some(b) = ev.get("attributes").and_then(|v| v.as_bytes()) {
            a.add("attributes", Json::string(b));
        }
    }
    if let Some(b) = ev.get("checksum").and_then(|v| v.as_bytes()) {
        a.add("checksum", Json::string(b));
    }
    a
}

/// The event path as UTF-8 (`auto_to_utf8` on Windows).
fn utf8_path(p: &[u8]) -> Vec<u8> {
    #[cfg(windows)]
    {
        return super::win::auto_to_utf8(p);
    }
    #[cfg(unix)]
    p.to_vec()
}

/// `fim_scan_info_json`
fn fim_scan_info_json(start: bool, ts: i64) -> Json {
    let mut root = Json::object();
    root.add("type", Json::string(if start { "scan_start" } else { "scan_end" }));
    let mut data = Json::object();
    data.add("timestamp", Json::number(ts as f64));
    root.add("data", data);
    root
}

/// `trail_path_separator`
fn trail_sep(p: &[u8]) -> Vec<u8> {
    let mut v = p.to_vec();
    if !v.is_empty() && *v.last().unwrap() != PATH_SEP {
        v.push(PATH_SEP);
    }
    v
}

/// `fim_configuration_directory`: the index of the deepest configured parent.
pub fn fim_configuration_directory(cfg: &SyscheckConfig, path: &[u8]) -> Option<usize> {
    if path.is_empty() {
        return None;
    }
    let full = trail_sep(path);
    let mut top = 0usize;
    let mut found = None;
    for (i, d) in cfg.directories.iter().enumerate() {
        let entry = trail_sep(d.path.as_bytes());
        // w_compare_str(full_entry, full_path)
        let m = if entry.len() > full.len() { 0 } else if full.starts_with(&entry) { entry.len() } else { 0 };
        if top < m && full[m - 1] == PATH_SEP {
            found = Some(i);
            top = m;
        }
    }
    found
}

/// `fim_check_depth`
pub fn fim_check_depth(path: &[u8], dir: &Directory) -> i32 {
    let parent = dir.path.len();
    if parent > path.len() {
        return -1;
    }
    let mut depth = -1;
    #[cfg(windows)]
    if parent == 3 && path.get(2) == Some(&b'\\') {
        depth = 0;
    }
    #[cfg(unix)]
    if parent == 1 {
        depth = 0;
    }
    depth + path[parent..].iter().filter(|&&c| c == PATH_SEP).count() as i32
}

/// `fim_check_ignore`
fn fim_check_ignore(cfg: &SyscheckConfig, file: &[u8], is_dir: bool) -> bool {
    let fs = bstr(file);
    for i in cfg.ignore.iter().flatten() {
        let ib = i.as_bytes();
        if file.len() >= ib.len() && file[..ib.len()].eq_ignore_ascii_case(ib) {
            mdebug2(cfmt(msgs::FIM_IGNORE_ENTRY, &[A::S(&fs), A::S(i)]));
            return true;
        }
    }
    for r in cfg.ignore_regex.iter().flatten() {
        if r.is_match_bytes(file) {
            if is_dir && r.raw().starts_with('!') {
                return false;
            }
            mdebug2(cfmt(msgs::FIM_IGNORE_SREGEX, &[A::S(&fs), A::S(r.raw())]));
            return true;
        }
    }
    false
}

/// `fim_check_restrict`
pub(super) fn fim_check_restrict(file: &[u8], r: Option<&siem_regex::OsMatch>) -> bool {
    if let Some(r) = r {
        if !r.is_match_bytes(file) {
            mdebug2(cfmt(msgs::FIM_FILE_IGNORE_RESTRICT, &[A::S(&bstr(file)), A::S(r.raw())]));
            return true;
        }
    }
    false
}

/// `OS_MD5_SHA1_SHA256_File(file, prefilter, ..., OS_BINARY, max_size)`
fn hash_file(file: &[u8], prefilter: Option<&[String]>, max_size: usize) -> Option<(String, String, String)> {
    use md5::Digest as _;
    use std::io::Read;
    let mut reader: Box<dyn Read> = match prefilter {
        None => {
            #[cfg(windows)]
            let p = {
                use std::os::windows::ffi::OsStringExt;
                let mut w = super::win::auto_to_wide(file)?;
                w.pop();
                std::ffi::OsString::from_wide(&w)
            };
            #[cfg(unix)]
            let p = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(file).to_os_string();
            Box::new(std::fs::File::open(p).ok()?)
        }
        Some(cmd) => {
            let out = std::process::Command::new(&cmd[0]).args(&cmd[1..]).arg(bstr(file)).stdout(std::process::Stdio::piped()).spawn().ok()?;
            Box::new(out.stdout?)
        }
    };
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut sha256 = sha2::Sha256::new();
    let mut buf = vec![0u8; 2048];
    let mut read = 0usize;
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        if max_size > 0 {
            read += n;
            if read >= max_size {
                mwarn(cfmt("'%s' filesize is larger than the maximum allowed (%d MB). File skipped.", &[A::B(file), A::I((max_size / 1048576) as i64)]));
                return None;
            }
        }
        md5.update(&buf[..n]);
        sha1::Digest::update(&mut sha1, &buf[..n]);
        sha2::Digest::update(&mut sha256, &buf[..n]);
    }
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Some((hex(&md5.finalize()), hex(&sha1::Digest::finalize(sha1)), hex(&sha2::Digest::finalize(sha256))))
}

impl Fim {
    pub fn new(sk: Arc<super::syscheck::Syscheck>, send: Box<dyn Fn(u8, &str, &[u8]) -> i32 + Send + Sync>) -> Fim {
        let comp_estimation_perc = sk.cfg.read_recursive().comp_estimation_perc;
        Fim {
            sk,
            base_line: AtomicBool::new(false),
            scan_mutex: Mutex::new(()),
            db_states: Mutex::new([DbState::Empty; 3]),
            fps: Mutex::new((0, 0)),
            n_msg_sent: AtomicI32::new(0),
            sync_eps: Mutex::new(0),
            shutdown: AtomicBool::new(false),
            diff: Mutex::new(super::diff::DiffState { folder_size: 0.0, comp_estimation_perc, disk_quota_full_msg: true }),
            send,
        }
    }

    /// `fim_send_msg`
    fn send_msg(&self, mq: u8, location: &str, msg: &[u8]) {
        if self.shutdown.load(Ordering::Relaxed) {
            return;
        }
        if (self.send)(mq, location, msg) < 0 {
            mdebug1("(1224): Error sending message to queue.");
            (self.send)(mq, location, msg);
        }
    }

    /// `fim_send_sync_state`
    pub fn send_sync_state(&self, location: &str, msg: &[u8]) {
        let max = self.sk.cfg.read_recursive().sync_max_eps;
        let lock = self.sync_eps.lock();
        self.send_msg(DBSYNC_MQ, location, msg);
        mdebug2(cfmt(msgs::FIM_DBSYNC_SEND, &[A::B(msg)]));
        if max != 0 {
            if let Ok(mut n) = lock {
                *n += 1;
                if *n == max {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    *n = 0;
                }
            }
        }
    }

    /// `send_syscheck_msg`
    pub fn send_syscheck_msg(&self, j: &Json) {
        let msg = j.print_unformatted();
        mdebug2(cfmt(msgs::FIM_SEND, &[A::B(&msg)]));
        self.send_msg(SYSCHECK_MQ, SYSCHECK, &msg);
        let max = self.sk.cfg.read_recursive().max_eps;
        if max == 0 {
            return;
        }
        if self.n_msg_sent.fetch_add(1, Ordering::SeqCst) + 1 >= max {
            std::thread::sleep(std::time::Duration::from_secs(1));
            self.n_msg_sent.store(0, Ordering::SeqCst);
        }
    }

    /// `send_log_msg`
    fn send_log_msg(&self, msg: &[u8]) {
        self.send_msg(LOCALFILE_MQ, SYSCHECK, msg);
    }

    /// `fim_send_scan_info`
    fn send_scan_info(&self, start: bool) {
        self.send_syscheck_msg(&fim_scan_info_json(start, now()));
    }

    /// `check_max_fps`
    fn check_max_fps(&self) {
        let max = self.sk.cfg.read_recursive().max_files_per_second;
        if max == 0 {
            return;
        }
        let Ok(mut st) = self.fps.lock() else { return };
        let t = now();
        if t != st.1 {
            st.0 = 0;
            st.1 = t;
        }
        if st.0 < max {
            st.0 += 1;
            return;
        }
        mdebug2(msgs::FIM_REACHED_MAX_FPS);
        drop(st);
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(mut st) = self.fps.lock() {
            st.0 = 0;
        }
    }

    /// `fim_get_data`
    #[cfg(windows)]
    pub fn fim_get_data(&self, file: &[u8], dir: &Directory, st: &super::win::Stat) -> Option<FileData> {
        use super::win;
        let (file_max_size, prefilter) = {
            let c = self.sk.cfg.read_recursive();
            (c.file_max_size, c.prefilter_cmd.clone())
        };
        let mut d = FileData::default();
        let fs = bstr(file);
        if dir.options & CHECK_SIZE != 0 {
            d.size = st.size as u64;
        }
        if dir.options & CHECK_PERM != 0 {
            match win::get_file_permissions(file) {
                Ok(mut acl) => {
                    win::decode_win_acl_json(&mut acl);
                    d.perm = Some(acl.print_unformatted());
                    d.perm_json = Some(acl);
                }
                Err(e) => {
                    mdebug1(cfmt(msgs::FIM_EXTRACT_PERM_FAIL, &[A::S(&fs), A::I(e as i64)]));
                    return None;
                }
            }
        }
        if dir.options & CHECK_ATTRS != 0 {
            d.attributes = Some(win::decode_win_attributes(win::get_file_attrs(file)).into_bytes());
        }
        if dir.options & CHECK_MTIME != 0 {
            d.mtime = win::get_utc_modification_time(file);
        }
        if dir.options & CHECK_OWNER != 0 {
            let (name, sid) = win::get_file_user(file);
            d.user_name = Some(name.into_bytes());
            d.uid = Some(sid.into_bytes());
        }
        d.hash_md5 = "d41d8cd98f00b204e9800998ecf8427e".into();
        d.hash_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709".into();
        d.hash_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into();
        d.scanned = 1;
        let is_reg = st.mode & S_IFMT == S_IFREG;
        if is_reg && st.size > 0 && (st.size as usize) < file_max_size && dir.options & CHECK_SUM != 0 {
            match hash_file(file, prefilter.as_deref(), file_max_size) {
                Some((m, s1, s2)) => {
                    d.hash_md5 = m;
                    d.hash_sha1 = s1;
                    d.hash_sha256 = s2;
                }
                None => {
                    mdebug1(cfmt(msgs::FIM_HASHES_FAIL, &[A::S(&fs)]));
                    return None;
                }
            }
        }
        if dir.options & CHECK_MD5SUM == 0 {
            d.hash_md5.clear();
        }
        if dir.options & CHECK_SHA1SUM == 0 {
            d.hash_sha1.clear();
        }
        if dir.options & CHECK_SHA256SUM == 0 {
            d.hash_sha256.clear();
        }
        d.inode = st.ino as u64;
        d.dev = st.dev as u64;
        d.options = dir.options;
        d.last_event = now();
        fim_get_checksum(&mut d);
        Some(d)
    }

    /// `fim_file`: in a transaction (scan) or as a single update (realtime/whodata).
    #[cfg(windows)]
    fn fim_file(&self, cfg: &SyscheckConfig, path: &[u8], dir: &Directory, evt: &mut EventData, txn: Option<&TxnCtx>) {
        self.check_max_fps();
        let Some(data) = self.fim_get_data(path, dir, &evt.statbuf) else {
            mdebug1(cfmt(msgs::FIM_GET_ATTRIBUTES, &[A::S(&bstr(path))]));
            return;
        };
        let Some(db) = fimdb::instance() else { return };
        match txn {
            Some(t) => {
                *t.latest.lock().unwrap() = Some((path.to_vec(), data.clone()));
                db.transaction_sync_row(&t.txn, &fimdb::file_item_json(path, &data, true));
                *t.latest.lock().unwrap() = None;
                self.drain(cfg, &t.pending, evt);
            }
            None => {
                let item = fimdb::file_item_json(path, &data, true);
                let (mode, options, report) = (evt.mode, dir.options, evt.report_event);
                let mut events: Vec<(Value, i32)> = Vec::new();
                let r = db.update_item(&item, &mut |t: ReturnTypeCallback, res: &Value| {
                    if report {
                        events.push(fimdb::create_json_event(&item, res, t == ReturnTypeCallback::Modified, mode, options));
                    }
                    Ok(())
                });
                match r {
                    Ok(()) => {}
                    Err(siem_dbsync::Error::MaxRows(_)) => db.log(fimdb::LogLevel::Warning, "Reached maximum files limit monitored, due to db_entry_limit configuration for files."),
                    Err(e) => db.log(fimdb::LogLevel::Error, &bstr(e.what())),
                }
                for (mut ev, etype) in events {
                    // convert_inode: numbers become strings
                    for k in ["attributes", "old_attributes"] {
                        if let Value::Object(m) = &mut ev {
                            if let Some(Value::Object(d)) = m.get_mut(&b"data"[..]) {
                                if let Some(Value::Object(a)) = d.get_mut(k.as_bytes()) {
                                    if let Some(i) = a.get(&b"inode"[..]) {
                                        if matches!(i, Value::UInt(_) | Value::Int(_)) {
                                            let s = i.dump().unwrap_or_default();
                                            a.insert(b"inode".to_vec(), Value::Str(s));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    evt.type_ = etype;
                    if let Some(j) = fimdb::to_cjson(&ev) {
                        self.fim_event_callback(cfg, j, dir, evt);
                    }
                }
            }
        }
    }

    /// `fim_event_callback`
    fn fim_event_callback(&self, cfg: &SyscheckConfig, mut ev: Json, dir: &Directory, evt: &EventData) {
        let Some(data) = ev.get_mut("data") else { return };
        let path = data.get("path").and_then(|p| p.as_bytes()).unwrap_or(b"").to_vec();
        if let Some(ca) = data.get("changed_attributes") {
            if ca.len() == 0 {
                mdebug2(cfmt(msgs::FIM_EMPTY_CHANGED_ATTRIBUTES, &[A::B(&path)]));
                return;
            }
        }
        if dir.options & CHECK_SEECHANGES != 0 {
            if let Some(diff) = self.fim_file_diff(cfg, &path, dir) {
                if evt.type_ == FIM_MODIFICATION {
                    data.add("content_changes", Json::string(diff));
                }
            }
        }
        if let Some(w) = &evt.w_evt {
            data.add("audit", fim_audit_json(w));
        }
        if let Some(t) = &dir.tag {
            data.add("tags", Json::string(t));
        }
        #[cfg(windows)]
        for k in ["attributes", "old_attributes"] {
            if let Some(a) = data.get_mut(k) {
                let p = a.get("perm").and_then(|p| p.as_bytes()).map(|b| b.to_vec());
                if let Some(Json::Object(m)) = Some(&mut *a) {
                    if let Some(slot) = m.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(b"perm")) {
                        slot.1 = p.as_deref().and_then(siem_cjson::parse).unwrap_or(Json::Null);
                    }
                }
            }
        }
        self.send_syscheck_msg(&ev);
    }

    /// `transaction_callback`
    fn transaction_callback(&self, cfg: &SyscheckConfig, t: ReturnTypeCallback, result: &Json, latest: Option<(Vec<u8>, FileData)>, evt: &mut EventData) {
        let path: Vec<u8> = if t == ReturnTypeCallback::Deleted {
            match result.get("path").and_then(|p| p.as_bytes()) {
                Some(p) => p.to_vec(),
                None => return,
            }
        } else if let Some((p, _)) = &latest {
            p.clone()
        } else {
            return;
        };
        let Some(di) = fim_configuration_directory(cfg, &path) else {
            mdebug2(cfmt(msgs::FIM_CONFIGURATION_NOTFOUND, &[A::S("file"), A::B(&path)]));
            return;
        };
        let dir = &cfg.directories[di];
        let diff = if dir.options & CHECK_SEECHANGES != 0 && t != ReturnTypeCallback::Deleted { self.fim_file_diff(cfg, &path, dir) } else { None };
        if !self.base_line.load(Ordering::SeqCst) {
            return;
        }
        match t {
            ReturnTypeCallback::Inserted => evt.type_ = FIM_ADD,
            ReturnTypeCallback::Modified => evt.type_ = FIM_MODIFICATION,
            ReturnTypeCallback::Deleted => {
                if dir.options & CHECK_SEECHANGES != 0 {
                    self.fim_diff_process_delete_file(&path);
                }
                evt.type_ = FIM_DELETE;
            }
            ReturnTypeCallback::MaxRows => {
                mdebug1(cfmt("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", &[A::B(&path)]));
                return;
            }
            _ => return,
        }
        let mut json_event = Json::object();
        json_event.add("type", Json::string("event"));
        let mut data = Json::object();
        data.add("path", Json::string(utf8_path(&path)));
        data.add("version", Json::number(2.0));
        data.add("mode", Json::string(EVENT_MODES[evt.mode as usize % 3]));
        data.add("type", Json::string(EVENT_TYPES[evt.type_ as usize % 3]));
        match result.get("last_event") {
            Some(ts) => {
                data.add("timestamp", Json::number(ts.as_i32().unwrap_or(0) as f64));
            }
            None => {
                data.add("timestamp", Json::number(latest.as_ref().map(|(_, d)| d.last_event).unwrap_or(0) as f64));
            }
        }
        if t == ReturnTypeCallback::Deleted || latest.is_none() {
            data.add("attributes", dbsync_attributes_json(result, dir.options));
        } else if let Some((_, ld)) = &latest {
            data.add("attributes", fim_attributes_json(ld));
            if let Some(old) = result.get("old") {
                let mut oa = Json::object();
                let mut ca = Json::array();
                fim_calculate_dbsync_difference(ld, old, &mut oa, &mut ca);
                let empty = ca.len() == 0;
                data.add("old_attributes", oa);
                data.add("changed_attributes", ca);
                if empty {
                    mdebug2(cfmt(msgs::FIM_EMPTY_CHANGED_ATTRIBUTES, &[A::B(&path)]));
                    return;
                }
            }
        }
        if let (Some(d), ReturnTypeCallback::Modified) = (&diff, t) {
            data.add("content_changes", Json::string(d));
        }
        if let Some(tag) = &dir.tag {
            data.add("tags", Json::string(tag));
        }
        json_event.add("data", data);
        self.send_syscheck_msg(&json_event);
    }

    /// `fim_checker`
    #[cfg(windows)]
    pub fn fim_checker(&self, cfg: &SyscheckConfig, path: &[u8], evt: &mut EventData, parent: Option<usize>, txn: Option<&TxnCtx>) {
        use super::win;
        if win::check_removed_file(path) {
            return;
        }
        let Some(ci) = fim_configuration_directory(cfg, path) else {
            mdebug2(cfmt(msgs::FIM_CONFIGURATION_NOTFOUND, &[A::S("file"), A::B(path)]));
            return;
        };
        let dir = &cfg.directories[ci];
        let parent = parent.unwrap_or(ci);
        if evt.mode == FIM_SCHEDULED {
            if parent != ci {
                return;
            }
        } else if evt.mode != fim_mode(dir.options) {
            return;
        }
        let depth = fim_check_depth(path, dir);
        if depth > dir.recursion_level {
            mdebug2(cfmt(msgs::FIM_MAX_RECURSION_LEVEL, &[A::I(depth as i64), A::I(dir.recursion_level as i64), A::B(path)]));
            return;
        }
        match win::stat64(path) {
            Err(e) => {
                if e != 2 {
                    mdebug1(cfmt(msgs::FIM_STAT_FAILED, &[A::B(path), A::I(e as i64), A::S(&siem_ipc::os_net::strerror(e))]));
                    return;
                }
                if (evt.mode == FIM_REALTIME && dir.options & REALTIME_ACTIVE == 0) || (evt.mode == FIM_WHODATA && dir.options & WHODATA_ACTIVE == 0) {
                    return;
                }
                if evt.mode != FIM_SCHEDULED {
                    evt.type_ = FIM_DELETE;
                    // fim_generate_delete_event
                    if dir.options & CHECK_SEECHANGES != 0 {
                        self.fim_diff_process_delete_file(path);
                    }
                    self.process_delete(cfg, path, evt, ci);
                }
                return;
            }
            Ok(st) => evt.statbuf = st,
        }
        if evt.w_evt.as_ref().is_some_and(|w| w.scan_directory == 1) && super::whodata::w_update_sacl(path) != 0 {
            mdebug1(cfmt(msgs::FIM_SCAL_NOREFRESH, &[A::B(path)]));
        }
        let path_type = evt.statbuf.mode & S_IFMT;
        if fim_check_ignore(cfg, path, path_type == S_IFDIR) {
            return;
        }
        if path_type == S_IFREG {
            if fim_check_restrict(path, dir.filerestrict.as_ref()) {
                return;
            }
            self.fim_file(cfg, path, dir, evt, txn);
        } else if path_type == S_IFDIR {
            if depth == dir.recursion_level {
                mdebug2(cfmt(msgs::FIM_DIR_RECURSION_LEVEL, &[A::B(path), A::I(depth as i64)]));
                return;
            }
            self.fim_directory(cfg, path, evt, ci, txn);
        }
    }

    /// `fim_directory`
    #[cfg(windows)]
    fn fim_directory(&self, cfg: &SyscheckConfig, dir: &[u8], evt: &mut EventData, ci: usize, txn: Option<&TxnCtx>) {
        let names = match read_dir_ansi(dir) {
            Ok(n) => n,
            Err(e) => {
                mwarn(cfmt(msgs::FIM_PATH_NOT_OPEN, &[A::B(dir), A::S(&siem_ipc::os_net::strerror(e))]));
                return;
            }
        };
        for name in names {
            if name == b"." || name == b".." {
                continue;
            }
            let mut f: Vec<u8> = dir.to_vec();
            if f.len() > 260 {
                f.truncate(260);
            }
            if f.last() != Some(&PATH_SEP) {
                f.push(PATH_SEP);
            }
            if f.len() + name.len() >= 260 {
                mwarn(cfmt(msgs::FIM_ERROR_PATH_TOO_LONG, &[A::B(&f), A::B(&name), A::I(260)]));
                continue;
            }
            f.extend_from_slice(&name);
            f.make_ascii_lowercase();
            self.fim_checker(cfg, &f, evt, Some(ci), txn);
        }
    }

    /// `process_delete_event` through `fim_db_get_path`.
    pub(super) fn process_delete(&self, cfg: &SyscheckConfig, path: &[u8], evt: &EventData, ci: usize) -> FimDbError {
        let Some(db) = fimdb::instance() else { return FimDbError::Err };
        match db.get_path(path) {
            Ok(Some((p, d))) => {
                if db.remove_path(&p) == FimDbError::Err {
                    return FimDbError::Ok;
                }
                if evt.report_event {
                    if let Some(j) = fim_json_event(&p, &d, None, &cfg.directories[ci], evt, None) {
                        self.send_syscheck_msg(&j);
                    }
                }
                FimDbError::Ok
            }
            _ => FimDbError::Err,
        }
    }

    /// One scan pass in a transaction (the directory loop and the deleted rows).
    #[cfg(windows)]
    fn scan_pass(&self, db: &fimdb::FimDb, evt: &mut EventData, first: bool) -> Option<bool> {
        let latest: Arc<Mutex<Option<(Vec<u8>, FileData)>>> = Arc::new(Mutex::new(None));
        let pending: Arc<Mutex<Vec<Pending>>> = Arc::new(Mutex::new(Vec::new()));
        let (l2, p2) = (latest.clone(), pending.clone());
        let cb: siem_dbsync::ResultCallback = Arc::new(move |t: ReturnTypeCallback, j: &Value| {
            if let Some(cj) = fimdb::to_cjson(j) {
                p2.lock().unwrap().push((t, cj, l2.lock().unwrap().clone()));
            }
            Ok(())
        });
        let Some(txn) = db.transaction_start(fimdb::FIMDB_FILE_TXN_TABLE, cb) else {
            if first {
                merror(cfmt(msgs::FIM_ERROR_TRANSACTION, &[A::S(fimdb::FIMDB_FILE_TXN_TABLE)]));
            }
            return None;
        };
        if first {
            let mut ds = self.diff.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(size) = self.diff_folder_size() {
                ds.folder_size = size;
            }
            ds.disk_quota_full_msg = true;
            let size = ds.folder_size;
            drop(ds);
            mdebug2(cfmt(msgs::FIM_DIFF_FOLDER_SIZE, &[A::S(DIFF_DIR), A::F(size as f64)]));
        }
        let ctx = TxnCtx { latest, pending, txn };
        let nodes_count;
        {
            let _g = self.scan_mutex.lock();
            if first {
                self.update_wildcards_config();
            }
            let cfg = self.sk.cfg.read_recursive();
            for i in 0..cfg.directories.len() {
                let path = cfg.directories[i].path.clone().into_bytes();
                if first {
                    self.fim_checker(&cfg, &path, evt, Some(i), Some(&ctx));
                } else {
                    let mut ev = EventData { report_event: true, mode: FIM_SCHEDULED, ..Default::default() };
                    self.fim_checker(&cfg, &path, &mut ev, Some(i), Some(&ctx));
                }
                if fim_mode(cfg.directories[i].options) == FIM_WHODATA {
                    super::whodata::whodata_adddir(&path, &cfg.directories[i], self);
                }
            }
            nodes_count = if first && cfg.file_limit_enabled { db.count_entries(fimdb::FIMDB_FILE_TABLE_NAME, false) } else { 0 };
        }
        let TxnCtx { pending, txn, .. } = ctx;
        let p3 = pending.clone();
        let mut del = |t: ReturnTypeCallback, j: &Value| -> siem_dbsync::R {
            if let Some(cj) = fimdb::to_cjson(j) {
                p3.lock().unwrap().push((t, cj, None));
            }
            Ok(())
        };
        db.transaction_deleted_rows(txn, &mut del);
        let cfg = self.sk.cfg.read_recursive();
        self.drain(&cfg, &pending, evt);
        let limit = cfg.file_entry_limit;
        Some(first && cfg.file_limit_enabled && nodes_count >= limit)
    }

    /// `fim_scan`
    #[cfg(windows)]
    pub fn fim_scan(&self) -> i64 {
        let start = std::time::Instant::now();
        // SAFETY: clock() has no preconditions.
        let cpu_start = unsafe { libc::clock() };
        minfo(msgs::FIM_FREQUENCY_STARTED);
        self.send_scan_info(true);
        let Some(db) = fimdb::instance() else { return now() };
        let mut evt = EventData { report_event: true, mode: FIM_SCHEDULED, ..Default::default() };
        match self.scan_pass(db, &mut evt, true) {
            None => return now(),
            Some(true) => {
                self.scan_pass(db, &mut evt, false);
            }
            Some(false) => {}
        }
        super::registry::fim_registry_scan(self);
        let elapsed = start.elapsed().as_secs_f64();
        let end_of_scan = now();
        let c = {
            let c = self.sk.cfg.read_recursive();
            (c.file_limit_enabled, c.file_entry_limit, c.registry_limit_enabled, c.db_entry_registry_limit)
        };
        if c.0 {
            let n = db.count_entries(fimdb::FIMDB_FILE_TABLE_NAME, false);
            self.check_db_state(c.1, n, 0, fimdb::FIMDB_FILE_TABLE_NAME);
        }
        if c.2 {
            let k = db.count_entries(fimdb::FIMDB_REGISTRY_KEY_TABLENAME, false);
            self.check_db_state(c.3, k, 1, fimdb::FIMDB_REGISTRY_KEY_TABLENAME);
            let v = db.count_entries(fimdb::FIMDB_REGISTRY_VALUE_TABLENAME, false);
            self.check_db_state(c.3, v, 2, fimdb::FIMDB_REGISTRY_VALUE_TABLENAME);
        }
        // the first scan sets the base line; Windows sets the realtime watches after it
        if self.base_line.swap(true, Ordering::SeqCst) {
            super::realtime::after_scan();
        }
        minfo(msgs::FIM_FREQUENCY_ENDED);
        self.send_scan_info(false);
        if is_debug() {
            // SAFETY: as above.
            let cpu = (unsafe { libc::clock() } - cpu_start) as f64 / 1000.0; // CLOCKS_PER_SEC on msvcrt
            mdebug1(cfmt(msgs::FIM_RUNNING_SCAN, &[A::F(elapsed), A::F(cpu)]));
            mdebug1(cfmt(msgs::FIM_ENTRIES_INFO, &[A::I(db.count_entries(fimdb::FIMDB_FILE_TABLE_NAME, false) as i64)]));
            mdebug1(cfmt(msgs::FIM_REGISTRY_ENTRIES_INFO, &[A::I(db.count_entries(fimdb::FIMDB_REGISTRY_KEY_TABLENAME, false) as i64)]));
            mdebug1(cfmt(msgs::FIM_REGISTRY_VALUES_ENTRIES_INFO, &[A::I(db.count_entries(fimdb::FIMDB_REGISTRY_VALUE_TABLENAME, false) as i64)]));
        }
        end_of_scan
    }

    /// Runs the queued transaction callbacks (the C runs them inside dbsync's call).
    fn drain(&self, cfg: &SyscheckConfig, pending: &Mutex<Vec<Pending>>, evt: &mut EventData) {
        let items = std::mem::take(&mut *pending.lock().unwrap());
        for (t, j, latest) in items {
            self.transaction_callback(cfg, t, &j, latest, evt);
        }
    }

    /// `fim_check_db_state`
    fn check_db_state(&self, limit: i32, count: i32, which: usize, table: &str) {
        let Ok(mut states) = self.db_states.lock() else { return };
        let st = &mut states[which];
        if count < 0 {
            mwarn(msgs::FIM_DATABASE_NODES_COUNT_FAIL);
            return;
        }
        let l = limit as f64;
        let c = count as f64;
        match *st {
            DbState::Full if count >= limit => return,
            DbState::P90 if count < limit && c >= l * 0.9 => return,
            DbState::P80 if c < l * 0.9 && c >= l * 0.8 => return,
            DbState::Normal => {
                if count == 0 {
                    *st = DbState::Empty;
                    return;
                } else if c < l * 0.8 {
                    return;
                }
            }
            DbState::Empty => {
                if count == 0 {
                    return;
                } else if c < l * 0.8 {
                    *st = DbState::Normal;
                    return;
                }
            }
            _ => {}
        }
        let is_file = table == fimdb::FIMDB_FILE_TABLE_NAME;
        let mut j = Json::object();
        j.add("fim_db_table", Json::string(table));
        let db = fimdb::instance();
        if is_file {
            j.add("file_limit", Json::number(limit as f64));
            j.add("file_count", Json::number(count as f64));
        } else if let Some(db) = db {
            j.add("registry_limit", Json::number(limit as f64));
            j.add("values_count", Json::number(db.count_entries(fimdb::FIMDB_REGISTRY_VALUE_TABLENAME, false) as f64));
            j.add("keys_count", Json::number(db.count_entries(fimdb::FIMDB_REGISTRY_KEY_TABLENAME, false) as f64));
        }
        let pick = |reg: &'static str, file: &'static str| if is_file { file } else { reg };
        if count >= limit {
            *st = DbState::Full;
            mwarn(pick(msgs::FIM_DB_FULL_ALERT_REG, msgs::FIM_DB_FULL_ALERT_FILE));
            j.add("alert_type", Json::string("full"));
        } else if c >= l * 0.9 {
            *st = DbState::P90;
            minfo(pick(msgs::FIM_DB_90_PERCENTAGE_ALERT_REG, msgs::FIM_DB_90_PERCENTAGE_ALERT_FILE));
            j.add("alert_type", Json::string("90_percentage"));
        } else if c >= l * 0.8 {
            *st = DbState::P80;
            minfo(pick(msgs::FIM_DB_80_PERCENTAGE_ALERT_REG, msgs::FIM_DB_80_PERCENTAGE_ALERT_FILE));
            j.add("alert_type", Json::string("80_percentage"));
        } else {
            *st = if count > 0 { DbState::Normal } else { DbState::Empty };
            minfo(pick(msgs::FIM_DB_NORMAL_ALERT_REG, msgs::FIM_DB_NORMAL_ALERT_FILE));
            j.add("alert_type", Json::string("normal"));
        }
        drop(states);
        let mut m = format!("wazuh: FIM DB: {}", String::from_utf8_lossy(&j.print_unformatted())).into_bytes();
        m.truncate(255);
        self.send_log_msg(&m);
    }

    /// `update_wildcards_config`
    pub fn update_wildcards_config(&self) {
        let mut cfg = self.sk.cfg.write();
        if cfg.wildcards.is_none() {
            return;
        }
        mdebug2(msgs::FIM_WILDCARDS_UPDATE_START);
        for d in &mut cfg.directories {
            d.is_expanded = false;
        }
        let file_size_limit = cfg.file_size_limit;
        let wildcards: Vec<(String, i32, Option<String>, i32, Option<String>, i32)> = cfg
            .wildcards
            .iter()
            .flatten()
            .map(|w| (w.path.clone(), w.options, w.filerestrict.as_ref().map(|r| r.raw().to_string()), w.recursion_level, w.tag.clone(), w.diff_size_limit))
            .collect();
        let mut ctx = siem_config::ConfigContext::new(siem_config::Platform::AGENT);
        for (path, opts, restrict, rec, tag, dsl) in wildcards {
            let Some(paths) = expand_wildcards(&mut ctx, &path) else { continue };
            for p in paths {
                let mut e = fim_create_directory(&mut ctx, &p, opts, restrict.as_deref(), rec, tag.as_deref(), dsl, true);
                #[cfg(windows)]
                {
                    e.path = e.path.to_ascii_lowercase();
                }
                e.is_expanded = true;
                if e.diff_size_limit == -1 {
                    e.diff_size_limit = file_size_limit;
                }
                fim_insert_directory(&mut cfg.directories, e);
            }
        }
        for (lv, m) in ctx.log.drain(..) {
            match lv {
                siem_config::LogLevel::Debug2 => mdebug2(m),
                siem_config::LogLevel::Debug1 => mdebug1(m),
                siem_config::LogLevel::Warn => mwarn(m),
                siem_config::LogLevel::Error => merror(m),
                siem_config::LogLevel::Info => minfo(m),
            }
        }
        // entries of a wildcard that were not expanded this time are removed (with their files)
        let removed: Vec<Directory> = {
            let mut keep = Vec::new();
            let mut gone = Vec::new();
            for d in cfg.directories.drain(..) {
                if d.is_wildcard && !d.is_expanded {
                    gone.push(d);
                } else {
                    keep.push(d);
                }
            }
            cfg.directories = keep;
            gone
        };
        drop(cfg);
        for d in removed.iter().rev() {
            mdebug2(cfmt(msgs::FIM_WILDCARDS_REMOVE_DIRECTORY, &[A::S(&d.path)]));
            self.fim_process_wildcard_removed(d);
        }
        mdebug2(msgs::FIM_WILDCARDS_UPDATE_FINALIZE);
    }

    /// `fim_process_wildcard_removed`
    fn fim_process_wildcard_removed(&self, d: &Directory) {
        let Some(db) = fimdb::instance() else { return };
        let evt = EventData { mode: FIM_SCHEDULED, report_event: true, type_: FIM_DELETE, ..Default::default() };
        if d.options & CHECK_SEECHANGES != 0 {
            self.fim_diff_process_delete_file(d.path.as_bytes());
        }
        let send_delete = |p: &[u8]| {
            if let Ok(Some((pp, data))) = db.get_path(p) {
                if db.remove_path(&pp) != FimDbError::Err && evt.report_event {
                    if let Some(j) = fim_json_event(&pp, &data, None, d, &evt, None) {
                        self.send_syscheck_msg(&j);
                    }
                }
                true
            } else {
                false
            }
        };
        if !send_delete(d.path.as_bytes()) {
            return;
        }
        let pattern = format!("{}{}%", d.path, PATH_SEP as char);
        if let Ok(paths) = db.search(Some(pattern.as_bytes()), None) {
            for p in paths {
                if d.options & CHECK_SEECHANGES != 0 {
                    self.fim_diff_process_delete_file(&p);
                }
                send_delete(&p);
            }
        }
    }

    /// `fim_diff_folder_size`: KB of queue/diff/local, None (unchanged) when it is not there.
    pub fn diff_folder_size(&self) -> Option<f32> {
        let local = format!("{DIFF_DIR}/local");
        std::path::Path::new(&local).is_dir().then(|| super::diff::dir_size(local.as_bytes()) / 1024.0)
    }

    pub fn base_line(&self) -> bool {
        self.base_line.load(Ordering::SeqCst)
    }
}

/// The transaction and the entry being written (`fim_txn_context_t`).
pub struct TxnCtx {
    latest: Arc<Mutex<Option<(Vec<u8>, FileData)>>>,
    pending: Arc<Mutex<Vec<Pending>>>,
    txn: siem_dbsync::DBSyncTxn,
}

/// A transaction callback queued with the entry being written.
type Pending = (ReturnTypeCallback, Json, Option<(Vec<u8>, FileData)>);

/// `FIM_MODE(options)`
pub fn fim_mode(o: i32) -> i32 {
    if o & WHODATA_ACTIVE != 0 {
        FIM_WHODATA
    } else if o & REALTIME_ACTIVE != 0 {
        FIM_REALTIME
    } else {
        FIM_SCHEDULED
    }
}

/// `fim_audit_json` (Windows fields)
pub fn fim_audit_json(w: &WhodataEvt) -> Json {
    let mut a = Json::object();
    if let Some(v) = &w.user_id {
        a.add("user_id", Json::string(v));
    }
    if let Some(v) = &w.user_name {
        a.add("user_name", Json::string(v));
    }
    if let Some(v) = &w.process_name {
        a.add("process_name", Json::string(v));
    }
    a.add("process_id", Json::number(w.process_id as f64));
    a
}

/// `fim_json_event`
pub fn fim_json_event(path: &[u8], new: &FileData, old: Option<&FileData>, dir: &Directory, evt: &EventData, diff: Option<&[u8]>) -> Option<Json> {
    let mut changed = None;
    if let Some(o) = old {
        let c = fim_json_compare_attrs(o, new);
        if c.len() == 0 {
            return None;
        }
        changed = Some(c);
    }
    let mut ev = Json::object();
    ev.add("type", Json::string("event"));
    let mut data = Json::object();
    data.add("path", Json::string(utf8_path(path)));
    data.add("version", Json::number(2.0));
    data.add("mode", Json::string(EVENT_MODES[evt.mode as usize % 3]));
    data.add("type", Json::string(EVENT_TYPES[evt.type_ as usize % 3]));
    data.add("timestamp", Json::number(new.last_event as f64));
    data.add("attributes", fim_attributes_json(new));
    if let (Some(o), Some(c)) = (old, changed) {
        data.add("changed_attributes", c);
        data.add("old_attributes", fim_attributes_json(o));
    }
    if let Some(w) = &evt.w_evt {
        data.add("audit", fim_audit_json(w));
    }
    if let Some(d) = diff {
        data.add("content_changes", Json::string(d));
    }
    if let Some(t) = &dir.tag {
        data.add("tags", Json::string(t));
    }
    ev.add("data", data);
    Some(ev)
}

/// `fim_json_compare_attrs` (Windows rules)
pub fn fim_json_compare_attrs(o: &FileData, n: &FileData) -> Json {
    let mut c = Json::array();
    if o.options & CHECK_SIZE != 0 && o.size != n.size {
        c.push(Json::string("size"));
    }
    #[cfg(windows)]
    {
        if o.options & CHECK_PERM != 0 && !super::win::compare_win_permissions(o.perm_json.as_ref(), n.perm_json.as_ref()) {
            c.push(Json::string("permission"));
        }
        if o.options & CHECK_ATTRS != 0 && o.attributes != n.attributes {
            c.push(Json::string("attributes"));
        }
    }
    #[cfg(unix)]
    if o.options & CHECK_PERM != 0 && o.perm != n.perm {
        c.push(Json::string("permission"));
    }
    if o.options & CHECK_OWNER != 0 {
        if let (Some(a), Some(b)) = (&o.uid, &n.uid) {
            if a != b {
                c.push(Json::string("uid"));
            }
        }
        if let (Some(a), Some(b)) = (&o.user_name, &n.user_name) {
            if (!cfg!(windows) || (!a.is_empty() && !b.is_empty())) && a != b {
                c.push(Json::string("user_name"));
            }
        }
    }
    if o.options & CHECK_GROUP != 0 {
        if let (Some(a), Some(b)) = (&o.gid, &n.gid) {
            if a != b {
                c.push(Json::string("gid"));
            }
        }
        if let (Some(a), Some(b)) = (&o.group_name, &n.group_name) {
            if a != b {
                c.push(Json::string("group_name"));
            }
        }
    }
    if o.options & CHECK_MTIME != 0 && o.mtime != n.mtime {
        c.push(Json::string("mtime"));
    }
    #[cfg(unix)]
    if o.options & CHECK_INODE != 0 && o.inode != n.inode {
        c.push(Json::string("inode"));
    }
    for (bit, a, b, l) in [
        (CHECK_MD5SUM, &o.hash_md5, &n.hash_md5, "md5"),
        (CHECK_SHA1SUM, &o.hash_sha1, &n.hash_sha1, "sha1"),
        (CHECK_SHA256SUM, &o.hash_sha256, &n.hash_sha256, "sha256"),
    ] {
        if o.options & bit != 0 && a != b {
            c.push(Json::string(l));
        }
    }
    c
}

/// `wopendir` + `readdir` names (mingw dirent: ANSI names).
#[cfg(windows)]
fn read_dir_ansi(dir: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstFileA, FindNextFileA, WIN32_FIND_DATAA};
    let p = bstr(dir);
    if siem_fileop::crt::is_network_path(&p) {
        mwarn(siem_fileop::crt::network_path_executed(&p));
        return Err(13);
    }
    // opendir("dir") searches "dir\*" (mingw dirent)
    let mut pat = dir.to_vec();
    if !matches!(pat.last(), Some(b'\\') | Some(b'/') | Some(b':')) {
        pat.push(b'\\');
    }
    pat.extend_from_slice(b"*\0");
    let mut out = Vec::new();
    // SAFETY: a find handle opened and closed here.
    unsafe {
        let mut fd: WIN32_FIND_DATAA = std::mem::zeroed();
        let h = FindFirstFileA(pat.as_ptr(), &mut fd);
        if h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let e = windows_sys::Win32::Foundation::GetLastError();
            // _findfirst errno: ENOENT for a missing path, EINVAL/EACCES otherwise
            return Err(match e {
                2 | 3 => 2,
                5 => 13,
                _ => 22,
            });
        }
        loop {
            let n = fd.cFileName.iter().position(|&c| c == 0).unwrap_or(fd.cFileName.len());
            out.push(fd.cFileName[..n].iter().map(|&c| c as u8).collect());
            if FindNextFileA(h, &mut fd) == 0 {
                break;
            }
        }
        FindClose(h);
    }
    Ok(out)
}
