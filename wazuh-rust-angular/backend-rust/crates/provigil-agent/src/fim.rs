//! ProVigil Endpoint Agent - File Integrity Monitoring (FIM) with Whodata & File Diff
//!
//! One baseline (`fim_db.rs`) compared by the scheduled scan, by real-time re-checks
//! (`realtime.rs`) and by who-data re-checks (`whodata.rs`), with unified diffs (`diff.rs`).
//! Per file: size, mtime, MD5 / SHA-1 / SHA-256, owner, permissions (DACL as SDDL) and
//! attributes; a modification lists what differs in `changed_attributes`.
//!
//! 100% clean-room Rust implementation (zero GPL derivation).

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use chrono::Utc;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::buffer::EventBuffer;
use crate::diff::{DiffConfig, DiffEngine};
use crate::whodata::Who;

/// `data\fim_synced.json`: the agent id each baseline was last sent to the manager for.
pub const SYNCED_FILE: &str = "data/fim_synced.json";
/// Entries of one `fim_state` event.
const STATE_BATCH: usize = 200;
/// `fim_state` events leave at most this often: a fleet's baselines reach the manager's
/// database at one batch per second per agent.
const STATE_EVERY: Duration = Duration::from_secs(1);
/// Queued events at which the next batch waits, so real events go first.
// shortcut: a `queue_size` under this can drop a batch, send_state would need the limit to prevent it
const STATE_BACKLOG: usize = 100;

static SYNCED_WRITE: Mutex<()> = Mutex::new(());

/// Baselines waiting for, or sending under, the manager's go-ahead (keepalive `fim_state_wanted`).
static STATE_WANTED: AtomicUsize = AtomicUsize::new(0);
/// The manager's last keepalive answer gave this agent a baseline slot (at most 20 agents of a
/// tenant send at a time).
static STATE_ALLOWED: AtomicBool = AtomicBool::new(false);

pub fn state_wanted() -> bool {
    STATE_WANTED.load(Ordering::SeqCst) > 0
}

pub fn allow_state(allowed: bool) {
    STATE_ALLOWED.store(allowed, Ordering::SeqCst);
}

pub fn state_allowed() -> bool {
    STATE_ALLOWED.load(Ordering::SeqCst)
}

/// Counts in [`STATE_WANTED`] while alive.
struct Wanted;

impl Wanted {
    fn new() -> Self {
        STATE_WANTED.fetch_add(1, Ordering::SeqCst);
        Wanted
    }
}

impl Drop for Wanted {
    fn drop(&mut self) {
        STATE_WANTED.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMetadata {
    pub size_bytes: u64,
    pub sha256: String,
    pub modified_timestamp: i64,
    pub md5: String,
    pub sha1: String,
    /// Owner account (`DOMAIN\name`) and SID, DACL as SDDL, attribute names; empty when not read.
    pub owner: String,
    pub owner_sid: String,
    pub permissions: String,
    pub attributes: String,
}

/// Paths matched exactly or as a folder (`C:\a\tmp` covers `C:\a\tmp\x`, not `C:\a\tmpfile`),
/// case-insensitive; entries starting with `regex:` are case-insensitive regexes.
#[derive(Clone, Default)]
struct PathList {
    paths: Vec<String>,
    regexes: Vec<Regex>,
}

impl PathList {
    fn new(list: &[String]) -> Self {
        let mut l = Self::default();
        for e in list {
            match e.strip_prefix("regex:") {
                Some(r) => match RegexBuilder::new(r).case_insensitive(true).build() {
                    Ok(re) => l.regexes.push(re),
                    Err(err) => warn!(entry = %e, error = %err, "File integrity path regex not valid; left out"),
                },
                None => l.paths.push(e.trim_end_matches(['\\', '/']).to_lowercase()),
            }
        }
        l
    }

    fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.regexes.is_empty()
    }

    fn matches(&self, path: &Path) -> bool {
        let p = path.to_string_lossy();
        let lower = p.to_lowercase();
        self.paths.iter().any(|i| lower.strip_prefix(i.as_str()).is_some_and(|rest| rest.is_empty() || rest.starts_with(['\\', '/'])))
            || self.regexes.iter().any(|r| r.is_match(&p))
    }
}

/// What the folder walk needs; cloned out so a scan walks and hashes without the lock.
#[derive(Clone)]
struct Walker {
    roots: Vec<PathBuf>,
    ignore: PathList,
    /// Folder levels walked below a monitored folder (0: only the files directly in it).
    max_depth: usize,
}

impl Walker {
    /// Folder levels between the monitored folder holding `path` and `path`.
    fn depth(&self, path: &Path) -> usize {
        self.roots
            .iter()
            .filter(|r| path.starts_with(r))
            .map(|r| path.components().count() - r.components().count())
            .min()
            .unwrap_or(0)
    }

    /// `found(path)` when a file, for its files when a folder (subfolders when `recursive`,
    /// down to the recursion level). Ignored paths are skipped, and so are links (junctions,
    /// symbolic links) unless configured themselves: no loops, nothing outside the folders.
    /// `found` returning false ends the walk, and the walk then returns false.
    fn walk(&self, path: &Path, depth: usize, recursive: bool, found: &mut dyn FnMut(PathBuf) -> bool) -> bool {
        if self.ignore.matches(path) {
            return true;
        }
        let Ok(mut meta) = fs::symlink_metadata(path) else { return true };
        if meta.file_type().is_symlink() {
            if !self.roots.iter().any(|r| r == path) {
                return true;
            }
            let Ok(m) = fs::metadata(path) else { return true };
            meta = m;
        }
        if meta.is_file() {
            if depth <= self.max_depth + 1 {
                return found(path.to_path_buf());
            }
        } else if meta.is_dir() && depth <= self.max_depth {
            let Ok(entries) = fs::read_dir(path) else { return true };
            for entry in entries.flatten() {
                let p = entry.path();
                if (recursive || !p.is_dir()) && !self.walk(&p, depth + 1, recursive, found) {
                    return false;
                }
            }
        }
        true
    }
}

pub struct FimScanner {
    walker: Walker,
    file_limit: usize,
    limit_warned: bool,
    baseline: HashMap<PathBuf, FileMetadata>,
    diff_engine: Option<DiffEngine>,
    /// Files diffed (empty: every file) and never diffed.
    diff_only: PathList,
    nodiff: PathList,
    /// The baseline on disk; without it the baseline lives in memory only.
    db: Option<crate::fim_db::FimDb>,
    /// Baseline paths changed or removed since the last write to `db`.
    dirty: HashSet<PathBuf>,
    /// No baseline yet (fresh install): the first scan records it without reporting
    /// every file as new.
    first_scan_quiet: bool,
    /// While a scheduled scan runs: the paths re-checked meanwhile, which the scan leaves
    /// alone (the re-check read them later than the scan did).
    fresh: Option<HashSet<PathBuf>>,
}

impl FimScanner {
    pub fn new(monitored_paths: Vec<PathBuf>) -> Self {
        Self {
            walker: Walker { roots: monitored_paths, ignore: PathList::default(), max_depth: 256 },
            file_limit: 100_000,
            limit_warned: false,
            baseline: HashMap::new(),
            diff_engine: None,
            diff_only: PathList::default(),
            nodiff: PathList::default(),
            db: None,
            dirty: HashSet::new(),
            first_scan_quiet: false,
            fresh: None,
        }
    }

    /// Keeps the baseline in `path` (SQLite) and starts from what it holds.
    pub fn with_database(mut self, path: &Path) -> Self {
        match crate::fim_db::FimDb::open(path).and_then(|db| db.load().map(|b| (db, b))) {
            Ok((db, base)) => {
                info!(files = base.len(), db = %path.display(), "File integrity baseline loaded");
                self.first_scan_quiet = base.is_empty();
                self.baseline = base;
                self.db = Some(db);
            }
            Err(e) => tracing::error!(error = %e, db = %path.display(), "File integrity database not usable; baseline kept in memory only"),
        }
        self
    }

    pub fn with_diff_engine(mut self, config: DiffConfig) -> Self {
        self.diff_engine = Some(DiffEngine::new(config));
        self
    }

    /// Diffs only for files in `only` (empty: every file), never for files in `never`.
    pub fn with_diff_paths(mut self, only: &[String], never: &[String]) -> Self {
        self.diff_only = PathList::new(only);
        self.nodiff = PathList::new(never);
        self
    }

    /// Paths never reported: exact paths or folders, or `regex:` entries (case-insensitive).
    pub fn with_ignore(mut self, entries: &[String]) -> Self {
        self.walker.ignore = PathList::new(entries);
        self
    }

    /// Folder levels walked below each monitored folder.
    pub fn with_recursion_level(mut self, level: u32) -> Self {
        self.walker.max_depth = level as usize;
        self
    }

    /// Files kept in the baseline at most; new files past it are not monitored.
    pub fn with_file_limit(mut self, limit: usize) -> Self {
        self.file_limit = limit;
        self
    }

    /// One scan holding the scanner throughout (tests, tools); the agent uses [`scan_shared`].
    pub fn scan(&mut self, agent_id: &str, agent_name: &str) -> Vec<Value> {
        let m = Mutex::new(std::mem::replace(self, FimScanner::new(Vec::new())));
        let events = scan_shared(&m, agent_id, agent_name, || true);
        *self = m.into_inner().unwrap_or_else(|e| e.into_inner());
        events
    }

    /// Re-checks one path (a real-time notification, a who-data handle close): a file, a
    /// folder (its files; `recursive` for the whole tree, else only the files directly in it)
    /// or a path that is gone (it and everything under it deleted). Events as from a scan,
    /// carrying `who` when given.
    pub fn recheck(&mut self, path: &Path, recursive: bool, who: Option<&Who>, agent_id: &str, agent_name: &str) -> Vec<Value> {
        let mut found = HashSet::new();
        self.walker.walk(path, self.walker.depth(path), recursive, &mut |p| {
            found.insert(p);
            true
        });
        let in_scope = |p: &Path| if recursive { p.starts_with(path) } else { p == path || p.parent() == Some(path) };
        let gone: Vec<PathBuf> = self.baseline.keys().filter(|p| in_scope(p) && !found.contains(*p)).cloned().collect();
        let mut events: Vec<Value> = gone.iter().map(|p| self.remove(p, who, agent_id, agent_name)).collect();
        for p in &found {
            // a file that cannot be read now keeps its baseline entry
            if let Some(m) = read_file(p) {
                events.extend(self.update(p, m, who, agent_id, agent_name));
            }
        }
        if let Some(fresh) = self.fresh.as_mut() {
            fresh.extend(found.into_iter().chain(gone));
        }
        self.flush();
        if who.is_none() {
            for e in &mut events {
                e["syscheck"]["mode"] = json!("realtime");
            }
        }
        events
    }

    /// The event for `path` now looking like `meta`, if any, and the baseline updated.
    fn update(&mut self, path: &Path, meta: FileMetadata, who: Option<&Who>, agent_id: &str, agent_name: &str) -> Option<Value> {
        if self.at_limit(path) {
            return None;
        }
        let path_str = path.to_string_lossy().to_string();
        let syscheck = match self.baseline.get(path) {
            Some(old) if *old == meta => return None,
            None => {
                info!(file = %path_str, "FIM detected new file");
                let _ = self.diff(path);
                let mut s = json!({ "path": path_str, "event": "added", "changed_attributes": [] });
                put_fields(&mut s, &meta, "after");
                Some(s)
            }
            Some(old) => {
                let changed = changed_attributes(old, &meta);
                // only fields not recorded before (an older baseline): recorded silently
                (!changed.is_empty()).then(|| {
                    info!(file = %path_str, changed = ?changed, "FIM detected file modification");
                    let mut s = json!({ "path": path_str, "event": "modified", "changed_attributes": changed });
                    put_fields(&mut s, old, "before");
                    put_fields(&mut s, &meta, "after");
                    if let Some(r) = changed.contains(&"sha256").then(|| self.diff(path)).flatten() {
                        if let Some(content) = r.diff_content {
                            s["diff"] = json!(content);
                            s["diff_truncated"] = json!(r.truncated);
                        } else if r.quota_full {
                            s["diff"] = json!("Diff not available: the diff storage quota is full");
                        }
                    }
                    s
                })
            }
        };
        self.baseline.insert(path.to_path_buf(), meta);
        self.dirty.insert(path.to_path_buf());
        syscheck.map(|s| fim_event(s, who, agent_id, agent_name))
    }

    /// The deletion event for `path` (in the baseline), removed from the baseline.
    fn remove(&mut self, path: &Path, who: Option<&Who>, agent_id: &str, agent_name: &str) -> Value {
        let path_str = path.to_string_lossy().to_string();
        info!(file = %path_str, "FIM detected file deletion");
        let mut s = json!({ "path": path_str, "event": "deleted", "changed_attributes": [] });
        if let Some(old) = self.baseline.remove(path) {
            put_fields(&mut s, &old, "before");
        }
        if let Some(d) = &self.diff_engine {
            d.remove_snapshot(path);
        }
        self.limit_warned = false;
        self.dirty.insert(path.to_path_buf());
        fim_event(s, who, agent_id, agent_name)
    }

    /// `path` is new and the baseline is full (warned once until a file is removed).
    fn at_limit(&mut self, path: &Path) -> bool {
        let full = !self.baseline.contains_key(path) && self.baseline.len() >= self.file_limit;
        if full && !std::mem::replace(&mut self.limit_warned, true) {
            warn!(limit = self.file_limit, file = %path.display(), "File integrity file limit reached; new files are not monitored");
        }
        full
    }

    /// The diff for `path` when it gets diffs.
    fn diff(&self, path: &Path) -> Option<crate::diff::DiffResult> {
        let d = self.diff_engine.as_ref()?;
        if self.nodiff.matches(path) || !self.diff_only.is_empty() && !self.diff_only.matches(path) {
            return None;
        }
        d.process_file_diff(path).ok().flatten()
    }

    /// Writes the changed baseline entries to disk (one transaction).
    fn flush(&mut self) {
        let dirty = std::mem::take(&mut self.dirty);
        let Some(db) = self.db.as_mut() else { return };
        let changed: Vec<(&PathBuf, &FileMetadata)> = dirty.iter().filter_map(|p| self.baseline.get(p).map(|m| (p, m))).collect();
        let gone: Vec<&PathBuf> = dirty.iter().filter(|p| !self.baseline.contains_key(*p)).collect();
        if let Err(e) = db.apply(&changed, &gone) {
            tracing::error!(error = %e, "File integrity baseline not saved");
        }
    }
}

/// The scheduled scan of every monitored folder: files are read and hashed without holding
/// `fim`, which is locked per file to compare and record it, so real-time and who-data
/// re-checks go on during a long scan. Ends early once `running()` turns false: the changes
/// found so far are kept and reported, nothing is taken as deleted.
pub fn scan_shared(fim: &Mutex<FimScanner>, agent_id: &str, agent_name: &str, running: fn() -> bool) -> Vec<Value> {
    let lock = || fim.lock().unwrap_or_else(|e| e.into_inner());
    let walker = {
        let mut f = lock();
        f.fresh = Some(HashSet::new());
        f.walker.clone()
    };
    let (mut seen, mut events) = (HashSet::new(), Vec::new());
    let mut stopped = false;
    for root in &walker.roots {
        stopped = !walker.walk(root, 0, true, &mut |p| {
            if !running() {
                return false;
            }
            let skip = {
                let mut f = lock();
                f.fresh.as_ref().is_some_and(|s| s.contains(&p)) || f.at_limit(&p)
            };
            if !skip {
                if let Some(meta) = read_file(&p) {
                    let mut f = lock();
                    if !f.fresh.as_ref().is_some_and(|s| s.contains(&p)) {
                        events.extend(f.update(&p, meta, None, agent_id, agent_name));
                    }
                }
            }
            seen.insert(p);
            true
        });
        if stopped {
            break;
        }
    }
    let mut f = lock();
    let fresh = f.fresh.take().unwrap_or_default();
    if stopped {
        // a first scan cut short is not saved: the next start builds the baseline again quietly
        if f.first_scan_quiet {
            f.dirty.clear();
            return Vec::new();
        }
        f.flush();
        return events;
    }
    let gone: Vec<PathBuf> = f.baseline.keys().filter(|p| !seen.contains(*p) && !fresh.contains(*p)).cloned().collect();
    for p in &gone {
        events.push(f.remove(p, None, agent_id, agent_name));
    }
    f.flush();
    if std::mem::take(&mut f.first_scan_quiet) {
        info!(files = f.baseline.len(), "File integrity baseline built (first scan: nothing reported)");
        events.clear();
    }
    events
}

/// What differs; a field not read on either side (empty) is no change: a baseline from
/// before it was recorded, or security that could not be read.
fn changed_attributes(old: &FileMetadata, new: &FileMetadata) -> Vec<&'static str> {
    let differs = |a: &str, b: &str| !a.is_empty() && !b.is_empty() && a != b;
    [
        ("size", old.size_bytes != new.size_bytes),
        ("permission", differs(&old.permissions, &new.permissions)),
        ("uid", differs(&old.owner_sid, &new.owner_sid)),
        ("attributes", differs(&old.attributes, &new.attributes)),
        ("mtime", old.modified_timestamp != new.modified_timestamp),
        ("md5", differs(&old.md5, &new.md5)),
        ("sha1", differs(&old.sha1, &new.sha1)),
        ("sha256", old.sha256 != new.sha256),
    ]
    .into_iter()
    .filter_map(|(name, d)| d.then_some(name))
    .collect()
}

/// `size_<when>`, `sha256_<when>`, ... of `m` into the event.
fn put_fields(s: &mut Value, m: &FileMetadata, when: &str) {
    for (k, v) in [
        ("size", json!(m.size_bytes)),
        ("sha256", json!(m.sha256)),
        ("md5", json!(m.md5)),
        ("sha1", json!(m.sha1)),
        ("mtime", json!(m.modified_timestamp)),
        ("owner", json!(m.owner)),
        ("owner_sid", json!(m.owner_sid)),
        ("permissions", json!(m.permissions)),
        ("attributes", json!(m.attributes)),
    ] {
        s[format!("{k}_{when}")] = v;
    }
}

/// MD5, SHA-1 and SHA-256 of a file in one streaming pass (64 KiB buffer).
pub fn compute_hashes(path: &Path) -> io::Result<(String, String, String)> {
    let mut file = File::open(path)?;
    let (mut md5, mut sha1, mut sha256) = (md5::Md5::new(), sha1::Sha1::new(), Sha256::new());
    let mut buffer = vec![0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        // a big file is not read to its end once the agent stops
        if !crate::collecting() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        md5.update(&buffer[..n]);
        sha1.update(&buffer[..n]);
        sha256.update(&buffer[..n]);
    }
    Ok((format!("{:x}", md5.finalize()), format!("{:x}", sha1.finalize()), format!("{:x}", sha256.finalize())))
}

/// What a file looks like now; `None` when it cannot be read.
pub fn read_file(path: &Path) -> Option<FileMetadata> {
    let meta = fs::metadata(path).ok()?;
    let (md5, sha1, sha256) = compute_hashes(path).ok()?;
    let modified_timestamp = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    #[cfg(windows)]
    let ((owner, owner_sid, permissions), attributes) = (win::security(path), win::attribute_names(&meta));
    #[cfg(not(windows))]
    let ((owner, owner_sid, permissions), attributes) = (Default::default(), String::new());
    Some(FileMetadata { size_bytes: meta.len(), sha256, modified_timestamp, md5, sha1, owner, owner_sid, permissions, attributes })
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::fs::MetadataExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::{
        GetFileSecurityW, GetSecurityDescriptorOwner, LookupAccountSidW, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSID,
    };

    use crate::wevt::win::wide;

    const ATTRIBUTES: [(u32, &str); 15] = [
        (0x1, "READONLY"),
        (0x2, "HIDDEN"),
        (0x4, "SYSTEM"),
        (0x20, "ARCHIVE"),
        (0x40, "DEVICE"),
        (0x80, "NORMAL"),
        (0x100, "TEMPORARY"),
        (0x200, "SPARSE_FILE"),
        (0x400, "REPARSE_POINT"),
        (0x800, "COMPRESSED"),
        (0x1000, "OFFLINE"),
        (0x2000, "NOT_CONTENT_INDEXED"),
        (0x4000, "ENCRYPTED"),
        (0x8000, "INTEGRITY_STREAM"),
        (0x20000, "NO_SCRUB_DATA"),
    ];

    /// `ARCHIVE, READONLY`-style names of the attributes set.
    pub(super) fn attribute_names(meta: &fs::Metadata) -> String {
        let a = meta.file_attributes();
        ATTRIBUTES.iter().filter(|(bit, _)| a & bit != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
    }

    /// (owner account, owner SID, DACL as SDDL); empty when not readable.
    pub(super) fn security(path: &Path) -> (String, String, String) {
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let name = wide(&path.to_string_lossy());
        let mut len = 0u32;
        unsafe { GetFileSecurityW(name.as_ptr(), info, null_mut(), 0, &mut len) };
        if len == 0 {
            return Default::default();
        }
        let mut sd = vec![0u64; (len as usize).div_ceil(8)];
        if unsafe { GetFileSecurityW(name.as_ptr(), info, sd.as_mut_ptr().cast(), len, &mut len) } == 0 {
            return Default::default();
        }
        let (sid, sddl) = unsafe { crate::registry::win::owner_and_dacl(sd.as_mut_ptr().cast()) };
        let (mut psid, mut defaulted): (PSID, _) = (null_mut(), 0);
        let owner = if unsafe { GetSecurityDescriptorOwner(sd.as_mut_ptr().cast(), &mut psid, &mut defaulted) } != 0 && !psid.is_null() {
            account(psid, &sid)
        } else {
            String::new()
        };
        (owner, sid, sddl)
    }

    thread_local! {
        /// SID text → account name (most files share a few owners; domain lookups are slow).
        static NAMES: std::cell::RefCell<HashMap<String, String>> = Default::default();
    }

    /// `DOMAIN\name` of a SID (empty when it does not resolve).
    fn account(psid: PSID, sid: &str) -> String {
        if let Some(n) = NAMES.with(|c| c.borrow().get(sid).cloned()) {
            return n;
        }
        let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
        let (mut nl, mut dl, mut kind) = (256u32, 256u32, 0);
        let ok = unsafe { LookupAccountSidW(null(), psid, name.as_mut_ptr(), &mut nl, domain.as_mut_ptr(), &mut dl, &mut kind) };
        let n = if ok == 0 {
            String::new()
        } else {
            let (n, d) = (String::from_utf16_lossy(&name[..nl as usize]), String::from_utf16_lossy(&domain[..dl as usize]));
            if d.is_empty() { n } else { format!("{d}\\{n}") }
        };
        NAMES.with(|c| c.borrow_mut().insert(sid.to_string(), n.clone()));
        n
    }
}

/// `mode`: who-data with `who`, else the scheduled scan (a real-time re-check sets its own).
fn fim_event(mut syscheck: Value, who: Option<&Who>, agent_id: &str, agent_name: &str) -> Value {
    syscheck["mode"] = json!(if who.is_some() { "whodata" } else { "scheduled" });
    if let Some(w) = who {
        syscheck["whodata"] = json!(w);
    }
    json!({
        "type": "fim",
        "timestamp": Utc::now().to_rfc3339(),
        "agent": {
            "id": agent_id,
            "name": agent_name
        },
        "syscheck": syscheck
    })
}

/// Pushes scan events at `per_second` at most (0 = all at once); stops pacing when the agent
/// stops (the rest are pushed at once, so the final flush still sends them).
pub fn push_paced(buffer: &EventBuffer, events: Vec<Value>, per_second: u32, running: fn() -> bool) {
    for (i, ev) in events.into_iter().enumerate() {
        if per_second > 0 && i > 0 && i % per_second as usize == 0 && running() {
            std::thread::sleep(Duration::from_secs(1));
        }
        buffer.push(ev);
    }
}

fn synced_ids(file: &Path) -> Value {
    fs::read(file).ok().and_then(|b| serde_json::from_slice(&b).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

/// Whether the `part` baseline was sent for this agent id.
pub(crate) fn state_sent(synced: &Path, part: &str, agent_id: &str) -> bool {
    synced_ids(synced)[part] == agent_id
}

/// One baseline as `fim_state` events of [`STATE_BATCH`] entries, read per batch with `entries`,
/// each sent only while `allowed()` (the manager's slot); the last one is marked `last`, which
/// frees the slot. Remembered in `synced` at the end; stopped before that, it is sent again from
/// the start (the manager replaces the rows). A backlog or a wait for the slot holds up only the
/// caller's next scan, which then finds what changed meanwhile; other events go on.
// shortcut: a stop or crash with batches still queued (fewer than STATE_BACKLOG) loses them, remembering after the manager's answer would close it
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_state<K>(
    buffer: &EventBuffer,
    agent: &(String, String),
    synced: &Path,
    part: &str,
    keys: &[K],
    running: fn() -> bool,
    allowed: fn() -> bool,
    mut entries: impl FnMut(&[K]) -> Vec<Value>,
) {
    let _wanted = Wanted::new();
    let batches = keys.chunks(STATE_BATCH).len();
    for (i, batch) in keys.chunks(STATE_BATCH).enumerate() {
        while running() && !allowed() {
            crate::nap(STATE_EVERY, running);
        }
        if !running() {
            return;
        }
        let last = i + 1 == batches;
        buffer.push(json!({
            "event_type": "fim_state",
            "timestamp": Utc::now().to_rfc3339(),
            "agent": { "id": agent.0, "name": agent.1 },
            "entries": entries(batch),
            "last": last,
        }));
        if last {
            break;
        }
        crate::nap(STATE_EVERY, running);
        while running() && buffer.len() >= STATE_BACKLOG {
            crate::nap(STATE_EVERY, running);
        }
    }
    if !running() {
        return;
    }
    let _turn = SYNCED_WRITE.lock().unwrap_or_else(|e| e.into_inner());
    let mut ids = synced_ids(synced);
    ids[part] = json!(agent.0);
    if let Err(e) = fs::write(synced, ids.to_string()) {
        warn!(error = %e, file = %synced.display(), "File integrity sync not remembered; sent again at the next start");
    }
    info!(part, entries = keys.len(), "File integrity baseline queued for the manager");
}

/// The file baseline to the manager once per agent id.
pub fn sync_files(fim: &Mutex<FimScanner>, buffer: &EventBuffer, agent: &(String, String), synced: &Path, running: fn() -> bool, allowed: fn() -> bool) {
    if state_sent(synced, "files", &agent.0) {
        return;
    }
    let lock = || fim.lock().unwrap_or_else(|e| e.into_inner());
    let paths: Vec<PathBuf> = lock().baseline.keys().cloned().collect();
    // read per batch: real-time re-checks go on, and an older copy must not overwrite their change
    send_state(buffer, agent, synced, "files", &paths, running, allowed, |batch| {
        let f = lock();
        let entry = |(p, m): (&PathBuf, &FileMetadata)| {
            let mut s = json!({ "path": p.to_string_lossy() });
            put_fields(&mut s, m, "after");
            s
        };
        batch.iter().filter_map(|p| f.baseline.get_key_value(p)).map(entry).collect()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fim_lifecycle_addition_modification_deletion() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("sensitive.conf");

        let mut scanner = FimScanner::new(vec![tmp.path().to_path_buf()]);

        // 1. Initial scan (empty)
        let ev1 = scanner.scan("001", "win-dev");
        assert!(ev1.is_empty());

        // 2. Create file -> Detect 'added'
        fs::write(&file_path, b"initial configuration").unwrap();
        let ev2 = scanner.scan("001", "win-dev");
        assert_eq!(ev2.len(), 1);
        assert_eq!(ev2[0]["syscheck"]["event"], "added");
        assert_eq!(ev2[0]["syscheck"]["mode"], "scheduled");
        assert_eq!(ev2[0]["syscheck"]["md5_after"], format!("{:x}", md5::Md5::digest(b"initial configuration")));

        // 3. Modify file -> Detect 'modified'
        fs::write(&file_path, b"compromised configuration").unwrap();
        let ev3 = scanner.scan("001", "win-dev");
        assert_eq!(ev3.len(), 1);
        assert_eq!(ev3[0]["syscheck"]["event"], "modified");
        let changed = ev3[0]["syscheck"]["changed_attributes"].as_array().unwrap();
        for a in ["size", "md5", "sha1", "sha256"] {
            assert!(changed.contains(&json!(a)), "{a} missing in {changed:?}");
        }
        assert_ne!(ev3[0]["syscheck"]["sha1_before"], ev3[0]["syscheck"]["sha1_after"]);

        // 4. Delete file -> Detect 'deleted'
        fs::remove_file(&file_path).unwrap();
        let ev4 = scanner.scan("001", "win-dev");
        assert_eq!(ev4.len(), 1);
        assert_eq!(ev4[0]["syscheck"]["event"], "deleted");
        assert_eq!(ev4[0]["syscheck"]["size_before"], 25);
    }

    #[test]
    fn test_fim_with_diff_and_whodata() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_diff = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("policy.txt");
        let diff_store = tmp_diff.path().join("diff_store");

        let diff_config = DiffConfig {
            enabled: true,
            storage_dir: diff_store,
            max_diff_size: 4096,
            max_file_size: 1024 * 1024,
            disk_quota_bytes: 10 * 1024 * 1024,
            compress_snapshots: false,
        };
        let who = Who {
            user_name: "admin".into(),
            user_id: "S-1-5-18".into(),
            process_name: r"C:\Windows\notepad.exe".into(),
            process_id: 1234,
            access_mask: 0x2,
        };

        let nodiff = vec![tmp.path().join("secret.txt").to_string_lossy().to_string()];
        let mut scanner = FimScanner::new(vec![tmp.path().to_path_buf()]).with_diff_engine(diff_config).with_diff_paths(&[], &nodiff);

        // Initial creation, re-checked with who-data
        fs::write(&file_path, "Rule: Allow 80\nRule: Allow 443\n").unwrap();
        fs::write(tmp.path().join("secret.txt"), "a\n").unwrap();
        let ev1 = scanner.recheck(&file_path, true, Some(&who), "001", "win-dev");
        assert_eq!(ev1.len(), 1);
        assert_eq!(ev1[0]["syscheck"]["whodata"]["process_name"], r"C:\Windows\notepad.exe");
        assert_eq!(ev1[0]["syscheck"]["whodata"]["user_id"], "S-1-5-18");
        assert_eq!(ev1[0]["syscheck"]["mode"], "whodata");
        assert_eq!(scanner.scan("001", "win-dev").len(), 1, "secret.txt added");

        // Modify
        fs::write(&file_path, "Rule: Allow 80\nRule: Allow 443\nRule: Allow 22\n").unwrap();
        fs::write(tmp.path().join("secret.txt"), "b\n").unwrap();
        let ev2 = scanner.scan("001", "win-dev");
        assert_eq!(ev2.len(), 2);
        let ev = |name: &str| ev2.iter().find(|e| e["syscheck"]["path"].as_str().unwrap().ends_with(name)).unwrap().clone();
        assert_eq!(ev("policy.txt")["syscheck"]["event"], "modified");
        assert!(ev("policy.txt")["syscheck"].get("whodata").is_none());
        let diff = ev("policy.txt")["syscheck"]["diff"].as_str().unwrap().to_string();
        assert!(diff.contains("+Rule: Allow 22"));
        assert!(ev("secret.txt")["syscheck"].get("diff").is_none(), "nodiff file diffed");

        // deleted: its snapshot goes too
        fs::remove_file(&file_path).unwrap();
        fs::remove_file(tmp.path().join("secret.txt")).unwrap();
        assert_eq!(scanner.scan("001", "win-dev").len(), 2);
        assert_eq!(fs::read_dir(tmp_diff.path().join("diff_store")).unwrap().count(), 0);
    }

    #[test]
    fn recheck_scopes_ignore_and_touch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let sub = root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(root.join("a.txt"), "a").unwrap();
        fs::write(sub.join("b.txt"), "b").unwrap();
        fs::write(root.join("Skip.log"), "s").unwrap();
        let ignore = vec![root.join("skip.log").to_string_lossy().to_string()];
        let mut s = FimScanner::new(vec![root.clone()]).with_ignore(&ignore);
        let ev = s.scan("1", "n");
        assert_eq!(ev.len(), 2, "ignored file reported: {ev:?}");

        // a touch is an mtime change only
        let f = File::options().write(true).open(root.join("a.txt")).unwrap();
        f.set_modified(std::time::SystemTime::now() + Duration::from_secs(60)).unwrap();
        drop(f);
        let ev = s.recheck(&root.join("a.txt"), true, None, "1", "n");
        assert_eq!(ev[0]["syscheck"]["changed_attributes"], json!(["mtime"]));
        assert_eq!(ev[0]["syscheck"]["mode"], "realtime");

        // shallow re-check of the root does not see (or delete) files in subfolders
        fs::remove_file(sub.join("b.txt")).unwrap();
        fs::write(root.join("c.txt"), "c").unwrap();
        let ev = s.recheck(&root, false, None, "1", "n");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["syscheck"]["event"], "added");
        // a folder that is gone: everything under it deleted
        fs::remove_dir_all(&sub).unwrap();
        let ev = s.recheck(&sub, true, None, "1", "n");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["syscheck"]["event"], "deleted");
        assert!(s.scan("1", "n").is_empty());
    }

    #[test]
    fn ignore_boundary_and_regex() {
        let l = PathList::new(&[r"C:\a\tmp".into(), r"regex:\.LOG$".into(), "regex:(".into()]);
        assert!(l.matches(Path::new(r"C:\a\tmp")));
        assert!(l.matches(Path::new(r"c:\A\TMP\x.txt")));
        assert!(!l.matches(Path::new(r"C:\a\tmpfile")));
        assert!(!l.matches(Path::new(r"C:\a\tmpdir\x.txt")));
        assert!(l.matches(Path::new(r"C:\b\app.log")));
        assert!(!l.matches(Path::new(r"C:\b\app.log.txt")));

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("tmp")).unwrap();
        for f in ["tmp/x.txt", "tmpfile", "app.LOG", "keep.txt"] {
            fs::write(root.join(f), "x").unwrap();
        }
        let ignore = vec![root.join("tmp").to_string_lossy().to_string(), r"regex:\.log$".into()];
        let mut s = FimScanner::new(vec![root.to_path_buf()]).with_ignore(&ignore);
        let mut names: Vec<String> =
            s.scan("1", "n").iter().map(|e| Path::new(e["syscheck"]["path"].as_str().unwrap()).file_name().unwrap().to_string_lossy().to_string()).collect();
        names.sort();
        assert_eq!(names, ["keep.txt", "tmpfile"]);
    }

    #[test]
    fn recursion_level_and_file_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::create_dir_all(root.join("s1").join("s2")).unwrap();
        fs::write(root.join("a.txt"), "a").unwrap();
        fs::write(root.join("s1").join("b.txt"), "b").unwrap();
        fs::write(root.join("s1").join("s2").join("c.txt"), "c").unwrap();
        let mut s = FimScanner::new(vec![root.clone()]).with_recursion_level(1);
        assert_eq!(s.scan("1", "n").len(), 2, "s2 is below the recursion level");
        // a re-check below the level reports nothing either
        fs::write(root.join("s1").join("s2").join("c.txt"), "cc").unwrap();
        assert!(s.recheck(&root.join("s1").join("s2").join("c.txt"), true, None, "1", "n").is_empty());

        let mut s = FimScanner::new(vec![root.clone()]).with_file_limit(2);
        assert_eq!(s.scan("1", "n").len(), 2);
        fs::write(root.join("new.txt"), "n").unwrap();
        assert!(s.scan("1", "n").is_empty(), "a file past the limit reported");
        assert_eq!(s.baseline.len(), 2);
    }

    /// A junction inside a monitored folder is not followed (no loops, nothing outside).
    #[cfg(windows)]
    #[test]
    fn junction_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, outside) = (tmp.path().join("root"), tmp.path().join("outside"));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("in.txt"), "i").unwrap();
        fs::write(outside.join("out.txt"), "o").unwrap();
        for (link, target) in [(root.join("j"), &outside), (root.join("loop"), &root)] {
            let ok = std::process::Command::new("cmd").arg("/C").arg("mklink").arg("/J").arg(&link).arg(target).output().unwrap();
            assert!(ok.status.success(), "{ok:?}");
        }
        let mut s = FimScanner::new(vec![root.clone()]);
        let ev = s.scan("1", "n");
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert!(s.recheck(&root.join("j"), true, None, "1", "n").is_empty());
    }

    /// Permission and attribute changes (content untouched) are reported with what changed.
    #[cfg(windows)]
    #[test]
    fn permission_and_attribute_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("p.txt");
        fs::write(&f, "x").unwrap();
        let mut s = FimScanner::new(vec![tmp.path().to_path_buf()]);
        let ev = s.scan("1", "n");
        let added = &ev[0]["syscheck"];
        assert!(added["owner_sid_after"].as_str().unwrap().starts_with("S-1-"), "{added}");
        assert!(added["permissions_after"].as_str().unwrap().starts_with("D:"), "{added}");
        assert!(!added["owner_after"].as_str().unwrap().is_empty());
        assert!(added["attributes_after"].as_str().unwrap().contains("ARCHIVE"));

        let ok = std::process::Command::new("icacls").arg(&f).arg("/grant").arg("*S-1-1-0:(R)").output().unwrap();
        assert!(ok.status.success(), "{ok:?}");
        let ev = s.scan("1", "n");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["syscheck"]["changed_attributes"], json!(["permission"]));
        assert_ne!(ev[0]["syscheck"]["permissions_before"], ev[0]["syscheck"]["permissions_after"]);

        let mut p = fs::metadata(&f).unwrap().permissions();
        p.set_readonly(true);
        fs::set_permissions(&f, p.clone()).unwrap();
        let ev = s.scan("1", "n");
        assert_eq!(ev[0]["syscheck"]["changed_attributes"], json!(["attributes"]));
        assert!(ev[0]["syscheck"]["attributes_after"].as_str().unwrap().contains("READONLY"));
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        fs::set_permissions(&f, p).unwrap();
    }

    /// A re-check is not held up by a running scheduled scan (the lock is taken per file).
    #[test]
    fn recheck_runs_during_scan() {
        use std::sync::Arc;
        use std::time::Instant;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        // hashing this takes a while (seconds in a debug build)
        fs::write(root.join("big.bin"), vec![7u8; 96 * 1024 * 1024]).unwrap();
        let fim = Arc::new(Mutex::new(FimScanner::new(vec![root.clone()])));
        let f2 = fim.clone();
        let scan = std::thread::spawn(move || scan_shared(&f2, "1", "n", || true));
        std::thread::sleep(Duration::from_millis(100));
        fs::write(root.join("small.txt"), "s").unwrap();
        let start = Instant::now();
        let ev = fim.lock().unwrap().recheck(&root.join("small.txt"), true, None, "1", "n");
        let took = start.elapsed();
        let still_scanning = !scan.is_finished();
        assert_eq!(ev.len(), 1);
        assert!(still_scanning, "the scan ended before the re-check; make big.bin bigger");
        assert!(took < Duration::from_millis(500), "re-check waited {took:?}");
        let scan_events = scan.join().unwrap();
        // the scan left the re-checked file alone, and kept it
        assert!(scan_events.iter().all(|e| !e["syscheck"]["path"].as_str().unwrap().ends_with("small.txt")), "{scan_events:?}");
        assert!(fim.lock().unwrap().scan("1", "n").is_empty());
    }

    /// A scan cut short by the stop: a first scan is not saved; a later one reports what it
    /// found so far and takes nothing as deleted.
    #[test]
    fn stopped_scan_takes_nothing_as_deleted() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn first_file_only() -> bool {
            CALLS.fetch_add(1, Ordering::SeqCst) == 0
        }
        let tmp = tempfile::tempdir().unwrap();
        let (root, db) = (tmp.path().join("w"), tmp.path().join("fim.db"));
        fs::create_dir_all(&root).unwrap();
        for n in ["a", "b", "c"] {
            fs::write(root.join(n), n).unwrap();
        }
        let open = || Mutex::new(FimScanner::new(vec![root.clone()]).with_database(&db));

        assert!(scan_shared(&open(), "1", "pc", first_file_only).is_empty());
        let m = open();
        assert!(m.lock().unwrap().first_scan_quiet, "a first scan cut short is not saved");
        assert!(scan_shared(&m, "1", "pc", || true).is_empty());

        for n in ["a", "b", "c"] {
            fs::write(root.join(n), format!("{n} changed")).unwrap();
        }
        CALLS.store(0, Ordering::SeqCst);
        let ev = scan_shared(&m, "1", "pc", first_file_only);
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0]["syscheck"]["event"], "modified");
        let ev = scan_shared(&m, "1", "pc", || true);
        assert_eq!(ev.len(), 2, "the rest at the next scan, nothing deleted: {ev:?}");
        assert!(ev.iter().all(|e| e["syscheck"]["event"] == "modified"));
    }

    fn entries(buffer: &EventBuffer) -> Vec<Vec<Value>> {
        let events = buffer.drain_batch(1000);
        assert!(events.iter().all(|e| e["event_type"] == "fim_state" && e["agent"]["id"].is_string()), "{events:?}");
        events.iter().map(|e| e["entries"].as_array().unwrap().clone()).collect()
    }

    /// Once per agent id, a restart included; a new id or the marker gone (`lib.rs` on a new
    /// enrollment, also under the same id) sends it again.
    #[test]
    fn baseline_sent_once_per_agent_id() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, synced) = (tmp.path().join("w"), tmp.path().join("fim_synced.json"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), "abc").unwrap();
        let db = tmp.path().join("fim.db");
        let buffer = EventBuffer::new(100);
        let agent = |id: &str| (id.to_string(), "pc".to_string());
        let start = || {
            let m = Mutex::new(FimScanner::new(vec![root.clone()]).with_database(&db));
            assert!(scan_shared(&m, "1", "pc", || true).is_empty(), "the first scan is quiet");
            m
        };
        let fim = start();
        sync_files(&fim, &buffer, &agent("7"), &synced, || true, || true);
        let sent = entries(&buffer);
        assert_eq!(sent.len(), 1);
        let e = &sent[0][0];
        assert_eq!(e["path"], root.join("a.txt").to_string_lossy().as_ref());
        assert_eq!((&e["size_after"], e["sha256_after"].as_str().map(str::len)), (&json!(3), Some(64)));

        sync_files(&fim, &buffer, &agent("7"), &synced, || true, || true);
        drop(fim);
        sync_files(&start(), &buffer, &agent("7"), &synced, || true, || true);
        assert!(buffer.is_empty(), "not again, nor after a restart");

        sync_files(&start(), &buffer, &agent("8"), &synced, || true, || true);
        assert_eq!(entries(&buffer).len(), 1, "a new id: again");
        fs::remove_file(&synced).unwrap();
        sync_files(&start(), &buffer, &agent("8"), &synced, || true, || true);
        assert_eq!(entries(&buffer).len(), 1, "a new enrollment under the same id: again");
    }

    #[test]
    fn stopped_send_is_not_remembered() {
        let tmp = tempfile::tempdir().unwrap();
        let synced = tmp.path().join("fim_synced.json");
        let buffer = EventBuffer::new(100);
        send_state(&buffer, &("7".into(), "pc".into()), &synced, "files", &[1, 2], || false, || true, |_| Vec::new());
        assert!(buffer.is_empty() && !state_sent(&synced, "files", "7"));
    }

    /// 200 entries a batch, a second apart, read when each leaves; each part remembered on its own.
    #[test]
    fn batches_of_200_paced() {
        let tmp = tempfile::tempdir().unwrap();
        let synced = tmp.path().join("fim_synced.json");
        let buffer = EventBuffer::new(100);
        let keys: Vec<u32> = (0..450).collect();
        let t = std::time::Instant::now();
        let mut reads = 0;
        send_state(&buffer, &("7".into(), "pc".into()), &synced, "registry", &keys, || true, || true, |b| {
            reads += 1;
            b.iter().map(|k| json!({ "n": k, "read": reads })).collect()
        });
        assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
        let sent = entries(&buffer);
        assert_eq!(sent.iter().map(Vec::len).collect::<Vec<_>>(), [200, 200, 50]);
        assert_eq!(sent[2][0]["read"], 3);
        assert!(state_sent(&synced, "registry", "7") && !state_sent(&synced, "files", "7"));
    }

    /// Nothing is queued until the manager gives the slot, asked for meanwhile; the last batch
    /// is marked.
    #[test]
    fn baseline_waits_for_the_slot() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static SLOT: AtomicBool = AtomicBool::new(false);
        let tmp = tempfile::tempdir().unwrap();
        let synced = tmp.path().join("fim_synced.json");
        let buffer = std::sync::Arc::new(EventBuffer::new(1000));
        let keys: Vec<u32> = (0..250).collect();
        let (b, s) = (buffer.clone(), synced.clone());
        let send = std::thread::spawn(move || send_state(&b, &("7".into(), "pc".into()), &s, "files", &keys, || true, || SLOT.load(Ordering::SeqCst), |b| b.iter().map(|k| json!(k)).collect()));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(buffer.is_empty(), "no slot yet");
        assert!(state_wanted(), "asked for in the keepalive");
        SLOT.store(true, Ordering::SeqCst);
        send.join().unwrap();
        let sent = buffer.drain_batch(10);
        assert_eq!(sent.iter().map(|e| e["last"].as_bool()).collect::<Vec<_>>(), [Some(false), Some(true)]);
        assert!(state_sent(&synced, "files", "7"));
    }

    /// A batch waits while real events are queued; a stop ends the wait.
    #[test]
    fn backlog_holds_the_next_batch() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static RUN: AtomicBool = AtomicBool::new(true);
        let tmp = tempfile::tempdir().unwrap();
        let synced = tmp.path().join("fim_synced.json");
        let buffer = std::sync::Arc::new(EventBuffer::new(1000));
        (0..STATE_BACKLOG).for_each(|i| buffer.push(json!({ "id": i })));
        let keys: Vec<u32> = (0..250).collect();
        let (b, s) = (buffer.clone(), synced.clone());
        let send = std::thread::spawn(move || send_state(&b, &("7".into(), "pc".into()), &s, "files", &keys, || RUN.load(Ordering::SeqCst), || true, |_| Vec::new()));
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(buffer.len(), STATE_BACKLOG + 1, "the second batch waits");
        RUN.store(false, Ordering::SeqCst);
        send.join().unwrap();
        assert!(!state_sent(&synced, "files", "7"));
    }
}
