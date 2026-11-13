use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

/// Structured attribution ("Who") for a file system modification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WhodataInfo {
    pub user_name: Option<String>,
    pub user_id: Option<u32>,
    pub audit_uid: Option<u32>,
    pub audit_name: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub parent_name: Option<String>,
    pub cwd: Option<String>,
}

impl WhodataInfo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user(mut self, uid: u32, name: impl Into<String>) -> Self {
        self.user_id = Some(uid);
        self.user_name = Some(name.into());
        self
    }

    pub fn with_audit_user(mut self, auid: u32, name: impl Into<String>) -> Self {
        self.audit_uid = Some(auid);
        self.audit_name = Some(name.into());
        self
    }

    pub fn with_process(mut self, pid: u32, ppid: Option<u32>, name: impl Into<String>) -> Self {
        self.process_id = Some(pid);
        self.parent_process_id = ppid;
        self.process_name = Some(name.into());
        self
    }

    pub fn with_parent(mut self, ppid: u32, name: impl Into<String>) -> Self {
        self.parent_process_id = Some(ppid);
        self.parent_name = Some(name.into());
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

/// An aggregated audit record representing a file system event from auditd
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub timestamp_sec: u64,
    pub serial: u64,
    pub path: String,
    pub whodata: WhodataInfo,
}

/// Partial record while assembling multi-line audit records sharing the same event serial
#[derive(Debug, Default, Clone)]
struct PendingAuditRecord {
    timestamp_sec: u64,
    serial: u64,
    paths: Vec<String>,
    whodata: WhodataInfo,
}

/// Linux Audit Whodata Engine: monitors Linux audit records, caches user IDs,
/// and correlates file tampering events with the initiating user and process.
#[derive(Clone)]
pub struct AuditWhodataEngine {
    records: Arc<RwLock<VecDeque<AuditRecord>>>,
    pending: Arc<RwLock<HashMap<u64, PendingAuditRecord>>>,
    user_cache: Arc<RwLock<HashMap<u32, String>>>,
    max_records: usize,
}

impl AuditWhodataEngine {
    pub fn new(max_records: usize) -> Self {
        let engine = Self {
            records: Arc::new(RwLock::new(VecDeque::with_capacity(max_records))),
            pending: Arc::new(RwLock::new(HashMap::new())),
            user_cache: Arc::new(RwLock::new(HashMap::new())),
            max_records,
        };
        engine.load_passwd_users();
        engine
    }

    /// Read `/etc/passwd` to populate initial UID -> username mapping
    pub fn load_passwd_users(&self) {
        let passwd_path = Path::new("/etc/passwd");
        if !passwd_path.exists() {
            // Populate standard system users if running in test / container environment
            if let Ok(mut cache) = self.user_cache.write() {
                cache.insert(0, "root".to_string());
                cache.insert(1000, "user".to_string());
            }
            return;
        }

        if let Ok(file) = File::open(passwd_path) {
            let reader = BufReader::new(file);
            let mut map = HashMap::new();
            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split(':').collect();
                if parts.len() >= 3 {
                    let user_name = parts[0].to_string();
                    if let Ok(uid) = parts[2].parse::<u32>() {
                        map.insert(uid, user_name);
                    }
                }
            }
            if let Ok(mut cache) = self.user_cache.write() {
                *cache = map;
            }
        }
    }

    /// Resolve a numeric UID or AUID to a human username
    pub fn resolve_user(&self, uid: u32) -> String {
        // Special case for unset audit user ID (4294967295 / -1)
        if uid == u32::MAX {
            return "unset".to_string();
        }

        if let Ok(cache) = self.user_cache.read() {
            if let Some(name) = cache.get(&uid) {
                return name.clone();
            }
        }

        // On Linux, try getpwuid
        #[cfg(target_os = "linux")]
        {
            let pw = unsafe { libc::getpwuid(uid as libc::uid_t) };
            if !pw.is_null() {
                let c_str = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
                if let Ok(name) = c_str.to_str() {
                    let name_str = name.to_string();
                    if let Ok(mut cache) = self.user_cache.write() {
                        cache.insert(uid, name_str.clone());
                    }
                    return name_str;
                }
            }
        }

        match uid {
            0 => "root".to_string(),
            _ => format!("uid_{}", uid),
        }
    }

    /// Ingest a single raw line from Linux Audit (audit.log or Netlink feed)
    pub fn ingest_audit_line(&self, line: &str) {
        let trimmed = line.trim();
        if !trimmed.starts_with("type=") {
            return;
        }

        let kv = Self::parse_audit_kv(trimmed);
        let Some(msg_raw) = kv.get("msg") else { return };
        let (timestamp_sec, serial) = Self::parse_audit_msg_header(msg_raw);
        if serial == 0 {
            return;
        }

        let rec_type = kv.get("type").map(|s| s.as_str()).unwrap_or("");

        let mut pending_guard = match self.pending.write() {
            Ok(g) => g,
            Err(_) => return,
        };

        let entry = pending_guard.entry(serial).or_insert_with(|| PendingAuditRecord {
            timestamp_sec,
            serial,
            paths: Vec::new(),
            whodata: WhodataInfo::new(),
        });

        match rec_type {
            "SYSCALL" => {
                if let Some(uid_str) = kv.get("uid") {
                    if let Ok(uid) = uid_str.parse::<u32>() {
                        let name = self.resolve_user(uid);
                        entry.whodata.user_id = Some(uid);
                        entry.whodata.user_name = Some(name);
                    }
                }
                if let Some(auid_str) = kv.get("auid") {
                    if let Ok(auid) = auid_str.parse::<u32>() {
                        if auid != u32::MAX {
                            let name = self.resolve_user(auid);
                            entry.whodata.audit_uid = Some(auid);
                            entry.whodata.audit_name = Some(name);
                        }
                    }
                }
                if let Some(pid_str) = kv.get("pid") {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        entry.whodata.process_id = Some(pid);
                    }
                }
                if let Some(ppid_str) = kv.get("ppid") {
                    if let Ok(ppid) = ppid_str.parse::<u32>() {
                        entry.whodata.parent_process_id = Some(ppid);
                    }
                }
                if let Some(exe) = kv.get("exe") {
                    let cleaned = Self::decode_hex_or_quoted(exe);
                    entry.whodata.process_name = Some(cleaned);
                } else if let Some(comm) = kv.get("comm") {
                    let cleaned = Self::decode_hex_or_quoted(comm);
                    entry.whodata.process_name = Some(cleaned);
                }
            }
            "PATH" => {
                if let Some(name) = kv.get("name") {
                    let cleaned = Self::decode_hex_or_quoted(name);
                    if !cleaned.is_empty() && !cleaned.starts_with("(null)") {
                        entry.paths.push(cleaned);
                    }
                }
            }
            "CWD" => {
                if let Some(cwd) = kv.get("cwd") {
                    entry.whodata.cwd = Some(Self::decode_hex_or_quoted(cwd));
                }
            }
            _ => {}
        }

        // If we have paths and syscall attribution, commit to the active records ring buffer
        if !entry.paths.is_empty() && (entry.whodata.user_id.is_some() || entry.whodata.process_id.is_some()) {
            let completed = entry.clone();
            drop(pending_guard);

            if let Ok(mut records) = self.records.write() {
                for path in completed.paths {
                    records.push_back(AuditRecord {
                        timestamp_sec: completed.timestamp_sec,
                        serial: completed.serial,
                        path,
                        whodata: completed.whodata.clone(),
                    });
                    if records.len() > self.max_records {
                        records.pop_front();
                    }
                }
            }
        }
    }

    /// Correlate a file modification detected by inotify with the responsible user and process
    pub fn correlate(&self, file_path: &Path) -> Option<WhodataInfo> {
        let path_str = file_path.to_string_lossy().to_string();
        let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let records = self.records.read().ok()?;

        // Traverse records in reverse chronological order (newest first)
        for record in records.iter().rev() {
            // Only correlate events within a reasonable time window (last 5 seconds)
            if now_sec >= record.timestamp_sec && (now_sec - record.timestamp_sec) > 5 {
                continue;
            }

            // Path matching: exact match, canonical match, or basename match
            let rec_path = &record.path;
            if rec_path == &path_str
                || rec_path.ends_with(&path_str)
                || path_str.ends_with(rec_path)
                || (!file_name.is_empty() && rec_path.ends_with(file_name))
            {
                debug!(
                    "provigil-whodata: Correlated file '{}' to user '{:?}' (process: '{:?}')",
                    path_str, record.whodata.user_name, record.whodata.process_name
                );
                return Some(record.whodata.clone());
            }
        }

        None
    }

    /// Spawns background worker tailing `/var/log/audit/audit.log`
    pub fn spawn_audit_tailer(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let candidate_paths = [
                "/var/log/audit/audit.log",
            ];

            let mut target_path: Option<PathBuf> = None;
            for p in &candidate_paths {
                let pb = PathBuf::from(p);
                if pb.exists() {
                    target_path = Some(pb);
                    break;
                }
            }

            let Some(audit_file) = target_path else {
                info!("provigil-whodata: Linux audit.log not present. Whodata engine ready for dynamic event ingestion.");
                return;
            };

            info!("provigil-whodata: Tailing Linux audit log stream at '{}'", audit_file.display());

            let mut offset = std::fs::metadata(&audit_file).map(|m| m.len()).unwrap_or(0);

            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;

                if let Ok(meta) = std::fs::metadata(&audit_file) {
                    if meta.len() < offset {
                        // Log rotation detected
                        offset = 0;
                    }
                }

                if let Ok(file) = File::open(&audit_file) {
                    let mut reader = BufReader::new(file);
                    if reader.seek(SeekFrom::Start(offset)).is_ok() {
                        let mut line = String::new();
                        while let Ok(n) = reader.read_line(&mut line) {
                            if n == 0 {
                                break;
                            }
                            offset += n as u64;
                            self.ingest_audit_line(&line);
                            line.clear();
                        }
                    }
                }
            }
        })
    }

    /// Helper to install Linux audit watch rules using `auditctl` if elevated
    pub fn setup_audit_watch_rules(paths: &[PathBuf]) {
        #[cfg(target_os = "linux")]
        {
            for path in paths {
                if !path.exists() {
                    continue;
                }
                let path_str = path.to_string_lossy();
                let status = std::process::Command::new("auditctl")
                    .args(["-w", &path_str, "-p", "wa", "-k", "provigil_fim"])
                    .status();

                match status {
                    Ok(s) if s.success() => {
                        debug!("provigil-whodata: auditctl watch rule installed for '{}'", path_str);
                    }
                    _ => {
                        debug!("provigil-whodata: Note: auditctl watch rule skipped for '{}' (non-root or auditctl absent)", path_str);
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = paths;
    }

    /// Parse key=value tokens from an audit log line
    fn parse_audit_kv(line: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let mut chars = line.chars().peekable();

        while let Some(&ch) = chars.peek() {
            if ch.is_whitespace() {
                chars.next();
                continue;
            }

            // Read key
            let mut key = String::new();
            while let Some(&kch) = chars.peek() {
                if kch == '=' || kch.is_whitespace() {
                    break;
                }
                key.push(kch);
                chars.next();
            }

            if chars.peek() == Some(&'=') {
                chars.next(); // consume '='
                let mut val = String::new();

                if chars.peek() == Some(&'"') {
                    chars.next(); // consume opening quote
                    while let Some(&vch) = chars.peek() {
                        if vch == '"' {
                            chars.next(); // consume closing quote
                            break;
                        }
                        val.push(vch);
                        chars.next();
                    }
                } else {
                    while let Some(&vch) = chars.peek() {
                        if vch.is_whitespace() {
                            break;
                        }
                        val.push(vch);
                        chars.next();
                    }
                }
                if !key.is_empty() {
                    map.insert(key, val);
                }
            }
        }
        map
    }

    /// Extracts seconds and serial number from `audit(1698765432.123:456)`
    fn parse_audit_msg_header(msg_field: &str) -> (u64, u64) {
        let start = msg_field.find('(').map(|i| i + 1).unwrap_or(0);
        let end = msg_field.find(')').unwrap_or(msg_field.len());
        let inner = &msg_field[start..end];

        let mut parts = inner.split(':');
        let ts_part = parts.next().unwrap_or("0");
        let serial_part = parts.next().unwrap_or("0");

        let sec = ts_part.split('.').next().unwrap_or("0").parse::<u64>().unwrap_or(0);
        let serial = serial_part.parse::<u64>().unwrap_or(0);

        (sec, serial)
    }

    /// Decode hex-encoded paths or command strings produced by auditd
    fn decode_hex_or_quoted(s: &str) -> String {
        let trimmed = s.trim_matches('"');
        // Auditd hex-encodes paths with special characters
        if trimmed.len() >= 2 && trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(bytes) = hex::decode(trimmed) {
                if let Ok(utf) = String::from_utf8(bytes) {
                    if utf.chars().all(|c| !c.is_control() || c.is_whitespace()) {
                        return utf;
                    }
                }
            }
        }
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_audit_msg_header() {
        let header = "audit(1700000000.123:456)";
        let (sec, serial) = AuditWhodataEngine::parse_audit_msg_header(header);
        assert_eq!(sec, 1700000000);
        assert_eq!(serial, 456);
    }

    #[test]
    fn test_decode_hex_or_quoted() {
        assert_eq!(AuditWhodataEngine::decode_hex_or_quoted("\"/var/log/syslog\""), "/var/log/syslog");
        assert_eq!(AuditWhodataEngine::decode_hex_or_quoted("plain_name"), "plain_name");
        // Hex for "/etc/passwd" -> 2f6574632f706173737764
        assert_eq!(AuditWhodataEngine::decode_hex_or_quoted("2f6574632f706173737764"), "/etc/passwd");
    }

    #[test]
    fn test_audit_whodata_correlation() {
        let engine = AuditWhodataEngine::new(100);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let syscall_line = format!(
            "type=SYSCALL msg=audit({}.500:999): arch=c000003e syscall=257 success=yes exit=3 items=1 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 comm=\"vim\" exe=\"/usr/bin/vim\"",
            now
        );
        let path_line = format!(
            "type=PATH msg=audit({}.500:999): item=0 name=\"/etc/shadow\" inode=12345 dev=08:01 mode=0100640",
            now
        );
        let cwd_line = format!(
            "type=CWD msg=audit({}.500:999): cwd=\"/root\"",
            now
        );

        engine.ingest_audit_line(&syscall_line);
        engine.ingest_audit_line(&cwd_line);
        engine.ingest_audit_line(&path_line);

        let correlated = engine.correlate(Path::new("/etc/shadow"));
        assert!(correlated.is_some(), "Expected correlation to find audit record for /etc/shadow");
        let info = correlated.unwrap();
        assert_eq!(info.process_name.as_deref(), Some("/usr/bin/vim"));
        assert_eq!(info.process_id, Some(5678));
        assert_eq!(info.parent_process_id, Some(1234));
        assert_eq!(info.audit_uid, Some(1000));
        assert_eq!(info.user_id, Some(0));
        assert_eq!(info.cwd.as_deref(), Some("/root"));
    }
}
