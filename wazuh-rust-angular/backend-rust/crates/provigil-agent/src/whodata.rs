//! Who-data: which user and process changed a file in a who-data folder.
//!
//! Source: the Security channel's object access events: 4656 (handle requested) and 4663
//! (access) give the path, user and process of a handle; at 4658 (handle closed) or 4660
//! (object deleted) the change is done and the path is re-checked against the baseline
//! (`FimScanner::recheck`), the event carrying who did it.
//!
//! Start (administrator rights): `SeSecurityPrivilege` enabled, the audit policy saved to
//! `data\audit_policy_backup.csv` and success auditing of "File System" and "Handle
//! Manipulation" turned on, an audit entry (SACL) for Everyone put on each folder. Stop: exactly
//! the audit entries this agent added are removed and the saved policy restored.
//!
//! 100% clean-room Rust implementation (zero GPL derivation).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

use crate::wevt::between;

/// Who made a change; sent as the event's `"whodata"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Who {
    pub user_name: String,
    /// The user's SID.
    pub user_id: String,
    pub process_name: String,
    pub process_id: u32,
    pub access_mask: u32,
}

/// The fields of a 4656 / 4663 / 4658 / 4660 event this module reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_id: u32,
    pub process_id: u32,
    pub handle_id: u64,
    /// `ObjectName` (4656 and 4663 only).
    pub path: Option<String>,
    pub user_name: String,
    pub user_id: String,
    pub process_name: String,
    pub access_mask: u32,
}

/// The text of `<Data Name='name'>text</Data>` (either quote style).
fn data<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    ['\'', '"'].iter().find_map(|q| between(xml, &format!("Name={q}{name}{q}>"), "<"))
}

fn hex(s: &str) -> Option<u64> {
    let s = s.trim();
    u64::from_str_radix(s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s), 16).ok()
}

impl AuditEvent {
    /// From the event XML; `None` for other events or when the handle fields are missing.
    pub fn from_xml(xml: &str) -> Option<AuditEvent> {
        let event_id: u32 = between(xml, "<EventID", "</EventID>")?.rsplit('>').next()?.trim().parse().ok()?;
        if !matches!(event_id, 4656 | 4663 | 4658 | 4660) {
            return None;
        }
        let text = |name: &str| data(xml, name).unwrap_or_default().to_string();
        Some(AuditEvent {
            event_id,
            process_id: hex(data(xml, "ProcessId")?)? as u32,
            handle_id: hex(data(xml, "HandleId")?)?,
            path: data(xml, "ObjectName").filter(|p| !p.is_empty()).map(str::to_string),
            user_name: text("SubjectUserName"),
            user_id: text("SubjectUserSid"),
            process_name: text("ProcessName"),
            access_mask: data(xml, "AccessMask").and_then(hex).unwrap_or(0) as u32,
        })
    }
}

/// Correlation entries older than this are dropped.
pub const MAX_AGE: Duration = Duration::from_secs(300);

/// Open handles on files under the who-data folders, by (process id, handle id).
pub struct Correlator {
    /// Lower-case folders.
    folders: Vec<PathBuf>,
    open: HashMap<(u32, u64), (PathBuf, Who, Instant)>,
}

impl Correlator {
    pub fn new(folders: &[PathBuf]) -> Self {
        let folders = folders.iter().map(|f| PathBuf::from(f.to_string_lossy().to_lowercase())).collect();
        Self { folders, open: HashMap::new() }
    }

    fn watched(&self, path: &str) -> bool {
        let p = PathBuf::from(path.to_lowercase());
        self.folders.iter().any(|f| p.starts_with(f))
    }

    /// Takes one event; at a handle's close or delete, the finished change (path, who).
    pub fn feed(&mut self, ev: AuditEvent, now: Instant) -> Option<(PathBuf, Who)> {
        let key = (ev.process_id, ev.handle_id);
        match ev.event_id {
            4656 | 4663 => {
                let path = ev.path.filter(|p| self.watched(p))?;
                let entry = self.open.entry(key).or_insert_with(|| {
                    let who = Who {
                        user_name: ev.user_name,
                        user_id: ev.user_id,
                        process_name: ev.process_name,
                        process_id: ev.process_id,
                        access_mask: 0,
                    };
                    (PathBuf::from(path), who, now)
                });
                entry.1.access_mask |= ev.access_mask;
                entry.2 = now;
                None
            }
            // an orphan close (a handle not on a watched file, or already expired) is ignored
            4658 | 4660 => self.open.remove(&key).map(|(p, w, _)| (p, w)),
            _ => None,
        }
    }

    /// Drops entries not seen for [`MAX_AGE`].
    pub fn expire(&mut self, now: Instant) {
        self.open.retain(|_, (_, _, seen)| now.duration_since(*seen) < MAX_AGE);
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

#[cfg(windows)]
pub use win::{has_audit_entry, spawn, start, Session};

/// Who-data needs Windows.
#[cfg(not(windows))]
pub struct Session;

#[cfg(not(windows))]
pub fn start(_folders: &[PathBuf], _data_dir: &Path) -> Result<Session, String> {
    Err("who-data needs Windows".into())
}

#[cfg(not(windows))]
pub fn spawn(
    _session: Session,
    _fim: std::sync::Arc<std::sync::Mutex<crate::fim::FimScanner>>,
    _buffer: std::sync::Arc<crate::buffer::EventBuffer>,
    _agent: (String, String),
    _running: fn() -> bool,
) -> Option<std::thread::JoinHandle<()>> {
    None
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use tracing::{error, info, warn};
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_NOT_ALL_ASSIGNED, ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, HANDLE, LUID, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        AddAce, AddAuditAccessAceEx, AdjustTokenPrivileges, AclSizeInformation, DeleteAce, EqualSid, GetAce,
        GetAclInformation, GetLengthSid, InitializeAcl, LookupPrivilegeValueW, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
        CONTAINER_INHERIT_ACE, LUID_AND_ATTRIBUTES, OBJECT_INHERIT_ACE, PSID, SACL_SECURITY_INFORMATION,
        SE_PRIVILEGE_ENABLED, SE_SECURITY_NAME, SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_AUDIT_ACE,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, WRITE_DAC};
    use windows_sys::Win32::System::EventLog::{EvtNext, EvtRenderEventXml, EvtSubscribe, EvtSubscribeToFutureEvents, EVT_HANDLE};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, OpenProcessToken, ResetEvent, WaitForSingleObject,
    };

    use crate::buffer::EventBuffer;
    use crate::fim::FimScanner;
    use crate::wevt::win::{last_error, render, wide, Evt, Signal};

    /// Audited on the folders: write data, append data, write attributes, change permissions, delete.
    const AUDIT_MASK: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | DELETE;
    /// `SYSTEM_AUDIT_ACE_TYPE` (its declaration sits in a windows-sys feature not otherwise needed).
    const SYSTEM_AUDIT_ACE_TYPE: u32 = 2;
    /// Inherited by files and subfolders.
    const INHERIT: u32 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    /// Audit policy subcategories by GUID (their names are translated on non-English Windows).
    const FILE_SYSTEM: &str = "{0CCE921D-69AE-11D9-BED3-505054503030}";
    const HANDLE_MANIPULATION: &str = "{0CCE9223-69AE-11D9-BED3-505054503030}";
    const QUERY: &str = "*[System[(EventID=4656 or EventID=4663 or EventID=4658 or EventID=4660)]]";
    /// Expired correlation entries dropped and lost audit entries put back this often.
    const UPKEEP: Duration = Duration::from_secs(300);

    /// System-allocated memory, freed when dropped.
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn everyone() -> Result<Local, String> {
        let mut sid: PSID = null_mut();
        if unsafe { ConvertStringSidToSidW(wide("S-1-1-0").as_ptr(), &mut sid) } == 0 {
            return Err(format!("Everyone SID not built: error {}", last_error()));
        }
        Ok(Local(sid))
    }

    /// The SACL (null when there is none) and the security descriptor holding it.
    fn read_sacl(path: &Path) -> Result<(Local, *mut ACL), String> {
        let (mut sacl, mut sd) = (null_mut(), null_mut());
        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide(&path.to_string_lossy()).as_ptr(), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
                null_mut(), null_mut(), null_mut(), &mut sacl, &mut sd,
            )
        };
        if rc != 0 {
            return Err(format!("audit entries not read: error {rc}"));
        }
        Ok((Local(sd), sacl))
    }

    fn write_sacl(path: &Path, acl: *const ACL) -> Result<(), String> {
        let rc = unsafe {
            SetNamedSecurityInfoW(
                wide(&path.to_string_lossy()).as_ptr(), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
                null_mut(), null_mut(), null(), acl,
            )
        };
        if rc != 0 {
            return Err(format!("audit entries not written: error {rc}"));
        }
        Ok(())
    }

    /// Index of this agent's audit entry (explicit, exactly our flags, mask and SID).
    ///
    /// Safety: `acl` is null or a valid ACL, `sid` a valid SID.
    unsafe fn find_ace(acl: *const ACL, sid: PSID) -> Option<u32> {
        if acl.is_null() {
            return None;
        }
        (0..u32::from((*acl).AceCount)).find(|&i| {
            let mut p = null_mut();
            if GetAce(acl, i, &mut p) == 0 {
                return false;
            }
            let ace = &*(p as *const SYSTEM_AUDIT_ACE);
            u32::from(ace.Header.AceType) == SYSTEM_AUDIT_ACE_TYPE
                && u32::from(ace.Header.AceFlags) == INHERIT | SUCCESSFUL_ACCESS_ACE_FLAG
                && ace.Mask == AUDIT_MASK
                && EqualSid((&ace.SidStart as *const u32).cast_mut().cast(), sid) != 0
        })
    }

    /// Whether the folder carries this agent's audit entry.
    pub fn has_audit_entry(path: &Path) -> bool {
        let (Ok(sid), Ok((_sd, sacl))) = (everyone(), read_sacl(path)) else { return false };
        unsafe { find_ace(sacl, sid.0).is_some() }
    }

    /// Adds the audit entry; `false` when it is already there.
    fn add_ace(path: &Path) -> Result<bool, String> {
        let sid = everyone()?;
        let (_sd, old) = read_sacl(path)?;
        unsafe {
            if find_ace(old, sid.0).is_some() {
                return Ok(false);
            }
            let (mut used, mut rev) = (0u32, ACL_REVISION);
            if !old.is_null() {
                let mut info = ACL_SIZE_INFORMATION { AceCount: 0, AclBytesInUse: 0, AclBytesFree: 0 };
                let size = size_of::<ACL_SIZE_INFORMATION>() as u32;
                if GetAclInformation(old, (&mut info as *mut ACL_SIZE_INFORMATION).cast(), size, AclSizeInformation) == 0 {
                    return Err(format!("audit entries not readable: error {}", last_error()));
                }
                used = info.AclBytesInUse - size_of::<ACL>() as u32;
                rev = rev.max(u32::from((*old).AclRevision));
            }
            let size = size_of::<ACL>() as u32 + used + size_of::<SYSTEM_AUDIT_ACE>() as u32 - 4 + GetLengthSid(sid.0);
            let mut buf = vec![0u32; (size as usize).div_ceil(4)];
            let acl: *mut ACL = buf.as_mut_ptr().cast();
            if InitializeAcl(acl, (buf.len() * 4) as u32, rev) == 0 {
                return Err(format!("audit list not built: error {}", last_error()));
            }
            if used > 0 {
                // the existing entries are contiguous after the header: copied in one go
                let mut first = null_mut();
                if GetAce(old, 0, &mut first) == 0 || AddAce(acl, rev, 0, first, used) == 0 {
                    return Err(format!("existing audit entries not copied: error {}", last_error()));
                }
            }
            if AddAuditAccessAceEx(acl, rev, INHERIT, AUDIT_MASK, sid.0, 1, 0) == 0 {
                return Err(format!("audit entry not built: error {}", last_error()));
            }
            write_sacl(path, acl)?;
        }
        Ok(true)
    }

    /// Removes the audit entry; `false` when it is not there.
    fn remove_ace(path: &Path) -> Result<bool, String> {
        let sid = everyone()?;
        let (_sd, sacl) = read_sacl(path)?;
        unsafe {
            let Some(i) = find_ace(sacl, sid.0) else { return Ok(false) };
            if DeleteAce(sacl, i) == 0 {
                return Err(format!("audit entry not removed: error {}", last_error()));
            }
            write_sacl(path, sacl)?;
        }
        Ok(true)
    }

    fn enable_security_privilege() -> Result<(), String> {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
                return Err(format!("process token not opened: error {}", last_error()));
            }
            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: LUID { LowPart: 0, HighPart: 0 }, Attributes: SE_PRIVILEGE_ENABLED }],
            };
            let ok = LookupPrivilegeValueW(null(), SE_SECURITY_NAME, &mut tp.Privileges[0].Luid) != 0
                && AdjustTokenPrivileges(token, 0, &tp, 0, null_mut(), null_mut()) != 0;
            let err = last_error();
            CloseHandle(token);
            if !ok || err == ERROR_NOT_ALL_ASSIGNED {
                return Err("administrator rights needed (SeSecurityPrivilege not available)".into());
            }
        }
        Ok(())
    }

    fn auditpol(args: &[&str]) -> Result<(), String> {
        let out = std::process::Command::new("auditpol").args(args).output().map_err(|e| format!("auditpol not run: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("auditpol {}: {}", args.join(" "), String::from_utf8_lossy(&out.stdout).trim()))
        }
    }

    /// Who-data switched on; dropping it switches it off again (audit entries this agent added
    /// removed, audit policy restored).
    pub struct Session {
        folders: Vec<PathBuf>,
        added: Vec<PathBuf>,
        backup: PathBuf,
        policy_saved: bool,
    }

    /// Enables who-data for `folders`; `Err` (nothing left changed) when not possible.
    pub fn start(folders: &[PathBuf], data_dir: &Path) -> Result<Session, String> {
        enable_security_privilege()?;
        let _ = std::fs::create_dir_all(data_dir);
        let backup = std::path::absolute(data_dir.join("audit_policy_backup.csv")).map_err(|e| e.to_string())?;
        let mut s = Session { folders: folders.to_vec(), added: Vec::new(), backup, policy_saved: false };
        // a backup left by an agent that did not stop cleanly holds the original policy: kept
        if !s.backup.exists() {
            auditpol(&["/backup", &format!("/file:{}", s.backup.display())])?;
        }
        s.policy_saved = true;
        for sub in [FILE_SYSTEM, HANDLE_MANIPULATION] {
            auditpol(&["/set", &format!("/subcategory:{sub}"), "/success:enable"])?;
        }
        s.put_audit_entries(false);
        Ok(s)
    }

    impl Session {
        /// Adds the audit entry to every folder that lacks it.
        fn put_audit_entries(&mut self, again: bool) {
            for f in &self.folders {
                if !f.is_dir() {
                    continue;
                }
                match add_ace(f) {
                    Ok(true) => {
                        if !self.added.contains(f) {
                            self.added.push(f.clone());
                        }
                        if again {
                            info!(folder = %f.display(), "Who-data audit entry was lost (folder recreated?); put back");
                        } else {
                            info!(folder = %f.display(), "Who-data audit entry added");
                        }
                    }
                    Ok(false) => {}
                    Err(e) => warn!(folder = %f.display(), error = %e, "Who-data audit entry not added"),
                }
            }
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            for f in self.added.drain(..) {
                match remove_ace(&f) {
                    Ok(_) => info!(folder = %f.display(), "Who-data audit entry removed"),
                    Err(e) => warn!(folder = %f.display(), error = %e, "Who-data audit entry not removed"),
                }
            }
            if self.policy_saved {
                match auditpol(&["/restore", &format!("/file:{}", self.backup.display())]) {
                    Ok(()) => {
                        let _ = std::fs::remove_file(&self.backup);
                        info!("Audit policy restored");
                    }
                    Err(e) => error!(error = %e, file = %self.backup.display(), "Audit policy not restored; the saved policy stays in this file"),
                }
            }
        }
    }

    /// Fields drop in order: the subscription closes before its signal event.
    struct Subscription(Evt, Signal);

    fn subscribe() -> Result<Subscription, u32> {
        let signal = Signal(unsafe { CreateEventW(null(), 1, 1, null()) });
        if signal.0.is_null() {
            return Err(last_error());
        }
        let h = unsafe {
            EvtSubscribe(0, signal.0, wide("Security").as_ptr(), wide(QUERY).as_ptr(), 0, null(), None, EvtSubscribeToFutureEvents)
        };
        if h == 0 {
            return Err(last_error());
        }
        Ok(Subscription(Evt(h), signal))
    }

    /// Reads the Security channel until the agent stops, then ends the session.
    pub fn spawn(
        session: Session,
        fim: Arc<Mutex<FimScanner>>,
        buffer: Arc<EventBuffer>,
        agent: (String, String),
        running: fn() -> bool,
    ) -> Option<JoinHandle<()>> {
        crate::thread("whodata".into(), move || run(session, fim, buffer, agent, running))
            .map_err(|e| error!(error = %e, "Who-data thread not started"))
            .ok()
    }

    fn run(mut session: Session, fim: Arc<Mutex<FimScanner>>, buffer: Arc<EventBuffer>, agent: (String, String), running: fn() -> bool) {
        let mut corr = Correlator::new(&session.folders);
        let mut upkeep = Instant::now();
        let mut warned = false;
        let mut batch = [0 as EVT_HANDLE; 64];
        while running() {
            let sub = match subscribe() {
                Ok(s) => {
                    info!(folders = session.folders.len(), "Who-data: Security channel subscribed");
                    warned = false;
                    s
                }
                Err(e) => {
                    if !warned {
                        error!(error = e, "Who-data: Security channel not subscribed; trying again every 10 s");
                        warned = true;
                    }
                    crate::nap(Duration::from_secs(10), running);
                    continue;
                }
            };
            'read: while running() {
                if unsafe { WaitForSingleObject(sub.1 .0, 1000) } == WAIT_OBJECT_0 {
                    unsafe { ResetEvent(sub.1 .0) };
                    while running() {
                        let mut n = 0u32;
                        if unsafe { EvtNext(sub.0 .0, batch.len() as u32, batch.as_mut_ptr(), 0, 0, &mut n) } == 0 {
                            match last_error() {
                                ERROR_NO_MORE_ITEMS | ERROR_TIMEOUT => break,
                                e => {
                                    warn!(error = e, "Who-data subscription failed; subscribing again");
                                    break 'read;
                                }
                            }
                        }
                        let events: Vec<Evt> = batch[..n as usize].iter().map(|&h| Evt(h)).collect();
                        for ev in &events {
                            let Some(audit) = render(ev.0, EvtRenderEventXml).as_deref().and_then(AuditEvent::from_xml) else {
                                continue;
                            };
                            if let Some((path, who)) = corr.feed(audit, Instant::now()) {
                                // a folder written to (a file added or renamed into it): its own files only
                                let recursive = !path.is_dir();
                                let out = fim.lock().unwrap_or_else(|e| e.into_inner()).recheck(&path, recursive, Some(&who), &agent.0, &agent.1);
                                out.into_iter().for_each(|e| buffer.push(e));
                            }
                        }
                    }
                }
                if upkeep.elapsed() >= UPKEEP {
                    corr.expire(Instant::now());
                    session.put_audit_entries(true);
                    upkeep = Instant::now();
                }
            }
        }
        // session dropped here: audit entries removed, policy restored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(event_id: u32, handle_id: u64, path: Option<&str>, mask: u32) -> AuditEvent {
        AuditEvent {
            event_id,
            process_id: 4892,
            handle_id,
            path: path.map(str::to_string),
            user_name: "alice".into(),
            user_id: "S-1-5-21-1-1001".into(),
            process_name: r"C:\Windows\System32\notepad.exe".into(),
            access_mask: mask,
        }
    }

    #[test]
    fn handle_sequence_gives_one_change() {
        let mut c = Correlator::new(&[PathBuf::from(r"C:\Data")]);
        let t = Instant::now();
        assert!(c.feed(ev(4656, 0x1a4, Some(r"C:\data\a.txt"), 0x2), t).is_none());
        assert!(c.feed(ev(4663, 0x1a4, Some(r"C:\data\a.txt"), 0x4), t).is_none());
        let (path, who) = c.feed(ev(4658, 0x1a4, None, 0), t).expect("change at close");
        assert_eq!(path, PathBuf::from(r"C:\data\a.txt"));
        assert_eq!(
            who,
            Who {
                user_name: "alice".into(),
                user_id: "S-1-5-21-1-1001".into(),
                process_name: r"C:\Windows\System32\notepad.exe".into(),
                process_id: 4892,
                access_mask: 0x6,
            }
        );
        assert!(c.is_empty());
        // orphan close, a second close, a delete after close: nothing
        assert!(c.feed(ev(4658, 0x999, None, 0), t).is_none());
        assert!(c.feed(ev(4658, 0x1a4, None, 0), t).is_none());
        // delete closes the change too; the close after it is an orphan
        c.feed(ev(4656, 0x10, Some(r"C:\Data\b.txt"), 0x10000), t);
        assert!(c.feed(ev(4660, 0x10, None, 0), t).is_some());
        assert!(c.feed(ev(4658, 0x10, None, 0), t).is_none());
        // outside the folders (and a folder name that only starts the same): not tracked
        c.feed(ev(4656, 0x20, Some(r"C:\Other\c.txt"), 0x2), t);
        c.feed(ev(4656, 0x21, Some(r"C:\DataX\c.txt"), 0x2), t);
        assert!(c.is_empty());
    }

    #[test]
    fn entries_expire() {
        let mut c = Correlator::new(&[PathBuf::from(r"C:\Data")]);
        let t = Instant::now();
        c.feed(ev(4656, 1, Some(r"C:\Data\a"), 2), t);
        c.feed(ev(4656, 2, Some(r"C:\Data\b"), 2), t + Duration::from_secs(200));
        c.expire(t + MAX_AGE + Duration::from_secs(1));
        assert_eq!(c.len(), 1);
        assert!(c.feed(ev(4658, 1, None, 0), t).is_none(), "expired entry");
        assert!(c.feed(ev(4658, 2, None, 0), t).is_some());
    }

    #[test]
    fn audit_event_from_xml() {
        let xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
            <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4663</EventID></System><EventData>\
            <Data Name='SubjectUserSid'>S-1-5-21-7-1001</Data><Data Name='SubjectUserName'>bob</Data>\
            <Data Name='SubjectDomainName'>PC</Data><Data Name='ObjectType'>File</Data>\
            <Data Name='ObjectName'>C:\\Data\\a.txt</Data><Data Name='HandleId'>0x2c8</Data>\
            <Data Name='AccessList'>%%4417</Data><Data Name='AccessMask'>0x2</Data>\
            <Data Name='ProcessId'>0x1f4</Data><Data Name='ProcessName'>C:\\Tools\\w.exe</Data></EventData></Event>";
        let e = AuditEvent::from_xml(xml).unwrap();
        assert_eq!(
            e,
            AuditEvent {
                event_id: 4663,
                process_id: 0x1f4,
                handle_id: 0x2c8,
                path: Some(r"C:\Data\a.txt".into()),
                user_name: "bob".into(),
                user_id: "S-1-5-21-7-1001".into(),
                process_name: r"C:\Tools\w.exe".into(),
                access_mask: 2,
            }
        );
        let close = r#"<Event><System><EventID Qualifiers="">4658</EventID></System><EventData><Data Name="HandleId">0x2c8</Data><Data Name="ProcessId">0x1f4</Data></EventData></Event>"#;
        let c = AuditEvent::from_xml(close).unwrap();
        assert_eq!((c.event_id, c.handle_id, c.path), (4658, 0x2c8, None));
        assert!(AuditEvent::from_xml("<Event><System><EventID>4624</EventID></System></Event>").is_none());
    }

    /// Needs administrator rights: modifies a file in a who-data folder, checks the event's
    /// who-data, then that the audit entry and the audit policy are back as they were.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn whodata_live_admin() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use crate::buffer::EventBuffer;
        use crate::fim::FimScanner;
        static RUN: AtomicBool = AtomicBool::new(true);
        fn running() -> bool {
            RUN.load(Ordering::SeqCst)
        }
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let policy = || {
            let out = std::process::Command::new("auditpol")
                .args(["/get", "/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030},{0CCE9223-69AE-11D9-BED3-505054503030}"])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).to_string()
        };
        let before = policy();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("who");
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("f.txt");
        std::fs::write(&file, "one").unwrap();
        let fim = Arc::new(Mutex::new(FimScanner::new(vec![root.clone()])));
        fim.lock().unwrap().scan("1", "t");
        let session = start(std::slice::from_ref(&root), &dir.path().join("data")).expect("who-data start (run as administrator)");
        assert!(has_audit_entry(&root));
        let buffer = Arc::new(EventBuffer::new(1000));
        let h = spawn(session, fim, buffer.clone(), ("1".into(), "t".into()), running).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        std::fs::write(&file, "two").unwrap();
        let mut got = None;
        for _ in 0..40 {
            got = buffer.drain_batch(100).into_iter().find(|e| e["syscheck"]["event"] == "modified");
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        RUN.store(false, Ordering::SeqCst);
        h.join().unwrap();
        let ev = got.expect("no who-data event");
        println!("{ev:#}");
        let who = &ev["syscheck"]["whodata"];
        let exe = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().to_lowercase();
        assert!(who["process_name"].as_str().unwrap().to_lowercase().ends_with(&exe), "{who}");
        assert!(who["user_name"].as_str().unwrap().eq_ignore_ascii_case(&std::env::var("USERNAME").unwrap()), "{who}");
        assert!(who["user_id"].as_str().unwrap().starts_with("S-1-5-"));
        assert!(!has_audit_entry(&root), "audit entry left on the folder");
        assert_eq!(policy(), before, "audit policy not restored");
        assert!(!dir.path().join("data").join("audit_policy_backup.csv").exists());
    }
}
