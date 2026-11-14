//! Real-time file monitoring: one directory change watch per folder (`ReadDirectoryChangesW`,
//! whole subtree, one overlapped 64 KiB read re-armed after each completion).
//!
//! A notification only says where to look: the path is re-checked against the baseline
//! (`FimScanner::recheck`) one second after its first notification, so a burst of changes to
//! one file gives one event, and a change that leaves the file as it was gives none. When the
//! notification buffer overflows the folder is re-scanned at once; a folder that disappears is
//! looked for again every 60 s.

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::buffer::EventBuffer;
use crate::fim::FimScanner;

/// Re-scans after a notification buffer overflow since the agent started.
pub static OVERFLOW_RESCANS: AtomicUsize = AtomicUsize::new(0);

/// `FILE_NOTIFY_INFORMATION` records: (action, path relative to the watched folder).
pub fn parse_notifications(buf: &[u8]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let word = |at: usize| buf.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    while let (Some(next), Some(action), Some(len)) = (word(off), word(off + 4), word(off + 8)) {
        let Some(name) = buf.get(off + 12..off + 12 + len as usize) else { break };
        let units: Vec<u16> = name.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        out.push((action, String::from_utf16_lossy(&units)));
        if next == 0 {
            break;
        }
        off += next as usize;
    }
    out
}

/// One watch thread per folder; real-time watchers run on Windows (`ReadDirectoryChangesW`) and Linux (`inotify`).
pub fn spawn(
    folders: &[PathBuf],
    fim: Arc<Mutex<FimScanner>>,
    buffer: Arc<EventBuffer>,
    agent: (String, String),
    running: fn() -> bool,
) -> Vec<JoinHandle<()>> {
    #[cfg(windows)]
    {
        folders
            .iter()
            .filter_map(|root| {
                let (root, fim, buffer, agent) = (root.clone(), fim.clone(), buffer.clone(), agent.clone());
                crate::thread(format!("realtime {}", root.display()), move || win::run(root, fim, buffer, agent, running))
                    .map_err(|e| tracing::error!(error = %e, "Real-time watch thread not started"))
                    .ok()
            })
            .collect()
    }
    #[cfg(target_os = "linux")]
    {
        folders
            .iter()
            .filter_map(|root| {
                let (root, fim, buffer, agent) = (root.clone(), fim.clone(), buffer.clone(), agent.clone());
                crate::thread(format!("realtime {}", root.display()), move || linux::run(root, fim, buffer, agent, running))
                    .map_err(|e| tracing::error!(error = %e, "Real-time inotify watch thread not started"))
                    .ok()
            })
            .collect()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        if !folders.is_empty() {
            tracing::warn!("Real-time file monitoring is unavailable on this OS; those folders are scanned on schedule only");
        }
        let _ = (fim, buffer, agent, running);
        Vec::new()
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq)]
struct InotifyRecord {
    wd: i32,
    mask: u32,
    name: String,
}

#[cfg(any(target_os = "linux", test))]
const IN_ISDIR_FLAG: u32 = 0x4000_0000;
#[cfg(any(target_os = "linux", test))]
const IN_CREATE_FLAG: u32 = 0x0000_0100;
#[cfg(any(target_os = "linux", test))]
const IN_MOVED_TO_FLAG: u32 = 0x0000_0080;
#[cfg(any(target_os = "linux", test))]
const IN_Q_OVERFLOW_FLAG: u32 = 0x0000_4000;

/// Decode Linux kernel `struct inotify_event` stream (`wd: i32, mask: u32, cookie: u32, len: u32, name: [u8; len]`).
#[cfg(any(target_os = "linux", test))]
fn parse_inotify_buffer(buf: &[u8]) -> Vec<InotifyRecord> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 16 <= buf.len() {
        let wd = i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
        let mask = u32::from_ne_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let name_len = u32::from_ne_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
        off += 16;
        let end = off.saturating_add(name_len).min(buf.len());
        let raw_name = &buf[off..end];
        let nul = raw_name.iter().position(|&b| b == 0).unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..nul]).into_owned();
        out.push(InotifyRecord { wd, mask, name });
        if off + name_len > buf.len() {
            break;
        }
        off += name_len;
    }
    out
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    use tracing::{info, warn};

    const MERGE: Duration = Duration::from_secs(1);
    const RETRY: Duration = Duration::from_secs(60);

    const WATCH_MASK: u32 = libc::IN_CREATE
        | libc::IN_MODIFY
        | libc::IN_CLOSE_WRITE
        | libc::IN_DELETE
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_ATTRIB
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF;

    struct InotifyWatch {
        fd: i32,
        wd_to_dir: HashMap<i32, PathBuf>,
    }

    impl Drop for InotifyWatch {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }

    impl InotifyWatch {
        fn open(root: &Path) -> Result<Self, std::io::Error> {
            let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut w = Self { fd, wd_to_dir: HashMap::new() };
            w.add_tree(root, 0)?;
            Ok(w)
        }

        fn add_dir(&mut self, dir: &Path) -> bool {
            let Ok(cpath) = CString::new(dir.as_os_str().as_bytes()) else { return false };
            let wd = unsafe { libc::inotify_add_watch(self.fd, cpath.as_ptr(), WATCH_MASK) };
            if wd >= 0 {
                self.wd_to_dir.insert(wd, dir.to_path_buf());
                true
            } else {
                false
            }
        }

        fn add_tree(&mut self, dir: &Path, depth: usize) -> Result<(), std::io::Error> {
            if !dir.is_dir() {
                return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "folder missing"));
            }
            if !self.add_dir(dir) {
                return Err(std::io::Error::last_os_error());
            }
            if depth >= 64 {
                return Ok(());
            }
            if let Ok(rd) = std::fs::read_dir(dir) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    if let Ok(meta) = std::fs::symlink_metadata(&p) {
                        if meta.is_dir() && !meta.file_type().is_symlink() {
                            let _ = self.add_tree(&p, depth + 1);
                        }
                    }
                }
            }
            Ok(())
        }

        fn poll_read(&self, buf: &mut [u8], timeout_ms: i32) -> Option<Result<usize, std::io::Error>> {
            let mut pfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
            let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if rc <= 0 {
                return None;
            }
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    None
                } else {
                    Some(Err(err))
                }
            } else {
                Some(Ok(n as usize))
            }
        }
    }

    pub(super) fn run(
        root: PathBuf,
        fim: Arc<Mutex<FimScanner>>,
        buffer: Arc<EventBuffer>,
        agent: (String, String),
        running: fn() -> bool,
    ) {
        let recheck = |paths: &[PathBuf]| {
            let mut events: Vec<Value> = Vec::new();
            {
                let mut f = fim.lock().unwrap_or_else(|e| e.into_inner());
                for p in paths {
                    events.extend(f.recheck(p, true, None, &agent.0, &agent.1));
                }
            }
            events.into_iter().for_each(|e| buffer.push(e));
        };

        let (mut warned, mut resync) = (false, false);
        let mut buf = vec![0u8; 64 * 1024];
        while running() {
            let mut w = match InotifyWatch::open(&root) {
                Ok(w) => w,
                Err(e) => {
                    if !warned {
                        warn!(folder = %root.display(), error = %e, "Real-time inotify watch not open; trying again every 60 s");
                        warned = true;
                    }
                    resync = true;
                    crate::nap(RETRY, running);
                    continue;
                }
            };
            info!(folder = %root.display(), watches = w.wd_to_dir.len(), "Real-time inotify watch started");
            warned = false;
            if std::mem::take(&mut resync) {
                recheck(std::slice::from_ref(&root));
            }
            let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
            while running() {
                if let Some(res) = w.poll_read(&mut buf, 250) {
                    match res {
                        Ok(n) => {
                            for ev in parse_inotify_buffer(&buf[..n]) {
                                if (ev.mask & IN_Q_OVERFLOW_FLAG) != 0 {
                                    warn!(folder = %root.display(), "inotify queue overflowed; re-scanning folder");
                                    OVERFLOW_RESCANS.fetch_add(1, Ordering::SeqCst);
                                    pending.clear();
                                    recheck(std::slice::from_ref(&root));
                                    break;
                                }
                                let Some(dir) = w.wd_to_dir.get(&ev.wd).cloned() else { continue };
                                let p = if ev.name.is_empty() { dir.clone() } else { dir.join(&ev.name) };
                                if (ev.mask & IN_ISDIR_FLAG) != 0 && (ev.mask & (IN_CREATE_FLAG | IN_MOVED_TO_FLAG)) != 0 {
                                    let _ = w.add_tree(&p, 0);
                                }
                                if (ev.mask & libc::IN_DELETE_SELF) != 0 && p == root {
                                    resync = true;
                                    break;
                                }
                                if !p.is_dir() || (ev.mask & libc::IN_DELETE) != 0 {
                                    pending.entry(p).or_insert_with(Instant::now);
                                }
                            }
                            if resync {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(folder = %root.display(), error = %e, "inotify read error; reopening watch");
                            resync = true;
                            break;
                        }
                    }
                }
                let now = Instant::now();
                let due: Vec<PathBuf> = pending
                    .iter()
                    .filter(|(_, t)| now.duration_since(**t) >= MERGE)
                    .map(|(p, _)| p.clone())
                    .collect();
                if !due.is_empty() {
                    due.iter().for_each(|p| { pending.remove(p); });
                    recheck(&due);
                }
                if !root.is_dir() {
                    resync = true;
                    break;
                }
            }
            drop(w);
            if resync && running() && !root.is_dir() {
                crate::nap(RETRY, running);
            }
        }
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    use serde_json::Value;
    use tracing::{info, warn};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NOTIFY_ENUM_DIR, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadDirectoryChangesW, FILE_ACTION_MODIFIED, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
        FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
        FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

    use crate::wevt::win::{last_error, wide};

    const BUF_BYTES: usize = 64 * 1024;
    const FILTER: u32 = FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE
        | FILE_NOTIFY_CHANGE_ATTRIBUTES
        | FILE_NOTIFY_CHANGE_SECURITY;
    /// Notifications for one path within this long are one re-check.
    const MERGE: Duration = Duration::from_secs(1);
    const RETRY: Duration = Duration::from_secs(60);

    /// The open folder, its event and the read in flight (cancelled and waited for on drop,
    /// so the system never writes into freed memory).
    struct Watch {
        dir: HANDLE,
        event: HANDLE,
        ov: Box<OVERLAPPED>,
        buf: Box<[u32]>,
        pending: bool,
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            unsafe {
                if self.pending {
                    let mut n = 0;
                    CancelIoEx(self.dir, &*self.ov);
                    GetOverlappedResult(self.dir, &*self.ov, &mut n, 1);
                }
                CloseHandle(self.dir);
                if !self.event.is_null() {
                    CloseHandle(self.event);
                }
            }
        }
    }

    impl Watch {
        fn open(root: &Path) -> Result<Watch, u32> {
            let dir = unsafe {
                CreateFileW(
                    wide(&root.to_string_lossy()).as_ptr(),
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    null_mut(),
                )
            };
            if dir == INVALID_HANDLE_VALUE {
                return Err(last_error());
            }
            let event = unsafe { CreateEventW(null(), 1, 0, null()) };
            let mut w = Watch {
                dir,
                event,
                ov: Box::default(),
                buf: vec![0u32; BUF_BYTES / 4].into_boxed_slice(),
                pending: false,
            };
            if event.is_null() {
                return Err(last_error());
            }
            w.arm()?;
            Ok(w)
        }

        fn arm(&mut self) -> Result<(), u32> {
            *self.ov = OVERLAPPED::default();
            self.ov.hEvent = self.event;
            unsafe { ResetEvent(self.event) };
            let ok = unsafe {
                ReadDirectoryChangesW(self.dir, self.buf.as_mut_ptr().cast(), BUF_BYTES as u32, 1, FILTER, null_mut(), &mut *self.ov, None)
            };
            self.pending = ok != 0;
            if ok == 0 { Err(last_error()) } else { Ok(()) }
        }

        /// `None` while nothing came within `ms`; else the bytes written or the error.
        fn wait(&mut self, ms: u32) -> Option<Result<usize, u32>> {
            if unsafe { WaitForSingleObject(self.event, ms) } != WAIT_OBJECT_0 {
                return None;
            }
            self.pending = false;
            let mut n = 0u32;
            if unsafe { GetOverlappedResult(self.dir, &*self.ov, &mut n, 0) } == 0 {
                return Some(Err(last_error()));
            }
            Some(Ok(n as usize))
        }

        fn bytes(&self, n: usize) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.buf.as_ptr().cast(), n.min(BUF_BYTES)) }
        }
    }

    pub(super) fn run(root: PathBuf, fim: Arc<Mutex<FimScanner>>, buffer: Arc<EventBuffer>, agent: (String, String), running: fn() -> bool) {
        let recheck = |paths: &[PathBuf]| {
            let mut events: Vec<Value> = Vec::new();
            {
                let mut f = fim.lock().unwrap_or_else(|e| e.into_inner());
                for p in paths {
                    events.extend(f.recheck(p, true, None, &agent.0, &agent.1));
                }
            }
            events.into_iter().for_each(|e| buffer.push(e));
        };
        let (mut warned, mut resync) = (false, false);
        while running() {
            let mut w = match Watch::open(&root) {
                Ok(w) => w,
                Err(e) => {
                    if !warned {
                        warn!(folder = %root.display(), error = e, "Real-time watch not open (folder missing?); trying again every 60 s");
                        warned = true;
                    }
                    resync = true;
                    crate::nap(RETRY, running);
                    continue;
                }
            };
            info!(folder = %root.display(), "Real-time watch started");
            warned = false;
            // changes while the folder was not watched
            if std::mem::take(&mut resync) {
                recheck(std::slice::from_ref(&root));
            }
            let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
            while running() {
                if let Some(done) = w.wait(250) {
                    match done {
                        Ok(n) if n > 0 => {
                            for (action, name) in parse_notifications(w.bytes(n)) {
                                let p = root.join(name);
                                // a folder's own write time moves with its content, which is notified itself
                                if action == FILE_ACTION_MODIFIED && p.is_dir() {
                                    continue;
                                }
                                pending.entry(p).or_insert_with(Instant::now);
                            }
                        }
                        Ok(_) | Err(ERROR_NOTIFY_ENUM_DIR) if root.is_dir() => {
                            warn!(folder = %root.display(), "Real-time notifications overflowed; re-scanning the folder");
                            OVERFLOW_RESCANS.fetch_add(1, Ordering::SeqCst);
                            pending.clear();
                            recheck(std::slice::from_ref(&root));
                        }
                        _ => {
                            warn!(folder = %root.display(), "Real-time watched folder gone; watch closed");
                            resync = true;
                            break;
                        }
                    }
                    if w.arm().is_err() {
                        resync = true;
                        break;
                    }
                }
                let now = Instant::now();
                let due: Vec<PathBuf> = pending.iter().filter(|(_, t)| now.duration_since(**t) >= MERGE).map(|(p, _)| p.clone()).collect();
                if !due.is_empty() {
                    due.iter().for_each(|p| {
                        pending.remove(p);
                    });
                    recheck(&due);
                }
            }
            drop(w);
            if resync && running() && !root.is_dir() {
                crate::nap(RETRY, running);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(next: u32, action: u32, name: &str) -> Vec<u8> {
        let units: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut r = Vec::new();
        r.extend(next.to_le_bytes());
        r.extend(action.to_le_bytes());
        r.extend((units.len() as u32).to_le_bytes());
        r.extend(units);
        r
    }

    #[test]
    fn notification_records() {
        let mut first = record(0, 4, r"sub\old.txt");
        let pad = (4 - first.len() % 4) % 4;
        first.extend(vec![0; pad]);
        let next = first.len() as u32;
        first[..4].copy_from_slice(&next.to_le_bytes());
        first.extend(record(0, 5, "new.txt"));
        assert_eq!(parse_notifications(&first), vec![(4, r"sub\old.txt".to_string()), (5, "new.txt".to_string())]);
        assert!(parse_notifications(&[]).is_empty());
        // a cut record is not read past the buffer
        assert!(parse_notifications(&first[..14]).is_empty());
    }

    /// Live on a temp folder: one event per change within 3 s (a touch is an mtime change), and a forced
    /// notification overflow re-scans without missing a file.
    #[cfg(windows)]
    #[test]
    fn realtime_live_temp_folder() {
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        use serde_json::Value;
        static RUN: AtomicBool = AtomicBool::new(true);
        fn running() -> bool {
            RUN.load(Ordering::SeqCst)
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("watched");
        std::fs::create_dir_all(&root).unwrap();
        let fim = Arc::new(Mutex::new(FimScanner::new(vec![root.clone()])));
        assert!(fim.lock().unwrap().scan("1", "t").is_empty());
        let buffer = Arc::new(EventBuffer::new(100_000));
        let threads = spawn(std::slice::from_ref(&root), fim.clone(), buffer.clone(), ("1".into(), "t".into()), running);
        std::thread::sleep(Duration::from_millis(500));

        // waits for `n` events (3 s at most), then 1.5 s more for any extra one
        let collect = |n: usize, limit: Duration| -> Vec<Value> {
            let start = Instant::now();
            let mut got = Vec::new();
            while got.len() < n && start.elapsed() < limit {
                got.extend(buffer.drain_batch(100_000));
                std::thread::sleep(Duration::from_millis(50));
            }
            std::thread::sleep(Duration::from_millis(1500));
            got.extend(buffer.drain_batch(100_000));
            got
        };
        let kinds = |evs: &[Value]| -> Vec<(String, String)> {
            let mut k: Vec<(String, String)> = evs
                .iter()
                .map(|e| {
                    let p = e["syscheck"]["path"].as_str().unwrap();
                    (e["syscheck"]["event"].as_str().unwrap().to_string(), Path::new(p).file_name().unwrap().to_string_lossy().to_string())
                })
                .collect();
            k.sort();
            k
        };
        use std::path::Path;
        let three = Duration::from_secs(3);
        let a = root.join("a.txt");

        std::fs::write(&a, "one").unwrap();
        assert_eq!(kinds(&collect(1, three)), vec![("added".into(), "a.txt".into())]);

        std::fs::write(&a, "two, longer").unwrap();
        let ev = collect(1, three);
        assert_eq!(kinds(&ev), vec![("modified".into(), "a.txt".into())]);
        assert_eq!(ev[0]["syscheck"]["size_after"], 11);

        let f = std::fs::File::options().write(true).open(&a).unwrap();
        f.set_modified(std::time::SystemTime::now() + Duration::from_secs(120)).unwrap();
        drop(f);
        let ev = collect(1, three);
        assert_eq!(ev.len(), 1, "touch: {ev:?}");
        assert_eq!(ev[0]["syscheck"]["changed_attributes"], serde_json::json!(["mtime"]));

        std::fs::rename(&a, root.join("b.txt")).unwrap();
        assert_eq!(kinds(&collect(2, three)), vec![("added".into(), "b.txt".into()), ("deleted".into(), "a.txt".into())]);

        std::fs::remove_file(root.join("b.txt")).unwrap();
        assert_eq!(kinds(&collect(1, three)), vec![("deleted".into(), "b.txt".into())]);

        // overflow: the watcher is held on the baseline lock (after its trigger's 1 s merge)
        // while thousands of files appear, so the system's notification buffer overflows
        let before = OVERFLOW_RESCANS.load(Ordering::SeqCst);
        std::fs::write(root.join("trigger.txt"), "t").unwrap();
        const N: usize = 2000;
        {
            let _held = fim.lock().unwrap();
            std::thread::sleep(Duration::from_millis(1500));
            for i in 0..N {
                std::fs::write(root.join(format!("overflow-file-with-a-rather-long-name-{i:05}.txt")), i.to_string()).unwrap();
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let ev = collect(N + 1, Duration::from_secs(60));
        let names: HashSet<String> = ev.iter().map(|e| e["syscheck"]["path"].as_str().unwrap().to_string()).collect();
        assert_eq!(ev.len(), N + 1, "duplicates or misses");
        assert_eq!(names.len(), N + 1);
        assert!(ev.iter().all(|e| e["syscheck"]["event"] == "added"));
        assert!(OVERFLOW_RESCANS.load(Ordering::SeqCst) > before, "no overflow re-scan happened");

        RUN.store(false, Ordering::SeqCst);
        threads.into_iter().for_each(|t| t.join().unwrap());
    }

    #[test]
    fn parses_raw_inotify_event_stream() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3i32.to_ne_bytes());
        buf.extend_from_slice(&(libc_like_close_write()).to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&8u32.to_ne_bytes());
        buf.extend_from_slice(b"test\0\0\0\0");
        buf.extend_from_slice(&(-1i32).to_ne_bytes());
        buf.extend_from_slice(&IN_Q_OVERFLOW_FLAG.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());

        let recs = parse_inotify_buffer(&buf);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].wd, 3);
        assert_eq!(recs[0].name, "test");
        assert_eq!(recs[1].mask, IN_Q_OVERFLOW_FLAG);
    }

    fn libc_like_close_write() -> u32 {
        0x0000_0008
    }
}
