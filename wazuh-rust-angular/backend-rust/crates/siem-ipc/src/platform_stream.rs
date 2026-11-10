//! The platform's stream (not in upstream): when siem-api starts a manager daemon with
//! `SIEM_STREAM_ADDR` (its loopback listener) and `SIEM_STREAM_TOKEN`, the daemon sends
//! what it would write to a file (analysisd: alerts and archived events; the
//! vulnerability scanner: its result documents) to siem-api, which stores it in
//! ClickHouse.
//!
//! Write-ahead: every line goes to the daemon's on-disk spool first
//! (`queue/stream-spool/<daemon>`, files `<first sequence>.wal`, at most [`SPOOL_MAX`]),
//! so the daemon never waits on the network. `send` only copies the line into a small buffer;
//! a thread writes the buffer to the file within [`BATCH`], so the daemon does not make a write
//! call per line. A process crash loses the lines still in that buffer: at most the last
//! [`BATCH`] plus a timer tick, and never more than [`BUFFER`] bytes; a line in the file
//! survives it (a power cut can take what the OS had not written, as ever). Another thread
//! sends the spool in order (read back from the OS cache) and siem-api answers `stored up to N` (u64 LE) once ClickHouse
//! holds every line up to N; only then do those lines leave the spool. After a reconnect or
//! a restart of either side, sending resumes after the last acknowledged line (at least
//! once: siem-api skips the lines it already stored). Lines are dropped (and counted) only
//! when the spool is full.
//!
//! Frames: `[u32 LE length of what follows][kind][u64 LE sequence][payload]`, kind `H`
//! (first, sequence 0: `<token> <source>`), `A` (alert), `E` (archived event) or
//! `V` (vulnerability result).

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

/// Bytes the on-disk spool may hold.
pub const SPOOL_MAX: u64 = 1 << 30;
/// Size of one spool file.
const SEGMENT: u64 = 64 << 20;
/// Bytes of lines waiting for the file; a full buffer is written by the caller.
const BUFFER: usize = 256 << 10;
/// How long the first line in the buffer waits, so that a write call takes many lines.
const BATCH: Duration = Duration::from_millis(2);
/// Bytes of a frame before its payload: length, kind, sequence.
pub const HEADER: usize = 13;

pub const ALERT: u8 = b'A';
pub const EVENT: u8 = b'E';
pub const HELLO: u8 = b'H';
pub const VULNERABILITY: u8 = b'V';
/// First byte of a datagram siem-api hands analysisd, which counts them apart from remoted's.
pub const FROM_API: u8 = 1;
/// First byte of a datagram a provigil-gateway hands analysisd; the second is the gateway's number
/// (`GATEWAY_SENDER`), so each gateway can read its own count.
pub const FROM_GATEWAY: u8 = 2;

pub struct Stream {
    spool: Arc<Spool>,
    pub dropped: u64,
}

/// One frame.
pub fn frame(kind: u8, seq: u64, payload: &[u8]) -> Vec<u8> {
    let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
    let mut f = Vec::with_capacity(HEADER + payload.len());
    f.extend_from_slice(&((payload.len() + HEADER - 4) as u32).to_le_bytes());
    f.push(kind);
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(payload);
    f
}

fn seq(f: &[u8]) -> u64 {
    u64::from_le_bytes(f[5..HEADER].try_into().unwrap())
}

/// One whole frame (with its length), or None at the end or a torn frame.
fn read_frame(r: &mut impl Read) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let mut b = vec![0u8; 4 + u32::from_le_bytes(len) as usize];
    b[..4].copy_from_slice(&len);
    r.read_exact(&mut b[4..]).ok()?;
    Some(b)
}

impl Stream {
    /// The stream siem-api asked for, with its writer thread; None when not asked.
    /// `spool`: the daemon's spool directory (`queue/stream-spool/<daemon>`); its name
    /// tells siem-api which daemon this is.
    pub fn from_env(spool: &Path) -> Option<Stream> {
        let addr = std::env::var("SIEM_STREAM_ADDR").ok().filter(|a| !a.is_empty())?;
        let token = std::env::var("SIEM_STREAM_TOKEN").ok().filter(|t| !t.is_empty())?;
        Stream::start(addr, token, spool, SPOOL_MAX)
    }

    /// A stream to `addr` with its own spool limit.
    pub fn start(addr: String, token: String, dir: &Path, max: u64) -> Option<Stream> {
        let spool = Arc::new(Spool::open(dir, max).ok()?);
        let hello = format!("{token} {}", dir.file_name()?.to_string_lossy());
        let s = spool.clone();
        std::thread::Builder::new().name("siem-stream".into()).spawn(move || writer(&addr, &hello, &s)).ok()?;
        let s = spool.clone();
        std::thread::Builder::new().name("siem-spool".into()).spawn(move || flusher(&s)).ok()?;
        let _ = LIVE.set(spool.clone());
        Some(Stream { spool, dropped: 0 })
    }

    /// Lines siem-api has not acknowledged yet.
    pub fn pending(&self) -> bool {
        let s = self.spool.st.lock().unwrap();
        s.acked + 1 < s.next
    }

    /// Spools one alert or event line. Some(warning) every 1,000 lines dropped.
    pub fn send(&mut self, kind: u8, json: &[u8]) -> Option<String> {
        if self.spool.append(kind, json) {
            return None;
        }
        self.dropped += 1;
        (self.dropped % 1000 == 1).then(|| format!("siem-api stream: spool of {} MB full, {} line(s) dropped so far", self.spool.max >> 20, self.dropped))
    }
}

impl Drop for Stream {
    /// The daemon stops: the writer stops too, every line stays spooled for the next start.
    fn drop(&mut self) {
        self.spool.flush();
        self.spool.closed.store(true, Ordering::SeqCst);
        self.spool.more.notify_all();
        self.spool.dirty.notify_all();
    }
}

/// The daemon's spool, for [`flush_at_exit`].
static LIVE: OnceLock<Arc<Spool>> = OnceLock::new();

/// For a signal handler: the buffer goes to the file. Skipped when the signal interrupted a
/// thread holding the spool's lock (waiting for it there would never end).
pub fn flush_at_exit() {
    if let Some(sp) = LIVE.get() {
        if let Ok(mut s) = sp.st.try_lock() {
            sp.write_buffer(&mut s);
        }
    }
}

struct Spool {
    dir: PathBuf,
    max: u64,
    st: Mutex<SpoolState>,
    /// lines reached the file
    more: Condvar,
    /// the buffer was empty and has a line now
    dirty: Condvar,
    closed: AtomicBool,
}

struct SpoolState {
    /// the spool files in order, (first sequence, bytes); lines are appended to the last
    segs: VecDeque<(u64, u64)>,
    /// the last file, open; none after a start (that file may end in a torn frame)
    file: Option<File>,
    /// the sequence of the next line
    next: u64,
    /// lines not in the file yet, whole frames
    buf: Vec<u8>,
    /// the sequence of the first of them
    buf_first: u64,
    /// the file holds every line before this sequence
    flushed: u64,
    /// stored by siem-api up to here (`acked`)
    acked: u64,
    bytes: u64,
}

fn seq_of(p: &Path, ext: &str) -> Option<u64> {
    p.file_name()?.to_str()?.strip_suffix(ext)?.parse().ok()
}

impl Spool {
    fn open(dir: &Path, max: u64) -> std::io::Result<Spool> {
        std::fs::create_dir_all(dir)?;
        let mut segs: Vec<(u64, u64)> = std::fs::read_dir(dir)?
            .flatten()
            .filter_map(|e| Some((seq_of(&e.path(), ".wal")?, std::fs::metadata(e.path()).ok()?.len())))
            .collect();
        segs.sort();
        let acked = std::fs::read_to_string(dir.join("acked")).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0);
        let mut last = 0;
        if let Some(&(first, _)) = segs.last() {
            last = first;
            if let Ok(f) = File::open(dir.join(format!("{first:020}.wal"))) {
                let mut r = BufReader::new(f);
                while let Some(f) = read_frame(&mut r) {
                    last = seq(&f);
                }
            }
        }
        // never a sequence used before, even when the spool was lost: siem-api skips the
        // sequences it already stored
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0);
        let next = (last.max(acked) + 1).max(now);
        let bytes = segs.iter().map(|s| s.1).sum();
        let sp = Spool {
            dir: dir.to_path_buf(),
            max,
            st: Mutex::new(SpoolState { segs: segs.into(), file: None, next, buf: Vec::new(), buf_first: next, flushed: next, acked, bytes }),
            more: Condvar::new(),
            dirty: Condvar::new(),
            closed: AtomicBool::new(false),
        };
        sp.migrate();
        Ok(sp)
    }

    fn path(&self, first: u64) -> PathBuf {
        self.dir.join(format!("{first:020}.wal"))
    }

    /// The spool of the version before (`<n>.spool` files of frames without a sequence and
    /// `read.pos`, the next one to send): its unsent lines move into this one, in order.
    fn migrate(&self) {
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return };
        let mut old: Vec<u64> = rd.flatten().filter_map(|e| seq_of(&e.path(), ".spool")).collect();
        old.sort();
        let pos = self.dir.join("read.pos");
        let (from, off) = std::fs::read_to_string(&pos)
            .ok()
            .and_then(|t| {
                let (a, b) = t.trim().split_once(' ')?;
                Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?))
            })
            .unwrap_or((0, 0));
        for n in old {
            let p = self.dir.join(format!("{n:020}.spool"));
            if let (true, Ok(mut f)) = (n >= from, File::open(&p)) {
                let _ = f.seek(SeekFrom::Start(if n == from { off } else { 0 }));
                let mut r = BufReader::new(f);
                while let Some(f) = read_frame(&mut r) {
                    if f.len() > 4 {
                        self.append(f[4], &f[5..]);
                    }
                }
            }
            if self.flush() {
                let _ = std::fs::remove_file(p);
            }
        }
        let _ = std::fs::remove_file(pos);
    }

    /// false when the spool is full (or the disk failed and the buffer is full too).
    fn append(&self, kind: u8, json: &[u8]) -> bool {
        let mut s = self.st.lock().unwrap();
        let f = frame(kind, s.next, json);
        let n = f.len() as u64;
        if s.bytes + n > self.max {
            return false;
        }
        if s.buf.len() + f.len() > BUFFER && !self.write_buffer(&mut s) {
            return false;
        }
        let first = s.buf.is_empty();
        if first {
            s.buf_first = s.next;
        }
        s.buf.extend_from_slice(&f);
        s.bytes += n;
        s.next += 1;
        drop(s);
        if first {
            self.dirty.notify_one();
        }
        true
    }

    /// The buffer to the file, or left in the buffer for another try.
    fn write_buffer(&self, s: &mut SpoolState) -> bool {
        if s.buf.is_empty() {
            return true;
        }
        if s.file.is_none() || s.segs.back().is_some_and(|b| b.1 >= SEGMENT) {
            let first = s.buf_first;
            let Ok(file) = OpenOptions::new().create(true).append(true).open(self.path(first)) else { return false };
            s.file = Some(file);
            s.segs.push_back((first, 0));
        }
        let whole = s.segs.back().map_or(0, |b| b.1);
        let SpoolState { file, buf, .. } = s;
        let file = file.as_mut().unwrap();
        if file.write_all(buf).is_err() {
            // no torn frame in the middle of the file
            let _ = file.set_len(whole);
            return false;
        }
        s.segs.back_mut().unwrap().1 += s.buf.len() as u64;
        s.buf.clear();
        s.flushed = s.next;
        true
    }

    fn flush(&self) -> bool {
        let done = self.write_buffer(&mut self.st.lock().unwrap());
        self.more.notify_all();
        done
    }

    /// siem-api stored every line up to `seq`: kept in `acked`, and the files holding only
    /// such lines go.
    fn ack(&self, seq: u64) {
        let mut s = self.st.lock().unwrap();
        if seq <= s.acked {
            return;
        }
        s.acked = seq;
        let _ = std::fs::write(self.dir.join("acked"), seq.to_string());
        while s.segs.len() > 1 && s.segs[1].0 <= seq + 1 {
            let (first, n) = s.segs.pop_front().unwrap();
            let _ = std::fs::remove_file(self.path(first));
            s.bytes = s.bytes.saturating_sub(n);
        }
    }
}

/// The writer's place in the spool: the next line to send (`want`) and where it is read.
struct Cursor {
    want: u64,
    seg: Option<u64>,
    off: u64,
    file: Option<BufReader<File>>,
    /// `next` of the spool when the end was reached
    seen: u64,
}

impl Cursor {
    /// The next frame to send, or None when everything was sent.
    fn next(&mut self, sp: &Spool) -> Option<Vec<u8>> {
        loop {
            let (end, after) = {
                let s = sp.st.lock().unwrap();
                self.seen = s.flushed;
                let i = match s.segs.iter().position(|x| Some(x.0) == self.seg) {
                    Some(i) => i,
                    None => {
                        // (re)started: the last file beginning at or before the line wanted
                        let i = s.segs.iter().rposition(|x| x.0 <= self.want).unwrap_or(0);
                        self.seg = Some(s.segs.get(i)?.0);
                        (self.off, self.file) = (0, None);
                        i
                    }
                };
                (s.segs[i].1, s.segs.get(i + 1).map(|x| x.0))
            };
            if self.off < end {
                if self.file.is_none() {
                    let mut f = File::open(sp.path(self.seg?)).ok()?;
                    f.seek(SeekFrom::Start(self.off)).ok()?;
                    self.file = Some(BufReader::with_capacity(256 << 10, f));
                }
                let r = self.file.as_mut()?;
                let mut len = [0u8; 4];
                if r.read_exact(&mut len).is_err() {
                    self.file = None;
                    return None;
                }
                let n = u32::from_le_bytes(len) as u64;
                // a whole frame (only a file written before a restart can end in a torn one)
                if n >= (HEADER - 4) as u64 && self.off + 4 + n <= end {
                    let mut b = vec![0u8; 4 + n as usize];
                    b[..4].copy_from_slice(&len);
                    if r.read_exact(&mut b[4..]).is_err() {
                        self.file = None;
                        return None;
                    }
                    self.off += 4 + n;
                    if seq(&b) >= self.want {
                        self.want = seq(&b) + 1;
                        return Some(b);
                    }
                    continue;
                }
                self.off = end;
            }
            // the end of this file: on to the next one, if any
            (self.seg, self.off, self.file) = (Some(after?), 0, None);
        }
    }

    /// Until a line reaches the file (or a while).
    fn wait(&self, sp: &Spool) {
        let s = sp.st.lock().unwrap();
        let _ = sp.more.wait_timeout_while(s, Duration::from_millis(200), |s| s.flushed == self.seen && !sp.closed.load(Ordering::SeqCst));
    }
}

/// Writes the buffer to the file, shortly after a line came, until the stream is closed.
fn flusher(sp: &Spool) {
    while !sp.closed.load(Ordering::SeqCst) {
        let s = sp.st.lock().unwrap();
        let (s, _) = sp.dirty.wait_timeout_while(s, Duration::from_millis(200), |s| s.buf.is_empty() && !sp.closed.load(Ordering::SeqCst)).unwrap();
        drop(s);
        std::thread::sleep(BATCH);
        sp.flush();
    }
}

/// Connects (again) and sends the spool after the last acknowledged line, while a thread
/// takes siem-api's acknowledgements; until the stream is closed.
fn writer(addr: &str, hello: &str, sp: &Spool) {
    while !sp.closed.load(Ordering::SeqCst) {
        let Ok(conn) = TcpStream::connect(addr) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        let _ = conn.set_nodelay(true);
        // siem-api gone: seen here even with nothing to send, so what it did not store goes again
        let gone = AtomicBool::new(false);
        std::thread::scope(|sc| {
            if let Ok(mut acks) = conn.try_clone() {
                let gone = &gone;
                sc.spawn(move || {
                    let mut b = [0u8; 8];
                    while acks.read_exact(&mut b).is_ok() {
                        sp.ack(u64::from_le_bytes(b));
                    }
                    gone.store(true, Ordering::SeqCst);
                    sp.more.notify_all();
                });
            }
            let _ = send(&conn, hello, sp, &gone);
            let _ = conn.shutdown(Shutdown::Both);
        });
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn send(conn: &TcpStream, hello: &str, sp: &Spool, gone: &AtomicBool) -> std::io::Result<()> {
    let mut out = BufWriter::with_capacity(256 << 10, conn);
    out.write_all(&frame(HELLO, 0, hello.as_bytes()))?;
    let want = sp.st.lock().unwrap().acked + 1;
    let mut cur = Cursor { want, seg: None, off: 0, file: None, seen: 0 };
    while !sp.closed.load(Ordering::SeqCst) && !gone.load(Ordering::SeqCst) {
        match cur.next(sp) {
            Some(f) => out.write_all(&f)?,
            None => {
                out.flush()?;
                cur.wait(sp);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_line(r: &mut impl Read) -> Option<(u8, u64, Vec<u8>)> {
        let f = read_frame(r)?;
        Some((f[4], seq(&f), f[HEADER..].to_vec()))
    }

    /// The payload of each of the next `n` lines, with the last line's sequence.
    fn lines(c: &mut TcpStream, n: usize) -> (Vec<String>, u64) {
        let (mut out, mut last) = (Vec::new(), 0);
        for _ in 0..n {
            let (_, s, b) = read_line(c).unwrap();
            assert!(s > last, "sequences go up");
            last = s;
            out.push(String::from_utf8(b).unwrap());
        }
        (out, last)
    }

    fn numbers(r: std::ops::Range<u32>) -> Vec<String> {
        r.map(|n| format!("{{\"n\":{n}}}")).collect()
    }

    /// A loopback address nothing listens on (yet).
    fn free_addr() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    }

    /// The next connection, past its hello.
    fn accept(l: &std::net::TcpListener) -> TcpStream {
        let (mut c, _) = l.accept().unwrap();
        c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let (kind, n, hello) = read_line(&mut c).unwrap();
        assert_eq!((kind, n), (HELLO, 0));
        assert!(hello.starts_with(b"t0k "), "{hello:?}");
        c
    }

    fn until(what: &str, f: impl Fn() -> bool) {
        let t = std::time::Instant::now();
        while !f() {
            assert!(t.elapsed() < Duration::from_secs(10), "{what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wal_files(dir: &Path) -> usize {
        std::fs::read_dir(dir).unwrap().filter(|e| e.as_ref().unwrap().path().extension().is_some_and(|x| x == "wal")).count()
    }

    #[test]
    fn frames_reach_the_listener_after_it_appears() {
        assert_eq!(frame(ALERT, 7, b"{\"a\":1}\n"), [&16u32.to_le_bytes()[..], b"A", &7u64.to_le_bytes(), b"{\"a\":1}"].concat());
        // the listener starts after the first lines were spooled: nothing is lost
        let addr = free_addr();
        let dir = tempfile::tempdir().unwrap();
        let mut s = Stream::start(addr.clone(), "t0k".into(), dir.path(), SPOOL_MAX).unwrap();
        assert!(s.send(ALERT, b"{\"n\":1}\n").is_none());
        assert!(s.send(EVENT, b"{\"n\":2}").is_none());
        std::thread::sleep(Duration::from_millis(300));
        let l = std::net::TcpListener::bind(&addr).unwrap();
        let mut c = accept(&l);
        let (a, b) = (read_line(&mut c).unwrap(), read_line(&mut c).unwrap());
        assert_eq!((a.0, a.2.as_slice()), (ALERT, &b"{\"n\":1}"[..]));
        assert_eq!((b.0, b.1, b.2.as_slice()), (EVENT, a.1 + 1, &b"{\"n\":2}"[..]));
    }

    #[test]
    fn a_killed_sender_resumes_after_the_last_acknowledged_line() {
        let dir = tempfile::tempdir().unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let mut s = Stream::start(addr.clone(), "t0k".into(), dir.path(), SPOOL_MAX).unwrap();
        for line in numbers(0..100) {
            s.send(EVENT, line.as_bytes());
        }
        let mut c = accept(&l);
        let (got, _) = lines(&mut c, 40);
        assert_eq!(got, numbers(0..40));
        let (more, stored) = lines(&mut c, 60);
        assert_eq!(more, numbers(40..100));
        // all 100 were received, 40 stored: only what is acknowledged counts
        c.write_all(&(stored - 60).to_le_bytes()).unwrap();
        until("the acknowledgement", || s.spool.st.lock().unwrap().acked == stored - 60);
        // killed, with a frame cut short at the end of its file
        drop(s);
        drop(c);
        std::thread::sleep(Duration::from_millis(300));
        let wal = std::fs::read_dir(dir.path()).unwrap().flatten().find(|e| e.path().extension().is_some_and(|x| x == "wal")).unwrap().path();
        OpenOptions::new().append(true).open(&wal).unwrap().write_all(&[200, 0, 0, 0, b'E', 1, 2]).unwrap();

        let mut s = Stream::start(addr, "t0k".into(), dir.path(), SPOOL_MAX).unwrap();
        s.send(EVENT, b"{\"n\":\"new\"}");
        let mut c = accept(&l);
        // the unacknowledged lines again, in order, then the new one
        let (got, last) = lines(&mut c, 61);
        assert_eq!(got[..60], numbers(40..100));
        assert_eq!(got[60], "{\"n\":\"new\"}");
        assert!(last > stored);
        // stored: the old file goes, the one being written stays
        assert_eq!(wal_files(dir.path()), 2);
        c.write_all(&last.to_le_bytes()).unwrap();
        until("the old file removed", || wal_files(dir.path()) == 1);
        assert_eq!(s.dropped, 0);
    }

    #[test]
    fn what_siem_api_did_not_store_is_sent_again() {
        let dir = tempfile::tempdir().unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut s = Stream::start(l.local_addr().unwrap().to_string(), "t0k".into(), dir.path(), SPOOL_MAX).unwrap();
        for line in numbers(0..50) {
            s.send(ALERT, line.as_bytes());
        }
        let mut c = accept(&l);
        let (_, last) = lines(&mut c, 50);
        c.write_all(&(last - 30).to_le_bytes()).unwrap();
        until("the acknowledgement", || s.spool.st.lock().unwrap().acked == last - 30);
        // siem-api dies having received all 50 and stored 20; nothing new is being sent
        drop(c);
        let mut c = accept(&l);
        let (got, again) = lines(&mut c, 30);
        assert_eq!(got, numbers(20..50));
        assert_eq!(again, last, "the same sequences: siem-api can tell a replay");
    }

    #[test]
    fn unacknowledged_lines_count_against_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let line = b"{\"n\":12345}"; // 24 bytes a frame
        let mut s = Stream::start(free_addr(), "t0k".into(), dir.path(), 160).unwrap();
        let warnings: Vec<String> = (0..100).filter_map(|_| s.send(EVENT, line)).collect();
        assert_eq!(s.dropped, 94);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("1 line(s) dropped"), "{}", warnings[0]);
        until("the lines in the file", || wal_files(dir.path()) == 1);
        s.spool.flush();
        assert_eq!(std::fs::metadata(dir.path().join(std::fs::read_dir(dir.path()).unwrap().flatten().find(|e| e.path().extension().is_some_and(|x| x == "wal")).unwrap().file_name())).unwrap().len(), 144);
    }

    #[test]
    fn lines_reach_the_file_soon_without_a_write_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Stream::start(free_addr(), "t0k".into(), dir.path(), SPOOL_MAX).unwrap();
        // a line waits in the buffer for at most about BATCH, with nobody connected
        s.send(EVENT, b"{\"n\":1}");
        let sp = s.spool.clone();
        let bytes = || sp.st.lock().unwrap().segs.iter().map(|x| x.1).sum::<u64>();
        until("the line in the file", || bytes() > 0);
        // past the buffer's size, the caller writes it: the buffer stays bounded
        let line = vec![b'x'; 1000];
        for _ in 0..2000 {
            s.send(EVENT, &line);
            assert!(s.spool.st.lock().unwrap().buf.len() <= BUFFER);
        }
        assert_eq!(s.dropped, 0);
        s.spool.flush();
        assert_eq!(bytes(), 20 + 2000 * (1000 + HEADER as u64));
    }

    #[test]
    fn a_failed_write_keeps_the_lines_and_a_crash_loses_only_the_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let sp = Spool::open(dir.path(), SPOOL_MAX).unwrap();
        assert!(sp.append(EVENT, b"in the file"));
        assert!(sp.flush());
        assert!(sp.append(EVENT, b"in the buffer"));
        // the file's place is taken: the line stays in the buffer for another try
        let first = sp.st.lock().unwrap().buf_first;
        let seg = sp.st.lock().unwrap().segs.back_mut().map(|b| {
            let keep = b.1;
            b.1 = SEGMENT;
            keep
        });
        std::fs::create_dir(sp.path(first)).unwrap();
        assert!(!sp.flush());
        assert_eq!(sp.st.lock().unwrap().flushed, first);
        std::fs::remove_dir(sp.path(first)).unwrap();
        sp.st.lock().unwrap().segs.back_mut().unwrap().1 = seg.unwrap();
        assert!(sp.flush());
        assert_eq!(sp.st.lock().unwrap().flushed, first + 1);
        // killed with a third line in the buffer: the two in the file are there after a restart
        assert!(sp.append(EVENT, b"lost"));
        std::mem::forget(sp);
        let sp = Spool::open(dir.path(), SPOOL_MAX).unwrap();
        assert_eq!(sp.st.lock().unwrap().bytes, 2 * HEADER as u64 + 24);
    }

    #[test]
    fn the_previous_spool_moves_in_unsent_lines_first() {
        let dir = tempfile::tempdir().unwrap();
        let old = |kind: u8, json: &[u8]| [&((json.len() + 1) as u32).to_le_bytes()[..], &[kind], json].concat();
        let sent = old(EVENT, b"{\"n\":0}");
        std::fs::write(dir.path().join(format!("{:020}.spool", 3)), [sent.clone(), old(EVENT, b"{\"n\":1}")].concat()).unwrap();
        std::fs::write(dir.path().join(format!("{:020}.spool", 4)), old(ALERT, b"{\"n\":2}")).unwrap();
        std::fs::write(dir.path().join("read.pos"), format!("{:020} {:020}\n", 3, sent.len())).unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _s = Stream::start(l.local_addr().unwrap().to_string(), "t0k".into(), dir.path(), SPOOL_MAX).unwrap();
        assert!(!dir.path().join("read.pos").exists());
        let mut c = accept(&l);
        assert_eq!(lines(&mut c, 2).0, numbers(1..3));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().flatten().filter(|e| e.path().extension().is_some_and(|x| x == "spool")).count(), 0);
    }
}
