//! A `FILE *` as the logcollector readers use it: buffered reads with
//! glibc's behaviour (sticky EOF since glibc 2.28, `fgets` writing into the
//! caller's buffer and leaving the rest of it untouched, `ftell`/`fseek`,
//! `fgetc`/`ungetc`, `fread`), on a file or on a `popen` pipe.
//!
//! On Windows the C agent links msvcrt instead: its `_filbuf` reads again
//! after EOF (nothing is sticky), and `popen` runs `%COMSPEC% /c command`
//! with a text-mode stream (CR LF becomes LF, Ctrl-Z ends the output).
//!
//! The readers keep fixed C buffers whose old bytes persist between lines,
//! and some of them look past the current string; keeping the buffers as
//! byte arrays filled by [`CFile::fgets`] reproduces that exactly.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::process::{Child, ChildStdout, Command, Stdio};

/// glibc's default buffer for regular files (`st_blksize`).
const BUFSIZ: usize = 4096;

enum Src {
    File(File),
    Pipe(ChildStdout),
}

pub struct CFile {
    src: Src,
    child: Option<Child>,
    buf: Vec<u8>,
    /// Read position inside `buf`.
    pos: usize,
    /// File offset of `buf[0]`.
    base: i64,
    eof: bool,
    err: bool,
    /// Last errno of a failed read.
    pub errno: i32,
    /// Text-mode pipe (msvcrt `_popen`): a CR held back until the next
    /// byte tells whether it starts a CR LF, and the Ctrl-Z end mark.
    text: bool,
    held_cr: bool,
    text_eof: bool,
}

/// The C string in a buffer (up to the first NUL).
pub fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `strlen`
pub fn strlen(b: &[u8]) -> usize {
    cstr(b).len()
}

impl CFile {
    /// `fopen(path, "rb")`
    pub fn open(path: &str) -> std::io::Result<CFile> {
        let f = File::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // w_file_cloexec
            // SAFETY: fcntl on our own descriptor.
            unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        Ok(CFile::from_file(f))
    }

    pub fn from_file(f: File) -> CFile {
        CFile {
            src: Src::File(f),
            child: None,
            buf: Vec::new(),
            pos: 0,
            base: 0,
            eof: false,
            err: false,
            errno: 0,
            text: false,
            held_cr: false,
            text_eof: false,
        }
    }

    /// `popen(command, "r")` (`/bin/sh -c command`).
    #[cfg(unix)]
    pub fn popen(command: &str) -> std::io::Result<CFile> {
        let mut child = Command::new("/bin/sh").arg("-c").arg(command).stdout(Stdio::piped()).spawn()?;
        let out = child.stdout.take().expect("piped stdout");
        Ok(CFile::pipe(child, out, false))
    }

    /// `popen(command, "r")` (msvcrt `_popen`: `%COMSPEC% /c command`,
    /// text mode).
    #[cfg(windows)]
    pub fn popen(command: &str) -> std::io::Result<CFile> {
        use std::os::windows::process::CommandExt;
        let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
        let mut child = Command::new(comspec).raw_arg(format!("/c {command}")).stdout(Stdio::piped()).spawn()?;
        let out = child.stdout.take().expect("piped stdout");
        Ok(CFile::pipe(child, out, true))
    }

    fn pipe(child: Child, out: ChildStdout, text: bool) -> CFile {
        CFile {
            src: Src::Pipe(out),
            child: Some(child),
            buf: Vec::new(),
            pos: 0,
            base: 0,
            eof: false,
            err: false,
            errno: 0,
            text,
            held_cr: false,
            text_eof: false,
        }
    }

    /// `pclose`
    pub fn pclose(mut self) {
        if let Some(mut c) = self.child.take() {
            drop(std::mem::replace(&mut self.src, Src::File(tempfile_null())));
            let _ = c.wait();
        }
    }

    /// The underlying file (for `fstat` / `fileno`).
    pub fn file(&self) -> Option<&File> {
        match &self.src {
            Src::File(f) => Some(f),
            Src::Pipe(_) => None,
        }
    }

    fn available(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// `__underflow` / `_filbuf`: refill the buffer. False at EOF or on
    /// error. glibc keeps EOF sticky; msvcrt reads again.
    fn fill(&mut self) -> bool {
        if cfg!(unix) && (self.eof || self.err) {
            return false;
        }
        if self.text_eof {
            self.eof = true;
            return false;
        }
        self.base += self.buf.len() as i64;
        self.buf.clear();
        self.pos = 0;
        let mut tmp = vec![0u8; BUFSIZ];
        let r = match &mut self.src {
            Src::File(f) => f.read(&mut tmp),
            Src::Pipe(p) => p.read(&mut tmp),
        };
        match r {
            Ok(0) => {
                if std::mem::take(&mut self.held_cr) {
                    self.buf = vec![b'\r'];
                    return true;
                }
                self.eof = true;
                false
            }
            Ok(n) => {
                tmp.truncate(n);
                if self.text {
                    tmp = self.text_translate(tmp);
                    if tmp.is_empty() {
                        // only a held CR (or the Ctrl-Z mark): read on
                        return self.fill();
                    }
                }
                self.eof = false;
                self.buf = tmp;
                true
            }
            Err(e) => {
                self.err = true;
                self.errno = e.raw_os_error().unwrap_or(0);
                false
            }
        }
    }

    /// msvcrt text-mode `_read` on a chunk: CR LF to LF (a CR at the end
    /// waits for the next chunk), Ctrl-Z ends the stream.
    fn text_translate(&mut self, raw: Vec<u8>) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len() + 1);
        let mut i = 0;
        if std::mem::take(&mut self.held_cr) {
            if raw.first() == Some(&b'\n') {
                out.push(b'\n');
                i = 1;
            } else {
                out.push(b'\r');
            }
        }
        while i < raw.len() {
            let c = raw[i];
            if c == 0x1a {
                self.text_eof = true;
                break;
            }
            if c == b'\r' {
                match raw.get(i + 1) {
                    Some(b'\n') => {
                        out.push(b'\n');
                        i += 2;
                        continue;
                    }
                    None => {
                        self.held_cr = true;
                        i += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            out.push(c);
            i += 1;
        }
        out
    }

    /// `fgets(buf, n, fp)`: up to `n - 1` bytes, through a newline, then a
    /// NUL. Returns false (and leaves `buf` alone) when nothing was read.
    pub fn fgets(&mut self, buf: &mut [u8], n: usize) -> bool {
        if n == 0 {
            return false;
        }
        if n == 1 {
            buf[0] = 0;
            return true;
        }
        let max = n - 1;
        let mut count = 0;
        while count < max {
            if self.available() == 0 && !self.fill() {
                break;
            }
            let c = self.buf[self.pos];
            self.pos += 1;
            buf[count] = c;
            count += 1;
            if c == b'\n' {
                break;
            }
        }
        if count == 0 || (self.err && count == 0) {
            return false;
        }
        buf[count] = 0;
        true
    }

    /// msvcrt `fgetwc` on a binary stream: a little-endian 16-bit unit, or
    /// -1 (`WEOF`) when a byte is missing.
    pub fn fgetwc(&mut self) -> i32 {
        let a = self.fgetc();
        if a < 0 {
            return -1;
        }
        let b = self.fgetc();
        if b < 0 {
            return -1;
        }
        a | b << 8
    }

    /// msvcrt `fgetws(s, count, fp)`: up to `count - 1` units, through an
    /// L'\n', then a 0. False (and `s` untouched) when nothing was read.
    pub fn fgetws(&mut self, s: &mut [u16], count: usize) -> bool {
        if count == 0 {
            return false;
        }
        let mut k = 0;
        let mut left = count;
        loop {
            left -= 1;
            if left == 0 {
                break;
            }
            let ch = self.fgetwc();
            if ch < 0 {
                if k == 0 {
                    return false;
                }
                break;
            }
            s[k] = ch as u16;
            k += 1;
            if ch == 0x0A {
                break;
            }
        }
        s[k] = 0;
        true
    }

    /// `fgetc`: the byte, or -1 (`EOF`).
    pub fn fgetc(&mut self) -> i32 {
        if self.available() == 0 && !self.fill() {
            return -1;
        }
        let c = self.buf[self.pos];
        self.pos += 1;
        c as i32
    }

    /// `ungetc(c, fp)` of the byte just read.
    pub fn ungetc(&mut self, c: i32) {
        if c < 0 {
            return;
        }
        if self.pos > 0 {
            self.pos -= 1;
            self.buf[self.pos] = c as u8;
        } else {
            self.buf.insert(0, c as u8);
            self.base -= 1;
        }
        self.eof = false;
    }

    /// `fread(buf, 1, n, fp)`
    pub fn fread(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            if self.available() == 0 && !self.fill() {
                break;
            }
            let k = self.available().min(out.len() - n);
            out[n..n + k].copy_from_slice(&self.buf[self.pos..self.pos + k]);
            self.pos += k;
            n += k;
        }
        n
    }

    /// `ftell` (`w_ftell`): -1 for a pipe.
    pub fn ftell(&self) -> i64 {
        match &self.src {
            Src::File(_) => self.base + self.pos as i64,
            Src::Pipe(_) => -1,
        }
    }

    /// `fseek(fp, off, whence)` (`w_fseek`): 0 or -1. Clears EOF.
    pub fn fseek(&mut self, off: i64, whence: i32) -> i32 {
        let cur = self.ftell();
        let Src::File(f) = &mut self.src else { return -1 };
        let target = match whence {
            0 => off,
            1 => cur + off,
            _ => match f.metadata() {
                Ok(m) => m.len() as i64 + off,
                Err(_) => return -1,
            },
        };
        if target < 0 {
            self.errno = 22; // EINVAL
            return -1;
        }
        if f.seek(SeekFrom::Start(target as u64)).is_err() {
            return -1;
        }
        self.buf.clear();
        self.pos = 0;
        self.base = target;
        self.eof = false;
        0
    }

    /// `feof`
    pub fn feof(&self) -> bool {
        self.eof
    }

    /// `ferror`
    pub fn ferror(&self) -> bool {
        self.err
    }

    /// `clearerr`
    pub fn clearerr(&mut self) {
        self.eof = false;
        self.err = false;
    }

    /// `fgetpos`
    pub fn fgetpos(&self) -> i64 {
        self.ftell()
    }

    /// `fsetpos`
    pub fn fsetpos(&mut self, pos: i64) {
        self.fseek(pos, 0);
    }
}

fn tempfile_null() -> File {
    #[cfg(unix)]
    let null = "/dev/null";
    #[cfg(windows)]
    let null = "NUL";
    File::open(null).unwrap_or_else(|_| File::open(".").expect("a file"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[cfg(unix)]
    #[test]
    fn fgets_like_glibc() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"abc\ndefgh\nij").unwrap();
        let mut f = CFile::open(p.to_str().unwrap()).unwrap();
        let mut b = [b'#'; 16];
        assert!(f.fgets(&mut b, 16));
        assert_eq!(&b[..5], b"abc\n\0");
        assert_eq!(f.ftell(), 4);
        assert!(f.fgets(&mut b, 4));
        assert_eq!(&b[..4], b"def\0");
        assert!(f.fgets(&mut b, 16));
        assert_eq!(cstr(&b), b"gh\n");
        assert!(f.fgets(&mut b, 16));
        assert_eq!(cstr(&b), b"ij");
        assert!(f.feof());
        // sticky EOF: appended data is not seen until clearerr
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"k\n").unwrap();
        assert!(!f.fgets(&mut b, 16));
        f.clearerr();
        assert!(f.fgets(&mut b, 16));
        assert_eq!(cstr(&b), b"k\n");
        assert_eq!(f.fseek(0, 0), 0);
        assert_eq!(f.fgetc(), b'a' as i32);
        f.ungetc(b'a' as i32);
        assert_eq!(f.ftell(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn popen_reads() {
        let mut f = CFile::popen("printf 'a\\nb\\n'").unwrap();
        let mut b = [0u8; 8];
        assert!(f.fgets(&mut b, 8));
        assert_eq!(cstr(&b), b"a\n");
        assert!(f.fgets(&mut b, 8));
        assert!(!f.fgets(&mut b, 8));
        f.pclose();
    }

    #[cfg(windows)]
    #[test]
    fn msvcrt_semantics() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"ab\n").unwrap();
        let mut f = CFile::open(p.to_str().unwrap()).unwrap();
        let mut b = [0u8; 16];
        assert!(f.fgets(&mut b, 16));
        assert!(!f.fgets(&mut b, 16));
        assert!(f.feof());
        // not sticky: appended data is read without clearerr
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"c\n").unwrap();
        assert!(f.fgets(&mut b, 16));
        assert_eq!(cstr(&b), b"c\n");
        // cmd.exe pipe in text mode
        let mut f = CFile::popen("echo a& echo b").unwrap();
        assert!(f.fgets(&mut b, 16));
        assert_eq!(cstr(&b), b"a\n");
        assert!(f.fgets(&mut b, 16));
        assert_eq!(cstr(&b), b"b\n");
        assert!(!f.fgets(&mut b, 16));
        f.pclose();
    }
}
