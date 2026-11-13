//! Running the response programs and other helpers.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// Which standard streams of a program are connected to us; the others go to the null device.
#[derive(Clone, Copy, Default)]
pub struct Bind {
    pub stdin: bool,
    pub stdout: bool,
    /// On the same pipe as standard output.
    pub stderr: bool,
}

/// A running program. A program that could not be started at all (no such file, not
/// executable) is represented too, as one that reads nothing, writes nothing and ends with exit
/// code 127: callers treat both the same way.
pub struct Program {
    child: Option<std::process::Child>,
    stdin: Option<std::process::ChildStdin>,
    /// Output as a reader thread delivers it (so a read can give up), and what is not taken yet.
    out: Option<Receiver<Vec<u8>>>,
    buf: Vec<u8>,
}

/// A line read with a time limit.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    Text(Vec<u8>),
    End,
    TimedOut,
}

/// The wait status of a program that never started (exit code 127).
pub const NOT_STARTED: i32 = 127 << 8;

/// The program path as run: relative paths with a folder are under `home`, bare names are looked
/// up in `PATH`.
fn program_path(home: &Path, program: &str) -> std::path::PathBuf {
    if program.contains('/') && !Path::new(program).is_absolute() {
        home.join(program)
    } else {
        program.into()
    }
}

/// Whether a start error means the program itself cannot run (rather than a system failure).
fn not_runnable(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied) || e.raw_os_error() == Some(8)
}

impl Program {
    /// Starts `program` (argument list `argv`, its first entry the program name it sees) in
    /// `home`, in a session of its own. Err: the system could not start a process.
    pub fn start(home: &Path, program: &str, argv: &[&str], bind: Bind) -> std::io::Result<Program> {
        let mut c = Command::new(program_path(home, program));
        c.args(argv.iter().skip(1)).current_dir(home);
        c.stdin(if bind.stdin { Stdio::piped() } else { Stdio::null() });
        let mut reader = None;
        if bind.stdout || bind.stderr {
            let (r, w) = std::io::pipe()?;
            c.stdout(if bind.stdout { Stdio::from(w.try_clone()?) } else { Stdio::null() });
            c.stderr(if bind.stderr { Stdio::from(w) } else { Stdio::null() });
            reader = Some(r);
        } else {
            c.stdout(Stdio::null()).stderr(Stdio::null());
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            if let Some(a0) = argv.first() {
                c.arg0(a0);
            }
            // SAFETY: setsid is async-signal-safe and touches no memory
            unsafe {
                c.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
        }
        let child = match c.spawn() {
            Ok(ch) => ch,
            Err(e) if not_runnable(&e) => return Ok(Program { child: None, stdin: None, out: None, buf: Vec::new() }),
            Err(e) => return Err(e),
        };
        // the command still holds the write ends of the pipe: drop it so reads end with the program
        drop(c);
        let mut child = child;
        let stdin = child.stdin.take();
        let out = reader.map(|mut r| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut chunk = [0u8; 4096];
                while let Ok(n @ 1..) = r.read(&mut chunk) {
                    if tx.send(chunk[..n].to_vec()).is_err() {
                        break;
                    }
                }
            });
            rx
        });
        Ok(Program { child: Some(child), stdin, out, buf: Vec::new() })
    }

    /// Writes `line` and a line break to the program's input (errors ignored: the program may
    /// have ended).
    pub fn write_line(&mut self, line: &[u8]) {
        if let Some(i) = self.stdin.as_mut() {
            let mut b = line.to_vec();
            b.push(b'\n');
            let _ = i.write_all(&b).and_then(|_| i.flush());
        }
    }

    /// The next line of output with its line break, at most `size - 1` bytes; None at the end.
    pub fn read_line(&mut self, size: usize) -> Option<Vec<u8>> {
        match self.read_line_within(size, None) {
            Line::Text(l) => Some(l),
            _ => None,
        }
    }

    /// [`read_line`](Self::read_line) giving up after `limit`.
    pub fn read_line_within(&mut self, size: usize, limit: Option<Duration>) -> Line {
        let deadline = limit.map(|l| Instant::now() + l);
        let max = size.saturating_sub(1);
        loop {
            if let Some(p) = self.buf.iter().take(max).position(|&c| c == b'\n') {
                return Line::Text(self.buf.drain(..=p).collect());
            }
            if max > 0 && self.buf.len() >= max {
                return Line::Text(self.buf.drain(..max).collect());
            }
            let Some(rx) = self.out.as_ref() else { return self.rest() };
            let got = match deadline {
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(d) => rx.recv_timeout(d.saturating_duration_since(Instant::now())),
            };
            match got {
                Ok(chunk) => self.buf.extend(chunk),
                Err(RecvTimeoutError::Disconnected) => {
                    self.out = None;
                    return self.rest();
                }
                Err(RecvTimeoutError::Timeout) => return Line::TimedOut,
            }
        }
    }

    /// What is left at the end of the output.
    fn rest(&mut self) -> Line {
        if self.buf.is_empty() {
            Line::End
        } else {
            Line::Text(std::mem::take(&mut self.buf))
        }
    }

    /// The rest of the output.
    pub fn read_all(&mut self) -> Vec<u8> {
        let mut v = std::mem::take(&mut self.buf);
        if let Some(rx) = self.out.take() {
            for chunk in rx {
                v.extend(chunk);
            }
        }
        v
    }

    /// Closes the streams and waits: the wait status (Unix: exit code × 256 or the signal; other
    /// systems: the exit code), -1 when waiting failed.
    pub fn close(self) -> i32 {
        self.close_within(None).0
    }

    /// [`close`](Self::close) stopping the program when it has not ended after `limit`: the
    /// status and whether it was stopped.
    pub fn close_within(mut self, limit: Option<Duration>) -> (i32, bool) {
        drop(self.stdin.take());
        drop(self.out.take());
        let Some(mut child) = self.child.take() else { return (NOT_STARTED, false) };
        let mut stopped = false;
        if let Some(l) = limit {
            let deadline = Instant::now() + l;
            while matches!(child.try_wait(), Ok(None)) {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    stopped = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let status = match child.wait() {
            #[cfg(unix)]
            Ok(s) => std::os::unix::process::ExitStatusExt::into_raw(s),
            #[cfg(not(unix))]
            Ok(s) => s.code().unwrap_or(-1),
            Err(_) => -1,
        };
        (status, stopped)
    }
}

/// Starts `argv[0]` with the arguments without waiting (it keeps our standard streams). The
/// caller reaps the child.
pub fn start_detached(home: &Path, argv: &[&str]) -> std::io::Result<std::process::Child> {
    let mut c = Command::new(program_path(home, argv[0]));
    c.args(&argv[1..]).current_dir(home);
    #[cfg(unix)]
    std::os::unix::process::CommandExt::arg0(&mut c, argv[0]);
    c.spawn()
}

/// What [`capture`] got.
pub struct Captured {
    /// 0, [`TIMED_OUT`], or -1 when the command could not run.
    pub result: i32,
    /// Standard output then standard error (unset when the command could not run).
    pub output: Option<Vec<u8>>,
    /// The exit code when the program ended; 127 when it could not run.
    pub status: Option<i32>,
}

pub const TIMED_OUT: i32 = 1;

/// Runs a command line (split at white space) in `home` and collects its output; after `secs`
/// seconds it is stopped.
pub fn capture(home: &Path, command: &str, secs: u64) -> Captured {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let failed = Captured { result: -1, output: None, status: Some(127) };
    let Some(first) = parts.first() else { return failed };
    let mut c = Command::new(program_path(home, first));
    c.args(&parts[1..]).current_dir(home).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let Ok(mut child) = c.spawn() else { return failed };
    let take = |r: Option<Box<dyn Read + Send>>| std::thread::spawn(move || {
        let mut v = Vec::new();
        if let Some(mut r) = r {
            let _ = r.read_to_end(&mut v);
        }
        v
    });
    let out = take(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err = take(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let (result, status) = loop {
        match child.try_wait() {
            Ok(Some(s)) => break (0, Some(s.code().unwrap_or(-1))),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break (TIMED_OUT, None);
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => break (-1, None),
        }
    };
    let mut output = out.join().unwrap_or_default();
    output.extend(err.join().unwrap_or_default());
    Captured { result, output: (result >= 0).then_some(output), status }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silent_program_is_given_up_and_stopped() {
        let home = std::env::temp_dir();
        #[cfg(windows)]
        let argv = ["powershell", "-NoProfile", "-Command", "Start-Sleep 30"];
        #[cfg(unix)]
        let argv = ["sleep", "30"];
        let mut p = Program::start(&home, argv[0], &argv, Bind { stdin: true, stdout: true, stderr: false }).unwrap();
        let t = Instant::now();
        assert_eq!(p.read_line_within(8192, Some(Duration::from_millis(500))), Line::TimedOut);
        let (_, stopped) = p.close_within(Some(Duration::ZERO));
        assert!(stopped && t.elapsed() < Duration::from_secs(10));
        // a program that cannot run reads as ended, status 127
        let mut gone = Program::start(&home, "no-such-program-here", &["no-such-program-here"], Bind { stdin: true, stdout: true, stderr: false }).unwrap();
        assert_eq!(gone.read_line(10), None);
        assert_eq!(gone.close(), NOT_STARTED);
    }
}
