//! Follows `active-response\active-responses.log`, where the response programs write their
//! results, so the agent can send each new line to the manager.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Lines read per call at most (the rest come on the next call).
const MAX_READ: u64 = 1024 * 1024;

/// The complete lines written since `pos` (moved past them). A file that got shorter was
/// emptied or replaced: it is read from the start. A last line without its end waits.
pub fn new_lines(path: &Path, pos: &mut u64) -> Vec<String> {
    let Ok(mut f) = std::fs::File::open(path) else { return Vec::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len < *pos {
        *pos = 0;
    }
    if len == *pos || f.seek(SeekFrom::Start(*pos)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if f.take(MAX_READ).read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let Some(end) = buf.iter().rposition(|&b| b == b'\n') else {
        // one line longer than MAX_READ: skip it rather than stall
        if buf.len() as u64 >= MAX_READ {
            *pos += buf.len() as u64;
        }
        return Vec::new();
    };
    *pos += end as u64 + 1;
    String::from_utf8_lossy(&buf[..end]).lines().map(|l| l.trim_end_matches('\r').to_string()).filter(|l| !l.trim().is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn follows_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("active-responses.log");
        let mut pos = 0;
        assert!(new_lines(&p, &mut pos).is_empty(), "no file yet");
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&p).unwrap();
        f.write_all(b"one\r\ntwo\npartial").unwrap();
        assert_eq!(new_lines(&p, &mut pos), vec!["one", "two"]);
        assert!(new_lines(&p, &mut pos).is_empty(), "the unfinished line waits");
        f.write_all(b" line\n").unwrap();
        assert_eq!(new_lines(&p, &mut pos), vec!["partial line"]);
        // emptied: read again from the start
        std::fs::write(&p, b"new\n").unwrap();
        assert_eq!(new_lines(&p, &mut pos), vec!["new"]);
    }
}
