//! The bits of C stdio the alert readers rely on: `fgets`, `ftell`, `fseek`,
//! `feof` and `clearerr` on a buffered file that may keep growing.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};

pub struct CFile {
    r: BufReader<File>,
    eof: bool,
}

impl CFile {
    pub fn open(path: &str) -> std::io::Result<CFile> {
        Ok(CFile { r: BufReader::new(File::open(path)?), eof: false })
    }

    pub fn from_file(f: File) -> CFile {
        CFile { r: BufReader::new(f), eof: false }
    }

    /// `fgets(buf, n, fp)`: at most `n - 1` bytes, up to and including '\n'.
    /// `None` when nothing could be read (EOF).
    pub fn fgets(&mut self, n: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let max = n.saturating_sub(1);
        while out.len() < max {
            let buf = match self.r.fill_buf() {
                Ok(b) => b,
                Err(_) => break,
            };
            if buf.is_empty() {
                self.eof = true;
                break;
            }
            let room = max - out.len();
            let take = buf.iter().take(room).position(|&c| c == b'\n').map(|p| p + 1).unwrap_or(buf.len().min(room));
            out.extend_from_slice(&buf[..take]);
            self.r.consume(take);
            if out.last() == Some(&b'\n') {
                break;
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    pub fn ftell(&mut self) -> i64 {
        self.r.stream_position().map(|p| p as i64).unwrap_or(-1)
    }

    pub fn seek(&mut self, pos: SeekFrom) -> bool {
        self.eof = false;
        self.r.seek(pos).is_ok()
    }

    pub fn feof(&self) -> bool {
        self.eof
    }

    pub fn clearerr(&mut self) {
        self.eof = false;
    }

    pub fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.r.get_ref().metadata()
    }
}

/// `st_ino` (on Windows the creation time stands in for it).
pub fn inode(m: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        m.ino()
    }
    #[cfg(not(unix))]
    {
        m.created().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos() as u64).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn fgets_like_c() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"ab\ncdef").unwrap();
        let mut f = CFile::open(p.to_str().unwrap()).unwrap();
        assert_eq!(f.fgets(100).unwrap(), b"ab\n");
        assert_eq!(f.fgets(3).unwrap(), b"cd");
        assert_eq!(f.fgets(100).unwrap(), b"ef");
        assert!(f.fgets(100).is_none() && f.feof());
        // data appended after EOF is read
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"\nx\n").unwrap();
        f.clearerr();
        assert_eq!(f.fgets(100).unwrap(), b"\n");
        assert_eq!(f.ftell(), 8);
    }
}
