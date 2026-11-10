//! What the C runtime does to `wfopen` streams. On Windows the agent links
//! msvcrt, and `wfopen` (`shared/file_op.c`) opens "r" and "w" streams in
//! text mode (`_O_TEXT`) but "a" streams without it. Text-mode reads turn
//! CR LF into LF and stop at a Ctrl-Z byte; text-mode writes turn every LF
//! into CR LF. On Unix every mode is binary, so these helpers translate
//! nothing.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Whether `wfopen(path, "r")` / `"w"` streams are translated here.
pub const TEXT_TRANSLATION: bool = cfg!(windows);

/// msvcrt `_read` in text mode over a whole file: `\r\n` becomes `\n`,
/// other `\r` stay, and a `0x1A` (Ctrl-Z) ends the data.
pub fn text_in(raw: &[u8]) -> Vec<u8> {
    let end = raw.iter().position(|&c| c == 0x1a).unwrap_or(raw.len());
    let raw = &raw[..end];
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\r' && raw.get(i + 1) == Some(&b'\n') {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    out
}

/// msvcrt `_write` in text mode: every `\n` is written as `\r\n`.
pub fn text_out(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 16);
    for &c in data {
        if c == b'\n' {
            out.push(b'\r');
        }
        out.push(c);
    }
    out
}

/// The contents of `wfopen(path, "r")`.
pub fn read_text(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let raw = fs::read(path)?;
    Ok(if TEXT_TRANSLATION { text_in(&raw) } else { raw })
}

/// `wfopen(path, "w")` + `fwrite(data)` + `fclose`.
pub fn write_text(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    if TEXT_TRANSLATION {
        fs::write(path, text_out(data))
    } else {
        fs::write(path, data)
    }
}

/// A `wfopen(path, "w")` stream: writes go through [`text_out`] on Windows.
pub struct TextFile(pub fs::File);

impl TextFile {
    pub fn create(path: impl AsRef<Path>) -> io::Result<TextFile> {
        fs::File::create(path).map(TextFile)
    }
}

impl Write for TextFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if TEXT_TRANSLATION {
            self.0.write_all(&text_out(buf))?;
            Ok(buf.len())
        } else {
            self.0.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// `is_network_path` (`shared/file_op.c`, Windows): UNC / device paths and
/// mapped network drives, which `wfopen` and friends refuse.
#[cfg(windows)]
pub fn is_network_path(path: &str) -> bool {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceA;
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegOpenKeyExA, HKEY, HKEY_CURRENT_USER, KEY_READ};

    let p = path.as_bytes();
    if p.len() >= 2 && p[0] == b'\\' && p[1] == b'\\' {
        return true;
    }
    if p.len() >= 2 && p[1] == b':' {
        let drive = p[0].to_ascii_uppercase();
        let device = [drive, b':', 0];
        let mut target = [0u8; 260];
        // SAFETY: NUL-terminated device name, buffer of MAX_PATH bytes.
        let r = unsafe { QueryDosDeviceA(device.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
        if r > 0 {
            let t = &target[..];
            if t.starts_with(b"\\Device\\Mup\\")
                || t.starts_with(b"\\Device\\LanmanRedirector\\")
                || t.starts_with(b"\\DosDevices\\UNC\\")
            {
                return true;
            }
            if t.starts_with(b"\\Device\\") {
                return false;
            }
        }
        // Fallback: HKCU\Network\<letter>
        let key = [b'N', b'e', b't', b'w', b'o', b'r', b'k', b'\\', drive, 0];
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: NUL-terminated subkey, out-pointer to an HKEY.
        if unsafe { RegOpenKeyExA(HKEY_CURRENT_USER, key.as_ptr(), 0, KEY_READ, &mut h) } == 0 {
            unsafe { RegCloseKey(h) };
            return true;
        }
    }
    false
}

/// `NETWORK_PATH_EXECUTED`
pub fn network_path_executed(path: &str) -> String {
    format!("(9800): File access denied. Network path usage is not allowed: '{path}'.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msvcrt_text_mode() {
        assert_eq!(text_in(b"a\r\nb\rc\r\n\r\x1ad\r\n"), b"a\nb\rc\n\r");
        assert_eq!(text_out(b"a\nb\r\n"), b"a\r\nb\r\r\n");
        assert_eq!(text_in(&text_out(b"x\ny\r\n")), b"x\ny\r\n");
    }
}
