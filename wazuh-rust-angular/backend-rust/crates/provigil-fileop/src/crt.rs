//! The agent's "r" and "w" streams: Microsoft C runtime text mode on Windows, untranslated elsewhere.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub const TEXT_TRANSLATION: bool = cfg!(windows);

/// Data ends at the first Ctrl-Z; each `\r\n` becomes `\n`.
pub fn text_in(raw: &[u8]) -> Vec<u8> {
    let raw = &raw[..raw.iter().position(|&b| b == 0x1a).unwrap_or(raw.len())];
    let mut out = Vec::with_capacity(raw.len());
    for (i, &b) in raw.iter().enumerate() {
        if b != b'\r' || raw.get(i + 1) != Some(&b'\n') {
            out.push(b);
        }
    }
    out
}

/// Every `\n` becomes `\r\n` (an existing `\r\n` becomes `\r\r\n`).
pub fn text_out(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

pub fn read_text(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let raw = fs::read(path)?;
    Ok(if TEXT_TRANSLATION { text_in(&raw) } else { raw })
}

pub fn write_text(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    if TEXT_TRANSLATION {
        fs::write(path, text_out(data))
    } else {
        fs::write(path, data)
    }
}

/// A file opened for writing in text mode.
pub struct TextFile(pub File);

impl TextFile {
    pub fn create(path: impl AsRef<Path>) -> io::Result<TextFile> {
        File::create(path).map(TextFile)
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

/// True for UNC paths and drive letters mapped to a network redirector.
#[cfg(windows)]
pub fn is_network_path(path: &str) -> bool {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_READ};
    if path.starts_with(r"\\") {
        return true;
    }
    let b = path.as_bytes();
    if b.len() < 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return false;
    }
    let letter = b[0] as char;
    let drive = crate::wide(&format!("{letter}:"));
    let mut buf = [0u16; 1024];
    // SAFETY: NUL-terminated name and a buffer of the stated length.
    if unsafe { QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } != 0 {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        if let Some(answer) = device_target_is_network(&String::from_utf16_lossy(&buf[..end])) {
            return answer;
        }
    }
    let key = crate::wide(&format!(r"Network\{letter}"));
    let mut h = std::ptr::null_mut();
    // SAFETY: NUL-terminated key name and a valid out pointer; the key is closed when opened.
    unsafe {
        let found = RegOpenKeyExW(HKEY_CURRENT_USER, key.as_ptr(), 0, KEY_READ, &mut h) == ERROR_SUCCESS;
        if found {
            RegCloseKey(h);
        }
        found
    }
}

/// What a drive's device target says: network redirector -> true, any other `\Device\` -> false,
/// anything else (a `subst` target, for example) -> None, so the registry decides.
pub fn device_target_is_network(target: &str) -> Option<bool> {
    if [r"\Device\Mup\", r"\Device\LanmanRedirector\", r"\DosDevices\UNC\"].iter().any(|p| target.starts_with(p)) {
        return Some(true);
    }
    target.starts_with(r"\Device\").then_some(false)
}

pub fn network_path_executed(path: &str) -> String {
    format!("(9800): File access denied. Network path usage is not allowed: '{path}'.")
}
