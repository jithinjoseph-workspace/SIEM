//! `getDefine_Int` / `_read_file` (`src/shared/validate_op.c`): internal
//! options from `local_internal_options.conf`, falling back to
//! `internal_options.conf`.

use crate::{messages, ConfigError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct InternalOptions {
    /// `OSSEC_LDEFINES` (checked first; a missing file is silently ignored).
    pub local: PathBuf,
    /// `OSSEC_DEFINES`
    pub defaults: PathBuf,
}

impl InternalOptions {
    /// Paths relative to a Wazuh home directory (`etc/...`).
    pub fn from_home(home: impl AsRef<Path>) -> Self {
        let h = home.as_ref();
        Self {
            local: h.join("etc").join("local_internal_options.conf"),
            defaults: h.join("etc").join("internal_options.conf"),
        }
    }

    /// `_read_file`. `Ok(None)` when the option is absent; `Err` only when a
    /// non-local file cannot be opened (Wazuh logs FOPEN_ERROR and treats it
    /// as absent, so that case is also `Ok(None)` with a log line).
    fn read_file(path: &Path, high: &str, low: &str, is_local: bool) -> Option<String> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                if !is_local {
                    tracing::error!("(1103): Could not open file '{}' due to [({})-({})].", path.display(), e.raw_os_error().unwrap_or(0), e);
                }
                return None;
            }
        };
        // fgets(buf, 1024): long lines are split into 1023-byte chunks.
        for raw in split_fgets(&data, 1024) {
            let line = String::from_utf8_lossy(raw);
            let first = line.as_bytes().first().copied();
            if matches!(first, Some(b'#') | Some(b' ') | Some(b'\n')) {
                continue;
            }
            let Some(dot) = line.find('.') else {
                tracing::error!("{}", messages::fgets_error(&path.display().to_string(), &line));
                continue;
            };
            if &line[..dot] != high {
                continue;
            }
            let rest = &line[dot + 1..];
            let Some(eq) = rest.find('=') else {
                tracing::error!("{}", messages::fgets_error(&path.display().to_string(), &line[..dot]));
                continue;
            };
            // Remove spaces between the low name and '='
            let name = rest[..eq].trim_end_matches(' ');
            if name != low {
                continue;
            }
            let mut value = rest[eq + 1..].trim_start_matches(' ').to_string();
            if let Some(p) = value.rfind('\n') {
                value.truncate(p);
            }
            if let Some(p) = value.rfind('\r') {
                value.truncate(p);
            }
            return Some(value);
        }
        None
    }

    /// Raw string value (local file first).
    pub fn get_string(&self, high: &str, low: &str) -> Option<String> {
        Self::read_file(&self.local, high, low, true).or_else(|| Self::read_file(&self.defaults, high, low, false))
    }

    /// `getDefine_Int`. Wazuh exits the daemon on error; we return `Err`.
    pub fn get_int(&self, high: &str, low: &str, min: i32, max: i32) -> Result<i32> {
        let value = self
            .get_string(high, low)
            .ok_or_else(|| ConfigError::new(messages::def_not_found(high, low)))?;
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ConfigError::new(messages::inv_def(high, low, &value)));
        }
        let ret = crate::util::atoi(&value);
        if ret < min || ret > max {
            return Err(ConfigError::new(messages::inv_def(high, low, &value)));
        }
        Ok(ret)
    }
}

/// Mimic `fgets(buf, size, fp)` line chunking (keeps the '\n').
fn split_fgets(data: &[u8], size: usize) -> Vec<&[u8]> {
    let max = size - 1;
    let mut out = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let mut end = start;
        while end < data.len() && end - start < max {
            end += 1;
            if data[end - 1] == b'\n' {
                break;
            }
        }
        out.push(&data[start..end]);
        start = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_wazuh_internal_options() {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("internal_options.conf"),
            "# comment\nremoted.recv_counter_flush=128\nremoted.verify_msg_id =0\nanalysisd.debug=0\n",
        )
        .unwrap();
        std::fs::write(etc.join("local_internal_options.conf"), "remoted.verify_msg_id= 1\r\n").unwrap();
        let o = InternalOptions::from_home(dir.path());
        assert_eq!(o.get_int("remoted", "recv_counter_flush", 10, 999999).unwrap(), 128);
        assert_eq!(o.get_int("remoted", "verify_msg_id", 0, 1).unwrap(), 1);
        assert!(o.get_int("remoted", "missing", 0, 1).is_err());
        assert!(o.get_int("remoted", "recv_counter_flush", 0, 1).is_err());
    }
}
