//! The response commands of `etc/shared/ar.conf`: `<name> - <program> - <timeout>` per line.

use crate::{atoi, cut, Execd, AR_BINDIR, AR_CONF, MAX_COMMANDS, NAME_ROOM, PATH_ROOM};

/// The commands read from `ar.conf`.
#[derive(Default)]
pub struct Table {
    /// (name, program path or "" when the program is missing, timeout in seconds)
    pub commands: Vec<(String, String, i32)>,
    /// Read before: a missing program is reported only on the first reading.
    pub read_before: bool,
}

fn invalid() -> String {
    format!("(1313): Invalid active response config: '{AR_CONF}'.")
}

impl Execd {
    /// Reads `ar.conf` again. False when it cannot be opened (the table is then empty).
    pub fn read_table(&self) -> bool {
        let mut t = self.table.lock().unwrap_or_else(|e| e.into_inner());
        t.commands.clear();
        let data = match std::fs::read(self.home.join(AR_CONF)) {
            Ok(d) => d,
            Err(e) => {
                self.log.error(format!("(1103): Could not open file '{AR_CONF}' due to [({})-({})].", crate::errno(&e), crate::strerror(&e)));
                return false;
            }
        };
        // lines of at most 65,535 bytes, a longer one read in parts
        let mut rest = &data[..];
        while !rest.is_empty() {
            let end = rest.iter().take(65535).position(|&c| c == b'\n').map_or(rest.len().min(65535), |p| p + 1);
            let (raw, tail) = rest.split_at(end);
            rest = tail;
            let line = String::from_utf8_lossy(&raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())]).into_owned();
            if line.starts_with('!') {
                self.log.error(invalid());
                continue;
            }
            let Some((name_full, after)) = line.split_once(" - ") else {
                self.log.error(invalid());
                continue;
            };
            let name = cut(name_full, NAME_ROOM);
            if name_full.len() >= NAME_ROOM {
                self.log.error(format!("(1318): Command name truncated {name}"));
            }
            let Some((program, timeout)) = after.split_once(" - ") else {
                self.log.error(invalid());
                continue;
            };
            let path = if provigil_fileop::ref_parent_folder(program) {
                self.log.error(format!("Active response command '{program}' vulnerable to directory traversal attack. Ignoring."));
                String::new()
            } else {
                let full = cut(&format!("{AR_BINDIR}/{program}"), PATH_ROOM);
                if std::fs::File::open(self.home.join(&full)).is_ok() {
                    full
                } else {
                    if !t.read_before {
                        self.log.info(format!("Active response command not present: '{full}'. Not using it on this system."));
                    }
                    String::new()
                }
            };
            let timeout = atoi(timeout.split('\n').next().unwrap_or(""));
            // a repeated name keeps its first entry, filled in when that one had no program
            let mut repeated = false;
            for c in t.commands.iter_mut().filter(|c| c.0 == name) {
                if c.1.is_empty() {
                    c.1 = path.clone();
                    repeated = true;
                    break;
                } else if path.is_empty() {
                    repeated = true;
                }
            }
            if !repeated && t.commands.len() <= MAX_COMMANDS {
                t.commands.push((name, path, timeout));
            }
        }
        t.read_before = true;
        true
    }

    /// The program and timeout of a command. `!<program>` runs that program of the response
    /// folder with no timeout.
    pub fn command(&self, name: &str) -> Option<(String, i32)> {
        if let Some(program) = name.strip_prefix('!') {
            if provigil_fileop::ref_parent_folder(program) {
                self.log.warn(format!("Active response command '{program}' vulnerable to directory traversal attack. Ignoring."));
                return None;
            }
            let path = format!("{AR_BINDIR}/{program}");
            if path.len() >= PATH_ROOM {
                self.log.warn(format!("Cannot execute command '{:.32}...': path too long.", program));
                return None;
            }
            return Some((path, 0));
        }
        let t = self.table.lock().unwrap_or_else(|e| e.into_inner());
        t.commands.iter().find(|c| c.0 == name).map(|c| (c.1.clone(), c.2))
    }
}
