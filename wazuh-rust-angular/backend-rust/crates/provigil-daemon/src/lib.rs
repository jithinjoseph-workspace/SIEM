//! What every ProVigil manager service needs: the log writer (`logs/ossec.log`), the internal
//! options (`etc/internal_options.conf`, overridden by `etc/local_internal_options.conf`), small
//! readers of `etc/ossec.conf`, and the PID file.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

// ------------------------------------------------------------------ log

/// Lines of `logs/ossec.log`: `YYYY/MM/DD HH:MM:SS <tag>: LEVEL: text`. Levels CRITICAL, ERROR,
/// WARNING, INFO, DEBUG (shown at debug level 1) and DEBUG2 (level 2, written as DEBUG).
pub struct Log {
    file: Mutex<Option<std::fs::File>>,
    debug: AtomicU8,
    tag: String,
}

impl Log {
    /// The log of the service `tag`, appending to `home/logs/ossec.log`.
    pub fn open(home: &Path, tag: &str) -> Log {
        let _ = std::fs::create_dir_all(home.join("logs"));
        let file = std::fs::OpenOptions::new().create(true).append(true).open(home.join("logs/ossec.log")).ok();
        Log { file: Mutex::new(file), debug: AtomicU8::new(0), tag: tag.to_string() }
    }

    /// A log that writes nowhere (tests).
    pub fn null() -> Log {
        Log { file: Mutex::new(None), debug: AtomicU8::new(2), tag: String::new() }
    }

    pub fn set_debug(&self, level: u8) {
        self.debug.store(level.min(2), Ordering::Relaxed);
    }

    pub fn debug_level(&self) -> u8 {
        self.debug.load(Ordering::Relaxed)
    }

    /// Whether lines of `level` are written.
    pub fn enabled(&self, level: &str) -> bool {
        let need = match level {
            "DEBUG" => 1,
            "DEBUG2" => 2,
            _ => 0,
        };
        self.debug_level() >= need
    }

    /// A line with the service's own tag.
    pub fn write(&self, level: &str, msg: impl AsRef<[u8]>) {
        self.tagged(&self.tag.clone(), level, msg);
    }

    /// A line with another tag (`provigil-modulesd:database`, ...).
    pub fn tagged(&self, tag: &str, level: &str, msg: impl AsRef<[u8]>) {
        if !self.enabled(level) {
            return;
        }
        let shown = if level == "DEBUG2" { "DEBUG" } else { level };
        let line = format!("{} {tag}: {shown}: {}\n", chrono::Local::now().format("%Y/%m/%d %H:%M:%S"), String::from_utf8_lossy(msg.as_ref()));
        if let Ok(mut f) = self.file.lock() {
            if let Some(f) = f.as_mut() {
                let _ = f.write_all(line.as_bytes());
            }
        }
        if level == "CRITICAL" {
            eprint!("{line}");
        }
    }

    pub fn critical(&self, m: impl AsRef<[u8]>) {
        self.write("CRITICAL", m)
    }
    pub fn error(&self, m: impl AsRef<[u8]>) {
        self.write("ERROR", m)
    }
    pub fn warn(&self, m: impl AsRef<[u8]>) {
        self.write("WARNING", m)
    }
    pub fn info(&self, m: impl AsRef<[u8]>) {
        self.write("INFO", m)
    }
    pub fn debug(&self, m: impl AsRef<[u8]>) {
        self.write("DEBUG", m)
    }
    pub fn debug2(&self, m: impl AsRef<[u8]>) {
        self.write("DEBUG2", m)
    }
}

// ------------------------------------------------------------------ internal options

/// `<group>.<key>=<value>` lines of the internal options files.
pub struct Options(HashMap<String, String>);

impl Options {
    pub fn read(home: &Path) -> Options {
        let mut m = HashMap::new();
        for f in ["etc/internal_options.conf", "etc/local_internal_options.conf"] {
            m.extend(parse_options(&std::fs::read_to_string(home.join(f)).unwrap_or_default()));
        }
        Options(m)
    }

    pub fn get(&self, group: &str, key: &str) -> Option<&str> {
        self.0.get(&format!("{group}.{key}")).map(String::as_str)
    }

    /// A whole number in `min..=max`, `default` when the option is absent; an error text otherwise.
    pub fn int(&self, group: &str, key: &str, default: i64, min: i64, max: i64) -> Result<i64, String> {
        match self.get(group, key) {
            None => Ok(default),
            Some(v) => match v.trim().parse::<i64>() {
                Ok(n) if (min..=max).contains(&n) => Ok(n),
                _ => Err(format!("Invalid value for {group}.{key}: '{v}' (allowed {min} to {max}).")),
            },
        }
    }
}

fn parse_options(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect()
}

// ------------------------------------------------------------------ ossec.conf

/// The text of `home/etc/ossec.conf`.
pub fn read_conf(home: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(home.join("etc/ossec.conf"))
}

/// The text between `<tag>` (or `<tag attributes>`) and `</tag>`, first occurrence.
pub fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let mut from = 0;
    while let Some(p) = xml[from..].find(&open) {
        let at = from + p + open.len();
        match xml[at..].chars().next() {
            Some('>') | Some(' ') | Some('\t') | Some('\n') | Some('\r') => {
                let start = at + xml[at..].find('>')? + 1;
                let end = xml[start..].find(&format!("</{tag}>"))?;
                return Some(xml[start..start + end].trim());
            }
            _ => from = at,
        }
    }
    None
}

/// (single node, cluster worker) from `ossec.conf`: an enabled `<cluster>` makes the manager not
/// single; its `node_type` worker makes it a worker.
pub fn cluster_mode(xml: &str) -> (bool, bool) {
    match element(xml, "cluster") {
        None => (true, false),
        Some(c) => {
            let disabled = element(c, "disabled").is_some_and(|d| d == "yes");
            let worker = element(c, "node_type").is_some_and(|t| t == "worker");
            (disabled, !disabled && worker)
        }
    }
}

/// The cluster node name, when one is set.
pub fn node_name(xml: &str) -> Option<String> {
    element(element(xml, "cluster")?, "node_name").map(str::to_string)
}

/// `1d`, `12h`, `30m`, `45s`, `1w` or plain seconds; None for anything else or zero.
pub fn seconds(v: &str) -> Option<i64> {
    let v = v.trim();
    let (n, unit) = v.split_at(v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len()));
    let n: i64 = n.parse().ok()?;
    let k = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => return None,
    };
    (n > 0).then_some(n * k)
}

// ------------------------------------------------------------------ PID file

/// Writes `home/var/run/<name>-<pid>.pid`; its path.
pub fn create_pid(home: &Path, name: &str) -> std::io::Result<PathBuf> {
    let pid = std::process::id();
    let dir = home.join("var/run");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{name}-{pid}.pid"));
    std::fs::write(&path, format!("{pid}\n"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers() {
        let o = Options(parse_options("# c\na.b=5\n a.c = x \nbad\n").into_iter().collect());
        assert_eq!(o.int("a", "b", 1, 0, 9), Ok(5));
        assert_eq!(o.int("a", "z", 1, 0, 9), Ok(1));
        assert!(o.int("a", "c", 1, 0, 9).unwrap_err().contains("a.c"));
        assert_eq!(o.int("a", "b", 1, 6, 9).is_err(), true);
        let xml = "<ossec_config><cluster><node_name>n1</node_name><disabled>no</disabled><node_type>worker</node_type></cluster>\
                   <wdb><backup database=\"global\"><enabled>no</enabled></backup></wdb><clusterx>z</clusterx></ossec_config>";
        assert_eq!(node_name(xml).as_deref(), Some("n1"));
        assert_eq!(cluster_mode(xml), (false, true));
        assert_eq!(cluster_mode("<ossec_config/>"), (true, false));
        assert_eq!(element(xml, "backup"), Some("<enabled>no</enabled>"));
        assert_eq!(element(xml, "clusterx"), Some("z"));
        assert_eq!((seconds("1d"), seconds("90"), seconds("0"), seconds("5x")), (Some(86400), Some(90), None, None));
    }
}
