//! Logging through the host's logger, with the three tags of the scanner.

use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Debug,
    Debug2,
    Info,
    Warning,
    Error,
    /// The host exits after writing it.
    Critical,
}

pub const TAG_VS: &str = "provigil-modulesd:vulnerability-scanner";
pub const TAG_CU: &str = "provigil-modulesd:content-updater";
pub const TAG_IC: &str = "indexer-connector";
/// Lines the host writes with its own tag.
pub const TAG_HOST: &str = "";

/// The host's logger. `enabled` lets debug lines skip their formatting.
pub trait Logger: Send + Sync {
    fn log(&self, tag: &str, level: Level, msg: &str);
    fn enabled(&self, _level: Level) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct Log(pub Arc<dyn Logger>);

impl Log {
    pub fn new(l: Arc<dyn Logger>) -> Self {
        Log(l)
    }
    pub fn write(&self, tag: &str, level: Level, args: fmt::Arguments) {
        if self.0.enabled(level) {
            match args.as_str() {
                Some(s) => self.0.log(tag, level, s),
                None => self.0.log(tag, level, &args.to_string()),
            }
        }
    }
    pub fn null() -> Self {
        Log(Arc::new(NullLogger))
    }
}

macro_rules! vs {
    ($log:expr, $lvl:ident, $($arg:tt)*) => {
        $log.write($crate::log::TAG_VS, $crate::log::Level::$lvl, format_args!($($arg)*))
    };
}
macro_rules! cu {
    ($log:expr, $lvl:ident, $($arg:tt)*) => {
        $log.write($crate::log::TAG_CU, $crate::log::Level::$lvl, format_args!($($arg)*))
    };
}
macro_rules! ic {
    ($log:expr, $lvl:ident, $($arg:tt)*) => {
        $log.write($crate::log::TAG_IC, $crate::log::Level::$lvl, format_args!($($arg)*))
    };
}
macro_rules! host {
    ($log:expr, $lvl:ident, $($arg:tt)*) => {
        $log.write($crate::log::TAG_HOST, $crate::log::Level::$lvl, format_args!($($arg)*))
    };
}

pub struct NullLogger;
impl Logger for NullLogger {
    fn log(&self, _: &str, _: Level, _: &str) {}
    fn enabled(&self, _: Level) -> bool {
        false
    }
}

/// Keeps every line; used by tests and by hosts that want to inspect the output.
#[derive(Default)]
pub struct MemoryLogger(pub Mutex<Vec<(String, Level, String)>>);

impl Logger for MemoryLogger {
    fn log(&self, tag: &str, level: Level, msg: &str) {
        self.0.lock().unwrap().push((tag.to_string(), level, msg.to_string()));
    }
}

impl MemoryLogger {
    pub fn has(&self, level: Level, msg: &str) -> bool {
        self.0.lock().unwrap().iter().any(|(_, l, m)| *l == level && m == msg)
    }
    pub fn has_text(&self, part: &str) -> bool {
        self.0.lock().unwrap().iter().any(|(_, _, m)| m.contains(part))
    }
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().iter().map(|(_, _, m)| m.clone()).collect()
    }
}
