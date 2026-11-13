//! Log files and command output (`localfiles` in `provigil-agent.json`): every new line of a
//! log file, and the output of periodic commands, goes to the manager through the buffer.
//!
//! Files are followed on one thread (a pass every second); each command runs on its own thread.
//! Read positions survive restarts in `data\file_positions.json`.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::buffer::EventBuffer;
use crate::config::LocalFile;

/// A line is cut at this many bytes.
const MAX_LINE: usize = 65_000;
/// Lines read from one file in one pass at most (the rest on the next pass).
const MAX_LINES_PER_PASS: usize = 10_000;
/// Bytes at the start of a file whose hash tells that the file was replaced.
const HEAD: usize = 1024;
/// Bytes read at once.
const CHUNK: usize = 1 << 20;
/// An unfinished last line is sent when the file has not grown for this long.
const IDLE_FLUSH: Duration = Duration::from_secs(5);
/// Wildcard locations are expanded again this often.
const EXPAND_EVERY: Duration = Duration::from_secs(60);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const FIRST_COMMAND_AFTER: Duration = Duration::from_secs(10);

/// Starts the log file thread and one thread per command (nothing when nothing is configured).
pub fn spawn(entries: &[LocalFile], positions: PathBuf, buffer: Arc<EventBuffer>, agent: Value, running: fn() -> bool) -> Vec<std::thread::JoinHandle<()>> {
    let (sources, commands) = split(entries);
    let mut threads = Vec::new();
    if !sources.is_empty() {
        let mut files = FileCollector::new(sources, positions);
        let (buffer, agent) = (buffer.clone(), agent.clone());
        let started = crate::thread("logfiles".into(), move || {
            while running() {
                for (location, message, labels) in files.pass(Instant::now()) {
                    let mut e = event("logfile", &location, &message, &agent);
                    if !labels.is_empty() {
                        e["labels"] = json!(labels);
                    }
                    buffer.push(e);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        match started {
            Ok(t) => threads.push(t),
            Err(e) => error!(error = %e, "Log file thread not started"),
        }
    }
    for job in commands {
        let (buffer, agent) = (buffer.clone(), agent.clone());
        let name = format!("command {}", job.label);
        match crate::thread(name, move || job.run(&buffer, &agent, running)) {
            Ok(t) => threads.push(t),
            Err(e) => error!(error = %e, "Command thread not started"),
        }
    }
    threads
}

pub(crate) fn event(kind: &str, location: &str, message: &str, agent: &Value) -> Value {
    json!({
        "event_type": kind,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "agent": agent,
        "location": location,
        "message": message,
    })
}

// ---------------------------------------------------------------- configuration

enum Format {
    Plain,
    Json,
    Lines(usize),
    Regex(RegexJoin),
    /// Blocks of lines separated by an empty line.
    Block,
    Command,
    FullCommand,
}

struct RegexJoin {
    re: Regex,
    mode: Mode,
    sep: &'static str,
    timeout: Duration,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Start,
    End,
    All,
}

fn parse_format(e: &LocalFile) -> Result<Format, String> {
    let f = e.log_format.trim().to_ascii_lowercase();
    Ok(match f.as_str() {
        "syslog" | "iis" | "apache" | "squid" | "snort-fast" | "nmapg" | "mysql_log" | "djb-multilog" | "audit" => Format::Plain,
        "json" => Format::Json,
        // an entry starts with its `yyyy-mm-dd hh:mm:ss` time; the lines after it belong to it
        "mssql_log" => Format::Regex(RegexJoin { re: Regex::new(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").expect("valid"), mode: Mode::Start, sep: " ", timeout: IDLE_FLUSH }),
        // lines starting with a tab continue the entry
        "postgresql_log" => Format::Regex(RegexJoin { re: Regex::new(r"^[^\t]").expect("valid"), mode: Mode::Start, sep: "", timeout: IDLE_FLUSH }),
        "snort-full" => Format::Block,
        "command" => Format::Command,
        "full_command" => Format::FullCommand,
        "multi-line-regex" => {
            let m = e.multiline_regex.as_ref().ok_or("multi-line-regex without multiline_regex")?;
            let re = Regex::new(&m.regex).map_err(|err| format!("multiline_regex.regex: {err}"))?;
            let mode = match m.match_at.as_str() {
                "start" => Mode::Start,
                "end" => Mode::End,
                "all" => Mode::All,
                o => return Err(format!("multiline_regex.match '{o}' unknown")),
            };
            let sep = match m.replace.as_str() {
                "no-replace" => "\n",
                "none" => "",
                "wspace" => " ",
                "tab" => "\t",
                o => return Err(format!("multiline_regex.replace '{o}' unknown")),
            };
            Format::Regex(RegexJoin { re, mode, sep, timeout: Duration::from_secs(m.timeout) })
        }
        _ => match f.strip_prefix("multi-line:").and_then(|n| n.trim().parse::<usize>().ok()) {
            Some(n) if n > 0 => Format::Lines(n),
            _ => return Err(format!("log_format '{}' unknown", e.log_format)),
        },
    })
}

/// `ignore` / `restrict`; an invalid expression is left out with a warning.
struct Filters {
    ignore: Vec<Regex>,
    restrict: Vec<Regex>,
}

impl Filters {
    fn new(e: &LocalFile) -> Self {
        let compile = |list: &[String]| {
            list.iter()
                .filter_map(|r| Regex::new(r).map_err(|err| warn!(regex = %r, error = %err, "Invalid ignore/restrict expression: not used")).ok())
                .collect()
        };
        Self { ignore: compile(&e.ignore), restrict: compile(&e.restrict) }
    }

    fn keep(&self, s: &str) -> bool {
        !self.ignore.iter().any(|r| r.is_match(s)) && (self.restrict.is_empty() || self.restrict.iter().any(|r| r.is_match(s)))
    }
}

/// `1d`, `12h`, `30m`, `90s` (a bare number is seconds; `w` weeks).
fn parse_age(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let mult = match unit.trim() {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    Some(Duration::from_secs(num.parse::<u64>().ok()?.checked_mul(mult)?))
}

/// The file entries and the command entries; an unusable entry is left out with a warning.
fn split(entries: &[LocalFile]) -> (Vec<Source>, Vec<CommandJob>) {
    let (mut sources, mut commands) = (Vec::new(), Vec::new());
    for e in entries {
        let format = match parse_format(e) {
            Ok(f) => f,
            Err(err) => {
                warn!(location = %e.location, error = %err, "Log file entry not used");
                continue;
            }
        };
        let filters = Filters::new(e);
        match format {
            Format::Command | Format::FullCommand => {
                if e.command.trim().is_empty() {
                    warn!(alias = %e.alias, "Command entry without a command: not used");
                    continue;
                }
                commands.push(CommandJob {
                    label: if e.alias.is_empty() { e.command.clone() } else { e.alias.clone() },
                    command: e.command.clone(),
                    full: matches!(format, Format::FullCommand),
                    every: Duration::from_secs(e.frequency.max(1)),
                    filters,
                });
            }
            format => {
                if e.location.trim().is_empty() {
                    warn!(log_format = %e.log_format, "Log file entry without a location: not used");
                    continue;
                }
                let age = e.age.as_deref().and_then(|a| {
                    parse_age(a).or_else(|| {
                        warn!(location = %e.location, age = %a, "Invalid age: not used");
                        None
                    })
                });
                sources.push(Source {
                    pattern: PathBuf::from(env_expanded(&e.location)),
                    wild: e.location.contains(['*', '?']),
                    exclude: e.exclude.clone(),
                    only_future: e.only_future_events,
                    opts: ReadOpts { format, filters, age, ignore_binaries: e.ignore_binaries, max_size: e.max_size, labels: e.labels.clone() },
                    files: HashMap::new(),
                    listed: Vec::new(),
                    expanded_at: None,
                    started: false,
                });
            }
        }
    }
    (sources, commands)
}

// ---------------------------------------------------------------- files

struct Source {
    pattern: PathBuf,
    wild: bool,
    exclude: Option<String>,
    only_future: bool,
    opts: ReadOpts,
    files: HashMap<PathBuf, Tracked>,
    listed: Vec<PathBuf>,
    expanded_at: Option<Instant>,
    /// The first pass is done: files found from now on are new, read from their start.
    started: bool,
}

struct ReadOpts {
    format: Format,
    filters: Filters,
    age: Option<Duration>,
    ignore_binaries: bool,
    /// A file read from its start begins at its last `max_size` bytes.
    max_size: Option<u64>,
    /// Added to each event of the entry.
    labels: BTreeMap<String, String>,
}

/// A followed file.
struct Tracked {
    offset: u64,
    size: u64,
    head_len: usize,
    hash: String,
    grew_at: Instant,
    /// The start of an over-long line was sent: the rest up to its LF is discarded.
    skip_to_lf: bool,
    binary: bool,
    joiner: Joiner,
}

/// A file's saved read position (`data\file_positions.json`).
#[derive(Clone, Serialize, Deserialize)]
struct Position {
    path: String,
    offset: u64,
    size: u64,
    /// How many of the first bytes `hash` covers (up to 1 KiB).
    head_len: usize,
    hash: String,
}

fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

fn read_head(f: &mut File, len: u64) -> Vec<u8> {
    let mut head = Vec::new();
    if f.seek(SeekFrom::Start(0)).is_ok() {
        let _ = f.take(len.min(HEAD as u64)).read_to_end(&mut head);
    }
    head
}

#[derive(Clone, Copy, PartialEq)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    /// The encoding the first bytes show, and where the text starts (after the byte order mark).
    fn of(head: &[u8]) -> (Self, u64) {
        match head {
            [0xFF, 0xFE, ..] => (Self::Utf16Le, 2),
            [0xFE, 0xFF, ..] => (Self::Utf16Be, 2),
            [0xEF, 0xBB, 0xBF, ..] => (Self::Utf8, 3),
            _ => (Self::Utf8, 0),
        }
    }

    fn unit(self) -> usize {
        if self == Self::Utf8 { 1 } else { 2 }
    }

    /// Where the next LF is in `buf` (which starts on a character unit).
    fn find_lf(self, buf: &[u8]) -> Option<usize> {
        match self {
            Self::Utf8 => buf.iter().position(|&b| b == b'\n'),
            Self::Utf16Le => buf.as_chunks::<2>().0.iter().position(|u| *u == [b'\n', 0]).map(|i| i * 2),
            Self::Utf16Be => buf.as_chunks::<2>().0.iter().position(|u| *u == [0, b'\n']).map(|i| i * 2),
        }
    }

    fn decode(self, raw: &[u8]) -> String {
        let units = |f: fn([u8; 2]) -> u16| raw.as_chunks::<2>().0.iter().map(|&u| f(u)).collect::<Vec<u16>>();
        match self {
            Self::Utf8 => String::from_utf8_lossy(raw).into_owned(),
            Self::Utf16Le => String::from_utf16_lossy(&units(u16::from_le_bytes)),
            Self::Utf16Be => String::from_utf16_lossy(&units(u16::from_be_bytes)),
        }
    }
}

/// Joins lines into messages as the format says.
#[derive(Default)]
struct Joiner {
    text: String,
    count: usize,
    last: Option<Instant>,
}

impl Joiner {
    fn push(&mut self, format: &Format, line: String, now: Instant, out: &mut Vec<String>) {
        match format {
            Format::Json => {
                if serde_json::from_str::<serde::de::IgnoredAny>(&line).is_ok() {
                    out.push(line);
                } else {
                    debug!(line = %line, "Not one JSON value: dropped");
                }
            }
            Format::Lines(n) => {
                self.add(&line, " ");
                if self.count >= *n {
                    out.push(self.take());
                }
            }
            Format::Regex(r) => {
                match r.mode {
                    Mode::Start => {
                        if self.count > 0 && r.re.is_match(&line) {
                            out.push(self.take());
                        }
                        self.add(&line, r.sep);
                    }
                    Mode::End => {
                        self.add(&line, r.sep);
                        if r.re.is_match(&line) {
                            out.push(self.take());
                        }
                    }
                    Mode::All => {
                        self.add(&line, r.sep);
                        if r.re.is_match(&self.text) {
                            out.push(self.take());
                        }
                    }
                }
                self.last = Some(now);
            }
            Format::Block => {
                self.add(&line, " ");
                self.last = Some(now);
            }
            _ => out.push(line),
        }
    }

    fn add(&mut self, line: &str, sep: &str) {
        if self.count > 0 {
            self.text.push_str(sep);
        }
        self.text.push_str(line);
        self.count += 1;
    }

    fn take(&mut self) -> String {
        self.count = 0;
        std::mem::take(&mut self.text)
    }

    /// A joined message without new lines for its timeout.
    fn due(&mut self, format: &Format, now: Instant) -> Option<String> {
        let timeout = match format {
            Format::Regex(r) => r.timeout,
            Format::Block => IDLE_FLUSH,
            _ => return None,
        };
        (self.count > 0 && self.last.is_some_and(|t| now.duration_since(t) >= timeout)).then(|| self.take())
    }
}

/// `*` any run of characters, `?` one character; case-insensitive on Windows.
fn wild_match(pattern: &str, name: &str) -> bool {
    let fold = |s: &str| -> Vec<char> { if cfg!(windows) { s.to_lowercase().chars().collect() } else { s.chars().collect() } };
    let (p, n) = (fold(pattern), fold(name));
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// The files a location names now; `exclude` is matched against the file name and the full path.
fn expand(pattern: &Path, wild: bool, exclude: Option<&str>) -> Vec<PathBuf> {
    if !wild {
        return if pattern.is_file() { vec![pattern.to_path_buf()] } else { Vec::new() };
    }
    let mut found = vec![PathBuf::new()];
    for part in pattern.components() {
        let name = part.as_os_str().to_string_lossy();
        if name.contains(['*', '?']) {
            found = found
                .iter()
                .flat_map(|dir| {
                    let d = if dir.as_os_str().is_empty() { Path::new(".") } else { dir.as_path() };
                    fs::read_dir(d)
                        .into_iter()
                        .flatten()
                        .flatten()
                        .filter(|e| wild_match(&name, &e.file_name().to_string_lossy()))
                        .map(|e| e.path())
                        .collect::<Vec<_>>()
                })
                .collect();
        } else {
            found.iter_mut().for_each(|p| p.push(part));
        }
    }
    let excluded = |p: &Path| {
        exclude.is_some_and(|x| wild_match(x, &p.to_string_lossy()) || p.file_name().is_some_and(|n| wild_match(x, &n.to_string_lossy())))
    };
    found.retain(|p| p.is_file() && !excluded(p));
    found.sort();
    found
}

/// `%NAME%` replaced by the environment variable's value (kept as written when not set).
fn env_expanded(s: &str) -> String {
    let (mut out, mut rest) = (String::new(), s);
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%').filter(|&j| j > 0).and_then(|j| std::env::var(&after[..j]).ok().map(|v| (j, v))) {
            Some((j, v)) => {
                out.push_str(&v);
                rest = &after[j + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out + rest
}

/// `%Y`, `%y`, `%m`, `%d` and `%H` replaced by the date and hour of `t`; other text kept.
fn dated(s: &str, t: &chrono::DateTime<chrono::Local>) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match chars.peek().copied().filter(|n| c == '%' && matches!(n, 'Y' | 'y' | 'm' | 'd' | 'H')) {
            Some(n) => {
                out.push_str(&t.format(&format!("%{n}")).to_string());
                chars.next();
            }
            None => out.push(c),
        }
    }
    out
}

/// Starts following a file: from its saved position when the file is still the same, from its
/// start (see `max_size`) when it was replaced or is new, from its end when `from_end`.
fn start(path: &Path, saved: Option<&Position>, from_end: bool, now: Instant, max_size: Option<u64>) -> Option<Tracked> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let head = read_head(&mut f, len);
    let offset = match saved {
        Some(p) if p.offset <= len && head.len() >= p.head_len && hash(&head[..p.head_len]) == p.hash => p.offset,
        Some(_) => 0,
        None if from_end => len,
        None => 0,
    };
    let mut t = Tracked { offset, size: len, head_len: head.len(), hash: hash(&head), grew_at: now, skip_to_lf: false, binary: false, joiner: Joiner::default() };
    if offset == 0 {
        skip_to_last(&mut f, &mut t, len, max_size);
    }
    Some(t)
}

/// `max_size`: a file read from its start begins at its last `max` bytes, at the next line.
fn skip_to_last(f: &mut File, t: &mut Tracked, len: u64, max: Option<u64>) {
    let Some(max) = max.filter(|&m| len.saturating_sub(t.offset) > m) else { return };
    // even: a UTF-16 file stays on a character boundary
    t.offset = len - (max & !1);
    let mut prev = [0u8];
    t.skip_to_lf = f.seek(SeekFrom::Start(t.offset - 1)).is_ok() && f.read_exact(&mut prev).is_ok() && prev[0] != b'\n';
}

/// One line as read: decoded, CR removed, dropped or cut as the rules say, then joined.
fn feed(joiner: &mut Joiner, raw: &[u8], enc: Encoding, path: &Path, format: &Format, now: Instant, out: &mut Vec<String>) {
    let mut s = enc.decode(raw);
    if s.ends_with('\r') {
        s.pop();
    }
    if s.is_empty() && matches!(format, Format::Block) {
        out.extend((joiner.count > 0).then(|| joiner.take()));
        return;
    }
    if s.is_empty() || s.contains('\0') || (cfg!(windows) && s.starts_with('#')) {
        return;
    }
    if s.len() > MAX_LINE {
        warn!(file = %path.display(), "Line longer than 65000 bytes: cut, the rest discarded");
        let mut n = MAX_LINE;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
    joiner.push(format, s, now, out);
}

/// The new messages of a file since the last pass.
fn read(t: &mut Tracked, path: &Path, o: &ReadOpts, now: Instant) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(mut f) = File::open(path) else { return out };
    let Ok(meta) = f.metadata() else { return out };
    if o.age.is_some_and(|age| meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|d| d > age)) {
        return out;
    }
    let len = meta.len();
    let head = read_head(&mut f, len);
    let same_start = head.len() >= t.head_len && hash(&head[..t.head_len]) == t.hash;
    // the manager's rules key on these texts
    let notice = if len < t.offset {
        Some(format!("ProVigil logcollector: File size reduced (inode remained): '{}'.", path.display()))
    } else if !same_start {
        Some(format!("ProVigil logcollector: File rotated (inode changed): '{}'.", path.display()))
    } else {
        None
    };
    if notice.is_some() {
        info!(file = %path.display(), "File truncated or replaced: reading it again from the start");
        t.offset = 0;
        t.skip_to_lf = false;
        t.binary = false;
        t.joiner = Joiner::default();
        skip_to_last(&mut f, t, len, o.max_size);
    }
    t.head_len = head.len();
    t.hash = hash(&head);
    if len != t.size {
        t.size = len;
        t.grew_at = now;
    }
    let (enc, text_start) = Encoding::of(&head);
    if o.ignore_binaries && enc == Encoding::Utf8 && head.contains(&0) {
        if !t.binary {
            info!(file = %path.display(), "File looks binary: skipped");
            t.binary = true;
        }
        return out;
    }
    t.offset = t.offset.max(text_start);

    let unit = enc.unit();
    let mut lines = 0;
    while lines < MAX_LINES_PER_PASS {
        let mut buf = Vec::new();
        if f.seek(SeekFrom::Start(t.offset)).is_err() || (&mut f).take(CHUNK as u64).read_to_end(&mut buf).is_err() || buf.is_empty() {
            break;
        }
        let mut used = 0;
        while lines < MAX_LINES_PER_PASS {
            let Some(end) = enc.find_lf(&buf[used..]) else { break };
            let raw = &buf[used..used + end];
            used += end + unit;
            lines += 1;
            if !std::mem::take(&mut t.skip_to_lf) {
                feed(&mut t.joiner, raw, enc, path, &o.format, now, &mut out);
            }
        }
        t.offset += used as u64;
        if lines >= MAX_LINES_PER_PASS {
            break;
        }
        let tail = &buf[used..];
        let whole = tail.len() / unit * unit;
        if tail.len() > MAX_LINE * unit {
            // too long to wait for its LF: its start now, the rest discarded up to the LF
            if !t.skip_to_lf {
                feed(&mut t.joiner, &tail[..whole], enc, path, &o.format, now, &mut out);
                t.skip_to_lf = true;
            }
            t.offset += whole as u64;
            lines += 1;
        } else if buf.len() < CHUNK {
            if whole > 0 && now.duration_since(t.grew_at) >= IDLE_FLUSH {
                if !std::mem::take(&mut t.skip_to_lf) {
                    feed(&mut t.joiner, &tail[..whole], enc, path, &o.format, now, &mut out);
                }
                t.offset += whole as u64;
            }
            break;
        }
    }
    out.extend(t.joiner.due(&o.format, now));
    out.retain(|m| o.filters.keep(m));
    if let Some(n) = notice {
        out.insert(0, n);
    }
    out
}

/// Follows the log files of every file entry.
pub(crate) struct FileCollector {
    sources: Vec<Source>,
    positions: PathBuf,
    /// Saved positions of files not followed yet.
    saved: HashMap<String, Position>,
    last_saved: String,
}

impl FileCollector {
    fn new(sources: Vec<Source>, positions: PathBuf) -> Self {
        let saved = fs::read_to_string(&positions)
            .ok()
            .and_then(|t| serde_json::from_str::<Vec<Position>>(&t).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|p| (p.path.clone(), p))
            .collect();
        Self { sources, positions, saved, last_saved: String::new() }
    }

    /// The collector of the file entries among `entries`.
    pub(crate) fn for_entries(entries: &[LocalFile], positions: PathBuf) -> Self {
        Self::new(split(entries).0, positions)
    }

    /// One read pass over every file: (location, message, labels) of each message to send.
    /// Positions are saved after it.
    pub(crate) fn pass(&mut self, now: Instant) -> Vec<(String, String, BTreeMap<String, String>)> {
        let mut out = Vec::new();
        for src in &mut self.sources {
            if !src.wild || src.expanded_at.is_none_or(|t| now.duration_since(t) >= EXPAND_EVERY) {
                let pattern = PathBuf::from(dated(&src.pattern.to_string_lossy(), &chrono::Local::now()));
                src.listed = expand(&pattern, src.wild, src.exclude.as_deref());
                src.expanded_at = Some(now);
                src.files.retain(|p, _| src.listed.contains(p));
            }
            for path in &src.listed {
                let key = path.to_string_lossy().into_owned();
                if !src.files.contains_key(path) {
                    let Some(t) = start(path, self.saved.get(&key), src.only_future && !src.started, now, src.opts.max_size) else { continue };
                    self.saved.remove(&key);
                    src.files.insert(path.clone(), t);
                }
                let Some(t) = src.files.get_mut(path) else { continue };
                out.extend(read(t, path, &src.opts, now).into_iter().map(|m| (key.clone(), m, src.opts.labels.clone())));
            }
            src.started = true;
        }
        self.save();
        out
    }

    fn save(&mut self) {
        let mut list: Vec<Position> = self
            .sources
            .iter()
            .flat_map(|s| s.files.iter())
            .map(|(p, t)| Position { path: p.to_string_lossy().into_owned(), offset: t.offset, size: t.size, head_len: t.head_len, hash: t.hash.clone() })
            .chain(self.saved.values().cloned())
            .collect();
        list.sort_by(|a, b| a.path.cmp(&b.path));
        let Ok(text) = serde_json::to_string_pretty(&list) else { return };
        if text == self.last_saved {
            return;
        }
        if let Some(dir) = self.positions.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let tmp = self.positions.with_extension("json.tmp");
        match fs::write(&tmp, &text).and_then(|()| fs::rename(&tmp, &self.positions)) {
            Ok(()) => self.last_saved = text,
            Err(e) => warn!(error = %e, "File positions not saved"),
        }
    }
}

// ---------------------------------------------------------------- commands

struct CommandJob {
    label: String,
    command: String,
    full: bool,
    every: Duration,
    filters: Filters,
}

impl CommandJob {
    fn run(self, buffer: &EventBuffer, agent: &Value, running: fn() -> bool) {
        let mut next = Instant::now() + FIRST_COMMAND_AFTER;
        loop {
            while Instant::now() < next {
                if !running() {
                    return;
                }
                std::thread::sleep(next.saturating_duration_since(Instant::now()).min(Duration::from_secs(1)));
            }
            if !running() {
                return;
            }
            next = Instant::now() + self.every;
            match run_command(&self.command, COMMAND_TIMEOUT, running) {
                Err(e) => {
                    error!(command = %self.command, error = %e, "Command could not be started: not run again until the agent restarts");
                    return;
                }
                Ok(None) => warn!(command = %self.command, "Command ran longer than 60 s: ended"),
                Ok(Some(output)) => {
                    for m in command_messages(self.full, &self.label, &output, &self.filters) {
                        buffer.push(event("command", &self.label, &m, agent));
                    }
                }
            }
        }
    }
}

/// Runs a command through the shell, without a console window or input: its standard output,
/// `None` when it ran longer than `timeout` or the agent stopped (its process tree is then
/// ended). `Err` when it could not start.
fn run_command(command: &str, timeout: Duration, running: fn() -> bool) -> std::io::Result<Option<String>> {
    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut c = Command::new("cmd");
        // /S: cmd removes only the outer quotes, so the command keeps its own quotes
        c.raw_arg(format!("/S /C \"{command}\"")).creation_flags(CREATE_NO_WINDOW);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.read_to_end(&mut b);
        let _ = tx.send(b);
    });
    let end = Instant::now() + timeout;
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(b) => {
                let _ = child.wait();
                return Ok(Some(String::from_utf8_lossy(&b).into_owned()));
            }
            Err(mpsc::RecvTimeoutError::Timeout) if running() && Instant::now() < end => {}
            Err(_) => {
                crate::commands::kill_tree(&mut child);
                return Ok(None);
            }
        }
    }
}

/// `command`: one message per output line; `full_command`: one message for the whole output.
fn command_messages(full: bool, label: &str, output: &str, filters: &Filters) -> Vec<String> {
    if full {
        let mut body = output.replace('\r', "").replace("\n\n", "\n");
        if body.ends_with('\n') {
            body.pop();
        }
        if body.is_empty() || !filters.keep(&body) {
            return Vec::new();
        }
        return vec![format!("ossec: output: '{label}':\n{body}")];
    }
    output
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !l.is_empty() && filters.keep(l))
        .map(|l| format!("ossec: output: '{label}': {l}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MultilineRegex;
    use std::io::Write;
    use std::time::SystemTime;

    fn entry(path: &Path, format: &str) -> LocalFile {
        LocalFile { location: path.to_string_lossy().into_owned(), log_format: format.into(), only_future_events: false, ..Default::default() }
    }

    fn collector(dir: &Path, entries: &[LocalFile]) -> FileCollector {
        FileCollector::new(split(entries).0, dir.join("file_positions.json"))
    }

    fn msgs(c: &mut FileCollector, now: Instant) -> Vec<String> {
        c.pass(now).into_iter().map(|(_, m, _)| m).collect()
    }

    fn append(p: &Path, b: &[u8]) {
        fs::OpenOptions::new().create(true).append(true).open(p).unwrap().write_all(b).unwrap();
    }

    #[test]
    fn line_splitting() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("app.log");
        let long = "x".repeat(70_000);
        fs::write(&p, format!("one\r\n\r\n\n#Fields: a b\nbad\0line\ntwo\n{long}\ntail")).unwrap();
        let mut c = collector(dir.path(), &[entry(&p, "syslog")]);
        let t0 = Instant::now();
        let got = msgs(&mut c, t0);
        let mut want = vec!["one".to_string()];
        if !cfg!(windows) {
            want.push("#Fields: a b".into());
        }
        want.extend(["two".to_string(), "x".repeat(65_000)]);
        assert_eq!(got, want);
        // the unfinished last line waits until the file has not grown for 5 s
        assert!(msgs(&mut c, t0 + Duration::from_secs(1)).is_empty());
        assert_eq!(msgs(&mut c, t0 + Duration::from_secs(6)), ["tail"]);

        // an over-long line still without its LF: its start now, the rest up to the LF dropped
        append(&p, format!("\n{}", "y".repeat(70_000)).as_bytes());
        let t1 = t0 + Duration::from_secs(7);
        assert_eq!(msgs(&mut c, t1), ["y".repeat(65_000)]);
        append(&p, b"zzz\nnext\n");
        assert_eq!(msgs(&mut c, t1), ["next"]);
    }

    #[test]
    fn at_most_10000_lines_per_pass() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("busy.log");
        fs::write(&p, "l\n".repeat(10_005)).unwrap();
        let mut c = collector(dir.path(), &[entry(&p, "syslog")]);
        let now = Instant::now();
        assert_eq!(msgs(&mut c, now).len(), 10_000);
        assert_eq!(msgs(&mut c, now).len(), 5);
    }

    #[test]
    fn rotation_and_positions_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("app.log");
        fs::write(&p, "one\ntwo\n").unwrap();
        let now = Instant::now();
        let mut c = collector(dir.path(), &[entry(&p, "syslog")]);
        assert_eq!(msgs(&mut c, now), ["one", "two"]);
        // shorter: read again from the start
        fs::write(&p, "x\n").unwrap();
        let shown = p.display();
        assert_eq!(msgs(&mut c, now), [format!("ProVigil logcollector: File size reduced (inode remained): '{shown}'."), "x".into()]);
        // longer, but its first bytes replaced
        fs::write(&p, "new first\nsecond\n").unwrap();
        assert_eq!(msgs(&mut c, now), [format!("ProVigil logcollector: File rotated (inode changed): '{shown}'."), "new first".into(), "second".into()]);
        // restart: the saved position is used (even with only_future_events)
        drop(c);
        append(&p, b"third\n");
        let mut e = entry(&p, "syslog");
        e.only_future_events = true;
        let mut c = collector(dir.path(), &[e.clone()]);
        assert_eq!(msgs(&mut c, now), ["third"]);
        // replaced while the agent was stopped: from the start
        drop(c);
        fs::write(&p, "other content\n").unwrap();
        let mut c = collector(dir.path(), &[e]);
        assert_eq!(msgs(&mut c, now), ["other content"]);
    }

    #[test]
    fn only_future_events_reads_from_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("app.log");
        fs::write(&p, "old\n").unwrap();
        let mut e = entry(&p, "syslog");
        e.only_future_events = true;
        let mut c = collector(dir.path(), &[e]);
        let now = Instant::now();
        assert!(msgs(&mut c, now).is_empty());
        append(&p, b"new\n");
        assert_eq!(msgs(&mut c, now), ["new"]);
    }

    #[test]
    fn wildcards_exclude_and_age() {
        let dir = tempfile::tempdir().unwrap();
        for (sub, file, line) in [("W3SVC1", "a.log", "a"), ("W3SVC2", "b.log", "b"), ("W3SVC2", "skip.log", "s"), ("Other", "c.log", "c"), ("W3SVC2", "d.txt", "d")] {
            fs::create_dir_all(dir.path().join(sub)).unwrap();
            fs::write(dir.path().join(sub).join(file), format!("{line}\n")).unwrap();
        }
        let mut e = entry(&dir.path().join("W3SVC*").join("*.log"), "iis");
        e.exclude = Some("skip*".into());
        let mut c = collector(dir.path(), &[e.clone()]);
        let mut got = c.pass(Instant::now());
        got.sort();
        assert_eq!(got.len(), 2);
        assert_eq!((&got[0].0, got[0].1.as_str()), (&dir.path().join("W3SVC1").join("a.log").to_string_lossy().into_owned(), "a"));
        assert_eq!(got[1].1, "b");

        // age: a file not modified for two days is skipped with age 1d
        let old = dir.path().join("W3SVC2").join("b.log");
        File::options().write(true).open(&old).unwrap().set_modified(SystemTime::now() - Duration::from_secs(2 * 86_400)).unwrap();
        e.age = Some("1d".into());
        let d2 = tempfile::tempdir().unwrap();
        let mut c = collector(d2.path(), &[e]);
        assert_eq!(msgs(&mut c, Instant::now()), ["a"]);
        assert_eq!(parse_age("12h"), Some(Duration::from_secs(43_200)));
        assert_eq!(parse_age("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_age("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_age("1y"), None);
    }

    #[test]
    fn utf16_le_with_bom() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("u16.log");
        let mut b = vec![0xFF, 0xFE];
        b.extend("héllo\r\nwörld\r\n".encode_utf16().flat_map(u16::to_le_bytes));
        fs::write(&p, b).unwrap();
        let mut c = collector(dir.path(), &[entry(&p, "syslog")]);
        assert_eq!(msgs(&mut c, Instant::now()), ["héllo", "wörld"]);
        // UTF-8 byte order mark skipped
        let p8 = dir.path().join("u8.log");
        fs::write(&p8, b"\xEF\xBB\xBFfirst\n").unwrap();
        let mut c = collector(dir.path(), &[entry(&p8, "syslog")]);
        assert_eq!(msgs(&mut c, Instant::now()), ["first"]);
    }

    fn read_all(format: LocalFile, content: &str, dir: &Path) -> (FileCollector, Vec<String>, Instant) {
        fs::write(dir.join("f.log"), content).unwrap();
        let mut c = collector(dir, &[LocalFile { location: dir.join("f.log").to_string_lossy().into_owned(), ..format }]);
        let now = Instant::now();
        let got = msgs(&mut c, now);
        (c, got, now)
    }

    fn fmt(f: &str, regex: Option<(&str, &str, &str)>) -> LocalFile {
        LocalFile {
            log_format: f.into(),
            only_future_events: false,
            multiline_regex: regex.map(|(r, m, rep)| MultilineRegex { regex: r.into(), match_at: m.into(), replace: rep.into(), timeout: 5 }),
            ..Default::default()
        }
    }

    #[test]
    fn json_and_multi_line() {
        let dir = tempfile::tempdir().unwrap();
        let (_, got, _) = read_all(fmt("json", None), "{\"a\":1}\nnot json\n[1,2]\n", dir.path());
        assert_eq!(got, ["{\"a\":1}", "[1,2]"]);

        let dir = tempfile::tempdir().unwrap();
        let (_, got, _) = read_all(fmt("multi-line:3", None), "a\nb\nc\nd\ne\nf\ng\n", dir.path());
        assert_eq!(got, ["a b c", "d e f"]);
    }

    #[test]
    fn multi_line_regex() {
        let dir = tempfile::tempdir().unwrap();
        let (mut c, got, now) = read_all(fmt("multi-line-regex", Some((r"^\d{4}", "start", "no-replace"))), "2026 a\n  x\n2026 b\n  y\n", dir.path());
        assert_eq!(got, ["2026 a\n  x"]);
        // the last message is sent after its timeout without new lines
        assert!(msgs(&mut c, now + Duration::from_secs(4)).is_empty());
        assert_eq!(msgs(&mut c, now + Duration::from_secs(6)), ["2026 b\n  y"]);

        let dir = tempfile::tempdir().unwrap();
        let (_, got, _) = read_all(fmt("multi-line-regex", Some((";$", "end", "wspace"))), "a\nb;\nc;\n", dir.path());
        assert_eq!(got, ["a b;", "c;"]);

        let dir = tempfile::tempdir().unwrap();
        let (_, got, _) = read_all(fmt("multi-line-regex", Some(("^BEGIN.*END$", "all", "tab"))), "BEGIN x\ny END\nBEGIN z END\n", dir.path());
        assert_eq!(got, ["BEGIN x\ty END", "BEGIN z END"]);

        let dir = tempfile::tempdir().unwrap();
        let (_, got, _) = read_all(fmt("multi-line-regex", Some(("^x", "start", "none"))), "xa\nb\nxc\n", dir.path());
        assert_eq!(got, ["xab"]);
    }

    #[test]
    fn mssql_postgresql_and_snort_full_entries() {
        let dir = tempfile::tempdir().unwrap();
        let text = "2026-11-04 10:00:01.12 Server  Starting\r\ncontinued a\r\ncontinued b\r\n2026-11-04 10:00:02.00 Logon  ok\r\n";
        let (mut c, got, now) = read_all(fmt("mssql_log", None), text, dir.path());
        assert_eq!(got, ["2026-11-04 10:00:01.12 Server  Starting continued a continued b"]);
        assert_eq!(msgs(&mut c, now + Duration::from_secs(6)), ["2026-11-04 10:00:02.00 Logon  ok"], "the last entry after 5 s without new lines");

        let dir = tempfile::tempdir().unwrap();
        let text = "2026-11-04 10:00:01 UTC LOG:  statement: select a\n\tfrom t\n\twhere b\n2026-11-04 10:00:02 UTC ERROR:  x\nplain line\n";
        let (mut c, got, now) = read_all(fmt("postgresql_log", None), text, dir.path());
        assert_eq!(got, ["2026-11-04 10:00:01 UTC LOG:  statement: select a\tfrom t\twhere b", "2026-11-04 10:00:02 UTC ERROR:  x"]);
        assert_eq!(msgs(&mut c, now + Duration::from_secs(6)), ["plain line"]);

        let dir = tempfile::tempdir().unwrap();
        let text = "[**] [1:1000:1] Ping [**]\n[Priority: 3]\n11/04-10:00:01 10.0.0.1 -> 10.0.0.2\n\n\n[**] [1:1001:1] Other [**]\nline 2\n";
        let (mut c, got, now) = read_all(fmt("snort-full", None), text, dir.path());
        assert_eq!(got, ["[**] [1:1000:1] Ping [**] [Priority: 3] 11/04-10:00:01 10.0.0.1 -> 10.0.0.2"]);
        assert_eq!(msgs(&mut c, now + Duration::from_secs(6)), ["[**] [1:1001:1] Other [**] line 2"]);
    }

    #[test]
    fn max_size_and_labels() {
        let text = "first line\nsecond line\nthird\n";
        for (max, want) in [(10, "third"), (6, "third"), (100, "first line")] {
            let dir = tempfile::tempdir().unwrap();
            let (_, got, _) = read_all(LocalFile { max_size: Some(max), ..fmt("syslog", None) }, text, dir.path());
            assert_eq!(got[0], want, "max_size {max}: from the next whole line");
        }

        let dir = tempfile::tempdir().unwrap();
        let labels = BTreeMap::from([("app".to_string(), "web".to_string())]);
        let (mut c, _, now) = read_all(LocalFile { max_size: Some(10), labels: labels.clone(), ..fmt("syslog", None) }, text, dir.path());
        let p = dir.path().join("f.log");
        append(&p, b"fourth\n");
        assert_eq!(c.pass(now), [(p.to_string_lossy().into_owned(), "fourth".to_string(), labels)]);
        // replaced: read from its start again, so its last bytes only
        fs::write(&p, "AAAAAAAAAAAAAAAAAAAA\nnew tail\n").unwrap();
        let got = msgs(&mut c, now);
        assert_eq!((got.len(), got[1].as_str()), (2, "new tail"), "{got:?}");
    }

    #[test]
    fn ignore_and_restrict() {
        let dir = tempfile::tempdir().unwrap();
        let f = LocalFile { restrict: vec!["^keep".into()], ignore: vec!["secret".into()], ..fmt("syslog", None) };
        let (_, got, _) = read_all(f, "keep 1\ndrop 2\nkeep secret\n", dir.path());
        assert_eq!(got, ["keep 1"]);
    }

    #[test]
    fn command_message_text() {
        let none = Filters { ignore: Vec::new(), restrict: Vec::new() };
        assert_eq!(command_messages(false, "list", "a\r\n\r\nb\r\n", &none), ["ossec: output: 'list': a", "ossec: output: 'list': b"]);
        assert_eq!(command_messages(true, "list", "a\r\n\r\nb\r\n", &none), ["ossec: output: 'list':\na\nb"]);
        assert!(command_messages(true, "list", "", &none).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn runs_a_command() {
        let out = run_command("echo a&echo b", Duration::from_secs(30), || true).unwrap().unwrap();
        let none = Filters { ignore: Vec::new(), restrict: Vec::new() };
        assert_eq!(command_messages(false, "echo a&echo b", &out, &none), ["ossec: output: 'echo a&echo b': a", "ossec: output: 'echo a&echo b': b"]);
        assert_eq!(command_messages(true, "echo a&echo b", &out, &none), ["ossec: output: 'echo a&echo b':\na\nb"]);
        // quotes in the command are kept
        let out = run_command("\"cmd\" /C echo \"q\"", Duration::from_secs(30), || true).unwrap().unwrap();
        assert_eq!(out.trim_end(), "\"q\"");
        // longer than the timeout: ended
        assert!(run_command("ping -n 5 127.0.0.1", Duration::from_secs(1), || true).unwrap().is_none());
        // the agent stopping ends it at once
        let t = std::time::Instant::now();
        assert!(run_command("ping -n 30 127.0.0.1", Duration::from_secs(60), || false).unwrap().is_none());
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn location_dates_and_environment() {
        use chrono::TimeZone;
        let t = chrono::Local.with_ymd_and_hms(2026, 3, 7, 9, 0, 0).unwrap();
        assert_eq!(dated(r"C:\logs\u_ex%y%m%d%H.log", &t), r"C:\logs\u_ex26030709.log");
        assert_eq!(dated("%Y-%m-%d %Q 100%", &t), "2026-03-07 %Q 100%");
        std::env::set_var("PROVIGIL_TEST_DIR", r"D:\app");
        assert_eq!(env_expanded(r"%PROVIGIL_TEST_DIR%\%Y%m%d.log"), r"D:\app\%Y%m%d.log");
        assert_eq!(env_expanded("%PROVIGIL_NOT_SET%x%"), "%PROVIGIL_NOT_SET%x%");
        // a dated location follows today's file
        let dir = tempfile::tempdir().unwrap();
        let today = chrono::Local::now().format("%Y%m%d").to_string();
        fs::write(dir.path().join(format!("app-{today}.log")), "now\n").unwrap();
        let mut c = collector(dir.path(), &[entry(&dir.path().join("app-%Y%m%d.log"), "syslog")]);
        assert_eq!(msgs(&mut c, Instant::now()), ["now"]);
    }

    #[test]
    fn wildcard_matching() {
        assert!(wild_match("W3SVC*", "W3SVC12"));
        assert!(wild_match("*.log", "u_ex.log"));
        assert!(wild_match("a?c", "abc"));
        assert!(!wild_match("*.log", "a.txt"));
        assert!(wild_match("*a*b", "xxaab"));
    }
}
