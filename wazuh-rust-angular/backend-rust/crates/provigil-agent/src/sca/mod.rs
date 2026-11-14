//! Configuration assessment (SCA): ProVigil's own YAML policies (`specs/agent-sca.md`), checked
//! against the registry, files, running processes, the local security policy and the audit
//! policy, and reported to the manager as a `check` message per check whose result changed and a
//! `summary` per policy, then a `policies` message per scan. Every check goes when nothing was sent
//! yet, for another agent id, when the policy text changed, or when the manager asks (`sca_full`:
//! its hash differs from the summary's; that send ends with `dump_end`, which drops other rows).
//!
//! Rule strings (`specs/agent-sca-full.md`): `[not ]<kind>:<target>[ -> <part>...]`, kinds `r:`
//! registry (`key`, `key -> value`, `key -> value -> <content>`), `f:` file (`path`,
//! `path -> <content>`), `d:` directory (`dir`, `dir -> <name regex>[ -> <content>]`, any depth),
//! `p:<content on a process name>`, `c:<command>[ -> <content>]` (`cmd /C`, 30 s, cached per scan),
//! `c:secedit-value:<name>[ -> <content>]` and `c:auditpol:<subcategory>[ -> <content>]`.
//! A content part is patterns joined by ` && ` that must all hold on one line: `r:<regex>`,
//! `!r:<regex>`, `n:<regex with one number group> compare <op> <number>` or a literal (numbers in
//! decimal or `0x` hex compare as numbers, text case-insensitively). Regexes are in the policy
//! dialect (see `regex`) and case-insensitive.
//! `$name` policy variables are put into targets; a comma list means any of several targets. A rule
//! that cannot be read (or has a bad regex) makes its check `not applicable` unless the other rules
//! already decide it.

use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::rootcheck::{expand, reg, running_processes, walk};
use crate::sent::Sent;

/// The policies compiled into the agent, one per line.
/// (the list and files are written by `specs/sca-manifest/build_policies.py`)
pub const BUILTIN: &[&str] = include!("policies/builtin.rs");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    All,
    Any,
    None,
}

impl Condition {
    fn as_str(self) -> &'static str {
        match self {
            Condition::All => "all",
            Condition::Any => "any",
            Condition::None => "none",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct PolicyInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, deserialize_with = "deserialize_references")]
    pub references: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Requirements {
    #[serde(default)]
    all: Vec<String>,
    #[serde(default)]
    any: Vec<String>,
    #[serde(default)]
    none: Vec<String>,
    condition: Option<Condition>,
    #[serde(default)]
    rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CheckDef {
    pub id: u32,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default, deserialize_with = "deserialize_references")]
    pub references: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_compliance")]
    pub compliance: BTreeMap<String, Vec<String>>,
    pub condition: Condition,
    pub rules: Vec<String>,
}

/// Accepts scalar string/map or a sequence of strings/unquoted YAML `Label: https://...` maps.
fn deserialize_references<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RefItem {
        Str(String),
        Map(BTreeMap<String, Option<String>>),
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RefField {
        One(RefItem),
        Many(Vec<RefItem>),
    }

    let Some(field) = Option::<RefField>::deserialize(deserializer)? else {
        return Ok(Vec::new());
    };
    let items = match field {
        RefField::One(item) => vec![item],
        RefField::Many(items) => items,
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            RefItem::Str(s) => out.push(s),
            RefItem::Map(map) => {
                for (k, v) in map {
                    match v {
                        Some(val) if !val.is_empty() => out.push(format!("{k}: {val}")),
                        _ => out.push(k),
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Accepts both a map `{ "cis": ["1.1"] }` (Windows built-ins) and a sequence of single-key maps
/// `[ { "cis": ["1.1"] }, ... ]` (standard Linux `ruleset/sca/*.yml`), with scalar or sequence values.
fn deserialize_compliance<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BTreeMap<String, Vec<String>>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum EntryVal {
        One(String),
        Many(Vec<String>),
        Int(i64),
    }
    impl EntryVal {
        fn into_vec(self) -> Vec<String> {
            match self {
                EntryVal::One(s) => vec![s],
                EntryVal::Many(v) => v,
                EntryVal::Int(n) => vec![n.to_string()],
            }
        }
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RawCompliance {
        Map(BTreeMap<String, EntryVal>),
        Seq(Vec<BTreeMap<String, EntryVal>>),
    }

    let Some(raw) = Option::<RawCompliance>::deserialize(deserializer)? else {
        return Ok(BTreeMap::new());
    };
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    match raw {
        RawCompliance::Map(map) => {
            for (k, v) in map {
                out.entry(k).or_default().extend(v.into_vec());
            }
        }
        RawCompliance::Seq(items) => {
            for item in items {
                for (k, v) in item {
                    out.entry(k).or_default().extend(v.into_vec());
                }
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    policy: PolicyInfo,
    #[serde(default)]
    requirements: Requirements,
    #[serde(default)]
    variables: HashMap<String, Option<String>>,
    checks: Vec<CheckDef>,
}

/// A policy's variables, longest name first.
type Vars = [(String, Option<String>)];

#[derive(Debug)]
enum Matcher {
    Equals(String),
    Regex(Regex),
    NotRegex(Regex),
    Numeric(Regex, String, i64),
    /// A regex that does not compile.
    Bad(String),
}

fn number(s: &str) -> Option<i64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// A policy regex (case-insensitive) in Rust syntax. The policy dialect: `\.` any character, `.` a
/// dot, `\s` space or tab, `\w` `[A-Za-z0-9@_-]`, `\p` punctuation, `\d` `\t` as usual, a backslash
/// before a symbol makes it literal, `[ ] { } ?` are literal; other escaped letters are Rust's.
fn regex(r: &str) -> Result<Regex, String> {
    let mut out = String::from("(?im)");
    let mut chars = r.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('.') => out.push('.'),
                Some('s') => out.push_str(r"[ \t]"),
                Some('w') => out.push_str("[A-Za-z0-9@_-]"),
                Some('p') => out.push_str("[[:punct:]]"),
                Some(l) if l.is_ascii_alphanumeric() => out.extend(['\\', l]),
                Some(x) => out.push_str(&regex::escape(&x.to_string())),
                None => out.push_str(r"\\"),
            },
            '.' | '[' | ']' | '{' | '}' | '?' => out.extend(['\\', c]),
            _ => out.push(c),
        }
    }
    Regex::new(&out).map_err(|e| format!("bad regex {r}: {e}"))
}

impl Matcher {
    fn parse(p: &str) -> Result<Matcher, String> {
        if let Some(r) = p.strip_prefix("!r:") {
            return Ok(regex(r).map_or_else(Matcher::Bad, Matcher::NotRegex));
        }
        if let Some(r) = p.strip_prefix("r:") {
            return Ok(regex(r).map_or_else(Matcher::Bad, Matcher::Regex));
        }
        if let Some(n) = p.strip_prefix("n:") {
            let bad = || format!("numeric match not understood: {p}");
            let (r, cmp) = n.rsplit_once(" compare ").ok_or_else(bad)?;
            let cmp = cmp.trim();
            let (op, num) = cmp.split_at(cmp.find(|c| !"<>=!".contains(c)).unwrap_or(cmp.len())); // `<=30` and `=0` occur too
            let op = if op == "=" { "==" } else { op };
            if !["<", "<=", "==", "!=", ">=", ">"].contains(&op) {
                return Err(bad());
            }
            let re = match regex(r) {
                Ok(re) => re,
                Err(e) => return Ok(Matcher::Bad(e)),
            };
            if re.captures_len() < 2 {
                return Err(bad());
            }
            return Ok(Matcher::Numeric(re, op.to_string(), number(num.trim()).ok_or_else(bad)?));
        }
        Ok(Matcher::Equals(p.to_string()))
    }

    fn matches(&self, v: &str) -> bool {
        match self {
            Matcher::Equals(e) => match (number(e), number(v)) {
                (Some(a), Some(b)) => a == b,
                _ => e.eq_ignore_ascii_case(v.trim()),
            },
            Matcher::Regex(r) => r.is_match(v),
            Matcher::NotRegex(r) => !r.is_match(v),
            Matcher::Numeric(r, op, n) => {
                let Some(x) = r.captures(v).and_then(|c| c.get(1)?.as_str().parse::<i64>().ok()) else { return false };
                match op.as_str() {
                    "<" => x < *n,
                    "<=" => x <= *n,
                    "==" => x == *n,
                    "!=" => x != *n,
                    ">=" => x >= *n,
                    _ => x > *n,
                }
            }
            Matcher::Bad(_) => false,
        }
    }
}

/// The last part of a rule: patterns joined by ` && `, all holding on the same line.
#[derive(Debug)]
struct Content(Vec<Matcher>);

impl Content {
    fn parse(p: &str) -> Result<Content, String> {
        // `&&` as a word separates patterns; `a && && b` happens in real policies, `a&&b` is one pattern
        let words: Vec<&str> = p.split(' ').collect();
        let m = words.split(|w| *w == "&&").map(|s| s.join(" ")).filter(|s| !s.trim().is_empty()).map(|s| Matcher::parse(s.trim()));
        let m = m.collect::<Result<Vec<_>, _>>()?;
        if m.is_empty() {
            return Err(format!("empty match: {p}"));
        }
        Ok(Content(m))
    }

    fn line(&self, l: &str) -> bool {
        self.0.iter().all(|m| m.matches(l))
    }

    /// Some line of the text satisfies every pattern.
    fn text(&self, t: &str) -> bool {
        t.lines().any(|l| self.line(l))
    }

    fn bad(&self) -> Option<String> {
        self.0.iter().find_map(|m| match m {
            Matcher::Bad(e) => Some(e.clone()),
            _ => None,
        })
    }
}

#[derive(Debug)]
enum Target {
    Registry { key: String, value: Option<String> },
    File(String),
    Dir(String, Option<Regex>),
    Process,
    Command(String),
    Secedit(String),
    Auditpol(String),
}

#[derive(Debug)]
pub struct Rule {
    negate: bool,
    /// One target per value of a comma-list variable; `Err` when the rule can never be evaluated
    /// (a variable without a value, a regex that does not compile).
    targets: Result<Vec<Target>, String>,
    expect: Option<Content>,
}

/// `target` with the variables put in: one target per value of a comma list.
fn substitute(target: &str, vars: &Vars) -> Result<Vec<String>, String> {
    let mut out = vec![target.to_string()];
    for (name, value) in vars {
        if !out[0].contains(name.as_str()) {
            continue;
        }
        let Some(value) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
            return Err(format!("variable {name} has no value"));
        };
        out = out.iter().flat_map(|t| value.split(',').map(move |v| t.replace(name.as_str(), v.trim()))).collect();
    }
    Ok(out)
}

/// `d:`: the directory exists; with a name regex, an entry at any depth under it has a matching
/// name (and, with content, is a file with a line satisfying it).
fn dir_holds(dir: &Path, name: Option<&Regex>, content: Option<&Content>) -> bool {
    let Some(name) = name else { return dir.is_dir() };
    let mut hit = false;
    walk(dir, usize::MAX, &mut |p| {
        hit = hit
            || (p.file_name().is_some_and(|n| name.is_match(&n.to_string_lossy()))
                && content.is_none_or(|c| std::fs::read(p).is_ok_and(|b| c.text(&String::from_utf8_lossy(&b)))));
    });
    hit
}

impl Rule {
    pub fn parse(s: &str) -> Result<Rule, String> {
        Rule::parse_with(s, &[])
    }

    fn parse_with(s: &str, vars: &Vars) -> Result<Rule, String> {
        let s = s.trim();
        let (negate, body) = match s.strip_prefix("not ") {
            Some(b) => (true, b.trim_start()),
            None => (false, s),
        };
        let bad = || format!("rule not understood: {s}");
        let (kind, rest) = body.split_once(':').ok_or_else(bad)?;
        let parts: Vec<&str> = rest.split(" -> ").map(str::trim).collect();
        if parts[0].is_empty() {
            return Err(bad());
        }
        let content_at = match (kind, parts.len()) {
            ("p", 1) => 0,
            ("r" | "d", 1..=3) => 2,
            ("f" | "c", 1..=usize::MAX) => 1,
            _ => return Err(bad()),
        };
        // a process rule's pattern is its first part (content_at 0); file and command rules may
        // give several contents, which must all hold
        let expect = if content_at > 0 && parts.len() > content_at + 1 {
            Some(Content::parse(&parts[content_at..].join(" && "))?)
        } else {
            parts.get(content_at).map(|p| Content::parse(p)).transpose()?
        };
        let mut broken = expect.as_ref().and_then(Content::bad);
        let name = match (kind, parts.get(1)) {
            ("d", Some(n)) => regex(n.strip_prefix("r:").unwrap_or(n)).map_err(|e| broken.get_or_insert(e).clone()).ok(),
            _ => None,
        };
        let make = |t: String| match kind {
            "r" => Target::Registry { key: t, value: parts.get(1).map(|v| v.to_string()) },
            "f" => Target::File(t),
            "d" => Target::Dir(t, name.clone()),
            "p" => Target::Process,
            _ => match (t.strip_prefix("secedit-value:"), t.strip_prefix("auditpol:")) {
                (Some(n), _) => Target::Secedit(n.trim().to_ascii_lowercase()),
                (_, Some(n)) => Target::Auditpol(n.trim().to_ascii_lowercase()),
                _ => Target::Command(t),
            },
        };
        let targets = match broken {
            Some(e) => {
                warn!(rule = %s, error = %e, "Configuration assessment rule cannot be evaluated");
                Err(e)
            }
            None => substitute(parts[0], vars).map(|ts| ts.into_iter().map(make).collect()),
        };
        Ok(Rule { negate, targets, expect })
    }

    /// Whether the rule holds; `Err` with the reason when it cannot be read.
    pub fn eval(&self, ctx: &Context) -> Result<bool, String> {
        let targets = self.targets.as_ref().map_err(Clone::clone)?;
        Ok(combine(Condition::Any, targets.iter().map(|t| self.holds(t, ctx)))? != self.negate)
    }

    /// Whether the rule holds for one target, before `not`.
    fn holds(&self, t: &Target, ctx: &Context) -> Result<bool, String> {
        let value = match t {
            Target::Registry { key, value } => reg::query(key, value.as_deref()).map_err(|e| format!("registry {key}: {e}"))?,
            Target::Secedit(n) => ctx.secedit().as_ref().map_err(Clone::clone)?.get(n).cloned(),
            Target::Auditpol(n) => ctx.auditpol().as_ref().map_err(Clone::clone)?.get(n).cloned(),
            Target::Process => return Ok(self.expect.as_ref().is_some_and(|c| ctx.processes().iter().any(|n| c.line(n)))),
            Target::File(p) => {
                let p = expand(p);
                let Some(c) = &self.expect else { return Ok(Path::new(&p).exists()) };
                return match std::fs::read(&p) {
                    Ok(b) => Ok(c.text(&String::from_utf8_lossy(&b))),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(e) => Err(format!("file {p}: {e}")),
                };
            }
            Target::Dir(d, name) => return Ok(dir_holds(Path::new(&expand(d)), name.as_ref(), self.expect.as_ref())),
            Target::Command(c) => {
                let (ok, out) = ctx.command(c)?;
                return Ok(self.expect.as_ref().map_or(ok, |m| m.text(&out)));
            }
        };
        Ok(value.is_some_and(|v| self.expect.as_ref().is_none_or(|m| m.line(&v))))
    }
}

/// all / any / none over rule results; a rule that cannot be read decides only when the others
/// do not.
fn combine(cond: Condition, results: impl IntoIterator<Item = Result<bool, String>>) -> Result<bool, String> {
    let (mut any_true, mut any_false, mut err) = (false, false, None);
    for r in results {
        match r {
            Ok(true) => any_true = true,
            Ok(false) => any_false = true,
            Err(e) => {
                err.get_or_insert(e);
            }
        }
    }
    let decided = match cond {
        Condition::All => any_false.then_some(false),
        Condition::Any => any_true.then_some(true),
        Condition::None => any_true.then_some(false),
    };
    match (decided, err) {
        (Some(d), _) => Ok(d),
        (None, Some(e)) => Err(e),
        (None, None) => Ok(cond != Condition::Any),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed,
    NotApplicable(String),
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Passed => "passed",
            Outcome::Failed => "failed",
            Outcome::NotApplicable(_) => "not applicable",
        }
    }
}

#[derive(Debug)]
pub struct Check {
    pub def: CheckDef,
    rules: Vec<Rule>,
}

impl Check {
    pub fn evaluate(&self, ctx: &Context) -> Outcome {
        match combine(self.def.condition, self.rules.iter().map(|r| r.eval(ctx))) {
            Ok(true) => Outcome::Passed,
            Ok(false) => Outcome::Failed,
            Err(e) => Outcome::NotApplicable(e),
        }
    }
}

#[derive(Debug)]
pub struct Policy {
    pub info: PolicyInfo,
    /// SHA-256 hex of the policy's YAML text.
    pub yaml_sha256: String,
    requirements: Vec<(Condition, Vec<Rule>)>,
    /// In ascending id order.
    pub checks: Vec<Check>,
}

fn parse_rules(rules: &[String], vars: &Vars) -> Result<Vec<Rule>, String> {
    rules.iter().map(|r| Rule::parse_with(r, vars)).collect()
}

/// Parses a check's rules, keeping any single rule with invalid syntax as non-evaluatable
/// so one upstream YAML typo (e.g. `compare => 5`) does not discard the entire benchmark.
fn parse_check_rules(rules: &[String], vars: &Vars, check_id: u32) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| match Rule::parse_with(r, vars) {
            Ok(rule) => rule,
            Err(e) => {
                warn!(check_id, rule = %r, error = %e, "Configuration assessment rule cannot be evaluated");
                Rule { negate: false, targets: Err(e), expect: None }
            }
        })
        .collect()
}

impl Policy {
    pub fn parse(yaml: &str) -> Result<Policy, String> {
        let f: PolicyFile = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
        if f.policy.id.trim().is_empty() || f.policy.name.trim().is_empty() {
            return Err("policy id and name are required".into());
        }
        let mut vars: Vec<(String, Option<String>)> = f.variables.into_iter().collect();
        vars.sort_by_key(|(n, _)| std::cmp::Reverse(n.len())); // `$conf-dirs` is put in before `$conf`
        let r = f.requirements;
        if r.condition.is_none() && !r.rules.is_empty() {
            return Err("requirements rules need a condition".into());
        }
        let requirements = [(Condition::All, r.all), (Condition::Any, r.any), (Condition::None, r.none)]
            .into_iter()
            .chain(r.condition.map(|c| (c, r.rules)))
            .filter(|(_, l)| !l.is_empty())
            .map(|(c, l)| Ok((c, parse_rules(&l, &vars)?)))
            .collect::<Result<_, String>>()?;
        let mut seen = HashSet::new();
        let mut checks = Vec::new();
        for def in f.checks {
            if !seen.insert(def.id) {
                return Err(format!("check id {} used twice", def.id));
            }
            if def.title.trim().is_empty() || def.rules.is_empty() {
                return Err(format!("check {} needs a title and at least one rule", def.id));
            }
            let rules = parse_check_rules(&def.rules, &vars, def.id);
            checks.push(Check { def, rules });
        }
        checks.sort_by_key(|c| c.def.id);
        Ok(Policy { info: f.policy, yaml_sha256: format!("{:x}", Sha256::digest(yaml.as_bytes())), requirements, checks })
    }

    /// Whether the policy applies to this system (no requirements: always).
    pub fn applies(&self, ctx: &Context) -> bool {
        self.requirements.iter().all(|(c, rules)| combine(*c, rules.iter().map(|r| r.eval(ctx))) == Ok(true))
    }
}

/// Whether a command exited 0, and its output; `Err` when it did not start or timed out.
type Ran = Result<(bool, String), String>;

/// What one scan reads once: processes, the local security policy, the audit policy, each command.
pub struct Context {
    processes: OnceCell<Vec<String>>,
    secedit: OnceCell<Result<HashMap<String, String>, String>>,
    auditpol: OnceCell<Result<HashMap<String, String>, String>>,
    /// By command line: whether it exited 0, and its output.
    commands: RefCell<HashMap<String, Ran>>,
    command_timeout: Duration,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            processes: OnceCell::new(),
            secedit: OnceCell::new(),
            auditpol: OnceCell::new(),
            commands: RefCell::default(),
            command_timeout: Duration::from_secs(30),
        }
    }
}

impl Context {
    fn command(&self, c: &str) -> Ran {
        if let Some(r) = self.commands.borrow().get(c) {
            return r.clone();
        }
        let r = run_command(c, self.command_timeout);
        self.commands.borrow_mut().insert(c.to_string(), r.clone());
        r
    }
    fn processes(&self) -> &[String] {
        self.processes.get_or_init(running_processes)
    }
    fn secedit(&self) -> &Result<HashMap<String, String>, String> {
        self.secedit.get_or_init(|| load_secedit().map_err(|e| format!("local security policy not exported: {e}")))
    }
    fn auditpol(&self) -> &Result<HashMap<String, String>, String> {
        self.auditpol.get_or_init(|| load_auditpol().map_err(|e| format!("audit policy not read: {e}")))
    }
}

/// `cmd /C` (elsewhere `sh -c`): whether it exited 0, and its standard output then standard error.
fn run_command(c: &str, timeout: Duration) -> Ran {
    #[cfg(windows)]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        let mut x = Command::new("cmd");
        x.raw_arg(format!("/S /C \"{c}\"")); // /S: cmd takes the command between the outer quotes as is
        x
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut x = Command::new("sh");
        x.args(["-c", c]);
        x
    };
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("command {c} did not start: {e}"))?;
    let pid = child.id().to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || tx.send(child.wait_with_output()));
    // the agent stopping ends it like the timeout
    let end = std::time::Instant::now() + timeout;
    let ran = loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Err(mpsc::RecvTimeoutError::Timeout) if crate::collecting() && std::time::Instant::now() < end => {}
            r => break r,
        }
    };
    match ran {
        Ok(Ok(o)) => {
            let (out, err) = (String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
            Ok((o.status.success(), out.lines().chain(err.lines()).collect::<Vec<_>>().join("\n")))
        }
        Ok(Err(e)) => Err(format!("command {c}: {e}")),
        Err(_) => {
            // the whole tree: cmd's children (powershell, ...) keep running when only cmd is killed
            #[cfg(windows)]
            let _ = Command::new("taskkill").args(["/F", "/T", "/PID", &pid]).output();
            #[cfg(not(windows))]
            let _ = Command::new("kill").args(["-9", &pid]).output();
            Err(format!("command {c} timed out after {} s", timeout.as_secs()))
        }
    }
}

/// UTF-16LE with a byte-order mark (what secedit writes), else UTF-8.
fn decode(b: &[u8]) -> String {
    match b.strip_prefix(&[0xFF, 0xFE]) {
        Some(w) => String::from_utf16_lossy(&w.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect::<Vec<_>>()),
        None => String::from_utf8_lossy(b).into_owned(),
    }
}

/// `Name = value` lines of a secedit export, by lower-case name (sections ignored).
pub fn parse_secedit(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('['))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

/// `auditpol /r` CSV: the inclusion setting by lower-case subcategory name and by GUID.
pub fn parse_auditpol(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for l in text.lines() {
        let c: Vec<&str> = l.split(',').map(str::trim).collect();
        if c.len() >= 5 && c[3].starts_with('{') {
            out.insert(c[2].to_ascii_lowercase(), c[4].to_string());
            out.insert(c[3].to_ascii_lowercase(), c[4].to_string());
        }
    }
    out
}

fn load_secedit() -> Result<HashMap<String, String>, String> {
    let path = std::env::temp_dir().join(format!("provigil-secedit-{}.inf", uuid::Uuid::new_v4()));
    let out = Command::new("secedit")
        .args(["/export", "/cfg"])
        .arg(&path)
        .args(["/areas", "SECURITYPOLICY", "USER_RIGHTS"])
        .output()
        .map_err(|e| format!("secedit did not run: {e}"))?;
    let bytes = std::fs::read(&path);
    let _ = std::fs::remove_file(&path); // the export holds the security policy: never left behind
    if !out.status.success() {
        return Err(format!("secedit ended with code {}", out.status.code().unwrap_or(-1)));
    }
    Ok(parse_secedit(&decode(&bytes.map_err(|e| format!("export not readable: {e}"))?)))
}

fn load_auditpol() -> Result<HashMap<String, String>, String> {
    let out = Command::new("auditpol").args(["/get", "/category:*", "/r"]).output().map_err(|e| format!("auditpol did not run: {e}"))?;
    if !out.status.success() {
        return Err(format!("auditpol ended with code {}", out.status.code().unwrap_or(-1)));
    }
    Ok(parse_auditpol(&String::from_utf8_lossy(&out.stdout)))
}

/// SHA-256 hex of the results in ascending check-id order joined with `:`, `not applicable` empty.
pub fn results_hash(results: &[(u32, &Outcome)]) -> String {
    let mut r = results.to_vec();
    r.sort_by_key(|(id, _)| *id);
    let text = r.iter().map(|(_, o)| if matches!(o, Outcome::NotApplicable(_)) { "" } else { o.as_str() }).collect::<Vec<_>>().join(":");
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

pub fn check_message(scan_id: u32, p: &Policy, c: &Check, outcome: &Outcome) -> Value {
    let d = &c.def;
    let compliance: BTreeMap<&String, String> = d.compliance.iter().map(|(k, v)| (k, v.join(","))).collect();
    let mut check = json!({
        "id": d.id,
        "title": d.title,
        "compliance": compliance,
        "rules": d.rules,
        "condition": d.condition.as_str(),
        "result": outcome.as_str(),
    });
    for (k, v) in [("description", &d.description), ("rationale", &d.rationale), ("remediation", &d.remediation)] {
        if !v.is_empty() {
            check[k] = json!(v);
        }
    }
    if !d.references.is_empty() {
        check["references"] = json!(d.references.join(","));
    }
    if let Outcome::NotApplicable(reason) = outcome {
        check["reason"] = json!(reason);
    }
    let targets = || c.rules.iter().flat_map(|r| r.targets.iter().flatten());
    if let Some(key) = targets().find_map(|t| match t { Target::Registry { key, .. } => Some(key), _ => None }) {
        check["registry"] = json!(key);
    }
    if let Some(file) = targets().find_map(|t| match t { Target::File(f) => Some(f), _ => None }) {
        check["file"] = json!(file);
    }
    json!({ "type": "check", "id": scan_id, "policy": p.info.name, "policy_id": p.info.id, "check": check })
}

pub fn summary_message(scan_id: u32, p: &Policy, results: &[(u32, &Outcome)], times: (i64, i64), first_scan: bool) -> Value {
    let count = |s: &str| results.iter().filter(|(_, o)| o.as_str() == s).count();
    let (passed, failed) = (count("passed"), count("failed"));
    let mut s = json!({
        "type": "summary",
        "scan_id": scan_id,
        "name": p.info.name,
        "policy_id": p.info.id,
        "file": format!("{}.yml", p.info.id),
        "start_time": times.0,
        "end_time": times.1,
        "passed": passed,
        "failed": failed,
        "invalid": count("not applicable"),
        "total_checks": results.len(),
        "score": (passed * 100).checked_div(passed + failed).unwrap_or(0),
        "hash": results_hash(results),
        "hash_file": p.yaml_sha256,
    });
    if !p.info.description.is_empty() {
        s["description"] = json!(p.info.description);
    }
    if !p.info.references.is_empty() {
        s["references"] = json!(p.info.references.join(","));
    }
    if first_scan {
        s["first_scan"] = json!(1);
    }
    s
}

fn event(agent: (&str, &str), message: &Value) -> Value {
    json!({
        "event_type": "sca",
        "timestamp": Utc::now().to_rfc3339(),
        "agent": { "id": agent.0, "name": agent.1 },
        "location": "sca",
        "message": message.to_string(),
    })
}

/// A random positive 31-bit scan id.
fn new_scan_id() -> u32 {
    ((uuid::Uuid::new_v4().as_u128() as u32) & 0x7FFF_FFFF).max(1)
}

/// One policy's events: a check event per check in id order, then the summary.
pub fn scan_policy(p: &Policy, ctx: &Context, agent: (&str, &str), first_scan: bool) -> Vec<Value> {
    policy_events(p, ctx, agent, first_scan, None, false).0
}

/// One policy's events and results. With `last` (the results the manager has) only the checks
/// whose result changed; the summary always, it carries the hash of all results.
fn policy_events(p: &Policy, ctx: &Context, agent: (&str, &str), first_scan: bool, last: Option<&HashMap<u32, String>>, asked: bool) -> (Vec<Value>, Vec<(u32, &'static str)>) {
    let scan_id = new_scan_id();
    let start = Utc::now().timestamp();
    // the stop ends the scan between checks ([`ScaScanner::scan`] then reports nothing)
    let outcomes: Vec<Outcome> = p.checks.iter().map_while(|c| crate::collecting().then(|| c.evaluate(ctx))).collect();
    let end = Utc::now().timestamp();
    let changed = |c: &Check, o: &Outcome| last.is_none_or(|l| l.get(&c.def.id).map(String::as_str) != Some(o.as_str()));
    let mut out: Vec<Value> = p.checks.iter().zip(&outcomes).filter(|(c, o)| changed(c, o)).map(|(c, o)| event(agent, &check_message(scan_id, p, c, o))).collect();
    let results: Vec<(u32, &Outcome)> = p.checks.iter().map(|c| c.def.id).zip(&outcomes).collect();
    out.push(event(agent, &summary_message(scan_id, p, &results, (start, end), first_scan)));
    if asked {
        out.push(event(agent, &json!({ "type": "dump_end", "elements_sent": outcomes.len(), "policy_id": p.info.id, "scan_id": scan_id })));
    }
    (out, results.iter().map(|(id, o)| (*id, o.as_str())).collect())
}

/// The loaded policies, and which were scanned since the agent started.
pub struct ScaScanner {
    policies: Vec<Policy>,
    scanned: HashSet<String>,
    /// Where the results last sent are kept; none: every scan sends every check.
    state: Option<PathBuf>,
    /// The policies the manager wants in full.
    asked: HashSet<String>,
    /// `full_send_splay_secs`.
    splay: Option<u64>,
}

impl ScaScanner {
    /// The built-in policies plus the `*.yml` / `*.yaml` files in `sca\` next to the agent.
    pub fn new() -> Self {
        Self::load(Path::new("sca"))
    }

    pub fn load(dir: &Path) -> Self {
        let mut texts: Vec<(String, String)> = BUILTIN.iter().map(|t| ("built-in".to_string(), t.to_string())).collect();
        let mut files: Vec<_> = std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files {
            if f.extension().is_some_and(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml")) {
                match std::fs::read_to_string(&f) {
                    Ok(t) => texts.push((f.display().to_string(), t)),
                    Err(e) => warn!(file = %f.display(), error = %e, "Configuration assessment policy not readable"),
                }
            }
        }
        let (mut policies, mut ids, mut check_ids) = (Vec::<Policy>::new(), HashSet::new(), HashSet::new());
        for (source, text) in texts {
            let p = match Policy::parse(&text) {
                Ok(p) => p,
                Err(e) => {
                    warn!(source = %source, error = %e, "Configuration assessment policy skipped");
                    continue;
                }
            };
            if ids.contains(&p.info.id) || p.checks.iter().any(|c| check_ids.contains(&c.def.id)) {
                warn!(source = %source, policy = %p.info.id, "Configuration assessment policy skipped: its id or a check id is already in use");
                continue;
            }
            ids.insert(p.info.id.clone());
            check_ids.extend(p.checks.iter().map(|c| c.def.id));
            policies.push(p);
        }
        ScaScanner { policies, scanned: HashSet::new(), state: None, asked: HashSet::new(), splay: Some(0) }
    }

    /// Sends only what changed since the results kept in this file; a full send waits its
    /// splay (`full_send_splay_secs`).
    pub fn with_state(mut self, path: PathBuf, splay: Option<u64>) -> Self {
        (self.state, self.splay) = (Some(path), splay);
        self
    }

    /// The manager asked for these policies in full, at the next scan.
    pub fn ask_full(&mut self, policies: impl IntoIterator<Item = String>) {
        self.asked.extend(policies);
    }

    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// These policies without the given ids (`sca_disabled_policies`).
    pub fn without(mut self, ids: &[String]) -> Self {
        self.policies.retain(|p| !ids.contains(&p.info.id));
        self
    }

    /// Every policy that applies to this system; the local and audit policies are read once.
    /// Ends with a `policies` message listing the policies scanned, so the manager drops the
    /// results of the others. Nothing when the agent stops meanwhile.
    pub fn scan(&mut self, agent_id: &str, agent_name: &str) -> Vec<Value> {
        let ctx = Context::default();
        let mut sent = self.state.as_deref().and_then(|f| Sent::open(f).map_err(|e| warn!(error = %e, "Configuration assessment results sent not readable: sending all")).ok());
        // nothing sent yet for this agent: an install's first send
        let first = sent.as_ref().is_none_or(|s| !s.has_sca(agent_id));
        let (mut out, mut ids, mut results, mut full) = (Vec::new(), Vec::new(), Vec::new(), false);
        for p in &self.policies {
            if !crate::collecting() {
                return Vec::new();
            }
            if !p.applies(&ctx) {
                info!(policy = %p.info.id, "Configuration assessment policy does not apply to this system");
                continue;
            }
            let first_scan = self.scanned.insert(p.info.id.clone());
            let asked = self.asked.contains(&p.info.id);
            let last = sent.as_ref().filter(|_| !asked).and_then(|s| s.sca(agent_id, &p.info.id, &p.yaml_sha256).ok()).filter(|l| !l.is_empty());
            full |= last.is_none();
            let (events, r) = policy_events(p, &ctx, (agent_id, agent_name), first_scan, last.as_ref(), asked);
            out.extend(events);
            results.push((p, r));
            ids.push(p.info.id.as_str());
        }
        // the scan ran; only the send of a full one waits (saved once it goes)
        if !crate::collecting() || (full && !crate::sent::wait_splay(self.splay, first)) {
            return Vec::new();
        }
        if let Some(s) = &mut sent {
            for (p, r) in &results {
                if let Err(e) = s.save_sca(agent_id, &p.info.id, &p.yaml_sha256, r) {
                    warn!(policy = %p.info.id, error = %e, "Configuration assessment results sent not saved");
                }
            }
        }
        self.asked.clear();
        out.push(event((agent_id, agent_name), &json!({ "type": "policies", "policies": ids })));
        out
    }
}

impl Default for ScaScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
