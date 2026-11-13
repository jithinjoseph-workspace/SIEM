//! Configuration assessment events (spec section 2.28): check results, scan summaries,
//! policy lists and dump ends are stored in provigil-db; changes become `sca.*` fields, and
//! a database out of step makes the manager ask the agent for its results again.

use std::collections::VecDeque;

use provigil_json::Json;

use crate::event::*;
use crate::host::Host;

pub const NAME: &str = "sca";
pub const MANAGER_QUEUE: &str = "queue/alerts/cfgaq";
pub const AGENT_QUEUE: &str = "queue/alerts/cfgarq";
/// Requests waiting to be sent.
const WAITING: usize = 1023;

fn cut(b: &[u8]) -> &[u8] {
    text_at(b, 0)
}

fn text(j: &Json) -> Option<&[u8]> {
    match j {
        Json::String(s) => Some(cut(s)),
        _ => None,
    }
}

fn int(j: &Json) -> i32 {
    match j {
        Json::Number { int, .. } => *int,
        _ => 0,
    }
}

fn double(j: &Json) -> f64 {
    match j {
        Json::Number { double, .. } => *double,
        _ => 0.0,
    }
}

fn six(d: f64) -> String {
    format!("{d:.6}")
}

/// Members of an object (with names) or elements of an array.
fn entries(j: &Json) -> Vec<(Option<&[u8]>, &Json)> {
    match j {
        Json::Object(m) => m.iter().map(|(k, v)| (Some(cut(k)), v)).collect(),
        Json::Array(a) => a.iter().map(|v| (None, v)).collect(),
        _ => Vec::new(),
    }
}

/// The first word, at most 64 bytes.
fn first_word(s: &[u8]) -> Vec<u8> {
    let space = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let start = s.iter().position(|c| !space(c)).unwrap_or(s.len());
    s[start..].iter().take(64).take_while(|c| !space(c)).copied().collect()
}

fn number_text(j: &Json) -> Vec<u8> {
    if f64::from(int(j)) == double(j) {
        int(j).to_string().into_bytes()
    } else {
        six(double(j)).into_bytes()
    }
}

#[derive(Debug, Default)]
pub struct Assessment {
    requests: VecDeque<Vec<u8>>,
}

struct Cx<'a> {
    host: &'a mut dyn Host,
    agent: Vec<u8>,
    order: usize,
}

impl Cx<'_> {
    fn error(&mut self, m: &[u8]) {
        self.host.log("ERROR", m);
    }

    fn query(&mut self, what: &[u8], arg: &[u8]) -> Option<Vec<u8>> {
        let mut q = [&b"agent "[..], &self.agent, b" sca ", what, arg].concat();
        q.truncate(65534);
        self.host.db_query(&q, 65536).ok()
    }

    /// (0, payload) found, (1, empty) not found, (-1, empty) error.
    fn find(&mut self, what: &[u8], arg: &[u8]) -> (i32, Vec<u8>) {
        match self.query(what, arg) {
            Some(r) if r.starts_with(b"ok found") => (0, r.get(9..).unwrap_or(b"").to_vec()),
            Some(r) if r == b"ok not found" => (1, Vec::new()),
            _ => (-1, Vec::new()),
        }
    }

    fn delete(&mut self, what: &[u8], arg: &[u8]) -> i32 {
        match self.query(what, arg) {
            Some(r) if r.starts_with(b"ok") => 0,
            Some(r) if r.starts_with(b"err") => 1,
            _ => -1,
        }
    }

    fn save(&mut self, what: &[u8], arg: &[u8]) -> bool {
        self.query(what, arg).is_some()
    }

    fn fill(&mut self, ev: &mut Event, k: &[u8], v: &[u8]) {
        crate::plugins::fill(ev, Some(k), cut(v), self.order);
    }

    fn agent_error(&mut self, what: &str) {
        let m = [what.as_bytes(), b" for agent '", &self.agent.clone(), b"'"].concat();
        self.error(&m);
    }
}

impl Assessment {
    fn request(&mut self, host: &mut dyn Host, agent: &[u8], policy: &[u8], first_scan: i32) {
        let mut m = [agent, b":sca-dump:", policy, format!(":{first_scan}").as_bytes()].concat();
        m.truncate(4095);
        if self.requests.len() >= WAITING {
            host.log("WARNING", b"SCA request queue is full.");
            return;
        }
        self.requests.push_back(m);
    }

    /// Sends the waiting requests: the manager's own to its queue (without the agent part),
    /// the agents' to theirs.
    pub fn send_requests(&mut self, host: &mut dyn Host) {
        while let Some(m) = self.requests.pop_front() {
            let Some(p) = m.iter().position(|&c| c == b':') else { continue };
            if &m[..p] == b"000" {
                host.send_queue(MANAGER_QUEUE, &m[p + 1..]);
            } else {
                host.send_queue(AGENT_QUEUE, &m);
            }
        }
    }

    /// One event; it always goes on to the rules, except without a text `type`.
    pub fn decode(&mut self, host: &mut dyn Host, decoder: DecoderId, order: usize, ev: &mut Event) -> bool {
        ev.decoder = decoder;
        let log = ev.log().to_vec();
        let Ok((mut event, _)) = provigil_json::parse_with_opts(&log, false) else {
            host.log("ERROR", b"Malformed configuration assessment JSON event.");
            return true;
        };
        let kind = match event.get("type") {
            Some(Json::String(t)) => cut(t).to_vec(),
            _ => return false,
        };
        let agent = cut(ev.agent_id.as_deref().unwrap_or(b"")).to_vec();
        let mut c = Cx { host, agent, order };
        match kind.as_slice() {
            b"check" => self.check(&mut c, ev, &mut event),
            b"summary" => self.summary(&mut c, ev, &event),
            b"policies" => policies(&mut c, &event),
            b"dump_end" => self.dump_end(&mut c, &event),
            _ => {}
        }
        true
    }

    fn check(&mut self, c: &mut Cx, ev: &mut Event, event: &mut Json) {
        let bad = |c: &mut Cx, m: &str| c.error(format!("Malformed JSON: {m}").as_bytes());
        let Some(scan) = event.get("id").cloned() else { return bad(c, "field 'id' not found.") };
        if !matches!(scan, Json::Number { .. }) {
            return bad(c, "field 'id' must be a number.");
        }
        let Some(policy) = event.get("policy").cloned() else { return bad(c, "field 'policy' not found.") };
        if text(&policy).is_none() {
            return bad(c, "field 'policy' must be a string.");
        }
        let Some(policy_id) = event.get("policy_id") else { return bad(c, "field 'policy_id' not found.") };
        if text(policy_id).is_none() {
            return bad(c, "field 'policy_id' must be a string.");
        }
        let Some(check) = event.get_mut("check") else { return bad(c, "field 'check' not found.") };
        let Some(id) = check.get("id").cloned() else { return bad(c, "field 'id' not found.") };
        if !matches!(id, Json::Number { .. }) {
            return bad(c, "field 'id' must be a number.");
        }
        let Some(title) = check.get("title").cloned() else { return bad(c, "field 'title' not found.") };
        if text(&title).is_none() {
            return bad(c, "field 'title' must be a string.");
        }
        // optional texts (their error texts as they were: `references` says 'reference',
        // `condition` has no final dot)
        let optional = |c: &mut Cx, key: &str, shown: &str, dot: &str| -> Result<Option<Json>, ()> {
            match check.get(key) {
                Some(j) if text(j).is_none() => {
                    c.error(format!("Malformed JSON: field '{shown}' must be a string{dot}").as_bytes());
                    Err(())
                }
                other => Ok(other.cloned()),
            }
        };
        let mut texts = Vec::new();
        for (k, shown, dot) in [
            ("description", "description", "."),
            ("rationale", "rationale", "."),
            ("remediation", "remediation", "."),
            ("references", "reference", "."),
            ("file", "file", "."),
            ("condition", "condition", ""),
            ("directory", "directory", "."),
            ("process", "process", "."),
            ("registry", "registry", "."),
            ("command", "command", "."),
            ("reason", "reason", "."),
        ] {
            let Ok(v) = optional(c, k, shown, dot) else { return };
            texts.push(v);
        }
        let [description, rationale, remediation, references, file, _condition, directory, process, registry, command, reason]: [Option<Json>; 11] = texts.try_into().expect("eleven");
        let compliance = check.get("compliance").cloned();
        let rules = check.get("rules").cloned();
        let result = match check.get("result") {
            None => {
                let r = Json::String(b"not applicable".to_vec());
                check.add("result", r.clone());
                r
            }
            Some(r) if text(r).is_none() => return bad(c, "field 'result' must be a string."),
            Some(r) => r.clone(),
        };
        let result = text(&result).unwrap_or(b"").to_vec();
        let reason = reason.as_ref().and_then(text).map(<[u8]>::to_vec);
        let (idn, scan_n) = (int(&id), int(&scan));
        let (found, before) = c.find(b"query ", idn.to_string().as_bytes());
        let fields = CheckFields {
            scan: &scan,
            id: &id,
            policy: &policy,
            title: &title,
            description: description.as_ref(),
            rationale: rationale.as_ref(),
            remediation: remediation.as_ref(),
            compliance: compliance.as_ref(),
            references: references.as_ref(),
            file: file.as_ref(),
            directory: directory.as_ref(),
            process: process.as_ref(),
            registry: registry.as_ref(),
            command: command.as_ref(),
            result: &result,
            reason: reason.as_deref(),
        };
        match found {
            -1 => c.agent_error("Error querying policy monitoring database"),
            0 => {
                let arg = [format!("{idn}|").as_bytes(), &result, b"|", reason.as_deref().unwrap_or(b""), format!("|{scan_n}").as_bytes()].concat();
                let saved = c.save(b"update ", &arg);
                if before != result {
                    fill_check(c, ev, &fields, Some(&before));
                }
                if !saved {
                    c.agent_error("Error updating policy monitoring database");
                }
            }
            1 => {
                let saved = c.save(b"insert ", &event.print_unformatted());
                if before != result {
                    fill_check(c, ev, &fields, None);
                }
                if !saved {
                    c.agent_error("Error storing policy monitoring information");
                    return;
                }
                for (key, v) in compliance.iter().flat_map(entries) {
                    let value = match v {
                        Json::String(s) => cut(s).to_vec(),
                        Json::Number { .. } => number_text(v),
                        _ => continue,
                    };
                    c.save(b"insert_compliance ", &[format!("{idn}|").as_bytes(), key.unwrap_or(b"(null)"), b"|", &value].concat());
                }
                for (_, rule) in rules.iter().flat_map(entries) {
                    let Some(r) = text(rule) else { continue };
                    let flag = r.first().copied().unwrap_or(0);
                    let kind: &[u8] = match flag {
                        b'f' => b"file",
                        b'd' => b"directory",
                        b'r' => b"registry",
                        b'c' => b"command",
                        b'p' => b"process",
                        b'n' => b"numeric",
                        _ => {
                            c.error(&[&b"Invalid type: "[..], &[flag]].concat());
                            continue;
                        }
                    };
                    c.save(b"insert_rules ", &[format!("{idn}|").as_bytes(), kind, b"|", r].concat());
                }
            }
            _ => {}
        }
    }

    fn summary(&mut self, c: &mut Cx, ev: &mut Event, event: &Json) {
        let g = |k: &str| event.get(k);
        let bad = |c: &mut Cx, m: &str| c.error(format!("Malformed JSON: {m}").as_bytes());
        let Some(policy_id) = g("policy_id") else { return };
        let Some(pid) = text(policy_id) else { return bad(c, "field 'policy_id' must be a string.") };
        let Some(scan) = g("scan_id") else { return };
        if !matches!(scan, Json::Number { .. }) {
            return bad(c, "field 'scan_id' must be a number.");
        }
        if int(scan) < 0 {
            return bad(c, "field 'scan_id' cannot be negative.");
        }
        let need = |c: &mut Cx, k: &str, shown: &str| {
            let r = g(k);
            if r.is_none() {
                c.error(format!("Malformed JSON: field '{shown}' not found.").as_bytes());
            }
            r
        };
        let Some(start) = need(c, "start_time", "start_time") else { return };
        let Some(end) = need(c, "end_time", "end_time") else { return };
        let Some(passed) = need(c, "passed", "passed") else { return };
        let Some(failed) = need(c, "failed", "failed") else { return };
        let Some(invalid) = need(c, "invalid", "invalid") else { return };
        let Some(total) = need(c, "total_checks", "total_checks") else { return };
        let Some(score) = need(c, "score", "score") else { return };
        let Some(hash) = need(c, "hash", "hash") else { return };
        let Some(hash) = text(hash) else { return bad(c, "field 'hash' must be a string.") };
        let Some(hash_file) = need(c, "hash_file", "hash_file") else { return };
        let Some(hash_file) = text(hash_file) else { return bad(c, "field 'hash_file' must be a string.") };
        let Some(file) = need(c, "file", "file") else { return };
        if text(file).is_none() {
            return bad(c, "field 'file' must be a string.");
        }
        let Some(name) = need(c, "name", "policy") else { return };
        if text(name).is_none() {
            return bad(c, "field 'policy' must be a string.");
        }
        let description = g("description");
        let references = g("references");
        let first_scan = g("first_scan").is_some();
        let force = g("force_alert").is_some();
        let info = ScanFields { scan, name, description, passed, failed, invalid, total, score, file, policy_id };
        let agent = c.agent.clone();

        let (stored, scan_info) = c.find(b"query_scan ", pid);
        let stored_hash = first_word(&scan_info);
        let counts = format!("{}|{}|{}|{}|{}", int(passed), int(failed), int(invalid), int(total), int(score));
        match stored {
            -1 => c.agent_error("Error querying policy monitoring database"),
            0 | 1 => {
                let update = stored == 0;
                let arg = if update {
                    [pid, format!("|{}|{}|{}|{counts}|", int(start), int(end), int(scan)).as_bytes(), hash].concat()
                } else {
                    [format!("{}|{}|{}|", int(start), int(end), int(scan)).as_bytes(), pid, format!("|{counts}|").as_bytes(), hash].concat()
                };
                if !c.save(if update { b"update_scan_info_start " } else { b"insert_scan_info " }, &arg) {
                    c.agent_error(if update { "Error updating scan policy monitoring database" } else { "Error storing scan policy monitoring information" });
                } else {
                    let mut filled = false;
                    if stored_hash != hash {
                        if !first_scan {
                            fill_scan(c, ev, &info);
                            filled = true;
                        } else if !update {
                            self.request(c.host, &agent, pid, 1);
                        }
                    }
                    if force && !filled {
                        fill_scan(c, ev, &info);
                    }
                }
            }
            _ => {}
        }

        match c.find(b"query_policy ", pid).0 {
            -1 => c.agent_error("Error querying policy monitoring database"),
            1 => {
                let opt = |c: &mut Cx, j: Option<&Json>, k: &str| -> Result<Option<Vec<u8>>, ()> {
                    match j {
                        None => Ok(None),
                        Some(v) => match text(v) {
                            Some(t) => Ok(Some(t.to_vec())),
                            None => {
                                c.error(format!("Malformed JSON: field '{k}' must be a string").as_bytes());
                                Err(())
                            }
                        },
                    }
                };
                let Ok(refs) = opt(c, references, "references") else { return };
                let Ok(desc) = opt(c, description, "description") else { return };
                let arg = [
                    text(name).unwrap_or(b""),
                    b"|",
                    text(file).unwrap_or(b""),
                    b"|",
                    pid,
                    b"|",
                    desc.as_deref().unwrap_or(b"NULL"),
                    b"|",
                    refs.as_deref().unwrap_or(b"NULL"),
                    b"|",
                    hash_file,
                ]
                .concat();
                if !c.save(b"insert_policy ", &arg) {
                    c.agent_error("Error storing scan policy monitoring information");
                }
            }
            _ => {
                let (r, old_hash) = c.find(b"query_policy_sha256 ", pid);
                if r == 0 && hash_file != old_hash.as_slice() {
                    if c.delete(b"delete_policy ", pid) == 0 {
                        c.delete(b"delete_check ", pid);
                        self.request(c.host, &agent, pid, 1);
                        c.host.log("INFO", &[&b"Policy '"[..], pid, b"' information for agent '", &agent, b"' is outdated. Requested latest scan results."].concat());
                    } else {
                        c.error(&[&b"Unable to purge DB content for policy '"[..], pid, b"'"].concat());
                    }
                }
            }
        }

        let (r, results) = c.find(b"query_results ", pid);
        match r {
            0 if results != hash => self.request(c.host, &agent, pid, i32::from(first_scan)),
            0 => {}
            1 => self.request(c.host, &agent, pid, i32::from(first_scan)),
            _ => c.agent_error("Error querying policy monitoring database"),
        }
    }

    fn dump_end(&mut self, c: &mut Cx, event: &Json) {
        if event.get("elements_sent").is_none() {
            return c.error(b"Malformed JSON: field 'elements_sent' not found.");
        }
        let Some(policy_id) = event.get("policy_id") else { return c.error(b"Malformed JSON: field 'policy_id' not found.") };
        let Some(pid) = text(policy_id) else { return c.error(b"Malformed JSON: field 'policy_id' must be a string.") };
        let Some(scan) = event.get("scan_id") else { return c.error(b"Malformed JSON: field 'scan_id' not found.") };
        if c.delete(b"delete_check_distinct ", &[pid, format!("|{}", int(scan)).as_bytes()].concat()) == -1 {
            c.agent_error("Error querying policy monitoring database");
        }
        let (r, results) = c.find(b"query_results ", pid);
        if r == 0 {
            let (rh, info) = c.find(b"query_scan ", pid);
            if rh == 0 && results != first_word(&info) {
                let agent = c.agent.clone();
                self.request(c.host, &agent, pid, 0);
            }
        }
    }
}

/// The stored policies the agent no longer has are deleted.
fn policies(c: &mut Cx, event: &Json) {
    let Some(list) = event.get("policies") else { return c.error(b"Malformed JSON: field 'policies' not found.") };
    let (r, ids) = c.find(b"query_policies ", b"");
    if r == -1 {
        return c.agent_error("Error querying policy monitoring database");
    }
    for id in ids.split(|&b| b == b',').filter(|t| !t.is_empty()) {
        if entries(list).iter().any(|(_, p)| text(p) == Some(id)) {
            continue;
        }
        if c.delete(b"delete_policy ", id) == 0 {
            c.delete(b"delete_check ", id);
        } else {
            c.error(&[&b"Unable to purge DB content for policy '"[..], id, b"'"].concat());
        }
    }
}

struct CheckFields<'a> {
    scan: &'a Json,
    id: &'a Json,
    policy: &'a Json,
    title: &'a Json,
    description: Option<&'a Json>,
    rationale: Option<&'a Json>,
    remediation: Option<&'a Json>,
    compliance: Option<&'a Json>,
    references: Option<&'a Json>,
    file: Option<&'a Json>,
    directory: Option<&'a Json>,
    process: Option<&'a Json>,
    registry: Option<&'a Json>,
    command: Option<&'a Json>,
    result: &'a [u8],
    reason: Option<&'a [u8]>,
}

fn fill_check(c: &mut Cx, ev: &mut Event, f: &CheckFields, before: Option<&[u8]>) {
    c.fill(ev, b"sca.type", b"check");
    let scan = if int(f.scan) >= 0 { int(f.scan).to_string() } else { six(double(f.scan)) };
    c.fill(ev, b"sca.scan_id", scan.as_bytes());
    c.fill(ev, b"sca.policy", text(f.policy).unwrap_or(b""));
    c.fill(ev, b"sca.check.id", &number_text(f.id));
    c.fill(ev, b"sca.check.title", text(f.title).unwrap_or(b""));
    for (k, j) in [(&b"sca.check.description"[..], f.description), (b"sca.check.rationale", f.rationale), (b"sca.check.remediation", f.remediation)] {
        if let Some(j) = j {
            c.fill(ev, k, text(j).unwrap_or(b""));
        }
    }
    for (key, v) in f.compliance.into_iter().flat_map(entries) {
        let value = match v {
            Json::String(s) => Some(cut(s).to_vec()),
            Json::Number { .. } => Some(number_text(v)),
            _ => {
                c.host.log("WARNING", &[&b"Unexpected type for compliance field: "[..], key.unwrap_or(b"(null)"), b". Expected string or number."].concat());
                None
            }
        };
        let mut k = [&b"sca.check.compliance."[..], key.unwrap_or(b"(null)")].concat();
        k.truncate(1023);
        if let Some(v) = value {
            c.fill(ev, &k, &v);
        }
    }
    if let Some(r) = f.references {
        c.fill(ev, b"sca.check.references", text(r).unwrap_or(b""));
    }
    for (k, j) in [(&b"sca.check.file"[..], f.file), (b"sca.check.directory", f.directory), (b"sca.check.registry", f.registry), (b"sca.check.process", f.process), (b"sca.check.command", f.command)] {
        if let Some(j) = j {
            c.fill(ev, k, &super::inventory::csv_json(text(j).unwrap_or(b"")));
        }
    }
    c.fill(ev, b"sca.check.result", f.result);
    if let Some(r) = f.reason {
        c.fill(ev, b"sca.check.reason", r);
    }
    if let Some(b) = before {
        c.fill(ev, b"sca.check.previous_result", b);
    }
}

struct ScanFields<'a> {
    scan: &'a Json,
    name: &'a Json,
    description: Option<&'a Json>,
    passed: &'a Json,
    failed: &'a Json,
    invalid: &'a Json,
    total: &'a Json,
    score: &'a Json,
    file: &'a Json,
    policy_id: &'a Json,
}

fn fill_scan(c: &mut Cx, ev: &mut Event, f: &ScanFields) {
    c.fill(ev, b"sca.type", b"summary");
    c.fill(ev, b"sca.scan_id", &number_text(f.scan));
    if let Some(n) = text(f.name) {
        c.fill(ev, b"sca.policy", n);
    }
    if let Some(d) = f.description.and_then(text) {
        c.fill(ev, b"sca.description", d);
    }
    if let Some(p) = text(f.policy_id) {
        c.fill(ev, b"sca.policy_id", p);
    }
    for (k, j) in [(&b"sca.passed"[..], f.passed), (b"sca.failed", f.failed), (b"sca.invalid", f.invalid), (b"sca.total_checks", f.total), (b"sca.score", f.score)] {
        let v = if int(j) >= 0 {
            int(j).to_string()
        } else if double(j) >= 0.0 {
            six(double(j))
        } else {
            // a negative count ends the fields here
            return;
        };
        c.fill(ev, k, v.as_bytes());
    }
    if let Some(fl) = text(f.file) {
        c.fill(ev, b"sca.file", fl);
    }
}
