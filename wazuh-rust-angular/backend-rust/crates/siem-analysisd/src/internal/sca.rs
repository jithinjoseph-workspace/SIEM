//! Security Configuration Assessment decoder
//! (analysisd/decoders/security_configuration_assessment.c): check results,
//! scan summaries, policy lists and dump-end events from the agents' SCA
//! module are stored in wazuh-db; changes become `sca.*` fields for the
//! rules, and out-of-sync databases make the manager request a dump.

use std::collections::VecDeque;

use siem_cjson::Json;

use crate::daemon::Env;
use crate::event::Event;

/// `SCA_MOD`
pub const SCA_MOD: &str = "sca";
/// `CFGAQUEUE`
pub const CFGAQUEUE: &str = "queue/alerts/cfgaq";
/// `CFGARQUEUE`
pub const CFGARQUEUE: &str = "queue/alerts/cfgarq";
const OS_MAXSTR: usize = 65536;
const OS_SIZE_1024: usize = 1024;
const OS_SIZE_4096: usize = 4096;
/// `queue_init(1024)` holds 1023 requests.
const REQUEST_QUEUE: usize = 1023;

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `->valuestring` (strings only).
fn vs(j: &Json) -> Option<&[u8]> {
    match j {
        Json::String(s) => Some(cstr(s)),
        _ => None,
    }
}

/// `->valueint`
fn vi(j: &Json) -> i32 {
    match j {
        Json::Number { int, .. } => *int,
        _ => 0,
    }
}

/// `->valuedouble`
fn vd(j: &Json) -> f64 {
    match j {
        Json::Number { double, .. } => *double,
        _ => 0.0,
    }
}

/// `printf("%lf")`
fn lf(d: f64) -> String {
    format!("{d:.6}")
}

/// `cJSON_ArrayForEach` with each item's `->string`.
fn items(j: &Json) -> Vec<(Option<&[u8]>, &Json)> {
    match j {
        Json::Object(m) => m.iter().map(|(k, v)| (Some(cstr(k)), v)).collect(),
        Json::Array(a) => a.iter().map(|v| (None, v)).collect(),
        _ => Vec::new(),
    }
}

/// `printf("%s", s)` of a possibly NULL string.
fn s_or_null(s: Option<&[u8]>) -> &[u8] {
    s.unwrap_or(b"(null)")
}

/// `sscanf(s, "%64s")`
fn scan_token(s: &[u8]) -> Vec<u8> {
    let ws = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let start = s.iter().position(|&c| !ws(c)).unwrap_or(s.len());
    s[start..].iter().take(64).take_while(|&&c| !ws(c)).copied().collect()
}

/// `csv_list_to_json_str_array`
pub(crate) fn csv_to_json(s: &[u8]) -> Vec<u8> {
    let a = s.split(|&c| c == b',').filter(|t| !t.is_empty()).map(|t| Json::String(t.to_vec())).collect();
    Json::Array(a).print()
}

/// Process-wide state: the dump request queue drained by `RequestDBThread`.
#[derive(Debug, Default)]
pub struct Sca {
    requests: VecDeque<Vec<u8>>,
}

struct Ctx<'a> {
    env: &'a mut dyn Env,
    agent: Vec<u8>,
    order_size: usize,
}

impl Ctx<'_> {
    fn err(&mut self, m: &[u8]) {
        self.env.log("ERROR", m);
    }

    fn query(&mut self, mut q: Vec<u8>) -> Option<Vec<u8>> {
        // snprintf(msg, OS_MAXSTR - 1, ...)
        q.truncate(OS_MAXSTR - 2);
        self.env.wdb_query_ex(&q, OS_MAXSTR).ok()
    }

    /// The `Find*` queries: (0, payload) found, (1, "") not found, (-1, "").
    fn find(&mut self, what: &[u8], arg: &[u8]) -> (i32, Vec<u8>) {
        let q = cat(&[b"agent ", &self.agent, b" sca ", what, arg]);
        match self.query(q) {
            Some(r) if r.starts_with(b"ok found") => (0, r.get(9..).unwrap_or(b"").to_vec()),
            Some(r) if r == b"ok not found" => (1, Vec::new()),
            _ => (-1, Vec::new()),
        }
    }

    /// The `Delete*` queries.
    fn delete(&mut self, what: &[u8], arg: &[u8]) -> i32 {
        let q = cat(&[b"agent ", &self.agent, b" sca ", what, arg]);
        match self.query(q) {
            Some(r) if r.starts_with(b"ok") => 0,
            Some(r) if r.starts_with(b"err") => 1,
            _ => -1,
        }
    }

    /// The `Save*` queries.
    fn save(&mut self, what: &[u8], arg: &[u8]) -> i32 {
        let q = cat(&[b"agent ", &self.agent, b" sca ", what, arg]);
        if self.query(q).is_some() {
            0
        } else {
            -1
        }
    }

    fn fill(&mut self, ev: &mut Event, k: &[u8], v: &[u8]) {
        crate::plugins::fill_data(ev, Some(k), cstr(v), self.order_size);
    }

    fn db_error(&mut self) {
        let m = cat(&[b"Error querying policy monitoring database for agent '", &self.agent.clone(), b"'"]);
        self.err(&m);
    }
}

impl Sca {
    /// `PushDumpRequest`
    fn push_dump(&mut self, env: &mut dyn Env, agent: &[u8], policy_id: &[u8], first_scan: i32) {
        let mut m = cat(&[agent, b":sca-dump:", policy_id, format!(":{first_scan}").as_bytes()]);
        m.truncate(OS_SIZE_4096 - 1);
        if self.requests.len() >= REQUEST_QUEUE {
            env.log("WARNING", b"SCA request queue is full.");
            return;
        }
        self.requests.push_back(m);
    }

    /// `RequestDBThread`: send the queued dump requests.
    pub fn drain(&mut self, env: &mut dyn Env) {
        while let Some(msg) = self.requests.pop_front() {
            let Some(p) = msg.iter().position(|&c| c == b':') else {
                continue;
            };
            let (agent, dump) = (&msg[..p], &msg[p + 1..]);
            if agent == b"000" {
                env.send_mq(CFGAQUEUE, dump);
            } else {
                env.send_mq(CFGARQUEUE, &msg);
            }
        }
    }

    /// `DecodeSCA`: false when the event goes no further.
    pub fn decode(&mut self, env: &mut dyn Env, dec: usize, order_size: usize, ev: &mut Event) -> bool {
        ev.decoder = dec;
        let log = ev.log().to_vec();
        let Ok((mut event, _)) = siem_cjson::parse_with_opts(&log, false) else {
            env.log("ERROR", b"Malformed configuration assessment JSON event.");
            return true;
        };
        let t = match event.get("type") {
            Some(Json::String(t)) => cstr(t).to_vec(),
            _ => return false,
        };
        let agent = cstr(ev.agent_id.as_deref().unwrap_or(b"")).to_vec();
        let mut c = Ctx { env, agent, order_size };
        match &t[..] {
            b"check" => self.check(&mut c, ev, &mut event),
            b"summary" => self.summary(&mut c, ev, &event),
            b"policies" => self.policies(&mut c, &event),
            b"dump_end" => self.dump_end(&mut c, &event),
            _ => {}
        }
        true
    }

    /// `HandleCheckEvent` (with `CheckEventJSON`).
    fn check(&mut self, c: &mut Ctx, ev: &mut Event, event: &mut Json) {
        let malformed = |c: &mut Ctx, m: &str| c.err(format!("Malformed JSON: {m}").as_bytes());
        // CheckEventJSON
        let Some(scan_id) = event.get("id").cloned() else {
            return malformed(c, "field 'id' not found.");
        };
        if !scan_id.is_number() {
            return malformed(c, "field 'id' must be a number.");
        }
        let Some(name) = event.get("policy").cloned() else {
            return malformed(c, "field 'policy' not found.");
        };
        if vs(&name).is_none() {
            return malformed(c, "field 'policy' must be a string.");
        }
        let Some(policy_id) = event.get("policy_id") else {
            return malformed(c, "field 'policy_id' not found.");
        };
        if vs(policy_id).is_none() {
            return malformed(c, "field 'policy_id' must be a string.");
        }
        let Some(check) = event.get_mut("check") else {
            return malformed(c, "field 'check' not found.");
        };
        let Some(id) = check.get("id").cloned() else {
            return malformed(c, "field 'id' not found.");
        };
        if !id.is_number() {
            return malformed(c, "field 'id' must be a number.");
        }
        let Some(title) = check.get("title").cloned() else {
            return malformed(c, "field 'title' not found.");
        };
        if vs(&title).is_none() {
            return malformed(c, "field 'title' must be a string.");
        }
        let opt = |c: &mut Ctx, key: &str, msg: &str| -> Result<Option<Json>, ()> {
            match check.get(key) {
                Some(j) if vs(j).is_none() => {
                    c.err(msg.as_bytes());
                    Err(())
                }
                other => Ok(other.cloned()),
            }
        };
        let Ok(description) = opt(c, "description", "Malformed JSON: field 'description' must be a string.") else { return };
        let Ok(rationale) = opt(c, "rationale", "Malformed JSON: field 'rationale' must be a string.") else { return };
        let Ok(remediation) = opt(c, "remediation", "Malformed JSON: field 'remediation' must be a string.") else { return };
        let Ok(reference) = opt(c, "references", "Malformed JSON: field 'reference' must be a string.") else { return };
        let compliance = check.get("compliance").cloned();
        let Ok(file) = opt(c, "file", "Malformed JSON: field 'file' must be a string.") else { return };
        let Ok(_condition) = opt(c, "condition", "Malformed JSON: field 'condition' must be a string") else { return };
        let Ok(directory) = opt(c, "directory", "Malformed JSON: field 'directory' must be a string.") else { return };
        let Ok(process) = opt(c, "process", "Malformed JSON: field 'process' must be a string.") else { return };
        let Ok(registry) = opt(c, "registry", "Malformed JSON: field 'registry' must be a string.") else { return };
        let Ok(command) = opt(c, "command", "Malformed JSON: field 'command' must be a string.") else { return };
        let rules = check.get("rules").cloned();
        let Ok(reason) = opt(c, "reason", "Malformed JSON: field 'reason' must be a string.") else { return };
        let result = match check.get("result") {
            None => {
                let r = Json::String(b"not applicable".to_vec());
                check.add("result", r.clone());
                r
            }
            Some(r) => {
                if vs(r).is_none() {
                    return malformed(c, "field 'result' must be a string.");
                }
                r.clone()
            }
        };
        let result_s = vs(&result).unwrap_or(b"").to_vec();
        let reason_s = reason.as_ref().and_then(vs).map(|r| r.to_vec());
        let idn = vi(&id);
        let scan = vi(&scan_id);

        let (found, old) = c.find(b"query ", idn.to_string().as_bytes());
        let fields = CheckFields {
            scan_id: &scan_id,
            id: &id,
            name: &name,
            title: &title,
            description: description.as_ref(),
            rationale: rationale.as_ref(),
            remediation: remediation.as_ref(),
            compliance: compliance.as_ref(),
            reference: reference.as_ref(),
            file: file.as_ref(),
            directory: directory.as_ref(),
            process: process.as_ref(),
            registry: registry.as_ref(),
            command: command.as_ref(),
            result: &result_s,
            reason: reason_s.as_deref(),
        };
        match found {
            -1 => c.db_error(),
            0 => {
                let arg = cat(&[
                    format!("{idn}|").as_bytes(),
                    &result_s,
                    b"|",
                    reason_s.as_deref().unwrap_or(b""),
                    format!("|{scan}").as_bytes(),
                ]);
                let r = c.save(b"update ", &arg);
                if old != result_s {
                    fill_check(c, ev, &fields, Some(&old));
                }
                if r < 0 {
                    let m = cat(&[b"Error updating policy monitoring database for agent '", &c.agent.clone(), b"'"]);
                    c.err(&m);
                }
            }
            1 => {
                let r = c.save(b"insert ", &event.print_unformatted());
                if old != result_s {
                    fill_check(c, ev, &fields, None);
                }
                if r < 0 {
                    let m = cat(&[b"Error storing policy monitoring information for agent '", &c.agent.clone(), b"'"]);
                    c.err(&m);
                    return;
                }
                if let Some(comp) = &compliance {
                    for (key, v) in items(comp) {
                        let value = match v {
                            Json::String(s) => cstr(s).to_vec(),
                            Json::Number { double, int } => {
                                if *double == *int as f64 { int.to_string().into_bytes() } else { lf(*double).into_bytes() }
                            }
                            // SaveCompliance asserts a value (the C daemon aborts)
                            _ => continue,
                        };
                        let arg = cat(&[format!("{idn}|").as_bytes(), s_or_null(key), b"|", &value]);
                        c.save(b"insert_compliance ", &arg);
                    }
                }
                if let Some(rules) = &rules {
                    for (_, rule) in items(rules) {
                        let Some(rv) = vs(rule) else { continue };
                        let flag = rv.first().copied().unwrap_or(0);
                        let ty: &[u8] = match flag {
                            b'f' => b"file",
                            b'd' => b"directory",
                            b'r' => b"registry",
                            b'c' => b"command",
                            b'p' => b"process",
                            b'n' => b"numeric",
                            _ => {
                                c.err(&[&b"Invalid type: "[..], &[flag]].concat());
                                continue;
                            }
                        };
                        let arg = cat(&[format!("{idn}|").as_bytes(), ty, b"|", rv]);
                        c.save(b"insert_rules ", &arg);
                    }
                }
            }
            _ => {}
        }
    }

    /// `HandleScanInfo`
    fn summary(&mut self, c: &mut Ctx, ev: &mut Event, event: &Json) {
        let g = |k: &str| event.get(k);
        let malformed = |c: &mut Ctx, m: &str| c.err(format!("Malformed JSON: {m}").as_bytes());
        let Some(policy_id) = g("policy_id") else { return };
        let Some(pid) = vs(policy_id) else {
            return malformed(c, "field 'policy_id' must be a string.");
        };
        let Some(scan_id) = g("scan_id") else { return };
        if !scan_id.is_number() {
            return malformed(c, "field 'scan_id' must be a number.");
        }
        if vi(scan_id) < 0 {
            return malformed(c, "field 'scan_id' cannot be negative.");
        }
        let need = |c: &mut Ctx, k: &str, name: &str| -> Option<&Json> {
            let r = g(k);
            if r.is_none() {
                c.err(format!("Malformed JSON: field '{name}' not found.").as_bytes());
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
        let Some(hash) = vs(hash) else {
            return malformed(c, "field 'hash' must be a string.");
        };
        let Some(hash_file) = need(c, "hash_file", "hash_file") else { return };
        let Some(hash_file) = vs(hash_file) else {
            return malformed(c, "field 'hash_file' must be a string.");
        };
        let Some(file) = need(c, "file", "file") else { return };
        if vs(file).is_none() {
            return malformed(c, "field 'file' must be a string.");
        }
        let Some(policy) = need(c, "name", "policy") else { return };
        if vs(policy).is_none() {
            return malformed(c, "field 'policy' must be a string.");
        }
        let description = g("description");
        let references = g("references");
        let first_scan = g("first_scan").is_some();
        let force_alert = g("force_alert").is_some();
        let info = ScanFields { scan_id, name: policy, description, pass: passed, failed, invalid, total, score, file, policy_id };

        let (result_db, scan_info) = c.find(b"query_scan ", pid);
        let hash_sha256 = scan_token(&scan_info);
        let mut filled = false;
        let nums = [vi(start), vi(end)];
        let counts = [vi(passed), vi(failed), vi(invalid), vi(total), vi(score)];
        match result_db {
            -1 => c.db_error(),
            0 | 1 => {
                let update = result_db == 0;
                let arg = if !update {
                    cat(&[
                        format!("{}|{}|{}|", nums[0], nums[1], vi(scan_id)).as_bytes(),
                        pid,
                        format!("|{}|{}|{}|{}|{}|", counts[0], counts[1], counts[2], counts[3], counts[4]).as_bytes(),
                        hash,
                    ])
                } else {
                    cat(&[
                        pid,
                        format!(
                            "|{}|{}|{}|{}|{}|{}|{}|{}|",
                            nums[0],
                            nums[1],
                            vi(scan_id),
                            counts[0],
                            counts[1],
                            counts[2],
                            counts[3],
                            counts[4]
                        )
                        .as_bytes(),
                        hash,
                    ])
                };
                let r = c.save(if update { b"update_scan_info_start " } else { b"insert_scan_info " }, &arg);
                if r < 0 {
                    let m = if update {
                        cat(&[b"Error updating scan policy monitoring database for agent '", &c.agent.clone(), b"'"])
                    } else {
                        cat(&[b"Error storing scan policy monitoring information for agent '", &c.agent.clone(), b"'"])
                    };
                    c.err(&m);
                } else {
                    if hash_sha256 != hash {
                        if !first_scan {
                            fill_scan(c, ev, &info);
                            filled = true;
                        } else if !update {
                            let agent = c.agent.clone();
                            self.push_dump(c.env, &agent, pid, 1);
                        }
                    }
                    if force_alert && !filled {
                        fill_scan(c, ev, &info);
                    }
                }
            }
            _ => {}
        }

        let (result_db, _) = c.find(b"query_policy ", pid);
        match result_db {
            -1 => c.db_error(),
            1 => {
                let mut references_db: Option<&[u8]> = None;
                let mut description_db: Option<&[u8]> = None;
                if let Some(r) = references {
                    let Some(r) = vs(r) else {
                        return malformed(c, "field 'references' must be a string");
                    };
                    references_db = Some(r);
                }
                if let Some(d) = description {
                    let Some(d) = vs(d) else {
                        return malformed(c, "field 'description' must be a string");
                    };
                    description_db = Some(d);
                }
                let arg = cat(&[
                    vs(policy).unwrap_or(b""),
                    b"|",
                    vs(file).unwrap_or(b""),
                    b"|",
                    pid,
                    b"|",
                    description_db.unwrap_or(b"NULL"),
                    b"|",
                    references_db.unwrap_or(b"NULL"),
                    b"|",
                    hash_file,
                ]);
                if c.save(b"insert_policy ", &arg) < 0 {
                    let m = cat(&[b"Error storing scan policy monitoring information for agent '", &c.agent.clone(), b"'"]);
                    c.err(&m);
                }
            }
            _ => {
                let (r, old_hash) = c.find(b"query_policy_sha256 ", pid);
                if r == 0 && hash_file != &old_hash[..] {
                    match c.delete(b"delete_policy ", pid) {
                        0 => {
                            c.delete(b"delete_check ", pid);
                            let agent = c.agent.clone();
                            self.push_dump(c.env, &agent, pid, 1);
                            let m = cat(&[
                                b"Policy '",
                                pid,
                                b"' information for agent '",
                                &agent,
                                b"' is outdated. Requested latest scan results.",
                            ]);
                            c.env.log("INFO", &m);
                        }
                        _ => c.err(&cat(&[b"Unable to purge DB content for policy '", pid, b"'"])),
                    }
                }
            }
        }

        let (result_db, results) = c.find(b"query_results ", pid);
        let agent = c.agent.clone();
        match result_db {
            0 => {
                if results != hash {
                    self.push_dump(c.env, &agent, pid, first_scan as i32);
                }
            }
            1 => self.push_dump(c.env, &agent, pid, first_scan as i32),
            _ => c.db_error(),
        }
    }

    /// `HandlePoliciesInfo`
    fn policies(&mut self, c: &mut Ctx, event: &Json) {
        let Some(policies) = event.get("policies") else {
            c.err(b"Malformed JSON: field 'policies' not found.");
            return;
        };
        let (r, ids) = c.find(b"query_policies ", b"");
        if r == -1 {
            c.db_error();
            return;
        }
        for p_id in ids.split(|&b| b == b',').filter(|t| !t.is_empty()) {
            let exists = items(policies).iter().any(|(_, p)| vs(p) == Some(p_id));
            if !exists {
                match c.delete(b"delete_policy ", p_id) {
                    0 => {
                        c.delete(b"delete_check ", p_id);
                    }
                    _ => c.err(&cat(&[b"Unable to purge DB content for policy '", p_id, b"'"])),
                }
            }
        }
    }

    /// `HandleDumpEvent`
    fn dump_end(&mut self, c: &mut Ctx, event: &Json) {
        if event.get("elements_sent").is_none() {
            c.err(b"Malformed JSON: field 'elements_sent' not found.");
            return;
        }
        let Some(policy_id) = event.get("policy_id") else {
            c.err(b"Malformed JSON: field 'policy_id' not found.");
            return;
        };
        let Some(pid) = vs(policy_id) else {
            c.err(b"Malformed JSON: field 'policy_id' must be a string.");
            return;
        };
        let Some(scan_id) = event.get("scan_id") else {
            c.err(b"Malformed JSON: field 'scan_id' not found.");
            return;
        };
        let arg = cat(&[pid, format!("|{}", vi(scan_id)).as_bytes()]);
        if c.delete(b"delete_check_distinct ", &arg) == -1 {
            c.db_error();
        }
        let (r, results) = c.find(b"query_results ", pid);
        if r == 0 {
            let (rh, info) = c.find(b"query_scan ", pid);
            let hash = scan_token(&info);
            if rh == 0 && results != hash {
                let agent = c.agent.clone();
                self.push_dump(c.env, &agent, pid, 0);
            }
        }
    }
}

struct CheckFields<'a> {
    scan_id: &'a Json,
    id: &'a Json,
    name: &'a Json,
    title: &'a Json,
    description: Option<&'a Json>,
    rationale: Option<&'a Json>,
    remediation: Option<&'a Json>,
    compliance: Option<&'a Json>,
    reference: Option<&'a Json>,
    file: Option<&'a Json>,
    directory: Option<&'a Json>,
    process: Option<&'a Json>,
    registry: Option<&'a Json>,
    command: Option<&'a Json>,
    result: &'a [u8],
    reason: Option<&'a [u8]>,
}

/// `FillCheckEventInfo`
fn fill_check(c: &mut Ctx, ev: &mut Event, f: &CheckFields, old_result: Option<&[u8]>) {
    c.fill(ev, b"sca.type", b"check");
    let v = if vi(f.scan_id) >= 0 { vi(f.scan_id).to_string() } else { lf(vd(f.scan_id)) };
    c.fill(ev, b"sca.scan_id", v.as_bytes());
    c.fill(ev, b"sca.policy", vs(f.name).unwrap_or(b""));
    let v = if vd(f.id) == vi(f.id) as f64 { vi(f.id).to_string() } else { lf(vd(f.id)) };
    c.fill(ev, b"sca.check.id", v.as_bytes());
    c.fill(ev, b"sca.check.title", vs(f.title).unwrap_or(b""));
    for (k, j) in [
        (&b"sca.check.description"[..], f.description),
        (b"sca.check.rationale", f.rationale),
        (b"sca.check.remediation", f.remediation),
    ] {
        if let Some(j) = j {
            c.fill(ev, k, vs(j).unwrap_or(b""));
        }
    }
    if let Some(comp) = f.compliance {
        for (key, v) in items(comp) {
            let value = match v {
                Json::String(s) => Some(cstr(s).to_vec()),
                Json::Number { double, int } => {
                    Some(if *double == *int as f64 { int.to_string().into_bytes() } else { lf(*double).into_bytes() })
                }
                _ => {
                    c.env.log(
                        "WARNING",
                        &cat(&[b"Unexpected type for compliance field: ", s_or_null(key), b". Expected string or number."]),
                    );
                    None
                }
            };
            let mut k = cat(&[b"sca.check.compliance.", s_or_null(key)]);
            k.truncate(OS_SIZE_1024 - 1);
            if let Some(v) = value {
                c.fill(ev, &k, &v);
            }
        }
    }
    if let Some(r) = f.reference {
        c.fill(ev, b"sca.check.references", vs(r).unwrap_or(b""));
    }
    for (k, j) in [
        (&b"sca.check.file"[..], f.file),
        (b"sca.check.directory", f.directory),
        (b"sca.check.registry", f.registry),
        (b"sca.check.process", f.process),
        (b"sca.check.command", f.command),
    ] {
        if let Some(j) = j {
            c.fill(ev, k, &csv_to_json(vs(j).unwrap_or(b"")));
        }
    }
    c.fill(ev, b"sca.check.result", f.result);
    if let Some(r) = f.reason {
        c.fill(ev, b"sca.check.reason", r);
    }
    if let Some(o) = old_result {
        c.fill(ev, b"sca.check.previous_result", o);
    }
}

struct ScanFields<'a> {
    scan_id: &'a Json,
    name: &'a Json,
    description: Option<&'a Json>,
    pass: &'a Json,
    failed: &'a Json,
    invalid: &'a Json,
    total: &'a Json,
    score: &'a Json,
    file: &'a Json,
    policy_id: &'a Json,
}

/// `FillScanInfo`
fn fill_scan(c: &mut Ctx, ev: &mut Event, f: &ScanFields) {
    c.fill(ev, b"sca.type", b"summary");
    let v = if vd(f.scan_id) == vi(f.scan_id) as f64 { vi(f.scan_id).to_string() } else { lf(vd(f.scan_id)) };
    c.fill(ev, b"sca.scan_id", v.as_bytes());
    if let Some(n) = vs(f.name) {
        c.fill(ev, b"sca.policy", n);
    }
    if let Some(d) = f.description.and_then(vs) {
        c.fill(ev, b"sca.description", d);
    }
    if let Some(p) = vs(f.policy_id) {
        c.fill(ev, b"sca.policy_id", p);
    }
    for (k, j) in [
        (&b"sca.passed"[..], f.pass),
        (b"sca.failed", f.failed),
        (b"sca.invalid", f.invalid),
        (b"sca.total_checks", f.total),
        (b"sca.score", f.score),
    ] {
        let v = if vi(j) >= 0 {
            vi(j).to_string()
        } else if vd(j) >= 0.0 {
            lf(vd(j))
        } else {
            // "Unexpected 'sca.<x>' type" (debug): the remaining fields are skipped
            return;
        };
        c.fill(ev, k, v.as_bytes());
    }
    if let Some(fl) = vs(f.file) {
        c.fill(ev, b"sca.file", fl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(scan_token(b"  abc def"), b"abc");
        assert_eq!(scan_token(&[b'a'; 70]), vec![b'a'; 64]);
        assert_eq!(csv_to_json(b"/a,,/b"), br#"["/a", "/b"]"#);
        assert_eq!(csv_to_json(b""), b"[]");
        assert_eq!(lf(1.5), "1.500000");
    }
}
