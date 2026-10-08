//! File integrity monitoring decoder (analysisd/decoders/syscheck.c): legacy
//! checksum messages (agents before 3.11) are compared with the agent's
//! FIM database, JSON events (3.11+) carry their own old/new attributes;
//! both become `syscheck_*` events with the FIM dynamic fields and a
//! human readable `full_log`.

use std::collections::HashMap;

use siem_cjson::Json;

use crate::daemon::Env;
use crate::decoders::Decoders;
use crate::event::{Event, F_LOCATION};
use crate::internal::syscheck_op::*;
use crate::syscheck_json::fim;

const OS_MAXSTR: usize = 65536;
const OS_SIZE_6144: usize = 6144;
const OS_FLSIZE: usize = 256;

pub const FIM_MOD: &str = "syscheck_integrity_changed";
pub const FIM_NEW: &str = "syscheck_new_entry";
pub const FIM_DEL: &str = "syscheck_deleted";
pub const FIM_REG_KEY_MOD: &str = "syscheck_registry_key_modified";
pub const FIM_REG_KEY_NEW: &str = "syscheck_registry_key_added";
pub const FIM_REG_KEY_DEL: &str = "syscheck_registry_key_deleted";
pub const FIM_REG_VAL_MOD: &str = "syscheck_registry_value_modified";
pub const FIM_REG_VAL_NEW: &str = "syscheck_registry_value_added";
pub const FIM_REG_VAL_DEL: &str = "syscheck_registry_value_deleted";

/// `sdb_init`'s field names.
pub const FIELD_NAMES: [&str; fim::NFIELDS] = [
    "file",
    "hard_links",
    "mode",
    "size",
    "size_before",
    "perm",
    "perm_before",
    "uid",
    "uid_before",
    "gid",
    "gid_before",
    "md5",
    "md5_before",
    "sha1",
    "sha1_before",
    "uname",
    "uname_before",
    "gname",
    "gname_before",
    "mtime",
    "mtime_before",
    "inode",
    "inode_before",
    "sha256",
    "sha256_before",
    "changed_content",
    "win_attributes",
    "win_attributes_before",
    "changed_fields",
    "user_id",
    "user_name",
    "group_id",
    "group_name",
    "process_name",
    "parent_name",
    "cwd",
    "parent_cwd",
    "audit_uid",
    "audit_name",
    "effective_uid",
    "effective_name",
    "ppid",
    "process_id",
    "tag",
    "symbolic_path",
    "arch",
    "value_name",
    "value_type",
    "hash_full_path",
    "entry_type",
    "event_type",
];

/// `fim_decoders_t` (ids looked up by name in the decoder store).
#[derive(Debug, Clone, Copy, Default)]
pub struct FimIds {
    pub add: [u16; 3],
    pub modify: [u16; 3],
    pub delete: [u16; 3],
}

const NAMES_ADD: [&str; 3] = [FIM_NEW, FIM_REG_KEY_NEW, FIM_REG_VAL_NEW];
const NAMES_MOD: [&str; 3] = [FIM_MOD, FIM_REG_KEY_MOD, FIM_REG_VAL_MOD];
const NAMES_DEL: [&str; 3] = [FIM_DEL, FIM_REG_KEY_DEL, FIM_REG_VAL_DEL];

impl FimIds {
    /// `fim_init` / `fim_hot_reload`
    pub fn load(d: &Decoders) -> FimIds {
        let mut f = FimIds::default();
        for i in 0..3 {
            f.add[i] = d.get_decoder_from_list(NAMES_ADD[i]);
            f.modify[i] = d.get_decoder_from_list(NAMES_MOD[i]);
            f.delete[i] = d.get_decoder_from_list(NAMES_DEL[i]);
        }
        f
    }
}

/// The `syscheck_*` options of `<global>` the decoder reads.
#[derive(Debug, Clone, Copy)]
pub struct FimConfig {
    pub alert_new: bool,
    pub auto_ignore: bool,
    pub ignore_time: i64,
    pub ignore_frequency: i32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EventType {
    Added,
    Modified,
    Deleted,
}

/// Process-wide FIM state: `fim_agentinfo` (end of the first scan per agent).
#[derive(Debug, Default)]
pub struct Fim {
    agentinfo: HashMap<B, i64>,
}

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn cat(p: &[&[u8]]) -> B {
    p.concat()
}

/// `snprintf(buf, size, "%s")`
fn trunc(mut v: B, size: usize) -> B {
    v.truncate(size.saturating_sub(1));
    v
}

/// `printf("%s")` of a possibly NULL string
fn s(v: &Option<B>) -> &[u8] {
    v.as_deref().unwrap_or(b"(null)")
}

/// `ctime_r` without the newline
fn ctime(t: i64) -> Option<String> {
    crate::localtime::ctime(t).map(|s| s.trim_end_matches('\n').to_string())
}

/// `wm_strcat(dst, src, sep)`
fn strcat(dst: &mut Option<B>, src: &[u8], sep: u8) {
    match dst {
        Some(d) => {
            if sep != 0 {
                d.push(sep);
            }
            d.extend_from_slice(src);
        }
        None => *dst = Some(src.to_vec()),
    }
}

struct Ctx<'a> {
    env: &'a mut dyn Env,
    agent: B,
}

impl Ctx<'_> {
    fn err(&mut self, m: &[u8]) {
        self.env.log("ERROR", m);
    }

    /// `wdbc_query_ex(&sdb->socket, query, response, OS_SIZE_6144)` with the
    /// query cut like `snprintf(.., OS_SIZE_6144, ..)`.
    fn query(&mut self, mut q: B, bad: &str) -> Result<B, i32> {
        q.truncate(OS_SIZE_6144 - 1);
        match self.env.wdb_query_ex(&q, OS_SIZE_6144) {
            Ok(r) => Ok(r),
            Err(c) => {
                if c == -2 {
                    self.err(&cat(&[bad.as_bytes(), b" '", &q, b"'."]));
                }
                Err(c)
            }
        }
    }

    /// `fim_send_db_query`
    fn send_db_query(&mut self, q: &[u8]) {
        let r = match self.env.wdb_query_ex(q, OS_MAXSTR) {
            Ok(r) => r,
            Err(-2) => return self.err(b"FIM decoder: Cannot communicate with database."),
            Err(_) => return self.err(b"FIM decoder: Cannot get response from database."),
        };
        let (head, arg) = match r.iter().position(|&c| c == b' ') {
            Some(p) => (&r[..p], &r[p + 1..]),
            None => (&r[..], &r[..]),
        };
        if head == b"err" && arg != b"Agent not found" {
            self.err(&cat(&[b"FIM decoder: Bad response from database: ", arg]));
        }
    }

    /// `fim_get_scantime`
    fn get_scantime(&mut self, param: &str) -> Option<i64> {
        let q = cat(&[b"agent ", &self.agent, b" syscheck scan_info_get ", param.as_bytes()]);
        let r = self.query(q, "FIM decoder: Bad result getting scan date").ok()?;
        let Some(p) = r.iter().position(|&c| c == b' ') else {
            self.err(&cat(&[b"FIM decoder: Bad formatted response '", &r, b"'"]));
            return None;
        };
        Some(atol(&r[p + 1..]))
    }
}

impl Fim {
    /// The syscheck decoder thread: `decode_fim_event` for JSON messages,
    /// `DecodeSyscheck` otherwise. True when the event goes on to the rules.
    #[allow(clippy::too_many_arguments)]
    pub fn decode(&mut self, env: &mut dyn Env, decs: &mut Decoders, dec: usize, ids: &FimIds, cfg: &FimConfig, ev: &mut Event) -> bool {
        ev.decoder = dec;
        let agent = cstr(ev.agent_id.as_deref().unwrap_or(b"")).to_vec();
        let mut c = Ctx { env, agent };
        if ev.log().first() == Some(&b'{') {
            self.decode_json(&mut c, decs, dec, ids, ev)
        } else {
            self.decode_legacy(&mut c, decs, dec, ids, cfg, ev) == 1
        }
    }

    /* ------------------------------------------------------- legacy */

    /// `DecodeSyscheck`
    fn decode_legacy(&mut self, c: &mut Ctx, decs: &mut Decoders, dec: usize, ids: &FimIds, cfg: &FimConfig, ev: &mut Event) -> i32 {
        let log = ev.log().to_vec();
        let Some(sp) = wstr_chr(&log, b' ') else {
            return match self.control_msg(c, &log, ev.time.sec) {
                -2 | -1 => -1,
                0 => {
                    c.err(b"(1277): Invalid syscheck message received.");
                    -1
                }
                _ => 0,
            };
        };
        let mut rest = log[sp + 1..].to_vec();
        normalize_path(&mut rest);
        let mut vals: Vec<Option<B>> = vec![None; fim::NFIELDS];
        let f_name = match rest.iter().position(|&ch| ch == b'\n') {
            Some(p) => {
                vals[fim::DIFF] = Some(rest[p + 1..].to_vec());
                rest[..p].to_vec()
            }
            None => rest,
        };
        let full = &log[..sp];
        let (c_sum, w_sum) = match wstr_chr(full, b'!') {
            Some(p) => (&full[..p], Some(&full[p + 1..])),
            None => (full, None),
        };
        self.db_search(c, decs, dec, ids, cfg, ev, &f_name, c_sum, w_sum, vals)
    }

    /// `fim_db_search`
    #[allow(clippy::too_many_arguments)]
    fn db_search(
        &mut self,
        c: &mut Ctx,
        decs: &mut Decoders,
        dec: usize,
        ids: &FimIds,
        cfg: &FimConfig,
        ev: &mut Event,
        f_name: &[u8],
        c_sum: &[u8],
        w_sum: Option<&[u8]>,
        mut vals: Vec<Option<B>>,
    ) -> i32 {
        let agent = c.agent.clone();
        let mut oldsum = Sum::default();
        let mut newsum = Sum::default();
        let q = cat(&[b"agent ", &agent, b" syscheck load ", f_name]);
        let mut q6 = q.clone();
        q6.truncate(OS_SIZE_6144 - 1);
        let Ok(response) = c.query(q, "FIM decoder: Bad load query:") else {
            return -1;
        };
        let Some(p) = wstr_chr(&response, b' ') else {
            c.err(&cat(&[b"FIM decoder: Bad response: '", &q6, b"' '", &response, b"'."]));
            return -1;
        };
        if &response[..p] != b"ok" {
            return -1;
        }
        let (old_check_sum, _) = sk_decode_extradata(&mut oldsum, &response[p + 1..]);
        let decode_newsum = sk_decode_sum(&mut newsum, c_sum, w_sum);
        let new_check_sum = adjust_checksum(&newsum, c_sum);

        if sum_compare(&old_check_sum, &new_check_sum) == 0 {
            let q = cat(&[b"agent ", &agent, b" syscheck updatedate ", f_name]);
            let _ = c.query(q, "FIM decoder: Bad result updating date field:");
            return 0;
        }

        let event_type;
        let mut changes = 0;
        match decode_newsum {
            1 => {
                vals[fim::EVENT_TYPE] = Some(b"deleted".to_vec());
                event_type = EventType::Deleted;
                if old_check_sum.is_empty() {
                    return 0;
                }
                let q = cat(&[b"agent ", &agent, b" syscheck delete ", f_name]);
                if c.query(q, "FIM decoder: Bad delete query:").is_err() {
                    return -1;
                }
            }
            0 => {
                if !old_check_sum.is_empty() {
                    vals[fim::EVENT_TYPE] = Some(b"modified".to_vec());
                    event_type = EventType::Modified;
                    changes = check_changes(cfg, oldsum.changes, oldsum.date_alert, ev.time.sec);
                    sk_decode_sum(&mut oldsum, &old_check_sum, None);
                    if changes == -1 {
                        return 0;
                    }
                } else {
                    vals[fim::EVENT_TYPE] = Some(b"added".to_vec());
                    event_type = EventType::Added;
                }
                let loc = ev.f[F_LOCATION].clone().unwrap_or_default();
                let ttype: &[u8] = if cstr(&loc).windows(17).any(|w| w == b"syscheck-registry") { b"registry" } else { b"file" };
                let sym = newsum.symbolic_path.as_deref().map(escape_field);
                let esc = replace(&new_check_sum, b" ", b"\\ ");
                let q = cat(&[
                    b"agent ",
                    &agent,
                    b" syscheck save ",
                    ttype,
                    b" ",
                    &esc,
                    format!("!{changes}:{}:", ev.time.sec).as_bytes(),
                    sym.as_deref().unwrap_or(b""),
                    b" ",
                    f_name,
                ]);
                if c.query(q, "FIM decoder: Bad save/update query:").is_err() {
                    return -1;
                }
                let end_scan = match self.agentinfo.get(&agent) {
                    Some(v) => *v,
                    None => {
                        let v = c.get_scantime("end_scan").unwrap_or(0);
                        self.agentinfo.insert(agent.clone(), v);
                        v
                    }
                };
                if event_type == EventType::Added && (end_scan == 0 || ev.time.sec < end_scan || !cfg.alert_new) {
                    return 0;
                }
            }
            _ => {
                c.env.log(
                    "WARNING",
                    &cat(&[
                        b"at fim_db_search: Agent '",
                        &agent,
                        b"' Couldn't decode fim sum '",
                        &new_check_sum,
                        b"' from file '",
                        f_name,
                        b"'.",
                    ]),
                );
                return -1;
            }
        }

        if newsum.silent {
            return 0;
        }
        sk_fill_event(&mut vals, f_name, &newsum);
        if fim_alert(decs, dec, ids, ev, f_name, &mut oldsum, &newsum, event_type, &mut vals) == -1 {
            return 0;
        }
        set_fields(ev, vals);
        1
    }

    /// `fim_control_msg`: 1 handled, 0 not a control message, <0 error.
    fn control_msg(&mut self, c: &mut Ctx, key: &[u8], value: i64) -> i32 {
        const SFS: &[u8] = b"fim-db-start-first-scan";
        const EFS: &[u8] = b"fim-db-end-first-scan";
        const SS: &[u8] = b"fim-db-start-scan";
        const ES: &[u8] = b"fim-db-end-scan";
        const COMPLETED: &[u8] = b"syscheck-db-completed";
        let mut msg: &[u8] = b"";
        if key == SFS {
            msg = b"first_start";
        }
        if key == EFS {
            if c.get_scantime("start_scan") == Some(0) {
                return -1;
            }
            msg = b"first_end";
        }
        if key == SS {
            msg = b"start_scan";
        }
        if key == ES {
            if c.get_scantime("start_scan") == Some(0) {
                return -1;
            }
            msg = b"end_scan";
        }
        if key == COMPLETED {
            msg = b"end_scan";
        }
        if msg.is_empty() {
            return 0;
        }
        let agent = c.agent.clone();
        let q = cat(&[b"agent ", &agent, b" syscheck scan_info_update ", msg, format!(" {value}").as_bytes()]);
        if let Err(code) = c.query(q, "FIM decoder: Bad result from scan_info query:") {
            return code;
        }
        if key == EFS || key == ES || key == COMPLETED {
            match self.agentinfo.get_mut(&agent) {
                None => {
                    self.agentinfo.insert(agent.clone(), value + 2);
                }
                Some(v) => *v = value,
            }
        }
        if key == SFS {
            let q = cat(&[b"agent ", &agent, format!(" syscheck control {value}").as_bytes()]);
            if let Err(code) = c.query(q, "FIM decoder: Bad result from checks control query:") {
                return code;
            }
        }
        if key == EFS {
            let q = cat(&[b"agent ", &agent, b" syscheck cleandb "]);
            let _ = c.query(q, "FIM decoder: Bad result from cleandb query:");
        }
        1
    }

    /* --------------------------------------------------------- JSON */

    /// `decode_fim_event`
    fn decode_json(&mut self, c: &mut Ctx, decs: &mut Decoders, dec: usize, ids: &FimIds, ev: &mut Event) -> bool {
        let log = ev.log().to_vec();
        let Ok((mut root, _)) = siem_cjson::parse_with_opts(&log, false) else {
            c.err(b"Malformed FIM JSON event");
            return false;
        };
        let ty = match root.get("type") {
            Some(Json::String(t)) => Some(cstr(t).to_vec()),
            _ => None,
        };
        let (Some(ty), true) = (ty, root.get("data").is_some()) else {
            c.err(b"Invalid FIM event");
            return false;
        };
        let data = root.get_mut("data").unwrap();
        match &ty[..] {
            b"event" => {
                if process_alert(c, decs, dec, ids, ev, data) == -1 {
                    c.err(&cat(&[b"Can't generate fim alert for event: '", &log, b"'"]));
                    return false;
                }
                true
            }
            b"scan_start" | b"scan_end" => {
                let which: &[u8] = if &ty[..] == b"scan_start" { b"start_scan" } else { b"end_scan" };
                match data.get("timestamp") {
                    Some(Json::Number { double, .. }) => {
                        let q = cat(&[
                            b"agent ",
                            &c.agent.clone(),
                            b" syscheck scan_info_update ",
                            which,
                            format!(" {}", c_long(*double)).as_bytes(),
                        ]);
                        if q.len() >= OS_SIZE_6144 {
                            c.err(b"FIM decoder: Cannot build save query: input is too long.");
                        } else {
                            c.send_db_query(&q);
                        }
                    }
                    _ => {}
                }
                false
            }
            _ => false,
        }
    }
}

/// The dynamic fields of a decoded FIM event (`lf->nfields = FIM_NFIELDS`).
fn set_fields(ev: &mut Event, vals: Vec<Option<B>>) {
    ev.fields = FIELD_NAMES
        .iter()
        .zip(vals)
        .map(|(k, v)| crate::event::DynamicField { key: k.as_bytes().to_vec(), value: v })
        .collect();
}

/// `fim_check_changes`
fn check_changes(cfg: &FimConfig, saved_frequency: i32, saved_time: i64, now: i64) -> i32 {
    if !cfg.auto_ignore {
        return 1;
    }
    if now - saved_time < cfg.ignore_time {
        if saved_frequency >= cfg.ignore_frequency {
            -1
        } else {
            saved_frequency + 1
        }
    } else {
        1
    }
}

/// `SumCompare`
fn sum_compare(s1: &[u8], s2: &[u8]) -> i32 {
    if s1.len() != s2.len() {
        return 1;
    }
    let colon = |s: &[u8], from: usize| s[from..].iter().position(|&c| c == b':').map(|p| p + from);
    let mut p1 = colon(s1, 0);
    let mut p2 = colon(s2, 0);
    while let (Some(a), Some(b)) = (p1, p2) {
        p1 = colon(s1, a + 1);
        p2 = colon(s2, b + 1);
    }
    let size1 = p1.unwrap_or(s1.len());
    let size2 = p2.unwrap_or(s2.len());
    if size1 == size2 && s1[..size1] == s2[..size1] {
        0
    } else {
        1
    }
}

/// `fim_adjust_checksum` on a copy of the new checksum.
fn adjust_checksum(newsum: &Sum, c_sum: &[u8]) -> B {
    let mut cs = c_sum.to_vec();
    if let Some(a) = &newsum.attributes {
        if let Some(p) = cs.iter().rposition(|&c| c == b':') {
            cs.truncate(p + 1);
            cs.extend_from_slice(a);
        }
    }
    if let Some(wp) = newsum.win_perm.as_ref().filter(|w| !w.is_empty()) {
        let Some(first) = cs.iter().position(|&c| c == b':') else { return cs };
        // first_part++; *(first_part++) = '\0';
        let cut = first + 1;
        if cut >= cs.len() {
            return cs;
        }
        let after = cut + 1;
        let tail = cs[after.min(cs.len())..].to_vec();
        cs.truncate(cut);
        let Some(sp) = tail.iter().position(|&c| c == b':') else { return cs };
        let second = tail[sp..].to_vec();
        cs.extend_from_slice(&replace(wp, b":", b"\\:"));
        cs.extend_from_slice(&second);
    }
    cs
}

/// `fim_alert`: -1 when nothing changed.
#[allow(clippy::too_many_arguments)]
fn fim_alert(
    decs: &mut Decoders,
    dec: usize,
    ids: &FimIds,
    ev: &mut Event,
    f_name: &[u8],
    oldsum: &mut Sum,
    newsum: &Sum,
    event_type: EventType,
    vals: &mut [Option<B>],
) -> i32 {
    let mut changes = false;
    // snprintf(localsdb->x, OS_FLSIZE, ...)
    let fl = |v: B| trunc(v, OS_FLSIZE);
    let (mut size, mut perm, mut owner, mut gowner, mut md5, mut sha1, mut sha256, mut mtime, mut inode, mut attrs) =
        (B::new(), B::new(), B::new(), B::new(), B::new(), B::new(), B::new(), B::new(), B::new(), B::new());
    let msg_type: &[u8] = match event_type {
        EventType::Deleted => {
            decs.infos[dec].id = ids.delete[0];
            decs.infos[dec].name = Some(FIM_DEL.into());
            changes = true;
            b"was deleted."
        }
        EventType::Added => {
            decs.infos[dec].id = ids.add[0];
            decs.infos[dec].name = Some(FIM_NEW.into());
            changes = true;
            b"was added."
        }
        EventType::Modified => {
            decs.infos[dec].id = ids.modify[0];
            decs.infos[dec].name = Some(FIM_MOD.into());
            let ch = &mut vals[fim::CHFIELDS].clone();
            let mut chf = ch.take();
            if let (Some(o), Some(n)) = (&oldsum.size, &newsum.size) {
                if o != n {
                    changes = true;
                    strcat(&mut chf, b"size", b',');
                    size = fl(cat(&[b"Size changed from '", o, b"' to '", n, b"'\n"]));
                    vals[fim::SIZE_BEFORE] = Some(o.clone());
                }
            }
            if oldsum.perm != 0 && newsum.perm != 0 {
                if oldsum.perm != newsum.perm && oldsum.perm > 0 && newsum.perm > 0 {
                    changes = true;
                    strcat(&mut chf, b"perm", b',');
                    let op = agent_file_perm(oldsum.perm);
                    let np = agent_file_perm(newsum.perm);
                    vals[fim::PERM_BEFORE] = Some(op.clone());
                    perm = fl(cat(&[b"Permissions changed from '", &op, b"' to '", &np, b"'\n"]));
                }
            } else if oldsum.win_perm.is_some() && newsum.win_perm.is_some() {
                let unesc = replace(oldsum.win_perm.as_deref().unwrap(), b"\\:", b":");
                oldsum.win_perm = Some(unesc.clone());
                let nw = newsum.win_perm.as_deref().unwrap();
                if unesc != nw && !unesc.is_empty() && !nw.is_empty() {
                    changes = true;
                    strcat(&mut chf, b"perm", b',');
                    perm = b"Permissions changed.\n".to_vec();
                    vals[fim::PERM_BEFORE] = Some(unesc);
                }
            }
            if let (Some(nu), Some(ou)) = (&newsum.uid, &oldsum.uid) {
                if nu != ou {
                    changes = true;
                    strcat(&mut chf, b"uid", b',');
                    if let (Some(on), Some(nn)) = (&oldsum.uname, &newsum.uname) {
                        owner = fl(cat(&[b"Ownership was '", on, b" (", ou, b")', now it is '", nn, b" (", nu, b")'\n"]));
                        vals[fim::UNAME_BEFORE] = Some(on.clone());
                    } else {
                        owner = fl(cat(&[b"Ownership was '", ou, b"', now it is '", nu, b"'\n"]));
                    }
                    vals[fim::UID_BEFORE] = Some(ou.clone());
                }
            }
            if let (Some(ng), Some(og)) = (&newsum.gid, &oldsum.gid) {
                if ng != og {
                    changes = true;
                    strcat(&mut chf, b"gid", b',');
                    if let (Some(on), Some(nn)) = (&oldsum.gname, &newsum.gname) {
                        gowner = fl(cat(&[b"Group ownership was '", on, b" (", og, b")', now it is '", nn, b" (", ng, b")'\n"]));
                        vals[fim::GNAME_BEFORE] = Some(on.clone());
                    } else {
                        gowner = fl(cat(&[b"Group ownership was '", og, b"', now it is '", ng, b"'\n"]));
                    }
                    vals[fim::GID_BEFORE] = Some(og.clone());
                }
            }
            let nonempty = |v: &Option<B>| v.as_ref().filter(|x| !x.is_empty()).cloned();
            if let (Some(n), Some(o)) = (nonempty(&newsum.md5), nonempty(&oldsum.md5)) {
                if n != o {
                    changes = true;
                    strcat(&mut chf, b"md5", b',');
                    md5 = fl(cat(&[b"Old md5sum was: '", &o, b"'\nNew md5sum is : '", &n, b"'\n"]));
                    vals[fim::MD5_BEFORE] = Some(o);
                }
            }
            if let (Some(n), Some(o)) = (nonempty(&newsum.sha1), nonempty(&oldsum.sha1)) {
                if n != o {
                    changes = true;
                    strcat(&mut chf, b"sha1", b',');
                    sha1 = fl(cat(&[b"Old sha1sum was: '", &o, b"'\nNew sha1sum is : '", &n, b"'\n"]));
                    vals[fim::SHA1_BEFORE] = Some(o);
                }
            }
            if let Some(n) = nonempty(&newsum.sha256) {
                match &oldsum.sha256 {
                    Some(o) => {
                        if &n != o {
                            changes = true;
                            strcat(&mut chf, b"sha256", b',');
                            sha256 = fl(cat(&[b"Old sha256sum was: '", o, b"'\nNew sha256sum is : '", &n, b"'\n"]));
                            vals[fim::SHA256_BEFORE] = Some(o.clone());
                        }
                    }
                    None => {
                        changes = true;
                        strcat(&mut chf, b"sha256", b',');
                        sha256 = fl(cat(&[b"New sha256sum is : '", &n, b"'\n"]));
                    }
                }
            }
            if oldsum.mtime != 0 && newsum.mtime != 0 && oldsum.mtime != newsum.mtime {
                changes = true;
                strcat(&mut chf, b"mtime", b',');
                vals[fim::MTIME_BEFORE] = Some(long_str(oldsum.mtime));
                let (o, n) = match (ctime(oldsum.mtime), ctime(newsum.mtime)) {
                    (Some(o), Some(n)) => (o, n),
                    _ => ("Unknown".to_string(), "Unknown".to_string()),
                };
                mtime = fl(format!("Old modification time was: '{o}', now it is '{n}'\n").into_bytes());
            }
            if oldsum.inode != 0 && newsum.inode != 0 && oldsum.inode != newsum.inode {
                changes = true;
                strcat(&mut chf, b"inode", b',');
                inode = fl(format!("Old inode was: '{}', now it is '{}'\n", oldsum.inode, newsum.inode).into_bytes());
                vals[fim::INODE_BEFORE] = Some(long_str(oldsum.inode));
            }
            if let (Some(o), Some(n)) = (&oldsum.attributes, &newsum.attributes) {
                if o != n {
                    changes = true;
                    strcat(&mut chf, b"attributes", b',');
                    attrs = trunc(cat(&[b"Old attributes were: '", o, b"'\nNow they are '", n, b"'\n"]), 1024);
                    vals[fim::ATTRS_BEFORE] = Some(o.clone());
                }
            }
            vals[fim::CHFIELDS] = chf;
            b"checksum changed."
        }
    };
    ev.decoder_syscheck_id = decs.infos[dec].id;
    let sym = match newsum.symbolic_path.as_ref().filter(|p| !p.is_empty()) {
        Some(p) => fl(cat(&[b"Symbolic path: '", p, b"'.\n"])),
        None => B::new(),
    };
    let fname = &f_name[..f_name.len().min(756)];
    let comment = trunc(
        cat(&[
            b"File '", fname, b"' ", msg_type, b"\n", &sym, &size, &perm, &owner, &gowner, &md5, &sha1, &sha256, &attrs, &mtime,
            &inode,
        ]),
        OS_MAXSTR,
    );
    if !changes {
        return -1;
    }
    if let Some(ch) = &mut vals[fim::CHFIELDS] {
        ch.push(b',');
    }
    let mut buf = comment;
    buf.push(0);
    ev.buf = buf;
    ev.log = 0;
    ev.program_name = None;
    ev.dec_timestamp = None;
    0
}

/// `fim_process_alert`
fn process_alert(c: &mut Ctx, decs: &mut Decoders, dec: usize, ids: &FimIds, ev: &mut Event, event: &mut Json) -> i32 {
    let mut vals: Vec<Option<B>> = vec![None; fim::NFIELDS];
    let mut attributes: Option<Json> = None;
    let mut old_attributes: Option<Json> = None;
    let mut audit: Option<Json> = None;
    let mut version = 0;
    let members: Vec<(Option<B>, Json)> = match &*event {
        Json::Object(m) => m.iter().map(|(k, v)| (Some(cstr(k).to_vec()), v.clone())).collect(),
        Json::Array(a) => a.iter().map(|v| (None, v.clone())).collect(),
        _ => Vec::new(),
    };
    for (key, object) in &members {
        let Some(key) = key else {
            return -1;
        };
        match object {
            Json::String(v) => {
                let v = Some(cstr(v).to_vec());
                match &key[..] {
                    b"path" => vals[fim::FILE] = v,
                    b"mode" => vals[fim::MODE] = v,
                    b"type" => vals[fim::EVENT_TYPE] = v,
                    b"tags" => vals[fim::TAG] = v,
                    b"content_changes" => vals[fim::DIFF] = v,
                    b"arch" => vals[fim::REGISTRY_ARCH] = v,
                    b"value_name" => vals[fim::REGISTRY_VALUE_NAME] = v,
                    b"index" => vals[fim::REGISTRY_HASH] = v,
                    _ => {}
                }
            }
            Json::Array(items) => {
                if &key[..] == b"changed_attributes" {
                    for it in items {
                        if let Json::String(s) = it {
                            strcat(&mut vals[fim::CHFIELDS], cstr(s), b',');
                        }
                    }
                } else if &key[..] == b"hard_links" {
                    vals[fim::HARD_LINKS] = Some(object.print_unformatted());
                }
            }
            Json::Object(_) => match &key[..] {
                b"attributes" => attributes = Some(object.clone()),
                b"old_attributes" => old_attributes = Some(object.clone()),
                b"audit" => audit = Some(object.clone()),
                _ => {}
            },
            Json::Number { int, .. } => {
                if &key[..] == b"version" {
                    version = *int;
                }
            }
            _ => {}
        }
    }
    let entry_type = match attributes.as_ref().and_then(|a| a.get("type")) {
        Some(Json::String(t)) => cstr(t).to_vec(),
        _ => return -1,
    };
    let is_reg = &entry_type[..] == b"registry_key" || &entry_type[..] == b"registry_value";
    if is_reg && version >= 3 && vals[fim::REGISTRY_HASH].is_none() {
        return -1;
    }
    if vals[fim::EVENT_TYPE].is_none() || vals[fim::FILE].is_none() {
        return -1;
    }
    let d = match &entry_type[..] {
        b"file" | b"registry" => 0,
        b"registry_key" => 1,
        b"registry_value" => 2,
        _ => return -1,
    };
    vals[fim::ENTRY_TYPE] = Some(entry_type.clone());
    let et = vals[fim::EVENT_TYPE].clone().unwrap();
    let (event_type, name, id) = match &et[..] {
        b"added" => (EventType::Added, NAMES_ADD[d], ids.add[d]),
        b"modified" => (EventType::Modified, NAMES_MOD[d], ids.modify[d]),
        b"deleted" => (EventType::Deleted, NAMES_DEL[d], ids.delete[d]),
        _ => return -1,
    };
    decs.infos[dec].name = Some(name.into());
    decs.infos[dec].id = id;
    ev.decoder_syscheck_id = id;

    if let Some(text) = generate_alert(&mut vals, event_type, attributes.as_ref(), old_attributes.as_ref(), audit.as_ref()) {
        // snprintf(lf->full_log, OS_MAXSTR, ...): written over the
        // allocation, lf->log is not moved
        let mut t = trunc(text, OS_MAXSTR);
        t.push(0);
        if ev.buf.len() < t.len() {
            ev.buf.resize(t.len(), 0);
        }
        ev.buf[..t.len()].copy_from_slice(&t);
    }
    set_fields(ev, vals.clone());

    let agent = c.agent.clone();
    match event_type {
        EventType::Added | EventType::Modified => {
            for k in ["mode", "type", "tags", "content_changes", "changed_attributes", "hard_links", "old_attributes", "audit"] {
                event.remove(k);
            }
            let q = cat(&[b"agent ", &agent, b" syscheck save2 ", &event.print_unformatted()]);
            if q.len() >= OS_MAXSTR {
                c.err(b"FIM decoder: Cannot build save2 query: input is too long.");
            } else {
                c.send_db_query(&q);
            }
        }
        EventType::Deleted => {
            let path = if &entry_type[..] == b"file" { &vals[fim::FILE] } else { &vals[fim::REGISTRY_HASH] };
            let q = cat(&[b"agent ", &agent, b" syscheck delete ", s(path)]);
            if q.len() >= OS_SIZE_6144 {
                c.err(b"FIM decoder: Cannot build delete query: input is too long.");
            } else {
                c.send_db_query(&q);
            }
        }
    }
    0
}

/// `fim_fetch_attributes_state`: -1 on an item without a key.
fn fetch_attributes(vals: &mut [Option<B>], attr: Option<&Json>, new_state: bool) -> i32 {
    let items: Vec<(Option<&[u8]>, &Json)> = match attr {
        Some(Json::Object(m)) => m.iter().map(|(k, v)| (Some(cstr(k)), v)).collect(),
        Some(Json::Array(a)) => a.iter().map(|v| (None, v)).collect(),
        _ => Vec::new(),
    };
    let pick = |n: usize, o: usize| if new_state { n } else { o };
    for (key, it) in items {
        let Some(key) = key else {
            return -1;
        };
        match it {
            Json::Number { double, .. } => {
                let idx = match key {
                    b"size" => Some(pick(fim::SIZE, fim::SIZE_BEFORE)),
                    b"inode" => Some(pick(fim::INODE, fim::INODE_BEFORE)),
                    b"mtime" => Some(pick(fim::MTIME, fim::MTIME_BEFORE)),
                    _ => None,
                };
                if let Some(i) = idx {
                    vals[i] = Some(long_str(c_long(*double)));
                }
            }
            Json::String(v) => {
                let v = cstr(v).to_vec();
                let idx = match key {
                    b"perm" => Some(pick(fim::PERM, fim::PERM_BEFORE)),
                    b"user_name" => Some(pick(fim::UNAME, fim::UNAME_BEFORE)),
                    b"group_name" => Some(pick(fim::GNAME, fim::GNAME_BEFORE)),
                    b"uid" => Some(pick(fim::UID, fim::UID_BEFORE)),
                    b"gid" => Some(pick(fim::GID, fim::GID_BEFORE)),
                    b"hash_md5" => Some(pick(fim::MD5, fim::MD5_BEFORE)),
                    b"hash_sha1" => Some(pick(fim::SHA1, fim::SHA1_BEFORE)),
                    b"hash_sha256" => Some(pick(fim::SHA256, fim::SHA256_BEFORE)),
                    b"attributes" => Some(pick(fim::ATTRS, fim::ATTRS_BEFORE)),
                    b"symlink_path" if new_state => Some(fim::SYM_PATH),
                    b"value_type" => Some(fim::REGISTRY_VALUE_TYPE),
                    b"inode" => Some(pick(fim::INODE, fim::INODE_BEFORE)),
                    _ => None,
                };
                if let Some(i) = idx {
                    vals[i] = Some(v);
                }
            }
            Json::Object(_) => {
                if key == b"perm" {
                    vals[pick(fim::PERM, fim::PERM_BEFORE)] = perm_json_to_old_format(it);
                }
            }
            _ => {}
        }
    }
    0
}

/// `decode_ace_json`
fn decode_ace(perm_array: Option<&Json>, account: &[u8], ace_type: &[u8]) -> Option<B> {
    let arr = perm_array?;
    let mut out = cat(&[account, b" (", ace_type, b"): "]);
    let mut perms: Option<B> = None;
    let items: Vec<&Json> = match arr {
        Json::Object(m) => m.iter().map(|(_, v)| v).collect(),
        Json::Array(a) => a.iter().collect(),
        _ => Vec::new(),
    };
    for it in items {
        if let Json::String(s) = it {
            strcat(&mut perms, cstr(s), b'|');
        }
    }
    if let Some(p) = perms {
        out.extend(p.iter().map(|c| c.to_ascii_uppercase()));
    }
    out.extend_from_slice(b", ");
    Some(out)
}

/// `perm_json_to_old_format`
fn perm_json_to_old_format(perm: &Json) -> Option<B> {
    let items: Vec<(Option<&[u8]>, &Json)> = match perm {
        Json::Object(m) => m.iter().map(|(k, v)| (Some(cstr(k)), v)).collect(),
        Json::Array(a) => a.iter().map(|v| (None, v)).collect(),
        _ => Vec::new(),
    };
    let mut out: Option<B> = None;
    for (key, it) in items {
        let name: B = match it.get("name") {
            Some(Json::String(n)) => cstr(n).to_vec(),
            _ => key.map(|k| k.to_vec()).unwrap_or_else(|| b"(null)".to_vec()),
        };
        if let Some(a) = decode_ace(it.get("allowed"), &name, b"allowed") {
            strcat(&mut out, &a, 0);
        }
        if let Some(d) = decode_ace(it.get("denied"), &name, b"denied") {
            strcat(&mut out, &d, 0);
        }
    }
    let mut out = out?;
    let l = out.len();
    if l > 2 && out[l - 2] == b',' {
        out.truncate(l - 2);
    }
    Some(out)
}

/// `fim_generate_comment`
fn comment(size: usize, a: &str, b: &str, c: &str, x: &Option<B>, y: &Option<B>) -> (B, usize) {
    let x = x.as_deref().unwrap_or(b"");
    let y = y.as_deref().unwrap_or(b"");
    if x == y {
        return (B::new(), 0);
    }
    let full = cat(&[a.as_bytes(), x, b.as_bytes(), y, c.as_bytes()]);
    let n = full.len();
    (trunc(full, size), n)
}

/// `fim_generate_alert`: the new `full_log`, None when it fails before.
fn generate_alert(vals: &mut [Option<B>], event_type: EventType, attributes: Option<&Json>, old: Option<&Json>, audit: Option<&Json>) -> Option<B> {
    if fetch_attributes(vals, attributes, true) != 0 || fetch_attributes(vals, old, false) != 0 {
        return None;
    }
    if let Some(Json::Object(m)) = audit {
        for (k, v) in m {
            let k = cstr(k);
            match v {
                Json::Number { double, .. } => {
                    let idx = match k {
                        b"ppid" => Some(fim::PPID),
                        b"process_id" => Some(fim::PROC_ID),
                        _ => None,
                    };
                    if let Some(i) = idx {
                        vals[i] = Some(trunc(long_str(c_long(*double)), 32));
                    }
                }
                Json::String(s) => {
                    let idx = match k {
                        b"user_id" => Some(fim::USER_ID),
                        b"user_name" => Some(fim::USER_NAME),
                        b"group_id" => Some(fim::GROUP_ID),
                        b"group_name" => Some(fim::GROUP_NAME),
                        b"process_name" => Some(fim::PROC_NAME),
                        b"parent_name" => Some(fim::PROC_PNAME),
                        b"cwd" => Some(fim::AUDIT_CWD),
                        b"parent_cwd" => Some(fim::AUDIT_PCWD),
                        b"audit_uid" => Some(fim::AUDIT_ID),
                        b"audit_name" => Some(fim::AUDIT_NAME),
                        b"effective_uid" => Some(fim::EFFECTIVE_UID),
                        b"effective_name" => Some(fim::EFFECTIVE_NAME),
                        _ => None,
                    };
                    if let Some(i) = idx {
                        vals[i] = Some(cstr(s).to_vec());
                    }
                }
                _ => {}
            }
        }
    }
    let sz = OS_FLSIZE + 1;
    let mut ch: Vec<B> = vec![B::new(); 12];
    if event_type == EventType::Modified {
        let v = |i: usize| vals[i].clone();
        ch[0] = comment(sz, "Size changed from '", "' to '", "'\n", &v(fim::SIZE_BEFORE), &v(fim::SIZE)).0;
        let (p, n) = comment(sz, "Permissions changed from '", "' to '", "'\n", &v(fim::PERM_BEFORE), &v(fim::PERM));
        ch[1] = if n >= sz { b"Permissions changed.\n".to_vec() } else { p };
        ch[2] = comment(sz, "Ownership was '", "', now it is '", "'\n", &v(fim::UID_BEFORE), &v(fim::UID)).0;
        ch[3] = comment(sz, "User name was '", "', now it is '", "'\n", &v(fim::UNAME_BEFORE), &v(fim::UNAME)).0;
        ch[4] = comment(sz, "Group ownership was '", "', now it is '", "'\n", &v(fim::GID_BEFORE), &v(fim::GID)).0;
        ch[5] = comment(sz, "Group name was '", "', now it is '", "'\n", &v(fim::GNAME_BEFORE), &v(fim::GNAME)).0;
        ch[6] = comment(sz, "Old modification time was: '", "', now it is '", "'\n", &v(fim::MTIME_BEFORE), &v(fim::MTIME)).0;
        ch[7] = comment(sz, "Old inode was: '", "', now it is '", "'\n", &v(fim::INODE_BEFORE), &v(fim::INODE)).0;
        ch[8] = comment(sz, "Old md5sum was: '", "'\nNew md5sum is : '", "'\n", &v(fim::MD5_BEFORE), &v(fim::MD5)).0;
        ch[9] = comment(sz, "Old sha1sum was: '", "'\nNew sha1sum is : '", "'\n", &v(fim::SHA1_BEFORE), &v(fim::SHA1)).0;
        ch[10] = comment(sz, "Old sha256sum was: '", "'\nNew sha256sum is : '", "'\n", &v(fim::SHA256_BEFORE), &v(fim::SHA256)).0;
        ch[11] = comment(257, "Old attributes were: '", "'\nNow they are '", "'\n", &v(fim::ATTRS_BEFORE), &v(fim::ATTRS)).0;
    }
    let changed = trunc(cat(&[b"Changed attributes: ", s(&vals[fim::CHFIELDS]), b"\n"]), 256);
    let hard = vals[fim::HARD_LINKS].as_ref().map(|h| {
        let mut t: Option<B> = None;
        if let Some(Json::Array(a)) = siem_cjson::parse(h) {
            for it in &a {
                if let Json::String(x) = it {
                    strcat(&mut t, cstr(x), b',');
                }
            }
        }
        trunc(cat(&[b"Hard links: ", s(&t), b"\n"]), 256)
    });
    let et = vals[fim::ENTRY_TYPE].clone().unwrap_or_default();
    let file = vals[fim::FILE].clone().unwrap_or_default();
    let arch = vals[fim::REGISTRY_ARCH].clone();
    let (entry, path): (&[u8], B) = match &et[..] {
        b"file" | b"registry" => {
            let path = if file.len() > 756 {
                let aux = &file[file.len() - 30..];
                trunc(cat(&[&file[..719], b" [...] ", aux]), 757)
            } else {
                file.clone()
            };
            (b"File", path)
        }
        b"registry_key" => {
            let path_len = 6 + file.len();
            let path = if path_len > 756 {
                // lf->fields[FIM_FILE].value + path_len - 30
                let aux = &file[path_len - 30..];
                trunc(cat(&[s(&arch), b" ", &file[..file.len().min(713)], b" [...] ", aux]), 757)
            } else {
                trunc(cat(&[s(&arch), b" ", &file]), 757)
            };
            (b"Registry Key", path)
        }
        _ => {
            if vals[fim::REGISTRY_VALUE_NAME].is_none() {
                vals[fim::REGISTRY_VALUE_NAME] = Some(b"Unknown key:Unknown Value".to_vec());
            }
            let vn = vals[fim::REGISTRY_VALUE_NAME].clone().unwrap();
            let path_len = 6 + file.len() + vn.len();
            let path = if path_len > 756 {
                let prec = 751i64 - vn.len() as i64;
                let prec = if prec < 0 { 0 } else { prec as usize };
                trunc(cat(&[s(&arch), b" ", &file[..file.len().min(prec)], b" [...] \\", &vn]), 757)
            } else {
                trunc(cat(&[s(&arch), b" ", &file, b"\\", &vn]), 757)
            };
            (b"Registry Value", path)
        }
    };
    let mut out = cat(&[
        entry,
        b" '",
        &path,
        b"' ",
        s(&vals[fim::EVENT_TYPE]),
        b"\n",
        hard.as_deref().unwrap_or(b""),
        b"Mode: ",
        s(&vals[fim::MODE]),
        b"\n",
        if vals[fim::CHFIELDS].is_some() { &changed } else { b"" },
    ]);
    for c in &ch {
        out.extend_from_slice(c);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(sum_compare(b"1:2:3", b"1:2:3"), 0);
        assert_eq!(sum_compare(b"1:2:3", b"1:2:4"), 1);
        assert_eq!(sum_compare(b"12", b"1:2"), 1);
        let n = Sum { win_perm: Some(b"a: b".to_vec()), ..Default::default() };
        assert_eq!(adjust_checksum(&n, b"10:|x,0,1:0:0"), b"10:a\\: b:0:0".to_vec());
    }
}
