//! The wazuh-db HTTP API on `queue/sockets/wdb-http.sock`: the router's
//! `router_register_api_endpoint` / `router_start_api` (router.cpp), the
//! wazuh-db gateway and its endpoints (shared_modules/router/src/wazuh-db)
//! over `wdb_global_pre` / `wdb_global_post`. Responses are serialized like
//! reflectiveJson.hpp, statements behave like sqlite3Wrapper.hpp and the
//! request bodies are parsed like nlohmann::json 3.11.2. Linux only.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use siem_log::WLog;
use siem_sqlite::{Db, Stmt, SQLITE_DONE, SQLITE_ERROR, SQLITE_OK, SQLITE_ROW};

use super::httplib::{Handler, Request, Response, Server};
use super::njson::{self, Value};
use super::state::Tv;
use super::*;

/// The router's logging (`router_initialize(taggedLogFunction)`): a level
/// ("ERROR", "WARNING", "INFO", "DEBUG", "DEBUG2") and the C string.
pub trait ApiLog: Send + Sync {
    fn log(&self, level: &str, msg: &[u8]);
}

impl ApiLog for WLog {
    fn log(&self, level: &str, msg: &[u8]) {
        self.tagged(ROUTER_TAG, level, msg);
    }
}

/// The router's log tag (`callbackLog(level, msg, ":router")`).
pub const ROUTER_TAG: &str = ":router";
/// `"queue/sockets/" + "wdb-http.sock"`
pub const WDB_HTTP_SOCK: &str = "queue/sockets/wdb-http.sock";

type R = Result<(), Vec<u8>>;

// ------------------------------------------------- sqlite3Wrapper.hpp

/// `SQLite::Statement`
struct Statement<'a> {
    db: &'a Db,
    st: Stmt,
    count: i32,
    index: i32,
}

impl<'a> Statement<'a> {
    /// `prepareSQLiteStatement`: throws `sqlite3_errmsg` on failure.
    fn new(db: &'a Db, sql: &str) -> Result<Self, Vec<u8>> {
        let (rc, st, _) = db.prepare_v2(sql.as_bytes());
        match st {
            Some(st) if rc == SQLITE_OK => {
                let count = st.bind_parameter_count();
                Ok(Statement { db, st, count, index: 0 })
            }
            // an empty statement prepares to NULL: sqlite3_bind_parameter_count(NULL) is 0
            _ if rc == SQLITE_OK => Err(b"Unspecified empty statement".to_vec()),
            _ => Err(db.errmsg()),
        }
    }

    /// `step`: SQLITE_ERROR without stepping until every parameter is bound.
    fn step(&self) -> Result<i32, Vec<u8>> {
        let mut ret = SQLITE_ERROR;
        if self.index == self.count {
            ret = self.st.step();
            if ret != SQLITE_ROW && ret != SQLITE_DONE && ret != SQLITE_OK {
                return Err(self.db.errmsg());
            }
        }
        Ok(ret)
    }

    fn reset(&mut self) {
        self.st.reset();
        self.index = 0;
    }

    fn check(&mut self, rc: i32) -> R {
        if rc != SQLITE_OK {
            return Err(self.db.errmsg());
        }
        self.index += 1;
        Ok(())
    }

    fn bind_i64(&mut self, i: i32, v: i64) -> R {
        let rc = self.st.bind_int64(i, v);
        self.check(rc)
    }

    fn bind_i32(&mut self, i: i32, v: i32) -> R {
        let rc = self.st.bind_int(i, v);
        self.check(rc)
    }

    /// `bind(i, std::string_view)` (exactly the bytes)
    fn bind_str(&mut self, i: i32, v: &[u8]) -> R {
        let rc = self.st.bind_text_len(i, v);
        self.check(rc)
    }

    fn value_i64(&self, i: i32) -> i64 {
        self.st.column_int64(i)
    }

    /// `value<std::string>`: "" for NULL, the C string otherwise.
    fn value_str(&self, i: i32) -> Vec<u8> {
        self.st.column_text(i).unwrap_or_default()
    }
}

impl Drop for Statement<'_> {
    fn drop(&mut self) {
        self.st.reset();
    }
}

// ------------------------------------------------- reflectiveJson.hpp

/// `ESCAPE_TABLE` / `escapeJSONString`
fn json_str(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    for &c in s {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1F => out.extend_from_slice(format!("\\u{c:04x}").as_bytes()),
            _ => out.push(c),
        }
    }
    out.push(b'"');
}

/// `isSingleSpace` for strings
fn single_space(s: &[u8]) -> bool {
    s == b" "
}

/// `DEFAULT_INT_VALUE`
const DEFAULT_INT_VALUE: i64 = i64::MIN;

/// An object being serialized (`serializeToJSON(obj, json)`), with the
/// NOEMPTY / NOSINGLESPACE rules applied per field.
struct Obj<'a> {
    out: &'a mut Vec<u8>,
    count: usize,
    noempty: bool,
}

impl<'a> Obj<'a> {
    fn new(out: &'a mut Vec<u8>, noempty: bool) -> Self {
        out.push(b'{');
        Obj { out, count: 0, noempty }
    }

    fn key(&mut self, k: &str) {
        if self.count > 0 {
            self.out.push(b',');
        }
        self.count += 1;
        self.out.push(b'"');
        self.out.extend_from_slice(k.as_bytes());
        self.out.extend_from_slice(b"\":");
    }

    fn str(&mut self, k: &str, v: &[u8]) {
        if (self.noempty && v.is_empty()) || single_space(v) {
            return;
        }
        self.key(k);
        json_str(self.out, v);
    }

    fn int(&mut self, k: &str, v: i64) {
        if self.noempty && v == DEFAULT_INT_VALUE {
            return;
        }
        self.key(k);
        self.out.extend_from_slice(v.to_string().as_bytes());
    }

    /// A vector field: `f` writes the elements (the field is empty when
    /// there are none).
    fn vec<T>(&mut self, k: &str, items: &[T], mut f: impl FnMut(&mut Vec<u8>, &T)) {
        if self.noempty && items.is_empty() {
            return;
        }
        self.key(k);
        self.out.push(b'[');
        for (i, it) in items.iter().enumerate() {
            if i > 0 {
                self.out.push(b',');
            }
            f(self.out, it);
        }
        self.out.push(b']');
    }

    /// A map field (keys written raw, without escaping).
    fn map<V>(&mut self, k: &str, m: &BTreeMap<Vec<u8>, V>, mut f: impl FnMut(&mut Vec<u8>, &V)) {
        if self.noempty && m.is_empty() {
            return;
        }
        self.key(k);
        self.out.push(b'{');
        for (i, (key, v)) in m.iter().enumerate() {
            if i > 0 {
                self.out.push(b',');
            }
            self.out.push(b'"');
            self.out.extend_from_slice(key);
            self.out.extend_from_slice(b"\":");
            f(self.out, v);
        }
        self.out.push(b'}');
    }

    fn end(self) {
        self.out.push(b'}');
    }
}

// ------------------------------------------------------------- endpoints

/// `EndpointGetV1AgentsIds`: a single field struct, so `serializeToJSON(obj)`
/// writes the bare vector.
fn get_v1_agents_ids(db: &Db, _req: &Request, res: &mut Response) -> R {
    let stmt = Statement::new(db, "SELECT id FROM agent WHERE id > 0")?;
    let mut ids = Vec::new();
    while stmt.step()? == SQLITE_ROW {
        ids.push(stmt.value_i64(0));
    }
    let mut out = Vec::new();
    write_i64_vec(&mut out, &ids);
    res.set_content(out, "application/json");
    Ok(())
}

fn write_i64_vec(out: &mut Vec<u8>, v: &[i64]) {
    out.push(b'[');
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(x.to_string().as_bytes());
    }
    out.push(b']');
}

fn write_str_vec(out: &mut Vec<u8>, v: &[Vec<u8>]) {
    out.push(b'[');
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json_str(out, x);
    }
    out.push(b']');
}

/// `EndpointGetV1AgentsIdsGroups`: `{"data":{"<id>":["g",...]}}`
fn get_v1_agents_ids_groups(db: &Db, _req: &Request, res: &mut Response) -> R {
    let stmt = Statement::new(
        db,
        "SELECT b.id_agent AS id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE b.id_agent > 0;",
    )?;
    // std::map<std::string, std::vector<std::string>>: keys sorted as strings
    let mut data: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    while stmt.step()? == SQLITE_ROW {
        data.entry(stmt.value_i64(0).to_string().into_bytes()).or_default().push(stmt.value_str(1));
    }
    let mut out = Vec::new();
    let mut o = Obj::new(&mut out, true);
    o.map("data", &data, |out, v| write_str_vec(out, v));
    o.end();
    res.set_content(out, "application/json");
    Ok(())
}

/// `EndpointGetV1AgentsIdsGroupsParam`: the ids of a group (bare vector)
fn get_v1_agents_ids_groups_param(db: &Db, req: &Request, res: &mut Response, log: &dyn ApiLog) -> R {
    let Some(name) = req.path_params.get("name") else {
        log.log("INFO", b"Missing parameter: name");
        res.status = 400;
        res.set_content(b"Missing parameter: name".to_vec(), "text/plain");
        return Ok(());
    };
    let mut stmt = Statement::new(
        db,
        "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > 0;",
    )?;
    stmt.bind_str(1, name)?;
    let mut ids = Vec::new();
    while stmt.step()? == SQLITE_ROW {
        // std::vector<int>: the int64 is narrowed
        ids.push(stmt.value_i64(0) as i32 as i64);
    }
    let mut out = Vec::new();
    write_i64_vec(&mut out, &ids);
    res.set_content(out, "application/json");
    Ok(())
}

/// `std::stoi`: what() is "stoi" on failure.
fn stoi(s: &[u8]) -> Result<i32, Vec<u8>> {
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: i128 = 0;
    let mut over = false;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v * 10 + (s[i] - b'0') as i128;
        if v > i64::MAX as i128 + 1 {
            over = true;
            v = i64::MAX as i128 + 1;
        }
        i += 1;
    }
    if i == start {
        return Err(b"stoi".to_vec());
    }
    let v = if neg { -v } else { v };
    // strtol's ERANGE, then the int range check
    if over || v > i32::MAX as i128 || v < i32::MIN as i128 {
        return Err(b"stoi".to_vec());
    }
    Ok(v as i32)
}

/// `EndpointGetV1AgentsParamGroups`: the groups of an agent (bare vector)
fn get_v1_agents_param_groups(db: &Db, req: &Request, res: &mut Response, log: &dyn ApiLog) -> R {
    let Some(id) = req.path_params.get("agent_id") else {
        log.log("INFO", b"Missing parameter: agent id");
        res.status = 400;
        res.set_content(b"Missing parameter: id".to_vec(), "text/plain");
        return Ok(());
    };
    let mut stmt = Statement::new(db, "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority")?;
    let id = stoi(id)?;
    stmt.bind_i32(1, id)?;
    let mut groups = Vec::new();
    while stmt.step()? == SQLITE_ROW {
        groups.push(stmt.value_str(0));
    }
    let mut out = Vec::new();
    write_str_vec(&mut out, &groups);
    res.set_content(out, "application/json");
    Ok(())
}

/// `SyncReq` of the GET /v1/agents/sync response
#[derive(Default)]
struct SyncReq {
    id: i64,
    s: [Vec<u8>; 16],
    last_keepalive: i64,
    connection_status: Vec<u8>,
    disconnection_time: i64,
    group_config_status: Vec<u8>,
    status_code: i64,
    labels: Vec<(Vec<u8>, Vec<u8>)>,
}

const SYNC_STR_FIELDS: [&str; 16] = [
    "name",
    "ip",
    "os_name",
    "os_version",
    "os_major",
    "os_minor",
    "os_codename",
    "os_build",
    "os_platform",
    "os_uname",
    "os_arch",
    "version",
    "config_sum",
    "merged_sum",
    "manager_host",
    "node_name",
];

impl SyncReq {
    fn new(id: i64) -> Self {
        SyncReq {
            id,
            last_keepalive: DEFAULT_INT_VALUE,
            disconnection_time: DEFAULT_INT_VALUE,
            status_code: DEFAULT_INT_VALUE,
            ..Default::default()
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        let mut o = Obj::new(out, true);
        o.int("id", self.id);
        for (k, v) in SYNC_STR_FIELDS.iter().zip(self.s.iter()) {
            o.str(k, v);
        }
        o.int("last_keepalive", self.last_keepalive);
        o.str("connection_status", &self.connection_status);
        o.int("disconnection_time", self.disconnection_time);
        o.str("group_config_status", &self.group_config_status);
        o.int("status_code", self.status_code);
        o.vec("labels", &self.labels, |out, (k, v)| {
            let mut l = Obj::new(out, true);
            l.str("key", k);
            l.str("value", v);
            l.end();
        });
        o.end();
    }
}

/// `EndpointGetV1AgentsSync`
fn get_v1_agents_sync(db: &Db, _req: &Request, res: &mut Response) -> R {
    let mut sync_req = Vec::new();
    let mut keepalive = Vec::new();
    let mut status = Vec::new();
    let mut stmt_count = Statement::new(db, "SELECT COUNT(*) FROM agent WHERE id > 0 AND sync_status = ?;")?;
    {
        stmt_count.bind_str(1, b"syncreq")?;
        while stmt_count.step()? == SQLITE_ROW {}
        let s = Statement::new(
            db,
            "SELECT id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, last_keepalive, connection_status, disconnection_time, group_config_status, status_code FROM agent WHERE id > 0 AND sync_status = 'syncreq';",
        )?;
        let mut labels = Statement::new(db, "SELECT key, value FROM labels WHERE id = ?;")?;
        while s.step()? == SQLITE_ROW {
            let id = s.value_i64(0);
            let mut r = SyncReq::new(id);
            for (i, f) in r.s.iter_mut().enumerate() {
                *f = s.value_str(i as i32 + 1);
            }
            r.last_keepalive = s.value_i64(17);
            r.connection_status = s.value_str(18);
            r.disconnection_time = s.value_i64(19);
            r.group_config_status = s.value_str(20);
            r.status_code = s.value_i64(21);
            labels.reset();
            labels.bind_i64(1, id)?;
            while labels.step()? == SQLITE_ROW {
                r.labels.push((labels.value_str(0), labels.value_str(1)));
            }
            sync_req.push(r);
        }
    }
    {
        stmt_count.reset();
        stmt_count.bind_str(1, b"syncreq_keepalive")?;
        while stmt_count.step()? == SQLITE_ROW {}
        let s = Statement::new(db, "SELECT id, version FROM agent WHERE id > 0 AND sync_status = 'syncreq_keepalive';")?;
        while s.step()? == SQLITE_ROW {
            let mut r = SyncReq::new(s.value_i64(0));
            r.s[11] = s.value_str(1);
            keepalive.push(r);
        }
    }
    {
        stmt_count.reset();
        stmt_count.bind_str(1, b"syncreq_status")?;
        while stmt_count.step()? == SQLITE_ROW {}
        let s = Statement::new(
            db,
            "SELECT id, version, connection_status, disconnection_time, status_code FROM agent WHERE id > 0 AND sync_status = 'syncreq_status';",
        )?;
        while s.step()? == SQLITE_ROW {
            let mut r = SyncReq::new(s.value_i64(0));
            r.s[11] = s.value_str(1);
            r.connection_status = s.value_str(2);
            r.disconnection_time = s.value_i64(3);
            r.status_code = s.value_i64(4);
            status.push(r);
        }
    }
    {
        let s = Statement::new(db, "UPDATE agent SET sync_status = 'synced' WHERE id > 0;")?;
        s.step()?;
    }
    let mut out = std::mem::take(&mut res.body);
    let mut o = Obj::new(&mut out, true);
    o.vec("syncreq", &sync_req, |out, r| r.write(out));
    o.vec("syncreq_keepalive", &keepalive, |out, r| r.write(out));
    o.vec("syncreq_status", &status, |out, r| r.write(out));
    o.end();
    res.body = out;
    res.set_header("Content-Type", b"application/json");
    Ok(())
}

/// `value<T>(json, key)`: the member or T{} when missing.
fn jstr<'v>(j: &'v Value, k: &str) -> Result<&'v [u8], Vec<u8>> {
    if j.contains(k) {
        j.at(k)?.get_str()
    } else {
        Ok(b"")
    }
}

fn jint(j: &Value, k: &str) -> Result<i64, Vec<u8>> {
    if j.contains(k) {
        j.at(k)?.get_i64()
    } else {
        Ok(0)
    }
}

/// `id<T>(json, key)`
fn jid(j: &Value, k: &str) -> Result<i64, Vec<u8>> {
    if j.contains(k) {
        j.at(k)?.get_i64()
    } else {
        Err(b"Missing required key.".to_vec())
    }
}

/// `EndpointPostV1AgentsSync`
fn post_v1_agents_sync(db: &Db, req: &Request, _res: &mut Response, log: &dyn ApiLog) -> R {
    let body = njson::parse(&req.body)?;
    if body.contains("syncreq") {
        let mut stmt = Statement::new(
            db,
            "UPDATE agent SET config_sum = ?, ip = ?, manager_host = ?, merged_sum = ?, name = ?, node_name = ?, os_arch = ?, os_build = ?, os_codename = ?, os_major = ?, os_minor = ?, os_name = ?, os_platform = ?, os_uname = ?, os_version = ?, version = ?, last_keepalive = ?, connection_status = ?, disconnection_time = ?, group_config_status = ?, status_code= ?, sync_status = 'synced' WHERE id = ?;",
        )?;
        let mut del = Statement::new(db, "DELETE FROM labels WHERE id = ?;")?;
        let mut ins = Statement::new(db, "INSERT INTO labels (id, key, value) VALUES (?, ?, ?);")?;
        for agent in body.at("syncreq")?.iter() {
            let id = jid(agent, "id")?;
            for (i, k) in [
                "config_sum",
                "ip",
                "manager_host",
                "merged_sum",
                "name",
                "node_name",
                "os_arch",
                "os_build",
                "os_codename",
                "os_major",
                "os_minor",
                "os_name",
                "os_platform",
                "os_uname",
                "os_version",
                "version",
            ]
            .iter()
            .enumerate()
            {
                let v = jstr(agent, k)?;
                stmt.bind_str(i as i32 + 1, v)?;
            }
            stmt.bind_i64(17, jint(agent, "last_keepalive")?)?;
            let v = jstr(agent, "connection_status")?;
            stmt.bind_str(18, v)?;
            stmt.bind_i64(19, jint(agent, "disconnection_time")?)?;
            let v = jstr(agent, "group_config_status")?;
            stmt.bind_str(20, v)?;
            stmt.bind_i64(21, jint(agent, "status_code")?)?;
            stmt.bind_i64(22, id)?;
            stmt.step()?;
            stmt.reset();
            del.bind_i64(1, id)?;
            del.step()?;
            del.reset();
            if agent.contains("labels") {
                for label in agent.at("labels")?.iter() {
                    ins.reset();
                    ins.bind_i64(1, id)?;
                    let k = jstr(label, "key")?;
                    ins.bind_str(2, k)?;
                    let v = jstr(label, "value")?;
                    ins.bind_str(3, v)?;
                    if let Err(e) = ins.step() {
                        let mut m = format!("Cannot set label for agent: {id}, ").into_bytes();
                        m.extend_from_slice(&e);
                        log.log("WARNING", cstr(&m));
                        break;
                    }
                }
            }
        }
    }
    if body.contains("syncreq_keepalive") {
        let mut stmt = Statement::new(
            db,
            "UPDATE agent SET last_keepalive = STRFTIME('%s', 'NOW'),sync_status = 'synced',connection_status = 'active',disconnection_time = 0,status_code = 0, version = ? WHERE id = ?;",
        )?;
        for agent in body.at("syncreq_keepalive")?.iter() {
            let v = jstr(agent, "version")?;
            stmt.bind_str(1, v)?;
            stmt.bind_i64(2, jid(agent, "id")?)?;
            stmt.step()?;
            stmt.reset();
        }
    }
    if body.contains("syncreq_status") {
        let mut stmt = Statement::new(
            db,
            "UPDATE agent SET connection_status = ?, sync_status = 'synced', disconnection_time = ?, status_code = ?, version = ? WHERE id = ?;",
        )?;
        for agent in body.at("syncreq_status")?.iter() {
            let v = jstr(agent, "connection_status")?;
            stmt.bind_str(1, v)?;
            stmt.bind_i64(2, jint(agent, "disconnection_time")?)?;
            stmt.bind_i64(3, jint(agent, "status_code")?)?;
            let v = jstr(agent, "version")?;
            stmt.bind_str(4, v)?;
            stmt.bind_i64(5, jid(agent, "id")?)?;
            stmt.step()?;
            stmt.reset();
        }
    }
    Ok(())
}

/// `EndpointPostV1AgentsSummary`
fn post_v1_agents_summary(db: &Db, req: &Request, res: &mut Response) -> R {
    let mut by_status: BTreeMap<Vec<u8>, i64> = BTreeMap::new();
    let mut by_groups: BTreeMap<Vec<u8>, i64> = BTreeMap::new();
    let mut by_os: BTreeMap<Vec<u8>, i64> = BTreeMap::new();
    if req.body.is_empty() {
        let s = Statement::new(
            db,
            "SELECT COUNT(*) as quantity, connection_status AS status FROM agent WHERE id > 0 GROUP BY status ORDER BY status ASC limit 5;",
        )?;
        while s.step()? == SQLITE_ROW {
            let q = s.value_i64(0);
            by_status.insert(s.value_str(1), q);
        }
        let s = Statement::new(
            db,
            "SELECT COUNT(*) as q, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '' GROUP BY b.id_group ORDER BY q DESC LIMIT 5;",
        )?;
        while s.step()? == SQLITE_ROW {
            let q = s.value_i64(0);
            by_groups.insert(s.value_str(1), q);
        }
        let s = Statement::new(
            db,
            "SELECT COUNT(*) as quantity, os_platform AS platform FROM agent WHERE id > 0 AND os_platform IS NOT NULL AND os_platform <> '' GROUP BY platform ORDER BY quantity DESC limit 5;",
        )?;
        while s.step()? == SQLITE_ROW {
            let q = s.value_i64(0);
            by_os.insert(s.value_str(1), q);
        }
    } else {
        // the numbers of the body (from_chars<int>)
        let view = &req.body;
        let mut ids: Vec<i64> = Vec::new();
        let mut pos = 0;
        while pos < view.len() {
            let Some(p) = view[pos..].iter().position(|&c| c.is_ascii_digit() || c == b'-') else {
                break;
            };
            pos += p;
            let mut end = pos;
            while end < view.len() && (view[end].is_ascii_digit() || view[end] == b'-') {
                end += 1;
            }
            if let Some(v) = from_chars_int(&view[pos..end]) {
                ids.push(v as i64);
            }
            pos = end;
        }
        ids.sort();
        let s = Statement::new(db, "SELECT id, connection_status AS status FROM agent WHERE id > 0;")?;
        while s.step()? == SQLITE_ROW {
            let id = s.value_i64(0);
            let status = s.value_str(1);
            if ids.binary_search(&id).is_ok() {
                *by_status.entry(status).or_insert(0) += 1;
            }
        }
        let s = Statement::new(
            db,
            "SELECT b.id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '';",
        )?;
        while s.step()? == SQLITE_ROW {
            let id = s.value_i64(0);
            let name = s.value_str(1);
            if ids.binary_search(&id).is_ok() {
                *by_groups.entry(name).or_insert(0) += 1;
            }
        }
        let s = Statement::new(
            db,
            "SELECT id, os_platform AS platform FROM agent WHERE id > 0 AND os_platform IS NOT NULL AND os_platform <> '';",
        )?;
        while s.step()? == SQLITE_ROW {
            let id = s.value_i64(0);
            let p = s.value_str(1);
            if ids.binary_search(&id).is_ok() {
                *by_os.entry(p).or_insert(0) += 1;
            }
        }
    }
    let mut out = Vec::new();
    let mut o = Obj::new(&mut out, true);
    let num = |out: &mut Vec<u8>, v: &i64| out.extend_from_slice(v.to_string().as_bytes());
    o.map("agents_by_status", &by_status, num);
    o.map("agents_by_groups", &by_groups, num);
    o.map("agents_by_os", &by_os, num);
    o.end();
    res.body = out;
    res.set_header("Content-Type", b"application/json");
    Ok(())
}

/// `std::from_chars(first, last, int)`: an optional '-' and digits; out of
/// range or no digits fail. The rest of the token is ignored.
fn from_chars_int(s: &[u8]) -> Option<i32> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    let n = digits.iter().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return None;
    }
    let mut v: i64 = 0;
    for &c in &digits[..n] {
        v = v * 10 + (c - b'0') as i64;
        if v > i32::MAX as i64 + 1 {
            return None;
        }
    }
    let v = if neg { -v } else { v };
    if v > i32::MAX as i64 || v < i32::MIN as i64 {
        return None;
    }
    Some(v as i32)
}

/// `EndpointPostV1AgentsRestartInfo`
fn post_v1_agents_restart_info(db: &Db, req: &Request, res: &mut Response) -> R {
    let body = if req.body.is_empty() { Value::Object(BTreeMap::new()) } else { njson::parse(&req.body)? };
    let mut sql = String::from("SELECT id, version FROM agent WHERE connection_status = 'active'");
    let mut filtered = false;
    if body.contains("ids") && body.at("ids")?.is_array() && body.at("ids")?.size() > 0 {
        filtered = true;
        let n = body.at("ids")?.size();
        let mut select_ids = String::new();
        for _ in 0..n {
            select_ids.push_str(if select_ids.is_empty() { "?" } else { ",?" });
        }
        let mut negate = false;
        if body.contains("negate") && body.at("negate")?.is_boolean() {
            negate = body.at("negate")?.get_bool()?;
        }
        sql.push_str(" AND id ");
        if negate {
            sql.push_str("NOT ");
        }
        sql.push_str(&format!("IN ({select_ids})"));
    }
    sql.push(';');
    let mut stmt = Statement::new(db, &sql)?;
    if filtered {
        let mut i = 1;
        for id in body.at("ids")?.iter() {
            stmt.bind_i64(i, id.get_i64()?)?;
            i += 1;
        }
    }
    let mut items = Vec::new();
    while stmt.step()? == SQLITE_ROW {
        items.push((stmt.value_i64(0), stmt.value_str(1)));
    }
    // serializeToJSON<Response, false>: empty fields are kept
    let mut out = Vec::new();
    let mut o = Obj::new(&mut out, false);
    o.vec("items", &items, |out, (id, version)| {
        let mut x = Obj::new(out, false);
        x.int("id", *id);
        x.str("version", version);
        x.end();
    });
    o.end();
    res.body = out;
    res.set_header("Content-Type", b"application/json");
    Ok(())
}

// ------------------------------------------------- gateway and router

impl Wdbd {
    /// `wdb_global_pre`: the global database in a transaction, or None.
    /// (Like the C, a failing `wdb_begin2` keeps the pool entry locked.)
    pub fn global_pre(&self) -> Option<Guard> {
        self.state.w_inc_global();
        let b = self.tv();
        let Some(wdb) = self.open_global() else {
            self.mdebug2(&msg!("Couldn't open DB global: ", WDB2_DIR, "/", WDB_GLOB_NAME, ".db"));
            self.state.w_inc_global_open_time(Tv::diff(self.tv(), b));
            return None;
        };
        if !wdb.enabled {
            self.mdebug2(&msg!("Database disabled: ", WDB2_DIR, "/", WDB_GLOB_NAME, ".db."));
            self.leave(wdb);
            self.state.w_inc_global_open_time(Tv::diff(self.tv(), b));
            return None;
        }
        self.state.w_inc_global_open_time(Tv::diff(self.tv(), b));
        let mut wdb = wdb;
        if !wdb.transaction && self.begin2(&mut wdb) < 0 {
            self.mdebug1(b"Cannot begin transaction");
            std::mem::forget(wdb);
            return None;
        }
        Some(wdb)
    }
}

/// `WDB::redirect` (gateway.hpp): the endpoint of a registered route.
fn redirect(d: &Wdbd, log: &dyn ApiLog, endpoint: &str, method: &str, req: &Request, res: &mut Response) -> R {
    // DEFER(cbPost)
    let Some(wdb) = d.global_pre() else {
        return Err(b"Database connection failed".to_vec());
    };
    let db = wdb.db();
    let r = match (method, endpoint) {
        ("GET", "/v1/agents/ids") => get_v1_agents_ids(db, req, res),
        ("GET", "/v1/agents/ids/groups/:name") => get_v1_agents_ids_groups_param(db, req, res, log),
        ("GET", "/v1/agents/ids/groups") => get_v1_agents_ids_groups(db, req, res),
        ("GET", "/v1/agents/:agent_id/groups") => get_v1_agents_param_groups(db, req, res, log),
        ("GET", "/v1/agents/sync") => get_v1_agents_sync(db, req, res),
        ("GET", _) => Err(b"Endpoint not implemented".to_vec()),
        ("POST", "/v1/agents/summary") => post_v1_agents_summary(db, req, res),
        ("POST", "/v1/agents/sync") => post_v1_agents_sync(db, req, res, log),
        ("POST", "/v1/agents/restartinfo") => post_v1_agents_restart_info(db, req, res),
        ("POST", _) => Err(b"Endpoint not implemented".to_vec()),
        _ => Err(b"Method not implemented".to_vec()),
    };
    d.leave(wdb);
    r
}

/// The routes main.c registers, in order.
pub const ENDPOINTS: [(&str, &str); 8] = [
    ("GET", "/v1/agents/ids"),
    ("GET", "/v1/agents/ids/groups/:name"),
    ("GET", "/v1/agents/ids/groups"),
    ("GET", "/v1/agents/:agent_id/groups"),
    ("POST", "/v1/agents/summary"),
    ("GET", "/v1/agents/sync"),
    ("POST", "/v1/agents/sync"),
    ("POST", "/v1/agents/restartinfo"),
];

/// A started API (`router_stop_api`).
pub struct ApiHandle {
    server: Arc<Server>,
    thread: Option<std::thread::JoinHandle<()>>,
    log: Arc<dyn ApiLog>,
}

impl ApiHandle {
    /// `router_stop_api("wdb-http.sock")`
    pub fn stop(mut self) {
        self.server.stop();
        if let Some(t) = self.thread.take() {
            self.log.log("INFO", b"Stopping server thread");
            let _ = t.join();
        }
    }
}

/// `router_register_api_endpoint` for the 8 routes and `router_start_api`.
pub fn start_api(d: Arc<Wdbd>, log: Arc<dyn ApiLog>) -> Option<ApiHandle> {
    let server = Arc::new(Server::new());
    for (method, endpoint) in ENDPOINTS {
        log.log("INFO", format!("Registering {method} endpoint: {endpoint}").as_bytes());
        let (dd, l) = (d.clone(), log.clone());
        let h: Handler = Arc::new(move |req: &mut Request, res: &mut Response| {
            if method == "GET" {
                let mut m = format!("GET: {endpoint} request parameters: ").into_bytes();
                m.extend_from_slice(&req.path);
                l.log("DEBUG2", cstr(&m));
            }
            let start = Instant::now();
            redirect(&dd, &*l, endpoint, method, req, res)?;
            let us = start.elapsed().as_micros();
            l.log("DEBUG", format!("{method}: {endpoint} request processed in {us} us").as_bytes());
            Ok(())
        });
        if method == "GET" {
            server.get(endpoint, h);
        } else {
            server.post(endpoint, h);
        }
    }
    let el = log.clone();
    server.set_exception_handler(Arc::new(move |req: &Request, res: &mut Response, what: &[u8]| {
        let mut m = what.to_vec();
        m.extend_from_slice(b" on endpoint: ");
        m.extend_from_slice(&req.path);
        el.log("ERROR", cstr(&m));
        res.status = 500;
    }));

    // router_start_api
    let path = d.path(WDB_HTTP_SOCK);
    let _ = std::fs::remove_file(&path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let (s, l) = (server.clone(), log.clone());
    let p = path.to_string_lossy().into_owned();
    let thread = std::thread::Builder::new()
        .name("router_api".into())
        .spawn(move || {
            let running = s.listen_unix(&p);
            if !running {
                l.log("ERROR", b"Error starting API. Failed to listen on socket");
                return;
            }
            use std::os::unix::fs::PermissionsExt;
            match std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o660)) {
                Ok(()) => l.log("DEBUG2", b"API socket permissions set to 0660"),
                Err(e) => {
                    let (_, t) = errno_text(&e);
                    l.log("ERROR", format!("Error setting API socket permissions: {t}").as_bytes());
                }
            }
        })
        .ok();
    // the C spin loop never waits (`running` is false until listen returns)
    log.log("INFO", b"API started successfully");
    Some(ApiHandle { server, thread, log })
}
