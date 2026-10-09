//! Differential test of dbsync and rsync against `tools/oracle/dbsync_harness.cpp`
//! (Wazuh's real C++ behind the same C API). Both run the same script in
//! the same scratch directory; every return value, log line, callback,
//! stderr line and the final contents of every database file must match.
//!
//! `SIEM_DBSYNC_ORACLE` is the oracle binary (built by
//! `tools/oracle/build.sh`); `SIEM_DBSYNC_FUZZ` (mutations),
//! `SIEM_DBSYNC_SEED`, `SIEM_DBSYNC_KEEP` (directory for the outputs).

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use siem_cjson::Json;
use siem_dbsync::capi::*;
use siem_dbsync::rsync::capi::*;
use siem_dbsync::ReturnTypeCallback;

const ORACLE_TIME: i64 = 1700000000;

/// Hex, "=" for the empty string (a field must not be empty).
fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "=".into();
    }
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

// ----------------------------------------------------------- Rust side

struct Out {
    main: std::thread::ThreadId,
    lines: Vec<String>,
    pending: Vec<String>,
}

fn out() -> &'static Mutex<Out> {
    static O: OnceLock<Mutex<Out>> = OnceLock::new();
    O.get_or_init(|| Mutex::new(Out { main: std::thread::current().id(), lines: Vec::new(), pending: Vec::new() }))
}

fn emit(l: String) {
    let mut o = out().lock().unwrap();
    if std::thread::current().id() == o.main {
        o.lines.push(l);
    } else {
        o.pending.push(l);
    }
}

fn flush_pending() {
    let mut o = out().lock().unwrap();
    let p = std::mem::take(&mut o.pending);
    o.lines.extend(p);
}

fn init_rust() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        out();
        siem_dbsync::set_cerr_hook(|l: &[u8]| emit(format!("E {}", hex(l))));
        siem_dbsync::rsync::set_clock(|| ORACLE_TIME);
        dbsync_initialize(|m: &[u8]| emit(format!("M {}", hex(m))));
        rsync_initialize(|m: &[u8]| emit(format!("N {}", hex(m))));
        rsync_initialize_full_log_function(Box::new(|level, tag, file, line, func, msg| {
            emit(format!("F {level} {tag} {file} {line} {func} {}", hex(msg)))
        }));
    });
}

fn handle(v: &[u64], f: &str) -> u64 {
    let n: usize = f.parse().unwrap();
    if n == 0 {
        0
    } else if n == 9999 || n > v.len() {
        u64::MAX - 7
    } else {
        v[n - 1]
    }
}

fn json(f: &str) -> Option<Json> {
    if f == "-" {
        return None;
    }
    let s = unhex(f);
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    let s = &s[..end];
    Some(siem_cjson::parse(s).unwrap_or_else(|| Json::string(s)))
}

fn opt(f: &str) -> Option<Vec<u8>> {
    if f == "-" {
        None
    } else {
        Some(unhex(f))
    }
}

fn dump(path: &[u8]) {
    use siem_sqlite::*;
    let (rc, db) = Db::open_v2(path, SQLITE_OPEN_READONLY);
    let Some(db) = db.filter(|_| rc == SQLITE_OK) else {
        emit("S -".into());
        return;
    };
    let (_, st, _) = db.prepare_v2(b"SELECT name, sql FROM sqlite_master ORDER BY type, name");
    let st = st.unwrap();
    let mut tables = Vec::new();
    while st.step() == SQLITE_ROW {
        let name = st.column_text(0).unwrap_or_default();
        let sql = st.column_text(1);
        emit(format!("S {} {}", hex(&name), sql.as_deref().map(hex).unwrap_or_else(|| "-".into())));
        if sql.map(|s| s.starts_with(b"CREATE TABLE")).unwrap_or(false) {
            tables.push(name);
        }
    }
    drop(st);
    for t in tables {
        let q = [b"SELECT * FROM \"".as_slice(), &t, b"\" ORDER BY rowid"].concat();
        let (rc, rs, _) = db.prepare_v2(&q);
        let Some(rs) = rs.filter(|_| rc == SQLITE_OK) else { continue };
        while rs.step() == SQLITE_ROW {
            let mut row = String::new();
            for i in 0..rs.column_count() {
                match rs.column_type(i) {
                    SQLITE_INTEGER => row += &format!("i{}", rs.column_int64(i)),
                    SQLITE_FLOAT => row += &format!("f{}", siem_cjson::fmt_g(rs.column_double(i), 17)),
                    SQLITE_NULL => row += "n",
                    _ => row += &format!("t{}", rs.column_bytes(i).unwrap_or_default().iter().map(|c| format!("{c:02x}")).collect::<String>()),
                }
                row += ",";
            }
            emit(format!("W {} {}", hex(&t), row));
        }
    }
}

fn run_rust(script: &[String]) -> Vec<String> {
    init_rust();
    let cb: CallbackData = Arc::new(|t: ReturnTypeCallback, j: Option<&Json>| {
        emit(format!("B {} {}", t as i32, j.map(|j| hex(&j.print_unformatted())).unwrap_or_else(|| "-".into())))
    });
    let scb: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(|p: &[u8]| emit(format!("Y {}", hex(p))));
    let (mut db, mut txn, mut rs) = (Vec::<u64>::new(), Vec::<u64>::new(), Vec::<u64>::new());
    for line in script {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        let mut r = 0;
        let mut print_r = true;
        match f[0] {
            "C" | "P" => {
                let (p, s) = (opt(f[3]), opt(f[4]));
                let h = if f[0] == "C" {
                    dbsync_create(f[1].parse().unwrap(), f[2].parse().unwrap(), p.as_deref(), s.as_deref())
                } else {
                    let n: i32 = f[5].parse().unwrap();
                    let stmts: Vec<Vec<u8>> = (0..n.max(0) as usize).map(|i| unhex(f[6 + i])).collect();
                    let refs: Vec<&[u8]> = stmts.iter().map(|s| s.as_slice()).collect();
                    dbsync_create_persistent(
                        f[1].parse().unwrap(),
                        f[2].parse().unwrap(),
                        p.as_deref(),
                        s.as_deref(),
                        if n < 0 { None } else { Some(&refs) },
                    )
                };
                if h != 0 {
                    db.push(h);
                }
                emit(format!("H {}", if h != 0 { db.len() } else { 0 }));
                print_r = false;
            }
            "X" => dbsync_teardown(),
            "TX" => {
                let j = json(f[2]);
                let t = dbsync_create_txn(
                    handle(&db, f[1]),
                    j.as_ref(),
                    f[3].parse().unwrap(),
                    f[4].parse().unwrap(),
                    if f.len() > 5 { None } else { Some(cb.clone()) },
                );
                if t != 0 {
                    txn.push(t);
                }
                emit(format!("H {}", if t != 0 { txn.len() } else { 0 }));
                print_r = false;
            }
            "TC" => r = dbsync_close_txn(handle(&txn, f[1])),
            "TR" => r = dbsync_sync_txn_row(handle(&txn, f[1]), json(f[2]).as_ref()),
            "TD" => r = dbsync_get_deleted_rows(handle(&txn, f[1]), Some(cb.clone())),
            "L" | "I" | "S" | "Q" | "D" | "U" | "V" => {
                let j = json(f[2]);
                let h = handle(&db, f[1]);
                r = match f[0] {
                    "L" => dbsync_add_table_relationship(h, j.as_ref()),
                    "I" => dbsync_insert_data(h, j.as_ref()),
                    "S" => dbsync_sync_row(h, j.as_ref(), Some(cb.clone())),
                    "Q" => dbsync_select_rows(h, j.as_ref(), Some(cb.clone())),
                    "D" => dbsync_delete_rows(h, j.as_ref()),
                    "V" => dbsync_update_with_snapshot_cb(h, j.as_ref(), Some(cb.clone())),
                    _ => {
                        let (ret, res) = dbsync_update_with_snapshot(h, j.as_ref(), true);
                        if let Some(Some(res)) = res {
                            emit(format!("J {}", hex(&res.print_unformatted())));
                        }
                        ret
                    }
                };
            }
            "M" => r = dbsync_set_table_max_rows(handle(&db, f[1]), opt(f[2]).as_deref(), f[3].parse().unwrap()),
            "RC" => {
                let h = rsync_create(f[1].parse().unwrap(), f[2].parse().unwrap());
                if h != 0 {
                    rs.push(h);
                }
                emit(format!("H {}", if h != 0 { rs.len() } else { 0 }));
                print_r = false;
            }
            "RS" => r = rsync_start_sync(handle(&rs, f[1]), handle(&db, f[2]), json(f[3]).as_ref(), Some(scb.clone())),
            "RR" => {
                r = rsync_register_sync_id(handle(&rs, f[1]), opt(f[2]).as_deref(), handle(&db, f[3]), json(f[4]).as_ref(), Some(scb.clone()))
            }
            "RP" => r = rsync_push_message(handle(&rs, f[1]), opt(f[2]).as_deref()),
            "RX" => {
                r = rsync_close(handle(&rs, f[1]));
                flush_pending();
            }
            "RT" => {
                rsync_teardown();
                flush_pending();
            }
            "SLEEP" => {
                std::thread::sleep(std::time::Duration::from_millis(f[1].parse().unwrap()));
                print_r = false;
            }
            "DUMP" => {
                dump(&unhex(f[1]));
                print_r = false;
            }
            _ => {
                emit(format!("? {line}"));
                print_r = false;
            }
        }
        if print_r {
            emit(format!("R {r}"));
        }
    }
    std::mem::take(&mut out().lock().unwrap().lines)
}

fn run_oracle(cmd: &str, dir: &Path, input: &str) -> Vec<String> {
    let mut child = Command::new(cmd).current_dir(dir).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn oracle");
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_string();
    let w = std::thread::spawn(move || {
        let _ = stdin.write_all(data.as_bytes());
    });
    let mut s = String::new();
    child.stdout.take().unwrap().read_to_string(&mut s).unwrap();
    w.join().unwrap();
    child.wait().unwrap();
    s.lines().map(String::from).collect()
}

// ------------------------------------------------------------- scripts

fn h(s: &str) -> String {
    hex(s.as_bytes())
}

const SCHEMA: &str = "CREATE TABLE processes (pid BIGINT, name TEXT, nice INTEGER, size UNSIGNED BIGINT, cpu DOUBLE, start TEXT, checksum TEXT, PRIMARY KEY (pid));\
CREATE TABLE ports (inode BIGINT, local_ip TEXT, local_port INTEGER, protocol TEXT, checksum TEXT, PRIMARY KEY (inode, protocol, local_port));\
CREATE TABLE packages (name TEXT, version TEXT, architecture TEXT, size BIGINT, checksum TEXT, item_id TEXT, PRIMARY KEY (name, version, architecture));\
CREATE TABLE files (path TEXT, inode INTEGER, size UNSIGNED BIGINT, mtime BIGINT, hash TEXT, checksum TEXT, PRIMARY KEY (path));\
CREATE TABLE nokeys (a TEXT, b INTEGER);\
CREATE TABLE odd (k TEXT PRIMARY KEY, v BLOB, w NUMERIC, x HIDDEN_TYPE)";

/// The corpus: every API function on good and bad input.
fn corpus() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut c = |s: String| v.push(s);
    // creation
    c(format!("C 1 1 - {}", h(SCHEMA)));
    c(format!("C 1 1 {} -", h("x.db")));
    c(format!("C 1 0 {} {}", h("x.db"), h(SCHEMA)));
    c(format!("C 1 1 {} {}", h(""), h(SCHEMA)));
    c(format!("C 1 1 {} {}", h("bad.db"), h("CREATE TABLE a(x;")));
    c(format!("C 1 1 {} {}", h("bad2.db"), h("CREATE TABLE a(x); ")));
    c(format!("C 1 1 {} {}", h("bad3.db"), h("SELECT 1;")));
    c(format!("C 1 1 {} {}", h("nodir/x.db"), h(SCHEMA)));
    c(format!("C 1 1 {} {}", h("main.db"), h(SCHEMA))); // handle 1
    c(format!("C 0 1 {} {}", h(":memory:"), h("CREATE TABLE t (k TEXT PRIMARY KEY, n BIGINT)"))); // handle 2
    // inserts
    let procs = r#"{"table":"processes","data":[{"pid":1,"name":"init","nice":0,"size":1000,"cpu":1.5,"start":"t0","checksum":"c1"},{"pid":2,"name":"bash","nice":-5,"size":2000,"cpu":0.25,"start":"t1","checksum":"c2"},{"pid":3,"name":"x","checksum":"c3"}]}"#;
    c(format!("I 1 {}", h(procs)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":[{"pid":1,"name":"dup"}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"nosuch","data":[{"a":1}]}"#)));
    c(format!("I 1 {}", h(r#"{"data":[{"a":1}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes"}"#)));
    c(format!("I 1 {}", h(r#"{}"#)));
    c(format!("I 1 {}", h(r#"{"table":5,"data":[]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":["str"]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":[null]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":[{"pid":"77x","name":5,"nice":"12","size":"-1","cpu":"2.5e1"}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":[{"pid":"abc"}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":[{"pid":9,"nice":"99999999999"}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":[{"pid":10,"cpu":"1e-400"}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":[{"pid":11.7,"size":5.5,"nice":true,"cpu":3}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":{"x":{"pid":12,"name":"obj"}}}"#)));
    c(format!("I 1 {}", h(r#"{"table":"odd","data":[{"k":"a","v":"b","w":1}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"ports","data":[{"inode":10,"local_ip":"0.0.0.0","local_port":22,"protocol":"tcp","checksum":"p1"},{"inode":11,"local_ip":"::","local_port":80,"protocol":"tcp6","checksum":"p2"}]}"#)));
    c(format!("I 0 {}", h(procs)));
    c(format!("I 9999 {}", h(procs)));
    c("I 1 -".into());
    c(format!("I 1 {}", h("not json")));
    // selects
    for q in [
        r#"{"table":"processes","query":{"column_list":["*"],"row_filter":"","distinct_opt":false,"order_by_opt":"pid"}}"#,
        r#"{"table":"processes","query":{"column_list":["pid","name"],"row_filter":"WHERE pid > 1","distinct_opt":true,"order_by_opt":"pid DESC","count_opt":1}}"#,
        r#"{"table":"processes","query":{"column_list":["count(*) AS n"],"row_filter":"","distinct_opt":false,"order_by_opt":""}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"row_filter":"WHERE name = ? AND pid > ?","row_filter_params":[{"type":"text","value":"bash"},{"type":"int","value":1}],"distinct_opt":false,"order_by_opt":""}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"row_filter":"WHERE name = ?","row_filter_params":[{"type":"blob","value":"bash"}]}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"row_filter":"WHERE name = ?","row_filter_params":[{"type":"int","value":"x"}]}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"row_filter":"WHERE name = ?"}}"#,
        r#"{"table":"processes","query":{"column_list":["nosuchcol"]}}"#,
        r#"{"table":"processes","query":{"column_list":[5]}}"#,
        r#"{"table":"processes","query":{"column_list":[]}}"#,
        r#"{"table":"processes","query":{"row_filter":""}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"distinct_opt":"yes"}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"count_opt":-1}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"count_opt":2.9}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"row_filter":5}}"#,
        r#"{"table":"processes","query":{"column_list":["*"],"order_by_opt":[1]}}"#,
        r#"{"table":"odd","query":{"column_list":["*"]}}"#,
        r#"{"table":"odd","query":{"column_list":["k","x'00ff' AS b"]}}"#,
        r#"{"table":"nosuch","query":{"column_list":["*"]}}"#,
        r#"{"table":"processes"}"#,
        r#"{"query":{"column_list":["*"]}}"#,
        r#"{}"#,
        r#"[]"#,
        r#"{"table":"processes","query":{"column_list":["db_status_field_dm","pid"]}}"#,
    ] {
        c(format!("Q 1 {}", h(q)));
    }
    c("Q 0 -".into());
    // sync rows
    for s in [
        r#"{"table":"processes","data":[{"pid":1,"name":"init","nice":0,"size":1000,"cpu":1.5,"start":"t0","checksum":"c1"}]}"#,
        r#"{"table":"processes","data":[{"pid":1,"name":"systemd","checksum":"c1b"}]}"#,
        r#"{"table":"processes","data":[{"pid":1,"name":"systemd2","checksum":"c1c"}],"options":{"return_old_data":true}}"#,
        r#"{"table":"processes","data":[{"pid":1,"name":"systemd2","checksum":"c1d"}],"options":{"return_old_data":true,"ignore":["checksum"]}}"#,
        r#"{"table":"processes","data":[{"pid":1,"name":"systemd3","checksum":"c1e"}],"options":{"ignore":["checksum"]}}"#,
        r#"{"table":"processes","data":[{"pid":1,"name":"s","checksum":"c1f"}],"options":{"ignore":"checksum","return_old_data":"yes"}}"#,
        r#"{"table":"processes","data":[{"pid":50,"name":"new","cpu":2,"size":7}]}"#,
        r#"{"table":"processes","data":[{"pid":50,"name":"new","cpu":2.0,"size":7}]}"#,
        r#"{"table":"processes","data":[{"pid":50,"name":"new","cpu":2.0,"size":"7"}]}"#,
        r#"{"table":"processes","data":[{"name":"nopid"}]}"#,
        r#"{"table":"processes","data":[{"pid":51,"nosuchcol":1}]}"#,
        r#"{"table":"processes","data":[{"pid":1,"nosuchcol":1}]}"#,
        r#"{"table":"processes","data":["x"]}"#,
        r#"{"table":"processes","data":[]}"#,
        r#"{"table":"processes","data":{"pid":60,"name":"one"}}"#,
        r#"{"table":"nokeys","data":[{"a":"x","b":1}]}"#,
        r#"{"table":"nosuch","data":[{"a":1}]}"#,
        r#"{"table":"ports","data":[{"inode":10,"local_ip":"127.0.0.1","local_port":22,"protocol":"tcp","checksum":"p1b"}]}"#,
        r#"{"table":"ports","data":[{"inode":12,"local_port":443,"protocol":"tcp"}]}"#,
        r#"{"table":"files","data":[{"path":"/a","inode":18446744073709551615,"size":5,"mtime":-1,"hash":"h","checksum":"f1"}]}"#,
        r#"{"table":"files","data":[{"path":"/a","inode":18446744073709551615,"size":5,"mtime":-1,"hash":"h2","checksum":"f2"}],"options":{"return_old_data":true}}"#,
        r#"{"table":"files","data":[{"path":"/b","inode":"77","size":"18446744073709551615","mtime":"x"}]}"#,
        r#"{"data":[]}"#,
        r#"{"table":"processes"}"#,
    ] {
        c(format!("S 1 {}", h(s)));
    }
    c("S 0 -".into());
    // row limits
    c(format!("M 1 {} 5", h("processes")));
    c(format!("S 1 {}", h(r#"{"table":"processes","data":[{"pid":100},{"pid":101},{"pid":102},{"pid":103},{"pid":104},{"pid":105}]}"#)));
    c(format!("I 1 {}", h(r#"{"table":"processes","data":[{"pid":200},{"pid":201}]}"#)));
    c(format!("M 1 {} -1", h("processes")));
    c(format!("M 1 {} 0", h("processes")));
    c(format!("M 1 {} 3", h("nosuch")));
    c(format!("M 1 - 3"));
    c(format!("M 0 {} 3", h("processes")));
    // relationships
    c(format!("L 1 {}", h(r#"{"base_table":"processes","relationed_tables":[{"table":"ports","field_match":{"inode":"pid"}}]}"#)));
    c(format!("L 1 {}", h(r#"{"base_table":"processes","relationed_tables":[{"table":"ports","field_match":["pid"]}]}"#)));
    c(format!("L 1 {}", h(r#"{"base_table":"nosuch","relationed_tables":[]}"#)));
    c(format!("L 1 {}", h(r#"{"base_table":"files"}"#)));
    c(format!("L 1 {}", h(r#"{"relationed_tables":[]}"#)));
    c(format!("L 1 {}", h(r#"{"base_table":"files","relationed_tables":[{"table":"ports","field_match":{"inode":5}}]}"#)));
    c(format!("L 1 {}", h(r#"{"base_table":"nokeys","relationed_tables":[{"table":"ports","field_match":{"inode":"b"}}]}"#)));
    // deletes
    for d in [
        r#"{"table":"processes","query":{"data":[{"pid":2},{"pid":999}]}}"#,
        r#"{"table":"processes","query":{"where_filter_opt":"pid >= 100"}}"#,
        r#"{"table":"processes","query":{"where_filter_opt":"bad syntax here"}}"#,
        r#"{"table":"processes","query":{"where_filter_opt":""}}"#,
        r#"{"table":"processes","query":{"data":[]}}"#,
        r#"{"table":"processes","query":{"where_filter_opt":5}}"#,
        r#"{"table":"processes","query":{}}"#,
        r#"{"table":"processes"}"#,
        r#"{"table":"ports","query":{"data":[{"inode":10,"local_port":22}]}}"#,
        r#"{"table":"ports","query":{"data":[{"inode":10,"local_port":22,"protocol":"tcp"}]}}"#,
        r#"{"table":"nokeys","query":{"data":[{"a":"x"}]}}"#,
        r#"{"table":"nosuch","query":{"data":[{"a":"x"}]}}"#,
        r#"{"query":{"data":[]}}"#,
    ] {
        c(format!("D 1 {}", h(d)));
    }
    // snapshots
    for u in [
        r#"{"table":"packages","data":[{"name":"a","version":"1","architecture":"x","size":1,"checksum":"k1","item_id":"i1"},{"name":"b","version":"2","architecture":"x","size":2,"checksum":"k2","item_id":"i2"}]}"#,
        r#"{"table":"packages","data":[{"name":"a","version":"1","architecture":"x","size":10,"checksum":"k1b","item_id":"i1"},{"name":"c","version":"3","architecture":"y","size":3,"checksum":"k3","item_id":"i3"}]}"#,
        r#"{"table":"packages","data":[{"name":"a","version":"1","architecture":"x","size":10,"checksum":"it's","item_id":"i1"}]}"#,
        r#"{"table":"packages","data":[]}"#,
        r#"{"table":"packages","data":[{"name":"d"}]}"#,
        r#"{"table":"nosuch","data":[]}"#,
        r#"{"table":5,"data":[]}"#,
        r#"{"table":"packages"}"#,
        r#"{"data":[]}"#,
        r#"{"table":"processes","data":[{"pid":1,"name":"systemd9","cpu":0.1}]}"#,
    ] {
        c(format!("U 1 {}", h(u)));
        c(format!("V 1 {}", h(u)));
    }
    c("U 1 -".into());
    // transactions
    c(format!("TX 1 {} 1 100", h(r#"["processes","ports"]"#))); // txn 1
    c(format!("TR 1 {}", h(r#"{"table":"processes","data":[{"pid":1,"name":"systemd9","cpu":0.1}]}"#)));
    c(format!("TR 1 {}", h(r#"{"table":"processes","data":[{"pid":3,"name":"x2","checksum":"c3"}]}"#)));
    c(format!("TR 1 {}", h(r#"{"table":"processes","data":[{"pid":300,"name":"new"}]}"#)));
    c(format!("TR 1 {}", h(r#"{"table":"ports","data":[{"inode":"11","local_port":80,"protocol":"tcp6"}]}"#)));
    c(format!("TR 1 {}", h(r#"{"table":"packages","data":[{"name":"a"}]}"#)));
    c(format!("TR 1 {}", h(r#"{"table":"processes","data":[{"name":"nopid"}]}"#)));
    c(format!("TR 1 {}", h(r#"{"data":[]}"#)));
    c(format!("TR 1 {}", h(r#""str""#)));
    c(format!("TR 1 {}", h(r#"{"table":"processes","data":[{"pid":301,"inode":5}]}"#)));
    c("TR 1 -".into());
    c(format!("TR 0 {}", h(r#"{"table":"processes","data":[]}"#)));
    c(format!("TR 9999 {}", h(r#"{"table":"processes","data":[]}"#)));
    c("TD 1".into());
    c(format!("TR 1 {}", h(r#"{"table":"processes","data":[{"pid":302,"name":"after"}]}"#)));
    c("TD 1".into());
    c("TC 1".into());
    c("TC 1".into());
    c("TC 0".into());
    c(format!("TX 1 {} 1 0", h(r#"["processes"]"#)));
    c(format!("TX 1 {} 1 1 nocb", h(r#"["processes"]"#)));
    c(format!("TX 1 {} 1 1", h(r#"["nosuch"]"#)));
    c(format!("TX 1 {} 1 1", h(r#"[5]"#)));
    c(format!("TX 0 {} 1 1", h(r#"["processes"]"#)));
    c(format!("TX 9999 {} 1 1", h(r#"["processes"]"#)));
    c(format!("TX 1 {} 1 1", h(r#"{"a":"files"}"#))); // txn 2 (object: its values)
    c(format!("TR 2 {}", h(r#"{"table":"files","data":[{"path":"/a","inode":5,"checksum":"zz"}]}"#)));
    c("TD 2".into());
    c(format!("TX 1 {} 1 1", h(r#"["files","packages"]"#))); // txn 3: max_queue 1
    c(format!("TR 3 {}", h(r#"{"table":"packages","data":[{"name":"a","version":"1","architecture":"x","size":11,"checksum":"q"}],"options":{"return_old_data":true}}"#)));
    c(format!("M 1 {} 1", h("files")));
    c(format!("TR 3 {}", h(r#"{"table":"files","data":[{"path":"/z1"},{"path":"/z2"}]}"#)));
    c("TD 3".into());
    c("TD 0".into());
    c("TD 9999".into());
    c("TC 3".into());
    // the second database
    c(format!("S 2 {}", h(r#"{"table":"t","data":[{"k":"a","n":1},{"k":"b","n":2}]}"#)));
    c(format!("Q 2 {}", h(r#"{"table":"t","query":{"column_list":["*"]}}"#)));
    // rsync
    c("RC 1 0".into()); // rsync 1
    let reg = r#"{"decoder_type":"JSON_RANGE","table":"packages","component":"syscollector_packages","index":"item_id","checksum_field":"checksum","last_event":"name","no_data_query_json":{"row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id","column_list":["*"],"distinct_opt":false,"order_by_opt":""},"count_range_query_json":{"row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id","count_field_name":"count","column_list":["count(*) AS count"],"distinct_opt":false,"order_by_opt":""},"row_data_query_json":{"row_filter":"WHERE item_id ='?'","column_list":["*"],"distinct_opt":false,"order_by_opt":""},"range_checksum_query_json":{"row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id","column_list":["*"],"distinct_opt":false,"order_by_opt":""}}"#;
    let start = r#"{"table":"packages","first_query":{"column_list":["item_id"],"row_filter":" ","order_by_opt":"item_id ASC","count_opt":1,"distinct_opt":false},"last_query":{"column_list":["item_id"],"row_filter":" ","order_by_opt":"item_id DESC","count_opt":1,"distinct_opt":false},"component":"syscollector_packages","index":"item_id","last_event":"name","checksum_field":"checksum","range_checksum_query_json":{"row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id","column_list":["item_id, checksum"],"distinct_opt":false,"order_by_opt":"","count_opt":100}}"#;
    c(format!("RR 1 {} 1 {}", h("syscollector_packages"), h(reg)));
    c(format!("RR 1 {} 1 {}", h("syscollector_packages"), h(reg)));
    c(format!("RR 1 {} 1 {}", h("other"), h(r#"{"decoder_type":"XML"}"#)));
    c(format!("RR 1 {} 1 {}", h("other2"), h(r#"{"decoder_type":5}"#)));
    c(format!("RR 1 - 1 {}", h(reg)));
    c(format!("RR 0 {} 1 {}", h("x3"), h(reg)));
    c(format!("RS 1 1 {}", h(start)));
    c(format!("RS 1 1 {}", h(r#"{"table":"packages"}"#)));
    c(format!("RS 1 1 {}", h(r#"{"table":"","first_query":{},"last_query":{}}"#)));
    c(format!("RS 1 1 {}", h(r#"{"table":"packages","first_query":{},"last_query":{}}"#)));
    c(format!("RS 0 1 {}", h(start)));
    c(format!("RS 1 0 {}", h(start)));
    for p in [
        r#"syscollector_packages checksum_fail {"begin":"i1","end":"i3","id":1700000000}"#,
        r#"syscollector_packages checksum_fail {"begin":"i1","end":"i1","id":1700000000}"#,
        r#"syscollector_packages checksum_fail {"begin":"i8","end":"i9","id":1700000000}"#,
        r#"syscollector_packages no_data {"begin":"i1","end":"i3","id":1700000000}"#,
        r#"syscollector_packages no_data {"begin":"i1","end":"i3","id":1699999999}"#,
        r#"syscollector_packages no_data {"begin":"i1","end":"i3","id":1700000001}"#,
        r#"syscollector_packages bogus {"begin":"i1","end":"i3","id":1}"#,
        r#"syscollector_packages checksum_fail {"begin":1,"end":3,"id":1}"#,
        r#"syscollector_packages checksum_fail {"begin":"x"}"#,
        r#"syscollector_packages checksum_fail notjson"#,
        r#"syscollector_packages checksum_fail"#,
        r#"unknown checksum_fail {}"#,
        r#"noheader"#,
        r#"syscollector_packages checksum_fail {"begin":"i'1","end":"i3","id":1}"#,
    ] {
        c(format!("RP 1 {}", h(p)));
    }
    c("RP 1 -".into());
    c("RP 0 -".into());
    c("RX 1".into());
    c("RX 1".into());
    c("RP 1 00".into());
    c("RC 2 0".into()); // rsync 2
    c(format!("RS 2 1 {}", h(&start.replace("item_id", "size").replace("syscollector_packages", "s2"))));
    c(format!("RR 2 {} 1 {}", h("s2"), h(&reg.replace("syscollector_packages", "s2"))));
    c(format!("RP 2 {}", h(r#"s2 checksum_fail {"begin":"a","end":"z","id":1700000000}"#)));
    // (a push right before rsync_teardown races the worker in the C++ too)
    c("RX 2".into());
    c("RT".into());
    c("RP 2 00".into());
    // teardown and the files
    c("X".into());
    c(format!("Q 1 {}", h(r#"{"table":"processes","query":{"column_list":["*"]}}"#)));
    c(format!("DUMP {}", h("main.db")));
    // persistent databases
    let p_schema = "CREATE TABLE t (k TEXT PRIMARY KEY, n BIGINT);";
    c(format!("P 1 1 {} {} 0", h("p.db"), h(p_schema))); // 3
    c(format!("S 3 {}", h(r#"{"table":"t","data":[{"k":"a","n":1}]}"#)));
    c("X".into());
    c(format!("P 1 1 {} {} 2 {} {}", h("p.db"), h(p_schema), h("ALTER TABLE t ADD COLUMN m TEXT;"), h("ALTER TABLE t ADD COLUMN o TEXT;"))); // 4
    c(format!("S 4 {}", h(r#"{"table":"t","data":[{"k":"a","n":2,"m":"x"}]}"#)));
    c(format!("TX 4 {} 1 1", h(r#"["t"]"#)));
    c("X".into());
    c(format!("DUMP {}", h("p.db")));
    c(format!("P 1 1 {} {} 2 {} {}", h("p.db"), h(p_schema), h("ALTER TABLE t ADD COLUMN m TEXT;"), h("ALTER TABLE t ADD COLUMN o TEXT;"))); // 5: current version, no transaction
    c(format!("Q 5 {}", h(r#"{"table":"t","query":{"column_list":["*"]}}"#)));
    c(format!("P 1 1 {} {} 3 {} {} {}", h("p.db"), h(p_schema), h("ALTER TABLE t ADD COLUMN m TEXT;"), h("ALTER TABLE t ADD COLUMN o TEXT;"), h("bad sql"))); // upgrade fails
    c(format!("P 1 1 {} {} -1", h("p2.db"), h(p_schema)));
    c("X".into());
    c(format!("DUMP {}", h("p.db")));
    c(format!("DUMP {}", h("p2.db")));
    c(format!("DUMP {}", h("nosuch.db")));
    v
}

// ------------------------------------------------------------- mutation

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const TOKENS: &[&str] = &[
    "null", "1", "-1", "0", "1.5", "\"x\"", "\"\"", "[]", "{}", "true", "18446744073709551615", "\"processes\"", "\"files\"",
    "\"pid\"", "\"inode\"", "\"checksum\"", "\"12\"", "\"-3\"", "\"a'b\"", "[\"processes\"]", "\"db_status_field_dm\"", "2.5e300",
];

fn mutate_json(rng: &mut Rng, s: &[u8]) -> Vec<u8> {
    let mut s = s.to_vec();
    for _ in 0..1 + rng.below(3) {
        let pos = if s.is_empty() { 0 } else { rng.below(s.len()) };
        match rng.below(4) {
            0 if !s.is_empty() => {
                s.remove(pos);
            }
            1 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                // replace a JSON value-ish region with a token
                let end = (pos + 1 + rng.below(6)).min(s.len());
                s.splice(pos..end, t.bytes());
            }
            2 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                s.splice(pos..pos, t.bytes());
            }
            _ => {
                const C: &[u8] = b"{}[],:\" 0123456789-.eatrufnl'\\";
                s.insert(pos, C[rng.below(C.len())]);
            }
        }
    }
    s
}

/// A pause before each rsync_close / rsync_teardown (see SLEEP).
fn with_drains(script: Vec<String>) -> Vec<String> {
    let mut v = Vec::new();
    for l in script {
        if l.starts_with("RX ") || l == "RT" {
            v.push("SLEEP 300".to_string());
        }
        v.push(l);
    }
    v
}

fn fuzz_script(base: &[String], rng: &mut Rng, n: usize) -> Vec<String> {
    // a fresh database, then mutated operations from the corpus
    let mut v = vec![format!("C 1 1 {} {}", h("fz.db"), h(SCHEMA))];
    let ops: Vec<&String> = base
        .iter()
        .filter(|l| {
            let c = l.split(' ').next().unwrap_or("");
            matches!(c, "I" | "S" | "Q" | "D" | "U" | "V" | "L" | "TR")
        })
        .collect();
    let mut txn = 0;
    for i in 0..n {
        if i % 40 == 0 {
            if txn > 0 && rng.below(2) == 0 {
                v.push(format!("TD {txn}"));
                v.push(format!("TC {txn}"));
            }
            v.push(format!("TX 1 {} 1 {}", h(r#"["processes","ports","packages","files"]"#), 1 + rng.below(3) * 50));
            txn += 1;
        }
        let l = ops[rng.below(ops.len())];
        let f: Vec<&str> = l.split(' ').collect();
        if f.len() < 3 || f[2] == "-" {
            continue;
        }
        let m = mutate_json(rng, &unhex(f[2]));
        let target = if f[0] == "TR" { txn.to_string() } else { "1".to_string() };
        v.push(format!("{} {} {}", f[0], target, hex(&m)));
    }
    v.push(format!("TD {txn}"));
    // rsync over what the database holds now: mutated configurations and
    // protocol messages (one worker thread, flushed by rsync_close)
    let rs_ops: Vec<&String> = base.iter().filter(|l| l.starts_with("RR 1 ") || l.starts_with("RS 1 1 ") || l.starts_with("RP 1 ")).collect();
    let mut handle = 0;
    for i in 0..n / 4 {
        if i % 25 == 0 {
            if handle > 0 {
                v.push(format!("RX {handle}"));
            }
            v.push("RC 1 0".into());
            handle += 1;
            // a valid registration and start first, mutated ones later
            for l in base.iter().filter(|l| l.starts_with("RR 1 ") || l.starts_with("RS 1 1 ")).take(2) {
                let f: Vec<&str> = l.split(' ').collect();
                let mut g: Vec<String> = f.iter().map(|s| s.to_string()).collect();
                g[1] = handle.to_string();
                v.push(g.join(" "));
            }
        }
        let l = rs_ops[rng.below(rs_ops.len())];
        let mut f: Vec<String> = l.split(' ').map(String::from).collect();
        f[1] = handle.to_string();
        let last = f.len() - 1;
        if f[last] != "-" && rng.below(4) != 0 {
            let m = mutate_json(rng, &unhex(&f[last]));
            f[last] = hex(&m);
        }
        if f[0] == "RR" && rng.below(2) == 0 {
            // a fresh component name keeps registrations possible
            f[2] = hex(format!("c{}", rng.below(5)).as_bytes());
        }
        v.push(f.join(" "));
    }
    if handle > 0 {
        v.push(format!("RX {handle}"));
    }
    v.push("RT".into());
    v.push("X".into());
    v.push(format!("DUMP {}", h("fz.db")));
    v
}

#[test]
fn dbsync_matches_oracle() {
    let Ok(cmd) = std::env::var("SIEM_DBSYNC_ORACLE") else {
        eprintln!("SIEM_DBSYNC_ORACLE not set: skipping");
        return;
    };
    let fuzz: usize = std::env::var("SIEM_DBSYNC_FUZZ").ok().and_then(|s| s.parse().ok()).unwrap_or(400);
    let seed: u64 = std::env::var("SIEM_DBSYNC_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let base = corpus();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x2545_F491_4F6C_DD1D));
    let mut scripts = vec![with_drains(base.clone())];
    if fuzz > 0 {
        scripts.push(with_drains(fuzz_script(&base, &mut rng, fuzz)));
    }
    let work: PathBuf = std::env::temp_dir().join(format!("siem_dbsync_oracle_{}", std::process::id()));
    let keep = std::env::var("SIEM_DBSYNC_KEEP").ok();
    let mut total = 0;
    for (n, script) in scripts.iter().enumerate() {
        let input: String = script.iter().map(|l| format!("{l}\n")).collect();
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let oracle = run_oracle(&cmd, &work, &input);
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        std::env::set_current_dir(&work).unwrap();
        let rust = run_rust(script);
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        if let Some(k) = &keep {
            let _ = std::fs::create_dir_all(k);
            let _ = std::fs::write(format!("{k}/input{n}.txt"), &input);
            let _ = std::fs::write(format!("{k}/rust{n}.txt"), rust.join("\n"));
            let _ = std::fs::write(format!("{k}/oracle{n}.txt"), oracle.join("\n"));
        }
        // align on R/H lines (one per command)
        let mut diffs = 0;
        let (mut i, mut j) = (0, 0);
        let mut cmd_no = 0;
        let mut cur_r: Vec<&String> = Vec::new();
        let mut cur_o: Vec<&String> = Vec::new();
        let is_end = |l: &str| l.starts_with("R ") || l.starts_with("H ") || l.starts_with("?");
        while i < rust.len() || j < oracle.len() {
            cur_r.clear();
            cur_o.clear();
            while i < rust.len() {
                cur_r.push(&rust[i]);
                i += 1;
                if is_end(&rust[i - 1]) {
                    break;
                }
            }
            while j < oracle.len() {
                cur_o.push(&oracle[j]);
                j += 1;
                if is_end(&oracle[j - 1]) {
                    break;
                }
            }
            if cur_r != cur_o {
                diffs += 1;
                if diffs <= 15 {
                    eprintln!("--- script {n} command #{cmd_no}");
                    for l in &cur_r {
                        eprintln!("  rust:   {}", decode(l));
                    }
                    for l in &cur_o {
                        eprintln!("  oracle: {}", decode(l));
                    }
                }
            }
            cmd_no += 1;
        }
        eprintln!("script {n}: {} commands, {} lines, {diffs} differing commands", script.len(), oracle.len());
        total += diffs;
    }
    let _ = std::fs::remove_dir_all(&work);
    assert_eq!(total, 0);
}

fn decode(l: &str) -> String {
    let p: Vec<&str> = l.split(' ').collect();
    let t = |s: &str| String::from_utf8_lossy(&unhex(s)).chars().take(500).collect::<String>();
    match p.as_slice() {
        ["M", x] | ["N", x] | ["E", x] | ["Y", x] | ["J", x] => format!("{} {:?}", p[0], t(x)),
        ["B", ty, x] if *x != "-" => format!("B {ty} {:?}", t(x)),
        ["F", a, b, c, d, e, x] => format!("F {a} {b} {c} {d} {e} {:?}", t(x)),
        ["W", tb, row] => format!("W {} {}", t(tb), row),
        ["S", a, b] if *b != "-" => format!("S {} {:?}", t(a), t(b)),
        _ => l.to_string(),
    }
}
