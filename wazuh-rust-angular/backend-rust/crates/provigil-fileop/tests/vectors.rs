//! Replays `specs/vectors/siem-fileop/*.json`, recorded from the crate this one replaces.
//! `pure` runs everywhere; the `*_unix` files run on Unix only, the `*_windows` files on Windows only.

use provigil_fileop::version_op::{self, OsInfo, System, UtsName};
use provigil_fileop::*;
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{env, fs};
use tracing::field::{Field, Visit};
use tracing::span;

type Logs = Arc<Mutex<Vec<(String, String)>>>;

/// Collects log events of the current thread.
struct Capture(Logs);

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        struct Msg(String);
        impl Visit for Msg {
            fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
                if f.name() == "message" {
                    self.0 = format!("{v:?}");
                }
            }
        }
        let mut m = Msg(String::new());
        e.record(&mut m);
        self.0.lock().unwrap().push((e.metadata().level().to_string(), m.0));
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

/// Runs `f`, returning its result and its logs with `root` shown as `<root>`.
fn logged<T>(root: &str, f: impl FnOnce() -> T) -> (T, Value) {
    let logs = Logs::default();
    let r = tracing::subscriber::with_default(Capture(logs.clone()), f);
    let got = logs.lock().unwrap().iter().map(|(l, m)| json!([l, m.replace(root, "<root>")])).collect();
    (r, Value::Array(got))
}

/// Cases and mismatches of one vector file.
struct Run {
    name: &'static str,
    cases: Vec<Value>,
    passed: usize,
    failed: Vec<String>,
    errs: Vec<String>,
}

impl Run {
    fn new(name: &'static str) -> Run {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/vectors/siem-fileop").join(format!("{name}.json"));
        let mut doc: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let cases = doc["cases"].as_array_mut().map(std::mem::take).unwrap();
        assert_eq!(doc["meta"]["count"].as_u64(), Some(cases.len() as u64), "{name}: case count");
        Run { name, cases, passed: 0, failed: vec![], errs: vec![] }
    }

    fn eq(&mut self, what: &str, got: impl Into<Value>, want: &Value) {
        let got = got.into();
        if &got != want {
            let cut = |v: &Value| v.to_string().chars().take(400).collect::<String>();
            self.errs.push(format!("{what}: got {} want {}", cut(&got), cut(want)));
        }
    }

    fn done(&mut self, label: impl std::fmt::Display) {
        if self.errs.is_empty() {
            self.passed += 1;
        } else {
            self.failed.push(format!("[{label}] {}", self.errs.join(" | ")));
            self.errs.clear();
        }
    }

    fn finish(self) {
        let total = self.passed + self.failed.len();
        println!("VECTORS {}: {}/{} passed", self.name, self.passed, total);
        for f in self.failed.iter().take(30) {
            println!("  FAIL {f}");
        }
        assert!(self.failed.is_empty(), "{}: {} failed", self.name, self.failed.len());
        assert!(total > 0, "{}: nothing checked", self.name);
    }
}

fn scratch() -> (PathBuf, String) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = env::temp_dir().join(format!("pv-fileop-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    let s = d.to_string_lossy().into_owned();
    (d, s)
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(s(v)).unwrap()
}

fn tree_into(base: &Path, dir: &Path, out: &mut Map<String, Value>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let rel = p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
        if p.is_dir() {
            out.insert(rel, "<dir>".into());
            tree_into(base, &p, out);
        } else {
            out.insert(rel, hex::encode(fs::read(&p).unwrap()).into());
        }
    }
}

fn tree(base: &Path) -> Map<String, Value> {
    let mut out = Map::new();
    tree_into(base, base, &mut out);
    out
}

#[test]
fn pure() {
    let mut r = Run::new("pure");
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        let input = s(&c["input"]);
        match s(&c["fn"]) {
            "dirname" => r.eq("dirname", dirname(input), &c["result"]),
            "default_path_offset" => r.eq("offset", default_path_offset(input), &c["result"]),
            "crt::text_in" => r.eq("in", hex::encode(crt::text_in(&unhex(&c["input_hex"]))), &c["result_hex"]),
            "crt::text_out" => r.eq("out", hex::encode(crt::text_out(&unhex(&c["input_hex"]))), &c["result_hex"]),
            "crt::network_path_executed" => r.eq("text", crt::network_path_executed(input), &c["result"]),
            "md5_hex" => r.eq("md5", md5_hex(&unhex(&c["input_hex"])), &c["result"]),
            "version_op::osx_release_name" => {
                r.eq("name", version_op::osx_release_name(c["input"].as_i64().unwrap() as i32), &c["result"])
            }
            _ => {
                let product = format!("{} {}", s(&c["OSSEC_NAME"]), s(&c["OSSEC_VERSION"]));
                r.eq("product", version_op::AGENT_PRODUCT, &product.into());
            }
        }
        r.done(n);
    }
    r.finish();
}

fn merge_case(r: &mut Run, c: &Value) {
    let (dir, root) = scratch();
    fs::create_dir_all(dir.join("g/sub")).unwrap();
    fs::write(dir.join("g/agent.conf"), "<agent_config/>\n").unwrap();
    fs::write(dir.join("g/sub/x.txt"), "x").unwrap();
    fs::write(dir.join("g/empty"), "").unwrap();
    fs::write(dir.join("g/sp ace.txt"), "a b\r\nc").unwrap();
    fs::write(dir.join("g/bin.dat"), [0u8, 1, 0xff]).unwrap();
    let file = s(&c["file"]).replace("<root>", &root);
    let offset = match s(&c["path_offset"]) {
        "" => None,
        "root length + 3" => Some(root.len() + 3),
        n => Some(n.parse().unwrap()),
    };
    let mut out = s(&c["buffer_before"]).as_bytes().to_vec();
    let (ok, logs) = logged(&root, || merge_append_file(&mut out, &file, offset));
    r.eq("ok", ok, &c["ok"]);
    r.eq("logs", logs, &c["logs"]);
    // The recorder masked the root through lossy text, so bytes that are not UTF-8 appear replaced.
    let masked = String::from_utf8_lossy(&out).replace(&root, "<root>");
    r.eq("buffer", hex::encode(masked), &c["buffer_after_hex_with_root_masked"]);
}

fn check_binary_case(r: &mut Run, c: &Value) {
    let (dir, root) = scratch();
    let f = dir.join("input");
    let mut data = match s(&c["content"]) {
        "nul in first 64KiB piece of a 70000-byte line" => vec![b'a'; 70000],
        "nul at byte 65535 before newline" => vec![b'a'; 65535],
        _ => unhex(&c["content_hex"]),
    };
    match s(&c["content"]) {
        "missing file" => {
            let (got, logs) = logged(&root, || check_binary_file(&format!("{root}/missing")));
            r.eq("result", got, &c["result"]);
            r.eq("logs", logs, &c["logs"]);
            return;
        }
        "nul in first 64KiB piece of a 70000-byte line" => {
            data[10] = 0;
            data.push(b'\n');
        }
        "nul at byte 65535 before newline" => data.extend([0, b'\n']),
        _ => {}
    }
    fs::write(&f, data).unwrap();
    let (got, logs) = logged(&root, || check_binary_file(&f.to_string_lossy()));
    r.eq("result", got, &c["result"]);
    r.eq("logs", logs, &c["logs"]);
}

fn tree_without_bundle(dir: &Path) -> Value {
    let mut t = tree(dir);
    t.remove("merged.mg");
    Value::Object(t)
}

fn unmerge_mode(r: &mut Run, (dir, root): (&Path, &str), merged: &str, out: &str, text: bool, want: &Value) {
    let opt = format!("{root}/{out}");
    let ((ok, names), logs) = logged(root, || unmerge_files_mode(merged, Some(&opt), text));
    let logs = mask_temp_names(logs);
    r.eq("ok", ok, &want["ok"]);
    r.eq("names", names, &want["names"]);
    r.eq("logs", logs, &want["logs"]);
    r.eq("tree", tree_without_bundle(dir), &want["tree_after"]);
}

/// The vectors show the six random characters of a temporary name as `XXXXXX`.
fn mask_temp_names(logs: Value) -> Value {
    let lead = "(1128): Could not create temporary file '";
    let fix = |m: &str| match (m.strip_prefix(lead), m.find("' due to")) {
        (Some(_), Some(end)) if end >= lead.len() + 6 => format!("{}XXXXXX{}", &m[..end - 6], &m[end..]),
        _ => m.to_string(),
    };
    let list = logs.as_array().unwrap().iter().map(|l| json!([l[0], fix(s(&l[1]))])).collect();
    Value::Array(list)
}

fn unmerge_case(r: &mut Run, c: &Value) {
    let bundle = unhex(&c["merged_hex"]);
    let (dir, root) = scratch();
    let merged = format!("{root}/merged.mg");
    fs::write(&merged, &bundle).unwrap();
    let (got, logs) = logged(&root, || test_unmerge_files(&merged));
    r.eq("test_unmerge", got, &c["test_unmerge_files"]);
    r.eq("test logs", logs, &c["test_logs"]);
    let Some(text) = c.get("unmerge_text") else { return };
    let (mut text, mut binary) = (text.clone(), c["unmerge_binary"].clone());
    if s(&c["merged"]) == "dot-dot name" {
        // Review fix 16 (owner): a refused `..` name creates no directory. The recording shows the old
        // code creating optdir here, so this one tree is checked against the new rule instead.
        println!("DEVIATION files_unix 'dot-dot name': optdir no longer created (review fix 16)");
        text["tree_after"] = json!({});
        binary["tree_after"] = json!({});
    }
    let text = &text;
    unmerge_mode(r, (&dir, &root), &merged, "out_text", true, text);
    unmerge_mode(r, (&dir, &root), &merged, "out_binary", false, &binary);

    let (dir2, root2) = scratch();
    let merged2 = format!("{root2}/merged.mg");
    fs::write(&merged2, &bundle).unwrap();
    let ((ok, names), _) = logged(&root2, || unmerge_files(&merged2, Some(&format!("{root2}/out_text"))));
    let same = json!(ok) == text["ok"] && json!(names) == text["names"] && tree_without_bundle(&dir2) == text["tree_after"];
    r.eq("default mode", same, &c["unmerge_files_default_mode_same_as_text"]);
}

/// The only test that changes the working directory; everything else uses absolute paths.
fn unmerge_no_optdir(r: &mut Run, c: &Value) {
    let (dir, root) = scratch();
    fs::write(dir.join("m.mg"), unhex(&c["tree_after"]["m.mg"])).unwrap();
    let back = env::current_dir().unwrap();
    env::set_current_dir(&dir).unwrap();
    let ((ok, names), logs) = logged(&root, || unmerge_files("m.mg", None));
    env::set_current_dir(back).unwrap();
    r.eq("ok", ok, &c["ok"]);
    r.eq("names", names, &c["names"]);
    r.eq("logs", logs, &c["logs"]);
    r.eq("tree", Value::Object(tree(&dir)), &c["tree_after"]);
}

fn file_case(r: &mut Run, c: &Value) {
    let (dir, _) = scratch();
    let input = unhex(&c["file_hex"]);
    let f = dir.join("input");
    fs::write(&f, &input).unwrap();
    r.eq("md5", md5_file(&f.to_string_lossy()), &c["md5_file"]);
    r.eq("read", hex::encode(crt::read_text(&f).unwrap()), &c["read_text_hex"]);
    let out = dir.join("written");
    crt::write_text(&out, &input).unwrap();
    r.eq("write", hex::encode(fs::read(&out).unwrap()), &c["write_text_file_hex"]);
    let out = dir.join("textfile");
    let mut t = crt::TextFile::create(&out).unwrap();
    t.write_all(&input).unwrap();
    t.write_all(b"\n").unwrap();
    t.flush().unwrap();
    drop(t);
    r.eq("textfile", hex::encode(fs::read(&out).unwrap()), &c["textfile_write_then_newline_hex"]);
}

fn mktemp_case(r: &mut Run, c: &Value) {
    let (_, root) = scratch();
    let pid = format!("{:05}", std::process::id() % 100_000);
    let show = |p: Option<String>| p.map(|p| p.replace(&root, "<root>").replace(&pid, "<pid5>"));
    let first = mktemp(&format!("{root}/fXXXXXX"));
    r.eq("first", show(first.clone()), &c["first"]);
    fs::write(first.unwrap(), "").unwrap();
    r.eq("taken", show(mktemp(&format!("{root}/fXXXXXX"))), &c["when_a_exists"]);
    r.eq("five", show(mktemp(&format!("{root}/fXXXXX"))), &c["five_x"]);
    r.eq("none", show(mktemp(&format!("{root}/f"))), &c["no_xxxxxx"]);
}

fn mkstemp_case(r: &mut Run, c: &Value) {
    let (dir, root) = scratch();
    let ((name, none), logs) = logged(&root, || (mkstemp_ex(&format!("{root}/sXXXXXX")), mkstemp_ex(&format!("{root}/s"))));
    r.eq("logs", logs, &c["logs"]);
    r.eq("none", none, &c["no_xxxxxx"]);
    let name = name.unwrap();
    let suffix = name.strip_prefix(&format!("{root}/s")).unwrap();
    let meta = fs::metadata(&name).unwrap();
    #[cfg(unix)]
    let mode = json!(std::os::unix::fs::MetadataExt::mode(&meta) & 0o777);
    #[cfg(not(unix))]
    let mode = Value::Null;
    let shape = json!({"exists_empty": meta.len() == 0, "suffix_alnum": suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
        "suffix_len": suffix.len(), "unix_mode": mode});
    r.eq("shape", shape, &c["result_shape"]);
    assert!(dir.exists());
}

fn rename_case(r: &mut Run, c: &Value) {
    let (dir, root) = scratch();
    fs::write(dir.join("r1"), "one").unwrap();
    let p = |n: &str| format!("{root}/{n}");
    let (first, _) = logged(&root, || rename_ex(&p("r1"), &p("r2")));
    r.eq("first", first, &json!(true));
    r.eq("tree", Value::Object(tree(&dir)), &c["tree_after_first"]);
    fs::write(dir.join("a"), "two").unwrap();
    let (over, _) = logged(&root, || rename_ex(&p("a"), &p("r2")));
    r.eq("over", over, &c["over_existing"]);
    let (missing, logs) = logged(&root, || rename_ex(&p("none"), &p("r3")));
    r.eq("missing", missing, &c["missing_source"]);
    r.eq("logs", logs, &c["logs"]);
    r.eq("dst created", dir.join("r3").exists(), &c["dst_created_on_failure"]);
}

fn file_tree_cases(r: &mut Run, c: &Value) {
    let (dir, root) = scratch();
    match s(&c["fn"]) {
        "wreaddir" => {
            let w = dir.join("w");
            fs::create_dir(&w).unwrap();
            for e in c["entries_created"].as_array().unwrap() {
                match s(e).strip_suffix('/') {
                    Some(d) => fs::create_dir(w.join(d)).unwrap(),
                    None => fs::write(w.join(s(e)), "").unwrap(),
                }
            }
            r.eq("result", wreaddir(&w.to_string_lossy()), &c["result"]);
            r.eq("missing", wreaddir(&format!("{root}/none")), &c["missing"]);
            let f = w.join("a");
            r.eq("file", wreaddir(&f.to_string_lossy()), &c["on_a_file"]);
        }
        "copy_file" => {
            let (src, dst) = (dir.join("src"), dir.join("dst"));
            fs::write(&src, s(&c["src_content"]).replace("\\n", "\n")).unwrap();
            if c["dst_before_hex"].is_string() {
                fs::write(&dst, unhex(&c["dst_before_hex"])).unwrap();
            }
            let mode = s(&c["mode"]).chars().next().unwrap();
            let done = copy_file(&src.to_string_lossy(), &dst.to_string_lossy(), mode, c["message"].as_str());
            r.eq("ok", done.is_ok(), &c["ok"]);
            r.eq("dst", hex::encode(fs::read(&dst).unwrap()), &c["dst_after_hex"]);
        }
        "copy_file missing source" => {
            let dst = dir.join("dst");
            let done = copy_file(&format!("{root}/none"), &dst.to_string_lossy(), 'a', None);
            r.eq("ok", done.is_ok(), &c["ok"]);
            r.eq("dst", dst.exists(), &c["dst_created"]);
        }
        "rmdir_ex" => {
            match s(&c["case"]) {
                "file" => {
                    fs::create_dir(dir.join("x")).unwrap();
                    fs::write(dir.join("x/f"), "f").unwrap();
                }
                "tree" => {
                    fs::create_dir_all(dir.join("x/a/b")).unwrap();
                    fs::write(dir.join("x/a/b/c"), "c").unwrap();
                }
                "empty dir" => fs::create_dir_all(dir.join("x/e")).unwrap(),
                _ => {}
            }
            r.eq("ok", rmdir_ex(&format!("{root}/{}", s(&c["target"]))).is_ok(), &c["ok"]);
            r.eq("tree", Value::Object(tree(&dir)), &c["tree_after"]);
        }
        "cldir_ex_ignore" => {
            let d = dir.join("c");
            for sub in ["sub/deep", "other", "keep"] {
                fs::create_dir_all(d.join(sub)).unwrap();
            }
            for (f, t) in [("merged.mg", "m"), ("agent.conf", "a"), ("sub/x.txt", "x"), ("sub/y.txt", "y"), ("sub/deep/z", "z")] {
                fs::write(d.join(f), t).unwrap();
            }
            let ignore: Vec<&str> = c["ignore"].as_array().unwrap().iter().map(s).collect();
            r.eq("ok", cldir_ex_ignore(&d.to_string_lossy(), &ignore).is_ok(), &c["ok"]);
            r.eq("tree", Value::Object(tree(&dir)), &c["tree_after"]);
        }
        "cldir_ex_ignore missing dir" => r.eq("ok", cldir_ex_ignore(&format!("{root}/none"), &[]).is_ok(), &c["ok"]),
        "mtime" => {
            let f = dir.join("f");
            let secs = c["file_set_to"].as_u64().unwrap();
            let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
            fs::File::create(&f).unwrap().set_modified(when).unwrap();
            r.eq("result", mtime(&f.to_string_lossy()), &c["result"]);
            r.eq("dir", mtime(&root).is_some(), &c["dir_is_some"]);
            r.eq("missing", mtime(&format!("{root}/none")), &c["missing"]);
        }
        other => panic!("unknown fn {other}"),
    }
}

#[test]
fn files() {
    let mut r = Run::new(if cfg!(windows) { "files_windows" } else { "files_unix" });
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        match s(&c["fn"]) {
            "crt::TEXT_TRANSLATION" => r.eq("flag", crt::TEXT_TRANSLATION, &c["result"]),
            "ref_parent_folder" => r.eq("ref", ref_parent_folder(s(&c["input"])), &c["result"]),
            "wfopen_errno" => {
                let e = match c["raw_os_error"].as_i64() {
                    Some(n) => io::Error::from_raw_os_error(n as i32),
                    None => io::ErrorKind::NotFound.into(),
                };
                r.eq("errno", wfopen_errno(&e), &c["result"]);
            }
            "strerror" => r.eq("text", strerror(c["input"].as_i64().unwrap() as i32), &c["result"]),
            "merge_append_file" => merge_case(&mut r, &c),
            "check_binary_file" => check_binary_case(&mut r, &c),
            "test_unmerge_files + unmerge_files" => unmerge_case(&mut r, &c),
            "unmerge_files optdir None" => unmerge_no_optdir(&mut r, &c),
            "unmerge_files missing merged file" => {
                let (_, root) = scratch();
                let ((ok, names), logs) = logged(&root, || unmerge_files(&format!("{root}/missing.mg"), None));
                r.eq("ok", ok, &c["ok"]);
                r.eq("names", names, &c["names"]);
                r.eq("logs", logs, &c["logs"]);
            }
            "md5_file / read_text / write_text / TextFile" => file_case(&mut r, &c),
            "md5_file missing" => {
                let (_, root) = scratch();
                let none = format!("{root}/none");
                r.eq("md5", md5_file(&none), &c["result"]);
                r.eq("read", crt::read_text(&none).is_err(), &c["read_text_missing_is_err"]);
            }
            "mktemp" => mktemp_case(&mut r, &c),
            "mkstemp_ex" => mkstemp_case(&mut r, &c),
            "rename_ex" => rename_case(&mut r, &c),
            #[cfg(windows)]
            "crt::is_network_path" => {
                // Drive letters depend on the machine: only the UNC / plain-text answers are fixed.
                let input = s(&c["input"]);
                let got = crt::is_network_path(input);
                if input.as_bytes().get(1) != Some(&b':') {
                    r.eq("result", got, &c["result"]);
                }
            }
            _ => file_tree_cases(&mut r, &c),
        }
        r.done(format!("{n} {} {}", s(&c["fn"]), c["merged"].as_str().or(c["input"].as_str()).unwrap_or("")));
    }
    if cfg!(windows) {
        println!("VECTORS files_unix: not run here (Unix only, unmerge needs elevation on Windows)");
    }
    r.finish();
}

/// A system made of a vector's files, command outputs and uname.
struct Fake {
    files: BTreeMap<String, Vec<u8>>,
    commands: BTreeMap<String, String>,
    executables: BTreeSet<String>,
    path: Option<String>,
    uname: Option<UtsName>,
    calls: RefCell<Vec<String>>,
}

impl Fake {
    fn new(c: &Value) -> Fake {
        let uname = c["uname"].as_array().map(|u| UtsName {
            sysname: s(&u[0]).into(),
            nodename: s(&u[1]).into(),
            release: s(&u[2]).into(),
            version: s(&u[3]).into(),
            machine: s(&u[4]).into(),
        });
        let map = |k: &str| c[k].as_object().into_iter().flatten().map(|(a, b)| (a.clone(), s(b).to_string()));
        Fake {
            files: map("files").map(|(k, v)| (k, v.into_bytes())).collect(),
            commands: map("commands").collect(),
            executables: c["executables"].as_array().unwrap().iter().map(|e| s(e).to_string()).collect(),
            path: c["path_env"].as_str().map(str::to_string),
            uname,
            calls: RefCell::default(),
        }
    }
}

impl System for Fake {
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        self.calls.borrow_mut().push(format!("read {path}"));
        self.files.get(path).cloned()
    }
    fn run(&self, cmd: &str) -> Option<String> {
        self.calls.borrow_mut().push(format!("run {cmd}"));
        self.commands.get(cmd).cloned()
    }
    fn is_executable(&self, path: &str) -> bool {
        self.executables.contains(path)
    }
    fn path_env(&self) -> Option<String> {
        self.path.clone()
    }
    fn uname(&self) -> Option<UtsName> {
        self.uname.clone()
    }
}

fn info_json(i: &OsInfo) -> Value {
    json!({"machine": i.machine, "nodename": i.nodename, "os_build": i.os_build, "os_codename": i.os_codename,
        "os_major": i.os_major, "os_minor": i.os_minor, "os_name": i.os_name, "os_patch": i.os_patch,
        "os_platform": i.os_platform, "os_release": i.os_release, "os_version": i.os_version, "release": i.release,
        "sysname": i.sysname, "version": i.version})
}

fn scenario(r: &mut Run, c: &Value) {
    let fake = Fake::new(c);
    let info = catch_unwind(AssertUnwindSafe(|| version_op::get_unix_version(&fake)));
    r.eq("probes", fake.calls.borrow().clone(), &c["probe_calls_in_order"]);
    let text = catch_unwind(AssertUnwindSafe(|| version_op::getuname_with(&fake)));
    if c["get_unix_version"].get("panic").is_some() {
        // Owner decision: empty values no longer panic; they are treated as empty.
        r.eq("no panic", info.is_ok() && text.is_ok(), &json!(true));
        return;
    }
    let got = info.ok().flatten().map_or(Value::Null, |i| info_json(&i));
    r.eq("info", got, &c["get_unix_version"]["result"]);
    r.eq("string", text.unwrap_or_default(), &c["getuname_with"]);
}

#[test]
fn version() {
    let mut r = Run::new(if cfg!(windows) { "version_windows" } else { "version_unix" });
    for (n, c) in std::mem::take(&mut r.cases).into_iter().enumerate() {
        match s(&c["fn"]) {
            "version_op::get_unix_version / getuname_with" => scenario(&mut r, &c),
            "version_op::get_binary_path" => {
                let got = version_op::get_binary_path(s(&c["binary"]), &Fake::new(&c));
                r.eq("found", got.is_ok(), &c["found"]);
                r.eq("path", got.unwrap_or_else(|e| e), &c["result"]);
            }
            "version_op::w_regexec (POSIX extended)" => {
                let got = version_op::w_regexec(s(&c["pattern"]), s(&c["subject"]), c["nmatch"].as_u64().unwrap() as usize);
                r.eq("groups", got.map_or(Value::Null, |g| json!(g)), &c["result"]);
            }
            "version_op::getuname (this machine; shape only)" => {
                let got = version_op::getuname();
                let pipes = |t: &str| t.matches('|').count();
                r.eq("pipes", pipes(got), &pipes(s(&c["example"])).into());
                r.eq("tail", got.ends_with(&format!(" - {}", version_op::AGENT_PRODUCT)), &json!(true));
                r.eq("len", got.len() <= if cfg!(windows) { 1023 } else { 511 }, &json!(true));
            }
            "win_version::get_release_from_build" => {
                r.eq("release", win_version::get_release_from_build(c["input"].as_str()), &c["result"]);
            }
            #[cfg(windows)]
            "win_version::get_win_version (this machine)" => {
                // Shape only: which fields are set, not this machine's values.
                let shape = |v: &Value| v.as_object().unwrap().iter().map(|(k, x)| (k.clone(), x.is_null())).collect::<BTreeMap<_, _>>();
                let got = info_json(&win_version::get_win_version().unwrap());
                r.eq("shape", json!(shape(&got)), &json!(shape(&c["result"])));
            }
            other => panic!("unknown fn {other}"),
        }
        r.done(format!("{n} {} {}", s(&c["fn"]), s(&c["scenario"])));
    }
    r.finish();
}

/// Owner decision with no vector: `DISTRIB_RELEASE=` counts as an empty value and does not panic.
#[test]
fn empty_lsb_release() {
    let c = json!({"files": {"/etc/lsb-release": "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=\n"}, "commands": {}, "executables": [],
        "path_env": null, "uname": ["Linux", "h", "r", "v", "m"]});
    let i = version_op::get_unix_version(&Fake::new(&c)).unwrap();
    assert_eq!(i.os_name.as_deref(), Some("Ubuntu"));
    assert_eq!(i.os_version.as_deref(), Some(""));
}

// ---- Review fixes 14-40: one test each, input -> output. ----

fn fake(files: &[(&str, &str)], commands: &[(&str, &str)], path: Option<&str>, executables: &[&str]) -> Fake {
    let c = json!({
        "files": files.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<Map<_, _>>(),
        "commands": commands.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<Map<_, _>>(),
        "executables": executables, "path_env": path, "uname": ["Linux", "h", "r", "v", "m"],
    });
    Fake::new(&c)
}

fn detect(f: &Fake) -> OsInfo {
    version_op::get_unix_version(f).unwrap()
}

#[test]
fn fix14_offset_inside_a_character_gives_empty_name() {
    let (dir, root) = scratch();
    fs::write(dir.join("é"), "x").unwrap();
    let mut out = Vec::new();
    // root + "/" + first byte of the two-byte 'é'
    assert!(merge_append_file(&mut out, &format!("{root}/é"), Some(root.len() + 2)));
    assert_eq!(out, b"!1 \nx");
}

#[test]
fn fix15_oversized_header_size_counts_as_zero() {
    let (dir, root) = scratch();
    let merged = format!("{root}/m.mg");
    fs::write(&merged, "!99999999999999999999999999 a.txt\nabc").unwrap();
    // Size 0, so "abc" is read as the next line, which is not a header.
    assert!(!test_unmerge_files(&merged));
    if cfg!(unix) {
        let (ok, names) = unmerge_files_mode(&merged, Some(&format!("{root}/out")), false);
        assert!(ok);
        assert_eq!(names, ["a.txt"]);
        assert_eq!(fs::read(dir.join("out/a.txt")).unwrap(), b"");
    }
}

#[test]
fn fix16_refused_name_creates_nothing() {
    let (dir, root) = scratch();
    let merged = format!("{root}/m.mg");
    fs::write(&merged, "!3 sub/../../evil.txt\nabc!2 ok.txt\nhi").unwrap();
    let ((ok, names), logs) = logged(&root, || unmerge_files_mode(&merged, Some(&format!("{root}/out")), false));
    assert!(!ok);
    assert!(names.is_empty());
    assert_eq!(logs[0][1], "Unmerging '<root>/m.mg': unable to unmerge '<root>/out/sub/../../evil.txt' (it contains '..')");
    assert_eq!(Value::Object(tree(&dir)), json!({"m.mg": hex::encode("!3 sub/../../evil.txt\nabc!2 ok.txt\nhi")}));
}

#[cfg(unix)]
#[test]
fn fix16_parent_uses_slash_dirname() {
    let (dir, root) = scratch();
    let merged = format!("{root}/m.mg");
    fs::write(&merged, "!1 a/b/c\nz").unwrap();
    let (ok, _) = unmerge_files_mode(&merged, Some(&format!("{root}/out")), false);
    assert!(ok);
    assert_eq!(fs::read(dir.join("out/a/b/c")).unwrap(), b"z");
}

#[cfg(unix)]
#[test]
fn fix17_temp_file_log_names_the_file() {
    let (_, root) = scratch();
    let (got, logs) = logged(&root, || mkstemp_ex(&format!("{root}/missing/tXXXXXX")));
    assert_eq!(got, None);
    let msg = s(&logs[0][1]).to_string();
    let name = msg.split('\'').nth(1).unwrap();
    let suffix = name.strip_prefix("<root>/missing/t").unwrap();
    assert_eq!(suffix.len(), 6);
    assert!(suffix != "XXXXXX" && suffix.bytes().all(|b| b.is_ascii_alphanumeric()), "{msg}");
}

#[cfg(windows)]
#[test]
fn fix17_all_26_names_taken_logs_22() {
    let (dir, root) = scratch();
    let pid = std::process::id() % 100_000;
    for c in 'a'..='z' {
        fs::write(dir.join(format!("t{c}{pid:05}")), "").unwrap();
    }
    let (got, logs) = logged(&root, || mkstemp_ex(&format!("{root}/tXXXXXX")));
    assert_eq!(got, None);
    assert_eq!(logs, json!([["ERROR", "Could not create temporary file (<root>/tXXXXXX) which returned 22 [(22)-(Invalid argument)]."]]));
}

/// Owner decision: a protected link is never walked, so nothing behind it is touched.
#[test]
fn fix18_protected_link_is_not_walked() {
    let (dir, root) = scratch();
    fs::create_dir_all(dir.join("outside")).unwrap();
    fs::write(dir.join("outside/victim.txt"), "keep me").unwrap();
    fs::create_dir_all(dir.join("c")).unwrap();
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(dir.join("outside"), dir.join("c/link"));
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_dir(dir.join("outside"), dir.join("c/link"));
    if linked.is_err() {
        println!("fix18: cannot create a directory link here (needs Developer Mode or elevation); skipped");
        return;
    }
    // "link/other" protects the link itself; walking it would delete victim.txt.
    cldir_ex_ignore(&format!("{root}/c"), &["link/other"]).unwrap();
    assert_eq!(fs::read_to_string(dir.join("outside/victim.txt")).unwrap(), "keep me");
    assert!(fs::symlink_metadata(dir.join("c/link")).is_ok(), "the protected link stays");
}

#[test]
fn fix19_protected_dir_left_non_empty_is_not_an_error() {
    let (dir, root) = scratch();
    fs::create_dir_all(dir.join("c/sub")).unwrap();
    fs::write(dir.join("c/sub/x.txt"), "x").unwrap();
    fs::write(dir.join("c/sub/y.txt"), "y").unwrap();
    assert!(cldir_ex_ignore(&format!("{root}/c"), &["sub/x.txt"]).is_ok());
    assert_eq!(Value::Object(tree(&dir)), json!({"c": "<dir>", "c/sub": "<dir>", "c/sub/x.txt": "78"}));
}

#[test]
fn fix20_other_device_targets() {
    assert_eq!(crt::device_target_is_network(r"\Device\Mup\server\share"), Some(true));
    assert_eq!(crt::device_target_is_network(r"\Device\HarddiskVolume3"), Some(false));
    // A subst drive: not a \Device\ path, so the HKCU\Network test decides.
    assert_eq!(crt::device_target_is_network(r"\??\C:\work"), None);
}

#[test]
fn fix21_product_constants() {
    assert_eq!(version_op::PRODUCT_NAME, "Wazuh");
    assert_eq!(version_op::PRODUCT_VERSION, "v4.14.7");
    assert_eq!(version_op::AGENT_PRODUCT, format!("{} {}", version_op::PRODUCT_NAME, version_op::PRODUCT_VERSION));
}

#[test]
fn fix22_output_of_a_failing_command_counts() {
    use version_op::Live;
    #[cfg(unix)]
    assert_eq!(Live.run("sh -c echo;false").as_deref(), Some("\n"));
    #[cfg(windows)]
    assert_eq!(Live.run("cmd /c echo x& exit 3").as_deref(), Some("x\r\n"));
    assert_eq!(Live.run("no-such-command-pv"), None);
}

#[test]
fn fix23_any_regular_file_is_found() {
    use version_op::Live;
    let (dir, root) = scratch();
    fs::write(dir.join("plain"), "").unwrap();
    assert!(Live.is_executable(&format!("{root}/plain")), "no execute bit needed");
    assert!(!Live.is_executable(&root), "a directory is not");
}

#[cfg(unix)]
#[test]
fn fix24_patterns_match_254_byte_pieces() {
    let line = format!("{}11.7\n", "x".repeat(252));
    let f = fake(&[("/etc/debian_version", &line)], &[], None, &[]);
    // The first piece ends after "11"; the old whole-line match would give 11.7.
    assert_eq!(detect(&f).os_version.as_deref(), Some("11"));
}

#[test]
fn fix25_key_value_rules() {
    let f = fake(&[("/etc/os-release", "=NAME=X\nVERSION=1\nID=  xy z\n")], &[], None, &[]);
    let i = detect(&f);
    assert_eq!((i.os_name.as_deref(), i.os_platform.as_deref()), (Some("X"), Some("xy")));
    let f = fake(&[("/etc/lsb-release", "==DISTRIB_RELEASE=18.04\n")], &[], None, &[]);
    assert_eq!(detect(&f).os_version.as_deref(), Some("18.04"));
    // First piece of the uname output is only a newline: nothing.
    let f = fake(&[], &[("uname", "\nLinux\n")], None, &[]);
    assert_eq!(detect(&f).os_name, None);
}

#[cfg(unix)]
#[test]
fn fix26_unset_group_gives_empty_text() {
    let f = fake(&[("/etc/os-release", "NAME=X\nVERSION=1.2.x\nID=x\n")], &[], None, &[]);
    let i = detect(&f);
    assert_eq!((i.os_major.as_deref(), i.os_minor.as_deref(), i.os_patch.as_deref()), (Some("1"), Some("2"), Some("")));
}

#[test]
fn fix27_binary_path_rules() {
    let get = |bin, path, exe: &[&str]| version_op::get_binary_path(bin, &fake(&[], &[], path, exe));
    assert_eq!(get("x", Some("/a::/b"), &["/x"]), Err("x".into()), "empty entries are skipped");
    assert_eq!(get("x", None, &["/usr/bin/x"]), Err("x".into()), "no PATH: not found");
    assert_eq!(get("bin/x", Some("/a"), &["/a/bin/x"]), Ok("/a/bin/x".into()), "only a leading / is a path");
    assert_eq!(get("/x", Some("/a"), &["/x"]), Ok("/x".into()));
}

#[cfg(unix)]
#[test]
fn fix28_version_patterns() {
    let v = |file: &str, text: &str| detect(&fake(&[(file, text)], &[], None, &[])).os_version;
    assert_eq!(v("/etc/gentoo-release", "Gentoo-2.14 r 3\n").as_deref(), Some("3"));
    assert_eq!(v("/etc/slackware-version", "Slackware15.0 x 9\n").as_deref(), Some("9"));
    assert_eq!(v("/etc/SuSE-release", "VERSION = 11.4\n").as_deref(), Some("11"));
    let f = fake(&[], &[("uname", "ZscalerOS\n"), ("uname -r", "12-RELEASE\tp3\n")], None, &[]);
    assert_eq!(detect(&f).os_version.as_deref(), Some("12-RELEASE"));
}

#[test]
fn fix29_lsb_release_keeps_quotes() {
    let f = fake(&[("/etc/lsb-release", "DISTRIB_RELEASE=\"18.04\"\n")], &[], None, &[]);
    assert_eq!(detect(&f).os_version.as_deref(), Some("\"18.04\""));
}

#[test]
fn fix30_darwin_name_from_system_version_key() {
    let name = |profile: &str| {
        let f = fake(&[], &[("uname", "Darwin\n"), ("system_profiler SPSoftwareDataType", profile)], None, &[]);
        detect(&f).os_name
    };
    assert_eq!(name("Software:\n  System Version Info: macOS 14.1\n").as_deref(), Some("macOS"));
    // No space after the name: the newline stays (the old value; the owner may waive this).
    assert_eq!(name("System Version:   Sonoma\n").as_deref(), Some("Sonoma\n"));
}

#[test]
fn fix31_sw_vers_with_only_a_newline_is_unset() {
    let f = fake(&[], &[("uname", "Darwin\n"), ("sw_vers -productVersion", "\n14.1\n"), ("sw_vers -buildVersion", "\n")], None, &[]);
    let i = detect(&f);
    assert_eq!((i.os_version.as_deref(), i.os_build), (Some("0.0"), None));
}

#[cfg(unix)]
#[test]
fn fix32_darwin_codename_from_resolved_uname() {
    let f = fake(
        &[],
        &[("/usr/bin/uname", "Darwin\n"), ("/usr/bin/uname -r", "Darwin Kernel 23.1.0\n"), ("sw_vers -productVersion", "14.1\n")],
        Some("/usr/bin"),
        &["/usr/bin/uname"],
    );
    let i = detect(&f);
    assert!(f.calls.borrow().contains(&"run /usr/bin/uname -r".to_string()));
    assert_eq!(i.os_codename.as_deref(), Some("Sonoma"));
    assert_eq!(i.os_version.as_deref(), Some("14.1 (Sonoma)"));
}

#[test]
fn fix33_sunos_word_after_solaris() {
    let v = |release: &str| version_op::get_unix_version(&fake(&[("/etc/release", release)], &[("uname", "SunOS\n")], None, &[]));
    assert_eq!(v("Oracle Solaris\t11.4\n").unwrap().os_version.as_deref(), Some("\t11.4\n"));
    assert_eq!(v("x Solaris").unwrap().os_version.as_deref(), Some(""), "found Solaris is success");
    assert_eq!(v("OpenIndiana\n"), None);
}

#[test]
fn fix34_aix_first_line_minus_last_char() {
    let v = |out: &str| detect(&fake(&[], &[("uname", "AIX\n"), ("oslevel", out)], None, &[])).os_version;
    assert_eq!(v("\n").as_deref(), Some(""), "set, not missing");
    assert_eq!(v("7.2.0.0\nmore\n").as_deref(), Some("7.2.0.0"));
}

/// A registry made of values; keys listed in `closed` cannot be opened.
#[derive(Default)]
struct FakeReg {
    strings: BTreeMap<(String, String), String>,
    dwords: BTreeMap<(String, String), u32>,
    closed: BTreeSet<String>,
    reads: RefCell<Vec<String>>,
}

impl FakeReg {
    fn s(mut self, key: &str, value: &str, v: &str) -> Self {
        self.strings.insert((key.into(), value.into()), v.into());
        self
    }
    fn d(mut self, key: &str, value: &str, v: u32) -> Self {
        self.dwords.insert((key.into(), value.into()), v);
        self
    }
    fn get<T: Clone>(&self, map: &BTreeMap<(String, String), T>, key: &str, value: &str) -> Result<T, u32> {
        self.reads.borrow_mut().push(value.into());
        map.get(&(key.into(), value.into())).cloned().ok_or(2)
    }
}

impl win_version::Registry for FakeReg {
    fn open(&self, key: &str) -> Result<(), u32> {
        if self.closed.contains(key) {
            Err(2)
        } else {
            Ok(())
        }
    }
    fn string(&self, key: &str, value: &str, _max: usize) -> Result<String, u32> {
        self.get(&self.strings, key, value)
    }
    fn dword(&self, key: &str, value: &str) -> Result<u32, u32> {
        self.get(&self.dwords, key, value)
    }
}

thread_local! {
    static WIN_LOGS: RefCell<Vec<(win_version::Level, String)>> = RefCell::default();
}

/// Detection messages of `f`, on this thread only (the hook itself is process-wide).
fn win_logs<T>(f: impl FnOnce() -> T) -> Vec<(win_version::Level, String)> {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        win_version::set_logger(Box::new(|l, m| WIN_LOGS.with(|w| w.borrow_mut().push((l, m.to_string())))));
    });
    WIN_LOGS.with(|w| w.borrow_mut().clear());
    f();
    WIN_LOGS.with(|w| w.take())
}

fn v6() -> Option<win_version::VersionInfo> {
    Some(win_version::VersionInfo { major: 6, minor: 2, build: 9200, platform_id: 2, ..Default::default() })
}

#[test]
fn fix35_detection_messages_reach_the_hook() {
    let reg = FakeReg { closed: [win_version::CURRENT_VERSION.to_string()].into(), ..Default::default() };
    let seen = win_logs(|| win_version::win_version_with(v6(), &reg));
    let key = format!("(1758): Unable to open registry key: '{}'.", win_version::CURRENT_VERSION);
    assert!(seen.contains(&(win_version::Level::Error, key)), "{seen:?}");
    let read = "Error reading 'CSDVersion' from Windows registry. (Error 2)".to_string();
    assert!(seen.contains(&(win_version::Level::Error, read)), "{seen:?}");
}

#[test]
fn fix36_registry_gaps_leave_parts_unset() {
    let cv = win_version::CURRENT_VERSION;
    let reg = FakeReg::default().s(cv, "ProductName", "Windows 10 Pro").d(cv, "CurrentMajorVersionNumber", 10).s(cv, "CurrentBuildNumber", "19045");
    let i = win_version::win_version_with(v6(), &reg).unwrap();
    assert_eq!((i.os_major, i.os_minor, i.os_build), (None, None, None));
    assert_eq!(i.os_version.as_deref(), Some("(null).(null).(null)"));
    // 6.2/6.3 path without CurrentVersion: the build is not even read.
    let reg = FakeReg::default().s(cv, "CurrentBuildNumber", "9600");
    let i = win_version::win_version_with(v6(), &reg).unwrap();
    assert_eq!(i.os_build, None);
    assert!(!reg.reads.borrow().contains(&"CurrentBuildNumber".to_string()));
}

#[test]
fn fix37_release_lookup_uses_build_with_ubr() {
    let cv = win_version::CURRENT_VERSION;
    let reg = |ubr: Option<u32>| {
        let r = FakeReg::default()
            .d(cv, "CurrentMajorVersionNumber", 10)
            .d(cv, "CurrentMinorVersionNumber", 0)
            .s(cv, "CurrentBuildNumber", "18363");
        match ubr {
            Some(u) => r.d(cv, "UBR", u),
            None => r,
        }
    };
    let release = |r: FakeReg| win_version::win_version_with(v6(), &r).unwrap().os_release;
    assert_eq!(release(reg(None)).as_deref(), Some("1909"));
    assert_eq!(release(reg(Some(1500))), None, "18363.1500 is not in the table");
}

#[test]
fn fix38_names_before_vista() {
    use win_version::{legacy_name, VersionInfo};
    let v = |major, minor, platform_id, product_type, x64, server_r2| VersionInfo {
        major, minor, build: 0, platform_id, product_type, x64, server_r2,
    };
    assert_eq!(legacy_name(&v(5, 0, 2, 1, false, false)), Some("Microsoft Windows 2000"));
    assert_eq!(legacy_name(&v(5, 1, 2, 1, false, false)), Some("Microsoft Windows XP"));
    assert_eq!(legacy_name(&v(5, 2, 2, 1, true, false)), Some("Microsoft Windows XP Professional x64 Edition"));
    assert_eq!(legacy_name(&v(5, 2, 2, 3, true, true)), Some("Microsoft Windows Server 2003 R2"));
    assert_eq!(legacy_name(&v(5, 2, 2, 3, false, false)), Some("Microsoft Windows Server 2003"));
    assert_eq!(legacy_name(&v(5, 3, 2, 1, false, false)), None);
    assert_eq!(legacy_name(&v(4, 0, 2, 1, false, false)), Some("Microsoft Windows NT"));
    assert_eq!(legacy_name(&v(4, 0, 1, 0, false, false)), Some("Microsoft Windows 95"));
    assert_eq!(legacy_name(&v(4, 10, 1, 0, false, false)), Some("Microsoft Windows 98"));
    assert_eq!(legacy_name(&v(4, 90, 1, 0, false, false)), Some("Microsoft Windows ME"));
    assert_eq!(legacy_name(&v(10, 0, 2, 1, false, false)), Some("Microsoft Windows"));
    let xp = VersionInfo { build: 0x0A28_0A28, ..v(5, 1, 2, 1, false, false) };
    let i = win_version::win_version_with(Some(xp), &FakeReg::default()).unwrap();
    assert_eq!((i.os_major.as_deref(), i.os_minor.as_deref(), i.os_build.as_deref()), (Some("5"), Some("1"), Some("2600")));
    assert_eq!(i.os_version.as_deref(), Some("5.1.2600"));
}

#[test]
fn fix39_service_pack_exact_values_only() {
    let sp = |n| {
        let reg = FakeReg::default().d(win_version::CONTROL_WINDOWS, "CSDVersion", n);
        win_version::win_version_with(v6(), &reg).unwrap().os_release
    };
    assert_eq!(sp(512).as_deref(), Some("sp2"));
    assert_eq!(sp(1536).as_deref(), Some("sp6"));
    assert_eq!(sp(300), None);
    assert_eq!(sp(1792), None);
}

#[test]
fn fix40_unknown_machine_and_node() {
    let i = win_version::win_version_with(v6(), &FakeReg::default()).unwrap();
    assert_eq!((i.machine.as_deref(), i.nodename.as_deref()), (Some("unknown"), Some("unknown")));
}

// ---- Review round 2 ----

#[test]
fn r2_4_commands_run_through_path() {
    let path = Some("/opt/bin");
    let exe = ["/opt/bin/uname", "/opt/bin/system_profiler", "/opt/bin/sw_vers", "/opt/bin/oslevel"];
    let darwin = fake(
        &[],
        &[
            ("/opt/bin/uname", "Darwin\n"),
            ("/opt/bin/system_profiler SPSoftwareDataType", "System Version: macOS 14.1\n"),
            ("/opt/bin/sw_vers -productVersion", "14.1\n"),
            ("/opt/bin/sw_vers -buildVersion", "23B74\n"),
            ("/opt/bin/uname -r", "23.1.0\n"),
        ],
        path,
        &exe,
    );
    let i = detect(&darwin);
    assert_eq!((i.os_name.as_deref(), i.os_build.as_deref()), (Some("macOS"), Some("23B74")));
    let calls = darwin.calls.borrow().iter().filter(|c| c.starts_with("run")).cloned().collect::<Vec<_>>();
    assert_eq!(
        calls,
        [
            "run /opt/bin/uname",
            "run /opt/bin/system_profiler SPSoftwareDataType",
            "run /opt/bin/sw_vers -productVersion",
            "run /opt/bin/sw_vers -buildVersion",
            "run /opt/bin/uname -r"
        ]
    );
    let aix = fake(&[], &[("/opt/bin/uname", "AIX\n"), ("/opt/bin/oslevel", "7.2\n")], path, &exe);
    assert_eq!(detect(&aix).os_version.as_deref(), Some("7.2"));
    for (name, out) in [("HP-UX", "B.11.31\n"), ("FreeBSD", "13.2-RELEASE\n"), ("ZscalerOS", "12-RELEASE\n")] {
        let uname = format!("{name}\n");
        let f = fake(&[], &[("/opt/bin/uname", uname.as_str()), ("/opt/bin/uname -r", out)], path, &exe);
        detect(&f);
        assert!(f.calls.borrow().contains(&"run /opt/bin/uname -r".to_string()), "{name}");
    }
}

#[test]
fn r2_5_warn_level_name() {
    assert_eq!(format!("{:?}", win_version::Level::Warn), "Warn");
}

#[test]
fn r2_6_windows_detection_messages() {
    use win_version::{Level::*, COMPUTER_NAME, CONTROL_WINDOWS, CURRENT_VERSION, ENVIRONMENT};
    let open = |k: &str| (Error, format!("(1758): Unable to open registry key: '{k}'."));
    let read = |v: &str| (Error, format!("Error reading '{v}' from Windows registry. (Error 2)"));
    let all_closed: BTreeSet<String> = [CURRENT_VERSION, CONTROL_WINDOWS, ENVIRONMENT, COMPUTER_NAME].map(String::from).into();
    let reg = FakeReg { closed: all_closed, ..Default::default() };
    let got = win_logs(|| win_version::win_version_with(v6(), &reg));
    assert_eq!(got, [open(CURRENT_VERSION), open(CURRENT_VERSION), open(CONTROL_WINDOWS), open(ENVIRONMENT), open(COMPUTER_NAME)]);

    // Major number present, everything else missing.
    let reg = FakeReg::default().d(CURRENT_VERSION, "CurrentMajorVersionNumber", 10);
    let got = win_logs(|| win_version::win_version_with(v6(), &reg));
    let release = (Debug1, "Could not read the 'ReleaseId' key from Windows registry. (Error 2)".to_string());
    let tail = [read("CSDVersion"), read("Architecture"), read("hostname")];
    assert_eq!(got, [vec![read("ProductName"), read("CurrentMinorVersionNumber"), release.clone()], tail.to_vec()].concat());

    // Build without a release; UBR missing gives no message; an unknown service pack value.
    let reg = FakeReg::default()
        .s(CURRENT_VERSION, "ProductName", "Windows 10 Pro")
        .d(CURRENT_VERSION, "CurrentMajorVersionNumber", 10)
        .d(CURRENT_VERSION, "CurrentMinorVersionNumber", 0)
        .s(CURRENT_VERSION, "CurrentBuildNumber", "19045")
        .d(CONTROL_WINDOWS, "CSDVersion", 300)
        .s(ENVIRONMENT, "PROCESSOR_ARCHITECTURE", "AMD64")
        .s(COMPUTER_NAME, "ComputerName", "pc");
    let got = win_logs(|| win_version::win_version_with(v6(), &reg));
    let unknown = (Debug1, "The release associated with the 19045 build is not recognized.".to_string());
    let sp = (Debug2, "The value of CSDVersion is not a recognizable service pack.: 300.".to_string());
    assert_eq!(got, [release.clone(), unknown, sp]);
    let with_ubr = reg.d(CURRENT_VERSION, "UBR", 5);
    let got = win_logs(|| win_version::win_version_with(v6(), &with_ubr));
    assert!(got.contains(&(Debug1, "The release associated with the 19045.5 build is not recognized.".into())), "{got:?}");

    // 6.2/6.3 path.
    let reg = FakeReg::default().s(CURRENT_VERSION, "ProductName", "Windows 8");
    let got = win_logs(|| win_version::win_version_with(v6(), &reg));
    assert_eq!(got[0], read("Current Version"));
    let reg = reg.s(CURRENT_VERSION, "CurrentVersion", "6.3");
    let got = win_logs(|| win_version::win_version_with(v6(), &reg));
    assert_eq!(got[0], read("CurrentBuildNumber"));
}

#[test]
fn r2_7_pre_vista_names() {
    use win_version::{legacy_name, VersionInfo};
    let x64 = VersionInfo { major: 5, minor: 2, product_type: 1, x64: true, ..Default::default() };
    assert_eq!(legacy_name(&x64), Some("Microsoft Windows XP Professional x64 Edition"));
    let odd4 = VersionInfo { major: 4, minor: 50, platform_id: 1, ..Default::default() };
    assert_eq!(legacy_name(&odd4), None);
    let unnamed = win_version::win_version_with(Some(odd4), &FakeReg::default()).unwrap();
    assert_eq!(unnamed.os_name, None, "the description falls back to Microsoft Windows");
}

#[cfg(unix)]
#[test]
fn r2_8_minor_needs_a_digit() {
    let i = detect(&fake(&[("/etc/os-release", "NAME=X\nVERSION=1.x\nID=x\n")], &[], None, &[]));
    assert_eq!((i.os_major.as_deref(), i.os_minor), (Some("1"), None));
    let i = detect(&fake(&[("/etc/os-release", "NAME=X\nVERSION=1.2.x\nID=x\n")], &[], None, &[]));
    assert_eq!((i.os_minor.as_deref(), i.os_patch.as_deref()), (Some("2"), Some("")));
}

#[test]
fn r2_9_os_release_id_word_then_quotes() {
    let id = |line: &str| detect(&fake(&[("/etc/os-release", &format!("NAME=X\nVERSION=1\n{line}\n"))], &[], None, &[])).os_platform;
    assert_eq!(id("ID= \"rhel\"").as_deref(), Some("rhel"));
    assert_eq!(id("ID=\"centos\" x").as_deref(), Some("centos"));
    assert_eq!(id("ID=  plain more").as_deref(), Some("plain"));
}

#[cfg(unix)]
#[test]
fn r2_10_suse_last_version_on_the_line() {
    let f = fake(&[("/etc/SuSE-release", "VERSION = 11 VERSION = 12\n")], &[], None, &[]);
    assert_eq!(detect(&f).os_version.as_deref(), Some("12"));
}

#[test]
fn r2_11_darwin_name_edges() {
    let name = |profile: String| detect(&fake(&[], &[("uname", "Darwin\n"), ("system_profiler SPSoftwareDataType", &profile)], None, &[])).os_name;
    assert_eq!(name(":System Version: z".into()).as_deref(), Some("z"));
    // A line with no word after the colon gives no name; a later line does.
    let pad = " ".repeat(240);
    let no_word = format!("System Version:{pad}");
    assert_eq!(no_word.len(), 255, "exactly one 255-byte piece, no newline");
    assert_eq!(name(format!("{no_word}\nSystem Version: macOS 15\n")).as_deref(), Some("macOS"));
}
