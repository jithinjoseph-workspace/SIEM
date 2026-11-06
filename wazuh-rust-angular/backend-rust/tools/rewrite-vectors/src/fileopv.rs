use crate::{h, logs, Out};
use serde_json::{json, Value};
use siem_fileop::crt;
use siem_fileop::version_op::{self, OsInfo, Probe, UtsName};
use siem_fileop::*;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

const K: &str = "siem-fileop";

fn root_of(work: &Path, name: &str) -> String {
    let d = work.join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.to_string_lossy().replace('\\', "/")
}

/// Every file (hex content) and directory ("<dir>") under `root`, by relative path.
fn tree(root: &str) -> BTreeMap<String, String> {
    fn walk(base: &Path, d: &Path, m: &mut BTreeMap<String, String>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
            if p.is_dir() {
                m.insert(rel, "<dir>".into());
                walk(base, &p, m);
            } else {
                m.insert(rel, h(&std::fs::read(&p).unwrap_or_default()));
            }
        }
    }
    let mut m = BTreeMap::new();
    walk(Path::new(root), Path::new(root), &mut m);
    m
}

fn mk(root: &str, files: &[(&str, &[u8])]) {
    for (rel, data) in files {
        let p = format!("{root}/{rel}");
        if rel.ends_with('/') {
            std::fs::create_dir_all(&p).unwrap();
        } else {
            std::fs::create_dir_all(dirname(&p)).unwrap();
            std::fs::write(&p, data).unwrap();
        }
    }
}

fn scrub(v: Value, root: &str) -> Value {
    let mut t = v.to_string().replace(root, "<root>");
    // the 6 random characters of a temporary file name are masked as XXXXXX
    let key = "Could not create temporary file '";
    let mut from = 0;
    while let Some(p) = t[from..].find(key) {
        let start = from + p + key.len();
        let end = start + t[start..].find('\'').unwrap();
        if end >= start + 6 {
            t.replace_range(end - 6..end, "XXXXXX");
        }
        from = end;
    }
    serde_json::from_str(&t).unwrap()
}

fn root_masked(b: &[u8], root: &str) -> Vec<u8> {
    String::from_utf8_lossy(b).replace(root, "<root>").into_bytes()
}

pub fn run(out: &Out, work: &Path, all: bool) -> usize {
    let p = out.platform;
    let mut n = 0;
    if all {
        n += pure(out);
    }
    n += files(out, work, &format!("files_{p}"));
    n += version(out, &format!("version_{p}"));
    n
}

/// Platform-independent string functions.
fn pure(out: &Out) -> usize {
    let mut cases = Vec::new();
    for s in ["etc/shared/default/agent.conf", "/agent.conf", "agent.conf", "a/b/", "/", "", "//", "a//b", "a//b//", "///x", "./a", "../a", ".", "..", "a/./b", "C:/x/y", "C:\\x\\y", "a/b\\c"] {
        cases.push(json!({"fn": "dirname", "input": s, "result": dirname(s)}));
        cases.push(json!({"fn": "default_path_offset", "input": s, "result": default_path_offset(s)}));
    }
    for d in [&b"a\r\nb\rc\r\n\r\x1ad\r\n"[..], b"", b"\r", b"\n", b"\r\r\n", b"x\x1a", b"\x1a", b"a\nb\r\n", b"\r\n\r\n", b"end\r"] {
        cases.push(json!({"fn": "crt::text_in", "input_hex": h(d), "result_hex": h(&crt::text_in(d))}));
        cases.push(json!({"fn": "crt::text_out", "input_hex": h(d), "result_hex": h(&crt::text_out(d))}));
    }
    cases.push(json!({"fn": "crt::network_path_executed", "input": "\\\\srv\\x", "result": crt::network_path_executed("\\\\srv\\x")}));
    for b in [&b""[..], b"abc", b"\x00\xff"] {
        cases.push(json!({"fn": "md5_hex", "input_hex": h(b), "result": md5_hex(b)}));
    }
    for v in -2..30 {
        cases.push(json!({"fn": "version_op::osx_release_name", "input": v, "result": version_op::osx_release_name(v)}));
    }
    cases.push(json!({"fn": "constants", "OSSEC_NAME": version_op::OSSEC_NAME, "OSSEC_VERSION": version_op::OSSEC_VERSION}));
    out.write(K, "pure", "Platform-independent: dirname, default_path_offset, crt::text_in / text_out (Windows text-mode translation), network_path_executed, md5_hex, osx_release_name, constants", cases)
}

fn files(out: &Out, work: &Path, name: &str) -> usize {
    let mut cases = Vec::new();
    cases.push(json!({"fn": "crt::TEXT_TRANSLATION", "result": crt::TEXT_TRANSLATION}));
    for s in ["", ".", "..", "../a", "a/..", "a/../b", "x/..y/..", "..a", "a/..b", ".../x", "..\\a", "a\\..\\b", "a\\..\\b/..x", "a\\..", "\\..", "a/...", "a/../", "/..", "a/b/c", "a\\.\\b", "....", "a/..\\b"] {
        cases.push(json!({"fn": "ref_parent_folder", "input": s, "result": ref_parent_folder(s)}));
    }
    for e in [2i32, 3, 5, 13, 17, 22, 32, 183] {
        let err = std::io::Error::from_raw_os_error(e);
        cases.push(json!({"fn": "wfopen_errno", "raw_os_error": e, "result": wfopen_errno(&err)}));
    }
    cases.push(json!({"fn": "wfopen_errno", "raw_os_error": null, "kind": "NotFound (no os code)", "result": wfopen_errno(&std::io::Error::new(std::io::ErrorKind::NotFound, "x"))}));
    for e in 0..45 {
        cases.push(json!({"fn": "strerror", "input": e, "result": strerror(e)}));
    }
    cases.push(json!({"fn": "strerror", "input": 9999, "result": strerror(9999)}));

    // merge_append_file
    let root = root_of(work, "merge");
    mk(&root, &[("g/agent.conf", b"<agent_config/>\n"), ("g/sub/x.txt", b"x"), ("g/empty", b""), ("g/sp ace.txt", b"a b\r\nc"), ("g/bin.dat", b"\x00\x01\xff")]);
    for (file, off) in [("g/agent.conf", None), ("g/agent.conf", Some(0usize)), ("g/agent.conf", Some(3)), ("g/agent.conf", Some(10_000)), ("g/sub/x.txt", None), ("g/empty", None), ("g/sp ace.txt", None), ("g/bin.dat", None), ("g/missing", None)] {
        let full = format!("{root}/{file}");
        let mut o = b"#g\n".to_vec();
        let ok = merge_append_file(&mut o, &full, off.map(|x| if x == 3 { root.len() + 3 } else { x }));
        let lg = logs();
        cases.push(scrub(json!({"fn": "merge_append_file", "file": format!("<root>/{file}"), "path_offset": off.map(|x| if x == 3 { "root length + 3".to_string() } else { x.to_string() }), "buffer_before": "#g\n", "ok": ok, "buffer_after_hex_with_root_masked": h(&root_masked(&o, &root)), "logs": lg}), &root));
    }

    // check_binary_file
    let root = root_of(work, "bin");
    let mut long = vec![b'a'; 70000];
    long[100] = 0;
    long.push(b'\n');
    let mut long2 = vec![b'a'; 65535];
    long2.push(0);
    long2.push(b'\n');
    let samples: Vec<(&str, Vec<u8>)> = vec![
        ("text", b"text\nmore\n".to_vec()), ("nul in line", b"text\nbad\x00line\n".to_vec()), ("nul in last line without newline", b"text\nlast\x00line".to_vec()),
        ("empty", vec![]), ("only nul", vec![0]), ("nul then newline", b"\x00\n".to_vec()), ("crlf nul", b"a\x00\r\n".to_vec()),
        ("nul in first 64KiB piece of a 70000-byte line", long), ("nul at byte 65535 before newline", long2), ("high bytes", b"\xff\xfe\n".to_vec()),
    ];
    for (what, d) in &samples {
        let f = format!("{root}/f");
        std::fs::write(&f, d).unwrap();
        let r = check_binary_file(&f);
        cases.push(json!({"fn": "check_binary_file", "content": what, "content_hex": if d.len() < 200 { Some(h(d)) } else { None }, "result": r, "logs": logs()}));
    }
    let r = check_binary_file(&format!("{root}/missing"));
    cases.push(scrub(json!({"fn": "check_binary_file", "content": "missing file", "result": r, "logs": logs()}), &root));

    // test_unmerge_files and unmerge_files
    let merged: Vec<(&str, Vec<u8>)> = vec![
        ("normal", b"#g\n!16 agent.conf\n<agent_config/>\n!1 sub/x.txt\nx".to_vec()),
        ("no comment line", b"!3 a.txt\nabc".to_vec()),
        ("empty file", vec![]),
        ("only comment", b"#default\n".to_vec()),
        ("size larger than data", b"!100 a.txt\nabc".to_vec()),
        ("size zero", b"!0 a.txt\n!2 b.txt\nhi".to_vec()),
        ("size not a number", b"!x a.txt\nabc".to_vec()),
        ("header without space", b"!3a.txt\nabc".to_vec()),
        ("empty name", b"!3 \nabc".to_vec()),
        ("garbage first line", b"hello\n!3 a.txt\nabc".to_vec()),
        ("dot-dot name", b"!3 ../evil.txt\nabc!2 ok.txt\nhi".to_vec()),
        ("name with spaces and unicode", "!3 my file é.txt\nabc".as_bytes().to_vec()),
        ("crlf in content", b"!5 a.txt\na\r\nb\n".to_vec()),
        ("crlf headers", b"#g\r\n!3 a.txt\r\nabc".to_vec()),
        ("nested dirs", b"!1 d1/d2/d3/f\nz".to_vec()),
        ("absolute-looking name", b"!1 /abs.txt\nz".to_vec()),
        ("leading zeros size", b"!003 a.txt\nabc".to_vec()),
        ("plus size", b"!+3 a.txt\nabc".to_vec()),
        ("header line over 2047 bytes", [b"!1 ".to_vec(), vec![b'n'; 2100], b"\nz".to_vec()].concat()),
        ("ctrl-z in content", b"!3 a.txt\na\x1ab".to_vec()),
        ("same name twice", b"!1 a.txt\n1!1 a.txt\n2".to_vec()),
    ];
    for (what, data) in &merged {
        let root = root_of(work, "unmerge");
        let mg = format!("{root}/merged.mg");
        std::fs::write(&mg, data).unwrap();
        let t = test_unmerge_files(&mg);
        let lt = logs();
        let mut v = json!({"fn": "test_unmerge_files + unmerge_files", "merged": what, "merged_hex": h(data), "test_unmerge_files": t, "test_logs": lt});
        // Windows: the temp files only grant Administrators and SYSTEM, so unmerging needs an elevated run
        if cfg!(unix) {
            for (mode, text) in [("text", true), ("binary", false)] {
                let od = format!("{root}/out_{mode}");
                let (ok, names) = unmerge_files_mode(&mg, Some(&od), text);
                let lg = logs();
                let mut tr = tree(&root);
                tr.remove("merged.mg");
                v[format!("unmerge_{mode}")] = scrub(json!({"ok": ok, "names": names, "tree_after": tr, "logs": lg}), &root);
            }
            let (ok, names) = unmerge_files(&mg, Some(&format!("{root}/out_default")));
            v["unmerge_files_default_mode_same_as_text"] = json!(ok == v["unmerge_text"]["ok"] && names.len() == v["unmerge_text"]["names"].as_array().unwrap().len());
            let _ = logs();
        }
        cases.push(v);
    }
    if cfg!(unix) {
        // optdir None writes relative to the current directory
        let root = root_of(work, "unmerge_none");
        let mg = format!("{root}/m.mg");
        std::fs::write(&mg, b"!2 rel_none.txt\nhi").unwrap();
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();
        let (ok, names) = unmerge_files(&mg, None);
        std::env::set_current_dir(cwd).unwrap();
        cases.push(scrub(json!({"fn": "unmerge_files optdir None", "merged": "!2 rel_none.txt\\nhi", "ok": ok, "names": names, "tree_after": tree(&root), "logs": logs()}), &root));
        let r = unmerge_files(&format!("{root}/missing.mg"), Some(&root));
        cases.push(scrub(json!({"fn": "unmerge_files missing merged file", "ok": r.0, "names": r.1, "logs": logs()}), &root));
    }

    // wreaddir, copy_file, rmdir_ex, cldir_ex_ignore
    let root = root_of(work, "dirs");
    mk(&root, &[("d/b", b"1"), ("d/a", b"2"), ("d/B", b"3"), ("d/_x", b""), ("d/sub/", b""), ("d/.hidden", b"h"), ("d/é", b"e"), ("d/10", b""), ("d/9", b"")]);
    cases.push(json!({"fn": "wreaddir", "entries_created": ["b", "a", "B", "_x", "sub/", ".hidden", "é", "10", "9"], "result": wreaddir(&format!("{root}/d")), "missing": wreaddir(&format!("{root}/nope")), "on_a_file": wreaddir(&format!("{root}/d/a"))}));
    for (mode, msg, dst_before) in [('a', Some("<!-- Source file: g/agent.conf -->\n"), Some(&b"old\n"[..])), ('a', None, None), ('c', None, Some(&b"old content"[..])), ('w', Some("msg"), None), ('x', Some(""), Some(&b"z"[..]))] {
        let src = format!("{root}/src.txt");
        let dst = format!("{root}/dst.txt");
        std::fs::write(&src, b"line1\nline2").unwrap();
        let _ = std::fs::remove_file(&dst);
        if let Some(b) = dst_before {
            std::fs::write(&dst, b).unwrap();
        }
        let r = copy_file(&src, &dst, mode, msg);
        cases.push(json!({"fn": "copy_file", "src_content": "line1\\nline2", "mode": mode.to_string(), "message": msg, "dst_before_hex": dst_before.map(h), "ok": r.is_ok(), "dst_after_hex": std::fs::read(&dst).ok().map(|d| h(&d))}));
    }
    let r = copy_file(&format!("{root}/nosrc"), &format!("{root}/dst2"), 'a', Some("m"));
    cases.push(json!({"fn": "copy_file missing source", "ok": r.is_ok(), "dst_created": Path::new(&format!("{root}/dst2")).exists()}));

    for (what, setup, target) in [("file", vec![("x/f", &b"1"[..])], "x/f"), ("tree", vec![("x/a/b/c", b"1"), ("x/a/d", b"2")], "x/a"), ("missing", vec![], "x/none"), ("empty dir", vec![("x/e/", b"")], "x/e")] {
        let root = root_of(work, "rm");
        mk(&root, &setup);
        let r = rmdir_ex(&format!("{root}/{target}"));
        cases.push(json!({"fn": "rmdir_ex", "case": what, "target": target, "ok": r.is_ok(), "tree_after": tree(&root)}));
    }
    let base: Vec<(&str, &[u8])> = vec![("c/merged.mg", b"m"), ("c/agent.conf", b"a"), ("c/sub/x.txt", b"x"), ("c/sub/y.txt", b"y"), ("c/sub/deep/z", b"z"), ("c/other/", b""), ("c/keep/", b"")];
    for ignore in [vec![], vec!["merged.mg"], vec!["merged.mg", "agent.conf"], vec!["sub/x.txt"], vec!["sub"], vec!["sub/deep/z"], vec!["keep"], vec!["nonexistent"], vec!["sub/"], vec!["su"]] {
        let root = root_of(work, "cl");
        mk(&root, &base);
        let r = cldir_ex_ignore(&format!("{root}/c"), &ignore);
        cases.push(json!({"fn": "cldir_ex_ignore", "tree_before": "c/merged.mg, c/agent.conf, c/sub/x.txt, c/sub/y.txt, c/sub/deep/z, c/other/ (empty dir), c/keep/ (empty dir)", "dir": "c", "ignore": ignore, "ok": r.is_ok(), "tree_after": tree(&root)}));
    }
    let root = root_of(work, "cl");
    let r = cldir_ex_ignore(&format!("{root}/missing"), &[]);
    cases.push(json!({"fn": "cldir_ex_ignore missing dir", "ok": r.is_ok()}));

    // md5_file (text mode on Windows), mtime, read_text / write_text / TextFile
    let root = root_of(work, "md5");
    for d in [&b"abc"[..], b"a\r\nb", b"a\x1ab", b"", b"\r\n"] {
        let f = format!("{root}/f");
        std::fs::write(&f, d).unwrap();
        let w = format!("{root}/w");
        crt::write_text(&w, d).unwrap();
        let tf = format!("{root}/tf");
        {
            use std::io::Write;
            let mut t = crt::TextFile::create(&tf).unwrap();
            t.write_all(d).unwrap();
            t.write_all(b"\n").unwrap();
        }
        cases.push(json!({"fn": "md5_file / read_text / write_text / TextFile", "file_hex": h(d), "md5_file": md5_file(&f), "read_text_hex": h(&crt::read_text(&f).unwrap()),
            "write_text_file_hex": h(&std::fs::read(&w).unwrap()), "textfile_write_then_newline_hex": h(&std::fs::read(&tf).unwrap())}));
    }
    cases.push(json!({"fn": "md5_file missing", "result": md5_file(&format!("{root}/none")), "read_text_missing_is_err": crt::read_text(format!("{root}/none")).is_err()}));
    let f = format!("{root}/t");
    std::fs::write(&f, b"x").unwrap();
    std::fs::File::options().write(true).open(&f).unwrap().set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)).unwrap();
    cases.push(json!({"fn": "mtime", "file_set_to": 1_700_000_000, "result": mtime(&f), "missing": mtime(&format!("{root}/none")), "dir_is_some": mtime(&root).is_some()}));

    // mktemp / mkstemp_ex / rename_ex
    let root = root_of(work, "tmp");
    let pid = format!("{:05}", std::process::id() % 100_000);
    let t1 = mktemp(&format!("{root}/fXXXXXX"));
    std::fs::write(format!("{root}/fa{pid}"), b"").unwrap();
    let t2 = mktemp(&format!("{root}/fXXXXXX"));
    cases.push(json!({"fn": "mktemp", "note": "<pid5> = process id mod 100000, 5 digits", "first": t1.map(|s| s.replace(&root, "<root>").replace(&pid, "<pid5>")),
        "when_a_exists": t2.map(|s| s.replace(&root, "<root>").replace(&pid, "<pid5>")), "no_xxxxxx": mktemp(&format!("{root}/f")), "five_x": mktemp(&format!("{root}/fXXXXX"))}));
    let st = mkstemp_ex(&format!("{root}/sXXXXXX"));
    let shape = st.as_ref().map(|s| {
        let suf = &s[root.len() + 2..];
        json!({"suffix_len": suf.len(), "suffix_alnum": suf.chars().all(|c| c.is_ascii_alphanumeric()), "exists_empty": std::fs::metadata(s).map(|m| m.len() == 0).unwrap_or(false),
               "unix_mode": file_mode(s)})
    });
    cases.push(json!({"fn": "mkstemp_ex", "result_shape": shape, "no_xxxxxx": mkstemp_ex(&format!("{root}/s")), "logs": scrub(logs(), &root)}));
    std::fs::write(format!("{root}/r1"), b"one").unwrap();
    std::fs::write(format!("{root}/r2"), b"two").unwrap();
    let a = rename_ex(&format!("{root}/r1"), &format!("{root}/r2"));
    let b = rename_ex(&format!("{root}/none"), &format!("{root}/r3"));
    cases.push(json!({"fn": "rename_ex", "over_existing": a, "tree_after_first": tree(&root).into_iter().filter(|(k, _)| k.starts_with('r')).collect::<BTreeMap<_, _>>(), "missing_source": b, "dst_created_on_failure": Path::new(&format!("{root}/r3")).exists(), "logs": scrub(logs(), &root)}));

    #[cfg(windows)]
    for p in ["\\\\server\\share\\x", "\\\\?\\C:\\x", "//server/share", "C:\\Windows", "c:\\x", "Z:\\x", "", "C", "relative\\path", "\\single"] {
        cases.push(json!({"fn": "crt::is_network_path", "input": p, "result": crt::is_network_path(p), "note": "drive results depend on this machine (no mapped drives here)"}));
    }
    out.write(K, name, "File helpers run on this platform: ref_parent_folder, wfopen_errno, strerror, merge_append_file, check_binary_file, test_unmerge_files, unmerge_files (unix only), wreaddir, copy_file, rmdir_ex, cldir_ex_ignore, md5_file, crt read/write, mtime, mktemp, mkstemp_ex, rename_ex, is_network_path (Windows)", cases)
}

#[cfg(unix)]
fn file_mode(p: &str) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).ok().map(|m| m.permissions().mode() & 0o777)
}
#[cfg(not(unix))]
fn file_mode(_: &str) -> Option<u32> {
    None
}

struct Fake {
    files: HashMap<String, Vec<u8>>,
    cmds: HashMap<String, Vec<u8>>,
    uname: Option<UtsName>,
    path: Option<String>,
    exe: Vec<String>,
    asked: std::cell::RefCell<Vec<String>>,
}

impl Probe for Fake {
    fn read_file(&self, p: &str) -> Option<Vec<u8>> {
        self.asked.borrow_mut().push(format!("read {p}"));
        self.files.get(p).cloned()
    }
    fn popen(&self, c: &str) -> Option<Vec<u8>> {
        self.asked.borrow_mut().push(format!("run {c}"));
        self.cmds.get(c).cloned()
    }
    fn uname(&self) -> Option<UtsName> {
        self.uname.clone()
    }
    fn path_env(&self) -> Option<String> {
        self.path.clone()
    }
    fn is_file(&self, p: &str) -> bool {
        self.exe.iter().any(|e| e == p)
    }
}

fn info_json(i: &OsInfo) -> Value {
    json!({"os_name": i.os_name, "os_major": i.os_major, "os_minor": i.os_minor, "os_patch": i.os_patch, "os_build": i.os_build, "os_version": i.os_version,
        "os_codename": i.os_codename, "os_release": i.os_release, "os_platform": i.os_platform, "sysname": i.sysname, "nodename": i.nodename,
        "release": i.release, "version": i.version, "machine": i.machine})
}

fn uts() -> UtsName {
    UtsName { sysname: "Linux".into(), nodename: "host1".into(), release: "5.15.0-91-generic".into(), version: "#101-Ubuntu SMP".into(), machine: "x86_64".into() }
}

fn version(out: &Out, name: &str) -> usize {
    let mut cases = Vec::new();
    let osr = |s: &str| -> Vec<(&'static str, Vec<u8>)> { vec![("/etc/os-release", s.as_bytes().to_vec())] };
    let long_line = format!("NAME=\"{}\"\nVERSION=\"1.2.3\"\nID=x\n", "N".repeat(300));
    let scenarios: Vec<(&str, Vec<(&'static str, Vec<u8>)>, Vec<(&'static str, &'static str)>, bool)> = vec![
        ("ubuntu os-release", osr("NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n"), vec![], true),
        ("VERSION_ID before VERSION", osr("NAME=Debian GNU/Linux\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nID=debian\n"), vec![], true),
        ("only VERSION_ID", osr("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.4\n"), vec![], true),
        ("unquoted with trailing text", osr("NAME=Fedora Linux\nVERSION=39 (Workstation Edition)\nID=fedora extra\nVERSION_ID=39\n"), vec![], true),
        ("quote not closed", osr("NAME=\"Open\nVERSION=\"1.0\nID=\"x\n"), vec![], true),
        ("duplicate keys keep first", osr("NAME=A\nNAME=B\nID=a\nID=b\nVERSION=1\nVERSION=2\n"), vec![], true),
        ("centos uses centos-release", vec![("/etc/os-release", b"NAME=\"CentOS Linux\"\nVERSION=\"7 (Core)\"\nID=\"centos\"\n".to_vec()), ("/etc/centos-release", b"CentOS Linux release 7.9.2009 (Core)\n".to_vec())], vec![], true),
        ("centos without centos-release", osr("NAME=\"CentOS Linux\"\nVERSION=\"7 (Core)\"\nID=\"centos\"\n"), vec![], true),
        ("arch", osr("NAME=\"Arch Linux\"\nID=arch\n"), vec![], true),
        ("opensuse-tumbleweed", osr("NAME=\"openSUSE Tumbleweed\"\nID=\"opensuse-tumbleweed\"\nVERSION_ID=\"20231101\"\n"), vec![], true),
        ("usr/lib/os-release", vec![("/usr/lib/os-release", b"NAME=X\nVERSION=9.1\nID=x\n".to_vec())], vec![], true),
        ("missing ID falls back", osr("NAME=X\nVERSION=1\n"), vec![], true),
        ("ID without value", osr("NAME=X\nVERSION=1\nID=\n"), vec![], true),
        ("NAME without value", osr("NAME=\nVERSION=1\nID=x\n"), vec![], true),
        ("line longer than 254 bytes", vec![("/etc/os-release", long_line.into_bytes())], vec![], true),
        ("NUL inside a line", osr("NAME=A\u{0}B\nVERSION=1\nID=x\n"), vec![], true),
        ("darwin version gets codename", osr("NAME=macOS\nVERSION=\"14.1 (Sonoma)\"\nID=darwin\n"), vec![], true),
        ("version without dots", osr("NAME=X\nVERSION=rolling\nID=x\n"), vec![], true),
        ("version 1.2.3.4", osr("NAME=X\nVERSION=1.2.3.4 (cn)\nID=x\n"), vec![], true),
        ("empty VERSION", osr("NAME=X\nVERSION=\"\"\nID=x\n"), vec![], true),
        ("centos-release", vec![("/etc/centos-release", b"CentOS release 6.10 (Final)\n".to_vec())], vec![], true),
        ("fedora-release", vec![("/etc/fedora-release", b"Fedora release 38 (Thirty Eight)\n".to_vec())], vec![], true),
        ("redhat-release server", vec![("/etc/redhat-release", b"Red Hat Enterprise Linux Server release 7.9 (Maipo)\n".to_vec())], vec![], true),
        ("redhat-release plain", vec![("/etc/redhat-release", b"Red Hat Enterprise Linux release 8.8 (Ootpa)\n".to_vec())], vec![], true),
        ("redhat-release says CentOS", vec![("/etc/redhat-release", b"CentOS Stream release 9\n".to_vec())], vec![], true),
        ("redhat-release no number", vec![("/etc/redhat-release", b"weird\nFedora 2\n".to_vec())], vec![], true),
        ("arch-release", vec![("/etc/arch-release", b"\n".to_vec())], vec![], true),
        ("gentoo-release", vec![("/etc/gentoo-release", b"Gentoo Base System release 2.14\n".to_vec())], vec![], true),
        ("SuSE-release", vec![("/etc/SuSE-release", b"SUSE Linux Enterprise Server 11 (x86_64)\nVERSION = 11\nPATCHLEVEL = 4\n".to_vec())], vec![], true),
        ("lsb-release", vec![("/etc/lsb-release", b"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=18.04\nDISTRIB_CODENAME=bionic\n".to_vec())], vec![], true),
        ("lsb-release without release", vec![("/etc/lsb-release", b"DISTRIB_ID=Ubuntu\n".to_vec())], vec![], true),
        ("debian_version", vec![("/etc/debian_version", b"11.7\n".to_vec())], vec![], true),
        ("debian_version text", vec![("/etc/debian_version", b"bookworm/sid\n".to_vec())], vec![], true),
        ("slackware-version", vec![("/etc/slackware-version", b"Slackware 15.0\n".to_vec())], vec![], true),
        ("alpine-release", vec![("/etc/alpine-release", b"3.19.1\n".to_vec())], vec![], true),
        ("uname Linux", vec![], vec![("uname", "Linux\n")], true),
        ("uname via PATH", vec![], vec![("/usr/bin/uname", "Linux\n")], true),
        ("uname Darwin", vec![], vec![("uname", "Darwin\n"), ("system_profiler SPSoftwareDataType", "Software:\n\n    System Software Overview:\n\n      System Version: macOS 14.1 (23B74)\n"), ("sw_vers -productVersion", "14.1\n"), ("sw_vers -buildVersion", "23B74\n"), ("uname -r", "23.1.0\n")], true),
        ("uname Darwin no tools", vec![], vec![("uname", "Darwin\n")], true),
        ("uname SunOS", vec![("/etc/release", b"   Oracle Solaris 11.4 X86\n".to_vec())], vec![("uname", "SunOS\n")], true),
        ("uname SunOS without release", vec![], vec![("uname", "SunOS\n")], true),
        ("uname SunOS no Solaris word", vec![("/etc/release", b"OpenIndiana 2023\n".to_vec())], vec![("uname", "SunOS\n")], true),
        ("uname HP-UX", vec![], vec![("uname", "HP-UX\n"), ("uname -r", "B.11.31\n")], true),
        ("uname FreeBSD", vec![], vec![("uname", "FreeBSD\n"), ("uname -r", "13.2-RELEASE\n")], true),
        ("uname OpenBSD", vec![], vec![("uname", "OpenBSD\n"), ("uname -r", "7.4\n")], true),
        ("uname ZscalerOS", vec![], vec![("uname", "ZscalerOS\n"), ("uname -r", "12-RELEASE-p3 x\n")], true),
        ("uname AIX", vec![], vec![("uname", "AIX\n"), ("oslevel", "7.2.0.0\n")], true),
        ("uname AIX empty oslevel", vec![], vec![("uname", "AIX\n"), ("oslevel", "")], true),
        ("uname unknown", vec![], vec![("uname", "Plan9\n")], true),
        ("uname empty output", vec![], vec![("uname", "")], true),
        ("nothing at all", vec![], vec![], true),
        ("no uname struct", osr("NAME=X\nVERSION=1\nID=x\n"), vec![], false),
        ("no uname struct, nothing", vec![], vec![], false),
        ("very long fields", osr(&format!("NAME={}\nVERSION=1\nID=x\n", "é".repeat(300))), vec![], true),
    ];
    for (what, files, cmds, has_uname) in scenarios {
        let path_cmd = cmds.iter().any(|(c, _)| c.starts_with('/'));
        let fake = Fake {
            files: files.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            cmds: cmds.iter().map(|(k, v)| (k.to_string(), v.as_bytes().to_vec())).collect(),
            uname: has_uname.then(uts),
            path: path_cmd.then(|| "/usr/local/bin::/usr/bin".to_string()),
            exe: if path_cmd { vec!["/usr/bin/uname".into()] } else { vec![] },
            asked: Default::default(),
        };
        let gv = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| version_op::get_unix_version(&fake)));
        let asked = fake.asked.borrow().clone();
        fake.asked.borrow_mut().clear();
        let gu = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| version_op::getuname_with(&fake)));
        cases.push(json!({"fn": "version_op::get_unix_version / getuname_with", "scenario": what,
            "files": fake.files.iter().map(|(k, v)| (k.clone(), String::from_utf8_lossy(v).into_owned())).collect::<BTreeMap<_, _>>(),
            "commands": cmds.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>(),
            "uname": has_uname.then(|| { let u = uts(); json!([u.sysname, u.nodename, u.release, u.version, u.machine]) }),
            "path_env": fake.path, "executables": fake.exe,
            "get_unix_version": match gv { Ok(v) => json!({"result": v.as_ref().map(info_json)}), Err(_) => json!({"panic": true}) },
            "probe_calls_in_order": asked,
            "getuname_with": match gu { Ok(s) => json!(s), Err(_) => json!({"panic": true}) }}));
    }
    for (path, exe, bin) in [(Some("/a:/b"), vec!["/b/x"], "x"), (Some("/a:/b"), vec![], "x"), (None, vec![], "x"), (Some(""), vec![], "x"), (Some("/a::/b/"), vec!["/b//x"], "x"), (Some("/a"), vec!["/abs"], "/abs"), (Some("/a"), vec![], "/abs")] {
        let fake = Fake { files: HashMap::new(), cmds: HashMap::new(), uname: None, path: path.map(str::to_string), exe: exe.iter().map(|s| s.to_string()).collect(), asked: Default::default() };
        let (ok, p) = version_op::get_binary_path(&fake, bin);
        cases.push(json!({"fn": "version_op::get_binary_path", "path_env": path, "executables": exe, "binary": bin, "found": ok, "result": p}));
    }
    #[cfg(unix)]
    for (pat, s) in [("^([0-9]+)\\.*", "22.04"), ("([0-9]+\\.)?([0-9]+\\.)?([0-9]+)", "3.19.1"), ("(", "x"), ("a", "b")] {
        cases.push(json!({"fn": "version_op::w_regexec (POSIX extended)", "pattern": pat, "subject": s, "nmatch": 3, "result": version_op::w_regexec(pat, s.as_bytes(), 3)}));
    }
    let live = version_op::getuname();
    cases.push(json!({"fn": "version_op::getuname (this machine; shape only)", "example": live, "len": live.len()}));
    #[cfg(windows)]
    {
        for b in [Some("10240"), Some("10586"), Some("14393"), Some("15063"), Some("17134"), Some("17763"), Some("18362"), Some("18363"), Some("19045"), Some(""), None] {
            cases.push(json!({"fn": "win_version::get_release_from_build", "input": b, "result": siem_fileop::win_version::get_release_from_build(b)}));
        }
        let wv = siem_fileop::win_version::get_win_version();
        cases.push(json!({"fn": "win_version::get_win_version (this machine)", "result": wv.as_ref().map(info_json)}));
    }
    out.write(K, name, "version_op: get_unix_version / getuname_with over a fake system (files, command outputs, uname struct; get_unix_version is unix-only in effect: its regex helper finds nothing on Windows), get_binary_path, w_regexec, live getuname; Windows: get_release_from_build, get_win_version", cases)
}
