use super::*;

fn ctx_with(secedit: Result<HashMap<String, String>, String>, auditpol: Result<HashMap<String, String>, String>) -> Context {
    Context { secedit: OnceCell::from(secedit), auditpol: OnceCell::from(auditpol), ..Default::default() }
}

fn holds(rule: &str, ctx: &Context) -> Result<bool, String> {
    Rule::parse(rule).unwrap().eval(ctx)
}

const SECEDIT_INI: &str = "[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordLength = 14\r\nPasswordComplexity = 1\r\nEnableGuestAccount = 0\r\nNewAdministratorName = \"Administrator\"\r\n[Privilege Rights]\r\nSeDebugPrivilege = *S-1-5-32-544\r\nSeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\n";

const AUDITPOL_CSV: &str = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n\
PC1,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,\r\n\
PC1,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,\r\n\
PC1,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing,\r\n";

#[test]
fn rule_parser() {
    for ok in [
        r"r:HKLM\SOFTWARE\X",
        r"r:HKLM\SOFTWARE\X -> V",
        r"r:HKLM\SOFTWARE\Windows NT\X -> V -> 0x1",
        r"not r:HKLM\SOFTWARE\X -> V",
        r"r:HKLM\X -> V -> n:^(\d+) compare >= 14",
        r"f:%WINDIR%\System32\x.dll",
        r"f:C:\x.ini -> r:^allow=1",
        "p:r:^teamviewer",
        "c:secedit-value:MinimumPasswordLength -> n:^(\\d+) compare >= 14",
        "c:auditpol:Logon -> r:Success and Failure",
        "not c:secedit-value:SeTcbPrivilege",
        "c:other:Name",
        r"c:reg query HKLM\X /v Y -> r:0x1 && !r:^#",
        r"d:C:\x -> r:\.conf$ -> n:^port (\d+) compare < 1024",
        r"f:/etc/x -> !r:^# && && r:timeout && n:\s+(\d+) compare <= 10",
        "r:HKLM -> V -> r:(",
    ] {
        assert!(Rule::parse(ok).is_ok(), "{ok}");
    }
    for bad in [
        "x:thing",
        "r:",
        "no kind",
        r"r:HKLM\X -> V -> 1 -> 2",
        "p:a -> b",
        "d:a -> b -> c -> d",
        "f:a -> && &&",
        r"r:HKLM\X -> V -> n:^\d+ compare >= 1",
        r"r:HKLM\X -> V -> n:^(\d+) compare => 1",
    ] {
        assert!(Rule::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn matchers() {
    let m = |p: &str, v: &str| Matcher::parse(p).unwrap().matches(v);
    assert!(m("1", "1") && m("0x1", "1") && m("0xff", "255") && m("Block", "block"));
    assert!(!m("1", "18") && !m("0x1", "0"));
    assert!(m("r:^(1|2)$", "2") && !m("r:^(1|2)$", "12"));
    assert!(m(r"n:^(\d+) compare >= 14", "14") && !m(r"n:^(\d+) compare >= 14", "13"));
    assert!(!m(r"n:^(\d+) compare >= 14", "-1"), "no number: no match");
    assert!(m(r"n:^(\d+) compare <= 4", "4") && m(r"n:^(\d+) compare != 0", "3") && m(r"n:^(\d+) compare > 0", "1"));
    assert!(m(r"n:^(\d+) compare == 7", "7") && !m(r"n:^(\d+) compare == 7", "8"));
    assert!(m(r"n:^(\d+) compare < 7", "6") && !m(r"n:^(\d+) compare < 7", "7"));
    assert!(!m(r"n:^(\d+) compare <= 4", "5") && !m(r"n:^(\d+) compare != 0", "0") && !m(r"n:^(\d+) compare > 0", "0"));
    assert!(m("!r:^#", "port 1") && !m("!r:^#", "# port 1"));
}

#[test]
fn regex_dialect() {
    let m = |p: &str, v: &str| Matcher::parse(p).unwrap().matches(v);
    assert!(m(r"r:dav_\.+module", "dav_fs_module"));
    assert!(!m("r:manual.conf", "manualxconf") && m("r:manual.conf", "Manual.conf"));
    let Matcher::Numeric(re, ..) = Matcher::parse(r"n:header=\d+\p(\d+) compare <= 40").unwrap() else { panic!() };
    assert_eq!(&re.captures("header=10,30").unwrap()[1], "30");
    assert!(m(r"n:header=\d+\p(\d+) compare <= 40", "header=10,30"));
    assert!(m(r"r:No Instance\(s\) Available.", "No Instance(s) Available.") && !m(r"r:No Instance\(s\) Available.", "No Instances Available!"));
    assert!(m(r"r:\.", "x") && !m(r"r:\.", ""));
    assert!(m(r"r:^a\sb$", "a\tb") && !m(r"r:^a\sb$", "a\nb"));
    assert!(m(r"r:^\w+$", "user@host_1-a") && !m(r"r:^\w+$", "a.b"));
    assert!(m("r:^[x]{2}?$", "[x]{2}?") && !m("r:^[x]{2}?$", "xx"), "[ ] {{ }} ? are literal");
    assert!(m(r"r:^\$\^\|\\$", r"$^|\") && m(r"r:\S+", "x"), "escaped symbols are literal; other letters are Rust's");
}

#[test]
fn bad_regex_is_not_applicable() {
    let ctx = Context::default();
    for rule in [r"r:HKLM\SOFTWARE -> V -> r:(", r"f:C:\x -> !r:\p(", r"d:C:\x -> r:( -> x", r"c:echo x -> n:(\d+)) compare < 1"] {
        let e = holds(rule, &ctx).unwrap_err();
        assert!(e.starts_with("bad regex"), "{rule}: {e}");
        assert!(holds(&format!("not {rule}"), &ctx).is_err(), "not keeps it not applicable");
    }
}

#[test]
fn content_patterns_on_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("httpd.conf");
    std::fs::write(&f, "# Timeout 5\nTimeout 300\nKeepAlive On\nListen 80\n").unwrap();
    let ctx = Context::default();
    let r = |content: &str| holds(&format!("f:{} -> {content}", f.display()), &ctx);
    assert_eq!(r("r:timeout && r:300"), Ok(true), "same line");
    assert_eq!(r("r:timeout && r:On"), Ok(false), "on different lines");
    assert_eq!(r(r"!r:^# && r:timeout && n:\s+(\d+) compare <= 10"), Ok(false), "only the commented line is low");
    assert_eq!(r(r"!r:^# && && r:timeout && n:\s+(\d+) compare >= 100"), Ok(true));
    assert_eq!(r(r"r:^# && n:\s+(\d+) compare <= 10"), Ok(true));
    assert_eq!(r("Listen 80"), Ok(true), "a literal is the whole line");
    assert_eq!(r("Listen"), Ok(false));
    assert_eq!(holds(&format!("not f:{} -> r:^keepalive off", f.display()), &ctx), Ok(true));
}

#[test]
fn dir_rules_look_at_every_depth() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("conf.d").join("extra");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("ssl.conf"), "SSLCompression off\n").unwrap();
    std::fs::write(dir.path().join("readme.txt"), "SSLCompression on\n").unwrap();
    let ctx = Context::default();
    let d = dir.path().display().to_string();
    let r = |rest: &str| holds(&format!("d:{d}{rest}"), &ctx);
    assert_eq!(r(""), Ok(true));
    assert_eq!(holds(&format!("d:{d}{}missing", std::path::MAIN_SEPARATOR), &ctx), Ok(false));
    assert_eq!(r(r" -> .conf$"), Ok(true), "found two levels down");
    assert_eq!(r(r" -> r:^extra$"), Ok(true), "a folder name counts");
    assert_eq!(r(r" -> .ini$"), Ok(false));
    assert_eq!(r(r" -> conf -> r:SSLCompression\s+off"), Ok(true));
    assert_eq!(r(r" -> conf -> r:SSLCompression\s+on"), Ok(false), "readme.txt has it but its name does not match");
    assert_eq!(holds(&format!("not d:{d} -> conf -> r:SSLCompression\\s+on"), &ctx), Ok(true));
}

#[test]
fn variables() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("php.ini");
    std::fs::write(&real, "expose_php = Off\n").unwrap();
    let missing = dir.path().join("none.ini").display().to_string();
    let vars = |v: &[(&str, Option<&str>)]| v.iter().map(|(n, x)| (n.to_string(), x.map(String::from))).collect::<Vec<_>>();
    let list = format!("{missing}, {}", real.display());
    let v = vars(&[("$ini-files", Some(&list)), ("$ini", Some(&missing)), ("$User", None), ("$empty", Some(" "))]);
    let ctx = Context::default();
    let r = |rule: &str| Rule::parse_with(rule, &v).unwrap().eval(&ctx);
    assert_eq!(r("f:$ini-files"), Ok(true), "any file of the list; `$ini` not put into `$ini-files`");
    assert_eq!(r("f:$ini-files -> r:^expose_php\\s*=\\s*off"), Ok(true));
    assert_eq!(r("not f:$ini-files -> r:^expose_php\\s*=\\s*on"), Ok(true));
    assert_eq!(r("f:$ini"), Ok(false));
    assert_eq!(r("c:sqlcmd -U $User -> r:x"), Err("variable $User has no value".into()));
    assert_eq!(r("f:$empty"), Err("variable $empty has no value".into()));
    assert_eq!(substitute("echo $env:TEMP", &v), Ok(vec!["echo $env:TEMP".to_string()]), "$env: is left alone");
}

#[test]
fn commands() {
    let ctx = Context::default();
    assert_eq!(holds("c:echo hello -> r:^hello", &ctx), Ok(true));
    assert_eq!(holds("c:echo oops 1>&2 -> r:^oops", &ctx), Ok(true), "standard error is read");
    assert_eq!(holds("c:echo hello -> r:^bye", &ctx), Ok(false));
    assert_eq!(holds("c:exit 0", &ctx), Ok(true));
    assert_eq!(holds("c:exit 3", &ctx), Ok(false));
    assert_eq!(holds("not c:exit 3", &ctx), Ok(true));
    let fail_with_output = if cfg!(windows) { "c:echo found& exit 1 -> r:^found" } else { "c:echo found; exit 1 -> r:^found" };
    assert_eq!(holds(fail_with_output, &ctx), Ok(true), "a non-zero exit with output is evaluated");
}

#[test]
fn command_timeout_is_not_applicable() {
    let ctx = Context { command_timeout: Duration::from_secs(1), ..Default::default() };
    let slow = if cfg!(windows) { "c:ping -n 6 127.0.0.1 -> r:x" } else { "c:sleep 5 -> r:x" };
    let t = std::time::Instant::now();
    let e = holds(slow, &ctx).unwrap_err();
    assert!(e.contains("timed out"), "{e}");
    assert!(t.elapsed().as_secs() < 5);
}

#[test]
fn a_command_runs_once_per_scan() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("runs.txt");
    let rule = format!("c:echo run>>\"{}\" -> r:x", log.display());
    let ctx = Context::default();
    for _ in 0..3 {
        assert_eq!(holds(&rule, &ctx), Ok(false));
    }
    assert_eq!(holds(&format!("not {rule}"), &ctx), Ok(true));
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 1);
    holds(&rule, &Context::default()).unwrap();
    assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2, "a new scan runs it again");
}

#[test]
fn requirements_condition_form() {
    let yaml = |req: &str| format!("policy: {{ id: p, name: P }}\nvariables: {{ $dirs: '{}' }}\nrequirements: {req}\nchecks: []\n", std::env::temp_dir().display());
    let ctx = Context::default();
    let p = Policy::parse(&yaml("{ condition: any, rules: ['d:/no/such/dir', 'd:$dirs'] }")).unwrap();
    assert!(p.applies(&ctx));
    let p = Policy::parse(&yaml("{ condition: none, rules: ['d:$dirs'] }")).unwrap();
    assert!(!p.applies(&ctx));
    assert!(Policy::parse(&yaml("{ rules: ['d:$dirs'] }")).is_err(), "rules need a condition");
}

/// Every rule string of the manifest the policies are generated from parses.
#[test]
fn manifest_rules_parse() {
    let settings: Value = serde_json::from_str(include_str!("../../../../specs/sca-manifest/settings.json")).unwrap();
    let policies: Value = serde_json::from_str(include_str!("../../../../specs/sca-manifest/policies.json")).unwrap();
    let rules = settings.as_array().unwrap().iter().chain(policies.as_array().unwrap().iter().map(|p| &p["requirements"]));
    let (mut n, mut broken) = (0, 0);
    for r in rules.flat_map(|s| s["rules"].as_array().unwrap()) {
        let rule = Rule::parse(r.as_str().unwrap()).unwrap_or_else(|e| panic!("{e}"));
        n += 1;
        if let Err(e) = &rule.targets {
            println!("not applicable: {}", e.replace('\n', " "));
            broken += 1;
        }
    }
    println!("{n} rules, {broken} with a regex that does not compile");
    assert!(n > 2500);
}

#[cfg(windows)]
#[test]
fn registry_rules() {
    let reg = |args: &[&str]| std::process::Command::new("reg").args(args).output().unwrap().status.success();
    let key = r"HKCU\Software\ProVigilTest";
    let _turn = crate::HKCU_TEST_KEY.lock().unwrap_or_else(|e| e.into_inner());
    assert!(reg(&["add", key, "/v", "Num", "/t", "REG_DWORD", "/d", "20", "/f"]));
    assert!(reg(&["add", key, "/v", "Text", "/t", "REG_SZ", "/d", "Hello World", "/f"]));
    assert!(reg(&["add", key, "/v", "Pipes", "/t", "REG_MULTI_SZ", "/d", r"netlogon\0samr", "/f"]));
    assert!(reg(&["add", key, "/v", "Big", "/t", "REG_QWORD", "/d", "20", "/f"]));
    let ctx = Context::default();
    let r = |rule: &str| holds(&rule.replace("KEY", key), &ctx);
    assert_eq!(r("r:KEY"), Ok(true));
    assert_eq!(r("r:KEY\\Missing"), Ok(false));
    assert_eq!(r("r:KEY -> Num"), Ok(true));
    assert_eq!(r("r:KEY -> Num -> 20"), Ok(true));
    assert_eq!(r("r:KEY -> Num -> 0x14"), Ok(true));
    assert_eq!(r("r:KEY -> Num -> 2"), Ok(false));
    assert_eq!(r(r"r:KEY -> Num -> n:^(\d+) compare >= 14"), Ok(true));
    assert_eq!(r(r"r:KEY -> Num -> n:^(\d+) compare < 14"), Ok(false));
    assert_eq!(r("r:KEY -> Text -> r:^hello"), Ok(true));
    assert_eq!(r("not r:KEY -> Absent"), Ok(true));
    assert_eq!(r("not r:KEY -> Num"), Ok(false));
    assert_eq!(r("r:KEY -> Pipes -> r:^netlogon samr $"), Ok(true), "REG_MULTI_SZ: each string followed by a space");
    assert_eq!(r("r:KEY -> Pipes -> r:^netlogon samr$"), Ok(false));
    assert_eq!(r("r:KEY -> Pipes -> netlogon samr"), Ok(true));
    assert_eq!(r("r:KEY -> Pipes -> r:^samr"), Ok(false), "one line, not one per string");
    assert_eq!(r("r:KEY -> Big -> r:^1400000000000000$"), Ok(true), "REG_QWORD as its bytes in hex");
    assert_eq!(holds(r"r:HKEY_CURRENT_USER\Software\ProVigilTest -> Num -> 20", &ctx), Ok(true));
    assert_eq!(holds(r"r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion -> ProductName -> r:^Windows", &ctx), Ok(true));
    assert_eq!(holds(r"r:HKCR\.txt", &ctx), Ok(true));
    assert_eq!(holds(r"r:HKU\.DEFAULT", &ctx), Ok(true));
    assert!(holds("r:HKXX\\Nothing", &ctx).is_err(), "an unreadable rule is an error, not false");
    assert!(reg(&["delete", key, "/f"]));
}

/// A key only in the 32-bit view (`WOW6432Node`) is found by its 64-bit path.
#[cfg(windows)]
#[test]
fn registry_32_bit_view() {
    let reg = |args: &[&str]| std::process::Command::new("reg").args(args).output().unwrap().status.success();
    let key = r"HKCU\Software\Classes\CLSID\{6d1f0c1e-5a3b-4c7e-9f21-0b7e3a1c9d42}";
    assert!(reg(&["add", key, "/v", "V", "/t", "REG_DWORD", "/d", "7", "/f", "/reg:32"]));
    let ctx = Context::default();
    let found = (holds(&format!("r:{key} -> V -> 7"), &ctx), holds(&format!("r:{key} -> W"), &ctx));
    assert!(reg(&["delete", key, "/f", "/reg:32"]));
    assert_eq!(found, (Ok(true), Ok(false)));
}

#[test]
fn file_rules() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("app.ini");
    std::fs::write(&f, "[main]\nallow_root=false\nport=8080\n").unwrap();
    let ctx = Context::default();
    let p = f.display().to_string();
    assert_eq!(holds(&format!("f:{p}"), &ctx), Ok(true));
    assert_eq!(holds(&format!("f:{p} -> r:^port=8080$"), &ctx), Ok(true));
    assert_eq!(holds(&format!("f:{p} -> r:^allow_root=true"), &ctx), Ok(false));
    assert_eq!(holds(&format!("f:{p}.missing"), &ctx), Ok(false));
    assert_eq!(holds(&format!("f:{p}.missing -> r:x"), &ctx), Ok(false));
    assert_eq!(holds(&format!("not f:{p}.missing"), &ctx), Ok(true));
}

#[test]
fn process_rule_finds_this_process() {
    let exe = std::env::current_exe().unwrap();
    let me = regex::escape(&exe.file_name().unwrap().to_string_lossy());
    let ctx = Context::default();
    assert_eq!(holds(&format!("p:r:^{me}$"), &ctx), Ok(true));
    assert_eq!(holds("p:r:^no-such-process-provigil$", &ctx), Ok(false));
    assert_eq!(holds("not p:r:^no-such-process-provigil$", &ctx), Ok(true));
}

#[test]
fn secedit_and_auditpol() {
    let utf16: Vec<u8> = [0xFF, 0xFE].into_iter().chain(SECEDIT_INI.encode_utf16().flat_map(u16::to_le_bytes)).collect();
    assert_eq!(decode(&utf16), SECEDIT_INI);
    let ctx = ctx_with(Ok(parse_secedit(&decode(&utf16))), Ok(parse_auditpol(AUDITPOL_CSV)));
    assert_eq!(holds(r"c:secedit-value:MinimumPasswordLength -> n:^(\d+) compare >= 14", &ctx), Ok(true));
    assert_eq!(holds("c:secedit-value:PasswordComplexity -> 1", &ctx), Ok(true));
    assert_eq!(holds(r"c:secedit-value:SeDebugPrivilege -> r:^\*S-1-5-32-544$", &ctx), Ok(true));
    assert_eq!(holds(r"not c:secedit-value:SeNetworkLogonRight -> r:\*S-1-1-0(,|$)", &ctx), Ok(false));
    assert_eq!(holds("not c:secedit-value:SeTcbPrivilege", &ctx), Ok(true), "a right given to no one is absent");
    assert_eq!(holds(r#"not c:secedit-value:NewAdministratorName -> r:^("Administrator"|Administrator)$"#, &ctx), Ok(false));
    assert_eq!(holds("c:auditpol:Logon -> r:^Success and Failure$", &ctx), Ok(true));
    assert_eq!(holds("c:auditpol:Logoff -> r:Success", &ctx), Ok(true));
    assert_eq!(holds("c:auditpol:Logoff -> r:Failure", &ctx), Ok(false));
    assert_eq!(holds("c:auditpol:Process Creation -> r:Success", &ctx), Ok(false));
    assert_eq!(holds("c:auditpol:{0cce922b-69ae-11d9-bed3-505054503030} -> No Auditing", &ctx), Ok(true));

    let down = ctx_with(Err("secedit ended with code 740".into()), Err("auditpol ended with code 1314".into()));
    assert_eq!(holds("c:secedit-value:PasswordComplexity -> 1", &down), Err("secedit ended with code 740".into()));
    assert!(holds("not c:auditpol:Logon", &down).is_err(), "not keeps the error");
}

#[test]
fn conditions_and_not_applicable() {
    let (t, f, e) = (Ok(true), Ok(false), Err::<bool, String>("denied".into()));
    use Condition::*;
    assert_eq!(combine(All, [t.clone(), t.clone()]), Ok(true));
    assert_eq!(combine(All, [t.clone(), f.clone()]), Ok(false));
    assert_eq!(combine(All, [e.clone(), f.clone()]), Ok(false), "a failing rule decides");
    assert_eq!(combine(All, [t.clone(), e.clone()]), Err("denied".into()));
    assert_eq!(combine(Any, [f.clone(), t.clone()]), Ok(true));
    assert_eq!(combine(Any, [f.clone(), f.clone()]), Ok(false));
    assert_eq!(combine(Any, [e.clone(), t.clone()]), Ok(true));
    assert_eq!(combine(Any, [f.clone(), e.clone()]), Err("denied".into()));
    assert_eq!(combine(None, [f.clone(), f.clone()]), Ok(true));
    assert_eq!(combine(None, [f.clone(), t.clone()]), Ok(false));
    assert_eq!(combine(None, [e.clone(), f.clone()]), Err("denied".into()));

    let p = Policy::parse(SAMPLE).unwrap();
    let ctx = ctx_with(Err("secedit ended with code 740".into()), Ok(parse_auditpol(AUDITPOL_CSV)));
    let outcomes: Vec<Outcome> = p.checks.iter().map(|c| c.evaluate(&ctx)).collect();
    assert_eq!(outcomes[0], Outcome::NotApplicable("secedit ended with code 740".into()));
    assert_eq!(outcomes[1], Outcome::Passed);
    assert_eq!(outcomes[2], Outcome::Failed);
}

#[test]
fn hash_of_results_in_id_order() {
    let (p, f, n) = (Outcome::Passed, Outcome::Failed, Outcome::NotApplicable("x".into()));
    // ids given 3,1,2,4: in id order failed, not applicable, passed, passed
    let h = results_hash(&[(3, &p), (1, &f), (2, &n), (4, &p)]);
    assert_eq!(h, "d5688cc581085f3dfe251149c9dd1780c15733cd6e4da1392ce100eae9728ad5"); // SHA-256 of "failed::passed:passed"
}

const SAMPLE: &str = r#"
policy:
  id: test_policy
  name: "Test policy"
  description: "For the tests"
  references: ["https://a.example", "https://b.example"]
checks:
  - id: 3
    title: "Logon is audited"
    rationale: "Logons show who used the system."
    remediation: "Audit logon success and failure."
    compliance: { nist_800_53: ["AU-2", "AU-12"], pci_dss: ["10.2.1"] }
    condition: any
    rules: ['c:auditpol:Logon -> r:^Success and Failure$', 'f:%WINDIR%\notepad.exe', 'r:HKLM\SOFTWARE\A']
  - id: 1
    title: "Long passwords"
    remediation: "Set the minimum length to 14."
    condition: all
    rules: ['c:secedit-value:MinimumPasswordLength -> n:^(\d+) compare >= 14']
  - id: 7
    title: "Process creation audited"
    description: "Process creation events are written."
    remediation: "Audit process creation."
    condition: any
    rules: ['c:auditpol:Process Creation -> r:Success']
"#;

#[test]
fn message_json() {
    let p = Policy::parse(SAMPLE).unwrap();
    assert_eq!(p.checks.iter().map(|c| c.def.id).collect::<Vec<_>>(), [1, 3, 7], "checks in id order");
    let na = Outcome::NotApplicable("secedit ended with code 740".into());
    let m = check_message(42, &p, &p.checks[1], &Outcome::Passed);
    assert_eq!(m["type"], "check");
    assert_eq!(m["id"], 42);
    assert_eq!(m["policy"], "Test policy");
    assert_eq!(m["policy_id"], "test_policy");
    let c = &m["check"];
    assert_eq!(c["id"], 3);
    assert_eq!(c["title"], "Logon is audited");
    assert_eq!(c["rationale"], "Logons show who used the system.");
    assert_eq!(c["remediation"], "Audit logon success and failure.");
    assert_eq!(c["compliance"], json!({ "nist_800_53": "AU-2,AU-12", "pci_dss": "10.2.1" }));
    assert_eq!(c["rules"][0], "c:auditpol:Logon -> r:^Success and Failure$");
    assert_eq!(c["condition"], "any");
    assert_eq!(c["result"], "passed");
    assert_eq!(c["registry"], r"HKLM\SOFTWARE\A");
    assert_eq!(c["file"], r"%WINDIR%\notepad.exe");
    let keys: Vec<&String> = c.as_object().unwrap().keys().collect();
    for absent in ["description", "reason", "references"] {
        assert!(!keys.iter().any(|k| *k == absent), "{absent} omitted when empty");
    }
    let m = check_message(42, &p, &p.checks[0], &na);
    assert_eq!(m["check"]["result"], "not applicable");
    assert_eq!(m["check"]["reason"], "secedit ended with code 740");
    assert!(m["check"].get("registry").is_none() && m["check"].get("file").is_none() && m["check"].get("rationale").is_none());
    assert_eq!(check_message(1, &p, &p.checks[2], &Outcome::Failed)["check"]["description"], "Process creation events are written.");

    let results = [(1, &na), (3, &Outcome::Passed), (7, &Outcome::Failed)];
    let s = summary_message(42, &p, &results, (100, 105), true);
    assert_eq!(s["type"], "summary");
    assert_eq!(s["scan_id"], 42);
    assert_eq!(s["name"], "Test policy");
    assert_eq!(s["policy_id"], "test_policy");
    assert_eq!(s["file"], "test_policy.yml");
    assert_eq!(s["description"], "For the tests");
    assert_eq!(s["references"], "https://a.example,https://b.example");
    assert_eq!((s["start_time"].as_i64(), s["end_time"].as_i64()), (Some(100), Some(105)));
    assert_eq!((s["passed"].as_u64(), s["failed"].as_u64(), s["invalid"].as_u64(), s["total_checks"].as_u64()), (Some(1), Some(1), Some(1), Some(3)));
    assert_eq!(s["score"], 50);
    assert_eq!(s["hash"], results_hash(&results));
    assert_eq!(s["hash_file"].as_str().unwrap(), format!("{:x}", Sha256::digest(SAMPLE.as_bytes())));
    assert_eq!(s["first_scan"], 1);
    let again = summary_message(43, &p, &[(1, &na)], (0, 0), false);
    assert!(again.get("first_scan").is_none());
    assert_eq!(again["score"], 0, "no passed or failed: score 0");

    // the event around a message
    let e = event(("058", "pc"), &m);
    assert_eq!((e["event_type"].as_str(), e["location"].as_str(), e["agent"]["id"].as_str()), (Some("sca"), Some("sca"), Some("058")));
    assert_eq!(serde_json::from_str::<Value>(e["message"].as_str().unwrap()).unwrap(), m);
    assert!(e["timestamp"].is_string());
}

#[test]
fn scan_sends_checks_then_summary() {
    let p = Policy::parse(SAMPLE).unwrap();
    let ctx = ctx_with(Err("no".into()), Ok(parse_auditpol(AUDITPOL_CSV)));
    let ev = scan_policy(&p, &ctx, ("058", "pc"), false);
    let msgs: Vec<Value> = ev.iter().map(|e| serde_json::from_str(e["message"].as_str().unwrap()).unwrap()).collect();
    assert_eq!(msgs.iter().map(|m| m["type"].as_str().unwrap()).collect::<Vec<_>>(), ["check", "check", "check", "summary"]);
    assert_eq!(msgs.iter().take(3).map(|m| m["check"]["id"].as_u64().unwrap()).collect::<Vec<_>>(), [1, 3, 7]);
    let id = msgs[0]["id"].as_u64().unwrap();
    assert!(id > 0 && id <= 0x7FFF_FFFF && msgs.iter().take(3).all(|m| m["id"] == id) && msgs[3]["scan_id"] == id);
}

#[test]
fn scan_ends_with_the_policies_scanned() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("own.yaml"), SAMPLE).unwrap();
    let builtin: Vec<String> = BUILTIN.iter().map(|t| Policy::parse(t).unwrap().info.id).collect();
    let mut s = ScaScanner::load(dir.path()).without(&builtin);
    let ev = s.scan("058", "pc");
    assert_eq!(ev.len(), 3 + 1 + 1, "checks, summary, policies");
    let last: Value = serde_json::from_str(ev.last().unwrap()["message"].as_str().unwrap()).unwrap();
    assert_eq!(last, json!({ "type": "policies", "policies": ["test_policy"] }));
    assert_eq!(ev.last().unwrap()["event_type"], "sca");
}

/// The message types of a scan's events, with the id of each check.
fn sent(ev: &[Value]) -> Vec<String> {
    let msgs = ev.iter().map(|e| serde_json::from_str::<Value>(e["message"].as_str().unwrap()).unwrap());
    msgs.map(|m| if m["type"] == "check" { format!("check {} {}", m["check"]["id"], m["check"]["result"].as_str().unwrap()) } else { m["type"].as_str().unwrap().to_string() }).collect()
}

fn message(ev: &[Value], kind: &str) -> Value {
    ev.iter().map(|e| serde_json::from_str::<Value>(e["message"].as_str().unwrap()).unwrap()).find(|m| m["type"] == kind).unwrap()
}

/// A folder with a policy of three checks on three files, and the scanner of that policy.
struct Fixture {
    dir: tempfile::TempDir,
    files: [std::path::PathBuf; 3],
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let files = ["a", "b", "c"].map(|n| dir.path().join(n));
        files.iter().for_each(|f| std::fs::write(f, "x").unwrap());
        let me = Fixture { dir, files };
        me.policy("Delta test");
        me
    }

    fn policy(&self, name: &str) {
        let check = |id: usize| format!("  - id: {}\n    title: Check {id}\n    condition: all\n    rules:\n      - 'f:{}'\n", id + 1, self.files[id].display());
        let text = format!("policy:\n  id: delta_test\n  name: {name}\nchecks:\n{}{}{}", check(0), check(1), check(2));
        std::fs::write(self.dir.path().join("delta.yml"), text).unwrap();
    }

    fn scanner(&self) -> ScaScanner {
        let builtin: Vec<String> = BUILTIN.iter().map(|t| Policy::parse(t).unwrap().info.id).collect();
        ScaScanner::load(self.dir.path()).without(&builtin).with_state(self.dir.path().join("sent.db"), Some(0))
    }
}

#[test]
fn after_the_first_scan_only_what_changed() {
    let f = Fixture::new();
    let mut s = f.scanner();
    let all = ["check 1 passed", "check 2 passed", "check 3 passed", "summary", "policies"];
    let first = s.scan("058", "pc");
    assert_eq!(sent(&first), all, "nothing saved: every check");

    let second = s.scan("058", "pc");
    assert_eq!(sent(&second), ["summary", "policies"], "unchanged: the summary only");
    assert_eq!(message(&second, "summary")["hash"], message(&first, "summary")["hash"]);
    assert_eq!((message(&second, "summary")["total_checks"].as_u64(), message(&second, "summary")["passed"].as_u64()), (Some(3), Some(3)));

    std::fs::remove_file(&f.files[1]).unwrap();
    let third = s.scan("058", "pc");
    assert_eq!(sent(&third), ["check 2 failed", "summary", "policies"], "exactly the one that changed");
    let (one, two) = (Outcome::Passed, Outcome::Failed);
    assert_eq!(message(&third, "summary")["hash"].as_str().unwrap(), results_hash(&[(1, &one), (2, &two), (3, &one)]), "the hash of all results");
    assert_eq!(message(&third, "summary")["failed"], 1);

    // a restart keeps what was sent; only `first_scan` is new
    let restarted = f.scanner().scan("058", "pc");
    assert_eq!(sent(&restarted), ["summary", "policies"]);
    assert_eq!(message(&restarted, "summary")["first_scan"], 1);
}

#[test]
fn a_full_send_for_a_new_id_a_new_policy_text_and_the_manager() {
    let f = Fixture::new();
    let mut s = f.scanner();
    let all = ["check 1 passed", "check 2 passed", "check 3 passed", "summary"];
    let with = |tail: &[&str]| all.iter().chain(tail).map(|t| t.to_string()).collect::<Vec<_>>();
    s.scan("058", "pc");

    assert_eq!(sent(&s.scan("059", "pc")), with(&["policies"]), "another agent id");
    assert_eq!(sent(&s.scan("058", "pc")).len(), 2, "each id's own results");

    s.ask_full(["delta_test".to_string(), "other".to_string()]);
    let asked = s.scan("058", "pc");
    assert_eq!(sent(&asked), with(&["dump_end", "policies"]), "the manager asks: every check, and its old rows go");
    let end = message(&asked, "dump_end");
    assert_eq!((end["elements_sent"].as_u64(), end["policy_id"].as_str()), (Some(3), Some("delta_test")));
    assert_eq!(end["scan_id"], message(&asked, "summary")["scan_id"]);
    assert_eq!(sent(&s.scan("058", "pc")).len(), 2, "once");

    f.policy("Delta test, new text");
    assert_eq!(sent(&f.scanner().scan("058", "pc")), with(&["policies"]), "the policy text changed");
}

#[test]
fn only_a_full_send_waits_its_splay() {
    let f = Fixture::new();
    f.scanner().scan("058", "pc");
    let builtin: Vec<String> = BUILTIN.iter().map(|t| Policy::parse(t).unwrap().info.id).collect();
    let mut wide = ScaScanner::load(f.dir.path()).without(&builtin).with_state(f.dir.path().join("sent.db"), Some(86_400));
    let t = std::time::Instant::now();
    assert_eq!(sent(&wide.scan("058", "pc")), ["summary", "policies"], "no change: sent at once");
    assert!(t.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn without_a_state_file_every_scan_sends_all() {
    let f = Fixture::new();
    let mut plain = ScaScanner::load(f.dir.path()).without(&BUILTIN.iter().map(|t| Policy::parse(t).unwrap().info.id).collect::<Vec<_>>());
    plain.scan("058", "pc");
    assert_eq!(sent(&plain.scan("058", "pc")).len(), 5, "no file to keep it in");
}

#[test]
fn builtin_policies() {
    let mut ids = HashSet::new();
    let mut counts = Vec::new();
    for text in BUILTIN {
        let p = Policy::parse(text).unwrap_or_else(|e| panic!("built-in policy does not parse: {e}"));
        assert!(!p.info.description.is_empty() && !p.requirements.is_empty());
        for c in &p.checks {
            assert!((60000..80000).contains(&c.def.id), "{} outside the built-in range", c.def.id);
            assert!(ids.insert(c.def.id), "check id {} used twice", c.def.id);
            assert!(!c.def.title.is_empty() && !c.def.remediation.is_empty() && !c.def.rationale.is_empty(), "check {}", c.def.id);
            assert!(!c.rules.is_empty() && !c.def.compliance.is_empty(), "check {}", c.def.id);
        }
        counts.push((p.info.id.clone(), p.checks.len()));
    }
    // same policies, check counts and rules as the manifest of the old agent's policies
    let manifest: Value = serde_json::from_str(include_str!("../../../../specs/sca-manifest/policies.json")).unwrap();
    let want: Vec<(String, usize)> = manifest.as_array().unwrap().iter().map(|p| (p["policy"].as_str().unwrap().to_string(), p["checks"].as_array().unwrap().len())).collect();
    assert_eq!(counts, want);
    // an extra policy reusing a built-in id is skipped
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dup.yml"), BUILTIN[1]).unwrap();
    std::fs::write(dir.path().join("own.yaml"), SAMPLE).unwrap();
    let s = ScaScanner::load(dir.path());
    let loaded: Vec<&str> = s.policies().iter().map(|p| p.info.id.as_str()).collect();
    assert_eq!(loaded.len(), BUILTIN.len() + 1);
    assert_eq!(loaded.last(), Some(&"test_policy"));
}

/// `cargo test -p provigil-agent live_sca -- --ignored --nocapture`
#[cfg(windows)]
#[test]
#[ignore]
fn live_sca() {
    let t = std::time::Instant::now();
    let ctx = Context::default();
    // exactly one Windows version policy applies to this PC
    let windows: Vec<Policy> = BUILTIN.iter().map(|t| Policy::parse(t).unwrap()).filter(|p| p.info.id.starts_with("provigil_win") && p.applies(&ctx)).collect();
    assert_eq!(windows.len(), 1, "{:?}", windows.iter().map(|p| &p.info.id).collect::<Vec<_>>());
    let p = &windows[0];
    println!("policy {}", p.info.id);
    let ev = scan_policy(p, &ctx, ("001", "test"), true);
    let took = t.elapsed();
    assert_eq!(ev.len(), p.checks.len() + 1);
    let s: Value = serde_json::from_str(ev.last().unwrap()["message"].as_str().unwrap()).unwrap();
    println!(
        "checks {} passed {} failed {} not applicable {} score {} in {:.1} s",
        s["total_checks"], s["passed"], s["failed"], s["invalid"], s["score"], took.as_secs_f64()
    );
    for e in &ev[..ev.len() - 1] {
        let m: Value = serde_json::from_str(e["message"].as_str().unwrap()).unwrap();
        if m["check"]["result"] == "not applicable" {
            println!("  n/a {} {}: {}", m["check"]["id"], m["check"]["title"], m["check"]["reason"]);
        }
    }
    assert!(took.as_secs() < 60);
}

/// Every rule of the Windows policies in the manifest, once, on this PC:
/// `cargo test -p provigil-agent live_manifest_rules -- --ignored --nocapture`
#[cfg(windows)]
#[test]
#[ignore]
fn live_manifest_rules() {
    let settings: Value = serde_json::from_str(include_str!("../../../../specs/sca-manifest/settings.json")).unwrap();
    let policies: Value = serde_json::from_str(include_str!("../../../../specs/sca-manifest/policies.json")).unwrap();
    let windows = |p: &str| ["provigil_win", "provigil_iis", "provigil_sqlserver"].iter().any(|w| p.starts_with(w));
    let vars: HashMap<&str, Vec<(String, Option<String>)>> = policies
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let mut v: Vec<_> = p["variables"].as_object().into_iter().flatten().map(|(n, x)| (n.clone(), x.as_str().map(String::from))).collect();
            v.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
            (p["policy"].as_str().unwrap(), v)
        })
        .collect();
    let t = std::time::Instant::now();
    let ctx = Context::default();
    let (mut yes, mut no, mut reasons) = (0, 0, BTreeMap::<String, (usize, String)>::new());
    for s in settings.as_array().unwrap() {
        let Some(policy) = s["used_by"].as_array().unwrap().iter().filter_map(Value::as_str).find(|p| windows(p)) else { continue };
        for r in s["rules"].as_array().unwrap() {
            match Rule::parse_with(r.as_str().unwrap(), &vars[policy]).unwrap().eval(&ctx) {
                Ok(true) => yes += 1,
                Ok(false) => no += 1,
                Err(e) => {
                    // group by the last line's cause, without the key / command it names
                    let cause = e.lines().last().unwrap_or_default().rsplit(": ").next().unwrap_or_default().to_string();
                    let g = reasons.entry(cause).or_insert((0, e.clone()));
                    g.0 += 1;
                }
            }
        }
    }
    let took = t.elapsed();
    println!("true {yes} false {no} cannot evaluate {} in {:.1} s", reasons.values().map(|g| g.0).sum::<usize>(), took.as_secs_f64());
    for (cause, (n, example)) in &reasons {
        println!("  {n:4} {cause}\n         e.g. {}", example.replace('\n', " ").chars().take(200).collect::<String>());
    }
    assert!(took.as_secs() < 120);
}
