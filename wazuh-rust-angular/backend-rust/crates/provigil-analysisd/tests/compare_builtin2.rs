//! The integrity and Windows event decoders and the built-in entries, old against new:
//! generated checksum messages, JSON integrity events and event channel XML through both,
//! with provigil-db answers from a script; events, entries, queries and logs identical.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use provigil_analysisd::builtin::{integrity as ni, windows as nw, Builtin};
use provigil_analysisd::config::Config;
use provigil_analysisd::decoders::{Decoder, DecoderSet};
use provigil_analysisd::event::{Event as NewEvent, Instant};
use provigil_analysisd::host::Host;
use provigil_analysisd::messages::Messages;
use provigil_analysisd::responses::{AgentVersion as NV, ResponseSink};
use siem_analysisd::ar::{AgentVersion as OV, ArBackend};
use siem_analysisd::daemon::Env;
use siem_analysisd::decoders::{DecoderInfo, Decoders};
use siem_analysisd::event::{Event as OldEvent, TimeSpec};
use siem_analysisd::internal::{syscheck as os, winevt as ow, InternalDecoders};
use siem_analysisd::logmsg::LogList;

struct Fake {
    seen: RefCell<Vec<String>>,
    salt: u64,
}

impl Fake {
    fn note(&self, s: String) {
        self.seen.borrow_mut().push(s);
    }
    /// Answers by query kind; the stored checksums vary with the salt.
    fn answer(&self, q: &[u8]) -> Result<Vec<u8>, i32> {
        let s = String::from_utf8_lossy(q);
        let h = q.iter().fold(self.salt, |h, &b| h.wrapping_mul(31).wrapping_add(u64::from(b)));
        let pick = |v: &[&str]| v[(h % v.len() as u64) as usize].as_bytes().to_vec();
        let a = if s.contains("syscheck load ") {
            Ok(pick(&[
                "ok 107:33188:0:0:abc:def:root:root:1600000000:123:sha:32!0:1699999000",
                "ok 107:33188:0:0:abc:def:root:root:1600000000:123:sha:32!3:1699999990:/sym",
                "ok 200:33261:1:1:abd:deg:bob:staff:1600000500:124:shb:2!1:1600000000",
                "ok 107:|SYSTEM,0,1|:0:0:abc:def",
                "ok ",
                "ok",
                "err x",
                "ok 107:33188:0:0:abc:def:root:root:1600000000:123",
                "bad",
            ]))
        } else if s.contains("scan_info_get") {
            Ok(pick(&["ok 1700000000", "ok 0", "ok 1800000000", "ok", "err"]))
        } else {
            match h % 9 {
                0 => Err(-2),
                1 => Err(-1),
                2 => Ok(b"err Agent not found".to_vec()),
                3 => Ok(b"err bad".to_vec()),
                _ => Ok(b"ok".to_vec()),
            }
        };
        self.note(format!("db {s} -> {:?}", a.as_ref().map(|v| String::from_utf8_lossy(v).into_owned())));
        a
    }
}

impl ArBackend for Fake {
    fn agent_version(&mut self, _: i32) -> OV {
        OV::NoInfo
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        None
    }
    fn node_name(&mut self) -> String {
        "n".into()
    }
    fn send_exec(&mut self, _: &[u8]) {}
    fn send_ar(&mut self, _: &[u8]) {}
}
impl ResponseSink for Fake {
    fn agent_version(&mut self, _: i32) -> NV {
        NV::NoInfo
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        None
    }
    fn node_name(&mut self) -> String {
        "n".into()
    }
    fn send_exec(&mut self, _: &[u8]) {}
    fn send_ar(&mut self, _: &[u8]) {}
}
impl Env for Fake {
    fn labels(&mut self, _: &[u8]) -> Vec<siem_analysisd::labels::Label> {
        Vec::new()
    }
    fn log(&self, level: &str, msg: &[u8]) {
        self.note(format!("{level} {}", String::from_utf8_lossy(msg)));
    }
    fn ar(&mut self) -> &mut dyn ArBackend {
        self
    }
    fn agents_of_node(&mut self, _: i32, _: i32) -> Option<Vec<i32>> {
        None
    }
    fn wdb_query_ex(&mut self, q: &[u8], _: usize) -> Result<Vec<u8>, i32> {
        self.answer(q)
    }
}
impl Host for Fake {
    fn labels(&mut self, _: &[u8]) -> Vec<provigil_analysisd::event::Label> {
        Vec::new()
    }
    fn log(&self, level: &str, msg: &[u8]) {
        self.note(format!("{level} {}", String::from_utf8_lossy(msg)));
    }
    fn responses(&mut self) -> &mut dyn ResponseSink {
        self
    }
    fn agents_of_node(&mut self, _: i32, _: i32) -> Option<Vec<i32>> {
        None
    }
    fn db_query(&mut self, q: &[u8], _: usize) -> Result<Vec<u8>, i32> {
        self.answer(q)
    }
}

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
    fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        v[self.below(v.len())]
    }
}

fn manager() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager")
}

fn sums(r: &mut Rng) -> String {
    let sum = r.pick(&[
        "107:33188:0:0:abc:def:root:root:1600000000:123:sha:32",
        "107:33188:0:0:abc:def:root:root:1600000000:123:sha:ARCHIVE",
        "200:33261:1:1:abd:deg:bob:staff:1600000500:124:shb:2",
        "107:|SYSTEM,0,1|Users,1,2147483648:0:0:abc:def",
        "107:|a\\:b,0,4:0:0:abc:def:x:y:1:2",
        "-1",
        "107:33188",
        "1:2:3:4:5:6",
        "x",
        "107:33188:0:0:abc:def:ro\\ot:root:1600000000:123",
    ]);
    let who = r.pick(&["", "!0:root:0:root:/bin/x:0:root:0:root:1:2:tag:/sym\\:x:+", "!0:root:0:root:/bin/x:0:root:0:root:-1:2", "!a:b", "!1:2:3:4:5:6:7:8:9:10:11:t1,t2:/s"]);
    format!("{sum}{who}")
}

fn integrity_json(r: &mut Rng) -> String {
    let attrs = |r: &mut Rng| {
        format!(
            "{{\"type\":{},\"size\":{},\"perm\":{},\"uid\":\"0\",\"gid\":\"0\",\"user_name\":\"root\",\"hash_md5\":{},\"hash_sha256\":\"s\",\"mtime\":{},\"inode\":{},\"attributes\":\"ARCHIVE\",\"symlink_path\":\"/l\",\"value_type\":\"REG_SZ\"}}",
            r.pick(&["\"file\"", "\"registry\"", "\"registry_key\"", "\"registry_value\"", "\"other\"", "1"]),
            r.pick(&["10", "20", "1e30"]),
            r.pick(&["\"rw-r--r--\"", "{\"S-1\":{\"name\":\"SYSTEM\",\"allowed\":[\"read\",\"write\"],\"denied\":[\"delete\"]},\"U\":{\"allowed\":[]}}", "[\"x\"]"]),
            r.pick(&["\"m1\"", "\"m2\""]),
            r.pick(&["1600000000", "1600000100"]),
            r.pick(&["5", "\"6\""])
        )
    };
    let path = if r.below(10) == 0 { "x".repeat(800) } else { r.pick(&["/etc/passwd", "HKEY_LOCAL_MACHINE\\Soft", "C:\\a"]).to_string() };
    let data = format!(
        "{{\"path\":\"{path}\",\"mode\":{},\"type\":{},\"tags\":\"t\",\"content_changes\":\"diff\",\"arch\":\"[x64]\",{}\"index\":\"h\",\"changed_attributes\":[\"size\",\"mtime\",1],\"hard_links\":[\"/a\",\"/b\"],\"version\":{},\"attributes\":{},\"old_attributes\":{},\"audit\":{{\"user_id\":\"0\",\"ppid\":12,\"process_id\":1e30,\"cwd\":\"/\"}}}}",
        r.pick(&["\"realtime\"", "\"whodata\""]),
        r.pick(&["\"added\"", "\"modified\"", "\"deleted\"", "\"other\""]),
        r.pick(&["\"value_name\":\"v\",", ""]),
        r.pick(&["2", "3"]),
        attrs(r),
        attrs(r)
    );
    let data = data.replace(if r.below(4) == 0 { "\"index\":\"h\"," } else { "\u{0}" }, "");
    match r.below(12) {
        0 => "{\"type\":\"scan_start\",\"data\":{\"timestamp\":1700000000}}".into(),
        1 => "{\"type\":\"scan_end\",\"data\":{\"timestamp\":1.5e40}}".into(),
        2 => "{bad".into(),
        3 => "{\"type\":\"event\"}".into(),
        4 => "{\"type\":\"event\",\"data\":[1]}".into(),
        _ => format!("{{\"type\":\"event\",\"data\":{data}}}"),
    }
}

fn windows_event(r: &mut Rng) -> String {
    let mut system = String::new();
    for _ in 0..r.below(8) {
        system.push_str(r.pick(&[
            "<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{5478}' EventSourceName='x'/>",
            "<EventID>4625</EventID>",
            "<Level>0</Level>",
            "<Level>2</Level>",
            "<Keywords>0x8010000000000000</Keywords>",
            "<Keywords>0x8020000000000000</Keywords>",
            "<TimeCreated SystemTime='2026-01-01T00:00:00Z'/>",
            "<Execution ProcessID='4' ThreadID='8'/>",
            "<Channel>Security</Channel>",
            "<Channel UserID='S-1'>System</Channel>",
            "<Security UserID='S-1-5-18'/>",
            "<Correlation ActivityID='{a}'/>",
            "<Computer>host</Computer>",
            "<Task></Task>",
        ]));
    }
    let mut data = String::new();
    for _ in 0..r.below(8) {
        data.push_str(r.pick(&[
            "<Data Name='TargetUserName'>bob</Data>",
            "<Data Name='SubjectUserName'>-</Data>",
            "<Data Name='CategoryId'>%%8273</Data>",
            "<Data Name='SubcategoryId'>%%12544</Data>",
            "<Data Name='AuditPolicyChanges'>%%8448, %%8451,%%9</Data>",
            "<Data Name='x'>(NULL)</Data>",
            "<Data>plain one  </Data>",
            "<Data>two</Data>",
            "<Data Other='a' Name='y'>val</Data>",
            "<Binary>00FF</Binary>",
            "<Data Name='z'>  </Data>",
        ]));
    }
    let extra = r.pick(&["", "<UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName><X>-</X></LogFileCleared></UserData>", "<RenderingInfo Culture='en'><Message>m</Message></RenderingInfo>"]);
    let xml = format!("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>{system}</System><EventData>{data}</EventData>{extra}</Event>");
    let xml = if r.below(15) == 0 { "<Event><System>".to_string() } else { xml };
    let message = r.pick(&["\"An account failed to log on.\\r\\n\\tSubject:  \"", "\"\"", "1", ""]);
    let json_xml = provigil_json::Json::string(xml).print_unformatted();
    let json_xml = String::from_utf8(json_xml).unwrap();
    match r.below(15) {
        0 => "{bad".into(),
        1 => "{\"Message\":\"x\"}".into(),
        _ if message.is_empty() => format!("{{\"Event\":{json_xml}}}"),
        _ => format!("{{\"Message\":{message},\"Event\":{json_xml}}}"),
    }
}

fn events(msg: &str) -> (OldEvent, NewEvent) {
    let mut o = OldEvent::new(0);
    let mut n = NewEvent::new(0);
    o.clean_msg(msg.as_bytes(), b"m", TimeSpec { sec: 1_700_000_100, nsec: 0 }).unwrap();
    n.clean(msg.as_bytes(), b"m", Instant { sec: 1_700_000_100, nsec: 0 }).unwrap();
    (o, n)
}

#[test]
fn integrity_and_windows() {
    let home = manager();
    let cfg = Config::load(&home, &home.join("etc/ossec.conf"), false).unwrap();
    let (mut od, mut nd) = (Decoders::default(), DecoderSet::default());
    let (mut ol, mut nl) = (LogList::default(), Messages::default());
    for f in &cfg.ruleset.decoders {
        od.read_decode_xml(f, 256, &home, &mut ol);
        nd.load_file(f, 256, &home, &mut nl);
    }
    od.set_decode_xml(&mut ol);
    nd.finish(&mut nl);
    let oi = InternalDecoders::init(&mut od, 256);
    let ni_ = Builtin::add(&mut nd, 256);
    assert_eq!(
        format!("{} {} {} {} {} {} {} {} {} {:?} {:?} {:?}", oi.rootcheck, oi.hostinfo, oi.hostinfo_new_id, oi.hostinfo_mod_id, oi.ciscat, oi.winevt, oi.sca, oi.syscollector, oi.fim, oi.fim_ids.add, oi.fim_ids.modify, oi.fim_ids.delete),
        format!("{} {} {} {} {} {} {} {} {} {:?} {:?} {:?}", ni_.rootcheck, ni_.hostinfo, ni_.hostinfo_new, ni_.hostinfo_changed, ni_.ciscat, ni_.windows, ni_.assessment, ni_.inventory, ni_.integrity, ni_.integrity_ids.added, ni_.integrity_ids.changed, ni_.integrity_ids.deleted)
    );
    for i in oi.rootcheck..=oi.fim {
        let (a, b) = (&od.infos[i], &nd.decoders[i]);
        assert_eq!(format!("{} {} {:?} {:?} {} {}", a.id, a.type_, a.name, a.fields, a.flags, a.plugin_offset), format!("{} {} {:?} {:?} {} {}", b.id, b.kind, b.name, b.field_names, b.json_flags, b.plugin_offset));
    }

    // engines over these decoders with one integrity rule, for the alert texts
    let mut oeng = siem_analysisd::engine::Engine::new(siem_analysisd::engine::EngineConfig::default());
    let mut neng = provigil_analysisd::engine::Engine::new(provigil_analysisd::engine::EngineSettings::default());
    oeng.decoders = od.clone();
    neng.decoders = nd.clone();
    oeng.rules.infos.push(std::sync::Arc::new(siem_analysisd::rules::RuleInfo { sigid: 550, level: 7, group: Some("ossec,syscheck,pci_dss_11.5,".into()), comment: Some("Integrity checksum changed.".into()), ..Default::default() }));
    neng.rules.rules.push(std::sync::Arc::new(provigil_analysisd::rules::Rule { sigid: 550, level: 7, group: Some("ossec,syscheck,pci_dss_11.5,".into()), comment: Some("Integrity checksum changed.".into()), ..Default::default() }));
    let mut texts = 0;
    let ocfg = os::FimConfig { alert_new: true, auto_ignore: true, ignore_time: 3600, ignore_frequency: 2 };
    let ncfg = ni::Options { alert_new: true, auto_ignore: true, ignore_time: 3600, ignore_frequency: 2 };
    let (mut ofim, mut nfim) = (os::Fim::default(), ni::Integrity::default());
    let (mut owin, mut nwin) = (ow::Winevt::default(), nw::Windows::default());
    let (mut ofake, mut nfake) = (Fake { seen: RefCell::new(Vec::new()), salt: 0 }, Fake { seen: RefCell::new(Vec::new()), salt: 0 });
    let mut r = Rng(0x9E3779B97F4A7C15);
    let (mut alerts, mut json_alerts, mut windows) = (0, 0, 0);
    for round in 0..60_000u64 {
        ofake.salt = round;
        nfake.salt = round;
        let agent = ["001", "002", "003"][r.below(3)];
        let (a, b);
        match r.below(3) {
            0 => {
                let body = match r.below(8) {
                    0 => r.pick(&["fim-db-start-first-scan", "fim-db-end-first-scan", "fim-db-start-scan", "fim-db-end-scan", "syscheck-db-completed", "other"]).to_string(),
                    _ => format!("{} {}{}", sums(&mut r), r.pick(&["/etc/passwd", "C:/Windows/x", "/a b", "/x"]), r.pick(&["", "\nWhat changed: 1c1"])),
                };
                let loc = r.pick(&["syscheck", "syscheck-registry"]);
                let (mut oe, mut ne) = events(&format!("8:[{agent}] (a) any->{loc}:{body}"));
                let (mut oinfo, mut ninfo) = (DecoderInfo::default(), Decoder::default());
                let x = ofim.decode(&mut ofake, &mut oinfo, oi.fim, &oi.fim_ids, &ocfg, &mut oe);
                let y = nfim.decode(&mut nfake, &mut ninfo, ni_.integrity, &ni_.integrity_ids, &ncfg, &mut ne);
                assert_eq!(x, y, "{body}");
                alerts += usize::from(x);
                a = format!("{} {:?} {:?} {} {} {:?} {:?} {}", x, oinfo.name, oe.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), oe.decoder, oe.decoder_syscheck_id, oe.buf, oe.program_name, oe.log);
                b = format!("{} {:?} {:?} {} {} {:?} {:?} {}", y, ninfo.name, ne.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), ne.decoder, ne.decoder_syscheck_id, ne.buf, ne.program_name, ne.log_start);
                assert_eq!(oinfo.id, ninfo.id);
                if x {
                    // the event as the rules see it: alerts.log, the JSON and archives
                    oe.generated_rule = Some(0);
                    ne.generated_rule = Some(0);
                    oe.comment = Some(b"Integrity checksum changed.".to_vec());
                    ne.comment = Some(b"Integrity checksum changed.".to_vec());
                    let (mut wa, mut wb) = (Vec::new(), Vec::new());
                    siem_analysisd::output::os_log(&oeng, &oe, &mut wa).unwrap();
                    provigil_analysisd::text_logs::alert(&neng, &ne, &mut wb).unwrap();
                    let (mut l1, mut l2) = (LogList::default(), Messages::default());
                    wa.extend(siem_analysisd::to_json::eventinfo_to_json(&oeng, &oe, false, &mut l1));
                    wb.extend(provigil_analysisd::alert_json::alert(&neng, &ne, false, &mut l2));
                    assert_eq!(String::from_utf8_lossy(&wa), String::from_utf8_lossy(&wb), "{body}");
                    texts += 1;
                }
            }
            1 => {
                let body = integrity_json(&mut r);
                let (mut oe, mut ne) = events(&format!("8:[{agent}] (a) any->syscheck:{body}"));
                let (mut oinfo, mut ninfo) = (DecoderInfo::default(), Decoder::default());
                let x = ofim.decode(&mut ofake, &mut oinfo, oi.fim, &oi.fim_ids, &ocfg, &mut oe);
                let y = nfim.decode(&mut nfake, &mut ninfo, ni_.integrity, &ni_.integrity_ids, &ncfg, &mut ne);
                json_alerts += usize::from(x);
                if x {
                    oe.generated_rule = Some(0);
                    ne.generated_rule = Some(0);
                    let (mut wa, mut wb) = (Vec::new(), Vec::new());
                    siem_analysisd::output::os_log(&oeng, &oe, &mut wa).unwrap();
                    provigil_analysisd::text_logs::alert(&neng, &ne, &mut wb).unwrap();
                    let (mut l1, mut l2) = (LogList::default(), Messages::default());
                    wa.extend(siem_analysisd::to_json::eventinfo_to_json(&oeng, &oe, false, &mut l1));
                    wb.extend(provigil_analysisd::alert_json::alert(&neng, &ne, false, &mut l2));
                    assert_eq!(String::from_utf8_lossy(&wa), String::from_utf8_lossy(&wb), "{body}");
                    assert_eq!(l1.msgs.iter().map(|m| m.msg.clone()).collect::<Vec<_>>(), l2.list.iter().map(|m| m.text.clone()).collect::<Vec<_>>());
                    texts += 1;
                }
                a = format!("{} {:?} {} {:?} {} {} {:?} {}", x, oinfo.name, oinfo.id, oe.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), oe.decoder, oe.decoder_syscheck_id, oe.buf, oe.log);
                b = format!("{} {:?} {} {:?} {} {} {:?} {}", y, ninfo.name, ninfo.id, ne.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), ne.decoder, ne.decoder_syscheck_id, ne.buf, ne.log_start);
            }
            _ => {
                let body = windows_event(&mut r);
                let (mut oe, mut ne) = events(&format!("f:[{agent}] (a) any->EventChannel:{body}"));
                let x = owin.decode(&mut ofake, &mut od, oi.winevt, 256, &mut oe);
                let y = nwin.decode(&mut nfake, &mut nd, ni_.windows, 256, &mut ne);
                windows += usize::from(x);
                a = format!("{} {:?} {:?} {:?} {}", x, oe.f, oe.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), oe.buf, oe.log);
                b = format!("{} {:?} {:?} {:?} {}", y, ne.f, ne.fields.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), ne.buf, ne.log_start);
            }
        }
        assert_eq!(a, b, "round {round}");
        assert_eq!(ofake.seen.take(), nfake.seen.take(), "round {round}");
    }
    assert!(texts > 2000, "{texts} alert texts");
    assert!(alerts > 200 && json_alerts > 2000 && windows > 10_000, "checksum alerts {alerts}, json {json_alerts}, windows {windows}");
}

#[test]
fn checksum_helpers() {
    let mut r = Rng(0xD1B54A32D192ED03);
    let parts = ["|", "a", ",", "0", "1", "4", "2147483648", "x", ":", "\\"];
    for _ in 0..200_000 {
        let s: String = (0..r.below(14)).map(|_| parts[r.below(parts.len())]).collect();
        assert_eq!(os_op::decode_win_permissions(s.as_bytes()), ni::windows_permissions(s.as_bytes()), "{s:?}");
        let mut a = os_op::Sum::default();
        let mut b = ni::Sum::default();
        let w = if r.below(2) == 0 { Some(s.as_bytes()) } else { None };
        assert_eq!(os_op::sk_decode_sum(&mut a, s.as_bytes(), w), ni::decode_sum(&mut b, s.as_bytes(), w));
        assert_eq!(format!("{a:?}").replace("wdata: Wdata", "who: Who"), format!("{b:?}"));
        let n = r.next() as u32;
        assert_eq!(os_op::decode_win_attributes(n), ni::windows_attributes(n));
        assert_eq!(os_op::agent_file_perm(n as i32), ni::mode_text(n as i32));
    }
    let long = format!("|{}", (0..2000).map(|i| format!("account{i},0,{}|", i * 7919)).collect::<String>());
    assert_eq!(os_op::decode_win_permissions(long.as_bytes()), ni::windows_permissions(long.as_bytes()));
}

use siem_analysisd::internal::syscheck_op as os_op;
