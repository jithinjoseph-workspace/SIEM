//! Lists, old against new: generated list texts must give the same records, lookups and
//! `.cdb` bytes.

use provigil_analysisd::lists as nl;
use provigil_analysisd::messages::Messages;
use provigil_regex::OsMatch;
use siem_analysisd::lists as ol;
use siem_analysisd::logmsg::LogList;

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

#[test]
fn generated_lists() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir_all(home.join("etc/lists")).unwrap();
    let mut r = Rng(0x2545F4914F6CDD1D);
    let parts: &[&[u8]] = &[b"a", b"b", b"10.", b"1", b".", b":", b"\"", b"\r", b"\n", b"\0", b" ", b"x:y", b"10.1.2.3", b"\"k:1\"", b"root"];
    for round in 0..6_000 {
        let mut text = Vec::new();
        for _ in 0..r.below(30) {
            text.extend_from_slice(parts[r.below(parts.len())]);
        }
        assert_eq!(ol::parse_list_text(&text), nl::parse_text(&text), "{:?}", String::from_utf8_lossy(&text));
        let recs = nl::parse_text(&text);
        assert_eq!(ol::write_cdb(&recs), nl::write_cdb(&recs));

        let name = format!("etc/lists/l{}", round % 3);
        std::fs::write(home.join(&name), &text).unwrap();
        let (mut o, mut n) = (ol::Lists::default(), nl::Lists::default());
        let (mut olog, mut nlog) = (LogList::default(), Messages::default());
        let file = if r.below(4) == 0 { format!("{name}.cdb") } else { name.clone() };
        assert_eq!(o.load_list(&file, home, &mut olog), n.load(&file, home, &mut nlog));
        let _ = o.load_list("etc/lists/missing", home, &mut olog);
        let _ = n.load("etc/lists/missing", home, &mut nlog);
        assert_eq!(olog.msgs.iter().map(|m| m.msg.clone()).collect::<Vec<_>>(), nlog.list.iter().map(|m| m.text.clone()).collect::<Vec<_>>());
        assert_eq!(o.find_list(&format!("{name}.cdb")), n.find(&format!("{name}.cdb")));
        let db = o.find_list(&name);
        for lookup in [0, 1, 2, 10, 11, 12, 5] {
            let pattern = [None, Some("a"), Some("^b"), Some("")][r.below(4)].and_then(|p| OsMatch::compile(p, 0).ok());
            let oc = ol::ListRule { field: 0, lookup_type: lookup, matcher: pattern.clone(), dfield: None, filename: name.clone(), db };
            let nc = nl::ListCheck { field: 0, lookup, value_pattern: pattern, dynamic_field: None, file: name.clone(), list: db };
            for key in [&b"a"[..], b"b", b"10.1.2.3", b"10.1.2", b"k:1", b"", b"x", b"root", b"10."] {
                assert_eq!(o.db_search(&oc, key), n.check(&nc, key), "{lookup} {key:?} in {:?}", String::from_utf8_lossy(&text));
            }
        }
    }
}
