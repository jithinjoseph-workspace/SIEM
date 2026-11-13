//! The file integrity part of the alert JSON, old against new, on generated field values.

use provigil_analysisd::alert_json as nj;
use provigil_analysisd::event::{DynamicField as NF, Event as NE};
use provigil_analysisd::messages::Messages;
use siem_analysisd::event::{DynamicField as OF, Event as OE};
use siem_analysisd::logmsg::LogList;
use siem_analysisd::syscheck_json as oj;

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

const VALUES: &[&str] = &[
    "",
    "0",
    "1",
    "123",
    "-5",
    "99999999999999999999",
    "1700000000",
    "/etc/passwd",
    "[\"/a\",\"/b\"]",
    "[bad",
    "rw-r--r--",
    "root",
    "SYSTEM (allowed): read_data|write_data, Users (denied): delete",
    "Administrators (allowed): , x",
    "u (allowed): |",
    "ARCHIVE, HIDDEN",
    "tag1,tag2,",
    "size,md5",
    "modified",
    "[x86]",
    "REG_SZ",
];

#[test]
fn generated_fim_fields() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    for _ in 0..200_000 {
        let n = if r.below(10) == 0 { r.below(51) } else { 51 };
        let mut oe = OE::new(0);
        let mut ne = NE::new(0);
        for _ in 0..n {
            let v = if r.below(6) == 0 { None } else { Some(VALUES[r.below(VALUES.len())].as_bytes().to_vec()) };
            oe.fields.push(OF { key: b"k".to_vec(), value: v.clone() });
            ne.fields.push(NF { key: b"k".to_vec(), value: v });
        }
        let order = [256, 20, 26][r.below(3)];
        let (mut ol, mut nl) = (LogList::default(), Messages::default());
        let a = oj::syscheck_section(&oe, order, &mut ol).map(|j| j.print_unformatted());
        let b = Some(nj::syscheck_section(&ne, order, &mut nl).print_unformatted());
        assert_eq!(a, b);
        assert_eq!(ol.msgs.iter().map(|m| m.msg.clone()).collect::<Vec<_>>(), nl.list.iter().map(|m| m.text.clone()).collect::<Vec<_>>());
        assert_eq!(oj::audit_section(&oe).map(|j| j.print_unformatted()), nj::audit_section(&ne).map(|j| j.print_unformatted()));
    }
    let parts = ["a (allowed): x|y", "b (denied):", " c(allowed):z", ",", "d", "(x)", "a (allowed): w", "e (allowed): ||"];
    for _ in 0..100_000 {
        let s: Vec<&str> = (0..r.below(5)).map(|_| parts[r.below(parts.len())]).collect();
        let s = s.join(if r.below(2) == 0 { "," } else { ", " });
        assert_eq!(oj::win_perm_to_json(s.as_bytes()).map(|j| j.print_unformatted()), nj::windows_permissions_json(s.as_bytes()).map(|j| j.print_unformatted()), "{s:?}");
        assert_eq!(oj::attrs_to_json(s.as_bytes()).print_unformatted(), nj::attributes_json(s.as_bytes()).print_unformatted());
    }
}
