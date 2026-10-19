//! `shared/report_op.c`: the daily report (`os_ReportdStart`) and its
//! filter configuration (`os_report_configfilter`), used by monitord's
//! `<reports>` and by `wazuh-reportd`.

use crate::alert::{atoi, AlertData, FileQueue, CRALERT_FP_SET, CRALERT_READ_ALL};
use crate::cfile::CFile;
use crate::log;

pub const REPORT_RELATED: i32 = 1;
pub const REPORT_FILTER: i32 = 2;
pub const REPORT_REL_USER: i32 = 0x001;
pub const REPORT_REL_SRCIP: i32 = 0x002;
pub const REPORT_REL_LEVEL: i32 = 0x004;
pub const REPORT_REL_RULE: i32 = 0x010;
pub const REPORT_REL_GROUP: i32 = 0x020;
pub const REPORT_REL_LOCATION: i32 = 0x040;
pub const REPORT_TYPE_DAILY: i32 = 0x100;
pub const REPORT_REL_FILE: i32 = 0x200;

/// `report_filter` (the configuration fields).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReportFilter {
    pub report_name: Option<String>,
    pub group: Option<String>,
    pub rule: Option<String>,
    pub level: Option<String>,
    pub location: Option<String>,
    pub user: Option<String>,
    pub srcip: Option<String>,
    pub files: Option<String>,
    pub related_user: i32,
    pub related_file: i32,
    pub related_srcip: i32,
    pub related_level: i32,
    pub related_rule: i32,
    pub related_group: i32,
    pub related_location: i32,
    pub report_type: i32,
    pub show_alerts: i32,
}

/// `_report_filter_value`; `err` gets the C error message.
fn report_filter_value(filter_by: &str, prev: i32, err: &mut dyn FnMut(String)) -> i32 {
    let bit = match filter_by {
        "group" => REPORT_REL_GROUP,
        "rule" => REPORT_REL_RULE,
        "level" => REPORT_REL_LEVEL,
        "location" => REPORT_REL_LOCATION,
        "srcip" => REPORT_REL_SRCIP,
        "user" => REPORT_REL_USER,
        "filename" => REPORT_REL_FILE,
        _ => {
            err(format!("Invalid relation '{filter_by}'."));
            return -1;
        }
    };
    prev | bit
}

/// `os_report_configfilter`: 0 or -1.
pub fn os_report_configfilter(filter_by: &str, value: &str, f: &mut ReportFilter, arg_type: i32, err: &mut dyn FnMut(String)) -> i32 {
    if arg_type == REPORT_FILTER {
        let slot = match filter_by {
            "group" => &mut f.group,
            "rule" => &mut f.rule,
            "level" => &mut f.level,
            "location" => &mut f.location,
            "user" => &mut f.user,
            "srcip" => &mut f.srcip,
            "filename" => &mut f.files,
            _ => {
                err(format!("Invalid filter '{filter_by}'."));
                return -1;
            }
        };
        *slot = Some(value.to_string());
    } else {
        let slot = match filter_by {
            "group" => &mut f.related_group,
            "rule" => &mut f.related_rule,
            "level" => &mut f.related_level,
            "location" => &mut f.related_location,
            "srcip" => &mut f.related_srcip,
            "user" => &mut f.related_user,
            "filename" => &mut f.related_file,
            _ => {
                err(format!("Invalid related entry '{filter_by}'."));
                return -1;
            }
        };
        // C passes the filter value: `<level type="relation">srcip</level>` relates level to srcip.
        *slot = report_filter_value(value, *slot, err);
        if *slot == -1 {
            return -1;
        }
    }
    0
}

/// `_os_report_str_int_compare`: 1 found, 0 not, -1 bad list.
fn str_int_compare(s: &str, id: u32) -> i32 {
    let b = s.as_bytes();
    let mut pt_check = false;
    for i in 0..b.len() {
        let c = b[i];
        if c == b',' || c == b' ' {
            pt_check = false;
        } else if c.is_ascii_digit() {
            if !pt_check && atoi(&b[i..]) == id as i64 {
                return 1;
            }
            pt_check = true;
        } else {
            return -1;
        }
    }
    0
}

/// `_os_report_check_filters`
fn check_filters(a: &AlertData, f: &ReportFilter) -> bool {
    if let (Some(g), Some(ag)) = (&f.group, &a.group) {
        if !ag.contains(g.as_str()) {
            return false;
        }
    }
    if let Some(r) = &f.rule {
        if str_int_compare(r, a.rule) != 1 {
            return false;
        }
    }
    if let Some(l) = &f.location {
        if !siem_regex::os_word_match(l, a.location.as_deref().unwrap_or("")) {
            return false;
        }
    }
    if let Some(l) = &f.level {
        if (a.level as i64) < atoi(l.as_bytes()) as u32 as i64 {
            return false;
        }
    }
    for (want, have) in [(&f.srcip, &a.srcip), (&f.user, &a.user), (&f.files, &a.filename)] {
        if let Some(w) = want {
            match have {
                Some(h) if h.contains(w.as_str()) => {}
                _ => return false,
            }
        }
    }
    true
}

/// `OSStore` of `OSList`s (alert indexes): a doubly linked list sorted by key.
struct Store {
    nodes: Vec<SNode>,
    first: Option<usize>,
    last: Option<usize>,
}

struct SNode {
    key: Vec<u8>,
    data: Vec<usize>,
    prev: Option<usize>,
    next: Option<usize>,
}

impl Store {
    fn new() -> Store {
        Store { nodes: Vec::new(), first: None, last: None }
    }

    /// `_os_report_add_tostore` (`OSStore_Get` + `OSStore_Put` in key order)
    fn add(&mut self, key: &[u8], alert: usize) {
        let mut cur = self.first;
        while let Some(c) = cur {
            match self.nodes[c].key.as_slice().cmp(key) {
                std::cmp::Ordering::Equal => {
                    self.nodes[c].data.push(alert);
                    return;
                }
                std::cmp::Ordering::Greater => break,
                std::cmp::Ordering::Less => cur = self.nodes[c].next,
            }
        }
        let n = self.nodes.len();
        self.nodes.push(SNode { key: key.to_vec(), data: vec![alert], prev: None, next: None });
        match cur {
            Some(c) => {
                let p = self.nodes[c].prev;
                match p {
                    Some(p) => self.nodes[p].next = Some(n),
                    None => self.first = Some(n),
                }
                self.nodes[n].prev = p;
                self.nodes[c].prev = Some(n);
                self.nodes[n].next = Some(c);
            }
            None => {
                match self.last {
                    Some(l) => {
                        self.nodes[l].next = Some(n);
                        self.nodes[n].prev = Some(l);
                    }
                    None => self.first = Some(n),
                }
                self.last = Some(n);
            }
        }
    }

    /// `OSStore_Sort(list, _os_report_sort_compare)` exactly as C moves the nodes.
    fn sort(&mut self) {
        let gt = |s: &Store, a: usize, b: usize| s.nodes[a].data.len() > s.nodes[b].data.len();
        let mut cur = self.first;
        while let Some(c) = cur {
            let mut c = c;
            let mut movenode = self.nodes[c].prev;
            while let Some(mv) = movenode {
                if gt(self, c, mv) {
                    movenode = self.nodes[mv].prev;
                } else if Some(mv) == self.nodes[c].prev {
                    break;
                } else {
                    let newnode = c;
                    let (cp, cn) = (self.nodes[c].prev, self.nodes[c].next);
                    if let Some(p) = cp {
                        self.nodes[p].next = cn;
                    }
                    match cn {
                        Some(n) => self.nodes[n].prev = cp,
                        None => self.last = cp,
                    }
                    c = cp.expect("prev exists: movenode is before it");
                    self.nodes[newnode].next = self.nodes[mv].next;
                    self.nodes[newnode].prev = Some(mv);
                    if let Some(n) = self.nodes[mv].next {
                        self.nodes[n].prev = Some(newnode);
                    }
                    self.nodes[mv].next = Some(newnode);
                    break;
                }
            }
            if movenode.is_none() && Some(c) != self.first {
                let newnode = c;
                let (cp, cn) = (self.nodes[c].prev, self.nodes[c].next);
                if let Some(p) = cp {
                    self.nodes[p].next = cn;
                }
                match cn {
                    Some(n) => self.nodes[n].prev = cp,
                    None => self.last = cp,
                }
                let Some(p) = cp else { return };
                c = p;
                self.nodes[newnode].prev = None;
                self.nodes[newnode].next = self.first;
                if let Some(f) = self.first {
                    self.nodes[f].prev = Some(newnode);
                }
                self.first = Some(newnode);
            }
            cur = self.nodes[c].next;
        }
    }

    fn order(&self) -> Vec<usize> {
        let mut v = Vec::new();
        let mut c = self.first;
        while let Some(i) = c {
            v.push(i);
            c = self.nodes[i].next;
        }
        v
    }
}

/// Report text (`l_print_out`: every line ends with "\r\n").
struct Out(Vec<u8>);

impl Out {
    fn line(&mut self, s: impl AsRef<[u8]>) {
        self.0.extend_from_slice(s.as_ref());
        self.0.extend_from_slice(b"\r\n");
    }
}

fn header(o: &mut Out, related: bool, hname: &str) {
    o.line(if related { format!("Related entries for '{hname}':") } else { format!("Top entries for '{hname}':") });
    o.line("------------------------------------------------");
}

fn pad_row(key: &[u8], n: usize) -> Vec<u8> {
    let mut v = key.to_vec();
    while v.len() < 78 {
        v.push(b' ');
    }
    v.push(b'|');
    let c = n.to_string();
    v.extend_from_slice(format!("{c:<8}|").as_bytes());
    v
}

/// `_os_report_print_related`
fn print_related(o: &mut Out, flag: i32, list: &[usize], al: &[AlertData]) {
    for (j, &idx) in list.iter().enumerate() {
        let saved = &al[idx];
        let dup = list[..j].iter().rev().any(|&k| {
            let x = &al[k];
            let eq = |a: &Option<String>, b: &Option<String>| matches!((a, b), (Some(a), Some(b)) if a == b);
            if flag & REPORT_REL_LOCATION != 0 {
                x.location == saved.location
            } else if flag & REPORT_REL_GROUP != 0 {
                x.group == saved.group
            } else if flag & REPORT_REL_RULE != 0 {
                x.rule == saved.rule
            } else if flag & REPORT_REL_USER != 0 {
                eq(&x.user, &saved.user)
            } else if flag & REPORT_REL_SRCIP != 0 {
                eq(&x.srcip, &saved.srcip)
            } else if flag & REPORT_REL_LEVEL != 0 {
                x.level == saved.level
            } else if flag & REPORT_REL_FILE != 0 {
                eq(&x.filename, &saved.filename)
            } else {
                false
            }
        });
        if dup {
            continue;
        }
        let s = |v: &Option<String>| v.clone().unwrap_or_default();
        if flag & REPORT_REL_LOCATION != 0 {
            o.line(format!("   location: '{}'", s(&saved.location)));
        } else if flag & REPORT_REL_GROUP != 0 {
            o.line(format!("   group: '{}'", s(&saved.group)));
        } else if flag & REPORT_REL_RULE != 0 {
            o.line(format!("   rule: '{}'", saved.rule as i32));
        } else if flag & REPORT_REL_SRCIP != 0 && saved.srcip.is_some() {
            o.line(format!("   srcip: '{}'", s(&saved.srcip)));
        } else if flag & REPORT_REL_USER != 0 && saved.user.is_some() {
            o.line(format!("   user: '{}'", s(&saved.user)));
        } else if flag & REPORT_REL_LEVEL != 0 {
            o.line(format!("   level: '{}'", saved.level as i32));
        } else if flag & REPORT_REL_FILE != 0 && saved.filename.is_some() {
            o.line(format!("   filename: '{}'", s(&saved.filename)));
        }
    }
}

/// `os_report_printtop`
fn printtop(o: &mut Out, st: &mut Store, hname: &str, related: i32, al: &[AlertData]) {
    let mut done = false;
    for i in st.order() {
        if related == 0 {
            let k = &mut st.nodes[i].key;
            if k.len() > 76 {
                k[74] = b'.';
                k[75] = b'.';
                k.truncate(76);
            }
        }
        if !done {
            header(o, related != 0, hname);
            done = true;
        }
        o.line(pad_row(&st.nodes[i].key, st.nodes[i].data.len()));
        if related != 0 {
            for f in [REPORT_REL_LOCATION, REPORT_REL_SRCIP, REPORT_REL_USER, REPORT_REL_RULE, REPORT_REL_GROUP, REPORT_REL_LEVEL, REPORT_REL_FILE] {
                if related & f != 0 {
                    print_related(o, f, &st.nodes[i].data, al);
                }
            }
        }
    }
    if done {
        o.line(" ");
        o.line(" ");
    }
}

/// `os_ReportdStart` on an alerts file (or stdin's content for reportd).
/// Returns the report text; empty when nothing passed the filters.
pub fn os_reportd_start(f: &ReportFilter, fp: CFile) -> Vec<u8> {
    let mut fq = FileQueue::init(Some(fp), CRALERT_READ_ALL | CRALERT_FP_SET);
    let mut processed = 0;
    let mut kept: Vec<AlertData> = Vec::new();
    let (mut srcip, mut user, mut level, mut rule, mut group, mut location, mut files) = (Store::new(), Store::new(), Store::new(), Store::new(), Store::new(), Store::new(), Store::new());
    // shortcut: C waits 5 s at the end of the file before giving up; skipped (no effect on the report)
    while let Some(a) = fq.read_filemon(1, &|_| {}) {
        processed += 1;
        if !check_filters(&a, f) {
            continue;
        }
        let i = kept.len();
        if let Some(s) = a.srcip.as_deref().filter(|s| *s != "(none)") {
            srcip.add(s.as_bytes(), i);
        }
        if let Some(u) = a.user.as_deref().filter(|u| *u != "(none)") {
            user.add(u.as_bytes(), i);
        }
        level.add(format!("Severity {}", a.level as i32).as_bytes(), i);
        let mut r = format!("{} - ", a.rule as i32).into_bytes();
        r.extend_from_slice(a.comment.as_deref().unwrap_or("(null)").as_bytes());
        r.truncate(75);
        rule.add(&r, i);
        let g = a.group.clone().unwrap_or_default();
        match siem_regex::str_break(',', &g, 32) {
            Some(parts) => {
                for p in parts {
                    let t = p.trim_start_matches(' ');
                    if !t.is_empty() {
                        group.add(t.as_bytes(), i);
                    }
                }
            }
            None => {
                let t = g.trim_start_matches(' ');
                if !t.is_empty() {
                    group.add(t.as_bytes(), i);
                }
            }
        }
        location.add(a.location.as_deref().unwrap_or("").as_bytes(), i);
        if let Some(fname) = &a.filename {
            files.add(fname.as_bytes(), i);
        }
        kept.push(a);
    }

    let mut o = Out(Vec::new());
    if kept.is_empty() {
        match &f.report_name {
            None => log().info("Report completed and zero alerts post-filter."),
            Some(n) => log().info(format!("Report '{n}' completed and zero alerts post-filter.")),
        }
        return o.0;
    }
    match &f.report_name {
        Some(n) => log().info(format!("Report '{n}' completed. Creating output...")),
        None => log().info("Report completed. Creating output..."),
    }
    o.line(" ");
    match &f.report_name {
        Some(n) => o.line(format!("Report '{n}' completed.")),
        None => o.line("Report completed. =="),
    }
    o.line("------------------------------------------------");
    o.line(format!("->Processed alerts: {processed}"));
    o.line(format!("->Post-filtering alerts: {}", kept.len()));
    o.line(format!("->First alert: {}", kept[0].date.as_deref().unwrap_or("(null)")));
    o.line(format!("->Last alert: {}", kept[kept.len() - 1].date.as_deref().unwrap_or("(null)")));
    o.line(" ");
    o.line(" ");
    for s in [&mut srcip, &mut user, &mut level, &mut group, &mut location, &mut rule, &mut files] {
        s.sort();
    }
    printtop(&mut o, &mut srcip, "Source ip", 0, &kept);
    printtop(&mut o, &mut user, "Username", 0, &kept);
    printtop(&mut o, &mut level, "Level", 0, &kept);
    printtop(&mut o, &mut group, "Group", 0, &kept);
    printtop(&mut o, &mut location, "Location", 0, &kept);
    printtop(&mut o, &mut rule, "Rule", 0, &kept);
    printtop(&mut o, &mut files, "Filenames", 0, &kept);
    for (st, name, rel) in [
        (&mut srcip, "Source ip", f.related_srcip),
        (&mut user, "Username", f.related_user),
        (&mut level, "Level", f.related_level),
        (&mut group, "Group", f.related_group),
        (&mut location, "Location", f.related_location),
        (&mut rule, "Rule", f.related_rule),
        (&mut files, "Filename", f.related_file),
    ] {
        if rel != 0 {
            printtop(&mut o, st, name, rel, &kept);
        }
    }
    if f.show_alerts != 0 {
        o.line("Log dump:");
        o.line("------------------------------------------------");
        for a in &kept {
            o.line(format!(
                "{} {}\nRule: {} (level {}) -> '{}'\n{}\n\n",
                a.date.as_deref().unwrap_or("(null)"),
                a.location.as_deref().unwrap_or("(null)"),
                a.rule as i32,
                a.level as i32,
                a.comment.as_deref().unwrap_or("(null)"),
                a.log.first().map(String::as_str).unwrap_or("(null)")
            ));
        }
    }
    o.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_lists() {
        assert_eq!(str_int_compare("5501, 5502", 5502), 1);
        assert_eq!(str_int_compare("55011", 5501), 0);
        assert_eq!(str_int_compare("5501;x", 1), -1);
    }

    #[test]
    fn store_sorted_by_count() {
        let mut s = Store::new();
        for (k, n) in [("b", 1), ("a", 3), ("c", 2)] {
            for i in 0..n {
                s.add(k.as_bytes(), i);
            }
        }
        s.sort();
        let keys: Vec<_> = s.order().iter().map(|&i| s.nodes[i].key.clone()).collect();
        assert_eq!(keys, vec![b"a".to_vec(), b"c".to_vec(), b"b".to_vec()]);
    }
}
