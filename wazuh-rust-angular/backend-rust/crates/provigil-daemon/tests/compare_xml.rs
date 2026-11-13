//! The configuration XML reader, old against new: the same documents must give the same
//! elements, attributes and contents, or the same error text and line.

use provigil_daemon::xml::{self, Node};
use siem_xml::{OsXml, XmlNode};

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
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

/// The old reader's visible tree.
fn old_tree(x: &OsXml, parent: Option<&XmlNode>) -> Vec<Node> {
    x.get_elements_by_node(parent)
        .unwrap_or_default()
        .iter()
        .map(|n| Node {
            name: n.element.clone(),
            attributes: n.attributes.iter().cloned().zip(n.values.iter().cloned()).collect(),
            content: n.content.clone().unwrap_or_default(),
            children: old_tree(x, Some(n)),
            from_var: false,
        })
        .collect()
}

/// The new reader's tree without the `var` marks.
fn new_tree(nodes: &[Node]) -> Vec<Node> {
    nodes.iter().map(|n| Node { children: new_tree(&n.children), from_var: false, ..n.clone() }).collect()
}

fn lines(nodes: &[Node], depth: usize) -> Vec<String> {
    nodes.iter().flat_map(|n| std::iter::once(format!("{}{} {:?} {:?}", "  ".repeat(depth), n.name, n.attributes, n.content)).chain(lines(&n.children, depth + 1))).collect()
}

fn check(doc: &[u8]) {
    let old = OsXml::read_bytes(doc, false);
    let new = xml::parse(doc);
    match (&old, &new) {
        (Ok(o), Ok(n)) => {
            let (a, b) = (old_tree(o, None), new_tree(n));
            if a != b {
                let (la, lb) = (lines(&a, 0), lines(&b, 0));
                let at = la.iter().zip(&lb).position(|(x, y)| x != y).unwrap_or(la.len().min(lb.len()));
                panic!("document {:?}
 old: {:#?}
 new: {:#?}", String::from_utf8_lossy(doc), &la[at.saturating_sub(3)..(at + 3).min(la.len())], &lb[at.saturating_sub(3)..(at + 3).min(lb.len())]);
            }
            for path in [&["a"][..], &["a", "b"], &["ossec_config", "active-response", "disabled"], &["a", "b", "c"]] {
                let mut o2 = o.clone();
                assert_eq!(o2.get_one_content_for_element(path).as_deref(), xml::first_content(n, path), "path {path:?} in {:?}", String::from_utf8_lossy(doc));
            }
        }
        (Err(o), Err(n)) => assert_eq!((o.message.as_str(), o.line), (n.message.as_str(), n.line), "document {:?}", String::from_utf8_lossy(doc)),
        _ => panic!("document {:?}\n old: {:?}\n new: {:?}", String::from_utf8_lossy(doc), old.map(|o| old_tree(&o, None)), new),
    }
}

/// Short random texts over the bytes that matter to the reader.
#[test]
fn random_text() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    let parts: Vec<&[u8]> = vec![
        b"<", b">", b"/", b"\\", b"!", b"-", b"=", b"\"", b"'", b" ", b"\n", b"\t", b"a", b"b", b"x", b"\0", b"<a>", b"</a>", b"<b>", b"</b>", b"<a/>", b"<!--", b"-->", b"<!", b"!>", b"x=\"1\"", b"y='2'",
        b"<var>", b"</var>", b"\xC3\xA9", b"\xFF", b"&lt;",
    ];
    for _ in 0..300_000 {
        let n = r.below(16);
        let d: Vec<u8> = (0..n).flat_map(|_| r.pick(&parts).to_vec()).collect();
        check(&d);
    }
}

fn name(r: &mut Rng) -> String {
    r.pick(&["a", "b", "c", "ossec_config", "active-response", "disabled", "var", "VAR", "x-y", "n1"]).to_string()
}

fn element(r: &mut Rng, depth: usize) -> String {
    let n = name(r);
    let ws = |r: &mut Rng| r.pick(&["", "", " ", "\n", "\n  ", "\t"]).to_string();
    let mut attrs = String::new();
    for i in 0..r.below(4) {
        let q = *r.pick(&["\"", "'"]);
        attrs.push_str(&format!("{}{}k{i}={q}{}{q}", r.pick(&[" ", "  ", "\n"]), ws(r), r.pick(&["v", "", "a b", "x/y", "<", "1"])));
    }
    match r.below(if depth > 4 { 3 } else { 6 }) {
        0 => format!("<{n}{attrs}/>"),
        1 => format!("<{n}{attrs} />"),
        2 => format!("<{n}{attrs}>{}</{n}>", r.pick(&["yes", "no", " yes ", "", "a\\<b", "x\\\\", "&amp;", "1,2, 3", "<!-- c -->v", "v<! c !>w"])),
        _ => {
            let kids: String = (0..r.below(4)).map(|_| format!("{}{}{}", ws(r), element(r, depth + 1), r.pick(&["", "text", "\n"]))).collect();
            format!("<{n}{attrs}>{kids}{}</{n}>", ws(r))
        }
    }
}

/// Generated documents, also cut short or with one byte changed.
#[test]
fn random_documents() {
    let mut r = Rng(0xD1B54A32D192ED03);
    for _ in 0..60_000 {
        let roots: String = (0..1 + r.below(3)).map(|_| format!("{}{}", r.pick(&["", "\n", "<!-- head -->\n", "junk "]), element(&mut r, 0))).collect();
        let d = roots.into_bytes();
        check(&d);
        let cut = r.below(d.len());
        check(&d[..cut]);
        let mut m = d.clone();
        let i = r.below(m.len());
        m[i] = *r.pick(&[b'<', b'>', b'/', b'\\', b'"', b'\'', b'=', b' ', b'!', b'-', 0]);
        check(&m);
    }
}

#[test]
fn limits() {
    for n in [1023, 1024, 1025] {
        check(&[b"<a>".repeat(n), b"</a>".repeat(n)].concat());
    }
    for n in [20478, 20479, 20480, 20481] {
        check(format!("<a>{}</a>", "x".repeat(n)).as_bytes());
        check(format!("<{} />", "n".repeat(n)).as_bytes());
        check(format!("<a k=\"{}\"/>", "v".repeat(n)).as_bytes());
        check(format!("<a {}=\"1\"/>", "k".repeat(n)).as_bytes());
    }
    for n in [47, 48, 49, 50] {
        let attrs: String = (0..n).map(|i| format!(" k{i}=\"1\"")).collect();
        check(format!("<a{attrs}></a>").as_bytes());
        check(format!("<a{attrs} ></a>").as_bytes());
    }
}
