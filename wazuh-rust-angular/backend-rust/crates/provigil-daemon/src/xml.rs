//! The configuration XML of the manager (`etc/ossec.conf` and the files in its format).
//!
//! It is a lenient dialect, and configurations in the field depend on its readings:
//!
//! * a document may hold several root elements; text outside elements is ignored;
//! * nothing is decoded: `&lt;` stays as written;
//! * a backslash makes the next `<` plain text (`\<`); two backslashes cancel out, and the
//!   backslashes stay in the text;
//! * `<!` starts a comment anywhere, even inside a name or a text; it ends at the first `!>` or
//!   `-->` after the `<!`;
//! * a name ends at `>` or white space; `<x/>` and `<x a="1"/>` have no content; after `<x />`
//!   or `<x a="1"/>` the `>` that follows is text of the enclosing element;
//! * attribute values are quoted with `"` or `'` and may not hold `>`; at most 49 attributes;
//! * an element's content is the text after its last child, up to a zero byte;
//! * a name, a content part or an attribute value has at most 20,479 bytes; elements nest at
//!   most 1,024 deep;
//! * elements named `var` (any case) are not listed, and listing looks through them: the
//!   children of an element are the elements one level below it, in document order, up to the
//!   next element at its level or above that is not a `var`. So the children of a `var` that
//!   follows an element at the same level are listed under that element (marked
//!   [`Node::from_var`]); a lookup by path ([`first_content`]) does not reach them.

/// The longest name, content part or attribute value, plus one.
const MAX_TEXT: usize = 20480;
const MAX_DEPTH: u32 = 1024;
const MAX_ATTRIBUTES: u32 = 48;
/// Error texts are cut to this many bytes.
const MAX_ERROR: usize = 126;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub content: String,
    pub children: Vec<Node>,
    /// Listed here through a `var` element (not inside this element): not reached by
    /// [`first_content`].
    pub from_var: bool,
}

/// A reading error: the text (`XMLERR: ...`) and the line it was found on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError {
    pub message: String,
    pub line: u32,
}

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (line {})", self.message, self.line)
    }
}

impl Node {
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// The content of an element at `path` (names from a root down). Each root with the first name
/// is tried in order; below it the lookup takes the first child with the next name and never
/// another one, and an element on the way that has attributes ends the try.
pub fn first_content<'a>(roots: &'a [Node], path: &[&str]) -> Option<&'a str> {
    let (head, rest) = path.split_first()?;
    roots.iter().filter(|n| n.name == *head).find_map(|n| below(n, rest))
}

fn below<'a>(n: &'a Node, path: &[&str]) -> Option<&'a str> {
    let Some((head, rest)) = path.split_first() else { return Some(&n.content) };
    if !n.attributes.is_empty() {
        return None;
    }
    below(n.children.iter().find(|c| !c.from_var && c.name == *head)?, rest)
}

/// An element as read, in document order (by its start tag).
struct Raw {
    name: String,
    attributes: Vec<(String, String)>,
    content: String,
    depth: u32,
    var: bool,
    parent: Option<usize>,
}

/// The listed tree of element `i` (see the module notes).
fn build(all: &[Raw], i: usize) -> Node {
    let d = all[i].depth;
    let mut children = Vec::new();
    for (j, e) in all.iter().enumerate().skip(i + 1) {
        if e.var {
            continue;
        }
        if e.depth <= d {
            break;
        }
        if e.depth == d + 1 {
            let mut c = build(all, j);
            c.from_var = e.parent != Some(i);
            children.push(c);
        }
    }
    let r = &all[i];
    Node { name: r.name.clone(), attributes: r.attributes.clone(), content: r.content.clone(), children, from_var: false }
}

/// Reads the file at `path`.
pub fn read_file(path: &std::path::Path) -> Result<Vec<Node>, XmlError> {
    match std::fs::read(path) {
        Ok(data) => parse(&data),
        Err(_) => Err(XmlError { message: cut(format!("XMLERR: File '{}' not found.", path.display())), line: 0 }),
    }
}

/// Reads a document (the root elements).
pub fn parse(data: &[u8]) -> Result<Vec<Node>, XmlError> {
    let mut r = Reader { b: data, pos: 0, line: 1, all: Vec::new() };
    let mut escaped = false;
    while let Some(c) = r.next() {
        escape(&mut escaped, c);
        if c != b'<' {
            continue;
        }
        if r.comment()? {
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        if r.peek() == Some(b'/') {
            r.next();
            return Err(r.fail("XMLERR: Element not opened.".into()));
        }
        // the roots share the document's escape state
        r.element(1, &mut escaped, None)?;
    }
    Ok((0..r.all.len()).filter(|&i| r.all[i].depth == 0 && !r.all[i].var).map(|i| build(&r.all, i)).collect())
}

/// A backslash turns the escape on and off; any byte but `<` turns it off.
fn escape(escaped: &mut bool, c: u8) {
    if c == b'\\' {
        *escaped = !*escaped;
    } else if c != b'<' {
        *escaped = false;
    }
}

/// The text up to its first zero byte.
fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
}

fn cut(m: String) -> String {
    let mut b = m.into_bytes();
    b.truncate(MAX_ERROR);
    String::from_utf8_lossy(&b).into_owned()
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    /// 1 + the line breaks read so far
    line: u32,
    all: Vec<Raw>,
}

impl Reader<'_> {
    fn next(&mut self) -> Option<u8> {
        let c = *self.b.get(self.pos)?;
        self.pos += 1;
        if c == b'\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn fail(&self, message: String) -> XmlError {
        XmlError { message: cut(message), line: self.line }
    }

    fn unclosed(&self) -> XmlError {
        self.fail("XMLERR: End of file and some elements were not closed.".into())
    }

    fn overflow(&self, len: usize) -> Result<(), XmlError> {
        if len >= MAX_TEXT {
            return Err(self.fail("XMLERR: String overflow.".into()));
        }
        Ok(())
    }

    /// After a `<`: skips a comment; false (nothing read) when none starts here.
    fn comment(&mut self) -> Result<bool, XmlError> {
        if self.peek() != Some(b'!') {
            return Ok(false);
        }
        self.next();
        let (mut before, mut last) = (0u8, 0u8);
        loop {
            let c = self.next().ok_or_else(|| self.fail("XMLERR: Comment not closed.".into()))?;
            if c == b'>' && (last == b'!' || (last == b'-' && before == b'-')) {
                return Ok(true);
            }
            (before, last) = (last, c);
        }
    }

    /// One element after its `<`, recorded with its descendants. `level`: nesting depth (roots
    /// are 1); `escaped`: the escape state, which an element shares with the text around it.
    fn element(&mut self, level: u32, escaped: &mut bool, parent: Option<usize>) -> Result<(), XmlError> {
        let mut name = Vec::new();
        let end = loop {
            let c = self.next().ok_or_else(|| self.unclosed())?;
            escape(escaped, c);
            self.overflow(name.len())?;
            if c == b'<' && self.comment()? {
                continue;
            }
            if c == b'>' || is_space(c) {
                break c;
            }
            name.push(c);
            if c == b'<' {
                *escaped = false;
            }
        };
        let mut empty = name.last() == Some(&b'/');
        if empty {
            name.pop();
        }
        let me = self.all.len();
        let shown = text(&name);
        self.all.push(Raw { var: shown.eq_ignore_ascii_case("var"), name: shown, attributes: Vec::new(), content: String::new(), depth: level - 1, parent });
        if is_space(end) {
            let mut attributes = Vec::new();
            empty |= self.attributes(&mut attributes, 0)?;
            self.all[me].attributes = attributes;
        }
        if empty {
            return Ok(());
        }
        let mut content = Vec::new();
        loop {
            let c = self.next().ok_or_else(|| self.unclosed())?;
            escape(escaped, c);
            self.overflow(content.len())?;
            if c == b'<' && self.comment()? {
                continue;
            }
            if c == b'<' && !*escaped {
                if self.peek() == Some(b'/') {
                    self.next();
                    return self.close(me, &name, &content, escaped);
                }
                if level + 1 > MAX_DEPTH {
                    return Err(self.fail("XMLERR: Max recursion level reached".into()));
                }
                // a child has its own escape state; the content restarts after it
                self.element(level + 1, &mut false, Some(me))?;
                content.clear();
                continue;
            }
            content.push(c);
            if c == b'<' {
                *escaped = false;
            }
        }
    }

    /// The closing tag after `</`: it must repeat the name exactly.
    fn close(&mut self, me: usize, name: &[u8], content: &[u8], escaped: &mut bool) -> Result<(), XmlError> {
        let mut tag = Vec::new();
        loop {
            let c = self.next().ok_or_else(|| self.unclosed())?;
            escape(escaped, c);
            self.overflow(tag.len())?;
            if c == b'<' && self.comment()? {
                continue;
            }
            if c == b'>' {
                break;
            }
            tag.push(c);
            if c == b'<' {
                *escaped = false;
            }
        }
        if text(&tag) != text(name) {
            return Err(self.fail(format!("XMLERR: Element '{}' not closed.", text(name))));
        }
        self.all[me].content = text(content);
        Ok(())
    }

    /// The attributes after a name and white space, one per call (`count` before it). True when
    /// the element ends with `/` (its `>` is left unread).
    fn attributes(&mut self, out: &mut Vec<(String, String)>, count: u32) -> Result<bool, XmlError> {
        if count > MAX_ATTRIBUTES {
            return Err(self.fail("XMLERR: Too many attributes.".into()));
        }
        let mut name: Vec<u8> = Vec::new();
        let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let eof = |r: &Self| r.fail("XMLERR: End of file while reading an attribute.".into());
        // the name, up to `=`
        loop {
            let c = self.next().ok_or_else(|| eof(self))?;
            if name.len() >= MAX_TEXT {
                let shown: String = lossy(&name[..name.len() - 1]).chars().take(20).collect();
                return Err(self.fail(format!("XMLERR: Overflow attempt at attribute '{shown}'.")));
            }
            match c {
                b'>' | b'/' if !name.is_empty() => return Err(self.fail(format!("XMLERR: Attribute '{}' has no value.", lossy(&name)))),
                b'>' => return Ok(false),
                b'/' => return Ok(true),
                b'=' => break,
                c if is_space(c) && name.is_empty() => {}
                c if is_space(c) => return Err(self.fail(format!("XMLERR: Attribute '{}' has no value.", lossy(&name)))),
                c => name.push(c),
            }
        }
        let shown = lossy(&name);
        if out.iter().any(|(k, _)| *k == shown) {
            return Err(self.fail(format!("XMLERR: Attribute '{shown}' already defined.")));
        }
        // the opening quote, after optional white space
        let mut quote = self.next();
        while quote.is_some_and(is_space) {
            quote = self.next();
        }
        let quote = match quote {
            Some(q @ (b'"' | b'\'')) => q,
            _ => return Err(self.fail(format!("XMLERR: Attribute '{shown}' not followed by a \" or '."))),
        };
        // the value, up to the same quote
        let mut value = Vec::new();
        loop {
            let c = self.next().ok_or_else(|| eof(self))?;
            if value.len() >= MAX_TEXT {
                let shown: String = shown.chars().take(20).collect();
                return Err(self.fail(format!("XMLERR: Overflow attempt at attribute '{shown}'.")));
            }
            if c == b'>' {
                return Err(self.fail(format!("XMLERR: Attribute '{shown}' not closed.")));
            }
            if c == quote {
                break;
            }
            value.push(c);
        }
        out.push((shown.clone(), lossy(&value)));
        match self.next() {
            Some(c) if is_space(c) => self.attributes(out, count + 1),
            Some(b'>') => Ok(false),
            Some(b'/') => Ok(true),
            _ => Err(self.fail(format!("XMLERR: Bad attribute closing for '{shown}'='{}'.", lossy(&value)))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_dialect() {
        let d = parse(b"junk <a x=\"1\" y='2'>t1<b>in</b> tail &lt;\\<c<!-- c -->d</a><e/><f />\n<!x !><g><h/>></g>").unwrap();
        assert_eq!(d.len(), 4);
        assert_eq!(d[0].attributes, [("x".to_string(), "1".to_string()), ("y".to_string(), "2".to_string())]);
        assert_eq!(d[0].content, " tail &lt;\\<cd");
        assert_eq!(d[0].children[0].content, "in");
        assert_eq!((d[1].name.as_str(), d[2].name.as_str(), d[3].content.as_str()), ("e", "f", ">"));
        // an element with attributes on the way ends the lookup
        assert_eq!(first_content(&d, &["a", "b"]), None);
        let c = parse(b"<a><b k='1'><c>no</c></b></a><a><b><c>yes</c></b></a>").unwrap();
        assert_eq!(first_content(&c, &["a", "b", "c"]), Some("yes"));
        let e = parse(b"<a>\n<b></c></a>").unwrap_err();
        assert_eq!((e.message.as_str(), e.line), ("XMLERR: Element 'b' not closed.", 2));
        assert_eq!(parse(b"</a>").unwrap_err().message, "XMLERR: Element not opened.");
        assert_eq!(parse(b"<a x>").unwrap_err().message, "XMLERR: Attribute 'x' has no value.");
        assert_eq!(parse(b"<a><!-- x").unwrap_err().message, "XMLERR: Comment not closed.");
        assert!(parse(&[b"<a>".repeat(1024), b"</a>".repeat(1024)].concat()).is_ok());
        assert_eq!(parse(&b"<a>".repeat(1025)).unwrap_err().message, "XMLERR: Max recursion level reached");
    }
}
