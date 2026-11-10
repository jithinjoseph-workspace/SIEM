//! The rule and decoder regular-expression dialect.
//!
//! This is a single left-to-right scan over the raw pattern bytes, not a backtracking engine. Stock
//! rules are tuned to its exact results, so `end` and the captures must stay byte-for-byte stable;
//! the recorded vectors in specs/vectors/siem-regex define it. Change nothing here without them.

use crate::until_nul;
pub use crate::{RegexError, OS_CASE_SENSITIVE, OS_PATTERN_MAXSIZE, OS_RETURN_SUBSTRING};

/// A repeat may leave at most this many points to come back to.
const RETRY_POINTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Repeat {
    Once,
    ZeroOrMore,
    OneOrMore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The end of the pattern, or a NUL byte in it (the pattern text stops there).
    End,
    /// `(` or `)`: both look the same to the scan.
    Mark,
    Literal(u8),
    Class(u8),
}

#[derive(Debug, Clone, Copy)]
struct Element {
    kind: Kind,
    repeat: Repeat,
    next: usize,
}

impl Element {
    fn is_repeated(&self) -> bool {
        self.repeat != Repeat::Once
    }

    /// A mark met where an element is expected stands for a literal `(`.
    fn takes_as_literal(&self, b: u8) -> bool {
        let c = match self.kind {
            Kind::Literal(c) => c,
            Kind::Mark => b'(',
            _ => return false,
        };
        // Literals at or above 0x80 never match; stock rules rely on it.
        c < 0x80 && b.to_ascii_lowercase() == c
    }

    fn takes_as_class(&self, b: u8) -> bool {
        matches!(self.kind, Kind::Class(letter) if in_class(letter, b))
    }
}

const fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'@')
}

pub(crate) const fn in_class(letter: u8, b: u8) -> bool {
    match letter {
        b'd' => b.is_ascii_digit(),
        b'D' => !b.is_ascii_digit(),
        b'w' => is_word(b),
        b'W' => !is_word(b),
        b's' => b == b' ',
        b'S' => b != b' ',
        b'p' => matches!(b, b'!'..=b'.' | b':'..=b'?' | b'[' | b']' | b'{' | b'|' | b'}'),
        b'.' => true,
        b't' => b == b'\t',
        other => b == other,
    }
}

fn valid_escape(c: u8) -> bool {
    b"dwspWDS.t$()\\|<".contains(&c)
}

/// What the pattern holds at each raw offset; the end-of-subject check may step onto a modifier.
fn decode(code: &[u8], p: usize) -> Element {
    let at = |i: usize| code.get(i).copied();
    let plain = |kind, next| Element { kind, repeat: Repeat::Once, next };
    match at(p) {
        None | Some(0) => plain(Kind::End, p),
        Some(b'\\') if at(p + 1).is_some_and(valid_escape) => {
            let kind = Kind::Class(code[p + 1]);
            match at(p + 2) {
                Some(b'*') => Element { kind, repeat: Repeat::ZeroOrMore, next: p + 3 },
                Some(b'+') => Element { kind, repeat: Repeat::OneOrMore, next: p + 3 },
                _ => plain(kind, p + 2),
            }
        }
        Some(b'(' | b')') => plain(Kind::Mark, p + 1),
        Some(c) => plain(Kind::Literal(c), p + 1),
    }
}

#[derive(Debug, Clone)]
struct Alternative {
    elements: Vec<Element>,
    /// For each mark offset: its number among the marks of this alternative.
    mark_no: Vec<Option<usize>>,
    marks: usize,
    start_anchor: bool,
    end_anchor: bool,
}

impl Alternative {
    fn new(text: &[u8], case_sensitive: bool) -> Alternative {
        let (start_anchor, mut body) = match text.split_first() {
            Some((b'^', rest)) => (true, rest),
            _ => (false, text),
        };
        let mut end_anchor = false;
        if let Some((b'$', rest)) = body.split_last() {
            let slashes = rest.iter().rev().take_while(|&&b| b == b'\\').count();
            if slashes % 2 == 0 {
                end_anchor = true;
                body = rest;
            }
        }
        let code = if case_sensitive { body.to_vec() } else { fold_literals(body) };
        let elements: Vec<Element> = (0..=code.len()).map(|p| decode(&code, p)).collect();
        let mut mark_no = vec![None; elements.len()];
        let (mut marks, mut p) = (0, 0);
        while p < code.len() {
            match code[p] {
                b'\\' => p += 2,
                b'(' | b')' => {
                    mark_no[p] = Some(marks);
                    marks += 1;
                    p += 1;
                }
                _ => p += 1,
            }
        }
        Alternative { elements, mark_no, marks, start_anchor, end_anchor }
    }

    fn at(&self, p: usize) -> Element {
        self.elements[p.min(self.elements.len() - 1)]
    }

    fn is_end(&self, p: usize) -> bool {
        self.at(p).kind == Kind::End
    }

    /// Steps over one mark, if there is one, and says whether the pattern ends there.
    fn ends_after_mark(&self, p: &mut usize) -> bool {
        if self.at(*p).kind == Kind::Mark {
            *p += 1;
        }
        self.is_end(*p)
    }

    /// The verdict once the subject has run out: whatever is left of the pattern must be empty
    /// enough. `going` says whether a repeat is still taking bytes.
    fn accepts_rest(&self, mut p: usize, going: bool) -> bool {
        if self.ends_after_mark(&mut p) {
            return true;
        }
        let here = self.at(p);
        if matches!(here.kind, Kind::Class(_)) && going {
            // The running repeat itself, then at most one zero-or-more escape.
            p += 2;
            if here.is_repeated() {
                p = here.next;
                if self.ends_after_mark(&mut p) {
                    return true;
                }
                let then = self.at(p);
                if matches!(then.kind, Kind::Class(_)) {
                    p += 2;
                    if then.repeat == Repeat::ZeroOrMore {
                        p = then.next;
                        if self.ends_after_mark(&mut p) {
                            return true;
                        }
                    }
                }
            }
        }
        // From wherever that left off: one zero-or-more escape and the end.
        let last = self.at(p);
        if matches!(last.kind, Kind::Class(_)) && last.repeat == Repeat::ZeroOrMore {
            p = last.next;
            return self.ends_after_mark(&mut p);
        }
        false
    }

    /// Runs the scan; `None` when it finds no match.
    fn run(&self, s: &[u8], capturing: bool, spans: &mut Vec<Option<usize>>) -> Option<isize> {
        spans.clear();
        spans.resize(self.marks, None);
        Scan::new(self, s, capturing).run(spans)
    }
}

fn fold_literals(body: &[u8]) -> Vec<u8> {
    let mut code = body.to_vec();
    let mut i = 0;
    while i < code.len() {
        if code[i] == b'\\' {
            i += 2;
            continue;
        }
        code[i] = code[i].to_ascii_lowercase();
        i += 1;
    }
    code
}

struct Scan<'a> {
    alt: &'a Alternative,
    s: &'a [u8],
    capturing: bool,
    i: usize,
    p: usize,
    /// Reported as the end of the match; `None` after the scan starts over.
    last: Option<isize>,
    /// A repeat is taking bytes (or handed one to a single escape and still counts as taking).
    going: bool,
    /// Where the next attempt starts from: the first byte a single element took in this attempt.
    first_taken: Option<usize>,
    retries: Vec<(usize, usize)>,
}

enum Step {
    Next,
    Same,
    Done(Option<isize>),
}

impl<'a> Scan<'a> {
    fn new(alt: &'a Alternative, s: &'a [u8], capturing: bool) -> Self {
        Scan {
            alt,
            s,
            capturing,
            i: 0,
            p: 0,
            last: Some(0),
            going: false,
            first_taken: None,
            retries: Vec::with_capacity(RETRY_POINTS),
        }
    }

    fn mark(&self, p: usize, at: usize, spans: &mut [Option<usize>]) {
        if self.capturing {
            if let Some(n) = self.alt.mark_no.get(p).copied().flatten() {
                spans[n] = Some(at);
            }
        }
    }

    fn run(mut self, spans: &mut [Option<usize>]) -> Option<isize> {
        while self.i < self.s.len() {
            match self.step(spans) {
                Step::Next => self.i += 1,
                Step::Same => {}
                Step::Done(found) => return found,
            }
        }
        self.subject_done(spans)
    }

    fn step(&mut self, spans: &mut [Option<usize>]) -> Step {
        let b = self.s[self.i];
        let mut el = self.alt.at(self.p);
        if el.kind == Kind::End {
            if !self.alt.end_anchor {
                return Step::Done(self.last);
            }
            return self.fail();
        }
        if el.kind == Kind::Mark {
            // Only one mark is passed here; a second one right after it is taken as a `(`.
            self.mark(self.p, self.i, spans);
            self.p = el.next;
            el = self.alt.at(self.p);
            if el.kind == Kind::End && !self.alt.end_anchor {
                return Step::Done(self.last);
            }
        }
        if matches!(el.kind, Kind::Class(_)) {
            return self.class(el, b, spans);
        }
        if el.takes_as_literal(b) {
            self.took_single(el);
            return Step::Next;
        }
        self.fail()
    }

    fn took_single(&mut self, el: Element) {
        self.p = el.next;
        self.first_taken.get_or_insert(self.i);
        self.last = Some(self.i as isize);
    }

    fn class(&mut self, el: Element, b: u8, spans: &mut [Option<usize>]) -> Step {
        if el.takes_as_class(b) {
            match el.repeat {
                Repeat::Once => self.took_single(el),
                Repeat::OneOrMore if !self.going => {
                    // The first byte of a one-or-more is never offered to what follows.
                    if self.alt.at(el.next).kind == Kind::Mark {
                        let at = if self.i + 1 == self.s.len() { self.i + 1 } else { self.i };
                        self.mark(el.next, at, spans);
                    }
                    self.going = true;
                    self.last = Some(self.i as isize);
                }
                _ => {
                    self.going = true;
                    if !self.offer_to_next(el, b, spans) {
                        return Step::Next;
                    }
                    self.last = Some(self.i as isize);
                }
            }
            return Step::Next;
        }
        if self.going && self.last.is_some() && self.near_pattern_end() {
            // A miss this close to the end of the pattern still counts as a match here.
            self.last = Some(self.i as isize);
            if !self.alt.end_anchor {
                return Step::Done(self.last);
            }
        } else if el.repeat == Repeat::OneOrMore && self.going {
            self.p = el.next;
            self.going = false;
            return Step::Same;
        } else if el.repeat == Repeat::ZeroOrMore {
            self.p = el.next;
            self.last = Some(self.i as isize - 1);
            self.going = false;
            return Step::Same;
        }
        self.going = false;
        self.fail()
    }

    /// The escape is the last thing in the pattern, or exactly one pattern byte follows it.
    fn near_pattern_end(&self) -> bool {
        let after = self.p + 2;
        self.alt.is_end(after) || self.alt.is_end(after + 1)
    }

    /// A repeat that took `b` checks whether the element after it could take `b` too. If so the
    /// scan moves on to the element after that one (or stays, for a repeat), keeping a point to
    /// come back to. Returns false when the pattern ends right after the repeat, which leaves the
    /// reported end where it was.
    fn offer_to_next(&mut self, el: Element, b: u8, spans: &mut [Option<usize>]) -> bool {
        let mut q = el.next;
        let crossed = self.alt.at(q).kind == Kind::Mark;
        if crossed {
            q += 1;
        }
        let next = self.alt.at(q);
        let mut lands_after = None;
        let mut reached_end = false;
        if next.kind == Kind::End {
            reached_end = true;
        } else if next.takes_as_class(b) {
            lands_after = Some(if next.is_repeated() { q } else { next.next });
        } else if !matches!(next.kind, Kind::Class(_)) && next.takes_as_literal(b) {
            self.going = false;
            lands_after = Some(next.next);
        }
        if (reached_end || lands_after.is_some()) && crossed {
            let at = if reached_end { self.i + 1 } else { self.i };
            self.mark(q - 1, at, spans);
        }
        if reached_end {
            return false;
        }
        if let Some(to) = lands_after {
            if self.retries.len() < RETRY_POINTS {
                self.retries.push((self.p, self.i));
            }
            self.p = to;
        }
        true
    }

    fn fail(&mut self) -> Step {
        if let Some((p, i)) = self.retries.pop() {
            self.p = p;
            self.i = i;
            return Step::Next;
        }
        if self.alt.start_anchor {
            return Step::Done(None);
        }
        if let Some(from) = self.first_taken.take() {
            self.i = from;
        }
        self.p = 0;
        self.last = None;
        Step::Next
    }

    /// The subject has run out: this decides the alternative, there is no later attempt.
    fn subject_done(mut self, spans: &mut [Option<usize>]) -> Option<isize> {
        if self.capturing {
            loop {
                let el = self.alt.at(self.p);
                if matches!(el.kind, Kind::Class(_)) && el.repeat == Repeat::ZeroOrMore {
                    self.p = el.next;
                } else {
                    break;
                }
            }
            if self.alt.at(self.p).kind == Kind::Mark {
                self.mark(self.p, self.s.len(), spans);
            }
        }
        if self.alt.accepts_rest(self.p, self.going) {
            self.last
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct OsRegex {
    raw: String,
    alternatives: Vec<Alternative>,
    wants_captures: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexMatch {
    pub end: isize,
    pub sub_strings: Vec<String>,
    pub sub_bytes: Vec<Vec<u8>>,
}

impl OsRegex {
    pub fn compile(pattern: &str, flags: u32) -> Result<OsRegex, RegexError> {
        let bytes = pattern.as_bytes();
        if bytes.len() > OS_PATTERN_MAXSIZE {
            return Err(RegexError::MaxSize);
        }
        let case_sensitive = flags & OS_CASE_SENSITIVE != 0;
        let mut alternatives = Vec::new();
        let (mut i, mut from, mut in_group, mut has_group) = (0, 0, false, false);
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => {
                    if !bytes.get(i + 1).copied().is_some_and(valid_escape) {
                        return Err(RegexError::BadRegex);
                    }
                    i += 1;
                }
                b'(' if in_group => return Err(RegexError::BadParenthesis),
                b'(' => in_group = true,
                b')' if !in_group => return Err(RegexError::BadParenthesis),
                b')' => {
                    in_group = false;
                    has_group = true;
                }
                b'|' if in_group => return Err(RegexError::BadParenthesis),
                b'|' => {
                    alternatives.push(Alternative::new(&bytes[from..i], case_sensitive));
                    from = i + 1;
                }
                _ => {}
            }
            i += 1;
        }
        if in_group {
            return Err(RegexError::BadParenthesis);
        }
        alternatives.push(Alternative::new(&bytes[from..], case_sensitive));
        let wants_captures = flags & OS_RETURN_SUBSTRING != 0 && has_group;
        Ok(OsRegex { raw: pattern.to_string(), alternatives, wants_captures })
    }

    pub fn execute_bytes(&self, s: &[u8]) -> Option<RegexMatch> {
        let s = until_nul(s);
        let mut spans = Vec::new();
        for alt in &self.alternatives {
            let Some(end) = alt.run(s, self.wants_captures, &mut spans) else {
                continue;
            };
            if !self.wants_captures {
                return Some(RegexMatch { end, sub_strings: Vec::new(), sub_bytes: Vec::new() });
            }
            return captured(s, end, &spans);
        }
        None
    }

    /// The same as [`OsRegex::execute_bytes`] on the text's bytes.
    pub fn execute(&self, s: &str) -> Option<RegexMatch> {
        self.execute_bytes(s.as_bytes())
    }

    pub fn is_match(&self, s: &str) -> bool {
        self.execute_bytes(s.as_bytes()).is_some()
    }

    pub fn has_sub_strings(&self) -> bool {
        self.wants_captures
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

/// Marks pair up in order as groups. Groups are listed up to the first one with a side never
/// reached; a group ending before it starts rejects the match.
fn captured(s: &[u8], end: isize, spans: &[Option<usize>]) -> Option<RegexMatch> {
    let mut sub_bytes = Vec::new();
    for &[open, close] in spans.as_chunks::<2>().0 {
        let (Some(from), Some(to)) = (open, close) else {
            break;
        };
        if to < from {
            return None;
        }
        sub_bytes.push(s[from..to].to_vec());
    }
    let sub_strings = sub_bytes.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect();
    Some(RegexMatch { end, sub_strings, sub_bytes })
}

pub fn os_regex(pattern: &str, s: &str) -> bool {
    OsRegex::compile(pattern, 0).is_ok_and(|re| re.is_match(s))
}

pub fn os_word_match(pattern: &str, s: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    // Both texts stop at a NUL; a piece that starts at the NUL is empty and matches anything.
    let p = until_nul(pattern.as_bytes());
    if p.len() < pattern.len() && (p.is_empty() || p.ends_with(b"|")) {
        return true;
    }
    let s = until_nul(s.as_bytes());
    let mut from = 0;
    loop {
        // One `|` where a piece should start is skipped; running out of pattern there matches.
        if p[from] == b'|' {
            from += 1;
            if from == p.len() {
                return true;
            }
        }
        // A second `|` in that place is a one-byte piece of its own.
        let doubled = p[from] == b'|';
        let to = if doubled {
            from + 1
        } else {
            p[from..].iter().position(|&b| b == b'|').map_or(p.len(), |n| from + n)
        };
        if word_piece_matches(&p[from..to], s) {
            return true;
        }
        if to == p.len() && !doubled {
            return false;
        }
        from = if doubled { to } else { to + 1 };
        if from == p.len() {
            return true;
        }
    }
}

fn word_piece_matches(piece: &[u8], s: &[u8]) -> bool {
    match piece.split_first() {
        Some((b'^', rest)) => s.len() >= rest.len() && s[..rest.len()].eq_ignore_ascii_case(rest),
        _ => s.windows(piece.len()).any(|w| w.eq_ignore_ascii_case(piece)),
    }
}
