//! The part of nlohmann::json 3.11.2 (Wazuh's deps/54 build) the router's
//! wazuh-db endpoints use: `json::parse` (strict, exceptions on) with its
//! exact error texts, `contains`, `at`, `get<T>` and the range-for
//! iteration semantics. Errors are the exceptions' `what()` strings.

use std::collections::BTreeMap;

/// A JSON value (`basic_json` with the default types).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(Vec<u8>),
    Array(Vec<Value>),
    /// `std::map<std::string, basic_json, std::less<>>`
    Object(BTreeMap<Vec<u8>, Value>),
}

const EOF: i32 = -1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Uninitialized,
    LiteralTrue,
    LiteralFalse,
    LiteralNull,
    ValueString,
    ValueUnsigned,
    ValueInteger,
    ValueFloat,
    BeginArray,
    BeginObject,
    EndArray,
    EndObject,
    NameSeparator,
    ValueSeparator,
    ParseError,
    EndOfInput,
    LiteralOrValue,
}

fn token_type_name(t: Tok) -> &'static str {
    match t {
        Tok::Uninitialized => "<uninitialized>",
        Tok::LiteralTrue => "true literal",
        Tok::LiteralFalse => "false literal",
        Tok::LiteralNull => "null literal",
        Tok::ValueString => "string literal",
        Tok::ValueUnsigned | Tok::ValueInteger | Tok::ValueFloat => "number literal",
        Tok::BeginArray => "'['",
        Tok::BeginObject => "'{'",
        Tok::EndArray => "']'",
        Tok::EndObject => "'}'",
        Tok::NameSeparator => "':'",
        Tok::ValueSeparator => "','",
        Tok::ParseError => "<parse error>",
        Tok::EndOfInput => "end of input",
        Tok::LiteralOrValue => "'[', '{', or a literal",
    }
}

#[derive(Default, Clone, Copy)]
struct Position {
    chars_read_total: usize,
    chars_read_current_line: usize,
    lines_read: usize,
}

struct Lexer<'a> {
    input: &'a [u8],
    cursor: usize,
    current: i32,
    next_unget: bool,
    position: Position,
    token_string: Vec<u8>,
    token_buffer: Vec<u8>,
    error_message: &'static str,
    value_integer: i64,
    value_unsigned: u64,
    value_float: f64,
}

/// The control character names of the string errors.
const CONTROL: [&str; 32] = [
    "invalid string: control character U+0000 (NUL) must be escaped to \\u0000",
    "invalid string: control character U+0001 (SOH) must be escaped to \\u0001",
    "invalid string: control character U+0002 (STX) must be escaped to \\u0002",
    "invalid string: control character U+0003 (ETX) must be escaped to \\u0003",
    "invalid string: control character U+0004 (EOT) must be escaped to \\u0004",
    "invalid string: control character U+0005 (ENQ) must be escaped to \\u0005",
    "invalid string: control character U+0006 (ACK) must be escaped to \\u0006",
    "invalid string: control character U+0007 (BEL) must be escaped to \\u0007",
    "invalid string: control character U+0008 (BS) must be escaped to \\u0008 or \\b",
    "invalid string: control character U+0009 (HT) must be escaped to \\u0009 or \\t",
    "invalid string: control character U+000A (LF) must be escaped to \\u000A or \\n",
    "invalid string: control character U+000B (VT) must be escaped to \\u000B",
    "invalid string: control character U+000C (FF) must be escaped to \\u000C or \\f",
    "invalid string: control character U+000D (CR) must be escaped to \\u000D or \\r",
    "invalid string: control character U+000E (SO) must be escaped to \\u000E",
    "invalid string: control character U+000F (SI) must be escaped to \\u000F",
    "invalid string: control character U+0010 (DLE) must be escaped to \\u0010",
    "invalid string: control character U+0011 (DC1) must be escaped to \\u0011",
    "invalid string: control character U+0012 (DC2) must be escaped to \\u0012",
    "invalid string: control character U+0013 (DC3) must be escaped to \\u0013",
    "invalid string: control character U+0014 (DC4) must be escaped to \\u0014",
    "invalid string: control character U+0015 (NAK) must be escaped to \\u0015",
    "invalid string: control character U+0016 (SYN) must be escaped to \\u0016",
    "invalid string: control character U+0017 (ETB) must be escaped to \\u0017",
    "invalid string: control character U+0018 (CAN) must be escaped to \\u0018",
    "invalid string: control character U+0019 (EM) must be escaped to \\u0019",
    "invalid string: control character U+001A (SUB) must be escaped to \\u001A",
    "invalid string: control character U+001B (ESC) must be escaped to \\u001B",
    "invalid string: control character U+001C (FS) must be escaped to \\u001C",
    "invalid string: control character U+001D (GS) must be escaped to \\u001D",
    "invalid string: control character U+001E (RS) must be escaped to \\u001E",
    "invalid string: control character U+001F (US) must be escaped to \\u001F",
];

impl<'a> Lexer<'a> {
    fn new(input: &'a [u8]) -> Self {
        Lexer {
            input,
            cursor: 0,
            current: EOF,
            next_unget: false,
            position: Position::default(),
            token_string: Vec::new(),
            token_buffer: Vec::new(),
            error_message: "",
            value_integer: 0,
            value_unsigned: 0,
            value_float: 0.0,
        }
    }

    fn get(&mut self) -> i32 {
        self.position.chars_read_total += 1;
        self.position.chars_read_current_line += 1;
        if self.next_unget {
            self.next_unget = false;
        } else {
            self.current = match self.input.get(self.cursor) {
                Some(&b) => {
                    self.cursor += 1;
                    b as i32
                }
                None => EOF,
            };
        }
        if self.current != EOF {
            self.token_string.push(self.current as u8);
        }
        if self.current == b'\n' as i32 {
            self.position.lines_read += 1;
            self.position.chars_read_current_line = 0;
        }
        self.current
    }

    fn unget(&mut self) {
        self.next_unget = true;
        self.position.chars_read_total = self.position.chars_read_total.wrapping_sub(1);
        if self.position.chars_read_current_line == 0 {
            if self.position.lines_read > 0 {
                self.position.lines_read -= 1;
            }
        } else {
            self.position.chars_read_current_line -= 1;
        }
        if self.current != EOF {
            self.token_string.pop();
        }
    }

    fn add(&mut self, c: i32) {
        self.token_buffer.push(c as u8);
    }

    fn reset(&mut self) {
        self.token_buffer.clear();
        self.token_string.clear();
        self.token_string.push(self.current as u8);
    }

    fn get_token_string(&self) -> Vec<u8> {
        let mut r = Vec::new();
        for &c in &self.token_string {
            if c <= 0x1F {
                r.extend_from_slice(format!("<U+{c:04X}>").as_bytes());
            } else {
                r.push(c);
            }
        }
        r
    }

    fn get_codepoint(&mut self) -> i32 {
        let mut codepoint = 0i32;
        for factor in [12u32, 8, 4, 0] {
            let c = self.get();
            let v = if (b'0' as i32..=b'9' as i32).contains(&c) {
                c - 0x30
            } else if (b'A' as i32..=b'F' as i32).contains(&c) {
                c - 0x37
            } else if (b'a' as i32..=b'f' as i32).contains(&c) {
                c - 0x57
            } else {
                return -1;
            };
            codepoint += v << factor;
        }
        codepoint
    }

    fn next_byte_in_range(&mut self, ranges: &[i32]) -> bool {
        self.add(self.current);
        for r in ranges.chunks(2) {
            let c = self.get();
            if r[0] <= c && c <= r[1] {
                self.add(c);
            } else {
                self.error_message = "invalid string: ill-formed UTF-8 byte";
                return false;
            }
        }
        true
    }

    fn scan_string(&mut self) -> Tok {
        self.reset();
        loop {
            let c = self.get();
            match c {
                EOF => {
                    self.error_message = "invalid string: missing closing quote";
                    return Tok::ParseError;
                }
                0x22 => return Tok::ValueString,
                0x5C => {
                    match self.get() {
                        0x22 => self.add(0x22),
                        0x5C => self.add(0x5C),
                        0x2F => self.add(0x2F),
                        0x62 => self.add(0x08),
                        0x66 => self.add(0x0C),
                        0x6E => self.add(0x0A),
                        0x72 => self.add(0x0D),
                        0x74 => self.add(0x09),
                        0x75 => {
                            let codepoint1 = self.get_codepoint();
                            let mut codepoint = codepoint1;
                            if codepoint1 == -1 {
                                self.error_message = "invalid string: '\\u' must be followed by 4 hex digits";
                                return Tok::ParseError;
                            }
                            if (0xD800..=0xDBFF).contains(&codepoint1) {
                                if self.get() == 0x5C && self.get() == 0x75 {
                                    let codepoint2 = self.get_codepoint();
                                    if codepoint2 == -1 {
                                        self.error_message = "invalid string: '\\u' must be followed by 4 hex digits";
                                        return Tok::ParseError;
                                    }
                                    if (0xDC00..=0xDFFF).contains(&codepoint2) {
                                        codepoint = (((codepoint1 as u32) << 10) + codepoint2 as u32 - 0x35FDC00) as i32;
                                    } else {
                                        self.error_message =
                                            "invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF";
                                        return Tok::ParseError;
                                    }
                                } else {
                                    self.error_message = "invalid string: surrogate U+D800..U+DBFF must be followed by U+DC00..U+DFFF";
                                    return Tok::ParseError;
                                }
                            } else if (0xDC00..=0xDFFF).contains(&codepoint1) {
                                self.error_message = "invalid string: surrogate U+DC00..U+DFFF must follow U+D800..U+DBFF";
                                return Tok::ParseError;
                            }
                            let cp = codepoint as u32;
                            if cp < 0x80 {
                                self.add(cp as i32);
                            } else if cp <= 0x7FF {
                                self.add((0xC0 | (cp >> 6)) as i32);
                                self.add((0x80 | (cp & 0x3F)) as i32);
                            } else if cp <= 0xFFFF {
                                self.add((0xE0 | (cp >> 12)) as i32);
                                self.add((0x80 | ((cp >> 6) & 0x3F)) as i32);
                                self.add((0x80 | (cp & 0x3F)) as i32);
                            } else {
                                self.add((0xF0 | (cp >> 18)) as i32);
                                self.add((0x80 | ((cp >> 12) & 0x3F)) as i32);
                                self.add((0x80 | ((cp >> 6) & 0x3F)) as i32);
                                self.add((0x80 | (cp & 0x3F)) as i32);
                            }
                        }
                        _ => {
                            self.error_message = "invalid string: forbidden character after backslash";
                            return Tok::ParseError;
                        }
                    }
                }
                0x00..=0x1F => {
                    self.error_message = CONTROL[c as usize];
                    return Tok::ParseError;
                }
                0x20..=0x7F => self.add(c),
                0xC2..=0xDF => {
                    if !self.next_byte_in_range(&[0x80, 0xBF]) {
                        return Tok::ParseError;
                    }
                }
                0xE0 => {
                    if !self.next_byte_in_range(&[0xA0, 0xBF, 0x80, 0xBF]) {
                        return Tok::ParseError;
                    }
                }
                0xE1..=0xEC | 0xEE..=0xEF => {
                    if !self.next_byte_in_range(&[0x80, 0xBF, 0x80, 0xBF]) {
                        return Tok::ParseError;
                    }
                }
                0xED => {
                    if !self.next_byte_in_range(&[0x80, 0x9F, 0x80, 0xBF]) {
                        return Tok::ParseError;
                    }
                }
                0xF0 => {
                    if !self.next_byte_in_range(&[0x90, 0xBF, 0x80, 0xBF, 0x80, 0xBF]) {
                        return Tok::ParseError;
                    }
                }
                0xF1..=0xF3 => {
                    if !self.next_byte_in_range(&[0x80, 0xBF, 0x80, 0xBF, 0x80, 0xBF]) {
                        return Tok::ParseError;
                    }
                }
                0xF4 => {
                    if !self.next_byte_in_range(&[0x80, 0x8F, 0x80, 0xBF, 0x80, 0xBF]) {
                        return Tok::ParseError;
                    }
                }
                _ => {
                    self.error_message = "invalid string: ill-formed UTF-8 byte";
                    return Tok::ParseError;
                }
            }
        }
    }

    fn is_digit(c: i32) -> bool {
        (b'0' as i32..=b'9' as i32).contains(&c)
    }

    fn scan_number(&mut self) -> Tok {
        self.reset();
        let mut number_type = Tok::ValueUnsigned;
        // init
        enum S {
            Minus,
            Zero,
            Any1,
            Decimal1,
            Decimal2,
            Exponent,
            Sign,
            Any2,
            Done,
        }
        let mut s = match self.current {
            0x2D => {
                self.add(self.current);
                S::Minus
            }
            0x30 => {
                self.add(self.current);
                S::Zero
            }
            _ => {
                self.add(self.current);
                S::Any1
            }
        };
        loop {
            s = match s {
                S::Minus => {
                    number_type = Tok::ValueInteger;
                    let c = self.get();
                    if c == 0x30 {
                        self.add(c);
                        S::Zero
                    } else if Self::is_digit(c) {
                        self.add(c);
                        S::Any1
                    } else {
                        self.error_message = "invalid number; expected digit after '-'";
                        return Tok::ParseError;
                    }
                }
                S::Zero => {
                    let c = self.get();
                    if c == 0x2E {
                        self.add(0x2E);
                        S::Decimal1
                    } else if c == 0x65 || c == 0x45 {
                        self.add(c);
                        S::Exponent
                    } else {
                        S::Done
                    }
                }
                S::Any1 => {
                    let c = self.get();
                    if Self::is_digit(c) {
                        self.add(c);
                        S::Any1
                    } else if c == 0x2E {
                        self.add(0x2E);
                        S::Decimal1
                    } else if c == 0x65 || c == 0x45 {
                        self.add(c);
                        S::Exponent
                    } else {
                        S::Done
                    }
                }
                S::Decimal1 => {
                    number_type = Tok::ValueFloat;
                    let c = self.get();
                    if Self::is_digit(c) {
                        self.add(c);
                        S::Decimal2
                    } else {
                        self.error_message = "invalid number; expected digit after '.'";
                        return Tok::ParseError;
                    }
                }
                S::Decimal2 => {
                    let c = self.get();
                    if Self::is_digit(c) {
                        self.add(c);
                        S::Decimal2
                    } else if c == 0x65 || c == 0x45 {
                        self.add(c);
                        S::Exponent
                    } else {
                        S::Done
                    }
                }
                S::Exponent => {
                    number_type = Tok::ValueFloat;
                    let c = self.get();
                    if c == 0x2B || c == 0x2D {
                        self.add(c);
                        S::Sign
                    } else if Self::is_digit(c) {
                        self.add(c);
                        S::Any2
                    } else {
                        self.error_message = "invalid number; expected '+', '-', or digit after exponent";
                        return Tok::ParseError;
                    }
                }
                S::Sign => {
                    let c = self.get();
                    if Self::is_digit(c) {
                        self.add(c);
                        S::Any2
                    } else {
                        self.error_message = "invalid number; expected digit after exponent sign";
                        return Tok::ParseError;
                    }
                }
                S::Any2 => {
                    let c = self.get();
                    if Self::is_digit(c) {
                        self.add(c);
                        S::Any2
                    } else {
                        S::Done
                    }
                }
                S::Done => break,
            };
        }
        self.unget();
        let text = std::str::from_utf8(&self.token_buffer).unwrap_or("0");
        // try integers first, fall back to floats
        if number_type == Tok::ValueUnsigned {
            if let Ok(x) = text.parse::<u64>() {
                self.value_unsigned = x;
                return Tok::ValueUnsigned;
            }
        } else if number_type == Tok::ValueInteger {
            if let Ok(x) = text.parse::<i64>() {
                self.value_integer = x;
                return Tok::ValueInteger;
            }
        }
        // strtod (correctly rounded, overflow gives inf)
        self.value_float = text.parse::<f64>().unwrap_or(0.0);
        Tok::ValueFloat
    }

    fn scan_literal(&mut self, lit: &[u8], t: Tok) -> Tok {
        for &b in &lit[1..] {
            let c = self.get();
            // to_char_type(EOF) is 0xFF
            let ch = if c == EOF { 0xFF } else { c as u8 };
            if ch != b {
                self.error_message = "invalid literal";
                return Tok::ParseError;
            }
        }
        t
    }

    fn skip_bom(&mut self) -> bool {
        if self.get() == 0xEF {
            return self.get() == 0xBB && self.get() == 0xBF;
        }
        self.unget();
        true
    }

    fn scan(&mut self) -> Tok {
        if self.position.chars_read_total == 0 && !self.skip_bom() {
            self.error_message = "invalid BOM; must be 0xEF 0xBB 0xBF if given";
            return Tok::ParseError;
        }
        loop {
            self.get();
            if !matches!(self.current, 0x20 | 0x09 | 0x0A | 0x0D) {
                break;
            }
        }
        match self.current {
            0x5B => Tok::BeginArray,
            0x5D => Tok::EndArray,
            0x7B => Tok::BeginObject,
            0x7D => Tok::EndObject,
            0x3A => Tok::NameSeparator,
            0x2C => Tok::ValueSeparator,
            0x74 => self.scan_literal(b"true", Tok::LiteralTrue),
            0x66 => self.scan_literal(b"false", Tok::LiteralFalse),
            0x6E => self.scan_literal(b"null", Tok::LiteralNull),
            0x22 => self.scan_string(),
            0x2D | 0x30..=0x39 => self.scan_number(),
            0x00 | EOF => Tok::EndOfInput,
            _ => {
                self.error_message = "invalid literal";
                Tok::ParseError
            }
        }
    }
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    last_token: Tok,
}

impl<'a> Parser<'a> {
    fn get_token(&mut self) -> Tok {
        self.last_token = self.lexer.scan();
        self.last_token
    }

    fn exception_message(&self, expected: Tok, context: &str) -> Vec<u8> {
        let mut m = b"syntax error ".to_vec();
        if !context.is_empty() {
            m.extend_from_slice(format!("while parsing {context} ").as_bytes());
        }
        m.extend_from_slice(b"- ");
        if self.last_token == Tok::ParseError {
            m.extend_from_slice(self.lexer.error_message.as_bytes());
            m.extend_from_slice(b"; last read: '");
            m.extend_from_slice(&self.lexer.get_token_string());
            m.push(b'\'');
        } else {
            m.extend_from_slice(format!("unexpected {}", token_type_name(self.last_token)).as_bytes());
        }
        if expected != Tok::Uninitialized {
            m.extend_from_slice(format!("; expected {}", token_type_name(expected)).as_bytes());
        }
        m
    }

    /// `parse_error::create(101, position, what)`
    fn parse_error(&self, expected: Tok, context: &str) -> Vec<u8> {
        let p = self.lexer.position;
        let mut w =
            format!("[json.exception.parse_error.101] parse error at line {}, column {}: ", p.lines_read + 1, p.chars_read_current_line)
                .into_bytes();
        w.extend_from_slice(&self.exception_message(expected, context));
        w
    }

    /// `sax_parse_internal` with the DOM builder.
    fn parse_internal(&mut self) -> Result<Value, Vec<u8>> {
        // the containers being built, with the pending object key
        let mut stack: Vec<(Value, Option<Vec<u8>>)> = Vec::new();
        let mut skip_to_state_evaluation = false;
        let mut finished: Option<Value> = None;
        loop {
            if !skip_to_state_evaluation {
                let value = match self.last_token {
                    Tok::BeginObject => {
                        if self.get_token() == Tok::EndObject {
                            Some(Value::Object(BTreeMap::new()))
                        } else {
                            if self.last_token != Tok::ValueString {
                                return Err(self.parse_error(Tok::ValueString, "object key"));
                            }
                            let key = std::mem::take(&mut self.lexer.token_buffer);
                            if self.get_token() != Tok::NameSeparator {
                                return Err(self.parse_error(Tok::NameSeparator, "object separator"));
                            }
                            stack.push((Value::Object(BTreeMap::new()), Some(key)));
                            self.get_token();
                            continue;
                        }
                    }
                    Tok::BeginArray => {
                        if self.get_token() == Tok::EndArray {
                            Some(Value::Array(Vec::new()))
                        } else {
                            stack.push((Value::Array(Vec::new()), None));
                            continue;
                        }
                    }
                    Tok::ValueFloat => {
                        let res = self.lexer.value_float;
                        if !res.is_finite() {
                            let mut w = b"[json.exception.out_of_range.406] number overflow parsing '".to_vec();
                            w.extend_from_slice(&self.lexer.get_token_string());
                            w.push(b'\'');
                            return Err(w);
                        }
                        Some(Value::Float(res))
                    }
                    Tok::LiteralFalse => Some(Value::Bool(false)),
                    Tok::LiteralNull => Some(Value::Null),
                    Tok::LiteralTrue => Some(Value::Bool(true)),
                    Tok::ValueInteger => Some(Value::Int(self.lexer.value_integer)),
                    Tok::ValueString => Some(Value::Str(std::mem::take(&mut self.lexer.token_buffer))),
                    Tok::ValueUnsigned => Some(Value::UInt(self.lexer.value_unsigned)),
                    Tok::ParseError => return Err(self.parse_error(Tok::Uninitialized, "value")),
                    _ => return Err(self.parse_error(Tok::LiteralOrValue, "value")),
                };
                // add the parsed value to its container (or finish)
                if let Some(v) = value {
                    match stack.last_mut() {
                        None => finished = Some(v),
                        Some((Value::Array(a), _)) => a.push(v),
                        Some((Value::Object(o), key)) => {
                            // operator[]: the last duplicate wins
                            o.insert(key.take().unwrap_or_default(), v);
                        }
                        Some(_) => {}
                    }
                }
            } else {
                skip_to_state_evaluation = false;
            }

            if stack.is_empty() {
                return Ok(finished.unwrap_or(Value::Null));
            }
            let is_array = matches!(stack.last(), Some((Value::Array(_), _)));
            if is_array {
                if self.get_token() == Tok::ValueSeparator {
                    self.get_token();
                    continue;
                }
                if self.last_token == Tok::EndArray {
                    let (done, _) = stack.pop().expect("array");
                    Self::attach(&mut stack, &mut finished, done);
                    skip_to_state_evaluation = true;
                    continue;
                }
                return Err(self.parse_error(Tok::EndArray, "array"));
            } else {
                if self.get_token() == Tok::ValueSeparator {
                    if self.get_token() != Tok::ValueString {
                        return Err(self.parse_error(Tok::ValueString, "object key"));
                    }
                    let key = std::mem::take(&mut self.lexer.token_buffer);
                    if let Some((_, k)) = stack.last_mut() {
                        *k = Some(key);
                    }
                    if self.get_token() != Tok::NameSeparator {
                        return Err(self.parse_error(Tok::NameSeparator, "object separator"));
                    }
                    self.get_token();
                    continue;
                }
                if self.last_token == Tok::EndObject {
                    let (done, _) = stack.pop().expect("object");
                    Self::attach(&mut stack, &mut finished, done);
                    skip_to_state_evaluation = true;
                    continue;
                }
                return Err(self.parse_error(Tok::EndObject, "object"));
            }
        }
    }

    fn attach(stack: &mut [(Value, Option<Vec<u8>>)], finished: &mut Option<Value>, v: Value) {
        match stack.last_mut() {
            None => *finished = Some(v),
            Some((Value::Array(a), _)) => a.push(v),
            Some((Value::Object(o), key)) => {
                o.insert(key.take().unwrap_or_default(), v);
            }
            Some(_) => {}
        }
    }
}

/// `nlohmann::json::parse(s)` (strict): the value or the exception text.
pub fn parse(s: &[u8]) -> Result<Value, Vec<u8>> {
    let mut p = Parser { lexer: Lexer::new(s), last_token: Tok::Uninitialized };
    p.get_token();
    let v = p.parse_internal()?;
    if p.get_token() != Tok::EndOfInput {
        return Err(p.parse_error(Tok::EndOfInput, "value"));
    }
    Ok(v)
}

/// `static_cast<int64_t>(double)` on x86-64 (cvttsd2si): out of range and
/// NaN give INT64_MIN.
pub fn f64_to_i64(d: f64) -> i64 {
    if d.is_nan() || d >= 9.223372036854775807e18 || d < -9.223372036854775808e18 {
        i64::MIN
    } else {
        d as i64
    }
}

impl Value {
    /// `type_name()`
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Object(_) => "object",
            Value::Array(_) => "array",
            Value::Str(_) => "string",
            Value::Bool(_) => "boolean",
            _ => "number",
        }
    }

    /// `contains(key)`: false for non objects.
    pub fn contains(&self, key: &str) -> bool {
        match self {
            Value::Object(o) => o.contains_key(key.as_bytes()),
            _ => false,
        }
    }

    /// `at(key)` on an object known to contain it.
    pub fn at(&self, key: &str) -> Result<&Value, Vec<u8>> {
        match self {
            Value::Object(o) => match o.get(key.as_bytes()) {
                Some(v) => Ok(v),
                None => Err(format!("[json.exception.out_of_range.403] key '{key}' not found").into_bytes()),
            },
            v => Err(format!("[json.exception.type_error.304] cannot use at() with {}", v.type_name()).into_bytes()),
        }
    }

    /// `get<int64_t>()`
    pub fn get_i64(&self) -> Result<i64, Vec<u8>> {
        match self {
            Value::UInt(u) => Ok(*u as i64),
            Value::Int(i) => Ok(*i),
            Value::Float(f) => Ok(f64_to_i64(*f)),
            v => Err(format!("[json.exception.type_error.302] type must be number, but is {}", v.type_name()).into_bytes()),
        }
    }

    /// `get<std::string_view>()`
    pub fn get_str(&self) -> Result<&[u8], Vec<u8>> {
        match self {
            Value::Str(s) => Ok(s),
            v => Err(format!("[json.exception.type_error.302] type must be string, but is {}", v.type_name()).into_bytes()),
        }
    }

    /// `get<bool>()`
    pub fn get_bool(&self) -> Result<bool, Vec<u8>> {
        match self {
            Value::Bool(b) => Ok(*b),
            v => Err(format!("[json.exception.type_error.302] type must be boolean, but is {}", v.type_name()).into_bytes()),
        }
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }

    pub fn is_boolean(&self) -> bool {
        matches!(self, Value::Bool(_))
    }

    /// `size()`
    pub fn size(&self) -> usize {
        match self {
            Value::Null => 0,
            Value::Array(a) => a.len(),
            Value::Object(o) => o.len(),
            _ => 1,
        }
    }

    /// `for (const auto& x : j)`: the elements of an array, the values of an
    /// object (in key order), nothing for null, the value itself otherwise.
    pub fn iter(&self) -> Vec<&Value> {
        match self {
            Value::Null => Vec::new(),
            Value::Array(a) => a.iter().collect(),
            Value::Object(o) => o.values().collect(),
            v => vec![v],
        }
    }
}

/// `dump_escaped(s, ensure_ascii = false)` with the strict error handler.
fn dump_string(out: &mut Vec<u8>, s: &[u8]) -> Result<(), Vec<u8>> {
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        // the length of a valid UTF-8 sequence starting here
        let n = match c {
            0x00..=0x7F => 1,
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => 0,
        };
        let valid = n > 0 && i + n <= s.len() && {
            let b = &s[i..i + n];
            match n {
                1 => true,
                2 => (0x80..=0xBF).contains(&b[1]),
                3 => {
                    let lo = if b[0] == 0xE0 { 0xA0 } else { 0x80 };
                    let hi = if b[0] == 0xED { 0x9F } else { 0xBF };
                    (lo..=hi).contains(&b[1]) && (0x80..=0xBF).contains(&b[2])
                }
                _ => {
                    let lo = if b[0] == 0xF0 { 0x90 } else { 0x80 };
                    let hi = if b[0] == 0xF4 { 0x8F } else { 0xBF };
                    (lo..=hi).contains(&b[1]) && (0x80..=0xBF).contains(&b[2]) && (0x80..=0xBF).contains(&b[3])
                }
            }
        };
        if !valid {
            if n > 0 && i + n > s.len() && s[i + 1..].iter().all(|&x| (0x80..=0xBF).contains(&x)) {
                return Err(format!("[json.exception.type_error.316] incomplete UTF-8 string; last byte: 0x{:02X}", s[s.len() - 1]).into_bytes());
            }
            let bad = if n == 0 { i } else { (i + 1..s.len().min(i + n)).find(|&k| !(0x80..=0xBF).contains(&s[k])).unwrap_or(i) };
            return Err(format!("[json.exception.type_error.316] invalid UTF-8 byte at index {}: 0x{:02X}", bad, s[bad]).into_bytes());
        }
        if n == 1 {
            match c {
                0x08 => out.extend_from_slice(b"\\b"),
                0x09 => out.extend_from_slice(b"\\t"),
                0x0A => out.extend_from_slice(b"\\n"),
                0x0C => out.extend_from_slice(b"\\f"),
                0x0D => out.extend_from_slice(b"\\r"),
                0x22 => out.extend_from_slice(b"\\\""),
                0x5C => out.extend_from_slice(b"\\\\"),
                0x00..=0x1F => out.extend_from_slice(format!("\\u{c:04x}").as_bytes()),
                _ => out.push(c),
            }
        } else {
            out.extend_from_slice(&s[i..i + n]);
        }
        i += n;
    }
    out.push(b'"');
    Ok(())
}

impl Value {
    /// `dump()` (compact). Floats are not used by the callers.
    pub fn dump(&self) -> Result<Vec<u8>, Vec<u8>> {
        let mut out = Vec::new();
        self.dump_into(&mut out)?;
        Ok(out)
    }

    fn dump_into(&self, out: &mut Vec<u8>) -> Result<(), Vec<u8>> {
        match self {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
            Value::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
            Value::UInt(u) => out.extend_from_slice(u.to_string().as_bytes()),
            Value::Float(f) => out.extend_from_slice(format!("{f}").as_bytes()),
            Value::Str(s) => dump_string(out, s)?,
            Value::Array(a) => {
                out.push(b'[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    v.dump_into(out)?;
                }
                out.push(b']');
            }
            Value::Object(o) => {
                out.push(b'{');
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    dump_string(out, k)?;
                    out.push(b':');
                    v.dump_into(out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }

    /// An object from (key, string) pairs (`json["k"] = "v"`).
    pub fn object_of(pairs: &[(&str, &[u8])]) -> Value {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert(k.as_bytes().to_vec(), Value::Str(v.to_vec()));
        }
        Value::Object(m)
    }

    /// `get_ref<const std::string&>()`
    pub fn get_ref_str(&self) -> Result<&[u8], Vec<u8>> {
        match self {
            Value::Str(s) => Ok(s),
            v => Err(format!("[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is {}", v.type_name()).into_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(s: &str) -> String {
        String::from_utf8(parse(s.as_bytes()).unwrap_err()).unwrap()
    }

    #[test]
    fn messages() {
        assert_eq!(
            err("x"),
            "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - invalid literal; last read: 'x'"
        );
        assert_eq!(
            err(""),
            "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal"
        );
        assert!(parse(b"{}\0junk").is_ok());
        assert_eq!(err("1e999"), "[json.exception.out_of_range.406] number overflow parsing '1e999'");
    }
}
