//! The part of flatbuffers 23.5.26 (Wazuh's deps/54 build, with Wazuh's
//! `zero_on_float_to_int` option) the router uses: `flatbuffers::Parser`
//! reading a schema and then JSON (`Parser::Parse`), and the
//! `FlatBufferBuilder` that lays the binary out. Byte-identical output and
//! identical `error_` texts are the goal.
//!
//! Schemas: namespaces, tables, enums, unions of tables, scalars, strings,
//! vectors (of scalars, strings and tables), defaults (`= null` included)
//! and the attributes `deprecated`, `required`, `id`, `original_order`;
//! code-generation-only attributes are accepted. Structs, fixed arrays,
//! vectors of unions, includes, rpc services, proto mode and the attributes
//! that change the binary otherwise (`key`, `shared`, `hash`,
//! `force_align`, `bit_flags`, `flexbuffer`, `nested_flatbuffer`,
//! `offset64`, `vector64`) are refused with an error: Wazuh's schemas use
//! none of them.
//!
//! JSON: the whole of `ParseTable`/`ParseAnyValue`/`ParseSingleValue` for
//! those types (unions with the type field before or after the value,
//! tables written as arrays, `null`, enum names, numbers in strings,
//! conversion functions such as `cos(1)`, comments, `$schema`,
//! unknown-field skipping) with the C library's `strtod`/`strtoll` rules.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;

// ---------------------------------------------------------------- types

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BaseType {
    None,
    UType,
    Bool,
    Char,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    Float,
    Double,
    String,
    Vector,
    Struct,
    Union,
    /// fixed-length array (structs only: always refused in tables)
    Array,
}

use BaseType as B;

impl BaseType {
    fn is_scalar(self) -> bool {
        !matches!(self, B::None | B::String | B::Vector | B::Struct | B::Union | B::Array)
    }
    fn is_integer(self) -> bool {
        matches!(self, B::UType | B::Bool | B::Char | B::UChar | B::Short | B::UShort | B::Int | B::UInt | B::Long | B::ULong)
    }
    fn is_float(self) -> bool {
        matches!(self, B::Float | B::Double)
    }
    fn is_unsigned(self) -> bool {
        matches!(self, B::UType | B::UChar | B::UShort | B::UInt | B::ULong)
    }
    /// `SizeOf`
    fn size_of(self) -> usize {
        match self {
            B::None | B::UType | B::Bool | B::Char | B::UChar => 1,
            B::Short | B::UShort => 2,
            B::Int | B::UInt | B::Float => 4,
            B::Long | B::ULong | B::Double => 8,
            B::String | B::Vector | B::Struct | B::Union | B::Array => 4,
        }
    }
    /// `TypeName`
    fn name(self) -> &'static str {
        match self {
            B::Bool => "bool",
            B::Char => "byte",
            B::UChar => "ubyte",
            B::Short => "short",
            B::UShort => "ushort",
            B::Int => "int",
            B::UInt => "uint",
            B::Long => "long",
            B::ULong => "ulong",
            B::Float => "float",
            B::Double => "double",
            B::String => "string",
            _ => "",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Type {
    base: BaseType,
    element: BaseType,
    struct_def: Option<usize>,
    enum_def: Option<usize>,
}

impl Type {
    fn new(base: BaseType) -> Type {
        Type { base, element: B::None, struct_def: None, enum_def: None }
    }
    /// `VectorType()`
    fn vector_type(&self) -> Type {
        Type { base: self.element, element: B::None, struct_def: self.struct_def, enum_def: self.enum_def }
    }
}

#[derive(Clone, Debug)]
struct Value {
    ty: Type,
    constant: Vec<u8>,
    offset: u16,
}

impl Value {
    fn new(ty: Type) -> Value {
        Value { ty, constant: b"0".to_vec(), offset: 0xFFFF }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Presence {
    Default,
    Optional,
    Required,
}

#[derive(Clone, Debug)]
struct FieldDef {
    name: Vec<u8>,
    value: Value,
    presence: Presence,
    deprecated: bool,
    attributes: Vec<(Vec<u8>, Value)>,
}

impl FieldDef {
    fn attr(&self, name: &str) -> Option<&Value> {
        self.attributes.iter().find(|(n, _)| n == name.as_bytes()).map(|(_, v)| v)
    }
    fn is_scalar_optional(&self) -> bool {
        self.value.ty.base.is_scalar() && self.presence == Presence::Optional
    }
}

#[derive(Clone, Debug, Default)]
struct StructDef {
    name: Vec<u8>,
    ns: Vec<Vec<u8>>,
    fields: Vec<FieldDef>,
    predecl: bool,
    sortbysize: bool,
    original_location: Option<Vec<u8>>,
}

impl StructDef {
    fn lookup(&self, name: &[u8]) -> Option<usize> {
        self.fields.iter().position(|f| f.name == name)
    }
}

#[derive(Clone, Debug)]
struct EnumVal {
    name: Vec<u8>,
    value: i64,
    union_type: Type,
}

#[derive(Clone, Debug)]
struct EnumDef {
    name: Vec<u8>,
    is_union: bool,
    underlying: Type,
    /// sorted by value once declared
    vals: Vec<EnumVal>,
}

impl EnumDef {
    fn lookup(&self, name: &[u8]) -> Option<&EnumVal> {
        self.vals.iter().find(|v| v.name == name)
    }
    fn is_uint64(&self) -> bool {
        self.underlying.base == B::ULong
    }
    /// `ReverseLookup(enum_idx, skip_union_default)`
    fn reverse_lookup(&self, idx: i64, skip_union_default: bool) -> Option<&EnumVal> {
        let skip = (self.is_union && skip_union_default) as usize;
        self.vals.iter().skip(skip).find(|v| v.value == idx)
    }
}

/// A symbol table (`SymbolTable<T>`): declaration order plus a dictionary.
#[derive(Default)]
struct Symbols {
    dict: HashMap<Vec<u8>, usize>,
}

// -------------------------------------------------------------- builder

/// `FlatBufferBuilder` (`vector_downward` storage, vtable deduplication).
pub struct Builder {
    buf: Vec<u8>,
    size: usize,
    vtables: Vec<u32>,
    field_locs: Vec<(u32, u16)>,
    max_voffset: u16,
    minalign: usize,
}

impl Default for Builder {
    fn default() -> Self {
        Builder { buf: vec![0; 1024], size: 0, vtables: Vec::new(), field_locs: Vec::new(), max_voffset: 0, minalign: 1 }
    }
}

fn padding_bytes(buf_size: usize, scalar_size: usize) -> usize {
    (!buf_size).wrapping_add(1) & (scalar_size - 1)
}

impl Builder {
    /// `Clear()`
    pub fn clear(&mut self) {
        self.clear_offsets();
        self.size = 0;
        self.vtables.clear();
        self.minalign = 1;
    }

    /// `GetSize()`
    pub fn size(&self) -> usize {
        self.size
    }

    /// The finished buffer (`GetBufferPointer()`, `GetSize()` bytes).
    pub fn data(&self) -> &[u8] {
        &self.buf[self.buf.len() - self.size..]
    }

    fn head(&self) -> usize {
        self.buf.len() - self.size
    }

    fn ensure(&mut self, n: usize) {
        if self.size + n > self.buf.len() {
            let cap = (self.buf.len() * 2).max(self.size + n);
            let mut nb = vec![0u8; cap];
            let l = nb.len();
            nb[l - self.size..].copy_from_slice(self.data());
            self.buf = nb;
        }
    }

    fn fill(&mut self, n: usize) {
        self.ensure(n);
        let h = self.head();
        self.buf[h - n..h].fill(0);
        self.size += n;
    }

    fn push_bytes(&mut self, b: &[u8]) {
        self.ensure(b.len());
        let h = self.head();
        self.buf[h - b.len()..h].copy_from_slice(b);
        self.size += b.len();
    }

    fn pop(&mut self, n: usize) {
        self.size -= n;
    }

    fn track_min_align(&mut self, a: usize) {
        if a > self.minalign {
            self.minalign = a;
        }
    }

    fn align(&mut self, elem: usize) {
        self.track_min_align(elem);
        self.fill(padding_bytes(self.size, elem));
    }

    fn pre_align(&mut self, len: usize, alignment: usize) {
        if len == 0 {
            return;
        }
        self.track_min_align(alignment);
        self.fill(padding_bytes(self.size + len, alignment));
    }

    /// `PushElement(T)`: the scalar's little-endian bytes.
    fn push_scalar(&mut self, b: &[u8]) -> u32 {
        self.align(b.len());
        self.push_bytes(b);
        self.size as u32
    }

    fn refer_to(&mut self, off: u32) -> u32 {
        self.align(4);
        (self.size as u32).wrapping_sub(off).wrapping_add(4)
    }

    fn track_field(&mut self, field: u16, off: u32) {
        self.field_locs.push((off, field));
        if field > self.max_voffset {
            self.max_voffset = field;
        }
    }

    fn add_scalar(&mut self, field: u16, b: &[u8]) {
        let off = self.push_scalar(b);
        self.track_field(field, off);
    }

    fn add_offset(&mut self, field: u16, off: u32) {
        if off == 0 {
            return;
        }
        let r = self.refer_to(off);
        if r == 0 {
            return;
        }
        self.add_scalar(field, &r.to_le_bytes());
    }

    fn clear_offsets(&mut self) {
        self.field_locs.clear();
        self.max_voffset = 0;
    }

    fn start_table(&mut self) -> u32 {
        self.size as u32
    }

    fn end_table(&mut self, start: u32) -> u32 {
        let vtable_offset_loc = self.push_scalar(&0i32.to_le_bytes());
        self.max_voffset = (self.max_voffset.wrapping_add(2)).max(4);
        self.fill(self.max_voffset as usize);
        let table_object_size = vtable_offset_loc.wrapping_sub(start);
        let h = self.head();
        self.buf[h + 2..h + 4].copy_from_slice(&(table_object_size as u16).to_le_bytes());
        self.buf[h..h + 2].copy_from_slice(&self.max_voffset.to_le_bytes());
        for &(off, id) in &self.field_locs {
            let pos = vtable_offset_loc.wrapping_sub(off) as u16;
            let i = h + id as usize;
            self.buf[i..i + 2].copy_from_slice(&pos.to_le_bytes());
        }
        self.clear_offsets();
        let vt1_size = u16::from_le_bytes([self.buf[h], self.buf[h + 1]]) as usize;
        let mut vt_use = self.size as u32;
        for &vt_off in &self.vtables {
            let i = self.buf.len() - vt_off as usize;
            let vt2_size = u16::from_le_bytes([self.buf[i], self.buf[i + 1]]) as usize;
            if vt1_size != vt2_size || self.buf[i..i + vt1_size] != self.buf[h..h + vt1_size] {
                continue;
            }
            vt_use = vt_off;
            let n = self.size - vtable_offset_loc as usize;
            self.pop(n);
            break;
        }
        if vt_use as usize == self.size {
            self.vtables.push(vt_use);
        }
        let i = self.buf.len() - vtable_offset_loc as usize;
        let rel = (vt_use as i32).wrapping_sub(vtable_offset_loc as i32);
        self.buf[i..i + 4].copy_from_slice(&rel.to_le_bytes());
        vtable_offset_loc
    }

    /// `CreateString(str, len)`
    fn create_string(&mut self, s: &[u8]) -> u32 {
        self.pre_align(s.len() + 1, 4);
        self.fill(1);
        self.push_bytes(s);
        self.push_scalar(&(s.len() as u32).to_le_bytes());
        self.size as u32
    }

    fn start_vector(&mut self, len: usize, elemsize: usize, alignment: usize) {
        self.pre_align(len * elemsize, 4);
        self.pre_align(len * elemsize, alignment);
    }

    fn end_vector(&mut self, len: usize) -> u32 {
        self.push_scalar(&(len as u32).to_le_bytes())
    }

    /// `Finish(root, file_identifier)`
    fn finish(&mut self, root: u32, file_identifier: Option<&[u8]>) {
        self.vtables.clear();
        self.track_min_align(0);
        let id_size = if file_identifier.is_some() { 4 } else { 0 };
        let minalign = self.minalign;
        self.pre_align(4 + id_size, minalign);
        if let Some(id) = file_identifier {
            self.push_bytes(id);
        }
        let r = self.refer_to(root);
        self.push_scalar(&r.to_le_bytes());
    }
}

// --------------------------------------------------------------- numbers

fn c_str(s: &[u8]) -> CString {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    CString::new(&s[..end]).unwrap()
}

/// The string the C++ sees through `c_str()`.
fn c_view(s: &[u8]) -> &[u8] {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    &s[..end]
}

fn set_errno(v: i32) {
    unsafe { *libc::__errno_location() = v }
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_xdigit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn is_alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

fn is_alpha_char(c: u8, alpha: u8) -> bool {
    (c & 0xDF) == (alpha & 0xDF)
}

fn is_identifier_start(c: u8) -> bool {
    is_alpha(c) || c == b'_'
}

/// `StringToIntegerImpl` for int64 (`strtoll`) or uint64 (`strtoull`).
fn string_to_integer(s: &[u8], base: i32, check_errno: bool, unsigned: bool) -> (bool, u64) {
    let cs = c_str(s);
    let b = cs.as_bytes_with_nul();
    if base <= 0 {
        let mut i = 0;
        while b[i] != 0 && !is_digit(b[i]) {
            i += 1;
        }
        if b[i] == b'0' && is_alpha_char(b[i + 1], b'X') {
            return string_to_integer(s, 16, check_errno, unsigned);
        }
        return string_to_integer(s, 10, check_errno, unsigned);
    }
    if check_errno {
        set_errno(0);
    }
    let mut end: *mut libc::c_char = std::ptr::null_mut();
    let v = unsafe {
        if unsigned {
            libc::strtoull(cs.as_ptr(), &mut end, base) as u64
        } else {
            libc::strtoll(cs.as_ptr(), &mut end, base) as u64
        }
    };
    let consumed = end as usize - cs.as_ptr() as usize;
    if b[consumed] != 0 || consumed == 0 {
        return (false, 0);
    }
    if check_errno && errno() != 0 {
        return (false, v);
    }
    (true, v)
}

/// A parsed scalar (`CTYPE val`).
#[derive(Clone, Copy, Debug)]
enum Num {
    I(i64),
    U(u64),
    F32(f32),
    F64(f64),
}

impl Num {
    fn le_bytes(self, bt: BaseType) -> Vec<u8> {
        match self {
            Num::I(v) => v.to_le_bytes()[..bt.size_of()].to_vec(),
            Num::U(v) => v.to_le_bytes()[..bt.size_of()].to_vec(),
            Num::F32(v) => v.to_le_bytes().to_vec(),
            Num::F64(v) => v.to_le_bytes().to_vec(),
        }
    }
    /// `IsTheSameAs`
    fn same_as(self, d: Num) -> bool {
        match (self, d) {
            (Num::I(a), Num::I(b)) => a == b,
            (Num::U(a), Num::U(b)) => a == b,
            (Num::F32(a), Num::F32(b)) => a == b || (b.is_nan() && a.is_nan()),
            (Num::F64(a), Num::F64(b)) => a == b || (b.is_nan() && a.is_nan()),
            _ => false,
        }
    }
}

/// (lowest, max) of the C type, as text (`TypeToIntervalString<T>`).
fn interval(bt: BaseType) -> String {
    let (lo, hi): (i128, i128) = match bt {
        B::Char => (i8::MIN as i128, i8::MAX as i128),
        B::UType | B::Bool | B::UChar => (0, u8::MAX as i128),
        B::Short => (i16::MIN as i128, i16::MAX as i128),
        B::UShort => (0, u16::MAX as i128),
        B::Int => (i32::MIN as i128, i32::MAX as i128),
        B::UInt => (0, u32::MAX as i128),
        B::Long => (i64::MIN as i128, i64::MAX as i128),
        _ => (0, u64::MAX as i128),
    };
    format!("[{lo}; {hi}]")
}

fn int_range(bt: BaseType) -> (i64, i64) {
    match bt {
        B::Char => (i8::MIN as i64, i8::MAX as i64),
        B::UType | B::Bool | B::UChar => (0, u8::MAX as i64),
        B::Short => (i16::MIN as i64, i16::MAX as i64),
        B::UShort => (0, u16::MAX as i64),
        B::Int => (i32::MIN as i64, i32::MAX as i64),
        _ => (0, u32::MAX as i64),
    }
}

/// `StringToNumber<T>`: (done, value as stored in `*val`).
fn string_to_number(s: &[u8], bt: BaseType) -> (bool, Num) {
    match bt {
        B::Long => {
            let (ok, v) = string_to_integer(s, 0, true, false);
            (ok, Num::I(v as i64))
        }
        B::ULong => {
            let (ok, v) = string_to_integer(s, 0, true, true);
            if !ok {
                return (false, Num::U(v));
            }
            if v != 0 {
                let b = c_view(s);
                let mut i = 0;
                while i < b.len() && !is_digit(b[i]) {
                    i += 1;
                }
                let j = if i > 0 { i - 1 } else { i };
                if b.get(j) == Some(&b'-') {
                    return (false, Num::U(u64::MAX));
                }
            }
            (true, Num::U(v))
        }
        B::Float | B::Double => {
            let cs = c_str(s);
            let mut end: *mut libc::c_char = std::ptr::null_mut();
            let (v32, v64) = unsafe {
                if bt == B::Float {
                    (libc::strtof(cs.as_ptr(), &mut end), 0.0)
                } else {
                    (0.0, libc::strtod(cs.as_ptr(), &mut end))
                }
            };
            let consumed = end as usize - cs.as_ptr() as usize;
            let done = consumed != 0 && cs.as_bytes_with_nul()[consumed] == 0;
            if bt == B::Float {
                let v = if !done { 0.0 } else if v32.is_nan() { f32::NAN } else { v32 };
                (done, Num::F32(v))
            } else {
                let v = if !done { 0.0 } else if v64.is_nan() { f64::NAN } else { v64 };
                (done, Num::F64(v))
            }
        }
        _ => {
            let (ok, v) = string_to_integer(s, 0, false, false);
            if !ok {
                return (false, Num::I(0));
            }
            let i = v as i64;
            let (min, max) = int_range(bt);
            if i > max {
                return (false, Num::I(max));
            }
            if i < min {
                return (false, Num::I(if bt.is_unsigned() { max } else { min }));
            }
            (true, Num::I(i))
        }
    }
}

/// `FloatToString(t, precision)`
fn float_to_string(t: f64, precision: i32) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let fmt = CString::new("%.*f").unwrap();
    let n = unsafe { libc::snprintf(buf.as_mut_ptr() as *mut libc::c_char, buf.len(), fmt.as_ptr(), precision as libc::c_int, t) };
    if n as usize >= buf.len() {
        buf = vec![0u8; n as usize + 1];
        unsafe { libc::snprintf(buf.as_mut_ptr() as *mut libc::c_char, buf.len(), fmt.as_ptr(), precision as libc::c_int, t) };
    }
    buf.truncate(n as usize);
    if let Some(p) = buf.iter().rposition(|&c| c != b'0') {
        let keep = p + if buf[p] == b'.' { 2 } else { 1 };
        buf.truncate(keep);
    }
    buf
}

fn num_to_string_i(v: i64) -> Vec<u8> {
    v.to_string().into_bytes()
}

// ---------------------------------------------------------------- parser

const K_TOKEN_EOF: i32 = 256;
const K_TOKEN_STRING_CONSTANT: i32 = 257;
const K_TOKEN_INTEGER_CONSTANT: i32 = 258;
const K_TOKEN_FLOAT_CONSTANT: i32 = 259;
const K_TOKEN_IDENTIFIER: i32 = 260;

/// `FLATBUFFERS_MAX_PARSING_DEPTH`
const MAX_PARSING_DEPTH: i32 = 64;

fn token_to_string(t: i32) -> Vec<u8> {
    match t {
        K_TOKEN_EOF => b"end of file".to_vec(),
        K_TOKEN_STRING_CONSTANT => b"string constant".to_vec(),
        K_TOKEN_INTEGER_CONSTANT => b"integer constant".to_vec(),
        K_TOKEN_FLOAT_CONSTANT => b"float constant".to_vec(),
        K_TOKEN_IDENTIFIER => b"identifier".to_vec(),
        _ => vec![t as u8],
    }
}

macro_rules! cat {
    ($($e:expr),* $(,)?) => {{
        let mut v: Vec<u8> = Vec::new();
        $( v.extend_from_slice(AsRef::<[u8]>::as_ref(&$e)); )*
        v
    }};
}

/// A failed `CheckedError`; the text is in `Parser::error`.
#[derive(Debug)]
pub struct Fail;

type R<T = ()> = Result<T, Fail>;

/// `IDLOptions` (the ones that matter here).
#[derive(Clone, Debug)]
pub struct Options {
    pub skip_unexpected_fields_in_json: bool,
    pub zero_on_float_to_int: bool,
}

#[derive(Clone)]
struct State {
    cursor: usize,
    line_start: usize,
    line: i32,
    token: i32,
    attr_is_trivial_ascii_string: bool,
    attribute: Vec<u8>,
    prev_cursor: usize,
}

type FieldRef = (usize, usize);

const KNOWN_ATTRIBUTES: &[&str] = &[
    "deprecated", "required", "key", "shared", "hash", "id", "force_align", "bit_flags", "original_order",
    "nested_flatbuffer", "csharp_partial", "streaming", "idempotent", "cpp_type", "cpp_ptr_type", "cpp_ptr_type_get",
    "cpp_str_type", "cpp_str_flex_ctor", "native_inline", "native_custom_alloc", "native_type", "native_type_pack_name",
    "native_default", "flexbuffer", "private", "offset64", "vector64",
];

/// Attributes that change the binary in ways this port does not implement.
const UNSUPPORTED_ATTRIBUTES: &[&str] =
    &["key", "shared", "hash", "force_align", "bit_flags", "flexbuffer", "nested_flatbuffer", "offset64", "vector64"];

/// `flatbuffers::Parser`
pub struct Parser {
    pub opts: Options,
    /// `error_`
    pub error: Vec<u8>,
    pub builder: Builder,

    src: Vec<u8>,
    st: State,
    depth: i32,
    field_stack: Vec<(Value, Option<FieldRef>)>,

    structs: Vec<StructDef>,
    /// declaration order (`structs_.vec`)
    struct_order: Vec<usize>,
    struct_syms: Symbols,
    enums: Vec<EnumDef>,
    enum_syms: Symbols,
    types: HashSet<Vec<u8>>,
    current_ns: Vec<Vec<u8>>,
    root: Option<usize>,
    file_identifier: Vec<u8>,
    known_attributes: HashSet<Vec<u8>>,
}

impl Default for Parser {
    fn default() -> Self {
        Parser::new()
    }
}

impl Parser {
    pub fn new() -> Parser {
        Parser {
            opts: Options { skip_unexpected_fields_in_json: false, zero_on_float_to_int: false },
            error: Vec::new(),
            builder: Builder::default(),
            src: vec![0],
            st: State {
                cursor: 0,
                line_start: 0,
                line: 0,
                token: -1,
                attr_is_trivial_ascii_string: true,
                attribute: Vec::new(),
                prev_cursor: 0,
            },
            depth: 0,
            field_stack: Vec::new(),
            structs: Vec::new(),
            struct_order: Vec::new(),
            struct_syms: Symbols::default(),
            enums: Vec::new(),
            enum_syms: Symbols::default(),
            types: HashSet::new(),
            current_ns: Vec::new(),
            root: None,
            file_identifier: Vec::new(),
            known_attributes: KNOWN_ATTRIBUTES.iter().map(|s| s.as_bytes().to_vec()).collect(),
        }
    }

    // ------------------------------------------------------- errors

    fn message(&mut self, msg: &[u8]) {
        if !self.error.is_empty() {
            self.error.push(b'\n');
        }
        let pos = self.st.cursor - self.st.line_start;
        self.error.extend_from_slice(format!("{}: {}", self.st.line, pos).as_bytes());
        self.error.extend_from_slice(b": ");
        self.error.extend_from_slice(msg);
    }

    /// `Warning(msg)` (warnings are on: they end up in `error_` too)
    fn warning(&mut self, msg: impl AsRef<[u8]>) {
        let m = cat!(b"warning: ", msg.as_ref());
        self.message(&m);
    }

    fn err<T>(&mut self, msg: impl AsRef<[u8]>) -> R<T> {
        let m = cat!(b"error: ", msg.as_ref());
        self.message(&m);
        Err(Fail)
    }

    /// `ParseDepthGuard`: run `f` one level deeper.
    fn guarded<T>(&mut self, f: impl FnOnce(&mut Parser) -> R<T>) -> R<T> {
        let caller_depth = self.depth;
        self.depth += 1;
        let r = if caller_depth >= MAX_PARSING_DEPTH {
            let d = self.depth;
            self.err(format!("maximum parsing depth {d} reached"))
        } else {
            f(self)
        };
        self.depth -= 1;
        r
    }

    // -------------------------------------------------------- lexer

    fn at(&self, i: usize) -> u8 {
        self.src.get(i).copied().unwrap_or(0)
    }

    fn cur(&self) -> u8 {
        self.at(self.st.cursor)
    }

    fn mark_new_line(&mut self) {
        self.st.line_start = self.st.cursor;
        self.st.line += 1;
    }

    fn parse_hex_num(&mut self, nibbles: usize) -> R<u64> {
        for i in 0..nibbles {
            if !is_xdigit(self.at(self.st.cursor + i)) {
                return self.err(format!("escape code must be followed by {nibbles} hex digits"));
            }
        }
        let s = &self.src[self.st.cursor..self.st.cursor + nibbles];
        let v = u64::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap();
        self.st.cursor += nibbles;
        Ok(v)
    }

    fn skip_byte_order_mark(&mut self) -> R {
        if self.cur() != 0xef {
            return Ok(());
        }
        self.st.cursor += 1;
        if self.cur() != 0xbb {
            return self.err("invalid utf-8 byte order mark");
        }
        self.st.cursor += 1;
        if self.cur() != 0xbf {
            return self.err("invalid utf-8 byte order mark");
        }
        self.st.cursor += 1;
        Ok(())
    }

    fn to_utf8(cp: u32, out: &mut Vec<u8>) {
        for i in 0..6u32 {
            let max_bits = 6 + i * 5 + (i == 0) as u32;
            if cp < (1u32 << max_bits) {
                let remain_bits = i * 6;
                out.push(((0xFEu32 << (max_bits - remain_bits)) | (cp >> remain_bits)) as u8);
                for j in (0..i).rev() {
                    out.push((((cp >> (j * 6)) & 0x3F) | 0x80) as u8);
                }
                return;
            }
        }
    }

    /// `Next()`
    fn next(&mut self) -> R {
        self.st.prev_cursor = self.st.cursor;
        let mut seen_newline = self.st.cursor == 0;
        self.st.attribute.clear();
        self.st.attr_is_trivial_ascii_string = true;
        loop {
            let mut c = self.cur();
            self.st.cursor += 1;
            self.st.token = c as i32;
            match c {
                0 => {
                    self.st.cursor -= 1;
                    self.st.token = K_TOKEN_EOF;
                    return Ok(());
                }
                b' ' | b'\r' | b'\t' => {}
                b'\n' => {
                    self.mark_new_line();
                    seen_newline = true;
                }
                b'{' | b'}' | b'(' | b')' | b'[' | b']' | b'<' | b'>' | b',' | b':' | b';' | b'=' => return Ok(()),
                b'"' | b'\'' => {
                    let mut unicode_high_surrogate: i64 = -1;
                    while self.cur() != c {
                        let ch = self.cur();
                        if ch < b' ' {
                            return self.err("illegal character in string constant");
                        }
                        if ch == b'\\' {
                            self.st.attr_is_trivial_ascii_string = false;
                            self.st.cursor += 1;
                            if unicode_high_surrogate != -1 && self.cur() != b'u' {
                                return self.err("illegal Unicode sequence (unpaired high surrogate)");
                            }
                            let e = self.cur();
                            let simple = match e {
                                b'n' => Some(b'\n'),
                                b't' => Some(b'\t'),
                                b'r' => Some(b'\r'),
                                b'b' => Some(0x08),
                                b'f' => Some(0x0c),
                                b'"' => Some(b'"'),
                                b'\'' => Some(b'\''),
                                b'\\' => Some(b'\\'),
                                b'/' => Some(b'/'),
                                _ => None,
                            };
                            if let Some(r) = simple {
                                self.st.attribute.push(r);
                                self.st.cursor += 1;
                            } else if e == b'x' {
                                self.st.cursor += 1;
                                let v = self.parse_hex_num(2)?;
                                self.st.attribute.push(v as u8);
                            } else if e == b'u' {
                                self.st.cursor += 1;
                                let val = self.parse_hex_num(4)?;
                                if (0xD800..=0xDBFF).contains(&val) {
                                    if unicode_high_surrogate != -1 {
                                        return self.err("illegal Unicode sequence (multiple high surrogates)");
                                    }
                                    unicode_high_surrogate = val as i64;
                                } else if (0xDC00..=0xDFFF).contains(&val) {
                                    if unicode_high_surrogate == -1 {
                                        return self.err("illegal Unicode sequence (unpaired low surrogate)");
                                    }
                                    let cp = 0x10000 + (((unicode_high_surrogate as u32) & 0x03FF) << 10) + (val as u32 & 0x03FF);
                                    Self::to_utf8(cp, &mut self.st.attribute);
                                    unicode_high_surrogate = -1;
                                } else {
                                    if unicode_high_surrogate != -1 {
                                        return self.err("illegal Unicode sequence (unpaired high surrogate)");
                                    }
                                    Self::to_utf8(val as u32, &mut self.st.attribute);
                                }
                            } else {
                                return self.err("unknown escape code in string constant");
                            }
                        } else {
                            if unicode_high_surrogate != -1 {
                                return self.err("illegal Unicode sequence (unpaired high surrogate)");
                            }
                            self.st.attr_is_trivial_ascii_string &= (b' '..=b'~').contains(&ch);
                            self.st.attribute.push(ch);
                            self.st.cursor += 1;
                        }
                    }
                    if unicode_high_surrogate != -1 {
                        return self.err("illegal Unicode sequence (unpaired high surrogate)");
                    }
                    self.st.cursor += 1;
                    if !self.st.attr_is_trivial_ascii_string && std::str::from_utf8(&self.st.attribute).is_err() {
                        return self.err("illegal UTF-8 sequence");
                    }
                    self.st.token = K_TOKEN_STRING_CONSTANT;
                    return Ok(());
                }
                b'/' if self.cur() == b'/' => {
                    self.st.cursor += 1;
                    let start = self.st.cursor;
                    while !matches!(self.cur(), 0 | b'\n' | b'\r') {
                        self.st.cursor += 1;
                    }
                    if self.at(start) == b'/' && !seen_newline {
                        return self.err("a documentation comment should be on a line on its own");
                    }
                }
                b'/' if self.cur() == b'*' => {
                    self.st.cursor += 1;
                    while self.cur() != b'*' || self.at(self.st.cursor + 1) != b'/' {
                        if self.cur() == b'\n' {
                            self.mark_new_line();
                        }
                        if self.cur() == 0 {
                            return self.err("end of file in comment");
                        }
                        self.st.cursor += 1;
                    }
                    self.st.cursor += 2;
                }
                _ => {
                    if is_identifier_start(c) {
                        let start = self.st.cursor - 1;
                        while is_identifier_start(self.cur()) || is_digit(self.cur()) {
                            self.st.cursor += 1;
                        }
                        self.st.attribute = self.src[start..self.st.cursor].to_vec();
                        self.st.token = K_TOKEN_IDENTIFIER;
                        return Ok(());
                    }
                    let has_sign = c == b'+' || c == b'-';
                    if has_sign {
                        let p = self.st.cursor;
                        if self.at(p) == b'i'
                            && self.at(p + 1) == b'n'
                            && self.at(p + 2) == b'f'
                            && !(is_identifier_start(self.at(p + 3)) || is_digit(self.at(p + 3)))
                        {
                            self.st.attribute = self.src[p - 1..p + 3].to_vec();
                            self.st.token = K_TOKEN_FLOAT_CONSTANT;
                            self.st.cursor += 3;
                            return Ok(());
                        }
                        if is_identifier_start(self.cur()) {
                            return Ok(());
                        }
                    }
                    let mut dot_lvl: i32 = if c == b'.' { 0 } else { 1 };
                    if dot_lvl == 0 && !is_digit(self.cur()) {
                        return Ok(());
                    }
                    if is_digit(c) || has_sign || dot_lvl == 0 {
                        let start = self.st.cursor - 1;
                        let mut start_digits = if !is_digit(c) { self.st.cursor } else { self.st.cursor - 1 };
                        if !is_digit(c) && is_digit(self.cur()) {
                            start_digits = self.st.cursor;
                            c = self.cur();
                            self.st.cursor += 1;
                        }
                        let use_hex = dot_lvl != 0 && c == b'0' && is_alpha_char(self.cur(), b'X');
                        if use_hex {
                            self.st.cursor += 1;
                            start_digits = self.st.cursor;
                        }
                        loop {
                            if use_hex {
                                while is_xdigit(self.cur()) {
                                    self.st.cursor += 1;
                                }
                            } else {
                                while is_digit(self.cur()) {
                                    self.st.cursor += 1;
                                }
                            }
                            if self.cur() == b'.' {
                                self.st.cursor += 1;
                                dot_lvl -= 1;
                                if dot_lvl >= 0 {
                                    continue;
                                }
                            }
                            break;
                        }
                        if dot_lvl >= 0 && self.st.cursor > start_digits {
                            if use_hex && dot_lvl == 0 {
                                start_digits = self.st.cursor;
                            }
                            if (use_hex && is_alpha_char(self.cur(), b'P')) || is_alpha_char(self.cur(), b'E') {
                                dot_lvl = 0;
                                self.st.cursor += 1;
                                if self.cur() == b'+' || self.cur() == b'-' {
                                    self.st.cursor += 1;
                                }
                                start_digits = self.st.cursor;
                                while is_digit(self.cur()) {
                                    self.st.cursor += 1;
                                }
                                if self.cur() == b'.' {
                                    self.st.cursor += 1;
                                    dot_lvl = -1;
                                }
                            }
                        }
                        if dot_lvl >= 0 && self.st.cursor > start_digits {
                            self.st.attribute = self.src[start..self.st.cursor].to_vec();
                            self.st.token = if dot_lvl != 0 { K_TOKEN_INTEGER_CONSTANT } else { K_TOKEN_FLOAT_CONSTANT };
                            return Ok(());
                        }
                        let s = self.src[start..self.st.cursor].to_vec();
                        return self.err(cat!(b"invalid number: ", s));
                    }
                    let ch = if (b' '..=b'~').contains(&c) { vec![c] } else { format!("code: {}", c as i8).into_bytes() };
                    return self.err(cat!(b"illegal character: ", ch));
                }
            }
        }
    }

    fn is(&self, t: i32) -> bool {
        self.st.token == t
    }

    fn is_ident(&self, id: &str) -> bool {
        self.st.token == K_TOKEN_IDENTIFIER && self.st.attribute == id.as_bytes()
    }

    fn token_to_string_id(&self, t: i32) -> Vec<u8> {
        if t == K_TOKEN_IDENTIFIER {
            self.st.attribute.clone()
        } else {
            token_to_string(t)
        }
    }

    fn expect(&mut self, t: i32) -> R {
        if t != self.st.token {
            let m = cat!(b"expecting: ", token_to_string(t), b" instead got: ", self.token_to_string_id(self.st.token));
            return self.err(m);
        }
        self.next()
    }

    fn parse_namespacing(&mut self, id: &mut Vec<u8>, mut last: Option<&mut Vec<u8>>) -> R {
        while self.is(b'.' as i32) {
            self.next()?;
            id.push(b'.');
            id.extend_from_slice(&self.st.attribute);
            if let Some(l) = last.as_deref_mut() {
                *l = self.st.attribute.clone();
            }
            self.expect(K_TOKEN_IDENTIFIER)?;
        }
        Ok(())
    }

    // ------------------------------------------------------ entry

    fn start_parse_file(&mut self, source: &[u8]) -> R {
        // `const char*`: the text ends at the first NUL
        let end = source.iter().position(|&c| c == 0).unwrap_or(source.len());
        self.src = source[..end].to_vec();
        self.src.push(0);
        self.st.prev_cursor = 0;
        self.st.cursor = 0;
        self.st.line = 0;
        self.mark_new_line();
        self.error.clear();
        self.skip_byte_order_mark()?;
        self.next()?;
        if self.is(K_TOKEN_EOF) {
            return self.err("input file is empty");
        }
        Ok(())
    }

    /// `Parse(source)`: schema declarations and/or a JSON object.
    pub fn parse(&mut self, source: &[u8]) -> bool {
        let r = self.parse_root(source);
        r.is_ok()
    }

    fn parse_root(&mut self, source: &[u8]) -> R {
        self.do_parse(source)?;
        for &i in &self.struct_order.clone() {
            if self.structs[i].predecl {
                let s = &self.structs[i];
                let mut e = cat!(b"type referenced but not defined (check namespace): ", s.name);
                if let Some(l) = &s.original_location {
                    e.extend_from_slice(b", originally at: ");
                    e.extend_from_slice(l);
                }
                return self.err(e);
            }
        }
        for ei in 0..self.enums.len() {
            if self.enums[ei].is_union {
                for v in &self.enums[ei].vals {
                    if v.union_type.base == B::String {
                        let m = cat!(b"only tables can be union elements in the generated language: ", v.name);
                        return self.err(m);
                    }
                }
            }
        }
        if self.is(b'{' as i32) {
            self.do_parse_json()?;
        }
        Ok(())
    }

    fn do_parse(&mut self, source: &[u8]) -> R {
        self.field_stack.clear();
        self.builder.clear();
        self.current_ns = Vec::new();
        self.start_parse_file(source)?;
        if self.is_ident("native_include") || self.is_ident("include") {
            return self.err("siem-router: includes are not supported");
        }
        while !self.is(K_TOKEN_EOF) {
            if self.is_ident("namespace") {
                self.parse_namespace()?;
            } else if self.is(b'{' as i32) {
                return Ok(());
            } else if self.is_ident("enum") {
                self.parse_enum(false)?;
            } else if self.is_ident("union") {
                self.parse_enum(true)?;
            } else if self.is_ident("root_type") {
                self.next()?;
                let mut root_type = self.st.attribute.clone();
                self.expect(K_TOKEN_IDENTIFIER)?;
                self.parse_namespacing(&mut root_type, None)?;
                if !self.set_root_type(&root_type) {
                    return self.err(cat!(b"unknown root type: ", root_type));
                }
                self.expect(b';' as i32)?;
            } else if self.is_ident("file_identifier") {
                self.next()?;
                self.file_identifier = self.st.attribute.clone();
                self.expect(K_TOKEN_STRING_CONSTANT)?;
                if self.file_identifier.len() != 4 {
                    return self.err("file_identifier must be exactly 4 characters");
                }
                self.expect(b';' as i32)?;
            } else if self.is_ident("file_extension") {
                self.next()?;
                self.expect(K_TOKEN_STRING_CONSTANT)?;
                self.expect(b';' as i32)?;
            } else if self.is_ident("include") {
                return self.err("includes must come before declarations");
            } else if self.is_ident("attribute") {
                self.next()?;
                let name = self.st.attribute.clone();
                if self.is(K_TOKEN_IDENTIFIER) {
                    self.next()?;
                } else {
                    self.expect(K_TOKEN_STRING_CONSTANT)?;
                }
                self.expect(b';' as i32)?;
                self.known_attributes.insert(name);
            } else if self.is_ident("rpc_service") {
                return self.err("siem-router: rpc services are not supported");
            } else {
                self.parse_decl()?;
            }
        }
        self.expect(K_TOKEN_EOF)
    }

    // ------------------------------------------------------ schema

    fn qualified(&self, name: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        for c in &self.current_ns {
            s.extend_from_slice(c);
            s.push(b'.');
        }
        s.extend_from_slice(name);
        s
    }

    /// `LookupTableByName`
    fn lookup_by_name(syms: &Symbols, name: &[u8], ns: &[Vec<u8>], skip_top: usize) -> Option<usize> {
        if syms.dict.is_empty() || ns.len() < skip_top {
            return None;
        }
        let n = ns.len() - skip_top;
        for i in (0..=n).rev() {
            let mut full = Vec::new();
            for c in &ns[..i] {
                full.extend_from_slice(c);
                full.push(b'.');
            }
            full.extend_from_slice(name);
            if let Some(&x) = syms.dict.get(&full) {
                return Some(x);
            }
        }
        None
    }

    fn lookup_enum(&self, id: &[u8]) -> Option<usize> {
        Self::lookup_by_name(&self.enum_syms, id, &self.current_ns, 0)
    }

    fn lookup_struct(&self, id: &[u8]) -> Option<usize> {
        self.struct_syms.dict.get(id).copied()
    }

    /// `LookupCreateStruct(name, create_if_new, definition)`
    fn lookup_create_struct(&mut self, name: &[u8], create_if_new: bool, definition: bool) -> Option<usize> {
        let qualified = self.qualified(name);
        let mut sd = self.lookup_struct(name);
        if let Some(i) = sd {
            if self.structs[i].predecl {
                if definition {
                    self.structs[i].ns = self.current_ns.clone();
                    self.struct_syms.dict.remove(name);
                    self.struct_syms.dict.insert(qualified, i);
                }
                return Some(i);
            }
        }
        sd = self.lookup_struct(&qualified);
        if let Some(i) = sd {
            if self.structs[i].predecl {
                if definition {
                    self.structs[i].ns = self.current_ns.clone();
                }
                return Some(i);
            }
        }
        if !definition && sd.is_none() {
            sd = Self::lookup_by_name(&self.struct_syms, name, &self.current_ns, 1);
        }
        if sd.is_none() && create_if_new {
            let i = self.structs.len();
            let mut s = StructDef { name: name.to_vec(), ns: self.current_ns.clone(), predecl: true, ..Default::default() };
            if definition {
                self.struct_syms.dict.insert(qualified, i);
            } else {
                self.struct_syms.dict.insert(name.to_vec(), i);
                s.original_location = Some(format!(":{}", self.st.line).into_bytes());
            }
            self.structs.push(s);
            self.struct_order.push(i);
            sd = Some(i);
        }
        sd
    }

    fn set_root_type(&mut self, name: &[u8]) -> bool {
        self.root = self.lookup_struct(name).or_else(|| self.lookup_struct(&self.qualified(name)));
        self.root.is_some()
    }

    fn parse_namespace(&mut self) -> R {
        self.next()?;
        let mut comps = Vec::new();
        if !self.is(b';' as i32) {
            loop {
                comps.push(self.st.attribute.clone());
                self.expect(K_TOKEN_IDENTIFIER)?;
                if self.is(b'.' as i32) {
                    self.next()?;
                } else {
                    break;
                }
            }
        }
        self.current_ns = comps;
        self.expect(b';' as i32)
    }

    fn parse_meta_data(&mut self) -> R<Vec<(Vec<u8>, Value)>> {
        let mut attrs: Vec<(Vec<u8>, Value)> = Vec::new();
        if self.is(b'(' as i32) {
            self.next()?;
            loop {
                let name = self.st.attribute.clone();
                if !(self.is(K_TOKEN_IDENTIFIER) || self.is(K_TOKEN_STRING_CONSTANT)) {
                    return self.err(cat!(b"attribute name must be either identifier or string: ", name));
                }
                if !self.known_attributes.contains(&name) {
                    return self.err(cat!(b"user define attributes must be declared before use: ", name));
                }
                if UNSUPPORTED_ATTRIBUTES.iter().any(|a| a.as_bytes() == name.as_slice()) {
                    return self.err(cat!(b"siem-router: unsupported attribute: ", name));
                }
                self.next()?;
                let known = attrs.iter().any(|(n, _)| *n == name);
                if known {
                    self.warning(cat!(b"attribute already found: ", name));
                }
                let mut e = Value::new(Type::new(B::None));
                if self.is(b':' as i32) {
                    self.next()?;
                    self.parse_single_value(Some(&name), &mut e, true)?;
                }
                if !known {
                    attrs.push((name, e));
                }
                if self.is(b')' as i32) {
                    self.next()?;
                    break;
                }
                self.expect(b',' as i32)?;
            }
        }
        Ok(attrs)
    }

    fn parse_type(&mut self) -> R<Type> {
        if self.st.token == K_TOKEN_IDENTIFIER {
            const NAMES: &[(&str, BaseType)] = &[
                ("bool", B::Bool),
                ("byte", B::Char),
                ("int8", B::Char),
                ("ubyte", B::UChar),
                ("uint8", B::UChar),
                ("short", B::Short),
                ("int16", B::Short),
                ("ushort", B::UShort),
                ("uint16", B::UShort),
                ("int", B::Int),
                ("int32", B::Int),
                ("uint", B::UInt),
                ("uint32", B::UInt),
                ("long", B::Long),
                ("int64", B::Long),
                ("ulong", B::ULong),
                ("uint64", B::ULong),
                ("float", B::Float),
                ("float32", B::Float),
                ("double", B::Double),
                ("float64", B::Double),
                ("string", B::String),
            ];
            if let Some(&(_, bt)) = NAMES.iter().find(|(n, _)| self.is_ident(n)) {
                self.next()?;
                return Ok(Type::new(bt));
            }
            self.parse_type_ident()
        } else if self.st.token == b'[' as i32 {
            self.guarded(|p| {
                p.next()?;
                let sub = p.parse_type()?;
                if sub.base == B::Vector || sub.base == B::Array {
                    return p.err("nested vector types not supported (wrap in table first)");
                }
                let mut base = B::Vector;
                if p.is(b':' as i32) {
                    p.next()?;
                    if p.st.token != K_TOKEN_INTEGER_CONSTANT {
                        return p.err("length of fixed-length array must be an integer value");
                    }
                    let (check, v) = string_to_number(&p.st.attribute.clone(), B::UShort);
                    if !check || matches!(v, Num::I(0)) {
                        return p.err("length of fixed-length array must be positive and fit to uint16_t type");
                    }
                    base = B::Array;
                    p.next()?;
                } else if sub.base == B::Union {
                    return p.err("siem-router: vectors of unions are not supported");
                }
                let t = Type { base, element: sub.base, struct_def: sub.struct_def, enum_def: sub.enum_def };
                p.expect(b']' as i32)?;
                Ok(t)
            })
        } else {
            self.err("illegal type syntax")
        }
    }

    fn parse_type_ident(&mut self) -> R<Type> {
        let mut id = self.st.attribute.clone();
        self.expect(K_TOKEN_IDENTIFIER)?;
        self.parse_namespacing(&mut id, None)?;
        if let Some(e) = self.lookup_enum(&id) {
            let mut t = self.enums[e].underlying;
            if self.enums[e].is_union {
                t.base = B::Union;
            }
            Ok(t)
        } else {
            let sd = self.lookup_create_struct(&id, true, false);
            Ok(Type { base: B::Struct, element: B::None, struct_def: sd, enum_def: None })
        }
    }

    fn add_field(&mut self, sd: usize, name: &[u8], ty: Type) -> R<usize> {
        let s = &mut self.structs[sd];
        let offset = 4 + 2 * s.fields.len() as u16;
        if s.lookup(name).is_some() {
            return self.err(cat!(b"field already exists: ", name));
        }
        let mut value = Value::new(ty);
        value.offset = offset;
        s.fields.push(FieldDef { name: name.to_vec(), value, presence: Presence::Default, deprecated: false, attributes: Vec::new() });
        Ok(s.fields.len() - 1)
    }

    fn parse_field(&mut self, sd: usize) -> R {
        let name = self.st.attribute.clone();
        if self.lookup_create_struct(&name, false, false).is_some() {
            return self.err("field name can not be the same as table/struct name");
        }
        if !name.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') {
            self.warning(cat!(b"field names should be lowercase snake_case, got: ", name));
        }
        self.expect(K_TOKEN_IDENTIFIER)?;
        self.expect(b':' as i32)?;
        let ty = self.parse_type()?;
        if ty.base == B::Array {
            return self.err("fixed-length array in table must be wrapped in struct");
        }
        let typefield = if ty.base == B::Union {
            let mut ut = self.enums[ty.enum_def.unwrap()].underlying;
            ut.base = B::UType;
            Some(self.add_field(sd, &cat!(name, b"_type"), ut)?)
        } else {
            None
        };
        let fi = self.add_field(sd, &name, ty)?;
        if self.is(b'=' as i32) {
            self.next()?;
            let mut v = self.structs[sd].fields[fi].value.clone();
            self.parse_single_value(Some(&name), &mut v, true)?;
            self.structs[sd].fields[fi].value = v;
            let c = self.structs[sd].fields[fi].value.constant.clone();
            if ty.base == B::Vector && c != b"0" && c != b"[]" {
                return self.err("The only supported default for vectors is `[]`.");
            }
        }
        if ty.base.is_float() {
            let text = &mut self.structs[sd].fields[fi].value.constant;
            let mut i = 0;
            while text.get(i) == Some(&b' ') {
                i += 1;
            }
            if matches!(text.get(i), Some(b'-' | b'+')) {
                i += 1;
            }
            if !is_identifier_start(text.get(i).copied().unwrap_or(0)) && !text.iter().any(|c| b".eEpP".contains(c)) {
                text.extend_from_slice(b".0");
            }
        }
        let attrs = self.parse_meta_data()?;
        let field = &mut self.structs[sd].fields[fi];
        field.deprecated = attrs.iter().any(|(n, _)| n == b"deprecated");
        let required = attrs.iter().any(|(n, _)| n == b"required");
        let c = field.value.constant.clone();
        let default_str_or_vec = (ty.base == B::String || ty.base == B::Vector) && c != b"0";
        let optional = if ty.base.is_scalar() { c == b"null" } else { !(required || default_str_or_vec) };
        let id_attr = attrs.iter().find(|(n, _)| n == b"id").map(|(_, v)| v.constant.clone());
        field.attributes = attrs;
        if required && optional {
            return self.err("Fields cannot be both optional and required.");
        }
        self.structs[sd].fields[fi].presence = if required {
            Presence::Required
        } else if optional {
            Presence::Optional
        } else {
            Presence::Default
        };
        if required && ty.base.is_scalar() {
            return self.err("only non-scalar fields in tables may be 'required'");
        }
        if let Some(e) = ty.enum_def {
            if ty.base == B::Union {
                if c != b"0" {
                    return self.err("Union defaults must be NONE");
                }
            } else if ty.base == B::Vector {
                if c != b"0" && c != b"[]" {
                    return self.err("Vector defaults may only be `[]`.");
                }
            } else if !ty.base.is_integer() {
                return self.err("Enums must have integer base types");
            } else if !optional {
                let ed = &self.enums[e];
                let found = if ed.is_uint64() {
                    let (_, v) = string_to_number(&c, B::ULong);
                    let Num::U(u) = v else { unreachable!() };
                    ed.reverse_lookup(u as i64, false).is_some()
                } else {
                    let (_, v) = string_to_number(&c, B::Long);
                    let Num::I(i) = v else { unreachable!() };
                    ed.reverse_lookup(i, false).is_some()
                };
                if !found {
                    let m = cat!(b"default value of `", c, b"` for field `", name, b"` is not part of enum `", ed.name, b"`.");
                    return self.err(m);
                }
            }
        }
        if let (Some(tf), Some(id_str)) = (typefield, id_attr) {
            let id = match self.atot(&id_str, B::UShort) {
                Ok(Num::I(i)) => Some(i),
                _ => None,
            };
            if let Some(id) = id.filter(|&i| i > 0) {
                let mut val = Value::new(Type::new(B::None));
                val.constant = num_to_string_i(id - 1);
                self.structs[sd].fields[tf].attributes.push((b"id".to_vec(), val));
            } else {
                let m = cat!(
                    b"a union type effectively adds two fields with non-negative ids, its id must be that of the second field (the first field is the type field and not explicitly declared in the schema);\nfield: ",
                    name,
                    b", id: ",
                    id_str
                );
                return self.err(m);
            }
        }
        if let Some(tf) = typefield {
            if self.structs[sd].fields[fi].deprecated {
                self.structs[sd].fields[tf].deprecated = true;
            }
        }
        self.expect(b';' as i32)
    }

    fn check_clash(&mut self, sd: usize, suffix: &[u8], basetype: BaseType) -> R {
        let len = suffix.len();
        let fields = self.structs[sd].fields.clone();
        for f in &fields {
            let fname = &f.name;
            if fname.len() > len && fname.ends_with(suffix) && f.value.ty.base != B::UType {
                if let Some(o) = self.structs[sd].lookup(&fname[..fname.len() - len]) {
                    if fields[o].value.ty.base == basetype {
                        let m = cat!(b"Field ", fname, b" would clash with generated functions for field ", fields[o].name);
                        return self.err(m);
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_decl(&mut self) -> R {
        if self.is_ident("struct") {
            return self.err("siem-router: structs are not supported");
        }
        if !self.is_ident("table") {
            return self.err("declaration expected");
        }
        self.next()?;
        let name = self.st.attribute.clone();
        self.expect(K_TOKEN_IDENTIFIER)?;
        let sd = self.lookup_create_struct(&name, true, true).unwrap();
        if !self.structs[sd].predecl {
            return self.err(cat!(b"datatype already exists: ", self.qualified(&name)));
        }
        self.structs[sd].predecl = false;
        self.structs[sd].name = name.clone();
        self.struct_order.retain(|&i| i != sd);
        self.struct_order.push(sd);
        let attrs = self.parse_meta_data()?;
        self.structs[sd].sortbysize = !attrs.iter().any(|(n, _)| n == b"original_order");
        self.expect(b'{' as i32)?;
        while !self.is(b'}' as i32) {
            self.parse_field(sd)?;
        }
        let nfields = self.structs[sd].fields.len();
        if nfields > 0 {
            let num_id_fields = self.structs[sd].fields.iter().filter(|f| f.attr("id").is_some()).count();
            if num_id_fields > 0 {
                if num_id_fields != nfields {
                    return self.err("either all fields or no fields must have an 'id' attribute");
                }
                let atoi = |f: &FieldDef| {
                    let c = c_str(&f.attr("id").unwrap().constant);
                    unsafe { libc::atoi(c.as_ptr()) }
                };
                self.structs[sd].fields.sort_by_key(atoi);
                for i in 0..nfields {
                    let id_str = self.structs[sd].fields[i].attr("id").unwrap().constant.clone();
                    let fname = self.structs[sd].fields[i].name.clone();
                    let Ok(Num::I(id)) = self.atot(&id_str, B::UShort) else {
                        return self.err(cat!(b"field id's must be non-negative number, field: ", fname, b", id: ", id_str));
                    };
                    if i as i64 != id {
                        let m = cat!(
                            b"field id's must be consecutive from 0, id ",
                            i.to_string(),
                            b" missing or set twice, field: ",
                            fname,
                            b", id: ",
                            id_str
                        );
                        return self.err(m);
                    }
                    self.structs[sd].fields[i].value.offset = 4 + 2 * i as u16;
                }
            }
        }
        self.check_clash(sd, b"_type", B::Union)?;
        self.check_clash(sd, b"Type", B::Union)?;
        self.check_clash(sd, b"_length", B::Vector)?;
        self.check_clash(sd, b"Length", B::Vector)?;
        self.check_clash(sd, b"_byte_vector", B::String)?;
        self.check_clash(sd, b"ByteVector", B::String)?;
        self.expect(b'}' as i32)?;
        let q = self.qualified(&name);
        if !self.types.insert(q.clone()) {
            return self.err(cat!(b"datatype already exists: ", q));
        }
        Ok(())
    }

    fn parse_enum(&mut self, is_union: bool) -> R {
        self.next()?;
        let enum_name = self.st.attribute.clone();
        self.expect(K_TOKEN_IDENTIFIER)?;
        let qualified = self.qualified(&enum_name);
        if self.enum_syms.dict.contains_key(&qualified) {
            return self.err(cat!(b"enum already exists: ", qualified));
        }
        let ei = self.enums.len();
        self.enum_syms.dict.insert(qualified.clone(), ei);
        self.enums.push(EnumDef {
            name: enum_name.clone(),
            is_union,
            underlying: Type { base: if is_union { B::UType } else { B::Int }, element: B::None, struct_def: None, enum_def: Some(ei) },
            vals: Vec::new(),
        });
        if !self.is(b':' as i32) {
            if !is_union {
                return self.err("must specify the underlying integer type for this enum (e.g. ': short', which was the default).");
            }
        } else {
            self.next()?;
            let mut t = self.parse_type()?;
            if !t.base.is_integer() || t.base == B::Bool {
                return self.err(format!("underlying {}type must be integral", if is_union { "union" } else { "enum" }));
            }
            t.enum_def = Some(ei);
            self.enums[ei].underlying = t;
        }
        self.parse_meta_data()?;
        self.expect(b'{' as i32)?;
        let mut vals: Vec<EnumVal> = Vec::new();
        let accept = |p: &mut Parser, vals: &mut Vec<EnumVal>, mut ev: EnumVal, user_value: bool| -> R {
            // ValidateValue(&ev.value, !user_value)
            let bt = p.enums[ei].underlying.base;
            let m = (!user_value) as i64;
            if bt == B::ULong {
                let v = ev.value as u64;
                if v > u64::MAX - m as u64 {
                    let msg = format!("enum value does not fit, \"{}{}\" out of {}", v, if m != 0 { " + 1" } else { "" }, interval(bt));
                    return p.err(msg);
                }
                ev.value = v.wrapping_add(m as u64) as i64;
            } else {
                let (lo, hi) = match bt {
                    B::Long => (i64::MIN, i64::MAX),
                    _ => int_range(bt),
                };
                let v = ev.value;
                if v < lo || v > hi - m {
                    let msg = format!("enum value does not fit, \"{}{}\" out of {}", v, if m != 0 { " + 1" } else { "" }, interval(bt));
                    return p.err(msg);
                }
                ev.value = v + m;
            }
            if vals.iter().any(|v| v.name == ev.name) {
                return p.err(cat!(b"enum value already exists: ", ev.name));
            }
            vals.push(ev);
            Ok(())
        };
        if is_union || self.is(b'}' as i32) {
            let ev = EnumVal { name: b"NONE".to_vec(), value: 0, union_type: Type::new(B::None) };
            accept(self, &mut vals, ev, true)?;
        }
        while !self.is(b'}' as i32) {
            let first = vals.is_empty();
            let mut user_value = first;
            let mut ev = EnumVal {
                name: self.st.attribute.clone(),
                value: if first { 0 } else { vals.last().unwrap().value },
                union_type: Type::new(B::None),
            };
            let mut full_name = ev.name.clone();
            self.expect(K_TOKEN_IDENTIFIER)?;
            if is_union {
                let mut last = ev.name.clone();
                self.parse_namespacing(&mut full_name, Some(&mut last))?;
                ev.name = full_name.iter().map(|&c| if c == b'.' { b'_' } else { c }).collect();
                if self.is(b':' as i32) {
                    self.next()?;
                    ev.union_type = self.parse_type()?;
                    if ev.union_type.base != B::Struct && ev.union_type.base != B::String {
                        return self.err("union value type may only be table/struct/string");
                    }
                } else {
                    let sd = self.lookup_create_struct(&full_name, true, false);
                    ev.union_type = Type { base: B::Struct, element: B::None, struct_def: sd, enum_def: None };
                }
            }
            if self.is(b'=' as i32) {
                self.next()?;
                user_value = true;
                let a = self.st.attribute.clone();
                let (fit, v) = if self.enums[ei].is_uint64() { string_to_number(&a, B::ULong) } else { string_to_number(&a, B::Long) };
                ev.value = match v {
                    Num::I(i) => i,
                    Num::U(u) => u as i64,
                    _ => 0,
                };
                if !fit {
                    return self.err(cat!(b"enum value does not fit, \"", a, b"\""));
                }
                self.expect(K_TOKEN_INTEGER_CONSTANT)?;
            }
            self.parse_meta_data()?;
            accept(self, &mut vals, ev, user_value)?;
            if !self.is(b',' as i32) {
                break;
            }
            self.next()?;
        }
        self.expect(b'}' as i32)?;
        if vals.is_empty() {
            return self.err("incomplete enum declaration, values not found");
        }
        if self.enums[ei].is_uint64() {
            vals.sort_by(|a, b| (a.value as u64).cmp(&(b.value as u64)).then_with(|| a.name.cmp(&b.name)));
        } else {
            vals.sort_by(|a, b| a.value.cmp(&b.value).then_with(|| a.name.cmp(&b.name)));
        }
        for w in vals.windows(2) {
            if w[0].value == w[1].value {
                let m = cat!(b"all enum values must be unique: ", w[0].name, b" and ", w[1].name, b" are both ", w[1].value.to_string());
                return self.err(m);
            }
        }
        self.enums[ei].vals = vals;
        if !self.types.insert(qualified.clone()) {
            return self.err(cat!(b"datatype already exists: ", qualified));
        }
        Ok(())
    }

    // -------------------------------------------------------- JSON

    fn do_parse_json(&mut self) -> R {
        if !self.is(b'{' as i32) {
            return self.expect(b'{' as i32);
        }
        let Some(root) = self.root else {
            return self.err("no root type set to parse json with");
        };
        if self.builder.size() != 0 {
            return self.err("cannot have more than one json object in a file");
        }
        let (_, toff) = self.parse_table(root)?;
        let fid = if self.file_identifier.is_empty() { None } else { Some(self.file_identifier.clone()) };
        self.builder.finish(toff, fid.as_deref());
        self.expect(K_TOKEN_EOF)
    }

    fn parse_comma(&mut self) -> R {
        self.expect(b',' as i32)
    }

    fn atot(&mut self, s: &[u8], bt: BaseType) -> R<Num> {
        let (done, v) = string_to_number(s, bt);
        let v = match v {
            Num::F32(f) if f.is_nan() => Num::F32(f.abs()),
            Num::F64(f) if f.is_nan() => Num::F64(f.abs()),
            v => v,
        };
        if done {
            return Ok(v);
        }
        let zero = match v {
            Num::I(i) => i == 0,
            Num::U(u) => u == 0,
            Num::F32(f) => f == 0.0,
            Num::F64(f) => f == 0.0,
        };
        if zero {
            self.err(cat!(b"invalid number: \"", c_view(s), b"\""))
        } else {
            self.err(cat!(b"invalid number: \"", c_view(s), b"\", constant does not fit ", interval(bt)))
        }
    }

    /// `atot<Offset<void>>`: `atoi`
    fn atoi(s: &[u8]) -> u32 {
        let c = c_str(s);
        unsafe { libc::atoi(c.as_ptr()) as u32 }
    }

    fn parse_string(&mut self, val: &mut Value) -> R {
        let s = self.st.attribute.clone();
        self.expect(K_TOKEN_STRING_CONSTANT)?;
        let off = self.builder.create_string(&s);
        val.constant = off.to_string().into_bytes();
        Ok(())
    }

    /// `ParseTableDelimiters`: `body(name, fieldn)` per field.
    fn parse_table_delimiters(
        &mut self,
        fieldn: &mut usize,
        struct_def: Option<usize>,
        body: &mut dyn FnMut(&mut Parser, &[u8], &mut usize) -> R,
    ) -> R {
        let mut terminator = b'}';
        let is_nested_vector = struct_def.is_some() && self.is(b'[' as i32);
        if is_nested_vector {
            self.next()?;
            terminator = b']';
        } else {
            self.expect(b'{' as i32)?;
        }
        loop {
            if self.is(terminator as i32) {
                break;
            }
            let name;
            if is_nested_vector {
                let sd = &self.structs[struct_def.unwrap()];
                if *fieldn >= sd.fields.len() {
                    return self.err("too many unnamed fields in nested array");
                }
                name = sd.fields[*fieldn].name.clone();
            } else {
                name = self.st.attribute.clone();
                if self.is(K_TOKEN_STRING_CONSTANT) {
                    self.next()?;
                } else {
                    self.expect(K_TOKEN_IDENTIFIER)?;
                }
                self.expect(b':' as i32)?;
            }
            body(self, &name, fieldn)?;
            if self.is(terminator as i32) {
                break;
            }
            self.parse_comma()?;
        }
        self.next()?;
        if is_nested_vector && *fieldn != self.structs[struct_def.unwrap()].fields.len() {
            return self.err("wrong number of unnamed fields in table vector");
        }
        Ok(())
    }

    fn parse_vector_delimiters(&mut self, count: &mut usize, body: &mut dyn FnMut(&mut Parser, usize) -> R) -> R {
        self.expect(b'[' as i32)?;
        loop {
            if self.is(b']' as i32) {
                break;
            }
            body(self, *count)?;
            *count += 1;
            if self.is(b']' as i32) {
                break;
            }
            self.parse_comma()?;
        }
        self.next()
    }

    fn skip_any_json_value(&mut self) -> R {
        self.guarded(|p| match p.st.token {
            t if t == b'{' as i32 => {
                let mut fieldn_outer = 0;
                p.parse_table_delimiters(&mut fieldn_outer, None, &mut |p, _, fieldn| {
                    p.skip_any_json_value()?;
                    *fieldn += 1;
                    Ok(())
                })
            }
            t if t == b'[' as i32 => {
                let mut count = 0;
                p.parse_vector_delimiters(&mut count, &mut |p, _| p.skip_any_json_value())
            }
            K_TOKEN_STRING_CONSTANT | K_TOKEN_INTEGER_CONSTANT | K_TOKEN_FLOAT_CONSTANT => p.next(),
            _ => {
                if p.is_ident("true") || p.is_ident("false") || p.is_ident("null") || p.is_ident("inf") {
                    p.next()
                } else {
                    p.token_error()
                }
            }
        })
    }

    fn token_error(&mut self) -> R {
        let m = cat!(b"cannot parse value starting with: ", self.token_to_string_id(self.st.token));
        self.err(m)
    }

    /// `ParseTable(struct_def, value, ovalue)`: the table's offset.
    fn parse_table(&mut self, sd: usize) -> R<(Vec<u8>, u32)> {
        self.guarded(|p| p.parse_table_inner(sd))
    }

    fn parse_table_inner(&mut self, sd: usize) -> R<(Vec<u8>, u32)> {
        let mut fieldn_outer = 0usize;
        self.parse_table_delimiters(&mut fieldn_outer, Some(sd), &mut |p, name, fieldn| {
            if name == b"$schema" {
                return p.expect(K_TOKEN_STRING_CONSTANT);
            }
            let Some(fi) = p.structs[sd].lookup(name) else {
                if !p.opts.skip_unexpected_fields_in_json {
                    return p.err(cat!(b"unknown field: ", name));
                }
                return p.skip_any_json_value();
            };
            let field = p.structs[sd].fields[fi].clone();
            if p.is_ident("null") && !field.value.ty.base.is_scalar() {
                return p.next();
            }
            let mut val = field.value.clone();
            p.parse_any_value(&mut val, Some((sd, fi)), *fieldn, Some(sd), 0, false)?;
            // insertion sort with the duplicate check
            let len = p.field_stack.len();
            let mut pos = len;
            for k in 0..*fieldn {
                let idx = len - 1 - k;
                let (sdi, fii) = p.field_stack[idx].1.expect("table field");
                if (sdi, fii) == (sd, fi) {
                    return p.err(cat!(b"field set more than once: ", field.name));
                }
                if p.structs[sdi].fields[fii].value.offset < field.value.offset {
                    break;
                }
                pos = idx;
            }
            p.field_stack.insert(pos, (val, Some((sd, fi))));
            *fieldn += 1;
            Ok(())
        })?;

        let fields_len = self.structs[sd].fields.len();
        for f in 0..fields_len {
            if self.structs[sd].fields[f].presence != Presence::Required {
                continue;
            }
            let start = self.field_stack.len() - fieldn_outer;
            let found = self.field_stack[start..].iter().any(|(_, r)| *r == Some((sd, f)));
            if !found {
                let m = cat!(b"required field is missing: ", self.structs[sd].fields[f].name, b" in ", self.structs[sd].name);
                return self.err(m);
            }
        }

        let start = self.builder.start_table();
        let sizes: &[usize] = if self.structs[sd].sortbysize { &[8, 4, 2, 1] } else { &[1] };
        let sortbysize = self.structs[sd].sortbysize;
        for &size in sizes {
            let len = self.field_stack.len();
            for k in 0..fieldn_outer {
                let (field_value, fref) = self.field_stack[len - 1 - k].clone();
                let (fsd, ffi) = fref.unwrap();
                let field = self.structs[fsd].fields[ffi].clone();
                let bt = field_value.ty.base;
                if sortbysize && size != bt.size_of() {
                    continue;
                }
                if bt.is_scalar() {
                    if field.is_scalar_optional() {
                        if field_value.constant != b"null" {
                            let v = self.atot(&field_value.constant, bt)?;
                            self.builder.add_scalar(field_value.offset, &v.le_bytes(bt));
                        }
                    } else {
                        let v = self.atot(&field_value.constant, bt)?;
                        let d = self.atot(&field.value.constant, bt)?;
                        if !v.same_as(d) {
                            self.builder.add_scalar(field_value.offset, &v.le_bytes(bt));
                        }
                    }
                } else {
                    let off = Self::atoi(&field_value.constant);
                    self.builder.add_offset(field_value.offset, off);
                }
            }
        }
        let n = self.field_stack.len() - fieldn_outer;
        self.field_stack.truncate(n);
        let val = self.builder.end_table(start);
        Ok((val.to_string().into_bytes(), val))
    }

    fn parse_vector(&mut self, vector_type: Type, field: Option<FieldRef>, fieldn: usize) -> R<u32> {
        let ty = vector_type.vector_type();
        let mut count = 0usize;
        self.parse_vector_delimiters(&mut count, &mut |p, count| {
            let mut val = Value::new(ty);
            p.parse_any_value(&mut val, field, fieldn, None, count, true)?;
            p.field_stack.push((val, None));
            Ok(())
        })?;
        let elem = ty.base.size_of();
        self.builder.start_vector(count, elem, elem);
        for _ in 0..count {
            let (val, _) = self.field_stack.pop().unwrap();
            let bt = val.ty.base;
            if bt.is_scalar() {
                let v = self.atot(&val.constant, bt)?;
                self.builder.push_scalar(&v.le_bytes(bt));
            } else {
                let off = Self::atoi(&val.constant);
                let r = self.builder.refer_to(off);
                self.builder.push_scalar(&r.to_le_bytes());
            }
        }
        self.builder.clear_offsets();
        Ok(self.builder.end_vector(count))
    }

    fn parse_any_value(
        &mut self,
        val: &mut Value,
        field: Option<FieldRef>,
        parent_fieldn: usize,
        parent_struct: Option<usize>,
        count: usize,
        inside_vector: bool,
    ) -> R {
        let field_def = field.map(|(s, f)| self.structs[s].fields[f].clone());
        let field_name = field_def.as_ref().map(|f| f.name.clone());
        match val.ty.base {
            B::Union => {
                let field_def = field_def.unwrap();
                let mut constant: Vec<u8> = Vec::new();
                let len = self.field_stack.len();
                for k in count..parent_fieldn + count {
                    let Some((s, f)) = self.field_stack[len - 1 - k].1 else { continue };
                    let ty = self.structs[s].fields[f].value.ty;
                    if ty.enum_def == val.ty.enum_def && !inside_vector && ty.base == B::UType {
                        constant = self.field_stack[len - 1 - k].0.constant.clone();
                        break;
                    }
                }
                if constant.is_empty() && !inside_vector {
                    let type_name = cat!(field_def.name, b"_type");
                    let ps = parent_struct.unwrap();
                    let tfi = self.structs[ps].lookup(&type_name).unwrap();
                    let backup = self.st.clone();
                    self.skip_any_json_value()?;
                    self.parse_comma()?;
                    let next_name = self.st.attribute.clone();
                    if self.is(K_TOKEN_STRING_CONSTANT) {
                        self.next()?;
                    } else {
                        self.expect(K_TOKEN_IDENTIFIER)?;
                    }
                    if next_name == type_name {
                        self.expect(b':' as i32)?;
                        let mut type_val = self.structs[ps].fields[tfi].value.clone();
                        self.guarded(|p| p.parse_any_value(&mut type_val, Some((ps, tfi)), 0, None, 0, false))?;
                        constant = type_val.constant;
                        self.st = backup;
                    }
                }
                if constant.is_empty() {
                    return self.err(cat!(b"missing type field for this union value: ", field_def.name));
                }
                let Num::I(enum_idx) = self.atot(&constant, B::UType)? else { unreachable!() };
                let ed = &self.enums[val.ty.enum_def.unwrap()];
                let Some(ev) = ed.reverse_lookup(enum_idx, true) else {
                    return self.err(cat!(b"illegal type id for: ", field_def.name));
                };
                match ev.union_type.base {
                    B::Struct => {
                        let sd = ev.union_type.struct_def.unwrap();
                        let (c, _) = self.parse_table(sd)?;
                        val.constant = c;
                    }
                    _ => return self.err("siem-router: string union members are not supported"),
                }
            }
            B::Struct => {
                let (c, _) = self.parse_table(val.ty.struct_def.unwrap())?;
                val.constant = c;
            }
            B::String => self.parse_string(val)?,
            B::Vector => {
                let off = self.parse_vector(val.ty, field, parent_fieldn)?;
                val.constant = off.to_string().into_bytes();
            }
            _ => self.parse_single_value(field_name.as_deref(), val, false)?,
        }
        Ok(())
    }

    fn try_typed_value(&mut self, name: Option<&[u8]>, dtoken: i32, check: bool, e: &mut Value, req: BaseType, matched: &mut bool) -> R {
        *matched = true;
        e.constant = self.st.attribute.clone();
        if !check {
            if e.ty.base == B::None {
                e.ty.base = req;
            } else {
                let m = cat!(
                    b"type mismatch: expecting: ",
                    e.ty.base.name(),
                    b", found: ",
                    req.name(),
                    b", name: ",
                    name.unwrap_or_default(),
                    b", value: ",
                    e.constant
                );
                return self.err(m);
            }
        }
        if dtoken != K_TOKEN_FLOAT_CONSTANT && e.ty.base.is_float() {
            let s = &e.constant;
            if let Some(k) = s.iter().position(|c| b"0123456789.".contains(c)) {
                if s.len() > k + 1 && s[k] == b'0' && is_alpha_char(s[k + 1], b'X') && !s[k + 2..].iter().any(|c| *c == b'p' || *c == b'P') {
                    let m = cat!(b"invalid number, the exponent suffix of hexadecimal floating-point literals is mandatory: \"", s, b"\"");
                    return self.err(m);
                }
            }
        }
        self.next()
    }

    fn parse_function(&mut self, name: Option<&[u8]>, e: &mut Value) -> R {
        self.guarded(|p| {
            let functionname = p.st.attribute.clone();
            if !e.ty.base.is_float() {
                let m = cat!(
                    functionname,
                    b": type of argument mismatch, expecting: double, found: ",
                    e.ty.base.name(),
                    b", name: ",
                    name.unwrap_or_default(),
                    b", value: ",
                    e.constant
                );
                return p.err(m);
            }
            p.next()?;
            p.expect(b'(' as i32)?;
            p.parse_single_value(name, e, false)?;
            p.expect(b')' as i32)?;
            let Num::F64(x) = p.atot(&e.constant.clone(), B::Double)? else { unreachable!() };
            const PI: f64 = 3.14159265358979323846;
            let y = match functionname.as_slice() {
                b"deg" => x / PI * 180.0,
                b"rad" => x * PI / 180.0,
                b"sin" => x.sin(),
                b"cos" => x.cos(),
                b"tan" => x.tan(),
                b"asin" => x.asin(),
                b"acos" => x.acos(),
                b"atan" => x.atan(),
                _ => {
                    let m = cat!(b"Unknown conversion function: ", functionname, b", field name: ", name.unwrap_or_default(), b", value: ", e.constant);
                    return p.err(m);
                }
            };
            e.constant = float_to_string(y, 12);
            Ok(())
        })
    }

    fn parse_enum_from_string(&mut self, ty: Type) -> R<Vec<u8>> {
        let base = ty.enum_def.map(|e| self.enums[e].underlying.base).unwrap_or(ty.base);
        if !base.is_integer() {
            return self.err("not a valid value for this field");
        }
        let mut u64v: u64 = 0;
        let attr = self.st.attribute.clone();
        for word in attr.split(|&c| c == b' ') {
            let ev_value = if let Some(e) = ty.enum_def {
                self.enums[e].lookup(word).map(|v| v.value)
            } else {
                let Some(dot) = word.iter().position(|&c| c == b'.') else {
                    return self.err("enum values need to be qualified by an enum type");
                };
                let enum_def_str = &word[..dot];
                let Some(e) = self.lookup_enum(enum_def_str) else {
                    return self.err(cat!(b"unknown enum: ", enum_def_str));
                };
                self.enums[e].lookup(&word[dot + 1..]).map(|v| v.value)
            };
            let Some(v) = ev_value else {
                return self.err(cat!(b"unknown enum value: ", word));
            };
            u64v |= v as u64;
        }
        Ok(if base.is_unsigned() { u64v.to_string().into_bytes() } else { (u64v as i64).to_string().into_bytes() })
    }

    fn parse_single_value(&mut self, name: Option<&[u8]>, e: &mut Value, check_now: bool) -> R {
        if self.st.token == b'+' as i32 || self.st.token == b'-' as i32 {
            let sign = self.st.token as u8;
            self.next()?;
            if self.st.token != K_TOKEN_IDENTIFIER {
                return self.err("constant name expected");
            }
            self.st.attribute.insert(0, sign);
        }
        let in_type = e.ty.base;
        let is_tok_ident = self.st.token == K_TOKEN_IDENTIFIER;
        let is_tok_string = self.st.token == K_TOKEN_STRING_CONSTANT;
        if is_tok_ident && self.cur() == b'(' {
            return self.parse_function(name, e);
        }
        let mut matched = false;
        macro_rules! try_ {
            ($force:expr, $dtoken:expr, $check:expr, $req:expr) => {
                if !matched && ($dtoken) == self.st.token && (($check) || $force) {
                    self.try_typed_value(name, $dtoken, $check, e, $req, &mut matched)?;
                }
            };
        }
        if is_tok_ident || is_tok_string {
            let k_token_string_or_ident = self.st.token;
            try_!(false, K_TOKEN_STRING_CONSTANT, in_type == B::String, B::String);
            if !matched && is_tok_string && in_type.is_scalar() && !self.st.attr_is_trivial_ascii_string {
                let m = cat!(
                    b"type mismatch or invalid value, an initializer of non-string field must be trivial ASCII string: type: ",
                    in_type.name(),
                    b", name: ",
                    name.unwrap_or_default(),
                    b", value: ",
                    self.st.attribute
                );
                return self.err(m);
            }
            if !matched && in_type == B::Bool {
                let is_true = self.st.attribute == b"true";
                if is_true || self.st.attribute == b"false" {
                    self.st.attribute = if is_true { b"1".to_vec() } else { b"0".to_vec() };
                    try_!(false, k_token_string_or_ident, true, B::Bool);
                }
            }
            if !matched && in_type.is_scalar() && self.st.attribute == b"null" {
                e.constant = b"null".to_vec();
                self.next()?;
                matched = true;
            }
            if !matched && in_type.is_integer() && in_type != B::Bool && is_identifier_start(self.st.attribute.first().copied().unwrap_or(0)) {
                e.constant = self.parse_enum_from_string(e.ty)?;
                self.next()?;
                matched = true;
            }
            if !matched && is_tok_string && in_type.is_scalar() {
                if let Some(p) = self.st.attribute.iter().rposition(|&c| c != b' ') {
                    self.st.attribute.truncate(p + 1);
                }
                if e.ty.base.is_float() && self.st.attribute.contains(&b')') {
                    let m = cat!(b"invalid number: ", self.st.attribute);
                    return self.err(m);
                }
            }
            try_!(false, k_token_string_or_ident, in_type.is_float(), B::Float);
            try_!(false, k_token_string_or_ident, in_type.is_integer(), B::Int);
            try_!(true, K_TOKEN_STRING_CONSTANT, in_type == B::String, B::String);
        } else {
            try_!(false, K_TOKEN_FLOAT_CONSTANT, in_type.is_float(), B::Float);
            if !matched && self.st.token == K_TOKEN_FLOAT_CONSTANT && in_type.is_integer() && self.opts.zero_on_float_to_int {
                self.st.attribute = b"0".to_vec();
                try_!(false, K_TOKEN_FLOAT_CONSTANT, in_type.is_integer(), B::Int);
            }
            try_!(true, K_TOKEN_INTEGER_CONSTANT, in_type.is_scalar(), B::Int);
        }
        if !matched && e.ty.base == B::Vector && self.st.token == b'[' as i32 {
            self.next()?;
            if self.st.token != b']' as i32 {
                return self.err("Expected `]` in vector default");
            }
            self.next()?;
            matched = true;
            e.constant = b"[]".to_vec();
        }
        if !matched {
            let m = cat!(b"Cannot assign token starting with '", self.token_to_string_id(self.st.token), b"' to value of <", in_type.name(), b"> type.");
            return self.err(m);
        }
        let match_type = e.ty.base;
        if check_now && match_type.is_scalar() && e.constant != b"null" {
            let v = self.atot(&e.constant.clone(), match_type)?;
            if match_type.is_integer() {
                e.constant = match v {
                    Num::I(i) => num_to_string_i(i),
                    Num::U(u) => u.to_string().into_bytes(),
                    _ => e.constant.clone(),
                };
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser(schema: &str) -> Parser {
        let mut p = Parser::new();
        p.opts.skip_unexpected_fields_in_json = true;
        p.opts.zero_on_float_to_int = true;
        assert!(p.parse(schema.as_bytes()), "{}", String::from_utf8_lossy(&p.error));
        p
    }

    #[test]
    fn simple_table() {
        let mut p = parser("table T { a:string; b:long; c:int = null; } root_type T;");
        assert!(p.parse(br#"{"a":"x","b":5,"c":0}"#), "{}", String::from_utf8_lossy(&p.error));
        // root offset, vtable (8 bytes: 3 fields + 2 header), table, string
        assert!(!p.parse(br#"{"b":"1x"}"#));
        assert_eq!(String::from_utf8_lossy(&p.error), "1: 10: error: invalid number: \"1x\"");
        assert!(!p.parse(br#"{"b":"x"}"#));
        assert_eq!(String::from_utf8_lossy(&p.error), "1: 8: error: enum values need to be qualified by an enum type");
    }
}
