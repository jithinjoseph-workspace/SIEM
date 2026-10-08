"""Generates src/wdb/state.rs from Wazuh's wazuh_db/wdb_state.c: every
w_inc_* counter function and wdb_create_state_json, transcribed statement by
statement (the C struct fields become string keys).

Usage: python gen_state.py <wazuh src> <out .rs>
"""
import re
import sys

src, out = sys.argv[1], sys.argv[2]
c = open(src + '/wazuh_db/wdb_state.c', encoding='utf-8').read()

out_fns = []
paths = set()

# --- the counter functions -------------------------------------------------
for m in re.finditer(r'^void (w_inc_\w+)\(([^)]*)\) \{\n(.*?)^\}', c, re.M | re.S):
    name, params, body = m.group(1), m.group(2).strip(), m.group(3)
    args = []
    if params:
        for p in params.split(','):
            p = p.strip()
            if p == 'struct timeval time':
                args.append('time: Tv')
            elif p == 'int type':
                args.append('type_: i32')
            else:
                raise SystemExit('param ' + p)
    lines = ['    pub fn %s(&self%s) {' % (name, ''.join(', ' + a for a in args)),
             '        let mut g = self.lock();']
    in_switch = False
    for raw in body.split('\n'):
        s = raw.strip()
        if not s or s.startswith('w_mutex_lock') or s.startswith('w_mutex_unlock'):
            continue
        mm = re.fullmatch(r'wdb_state\.([\w.]+)\+\+;', s)
        if mm:
            paths.add(mm.group(1))
            lines.append('        ' + ('    ' if in_switch else '') + 'g.inc("%s");' % mm.group(1))
            continue
        mm = re.fullmatch(r'timeradd\(&wdb_state\.([\w.]+), &time, &wdb_state\.([\w.]+)\);', s)
        if mm:
            assert mm.group(1) == mm.group(2)
            paths.add(mm.group(1))
            lines.append('        ' + ('        ' if in_switch else '') + 'g.add("%s", time);' % mm.group(1))
            continue
        if s == 'switch (type) {':
            in_switch = True
            lines.append('        match type_ {')
            continue
        mm = re.fullmatch(r'case (WDB_\w+):', s)
        if mm:
            lines.append('            c if c == super::%s => {' % mm.group(1))
            continue
        if s == 'break;':
            lines.append('            }')
            continue
        if s == 'default:':
            lines.append('            _ => {')
            continue
        if s == '}' and in_switch:
            in_switch = False
            lines.append('        }')
            continue
        raise SystemExit('unhandled in %s: %r' % (name, s))
    lines.append('    }')
    out_fns.append('\n'.join(lines))

# --- the time aggregates --------------------------------------------------
aggs = []
for m in re.finditer(r'^STATIC uint64_t (get_\w+_time)\(wdb_state_t \*state\)\{\n(.*?)^\}', c, re.M | re.S):
    name, body = m.group(1), m.group(2)
    terms = []
    for s in body.split('\n'):
        s = s.strip()
        mm = re.fullmatch(r'timeradd\(&state->([\w.]+), &state->([\w.]+), &task_time\);', s)
        if mm:
            terms += [mm.group(1), mm.group(2)]
            continue
        mm = re.fullmatch(r'timeradd\(&task_time, &state->([\w.]+), &task_time\);', s)
        if mm:
            terms.append(mm.group(1))
            continue
        if s in ('', 'struct timeval task_time;', 'return timeval_to_milis(task_time);'):
            continue
        raise SystemExit('unhandled agg %s: %r' % (name, s))
    for t in terms:
        paths.add(t)
    aggs.append((name, terms))
m = re.search(r'STATIC uint64_t get_time_total\(wdb_state_t \*state\)\{\n\s*return (.*?);\n\}', c, re.S)
total_expr = m.group(1)

# --- the JSON ---------------------------------------------------------------
m = re.search(r'cJSON\* wdb_create_state_json\(\) \{\n(.*?)\n    return wdb_state_json;\n\}', c, re.S)
json_lines = []


def expr(e):
    e = e.strip()
    mm = re.fullmatch(r'timeval_to_milis\(wdb_state_cpy\.([\w.]+)\)', e)
    if mm:
        paths.add(mm.group(1))
        return 's.ms("%s") as f64' % mm.group(1)
    mm = re.fullmatch(r'wdb_state_cpy\.uptime', e)
    if mm:
        return 's.uptime as f64'
    mm = re.fullmatch(r'wdb_state_cpy\.([\w.]+)', e)
    if mm:
        paths.add(mm.group(1))
        return 's.n("%s") as f64' % mm.group(1)
    mm = re.fullmatch(r'(get_\w+)\(&wdb_state_cpy\)', e)
    if mm:
        return 's.%s() as f64' % mm.group(1)
    if e == 'time(NULL)':
        return 'now as f64'
    raise SystemExit('expr ' + e)


for s in m.group(1).split('\n'):
    s = s.strip()
    if not s or s.startswith('//') or s in ('wdb_state_t wdb_state_cpy;', 'w_mutex_lock(&db_state_t_mutex);',
                                            'memcpy(&wdb_state_cpy, &wdb_state, sizeof(wdb_state_t));',
                                            'w_mutex_unlock(&db_state_t_mutex);'):
        continue
    mm = re.fullmatch(r'cJSON \*(\w+) = cJSON_CreateObject\(\);', s)
    if mm:
        json_lines.append('        let %s = b.obj();' % mm.group(1))
        continue
    mm = re.fullmatch(r'cJSON_AddItemToObject\((\w+), "([\w-]+)", (\w+)\);', s)
    if mm:
        json_lines.append('        b.node(%s, "%s", %s);' % mm.groups())
        continue
    mm = re.fullmatch(r'cJSON_AddNumberToObject\((\w+), "([\w-]+)", (.*)\);', s)
    if mm:
        json_lines.append('        b.num(%s, "%s", %s);' % (mm.group(1), mm.group(2), expr(mm.group(3))))
        continue
    mm = re.fullmatch(r'cJSON_AddStringToObject\((\w+), "(\w+)", ARGV0\);', s)
    if mm:
        json_lines.append('        b.string(%s, "%s", ARGV0);' % mm.groups())
        continue
    raise SystemExit('json %r' % s)

with open(out, 'w', encoding='utf-8', newline='\n') as f:
    f.write('''//! wazuh-db's usage counters (wazuh_db/wdb_state.c).
//! Generated by tools/gen_state.py from the C source: do not edit.

#![allow(non_snake_case)]

use std::collections::HashMap;

use parking_lot::{Mutex, MutexGuard};
use siem_cjson::Json;

const ARGV0: &str = "wazuh-db";

/// `struct timeval`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tv {
    pub sec: i64,
    pub usec: i64,
}

impl Tv {
    /// `timersub(end, begin)`
    pub fn diff(end: Tv, begin: Tv) -> Tv {
        let mut sec = end.sec - begin.sec;
        let mut usec = end.usec - begin.usec;
        if usec < 0 {
            sec -= 1;
            usec += 1_000_000;
        }
        Tv { sec, usec }
    }

    /// `timeradd`
    pub fn add(self, o: Tv) -> Tv {
        let mut sec = self.sec + o.sec;
        let mut usec = self.usec + o.usec;
        if usec >= 1_000_000 {
            sec += 1;
            usec -= 1_000_000;
        }
        Tv { sec, usec }
    }

    /// `timeval_to_milis`
    pub fn ms(self) -> u64 {
        (self.sec as u64).wrapping_mul(1000).wrapping_add((self.usec / 1000) as u64)
    }
}

/// `wdb_state_t`
#[derive(Debug, Clone, Default)]
pub struct Counters {
    pub uptime: i64,
    n: HashMap<&'static str, u64>,
    t: HashMap<&'static str, Tv>,
}

impl Counters {
    fn inc(&mut self, k: &'static str) {
        *self.n.entry(k).or_default() += 1;
    }

    fn add(&mut self, k: &'static str, time: Tv) {
        let e = self.t.entry(k).or_default();
        *e = e.add(time);
    }

    /// A query counter.
    pub fn n(&self, k: &str) -> u64 {
        self.n.get(k).copied().unwrap_or(0)
    }

    fn tv(&self, k: &str) -> Tv {
        self.t.get(k).copied().unwrap_or_default()
    }

    /// A time counter in milliseconds.
    pub fn ms(&self, k: &str) -> u64 {
        self.tv(k).ms()
    }

    fn sum(&self, terms: &[&str]) -> u64 {
        let mut t = Tv::default();
        for k in terms {
            t = t.add(self.tv(k));
        }
        t.ms()
    }
''')
    for name, terms in aggs:
        f.write('\n    /// `%s`\n    pub fn %s(&self) -> u64 {\n        self.sum(&[\n' % (name, name))
        for t in terms:
            f.write('            "%s",\n' % t)
        f.write('        ])\n    }\n')
    te = total_expr
    te = re.sub(r'(get_\w+_time)\(state\)', r'self.\1()', te)
    te = re.sub(r'timeval_to_milis\(state->([\w.]+)\)', r'self.ms("\1")', te)
    f.write('\n    /// `get_time_total`\n    pub fn get_time_total(&self) -> u64 {\n        %s\n    }\n}\n' % te)
    f.write('''
/// `wdb_state` with its mutex.
#[derive(Debug, Default)]
pub struct State {
    m: Mutex<Counters>,
}

/// Builds a cJSON object tree in insertion order (objects are added to
/// their parents before being filled, like the C code does).
struct Builder {
    nodes: Vec<Vec<(&'static str, Item)>>,
}

enum Item {
    Num(f64),
    Str(&'static str),
    Node(usize),
}

impl Builder {
    fn obj(&mut self) -> usize {
        self.nodes.push(Vec::new());
        self.nodes.len() - 1
    }
    fn node(&mut self, parent: usize, k: &'static str, child: usize) {
        self.nodes[parent].push((k, Item::Node(child)));
    }
    fn num(&mut self, parent: usize, k: &'static str, v: f64) {
        self.nodes[parent].push((k, Item::Num(v)));
    }
    fn string(&mut self, parent: usize, k: &'static str, v: &'static str) {
        self.nodes[parent].push((k, Item::Str(v)));
    }
    fn build(&self, i: usize) -> Json {
        let mut o = Json::object();
        for (k, v) in &self.nodes[i] {
            let j = match v {
                Item::Num(n) => Json::number(*n),
                Item::Str(s) => Json::string(s),
                Item::Node(c) => self.build(*c),
            };
            o.add(k, j);
        }
        o
    }
}

impl State {
    fn lock(&self) -> MutexGuard<'_, Counters> {
        self.m.lock()
    }

    /// A copy of the counters.
    pub fn snapshot(&self) -> Counters {
        self.lock().clone()
    }

    /// `wdb_state.uptime = ...`
    pub fn set_uptime(&self, t: i64) {
        self.lock().uptime = t;
    }
''')
    for fn in out_fns:
        f.write('\n' + fn + '\n')
    f.write('''
    /// `wdb_create_state_json` (`now`: `time(NULL)`)
    pub fn create_state_json(&self, now: i64) -> Json {
        let s = self.snapshot();
        let mut b = Builder { nodes: Vec::new() };
''')
    f.write('\n'.join(json_lines) + '\n')
    f.write('        b.build(wdb_state_json)\n    }\n}\n')
print(len(out_fns), 'functions,', len(json_lines), 'json lines,', len(paths), 'paths')
