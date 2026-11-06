//! Test-vector generator: calls the OLD crates and records what they return.
//! Usage: rewrite-vectors <out-dir> <work-dir> <all|fileop>
//! `all` writes regex + crypto + fileop; `fileop` writes only the platform files of fileop.

mod cryptov;
mod fileopv;
mod regexv;

use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;

pub fn h(b: &[u8]) -> String {
    hex::encode(b)
}

/// Latin-1 text to bytes ('\u{80}' -> 0x80), so byte alphabets can be written as &str.
pub fn l1(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}

pub struct Rng(u64);
impl Rng {
    pub fn new(s: u64) -> Self {
        Rng(s)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
    pub fn bytes(&mut self, alphabet: &[u8], max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| *self.pick(alphabet)).collect()
    }
}

pub struct Out {
    pub dir: PathBuf,
    pub platform: &'static str,
}

impl Out {
    /// One JSON file per name (split in parts under 18 MB): {"meta":{..},"cases":[one case per line]}.
    pub fn write(&self, krate: &str, name: &str, about: &str, cases: Vec<Value>) -> usize {
        let dir = self.dir.join(krate);
        std::fs::create_dir_all(&dir).unwrap();
        let lines: Vec<String> = cases.iter().map(|c| serde_json::to_string(c).unwrap()).collect();
        const MAX: usize = 18_000_000;
        let mut parts: Vec<Vec<&String>> = vec![vec![]];
        let mut size = 0;
        for l in &lines {
            if size + l.len() > MAX && !parts.last().unwrap().is_empty() {
                parts.push(vec![]);
                size = 0;
            }
            size += l.len() + 2;
            parts.last_mut().unwrap().push(l);
        }
        let n = parts.len();
        for (i, p) in parts.iter().enumerate() {
            let file = if n == 1 { format!("{name}.json") } else { format!("{name}.part{}.json", i + 1) };
            let meta = json!({"about": about, "platform": self.platform, "part": i + 1, "parts": n, "count": p.len()});
            let mut s = format!("{{\"meta\":{meta},\n\"cases\":[\n");
            s += &p.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(",\n");
            s += "\n]}\n";
            std::fs::write(dir.join(file), s).unwrap();
        }
        println!("{krate}/{name}: {} cases in {n} file(s)", cases.len());
        cases.len()
    }
}

// ---- log capture: the old crates log through `tracing` when no daemon logger is set

pub static LOGS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
struct Cap;
struct Vis(String);
impl tracing::field::Visit for Vis {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            self.0 = format!("{v:?}");
        }
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        if f.name() == "message" {
            self.0 = v.to_string();
        }
    }
}
impl tracing::Subscriber for Cap {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        let mut v = Vis(String::new());
        e.record(&mut v);
        LOGS.lock().unwrap().push((e.metadata().level().to_string(), v.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Log lines captured since the last call, as [level, text].
pub fn logs() -> Value {
    let v: Vec<Value> = LOGS.lock().unwrap().drain(..).map(|(l, m)| json!([l, m])).collect();
    json!(v)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let out = Out { dir: PathBuf::from(&a[1]), platform: if cfg!(windows) { "windows" } else { "unix" } };
    let work = PathBuf::from(&a[2]);
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    tracing::subscriber::set_global_default(Cap).unwrap();
    // a panic in the old code is recorded as a result, keep stderr quiet
    std::panic::set_hook(Box::new(|_| {}));
    let mut total = 0;
    if a[3] == "all" {
        total += regexv::run(&out);
        total += cryptov::run(&out, &work);
    }
    total += fileopv::run(&out, &work, a[3] == "all");
    println!("total {total} cases");
}
