//! The feed database (`queue/vd/feed`): applying feed messages, records derived from published
//! CVEs, the global maps, the translation cache and the lookups the scans use.

use crate::json::{compact, type_name};
use crate::kvstore::KvStore;
use crate::log::Log;
use crate::schema::{self, CVE_ENTRY, TRANSLATION};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub const COL_CVE: &str = "cve5";
pub const COL_TRANSLATION: &str = "translation";
pub const COL_VENDOR_MAP: &str = "vendor_map";
pub const COL_OSCPE: &str = "oscpe_rules";
pub const COL_CNA_MAPPING: &str = "cna_mapping";
pub const COL_REMEDIATIONS: &str = "remediations";
pub const COL_HOTFIXES: &str = "hotfixes_applications";
pub const KEY_VENDOR_MAP: &str = "FEED-GLOBAL";
pub const KEY_OSCPE: &str = "OSCPE-GLOBAL";
pub const KEY_CNA_MAPPING: &str = "CNA-MAPPING-GLOBAL";

type R<T> = Result<T, String>;

/// Compact JSON, zlib-compressed (fast level) when longer than 64 bytes.
pub fn encode(text: &str) -> Vec<u8> {
    if text.len() <= 64 {
        return text.as_bytes().to_vec();
    }
    let mut e = ZlibEncoder::new(Vec::new(), Compression::fast());
    let _ = e.write_all(text.as_bytes());
    e.finish().unwrap_or_else(|_| text.as_bytes().to_vec())
}

/// A value starting with 0x78 is compressed (JSON never starts with it).
pub fn decode(v: &[u8]) -> Option<String> {
    if v.first() == Some(&0x78) {
        let mut s = String::new();
        ZlibDecoder::new(v).read_to_string(&mut s).ok()?;
        Some(s)
    } else {
        String::from_utf8(v.to_vec()).ok()
    }
}

fn decode_json(v: &[u8]) -> Option<Value> {
    decode(v).and_then(|s| serde_json::from_str(&s).ok())
}

fn parse_json(s: &str) -> R<Value> {
    serde_json::from_str(s).map_err(|e| format!("JSON parse error: {e}"))
}

fn must_number(v: Option<&Value>) -> R<i64> {
    match v {
        Some(Value::Number(n)) => Ok(n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64)),
        other => Err(format!("JSON value must be number, but is {}", type_name(other.unwrap_or(&Value::Null)))),
    }
}

/// A cached translation (6.9).
pub struct Translation {
    product: Option<Regex>,
    vendor: Option<Regex>,
    version: Option<Regex>,
    target: Vec<String>,
    entries: Vec<(String, String, String)>,
}

#[derive(Default)]
pub struct Maps {
    pub vendor: Value,
    pub oscpe: Value,
    pub cna_mapping: Value,
    translations: BTreeMap<String, Translation>,
}

pub struct FeedDb {
    pub store: KvStore,
    pub maps: Maps,
    home: PathBuf,
    /// Resources created, updated or deleted since the last `take_changes`.
    changed: AtomicUsize,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Translation,
    Cve,
    Map(&'static str, &'static str),
}

impl FeedDb {
    pub fn open(home: &Path, dir: &Path) -> R<FeedDb> {
        Ok(FeedDb { store: KvStore::open(dir)?, maps: Maps::default(), home: home.to_path_buf(), changed: AtomicUsize::new(0) })
    }

    fn ensure(&self, c: &str) -> R<()> {
        if !self.store.has_column(c) {
            self.store.create_column(c)?;
        }
        Ok(())
    }

    // ---- messages (6.1-6.3) -----------------------------------------------------------------

    /// Applies one published message: (offset, hash, status) or an error. The write batch is
    /// committed also when an error stops the message (applied resources stay).
    /// Number of resources changed since the last call (feed updates without changes do not
    /// trigger a re-scan).
    pub fn take_changes(&self) -> usize {
        self.changed.swap(0, Ordering::Relaxed)
    }

    pub fn apply_message(&self, msg: &Value, stop: &AtomicBool, log: &Log) -> R<(i64, String, bool)> {
        let (Some(paths), Some(ty), Some(_)) = (msg.get("paths"), msg.get("type"), msg.get("offset")) else {
            return Err("Invalid message. Missing required fields.".into());
        };
        let paths: Vec<String> = paths.as_array().map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_string)).collect()).unwrap_or_default();
        self.store.begin_batch()?;
        let r = match ty.as_str() {
            Some("offsets") => self.apply_pages(&paths, stop, log),
            Some("raw") => self.apply_raw(&paths, msg, stop, log),
            _ => Err("Invalid message. Unknown type.".into()),
        };
        // The batch is committed also when the message failed; a commit error is reported.
        let c = self.store.end_batch();
        let r = r?;
        c?;
        Ok(r)
    }

    fn path(&self, p: &str) -> PathBuf {
        let pb = Path::new(p);
        if pb.is_absolute() {
            pb.to_path_buf()
        } else {
            self.home.join(p)
        }
    }

    fn apply_pages(&self, paths: &[String], stop: &AtomicBool, log: &Log) -> R<(i64, String, bool)> {
        let mut last = 0i64;
        'files: for p in paths {
            vs!(log, Debug2, "Processing file: {p}");
            let text = std::fs::read_to_string(self.path(p)).map_err(|e| format!("Unable to open file: {p} ({e})"))?;
            let page = parse_json(&text)?;
            let Some(items) = page.get("data").and_then(Value::as_array) else { continue };
            for item in items {
                self.apply_resource(item, log)?;
                last = match item.get("offset") {
                    Some(Value::Number(n)) if n.as_i64().is_some() => n.as_i64().unwrap_or(0),
                    _ => return Err(crate::json::key_missing_text("offset")),
                };
                if stop.load(Ordering::Relaxed) {
                    break 'files;
                }
            }
        }
        vs!(log, Debug2, "Last offset processed: {last}");
        Ok((last, String::new(), true))
    }

    fn apply_raw(&self, paths: &[String], msg: &Value, stop: &AtomicBool, log: &Log) -> R<(i64, String, bool)> {
        if paths.len() != 1 {
            return Err("Invalid raw message. Multiple files provided.".into());
        }
        self.store.delete_all()?;
        let p = &paths[0];
        vs!(log, Debug2, "Processing file: {p}");
        let f = std::fs::File::open(self.path(p)).map_err(|_| format!("Unable to open input file: {p}"))?;
        let mut rd = BufReader::with_capacity(1 << 20, f);
        let mut line = Vec::new();
        let mut n = 0u64;
        let mut max = 0i64;
        loop {
            if stop.load(Ordering::Relaxed) {
                return Ok((0, String::new(), true));
            }
            line.clear();
            if rd.read_until(b'\n', &mut line).map_err(|e| e.to_string())? == 0 {
                break;
            }
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            n += 1;
            if n % 1000 == 1 {
                vs!(log, Debug2, "Processing line: {n}");
            }
            let v: Value = serde_json::from_slice(&line).map_err(|_| format!("Invalid line found in file: {p}"))?;
            let (Some(name), Some(off)) = (v.get("name"), v.get("offset")) else {
                return Err(format!("Invalid line found in file: {p}"));
            };
            max = max.max(off.as_i64().unwrap_or(0));
            let mut res = v.clone();
            res["resource"] = name.clone();
            res["type"] = "create".into();
            self.apply_resource(&res, log)?;
        }
        let hash = msg.pointer("/fileMetadata/hash").and_then(Value::as_str).unwrap_or("").to_string();
        Ok((max, hash, true))
    }

    // ---- one resource (6.4) -----------------------------------------------------------------

    pub fn apply_resource(&self, res: &Value, log: &Log) -> R<()> {
        let name = match res.get("resource") {
            None => return Err("Missing key 'resource'.".into()),
            Some(Value::String(s)) => s.as_str(),
            Some(o) => return Err(crate::json::wrong_type_text("string", o)),
        };
        let kind = if name.starts_with("TID-") {
            Kind::Translation
        } else if name.starts_with("CVE-") {
            Kind::Cve
        } else if name.starts_with(KEY_VENDOR_MAP) {
            Kind::Map(COL_VENDOR_MAP, KEY_VENDOR_MAP)
        } else if name.starts_with(KEY_OSCPE) {
            Kind::Map(COL_OSCPE, KEY_OSCPE)
        } else if name.starts_with(KEY_CNA_MAPPING) {
            Kind::Map(COL_CNA_MAPPING, KEY_CNA_MAPPING)
        } else {
            vs!(log, Debug2, "Invalid resource type: {name}.");
            return Ok(());
        };
        for c in [COL_CVE, COL_TRANSLATION, COL_VENDOR_MAP, COL_OSCPE, COL_CNA_MAPPING] {
            self.ensure(c)?;
        }
        let (col, key) = match kind {
            Kind::Cve => (COL_CVE, name),
            Kind::Translation => (COL_TRANSLATION, name),
            Kind::Map(c, _) => (c, name),
        };
        let ty = res.get("type").and_then(Value::as_str).unwrap_or("");
        let record: Option<Value> = match ty {
            "create" => {
                let payload = res.get("payload").ok_or_else(|| crate::json::key_missing_text("payload"))?;
                Some(self.store_payload(kind, col, key, payload)?)
            }
            "update" => {
                let stored = self.store.get(col, key.as_bytes())?.ok_or("Unable to find resource.")?;
                let ops = res.get("operations").ok_or_else(|| crate::json::key_missing_text("operations"))?;
                Some(self.update_stored(kind, col, key, &stored, ops)?)
            }
            "delete" => {
                if kind == Kind::Translation {
                    self.store.delete(col, key.as_bytes())?;
                }
                None
            }
            _ => return Err("Unknown event type".into()),
        };
        if record.is_some() || kind == Kind::Translation {
            self.changed.fetch_add(1, Ordering::Relaxed);
        }
        if kind != Kind::Cve {
            return Ok(());
        }
        let Some(rec) = record else { return Err("CVE5 buffer is empty".into()) };
        let state = rec.pointer("/cveMetadata/state").and_then(Value::as_str).unwrap_or("");
        match (ty, state) {
            (_, "PUBLISHED") => {
                let offset = must_number(res.get("offset"))?;
                self.store_hotfix_index(&rec)?;
                self.store_remediations(&rec, log)?;
                self.store_descriptions(&rec, offset as i32)?;
                self.store_candidates(&rec)?;
            }
            ("update", "REJECTED") => self.remove_derived(&rec)?,
            ("update", _) => return Err("Invalid state of resource.".into()),
            _ => {}
        }
        Ok(())
    }

    fn store_payload(&self, kind: Kind, col: &str, key: &str, payload: &Value) -> R<Value> {
        match kind {
            Kind::Map(..) => {
                self.store.put(col, key.as_bytes(), compact(payload).as_bytes())?;
                Ok(payload.clone())
            }
            _ => {
                let root = if kind == Kind::Cve { CVE_ENTRY } else { TRANSLATION };
                let n = schema::normalize(root, payload).map_err(|e| format!("Unable to parse payload: {e}"))?;
                self.store.put(col, key.as_bytes(), &encode(&compact(&n)))?;
                Ok(n)
            }
        }
    }

    fn update_stored(&self, kind: Kind, col: &str, key: &str, stored: &[u8], ops: &Value) -> R<Value> {
        match kind {
            Kind::Map(..) => {
                let mut doc = parse_json(&String::from_utf8_lossy(stored))?;
                crate::patch::apply(&mut doc, ops)?;
                self.store.put(col, key.as_bytes(), compact(&doc).as_bytes())?;
                Ok(doc)
            }
            _ => {
                let (root, unreadable) = if kind == Kind::Cve {
                    (CVE_ENTRY, "Stored CVE record is unreadable")
                } else {
                    (TRANSLATION, "Stored translation record is unreadable")
                };
                let doc = decode_json(stored).ok_or(unreadable)?;
                let mut doc = schema::text_form(&doc);
                crate::patch::apply(&mut doc, ops)?;
                let n = schema::normalize(root, &doc).map_err(|e| format!("Unable to parse patched data: {e}"))?;
                self.store.put(col, key.as_bytes(), &encode(&compact(&n)))?;
                Ok(n)
            }
        }
    }

    // ---- derived records (6.7) --------------------------------------------------------------

    fn hotfix_keys(rec: &Value) -> Vec<String> {
        let cve = rec.pointer("/cveMetadata/cveId").and_then(Value::as_str).unwrap_or("");
        rec.pointer("/containers/cna/x_remediations/windows")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(|w| w.get("anyOf").and_then(Value::as_array).into_iter().flatten())
            .filter_map(Value::as_str)
            .map(|kb| format!("{kb}_{cve}"))
            .collect()
    }

    fn store_hotfix_index(&self, rec: &Value) -> R<()> {
        let keys = Self::hotfix_keys(rec);
        // The column exists once a CVE has the Windows remediation path, even without hotfixes.
        if rec.pointer("/containers/cna/x_remediations/windows").is_some() {
            self.ensure(COL_HOTFIXES)?;
        }
        for k in keys {
            self.store.put(COL_HOTFIXES, k.as_bytes(), b"")?;
        }
        Ok(())
    }

    fn store_remediations(&self, rec: &Value, log: &Log) -> R<()> {
        let Some(rem) = rec.pointer("/containers/cna/x_remediations") else { return Ok(()) };
        let Some(windows) = rem.get("windows").and_then(Value::as_array) else {
            vs!(log, Error, "Remediations database is empty.");
            return Ok(());
        };
        let mut updates = Vec::new();
        for w in windows {
            match w.get("anyOf").and_then(Value::as_array) {
                Some(a) => updates.extend(a.iter().cloned()),
                None => vs!(log, Error, "No updates available."),
            }
        }
        if !updates.is_empty() {
            self.ensure(COL_REMEDIATIONS)?;
            let cve = rec.pointer("/cveMetadata/cveId").and_then(Value::as_str).unwrap_or("");
            self.store.put(COL_REMEDIATIONS, cve.as_bytes(), &encode(&compact(&json!({"updates": updates}))))?;
        }
        Ok(())
    }

    fn containers(rec: &Value) -> Vec<&Value> {
        let mut v = Vec::new();
        if let Some(c) = rec.pointer("/containers/cna") {
            v.push(c);
        }
        if let Some(a) = rec.pointer("/containers/adp").and_then(Value::as_array) {
            v.extend(a.iter());
        }
        v
    }

    fn store_descriptions(&self, rec: &Value, offset: i32) -> R<()> {
        let meta = rec.get("cveMetadata").cloned().unwrap_or(Value::Null);
        let cve = crate::json::s(&meta, "cveId");
        for c in Self::containers(rec) {
            let pm = c.get("providerMetadata").cloned().unwrap_or(Value::Null);
            let Some(src) = pm.get("x_subShortName").or_else(|| pm.get("shortName")).and_then(Value::as_str) else { continue };
            let desc = c
                .get("descriptions")
                .and_then(Value::as_array)
                .and_then(|a| a.iter().find(|d| d.get("lang").and_then(Value::as_str) == Some("en")))
                .map(|d| crate::json::s(d, "value"))
                .unwrap_or("");
            if desc.is_empty() {
                continue;
            }
            let refs: Vec<&str> = c.get("references").and_then(Value::as_array).into_iter().flatten().filter_map(|r| r.get("url").and_then(Value::as_str)).collect();
            if refs.is_empty() {
                continue;
            }
            let mut metric: Option<(&Value, &Value)> = None;
            for m in c.get("metrics").and_then(Value::as_array).into_iter().flatten() {
                if let Some(x) = m.get("cvssV3_1") {
                    metric = Some((m, x));
                    break;
                }
                if let Some(x) = m.get("cvssV3_0") {
                    metric = Some((m, x));
                }
            }
            let mv = |k: &str| metric.map_or("", |(_, x)| crate::json::s(x, k)).to_string();
            let score = metric.and_then(|(_, x)| x.get("baseScore")).and_then(Value::as_f64).unwrap_or(0.0) as f32;
            let cwe = c.pointer("/problemTypes/0/descriptions/0/cweId").and_then(Value::as_str).unwrap_or("");
            let d = json!({
                "accessComplexity": "", "authentication": "",
                "assignerShortName": crate::json::s(&meta, "assignerShortName"),
                "attackVector": mv("attackVector"), "availabilityImpact": mv("availabilityImpact"),
                "classification": metric.map_or("", |(m, _)| crate::json::s(m, "format")),
                "confidentialityImpact": mv("confidentialityImpact"), "cweId": cwe,
                "datePublished": crate::json::s(&meta, "datePublished"), "dateUpdated": crate::json::s(&meta, "dateUpdated"),
                "description": desc, "integrityImpact": mv("integrityImpact"), "privilegesRequired": mv("privilegesRequired"),
                "reference": refs.join(", "), "scope": mv("scope"),
                "scoreBase": format!("{score}").parse::<f64>().unwrap_or(0.0),
                "scoreVersion": mv("version"), "severity": mv("baseSeverity"), "userInteraction": mv("userInteraction"),
                "offset": offset.to_string(),
            });
            let col = format!("descriptions_{src}");
            self.ensure(&col)?;
            self.store.put(&col, cve.as_bytes(), &encode(&compact(&d)))?;
        }
        Ok(())
    }

    fn candidate(cve: &str, short: &str, a: &Value) -> Value {
        let status = |s: Option<&str>| match s {
            Some("affected") => "affected",
            Some("unaffected") => "unaffected",
            _ => "unknown",
        };
        let mut c = json!({"cveId": cve, "defaultStatus": status(a.get("defaultStatus").and_then(Value::as_str))});
        if let Some(p) = a.get("platforms").and_then(Value::as_array).filter(|p| !p.is_empty()) {
            c["platforms"] = Value::Array(p.clone());
        }
        let versions: Vec<Value> = a
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|v| {
                let mut o = Map::new();
                o.insert("status".into(), status(v.get("status").and_then(Value::as_str)).into());
                for k in ["version", "lessThan", "lessThanOrEqual", "versionType"] {
                    if let Some(x) = v.get(k) {
                        o.insert(k.into(), x.clone());
                    }
                }
                Value::Object(o)
            })
            .collect();
        c["versions"] = Value::Array(versions);
        if short == "nvd" || short == "cisa" {
            if let Some(v) = a.get("vendor") {
                c["vendor"] = v.clone();
            }
        }
        c
    }

    fn store_candidates(&self, rec: &Value) -> R<()> {
        let Some(containers) = rec.get("containers") else { return Ok(()) };
        let cve = rec.pointer("/cveMetadata/cveId").and_then(Value::as_str).ok_or("Empty cveId.")?;
        let mut work: Vec<(&str, &Vec<Value>)> = Vec::new();
        for adp in containers.get("adp").and_then(Value::as_array).into_iter().flatten() {
            if let (Some(s), Some(a)) = (adp.pointer("/providerMetadata/x_subShortName").and_then(Value::as_str), adp.get("affected").and_then(Value::as_array)) {
                work.push((s, a));
            }
        }
        if let Some(cna) = containers.get("cna") {
            if let (Some(a), Some(s)) = (cna.get("affected").and_then(Value::as_array), cna.pointer("/providerMetadata/shortName").and_then(Value::as_str)) {
                work.push((s, a));
            }
        }
        for (short, affected) in work {
            let rev = format!("cve_package_{short}");
            self.ensure(short)?;
            self.ensure(&rev)?;
            let mut groups: BTreeMap<String, Vec<Value>> = BTreeMap::new();
            for a in affected {
                if let Some(p) = a.get("product").and_then(Value::as_str) {
                    groups.entry(p.to_lowercase()).or_default().push(Self::candidate(cve, short, a));
                }
            }
            let suffix = format!("_{cve}");
            for (k, v) in self.store.prefix(&rev, format!("{cve}_").as_bytes())? {
                let val = String::from_utf8_lossy(&v).into_owned();
                // The product is the stored text without its last `_<CVE id>` characters.
                let product = val.get(..val.len().saturating_sub(suffix.len())).unwrap_or("");
                if !groups.contains_key(product) {
                    self.store.delete(short, val.as_bytes())?;
                    self.store.delete(&rev, &k)?;
                }
            }
            for (product, cands) in groups {
                let text = compact(&json!({"candidates": cands}));
                let key = format!("{product}_{cve}");
                let old = match self.store.get(short, key.as_bytes())? {
                    Some(b) => Some(decode(&b).ok_or("Stored candidate list is unreadable")?),
                    None => None,
                };
                if old.as_deref() != Some(text.as_str()) {
                    self.store.put(short, key.as_bytes(), &encode(&text))?;
                    self.store.put(&rev, format!("{cve}_{product}").as_bytes(), key.as_bytes())?;
                }
            }
        }
        Ok(())
    }

    fn remove_derived(&self, rec: &Value) -> R<()> {
        let cve = rec.pointer("/cveMetadata/cveId").and_then(Value::as_str).unwrap_or("");
        if self.store.has_column(COL_HOTFIXES) {
            for k in Self::hotfix_keys(rec) {
                self.store.delete(COL_HOTFIXES, k.as_bytes())?;
            }
        }
        if self.store.has_column(COL_REMEDIATIONS) {
            self.store.delete(COL_REMEDIATIONS, cve.as_bytes())?;
        }
        let cols = self.store.columns();
        for c in cols.iter().filter(|c| c.starts_with("descriptions")) {
            self.store.delete(c, cve.as_bytes())?;
        }
        for c in &cols {
            let Some(x) = c.strip_prefix("cve_package_") else { continue };
            for (k, v) in self.store.prefix(c, format!("{cve}_").as_bytes())? {
                if self.store.has_column(x) {
                    self.store.delete(x, &v)?;
                }
                self.store.delete(c, &k)?;
            }
        }
        Ok(())
    }

    // ---- global maps (6.9) ------------------------------------------------------------------

    pub fn load_maps(&mut self, translation_cap: usize) -> R<()> {
        let get = |col: &str, key: &str| -> R<Option<Vec<u8>>> {
            if !self.store.has_column(col) {
                return Err(format!("Couldn't find column family: '{col}'"));
            }
            self.store.get(col, key.as_bytes())
        };
        let v = get(COL_VENDOR_MAP, KEY_VENDOR_MAP)?.ok_or("Vendor map can not be found in DB.")?;
        if v.is_empty() {
            return Err("Vendor map is empty.".into());
        }
        self.maps.vendor = parse_json(&String::from_utf8_lossy(&v))?;
        let v = get(COL_OSCPE, KEY_OSCPE)?.ok_or("OS CPE rules can not be found in DB.")?;
        self.maps.oscpe = parse_json(&String::from_utf8_lossy(&v))?;
        let v = get(COL_CNA_MAPPING, KEY_CNA_MAPPING)?.ok_or("CNA mapping can not be found in DB.")?;
        self.maps.cna_mapping = parse_json(&String::from_utf8_lossy(&v))?;
        if !self.store.has_column(COL_TRANSLATION) {
            return Err(format!("Couldn't find column family: '{COL_TRANSLATION}'"));
        }
        let mut err: Option<String> = None;
        let maps = &mut self.maps;
        self.store.scan(COL_TRANSLATION, b"", |k, v| {
            if maps.translations.len() >= translation_cap {
                return false;
            }
            match Self::compile(v) {
                Ok(t) => {
                    maps.translations.insert(String::from_utf8_lossy(k).into_owned(), t);
                    true
                }
                Err(e) => {
                    err = Some(e);
                    false
                }
            }
        })?;
        err.map_or(Ok(()), Err)
    }

    fn compile(v: &[u8]) -> R<Translation> {
        let t = decode_json(v).ok_or("Stored translation cache entry is unreadable.")?;
        let re = |k: &str| -> R<Option<Regex>> {
            match t.pointer(&format!("/source/{k}")).and_then(Value::as_str) {
                Some(p) if !p.is_empty() => Regex::new(p).map(Some).map_err(|e| e.to_string()),
                _ => Ok(None),
            }
        };
        Ok(Translation {
            product: re("product")?,
            vendor: re("vendor")?,
            version: re("version")?,
            target: t.get("target").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect(),
            entries: t
                .get("translation")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|e| (crate::json::s(e, "product").to_string(), crate::json::s(e, "vendor").to_string(), crate::json::s(e, "version").to_string()))
                .collect(),
        })
    }

    // ---- lookups (6.10) ---------------------------------------------------------------------

    /// Candidate lists of (cna, product), one per stored key in key order. A visitor that stops
    /// ends the current list only; the next list continues.
    pub fn candidate_lists(&self, cna: &str, product: &str) -> R<Vec<Vec<Value>>> {
        if cna.is_empty() || product.is_empty() {
            return Err("Invalid package/cna name.".into());
        }
        let rows = self.store.prefix(cna, format!("{product}_CVE").as_bytes())?;
        let mut out = Vec::with_capacity(rows.len());
        for (_, v) in rows {
            let mut list = decode_json(&v).ok_or("Stored candidate list is unreadable")?;
            match list.get_mut("candidates").map(Value::take) {
                Some(Value::Array(a)) => out.push(a),
                _ => out.push(Vec::new()),
            }
        }
        Ok(out)
    }

    pub fn description(&self, cve: &str, source: &str, log: &Log) -> R<Option<Value>> {
        let col = format!("descriptions_{source}");
        match self.store.get(&col, cve.as_bytes())? {
            Some(v) => Ok(decode_json(&v)),
            None => {
                vs!(log, Debug2, "Vulnerability description not found for {cve} in {col}.");
                Ok(None)
            }
        }
    }

    pub fn remediation(&self, cve: &str) -> R<Option<Vec<String>>> {
        match self.store.get(COL_REMEDIATIONS, cve.as_bytes())? {
            None => Ok(None),
            Some(v) => {
                let d = decode_json(&v).ok_or("Stored remediation record is unreadable.")?;
                Ok(Some(d.get("updates").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect()))
            }
        }
    }

    /// Keys of the hotfix index for the hotfix: whole id parts only (`KB123` or `KB123_...`).
    pub fn hotfix_keys_for(&self, hotfix: &str) -> R<Vec<String>> {
        if !self.store.has_column(COL_HOTFIXES) {
            return Ok(Vec::new());
        }
        let mut keys = self.store.keys_text(COL_HOTFIXES, &format!("{hotfix}_"))?;
        if self.store.get(COL_HOTFIXES, hotfix.as_bytes())?.is_some() {
            keys.insert(0, hotfix.to_string());
        }
        Ok(keys)
    }

    fn one_key(list: &str, key: &str, vendor: &Value) -> String {
        vendor
            .get(list)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .find_map(|o| o.iter().next().filter(|(k, _)| *k == key).map(|(_, v)| v.as_str().unwrap_or("").to_string()))
            .unwrap_or_default()
    }

    pub fn cna_by_format(&self, format: &str) -> String {
        Self::one_key("format", format, &self.maps.vendor)
    }
    pub fn cna_by_source(&self, source: &str) -> String {
        Self::one_key("source", source, &self.maps.vendor)
    }

    fn by_vendor(&self, list: &str, vendor: &str, platform: &str, hit: impl Fn(&str, &str) -> bool) -> String {
        self.maps
            .vendor
            .get(list)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .find_map(|o| {
                let (k, v) = o.iter().next()?;
                let has_platform = v.get("platforms").and_then(Value::as_array).is_some_and(|p| p.iter().any(|x| x.as_str() == Some(platform)));
                (hit(vendor, k) && has_platform).then(|| crate::json::s(v, "cna").to_string())
            })
            .unwrap_or_default()
    }

    pub fn cna_by_prefix(&self, vendor: &str, platform: &str) -> String {
        self.by_vendor("prefix", vendor, platform, |v, k| v.starts_with(k))
    }
    pub fn cna_by_contains(&self, vendor: &str, platform: &str) -> String {
        self.by_vendor("contains", vendor, platform, |v, k| v.contains(k))
    }

    /// Every (product, vendor, version) the cached translations give for a package.
    pub fn translate(&self, name: &str, vendor: &str, platform: &str) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for t in self.maps.translations.values() {
            if !t.target.iter().any(|x| x == platform) {
                continue;
            }
            if t.product.as_ref().is_some_and(|r| !r.is_match(name)) || t.vendor.as_ref().is_some_and(|r| !r.is_match(vendor)) {
                continue;
            }
            for (p, v, ver) in &t.entries {
                // The version pattern is applied to the package name (kept behaviour).
                let version = match t.version.as_ref().and_then(|r| r.captures(name)) {
                    Some(c) => c.get(1).map_or(String::new(), |m| m.as_str().to_string()),
                    None => ver.clone(),
                };
                out.push((p.clone(), v.clone(), version));
            }
        }
        out
    }

    /// Columns used by tests and diagnostics.
    pub fn column_names(&self) -> BTreeSet<String> {
        self.store.columns().into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{Level, MemoryLogger};
    use std::sync::Arc;

    fn db() -> (tempfile::TempDir, FeedDb) {
        let d = tempfile::tempdir().unwrap();
        let f = FeedDb::open(d.path(), &d.path().join("feed")).unwrap();
        (d, f)
    }

    fn cve1() -> Value {
        json!({"resource":"CVE-2024-1","type":"create","offset":7,"payload":{
            "cveMetadata":{"cveId":"CVE-2024-1","state":"PUBLISHED","assignerShortName":"mitre","datePublished":"2024-01-01"},
            "containers":{"cna":{
                "providerMetadata":{"orgId":"o","shortName":"nvd"},
                "descriptions":[{"lang":"en","value":"bad"}],
                "references":[{"url":"a"},{"url":"b"}],
                "metrics":[{"format":"CVSS","cvssV2_0":{"version":"2.0","baseScore":5.0}}],
                "affected":[{"vendor":"acme","product":"Foo","defaultStatus":"unaffected","versions":[{"status":"affected","version":"0","lessThan":"2.0","versionType":"custom"}]}],
                "x_remediations":{"windows":[{"anyOf":["KB1","KB2"]}]}
            }}}})
    }

    fn cands(f: &FeedDb, cna: &str, p: &str) -> Vec<Value> {
        f.candidate_lists(cna, p).unwrap().into_iter().flatten().collect()
    }

    #[test]
    fn create_update_reject() {
        let (_d, f) = db();
        let log = Log::null();
        f.apply_resource(&cve1(), &log).unwrap();
        let c = cands(&f, "nvd", "foo");
        assert_eq!(c.len(), 1);
        assert_eq!((c[0]["vendor"].as_str(), c[0]["versions"][0]["lessThan"].as_str()), (Some("acme"), Some("2.0")));
        let d = f.description("CVE-2024-1", "nvd", &log).unwrap().unwrap();
        assert_eq!((d["severity"].as_str(), d["reference"].as_str(), d["offset"].as_str(), d["scoreBase"].as_f64()), (Some(""), Some("a, b"), Some("7"), Some(0.0)));
        assert_eq!(f.remediation("CVE-2024-1").unwrap().unwrap(), vec!["KB1", "KB2"]);
        assert_eq!(f.hotfix_keys_for("KB2").unwrap(), vec!["KB2_CVE-2024-1"]);

        let upd = |ops: Value| json!({"resource":"CVE-2024-1","type":"update","offset":8,"operations":ops});
        f.apply_resource(&upd(json!([{"op":"replace","path":"/containers/cna/affected/0/product","value":"bar"}])), &log).unwrap();
        assert!(cands(&f, "nvd", "foo").is_empty());
        assert_eq!(cands(&f, "nvd", "bar").len(), 1);
        assert_eq!(f.store.keys_text("cve_package_nvd", "CVE-2024-1_").unwrap(), vec!["CVE-2024-1_bar"]);

        assert_eq!(f.apply_resource(&upd(json!([{"op":"replace","path":"/cveMetadata/state","value":"RESERVED"}])), &log).unwrap_err(), "Invalid state of resource.");
        f.apply_resource(&upd(json!([{"op":"replace","path":"/cveMetadata/state","value":"REJECTED"}])), &log).unwrap();
        assert!(cands(&f, "nvd", "bar").is_empty());
        assert!(f.description("CVE-2024-1", "nvd", &log).unwrap().is_none());
        assert!(f.hotfix_keys_for("KB2").unwrap().is_empty());
        assert!(f.remediation("CVE-2024-1").unwrap().is_none());
        assert!(f.store.get(COL_CVE, b"CVE-2024-1").unwrap().is_some());

        let e = |r: Value| f.apply_resource(&r, &log).unwrap_err();
        assert_eq!(e(json!({"resource":"CVE-9","type":"update","operations":[]})), "Unable to find resource.");
        assert_eq!(e(json!({"resource":"CVE-2024-1","type":"bogus"})), "Unknown event type");
        assert_eq!(e(json!({"resource":"CVE-2024-1","type":"delete"})), "CVE5 buffer is empty");
        assert_eq!(e(json!({"type":"delete"})), "Missing key 'resource'.");
        assert_eq!(e(json!({"resource":"CVE-2024-1","type":"update","operations":[{"op":"replace","path":"/nothere/x","value":1}]})), "JSON key 'nothere' not found");
        assert!(e(json!({"resource":"CVE-2024-1","type":"update","operations":[{"op":"test","path":"/dataType","value":1}]})).starts_with("JSON patch test failed: "));
        assert_eq!(e(json!({"resource":"CVE-3","type":"create","offset":1,"payload":{"bogus":1}})), "Unable to parse payload: line 1, column 10: unknown field: bogus");
        assert!(e(json!({"resource":"CVE-3","type":"create","offset":1,"payload":{"cveMetadata":{"serial":1.5}}})).ends_with("cannot store decimal number in a int field"));
    }

    #[test]
    fn translations_and_unknown_kinds() {
        let (_d, f) = db();
        let l = Arc::new(MemoryLogger::default());
        let log = Log::new(l.clone());
        f.apply_resource(&json!({"resource":"TCPE","type":"create","payload":{}}), &log).unwrap();
        assert!(l.has(Level::Debug2, "Invalid resource type: TCPE."));
        f.apply_resource(&json!({"resource":"TID-1","type":"create","payload":{"target":["windows"]}}), &log).unwrap();
        assert!(f.store.get(COL_TRANSLATION, b"TID-1").unwrap().is_some());
        f.apply_resource(&json!({"resource":"TID-1","type":"delete"}), &log).unwrap();
        assert!(f.store.get(COL_TRANSLATION, b"TID-1").unwrap().is_none());
    }

    #[test]
    fn remediation_errors_and_crafted_candidates() {
        let (_d, f) = db();
        let l = Arc::new(MemoryLogger::default());
        let log = Log::new(l.clone());
        let mk = |rem: Value| json!({"resource":"CVE-5","type":"create","offset":1,"payload":{"cveMetadata":{"cveId":"CVE-5","state":"PUBLISHED"},"containers":{"cna":{"x_remediations":rem}}}});
        f.apply_resource(&mk(json!({})), &log).unwrap();
        assert!(l.has(Level::Error, "Remediations database is empty."));
        f.apply_resource(&mk(json!({"windows":[{"type":"x"}]})), &log).unwrap();
        assert!(l.has(Level::Error, "No updates available."));

        let aff = |vendor: &str, product: &str| json!({"vendor":vendor,"product":product,"defaultStatus":"bogus","platforms":[],"versions":[{"status":"weird","version":"1"}]});
        let r = json!({"resource":"CVE-6","type":"create","offset":2,"payload":{"cveMetadata":{"cveId":"CVE-6","state":"PUBLISHED"},"containers":{
            "cna":{"providerMetadata":{"orgId":"o","shortName":"nvd"},"affected":[aff("v","Foo"),aff("v","FOO")]},
            "adp":[
                {"providerMetadata":{"orgId":"o","shortName":"x","x_subShortName":"cisa"},"affected":[aff("v","foo")]},
                {"providerMetadata":{"orgId":"o","shortName":"nvd","x_subShortName":"redhat"},"affected":[aff("v","foo")]},
                {"providerMetadata":{"orgId":"o","shortName":"other"},"affected":[aff("v","foo")]}
            ]}}});
        f.apply_resource(&r, &log).unwrap();
        let n = cands(&f, "nvd", "foo");
        assert_eq!(n.len(), 2);
        assert_eq!(n[0], json!({"cveId":"CVE-6","defaultStatus":"unknown","vendor":"v","versions":[{"status":"unknown","version":"1"}]}));
        assert_eq!(cands(&f, "cisa", "foo")[0]["vendor"], "v");
        assert!(cands(&f, "redhat", "foo")[0].get("vendor").is_none());
        assert!(!f.store.has_column("other"));
    }

    #[test]
    fn description_metric_choice() {
        let (_d, f) = db();
        let log = Log::null();
        let mut r = json!({"resource":"CVE-7","type":"create","offset":3,"payload":{"cveMetadata":{"cveId":"CVE-7","state":"PUBLISHED"},"containers":{"cna":{
            "providerMetadata":{"orgId":"o","shortName":"nvd"},"descriptions":[{"lang":"en","value":"d"}],"references":[{"url":"u"}],
            "metrics":[{"format":"CVSS","cvssV3_0":{"baseScore":"6.1 ","baseSeverity":"MEDIUM","version":"3.0"}},{"cvssV2_0":{"baseScore":9.0}},{"format":"CVSS","cvssV3_1":{"baseScore":7.25,"baseSeverity":"HIGH","version":"3.1"}}]}}}});
        f.apply_resource(&r, &log).unwrap();
        let d = f.description("CVE-7", "nvd", &log).unwrap().unwrap();
        assert_eq!((d["scoreBase"].as_f64(), d["severity"].as_str(), d["scoreVersion"].as_str()), (Some(7.25), Some("HIGH"), Some("3.1")));
        r["payload"]["containers"]["cna"]["metrics"].as_array_mut().unwrap().pop();
        f.apply_resource(&r, &log).unwrap();
        let d = f.description("CVE-7", "nvd", &log).unwrap().unwrap();
        assert_eq!((d["scoreBase"].as_f64(), d["severity"].as_str(), d["scoreVersion"].as_str()), (Some(6.1), Some("MEDIUM"), Some("3.0")));
    }

    #[test]
    fn messages() {
        let (d, f) = db();
        let stop = AtomicBool::new(false);
        let log = Log::null();
        assert_eq!(f.apply_message(&json!({"type":"raw","offset":0}), &stop, &log).unwrap_err(), "Invalid message. Missing required fields.");
        assert_eq!(f.apply_message(&json!({"paths":[],"type":"nope","offset":0}), &stop, &log).unwrap_err(), "Invalid message. Unknown type.");
        assert_eq!(f.apply_message(&json!({"paths":["a","b"],"type":"raw","offset":0}), &stop, &log).unwrap_err(), "Invalid raw message. Multiple files provided.");
        f.apply_resource(&json!({"resource":"TID-9","type":"create","payload":{}}), &log).unwrap();
        let p = d.path().join("snap.json");
        std::fs::write(&p, "{\"name\":\"FEED-GLOBAL\",\"offset\":3,\"payload\":{\"format\":[]}}\n{\"name\":\"CVE-1\",\"offset\":9,\"payload\":{\"cveMetadata\":{\"cveId\":\"CVE-1\",\"state\":\"PUBLISHED\"}}}\n").unwrap();
        let msg = json!({"paths":["snap.json"],"type":"raw","offset":0,"fileMetadata":{"hash":"h"}});
        assert_eq!(f.apply_message(&msg, &stop, &log).unwrap(), (9, "h".to_string(), true));
        assert!(f.store.get(COL_TRANSLATION, b"TID-9").unwrap().is_none());
        std::fs::write(&p, "{\"name\":\"FEED-GLOBAL\",\"offset\":3,\"payload\":{}}\n\n{\"name\":\"CVE-1\",\"offset\":9}\n").unwrap();
        assert_eq!(f.apply_message(&msg, &stop, &log).unwrap_err(), "Invalid line found in file: snap.json");
        std::fs::write(d.path().join("1000-api_file.json"), r#"{"data":[{"resource":"TID-2","type":"create","offset":12,"payload":{}}]}"#).unwrap();
        let m = json!({"paths":["1000-api_file.json"],"type":"offsets","offset":0});
        assert_eq!(f.apply_message(&m, &stop, &log).unwrap(), (12, String::new(), true));
        std::fs::write(d.path().join("1000-api_file.json"), r#"{"data":[]}"#).unwrap();
        assert_eq!(f.apply_message(&m, &stop, &log).unwrap().0, 0);
        stop.store(true, Ordering::Relaxed);
        assert_eq!(f.apply_message(&msg, &stop, &log).unwrap(), (0, String::new(), true));
    }

    #[test]
    fn value_encoding() {
        let short = r#"{"a":1}"#;
        assert_eq!(encode(short), short.as_bytes());
        let long = format!("{{\"a\":\"{}\"}}", "x".repeat(80));
        let e = encode(&long);
        assert_eq!(e[0], 0x78);
        assert_eq!(decode(&e).unwrap(), long);
    }

    #[test]
    fn corrections_d6_d11() {
        let (_d, f) = db();
        let log = Log::null();
        // D11: no remediations column is an error.
        assert_eq!(f.remediation("CVE-1").unwrap_err(), "Couldn't find column family: 'remediations'");
        // D6: full Unicode lower-casing of products.
        let r = json!({"resource":"CVE-8","type":"create","offset":1,"payload":{"cveMetadata":{"cveId":"CVE-8","state":"PUBLISHED"},"containers":{"cna":{
            "providerMetadata":{"orgId":"o","shortName":"nvd"},"affected":[{"product":"ÄPFEL","defaultStatus":"affected"}]}}}});
        f.apply_resource(&r, &log).unwrap();
        assert_eq!(cands(&f, "nvd", "äpfel").len(), 1);
        assert_eq!(f.store.keys_text("cve_package_nvd", "CVE-8_").unwrap(), vec!["CVE-8_äpfel"]);
    }

    #[test]
    fn hotfix_lookup_whole_ids() {
        // C1: KB123 never matches KB1234.
        let (_d, f) = db();
        let mk = |cve: &str, kb: &str| json!({"resource":cve,"type":"create","offset":1,"payload":{"cveMetadata":{"cveId":cve,"state":"PUBLISHED"},"containers":{"cna":{"x_remediations":{"windows":[{"anyOf":[kb]}]}}}}});
        f.apply_resource(&mk("CVE-1", "KB1234"), &Log::null()).unwrap();
        f.apply_resource(&mk("CVE-2", "KB123"), &Log::null()).unwrap();
        assert_eq!(f.hotfix_keys_for("KB123").unwrap(), vec!["KB123_CVE-2"]);
    }

    #[test]
    fn maps_missing() {
        let (_d, mut f) = db();
        assert_eq!(f.load_maps(10).unwrap_err(), "Couldn't find column family: 'vendor_map'");
    }
}
