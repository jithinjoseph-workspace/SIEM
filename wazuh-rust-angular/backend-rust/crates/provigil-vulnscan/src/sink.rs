//! Document sink: state documents kept locally (`queue/indexer/db/<index>`) or streamed to
//! siem-api with an "already sent" memory (`queue/indexer/sent/<index>`).

use crate::json::compact;
use crate::kvstore::{KvStore, DEFAULT_COLUMN};
use crate::log::Log;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

/// Frame kind of vulnerability documents on the platform stream.
pub const STREAM_KIND: u8 = b'V';

/// The platform stream towards siem-api. `Ok(Some(text))` is a warning (e.g. spool full).
// shortcut: the stream framing and spool (`queue/stream-spool/vulnerability`) belong to the
// shared stream library and are not defined here; the host supplies an adapter at wiring time.
pub trait StreamSpool: Send + Sync {
    fn send(&self, kind: u8, body: &str) -> Result<Option<String>, String>;
}

/// True when siem-api started the daemon with a stream address and token.
pub fn stream_env() -> bool {
    let set = |k: &str| std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false);
    set("SIEM_STREAM_ADDR") && set("SIEM_STREAM_TOKEN")
}

#[derive(Default)]
struct Rescan {
    seen: HashSet<String>,
    /// Deferred deletions: (operation, id).
    deferred: Vec<(String, String)>,
}

enum Mode {
    Local(KvStore),
    Stream { spool: Arc<dyn StreamSpool>, sent: KvStore, rescan: Option<Rescan> },
}

pub struct DocSink {
    mode: Mode,
    log: Log,
}

fn hash_without_detected_at(data: &Value) -> String {
    let mut d = data.clone();
    if let Some(v) = d.get_mut("vulnerability").and_then(Value::as_object_mut) {
        v.remove("detected_at");
    }
    hex::encode(Sha1::digest(compact(&d).as_bytes()))
}

/// Stored ids a deletion covers, by whole id parts: `DELETED` is the id itself and ids under
/// `<id>_` (the offset suffix); `DELETED_BY_QUERY` (an agent) is every id under `<id>_`.
fn matching(store: &KvStore, op: &str, id: &str) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    if op == "DELETED" && store.get(DEFAULT_COLUMN, id.as_bytes())?.is_some() {
        v.push(id.to_string());
    }
    v.extend(store.keys_text(DEFAULT_COLUMN, &format!("{id}_"))?);
    Ok(v)
}

impl DocSink {
    pub fn open(home: &Path, index: &str, stream: Option<Arc<dyn StreamSpool>>, log: Log) -> Result<DocSink, String> {
        if index.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(format!("Index name must be lowercase: {index}"));
        }
        let mode = match stream {
            Some(spool) => Mode::Stream { spool, sent: KvStore::open(&home.join("queue/indexer/sent").join(index))?, rescan: None },
            None => Mode::Local(KvStore::open(&home.join("queue/indexer/db").join(index))?),
        };
        Ok(DocSink { mode, log })
    }

    pub fn is_stream(&self) -> bool {
        matches!(self.mode, Mode::Stream { .. })
    }

    /// Starts the re-scan mode (no effect for a full re-scan or in local mode).
    pub fn begin_rescan(&mut self, full: bool) {
        if let Mode::Stream { rescan, .. } = &mut self.mode {
            *rescan = if full { None } else { Some(Rescan::default()) };
        }
    }

    /// Ends the re-scan mode: remembered documents under the deferred prefixes that were not
    /// seen again are deleted.
    pub fn end_rescan(&mut self) {
        let log = self.log.clone();
        let Mode::Stream { spool, sent, rescan } = &mut self.mode else { return };
        let Some(mut r) = rescan.take() else { return };
        r.deferred.sort();
        r.deferred.dedup();
        for (op, id) in &r.deferred {
            let ids = match matching(sent, op, id) {
                Ok(i) => i,
                Err(e) => {
                    ic!(log, Error, "Error processing event: {e}");
                    // An error ends the clean-up of the re-scan.
                    return;
                }
            };
            for id in ids.into_iter().filter(|i| !r.seen.contains(i)) {
                Self::send(spool.as_ref(), &compact(&json!({"id": id, "operation": "DELETED"})), &log);
                let _ = sent.delete(DEFAULT_COLUMN, id.as_bytes());
            }
        }
    }

    /// Sends one line; a send never fails the publish: a dropped line is a warning and the
    /// caller still remembers it.
    fn send(spool: &dyn StreamSpool, body: &str, log: &Log) {
        match spool.send(STREAM_KIND, body) {
            Ok(None) => {}
            Ok(Some(w)) | Err(w) => ic!(log, Warning, "{w}"),
        }
    }

    pub fn publish(&mut self, msg: &str) {
        let log = self.log.clone();
        let Ok(v) = serde_json::from_str::<Value>(msg) else { return };
        let op = v.get("operation").and_then(Value::as_str).unwrap_or("");
        let id = v.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let deletion = op == "DELETED" || op == "DELETED_BY_QUERY";
        match &mut self.mode {
            Mode::Local(db) => {
                let r: Result<(), String> = (|| {
                    if deletion {
                        for k in matching(db, op, &id)? {
                            db.delete(DEFAULT_COLUMN, k.as_bytes())?;
                        }
                    } else if let Some(d) = v.get("data") {
                        db.put_text(DEFAULT_COLUMN, &id, &compact(d))?;
                    } else {
                        ic!(log, Warning, "Event required field (data) is missing required fields: {msg}");
                    }
                    Ok(())
                })();
                if let Err(e) = r {
                    ic!(log, Error, "Error processing event: {e}");
                }
            }
            Mode::Stream { spool, sent, rescan } => {
                let r: Result<(), String> = (|| {
                    if deletion {

                        let known = matching(sent, op, &id)?;
                        if let Some(r) = rescan.as_mut().filter(|_| !known.is_empty()) {
                            r.deferred.push((op.to_string(), id.clone()));
                            return Ok(());
                        }
                        Self::send(spool.as_ref(), msg, &log);
                        for k in known {
                            sent.delete(DEFAULT_COLUMN, k.as_bytes())?;
                        }
                        return Ok(());
                    }
                    let Some(data) = v.get("data") else {
                        Self::send(spool.as_ref(), msg, &log);
                        return Ok(());
                    };
                    let hash = hash_without_detected_at(data);
                    if let Some(r) = rescan.as_mut() {
                        r.seen.insert(id.clone());
                        let mut replaced = false;
                        // An id without `_<part>` has no older versions to replace.
                        if let Some((base, _)) = id.rsplit_once('_') {
                            for old in sent.keys_text(DEFAULT_COLUMN, &format!("{base}_"))?.into_iter().filter(|k| *k != id) {
                                Self::send(spool.as_ref(), &compact(&json!({"id": old, "operation": "DELETED"})), &log);
                                sent.delete(DEFAULT_COLUMN, old.as_bytes())?;
                                replaced = true;
                            }
                        }
                        if !replaced && sent.get_text(DEFAULT_COLUMN, &id)?.as_deref() == Some(hash.as_str()) {
                            return Ok(());
                        }
                    }
                    Self::send(spool.as_ref(), msg, &log);
                    sent.put_text(DEFAULT_COLUMN, &id, &hash)?;
                    Ok(())
                })();
                if let Err(e) = r {
                    ic!(log, Error, "Error processing event: {e}");
                }
            }
        }
    }

    /// Stored documents of the local mode (tests and diagnostics).
    pub fn local_keys(&self) -> Vec<String> {
        match &self.mode {
            Mode::Local(db) => db.keys_text(DEFAULT_COLUMN, "").unwrap_or_default(),
            Mode::Stream { sent, .. } => sent.keys_text(DEFAULT_COLUMN, "").unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{Level, MemoryLogger};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Spool(Mutex<Vec<String>>);
    impl StreamSpool for Spool {
        fn send(&self, kind: u8, body: &str) -> Result<Option<String>, String> {
            assert_eq!(kind, b'V');
            self.0.lock().unwrap().push(body.to_string());
            Ok(None)
        }
    }

    fn doc(id: &str, score: f64) -> String {
        compact(&json!({"data":{"vulnerability":{"detected_at":format!("{}", rand_now()),"score":{"base":score}}},"id":id,"no-index":false,"operation":"INSERTED"}))
    }
    fn rand_now() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }
    fn dbq(id: &str) -> String {
        compact(&json!({"id":id,"no-index":false,"operation":"DELETED_BY_QUERY"}))
    }
    fn ids(sp: &Spool) -> Vec<String> {
        let v: Vec<String> = sp.0.lock().unwrap().drain(..).map(|m| {
            let v: Value = serde_json::from_str(&m).unwrap();
            format!("{} {}", v["operation"].as_str().unwrap(), v["id"].as_str().unwrap())
        }).collect();
        v
    }

    #[test]
    fn stream_rescan_example() {
        let home = tempfile::tempdir().unwrap();
        let sp = Arc::new(Spool::default());
        let mut s = DocSink::open(home.path(), "idx", Some(sp.clone()), Log::null()).unwrap();
        let round = |s: &mut DocSink, full: bool, docs: &[(&str, f64)]| {
            s.begin_rescan(full);
            s.publish(&dbq("001"));
            for (id, sc) in docs {
                s.publish(&doc(id, *sc));
            }
            s.end_rescan();
        };
        round(&mut s, false, &[("001_pkgA_CVE-1_0", 1.0), ("001_pkgA_CVE-2_0", 1.0), ("001_os_CVE-3_0", 1.0)]);
        assert_eq!(ids(&sp), vec!["DELETED_BY_QUERY 001", "INSERTED 001_pkgA_CVE-1_0", "INSERTED 001_pkgA_CVE-2_0", "INSERTED 001_os_CVE-3_0"]);
        round(&mut s, false, &[("001_pkgA_CVE-1_0", 1.0), ("001_pkgA_CVE-2_0", 1.0), ("001_os_CVE-3_0", 1.0)]);
        assert!(ids(&sp).is_empty());
        round(&mut s, false, &[("001_pkgA_CVE-1_7", 1.0), ("001_os_CVE-3_0", 2.0), ("001_os_CVE-4_0", 1.0)]);
        assert_eq!(ids(&sp), vec!["DELETED 001_pkgA_CVE-1_0", "INSERTED 001_pkgA_CVE-1_7", "INSERTED 001_os_CVE-3_0", "INSERTED 001_os_CVE-4_0", "DELETED 001_pkgA_CVE-2_0"]);
        round(&mut s, true, &[("001_pkgA_CVE-1_7", 1.0)]);
        assert_eq!(ids(&sp), vec!["DELETED_BY_QUERY 001", "INSERTED 001_pkgA_CVE-1_7"]);
        round(&mut s, false, &[("001_pkgA_CVE-1_7", 1.0)]);
        assert!(ids(&sp).is_empty());
    }

    struct Down;
    impl StreamSpool for Down {
        fn send(&self, _: u8, _: &str) -> Result<Option<String>, String> {
            Err("spool full".into())
        }
    }

    #[test]
    fn send_failure_is_a_warning_and_remembered() {
        // D19
        let home = tempfile::tempdir().unwrap();
        let l = Arc::new(MemoryLogger::default());
        let mut s = DocSink::open(home.path(), "idx", Some(Arc::new(Down)), Log::new(l.clone())).unwrap();
        s.publish(&doc("001_x_CVE-1_5", 1.0));
        assert!(l.has(Level::Warning, "spool full"));
        assert_eq!(s.local_keys(), vec!["001_x_CVE-1_5"]);
    }

    #[test]
    fn local_mode() {
        let home = tempfile::tempdir().unwrap();
        let l = Arc::new(MemoryLogger::default());
        let mut s = DocSink::open(home.path(), "idx", None, Log::new(l.clone())).unwrap();
        s.publish(&doc("001_x_CVE-1_5", 1.0));
        s.publish(&doc("001_x_CVE-12_5", 1.0));
        s.publish(&doc("001_y_CVE-1_5", 1.0));
        s.publish(&compact(&json!({"id":"001_x_CVE-1","operation":"DELETED"})));
        // C1: whole id parts only.
        assert_eq!(s.local_keys(), vec!["001_x_CVE-12_5", "001_y_CVE-1_5"]);
        s.publish(&doc("100_abc_CVE-2024-10_7", 1.0));
        s.publish(&doc("100_abc_CVE-2024-1_7", 1.0));
        s.publish(&doc("1000_abc_CVE-2024-1_7", 1.0));
        s.publish(&compact(&json!({"id":"100_abc_CVE-2024-1","operation":"DELETED"})));
        assert!(s.local_keys().contains(&"100_abc_CVE-2024-10_7".to_string()) && !s.local_keys().contains(&"100_abc_CVE-2024-1_7".to_string()));
        s.publish(&compact(&json!({"id":"100","operation":"DELETED_BY_QUERY"})));
        assert!(s.local_keys().contains(&"1000_abc_CVE-2024-1_7".to_string()) && !s.local_keys().iter().any(|k| k.starts_with("100_")));
        let m = compact(&json!({"id":"a","operation":"INSERTED"}));
        s.publish(&m);
        assert!(l.has(Level::Warning, &format!("Event required field (data) is missing required fields: {m}")));
        assert!(DocSink::open(home.path(), "Idx", None, Log::null()).is_err());
    }
}
