//! Feed content updater: downloads the feed (online offsets/snapshot or an offline file), hands
//! it to the feed-processing callback and records the processed version.

use crate::json::{compact, key_missing_text, type_name};
use crate::kvstore::KvStore;
use crate::legacy_names::CONTENT_VERSION;
use crate::log::Log;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

const PHASE_RUN: &str = "UpdaterRun";
const PHASE_CHAIN: &str = "UpdaterChain";
const COL_OFFSET: &str = "current_offset";
const COL_HASH: &str = "downloaded_file_hash";
const PAGE: i64 = 1000;

/// Called with the published run state (compact JSON); returns (offset, hash, status).
pub type Callback = Arc<dyn Fn(&str) -> (i64, String, bool) + Send + Sync>;

/// Stop flag that also ends waits at once.
#[derive(Default)]
pub struct StopSignal {
    flag: Mutex<bool>,
    cv: Condvar,
    quick: AtomicBool,
}

impl StopSignal {
    pub fn set(&self) {
        *self.flag.lock().unwrap() = true;
        self.quick.store(true, Ordering::Relaxed);
        self.cv.notify_all();
    }
    pub fn is_set(&self) -> bool {
        self.quick.load(Ordering::Relaxed)
    }
    pub fn flag(&self) -> &AtomicBool {
        &self.quick
    }
    /// Waits up to `d`; true when stopped.
    pub fn wait(&self, d: Duration) -> bool {
        let g = self.flag.lock().unwrap();
        if *g || d.is_zero() {
            return *g;
        }
        let (g, _) = self.cv.wait_timeout_while(g, d, |s| !*s).unwrap();
        *g
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Step {
    OffsetsDl,
    SnapshotDl,
    OfflineDl,
    Zip,
    Gzip,
    Skip,
    Publish,
    StoreOffset,
    StoreOffline,
    Clean,
}

impl Step {
    fn name(self) -> &'static str {
        match self {
            Step::OffsetsDl => "FeedOffsetsDownloader",
            Step::SnapshotDl => "FeedSnapshotDownloader",
            Step::OfflineDl => "OfflineFileDownloader",
            Step::Zip => "ZipExtractor",
            Step::Gzip => "GzipExtractor",
            Step::Skip => "NoOpStep",
            Step::Publish => "FeedPublisher",
            Step::StoreOffset => "StoreFeedOffset",
            Step::StoreOffline => "StoreOfflineHash",
            Step::Clean => "WorkFolderCleaner",
        }
    }
}

/// A failed run; `offset` marks failures that trigger a snapshot download.
#[derive(Debug)]
struct RunErr {
    offset: bool,
    msg: String,
}

fn other(msg: impl Into<String>) -> RunErr {
    RunErr { offset: false, msg: msg.into() }
}

struct HttpErr {
    code: u16,
    msg: String,
    body: String,
}

enum Fail {
    Http(HttpErr),
    Io(String),
}

struct RunState {
    data: Value,
    offset: i64,
}

impl RunState {
    fn new(offset: i64) -> Self {
        RunState { data: json!({"type":"raw","offset":0,"paths":[],"stageStatus":[]}), offset }
    }
    fn stage(&mut self, step: Step, ok: bool) {
        if let Some(a) = self.data["stageStatus"].as_array_mut() {
            a.push(json!({"stage": step.name(), "status": if ok { "ok" } else { "fail" }}));
        }
    }
    fn paths(&self) -> Vec<String> {
        self.data["paths"].as_array().map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_string)).collect()).unwrap_or_default()
    }
}

#[derive(Default)]
struct Meta {
    last_offset: Option<i64>,
    link: Option<String>,
    snap_offset: Option<i64>,
}

struct Sched {
    interval: u64,
    woken: bool,
    running: bool,
}

struct Inner {
    topic: String,
    cfg: Mutex<Value>,
    /// The regular step chain, built once.
    chain: Vec<Step>,
    log: Log,
    http: reqwest::blocking::Client,
    user_agent: String,
    meta: Option<KvStore>,
    last_hash: Mutex<String>,
    stop: Arc<StopSignal>,
    callback: Callback,
    output: String,
    in_progress: AtomicBool,
    sched: Mutex<Sched>,
    wake: Condvar,
}

pub struct Updater {
    inner: Arc<Inner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

fn now_key() -> String {
    chrono::Utc::now().format("%Y%m%d%H%M%S").to_string()
}

/// Text after the last `/` (a query string included).
fn last_segment(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or("")
}

/// File name of an offline URL's path: a trailing `/` is ignored.
fn file_name(url: &str) -> &str {
    last_segment(url.trim_end_matches('/'))
}

impl Updater {
    /// Creates the updater and starts its scheduler (the first update runs at once).
    pub fn create(home: &Path, params: &Value, callback: Callback, stop: Arc<StopSignal>, log: Log) -> Result<Updater, String> {
        Self::build(home, params, callback, stop, log, true).map_err(|e| format!("Orchestration creation failed. {e}"))
    }

    fn build(home: &Path, params: &Value, callback: Callback, stop: Arc<StopSignal>, log: Log, start: bool) -> Result<Updater, String> {
        let topic = params.get("topicName").and_then(Value::as_str).ok_or_else(|| key_missing_text("topicName"))?.to_string();
        let mut cfg = params.get("configData").cloned().ok_or_else(|| key_missing_text("configData"))?;
        let interval = params.get("interval").and_then(Value::as_u64).unwrap_or(3600);
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(300))
            .timeout(None::<Duration>)
            .build()
            .map_err(|e| e.to_string())?;
        cu!(log, Debug, "Creating '{topic}' feed updater");
        cu!(log, Debug, "{PHASE_RUN} - Starting process");

        let db_path = cfg.get("databasePath").and_then(Value::as_str).unwrap_or("").to_string();
        let mut meta = None;
        let mut last_hash = String::new();
        if !db_path.is_empty() {
            let store = KvStore::open(&home.join(&db_path).join(format!("updater_{topic}_metadata")))?;
            for c in [COL_OFFSET, COL_HASH] {
                if !store.has_column(c) {
                    cu!(log, Debug, "Column '{c}' doesn't exist so it will be created");
                    store.create_column(c)?;
                }
            }
            if let Ok((_, v)) = store.last(COL_HASH) {
                last_hash = String::from_utf8_lossy(&v).into_owned();
            }
            let stored = match store.last(COL_OFFSET) {
                Ok((_, v)) => String::from_utf8_lossy(&v).trim().parse::<i64>().unwrap_or(0),
                Err(_) => {
                    store.put_text(COL_OFFSET, &now_key(), "0")?;
                    0
                }
            };
            let configured = cfg.get("offset").and_then(Value::as_i64).unwrap_or(0);
            if configured < 0 {
                return Err(format!("Offset should be a non-negative number: {configured}"));
            }
            if configured > stored {
                store.put_text(COL_OFFSET, &now_key(), &configured.to_string())?;
            }
            meta = Some(store);
        }

        // Paths in messages and log lines are `<home>/<outputFolder>/...`.
        let home_text = home.to_string_lossy().replace('\\', "/");
        let output = match cfg.get("outputFolder").and_then(Value::as_str) {
            Some(o) if !o.is_empty() && Path::new(o).is_absolute() => o.replace('\\', "/"),
            Some(o) if !o.is_empty() => crate::config::home_path(&home_text, o),
            _ => std::env::temp_dir().join("output_folder").to_string_lossy().replace('\\', "/"),
        };
        let out_abs = PathBuf::from(&output);
        if out_abs.exists() {
            cu!(log, Debug2, "Removing previous output folder '{output}'");
            let _ = fs::remove_dir_all(&out_abs);
        }
        cu!(log, Debug2, "Creating output folders at '{output}'");
        fs::create_dir_all(out_abs.join("downloads")).map_err(|e| e.to_string())?;
        fs::create_dir_all(out_abs.join("contents")).map_err(|e| e.to_string())?;

        let consumer = cfg.get("consumerName").and_then(Value::as_str).unwrap_or("");
        if consumer.is_empty() {
            return Err("Missing or empty consumerName".into());
        }
        let user_agent = format!("{consumer}/{CONTENT_VERSION}");
        let chain = Self::chain(&mut cfg, None, None, &log)?;
        cu!(log, Debug, "Content updater orchestration created");

        let inner = Arc::new(Inner {
            topic,
            cfg: Mutex::new(cfg),
            chain,
            log,
            http,
            user_agent,
            meta,
            last_hash: Mutex::new(last_hash),
            stop,
            callback,
            output,
            in_progress: AtomicBool::new(false),
            sched: Mutex::new(Sched { interval, woken: false, running: true }),
            wake: Condvar::new(),
        });
        let u = Updater { inner: inner.clone(), thread: Mutex::new(None) };
        if start {
            *u.thread.lock().unwrap() = Some(std::thread::spawn(move || inner.scheduler()));
        }
        Ok(u)
    }

    /// Builds the step chain from the configuration (with optional source/compression overrides).
    fn chain(cfg: &mut Value, source: Option<&str>, compression: Option<&str>, log: &Log) -> Result<Vec<Step>, String> {
        cu!(log, Debug, "{PHASE_CHAIN} - Starting process");
        let src = source.map(str::to_string).unwrap_or_else(|| cfg["contentSource"].as_str().unwrap_or("").to_string());
        if src == "offline" && compression.is_none() {
            let url = cfg["url"].as_str().unwrap_or("");
            let c = if url.ends_with(".gz") {
                "gzip"
            } else if url.ends_with(".xz") {
                "xz"
            } else if url.ends_with(".zip") {
                "zip"
            } else {
                "raw"
            };
            cfg["compressionType"] = c.into();
        }
        let comp = compression.map(str::to_string).unwrap_or_else(|| cfg["compressionType"].as_str().unwrap_or("").to_string());
        let versioned = match &cfg["versionedContent"] {
            Value::Bool(false) => "false".to_string(),
            v => v.as_str().unwrap_or("").to_string(),
        };
        cu!(log, Debug, "Creating '{src}' downloader");
        let dl = match src.as_str() {
            "cti-offset" => Step::OffsetsDl,
            "cti-snapshot" => Step::SnapshotDl,
            "offline" => Step::OfflineDl,
            _ => return Err(format!("Invalid 'contentSource' type: {src}")),
        };
        cu!(log, Debug, "Creating '{comp}' decompressor");
        let dc = match comp.as_str() {
            "gzip" => Step::Gzip,
            "zip" => Step::Zip,
            "raw" => Step::Skip,
            _ => return Err(format!("Invalid 'compressionType': {comp}")),
        };
        cu!(log, Debug, "Creating '{versioned}' version updater");
        let vu = match versioned.as_str() {
            "cti-api" => Step::StoreOffset,
            "offline" => Step::StoreOffline,
            "false" => Step::Skip,
            _ => return Err(format!("Invalid 'versionedContent' type: {versioned}")),
        };
        let clean = if cfg["deleteDownloadedContent"].as_bool().unwrap_or(false) {
            cu!(log, Debug, "Content cleaner created");
            Step::Clean
        } else {
            Step::Skip
        };
        Ok(vec![dl, dc, Step::Publish, vu, clean])
    }

    /// Sets the interval and wakes the scheduler (which starts an update at once).
    pub fn change_interval(&self, secs: u64) {
        let mut s = self.inner.sched.lock().unwrap();
        s.interval = secs;
        s.woken = true;
        self.inner.wake.notify_all();
    }

    pub fn stop(&self) {
        self.inner.stop.set();
        {
            let mut s = self.inner.sched.lock().unwrap();
            s.running = false;
            self.inner.wake.notify_all();
        }
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
        cu!(self.inner.log, Debug2, "Scheduler stopped for '{}'", self.inner.topic);
    }

    /// One scheduled run, without the scheduler (tests).
    pub fn run_now(&self) -> Result<(), String> {
        self.inner.run_once()
    }

    pub fn stored_offset(&self) -> Option<i64> {
        self.inner.meta.as_ref().and_then(|m| m.last(COL_OFFSET).ok()).and_then(|(_, v)| String::from_utf8_lossy(&v).parse().ok())
    }
}

impl Inner {
    fn scheduler(self: Arc<Self>) {
        loop {
            if !self.sched.lock().unwrap().running {
                break;
            }
            cu!(self.log, Debug2, "Starting scheduled action for '{}'", self.topic);
            if self.in_progress.swap(true, Ordering::SeqCst) {
                cu!(self.log, Debug2, "Action in progress for '{}', scheduled request ignored", self.topic);
            } else {
                cu!(self.log, Debug2, "Action for '{}' started", self.topic);
                if let Err(e) = self.run_once() {
                    cu!(self.log, Error, "Action for '{}' failed: {e}.", self.topic);
                }
                cu!(self.log, Debug2, "Action for '{}' finished", self.topic);
                self.in_progress.store(false, Ordering::SeqCst);
            }
            let mut s = self.sched.lock().unwrap();
            let d = Duration::from_secs(s.interval);
            if !s.woken && s.running {
                s = self.wake.wait_timeout_while(s, d, |x| !x.woken && x.running).unwrap().0;
            }
            s.woken = false;
        }
    }

    fn run_once(&self) -> Result<(), String> {
        match self.content_update(false) {
            Ok(()) => Ok(()),
            Err(e) if e.offset => {
                cu!(self.log, Warning, "Offset processing failed. Triggered a snapshot download.");
                self.last_hash.lock().unwrap().clear();
                self.content_update(true).map_err(|e| e.msg)
            }
            Err(e) => {
                self.last_hash.lock().unwrap().clear();
                Err(format!("Orchestration run failed: {}", e.msg))
            }
        }
    }

    fn content_update(&self, reset: bool) -> Result<(), RunErr> {
        cu!(self.log, Debug2, "Running '{}' content update", self.topic);
        let current = if reset {
            0
        } else {
            match &self.meta {
                Some(m) => {
                    let (_, v) = m.last(COL_OFFSET).map_err(other)?;
                    String::from_utf8_lossy(&v).trim().parse::<i64>().map_err(|_| other(crate::version::BAD_INTEGER))?
                }
                None => 0,
            }
        };
        let source = self.cfg.lock().unwrap()["contentSource"].as_str().unwrap_or("").to_string();
        cu!(self.log, Debug2, "Current offset: '{current}'. Current hash: '{}'. ContentSource: '{source}'", self.last_hash.lock().unwrap());
        let mut st = RunState::new(current);
        if (current == 0 && source == "cti-offset") || reset {
            cu!(self.log, Debug2, "Triggering full content download");
            cu!(self.log, Debug, "Performing full-content download");
            let mut cfg = self.cfg.lock().unwrap().clone();
            let chain = Updater::chain(&mut cfg, Some("cti-snapshot"), Some("zip"), &self.log).map_err(other)?;
            if let Err(e) = self.run_chain(&chain, &cfg, &mut st) {
                cu!(self.log, Warning, "Couldn't run full content download: {}.", e.msg);
                return Err(e);
            }
            st.data = RunState::new(0).data;
        }
        // The regular chain was built once at creation.
        let cfg = self.cfg.lock().unwrap().clone();
        let chain = self.chain.clone();
        self.run_chain(&chain, &cfg, &mut st).map_err(|e| RunErr { offset: true, msg: e.msg })
    }

    fn run_chain(&self, chain: &[Step], cfg: &Value, st: &mut RunState) -> Result<(), RunErr> {
        for step in chain {
            cu!(self.log, Debug, "{} - Starting process", step.name());
            match step {
                Step::OffsetsDl => self.offsets_download(cfg, st)?,
                Step::SnapshotDl => self.snapshot_download(cfg, st)?,
                Step::OfflineDl => {
                    if let Err(e) = self.offline_download(cfg, st) {
                        st.stage(*step, false);
                        return Err(other(format!("Download failed: {e}")));
                    }
                    st.stage(*step, true);
                }
                Step::Zip | Step::Gzip => {
                    if let Err(e) = self.decompress(*step, st) {
                        st.stage(*step, false);
                        return Err(other(format!("Decompression failed: {e}")));
                    }
                    st.stage(*step, true);
                }
                Step::Skip => {}
                Step::Publish => self.publish(st)?,
                Step::StoreOffset => self.store_offset(st)?,
                Step::StoreOffline => self.store_offline(st)?,
                Step::Clean => self.clean(),
            }
        }
        Ok(())
    }

    /// Work paths are already `<home>/<outputFolder>/...`.
    fn abs(&self, rel: &str) -> PathBuf {
        PathBuf::from(rel)
    }

    // ---- HTTP ---------------------------------------------------------------------------------

    fn get(&self, url: &str, dest: Option<&Path>) -> Result<Vec<u8>, Fail> {
        let resp = self.http.get(url).header(reqwest::header::USER_AGENT, &self.user_agent).send().map_err(|e| Fail::Http(transport(&e)))?;
        let code = resp.status().as_u16();
        if code >= 400 {
            let body = resp.text().unwrap_or_default();
            return Err(Fail::Http(HttpErr { code, msg: "HTTP response code said error".into(), body }));
        }
        match dest {
            Some(p) => {
                let mut f = fs::File::create(p).map_err(|e| Fail::Io(e.to_string()))?;
                let mut resp = resp;
                resp.copy_to(&mut f).map_err(|e| Fail::Http(transport(&e)))?;
                Ok(Vec::new())
            }
            None => resp.bytes().map(|b| b.to_vec()).map_err(|e| Fail::Http(transport(&e))),
        }
    }

    /// GET with the content-server retry rules; `None` when stopped.
    fn fetch(&self, url: &str, dest: Option<&Path>) -> Result<Option<Vec<u8>>, String> {
        let mut wait = 0u64;
        let mut streak: Option<u32> = None;
        loop {
            if self.stop.wait(Duration::from_secs(wait)) {
                return Ok(None);
            }
            let e = match self.get(url, dest) {
                Ok(b) => return Ok(Some(b)),
                Err(Fail::Io(s)) => return Err(s),
                Err(Fail::Http(e)) => e,
            };
            if e.code == 429 {
                wait = 90;
                streak = None;
            } else if (500..600).contains(&e.code) {
                streak = Some(match streak {
                    None => {
                        wait = 1;
                        0
                    }
                    Some(n) => {
                        if wait < 30 {
                            wait = 30u64.min(1u64 << n.min(62));
                        }
                        n + 1
                    }
                });
            } else {
                return Err(format!("Error {} from server: {} - Response body: {}", e.code, e.msg, e.body));
            }
            cu!(self.log, Debug, "Error {} from server: {} - Response body: {}", e.code, e.msg, e.body);
            cu!(self.log, Debug, "Retrying download in {wait} seconds");
        }
    }

    fn metadata(&self, url: &str) -> Result<Option<Meta>, String> {
        let Some(body) = self.fetch(url, None)? else { return Ok(None) };
        let body = String::from_utf8_lossy(&body).into_owned();
        cu!(self.log, Debug2, "CTI raw metadata: '{body}'");
        let v: Value = serde_json::from_str(&body).map_err(|_| "Invalid CTI metadata format".to_string())?;
        let data = v.get("data").ok_or("No 'data' field in CTI metadata")?;
        let mut m = Meta::default();
        for key in ["last_offset", "last_snapshot_link", "last_snapshot_offset"] {
            let x = match data.get(key) {
                None => {
                    cu!(self.log, Warning, "Missing CTI metadata key: {key}.");
                    continue;
                }
                Some(x) if x.is_null() || x.as_str() == Some("") => {
                    cu!(self.log, Warning, "Null or empty CTI metadata value for key: {key}.");
                    continue;
                }
                Some(x) => x,
            };
            if key == "last_snapshot_link" {
                m.link = Some(x.as_str().ok_or_else(|| format!("JSON value must be string, but is {}", type_name(x)))?.to_string());
            } else {
                let n = x.as_i64().ok_or_else(|| format!("JSON value must be number, but is {}", type_name(x)))?;
                if key == "last_offset" {
                    m.last_offset = Some(n);
                } else {
                    m.snap_offset = Some(n);
                }
            }
        }
        Ok(Some(m))
    }

    // ---- steps --------------------------------------------------------------------------------

    fn offsets_download(&self, cfg: &Value, st: &mut RunState) -> Result<(), RunErr> {
        st.data["type"] = "offsets".into();
        cu!(self.log, Debug2, "Initial API offset: {}", st.offset);
        let url = cfg["url"].as_str().unwrap_or("").to_string();
        let r = (|| -> Result<(), String> {
            let Some(meta) = self.metadata(&url)? else {
                cu!(self.log, Warning, "The offsets download has been interrupted.");
                return Ok(());
            };
            let last = meta.last_offset.ok_or("Can't download offsets due to missing CTI metadata")?;
            let folder = if cfg["compressionType"].as_str() == Some("raw") { "contents" } else { "downloads" };
            let file_name = cfg["contentFileName"].as_str().ok_or_else(|| key_missing_text("contentFileName"))?;
            let mut from = st.offset;
            let mut paths = Vec::new();
            while from < last {
                if self.stop.is_set() {
                    cu!(self.log, Warning, "The offsets download has been interrupted.");
                    return Ok(());
                }
                let to = last.min(from + PAGE);
                let rel = format!("{}/{folder}/{to}-{file_name}", self.output);
                let page = format!("{url}/changes?from_offset={from}&to_offset={to}");
                cu!(self.log, Debug2, "Downloading offsets from: '{page}'");
                if self.fetch(&page, Some(&self.abs(&rel)))?.is_none() {
                    cu!(self.log, Warning, "The offsets download has been interrupted.");
                    return Ok(());
                }
                paths.push(Value::from(rel));
                from = to;
            }
            st.data["paths"] = Value::Array(paths);
            st.data["offset"] = from.into();
            Ok(())
        })();
        st.stage(Step::OffsetsDl, r.is_ok());
        r.map_err(other)
    }

    fn snapshot_download(&self, cfg: &Value, st: &mut RunState) -> Result<(), RunErr> {
        let url = cfg["url"].as_str().unwrap_or("").to_string();
        let r = (|| -> Result<(), String> {
            let missing = "Can't download snapshot due to missing CTI metadata";
            let meta = self.metadata(&url)?.ok_or(missing)?;
            let (Some(link), Some(off)) = (meta.link, meta.snap_offset) else { return Err(missing.into()) };
            st.offset = off;
            let rel = format!("{}/downloads/{}", self.output, last_segment(&link));
            cu!(self.log, Debug2, "Downloading snapshot from '{link}'");
            if self.fetch(&link, Some(&self.abs(&rel)))?.is_some() {
                if let Some(a) = st.data["paths"].as_array_mut() {
                a.push(rel.into());
            }
                st.data["offset"] = off.into();
            }
            Ok(())
        })();
        st.stage(Step::SnapshotDl, r.is_ok());
        r.map_err(other)
    }

    fn offline_download(&self, cfg: &Value, st: &mut RunState) -> Result<(), String> {
        let url = cfg["url"].as_str().unwrap_or("").to_string();
        let name = file_name(&url);
        if name.is_empty() {
            return Err(format!("Couldn't get filename from URL: {url}"));
        }
        let folder = if cfg["compressionType"].as_str() == Some("raw") { "contents" } else { "downloads" };
        let rel = format!("{}/{folder}/{name}", self.output);
        let out = self.abs(&rel);
        if let Some(path) = url.strip_prefix("file://") {
            if !Path::new(path).exists() {
                cu!(self.log, Warning, "File '{url}' doesn't exist.");
                return Ok(());
            }
            cu!(self.log, Debug2, "Copying file from '{url}' into '{rel}'");
            fs::copy(path, &out).map_err(|e| e.to_string())?;
        } else if url.starts_with("http://") || url.starts_with("https://") {
            cu!(self.log, Debug2, "Downloading file from '{url}' into '{rel}'");
            match self.get(&url, Some(&out)) {
                Ok(_) => {}
                Err(Fail::Http(e)) => {
                    cu!(self.log, Warning, "Error '{}' when downloading file: {}.", e.code, e.msg);
                    cu!(self.log, Warning, "Response body: {}", e.body);
                    return Ok(());
                }
                // A file that cannot be created fails the step with the system error text.
                Err(Fail::Io(e)) => return Err(e),
            }
        } else {
            return Err(format!("Unknown URL prefix for {url}"));
        }
        let mut f = fs::File::open(&out).map_err(|_| format!("Unable to open '{rel}' for hashing."))?;
        let mut h = Sha1::new();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut buf).map_err(|_| format!("Unable to open '{rel}' for hashing."))?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        let hash = hex::encode(h.finalize());
        if hash != *self.last_hash.lock().unwrap() {
            if let Some(a) = st.data["paths"].as_array_mut() {
                a.push(rel.into());
            }
            st.data["fileMetadata"] = json!({"hash": hash});
        } else {
            cu!(self.log, Debug2, "File '{rel}' didn't change from last download so it won't be published");
        }
        Ok(())
    }

    fn decompress(&self, step: Step, st: &mut RunState) -> Result<(), String> {
        let contents = format!("{}/contents", self.output);
        let mut produced = Vec::new();
        for p in st.paths() {
            cu!(self.log, Debug2, "Decompressing '{p}' into '{contents}'");
            if step == Step::Gzip {
                let name = Path::new(&p).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                let rel = format!("{contents}/{name}");
                let input = fs::File::open(self.abs(&p)).map_err(|_| format!("Unable to open compressed file: {p}"))?;
                let mut out = fs::File::create(self.abs(&rel)).map_err(|_| format!("Unable to create destination file: {rel}"))?;
                std::io::copy(&mut flate2::read::MultiGzDecoder::new(std::io::BufReader::new(input)), &mut out).map_err(|e| e.to_string())?;
                produced.push(Value::from(rel));
            } else {
                let f = fs::File::open(self.abs(&p)).map_err(|_| format!("Unable to open compressed file: {p}"))?;
                let mut z = zip::ZipArchive::new(f).map_err(|_| format!("Unable to open compressed file: {p}"))?;
                for i in 0..z.len() {
                    let mut e = z.by_index(i).map_err(|_| format!("Unable to get current file information from zip file: {p}"))?;
                    let raw = e.name().to_string();
                    // The destination path is shown when it would leave the output folder.
                    let rel = format!("{contents}/{raw}");
                    if e.enclosed_name().is_none() {
                        return Err(format!("A potentially insecure path was found: {rel}"));
                    }
                    let abs = self.abs(&rel);
                    if raw.ends_with('/') {
                        fs::create_dir_all(&abs).map_err(|e| e.to_string())?;
                    } else {
                        // Parents come only from directory entries of the archive.
                        let mut out = fs::File::create(&abs).map_err(|_| format!("Unable to create destination file: {rel}"))?;
                        std::io::copy(&mut e, &mut out).map_err(|e| e.to_string())?;
                    }
                    produced.push(Value::from(rel));
                }
            }
        }
        st.data["paths"] = Value::Array(produced);
        Ok(())
    }

    fn publish(&self, st: &mut RunState) -> Result<(), RunErr> {
        if st.paths().is_empty() {
            cu!(self.log, Debug2, "No data to publish");
            return Ok(());
        }
        let msg = compact(&st.data);
        cu!(self.log, Debug2, "Data to be published: '{msg}'");
        let (offset, hash, ok) = (self.callback)(&msg);
        if !ok {
            cu!(self.log, Debug2, "Failed to publish data");
            return Err(if st.data["type"] == "offsets" {
                RunErr { offset: true, msg: "Failed to process offsets".into() }
            } else {
                other("Failed to process the snapshot")
            });
        }
        st.offset = offset;
        *self.last_hash.lock().unwrap() = hash.clone();
        cu!(self.log, Debug2, "Data published. Offset: '{offset}', Hash: '{hash}'");
        Ok(())
    }

    /// Version recording: without a store nothing is logged, the step fails.
    fn store_offset(&self, st: &RunState) -> Result<(), RunErr> {
        let fail = |e: &str| other(format!("{} - Error updating the content version: {e}", Step::StoreOffset.name()));
        let m = self.meta.as_ref().ok_or_else(|| fail("Updater metadata store is not open"))?;
        cu!(self.log, Debug2, "Updating offset with value: '{}'", st.offset);
        m.put_text(COL_OFFSET, &now_key(), &st.offset.to_string()).map_err(|e| fail(&e))
    }

    fn store_offline(&self, st: &RunState) -> Result<(), RunErr> {
        let fail = |e: &str| other(format!("{} - Error updating the content version: {e}", Step::StoreOffline.name()));
        let m = self.meta.as_ref().ok_or_else(|| fail("Updater metadata store is not open"))?;
        let hash = self.last_hash.lock().unwrap().clone();
        cu!(self.log, Debug2, "Updating hash with value: '{hash}'");
        m.put_text(COL_HASH, &now_key(), &hash)
            .and_then(|_| m.put_text(COL_OFFSET, &now_key(), &st.offset.to_string()))
            .map_err(|e| fail(&e))
    }

    fn clean(&self) {
        for d in ["downloads", "contents"] {
            let rel = format!("{}/{d}", self.output);
            cu!(self.log, Debug, "Cleaning up the folder: {rel}.");
            let abs = self.abs(&rel);
            if !abs.exists() {
                cu!(self.log, Warning, "The path does not exist: {rel}.");
                return;
            }
            let _ = fs::remove_dir_all(&abs);
            let _ = fs::create_dir_all(&abs);
        }
    }
}

fn transport(e: &reqwest::Error) -> HttpErr {
    let msg = if e.is_timeout() {
        "Timeout was reached".to_string()
    } else if e.is_connect() {
        "Couldn't connect to server".to_string()
    } else {
        let mut s = e.to_string();
        let mut src = std::error::Error::source(e);
        while let Some(c) = src {
            s.push_str(": ");
            s.push_str(&c.to_string());
            src = c.source();
        }
        s
    };
    HttpErr { code: 0, msg, body: String::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::FeedDb;
    use crate::log::{Level, MemoryLogger};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    type Handler = Arc<dyn Fn(&str, usize) -> (u16, Vec<u8>) + Send + Sync>;

    /// Minimal HTTP/1.1 server: one request per connection.
    fn server(h: Handler, agents: Arc<Mutex<Vec<String>>>) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut n = 0;
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                r.read_line(&mut first).unwrap();
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(ua) = line.to_ascii_lowercase().strip_prefix("user-agent: ") {
                        let _ = ua;
                        agents.lock().unwrap().push(line[12..].trim().to_string());
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
                n += 1;
                let (code, body) = h(&path, n);
                let _ = write!(s, "HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(&body);
            }
        });
        format!("http://{addr}")
    }

    fn zip_bytes(name: &str, content: &str) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        w.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(content.as_bytes()).unwrap();
        w.finish().unwrap().into_inner()
    }

    fn params(url: &str, source: &str) -> Value {
        let (src, ver) = if source == "offline" { ("offline", "offline") } else { ("cti-offset", "cti-api") };
        json!({"topicName":"vulnerability_feed_manager","interval":3600,"ondemand":true,"configData":{
            "consumerName":"C","compressionType":"raw","deleteDownloadedContent":true,"outputFolder":"queue/vd_updater/tmp",
            "databasePath":"queue/vd_updater/x","offset":0,"contentSource":src,"versionedContent":ver,"contentFileName":"api_file.json","url":url}})
    }

    fn feed_callback(home: &Path) -> (Callback, Arc<Mutex<FeedDb>>) {
        let db = Arc::new(Mutex::new(FeedDb::open(home, &home.join("feed")).unwrap()));
        let d2 = db.clone();
        let cb: Callback = Arc::new(move |m: &str| {
            let v: Value = serde_json::from_str(m).unwrap();
            d2.lock().unwrap().apply_message(&v, &AtomicBool::new(false), &Log::null()).unwrap_or_default()
        });
        (cb, db)
    }

    #[test]
    fn online_snapshot_then_pages_with_retry() {
        let home = tempfile::tempdir().unwrap();
        let agents = Arc::new(Mutex::new(Vec::new()));
        let fail_once = Arc::new(AtomicBool::new(true));
        let base = Arc::new(Mutex::new(String::new()));
        let (b2, f2) = (base.clone(), fail_once.clone());
        let pages = Arc::new(Mutex::new(Vec::new()));
        let p2 = pages.clone();
        let h: Handler = Arc::new(move |path, _| {
            let b = b2.lock().unwrap().clone();
            if path == "/meta" {
                (200, format!(r#"{{"data":{{"last_offset":1500,"last_snapshot_link":"{b}/store/snap.zip","last_snapshot_offset":100}}}}"#).into_bytes())
            } else if path == "/store/snap.zip" {
                (200, zip_bytes("snap.json", "{\"name\":\"TID-1\",\"offset\":120,\"payload\":{}}\n"))
            } else if path.starts_with("/meta/changes") {
                if f2.swap(false, Ordering::SeqCst) {
                    return (500, b"busy".to_vec());
                }
                p2.lock().unwrap().push(path.to_string());
                let to: i64 = path.rsplit('=').next().unwrap().parse().unwrap();
                (200, format!(r#"{{"data":[{{"resource":"TID-2","type":"create","offset":{to},"payload":{{}}}}]}}"#).into_bytes())
            } else {
                (404, b"no".to_vec())
            }
        });
        let url = server(h, agents.clone());
        *base.lock().unwrap() = url.clone();
        let l = Arc::new(MemoryLogger::default());
        let (cb, _db) = feed_callback(home.path());
        let u = Updater::build(home.path(), &params(&format!("{url}/meta"), "online"), cb, Arc::new(StopSignal::default()), Log::new(l.clone()), false).unwrap();
        u.run_now().unwrap();
        assert_eq!(u.stored_offset(), Some(1500));
        assert_eq!(*pages.lock().unwrap(), vec!["/meta/changes?from_offset=120&to_offset=1120", "/meta/changes?from_offset=1120&to_offset=1500"]);
        assert!(l.has(Level::Debug, "Retrying download in 1 seconds"));
        assert!(agents.lock().unwrap().iter().all(|a| a == &format!("C/{CONTENT_VERSION}")));
        assert_eq!(fs::read_dir(home.path().join("queue/vd_updater/tmp/contents")).unwrap().count(), 0);
        // Second run: nothing new.
        u.run_now().unwrap();
        assert!(l.has(Level::Debug2, "No data to publish"));
        assert_eq!(u.stored_offset(), Some(1500));
    }

    #[test]
    fn page_404_fails_after_snapshot_retry() {
        let home = tempfile::tempdir().unwrap();
        let h: Handler = Arc::new(move |path, _| {
            if path == "/meta" {
                (200, br#"{"data":{"last_offset":10}}"#.to_vec())
            } else {
                (404, b"gone".to_vec())
            }
        });
        let url = server(h, Arc::new(Mutex::new(Vec::new())));
        let l = Arc::new(MemoryLogger::default());
        let (cb, _db) = feed_callback(home.path());
        let mut p = params(&format!("{url}/meta"), "online");
        p["configData"]["offset"] = 5.into();
        let u = Updater::build(home.path(), &p, cb, Arc::new(StopSignal::default()), Log::new(l.clone()), false).unwrap();
        let e = u.run_now().unwrap_err();
        assert!(l.has(Level::Warning, "Offset processing failed. Triggered a snapshot download."));
        assert!(l.has(Level::Warning, "Missing CTI metadata key: last_snapshot_link."));
        assert_eq!(e, "Can't download snapshot due to missing CTI metadata");
    }

    #[test]
    fn offline_file_processed_once() {
        let home = tempfile::tempdir().unwrap();
        let src = home.path().join("feed.json");
        fs::write(&src, "{\"name\":\"TID-1\",\"offset\":4,\"payload\":{}}\n").unwrap();
        let l = Arc::new(MemoryLogger::default());
        let (cb, db) = feed_callback(home.path());
        let url = format!("file://{}", src.to_string_lossy().replace('\\', "/"));
        let u = Updater::build(home.path(), &params(&url, "offline"), cb, Arc::new(StopSignal::default()), Log::new(l.clone()), false).unwrap();
        u.run_now().unwrap();
        assert!(db.lock().unwrap().store.get("translation", b"TID-1").unwrap().is_some());
        u.run_now().unwrap();
        assert!(l.has_text("didn't change from last download so it won't be published"));
        fs::remove_file(&src).unwrap();
        u.run_now().unwrap();
        assert!(l.has(Level::Warning, &format!("File '{url}' doesn't exist.")));
        // D17: the regular chain was built once, at creation.
        assert_eq!(l.lines().iter().filter(|m| *m == "Creating 'offline' downloader").count(), 1);
        // D43: work paths carry the home directory.
        let home_text = home.path().to_string_lossy().replace('\\', "/");
        assert!(l.has_text(&format!("\"paths\":[\"{home_text}/queue/vd_updater/tmp/contents/feed.json\"]")));
    }

    #[test]
    fn creation_errors_and_stop() {
        let home = tempfile::tempdir().unwrap();
        let cb: Callback = Arc::new(|_| (0, String::new(), true));
        let mut p = params("file:///x/feed.xz", "offline");
        let e = Updater::create(home.path(), &p, cb.clone(), Arc::new(StopSignal::default()), Log::null()).err().unwrap();
        assert_eq!(e, "Orchestration creation failed. Invalid 'compressionType': xz");
        p["configData"]["offset"] = (-1).into();
        assert!(Updater::create(home.path(), &p, cb.clone(), Arc::new(StopSignal::default()), Log::null()).err().unwrap().ends_with("Offset should be a non-negative number: -1"));
        assert_eq!(Updater::create(home.path(), &json!({"configData":{}}), cb.clone(), Arc::new(StopSignal::default()), Log::null()).err().unwrap(), "Orchestration creation failed. JSON key 'topicName' not found");

        // A server that always answers 500: stop ends the retry wait at once.
        let h: Handler = Arc::new(|_, _| (500, Vec::new()));
        let url = server(h, Arc::new(Mutex::new(Vec::new())));
        let l = Arc::new(MemoryLogger::default());
        let u = Updater::create(home.path(), &params(&format!("{url}/meta"), "online"), cb, Arc::new(StopSignal::default()), Log::new(l.clone())).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let t = std::time::Instant::now();
        u.stop();
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(l.has(Level::Debug2, "Scheduler stopped for 'vulnerability_feed_manager'"));
    }

    #[test]
    fn retry_waits() {
        // 429 -> 90 s is logged before waiting; the stop flag ends the wait.
        let home = tempfile::tempdir().unwrap();
        let h: Handler = Arc::new(|_, _| (429, b"slow".to_vec()));
        let url = server(h, Arc::new(Mutex::new(Vec::new())));
        let l = Arc::new(MemoryLogger::default());
        let stop = Arc::new(StopSignal::default());
        let cb: Callback = Arc::new(|_| (0, String::new(), true));
        let u = Updater::build(home.path(), &params(&format!("{url}/meta"), "online"), cb, stop.clone(), Log::new(l.clone()), false).unwrap();
        let s2 = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            s2.set();
        });
        let _ = u.run_now();
        assert!(l.has(Level::Debug, "Retrying download in 90 seconds"));
    }
}
