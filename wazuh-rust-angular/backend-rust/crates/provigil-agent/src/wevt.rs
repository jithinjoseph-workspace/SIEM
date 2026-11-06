//! Windows event channels: one live subscription per channel through the event log API.
//!
//! Every event is sent as its XML plus the provider's formatted message (the manager builds the
//! `win.*` fields from the XML). The channel's position is kept in `bookmarks\<channel>`, so a
//! restarted agent sends what happened while it was stopped.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::Value;

use crate::buffer::EventBuffer;

/// The payload text (`{"Message":..,"Event":..}`) must stay under this many bytes.
const MAX_PAYLOAD: usize = 63_000;

/// Starts one reader thread per channel (API calls stay off the async runtime). `queries` holds
/// the XPath filter per channel name; `running` is polled to stop. Non-Windows: starts nothing.
pub fn spawn_readers(
    channels: &[String],
    queries: &HashMap<String, String>,
    reconnect: Duration,
    bookmark_dir: &Path,
    buffer: Arc<EventBuffer>,
    agent: Value,
    running: fn() -> bool,
) -> Vec<JoinHandle<()>> {
    #[cfg(windows)]
    {
        channels
            .iter()
            .filter_map(|c| {
                let r = Reader {
                    channel: c.clone(),
                    query: queries.get(c).cloned(),
                    file: bookmark_path(bookmark_dir, c),
                    buffer: buffer.clone(),
                    agent: agent.clone(),
                    reconnect,
                    running,
                };
                crate::thread(format!("wevt {c}"), move || win::run(r))
                    .map_err(|e| tracing::error!(channel = %c, error = %e, "Event channel thread not started"))
                    .ok()
            })
            .collect()
    }
    #[cfg(not(windows))]
    {
        let _ = (channels, queries, reconnect, bookmark_dir, buffer, agent, running);
        Vec::new()
    }
}

/// `bookmarks\Microsoft-Windows-Sysmon_Operational` for `Microsoft-Windows-Sysmon/Operational`.
pub fn bookmark_path(dir: &Path, channel: &str) -> PathBuf {
    dir.join(channel.replace('/', "_"))
}

/// CR and LF become spaces; so does a TAB right after CR, LF, `:` or another such TAB.
pub fn clean_xml(xml: &str) -> String {
    let mut after = false;
    xml.chars()
        .map(|c| {
            let (out, next) = match c {
                '\r' | '\n' => (' ', true),
                '\t' if after => (' ', true),
                ':' => (':', true),
                _ => (c, false),
            };
            after = next;
            out
        })
        .collect()
}

/// The provider from `Provider Name='…'` (Windows renders single quotes).
pub fn provider_name(xml: &str) -> Option<&str> {
    between(xml, "Provider Name='", "'")
}

pub(crate) fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    s[start..].find(close).map(|end| &s[start..start + end])
}

/// Bytes `c` takes inside a JSON string as serde_json writes it.
fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

fn js(s: &str) -> String {
    Value::from(s).to_string()
}

/// `{"Message":..,"Event":..}` under [`MAX_PAYLOAD`] bytes: the message is cut to fit (at a
/// character), left out when nothing of it fits; `None` when the XML alone is too long.
pub fn build_payload(message: Option<&str>, xml: &str) -> Option<String> {
    let event = js(xml);
    let bare = format!("{{\"Event\":{event}}}");
    if bare.len() >= MAX_PAYLOAD {
        return None;
    }
    let Some(msg) = message else { return Some(bare) };
    // what is left for the message's characters once `"Message":"",` is added
    let Some(mut room) = (MAX_PAYLOAD - 1).checked_sub(bare.len() + r#""Message":"","#.len()) else {
        return Some(bare);
    };
    let cut = msg
        .char_indices()
        .find(|&(_, c)| {
            let n = escaped_len(c);
            if n > room {
                return true;
            }
            room -= n;
            false
        })
        .map_or(msg.len(), |(i, _)| i);
    Some(format!("{{\"Message\":{},\"Event\":{event}}}", js(&msg[..cut])))
}

#[cfg(windows)]
struct Reader {
    channel: String,
    query: Option<String>,
    file: PathBuf,
    buffer: Arc<EventBuffer>,
    agent: Value,
    reconnect: Duration,
    running: fn() -> bool,
}

/// The subscription helpers are shared with `whodata.rs`.
#[cfg(windows)]
pub(crate) mod win {
    use super::*;
    use std::collections::HashSet;
    use std::ptr::{null, null_mut};
    use std::time::Instant;
    use serde_json::json;
    use tracing::{debug, error, info, warn};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_EVT_INVALID_QUERY,
        ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT, HANDLE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::EventLog::*;
    use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

    /// A missing channel (e.g. Sysmon not installed) is looked for again this often.
    const MISSING_RETRY: Duration = Duration::from_secs(300);

    pub(crate) struct Evt(pub(crate) EVT_HANDLE);
    impl Drop for Evt {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { EvtClose(self.0) };
            }
        }
    }

    pub(crate) struct Signal(pub(crate) HANDLE);
    impl Drop for Signal {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// Fields drop in order: the subscription closes before its signal event.
    struct Subscription {
        sub: Evt,
        bookmark: Evt,
        signal: Signal,
    }

    pub(crate) fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    pub(crate) fn last_error() -> u32 {
        unsafe { GetLastError() }
    }

    /// The event's XML (`EvtRenderEventXml`) or a bookmark's XML (`EvtRenderBookmark`).
    pub(crate) fn render(h: EVT_HANDLE, flags: u32) -> Option<String> {
        let (mut used, mut count) = (0u32, 0u32);
        unsafe {
            if EvtRender(0, h, flags, 0, null_mut(), &mut used, &mut count) == 0
                && GetLastError() != ERROR_INSUFFICIENT_BUFFER
            {
                return None;
            }
            let mut buf = vec![0u16; (used as usize).div_ceil(2)];
            let size = (buf.len() * 2) as u32;
            if EvtRender(0, h, flags, size, buf.as_mut_ptr().cast(), &mut used, &mut count) == 0 {
                return None;
            }
            Some(from_wide(&buf))
        }
    }

    fn format_message(meta: EVT_HANDLE, ev: EVT_HANDLE) -> Option<String> {
        let mut used = 0u32;
        unsafe {
            if EvtFormatMessage(meta, ev, 0, 0, null(), EvtFormatMessageEvent, 0, null_mut(), &mut used) == 0
                && GetLastError() != ERROR_INSUFFICIENT_BUFFER
            {
                return None;
            }
            let mut buf = vec![0u16; used as usize];
            if used == 0
                || EvtFormatMessage(meta, ev, 0, 0, null(), EvtFormatMessageEvent, used, buf.as_mut_ptr(), &mut used) == 0
            {
                return None;
            }
            Some(from_wide(&buf))
        }
    }

    /// Publisher metadata per provider, opened once; a provider without messages is noted once.
    #[derive(Default)]
    struct Providers {
        meta: HashMap<String, Evt>,
        noted: HashSet<String>,
    }

    impl Providers {
        fn message(&mut self, name: &str, ev: EVT_HANDLE) -> Option<String> {
            let meta = self
                .meta
                .entry(name.to_string())
                .or_insert_with(|| Evt(unsafe { EvtOpenPublisherMetadata(0, wide(name).as_ptr(), null(), 0, 0) }))
                .0;
            let msg = if meta == 0 { None } else { format_message(meta, ev) };
            if msg.is_none() && self.noted.insert(name.to_string()) {
                debug!(provider = name, "No formatted message from this provider; its events are sent without one");
            }
            msg
        }
    }

    fn nap(d: Duration, running: fn() -> bool) {
        let end = Instant::now() + d;
        while running() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    pub(super) fn run(r: Reader) {
        let ch = r.channel.as_str();
        let (mut down, mut missing) = (false, false);
        let mut providers = Providers::default();
        while (r.running)() {
            match subscribe(&r) {
                Ok(s) => {
                    info!(channel = ch, "Event channel subscribed");
                    missing = false;
                    match read(&r, &s, &mut providers) {
                        Ok(()) => break,
                        Err(e) => {
                            warn!(channel = ch, error = e, "Event channel subscription failed; subscribing again");
                            down = true;
                        }
                    }
                }
                Err(ERROR_EVT_CHANNEL_NOT_FOUND) => {
                    if !missing {
                        info!(channel = ch, "Event channel not found; looking again every 5 minutes");
                        missing = true;
                    }
                    nap(MISSING_RETRY, r.running);
                    continue;
                }
                Err(ERROR_EVT_INVALID_QUERY) => {
                    error!(channel = ch, query = ?r.query, "Invalid XPath query; the channel stays off until it is fixed");
                    return;
                }
                Err(e) => {
                    if !down {
                        warn!(channel = ch, error = e, retry_secs = r.reconnect.as_secs(), "Event channel subscription failed; trying again");
                        down = true;
                    }
                }
            }
            nap(r.reconnect, r.running);
        }
        debug!(channel = ch, "Event channel closed");
    }

    /// After the saved bookmark when the API accepts it, else new events only.
    fn subscribe(r: &Reader) -> Result<Subscription, u32> {
        let signal = Signal(unsafe { CreateEventW(null(), 1, 1, null()) });
        if signal.0.is_null() {
            return Err(last_error());
        }
        let sig = signal.0;
        let channel = wide(&r.channel);
        let query = r.query.as_deref().map(wide);
        let query_ptr = query.as_ref().map_or(null(), |q| q.as_ptr());
        let open = |bookmark: EVT_HANDLE, flags: u32| {
            let h = unsafe { EvtSubscribe(0, sig, channel.as_ptr(), query_ptr, bookmark, null(), None, flags) };
            if h == 0 { Err(last_error()) } else { Ok(Evt(h)) }
        };
        if let Ok(xml) = std::fs::read_to_string(&r.file) {
            let bookmark = Evt(unsafe { EvtCreateBookmark(wide(&xml).as_ptr()) });
            if bookmark.0 == 0 {
                debug!(channel = %r.channel, "Saved bookmark not usable; new events only");
            } else {
                match open(bookmark.0, EvtSubscribeStartAfterBookmark | EvtSubscribeStrict) {
                    Ok(sub) => return Ok(Subscription { sub, bookmark, signal }),
                    Err(e @ (ERROR_EVT_CHANNEL_NOT_FOUND | ERROR_EVT_INVALID_QUERY)) => return Err(e),
                    Err(e) => debug!(channel = %r.channel, error = e, "Saved bookmark rejected; new events only"),
                }
            }
        }
        let bookmark = Evt(unsafe { EvtCreateBookmark(null()) });
        if bookmark.0 == 0 {
            return Err(last_error());
        }
        // the API wants no bookmark here; this one only records the position from now on
        let sub = open(0, EvtSubscribeToFutureEvents)?;
        Ok(Subscription { sub, bookmark, signal })
    }

    /// Reads until stopped (`Ok`) or the subscription breaks (`Err` with the Windows error).
    fn read(r: &Reader, s: &Subscription, providers: &mut Providers) -> Result<(), u32> {
        let mut batch = [0 as EVT_HANDLE; 64];
        while (r.running)() {
            // EvtNext only when signalled (unsignalled it fails with ERROR_INVALID_OPERATION);
            // a broken subscription signals too, and EvtNext then returns its error
            if unsafe { WaitForSingleObject(s.signal.0, 1000) } != WAIT_OBJECT_0 {
                continue;
            }
            unsafe { ResetEvent(s.signal.0) };
            // a backlog (after a restart) is read in batches, with the stop checked between them
            while (r.running)() {
                let mut n = 0u32;
                if unsafe { EvtNext(s.sub.0, batch.len() as u32, batch.as_mut_ptr(), 0, 0, &mut n) } == 0 {
                    match last_error() {
                        ERROR_NO_MORE_ITEMS | ERROR_TIMEOUT => break,
                        e => return Err(e),
                    }
                }
                let events: Vec<Evt> = batch[..n as usize].iter().map(|&h| Evt(h)).collect();
                for ev in &events {
                    send(r, s, ev, providers);
                }
            }
        }
        Ok(())
    }

    fn send(r: &Reader, s: &Subscription, ev: &Evt, providers: &mut Providers) {
        match render(ev.0, EvtRenderEventXml) {
            None => warn!(channel = %r.channel, error = last_error(), "Event not rendered; skipped"),
            Some(xml) => {
                let message = provider_name(&xml).and_then(|p| providers.message(p, ev.0));
                match build_payload(message.as_deref(), &clean_xml(&xml)) {
                    Some(payload) => r.buffer.push(json!({
                        "event_type": "windows_eventchannel",
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "agent": r.agent,
                        "location": "EventChannel",
                        "channel": r.channel,
                        "message": payload,
                    })),
                    None => warn!(
                        channel = %r.channel,
                        record_id = between(&xml, "<EventRecordID>", "</EventRecordID>").unwrap_or("?"),
                        "Event XML over 63000 bytes; event dropped"
                    ),
                }
            }
        }
        unsafe { EvtUpdateBookmark(s.bookmark.0, ev.0) };
        if let Some(b) = render(s.bookmark.0, EvtRenderBookmark) {
            if let Err(e) = save(&r.file, &b) {
                warn!(channel = %r.channel, error = %e, "Bookmark not saved");
            }
        }
    }

    /// Written aside then renamed, so a crash never leaves a half-written bookmark.
    fn save(file: &Path, xml: &str) -> std::io::Result<()> {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = file.with_extension("tmp");
        std::fs::write(&tmp, xml)?;
        std::fs::rename(&tmp, file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_cleanup() {
        assert_eq!(clean_xml("a\r\nb"), "a  b");
        assert_eq!(clean_xml("a\n\t\tb"), "a   b");
        assert_eq!(clean_xml("Name:\t\tx"), "Name:  x");
        assert_eq!(clean_xml("a\tb\t\tc"), "a\tb\t\tc");
        assert_eq!(clean_xml("a\n x\tb"), "a  x\tb");
    }

    #[test]
    fn payload_order_absent_message_and_escaping() {
        let p = build_payload(Some("say \"hi\" C:\\x"), "<Event a='1'/>").unwrap();
        assert_eq!(p, r#"{"Message":"say \"hi\" C:\\x","Event":"<Event a='1'/>"}"#);
        assert_eq!(build_payload(None, "<E/>").unwrap(), r#"{"Event":"<E/>"}"#);
        let v: Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["Message"], "say \"hi\" C:\\x");
    }

    #[test]
    fn payload_size_limit() {
        let xml = "x".repeat(1000);
        let msg = format!("{}\"é", "m".repeat(70_000));
        let p = build_payload(Some(&msg), &xml).unwrap();
        assert!(p.len() < MAX_PAYLOAD && p.len() > MAX_PAYLOAD - 10);
        let v: Value = serde_json::from_str(&p).unwrap();
        assert!(msg.starts_with(v["Message"].as_str().unwrap()));
        assert_eq!(v["Event"], xml.as_str());
        // a message full of escapes, cut between multi-byte characters, still fits
        let p = build_payload(Some(&"\"é\u{1}".repeat(20_000)), &xml).unwrap();
        assert!(p.len() < MAX_PAYLOAD);
        serde_json::from_str::<Value>(&p).unwrap();
        // XML alone too long: dropped
        assert!(build_payload(Some("m"), &"x".repeat(MAX_PAYLOAD)).is_none());
        assert!(build_payload(None, &"x".repeat(MAX_PAYLOAD)).is_none());
    }

    #[test]
    fn provider_from_single_quoted_attribute() {
        let xml = "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{5484}'/></System></Event>";
        assert_eq!(provider_name(xml), Some("Microsoft-Windows-Security-Auditing"));
        assert_eq!(provider_name("<Event/>"), None);
    }

    #[test]
    fn sysmon_bookmark_file_name() {
        let p = bookmark_path(Path::new("bookmarks"), "Microsoft-Windows-Sysmon/Operational");
        assert_eq!(p, Path::new("bookmarks").join("Microsoft-Windows-Sysmon_Operational"));
    }

    /// Writes events with eventcreate and reads them back through the Application channel.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn wevt_live_application_bookmark() {
        use serde_json::json;
        use std::sync::atomic::{AtomicBool, Ordering};
        static RUN: AtomicBool = AtomicBool::new(true);
        fn running() -> bool {
            RUN.load(Ordering::SeqCst)
        }
        let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).with_test_writer().try_init();
        let dir = tempfile::tempdir().unwrap();
        let channels = ["Application".to_string()];
        let queries = HashMap::from([("Application".to_string(), "Event/System[EventID=999]".to_string())]);
        let buffer = Arc::new(EventBuffer::new(10_000));
        let start = || {
            RUN.store(true, Ordering::SeqCst);
            let h = spawn_readers(&channels, &queries, Duration::from_secs(5), dir.path(), buffer.clone(), json!({"id": "000", "name": "test"}), running);
            std::thread::sleep(Duration::from_secs(2)); // subscription in place
            h
        };
        let stop = |h: Vec<JoinHandle<()>>| {
            RUN.store(false, Ordering::SeqCst);
            h.into_iter().for_each(|t| t.join().unwrap());
        };
        let write = |text: &str| {
            let ok = std::process::Command::new("eventcreate")
                .args(["/T", "INFORMATION", "/ID", "999", "/L", "APPLICATION", "/SO", "ProVigilTest", "/D", text])
                .status()
                .unwrap()
                .success();
            assert!(ok, "eventcreate failed");
        };
        // everything drained until an event whose Message has `text`, or 15 s
        let collect = |text: &str| -> (Vec<Value>, Option<Value>) {
            let mut seen = Vec::new();
            for _ in 0..30 {
                for ev in buffer.drain_batch(10_000) {
                    let payload: Value = serde_json::from_str(ev["message"].as_str().unwrap()).unwrap();
                    seen.push(ev.clone());
                    if payload["Message"].as_str().is_some_and(|m| m.trim() == text) {
                        return (seen, Some(ev));
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            (seen, None)
        };
        let rid = |ev: &Value| {
            let payload: Value = serde_json::from_str(ev["message"].as_str().unwrap()).unwrap();
            between(payload["Event"].as_str().unwrap(), "<EventRecordID>", "</EventRecordID>").unwrap().to_string()
        };

        let h = start();
        write("provigil wevt test");
        let (seen, first) = collect("provigil wevt test");
        if first.is_none() {
            println!("read instead: {seen:#?}");
        }
        let first = first.expect("event not read from the Application channel");
        println!("first event: {first}");
        assert_eq!(first["event_type"], "windows_eventchannel");
        assert_eq!(first["channel"], "Application");
        assert!(first["message"].as_str().unwrap().contains("Provider Name='ProVigilTest'"));
        let rid1 = rid(&first);
        stop(h);
        let saved = std::fs::read_to_string(bookmark_path(dir.path(), "Application")).unwrap();
        println!("bookmark: {saved}");
        assert!(saved.contains(&format!("RecordId='{rid1}'")));

        // written while stopped: sent after the restart, the first one not again
        write("provigil wevt test 2");
        let h = start();
        let (mut seen, second) = collect("provigil wevt test 2");
        let second = second.expect("event written while stopped not sent after restart");
        println!("after restart: {second}");
        std::thread::sleep(Duration::from_secs(2));
        seen.extend(buffer.drain_batch(10_000));
        stop(h);
        assert!(seen.iter().all(|ev| rid(ev) != rid1), "first event sent again");
        println!("events after restart: {}, record {rid1} not among them", seen.len());
    }
}
