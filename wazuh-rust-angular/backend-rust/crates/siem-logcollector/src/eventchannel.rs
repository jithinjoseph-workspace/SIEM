//! `logcollector/read_win_event_channel.c`: the `eventchannel` log format
//! (Windows Vista and later). Each channel is an `EvtSubscribe`
//! subscription whose callback renders the event XML, adds the provider's
//! formatted message and sends `{"Message":...,"Event":...}` with the
//! `WIN_EVT_MQ` queue id; with bookmarks (`only-future-events` no) the last
//! event read is kept in `bookmarks/<channel>`.
//!
//! As in C, the subscription context is the channel structure (owned by the
//! subscription until it is replaced), the bookmark file is written and read
//! through text-mode streams, and the provider name comes from the
//! `Provider Name='...'` attribute of the XML.

use std::ffi::c_void;
use std::sync::Arc;

use siem_cjson::Json;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtCreateBookmark, EvtFormatMessage, EvtFormatMessageEvent, EvtOpenPublisherMetadata, EvtRender,
    EvtRenderBookmark, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeStartAfterBookmark,
    EvtSubscribeToFutureEvents, EvtUpdateBookmark, EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION,
};

use crate::*;

/// `BOOKMARKS_DIR`
const BOOKMARKS_DIR: &str = "bookmarks";
/// `WIN_EVT_MQ`
const WIN_EVT_MQ: u8 = b'f';
const ERROR_EVT_MESSAGE_NOT_FOUND: u32 = 15027;
const ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND: u32 = 15033;
const RPC_S_SERVER_UNAVAILABLE: u32 = 1722;
const RPC_S_UNKNOWN_IF: u32 = 1717;

/// `os_channel`
struct OsChannel {
    lc: Arc<Lc>,
    evt_log: String,
    bookmark_enabled: bool,
    bookmark_filename: String,
    query: Option<String>,
    reconnect_time: i32,
    subscription: EVT_HANDLE,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `convert_unix_string`: UTF-8 to a NUL-terminated wide string.
fn convert_unix_string(s: &str) -> Vec<u16> {
    wide(s)
}

/// `convert_windows_string` (`WC_ERR_INVALID_CHARS`): `None`, logged to
/// the file only, when the string has invalid UTF-16.
fn convert_windows_string(lc: &Lc, w: &[u16]) -> Option<String> {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    match String::from_utf16(&w[..n]) {
        Ok(s) => Some(s),
        Err(_) => {
            // ERROR_NO_UNICODE_TRANSLATION
            lc.log.ferror("Could not WideCharToMultiByte() when determining size which returned (1113)");
            None
        }
    }
}

/// `filter_special_chars`: drop each backslash, keeping the next character.
pub fn filter_special_chars(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 1;
            if i >= b.len() {
                break;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `FormatMessage(FROM_SYSTEM | IGNORE_INSERTS | MAX_WIDTH_MASK, err)`
fn system_message(err: u32) -> String {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FormatMessageA, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    };
    const FORMAT_MESSAGE_MAX_WIDTH_MASK: u32 = 0xFF;
    let mut buf = vec![0u8; OS_SIZE_1024];
    // SAFETY: a 1024-byte buffer.
    unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            std::ptr::null(),
            err,
            0x0400, // MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
            buf.as_mut_ptr(),
            OS_SIZE_1024 as u32,
            std::ptr::null(),
        )
    };
    String::from_utf8_lossy(cstr(&buf)).into_owned()
}

/// `get_message`: the provider's message for the event.
fn get_message(lc: &Lc, evt: EVT_HANDLE, provider: &[u16], flags: u32) -> Option<String> {
    // SAFETY: Evt* calls on handles we own, buffers sized as reported.
    unsafe {
        let publisher = EvtOpenPublisherMetadata(0, provider.as_ptr(), std::ptr::null(), 0, 0);
        if publisher == 0 {
            let err = GetLastError();
            lc.log.debug1(format!(
                "Could not EvtOpenPublisherMetadata() with flags ({flags}) which returned ({err}): {}",
                system_message(err)
            ));
            return None;
        }
        let close = |p| {
            EvtClose(p);
        };
        let mut size: u32 = 0;
        if EvtFormatMessage(publisher, evt, 0, 0, std::ptr::null(), flags, 0, std::ptr::null_mut(), &mut size) != 0 {
            lc.log.error(format!(
                "Could not EvtFormatMessage() to determine buffer size with flags ({flags}): unexpected result"
            ));
            close(publisher);
            return None;
        }
        let last = GetLastError();
        match last {
            ERROR_INSUFFICIENT_BUFFER => {}
            ERROR_EVT_MESSAGE_NOT_FOUND | ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND => {
                lc.log.debug1(format!(
                    "Could not EvtFormatMessage() to determine buffer size with flags ({flags}) which returned ({last})"
                ));
                close(publisher);
                return None;
            }
            _ => {
                lc.log.error(format!(
                    "Could not EvtFormatMessage() to determine buffer size with flags ({flags}) which returned ({last})"
                ));
                close(publisher);
                return None;
            }
        }
        size += 1;
        let mut buffer = vec![0u16; size as usize];
        if EvtFormatMessage(publisher, evt, 0, 0, std::ptr::null(), flags, size, buffer.as_mut_ptr(), &mut size) == 0 {
            lc.log.error(format!(
                "Could not EvtFormatMessage() with flags ({flags}) which returned ({})",
                GetLastError()
            ));
            close(publisher);
            return None;
        }
        let m = convert_windows_string(lc, &buffer);
        close(publisher);
        m
    }
}

/// `read_bookmark`: the stored bookmark (`wfopen(file, "r")` + `fread` of
/// wide characters).
fn read_bookmark(ch: &OsChannel) -> EVT_HANDLE {
    let lc = &ch.lc;
    let data = match siem_fileop::crt::read_text(&ch.bookmark_filename) {
        Ok(d) => d,
        Err(e) => {
            // errno is GetLastError() here: report anything but "not found"
            let n = e.raw_os_error().unwrap_or(0);
            if n != 2 {
                lc.log.error(format!(
                    "Could not wfopen() existing bookmark ({}) for ({}) which returned [({n})-({})]",
                    ch.bookmark_filename,
                    ch.evt_log,
                    strerror(n)
                ));
            }
            return 0;
        }
    };
    // fread(bookmark_xml, sizeof(wchar_t), OS_MAXSTR, fp)
    let mut xml: Vec<u16> = data.chunks_exact(2).take(OS_MAXSTR - 1).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
    if xml.is_empty() {
        return 0;
    }
    xml.push(0);
    // SAFETY: a NUL-terminated wide string.
    let b = unsafe { EvtCreateBookmark(xml.as_ptr()) };
    if b == 0 {
        lc.log.error(format!(
            "Could not EvtCreateBookmark() bookmark ({}) for ({}) which returned ({})",
            ch.bookmark_filename,
            ch.evt_log,
            unsafe { GetLastError() }
        ));
    }
    b
}

/// `update_bookmark`: 1 when the bookmark file was written.
fn update_bookmark(evt: EVT_HANDLE, ch: &OsChannel) -> i32 {
    let lc = &ch.lc;
    let (f, l) = (&ch.bookmark_filename, &ch.evt_log);
    // SAFETY: Evt* calls on handles we own, buffers sized as reported.
    unsafe {
        let bookmark = EvtCreateBookmark(std::ptr::null());
        if bookmark == 0 {
            lc.log.error(format!(
                "Could not EvtCreateBookmark() bookmark ({f}) for ({l}) which returned ({})",
                GetLastError()
            ));
            return 0;
        }
        let done = |r: i32| {
            EvtClose(bookmark);
            r
        };
        if EvtUpdateBookmark(bookmark, evt) == 0 {
            lc.log.error(format!(
                "Could not EvtUpdateBookmark() bookmark ({f}) for ({l}) which returned ({})",
                GetLastError()
            ));
            return done(0);
        }
        let (mut size, mut count) = (0u32, 0u32);
        let r = EvtRender(0, bookmark, EvtRenderBookmark, 0, std::ptr::null_mut(), &mut size, &mut count);
        if r != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            lc.log.error(format!(
                "Could not EvtRender() to get buffer size to update bookmark ({f}) for ({l}) which returned ({})",
                GetLastError()
            ));
            return done(0);
        }
        let mut buffer = vec![0u8; size as usize];
        if EvtRender(0, bookmark, EvtRenderBookmark, size, buffer.as_mut_ptr().cast(), &mut size, &mut count) == 0 {
            lc.log.error(format!(
                "Could not EvtRender() bookmark ({f}) for ({l}) which returned ({})",
                GetLastError()
            ));
            return done(0);
        }
        buffer.truncate(size as usize);
        // wfopen(file, "w") + fwrite: a text-mode stream
        if let Err(e) = siem_fileop::crt::write_text(f, &buffer) {
            let n = e.raw_os_error().unwrap_or(0);
            lc.log.warn(format!(
                "Could not wfopen() bookmark ({f}) for ({l}) which returned [({n})-({})]",
                strerror(n)
            ));
            return done(0);
        }
        done(1)
    }
}

/// `send_channel_event`
fn send_channel_event(evt: EVT_HANDLE, ch: &OsChannel) {
    let lc = &ch.lc;
    // SAFETY: EvtRender with a buffer of the reported size.
    let xml_event = unsafe {
        let (mut len, mut count) = (0u32, 0u32);
        let r = EvtRender(0, evt, EvtRenderEventXml, 0, std::ptr::null_mut(), &mut len, &mut count);
        if r != 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            lc.log.error(format!(
                "Could not EvtRender() to determine buffer size for ({}) which returned ({})",
                ch.evt_log,
                GetLastError()
            ));
            return;
        }
        let mut buf = vec![0u16; (len as usize + 1) / 2 + 1];
        if EvtRender(0, evt, EvtRenderEventXml, len, buf.as_mut_ptr().cast(), &mut len, &mut count) == 0 {
            lc.log.error(format!("Could not EvtRender() for ({}) which returned ({})", ch.evt_log, GetLastError()));
            return;
        }
        match convert_windows_string(lc, &buf) {
            Some(x) => x,
            None => return,
        }
    };

    // The provider name: Provider Name='...'
    let mut provider_name = String::new();
    if let Some(fp) = xml_event.find("Provider Name=") {
        if let Some(b) = xml_event[fp..].find('\'').map(|k| fp + k) {
            if let Some(e) = xml_event[b + 1..].find('\'').map(|k| b + 1 + k) {
                let num = e - b - 1;
                if num > OS_MAXSTR - 1 {
                    lc.log.warn("The event message has exceeded the maximum size.");
                    return;
                }
                provider_name = xml_event[b + 1..e].to_string();
            }
        }
    }

    let mut event_json = Json::object();
    let wprovider = convert_unix_string(&provider_name);
    match get_message(lc, evt, &wprovider, EvtFormatMessageEvent as u32) {
        None => lc.log.debug1(format!("Could not get message for ({})", ch.evt_log)),
        Some(m) => {
            event_json.add("Message", Json::string(&m));
        }
    }

    let mut xml = xml_event.into_bytes();
    crate::win::win_format_event_string(&mut xml);
    event_json.add("Event", Json::string(&xml));
    let msg_sent = event_json.print_unformatted();

    crate::state::update_file(lc, &ch.evt_log, msg_sent.len() as u64);
    let q = lc.logr_queue.load(std::sync::atomic::Ordering::SeqCst);
    if siem_ipc::mq_op::send_msg(q, &msg_sent, "EventChannel", WIN_EVT_MQ) < 0 {
        lc.log.error("(1224): Error sending message to queue.");
        crate::state::update_target(lc, &ch.evt_log, "agent", true);
    } else {
        crate::state::update_target(lc, &ch.evt_log, "agent", false);
    }

    if ch.bookmark_enabled {
        update_bookmark(evt, ch);
    }
}

/// `os_channel_destroy`
unsafe fn os_channel_destroy(ch: *mut OsChannel) {
    if ch.is_null() {
        return;
    }
    let c = Box::from_raw(ch);
    if c.subscription != 0 && EvtClose(c.subscription) == 0 {
        c.lc.log.error(format!("Could not close subscription to channel '{}': {}", c.evt_log, GetLastError()));
    }
}

/// `event_channel_callback`
unsafe extern "system" fn event_channel_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    ctx: *const c_void,
    evt: EVT_HANDLE,
) -> u32 {
    let ch = ctx as *mut OsChannel;
    let c = &*ch;
    if action == EvtSubscribeActionDeliver {
        send_channel_event(evt, c);
    } else {
        c.lc.log.warn(format!(
            "The eventlog service is down. Unable to collect logs from '{}' channel.",
            c.evt_log
        ));
        loop {
            // Try to restart EventChannel
            if win_start_event_channel(&c.lc, &c.evt_log, !c.bookmark_enabled, c.query.as_deref(), c.reconnect_time) == -1 {
                c.lc.log.debug1(format!("Trying to reconnect {} channel in {} seconds.", c.evt_log, c.reconnect_time));
                sleep_secs(c.reconnect_time as i64);
            } else {
                c.lc.log.info(format!("'{}' channel has been reconnected succesfully.", c.evt_log));
                os_channel_destroy(ch);
                break;
            }
        }
    }
    0
}

/// `win_start_event_channel`: 0, or -1 when the channel could not be
/// subscribed.
pub fn win_start_event_channel(_lc: &Lc, evt_log: &str, future: bool, query: Option<&str>, reconnect_time: i32) -> i32 {
    let lc = match crate::collector::LC.get() {
        Some(a) => Arc::clone(a),
        None => return -1,
    };
    // Replace the last '/' with '_'
    let mut bookmark_name = evt_log.to_string();
    if let Some(p) = bookmark_name.rfind('/') {
        bookmark_name.replace_range(p..p + 1, "_");
    }
    let wchannel = convert_unix_string(evt_log);
    let wquery = query.map(|q| convert_unix_string(&filter_special_chars(q)));
    let bookmark_enabled = !future;
    let bookmark_filename = if bookmark_enabled {
        let mut f = format!("{BOOKMARKS_DIR}/{bookmark_name}");
        f.truncate(OS_MAXSTR - 1);
        f
    } else {
        String::new()
    };
    let ch = Box::into_raw(Box::new(OsChannel {
        lc: Arc::clone(&lc),
        evt_log: evt_log.to_string(),
        bookmark_enabled,
        bookmark_filename,
        query: query.map(str::to_string),
        reconnect_time,
        subscription: 0,
    }));
    // SAFETY: the channel lives until os_channel_destroy; EvtSubscribe gets
    // NUL-terminated wide strings.
    unsafe {
        let mut flags = EvtSubscribeToFutureEvents;
        let mut bookmark: EVT_HANDLE = 0;
        if bookmark_enabled {
            bookmark = read_bookmark(&*ch);
            if bookmark != 0 {
                flags = EvtSubscribeStartAfterBookmark;
            }
        }
        let q = wquery.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());
        let mut sub = EvtSubscribe(0, std::ptr::null_mut(), wchannel.as_ptr(), q, bookmark, ch as *const c_void, Some(event_channel_callback), flags);
        if sub == 0 && flags == EvtSubscribeStartAfterBookmark {
            sub = EvtSubscribe(0, std::ptr::null_mut(), wchannel.as_ptr(), q, 0, ch as *const c_void, Some(event_channel_callback), EvtSubscribeToFutureEvents);
        }
        (*ch).subscription = sub;
        let status = if sub == 0 {
            let id = GetLastError();
            if id != RPC_S_SERVER_UNAVAILABLE && id != RPC_S_UNKNOWN_IF {
                lc.log.error(format!("Could not EvtSubscribe() for ({evt_log}) which returned ({id})"));
            }
            false
        } else {
            crate::state::update_file(&lc, evt_log, 0);
            crate::state::update_target(&lc, evt_log, "agent", false);
            true
        };
        if !status {
            os_channel_destroy(ch);
        }
        if bookmark != 0 {
            EvtClose(bookmark);
        }
        if status {
            0
        } else {
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_chars() {
        assert_eq!(filter_special_chars(r"Event[System[\(EventID=1\)]]\"), "Event[System[(EventID=1)]]");
    }
}
