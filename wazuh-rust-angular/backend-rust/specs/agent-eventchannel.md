# provigil-agent: Windows event channels (`src/wevt.rs`)

Written 2026-11-03 from a study of how the old Windows agent collects event channels. Describes
what the new code must do. Contains no code. The new code is written from this description
only; no old agent code is opened.

## Why

Detection rules, Sigma rules, tamper protection and YARA candidates on the manager all read the
structured fields of Windows events (`win.system.eventID`, `win.eventdata.commandLine`,
`subjectUserName`, `logonType`, `parentImage`, …). The manager builds those fields itself from the
event's XML, exactly as it does for the old agent. So the agent must send, for every event, the
event's XML and its formatted message, and must not lose, cap or skip events.

The current `src/events.rs` reading (PowerShell `Get-WinEvent` every 5 s, newest 20–50 only,
message text only) is replaced. Its bookmark file and the file-tail parts of `events.rs` are not
used by the new module.

## Configuration (`src/config.rs`)

- `event_channels: Vec<String>` stays (channel names). New default list:
  `Security`, `System`, `Application`, `Microsoft-Windows-Sysmon/Operational`,
  `Microsoft-Windows-PowerShell/Operational`, `Windows PowerShell`,
  `Microsoft-Windows-Windows Defender/Operational`, `Microsoft-Windows-TaskScheduler/Operational`.
- New `event_channel_queries: HashMap<String, String>` (serde default): an XPath filter per
  channel name. Default entries:
  - `Microsoft-Windows-PowerShell/Operational` → `Event/System[EventID=4103 or EventID=4104]`
  - `Windows PowerShell` → `Event/System[EventID=400 or EventID=600 or EventID=800]`
- New `event_channel_reconnect_secs: u64` (serde default 5).

## Behaviour

- **One live subscription per channel** through the Windows event log API (`wevtapi`, crate
  `windows-sys`, feature `Win32_System_EventLog`). Events are delivered in order; there is no
  per-poll limit that drops events. No external program (PowerShell, wevtutil) is started.
- **Bookmarks:** after each event is handed to the agent's buffer, the channel's position is saved
  to `bookmarks\<channel>` (in the agent folder; `/` in the channel name replaced by `_`), as the
  Windows bookmark XML the API renders. At start, a channel with a usable bookmark continues right
  after it (events that happened while the agent was stopped are sent); a channel without one, or
  whose bookmark the API rejects, starts with new events only.
- **Per event:**
  1. Render the event as XML (the API's event-XML rendering).
  2. Take the provider name from the XML's `Provider Name='…'` attribute and get the provider's
     formatted message for the event (publisher metadata + event message formatting). When it
     cannot be had (no provider metadata, message not found), the message is left out; log once
     per provider at debug level, never fail the event.
  3. Clean the XML text: every CR and LF becomes a space; every TAB that directly follows a CR,
     LF or `:` (and every TAB right after such a replaced TAB) becomes a space.
  4. Build the payload text: a JSON object with first `"Message"` (the formatted message as is,
     when present) then `"Event"` (the cleaned XML), compact, e.g.
     `{"Message":"An account was successfully logged on. ...","Event":"<Event xmlns=...>...</Event>"}`.
  5. Size: the payload must stay under 63,000 bytes. If it is longer, shorten the `Message` value
     (on a character boundary) until it fits; if the XML alone is too long, drop the event and log
     a warning with the channel and record id.
  6. Push to the buffer one JSON event:
     `{"event_type":"windows_eventchannel","timestamp":<now, RFC 3339>,"agent":{"id":..,"name":..},"location":"EventChannel","channel":<channel name>,"message":<the payload text>}`.
- **Missing channel** (e.g. Sysmon not installed): log once at info and try again every 5 minutes.
- **Event log service stopped or subscription failed later:** log a warning, retry every
  `event_channel_reconnect_secs`, log at info when the channel is back.
- **XPath query:** used as configured; an invalid query is logged as an error for that channel
  (the channel then runs without the filter is NOT allowed: it stays off until fixed).
- **Threads:** the API calls run on their own thread(s), not on the async runtime's worker
  threads. The buffer push is what crosses over.
- **Shutdown:** subscriptions closed, last bookmarks written.

## Wiring (`src/lib.rs`)

Loop 3 ("Windows Event Log Collector") starts the new reader instead of `EventCollector`
(`events.rs` stays in the crate for its other parts; remove only what becomes unused).
Non-Windows builds: the module compiles and does nothing.

## Tests

- XML cleanup (CR, LF, TABs after newline and after `:`; other TABs kept).
- Payload: key order `Message` then `Event`; `Message` absent when none; JSON-escaping of quotes
  and backslashes; size limit (Message shortened; XML-too-long dropped).
- Provider name taken from `Provider Name='…'` (single quotes, as Windows renders it).
- Bookmark file name for `Microsoft-Windows-Sysmon/Operational`.
- Windows-only, `#[ignore]`: write an event with `eventcreate /T INFORMATION /ID 999 /L
  APPLICATION /SO ProVigilTest /D "provigil wevt test"`, read the Application channel with a
  bookmark, find the event with its message, restart the reader and check the event is not sent
  again.

Then `cargo test -p provigil-agent`, `cargo clippy -p provigil-agent --all-targets --no-deps`
clean, `cargo build -p provigil-agent`.
