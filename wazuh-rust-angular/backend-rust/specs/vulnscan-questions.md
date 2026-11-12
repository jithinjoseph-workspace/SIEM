# provigil-vulnscan: open questions and decisions

Questions met while building `crates/provigil-vulnscan` from `specs/vulnerability-scanner.md`
alone. Each entry says what was decided so the owner can confirm or change it.

## Wording (log and error texts only)

1. **Parser-library texts.** The spec (section 20, last paragraph) lists the `[json.exception...]`
   texts as fixed words, but the build order asked for own wording for every parser-library
   detail text. Own wording was used; the numeric id is kept (it appears in
   `json exception [<id>](<text>)`). Mapping:
   - 403 `key '<k>' not found` -> `JSON key '<k>' not found`
   - 302 `type must be <x>, but is <y>` -> `JSON value must be <x>, but is <y>`
   - 303 `incompatible ReferenceType for get_ref, actual type is <t>` -> `JSON value is not a text, actual type is <t>`
   - 101 parse error -> `JSON parse error: <detail>`
   - patch/pointer texts (104-110, 401-410, 501) -> `JSON patch ...` / `JSON pointer ...` /
     `JSON array index ...` with the same meaning (see `src/patch.rs`).
2. **Record schema errors (6.5).** (Unknown-key position corrected by D20.) Reworded: `1: <col>: error: <msg>` -> `line 1, column <col>: <msg>`;
   `expecting: string constant instead of: <t>` -> `expected a text value, found <t>` (likewise
   `an object`, `an array`); `Cannot assign token starting with '<t>' to value of <int> type.` ->
   `cannot store <t> in a int field`; `constant does not fit <f>` -> `value does not fit field <f>`;
   `unknown enum value: <x>, for enum: <e>` -> `unknown name <x> for <e>`. Token names: `null`,
   `true/false`, `decimal number`, `integer number`, `text`, `array`, `object`. Column positions
   are computed exactly as specified.
3. **Old-name literals that only reach logs (L11, L12-*, L13-*)** got own texts, kept in the code
   where used: L11 deprecation warning; L12-a `feed updater`; L12-b `UpdaterRun`; L12-c
   `UpdaterChain`; step names `FeedOffsetsDownloader`, `FeedSnapshotDownloader`,
   `OfflineFileDownloader`, `ZipExtractor`, `GzipExtractor`, `NoOpStep`, `FeedPublisher`,
   `StoreFeedOffset` (L12-d), `StoreOfflineHash` (L12-e), `WorkFolderCleaner` (also the `stage`
   values; the feed processor ignores them); L12-f `Vulnerability scanner start failed`; L12-g
   `Inventory sync subscription failed`; L12-h `Event processing failed`; L12-i `Delayed event
   processing failed`; L12-j `Agent data not ready`; L12-k `Agent re-scan incomplete`; L12-l
   `version value`; L12-m `Unknown inventory column`; L12-o `Invalid integer value`; L12-p
   `Version number out of range`; L13-a..i: `Updater metadata store is not open`, `Stored CVE
   record is unreadable`, `Stored translation record is unreadable`, `OS CPE rules can not be
   found in DB.`, `CNA mapping can not be found in DB.`, `Stored translation cache entry is
   unreadable.`, `Stored candidate list is unreadable`, `Stored remediation record is
   unreadable.`, `Failed to open key-value store. Reason`.

## Outside interfaces (shortcuts, supplied by the host at wiring time)

4. **Router messages.** The binary delta / sync schemas belong to the router library. The
   `Router` trait delivers each message already converted to JSON; the scanner applies the
   topic filters of 7.1. (`src/scanner.rs`, `shortcut:` comment.)
5. **Platform stream. SETTLED by D19:** without an adapter the local mode is used; the text below is history. Frame format and spool are owned by the shared stream library. The
   `StreamSpool` trait sends one `V` message and may return a warning text. When
   `SIEM_STREAM_ADDR`/`SIEM_STREAM_TOKEN` are set but no adapter is given, the start fails with
   `Stream mode is set but no stream adapter was given` (decision: never silently fall back to
   the local database). (`src/sink.rs`)
6. **Windows sockets. RESOLVED by spec section 21.** On Windows the scanner connects by itself:
   provigil-db over TCP to `127.0.0.1:<port in queue/db/wdb.port>` and reports as UDP datagrams
   to `127.0.0.1:<port in queue/sockets/queue.port>` from a socket bound to `127.0.0.1:0`. The
   port file is read on every connection attempt; a missing file or bad text counts as a refused
   connection. Framing, retries, reconnect, error texts and queueing are the same as on Unix.
   A host-supplied `AgentDb` client or `Datagram` endpoint still takes precedence.
   (`SocketAgentDb::local`/`loopback` and `read_port` in `src/agentdb.rs`; `UdpDatagramSender`
   and `local_datagram` in `src/report.rs`.)
7. SETTLED by D19 (a failed send is a warning and the document is still remembered); was: A failed stream send does not remember the document (it is sent again next time).

## Behaviour details the spec leaves open

8. PARTLY SETTLED by D10 (non-finite values are stored as the integer `0`); still open: Stored decimals: the 32-bit value is written in its shortest text as a JSON number, so `10`
   becomes `10.0`, `6.1` stays `6.1`. Unknown whether existing files store `10` or `10.0`
   (only matters for byte-identical values; reading works either way).
9. Candidate lists always carry `versions` (an empty list when the affected entry has none).
10. SETTLED by D8 (release numbers saturate at 64 bits, then 32-bit truncation; other numbers above 64 bits are errors); was: Python versions: numbers are truncated to unsigned 32 bits (the spec says "32-bit with
    wrap-around" without a sign).
11. SETTLED by D9 (the whole rest after the colon is the version); was: RPM versions whose first `-` comes before the first `:` get an empty version part.
12. Version range with both `lessThan` and `lessThanOrEqual`: when `lessThan` applies (not empty,
    not `*`) its comparison alone decides the upper bound.
13. SETTLED by D15 (`<inventory key>_<cve>`, CVEs in sorted order); was: Hotfix-solved log line `CVE '<cve>' was remediated by hotfix '<kb>' for '<id>'.`: `<id>` is the
    package inventory key.
14. `score.base` of `-1` is written as the JSON number `-1.0`.
15. SETTLED by D3 (stripped like the all-agents list); was: Re-scan of one agent: the agent-info `version` is used as is (the leading-character strip of
    the all-agents list is not applied).
16. OS alerts use the raw OS version (`os_version` of the row) as `package.version`.
17. `$schema` is accepted (and ignored) in every table of a record, not only the root.
18. The postponement uses the agent named by the "not ready" result; if it differs from the
    delayed item's agent the item is retried every second.

## Not done (with reason)

19. Spec tests 19.3.21, 19.5.4 and the 19.7 multiset comparison need the old scanner as an
    oracle on the reference data set. A clean-room build cannot use it; the listed specific
    checks of 19.7 are covered by `src/tests.rs` on a crafted feed instead.
20. Unreachable error texts not wired: `Unable to extract data from message. Unknown type`,
    `Error casting ... type`, `Invalid number.` and the L12-n text (the spec marks them
    unreachable; the matching code paths do not exist in this design).
21. Cross-compilation for Linux was not run (only debug builds on this Windows machine were
    allowed); the `cfg(unix)` parts (Unix sockets, `gethostname`) are compiled only there.

## Decisions taken while applying the corrections (specs/vulnscan-fixes.md)

22. D14: the `Processing and publish key:` line of a deletion names the published id
    (`<key>_<cve>` for 12.3/12.5, the agent id for the 12.6 `DELETED_BY_QUERY`).
23. D33: a not-ready hotfix answer gives the per-candidate text `DB query not synced`; other
    hotfix query failures keep `Unable to retrieve remediation data from provigil-db (agent
    <id>). Reason: <text>`.
24. D45: read as "a destination file that cannot be created fails the request with the system
    error text": the offline HTTP download now fails the step (`Download failed: <error>`)
    instead of logging the two download warnings.
25. D46: the insecure-path error shows the destination path `<output>/contents/<entry name>`;
    parent directories are no longer created (only directory entries create directories).
26. D48: version recording without a store fails before its `Updating ...` debug line.
27. D52: an id without `_<part>` has no older versions to replace; an error while reading the
    remembered ids at the end of a re-scan ends that clean-up (no next prefix).
28. D51: the product of a reverse-index value is its text minus the last `len("_<CVE id>")`
    characters; an unreadable stored candidate list is the error `Stored candidate list is
    unreadable` (the list is not rewritten).
29. D31: a non-text delta `operation` is still classified as unknown (the row does not ask for
    a change there).
30. D38 (queue keys must be digits only) is kept as it is; D40 (the lazily connecting
    agent-database client cannot fail at creation) is accepted as structural.

## Interpretations for the changes of spec section 22 (C1–C4)

31. C2 job storage: the job is a new durable queue `queue/vd/rescan` (same on-disk format as
    4.3), one entry per agent (`{"agent":{...},"no-index","full","done","total"}`); an entry is
    removed after its agent was handled, so a restart continues with that agent.
32. C2 per-agent work: each job entry runs the agent's clean-up (one `DELETED_BY_QUERY` for the
    agent) and its scan inside the sink's re-scan mode, instead of one clean-up of all agents
    before the list. Agents that have inventory but are no longer in the agent list are cleaned
    up when the job starts. The delayed queue is emptied when the job starts.
33. C2 priority: the event thread runs one job entry only when the event queue is empty; the
    delayed queue keeps its own thread. An agent of the job that is not ready gets a `scanAgent`
    in the delayed queue (as for an incomplete re-scan).
34. C2 "changed": a resource counts as changed when a create or update stored a record, or a
    translation was deleted; ignored resource kinds and failed resources do not count. A
    snapshot always counts (it rewrites the database).
35. C3 `Solved` alert for a pair no longer found: built like the hotfix alert of 13.3.3 without
    the hotfix (title `<cve> affecting one or many packages was solved`, `package.name` `one or
    many packages`), because the package that held it is gone; descriptions from the `nvd`
    sources. New pairs reuse the alert the real-time chain builds for them.
36. C3 for single-agent re-scans: zero or several agent-info rows still re-scan nothing and alert
    nothing (the remembered set is dropped).
37. C4 clear alert line: logged as `WARNING` `Vulnerability report for agent ID <id>, clean all
    packages alert.` / `... clean all OS alert.` (13.3.5), sent once per clear.
