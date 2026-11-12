# provigil-vulnscan: line-by-line review against the old scanner

Reviewer pass of `crates/provigil-vulnscan` (new, clean-room) against
`crates/siem-vulnerability-scanner` (old, reference behaviour), 2026-11-12. Every old file was
walked top to bottom (`lib.rs`, `cache.rs`, `config.rs`, `queue.rs`, `kvdb.rs`, `fbs.rs`,
`json_patch.rs`, `feed.rs`, `content_updater.rs`, `version_matcher.rs`, `scanner.rs`,
`scan/context.rs`, `scan/scanners.rs`, `scan/details.rs`, `scan/inventory.rs`, `scan/util.rs`,
`scan/sinks.rs`, `scan/orchestrator.rs`, `scan/wdb.rs`) plus the host part in
`siem-modulesd/src/bin/provigil-modulesd.rs`. No product code was changed.

Differential program (throwaway, outside `crates/`): `scratch/vulnscan-compare/` (own workspace,
both crates by path, shared target dir). Run: `target/debug/vulnscan-compare.exe [versions|cpe|patch|schema|targeted|feed]`.

## Summary

| | Count |
|---|---|
| Checklist items OK | 99 |
| Checklist items DIFFERENT | 57 |
| Checklist items MISSING | 0 |
| Defects (table below) | 52 (high 5, medium 18, low 29) |
| Accepted rewordings checked (meaning and level kept) | 14 groups |
| Questions settled | 21 (match 9, accepted rewording 3, mismatch 5, partial 2, n/a or not checked 2) |
| Load-bearing literals L1-L10, L17, `rocksdb` dir | all exactly equal |

## Defects

Severity: high = scan results / outputs / on-disk format differ or a feature is lost; medium =
log or error behaviour or an edge case that changes what is processed; low = cosmetic or
practically unreachable. "Fix" is the behaviour the spec should state (own words, for the
clean-room writer).

| Id | Sev | Old location | New location | Old does | New does | Fix (spec text) |
|---|---|---|---|---|---|---|
| D1 | high | version_matcher.rs, Python order | version.rs `cmp_py` | When only one of two Python versions has a dev part, the one **without** dev is the smaller (`1.0` < `1.0.dev1`). | The one without dev is greater (`1.0` > `1.0.dev1`). Spec 10.3 says "greater"; the old code does the opposite. 66-79 mismatching pairs per Python/unspecified/apk kind, e.g. `1` vs `1.0.dev1`: old Less, new Greater. | 10.3: "then dev: when exactly one has a dev part, the one **without** it is the **smaller**; both: compare numbers." Keep the pre-release rule before it (so `1.0.dev1` vs `1.0a1` is still Greater). |
| D2 | high | version_matcher.rs, Python pattern | version.rs `parse_py` | The release `N(.N)*` is required whenever anything follows the optional `v`; only the empty text and `v` alone match with an empty release. `dev`, `a1`, `rc1`, `post1`, `-1`, `.dev1` are **not** Python versions (the try-all strategy goes on to the next type; the Python kind does not parse them). | Release is optional on its own, so `dev`, `a1`, `post1`, `-1` etc. parse as Python. ~1,100 mismatching pairs per Python/unspecified/apk kind (e.g. Python `""` vs `dev`: old error, new Greater; unspecified `post1` vs `-1`: old Greater (both RPM), new Equal). | 10.3: "Pattern: optional `v`, then either nothing at all (empty release) or: optional `<epoch>!`, a **required** release `N(.N)*`, then the optional pre/post/dev parts. A text with a pre/post/dev part but no release is not a Python version." |
| D3 | high | scan/orchestrator.rs `build_single_agent_list` | scan.rs `rescan_one` | The agent-info `version` gets the same leading-character strip as the all-agents list (characters of «L8» removed from the start), e.g. `<L6> v4.14.7` -> `v4.14.7`. | Used as is (question 15). `agent.version` in documents of single-agent re-scans differs from the old ones and from all-agents re-scans. | 9.12 re-scan one: "the `version` read from agent-info (missing or not a text = empty) is stripped of leading «L8» characters exactly like the all-agents list." |
| D4 | high | json_patch.rs `add` | patch.rs `add`/`parent_create` | `add` requires the parent of the target to exist; a missing intermediate member gives `key '<k>' not found` (403), an array index beyond the end 401, walking into a scalar 404. Nothing is created except the last member. (Also via `move`/`copy`.) | Creates missing intermediate objects and pads arrays with nulls (42 of 20,000 random patches: old error, new success, e.g. `{"op":"add","path":"/c/q/r","value":1}` on a doc without `/c/q`). A feed update the old scanner rejects (feed run fails, offsets fall back to a snapshot) is accepted. | 6.6 add: "the parent (path without its last token) is resolved with the normal walking rules and must exist (missing key 403, index beyond the end 401, scalar 404); only then: parent null -> becomes an object holding the key; object -> set key; array -> `-` appends, index <= length inserts, larger 401." |
| D5 | high | json_patch.rs `add`/`remove` | patch.rs | When the parent of the target is a scalar (text, number, boolean) — or null for `remove` — `add` and `remove` do nothing and succeed. | Error `JSON pointer token '<t>' cannot be resolved` (262 of 20,000 random patches, e.g. `{"op":"remove","path":"/n/k"}` with `/n` null; `{"op":"add","path":"/f/g",...}` with `/f` = 3). The resource fails instead of being applied. | 6.6: "add: parent is a text/number/boolean -> nothing changes, no error. remove: parent is anything other than an object or array (including null) -> nothing changes, no error." |
| D6 | medium | feed.rs `candidates` | feed.rs `store_candidates` | Product names are lower-cased with full Unicode rules (`ÄPFEL` -> `äpfel`) for candidate keys and the reverse index. | ASCII-only lower-casing (`ÄPFEL` -> `Äpfel`); the feed differential shows different keys in `nvd` and `cve_package_nvd`. The scan then matches packages the old one did not (package names are ASCII-lowered in both). | 6.7.4: "products are lower-cased with full Unicode lower-casing (not ASCII-only) when grouping and in the keys." |
| D7 | medium | scan/scanners.rs `match_versions` | scan.rs `match_versions` | The installed version is parsed **once before** looking at the ranges; a parse **error** (RPM epoch not a number, number above 64 bits) ends this candidate with `Failed to scan package/OS ... Error: '<text>'` and no match — also no default-status match. | Parses only when a comparison is needed; with no comparison needed (empty ranges, or only `0` / `*` bounds) the default-status rule can still match. | 9.5.1: "First parse the installed version with the kind; a parse error ends this candidate with that error (logged as the per-candidate failure line), before any range or default status is looked at. A version that simply does not parse is not an error here." |
| D8 | medium | version_matcher.rs Python numbers | version.rs `parse_py` | Release numbers are read digit by digit with 32-bit wrap-around and never fail (`1.18446744073709551616` is valid). Epoch/pre/post/dev numbers above 64 bits fail. | Every release number above 64 bits fails with «L12-p» (e.g. `1.0` vs `1.18446744073709551616`: old Less, new error). | 10.3: "release numbers: each read as unsigned 32-bit with wrap-around, no size limit and no error; epoch, pre, post and dev numbers: above 64 bits is a parse error, else truncated to 32 bits." |
| D9 | medium | version_matcher.rs `rpm` | version.rs `parse_rpm` | When the first `-` comes before the first `:`, the version part is everything after the colon to the end (`1-2:3.0`: epoch 1, version `3.0`, release `2:3.0`). | Version part empty (question 11). `1-2:3.0` vs `1:1.0`: old Greater, new Less. | 10.7: "version = text after the colon (or from the start) up to the first `-`; if that `-` lies before the colon, the version is the whole rest after the colon." |
| D10 | medium | fbs.rs decimal fields | schema.rs `norm_float` | A decimal given as text `inf`, `nan`, `Infinity` or a value that overflows 32 bits (`3.4028236e38`) is accepted and stored as the **integer** `0`; a numeric overflow (`1e300`) is also stored as integer `0`. | Text forms are rejected (`invalid number`, the whole record fails); numeric overflow stored as `0.0`. | 6.5.1 decimal field: "a value that is not finite after conversion to 32 bits (infinite, NaN, overflow), from a number or a text, is stored as the integer 0 (written `0`); the texts `inf`, `nan`, `infinity` (any case) are accepted as such values." |
| D11 | medium | feed.rs `get_vulnerability_remediation`; scan/scanners.rs `os_scanner`, `package_hotfix_solved` | feed.rs `remediation`; scan.rs `os_scan`, `remediated` | Remediation lookup on a feed without the `remediations` column is an error (`Couldn't find column family: 'remediations'`): the Windows OS scan stops its remediation filtering at the first CVE with `WARNING Failed to scan OS ...` and keeps the CVEs not yet filtered; the package hotfix check logs the per-candidate `Failed to scan package` DEBUG line (the CVE stays found, the list continues). | Missing column = no remediation: every Windows OS CVE is discarded as "No remediation available"; package check returns "not solved" silently. | 6.10: "remediation lookup: a missing `remediations` column is an error (`Couldn't find column family: 'remediations'`), handled by the callers as any lookup error (9.6, 9.8)." |
| D12 | medium | scan/wdb.rs `query` | agentdb.rs `SocketAgentDb::query` | A **connect** failure ends the query at once with the transport error text (e.g. the OS "file not found" / "connection refused" text); only an exchange failure on an open connection is retried once and gives `Connection with provigil-db lost.` | Connect failures are retried and always end as `Connection with provigil-db lost.` These texts reach `Unable to retrieve ... Reason: <text>` lines. | 8.1: "connecting is attempted once per query attempt; a connect failure ends the query immediately with the system error text; an exchange error drops the connection and retries once; two exchange errors give `Connection with provigil-db lost.`" |
| D13 | medium | scan/wdb.rs `parse_packets` | agentdb.rs `interpret` | `ok` with nothing after it and no earlier `due` parts is a JSON parse error (`Error parsing JSON response: . Exception id: 101. ...`). Codes are matched as prefixes (`ok`, `err`, `ign`, `unk`, `due`) and the body is everything after the 3rd character (+1 for the space): `okay` is an `ok` with a bad body. | Bare `ok` = empty result; code is the text before the first space (`okay` -> invalid response). | 8.2: "`ok` with empty body and no `due` parts: error `Error parsing JSON response: <body>. Exception id: 101. <detail>`. The answer kind is decided by the text **starting with** `due`/`ok`/`err`/`ign`/`unk`; the body is what follows the code and one character." |
| D14 | medium | scan/inventory.rs `scan_inventory_sync`, `clean_inventory`, `clean_agent_inventory` | inventory.rs `publish_deletion` | The deletions these steps publish go through the element publisher, so each one writes `DEBUG2 Processing and publish key: <key>` (key = CVE for old OS keys, the document id for clean-up all, `DeleteByQuery request` for one agent) and the "Invalid element" check. | Published straight to the sink: those DEBUG2 lines are missing. | 12.3/12.5/12.6: "the deletions are published through the element publisher of 13.5.2 (one `Processing and publish key: <key>` line each, with the keys named here)." |
| D15 | medium | scan/inventory.rs `cve_solved_inventory_sync` | inventory.rs `inventory_hotfix_solved` | Log `CVE '<cve>' was remediated by hotfix '<kb>' for '<key>_<cve>'.` (the document id); lines grouped per CVE in sorted CVE order. | `... for '<key>'.` in stored-list order (question 13). | 12.4: "log `DEBUG2` `CVE '<cve>' was remediated by hotfix '<kb>' for '<inventory key>_<cve>'.`, CVEs taken in sorted order, one line per removed occurrence." |
| D16 | medium | scanner.rs `rsync_wanted` | scanner.rs `subscribe` | `state` messages with a missing/null `attributes_type` are dropped silently; only `integrity_clear` / `integrity_check_global` log the «L12-g» error. | Also logs the error for `state` messages. | 7.1: "the `attributes_type is null` error is logged only for `integrity_clear` and `integrity_check_global`; a `state` message without it is dropped silently." |
| D17 | medium | content_updater.rs `Orchestrator::new`/`run` | updater.rs `content_update` | The regular step chain is built once, at creation; its CU debug lines (chain-building start, `Creating '<x>' downloader/decompressor/version updater`, `Content cleaner created`) appear at creation and again only when a full download builds its own chain. | Rebuilds the chain at every scheduled run: those lines repeat every run. | 5.3/5.5: "the regular chain is built once when the updater is created and reused by every run; only the full-download chain is built per run." |
| D18 | medium | provigil-modulesd host (gethostname) | host.rs `hostname` | Host name from the system host-name call on every platform (on Windows the network host name, case kept, up to 255 bytes). | On Windows uses the `COMPUTERNAME` environment variable (upper-case, 15 chars). Changes cluster name in documents, agent `000`'s name and the stored `cluster_previous_name` (a change triggers a full re-scan on first start). | 2.1 step 3: "host name = the system host-name call (`gethostname`) on all platforms, at most 255 bytes; `undefined` when it fails." |
| D19 | medium | scanner.rs (Indexer::open via stream env) | scanner.rs `start_inner`, sink.rs | With `SIEM_STREAM_ADDR`/`SIEM_STREAM_TOKEN` set, a stream that cannot be opened falls back to the local document database (no failure). A spool-full drop is only a warning and the document is still remembered as sent. | Start fails when no stream adapter is given (question 5); an adapter error leaves the document unremembered (question 7). | 13.5.1/13.5.2: "if the stream cannot be opened, use the local mode; a send never fails the publish: a dropped line yields a warning and the hash is still remembered." (Or the owner confirms questions 5 and 7 as intended changes.) |
| D20 | medium | fbs.rs `parse_json` / `token_end` | schema.rs `norm_table` | Error column for an **unknown field** is the position after the first token of its value (for an object/array value: after its opening bracket), like every other error. `{"x":{"a":1}}` -> column 6. | After the **whole** value (spec 6.5.1 says so): `{"zz":{"a":1}}` old 7, new 13 (102 of 12,000 random records). | 6.5.1: "for an unknown key the position is after the first token of that key's value (the opening bracket for an object or array, else the whole scalar)." |
| D21 | medium | scan/details.rs `event_details` | output.rs `document_details` | The element id gets `_<offset>` appended right after the description merge, **before** the scanner-source lookup; if that lookup then fails (no `adp_descriptions` entry for the detection source / no `adp` field) the element is published with the offset-suffixed id and no data. A missing `adp` field is an error (403). | Id changed only when the whole document succeeds; a missing `adp` field writes `scanner.source: null` without error. | 13.1: "after the description merge append `_<offset>` to the element id; then build the document; `adp_descriptions[<source>].adp` must exist (403 otherwise). On any error after the merge the id keeps the suffix." |
| D22 | medium | scan/scanners.rs `PackageScanner::handle`, `os_scanner` | scan.rs `vendor_list`, `os_scan` | `adp_default_array` present but not an array: packages scan with no CNA at all, silently; elements that are not texts are a 302 error only when reached (earlier CNAs already scanned). OS: non-text elements become `""`. | Not an array -> 302-style error for the event; all elements checked before any scan. | 9.3: "a present `adp_default_array` that is not a list is treated as an empty list (no scan, no error); its elements are checked one by one as they are used (a non-text element is error 302 at that point)." |
| D23 | medium | scan/scanners.rs `os_scanner` | scan.rs `os_scan` | The `Using CNA '<c>' from CNA array for OS.` line is written just before scanning each CNA (interleaved with that CNA's scan lines). | All lines written first, then the scans. | 9.8: "log the CNA line immediately before scanning with that CNA." |
| D24 | low | version_matcher.rs Calendar | version.rs `parse_cal` | Year kept in 16 bits, micro truncated to 32 bits (`2023.1.1.4294967296` equals `2023.1.1.0`). | 64-bit micro (Greater). | 10.2: "micro is truncated to 32 bits after parsing; values above 64 bits are a parse error." |
| D25 | low | version_matcher.rs MajorMinor/SemVer | version.rs `parse_mm`, `parse_sem` | Numbers truncated to 32 bits after parsing (`4294967296.0` equals `0.0`). Semantic numbers above 64 bits are a parse error. | Kept as 64-bit; Semantic numbers above 64 bits make the text "not this type". | 10.4/10.5: "numbers are truncated to 32 bits; above 64 bits: parse error (both kinds)." |
| D26 | low | version_matcher.rs `dpkg` | version.rs `parse_deb` | Whitespace set includes vertical tab (`1.0\v` parses); the epoch may carry a `+` sign (`+1:1.0` = epoch 1). | VT not whitespace; `+` epoch rejected. 18-220 mismatching pairs per Debian-based kind. | 10.6: "whitespace = space, tab, LF, VT, FF, CR; the epoch is read like a C long (optional leading `+`)." |
| D27 | low | version_matcher.rs `compare` | version.rs `compare` | Parses A; if A does not parse (or fails) the comparison ends there (B is not parsed, no B debug lines, B's parse error never reported). | Always parses both; B's parse error can replace the "Unable to compare" text (~500 pairs per try-all kind). | 10.1: "parse A first; if it fails or does not parse, stop with that error / `Unable to compare versions`; only then parse B." |
| D28 | low | scan/scanners.rs `match_versions` | scan.rs `match_versions` | Installed version parsed once per candidate (one set of `Error creating ...` DEBUG2 lines). | Re-parsed for every comparison, repeating those lines. | 10.9/9.5.1: "the installed version is parsed once per candidate." |
| D29 | low | scan/util.rs `parse_cpe` | cpe.rs `Cpe::parse` | For the empty text the field count underflows to the maximum, so an empty OS CPE "matches" any candidate CPE whose compared fields are `*` or empty (`""` vs `cpe:/o:a`: true). | Field count 0 -> no match (14 of 930 CPE cases). | 11: "for an empty text the field count is 'unbounded' (comparison uses the other side's count)." |
| D30 | low | scan/context.rs `build_cpe_name` | event.rs `build_cpe` | A matching OS-CPE rule whose template is empty or not a text gives an empty CPE name. | Gives `cpe:/o:`. | 9.1: "an empty template result leaves the CPE name empty." |
| D31 | low | scan/context.rs (delta/sync accessors) | event.rs `Ctx::field`, scan.rs | Fields of delta/sync rows that are not texts read as empty (no error); a hotfix insert only adds the hotfix to the cache when the field is a text; delta `operation` that is not a text = "Operation not found in delta." | `opt_text` raises 302 for non-text fields (package fields, OS fields of events, hotfix id); missing hotfix adds `""` to the cache; non-text `operation` classified as unknown. | 7.2/9.x: "for delta and sync messages, non-text fields read as empty; only JSON-action data fields raise 303 when not texts; the hotfix cache only gets a text hotfix id." |
| D32 | low | scan/scanners.rs `get_cna` | scan.rs `expand_cna` | CNA-mapping values must be texts (302/303 errors); the mapping objects are read with "at" semantics (304 for non-objects). | Non-texts read as empty / fall back silently. | 9.3: "mapped name, platform and major-version equivalences must be texts (error 302/303)." |
| D33 | low | scan/scanners.rs `platform_verify`, `package_hotfix_solved` | scan.rs `platform_ok`, `remediated` | A platform that is a CPE is never compared with the code name; non-text platforms count as `""`. Agent hotfix rows without `hotfix` are skipped; a not-ready answer becomes the per-candidate DEBUG failure with text `DB query not synced`. | CPE platforms also compared with code name; non-texts skipped; rows without `hotfix` add `""`; failure text `Unable to retrieve remediation data ... Reason: ...`. | 9.5/9.6 as described in "Old does". |
| D34 | low | scan/orchestrator.rs `build_all_agent_list`, `scan_agent_*` | scan.rs `rescan_all`, `scan_list` | Agent `id` read with integer conversion that accepts decimals and booleans; read order id, name, version, ip. Invalid agent id in a re-scan: ERROR "Unable to retrieve OS/packages agent data ..." and the agent continues. Package `size` not a number: 302 error for that agent. | Integers only; order name, ip, version; invalid id aborts the agent ("Error handling request"); bad `size` = 0. | 9.12 as described. |
| D35 | low | scan/inventory.rs `scan_inventory_sync` | inventory.rs `inventory_os_sync` | Stored empty list (`""`) counts as "was empty": no delete line. | Deletes and logs. | 12.3: "an existing but empty stored value counts as no list." |
| D36 | low | scan/util.rs `raw_timestamp_to_iso8601` | output.rs `install_time` | The ISO forms are checked by character class only (digits / `-` `T` `:` `.` `Z` at fixed places), so `2024-13-45T99:99:99Z` is accepted. | Real date parsing rejects impossible dates. | 13.1.1: "20/24-character forms checked by character class only." |
| D37 | low | kvdb.rs | kvstore.rs | Write errors are `Error putting data: <reason>` for put **and delete**; read errors `Error getting data: <reason>` for get, prefix scan and last; batch begin/commit errors are returned. | Delete/scan/last errors without prefix; batch errors ignored. | 4.2: as in "Old does". |
| D38 | low | queue.rs `open` | queue.rs `open` | Keys parsed as unsigned integers (a leading `+` accepted). | Digits only. | 4.3: negligible; may stay. |
| D39 | low | provigil-modulesd host | host.rs, config.rs `internal_options` | An invalid «L17» value stops the whole daemon (critical, exit 1). | Logs an error and does not start the scanner. | 2.1/3.2: "invalid «L17»: the host logs CRITICAL and exits." |
| D40 | low | wdb socket creation | host.rs | Creating the client can fail -> `vulnerability_scanner: failed to initialize wdb socket: <e>`. | Lazy client, cannot fail; line unreachable. | Accept (structural) or keep the line for creation failures. |
| D41 | low | scanner.rs `facade_start` | scanner.rs `start_inner` | Content updater is created before the inventory store and delayed queue are opened (spec 2.5 steps 12 -> 14). | Opens inventory/delayed first. | 2.5: keep the stated order. |
| D42 | low | scanner.rs `parse_str_to_time` | config.rs `parse_time` | Leading whitespace of any kind; `-0m` = 0; numbers that do not fit 64 bits -> -1. | Only spaces; `-` invalid; saturates huge values. | 3.3 as in "Old does". |
| D43 | low | content_updater.rs (paths) | updater.rs | Output folder and every path in messages and CU log lines are absolute (`<home>/queue/vd_updater/tmp/...`). | Relative (`queue/vd_updater/tmp/...`) in log lines, published `paths`, hashing error text, clean-up lines. | 5.3-5.14: "paths are `<home>/<outputFolder>/...` in messages and log lines." |
| D44 | low | content_updater.rs `snapshot_download`, `offline_download` | updater.rs `last_segment` | File name = text after the last `/` (query string included); offline uses the path's file name (trailing `/` ignored). | Strips `?`/`#` parts; trailing `/` -> "Couldn't get filename". | 5.8/5.9 as in "Old does". |
| D45 | low | content_updater.rs `get` | updater.rs `get`/`fetch` | A local file-create/write error during a download is treated like a transport error: `Error 0 from server: <e> - Response body: ` (no retry). | Returned as the plain error text. | 5.10. |
| D46 | low | content_updater.rs `zip_decompress` | updater.rs `decompress` | Insecure path text shows the full output path (`<contents dir>/<entry name>`); directories created with a single-level create; files in missing sub-folders fail. | Shows the raw entry name; creates parents. | 5.11. |
| D47 | low | content_updater.rs offsets | updater.rs `offsets_download` | Missing `contentFileName` -> empty name (`<to>-`). | Defaults to `api_file.json` (unreachable with the built parameters). | 5.7. |
| D48 | low | content_updater.rs `UpdateCtiApiOffset` | updater.rs `store_offset` | `Updating offset with value` logged only when the store is open. | Always logged. | 5.13. |
| D49 | low | fbs.rs integers / enumerations | schema.rs `norm_int`, `norm_enum` | Integer field from text: any parse failure (incl. out of 32-bit range, backslash) -> `invalid number: "<text>"`. Enumeration from text: parsed as 8-bit, failure -> `invalid number`; a number beyond 64-bit signed -> type-mismatch token `integer constant`/`<byte>`; float text uses the text after trailing-space trimming. | `value does not fit field <f>` / `cannot store text in a int field` / trimmed vs untrimmed text (127 of 12,000 records). | 6.5.1 as in "Old does". |
| D50 | low | feed.rs `store_vulnerability_hotfixes` | feed.rs `store_hotfix_index` | Creates the `hotfixes_applications` column whenever `x_remediations.windows` is a list, even with no keys. | Only when there are keys. | 6.7.1. |
| D51 | low | feed.rs `candidates` | feed.rs `store_candidates` | Stale-product detection removes the first `_<cve>` occurrence from the stored value; an unreadable stored list is an error. | Strips a trailing `_<cve>` only; unreadable list rewritten. | 6.7.4. |
| D52 | low | scan/sinks.rs `publish_stream`, `rescan` | sink.rs | Ids without `_`: no "replaced" search; first error at the end of a re-scan stops processing the remaining prefixes. | Uses the id itself as base; continues with the next prefix. | 13.5.2/13.5.3. |

## Questions settled (specs/vulnscan-questions.md)

| # | Old behaviour | New behaviour | Match |
|---|---|---|---|
| 1 | Parser-library texts with ids (`[json.exception.<kind>.<id>] ...`) | Own wording, ids kept | accepted rewording |
| 2 | `1: <col>: error: <msg>` with fixed token names | `line 1, column <col>: <msg>` | accepted rewording, but columns differ for unknown fields with object/array values (D20) and several message kinds differ (D49) |
| 3 | Old-name literals in logs | Own texts, same level | accepted (checked levels: all equal) |
| 4 | Router messages converted to JSON inside the scanner; filters 7.1 | Host adapter delivers JSON; same filters | partial: `state` + null `attributes_type` now logs (D16) |
| 5 | Stream env set but stream not openable -> local mode | Start fails without adapter | no (D19) |
| 6 | Windows: TCP/UDP loopback with `<path>.port`, read per attempt (shared ipc library) | Same | yes |
| 7 | Spool drop = warning, document still remembered | Adapter error -> not remembered | partial (D19) |
| 8 | Decimals stored as `10.0` (32-bit shortest text read as a double) | `10.0` | yes (feed and schema differentials: identical stored text) |
| 9 | `versions` always written (empty list allowed) | same | yes |
| 10 | Release numbers wrap at 32 bits without limit; other numbers: >64 bits error, then truncated to 32 bits | All >64 bits error | no (D8) |
| 11 | Version = rest after the colon | empty | no (D9) |
| 12 | Non-empty, non-`*` `lessThan` decides alone; recorded condition is `lessThanOrEqual` when present | same | yes |
| 13 | `<id>` = `<inventory key>_<cve>` | `<inventory key>` | no (D15) |
| 14 | `-1.0` | `-1.0` | yes |
| 15 | agent-info version is stripped like the list | used as is | no (D3) |
| 16 | OS alerts use raw `os_version` | same | yes |
| 17 | `$schema` accepted in every table | same | yes |
| 18 | Postpones the agent named by the error; item stays queued | same | yes |
| 19 | (tests needing the oracle) | this review ran the differential checks | n/a |
| 20 | Those texts are unreachable in the old code too | not wired | yes |
| 21 | (Linux build not run) | - | not checked |

## Checklist (specs/FEATURES.md, provigil-vulnscan section)

| # | Status | Note |
|---|---|---|
| 1 | OK | |
| 2 | DIFFERENT | D40 |
| 3 | OK | |
| 4 | OK | |
| 5 | OK | |
| 6 | DIFFERENT | D41 |
| 7 | OK | |
| 8 | OK | L12-f reworded |
| 9 | OK | |
| 10 | OK | L11 reworded |
| 11 | OK | |
| 12 | OK | |
| 13 | DIFFERENT | D39 |
| 14 | DIFFERENT | D42 |
| 15 | OK | |
| 16 | OK | |
| 17 | OK | |
| 18 | OK | |
| 19 | OK | |
| 20 | OK | |
| 21 | OK | |
| 22 | OK | |
| 23 | OK | |
| 24 | DIFFERENT | D37 |
| 25 | OK | |
| 26 | OK | |
| 27 | OK | |
| 28 | OK | |
| 29 | OK | |
| 30 | OK | |
| 31 | OK | |
| 32 | OK | |
| 33 | OK | |
| 34 | OK | |
| 35 | DIFFERENT | D43 |
| 36 | DIFFERENT | D17 |
| 37 | OK | stage names reworded (accepted) |
| 38 | OK | |
| 39 | OK | |
| 40 | OK | |
| 41 | OK | |
| 42 | DIFFERENT | D43, D47 |
| 43 | DIFFERENT | D44 |
| 44 | DIFFERENT | D43, D44 |
| 45 | OK | |
| 46 | OK | sequence 1,1,2,4,8,16,30 identical |
| 47 | DIFFERENT | D45 |
| 48 | DIFFERENT | D46 |
| 49 | OK | |
| 50 | OK | |
| 51 | DIFFERENT | D43 |
| 52 | OK | |
| 53 | OK | |
| 54 | OK | |
| 55 | OK | |
| 56 | OK | |
| 57 | OK | |
| 58 | OK | |
| 59 | OK | |
| 60 | OK | |
| 61 | OK | |
| 62 | DIFFERENT | D10, D20, D49 |
| 63 | OK | text form identical in 7,800 successful random records |
| 64 | DIFFERENT | D4, D5 |
| 65 | DIFFERENT | D50 |
| 66 | OK | |
| 67 | OK | |
| 68 | DIFFERENT | D6, D51 |
| 69 | OK | |
| 70 | OK | |
| 71 | OK | |
| 72 | OK | |
| 73 | DIFFERENT | D11 |
| 74 | OK | |
| 75 | DIFFERENT | D16 |
| 76 | DIFFERENT | D16 |
| 77 | OK | |
| 78 | DIFFERENT | D31 |
| 79 | OK | |
| 80 | OK | |
| 81 | OK | |
| 82 | OK | |
| 83 | OK | |
| 84 | OK | |
| 85 | OK | |
| 86 | DIFFERENT | D14 |
| 87 | OK | |
| 88 | OK | |
| 89 | DIFFERENT | D12 |
| 90 | DIFFERENT | D13 |
| 91 | OK | |
| 92 | DIFFERENT | D30 |
| 93 | OK | |
| 94 | DIFFERENT | D32 |
| 95 | DIFFERENT | D22 |
| 96 | OK | |
| 97 | OK | |
| 98 | DIFFERENT | D29, D33 |
| 99 | OK | |
| 100 | DIFFERENT | D7 |
| 101 | OK | |
| 102 | OK | |
| 103 | DIFFERENT | D11, D33 |
| 104 | OK | |
| 105 | OK | |
| 106 | DIFFERENT | D11 |
| 107 | OK | |
| 108 | OK | |
| 109 | OK | |
| 110 | OK | |
| 111 | DIFFERENT | D34 |
| 112 | DIFFERENT | D3 |
| 113 | DIFFERENT | D34 |
| 114 | OK | |
| 115 | OK | |
| 116 | DIFFERENT | D27 |
| 117 | DIFFERENT | D24 |
| 118 | DIFFERENT | D1, D2, D8 |
| 119 | DIFFERENT | D25 |
| 120 | DIFFERENT | D25 |
| 121 | DIFFERENT | D26 |
| 122 | DIFFERENT | D9 |
| 123 | OK | all worked examples hold in both |
| 124 | DIFFERENT | D28 |
| 125 | DIFFERENT | D29 |
| 126 | OK | |
| 127 | OK | |
| 128 | DIFFERENT | D35, D14 |
| 129 | DIFFERENT | D15 |
| 130 | DIFFERENT | D14 |
| 131 | DIFFERENT | D14 |
| 132 | OK | |
| 133 | OK | |
| 134 | DIFFERENT | D21 |
| 135 | DIFFERENT | D21 |
| 136 | OK | |
| 137 | DIFFERENT | D36 |
| 138 | OK | |
| 139 | OK | |
| 140 | OK | |
| 141 | OK | |
| 142 | OK | |
| 143 | OK | |
| 144 | OK | |
| 145 | OK | |
| 146 | DIFFERENT | D19 |
| 147 | OK | |
| 148 | OK | |
| 149 | DIFFERENT | D19, D52 |
| 150 | DIFFERENT | D52 |
| 151 | DIFFERENT | D14-D17, D23, D28 |
| 152 | DIFFERENT | D12, D13, D37, D45, D46, D49 |
| 153 | OK | |
| 154 | DIFFERENT | D3, D18 |
| 155 | OK | L1-L10, L17, `rocksdb` exactly equal |
| 156 | DIFFERENT | differential checks now run; mismatches listed below |

## Accepted rewordings (meaning and level checked, not defects)

| Group | Old text (kind) | New text | Level same |
|---|---|---|---|
| L11 | deprecated-section warning naming the old docs site | own text | yes (WARNING, host) |
| L12-a/b/c | updater creation / run-context / chain-factory debug names | `Creating '<topic>' feed updater`, `UpdaterRun`, `UpdaterChain` | yes |
| L12 steps / L12-d/e | step names and version-step error prefixes; first five also `stage` values | `FeedOffsetsDownloader` ... `WorkFolderCleaner`, `StoreFeedOffset - ...`, `StoreOfflineHash - ...` | yes (stage values only read by the feed processor, which ignores them) |
| L12-f/g/h/i | facade/orchestrator class prefixes | `Vulnerability scanner start failed`, `Inventory sync subscription failed`, `Event processing failed`, `Delayed event processing failed` | yes (ERROR) |
| L12-j/k | exception names in DEBUG2 lines | `Agent data not ready`, `Agent re-scan incomplete` | yes |
| L12-l | version object name in parser lines | `version value` | yes (DEBUG2) |
| L12-m | map lookup failure | `Unknown inventory column` | yes |
| L12-o/p | integer-conversion function names | `Invalid integer value`, `Version number out of range` | yes |
| L13-a..i | storage-library texts | own texts | yes |
| JSON 403/302/303/304 | `[json.exception.*] key '<k>' not found`, `type must be <x>, but is <y>`, `incompatible ReferenceType ...` | `JSON key '<k>' not found`, `JSON value must be ...`, `JSON value is not a text ...` | yes |
| JSON 101 | parse error with library detail | `JSON parse error: <detail>` | yes |
| JSON patch/pointer | 104-110, 401-410, 501 texts | `JSON patch ...`, `JSON pointer ...`, `JSON array index ...` | yes (except behaviour D4/D5) |
| Record schema | `1: <col>: error: ...` with token names | `line 1, column <col>: ...` (own token names) | yes (except D20/D49) |
| Log tags | `provigil-modulesd:vulnerability-scanner`, `provigil-modulesd:content-updater`, `indexer-connector` | identical | yes |

## Differential test results

All runs with the program in `scratch/vulnscan-compare/` (debug build, both crates linked).

| Area | Cases | Mismatches | Notes |
|---|---|---|---|
| Version comparison, 13 kinds/strategies | 329,173 pairs (138 curated edge texts all-pairs + 6,000 random pairs per kind) | 11,399 | Calendar 157, Python 2,678, MajorMinor 465, Semantic 68, Debian 421, RPM 4, unspecified 2,755, Windows 424, macOS 420, pacman 422, snap 427, pkg 421, apk 2,737. Causes: D1, D2, D8, D9, D24-D27. Error texts compared after mapping the integer-conversion names to their accepted rewordings. |
| CPE parse + compare | 930 | 14 | all involve the empty text (D29). |
| JSON patch (random 1-3 ops on a fixed doc) | 20,000 | 307 | 45 old error / new success (D4), 262 old success / new error (D5); 0 cases with both successful but different documents; error-vs-error not compared (rewording accepted). |
| Record schema normalising (CVE + translation, random mutations) | 12,000 | 229 | 0 value differences, 0 text-form differences, 0 stored-text differences; 102 column differences (D20), 127 message differences (D49). Targeted decimals: `inf`/`nan`/`Infinity`/`3.4028236e38` old stores `0`, new rejects; `1e300` old `0`, new `0.0` (D10). |
| Feed records (21 resources: maps, CVE create/update/reject, translations, errors) | 21 resources, 24 stored rows | 4 rows | All results (ok/err) agree; all rows identical (descriptions, scores `10.0`, candidates, reverse index, hotfix index, remediations, translations, maps) except the non-ASCII product keys (D6). Error texts for invalid patches differ by D4/D5 cause. |

Examples (exact inputs):
- Python `1` vs `1.0.dev1`: old Less, new Greater (D1).
- Python `""` vs `dev`: old `Unable to compare versions ( vs dev).`, new Greater (D2).
- Python `1.0` vs `1.18446744073709551616`: old Less, new `Version number out of range` (D8).
- RPM `1-2:3.0` vs `1:1.0`: old Greater, new Less (D9).
- Calendar `2023.1.1.4294967296` vs `2023.1.1.0`: old Equal, new Greater (D24).
- MajorMinor `4294967296.0` vs `0.0`: old Equal, new Greater; Semantic `1.0.4294967296` vs `1.0.0`: old Equal, new Greater (D25).
- Debian `1:1.0` vs `+1:1.0`: old Equal, new error; `1.0` vs `1.0\v`: old Equal, new error (D26).
- CPE `""` vs `cpe:/o:a`: old match, new no match (D29).
- Patch `[{"op":"add","path":"/c/q/r","value":1}]` (no `/c/q`): old 403 error, new creates `{"q":{"r":1}}` (D4).
- Patch `[{"op":"remove","path":"/n/k"}]` (`/n` null): old no-op success, new error (D5).
- Record `{"zz":{"a":1}}`: old column 7, new column 13 (D20).
- Feed product `ÄPFEL`: old key `äpfel_CVE-2024-0001`, new `Äpfel_CVE-2024-0001` (D6).

## Not checked

- Linux-only paths (Unix sockets, `gethostname` on Unix) were not built or run; Windows only.
- End-to-end scans (agent-database fake, report and document outputs) were reviewed by reading only;
  no differential run of whole events (the old orchestration needs its router and logger setup).
- Whether the old Windows host-name call actually succeeds (it may need socket-library start-up);
  D18 assumes it does.
- Whether provigil-db ever answers a bare `ok` for the scanner's queries (D13 relevance).
- Content updater HTTP behaviour was compared by reading, not by running both against a test server.
