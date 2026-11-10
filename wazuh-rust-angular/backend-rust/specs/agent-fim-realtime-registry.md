# provigil-agent: real-time file monitoring, who-data, registry monitoring

Written 2026-11-03 from a study of how the old agent does these. Describes what the new code must
do. Contains no code. Written from this description only; no old agent code is opened.

The existing `src/fim.rs` (scheduled scan, SQLite baseline `fim_db.rs`, diffs `diff.rs`) and
`src/registry.rs` are ProVigil's own code and are extended. The event JSON the agent already sends
(`{"type":"fim","syscheck":{path,event,size_*,sha256_*,whodata?,diff?}}`) keeps its fields; new
fields are added as stated.

## 1. Configuration (`provigil-agent.json`)

`fim_paths` stays (list of folders/files). New, all serde-default:
- `fim_realtime: Vec<String>` — folders watched in real time (default: empty).
- `fim_whodata: Vec<String>` — folders watched in real time with who-data (default: empty).
  A folder in both lists is who-data.
- `fim_ignore: Vec<String>` — path prefixes, case-insensitive, never reported.
- `fim_max_files_per_second: u32` — default 50 (0 = no limit) for events from scans.
- `registry_keys` stays (list of keys); entries may be written `HKLM\...` or `HKEY_LOCAL_MACHINE\...`;
  an optional ` [x32]` suffix means the 32-bit view (default: 64-bit view).
- `registry_ignore: Vec<String>` — key prefixes, case-insensitive.
- `registry_recursion_level: u32` — default 512 (depth below a configured key).
- `registry_scan_interval_secs: u64` — default 3600.

## 2. Real-time file monitoring

- Each real-time folder is watched with the Windows directory change notification API
  (`ReadDirectoryChangesW`, subtree, file name / dir name / size / last write / attributes /
  security changes), one overlapped read per folder with a 64 KiB buffer, re-armed after each
  completion.
- A notification is not an event by itself: the changed path is re-checked against the baseline
  (hash, size, mtime, attributes) and an event is sent only if it really changed, was added or
  deleted — with the same JSON and baseline update as the scheduled scan. Events within 1 s for
  the same path are merged.
- Buffer overflow (the API reports it): the folder is fully re-scanned at once.
- A watched folder that disappears: its watch is closed and retried every 60 s; the deleted files
  are reported by the next scan.
- The scheduled scan keeps running for all `fim_paths` and real-time folders (it is the safety net).

## 3. Who-data (who changed a file)

On start, for each who-data folder (needs administrator rights; when not available, log one
error and fall back to plain real-time for those folders):
- Enable auditing of the subcategories "File System" and "Handle Manipulation" (success) with
  `auditpol`, after saving the current audit policy to `data\audit_policy_backup.csv`
  (`auditpol /backup`); on agent stop restore it (`auditpol /restore`).
- Add an audit entry (SACL) for Everyone on the folder (inherited by files and subfolders) for
  write data, append data, write attributes, change permissions (WRITE_DAC) and delete, success.
  Remember which folders got it; remove exactly that entry on agent stop. Enabling the
  `SeSecurityPrivilege` privilege is needed for both.
- Subscribe to the Security channel (same reader as `wevt.rs` or a dedicated subscription) for
  events 4656 (handle requested), 4663 (access attempt), 4658 (handle closed), 4660 (object deleted)
  on file objects under the who-data folders.
- Correlate by process id + handle id: 4656/4663 give the path, user name, user SID, process name,
  process id and access mask; at 4658 (close) or 4660 (delete) the change is considered done and
  the path is re-checked like a real-time notification; the event sent carries
  `"whodata": {"user_name", "user_id" (SID), "process_name", "process_id", "access_mask"}`.
  Correlation entries older than 5 minutes are dropped.
- Every 5 minutes, re-apply the SACL to who-data folders that lost it (e.g. recreated) and log it.
- `whodata.rs`'s test-only cache is replaced by this real source.

## 4. Registry monitoring

- Every `registry_scan_interval_secs` (and once at start), walk each configured key (Win32 registry
  API, 64- or 32-bit view as configured) down to `registry_recursion_level`, skipping
  `registry_ignore`.
- Per key: last write time, owner, permissions (SDDL text). Per value: name, type
  (`REG_SZ`, `REG_EXPAND_SZ`, `REG_BINARY`, `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`, `REG_LINK`,
  `REG_MULTI_SZ`, `REG_RESOURCE_LIST`, `REG_FULL_RESOURCE_DESCRIPTOR`,
  `REG_RESOURCE_REQUIREMENTS_LIST`, `REG_QWORD`, `REG_UNKNOWN`), size, MD5, SHA-1 and SHA-256 of the
  data.
- Baseline in the same SQLite file (`data\fim.db`), a new table for keys and values (path, arch,
  value name, type, size, hashes, mtime, permissions).
- Events: key added / modified / deleted, value added / modified / deleted. JSON:
  `{"type":"registry","timestamp","agent","registry":{"key","arch":"[x64]"|"[x32]","value_name"?,"value_type"?,"event":"added"|"modified"|"deleted","size_after"?,"sha256_after"?,"sha256_before"?,"changed_attributes":[...],"value_data"?:<text for REG_SZ/EXPAND_SZ/DWORD/QWORD/MULTI_SZ, at most 1024 chars>}}`.
  The existing `"value"`, `"old_value"`, `"new_value"` fields of today's autostart events stay
  for compatibility.
- A fresh baseline (empty table) is built quietly, like the file baseline.

## 5. Common

- All of this runs off the async worker threads; events go through the buffer.
- Rate: scan events are paced by `fim_max_files_per_second`; real-time and who-data events are not.

## Tests

- Real-time: write, modify, rename and delete files in a temp folder; each change gives exactly one
  event of the right kind within 3 s; a touch without content change gives none; overflow (many
  files at once) triggers a re-scan and no change is missed.
- Who-data (Windows, `#[ignore]`, needs admin): modify a file in a who-data temp folder; the event
  carries this process's name and the current user; the SACL and audit policy are restored on stop.
- Registry: in `HKCU\Software\ProVigilTest` (created by the test) add a key, add a DWORD and a
  REG_SZ value, change one, delete one, delete the key: one event each, value types and data right;
  recursion level and ignore honoured; baseline survives a restart (no events on the second scan).
- Correlation logic (unit): 4656 + 4663 + 4658 sequence produces one change with the user and
  process; an orphan close is ignored; entries expire.

Then `cargo test -p provigil-agent`, clippy clean on the files changed (`--no-deps`), build.
