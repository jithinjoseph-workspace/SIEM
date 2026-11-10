# provigil-agent: rootcheck (`src/rootcheck.rs`, extended)

Written 2026-11-03 from a study of how the old Windows agent does rootcheck. Describes what the new
code must do. Contains no code. Written from this description only; no old agent code is opened.
The signature lists are ProVigil's own (the old agent's text lists are upstream data and are NOT
used or copied).

## Checks (Windows), one scan every `rootcheck_interval_secs` and on a `scan` command

1. **Known rootkit / malware files**: a list of paths (environment variables such as `%WINDIR%`
   expanded; `*` prefix = file name searched under `%SystemDrive%\` up to depth 6) with a name and a
   reference link. Present → finding
   `Rootkit '<name>' detected by the presence of file '<path>'.`
2. **Trojaned system programs**: a list of (program path, regular expression on the file's bytes
   read as text, name). Match → `Trojaned version of file '<path>' detected. Signature used: '<regex>' (<name>).`
3. **Windows policy checks** (three lists, each entry: a name, a reference, and conditions):
   - "Windows Malware:" (processes or files or registry entries that indicate malware),
   - "Application Found:" (applications that indicate risk, e.g. remote-access or P2P tools),
   - "Windows Audit:" (registry settings that should or should not be set).
   Conditions of an entry, all must hold (any-of when the entry says `any`): `f:<path>` file exists
   (optionally `-> <regex>` on its content), `r:<key>` registry key exists (optionally
   `-> <value name>` exists, `-> <value name> -> <regex>` value data matches), `p:<process name>`
   process running (case-insensitive, `r:` prefix for regex). A `!` before a condition negates it.
   Match → `<list title> <entry name>.<detail> Reference: <reference> .` (no Reference part when none).
4. **NTFS alternate data streams**: in `%WINDIR%`, `%WINDIR%\System32` and the Program Files folders
   (not recursive beyond depth 4), any file or folder with a named data stream other than the
   standard ones (`Zone.Identifier`, `SmartScreen`, `encryptable`, `WofCompressedData`) →
   `NTFS Alternate data stream found: '<path>:<stream>'. Possible hidden content.`
   (found with the stream enumeration API).
5. Existing checks stay: masquerading system binaries, drivers folder.

Before and after each scan: `Starting rootcheck scan.` and `Ending rootcheck scan.`

## Lists

Our own signature lists, compiled into the agent (a `rootcheck_signatures` module), at least:
- rootkit/malware files: 30+ entries of well-known Windows malware and hacktool artefacts
  (e.g. Mimikatz, PsExec service binaries left by attackers, known RAT installers, cryptominers),
  each with a public reference URL (vendor or MITRE ATT&CK page);
- trojaned programs: 10+ entries for `%WINDIR%\System32` tools (e.g. `cmd.exe`, `net.exe`,
  `svchost.exe`) with byte patterns of known tampering (written by us from public descriptions);
- policy checks: 20+ malware, 15+ application, 20+ audit entries (e.g. Guest enabled, LM hash
  storage, WDigest UseLogonCredential = 1, SMBv1 enabled, RDP without NLA, autorun enabled,
  Defender real-time protection disabled by policy, known RAT processes, TeamViewer / AnyDesk /
  ngrok present).
- Config can add more from files: `rootcheck_files_list`, `rootcheck_trojans_list`,
  `rootcheck_policies` (paths to text files in the same simple formats, documented in the module).

## What the agent sends

Each finding (and the start/end lines): `{"event_type":"rootcheck","timestamp","agent":{..},"location":"rootcheck","message":<the exact text above>}`.
The existing `rootcheck_alert` event (with title, severity, evidence, path) is still sent too, for
the console; the `rootcheck` event is what the manager's rules read.

## Tests

- Each check type against temp files / a test registry key under `HKCU\Software\ProVigilTest` /
  this test process name; negation; any-of; message texts exact.
- ADS: create `file.txt:hidden` in a temp folder (scan root overridable in tests) → one finding;
  `Zone.Identifier` ignored.
- Lists parse; every built-in entry has a name and a reference.

Then `cargo test -p provigil-agent`, clippy clean on the files changed (`--no-deps`), build.
