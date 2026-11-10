# Rewrite spec: `siem-fileop`

Clean-room description of the file-helper crate: shared-configuration bundles (merged files), directory
helpers, text-mode file I/O for Windows, temporary files, and the operating-system description string.
It says **what**, not how. The writer must not open the old crate (`crates/siem-fileop/`) or `old-code/`.

Vectors in `specs/vectors/siem-fileop/` come from running the old crate; they define correct behaviour.
Platform matters here: `*_windows.json` were made on Windows 11 (not elevated), `*_unix.json` on Linux
(WSL Ubuntu 20.04); `pure.json` is the same on both. Paths in vectors are relative to a scratch folder
shown as `<root>`; temporary-file random suffixes are shown as `XXXXXX`; `<pid5>` is the process id
modulo 100000 as 5 digits.

Libraries: `md-5` (MIT/Apache), `libc` (for `strerror` and, on Unix, `uname`/`regcomp`), `windows-sys`
(MIT/Apache) on Windows, `tracing`, and the workspace's `siem-log` for the daemon logger.

---

## 1. Public interface

### 1.1 Used by other crates

| # | Item | Signature | Used by (files) |
|---|---|---|---|
| P1 | `set_logger` | `fn (log: Arc<siem_log::WLog>)` | siem-agentd `bin/wazuh-agentd.rs`; siem-execd `bin/provigil-execd.rs`; siem-winagent `main.rs` |
| P2 | `default_path_offset` | `fn (file: &str) -> usize` | siem-remoted `manager.rs` |
| P3 | `merge_append_file` | `fn (out: &mut Vec<u8>, file: &str, path_offset: Option<usize>) -> bool` | siem-remoted `manager.rs` |
| P4 | `check_binary_file` | `fn (path: &str) -> bool` | siem-remoted `manager.rs` |
| P5 | `test_unmerge_files` | `fn (path: &str) -> bool` | siem-remoted `shared_download.rs` |
| P6 | `unmerge_files` | `fn (path: &str, optdir: Option<&str>) -> (bool, Vec<String>)` | siem-agentd `receiver.rs` |
| P7 | `unmerge_files_mode` | `fn (path: &str, optdir: Option<&str>, text: bool) -> (bool, Vec<String>)` | siem-execd `wcom.rs`; siem-winagent `upgrade.rs` |
| P8 | `ref_parent_folder` | `fn (path: &str) -> bool` | siem-agentd `receiver.rs`; siem-agentlessd `config.rs`; siem-execd `exec.rs`, `wcom.rs`; siem-modulesd `download.rs`; siem-winagent `upgrade.rs` |
| P9 | `wreaddir` | `fn (dir: &str) -> Option<Vec<String>>` | siem-remoted `manager.rs` |
| P10 | `copy_file` | `fn (src: &str, dst: &str, mode: char, message: Option<&str>) -> io::Result<()>` | siem-remoted `manager.rs` |
| P11 | `rmdir_ex` | `fn (path: &str) -> io::Result<()>` | siem-remoted `manager.rs`; siem-modulesd `database.rs` |
| P12 | `cldir_ex_ignore` | `fn (dir: &str, ignore: &[&str]) -> io::Result<()>` | siem-agentd `receiver.rs`; siem-remoted `manager.rs`; siem-syscheckd `port/run_check.rs`; siem-winagent `upgrade.rs` |
| P13 | `md5_file` | `fn (path: &str) -> Option<String>` | siem-agentd `notify.rs`, `receiver.rs`; siem-agentlessd `lib.rs`; siem-remoted `manager.rs` |
| P14 | `md5_hex` | `fn (data: &[u8]) -> String` | siem-remoted `manager.rs`, `tests/agent_e2e.rs` |
| P15 | `mtime` | `fn (path: &str) -> Option<i64>` | siem-agentlessd; siem-remoted `manager.rs` |
| P16 | `mktemp` | `fn (template: &str) -> Option<String>` | siem-winagent `upgrade.rs` |
| P17 | `wfopen_errno` | `fn (e: &io::Error) -> i32` | siem-winagent `upgrade.rs`, `wm_osquery.rs` |
| P18 | `strerror` | `fn (n: i32) -> String` | siem-winagent `upgrade.rs`, `wm_osquery.rs` |
| P19 | `crt::TEXT_TRANSLATION` | `pub const bool` (true on Windows, false elsewhere) | siem-sca `check.rs` |
| P20 | `crt::text_in` | `fn (raw: &[u8]) -> Vec<u8>` | siem-config `internal_options.rs`; siem-logcollector `win.rs`; siem-sca `check.rs` |
| P21 | `crt::read_text` | `fn (path: impl AsRef<Path>) -> io::Result<Vec<u8>>` | siem-execd `exec.rs`; siem-logcollector `config.rs`, `eventchannel.rs`, `eventlog.rs`, `status.rs`; siem-sca `wm.rs`; siem-syscheckd `port/rootcheck.rs` |
| P22 | `crt::write_text` | `fn (path: impl AsRef<Path>, data: &[u8]) -> io::Result<()>` | siem-logcollector `eventchannel.rs` |
| P23 | `crt::TextFile` | `pub struct TextFile(pub fs::File)`; `fn create(path: impl AsRef<Path>) -> io::Result<TextFile>`; `impl std::io::Write` | siem-agentd `enrollment.rs`, `receiver.rs`, `state.rs`; siem-logcollector `state.rs`, `status.rs` |
| P24 | `crt::is_network_path` | `#[cfg(windows)] fn (path: &str) -> bool` | siem-config `localfile.rs`; siem-execd; siem-logcollector; siem-sca; siem-syscheckd; siem-winagent (many) |
| P25 | `crt::network_path_executed` | `fn (path: &str) -> String` | same callers |
| P26 | `version_op::getuname` | `fn () -> &'static str` | siem-agentd `agentd.rs`, `config.rs`, `notify.rs`; siem-logcollector `collector.rs`, `config.rs`; siem-modulesd `database.rs` |

Module names that must exist: `crt`, `version_op`.

### 1.2 Public today, used by nobody outside the crate (may be dropped; listed on purpose)

| # | Item | Why it can go |
|---|---|---|
| PU1 | `dirname` | no caller; needed inside (P2, P6). Vectors in `pure.json`. |
| PU2 | `mkstemp_ex`, `rename_ex` | no caller; needed inside P6. |
| PU3 | `crt::text_out` | no caller; needed inside P22/P23. |
| PU4 | `version_op::{OSSEC_NAME, OSSEC_VERSION}` | no caller; their values end up in `getuname()` (see 2.8). |
| PU5 | `version_op::{OsInfo, UtsName, Probe, System, w_regexec, get_binary_path, osx_release_name, get_unix_version, getuname_with}` | no caller; they are the parts of `getuname()` on Unix. Keep an injectable source (files, command outputs, uname) so the vectors can be replayed in tests. |
| PU6 | `win_version` module (`Level`, `set_logger`, `get_release_from_build`, `get_win_version`, `getuname`) | no caller; `getuname()` uses it on Windows. Nobody installs its logger, so its messages are never shown today. |
| PU7 | `TextFile.0` field being public | nobody reads it. |

Count: 26 used items, 7 unused groups (about 22 single items).

---

## 2. Behaviour

### 2.1 Logging

Messages go to the logger set by `set_logger` (first call wins, later calls ignored) as error / warn /
debug-level-2; with no logger set they go to `tracing` (error / warn / debug). The exact texts are in
the vectors (`logs` fields); they are listed with each function below.

### 2.2 Paths

- `dirname(path)` (POSIX `dirname` on `/`-separated text; `\` is not a separator): trailing `/`
  removed; no `/` left -> `"."`; only leading slashes -> `"/"`; otherwise the part before the last `/`
  with its trailing slashes removed (`"/"` if that is empty). `"" -> "."`, `"//" -> "/"`, `"a//b" -> "a"`,
  `"a/b/" -> "a"`, `".." -> "."`.
- `default_path_offset(file)` = length of `dirname(file)` plus 1 when that dirname does not end with
  `/` (so `"etc/shared/default/agent.conf"` -> 19, `"/agent.conf"` -> 1, `"agent.conf"` -> 2).
- `ref_parent_folder(path)`: true when the path has a `..` component: it starts with `..` followed by
  end or a separator, or it contains `/..` followed by end or a separator. On Windows `\` also counts as
  a separator after `..`, and `\..` is searched too, **but only where no `/..` follows**: the search
  moves from one `/..` to the next and looks for `\..` only after the last one, so a non-component
  `/..` placed after a `\..` hides it (`a\..\b/..x` is false, `a/..x\..\b` is true). `..a`, `a/..b`, `.../x`,
  `....` are false. Exact cases per platform in `files_*.json`.

### 2.3 Merged bundle format (`merged.mg`)

A merged file is a byte stream of records. Lines starting with `#` are comments (the producer writes
`#<group>\n` first). A record is a header line `!<size> <name>\n` followed by exactly `<size>` bytes of
file content (no separator after the content). `<name>` is the path relative to the bundle root, `/`
separated.

- `merge_append_file(out, file, offset)`: reads the whole file; unreadable -> log ERROR `Unable to open
  file: '<file>' due to [(<errno>)-(<error text>)].` and return false (nothing appended). Empty file ->
  log WARN `File '<file>' is empty.` (still appended). Appends `!<len> <name>\n` + content, where
  `<name>` is `file` from byte `offset` on (`None` -> `default_path_offset(file)`; an offset past the
  end gives an empty name). Returns true.
- `check_binary_file(path)`: unreadable -> log ERROR `Unable to open file '<path>' due to
  [(<errno>)-(<text>)].` and true. Otherwise the file is cut into pieces of at most 65,536 bytes, each
  ending after a `\n` when one comes first; a piece that **ends with `\n`** and contains a NUL before it
  -> log DEBUG `Line contains some zero-bytes.` and true. Pieces without a trailing `\n` (the last line,
  or the first 64 KiB of a longer line) are not checked. Else false.
- `test_unmerge_files(path)`: unreadable -> log ERROR `Unable to read merged file: '<path>'.`, false.
  Reads lines of at most 2,047 bytes (a longer line is read in pieces); a line starting with `#` is
  skipped; a line not starting with `!` -> false; a header with no space -> remember failure and go on;
  empty name -> false; size = the digits right after `!` (none -> 0); if fewer than `size` bytes remain
  -> false; skip `size` bytes. End: true unless a failure was remembered.
- `unmerge_files_mode(path, optdir, text)` (`unmerge_files` = text mode): returns `(ok, names)`.
  - Read the whole merged file (text mode reads through `read_text`, binary mode raw). Failure -> log
    ERROR `Unable to read merged file: '<path>' due to [(<n>)-(<strerror(n)>)].` where `n` =
    `wfopen_errno`, return `(false, [])`.
  - Walk lines as in `test_unmerge_files` (2,047-byte pieces); lines not starting with `!` are skipped.
    Header without a space -> `ok = false`, continue. Size: digits after `!` (none -> 0). Name: text
    after the first space up to the newline (keeps `\r`; invalid UTF-8 replaced).
  - Target = `"<optdir>/<name>"` (or `name` without optdir). If it has a `..` component -> log ERROR
    `Unmerging '<path>': unable to unmerge '<target>' (it contains '..')`, the record is not written and
    unmerging **stops** with `ok = false` (later records ignored).
  - Create the target's parent directories (failure -> log ERROR `Unmerging '<path>': couldn't create
    directory '<name>'` and stop with `ok = false`).
  - Content = the next `size` bytes (fewer if the file ends).
  - Write the content to a new temporary file `<target>` + 6 random letters/digits (see `mkstemp_ex`);
    creation failure -> log ERROR `Unmerging '<path>': could not create temporary file for '<name>'`,
    stop with `ok = false`. Write in text mode (`write_text`) or raw; a write failure -> log ERROR
    `Unable to unmerge file '<tmp>' due to [(<n>)-(<text>)].`, `ok = false`, and still try the rename.
  - Rename the temporary file over the target with `rename_ex`; failure -> delete the temporary file,
    stop with `ok = false`.
  - Add the name relative to `optdir` (`target` without `"<optdir>/"`; the base name if it does not start
    with that; the target itself without optdir) to `names`, even when the write failed.
  - Same name twice: the later content wins, the name is listed twice. An absolute-looking name `/x`
    becomes `<optdir>//x` (written inside optdir) and is listed as `/x`.
  - Windows, not elevated: the temporary file only grants Administrators and SYSTEM, so the write fails
    and unmerging returns false; the Unix vectors show the full behaviour.

### 2.4 Directories

- `wreaddir(dir)`: entry names (lossy UTF-8) without `.`/`..`, sorted by bytes; `None` if the directory
  cannot be read (also for a file).
- `copy_file(src, dst, mode, message)`: read all of `src` (error -> returned, `dst` untouched); `mode`
  `'a'` opens `dst` for append (created if missing), any other char creates/truncates it; writes
  `message` (if any) then the content. Binary, no translation.
- `rmdir_ex(path)`: a directory -> removed with everything in it; a file or link -> removed; missing ->
  Ok; other stat errors returned.
- `cldir_ex_ignore(dir, ignore)`: removes everything inside `dir` except what `ignore` protects; `dir`
  itself stays. For each entry, relative path `rel` (from `dir`, `/`-joined): it is protected when an
  ignore item equals `rel` or starts with `rel + "/"`. A protected **directory** is cleaned the same way
  (recursively) and then removed if it ended up empty; a protected file stays; an unprotected entry is
  removed with `rmdir_ex`. Consequences (vectors): ignoring `sub` deletes `sub` and all of it;
  ignoring `sub/x.txt` keeps only `sub/x.txt`; an empty protected directory is removed; `sub/` and
  partial names (`su`) protect nothing. A missing `dir` -> error.

### 2.5 Files

- `md5_file(path)`: MD5 (lower-case hex) of the file read through `read_text` (so on Windows `\r\n`
  counts as `\n` and a Ctrl-Z ends the data); `None` if unreadable.
- `md5_hex(data)`: MD5 of the bytes, lower-case hex.
- `mtime(path)`: modification time in whole seconds since 1970; `None` if the path cannot be stat'ed
  (directories work); times before 1970 give 0.
- `mktemp(template)`: template must end in `XXXXXX` (else `None`); returns template minus `XXXXXX` +
  the first letter `a`..`z` + the process id modulo 100000 as 5 digits, choosing the first letter for
  which no such path exists; `None` if all 26 exist. Creates nothing.
- `mkstemp_ex(template)` (inside P6): template must end in `XXXXXX`. Creates a new empty file whose name
  replaces `XXXXXX` and returns its name. Unix: 6 random characters from `A-Z a-z 0-9`, mode 0600, up to
  100 tries on name clashes; other errors -> log ERROR `(1128): Could not create temporary file '<name>'
  due to [(<errno>)-(<strerror>)].` and `None`. Windows: name from `mktemp`; a template without
  `XXXXXX` -> log ERROR `Could not create temporary file (<template>) which returned 22
  [(22)-(Invalid argument)].`; the file is created new with an access list granting full control only
  to BUILTIN\Administrators and SYSTEM (no inheritance); failures log `Could not set ACL entries which
  returned (<code>)` or `Could not create temporary file (<name>) which returned (<code>)`.
- `rename_ex(src, dst)` (inside P6): Unix: rename; failure -> log ERROR `(1124): Could not rename file
  '<src>' to '<dst>' due to [(<errno>)-(<strerror>)].`, false. Windows: when `dst` does not exist it is
  first created empty (failure -> log DEBUG `Could not create file (<dst>) which returned (<code>)`,
  false); then the destination is replaced by the source keeping the destination's security
  (`ReplaceFile`); failure -> log DEBUG `Could not move (<src>) to (<dst>) which returned (<code>)`,
  delete the destination if it was just created, false.
- `strerror(n)`: the C library's message for `n` (platform text: Windows `No error` / `Unknown error`,
  Linux `Success` / `Unknown error <n>`; vectors list 0-44 and 9999 per platform).
- `wfopen_errno(e)`: Windows: the raw OS error code (0 if none). Unix: `NotFound` -> ENOENT,
  `PermissionDenied` -> EACCES, `AlreadyExists` -> EEXIST, otherwise the raw code (0 if none).

### 2.6 Windows text mode (`crt`)

The agent's "r" and "w" streams behave like the Microsoft C runtime's text mode on Windows; on other
platforms nothing is translated (`TEXT_TRANSLATION = false`).
- `text_in(raw)`: data ends at the first Ctrl-Z (0x1A); each `\r\n` becomes `\n`; a lone `\r` stays.
  (Pure function, the same on every platform.)
- `text_out(data)`: every `\n` becomes `\r\n` (an existing `\r\n` becomes `\r\r\n`).
- `read_text(path)`: whole file, through `text_in` on Windows; raw elsewhere.
- `write_text(path, data)`: create/truncate and write, through `text_out` on Windows.
- `TextFile::create(path)` + `Write`: each write goes through `text_out` on Windows (reports the
  untranslated length as written); raw elsewhere. `flush` flushes the file.
- `is_network_path(path)` (Windows only): true for paths starting with two backslashes (`\\server\...`,
  `\\?\...`); for `X:` paths true when the drive letter maps to a network redirector (`\Device\Mup\`,
  `\Device\LanmanRedirector\`, `\DosDevices\UNC\`), false for other `\Device\` targets, and when the
  drive is unknown true if the user registry has `Network\<letter>`. Everything else false (`//server`
  is false). Results for drive letters depend on the machine.
- `network_path_executed(path)` = `(9800): File access denied. Network path usage is not allowed:
  '<path>'.`

### 2.7 `getuname()` - operating-system description (computed once per process)

**Unix form**: `"<sysname> |<nodename> |<release> |<version> |<machine> [<os_name>|<os_platform>:
<os_version>] - <product> <product version>"`, any missing field printed as `(null)`; if the OS
detection gives nothing but `uname` works: `"<sysname> <nodename> <release> <version> <machine> -
<product> <version>"`; if `uname` fails too: `"No system info available - <product> <version>"`. Cut to
511 bytes (on a character boundary). Product name / version today are the constants in `pure.json`
(`constants`); the owner decides whether they stay (they are upstream names).

OS detection on Unix (`get_unix_version`), in order:
1. `/etc/os-release`, else `/usr/lib/os-release`: read in pieces of at most 254 bytes per line; for each
   line, the text before the first `=` is the key:
   - `NAME` (first one only) -> os name; `VERSION` (first only, and it replaces a value taken from
     `VERSION_ID`) -> os version; `VERSION_ID` (only if no `VERSION` and no earlier `VERSION_ID`) -> os
     version; `ID` (first only) -> platform, value ends at a space or newline. Values: up to the
     newline; a leading `"` is dropped and the value ends at the next `"` (if any).
   - A key with nothing after `=` (e.g. `NAME=` + newline) makes the old code **panic** (vectors record
     `panic`); the new code may treat it as missing - flag the difference.
   - Platform `centos`: version replaced by the first `<digits>[.<digits>]` found in
     `/etc/centos-release` (when that file exists). Platform `opensuse-tumbleweed` or `arch`: version "".
2. If name, platform, or (version and build) is still missing, all are cleared and the first existing
   file decides: `/etc/centos-release` (CentOS Linux / centos), `/etc/fedora-release` (Fedora /
   fedora, version = ` <digits> `), `/etc/redhat-release` (per line: contains `CentOS` -> CentOS Linux /
   centos; `Fedora` -> Fedora / fedora; else `Red Hat Enterprise Linux Server` (line contains `Server`)
   or `Red Hat Enterprise Linux`, platform rhel; stop at the first line with a number), `/etc/arch-release`
   (Arch Linux / arch, version or ""), `/etc/gentoo-release` (Gentoo / gentoo), `/etc/SuSE-release`
   (SuSE Linux / suse, number after `VERSION = `), `/etc/lsb-release` (Ubuntu / ubuntu, value of
   `DISTRIB_RELEASE`; a `DISTRIB_RELEASE` without value panics), `/etc/debian_version` (Debian GNU/Linux /
   debian), `/etc/slackware-version` (Slackware / slackware), `/etc/alpine-release` (Alpine Linux /
   alpine, `x.y.z`). Version patterns are POSIX extended regexes: `([0-9][0-9]*\.?[0-9]*)\.*` (first line
   that matches) unless stated.
3. None of those files: run the `uname` command (found through `PATH`, else plain `uname`) and use its
   first line: `Darwin` (platform darwin; name from `system_profiler SPSoftwareDataType` line `System
   Version:` first word after it; version `sw_vers -productVersion`; build `sw_vers -buildVersion`;
   codename from `uname -r` major number: 10 Snow Leopard ... 24 Sequoia, else `Unknown`), `SunOS`
   (name/platform SunOS/sunos, version = word after `Solaris` on the first line of `/etc/release`; no
   file, no line, or no `Solaris` -> detection fails, see "uname form"), `HP-UX` (from `uname -r`
   `B.<x.y>`), `OpenBSD`/`NetBSD`/`FreeBSD` (BSD/bsd, number from `uname -r`), `ZscalerOS` (BSD/bsd,
   `<digits>-<non-space>` from `uname -r`), `AIX` (AIX/aix, `oslevel` output minus its last character),
   `Linux` (Linux/linux). Unknown output, no output, or the command failing -> fields stay empty.
4. `uname()` system call fills sysname, nodename, release, version, machine; if it fails detection
   returns nothing.
5. Version post-processing: missing version -> `"0.0"`. Non-empty version: text after ` (` (minus the
   last character) is the codename; major/minor/patch from `^([0-9]+)`, `^[0-9]+\.([0-9]+)`,
   `^[0-9]+\.[0-9]+\.([0-9]+)`; platform darwin with a codename -> version becomes `"<version>
   (<codename>)"` (so `14.1 (Sonoma)` from os-release becomes `14.1 (Sonoma) (Sonoma)`).
   On Windows this Unix path finds no regex matches (the regex helper returns nothing there); it is not
   used on Windows.

**Windows form**: `"<os_name> [Ver: <os_version>] |<nodename> |<machine> - <product> <version>"`
(missing name -> `Microsoft Windows`, others -> `unknown`); if version detection fails entirely
`"Microsoft Windows - <product> <version>"`; cut to 1,023 bytes. Detection (`get_win_version`):
- `GetVersionEx` major.minor (6.2 for an unmanifested process on Windows 8+) is `version`.
- Major 6: name = `Microsoft ` + registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName`
  (read as 64-bit view; failure -> `Microsoft Windows undefined version`); if `CurrentMajorVersionNumber`
  exists: major, minor (`CurrentMinorVersionNumber`), build = `CurrentBuildNumber` (read into a 30-byte
  buffer) + `.<UBR>` when UBR exists, cut to 63 chars; release = `ReleaseId`, else from the build table
  `10240->1507, 10586->1511, 14393->1607, 15063->1709, 17134->1803, 17763->1809, 18362->1903,
  18363->1909` (others none; keep `15063->1709` as is). Else (6.2/6.3): major/minor from `CurrentVersion`
  split at the first `.`, build from `CurrentBuildNumber`. os_version = `major.minor.build` (`(null)` for
  missing parts), cut to 63. Name containing `Windows 10` with build >= 22000 -> `Windows 11`.
- Other majors: fixed names (5.0 Windows 2000, 5.1 XP, 5.2 XP Professional x64 / Server 2003 R2 /
  Server 2003, 4.x NT/95/98/ME by platform id and minor, other 5.x none, anything else `Microsoft
  Windows`), version `major.minor.build`.
- Release still unknown: `SYSTEM\CurrentControlSet\Control\Windows\CSDVersion` 256..1536 -> `sp1`..`sp6`.
- Machine from `PROCESSOR_ARCHITECTURE` in `System\CurrentControlSet\Control\Session Manager\Environment`:
  starts with AMD64/IA64/ARM64 -> `x86_64`, x86 -> `i686`, else `unknown`.
- Node name from `...\ComputerName\ActiveComputerName\ComputerName` read into 30 bytes (names of 30+
  bytes fail -> `unknown`).
- Its log messages (`(1758): Unable to open registry key: '<key>'.`, `Error reading '<value>' from Windows
  registry. (Error <n>)`, etc.) go to a logger nobody installs, so they are never shown today.

Vectors: `version_unix.json` (55 fake-system scenarios with the probe call order, `get_binary_path`,
POSIX regex samples, live `getuname`), `version_windows.json` (same scenarios run on Windows, release
table, live `get_win_version`).

---

## 3. Feature table

| # | Feature | Vectors |
|---|---|---|
| H1 | Logger hook with tracing fallback | files_* (`logs`) |
| H2 | `dirname`, `default_path_offset` | pure |
| H3 | `ref_parent_folder` incl. Windows `\` rules and hiding quirk | files_unix, files_windows |
| H4 | Merged record format `!<size> <name>\n<content>` | files_* |
| H5 | `merge_append_file` offsets, empty-file warning, unreadable error | files_* |
| H6 | `check_binary_file` 64 KiB pieces, only newline-ended pieces checked | files_* |
| H7 | `test_unmerge_files` structure rules | files_* |
| H8 | `unmerge_files_mode`: `..` refusal stops, dirs created, temp + rename, names list, text/binary | files_unix |
| H9 | `wreaddir` sorted by bytes | files_* |
| H10 | `copy_file` append vs truncate, message first | files_* |
| H11 | `rmdir_ex` file/tree/missing | files_* |
| H12 | `cldir_ex_ignore` protection rules | files_* |
| H13 | `md5_file` through text mode, `md5_hex` | files_*, pure |
| H14 | `mtime` | files_* |
| H15 | `mktemp` letter + pid naming | files_* |
| H16 | `mkstemp_ex` (0600 / admin-only ACL) | files_* |
| H17 | `rename_ex` (rename / ReplaceFile) | files_* |
| H18 | `strerror`, `wfopen_errno` per platform | files_* |
| H19 | `text_in` / `text_out` | pure |
| H20 | `read_text` / `write_text` / `TextFile` per platform | files_* |
| H21 | `is_network_path` (Windows) | files_windows |
| H22 | `network_path_executed` text | pure |
| H23 | Unix OS detection order and parsing (os-release, release files, uname command) | version_unix |
| H24 | Version split into major/minor/patch/codename, darwin quirk, `0.0` default | version_unix |
| H25 | Unix `getuname` three output forms, 511-byte cut | version_unix |
| H26 | Windows detection (registry, build table, Windows 11 rename, service pack, machine, node name) | version_windows |
| H27 | Windows `getuname` form, 1,023-byte cut, computed once | version_windows |
| H28 | OSX release names 10..24 | pure |

## 4. Vector files

| File | Cases |
|---|---|
| pure.json | 93 |
| files_unix.json | 153 |
| files_windows.json | 161 |
| version_unix.json | 66 |
| version_windows.json | 74 |
| **total** | **547** |
