# provigil-agent: log files and command output (`src/logfiles.rs`)

Written 2026-11-03 from a study of how the old agent collects log files and command output.
Describes what the new code must do. Contains no code. Written from this description only; no old
agent code is opened.

## Why

The manager's rules match log lines from files (IIS, application logs, firewall logs, …) and
the output of periodic commands (e.g. `netstat`, `tasklist`, local admin lists). The agent sends
each line (or each command output) and the manager's analysis engine decodes and matches it the
same way as for the old agent.

## What the agent sends (exact)

- A log file line: one buffer event
  `{"event_type":"logfile","timestamp":<now>,"agent":{"id","name"},"location":<the file's full path>,"message":<the line>}`.
- Command output (`command`): one event per output line, `"event_type":"command"`, `"location"`:
  the alias (or the command text when no alias), `"message"`: `ossec: output: '<alias or command>': <line>`.
- Full command output (`full_command`): one event for the whole output, `"event_type":"command"`,
  same location, `"message"`: `ossec: output: '<alias or command>':` + `\n` + the output, with every
  CR removed, two consecutive newlines collapsed into one, and a final newline removed.
- Labels (see Labels) are not added to these; the manager adds agent labels itself.

## Configuration (`provigil-agent.json`, new field `localfiles`: list; serde default: none)

Each entry:
- `location`: a file path, which may contain wildcards `*` and `?` in the file and folder names
  (e.g. `C:\inetpub\logs\LogFiles\W3SVC*\*.log`), or for commands nothing.
- `log_format`: `syslog` (default; also accepted as names meaning the same plain-line reading:
  `iis`, `apache`, `squid`, `snort-fast`, `nmapg`, `mysql_log`, `postgresql_log`, `mssql_log`,
  `djb-multilog`, `audit`), `json`, `multi-line:<n>`, `multi-line-regex`, `command`, `full_command`.
- `command`, `alias`, `frequency` (seconds between runs, default 360) for the two command formats.
- `only_future_events` (default true): a file seen for the first time is read from its current end.
- `age` (optional, e.g. `1d`, `12h`, `30m`, `90s`): files not modified for longer are skipped.
- `exclude` (optional wildcard pattern): matching files of a wildcard location are skipped.
- `ignore_binaries` (default false): files that look binary are skipped.
- `ignore` / `restrict` (optional lists of regular expressions): lines matching any `ignore`
  expression are dropped; with `restrict`, only lines matching one are kept.
- `multiline_regex` (for `multi-line-regex`): `{ "regex": ..., "match": "start"|"end"|"all", "replace": "no-replace"|"none"|"wspace"|"tab", "timeout": <seconds, default 5> }`.

Default `localfiles` (Windows): the agent's own response log is NOT one of them (it is already
followed by `ar_log.rs`). No default files; the group configuration (later work) and the
installer may add some.

## Reading files

- Positions are kept across restarts in `data\file_positions.json`: per file its path, the read
  offset, the file size, and a hash of the first 1 KiB read (to detect a replaced file). Saved after
  every read pass.
- A file is checked every second (wildcards are expanded again every 60 s, so new files are
  picked up).
- **Rotation / truncation:** when a file got shorter than the saved offset, or its first bytes no
  longer match the saved hash, it is read again from the start.
- **Lines:** split at LF; a trailing CR is removed; empty lines are dropped; on Windows lines
  starting with `#` are dropped (IIS and other W3C headers). Lines containing NUL bytes are
  dropped. A line longer than 65,000 bytes is cut there (the rest of that line is discarded, with
  one warning). A last line without its LF waits until it is complete; when the file has not
  grown for 5 s, that incomplete line is sent as it is.
- **Encoding:** UTF-8 by default; a file starting with a UTF-16 LE or BE byte order mark is read
  as UTF-16 and sent as UTF-8; a UTF-8 BOM is skipped.
- **json:** each line must be one JSON value; invalid JSON lines are dropped (debug log).
- **multi-line:n:** every n lines are joined with a single space into one message.
- **multi-line-regex:** lines are collected into one message: `start` — a new message begins at a
  line matching the regex; `end` — a message ends at a line matching it; `all` — the joined text
  must match it. Lines are joined with LF replaced as `replace` says (`no-replace` keeps LF,
  `none` joins directly, `wspace` with a space, `tab` with a tab). A message still being written
  is sent after `timeout` seconds without new lines.
- **Rate:** at most 10,000 lines per file per pass, the rest on the next pass (one busy file must
  not starve the others).

## Commands

- Run with `cmd /C <command>` on Windows (`sh -c` elsewhere), without a console window, no input,
  capturing standard output (standard error discarded), at most 60 s (then ended, one warning).
- First run 10 s after start, then every `frequency` seconds.
- A command that cannot start: logged once as an error, and not run again until the agent
  restarts.

## Threads

The reading runs off the async worker threads; events go through the agent's buffer.

## Tests

- Line splitting: CR/LF, empty lines, `#` lines on Windows, NUL lines, the 65,000-byte cut, an
  unfinished last line waiting then sent after 5 s.
- Rotation (shorter file, replaced first bytes) and positions surviving a restart.
- Wildcards with `exclude`; `age` filter.
- UTF-16 LE file with BOM.
- json (valid kept, invalid dropped), multi-line:3, multi-line-regex start / end / all and its
  timeout.
- ignore / restrict.
- command and full_command message text (prefix, CR removal, double newline collapse) with a
  test command (`cmd /C echo a&echo b`).

Then `cargo test -p provigil-agent`, clippy clean on the files changed (`--no-deps`), build.
