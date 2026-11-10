# siem-engine: siem-api's in-process detection

Written 2026-11-03 for ProVigil's own replacement of this crate. Describes what the crate
must do. Contains no code. The new code is written from this description only; the old
crate's files are not opened. Every feature here is listed in `FEATURES.md`.

## Purpose

siem-api checks some events itself (syslog devices, older agents, forwarded events): it
decodes the log line, matches it against rules and, when one fires, makes an alert. The
console's rule list and Logtest page use the same engine, and Red Swarm tests the rules it
writes with it.

Dependencies: `siem-core` (event, alert and rule types), `regex`, `serde` / `serde_json`,
`chrono`, `uuid`, `quick-xml` (reading the XML rule format). No binary target.

## Public API (siem-api and siem-redswarm call these)

- `AnalysisEngine`: `Clone` and cheap to clone; every clone shares the rules deployed at run
  time and the correlation memory.
  - `AnalysisEngine::new()`: built-in decoders and detections, plus the XML rules and
    decoders of a ruleset folder when one is found (see "Ruleset folder").
  - `process_event(&self, event: &siem_core::RawEvent, agent_name: &str, agent_ip: &str) -> Option<siem_core::Alert>`
  - `list_rules(&self) -> Vec<siem_core::Rule>`: every active rule: built-in, from the
    folder and deployed at run time.
  - `set_custom_rules_xml(&self, xml: &str)`: replaces the rules deployed at run time (an
    XML text with one or more rules); every clone sees them at once.
- `parse_rules_xml(xml: &str) -> Vec<XmlRule>` and `XmlRule::matches_log(&self, log: &str) -> bool`
  (true when the rule matches that one line with no other context: no parent rule, no
  history). siem-redswarm (`src/synthesizer.rs`, two places) changes to this method.
- `LogtestEngine::new(engine: AnalysisEngine)`, `test_log(&self, line: &str) -> LogtestResult`,
  and `LogtestResult::format_text(&self) -> String`. siem-api (`main.rs`,
  `post_logtest_handler`) changes its call from `format_provigil_output` to `format_text`.

`LogtestResult` is sent to the console as JSON with exactly these fields: `raw_event`
(text), `predecoded_timestamp`, `predecoded_hostname`, `predecoded_program_name` (optional
text), `predecoded_log` (text), `decoder_name` (text), `extracted_fields` (map text → text),
`matched_rule_id` (optional number), `matched_rule_level` (optional number),
`matched_rule_description` (optional text), `matched_rule_groups` (list of text),
`mitre_attack` (optional `{id, tactic, technique}`).

## How an event is checked

1. **Decode.** Built-in decoders are tried in order (below); the first that recognises the
   line fills the decoded fields. Then the XML decoders are tried; the first matching one
   (with its children) adds its fields. When nothing recognises the line, the first IPv4
   address in it becomes the source IP and the decoder name is `generic-syslog`.
2. **XML rules** (folder and run-time), in file order. A rule that matches is remembered for
   this event (its id and groups, for later rules that name it as parent) and recorded in
   the correlation memory. Among matching rules that are not "no alert", the one with the
   highest level makes the alert (on a tie, the later one). If that level is above 0, it is
   the result.
3. **Built-in detections** (below), in order: the first that matches makes the alert.
4. **SSH brute force**: a line containing "failed password" or "invalid user" (any case)
   with a source IP counts one failure for that IP. The 4th failure from the same IP within
   5 minutes makes a level-10 alert: rule 5712, "sshd: Multiple failed login attempts (N
   attempts detected) - Potential Brute-Force Attack", groups `syslog`, `sshd`,
   `authentication_failed`, MITRE T1110 Credential Access / Brute Force; then that IP's
   count starts again. This alert takes priority over steps 2–3 for that line.
5. Otherwise: no alert.

The alert: new id, current time, the rule's id / level / description / groups / MITRE, the
agent's id (from the event), name and IP (arguments), manager name `provigil-manager`,
decoder name, the original line as `full_log`, the decoded fields, the event's location,
and the XML decoder's extra fields in `data`.

For correlation, the event's source IP is the decoded source IP, else a `srcip` field, else
the agent's IP; its user is the decoded user, else a `dstuser` or `srcuser` field.

## Built-in decoders (name: what it recognises → fields)

All case-insensitive.
- `sshd-auth`: "Failed …", "Accepted …" or "Invalid user …" lines with "from <IPv4> port
  <n>", optionally "password for" → user, source IP, source port.
- `syscheck-fim`: `File '<path>' modified|added|deleted|checksum changed` → file path, action.
- `windows-registry`: `Registry '<path>' modified|added|deleted|value changed` → path, action.
- `windows-eventchannel`: `Windows-Event [<channel>] EventID:<n> … User:<user>` → user (channel
  and event id into the extra fields).
- `windows-sca`: `SCA [FAIL|PASS]: <check>` → status (check into the extra fields).
- `sudo-cmd`: `<user> : … COMMAND=<path>` → user, file path.
- `windows-sysmon`: `Process Create: <path> … User: <user>` → file path, user.

## Built-in detections (id, level, what the line contains, groups, MITRE technique)

All case-insensitive. Descriptions are written by the implementer (short, starting with the
source as below). MITRE tactic and technique names are filled in for each id.

| Id | Level | The line contains | Groups | MITRE |
|---|---|---|---|---|
| 5710 | 5 | "Invalid user <name> from <digits>" | syslog, sshd, invalid_login | T1110 |
| 60101 | 6 | event id 4625 ("EventID: 4625" or "EventID=4625") or "An account failed to log on" | windows, security, authentication_failed | T1110 |
| 60102 | 12 | event id 1102 or "The audit log was cleared" | windows, security, log_cleared | T1070.001 |
| 60103 | 10 | event id 7045 or "A service was installed in the system" | windows, system, persistence | T1543.003 |
| 60104 | 13 | `vssadmin … delete shadows`, `certutil … -urlcache`, or `bitsadmin … /transfer` | windows, execution, defense_evasion | T1490 |
| 60200 | 11 | a registry change line whose path contains `CurrentVersion\Run`, `CurrentVersion\RunOnce` or `Winlogon` | windows, registry, persistence | T1547.001 |
| 60300 | 8 | `SCA [FAIL]: <check>` | windows, sca, compliance | T1082 |
| 5503 | 12 | a file change (modified / checksum changed) of `/etc/shadow`, `/etc/passwd`, `/etc/sudoers` or `C:\Windows\System32\drivers\etc\hosts` | syscheck, fim, tampering | T1098 |
| 5501 | 7 | any file change line (`File '…' modified|added|deleted`) | syscheck, fim | T1565 |
| 556 | 3 | "File integrity monitoring scan started" | syscheck, fim, scan_lifecycle | none |
| 557 | 3 | "File integrity monitoring scan ended" | syscheck, fim, scan_lifecycle | none |
| 5541 | 8 | "Permissions changed for" | syscheck, fim, permission_tampering | T1222 |
| 5542 | 8 | "Ownership changed for" | syscheck, fim, ownership_tampering | T1222 |
| 51001 | 13 | "rootcheck: Known trojan/rootkit signature detected" | rootcheck, malware | T1014 |
| 51002 | 11 | "rootcheck: NTFS Alternate Data Stream found" | rootcheck, defense_evasion | T1564.004 |
| 60100 | 14 | `powershell` with `-enc`, `-encodedcommand`, `-nop` or `-w hidden`; or `mimikatz`; or `sekurlsa::logonpasswords` | windows, powershell, execution | T1059.001 |
| 5402 | 9 | `sudo: <user> : … COMMAND=/usr/bin/su`, `/bin/bash` or `/bin/sh` | syslog, sudo, privilege_escalation | T1548 |
| 70010 | 15 | a file name ending `.locked`, `.crypt`, `.encrypted`, `.crypted` or `.wnry` | malware, ransomware, impact | T1486 |

Order matters: 5503 is checked before 5501.

## The XML rule format (reading it)

The same format the manager's rule files use, so rules written for the manager (and by Red
Swarm) work here too.

- Rules sit in `<group name="a,b,">` elements; each name (comma-separated, empties ignored)
  is added to the groups of every rule inside. A file may hold several groups; a text may be
  a bare `<rule>` too.
- `<rule id="N" level="L">`, optional `noalert="1"` (matches but never alerts),
  `frequency="F"`, `timeframe="T"` (seconds).
- Inside a rule, all present conditions must hold:
  - `<if_sid>N</if_sid>`: rule N matched earlier for this same event.
  - `<if_group>g</if_group>`: a rule with group g matched earlier for this event.
  - `<if_matched_sid>N</if_matched_sid>` / `<if_matched_group>g</if_matched_group>` with
    frequency F and timeframe T: counting this event, rule N (or a rule of group g) matched
    at least F times within the last T seconds for the same agent; with `<same_source_ip/>`
    also the same source IP, with `<same_user/>` the same user. The correlation memory keeps
    the last 50,000 matches.
  - `<decoded_as>name</decoded_as>`: the event was decoded by that decoder (or its parent).
  - `<match>text</match>`: the line contains the text, any case; `|` separates
    alternatives (any one is enough).
  - `<regex>pattern</regex>`: the line matches the regular expression.
  - `<field name="x">pattern</field>`: field x (from the decoders; a dotted name like
    `win.eventdata.x` may also be found by its last part `x`) exists and matches the pattern.
  - A rule with none of the conditions above never matches.
- `<description>`, `<group>a,b</group>` (more groups), `<mitre><id>T…</id></mitre>` (the
  first id becomes the alert's MITRE id).
- Patterns that are not valid regular expressions make that rule (or decoder) skipped,
  never a crash. Unknown elements are ignored.

Decoders: `<decoder name="x">` with optional `<parent>p</parent>` (only tried after p
matched), `<program_name>` (pattern on the syslog program name), `<prematch>` (pattern the
line must match), `<regex>` with `<order>a, b, c</order>` (capture groups in order become
those fields; `srcip`, `dstip`, `srcport`, `dstport`, `user` / `srcuser` / `dstuser` also
fill the matching decoded fields). A decoder needs at least a prematch, program name or
regex.

## Ruleset folder

At start the engine looks for a folder with a `rules/` or `decoders/` sub-folder: the path
in `PROVIGIL_RULESET_PATH` (or the older `WAZUH_RULESET_PATH`), else `ruleset`,
`../ruleset`, `../../ruleset` (from the working folder). It loads every `.xml` file in
`decoders/` then `rules/`, in file-name order. None found: built-ins only.

## Logtest

`test_log` trims the line, splits a syslog header when there is one (`Mon DD HH:MM:SS host
program[pid]: message`, or an ISO date-time instead of the first part) into timestamp, host,
program and log; runs the line through `process_event` (agent "000", name `logtest`, IP
`127.0.0.1`); and fills the result: the decoder's name (else the program name, else
`syslog`), the decoded fields that are set (`srcip`, `srcport`, `user`, `action`,
`program_name`, `file_path`, plus extra fields), and the matching rule's id, level,
description, groups and MITRE. `format_text` lays the same out in three titled parts
(pre-decoding, decoding, rule matching), one `name: 'value'` per line, and "No rule
matched." when none did.

## Tests

- each built-in decoder and each built-in detection on a sample line (and 5503 before 5501)
- brute force: 3 failures no alert, the 4th from the same IP within 5 minutes alerts, a
  different IP counts apart, failures older than 5 minutes do not count
- XML: parent rule chain, parent group, `match` alternatives, regex, field condition,
  noalert, highest level wins, level 0 gives no alert, group names added, MITRE id
- frequency / timeframe with same source IP
- decoders with parent, prematch and field order
- run-time rules replace each other and are seen by a clone
- `parse_rules_xml` + `matches_log`; invalid pattern skipped without a crash
- logtest on an sshd line: header split, decoder, rule, text output

Then `cargo test -p siem-engine`, clippy clean, `cargo build -p siem-api -p siem-redswarm`,
`cargo test -p siem-redswarm`, `cargo test -p siem-api --bin siem-api`.
