# siem-core: shared alert, event and agent types

Written 2026-11-03 for ProVigil's own replacement of this crate. Describes what the crate
must provide. Contains no code. The new code is written from this description only; the
old crate's files are not opened.

## Purpose

The data shapes every other crate shares: events coming in, alerts going out, agents, rules
and console statistics. They are stored in ClickHouse and read by the console, so **the JSON
form of each type must stay exactly as written below** (same field names, same nesting,
same optional fields). Nothing else is in this crate: no file reading, no parsing.

Dependencies allowed: `serde` (derive), `serde_json`, `chrono` (with serde), `uuid` (v4,
serde). Every type derives `Debug`, `Clone`, `Serialize`, `Deserialize`.

## Types

### `EventSource` (enum)
Where an event came from. JSON: a lower-case snake_case string for each plain variant:
`"syslog"`, `"windows_event"`, `"fim"`, `"registry"`, `"syscollector"`, `"sca"`, `"auth"`,
`"network"`, `"active_response"`. One variant carries a name, `Custom(String)`, whose JSON is
`{"custom": "<name>"}`. Variants in Rust: `Syslog`, `WindowsEvent`, `Fim`, `Registry`,
`Syscollector`, `Sca`, `Auth`, `Network`, `ActiveResponse`, `Custom(String)`. Also
`PartialEq`, `Eq`.

### `RawEvent` (struct)
One received event.

| Field | Type | JSON | Notes |
|---|---|---|---|
| `id` | UUID | string | |
| `timestamp` | UTC date-time | RFC 3339 string | |
| `agent_id` | text | string | |
| `source` | `EventSource` | see above | |
| `location` | text | string | e.g. a log file path or channel name |
| `message` | text | string | the original log line |
| `metadata` | map text → text | object | may be missing in JSON: then empty |

`RawEvent::new(agent_id, source, location, message)` makes one with a new random id, the
current time and empty metadata. The text arguments accept anything that converts into a
`String`.

### `DecodedFields` (struct, also `Default`)
Fields taken out of a log line. `decoder_name`: text (required). Optional (JSON `null` when
absent): `src_ip`, `dst_ip` (text), `src_port`, `dst_port` (16-bit unsigned), `user`,
`program_name` (text), `process_id` (32-bit unsigned), `file_path`, `action`, `status`
(text). `extra`: map text → text (required in JSON, may be empty).

### `MitreAttack` (struct)
`id` (e.g. `T1110`), `tactic` (e.g. `Credential Access`), `technique` (e.g. `Brute Force`),
all text, all required.

### `Rule` (struct)
A detection rule: `id` (32-bit unsigned), `level` (8-bit unsigned), `description`,
`regex_pattern` (text), `groups` (list of text), `mitre` (optional `MitreAttack`).

### `RuleAlertInfo` (struct)
The rule part of an alert: `id` (32-bit unsigned), `level` (8-bit unsigned), `description`,
`groups` (list of text), `mitre` (optional `MitreAttack`).

### `AgentAlertInfo` (struct)
`id`, `name`, `ip`: all text, required.

### `ManagerAlertInfo` and `DecoderAlertInfo` (structs, also `Default`)
Each has one text field, `name`.

### `Alert` (struct)

| Field | Type | JSON |
|---|---|---|
| `id` | UUID | string |
| `timestamp` | UTC date-time | RFC 3339 string |
| `rule` | `RuleAlertInfo` | object |
| `agent` | `AgentAlertInfo` | object |
| `manager` | optional `ManagerAlertInfo` | may be missing: then none |
| `decoder` | optional `DecoderAlertInfo` | may be missing: then none |
| `full_log` | text | string |
| `decoded` | `DecodedFields` | object |
| `location` | text | string |
| `data` | map text → any JSON value | may be missing: then empty |

### `AgentStatus` (enum, also `PartialEq`, `Eq`)
`Active`, `Disconnected`, `Pending`; JSON `"active"`, `"disconnected"`, `"pending"`.

### `Agent` (struct)
`id`, `name`, `ip`, `os`, `version` (text), `status` (`AgentStatus`), `last_keepalive`
(UTC date-time), `os_type` (text: `linux`, `windows` or `macos`). All required.

### `SiemStats` (struct, also `Default`)
Console totals: `total_events`, `total_alerts`, `critical_alerts` (levels 12 and up),
`high_alerts` (8–11), `medium_alerts` (4–7), `low_alerts` (1–3), all 64-bit unsigned;
`active_agents`, `total_agents` (`usize`).

## Tests the new crate must have

- An alert written as JSON and read back is equal field by field, and its JSON has exactly
  the field names above (check `rule.level`, `agent.ip`, `decoded.src_ip`, `data`).
- An alert JSON without `manager`, `decoder` and `data` is read with none / empty.
- `EventSource` JSON: `"windows_event"` for `WindowsEvent`, `{"custom":"x"}` for
  `Custom("x")`, and both read back.
- `AgentStatus` JSON is lower case.
- `RawEvent::new` fills id, time and empty metadata; a `RawEvent` JSON without `metadata`
  reads with an empty map.

## Also

- The crate's description in `Cargo.toml`: "ProVigil shared types: alerts, events, agents,
  rules and console statistics". No other dependencies than the four above.
