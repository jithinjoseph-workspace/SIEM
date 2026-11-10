# provigil-agent: complete the inventory (`src/syscollector.rs`)

Written 2026-11-03. Describes what the inventory must collect so it covers everything the old
agent stored (the old agent database's inventory tables are the reference for the fields).
Contains no code. `syscollector.rs` is ProVigil's own code (from the owner's `siem-agent`); it is
extended and corrected, not replaced.

## Must be fixed

- **Fake data:** `collect_listening_ports` returns made-up ports (`0.0.0.0:135`, `0.0.0.0:445`,
  `127.0.0.1:8088`, count 12) when `netstat` fails. Nothing may ever be invented: when a part
  cannot be collected it is empty, and the event says so (`"errors": ["ports: <reason>"]`).
- The 15-port cap and "listening TCP only" go away (see Ports).

## What `inventory_json` must contain (all existing fields stay; new ones added)

Field names below are exact (the manager maps them into its tables). Missing values: JSON `null`.

### hardware (new object `hardware`)
`cpu_name` (`ProcessorNameString` of `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0`),
`cpu_cores` (logical processors), `cpu_mhz` (`~MHz` of the same key), `ram_total_kb`,
`ram_free_kb`, `ram_usage_percent` (memory status API), `board_serial` (the baseboard serial
number; may come from the CIM class `Win32_BaseBoard` once per scan; `null` when the firmware has
none).

### packages (each item; existing fields stay)
Add `location` (`InstallLocation`), `description` (`Comments`), `source` (`"machine"`,
`"machine_x86"` or `"user"`), `user_sid` (for per-user ones). Sources: the machine `Uninstall`
keys (64- and 32-bit views) and every loaded user hive's
`HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Uninstall`. An entry needs a `DisplayName`;
entries with `SystemComponent = 1` or a `ParentKeyName` (updates of another product) are left
out. Same name + version + architecture from two sources: kept once.

### ports (new array `ports`, replaces the text list for the manager)
Every TCP connection and listener and every UDP endpoint, IPv4 and IPv6, from the IP Helper API
tables with owning process: `protocol` (`tcp`, `tcp6`, `udp`, `udp6`), `local_ip`, `local_port`,
`remote_ip`, `remote_port` (`null` for UDP and listeners), `state` (`listening`, `established`,
`time_wait`, … lower case; `null` for UDP), `pid`, `process` (the process name of that PID).
`listening_ports` / `open_ports_count` stay for the existing summary, computed from this list
(no cap).

### processes (each item; existing fields stay)
Add `priority` (base priority), `threads` (thread count), `virtual_kb`, `session_id`.

### network_interfaces (each item; existing fields stay)
Add `type` (`ethernet`, `wireless`, `loopback`, `tunnel`, `other`), `state` (`up` / `down`),
`mtu`, `rx_errors`, `tx_errors`, `rx_dropped`, `tx_dropped`, `gateway` (IPv4 default gateway or
`null`), `dhcp` (`enabled` / `disabled`), `metric`, and `addresses`: array of
`{ "address", "netmask", "broadcast", "family": "ipv4"|"ipv6" }` (netmask from the prefix length;
broadcast for IPv4 only). From the adapter-addresses and interface-entry APIs.

### services (each item; existing fields stay)
Add `path` (the service's executable / image path), `pid` (`null` when stopped), `description`.

### users (new array `users`; `local_users` names stay)
Local accounts: `name`, `full_name`, `sid`, `home`, `disabled` (bool), `last_logon` (RFC 3339 or
`null`), `groups` (names of local groups the user is in).

### groups (new array `groups`)
Local groups: `name`, `sid`, `description`, `members` (account names).

### browser_extensions (new array)
For every user profile on the machine: Chrome and Edge (`…\User Data\<profile>\Extensions\<id>\<version>\manifest.json`:
`name` — when it is a `__MSG_…__` placeholder, the value from `_locales\<default_locale>\messages.json` —
and `version`) and Firefox (`…\Profiles\<profile>\extensions.json`: `addons[].defaultLocale.name`,
`version`, `active`). Item: `browser` (`chrome`, `edge`, `firefox`), `user`, `profile`, `id`,
`name`, `version`, `enabled`.

## Rules

- Windows APIs through `windows-sys` (add the features needed) or the registry; one PowerShell /
  CIM call per scan at most (only where no API is practical, e.g. the board serial). No other
  external programs (the `netstat` call goes).
- A part that fails is empty and listed in `errors`; the rest of the inventory is still sent.
- Runs off the async worker threads (it is blocking work).
- Non-Windows builds compile; parts are empty.

## Tests
- No fake data: with the port collection failing, `ports` is empty and `errors` names it.
- Package de-duplication and the `SystemComponent` / `ParentKeyName` exclusions (from a
  synthetic list of registry entries).
- Netmask from prefix length (24 → 255.255.255.0, 0, 32) and IPv4 broadcast.
- Browser extension name resolution from a temporary `manifest.json` + `messages.json`, and a
  Firefox `extensions.json`.
- Windows-only `#[ignore]`: a real scan returns at least one listening port with a PID and
  process name, the CPU name, at least one user with a SID, and the Administrators group.

Then `cargo test -p provigil-agent`, clippy clean (`--no-deps`), build.
