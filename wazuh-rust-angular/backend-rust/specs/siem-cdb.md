# siem-cdb: threat indicator lists

Written 2026-11-03 for ProVigil's own replacement of this crate. Describes what the crate
must do. Contains no code. The new code is written from this description only; the old
crate's files are not opened.

## Purpose

Holds the platform's threat indicator lists in memory and answers "is this value on a
list?" fast. Three lists exist:

| List name | Holds | Filled by |
|---|---|---|
| `malicious_ips` | IPv4 / IPv6 addresses and address ranges (CIDR, e.g. `203.0.113.0/24`) | the botnet C2 feed, hourly (siem-api `main.rs`, `spawn_threat_intel_feed_scheduler`) |
| `malicious_hashes` | file hashes: MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex) | later feeds |
| `malicious_domains` | domain names | the malicious-URL feed, hourly |

Each entry has a value and a short description (where it came from, e.g. "Feodo
Tracker: Emotet C2"). The lists start empty: no indicators are bundled with the program.

## What siem-api calls (keep these names and shapes)

- The manager type is `ThreatIntelManager`, shared between threads behind an `Arc`.
  Every method takes `&self`; readers and writers may run at the same time.
- `ThreatIntelManager::new()`: empty lists. siem-api's two construction sites
  (`main.rs`, `analyst_tests.rs`) change from `new_with_builtin_feeds()` to this.
- `insert_entry(list, value, description)`: adds the value to the named list, or
  replaces its description when it is already there (counted once). An unknown list name
  creates that list. A value that is not valid for its list (e.g. not an IP or range in
  `malicious_ips`, not 32/40/64 hex characters in `malicious_hashes`, not a domain in
  `malicious_domains`) is not added; the method reports whether it was added.
- `get_list(name)`: the named list, or nothing when there is none. The list answers
  `total_entries()`: how many values it holds, as a `usize`.
- `check_ip(value)`, `check_hash(value)`, `check_domain(value)`: when the value is on
  the matching list, the list's name and the entry's description (both `String`);
  otherwise nothing.

## Added 2026-11-03: loading a list from text, listing a list

- `load_from_text(list, text) -> (usize, usize)`: adds the entries of a text to the named
  list, one per line: `value:description`, or a value alone (description "imported"). Lines
  that are empty or start with `#` are skipped. Because IPv6 addresses contain `:`, a line in
  `malicious_ips` is split at the first `:` only when the part before it is a valid IP or
  range on its own; otherwise the whole line is the value (and when that is not valid
  either, the line is refused). The same validity rules as `insert_entry` apply. Returns
  (added, refused) counts.
- `entries(list) -> Vec<(String, String)>`: every entry of the list as (value,
  description), ranges written as `network/prefix`, sorted by value. Empty for an unknown
  list.

Tests: comments and blank lines skipped; value-only lines; IPv6 with and without a
description; invalid lines counted as refused; `entries` lists exact values and ranges.

## Matching rules

- **IPs:** the value is trimmed and parsed as an IPv4 or IPv6 address; anything else
  never matches. It matches an exact entry, or any range entry that contains it. IPv4
  written inside IPv6 (`::ffff:203.0.113.5`) is treated as the IPv4 address.
- **Hashes:** compared without regard to letter case and surrounding spaces.
- **Domains:** compared without regard to letter case, surrounding spaces and a final
  dot. A listed domain also matches its subdomains: `evil.example` matches
  `cdn.evil.example`, but not `notevil.example`. A value given as a URL
  (`http://evil.example/path`) is checked by its host name.
- When a value matches more than one entry (an exact IP and a range), the exact entry's
  description is returned.

## Size and speed

Up to about a million entries across the lists. Exact IP, hash and domain lookups do not
slow down as lists grow; range lookups may scan the ranges (a few thousand at most).
siem-api checks every source IP of the last week's alerts in one request, so a lookup
must stay in the microseconds.

## Tests the new crate must have

- adding the same value twice counts once and keeps the newer description
- invalid values are refused per list
- an IP inside a listed range matches, one outside does not; IPv4-in-IPv6 matches
- hash case-insensitivity; domain case, final dot, subdomain and URL handling;
  `notevil.example` does not match `evil.example`
- an exact IP entry wins over a range for the description
- reads and writes from several threads at once

## Also change in siem-api

- `main.rs` `get_threat_intel_lists_handler`: the `format` labels say "IP / CIDR",
  "MD5 / SHA-1 / SHA-256" and "Domain" (not "CDB …").
- The crate's description in its `Cargo.toml`: "Threat indicator lists (IPs and ranges,
  file hashes, domains) with fast lookups".

## File layout

`src/lib.rs` (connects the files), `src/matcher.rs` (one list and the rules for its values),
`src/threat_intel.rs` (the manager and its tests).
