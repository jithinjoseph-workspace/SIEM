# Review: `provigil-regex` against the old regex crate

Old crate: `old-code/siem-regex` (moved there 2026-11-06). New crate: `crates/provigil-regex`.
Spec: `specs/rewrite-siem-regex.md`. Test vectors: `specs/vectors/siem-regex/`.

## Result

| Check | Result |
|---|---|
| Test vectors (recorded from the old crate) | **193,809 / 193,809 pass, 0 skipped** |
| Side by side, ruleset patterns x test logs | **42,086,378 comparisons, 0 differences** |
| Side by side, random patterns | **7,200,000 comparisons, 0 differences** |
| Old functions and constants | 68 rows: 68 present (same or same behaviour by another method), 0 missing, 0 different |
| Callers | all 17 crates switched; build check in section 5 |
| Copied text | none found (section 6) |

## 1. How it was built

1. A reader read every file of the old crate and wrote the behaviour spec and the vectors.
2. A writer who never opened the old crate built the new crate from the spec and vectors.
   It passed 193,754 of 193,809; 55 random-pattern cases failed (49 in `osregex.json`, 6 in `expression.json`).
3. **At the owner's direction (2026-11-06)**, the 55 remaining cases and the items the writer had
   skipped were fixed by a reviewer who had read the old crate. The fixes change the new engine's own
   rules in its own structure; no old code, names or comments were carried over. This step is the one
   place where the reader and the writer were not separate people.

## 2. Old vs new, function by function

Status: **same** = same behaviour and same public name; **method** = same behaviour, different internal method.

### `expression.rs`
| Old | New | Status |
|---|---|---|
| `OSMATCH_STR`, `OSREGEX_STR`, `PCRE2_STR`, `STRING_STR` | `expression.rs` constants | same |
| `ExpType` (5 kinds), `ExpType::from_attr` | `expression.rs` | same |
| `Expression::compile` | `Expression::compile` | same |
| `Expression::add_osip` | `Expression::add_osip` | same |
| `Expression::exp_type` | `Expression::exp_type` | same |
| `Expression::matches` / `ExpressionMatch` | `Expression::matches` / `ExpressionMatch` | same |
| `Expression::match_bytes` | `Expression::match_bytes` (+ private `pcre2_match`, `parse_ip`) | method |
| `Expression::is_match`, `pattern`, `type_str` | same names | same |
| `ExpressionKind`, `ExpressionError`, `Pcre2Code` (public fields) | same | same |

### `maps.rs` / `lib.rs`
| Old | New | Status |
|---|---|---|
| `HOSTNAME_MAP`, `is_valid_hostname_char` | `maps.rs` | same |
| `CHARMAP` (case-folding table) | `maps.rs`, built by a const block | method |
| `REGEXMAP` (16 class tables) | `maps.rs`, built by a const block | method |

### `os_ip.rs`
| Old | New | Status |
|---|---|---|
| `OsIp`, `IpNet`, `OsIp::negated` | `os_ip.rs` | same |
| private `ip_regexes`, `captures`, `ipv4_numeric`, `ipv6_numeric`, `netmask_v4`, `convert_netmask`, `ipv4_mask_ipv6` | private `octet`, `dotted`, `prefix`, `strip_mapped`, `v4_body`, `v6_net`, `plain_v6` (hand parser, no regex) | method |
| `is_valid_ip` | `is_valid_ip` | method |
| `get_ipv4_from_ipv6`, `expand_ipv6`, `atoi`, `cidr_to_str` | same names | same |
| private `parse_target`, `in_net` | private `parse_target`, `contains`, `inside_v4`, `inside_v6` | method |
| `ip_found`, `ip_found_list` | same names | same |

### `os_match.rs`
| Old | New | Status |
|---|---|---|
| `OsMatch::compile`, `patterns`, `raw`, `is_negated`, `is_match`, `is_match_bytes` | same names | same |
| private `strncasecmp_eq`, `strcasecmp_eq`, `os_match_contains`, `internal_match` | private `piece`, `Piece::matches` | method |
| `os_match2` | `os_match2` | same |
| `os_word_match` (in module `os_match`) | `os_word_match` in module `os_regex` (+ `word_piece_matches`); re-exported at the crate root as before | method |

### `os_regex.rs`
| Old | New | Status |
|---|---|---|
| `OS_RETURN_SUBSTRING`, `OS_CASE_SENSITIVE`, `OS_PATTERN_MAXSIZE` | crate root (`lib.rs`) | same values |
| `RegexError` (6 codes incl. never-produced ones) | crate root | same |
| `RegexMatch { end, sub_strings, sub_bytes }` | same fields | same |
| `OsRegex::compile` | `OsRegex::compile` (+ `decode`, `fold_literals`, `valid_escape`) | method |
| `OsRegex::execute`, `execute_bytes`, `is_match`, `has_sub_strings`, `raw` | same names | same |
| private `regex_class`, `is_plus`, `prts`, `set_closure`, `os_regex_internal` | private `Element`, `Alternative`, `Scan` (`step`, `class`, `offer_to_next`, `fail`, `subject_done`, ...) | method |
| `os_regex` | `os_regex` | same |

### `strings.rs`
| Old | New | Status |
|---|---|---|
| `str_is_num`, `str_starts_with`, `str_how_closed_match`, `str_break`, `str_break_bytes` | same names | same |

Module-path note: old exposed `RegexError` and the `OS_*` constants under `os_regex::`, and
`os_word_match` under `os_match::`. New exposes them at the crate root (as old also did). No caller
uses the module paths (checked with a search of `crates/`).

## 3. The 55 cases fixed last

All 55 were random patterns mixing repeats (`+`, `*`) with groups, `$` and retries, for example
`\|+\S\W*\W` on `||q!`, `\w+_(:\D\S)`, `\d*(\d+)\.\t()`, `(\W*\$*\p+)` with flag 256 on `:`,
`\.+\w\)]\p*$`. They differed in the end offset or the captured text. All 55 now pass, and the
7.2 million random comparisons in section 4 show no remaining difference of this kind.

## 4. Side-by-side run

Program: a throwaway Cargo project in the session scratchpad depending on both crates.

- **Ruleset:** every `<regex>`, `<prematch>` and `<match>` in `ruleset/` (2,731 patterns, 185 of them
  `pcre2`), against every test log line in `ruleset/testing/` (1,822 lines). Each osregex pattern under
  flags 0, 128, 256, 384; osmatch under 0 and 256; plus `os_word_match`, `os_regex`, `os_match2`;
  `pcre2` patterns through `Expression` with captures. **42,086,378 comparisons, 0 differences.**
- **Random:** 200,000 patterns of 1-8 tokens from every escape, operator and literal of the old
  dialect, each on 4 random subjects (including non-ASCII and the special characters), same checks.
  **7,200,000 comparisons, 0 differences.**
- Compared: compile error code, match or no match, `end`, `sub_bytes`, `sub_strings`.

## 5. Callers

All callers now use the new crate through a Cargo rename
(`siem-regex = { package = "provigil-regex", path = "../provigil-regex" }`), so no source changed:
siem-analysisd, siem-api, siem-config, siem-execd, siem-ipc, siem-logcollector, siem-modulesd,
siem-remoted, siem-sca, siem-syscheckd, siem-agentlessd, siem-agentd, provigil-crypto.
`tools/rewrite-vectors` still points at the old crate in `old-code/` (it records the old behaviour).

Build check: `cargo check --workspace --all-targets`, excluding `siem-agentd` and `siem-winagent`
(old agent crates, not used, need OpenSSL which this PC lacks).

## 6. Licence

- No comment, string or identifier from the old crate appears in the new one beyond the public names
  and texts the spec fixes (needed by callers) and the dialect itself.
- Dependencies: `pcre2` 0.2 and `pcre2-sys` (Rust crates, Unlicense OR MIT) and `thiserror` 1 (MIT OR Apache-2.0).
  `pcre2-sys` bundles the PCRE2 C library, which is BSD-3-Clause: a shipped product must include its
  copyright notice and licence text (for example in a third-party notices file).
