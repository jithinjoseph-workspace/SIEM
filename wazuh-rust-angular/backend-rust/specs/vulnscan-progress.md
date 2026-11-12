# provigil-vulnscan: progress

Clean-room rewrite from `specs/vulnerability-scanner.md`. Checklist numbers refer to the
`provigil-vulnscan` section of `specs/FEATURES.md`. Status 2026-11-12: built, 50 tests pass,
clippy clean. Not wired into any daemon yet.

## Done (module -> spec sections -> checklist items)
- host.rs: 2.1 host launch, host log lines -> 1, 2
- scanner.rs: 2.2-2.5 entry points, start sequence, 3.5 policy, 3.6 prebuilt check, 6.8 feed
  callback, 7.1 router filters, 7.3-7.5 event/delayed threads and postponement, 7.7 result
  handling -> 3-8, 18-21, 70, 75-76, 82-87
- config.rs: 3.1-3.4 -> 9-17
- kvstore.rs, queue.rs, lru.rs: 4.2, 4.3, 16 -> 22-25, 153 (Q4, Q26, Q43)
- feed.rs, schema.rs, patch.rs: 4.4, 6.1-6.10 -> 26-32, 54-74 (Q5, Q10-Q13, Q23, Q35)
- updater.rs: 4.5, 5.1-5.15 -> 33, 35-53 (Q6-Q9, Q24, Q34)
- agentdb.rs: 8 -> 88-91
- event.rs: 7.2, 9.1 CPE name -> 77-81, 92
- scan.rs: 9.2-9.13 -> 93-115 (Q14-Q18, Q25, Q27, Q40, Q41)
- version.rs: 10 -> 116-124 (Q20)
- cpe.rs: 11 -> 125
- inventory.rs: 4.6, 12 -> 34, 126-132 (Q21, Q22, Q36, Q38)
- output.rs: 13.1-13.3 -> 133-143 (Q19, Q28, Q29, Q31, Q39, Q42)
- report.rs: 13.4 -> 144-145 (Q37)
- sink.rs: 13.5 -> 146-150 (Q2)
- legacy_names.rs: section 20 literals that are read or on disk -> 155
- tests.rs + unit tests in each module: section 19 lists -> 156 (partly, see below)

- Spec section 21 (local sockets on Windows): TCP loopback client for provigil-db and UDP
  loopback report sender, both reading `<path>.port` on every connection attempt; used by
  default on non-Unix builds (`src/agentdb.rs`, `src/report.rs`, `src/host.rs`,
  `src/scanner.rs`). Tests: fake provigil-db with a port file, missing port file, port change
  between attempts, UDP report received through a port file. 52 tests pass, clippy clean.

## Left / open
- 156: the differential checks against the old scanner (19.3.21, 19.5.4, 19.7 multisets) need
  the old code as oracle; not possible in a clean room. See `specs/vulnscan-questions.md`.
- Wiring into provigil-modulesd (not part of this job).

## Corrections D1–D56 (specs/vulnscan-fixes.md)

All 56 rows are applied; 62 tests pass, clippy clean. Tests for every high and medium row.

| Id | Status | Where | Test |
|---|---|---|---|
| D1 | done | version.rs `cmp_py` | version `corrections_d1_d2_d8_d9` |
| D2 | done | version.rs `parse_py` | same |
| D3 | done | scan.rs `rescan_one` | tests `corrections_rescan_and_inventory` |
| D4 | done | patch.rs `add` | patch `operations` |
| D5 | done | patch.rs `add`/`remove` | patch `operations` |
| D6 | done | feed.rs `store_candidates` | feed `corrections_d6_d11` |
| D7 | done | scan.rs `match_versions` | tests `corrections_scan_rules` |
| D8 | done | version.rs | version `corrections_d1_d2_d8_d9` |
| D9 | done | version.rs `parse_rpm` | same |
| D10 | done | schema.rs `norm_float` | schema `corrections_d10_d20_d49` |
| D11 | done | feed.rs `remediation` | feed `corrections_d6_d11` |
| D12 | done | agentdb.rs `query` | agentdb `loopback_port_file` |
| D13 | done | agentdb.rs `interpret` | agentdb `answers` |
| D14 | done | inventory.rs `publish_deletion` | tests `corrections_rescan_and_inventory` |
| D15 | done | inventory.rs `inventory_hotfix_solved` | same |
| D16 | done | scanner.rs `subscribe` | tests `router_filters` |
| D17 | done | updater.rs (chain built once) | updater `offline_file_processed_once` |
| D18 | done | host.rs `hostname` (gethostname on Windows too) | host `hostname_is_the_system_name` |
| D19 | done | scanner.rs start, sink.rs `send` | sink `send_failure_is_a_warning_and_remembered` |
| D20 | done | schema.rs `norm_table` | schema `corrections_d10_d20_d49` |
| D21 | done | output.rs `document_details` | tests `corrections_scan_rules` |
| D22 | done | scan.rs `vendor_list` | tests `corrections_scan_rules` |
| D23 | done | scan.rs `os_scan` | tests `corrections_scan_rules` |
| D24 | done | version.rs `parse_cal` | version `corrections_low` |
| D25 | done | version.rs `parse_mm`, `parse_sem` | version `corrections_low` |
| D26 | done | version.rs `parse_deb` | version `corrections_low` |
| D27 | done | version.rs `compare` | version `corrections_low` |
| D28 | done | scan.rs `match_versions` (parsed once) | - |
| D29 | done | cpe.rs | cpe `examples` |
| D30 | done | event.rs `build_cpe` | event `cpe_from_rules` |
| D31 | done | event.rs `field`, `from_row`; scan.rs hotfix cache | event `cpe_from_rules` |
| D32 | done | scan.rs `expand_cna` | - |
| D33 | done | scan.rs `platform_ok`, `remediated`, `os_scan` | - |
| D34 | done | scan.rs `rescan_all`, `scan_list` | - |
| D35 | done | inventory.rs `inventory_os_sync` | - |
| D36 | done | output.rs `install_time` | output `helpers` |
| D37 | done | kvstore.rs error texts, batch errors returned | - |
| D38 | done (no change, the row allows it) | queue.rs | - |
| D39 | done | host.rs (CRITICAL + exit), log.rs `Critical` | - |
| D40 | done (accepted as structural) | host.rs | - |
| D41 | done | scanner.rs start order (core slot for the feed callback) | - |
| D42 | done | config.rs `parse_time` | config `times` |
| D43 | done | updater.rs work paths `<home>/<outputFolder>/...` | updater `offline_file_processed_once` |
| D44 | done | updater.rs `last_segment`, `file_name` | - |
| D45 | done | updater.rs offline HTTP file errors | - |
| D46 | done | updater.rs `decompress` | - |
| D47 | done | updater.rs `offsets_download` | - |
| D48 | done | updater.rs `store_offset`, `store_offline` | - |
| D49 | done | schema.rs `norm_int`, `norm_enum` | schema `corrections_d10_d20_d49` |
| D50 | done | feed.rs `store_hotfix_index` | - |
| D51 | done | feed.rs `store_candidates` | - |
| D52 | done | sink.rs | - |
| D53 | done (clarifies D8: release numbers wrap digit by digit in 32 bits, no 64-bit step) | version.rs `release_num` | version `corrections_d1_d2_d8_d9` |
| D54 | done (the scanner owns the router handle until `stop`) | scanner.rs `Scanner.router` | tests `scanner_owns_the_router` |
| D55 | done (one join rule for home + folder texts) | config.rs `home_path`, used by updater.rs | config `home_path_tests::joins` |
| D56 | done (after `due` parts any `ok` closes the answer; result = the parts, body ignored) | agentdb.rs `interpret` | agentdb `answers` |

Interpretations of terse rows are listed in `specs/vulnscan-questions.md` (items 22-30).

## Changes C1–C4 (spec section 22, owner-approved)

69 tests pass, clippy clean.

| Id | Status | Where | Tests |
|---|---|---|---|
| C1 whole-part prefixes | done: agent searches use `<agent>_` (inventory 12.3/12.4/12.6, local documents, "already sent" memory); `DELETED` covers the id itself and `<id>_...`; hotfix lookups match `KB` or `KB_...` only | inventory.rs, sink.rs `matching`, feed.rs `hotfix_keys_for` | tests `c1_agent_cleanup_is_whole_id`; sink `local_mode`; feed `hotfix_lookup_whole_ids` |
| C2 feed updates without overload | done: no re-scan when an update changed nothing (with the INFO line); every `reboot` starts a persisted background job (`queue/vd/rescan`, one entry per agent) that runs only when no real-time event waits; progress every 50 agents and at the end; a new `reboot` replaces the job | feed.rs `take_changes`, scanner.rs callback and `work_step`, scan.rs `start_rescan_job`/`job_step` | tests `c2_no_change_no_rescan`, `c2_background_job_yields_and_restarts` |
| C3 re-scan change alerts | done: pairs remembered before the clean-up, `Active` alerts for new pairs and `Solved` alerts for gone pairs after a complete re-scan, none on a first scan or a failed scan, cap 500 with the warning | scan.rs `rescan_agent_data`, output.rs `collect_alerts`/`change_alerts` | tests `c3_rescan_change_alerts`, `c3_alert_cap` |
| C4 integrity clear | done: only the component's keys go (per-element `DELETED`, OS also `os_initial_scan`), no `DELETED_BY_QUERY`, one clear alert with the component title | inventory.rs `integrity_clear`, output.rs `clear_alert`/`send_clear_alert` | tests `end_to_end_scans` step 9, `c4_os_clear_keeps_packages` |
