# provigil-agent: configuration assessment (SCA) engine and policies

Written 2026-11-03 from a study of how the old agent reports SCA to the manager. Describes what the
new code must do. Contains no code. Written from this description only; no old agent code and no
old policy files are opened.

## Licence note (policies)

The old agent's policy files are upstream data built from CIS Benchmarks (CIS's licence does not
allow commercial redistribution). ProVigil's policies are written by us, from Microsoft's public
Windows security baseline settings (Microsoft Security Compliance Toolkit) and general hardening
practice; check titles and texts are our own words; compliance mappings name public framework
controls (NIST 800-53, PCI DSS, HIPAA, ISO 27001) only.

## 1. Policy format (our own, YAML; crate `serde_yaml` is fine)

```yaml
policy:
  id: provigil_win_baseline          # unique id
  name: "ProVigil Windows baseline"
  description: "..."
  references: ["https://..."]
requirements:                        # optional: policy applies only when these hold
  any: ["r:HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion -> ProductName -> r:Windows"]
checks:
  - id: 50001                        # unique across all ProVigil policies (50000–59999 Windows)
    title: "..."
    description: "..."
    rationale: "..."
    remediation: "..."
    compliance: { nist_800_53: ["AC-7"], pci_dss: ["8.3.4"] }
    condition: all                   # all | any | none
    rules:
      - "r:HKLM\\...\\Key -> ValueName -> 1"          # registry value equals (decimal or 0x hex for DWORDs)
      - "r:HKLM\\...\\Key -> ValueName -> r:^(1|2)$"  # value matches regex
      - "r:HKLM\\...\\Key -> ValueName -> n:^(\\d+) compare >= 14"   # numeric compare
      - "r:HKLM\\...\\Key"                             # key exists
      - "not r:HKLM\\...\\Key -> ValueName"            # value absent
      - "f:%WINDIR%\\System32\\x.dll"                  # file exists
      - "c:secedit-value:MinimumPasswordLength -> n:^(\\d+) compare >= 14"   # local security policy
      - "c:auditpol:Logon -> r:Success and Failure"    # audit policy subcategory setting
      - "p:r:^teamviewer"                              # process running (regex)
```

Rule kinds: registry (`r:`), file (`f:`, optional `-> r:<regex>` on content), process (`p:`),
local security policy values (`c:secedit-value:<name>`; the agent exports the policy once per scan
with `secedit /export /cfg <temp> /areas SECURITYPOLICY USER_RIGHTS` and reads the INI), audit policy
(`c:auditpol:<subcategory name>`; one `auditpol /get /category:* /r` per scan, CSV). `not ` negates a
rule. A check whose rules cannot be evaluated (e.g. access denied, secedit unavailable) is
`not applicable` with a reason.

## 2. Policies shipped (compiled into the agent; more can be added as files in `sca\` next to the agent)

- `provigil_win_baseline`: 150+ checks for Windows 10/11 and Server 2016–2025: account and password
  policy, lockout, audit policy subcategories, user rights (e.g. debug programs, act as part of OS),
  security options (LM hash, NTLM levels, SMB signing, anonymous access, UAC), Windows Defender and
  firewall profiles, SMBv1, RDP (NLA, encryption), WinRM, PowerShell logging, autorun, WDigest,
  LSA protection, Credential Guard, BitLocker status, Windows Update settings, screen lock, remote
  assistance, unsigned driver policy. The 14 checks the agent has today are included (same ids
  are NOT required; they move to this policy).
- `provigil_win_apps`: 20+ checks for risky software (remote-access tools, P2P, outdated runtimes)
  and browser hardening policy keys.

## 3. What the agent sends (exact: the manager's analysis engine stores and alerts on these)

Per scan of a policy (at start, then every `sca_interval_secs`, and on a `scan` command), with
`scan_id` a random positive 31-bit integer per scan:

- one event per check, in check-id order:
  `{"event_type":"sca","timestamp","agent","location":"sca","message":<JSON text>}` where the JSON text is
  `{"type":"check","id":<scan_id>,"policy":<policy name>,"policy_id":<policy id>,"check":{"id":<check id>,"title":..,"description":..,"rationale":..,"remediation":..,"compliance":{<key>:"<v1>,<v2>"},"rules":[<rule strings>],"condition":"all|any|none","result":"passed|failed|not applicable","reason":<only when not applicable>,"registry":<the first registry key of the rules, when any>,"file":<first file rule path, when any>}}`
  (`compliance` values are comma-joined strings; omit `description`, `rationale`, `remediation`,
  `references` when empty).
- then the summary:
  `{"type":"summary","scan_id":<scan_id>,"name":<policy name>,"policy_id":..,"file":"<policy id>.yml","description":..,"references":"<comma-joined>","start_time":<unix s>,"end_time":<unix s>,"passed":n,"failed":n,"invalid":n,"total_checks":n,"score":<passed*100/(passed+failed), 0 when none>,"hash":<H>,"hash_file":<SHA-256 hex of the policy's YAML text>,"first_scan":1 (only on the agent's first scan of this policy since it started)}`
  where H = SHA-256 hex of the check results in ascending check-id order, joined with `:`, with each
  `not applicable` written as an empty string (so the manager's stored results hash the same).
- Order matters: all check events of a scan before its summary (same buffer, same batch order).

Checks keep being sent every scan (so the manager never needs to ask the agent for a resend).

## 4. Remove

The `sca` object events of today (`{"event_type":"sca","sca":{"type":"check"|"summary",...}}`) are
no longer sent; `src/sca.rs` is replaced by the engine (`src/sca/` module) — its 14 checks become
part of `provigil_win_baseline`.

## Tests

- Rule parser and each rule kind against a test registry key `HKCU\Software\ProVigilTest`, temp
  files, this process, a sample `secedit` INI and a sample `auditpol` CSV; `not`; all/any/none;
  not-applicable with reason.
- Hash: for results passed, failed, not applicable, passed (ids 3,1,2,4 given out of order) the hash
  is SHA-256 of `failed:passed::passed`... i.e. ordered by id 1,2,3,4 → exactly
  `<r1>:<r2>:<r3>:<r4>` with not applicable empty; compare with a hard-coded expected value.
- Message JSON exact field names; compliance values joined; summary score.
- Built-in policies parse; every check has id, title, remediation, at least one rule; ids unique.
- Windows `#[ignore]`: a real scan of `provigil_win_baseline` finishes in under 60 s and produces
  one check event per check plus one summary.

Then `cargo test -p provigil-agent`, clippy clean on the files changed (`--no-deps`), build.
