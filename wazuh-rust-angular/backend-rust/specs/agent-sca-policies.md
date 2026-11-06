# provigil-agent: the full set of Windows configuration policies

Written 2026-11-04 from a study of which areas the old agent's Windows policies cover and how many
checks each has. Describes what our policies must cover. Contains no policy text. The old policy
files (upstream data built from CIS Benchmarks) are not opened by the writer; titles, texts,
rationale, remediation and expected values are written from Microsoft's public documentation of
each setting (Group Policy reference, Windows security baselines of the Microsoft Security
Compliance Toolkit) in our own words. Compliance mappings: NIST 800-53, PCI DSS, HIPAA, ISO 27001
controls only (no CIS numbers or titles). Check ids: 50000–59999, unique across all policies.

Engine and event format: `specs/agent-sca.md` (built first). This adds the policies.

## Policies and their selection

One policy per Windows version; the agent runs the one(s) whose requirements match:

| Policy id | Applies to (requirements) | Target number of checks |
|---|---|---|
| `provigil_win10` | ProductName starts `Windows 10` and CurrentBuildNumber < 22000, workstation | 420 |
| `provigil_win11` | ProductName starts `Windows 10` or `Windows 11` and CurrentBuildNumber >= 22000, workstation | 480 |
| `provigil_win2012r2` | ProductName starts `Windows Server 2012 R2` | 290 |
| `provigil_win2016` | ProductName starts `Windows Server 2016` | 330 |
| `provigil_win2019` | ProductName starts `Windows Server 2019` | 345 |
| `provigil_win2022` | ProductName starts `Windows Server 2022` | 360 |
| `provigil_win2025` | ProductName starts `Windows Server 2025` | 400 |

(Windows 11 still reports "Windows 10" in ProductName; the build number decides. "Workstation" =
`HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions -> ProductType` is `WinNT`.)

The general `provigil_win_baseline` from `agent-sca.md` becomes the fallback for versions not in the
table; the versions above don't also run it.

## Coverage each policy must have (areas and approximate check counts)

Counts are for the Windows 11 policy; servers have fewer workstation-only items (BitLocker,
services, Store, power) and more server items (domain controller / member server settings, LDAP,
Netlogon, NTDS, SMB server), in proportion to their targets above.

| Area | Win 11 | Server 2022 | How it is read |
|---|---|---|---|
| Account policy: password length, history, age, complexity, reversible encryption; lockout duration, threshold, reset | 10 | 10 | local security policy (`secedit` export) |
| User rights assignments (who may log on locally / over the network / via RDP, debug programs, act as part of the OS, backup / restore, take ownership, load drivers, impersonate, create tokens, …) | 35 | 40 | `secedit` export (`[Privilege Rights]`) |
| Audit policy subcategories (logon, account lockout, special logon, process creation, policy change, user / group / computer account management, sensitive privilege use, system integrity, security state change, removable storage, …) | 28 | 34 | `auditpol` CSV |
| Security options: accounts (guest, admin rename, blank passwords), audit, devices, domain member / controller, interactive logon, network client / server SMB signing, network access (anonymous, shares, pipes), network security (LM hash, NTLM levels, Kerberos types, LDAP signing), shutdown, system objects, UAC | 60 | 66 | registry (`Lsa`, `LanmanServer`, `LanmanWorkstation`, `Netlogon`, `Policies\System`, …) |
| System services that should be disabled on a hardened host (e.g. remote registry, SSDP, UPnP host, Xbox services, web / FTP / SNMP services when present) | 56 | 14 | registry `Services\<name> -> Start` |
| Windows Firewall: domain / private / public profile on, inbound block, outbound allow, notifications, logging (size, dropped, successful) | 23 | 26 | registry `Policies\Microsoft\WindowsFirewall` |
| Remote Desktop: client / server settings, NLA, encryption level, session limits, drive / clipboard redirection, password saving | 20 | 20 | registry `Terminal Services` |
| BitLocker: OS / fixed / removable drives, recovery options, encryption methods, TPM / PIN requirements | 47 | 0 | registry `Policies\Microsoft\FVE` |
| LAPS (local admin password solution) settings | 8 | 5 | registry LAPS policy keys |
| Event log sizes and retention (application, security, setup, system) | 8 | 8 | registry `Policies\Microsoft\Windows\EventLog` |
| WinRM client / service: basic auth, unencrypted traffic, digest, RunAs | 8 | 8 | registry `Policies\Microsoft\Windows\WinRM` |
| PowerShell logging (module, script block, transcription) | 3 | 3 | registry `Policies\Microsoft\Windows\PowerShell` |
| Windows Defender / SmartScreen / Exploit Guard: real-time, behaviour monitoring, cloud protection, scanning removable drives, PUA, ASR rules | 12 | 8 | registry `Policies\Microsoft\Windows Defender` |
| Device Guard / Credential Guard / virtualization-based security, LSA protection | 8 | 7 | registry `DeviceGuard`, `Lsa` |
| Windows Update / Delivery Optimization | 9 | 6 | registry `Policies\Microsoft\Windows\WindowsUpdate` |
| Printers / Point and Print / print spooler hardening | 13 | 13 | registry `Windows NT\Printers` |
| Data collection / telemetry / cloud content / Store / consumer features | 16 | 9 | registry |
| Explorer / AutoPlay / AutoRun / attachment manager / search / Cortana | 20 | 12 | registry |
| Network: TCP/IP hardening (source routing, ICMP redirects, keep-alive), NetBIOS, LLMNR, DNS client, WLAN, network connections | 15 | 12 | registry |
| Logon UI / lock screen / screen saver / power and sleep | 15 | 8 | registry (machine and user policy) |
| Remaining administrative-template items (installer, group policy processing, device install, kernel DMA, app runtime, SMB v1, WDigest, …) | the rest up to the target | idem | registry |

Expected values: Microsoft's recommended setting from its security baseline for that version where
one exists, else the safer documented value. Each check: `id`, `title` (our wording: "<setting>:
<expected state>"), `description`, `rationale`, `remediation` (the Group Policy path to set it, and
the registry value it writes), `compliance`, `rules`, `condition`.

## Application policies (Windows servers)

| Policy id | Applies when | Target |
|---|---|---|
| `provigil_iis10` | `W3SVC` service present | 40 |
| `provigil_sqlserver` | any `MSSQL$*` / `MSSQLSERVER` service present (versions 2012–2022 in one policy, version-specific checks gated by the instance version) | 25 |
| `provigil_mysql` | `MySQL*` service present | 25 |
| `provigil_postgresql` | `postgresql*` service present | 30 |
| `provigil_apache` | `Apache*` service present | 30 |
| `provigil_web_exposure` | IIS or Apache present | 16 |

Application checks read configuration files (`f:` with regex on content, e.g. `web.config`,
`applicationHost.config`, `my.ini`, `postgresql.conf`, `httpd.conf`) and registry, using the paths
the services report. Areas: version disclosure, directory listing, default content, TLS protocols
and ciphers, logging, authentication modes, sample databases, remote access, file permissions.

## Revision 2026-11-04: two files, checks gated per version

Instead of seven near-identical files, the same coverage is delivered as two policies whose checks
each say which versions they apply to (an optional per-check `requirements` block, same syntax as
the policy-level one; a check whose requirements fail is not evaluated and not reported, so each
version reports exactly its own set and the hash covers only reported checks):

| Policy id | Policy requirements | Checks reported per version (targets above) |
|---|---|---|
| `provigil_windows_workstation` | ProductType `WinNT` | Windows 10 ≈ 420, Windows 11 ≈ 480 (Windows 11 = build >= 22000) |
| `provigil_windows_server` | ProductType `ServerNT` or `LanmanNT` | 2012 ≈ 290, 2012 R2 ≈ 290, 2016 ≈ 330, 2019 ≈ 345, 2022 ≈ 360, 2025 ≈ 400 |

Domain-controller-only checks: requirement ProductType `LanmanNT`; member-server-only: `ServerNT`.
`provigil_win_baseline` is folded into these two and removed (its 216 checks are the starting
point, ids kept where the check is kept). Check ids: workstation 52000–53999, server 54000–55999
(kept baseline ids 50001–50216 stay as they are). `provigil_win_apps` is expanded to the
application targets above as one file with per-application requirements (ids 51001–51999).

## Delivery

- Policies are YAML files in the crate (`src/sca/policies/*.yml`), compiled in with `include_str!`.
- Writing them is split per policy (each its own task); every policy file is reviewed for: no CIS
  number or text, unique ids, each check with remediation and at least one rule, counts within 10%
  of the target.
- Tests per policy: parses; ids unique across all; the live `#[ignore]` scan on this PC (Windows 11)
  of `provigil_win11` finishes under 120 s and reports every check (passed / failed / not
  applicable), nothing erroring.
