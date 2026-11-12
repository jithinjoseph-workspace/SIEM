# Mass agent deployment: one run from one PC

Status: steps 1–6 built 2026-11-11 (C1 computer-name enrollment; C2 deployment tokens; C3
`deploy/install-provigil.ps1`; C4/C5 `deploy/deploy-provigil.ps1` with discovery and the Windows push in
PowerShell, `crates/provigil-deploy` for the Linux SSH push and the results report; C6 `install.sh`
result line; C7 `deploy_targets` + gateway `/api/v1/deploy/report` + console results; C8 kit download
`siem-api/src/deploy_kit.rs`, guide `deploy/GUIDE.md`). Step 7: Linux lab in Docker
(`deploy/lab/`); the Windows labs (path A, path B) need VMs. Built differently from the plan: see
section 14. Owner's requirement: a client's IT administrator installs the
ProVigil agent on all their PCs (about 500; Windows 10, Windows 11 and Linux; the number is not known
in advance) by running one script on one PC. The script reboots the PC, logs in by itself as a
separate deployment account the client created for us, finds every PC, installs the right agent on
each, and logs off. Every PC enrolls itself with its own name and ID and appears in the console. The
client authorises this in writing.

Hosted (cloud) ProVigil: only the agent is installed at the client. Agents connect outbound to the
cloud gateway (HTTPS 8443, gRPC/TLS 8089); nothing inbound at the client, no VPN.

## 0. Goal and outcomes

**Goal.** A client with hundreds of PCs gets every PC protected by ProVigil from one run on one PC,
without anyone visiting the PCs, and both the client and we can see in the console which PCs are
protected and which are not, and why.

**Outcomes (what exists when this is done):**

| # | Outcome | How we know it is reached |
|---|---|---|
| O1 | One run on the admin PC installs the agent on every reachable Windows 10/11/Server and Linux PC | Lab: 100% of reachable PCs installed in one run |
| O2 | Each PC enrolls by itself with its own name and ID and appears in the console | Each PC in the agent list within 5 minutes of its install, named after the computer |
| O3 | Unknown fleets are found: the admin does not need a PC list | Discovery finds every PC of the lab (AD and network scan); devices that are not PCs are skipped |
| O4 | Nothing is silently missed | Every PC not installed is listed with a reason and a fix (access denied, firewall, off, not supported) |
| O5 | The client's credentials stay safe | After the run: no auto-login setting, no stored password, no copied files left; passwords never in logs or results |
| O6 | The deployment cannot be abused | The kit's token expires, has a maximum count, can be revoked; the tenant key is never in the kit |
| O7 | Both client situations are covered | Path A (domain) and path B (workgroup) labs pass; path A also by Group Policy startup script |
| O8 | Progress is visible to us and the client | Console Deployment page: expected, enrolled, failed, not reporting; CSV export |
| O9 | The client can do it alone | Kit download from the console with a guide and checklist; a dry run lists the PCs before installing |

**Business result:** onboarding a 500-PC client changes from days of per-PC installs to one run plus
a review of the exceptions; it is the first thing a pilot client does, so it decides their first
impression.

**Not in this plan (later or separate):** the MSI package for Intune / SCCM / Company Portal; Mac
PCs; installing where no administrator account works (not possible by design); proxy support in the
agent (decision 13.4).

Contents: 0 goal · 1 situations · 2 what exists · 3 the flow · 4 pieces to build (C1–C8) · 5 discovery ·
6 push · 7 results and console · 8 security · 9 client checklist · 10 tests · 11 plan and effort ·
12 risks · 13 open questions.

---

## 1. The two client situations

| | Path A: Active Directory domain | Path B: no domain (workgroup) |
|---|---|---|
| Deployment account | Domain account (e.g. `CORP\provigil-deploy`) in every PC's Administrators group: one Group Policy "Restricted Groups" / "Local Users and Groups" setting, or membership of Domain Admins | Local account with the **same name and password** on every PC (e.g. `provigil-deploy`), or the built-in Administrator if it has the same password everywhere |
| Remote admin rights | Domain accounts work remotely as admin by default | Windows filters local accounts over the network (remote UAC): each PC needs `LocalAccountTokenFilterPolicy = 1`, or the built-in Administrator (RID 500) is used. Usually set in the client's PC image; if not, path B cannot reach that PC |
| How PCs are found | Active Directory computer list (enabled computers, with OS and last logon), plus a network scan for Linux and stragglers | Network scan of the local ranges |
| Firewall on PCs | File and Printer Sharing (445) or WinRM (5985) allowed from the admin PC (normally by Group Policy) | Same; on workgroup PCs the network profile must be Private with file sharing on |
| Extra option | Group Policy computer startup script (C3): no account needed, runs as SYSTEM on each PC at its next boot; catches PCs that were off | — |
| Linux PCs | SSH (22) login with sudo, given by the client | Same |
| 10-second check | On the admin PC, as the deployment account: `Test-Path \\PC-NAME\admin$` → `True` | Same |

Not possible on either path: installing with only a standard user on the target. A Windows service
needs administrator rights on that PC. PCs the account cannot reach are listed with the reason, for a
per-PC install (email link, USB, or the client's IT tool).

## 2. What already exists

- Windows install script generated by the console (ndr-ui `services/siem/agent-deploy.ts`,
  `windowsInstallScript`): downloads `provigil-agent.exe` and the active-response programs, checks each
  SHA-256 against the manager's list, installs the `ProVigilSvc` service, writes `ca.pem` and
  `provigil-agent.json`, waits for the agent to enroll and prints its ID; optional Sysmon, audit
  policy and PowerShell logging. A reinstall keeps the name and ID.
- Linux installer `crates/siem-agent-linux/install.sh` (systemd service, enrollment with the CA).
- Enrollment: the agent enrolls over TLS at the gateway (`crates/provigil-gateway/src/core.rs`,
  `cache.rs` checks the tenant key from ClickHouse `tenant_agent_keys`), which forwards it to siem-api
  (`gateway_api.rs` → `enroll_agent`); the agent gets an ID unique across tenants.
- Upgrades from the console (agent upgrade through the gateway): after the first install, no more
  admin work is needed on the PCs.
- Gateway load-tested for thousands of agents: 500 enrolling at once is within limits.

Missing: one name per PC (the command has one fixed name), a limited token (the command carries the
tenant key), many-PC push, discovery, Linux push, results tracking, reboot/auto-login flow.

## 3. The flow

### Stage 1: on the admin PC, as the admin's own account

1. Self-check: running elevated; PowerShell 5.1+; the kit is complete (SHA-256 of every file against
   `deploy.json`); the cloud is reachable (HTTPS to the gateway, CA checked). Stop with a clear message
   otherwise.
2. Ask (one window): deployment account (name, password); path A: AD scope (whole domain or OU);
   network ranges (default: the admin PC's own subnets); Linux login (user, password or key file;
   optional).
3. Verify the deployment account before changing anything: a local logon test (`LogonUser`), and on
   path A a lookup in the domain. Test `\\<one sample PC>\admin$` with it when a sample is given.
4. Copy the kit to `C:\ProgramData\ProVigilDeploy\` (ACL: Administrators and SYSTEM only).
5. Keep what stage 2 needs across the reboot in `run.json` (ranges, scope, options) and the Linux
   secret encrypted with DPAPI LocalMachine scope in `linux.bin` (same ACL; deleted at the end).
6. One-time automatic login:
   - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`: `AutoAdminLogon = 1`,
     `DefaultUserName`, `DefaultDomainName`, `AutoLogonCount = 1`.
   - The password as the LSA secret `DefaultPassword` (`LsaStorePrivateData`), the way Windows'
     auto-login tool stores it, never as the plain-text registry value.
7. Scheduled task `ProVigil Deploy Stage 2`: trigger at logon of the deployment account; run with
   highest privileges; action `powershell -NoProfile -ExecutionPolicy Bypass -File
   C:\ProgramData\ProVigilDeploy\deploy-provigil.ps1 -Stage 2`.
8. Write the start of the run to the console (C7, `status = started`).
9. A visible 60-second countdown ("Cancel" removes everything from steps 4–7), then reboot.

### Stage 2: after the reboot, as the deployment account (runs by itself)

1. First, always (also when anything later fails): remove `AutoAdminLogon`, `DefaultUserName`,
   `AutoLogonCount`, the LSA secret and the stage 2 task. Check they are gone; log it.
2. A progress window (computers found, installed, failed, remaining); also written to
   `C:\ProgramData\ProVigilDeploy\logs\deploy.log`.
3. Install the agent on this PC (C3, local).
4. Discover (section 5).
5. Push in parallel, 30 at a time (section 6), Windows and Linux together.
6. Results: `results.csv` and `results.json` in the kit folder; sent to the console (C7).
7. Retries (decision in 13.2): a task every hour for 24 hours that runs only the PCs not yet
   installed, then removes itself and the kit secrets.
8. Summary window (installed / already installed / failed / unreachable / not a PC, with the CSV
   path), 2-minute timeout, then log off.

### Modes of the same script

| Parameter | Meaning |
|---|---|
| `-Stage 1` (default) | The full flow above |
| `-NoReboot` | Stage 2 straight away in the current session (the admin already is the deployment account; also for tests) |
| `-DiscoverOnly` | Find and list PCs, install nothing (a dry run to show the client first) |
| `-ComputerList file.txt` | Only these PCs (names or addresses), no scan |
| `-SearchBase "OU=..."` / `-Ranges "10.1.0.0/24,..."` | Limit discovery |
| `-Throttle 30` | Parallel installs |
| `-Local` | Install on this PC only (C3; also the Group Policy startup script) |
| `-Uninstall` | Remove the agent from the listed PCs (tamper protection: open a maintenance window in the console first) |

## 4. Pieces to build

### C1. Enrollment by computer name

- Windows: agent name = `$env:COMPUTERNAME`; Linux: `hostname -s`; cleaned to `[A-Za-z0-9._-]`,
  2–128 characters; a reinstall keeps the existing name and ID (already the case).
- Two PCs with the same name (rare outside domains): the second gets `-<last 4 of MAC>`.
- Files: `services/siem/agent-deploy.ts` (a "use the computer name" option for the console command
  too), `install.sh` (`SIEM_AGENT_NAME` default from `hostname`).

### C2. Deployment token

- New siem-api table `deploy_tokens` (per tenant DB, in `ANALYST_DDL`): `id`, `label` (batch name),
  `token_hash` (SHA-256), `created_by`, `created_at`, `expires_at`, `max_enrollments`, `revoked`,
  `groups` (agent group to put PCs in).
- Token format `pvd_<id>_<32 random bytes, base64url>`; shown once at creation, stored only hashed.
- Gateway `cache.rs`: load token hashes with tenant, expiry and revoked flag next to
  `tenant_agent_keys`; refuse expired or revoked tokens early.
- siem-api enrollment (`enroll_agent`): final check (not expired, not revoked, enrolled count for
  this batch below `max_enrollments`; the count is read from the agent registry by batch, so no
  counter can drift); record `deploy_batch = id` on the agent. A reinstall of an already-enrolled
  PC does not count again.
- API (tenant admin): `POST /api/v1/deploy/tokens` `{label, days, max, groups}`, `GET
  /api/v1/deploy/tokens`, `DELETE /api/v1/deploy/tokens/:id` (revoke).
- Defaults: 7 days, maximum = expected PCs + 10% (decision 13.3).

### C3. Local install script `install-provigil.ps1`

- The current `windowsInstallScript` as a file, reading `deploy.json` (gateway addresses, CA, token,
  group, optional Sysmon / audit policy / PowerShell logging) instead of having them pasted in.
- Installs from its own folder (the kit or a share), not by downloading 58 MB per PC; SHA-256 checked.
- Exit codes: 0 installed, 1 already installed and enrolled, 2 enrollment failed (with the reason
  from the agent log), 3 files bad, 4 not elevated; prints one JSON line
  `{computer, agent_id, agent_name, os, version, outcome, reason}` for the push to collect.
- Group Policy (path A): the same file as a computer startup script, with the kit on a read-only
  share (`\\server\ProVigil$`); it skips quickly when the agent is already installed and current.

### C4. `provigil-deploy.exe` (new crate `provigil-deploy`)

One program for discovery and pushing, so Windows and Linux end in one results list.

- `discover` (section 5): AD via LDAP over the logged-in account, network scan, OS detection; JSON.
- `push-windows` (section 6): admin share copy and remote run, with the logged-in account's
  credentials (path A) or NTLM pass-through of the matching local account (path B), or explicit ones.
- `push-linux` (section 6): SSH (`russh`, Apache-2.0) with password or key, `sudo -S`.
- `report`: results to the console (C7) with the token.
- Bounded parallelism, per-PC timeout (10 min), no password in logs or output.

### C5. Two-stage `deploy-provigil.ps1`

Section 3: checks, prompt window, auto-login and LSA secret, stage 2 task, countdown and reboot,
first-step cleanup, progress window, calls to C3 and C4, retries, summary, log off; the modes table.

### C6. Linux side

- `install.sh` takes the token and the computer name (C1), installs from the copied files
  (no download), prints the same JSON result line as C3.
- Supported: Ubuntu 20.04+, Debian 11+, RHEL / Rocky / Alma 8+, CentOS Stream; systemd needed;
  others reported "not supported".

### C7. Deployment results and console view

- siem-api `deploy.rs`: tables `deploy_runs` (batch, admin PC, started, finished, counts) and
  `deploy_targets` (batch, computer, address, OS, method, outcome, reason, agent ID, time; one row
  per PC, latest wins).
- `POST /api/v1/deploy/report` (token auth; through the gateway's HTTPS port, since client networks
  only reach the gateway), `GET /api/v1/deploy/batches`, `GET /api/v1/deploy/batches/:id`.
- Console page (tenant admin, "Deployment"): per batch: expected PCs, enrolled, failed with reasons,
  unreachable, not yet reporting events; filter and CSV export; "Revoke token"; "Generate kit".
  Enrolled agents link to their agent page.

### C8. Kit download

- Console button on the tenant admin Setup page: creates a token (C2) and a zip:
  `deploy-provigil.ps1`, `install-provigil.ps1`, `provigil-deploy.exe`, the Windows agent and
  active-response files, the Linux agent and `install.sh`, `ca.pem`, `deploy.json` (gateway
  addresses, token, group, SHA-256 of every file), `GUIDE.pdf` (both paths, the checklist of
  section 9, the commands).

## 5. Discovery

| Source | What it gives |
|---|---|
| Active Directory (path A) | Enabled computer accounts, OS name and version, last logon (stale accounts > 90 days marked, not skipped) |
| Admin PC network ranges (or given ranges) | Every address that answers |
| Ping TTL | ~128 Windows, ~64 Linux / Mac (a first guess) |
| Port 445 | Windows file sharing (push possible) |
| Port 5985 | Windows remote PowerShell |
| Port 22 + SSH greeting | Linux, often with the distribution (`OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`) |
| After login | Windows edition and build (Win32_OperatingSystem); Linux `/etc/os-release` |
| Console | PCs already enrolled in the tenant: skipped, or upgraded when older |

- Printers, phones, switches and other devices: "not a PC", skipped.
- The scan is gentle (a few hundred probes per second at most), only the given ranges; the guide asks
  the client to tell their security team before the run (a scan can trigger their alarms).

## 6. Push

### Windows (10, 11, Server; one agent for all)

1. Connect to `\\PC\admin$` (logged-in account; path B: matching local account, or explicit).
2. Copy the agent files and `install-provigil.ps1` to `\\PC\admin$\Temp\ProVigil\`.
3. Run it as SYSTEM, first method that works:
   1. WinRM (5985 open): `Invoke-Command` running the script;
   2. Service Control Manager over 445: a temporary service that runs the script once, then deleted
      (works with file sharing alone);
   3. Task Scheduler remote (RPC): a one-time task as SYSTEM, then deleted.
4. Collect the JSON result line; wait for enrollment (the agent ID); delete the copied files.
5. Outcomes: installed, already installed, failed (with the reason: access denied, firewall, file
   check, enrollment refused, timeout), unreachable, not a PC.

### Linux

1. SSH login (password or key), check sudo (`sudo -n true`, else `sudo -S` with the password).
2. Copy the Linux agent and `install.sh` to `/tmp/provigil-<random>/`.
3. Run `install.sh` with the token and the computer name; collect the JSON result line.
4. Remove the temporary folder.

## 7. Results

`results.csv` columns: `computer, address, os, os_version, method, outcome, reason, agent_id, time`.
The same rows go to the console (C7), so the client's admin and our team see the same list.

## 8. Security

- Kit carries the deployment token (expiring, limited, revocable), never the tenant key.
- Deployment password: in memory during stage 1, then only as the one-time LSA secret, removed as the
  first step of stage 2; never in files, logs, results or the console. Linux secret: DPAPI
  LocalMachine, Administrators/SYSTEM-only file, deleted at the end of the run.
- Retries (if chosen): the Task Scheduler stored credential (Windows-protected), removed after 24 hours.
- Kit folder and the files copied to PCs: Administrators/SYSTEM only, removed after install.
- Every file SHA-256 checked before it is run; TLS with our CA for every connection to the cloud.
- Code signing of the scripts and programs (decision 13.1): client policies (AllSigned, AppLocker,
  Smart App Control) may block unsigned files.
- The run only covers networks and computers the client authorised in writing; the guide says so.
- Audit: the run, its admin PC and every PC result are kept in the console (C7).

## 9. Client checklist (goes in the kit guide)

- [ ] Written authorisation for the deployment (networks, date).
- [ ] Path A: domain account for ProVigil in all PCs' Administrators group.
      Path B: the same local administrator on all PCs, and `LocalAccountTokenFilterPolicy = 1`
      (or the built-in Administrator).
- [ ] `Test-Path \\PC-NAME\admin$` is `True` from the admin PC for a sample PC.
- [ ] File sharing (445) or remote PowerShell (5985) allowed from the admin PC to the PCs.
- [ ] Linux: SSH (22) on, one login with sudo.
- [ ] Outbound 8443 and 8089 from all PCs to the ProVigil cloud address (no proxy, or decision 13.4).
- [ ] Network ranges to scan; the security team informed.
- [ ] PCs switched on during the run (or within the 24-hour retries).

## 10. Tests (virtual machines only, never the dev PC)

| Lab | Machines | Checks |
|---|---|---|
| Path A | Domain controller, admin PC (Win 11), Win 10 and Win 11 members, Ubuntu, Rocky | Full run with a real reboot; auto-login and secret gone afterwards; all enroll with their own names; one PC off during the run is installed by a retry; one with the firewall closed is reported with the reason; GPO startup script installs a new PC at boot |
| Path B | Three workgroup PCs with the same local admin, one with a different password, one without `LocalAccountTokenFilterPolicy` | The first three installed; the other two reported "access denied" with the fix |
| Token | Simulated enrollments | Expiry, revoke and maximum enforced; a reinstall does not count twice |
| Failure | Kill stage 2 mid-run, wrong password, cloud unreachable | No auto-login left behind; clear messages; a rerun continues |
| Scale | 500 simulated targets (load-test agents) | Throttle 30 holds; results complete; console view fast |

Acceptance: on both labs, one run from the admin PC installs every reachable PC, each appears in the
console with its own name and ID within 5 minutes of its install, every unreachable PC is listed
with a reason, and no password or auto-login setting remains on the admin PC.

## 11. Plan and effort (estimates, one developer, working days)

| Step | Pieces | Effort |
|---|---|---|
| 1 | C1 computer-name enrollment, C2 deployment token (DB, gateway, siem-api, API) | 2.5 |
| 2 | C3 local install script + Group Policy startup use | 1.5 |
| 3 | C4 discovery and Windows push | 3 |
| 4 | C5 two-stage flow (auto-login, task, reboot, cleanup, retries, windows) | 3 |
| 5 | C4/C6 Linux push and `install.sh` changes | 2 |
| 6 | C7 results and console Deployment page, C8 kit download and guide | 3.5 |
| 7 | Labs (path A, path B), fixes, documentation | 3.5 |
|   | **Total** | **about 19 days** |

Each step is finished and tested before the next. Later, separate plan: an MSI package for Intune,
SCCM, Company Portal and Group Policy software install.

## 12. Risks

| Risk | Effect | Answer |
|---|---|---|
| Path B without `LocalAccountTokenFilterPolicy` | Push gets "access denied" | Use the built-in Administrator, or set it in the PC image; per-PC install otherwise |
| Client endpoint security flags the scan or the remote service | Run blocked or alarms | Tell their security team; `-ComputerList` instead of a scan; code signing |
| Unsigned scripts blocked by policy | Nothing runs | Code-signing certificate (13.1) |
| Corporate proxy only | Agents cannot reach the cloud | Proxy support in the agent (13.4) |
| PCs off or on VPN during the run | Not installed | 24-hour retries; GPO startup script (path A); rerun later |
| Auto-login left behind after a crash | Security gap | Cleanup is the first step of stage 2; `-Stage 1` cancel removes it; a stale-setting check at every run |
| Duplicate computer names | Two PCs as one agent | MAC suffix (C1) |

## 13. Open questions for the owner

1. Code-signing certificate for the kit: buy one?
2. Retries over 24 hours need the deployment password kept by Task Scheduler for that time: accept,
   or no retries (rerun by hand / GPO startup script)?
3. Token defaults: 7 days, maximum = expected PCs + 10%?
4. Proxy support in the agent: needed for clients that only reach the internet through a proxy?
5. Sysmon, audit policy and PowerShell logging on by default in the kit?

## 14. As built (differences from the plan above)

- Discovery and the Windows push are in `deploy-provigil.ps1` (PowerShell runspaces, `[adsisearcher]`,
  `sc.exe` / `schtasks.exe` / `Invoke-Command`), not in the Rust program: Windows' own tools carry
  the logged-in account's credentials to the admin share with no extra code. `provigil-deploy.exe`
  does what PowerShell 5.1 cannot do well: SSH (`push-linux`) and the report over TLS with the kit's
  CA (`report`; without rows it is stage 1's cloud and token check).
- Retries (decision 13.2): no stored password. A rerun with `-NoReboot -Retry` takes the PCs that
  failed or were unreachable; with a domain the Group Policy startup script catches PCs that were off.
- Runs are not a table of their own: the console shows per token the PCs reported (`deploy_targets`,
  main database, one row per PC, latest report wins) and the agents the token enrolled.
- The gateway's per-address enrollment limit (5 a minute) does not apply to deployment tokens: a
  client's PCs usually share one public address; the token's maximum and the total per-second limit
  still apply.
- Kit options: audit policy and PowerShell logging on by default in the console, Sysmon off
  (decision 13.5 proposed, owner to confirm).
- Not built: the MAC suffix for duplicate computer names (C1); the second PC with the same name would
  take over the first one's agent. Rare outside domains (Windows names are random by default).
- SSH host keys are accepted without a known-hosts check (client LAN, hosts the admin chose).
