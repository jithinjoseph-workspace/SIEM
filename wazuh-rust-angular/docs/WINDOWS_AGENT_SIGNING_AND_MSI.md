# Windows agent: code signing and MSI installer (planned)

Status: **planned, not started.** The agent itself is ready to package; this
document records what is missing and the steps to finish it later.

## Why it is needed

| Today | Problem for production |
|---|---|
| The deploy wizard gives a PowerShell command that downloads `wazuh-agent.exe` and the other files from the manager, enrolls, sets the ACLs and installs the service | Fine for tests and small fleets, but IT teams deploy with GPO, Intune or SCCM, and those expect an **MSI** |
| `wazuh-agent.exe`, `netsh.exe`, `restart-wazuh.exe`, `route-null.exe` are **unsigned** | SmartScreen and many EDR/antivirus products warn about or block unsigned binaries that run as SYSTEM. This can only be fixed with a real certificate, not in code |

## Two different kinds of signing (do not mix them up)

| | Authenticode (this document) | WPK signing (see `AGENT_RELEASE_AND_UPDATE_PLAN.md`) |
|---|---|---|
| What is signed | The `.exe` files and the `.msi` | The upgrade package (`.wpk`) sent by the manager |
| Who checks it | Windows, SmartScreen, antivirus | Our agent (`siem-winagent/src/upgrade.rs`) against `wpk_root.pem` |
| Certificate | Bought from a public CA (Sectigo, DigiCert, …) | Our own platform CA, no purchase needed |

## What to buy / prepare

1. **Code-signing certificate.**
   - EV (Extended Validation) is recommended: SmartScreen trusts it immediately.
     About $250–500 / year. Since 2023 the private key must live on a hardware
     token or a cloud HSM (e.g. DigiCert KeyLocker, Azure Trusted Signing).
   - **Azure Trusted Signing** (about $10 / month) is the cheapest option if the
     company qualifies (needs a verified organisation, 3+ years of history).
   - An OV certificate is cheaper but SmartScreen warns until the files build up
     reputation.
2. **Tools** on the build machine (both free):
   - `signtool.exe` from the Windows SDK.
   - WiX Toolset v5: `dotnet tool install --global wix` (.NET 8 is already installed here).
3. **Decide** the product name, publisher name and a fixed `UpgradeCode` GUID
   (it must never change, or upgrades install side by side).

## Steps

### 1. Sign the binaries
Sign every exe after `cargo build --release` and before packaging, with a timestamp
so the signature stays valid after the certificate expires:

```
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /n "<Company>" ^
  wazuh-agent.exe netsh.exe restart-wazuh.exe route-null.exe
signtool verify /pa /v wazuh-agent.exe
```

Then copy the signed files to `backend-rust/data/agent-dist/windows/` (what the
manager serves today) with `scratchpad/stage_dist.sh` or its build-script replacement.

### 2. Build the MSI (WiX)
The MSI must do exactly what the current install script does
(`ndr-ui/src/services/siem/agent-deploy.ts`, `windowsInstallScript`). That script was
written to copy Wazuh's own MSI (`wazuh-installer.wxs`, `InstallerScripts.vbs`), so use
the Wazuh 4.14.7 `.wxs` as the reference:

- Install to `C:\Program Files (x86)\ossec-agent` with the same folders
  (`WINDOWS_AGENT_DIRS`) and files (`WINDOWS_AGENT_FILES`, `WINDOWS_AR_FILES` into
  `active-response\bin`, `norm_config.json`, the CIS policies).
- Pick the CIS SCA policy by Windows build / workstation-or-server (same table as the script).
- Set the ACLs: only Administrators and SYSTEM can read `client.keys` and the config (`WINDOWS_AGENT_ACLS`).
- Register the service `WazuhSvc` (`wazuh-agent.exe install-service`) and start it.
- MSI properties for silent installs, e.g.
  `msiexec /i siem-agent.msi /qn MANAGER_URL=https://siem.example.com TENANT_KEY=... AGENT_GROUP=default [AGENT_NAME=...]`
  - Enrollment runs as a custom action calling `POST /api/v1/agents/enroll` with
    `X-Tenant-Key` (or the agent's own enrollment code, if we add it), writes `client.keys`.
  - `ossec.conf` with the manager address (today downloaded from `/downloads/windows/ossec.conf?manager=`).
- **Upgrade:** `MajorUpgrade` with the fixed `UpgradeCode`; keep `client.keys`,
  `ossec.conf` and `queue\` (the agent's state) so a reinstall keeps its id.
- **Uninstall:** stop and remove the service; leave `client.keys` only if we choose
  to (Wazuh removes everything except logs).
- Sign the `.msi` with the same `signtool` command.

### 3. Hook it into the platform
- Manager serves the MSI at `/downloads/windows/siem-agent.msi`.
- Deploy wizard: add a "Download MSI" option and show the `msiexec` silent command
  (with the tenant key and group filled in), next to the existing PowerShell command.
- WPK upgrades: the WPK's `upgrade.bat` should run `msiexec /i siem-agent.msi /qn`
  (that is what Wazuh's Windows WPK does), so upgrades and fresh installs use the
  same installer. Ties in with `AGENT_RELEASE_AND_UPDATE_PLAN.md` step 1.

### 4. Test
- Fresh install, silent install, reinstall same version, upgrade from older MSI,
  uninstall — on Windows 10, 11, Server 2019/2022.
- After each: service running, agent connected, same agent id after reinstall/upgrade,
  `client.keys` ACL correct, `signtool verify /pa` passes on every installed exe.
- Run `scratchpad/admin_checks.ps1` style checks (FIM/whodata, upgrade, service stop) on the installed agent.

## Open decisions
- Which certificate (EV token, cloud HSM, or Azure Trusted Signing) and which company name.
- Where signing runs (a build machine with the token, or CI with a cloud HSM).
- Should uninstall keep `client.keys` (re-install keeps the id) or remove everything like Wazuh?

## Effort (rough)
- Signing binaries in the build: half a day once the certificate exists.
- MSI with enrollment custom action, upgrade and uninstall: 2–3 days.
- Deploy wizard + WPK `upgrade.bat` change + test matrix: 1–2 days.
