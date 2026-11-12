# ProVigil deployment kit: guide

This kit installs the ProVigil agent on all your PCs (Windows 10, Windows 11, Windows Server and
Linux) from one run on one PC. Every PC enrolls itself with its own computer name and appears in the
ProVigil console. The kit contains a deployment token that expires and enrolls a limited number of
PCs; your administrator can revoke it in the console at any time (Agent Deployment).

## 1. Before you start (checklist)

- [ ] Written authorisation for this deployment (which networks, which date).
- [ ] Your security team knows: the run scans your networks and starts installs remotely, which
      endpoint security may report.
- [ ] A **deployment account** that is an administrator on every PC, including the PC you run from:
  - **With a domain (Active Directory):** a domain account (for example `CORP\provigil-deploy`) in
    every PC's Administrators group (Group Policy "Restricted Groups", or Domain Admins).
  - **Without a domain (workgroup):** a local account with the **same name and password** on every
    PC, and on each PC the registry value
    `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy = 1`
    (DWORD), or the built-in Administrator with the same password everywhere.
- [ ] From the PC you run from, as the deployment account, `Test-Path \\PC-NAME\admin$` gives `True`
      for a sample PC.
- [ ] File and Printer Sharing (TCP 445) or Windows Remote Management (TCP 5985) is allowed from the
      PC you run from to the other PCs.
- [ ] Linux PCs: SSH (TCP 22) on, and one login that may use `sudo` (password or key file).
- [ ] All PCs reach the ProVigil cloud: outbound TCP 8443 and 8089 to the address in `deploy.json`.
- [ ] PCs are switched on during the run.
- [ ] The PC you run from shows no logon notice ("legal notice") at sign-in: such a notice stops the
      automatic sign-in. Use `-NoReboot` (section 3) on such PCs.

Not possible: installing with only a standard user account on the target PCs. A Windows service and
a Linux service need administrator rights on each PC.

## 2. The normal run (with restart and automatic sign-in)

1. Unzip the kit, for example to `C:\ProVigilDeploy`.
2. Open **PowerShell as administrator** with your own administrator account and run:

   ```
   cd C:\ProVigilDeploy
   powershell -ExecutionPolicy Bypass -File .\deploy-provigil.ps1
   ```

3. The script checks the kit and the cloud, then asks for:
   - the deployment account (name and password; it is tested before anything changes);
   - the networks to scan (Enter keeps this PC's own networks);
   - an optional Linux SSH user, and its password or key file.
4. Type `YES`. The PC restarts after 60 seconds (press `C` to cancel and undo everything).
5. Windows signs in by itself **once** as the deployment account. The first thing the script does is
   remove the automatic sign-in and its stored password. It then installs the agent on this PC, finds
   the PCs (Active Directory when the PC is in a domain, plus the network scan), installs on Windows
   PCs 30 at a time and on Linux PCs over SSH.
6. A summary appears (installed, already installed, failed, access denied, unreachable). The full
   list is in `C:\ProgramData\ProVigilDeploy\logs\results.csv` and in the console. After two
   minutes, Windows signs out.

## 3. Other ways to run

| Command | What it does |
|---|---|
| `.\deploy-provigil.ps1 -DiscoverOnly -NoReboot` | Lists the PCs it would install on (`logs\discovered.csv`); installs nothing |
| `.\deploy-provigil.ps1 -NoReboot` | Everything now, in this session (you are signed in as the deployment account) |
| `.\deploy-provigil.ps1 -NoReboot -Retry` | Only the PCs that failed or were unreachable last time |
| `.\deploy-provigil.ps1 -ComputerList pcs.txt -NoReboot` | Only the PCs in the file (one name or address per line), no scan |
| `.\deploy-provigil.ps1 -SearchBase "OU=PCs,DC=corp,DC=local"` | Active Directory: only this OU |
| `.\deploy-provigil.ps1 -Ranges "10.1.0.0/24,10.2.0.0/23"` | Scan these networks (/16 to /32) |
| `.\deploy-provigil.ps1 -NoReboot -LinuxUser admin` | Linux PCs with this SSH user (asks for the password); `-LinuxKey file` for a key |
| `.\deploy-provigil.ps1 -Throttle 10` | Fewer installs at a time (default 30) |
| `.\deploy-provigil.ps1 -Local` | Installs on this PC only |
| `.\deploy-provigil.ps1 -Uninstall -ComputerList pcs.txt -NoReboot` | Removes the agent (open a maintenance window in the console first) |

## 4. With a domain: Group Policy startup script (optional)

This catches PCs that were off during the run and new PCs later, without any account:

1. Copy the kit folder to a share that Domain Computers may read, for example
   `\\fileserver\ProVigil$` (read-only).
2. Group Policy Management, a GPO linked to the PCs' OU:
   Computer Configuration > Policies > Windows Settings > Scripts > Startup > PowerShell Scripts >
   Add `\\fileserver\ProVigil$\install-provigil.ps1`.
3. At each start, every PC runs it as SYSTEM: it installs the agent when missing, and returns in a
   second when the agent is already installed and current. Its log: `C:\ProgramData\ProVigil-install.log`.

The token in the kit expires (see the console); create a new token and kit before then if the GPO
should keep installing new PCs.

## 5. When a PC is not installed

| Result | Meaning | Fix |
|---|---|---|
| access denied | The deployment account is not an administrator there | Domain: add it to the PC's Administrators. Workgroup: same local admin and password, `LocalAccountTokenFilterPolicy = 1` |
| unreachable | PC off, or ports 445 / 5985 / 22 closed | Switch it on, allow File and Printer Sharing from the admin PC, then `-Retry` |
| failed: the agent did not enroll | The PC cannot reach the cloud on 8443 / 8089, or the token expired or is used up | Open the outbound ports; check the token in the console |
| failed: kit file does not match | A file was changed or damaged | Download the kit again |
| not supported | Linux without systemd | Install by hand |
| not a PC | Answers ping only (printer, phone, switch) | Nothing to do |

Also possible for single PCs: the console's install command (Agent Deployment), run on that PC.

## 6. What stays behind

On the PC you ran from: nothing of the automatic sign-in (removed first in stage 2, and its count is
one), no stored password, no Linux password (deleted at the end), the kit and its logs in
`C:\ProgramData\ProVigilDeploy` (readable by administrators only; delete it when you are done). On
each PC: the agent in `C:\Program Files (x86)\ProVigil Agent` (or `/var/ossec` on Linux); the copied
install files are deleted after the install.
