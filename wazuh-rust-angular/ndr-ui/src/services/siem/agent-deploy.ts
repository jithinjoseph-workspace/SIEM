import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, map, of } from 'rxjs';

/**
 * Agent deployment commands (the Wazuh agent, wazuh-agent.exe, on Windows;
 * siem-agent-linux + install.sh on Linux).
 *
 * Every command passes the manager URL, the agent name, the group and the
 * tenant's agent key. On first start the agent enrolls with the manager
 * (POST /api/v1/agents/enroll), gets an agent id that is unique across all
 * tenants and keeps it in client.keys; the tenant key puts it in the right
 * tenant. Re-running the command on the same host keeps the same id.
 */

export type DeployOs = 'linux' | 'windows' | 'macos';
export type WinInstallMode = 'auto-elevate' | 'admin-ps';

export interface DeployParams {
  os: DeployOs;
  managerUrl: string;
  agentName: string;
  group: string;
  tenantKey: string;
  winMode: WinInstallMode;
  /** Windows: also install Sysmon (Microsoft Sysinternals) with the manager's configuration (`/downloads/windows/sysmon.xml`). */
  winSysmon?: boolean;
  /** Windows: turn on PowerShell script block (4104) and module (4103) logging. */
  winPsLogging?: boolean;
}

/**
 * The optional Windows logging steps; they run after the agent is installed and started,
 * and a failure only warns (the agent is not affected). The agents' shared config
 * collects the Sysmon and PowerShell logs (etc/shared/default/agent.conf).
 */
function windowsLoggingSteps(p: DeployParams): string[] {
  const steps: string[] = [];
  if (p.winPsLogging) {
    steps.push(
      `try { $k = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell'; ` +
      `New-Item -Path "$k\\ScriptBlockLogging" -Force | Out-Null; Set-ItemProperty -Path "$k\\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord; ` +
      `New-Item -Path "$k\\ModuleLogging\\ModuleNames" -Force | Out-Null; Set-ItemProperty -Path "$k\\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord; ` +
      `Set-ItemProperty -Path "$k\\ModuleLogging\\ModuleNames" -Name '*' -Value '*'; Write-Host 'PowerShell script block and module logging turned on' } ` +
      `catch { Write-Warning "PowerShell logging not changed: $_" }`,
    );
  }
  if (p.winSysmon) {
    // Sysmon only from Microsoft over HTTPS, run only if Microsoft signed it; an installed
    // Sysmon gets the configuration (-c), so re-running the command updates the fleet's
    steps.push(
      `try { $t = Join-Path $env:TEMP ('sysmon-' + [guid]::NewGuid()); New-Item -ItemType Directory -Path $t | Out-Null; try { ` +
      `Invoke-WebRequest -UseBasicParsing -Uri "$u/downloads/windows/sysmon.xml" -OutFile "$t\\sysmon.xml"; [xml](Get-Content -Raw "$t\\sysmon.xml") | Out-Null; ` +
      `$svc = Get-CimInstance Win32_Service -Filter "Name='Sysmon64' OR Name='Sysmon64a' OR Name='Sysmon'" | Select-Object -First 1; ` +
      `if ($svc) { $exe = $svc.PathName.Trim('"'); $op = '-c' } else { ` +
      `Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$t\\Sysmon.zip"; Expand-Archive -Path "$t\\Sysmon.zip" -DestinationPath $t -Force; ` +
      `$exe = Join-Path $t $(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'Sysmon64a.exe' } elseif ([Environment]::Is64BitOperatingSystem) { 'Sysmon64.exe' } else { 'Sysmon.exe' }); $op = '-i' }; ` +
      `$sig = Get-AuthenticodeSignature $exe; ` +
      `if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation,' -or $sig.SignerCertificate.Issuer -notmatch 'O=Microsoft Corporation,') { throw "$exe is not signed by Microsoft ($($sig.Status))" }; ` +
      // Sysmon writes UTF-16 to stderr (an error under 'Stop'): drop the NULs, keep its last
      // lines as the reason of a failure
      `$eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; ` +
      `$o = (& $exe -accepteula $op "$t\\sysmon.xml" 2>&1 | Out-String) -replace [char]0, ''; $ErrorActionPreference = $eap; ` +
      `if ($LASTEXITCODE -ne 0) { throw "Sysmon $op exited with $($LASTEXITCODE): $((($o -split '\\r?\\n') | Where-Object { $_.Trim() } | Select-Object -Last 3) -join ' / ')" }; ` +
      `Write-Host $(if ($op -eq '-c') { 'Sysmon configuration updated' } else { 'Sysmon installed with the SIEM configuration' }) ` +
      `} finally { Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue } } ` +
      `catch { Write-Warning "Sysmon not installed: $_" }`,
    );
  }
  return steps;
}

export const WINDOWS_SERVICE = 'WazuhSvc';
export const LINUX_SERVICE = 'wazuh-rust-agent';

/** Default manager URL: the console's own origin (the dev server and Caddy
 *  both forward /api and /downloads to siem-api).
 *  Always uses the real hostname/IP the browser connected to — no hardcoded IPs. */
export function defaultManagerUrl(): string {
  if (typeof window === 'undefined') return 'http://127.0.0.1:8088';
  return `${window.location.protocol}//${window.location.host}`;
}

/** Async version: asks the backend for its LAN IP so deploy commands point to
 *  the right address even when the UI is accessed via localhost (e.g. developer
 *  running `ng serve` while agents need to reach the real LAN IP).
 *  Falls back to defaultManagerUrl() on any error. */
export async function fetchManagerUrl(): Promise<string> {
  try {
    const base = defaultManagerUrl();
    const res = await fetch(`${base}/api/server-info`);
    if (res.ok) {
      const data = await res.json();
      if (data?.manager_url) return data.manager_url as string;
    }
  } catch {
    // network error — fall back to current origin
  }
  return defaultManagerUrl();
}

/** True when the manager URL points at this machine (localhost, 127.x, ::1): the
 *  agent can only reach it when installed on the manager host itself. */
export function isLoopbackManager(url: string): boolean {
  try {
    const h = new URL(url.trim()).hostname.replace(/^\[|\]$/g, '');
    return h === 'localhost' || h === '::1' || /^127\./.test(h);
  } catch {
    return false;
  }
}

/** Wazuh agent names: letters, digits, '.', '_', '-' (2..128 chars). */
export function isValidAgentName(name: string): boolean {
  return /^[A-Za-z0-9._-]{2,128}$/.test(name);
}

/** A new agent name such as `linux-node-7f3a`, unique among `taken`. */
export function generateAgentName(os: DeployOs, taken: Iterable<string> = []): string {
  const prefix = os === 'windows' ? 'win-node' : os === 'macos' ? 'mac-node' : 'linux-node';
  const used = new Set([...taken].map(n => n.toLowerCase()));
  for (let i = 0; i < 50; i++) {
    const suffix = Math.floor(Math.random() * 0x10000).toString(16).padStart(4, '0');
    const name = `${prefix}-${suffix}`;
    if (!used.has(name)) return name;
  }
  return `${prefix}-${Date.now().toString(36)}`;
}

function clean(p: DeployParams) {
  return {
    url: (p.managerUrl || defaultManagerUrl()).trim().replace(/\/+$/, ''),
    name: p.agentName.trim(),
    group: (p.group || 'default').trim() || 'default',
    key: (p.tenantKey || '').trim(),
  };
}

/** Single-quote for POSIX shells. */
const sq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
/** Double-quote for PowerShell. */
const pq = (s: string) => `"${s.replace(/[`"$]/g, m => '`' + m)}"`;

/** Install directory of the Windows agent (the MSI's default). */
export const WINDOWS_AGENT_DIR = '${env:ProgramFiles(x86)}\\ossec-agent';

/** The files of the Windows agent package served by the manager. */
const WINDOWS_AGENT_FILES = ['wazuh-agent.exe', 'internal_options.conf', 'local_internal_options.conf', 'vista_sec.txt', 'help.txt'];

/** The active-response programs installed in active-response\bin. */
const WINDOWS_AR_FILES = ['netsh.exe', 'restart-wazuh.exe', 'route-null.exe', 'kill-process.exe', 'quarantine-file.exe', 'isolate-host.exe'];

/** The directories the MSI creates under the install directory. */
const WINDOWS_AGENT_DIRS = [
  'active-response\\bin', 'bookmarks', 'incoming', 'logs', 'queue\\diff', 'queue\\fim\\db', 'queue\\syscollector\\db',
  'queue\\logcollector', 'rids', 'ruleset\\sca', 'shared', 'syscheck', 'tmp', 'upgrade', 'wodles',
];

/** `icacls` steps of the MSI (S-1-5-32-544 Administrators, S-1-5-18 SYSTEM, S-1-5-11 Authenticated Users). */
const WINDOWS_AGENT_ACLS = [
  `icacls "$d" /reset /t /q | Out-Null`,
  `icacls "$d" /inheritancelevel:r /q | Out-Null`,
  `icacls "$d" /grant '*S-1-5-32-544:(OI)(CI)F' /q | Out-Null`,
  `icacls "$d" /grant '*S-1-5-18:(OI)(CI)F' /q | Out-Null`,
  `icacls "$d\\*" /grant '*S-1-5-11:(OI)(CI)RX' /q | Out-Null`,
  `icacls "$d\\*" /grant '*S-1-5-11:RX' /q | Out-Null`,
  `icacls "$d" /grant '*S-1-5-11:RX' /q | Out-Null`,
  `icacls "$d\\*ossec.conf" /remove '*S-1-5-11' /q | Out-Null`,
  `icacls "$d\\client.keys" /remove '*S-1-5-11' /q | Out-Null`,
];

/**
 * The PowerShell that installs the Wazuh agent (`wazuh-agent.exe`, the
 * `WazuhSvc` service) like the MSI does, and starts it (needs admin):
 * downloads the package, enrolls through the manager API (the tenant key
 * picks the tenant), writes `client.keys` and `ossec.conf` (manager address
 * = the console host, port 1514/tcp), installs and starts the service.
 */
export function windowsInstallScript(p: DeployParams): string {
  const c = clean(p);
  return [
    `$ErrorActionPreference = 'Stop'`,
    `$ProgressPreference = 'SilentlyContinue'`,
    `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`,
    `$u = ${pq(c.url)}`,
    `$d = "${WINDOWS_AGENT_DIR}"`,
    `if (Get-Service ${WINDOWS_SERVICE} -ErrorAction SilentlyContinue) { Stop-Service ${WINDOWS_SERVICE} -Force -ErrorAction SilentlyContinue }`,
    `foreach ($s in @(${WINDOWS_AGENT_DIRS.map(x => `'${x}'`).join(',')})) { New-Item -ItemType Directory -Force -Path "$d\\$s" | Out-Null }`,
    `if (-not (Test-Path "$d\\active-response\\active-responses.log")) { New-Item -ItemType File -Path "$d\\active-response\\active-responses.log" | Out-Null }`,
    `foreach ($f in @(${WINDOWS_AGENT_FILES.map(x => `'${x}'`).join(',')})) { Invoke-WebRequest -UseBasicParsing -Uri "$u/downloads/windows/$f" -OutFile "$d\\$f" }`,
    // the active responses the manager can run on the agent (netsh firewall block, restart)
    `foreach ($f in @(${WINDOWS_AR_FILES.map(x => `'${x}'`).join(',')})) { try { Invoke-WebRequest -UseBasicParsing -Uri "$u/downloads/windows/$f" -OutFile "$d\\active-response\\bin\\$f" } catch { Write-Warning "Active response $f not available from the manager" } }`,
    // where the MSI installs the syscollector normalizer
    `Invoke-WebRequest -UseBasicParsing -Uri "$u/downloads/windows/norm_config.json" -OutFile "$d\\queue\\syscollector\\norm_config.json"`,
    // the CIS policy the MSI installs for this OS (wazuh-installer.wxs: build number, workstation or server)
    `$os = Get-CimInstance Win32_OperatingSystem; $b = [int]$os.BuildNumber`,
    `$sca = if ($os.ProductType -eq 1) { if ($b -ge 22000) { 'cis_win11_enterprise.yml' } elseif ($b -ge 10240) { 'cis_win10_enterprise.yml' } } else { @{ 9200 = 'cis_win2012_non_r2.yml'; 9600 = 'cis_win2012r2.yml'; 14393 = 'cis_win2016.yml'; 17763 = 'cis_win2019.yml'; 20348 = 'cis_win2022.yml'; 26100 = 'cis_win2025.yml' }[$b] }`,
    // optional: a manager without the policy still installs the agent
    `if ($sca) { try { Invoke-WebRequest -UseBasicParsing -Uri "$u/downloads/windows/$sca" -OutFile "$d\\ruleset\\sca\\$sca" } catch { Write-Warning "SCA policy $sca not available from the manager" } }`,
    `$m = ([Uri]$u).Host`,
    `Invoke-WebRequest -UseBasicParsing -Uri "$u/downloads/windows/ossec.conf?manager=$m" -OutFile "$d\\ossec.conf"`,
    // enroll last, so a failed download leaves no never-connected agent; a reinstall keeps
    // the host's agent name (and so its id) instead of adding a second agent
    `$n = ${pq(c.name)}`,
    `if (Test-Path "$d\\client.keys") { $k = ((Get-Content "$d\\client.keys" -TotalCount 1) -split ' '); if ($k.Count -ge 4 -and $k[1]) { $n = $k[1] } }`,
    `$h = @{}`,
    c.key ? `$h['X-Tenant-Key'] = ${pq(c.key)}` : `$null = $h`,
    `$b = @{ name = $n; groups = ${pq(c.group)}; os_type = 'windows'; force = $true } | ConvertTo-Json`,
    `$r = Invoke-RestMethod -Method Post -Uri "$u/api/v1/agents/enroll" -Headers $h -ContentType 'application/json' -Body $b`,
    `[IO.File]::WriteAllText("$d\\client.keys", "$($r.agent_id) $($r.agent_name) $($r.agent_ip) $($r.raw_key)` + '`n' + `")`,
    // the MSI's permissions (InstallerScripts.vbs): only Administrators and SYSTEM may read the key
    ...WINDOWS_AGENT_ACLS,
    `& "$d\\wazuh-agent.exe" install-service | Out-Null`,
    `Start-Service -Name ${WINDOWS_SERVICE}`,
    `Write-Host "Wazuh agent $($r.agent_id) ($($r.agent_name)) installed; manager $($m):1514"`,
    ...windowsLoggingSteps(p),
    `Get-Service ${WINDOWS_SERVICE}`,
  ].join('; ');
}

/** UTF-16LE base64, for `powershell -EncodedCommand`. */
function encodePs(script: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < script.length; i++) {
    const code = script.charCodeAt(i);
    bytes.push(code & 0xff, code >> 8);
  }
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** The command to paste on the endpoint. */
export function installCommand(p: DeployParams): string {
  const c = clean(p);
  if (p.os === 'windows') {
    const script = windowsInstallScript(p);
    if (p.winMode === 'admin-ps') return script;
    // Auto-elevate: re-launch the same script in an elevated PowerShell (UAC prompt).
    return `Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -NoExit -ExecutionPolicy Bypass -EncodedCommand ${encodePs(script)}'`;
  }
  if (p.os === 'linux') {
    const env = [
      `SIEM_MANAGER_URL=${sq(c.url)}`,
      `SIEM_AGENT_NAME=${sq(c.name)}`,
      `SIEM_AGENT_GROUP=${sq(c.group)}`,
      `SIEM_TENANT_KEY=${sq(c.key)}`,
    ].join(' ');
    return `curl -sSL ${sq(c.url + '/downloads/install.sh')} | sudo ${env} bash`;
  }
  return '';
}

/** The command that (re)starts the agent service and shows its state. */
export function startCommand(p: DeployParams): string {
  if (p.os === 'windows') return `Start-Service -Name ${WINDOWS_SERVICE}; Get-Service ${WINDOWS_SERVICE}`;
  if (p.os === 'linux') return `sudo systemctl restart ${LINUX_SERVICE} && sudo systemctl status ${LINUX_SERVICE} --no-pager`;
  return '';
}

/** One-click Windows .bat (asks for elevation, then runs the installer). */
export function windowsBatScript(p: DeployParams): string {
  const script = windowsInstallScript(p);
  return [
    '@echo off',
    'title SIEM Agent Installer',
    'net session >nul 2>&1',
    'if %errorlevel% neq 0 (',
    '  powershell -NoProfile -Command "Start-Process -FilePath \'%~f0\' -Verb RunAs"',
    '  exit /b',
    ')',
    `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encodePs(script)}`,
    'pause',
    '',
  ].join('\r\n');
}

/** Linux deployment script (same as the one-liner, as a file). */
export function linuxDeployScript(p: DeployParams): string {
  const c = clean(p);
  return [
    '#!/bin/bash',
    '# SIEM agent deployment: downloads install.sh from the manager, enrolls the agent and starts it.',
    'set -e',
    `export SIEM_MANAGER_URL=${sq(c.url)}`,
    `export SIEM_AGENT_NAME=${sq(c.name)}`,
    `export SIEM_AGENT_GROUP=${sq(c.group)}`,
    `export SIEM_TENANT_KEY=${sq(c.key)}`,
    'if [ "$EUID" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi',
    `curl -sSL "$SIEM_MANAGER_URL/downloads/install.sh" | bash`,
    '',
  ].join('\n');
}

export function downloadText(filename: string, text: string, mime = 'text/plain') {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/** Fetches the caller's tenant agent key (siem-api, X-Tenant-Key). */
@Injectable({ providedIn: 'root' })
export class AgentDeployService {
  private http = inject(HttpClient);

  /** `key` is '' when the user may not read it (then agents join the default tenant). */
  tenantKey(): Observable<{ key: string; tenant: string; error?: string }> {
    return this.http.get<any>('/api/v1/tenant/agent-key').pipe(
      map(r => ({ key: r?.agent_key || '', tenant: r?.tenant_id || '' })),
      catchError(err =>
        of({
          key: '',
          tenant: '',
          error: err?.status === 403 ? 'You are not allowed to read this tenant\'s agent key.' : 'Could not load the tenant agent key.',
        }),
      ),
    );
  }
}
