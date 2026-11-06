import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, map, of } from 'rxjs';

/**
 * Agent deployment commands (the ProVigil agent, provigil-agent.exe, on Windows;
 * siem-agent-linux + install.sh on Linux).
 *
 * Every command carries the manager's addresses, its CA certificate (public), the
 * agent name, the group and the tenant's agent key. The agent enrolls itself over TLS
 * with that CA at its first start, and gets an agent id that is unique across all
 * tenants; the tenant key puts it in the right tenant. Re-running the command on the
 * same host keeps the same id, with a new key.
 */

export type DeployOs = 'linux' | 'windows' | 'macos';
export type WinInstallMode = 'auto-elevate' | 'admin-ps';

/** What the commands need from `/api/server-info`. */
export interface ServerInfo {
  https_url: string;
  grpc_url: string;
  ca_pem: string;
  /** `{name: sha256}` of the published Windows agent files. */
  agent_files: Record<string, string>;
}

export interface DeployParams {
  os: DeployOs;
  /** Without it no command is generated: an agent needs the CA to reach the manager. */
  server: ServerInfo | null;
  managerUrl: string;
  agentName: string;
  group: string;
  tenantKey: string;
  winMode: WinInstallMode;
  /** Windows: also install Sysmon (Microsoft Sysinternals) with the manager's configuration (`/downloads/windows/sysmon.xml`). */
  winSysmon?: boolean;
  /** Windows: turn on PowerShell script block (4104) and module (4103) logging. */
  winPsLogging?: boolean;
  /** Windows: the audit policy the detections need (logons, lockouts, account changes, process starts with command line). */
  winAuditPolicy?: boolean;
}

/** Audit subcategories by GUID (their names are translated in non-English Windows): [GUID, what, success, failure]. */
const AUDIT_SUBCATEGORIES: [string, string, boolean, boolean][] = [
  ['{0CCE923F-69AE-11D9-BED3-505054503030}', 'Credential Validation', true, true],
  ['{0CCE9215-69AE-11D9-BED3-505054503030}', 'Logon', true, true],
  ['{0CCE9217-69AE-11D9-BED3-505054503030}', 'Account Lockout', false, true],
  ['{0CCE9235-69AE-11D9-BED3-505054503030}', 'User Account Management', true, true],
  ['{0CCE9237-69AE-11D9-BED3-505054503030}', 'Security Group Management', true, false],
  ['{0CCE922B-69AE-11D9-BED3-505054503030}', 'Process Creation', true, false],
];

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
  if (p.winAuditPolicy) {
    // subcategory settings override the legacy category ones, else they may not apply
    const sets = AUDIT_SUBCATEGORIES.map(([guid, , ok, fail]) =>
      `& auditpol /set /subcategory:"${guid}"${ok ? ' /success:enable' : ''}${fail ? ' /failure:enable' : ''} | Out-Null; if ($LASTEXITCODE -ne 0) { throw "auditpol ${guid} exited with $LASTEXITCODE" }; `).join('');
    steps.push(
      `try { Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord; ` +
      sets +
      `$k = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit'; New-Item -Path $k -Force | Out-Null; ` +
      `Set-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord; ` +
      `Write-Host 'Windows audit policy set: ${AUDIT_SUBCATEGORIES.map(a => a[1]).join(', ')} (with command lines)' } ` +
      `catch { Write-Warning "Audit policy not changed: $_" }`,
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

export const WINDOWS_SERVICE = 'ProVigilSvc';
/** The service and folder of agents installed before the ProVigil rename (migrated on reinstall). */
export const LEGACY_WINDOWS_SERVICE = 'WazuhSvc';
export const LEGACY_WINDOWS_AGENT_DIR = '${env:ProgramFiles(x86)}\\ossec-agent';
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
      // a manager that does not know its LAN address: the address this console is reached at
      if (data?.manager_url && (isLoopbackManager(base) || !isLoopbackManager(data.manager_url))) return data.manager_url as string;
    }
  } catch {
    // network error — fall back to current origin
  }
  return defaultManagerUrl();
}

/** The manager's TLS addresses and CA; null when it has none (TLS failed at its start). */
export async function fetchServerInfo(): Promise<ServerInfo | null> {
  try {
    const res = await fetch(`${defaultManagerUrl()}/api/server-info`);
    const data = res.ok ? await res.json() : null;
    return data?.https_url && data?.grpc_url && data?.ca_pem ? data : null;
  } catch {
    return null;
  }
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

/** An address of the manager on the host the console is reached at (its scheme and port stay). */
function onConsoleHost(url: string, consoleUrl: string): string {
  try {
    const host = new URL(consoleUrl).hostname;
    return url.replace(/^(\w+:\/\/).*(:\d+)$/, (_, scheme, port) => scheme + host + port);
  } catch {
    return url;
  }
}

/** Install directory of the Windows agent (the MSI's default). */
export const WINDOWS_AGENT_DIR = '${env:ProgramFiles(x86)}\\ProVigil Agent';

/** The files of the Windows agent package served by the manager: the agent alone (its settings
 *  are written by this script into provigil-agent.json; no upstream configuration files). */
const WINDOWS_AGENT_FILES = ['provigil-agent.exe'];

/** The active-response programs installed in active-response\bin. */
const WINDOWS_AR_FILES = ['netsh.exe', 'restart-agent.exe', 'route-null.exe', 'kill-process.exe', 'quarantine-file.exe', 'isolate-host.exe', 'yara-scan.exe', 'live-response.exe', 'tamper-protect.exe'];

/** The folders the ProVigil agent uses under its install directory. */
const WINDOWS_AGENT_DIRS = ['active-response\\bin', 'bookmarks', 'data', 'logs', 'shared', 'upgrade'];

/** `icacls` steps of the MSI (S-1-5-32-544 Administrators, S-1-5-18 SYSTEM, S-1-5-11 Authenticated Users). */
const WINDOWS_AGENT_ACLS = [
  `icacls "$d" /reset /t /q | Out-Null`,
  `icacls "$d" /inheritancelevel:r /q | Out-Null`,
  `icacls "$d" /grant '*S-1-5-32-544:(OI)(CI)F' /q | Out-Null`,
  `icacls "$d" /grant '*S-1-5-18:(OI)(CI)F' /q | Out-Null`,
  `icacls "$d\\*" /grant '*S-1-5-11:(OI)(CI)RX' /q | Out-Null`,
  `icacls "$d\\*" /grant '*S-1-5-11:RX' /q | Out-Null`,
  `icacls "$d" /grant '*S-1-5-11:RX' /q | Out-Null`,
  `icacls "$d\\provigil-agent.json" /remove '*S-1-5-11' /q | Out-Null`,
];

/**
 * The PowerShell that installs the ProVigil agent (`provigil-agent.exe`, the
 * `ProVigilSvc` service) like the MSI does, and starts it (needs admin). An agent
 * installed before the rename (`WazuhSvc`, `ossec-agent`) is replaced: its service is
 * removed, and the host keeps its agent name, so its agent id.
 * Each download is checked against the SHA-256 from the manager (Windows PowerShell 5.1 cannot
 * pin a CA for one request, so they may come over plain HTTP) before anything is changed. It
 * then writes the CA and `provigil-agent.json`, starts the service, and waits for the agent to
 * enroll itself over TLS: no key is ever handled here.
 */
export function windowsInstallScript(p: DeployParams): string {
  const c = clean(p);
  const s = p.server!;
  const files = [...WINDOWS_AGENT_FILES, ...WINDOWS_AR_FILES].filter(f => s.agent_files[f]);
  // a double-quoted string on one line: the script may be pasted
  const caPem = pq(s.ca_pem).replace(/\r?\n/g, '`n');
  return [
    `$ErrorActionPreference = 'Stop'`,
    `$ProgressPreference = 'SilentlyContinue'`,
    `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`,
    `$u = ${pq(c.url)}`,
    `$d = "${WINDOWS_AGENT_DIR}"`,
    `$m = ${pq(onConsoleHost(s.https_url, c.url))}`,
    `$hash = @{ ${files.map(f => `'${f}' = '${s.agent_files[f]}'`).join('; ')} }`,
    `$t = Join-Path $env:TEMP ('provigil-' + [guid]::NewGuid()); New-Item -ItemType Directory -Path $t | Out-Null`,
    // all checked before the service stops: a bad file leaves the installed agent as it was
    `foreach ($f in $hash.Keys) { Invoke-WebRequest -UseBasicParsing -Uri "$u/downloads/windows/$f" -OutFile "$t\\$f"; if ((Get-FileHash -Algorithm SHA256 -LiteralPath "$t\\$f").Hash -ne $hash[$f]) { Remove-Item -Recurse -Force $t; throw "$f does not match the manager's SHA-256: nothing was installed. If the agent was published again, generate this command again." } }`,
    `if (Get-Service ${WINDOWS_SERVICE} -ErrorAction SilentlyContinue) { Stop-Service ${WINDOWS_SERVICE} -Force -ErrorAction SilentlyContinue }`,
    // the agent from before the rename: removed (with tamper protection on, open a maintenance window first)
    `if (Get-Service ${LEGACY_WINDOWS_SERVICE} -ErrorAction SilentlyContinue) { Stop-Service ${LEGACY_WINDOWS_SERVICE} -Force -ErrorAction SilentlyContinue; sc.exe delete ${LEGACY_WINDOWS_SERVICE} | Out-Null }`,
    `foreach ($s in @(${WINDOWS_AGENT_DIRS.map(x => `'${x}'`).join(',')})) { New-Item -ItemType Directory -Force -Path "$d\\$s" | Out-Null }`,
    `if (-not (Test-Path "$d\\active-response\\active-responses.log")) { New-Item -ItemType File -Path "$d\\active-response\\active-responses.log" | Out-Null }`,
    `Move-Item -Force -LiteralPath "$t\\provigil-agent.exe" -Destination "$d\\provigil-agent.exe"`,
    // the active responses the manager can run on the agent (netsh firewall block, restart)
    `Get-ChildItem -LiteralPath $t | Move-Item -Force -Destination "$d\\active-response\\bin"`,
    `Remove-Item -Recurse -Force $t`,
    // a reinstall keeps the host's agent name (and so its id) instead of adding a second agent
    `$n = ${pq(c.name)}`,
    `$old = "${LEGACY_WINDOWS_AGENT_DIR}"`,
    `foreach ($f in @("$old\\client.keys", "$d\\client.keys")) { if (Test-Path $f) { $k = ((Get-Content $f -TotalCount 1) -split ' '); if ($k.Count -ge 4 -and $k[1]) { $n = $k[1] } } }`,
    `$id = "$d\\data\\agent-identity.json"`,
    `if (Test-Path $id) { try { $i = Get-Content -Raw $id | ConvertFrom-Json; if ($i.agent_name) { $n = $i.agent_name } } catch { } }`,
    // the agent enrolls again, for a new key: nothing of the old enrollment stays
    `Remove-Item -Force -ErrorAction SilentlyContinue $id, "$d\\data\\force-enroll-used", "$d\\client.keys", "$d\\data\\client.keys"`,
    // UTF-8 without BOM (WriteAllText)
    `[IO.File]::WriteAllText("$d\\ca.pem", ${caPem})`,
    // the agent's settings: the manager's addresses on the host this console is reached at
    // (never a fixed IP), its CA, the tenant key and the name
    `$cfg = @{ manager_url = $m; grpc_url = ${pq(onConsoleHost(s.grpc_url, c.url))}; ca_file = "$d\\ca.pem"; agent_name = $n; groups = ${pq(c.group)}; force_enroll = $true }`,
    c.key ? `$cfg['tenant_key'] = ${pq(c.key)}` : `$null = $cfg`,
    `[IO.File]::WriteAllText("$d\\provigil-agent.json", ($cfg | ConvertTo-Json))`,
    // the MSI's permissions (InstallerScripts.vbs): only Administrators and SYSTEM may read the key
    ...WINDOWS_AGENT_ACLS,
    `& "$d\\provigil-agent.exe" install-service | Out-Null`,
    `Start-Service -Name ${WINDOWS_SERVICE}`,
    // the agent writes its identity once the manager enrolled it over TLS
    `$w = 0; while (-not (Test-Path $id) -and $w -lt 60) { Start-Sleep -Seconds 2; $w += 2 }`,
    `if (-not (Test-Path $id)) { throw "The agent did not enroll with $m within 60 s. Check that this computer reaches that address, that it is one the manager's certificate names, and the tenant key; the reason is in $d\\logs\\provigil-agent.log" }`,
    `Start-Sleep -Seconds 1; $r = Get-Content -Raw $id | ConvertFrom-Json`,
    `Write-Host "ProVigil agent $($r.agent_id) ($($r.agent_name)) installed; connected to $m"`,
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

/** The Linux agent's settings for install.sh: its CA in `$t/ca.pem`. */
function linuxEnv(p: DeployParams): string[] {
  const c = clean(p);
  return [
    `SIEM_MANAGER_URL=${sq(onConsoleHost(p.server!.https_url, c.url))}`,
    `SIEM_CA_FILE="$t/ca.pem"`,
    `SIEM_AGENT_NAME=${sq(c.name)}`,
    `SIEM_AGENT_GROUP=${sq(c.group)}`,
    `SIEM_TENANT_KEY=${sq(c.key)}`,
  ];
}

/** Writes the CA to a new `$t`, then fetches install.sh from the manager over TLS with it. */
function linuxFetch(p: DeployParams): string {
  const url = onConsoleHost(p.server!.https_url, clean(p).url);
  return `t=$(mktemp -d) && printf %s ${sq(btoa(p.server!.ca_pem))} | base64 -d > "$t/ca.pem" && curl -fsSL --cacert "$t/ca.pem" ${sq(url + '/downloads/install.sh')} -o "$t/install.sh"`;
}

/** The command to paste on the endpoint ('' until the manager's TLS details are known). */
export function installCommand(p: DeployParams): string {
  if (!canDeploy(p)) return '';
  if (p.os === 'windows') {
    const script = windowsInstallScript(p);
    if (p.winMode === 'admin-ps') return script;
    // Auto-elevate: re-launch the same script in an elevated PowerShell (UAC prompt).
    return `Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -NoExit -ExecutionPolicy Bypass -EncodedCommand ${encodePs(script)}'`;
  }
  if (p.os === 'linux') {
    return `${linuxFetch(p)} && sudo ${linuxEnv(p).join(' ')} bash "$t/install.sh"; rm -rf "$t"`;
  }
  return '';
}

/** The manager's TLS details are there, and for Windows the agent program is published. */
export function canDeploy(p: DeployParams): boolean {
  return !!p.server && (p.os !== 'windows' || !!p.server.agent_files['provigil-agent.exe']);
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
  return [
    '#!/bin/bash',
    '# SIEM agent deployment: downloads install.sh from the manager over TLS, enrolls the agent and starts it.',
    'set -e',
    'if [ "$EUID" -ne 0 ]; then exec sudo bash "$0" "$@"; fi',
    linuxFetch(p),
    `trap 'rm -rf "$t"' EXIT`,
    `${linuxEnv(p).join(' ')} bash "$t/install.sh"`,
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
