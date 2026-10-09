import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, map, of } from 'rxjs';

/**
 * Agent deployment commands for the SIEM agents (siem-agent.exe on Windows,
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
}

export const WINDOWS_SERVICE = 'WazuhRustSvc';
export const LINUX_SERVICE = 'wazuh-rust-agent';

/** Default manager URL: the console's own origin (the dev server and Caddy
 *  both forward /api and /downloads to siem-api). */
export function defaultManagerUrl(): string {
  if (typeof window === 'undefined') return 'http://127.0.0.1:8088';
  return `${window.location.protocol}//${window.location.host}`;
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

/** The PowerShell that installs and starts the Windows service (needs admin). */
export function windowsInstallScript(p: DeployParams): string {
  const c = clean(p);
  return [
    `$d = "$env:ProgramFiles\\Wazuh-Agent"`,
    `New-Item -ItemType Directory -Force -Path $d | Out-Null`,
    `Invoke-WebRequest -UseBasicParsing -Uri ${pq(c.url + '/downloads/siem-agent.exe')} -OutFile "$d\\siem-agent.exe"`,
    `& "$d\\siem-agent.exe" install-service ${pq(c.url)} ${pq(c.name)} ${pq(c.group)} ${pq(c.key)}`,
    `Start-Service -Name ${WINDOWS_SERVICE} -ErrorAction SilentlyContinue`,
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
