import { Component, EventEmitter, Input, OnInit, Output, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, Terminal, RefreshCw, Monitor, Copy, CheckCircle2, Download, Play } from 'lucide-angular';
import { SiemService } from '../../services/siem/siem.service';
import {
  AgentDeployService, DeployOs, DeployParams, WinInstallMode,
  defaultManagerUrl, fetchManagerUrl, downloadText, generateAgentName, installCommand, isLoopbackManager, isValidAgentName,
  linuxDeployScript, startCommand, windowsBatScript,
} from '../../services/siem/agent-deploy';

/**
 * The agent enrollment wizard (OS, manager URL, name, group, the tenant's
 * enrolment key, install and start commands). Used in the analyst Agents page
 * (in a modal) and on the tenant admin's Agent Deployment page. Needs the tenant
 * admin or the `siem-agent-deploy` permission (siem-api checks the key request).
 */
@Component({
  selector: 'app-agent-deploy',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './agent-deploy.html',
})
export class AgentDeploy implements OnInit {
  private siem = inject(SiemService);
  private deploy = inject(AgentDeployService);

  /** Shown in a modal: offers a Close button. */
  @Input() closable = false;
  @Output() closed = new EventEmitter<void>();

  TerminalIcon = Terminal;
  RefreshIcon = RefreshCw;
  MonitorIcon = Monitor;
  CopyIcon = Copy;
  CheckIcon = CheckCircle2;
  DownloadIcon = Download;
  PlayIcon = Play;

  agentNames = signal<string[]>([]);
  groups = signal<{ name: string }[]>([]);
  deployOs = signal<DeployOs>('linux');
  deployManagerUrl = signal<string>(defaultManagerUrl());
  deployManagerLoopback = computed(() => isLoopbackManager(this.deployManagerUrl()));
  deployAgentName = signal<string>('');
  deployGroup = signal<string>('default');
  deployTenantKey = signal<string>('');
  deployTenantId = signal<string>('');
  deployKeyError = signal<string | null>(null);
  winInstallMode = signal<WinInstallMode>('auto-elevate');
  copied = signal(false);
  copiedStart = signal(false);

  private deployParams = computed<DeployParams>(() => ({
    os: this.deployOs(),
    managerUrl: this.deployManagerUrl(),
    agentName: this.deployAgentName(),
    group: this.deployGroup(),
    tenantKey: this.deployTenantKey(),
    winMode: this.winInstallMode(),
  }));
  deployNameValid = computed(() => isValidAgentName(this.deployAgentName().trim()));
  deployNameTaken = computed(() => this.agentNames().includes(this.deployAgentName().trim().toLowerCase()));
  deployInstallCommand = computed(() => (this.deployNameValid() ? installCommand(this.deployParams()) : ''));
  deployStartCommand = computed(() => startCommand(this.deployParams()));

  ngOnInit() {
    fetchManagerUrl().then(url => this.deployManagerUrl.set(url));
    this.deploy.tenantKey().subscribe(r => {
      this.deployTenantKey.set(r.key);
      this.deployTenantId.set(r.tenant);
      this.deployKeyError.set(r.error ?? null);
    });
    this.siem.getGroups().subscribe({ next: g => this.groups.set(g), error: () => {} });
    this.siem.getAgents().subscribe({
      next: list => {
        this.agentNames.set(list.map(a => a.name.toLowerCase()));
        this.regenerateAgentName();
      },
      error: () => this.regenerateAgentName(),
    });
    this.regenerateAgentName();
  }

  /** Picks the OS and proposes a fresh, unused agent name for it. */
  selectDeployOs(os: DeployOs) {
    this.deployOs.set(os);
    this.regenerateAgentName();
  }

  regenerateAgentName() {
    this.deployAgentName.set(generateAgentName(this.deployOs(), this.agentNames()));
  }

  downloadBatScript() {
    downloadText(`install-${this.deployAgentName().trim()}.bat`, windowsBatScript(this.deployParams()), 'application/x-bat');
  }

  downloadDeployScript() {
    downloadText(`install-${this.deployAgentName().trim()}.sh`, linuxDeployScript(this.deployParams()), 'text/x-shellscript');
  }

  copyInstallCommand() {
    this.copy(this.deployInstallCommand(), this.copied);
  }

  copyStartCommand() {
    this.copy(this.deployStartCommand(), this.copiedStart);
  }

  /** Clipboard API where allowed (https / localhost), else execCommand (plain-http LAN addresses). */
  private copy(text: string, flag: ReturnType<typeof signal<boolean>>) {
    if (!text) return;
    const done = () => { flag.set(true); setTimeout(() => flag.set(false), 2500); };
    const fallback = () => {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (ok) done();
    };
    if (navigator?.clipboard?.writeText && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done).catch(fallback);
    } else {
      fallback();
    }
  }
}
