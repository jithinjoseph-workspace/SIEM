import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Server, Shield, Terminal, RefreshCw, Plus, Search, Filter,
  CheckCircle2, AlertTriangle, Monitor, Cpu, HardDrive, Network,
  Layers, Copy, Check, Download, Play, X, ExternalLink, Activity
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import {
  AgentDeployService, DeployOs, DeployParams, WinInstallMode,
  defaultManagerUrl, downloadText, generateAgentName, installCommand, isValidAgentName,
  linuxDeployScript, startCommand, windowsBatScript,
} from '../../../services/siem/agent-deploy';
import { Agent, AgentInventory, ScaCheckResult, RawEvent } from '../../../services/siem/siem.models';

type AgentDetailTab = 'specs' | 'network_ports' | 'users_services' | 'sca' | 'fim' | 'actions';

@Component({
  selector: 'app-agents',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './agents.html',
  styleUrl: './agents.css',
})
export class Agents implements OnInit {
  private siem = inject(SiemService);
  private deploy = inject(AgentDeployService);

  // Icons
  ServerIcon = Server;
  ShieldIcon = Shield;
  TerminalIcon = Terminal;
  RefreshIcon = RefreshCw;
  PlusIcon = Plus;
  SearchIcon = Search;
  FilterIcon = Filter;
  CheckIcon = CheckCircle2;
  AlertIcon = AlertTriangle;
  MonitorIcon = Monitor;
  CpuIcon = Cpu;
  DiskIcon = HardDrive;
  NetworkIcon = Network;
  LayersIcon = Layers;
  CopyIcon = Copy;
  CopiedIcon = Check;
  DownloadIcon = Download;
  PlayIcon = Play;
  CloseIcon = X;
  ExternalIcon = ExternalLink;
  ActivityIcon = Activity;

  // State
  agents = signal<Agent[]>([]);
  rawEvents = signal<RawEvent[]>([]);
  loading = signal<boolean>(false);
  searchQuery = signal<string>('');
  osFilter = signal<'all' | 'windows' | 'linux' | 'macos'>('all');
  statusFilter = signal<'all' | 'active' | 'disconnected'>('all');

  selectedAgent = signal<Agent | null>(null);
  selectedAgentTab = signal<AgentDetailTab>('specs');
  agentActionFeedback = signal<string | null>(null);

  // Deploy wizard: commands come from services/siem/agent-deploy.ts (enrollment
  // with a unique agent id, tenant key, manager URL, name and group).
  showDeployModal = signal<boolean>(false);
  deployOs = signal<DeployOs>('linux');
  deployManagerUrl = signal<string>(defaultManagerUrl());
  deployAgentName = signal<string>('');
  deployGroup = signal<string>('default');
  deployTenantKey = signal<string>('');
  deployTenantId = signal<string>('');
  deployKeyError = signal<string | null>(null);
  winInstallMode = signal<WinInstallMode>('auto-elevate');
  copied = signal<boolean>(false);
  copiedStart = signal<boolean>(false);

  private deployParams = computed<DeployParams>(() => ({
    os: this.deployOs(),
    managerUrl: this.deployManagerUrl(),
    agentName: this.deployAgentName(),
    group: this.deployGroup(),
    tenantKey: this.deployTenantKey(),
    winMode: this.winInstallMode(),
  }));
  deployNameValid = computed(() => isValidAgentName(this.deployAgentName().trim()));
  deployNameTaken = computed(() => {
    const n = this.deployAgentName().trim().toLowerCase();
    return this.agents().some(a => a.name.toLowerCase() === n);
  });
  deployInstallCommand = computed(() => (this.deployNameValid() ? installCommand(this.deployParams()) : ''));
  deployStartCommand = computed(() => startCommand(this.deployParams()));

  filteredAgents = computed(() => {
    let list = this.agents();
    const q = this.searchQuery().toLowerCase().trim();
    const os = this.osFilter();
    const st = this.statusFilter();

    if (os !== 'all') {
      list = list.filter(a => a.os_type === os);
    }
    if (st !== 'all') {
      list = list.filter(a => a.status === st);
    }
    if (q) {
      list = list.filter(a =>
        a.name.toLowerCase().includes(q) ||
        a.ip.includes(q) ||
        a.id.toLowerCase().includes(q) ||
        a.os.toLowerCase().includes(q)
      );
    }
    return list;
  });

  /** Latest inventory the agent reported (GET /api/v1/agents/:id/inventory). */
  selectedAgentInventory = signal<AgentInventory | null>(null);
  inventoryLoading = signal<boolean>(false);

  /** SCA results stored for the agent (GET /api/v1/agents/:id/sca). */
  selectedAgentScaChecks = signal<ScaCheckResult[]>([]);
  scaSummary = signal<{ policy_id?: string; score: number; passed: number; failed: number } | null>(null);
  /** IP for the block / unblock actions. */
  actionIp = signal<string>('');
  /** Per-card feedback for the quick actions. */
  rowFeedback = signal<Record<string, string>>({});
  /** Deactivated agents (kept in the registry, stopped on the endpoint). */
  deactivatedAgents = signal<{ id: string; name: string; os_type: string; groups: string; enrolled_at: string }[]>([]);
  deactivatedFeedback = signal<string | null>(null);

  ngOnInit() {
    this.loadAgents();
  }

  loadAgents() {
    this.loadDeactivated();
    this.loading.set(true);
    this.siem.getAgents().subscribe({
      next: (list) => {
        this.agents.set(list);
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  openAgentDetails(agent: Agent) {
    this.selectedAgent.set(agent);
    this.selectedAgentTab.set('specs');
    this.agentActionFeedback.set(null);
    this.loadAgentDetails(agent.id);
  }

  private loadAgentDetails(agentId: string) {
    this.selectedAgentInventory.set(null);
    this.selectedAgentScaChecks.set([]);
    this.scaSummary.set(null);
    this.inventoryLoading.set(true);
    this.siem.getAgentInventory(agentId).subscribe(inv => {
      if (this.selectedAgent()?.id !== agentId) return;
      this.selectedAgentInventory.set(inv);
      this.inventoryLoading.set(false);
    });
    this.siem.getAgentSca(agentId).subscribe(sca => {
      if (this.selectedAgent()?.id !== agentId || !sca) return;
      this.selectedAgentScaChecks.set(sca.checks || []);
      this.scaSummary.set({ policy_id: sca.policy_id, score: sca.score ?? 0, passed: sca.passed ?? 0, failed: sca.failed ?? 0 });
    });
  }

  isPassed(status: string): boolean {
    return /pass/i.test(status || '');
  }

  validIp(ip: string): boolean {
    const v = (ip || '').trim();
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(v) || (v.includes(':') && /^[0-9a-fA-F:]+$/.test(v));
  }

  closeAgentDetails() {
    this.selectedAgent.set(null);
  }

  /** Queues a command for the selected agent (siem-api /api/v1/agent/commands). */
  triggerAgentAction(action: string, target: string = 'all') {
    const ag = this.selectedAgent();
    if (!ag) return;
    this.agentActionFeedback.set(`Dispatching '${action}' to ${ag.name}…`);
    this.siem.sendAgentCommand(ag.id, action, target).subscribe({
      next: () => {
        this.agentActionFeedback.set(`✓ '${action}' queued for ${ag.name}; the agent runs it on its next poll.`);
        setTimeout(() => this.agentActionFeedback.set(null), 5000);
        // Inventory / SCA results arrive a few seconds later.
        if (action === 'syscollector_scan' || action === 'sca_scan') {
          setTimeout(() => this.selectedAgent()?.id === ag.id && this.loadAgentDetails(ag.id), 8000);
        }
      },
      error: (err) => {
        const msg = err?.error?.message || err?.statusText || 'request failed';
        this.agentActionFeedback.set(`✗ Could not queue '${action}': ${msg}`);
      },
    });
  }

  loadDeactivated() {
    this.siem.getDeactivatedAgents().subscribe(list => this.deactivatedAgents.set(list));
  }

  /** Keeps the agent (not deleted), takes it out of the fleet and stops it on the endpoint. */
  deactivateAgent(ag: Agent) {
    if (!confirm(`Deactivate agent ${ag.name} (${ag.id})?\n\nIt stops monitoring and sending data. It is not deleted: you can reactivate it later.`)) return;
    this.siem.deactivateAgent(ag.id).subscribe({
      next: () => {
        this.deactivatedFeedback.set(`✓ ${ag.name} deactivated. The agent stops within a few seconds.`);
        if (this.selectedAgent()?.id === ag.id) this.closeAgentDetails();
        this.loadAgents();
      },
      error: (err) => this.deactivatedFeedback.set(`✗ Could not deactivate ${ag.name}: ${err?.error?.message || 'request failed'}`),
    });
  }

  reactivateAgent(id: string, name: string) {
    this.siem.activateAgent(id).subscribe({
      next: () => {
        this.deactivatedFeedback.set(`✓ ${name} reactivated. The agent resumes within a minute.`);
        this.loadAgents();
      },
      error: (err) => this.deactivatedFeedback.set(`✗ Could not reactivate ${name}: ${err?.error?.message || 'request failed'}`),
    });
  }

  deleteAgentPermanently(id: string, name: string) {
    if (!confirm(`Delete agent ${name} (${id}) permanently?\n\nIts registration is removed and the id is never reused. Its past data stays.`)) return;
    this.siem.deleteAgent(id).subscribe({
      next: () => {
        this.deactivatedFeedback.set(`✓ ${name} deleted.`);
        this.loadAgents();
      },
      error: (err) => this.deactivatedFeedback.set(`✗ Could not delete ${name}: ${err?.error?.message || 'request failed'}`),
    });
  }

  quickAction(ag: Agent, action: string) {
    const set = (text: string) => this.rowFeedback.update(m => ({ ...m, [ag.id]: text }));
    set(`Dispatching '${action}'…`);
    this.siem.sendAgentCommand(ag.id, action).subscribe({
      next: () => {
        set(`✓ '${action}' queued`);
        setTimeout(() => this.rowFeedback.update(m => { const c = { ...m }; delete c[ag.id]; return c; }), 4000);
      },
      error: (err) => set(`✗ ${err?.error?.message || 'request failed'}`),
    });
  }

  blockIpOnAgent() {
    const ip = this.actionIp().trim();
    if (this.validIp(ip)) this.triggerAgentAction('block_ip', ip);
  }

  unblockIpOnAgent() {
    const ip = this.actionIp().trim();
    if (this.validIp(ip)) this.triggerAgentAction('unblock_ip', ip);
  }

  openDeployModal() {
    this.selectDeployOs(this.deployOs());
    this.copied.set(false);
    this.copiedStart.set(false);
    this.showDeployModal.set(true);
    this.deployKeyError.set(null);
    this.deploy.tenantKey().subscribe(r => {
      this.deployTenantKey.set(r.key);
      this.deployTenantId.set(r.tenant);
      this.deployKeyError.set(r.error ?? null);
    });
  }

  /** Picks the OS and proposes a fresh, unused agent name for it. */
  selectDeployOs(os: DeployOs) {
    this.deployOs.set(os);
    this.regenerateAgentName();
  }

  regenerateAgentName() {
    this.deployAgentName.set(generateAgentName(this.deployOs(), this.agents().map(a => a.name)));
  }

  downloadBatScript() {
    downloadText(`install-${this.deployAgentName().trim()}.bat`, windowsBatScript(this.deployParams()), 'application/x-bat');
  }

  downloadDeployScript() {
    downloadText(`install-${this.deployAgentName().trim()}.sh`, linuxDeployScript(this.deployParams()), 'text/x-shellscript');
  }

  copyInstallCommand() {
    navigator.clipboard?.writeText(this.deployInstallCommand());
    this.copied.set(true);
    setTimeout(() => this.copied.set(false), 2500);
  }

  copyStartCommand() {
    navigator.clipboard?.writeText(this.deployStartCommand());
    this.copiedStart.set(true);
    setTimeout(() => this.copiedStart.set(false), 2500);
  }
}
