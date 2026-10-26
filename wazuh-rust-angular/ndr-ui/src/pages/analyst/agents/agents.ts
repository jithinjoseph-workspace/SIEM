import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Server, Shield, Terminal, RefreshCw, Plus, Search, Filter,
  CheckCircle2, AlertTriangle, Monitor, Cpu, HardDrive, Network,
  Layers, Copy, Check, Download, Play, X, ExternalLink, Activity,
  LayoutGrid, Lock, ShieldAlert, TrendingUp, TrendingDown
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { AuthService } from '../../../services/auth/auth';
import { defaultManagerUrl, fetchManagerUrl, downloadText } from '../../../services/siem/agent-deploy';
import { AgentDeploy } from '../../../components/agent-deploy/agent-deploy';
import { Agent, AgentInventory, ScaCheckResult, RawEvent } from '../../../services/siem/siem.models';

type AgentDetailTab = 'specs' | 'network_ports' | 'users_services' | 'sca' | 'fim' | 'rootcheck' | 'groups' | 'upgrade' | 'actions';

@Component({
  selector: 'app-agents',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule, AgentDeploy],
  templateUrl: './agents.html',
  styleUrl: './agents.css',
})
export class Agents implements OnInit {
  private siem = inject(SiemService);
  private auth = inject(AuthService);
  /** Upgrades are for the tenant's admins (the API checks it too). */
  canUpgrade = this.auth.isAdmin() || this.auth.isTenantAdmin();
  /** Enrolling agents: tenant admins, or analysts the admin gave "Deploy agents". */
  canDeploy = this.auth.isAdmin() || this.auth.isTenantAdmin() || this.auth.hasPermission('siem-agent-deploy');

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
  GridIcon = LayoutGrid;
  LockIcon = Lock;
  ShieldAlertIcon = ShieldAlert;
  TrendingUpIcon = TrendingUp;
  TrendingDownIcon = TrendingDown;

  // View Mode: 'table' (like reference image) or 'grid' (cards)
  viewMode = signal<'table' | 'grid'>('table');

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


  // the enrollment wizard is components/agent-deploy
  showDeployModal = signal<boolean>(false);
  deployManagerUrl = signal<string>(defaultManagerUrl());

  totalCount = computed(() => this.agents().length);
  activeCount = computed(() => this.agents().filter(a => a.status === 'active').length);
  disconnectedCount = computed(() => this.agents().filter(a => a.status !== 'active').length);
  windowsCount = computed(() => this.agents().filter(a => a.os_type === 'windows').length);
  linuxCount = computed(() => this.agents().filter(a => a.os_type === 'linux').length);

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
  /** IP and duration for the block action. */
  actionIp = signal<string>('');
  blockSeconds = signal<number>(3600);
  /** Windows agents: firewall rule (netsh) or null route. */
  blockMethod = signal<string>('netsh');

  /** FIM entries and rootcheck findings of the selected agent (wazuh-db). */
  fimEntries = signal<any[]>([]);
  fimTotal = signal<number>(0);
  fimFilter = signal<string>('');
  fimLoading = signal<boolean>(false);
  filteredFim = computed(() => {
    const q = this.fimFilter().toLowerCase().trim();
    return q ? this.fimEntries().filter(e => (e.full_path || '').toLowerCase().includes(q)) : this.fimEntries();
  });
  rootcheckEvents = signal<any[]>([]);
  rootcheckLoading = signal<boolean>(false);

  /** Upgrade form and the agent's last upgrade task. */
  upgradeMode = signal<'repo' | 'custom'>('repo');
  upgradeVersion = signal<string>('');
  upgradeForce = signal<boolean>(false);
  upgradeUseHttp = signal<boolean>(false);
  upgradeRepo = signal<string>('');
  upgradePackageType = signal<string>('');
  upgradeFilePath = signal<string>('');
  upgradeInstaller = signal<string>('');
  upgradeBusy = signal<boolean>(false);
  upgradeFeedback = signal<string | null>(null);
  upgradeTask = signal<any | null>(null);
  private upgradePoll: any = null;
  /** Per-card feedback for the quick actions. */
  rowFeedback = signal<Record<string, string>>({});
  /** Deactivated agents (kept in the registry, stopped on the endpoint). */
  deactivatedAgents = signal<{ id: string; name: string; os_type: string; groups: string; enrolled_at: string }[]>([]);
  deactivatedFeedback = signal<string | null>(null);

  /** Agent groups: each has a centralized agent.conf the manager pushes to its agents. */
  groups = signal<{ name: string; agents: number; agent_ids: string[]; editable: boolean }[]>([]);
  newGroupName = signal<string>('');
  groupFeedback = signal<string | null>(null);
  editingGroup = signal<string | null>(null);
  groupConf = signal<string>('');
  groupConfBusy = signal<boolean>(false);
  /** Group choice of the selected agent (Groups tab). */
  agentGroupPick = signal<Record<string, boolean>>({});
  agentGroupFeedback = signal<string | null>(null);

  ngOnInit() {
    this.loadAgents();
    // Resolve the real LAN IP from the backend so deploy commands work from any client
    fetchManagerUrl().then(url => this.deployManagerUrl.set(url));
  }

  loadAgents() {
    this.loadDeactivated();
    this.loadGroups();
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
    this.upgradeFeedback.set(null);
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
    this.stopUpgradePoll();
  }

  selectTab(tab: AgentDetailTab) {
    this.selectedAgentTab.set(tab);
    const ag = this.selectedAgent();
    if (!ag) return;
    if (tab === 'fim') this.loadFim(ag.id);
    if (tab === 'rootcheck') this.loadRootcheck(ag.id);
    if (tab === 'upgrade') this.loadUpgradeTask(ag.id);
    if (tab === 'groups') this.pickAgentGroups(ag.id);
  }

  isGroupEditable(name: string): boolean {
    return !!this.groups().find(g => g.name === name)?.editable;
  }

  loadGroups() {
    this.siem.getGroups().subscribe(g => this.groups.set(g));
  }

  createGroup() {
    const name = this.newGroupName().trim();
    if (!name) return;
    this.siem.createGroup(name).subscribe({
      next: (r) => { this.groupFeedback.set(`✓ ${r?.message || 'Group created'}`); this.newGroupName.set(''); this.loadGroups(); },
      error: (err) => this.groupFeedback.set(`✗ ${err?.error?.message || 'request failed'}`),
    });
  }

  deleteGroup(name: string) {
    if (!confirm(`Delete group ${name}?

Its agent.conf is removed. Its agents keep their other groups (or go back to 'default').`)) return;
    this.siem.deleteGroup(name).subscribe({
      next: (r) => {
        this.groupFeedback.set(`✓ ${r?.message || 'Group deleted'}`);
        if (this.editingGroup() === name) this.editingGroup.set(null);
        this.loadGroups();
      },
      error: (err) => this.groupFeedback.set(`✗ ${err?.error?.message || 'request failed'}`),
    });
  }

  editGroupConf(name: string) {
    this.editingGroup.set(name);
    this.groupConf.set('');
    this.siem.getGroupConf(name).subscribe({
      next: (t) => this.editingGroup() === name && this.groupConf.set(t),
      error: () => this.groupFeedback.set(`✗ Could not load the agent.conf of ${name}`),
    });
  }

  saveGroupConf() {
    const name = this.editingGroup();
    if (!name) return;
    this.groupConfBusy.set(true);
    this.siem.saveGroupConf(name, this.groupConf()).subscribe({
      next: (r) => { this.groupConfBusy.set(false); this.groupFeedback.set(`✓ ${r?.message || 'Saved'}`); },
      error: (err) => { this.groupConfBusy.set(false); this.groupFeedback.set(`✗ ${err?.error?.message || 'request failed'}`); },
    });
  }

  private pickAgentGroups(agentId: string) {
    this.agentGroupFeedback.set(null);
    const pick: Record<string, boolean> = {};
    for (const g of this.groups()) pick[g.name] = g.agent_ids.includes(agentId);
    this.agentGroupPick.set(pick);
  }

  toggleAgentGroup(name: string, on: boolean) {
    this.agentGroupPick.update(m => ({ ...m, [name]: on }));
  }

  saveAgentGroups() {
    const ag = this.selectedAgent();
    if (!ag) return;
    // order: the groups' agent.conf files are merged in this order (later ones win)
    const picked = this.groups().map(g => g.name).filter(n => this.agentGroupPick()[n]);
    this.siem.setAgentGroups(ag.id, picked).subscribe({
      next: (r) => {
        const msg = `✓ Groups: ${(r?.groups || picked).join(', ')}. The agent gets the new configuration on its next keepalive.`;
        this.siem.getGroups().subscribe(g => { this.groups.set(g); this.pickAgentGroups(ag.id); this.agentGroupFeedback.set(msg); });
      },
      error: (err) => this.agentGroupFeedback.set(`✗ ${err?.error?.message || 'request failed'}`),
    });
  }

  loadFim(agentId: string) {
    this.fimLoading.set(true);
    this.siem.getAgentFim(agentId).subscribe(r => {
      if (this.selectedAgent()?.id !== agentId) return;
      this.fimEntries.set(r?.entries || []);
      this.fimTotal.set(r?.total ?? 0);
      this.fimLoading.set(false);
    });
  }

  loadRootcheck(agentId: string) {
    this.rootcheckLoading.set(true);
    this.siem.getAgentRootcheck(agentId).subscribe(r => {
      if (this.selectedAgent()?.id !== agentId) return;
      this.rootcheckEvents.set(r?.events || []);
      this.rootcheckLoading.set(false);
    });
  }

  runRootcheck() {
    const ag = this.selectedAgent();
    if (!ag) return;
    this.agentActionFeedback.set(`Starting a rootcheck scan on ${ag.name}…`);
    this.siem.runRootcheck(ag.id).subscribe({
      next: (r) => this.agentActionFeedback.set(`✓ ${r?.message || 'Scan started'}. Findings appear here when the agent finishes.`),
      error: (err) => this.agentActionFeedback.set(`✗ ${err?.error?.message || 'request failed'}`),
    });
  }

  /** The agent's last upgrade task (polled while it is running). */
  loadUpgradeTask(agentId: string) {
    this.siem.getAgentUpgrade(agentId).subscribe(r => {
      if (this.selectedAgent()?.id !== agentId) return;
      const t = (r?.data || [])[0] || null;
      this.upgradeTask.set(t && t.error === 0 ? t : null);
      const running = t && (t.status === 'In queue' || t.status === 'Updating');
      if (running && !this.upgradePoll) {
        this.upgradePoll = setInterval(() => {
          const cur = this.selectedAgent();
          if (!cur || this.selectedAgentTab() !== 'upgrade') return this.stopUpgradePoll();
          this.loadUpgradeTask(cur.id);
        }, 5000);
      } else if (!running) {
        this.stopUpgradePoll();
      }
    });
  }

  private stopUpgradePoll() {
    if (this.upgradePoll) clearInterval(this.upgradePoll);
    this.upgradePoll = null;
  }

  startUpgrade() {
    const ag = this.selectedAgent();
    if (!ag) return;
    const custom = this.upgradeMode() === 'custom';
    if (custom && !this.upgradeFilePath().trim()) {
      this.upgradeFeedback.set('✗ Enter the WPK file path on the manager.');
      return;
    }
    const what = custom ? `the WPK ${this.upgradeFilePath().trim()}` : (this.upgradeVersion().trim() || 'the manager version');
    if (!confirm(`Upgrade agent ${ag.name} (${ag.id}) to ${what}?\n\nThe agent restarts when the upgrade is installed.`)) return;
    const body: any = custom
      ? { file_path: this.upgradeFilePath().trim(), ...(this.upgradeInstaller().trim() ? { installer: this.upgradeInstaller().trim() } : {}) }
      : {
          ...(this.upgradeVersion().trim() ? { target_version: this.upgradeVersion().trim() } : {}),
          ...(this.upgradeRepo().trim() ? { wpk_repo: this.upgradeRepo().trim() } : {}),
          ...(this.upgradePackageType() ? { package_type: this.upgradePackageType() } : {}),
          force: this.upgradeForce(),
          use_http: this.upgradeUseHttp(),
        };
    this.upgradeBusy.set(true);
    this.upgradeFeedback.set('Sending the upgrade request (the manager may take up to 30 s right after it starts)…');
    this.siem.upgradeAgent(ag.id, body).subscribe({
      next: (r) => {
        this.upgradeBusy.set(false);
        const d = (r?.data || [])[0];
        if (d && d.error === 0) {
          this.upgradeFeedback.set(`✓ Upgrade task ${d.task_id} created. Progress is shown below.`);
        } else {
          this.upgradeFeedback.set(`✗ ${d?.message || r?.message || 'The upgrade could not start'}`);
        }
        this.loadUpgradeTask(ag.id);
      },
      error: (err) => {
        this.upgradeBusy.set(false);
        this.upgradeFeedback.set(`✗ ${err?.error?.error || err?.error?.message || 'request failed'}`);
      },
    });
  }

  /** Sends an action to the selected agent (siem-api /api/v1/agent/commands). */
  triggerAgentAction(action: string, target: string = 'all', durationSeconds?: number, method?: string) {
    const ag = this.selectedAgent();
    if (!ag) return;
    this.agentActionFeedback.set(`Dispatching '${action}' to ${ag.name}…`);
    this.siem.sendAgentCommand(ag.id, action, target, durationSeconds, method).subscribe({
      next: (r) => {
        this.agentActionFeedback.set(`✓ ${r?.message || `'${action}' queued for ${ag.name}; the agent runs it on its next poll.`}`);
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
      next: (r) => {
        set(`✓ ${r?.message || `'${action}' queued`}`);
        setTimeout(() => this.rowFeedback.update(m => { const c = { ...m }; delete c[ag.id]; return c; }), 4000);
      },
      error: (err) => set(`✗ ${err?.error?.message || 'request failed'}`),
    });
  }

  blockIpOnAgent() {
    const ip = this.actionIp().trim();
    const windows = this.selectedAgent()?.os_type === 'windows';
    if (this.validIp(ip)) this.triggerAgentAction('block_ip', ip, this.blockSeconds(), windows ? this.blockMethod() : undefined);
  }


  /** Calculate endpoint security risk score (0-100) */
  getAgentRisk(agent: Agent): { score: number; label: string; color: string } {
    if (agent.status !== 'active') {
      return { score: 92, label: 'Critical', color: 'rose' };
    }
    if (agent.os_type === 'windows') {
      return { score: 14, label: 'Low', color: 'emerald' };
    }
    return { score: 18, label: 'Low', color: 'emerald' };
  }

  /** Format keepalive into readable time */
  getFormattedKeepalive(dateStr?: string): string {
    if (!dateStr) return 'Active now';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr;
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ', ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return dateStr;
    }
  }

  /** Export filtered agents as CSV */
  exportCsv() {
    const list = this.filteredAgents();
    if (list.length === 0) return;
    const headers = ['ID', 'Name', 'IP', 'OS', 'OS Type', 'Version', 'Status', 'Last Keepalive'];
    const rows = list.map(a => [
      a.id,
      `"${a.name.replace(/"/g, '""')}"`,
      a.ip,
      `"${a.os.replace(/"/g, '""')}"`,
      a.os_type,
      a.version,
      a.status,
      `"${a.last_keepalive || ''}"`
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    downloadText('endpoints-fleet.csv', csvContent, 'text/csv');
  }
}
