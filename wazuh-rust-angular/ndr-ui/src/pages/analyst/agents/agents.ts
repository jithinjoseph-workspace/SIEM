import { Component, OnInit, signal, computed, inject, HostListener } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Server, Shield, Terminal, RefreshCw, Plus, Search, Filter,
  CheckCircle2, AlertTriangle, Monitor, Cpu, HardDrive, Network,
  Layers, Copy, Check, Download, Play, X, ExternalLink, Activity,
  LayoutGrid, Lock, ShieldAlert, TrendingDown, Laptop, BarChart3, Users, FileSearch,
  Bug, Boxes, ArrowUpCircle, Zap, Power, ScanSearch
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
  imports: [CommonModule, FormsModule, RouterLink, LucideAngularModule, AgentDeploy],
  templateUrl: './agents.html',
  styleUrl: './agents.css',
})
export class Agents implements OnInit {
  private siem = inject(SiemService);
  private auth = inject(AuthService);
  private route = inject(ActivatedRoute);
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
  TrendingDownIcon = TrendingDown;
  LaptopIcon = Laptop;
  ChartIcon = BarChart3;
  PowerIcon = Power;
  ScanIcon = ScanSearch;

  /** The tabs of the agent details (Upgrade only for the tenant's admins). */
  readonly detailTabs = computed(() => ([
    { id: 'specs', label: 'Hardware', icon: Cpu },
    { id: 'network_ports', label: 'Network', icon: Network },
    { id: 'users_services', label: 'Software', icon: Boxes },
    { id: 'sca', label: 'CIS SCA', icon: ShieldAlert },
    { id: 'fim', label: 'FIM', icon: FileSearch },
    { id: 'rootcheck', label: 'Rootcheck', icon: Bug },
    { id: 'groups', label: 'Groups', icon: Users },
    ...(this.canUpgrade ? [{ id: 'upgrade', label: 'Upgrade', icon: ArrowUpCircle }] : []),
    { id: 'actions', label: 'Response', icon: Zap },
  ] as { id: AgentDetailTab; label: string; icon: any }[]));

  // View Mode: 'table' (like reference image) or 'grid' (cards)
  viewMode = signal<'table' | 'grid'>(this.stored('agents.view') === 'grid' ? 'grid' : 'table');
  /** Advanced view: the fleet charts and the extra table columns. */
  advanced = signal<boolean>(this.stored('agents.advanced') !== 'off');

  setView(v: 'table' | 'grid') { this.viewMode.set(v); this.store('agents.view', v); }
  toggleAdvanced() { this.advanced.update(a => !a); this.store('agents.advanced', this.advanced() ? 'on' : 'off'); }
  private stored(k: string): string | null { try { return localStorage.getItem(k); } catch { return null; } }
  private store(k: string, v: string) { try { localStorage.setItem(k, v); } catch {} }

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
  outdatedCount = computed(() => this.agents().filter(a => a.version && !this.agentCurrent(a)).length);
  onlinePct = computed(() => this.totalCount() ? Math.round(this.activeCount() * 100 / this.totalCount()) : 0);

  // ── Fleet charts (all from the agents, CVE and Sysmon data the page loads) ──
  /** Connection state of the agents (status colors; each has a label). */
  statusSplit = computed(() => this.split([
    { label: 'Online', n: this.activeCount(), color: 'var(--st-good)' },
    { label: 'Disconnected', n: this.agents().filter(a => a.status === 'disconnected').length, color: 'var(--st-critical)' },
    { label: 'Never connected', n: this.agents().filter(a => a.status === 'pending').length, color: 'var(--st-warning)' },
  ]));
  /** Operating systems (a fixed hue per OS, so a filter never repaints them). */
  platformSplit = computed(() => this.split([
    { label: 'Windows', n: this.windowsCount(), color: 'var(--series-1)', os: 'windows' as const },
    { label: 'Linux', n: this.linuxCount(), color: 'var(--series-2)', os: 'linux' as const },
    { label: 'macOS', n: this.agents().filter(a => a.os_type === 'macos').length, color: 'var(--series-3)', os: 'macos' as const },
  ]));
  versionSplit = computed(() => this.split([
    { label: 'Current', n: this.agents().filter(a => this.agentCurrent(a)).length, color: 'var(--st-good)' },
    { label: 'Outdated', n: this.outdatedCount(), color: 'var(--st-warning)' },
  ]));
  /** The agents with the most open CVEs (critical, high, medium). */
  cveTop = computed(() => {
    const per = this.agentVulns();
    const rows = this.agents().map(a => ({ agent: a, ...(per[a.id] ?? { critical: 0, high: 0, medium: 0 }) }))
      .map(r => ({ ...r, total: r.critical + r.high + r.medium }))
      .filter(r => r.total > 0)
      .sort((x, y) => (y.critical - x.critical) || (y.high - x.high) || (y.total - x.total))
      .slice(0, 6);
    const max = Math.max(1, ...rows.map(r => r.total));
    return rows.map(r => ({ ...r, scale: r.total * 100 / max }));
  });
  /** Sysmon events of the Windows agents in 24 h. */
  sysmonTop = computed(() => {
    const t = this.sysmonTelemetry() ?? {};
    const rows = this.agents().filter(a => a.os_type === 'windows')
      .map(a => ({ agent: a, events: t[a.id]?.events_24h ?? 0 }))
      .sort((x, y) => y.events - x.events).slice(0, 6);
    const max = Math.max(1, ...rows.map(r => r.events));
    return rows.map(r => ({ ...r, pct: r.events * 100 / max }));
  });
  sysmonCovered = computed(() => {
    const t = this.sysmonTelemetry();
    return t ? this.agents().filter(a => a.os_type === 'windows' && (t[a.id]?.events_24h ?? 0) > 0).length : 0;
  });

  private split<T extends { n: number }>(parts: T[]) {
    const total = parts.reduce((s, p) => s + p.n, 0);
    return parts.filter(p => p.n > 0).map(p => {
      const pct = total ? p.n * 100 / total : 0;
      return { ...p, pct, pctLabel: Math.round(pct) + '%' };
    });
  }

  /** Chart tooltip (one for the page, follows the pointer or the focused mark). */
  tip = signal<{ x: number; y: number; text: string } | null>(null);
  showTip(ev: Event, text: string) {
    const me = ev as MouseEvent;
    let x = me.clientX, y = me.clientY;
    if (x === undefined) { const r = (ev.target as HTMLElement).getBoundingClientRect(); x = r.left + r.width / 2; y = r.top; }
    const w = Math.min(260, innerWidth - 16);
    this.tip.set({ x: Math.max(8, Math.min(x + 14, innerWidth - w - 8)), y: y + 48 > innerHeight ? y - 44 : y + 16, text });
  }
  hideTip() { this.tip.set(null); }

  /** Relative time since the agent's last keepalive. */
  ago(dateStr?: string): string {
    const t = dateStr ? new Date(dateStr).getTime() : NaN;
    if (isNaN(t)) return dateStr || '—';
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.round(s / 60) + 'm ago';
    if (s < 86400) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
  }

  @HostListener('document:keydown.escape')
  onEscape() {
    if (this.showDeployModal()) this.showDeployModal.set(false);
    else if (this.selectedAgent()) this.closeAgentDetails();
  }

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
  scaSummary = signal<{ policy_id?: string; policy_name?: string; score: number; passed: number; failed: number; not_applicable: number; scanned_at?: string } | null>(null);
  scaFilter = signal<'all' | 'failed' | 'passed'>('all');
  scaQuery = signal<string>('');
  scaOpen = signal<number | null>(null);
  filteredSca = computed(() => {
    const f = this.scaFilter(), q = this.scaQuery().toLowerCase().trim();
    return this.selectedAgentScaChecks().filter(c =>
      (f === 'all' || (f === 'failed' ? this.isFailed(c.status) : this.isPassed(c.status))) &&
      (!q || (c.title || '').toLowerCase().includes(q) || String(c.check_id).includes(q)));
  });
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

  /** The tenant's open CVEs (vulnerability detector), for the fleet status line. */
  fleetVulns = signal<{ critical: number; high: number } | null>(null);
  /** Open CVEs per agent (critical, high, medium), for the risk score. */
  agentVulns = signal<Record<string, { critical: number; high: number; medium: number }>>({});
  /** The manager's Wazuh version: an agent on it is current. */
  readonly managerVersion = '4.14.7';

  ngOnInit() {
    this.loadAgents();
    this.siem.getVulnerabilities().subscribe({
      next: v => {
        this.fleetVulns.set({ critical: v.critical_count ?? 0, high: v.high_count ?? 0 });
        const per: Record<string, { critical: number; high: number; medium: number }> = {};
        for (const x of v.vulnerabilities ?? []) {
          if (x.status !== 'active') continue;
          const c = (per[x.agent_id] ??= { critical: 0, high: 0, medium: 0 });
          if (x.severity === 'Critical') c.critical++; else if (x.severity === 'High') c.high++; else if (x.severity === 'Medium') c.medium++;
        }
        this.agentVulns.set(per);
      },
      error: () => {}
    });
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
        // ?agent=<id> (from the console's globe and other pages): that agent's details
        const wanted = this.route.snapshot.queryParamMap.get('agent');
        const ag = wanted ? list.find(a => a.id === wanted) : undefined;
        if (ag && this.selectedAgent()?.id !== ag.id) this.openAgentDetails(ag);
      },
      error: () => this.loading.set(false)
    });
    this.siem.getAgentsTelemetry().subscribe(t => this.sysmonTelemetry.set(t?.sysmon ?? null));
  }

  /** Sysmon events per agent in the last 24 h; null = unknown (the query failed). */
  sysmonTelemetry = signal<Record<string, { events_24h: number; last: number }> | null>(null);

  openAgentDetails(agent: Agent) {
    this.selectedAgent.set(agent);
    this.selectedAgentTab.set('specs');
    this.scaFilter.set('all');
    this.scaQuery.set('');
    this.scaOpen.set(null);
    this.fimFilter.set('');
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
      const s = sca as any;
      this.scaSummary.set({ policy_id: s.policy_id, policy_name: s.policy_name, score: s.score ?? 0, passed: s.passed ?? 0, failed: s.failed ?? 0,
        not_applicable: s.not_applicable ?? 0, scanned_at: s.scanned_at });
    });
  }

  isPassed(status: string): boolean {
    return /pass/i.test(status || '');
  }

  isFailed(status: string): boolean {
    return /fail/i.test(status || '');
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

  // EDR (Windows agents)
  edrPid = signal<string>('');
  edrImage = signal<string>('');
  edrPath = signal<string>('');
  edrQuarantineId = signal<string>('');

  edrAction(action: string, params: Record<string, string | number>, confirmText?: string) {
    const ag = this.selectedAgent();
    if (!ag || (confirmText && !confirm(confirmText))) return;
    this.agentActionFeedback.set(`Sending '${action}' to ${ag.name}…`);
    this.siem.sendEdrAction(ag.id, action, params).subscribe({
      next: (r) => this.agentActionFeedback.set(`✓ ${r?.message || 'Sent'}. The result arrives as an active-response event from the agent.`),
      error: (err) => this.agentActionFeedback.set(`✗ ${err?.error?.message || err?.statusText || 'request failed'}`),
    });
  }

  killProcess() {
    const pid = this.edrPid().trim();
    const image = this.edrImage().trim();
    this.edrAction('kill_process', image ? { pid, image } : { pid }, `Kill process ${pid}${image ? ` (${image})` : ''} on ${this.selectedAgent()?.name}?`);
  }

  quarantineFile() {
    const path = this.edrPath().trim();
    this.edrAction('quarantine_file', { path }, `Move ${path} into quarantine on ${this.selectedAgent()?.name}?`);
  }

  restoreFile() {
    this.edrAction('restore_file', { quarantine_id: this.edrQuarantineId().trim() });
  }

  isolateHost() {
    this.edrAction('isolate_host', {}, `Isolate ${this.selectedAgent()?.name} from the network?\n\nOnly the manager stays reachable. It lifts by itself after 24 h, or with Release.`);
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
  /** Risk from the agent's open CVEs (critical x10, high x3, medium x1, at most 100). */
  getAgentRisk(agent: Agent): { score: number; label: string; color: string } {
    const v = this.agentVulns()[agent.id] ?? { critical: 0, high: 0, medium: 0 };
    const score = Math.min(100, v.critical * 10 + v.high * 3 + v.medium);
    const label = score >= 70 ? 'Critical' : score >= 40 ? 'High' : score >= 15 ? 'Medium' : 'Low';
    return { score, label, color: score >= 40 ? 'rose' : 'emerald' };
  }

  /** Whether the agent runs the manager's Wazuh version. */
  agentCurrent(agent: Agent): boolean {
    return (agent.version || '').includes(this.managerVersion);
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
