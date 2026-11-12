import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  AlertTriangle, RefreshCw, Play, ShieldAlert, CheckCircle2,
  Filter, Search, Bug, Database, Layers, ArrowLeft, Download, X
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { Agent, VulnerabilityDetectionItem } from '../../../services/siem/siem.models';

type Severity = 'critical' | 'high' | 'medium' | 'low';
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
/** The report's columns (`columns=` of the API), in its default order. */
const REPORT_COLUMNS = [
  { key: 'risk', label: 'Risk' },
  { key: 'cve', label: 'CVE ID' },
  { key: 'title', label: 'Vulnerability Title' },
  { key: 'description', label: 'Description' },
  { key: 'cvss', label: 'CVSS Score' },
  { key: 'agent', label: 'Agent' },
  { key: 'package', label: 'Package' },
  { key: 'installed', label: 'Installed Version' },
  { key: 'fixed', label: 'Fixed Version' },
  { key: 'location', label: 'Location' },
  { key: 'recommendation', label: 'Recommendation' },
  { key: 'published', label: 'Published' },
  { key: 'detected', label: 'Detected' },
  { key: 'reference', label: 'Reference' },
  { key: 'check', label: 'Check' },
  { key: 'status', label: 'Status' },
];
const COLUMNS_KEY = 'provigil.vulnReport.columns';

@Component({
  selector: 'app-vulnerabilities',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './vulnerabilities.html',
  styleUrl: './vulnerabilities.css',
})
export class Vulnerabilities implements OnInit {
  private siem = inject(SiemService);
  scanMessage = signal<string | null>(null);

  // Icons
  AlertIcon = AlertTriangle;
  RefreshIcon = RefreshCw;
  PlayIcon = Play;
  ShieldIcon = ShieldAlert;
  CheckIcon = CheckCircle2;
  FilterIcon = Filter;
  SearchIcon = Search;
  BugIcon = Bug;
  DbIcon = Database;
  LayersIcon = Layers;
  BackIcon = ArrowLeft;
  DownloadIcon = Download;
  CloseIcon = X;

  // State
  vulnItems = signal<VulnerabilityDetectionItem[]>([]);
  vulnStats = signal<{ total: number; critical: number; high: number; medium: number; low: number }>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  severityFilter = signal<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  searchQuery = signal<string>('');
  loading = signal<boolean>(false);
  isScanning = signal<boolean>(false);

  filteredVulns = computed(() => {
    let list = this.vulnItems();
    const sev = this.severityFilter();
    const q = this.searchQuery().toLowerCase().trim();
    const agent = this.selectedAgent();

    if (agent) {
      list = list.filter(v => v.agent_id === agent);
    } else if (this.groupFilter() || this.segmentFilter() || this.typeFilter()) {
      this.groupsOf(); this.seg();
      list = list.filter(v => this.inGroup(v.agent_id));
    }
    if (sev !== 'all') {
      list = list.filter(v => v.severity.toLowerCase() === sev);
    }
    if (q) {
      list = list.filter(v =>
        v.cve.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.package_name.toLowerCase().includes(q) ||
        v.agent_id.toLowerCase().includes(q)
      );
    }
    return list;
  });

  /** The default Agents view, or the fleet By CVE view. */
  tab = signal<'agents' | 'cve'>('agents');
  agents = signal<Agent[]>([]);
  /** The agent whose CVE list is open. */
  selectedAgent = signal<string | null>(null);
  /** Ticked rows of the Agents view, for the export. */
  ticked = signal<Set<string>>(new Set());
  readonly agentPageSize = 100;
  agentPage = signal<number>(0);

  /** One row per agent, also those without detections; most critical first. */
  agentRows = computed(() => {
    const m = new Map<string, { id: string; name: string; os: string; critical: number; high: number; medium: number; low: number; total: number }>();
    const row = (id: string) => {
      let r = m.get(id);
      if (!r) m.set(id, r = { id, name: id, os: '', critical: 0, high: 0, medium: 0, low: 0, total: 0 });
      return r;
    };
    for (const a of this.agents()) Object.assign(row(a.id), { name: a.name, os: a.os });
    for (const v of this.vulnItems()) {
      const r = row(v.agent_id);
      if (r.name === r.id && v.agent_name) r.name = v.agent_name;
      if (!r.os && v.os) r.os = v.os;
      const s = v.severity.toLowerCase() as Severity;
      if (SEVERITIES.includes(s)) r[s]++;
      r.total++;
    }
    return [...m.values()].sort((a, b) => b.critical - a.critical || b.high - a.high || b.total - a.total || a.name.localeCompare(b.name));
  });
  /** The tenant's agent groups and their agents, for the group filter and labels. */
  groups = signal<{ name: string; agent_ids: string[] }[]>([]);
  groupFilter = signal<string>('');
  groupsOf = computed(() => {
    const m = new Map<string, string[]>();
    for (const g of this.groups()) for (const id of g.agent_ids) m.set(id, [...(m.get(id) ?? []), g.name]);
    return m;
  });
  /** Network segments (subnets, named by the tenant admin) and PC types. */
  seg = signal<{ agents: Record<string, { segments: string[]; guessed: boolean; type: string }>; names: { cidr: string; name: string }[]; editable: boolean }>({ agents: {}, names: [], editable: false });
  segmentFilter = signal<string>('');
  typeFilter = signal<string>('');
  readonly types = [
    { id: 'windows-workstation', label: 'Windows workstation' }, { id: 'windows-server', label: 'Windows server' },
    { id: 'linux', label: 'Linux' }, { id: 'macos', label: 'macOS' }, { id: 'unknown', label: 'Unknown' },
  ];
  segName = computed(() => new Map(this.seg().names.map(n => [n.cidr, n.name])));
  /** Every segment an agent is in, with how many agents, named ones first. */
  segments = computed(() => {
    const count = new Map<string, number>();
    for (const a of Object.values(this.seg().agents)) for (const s of a.segments) count.set(s, (count.get(s) ?? 0) + 1);
    for (const n of this.seg().names) if (!count.has(n.cidr)) count.set(n.cidr, 0);
    return [...count.entries()].map(([cidr, agents]) => ({ cidr, agents, name: this.segName().get(cidr) ?? '' }))
      .sort((a, b) => Number(!a.name) - Number(!b.name) || a.cidr.localeCompare(b.cidr, undefined, { numeric: true }));
  });
  segLabel(cidr: string): string {
    const n = this.segName().get(cidr);
    return n ? `${n} (${cidr})` : cidr;
  }
  agentSegs(id: string) { return this.seg().agents[id]?.segments ?? []; }
  segTitle(id: string): string {
    return this.seg().agents[id]?.guessed ? 'Guessed from the agent address (no network inventory)' : 'From the network card of the PC';
  }
  private inGroup(agentId: string): boolean {
    const g = this.groupFilter();
    const s = this.segmentFilter();
    const t = this.typeFilter();
    const a = this.seg().agents[agentId];
    return (!g || (this.groupsOf().get(agentId) ?? []).includes(g))
      && (!s || (a?.segments ?? []).includes(s))
      && (!t || (a?.type ?? 'unknown') === t);
  }
  namingOpen = signal<boolean>(false);
  segDraft: Record<string, string> = {};
  segMessage = signal<string | null>(null);
  saveSegmentName(cidr: string) {
    const name = (this.segDraft[cidr] ?? '').trim();
    this.siem.setSegmentName(cidr, name).subscribe({
      next: () => { this.segMessage.set(name ? `${cidr} is now "${name}".` : `The name of ${cidr} was removed.`); this.loadSegments(); },
      error: e => this.segMessage.set(e?.error?.message || 'The name was not saved.'),
    });
  }
  loadSegments() {
    this.siem.getSegments().subscribe(s => {
      this.seg.set(s);
      this.segDraft = Object.fromEntries(s.names.map(n => [n.cidr, n.name]));
    });
  }
  filteredAgents = computed(() => {
    const sev = this.severityFilter();
    const q = this.searchQuery().toLowerCase().trim();
    this.groupFilter(); this.groupsOf(); this.segmentFilter(); this.typeFilter(); this.seg();
    return this.agentRows().filter(r => this.inGroup(r.id) && (sev === 'all' || r[sev] > 0) && (!q || r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.os.toLowerCase().includes(q)));
  });
  agentPages = computed(() => Math.max(1, Math.ceil(this.filteredAgents().length / this.agentPageSize)));
  pagedAgents = computed(() => {
    const start = this.agentPage() * this.agentPageSize;
    return this.filteredAgents().slice(start, start + this.agentPageSize);
  });
  /** The open agent's row, for its heading and the KPI cards. */
  agentRow = computed(() => this.agentRows().find(r => r.id === this.selectedAgent()) ?? null);
  kpis = computed(() => this.agentRow() ?? this.vulnStats());

  /** The CVE table: one row per CVE and package with its agents (fleet), or the open agent's CVEs. */
  byCve = computed(() => !this.selectedAgent());
  /** At most this many rows are drawn; the search narrows the rest. */
  readonly maxRows = 500;
  rows = computed(() => {
    const list = this.filteredVulns();
    if (!this.byCve()) return list.map(v => ({ ...v, agents: [v.agent_id] }));
    const groups = new Map<string, VulnerabilityDetectionItem & { agents: string[] }>();
    for (const v of list) {
      const k = `${v.cve}|${v.package_name}|${v.installed_version}`;
      const g = groups.get(k);
      if (g) { if (!g.agents.includes(v.agent_id)) g.agents.push(v.agent_id); } else groups.set(k, { ...v, agents: [v.agent_id] });
    }
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    return [...groups.values()].sort((a, b) => (rank[a.severity.toLowerCase()] ?? 4) - (rank[b.severity.toLowerCase()] ?? 4) || b.agents.length - a.agents.length);
  });

  // Export dialog
  readonly severities = SEVERITIES;
  readonly reportColumns = REPORT_COLUMNS;
  exportOpen = signal<boolean>(false);
  exportAgents = signal<'current' | 'ticked' | 'all'>('all');
  exportSeverities = signal<Set<Severity>>(new Set(SEVERITIES));
  exportColumns = signal<Set<string>>(this.savedColumns());
  exporting = signal<boolean>(false);
  exportError = signal<string | null>(null);

  ngOnInit() {
    this.loadVulnerabilities();
    this.siem.getGroups().subscribe(g => this.groups.set(g));
    this.loadSegments();
  }

  showTab(tab: 'agents' | 'cve') {
    this.tab.set(tab);
    this.selectedAgent.set(null);
  }

  /** The search was for agents; here it would hide the CVEs. */
  openAgent(id: string) {
    this.selectedAgent.set(id);
    this.searchQuery.set('');
  }

  /** Search or filter changed: back to the first page of agents. */
  firstPage() {
    this.agentPage.set(0);
  }

  toggled<T>(set: Set<T>, value: T): Set<T> {
    const next = new Set(set);
    if (!next.delete(value)) next.add(value);
    return next;
  }

  openExport() {
    this.exportAgents.set(this.selectedAgent() ? 'current' : this.ticked().size ? 'ticked' : 'all');
    this.exportError.set(null);
    this.exportOpen.set(true);
  }

  private savedColumns(): Set<string> {
    const all = REPORT_COLUMNS.map(c => c.key);
    try {
      const saved: unknown = JSON.parse(localStorage.getItem(COLUMNS_KEY) ?? 'null');
      const known = Array.isArray(saved) ? all.filter(k => saved.includes(k)) : [];
      return new Set(known.length ? known : all);
    } catch {
      return new Set(all);
    }
  }

  toggleColumn(key: string) {
    this.exportColumns.set(this.toggled(this.exportColumns(), key));
    try {
      localStorage.setItem(COLUMNS_KEY, JSON.stringify([...this.exportColumns()]));
    } catch { /* not remembered: private window or storage blocked */ }
  }

  download() {
    const pick = this.exportAgents();
    const current = this.selectedAgent();
    const severity = [...this.exportSeverities()];
    this.exporting.set(true);
    this.exportError.set(null);
    this.siem.downloadVulnerabilityReport({
      agents: pick === 'current' && current ? [current] : pick === 'ticked' ? [...this.ticked()] : [],
      // all four: no filter, so CVEs not rated yet stay in
      severity: severity.length === SEVERITIES.length ? [] : severity,
      columns: REPORT_COLUMNS.map(c => c.key).filter(k => this.exportColumns().has(k)),
    }).subscribe({
      next: () => {
        this.exporting.set(false);
        this.exportOpen.set(false);
      },
      error: (err) => {
        this.exporting.set(false);
        this.exportError.set(err?.status === 413 ? 'Too many detections for one sheet: pick fewer agents or severities.' : err?.status === 403 ? 'One of these agents is outside your scope.' : 'The report could not be built.');
      }
    });
  }

  loadVulnerabilities() {
    this.loading.set(true);
    this.siem.getAgents().subscribe(a => this.agents.set(a));
    this.siem.getVulnerabilities().subscribe({
      next: (res) => {
        this.vulnItems.set(res.vulnerabilities);
        this.vulnStats.set({
          total: res.total,
          critical: res.critical_count,
          high: res.high_count,
          medium: res.medium_count,
          low: res.low_count
        });
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  triggerScanNow() {
    this.isScanning.set(true);
    this.scanMessage.set(null);
    this.siem.triggerVulnScan().subscribe({
      next: (r: any) => {
        this.isScanning.set(false);
        this.scanMessage.set(`✓ ${r?.message ?? 'Results refreshed'}`);
        this.loadVulnerabilities();
      },
      error: (err) => {
        this.isScanning.set(false);
        this.scanMessage.set(`✗ ${err?.error?.message || 'scan failed'}`);
        this.loadVulnerabilities();
      }
    });
  }
}
