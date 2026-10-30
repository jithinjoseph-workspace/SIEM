import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  ShieldCheck, RefreshCw, CheckCircle2, AlertTriangle, XCircle, Info, Layers,
  FileText, Download, Filter, Maximize2, Lock, Key, Database, UserCheck,
  ChevronRight, Check, ExternalLink, Clock, ShieldAlert, FileSpreadsheet,
  AlertOctagon, SlidersHorizontal, Search
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { ComplianceFramework, ComplianceProfileCheck, ComplianceProfileResponse, ComplianceResponse } from '../../../services/siem/siem.models';
import { downloadText } from '../../../services/siem/agent-deploy';

export interface AuditLogItem {
  id: string;
  timestamp: string;
  actor: string;
  actorInitial: string;
  action: string;
  resource: string;
  risk: 'Informational' | 'Low' | 'Medium' | 'High';
  status: 'Pass' | 'Review Needed' | 'Fail';
}

export interface RemediationItem {
  id: string;
  title: string;
  framework: string;
  category: string;
  priority: 'critical' | 'warning' | 'medium';
  iconType: 'key' | 'policy' | 'audit' | 'db' | 'shield';
  resolved?: boolean;
  fw: string;
  reqId: string;
  /** the agent's remediation text for the failing check */
  detail?: string;
}

export interface ExtendedFramework extends ComplianceFramework {
  lastSync?: string;
  color?: 'cyan' | 'amber' | 'emerald' | 'rose' | 'indigo';
}

@Component({
  selector: 'app-compliance',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './compliance.html',
  styleUrl: './compliance.css',
})
export class Compliance implements OnInit {
  private siem = inject(SiemService);

  // Icons
  ShieldCheckIcon = ShieldCheck;
  RefreshIcon = RefreshCw;
  CheckIcon = CheckCircle2;
  AlertIcon = AlertTriangle;
  ErrorIcon = XCircle;
  InfoIcon = Info;
  LayersIcon = Layers;
  FileTextIcon = FileText;
  DownloadIcon = Download;
  FilterIcon = Filter;
  MaximizeIcon = Maximize2;
  LockIcon = Lock;
  KeyIcon = Key;
  DatabaseIcon = Database;
  UserCheckIcon = UserCheck;
  ChevronRightIcon = ChevronRight;
  CheckMarkIcon = Check;
  ExternalLinkIcon = ExternalLink;
  ClockIcon = Clock;
  ShieldAlertIcon = ShieldAlert;
  FileSpreadsheetIcon = FileSpreadsheet;
  AlertOctagonIcon = AlertOctagon;
  SlidersIcon = SlidersHorizontal;
  SearchIcon = Search;

  // Frameworks State
  frameworks = signal<ExtendedFramework[]>([]);
  selectedFramework = signal<ExtendedFramework | null>(null);
  loading = signal<boolean>(false);

  // Requirement Controls Filter
  controlSearch = signal<string>('');
  controlStatusFilter = signal<'all' | 'passed' | 'warning' | 'failed'>('all');

  // Report Generator State
  reportType = signal<string>('Executive Summary');
  reportFormat = signal<'pdf' | 'csv'>('pdf');
  includeEvidence = signal<boolean>(true);
  anonymizeActors = signal<boolean>(false);
  generatingReport = signal<boolean>(false);
  reportFeedback = signal<string | null>(null);

  /** The failing configuration checks, the ones breaking the most requirements first, with the agent's fix. */
  remediations = signal<RemediationItem[]>([]);
  remediationFeedback = signal<string | null>(null);

  /** The tenant's recent alerts whose rule a requirement maps (the evidence behind the scores). */
  auditLogs = signal<AuditLogItem[]>([]);

  auditSearch = signal<string>('');
  auditStatusFilter = signal<'all' | 'pass' | 'fail' | 'review'>('all');

  /** checks marked not needed, and who last changed the audit settings */
  excludedCount = signal(0);
  settingsUpdatedBy = signal('');

  // Audit settings: frameworks reported on, their agent-group scope, checks not needed
  settingsOpen = signal(false);
  settings = signal<ComplianceProfileResponse | null>(null);
  settingsLoading = signal(false);
  savingSettings = signal(false);
  settingsMsg = signal<{ ok: boolean; text: string } | null>(null);
  draftFrameworks = signal<Set<string>>(new Set());
  draftScope = signal<Record<string, string[]>>({});
  draftExcluded = signal<Set<string>>(new Set());
  checkSearch = signal('');
  checkPolicy = signal('');
  checkFramework = signal('');
  checkView = signal<'all' | 'required' | 'not_needed'>('all');
  checkLimit = signal(200);

  policies = computed(() => {
    const m = new Map<string, string>();
    for (const c of this.settings()?.checks ?? []) m.set(c.policy_id, c.policy);
    return [...m].map(([id, name]) => ({ id, name }));
  });
  filteredChecks = computed(() => {
    const q = this.checkSearch().toLowerCase().trim(), pol = this.checkPolicy(), fw = this.checkFramework(), view = this.checkView();
    const ex = this.draftExcluded();
    return (this.settings()?.checks ?? []).filter(c =>
      (!pol || c.policy_id === pol) && (!fw || c.frameworks.includes(fw))
      && (view === 'all' || (view === 'required') === !ex.has(c.check_id))
      && (!q || c.check_id.includes(q) || c.title.toLowerCase().includes(q)));
  });
  shownChecks = computed(() => this.filteredChecks().slice(0, this.checkLimit()));
  requiredCount = computed(() => (this.settings()?.checks ?? []).filter(c => !this.draftExcluded().has(c.check_id)).length);

  // Computed metrics: the average of the frameworks that have a configuration score
  overallMappedPercent = computed(() => {
    const scored = this.frameworks().map(f => f.score_percent).filter((p): p is number => p !== null);
    if (scored.length === 0) return 0;
    return Math.round(scored.reduce((acc, p) => acc + p, 0) / scored.length);
  });

  // Circular gauge SVG parameters (radius = 54, circumference ~ 339.292)
  readonly circleCircumference = 339.292;
  gaugeDashOffset = computed(() => {
    const pct = Math.min(100, Math.max(0, this.overallMappedPercent()));
    return this.circleCircumference * (1 - pct / 100);
  });

  private requirements = computed(() => this.frameworks().flatMap(f => f.requirements));
  passingControlsCount = computed(() => this.requirements().filter(r => r.status === 'passed').length);
  failingControlsCount = computed(() => this.requirements().filter(r => r.status !== 'passed').length);
  /** requirements seen only in alerts: no configuration check maps them */
  unmappedControlsCount = computed(() => this.requirements().filter(r => r.source === 'alerts').length);

  passAuditCount = computed(() => this.auditLogs().filter(l => l.status === 'Pass').length);
  failAuditCount = computed(() => this.auditLogs().filter(l => l.status === 'Fail').length);

  filteredAuditLogs = computed(() => {
    const q = this.auditSearch().toLowerCase().trim();
    const st = this.auditStatusFilter();
    return this.auditLogs().filter(l => {
      const matchSearch = !q ||
        l.actor.toLowerCase().includes(q) ||
        l.action.toLowerCase().includes(q) ||
        l.resource.toLowerCase().includes(q) ||
        l.risk.toLowerCase().includes(q);
      const matchStatus = st === 'all' ||
        (st === 'pass' && l.status === 'Pass') ||
        (st === 'fail' && l.status === 'Fail') ||
        (st === 'review' && l.status === 'Review Needed');
      return matchSearch && matchStatus;
    });
  });

  filteredRequirements = computed(() => {
    const fw = this.selectedFramework();
    if (!fw) return [];
    const q = this.controlSearch().toLowerCase().trim();
    const st = this.controlStatusFilter();
    return fw.requirements.filter(req => {
      const matchQuery = !q ||
        req.id.toLowerCase().includes(q) ||
        req.title.toLowerCase().includes(q) ||
        req.description.toLowerCase().includes(q);
      const matchStatus = st === 'all' || req.status === st;
      return matchQuery && matchStatus;
    });
  });

  ngOnInit() {
    this.loadCompliance();
  }

  /** `refresh` (Re-evaluate): the agents' latest scan results are fetched first. */
  loadCompliance(refresh = false) {
    this.loading.set(true);
    this.siem.getCompliance(refresh).subscribe({
      next: (res) => {
        const synced = res.last_updated ? this.ago(res.last_updated) : undefined;
        const enriched: ExtendedFramework[] = (res.frameworks || []).map(f => {
          const p = f.score_percent;
          const color: ExtendedFramework['color'] = p === null ? 'indigo' : p >= 90 ? 'emerald' : p >= 75 ? 'cyan' : p >= 60 ? 'amber' : 'rose';
          return { ...f, lastSync: synced, color };
        });

        this.frameworks.set(enriched);
        this.excludedCount.set(res.excluded_checks ?? 0);
        this.settingsUpdatedBy.set(res.profile_updated_by ?? '');
        // keep the selection only while that framework is still reported on
        const sel = this.selectedFramework();
        this.selectedFramework.set(enriched.find(f => f.name === sel?.name) ?? enriched[0] ?? null);
        this.loading.set(false);
        this.setRemediations(res);
        this.setEvidence(res);
      },
      error: () => this.loading.set(false)
    });
  }

  private setRemediations(res: ComplianceResponse) {
    this.remediations.set((res.remediations ?? []).map(r => {
      const [fw, reqId] = (r.requirements[0] ?? '').split(' ');
      return {
        id: r.check_id,
        title: r.title,
        framework: `Check ${r.check_id} • fails on ${r.failed_agents} agent(s) • ${r.requirements.join(', ')}`,
        category: fw ?? '',
        priority: r.requirements.length >= 3 ? 'critical' : 'warning',
        iconType: 'shield',
        fw: fw ?? '',
        reqId: reqId ?? '',
        detail: r.remediation,
      } as RemediationItem;
    }));
  }

  /** The recent alerts whose Wazuh rule carries compliance groups (the evidence behind the alert counts). */
  private setEvidence(res: ComplianceResponse) {
    this.auditLogs.set((res.evidence ?? []).map((e, i) => {
      const actor = e.agent_name || e.agent_id || 'manager';
      return {
        id: `${e.timestamp}-${i}`,
        timestamp: new Date(e.timestamp).toLocaleString(),
        actor,
        actorInitial: actor.slice(0, 2).toUpperCase(),
        action: e.description || `Rule ${e.rule_id}`,
        resource: e.requirements.join(', '),
        risk: e.level >= 12 ? 'High' : e.level >= 7 ? 'Medium' : e.level >= 4 ? 'Low' : 'Informational',
        // an alert is a finding to review; level 7 and up (Wazuh's "high importance") a failure
        status: e.level >= 7 ? 'Fail' : 'Review Needed',
      } as AuditLogItem;
    }));
  }

  /** The recent alerts behind the requirements: each mapped rule that fired. */
  private loadEvidence(frameworks: ExtendedFramework[]) {
    const byRule = new Map<number, string>();
    for (const fw of frameworks) for (const r of fw.requirements) for (const id of r.rule_ids ?? []) if (!byRule.has(id)) byRule.set(id, `${fw.name} ${r.id}`);
    this.siem.getAlerts(5000).subscribe({
      next: alerts => this.auditLogs.set((alerts ?? [])
        .filter(a => byRule.has(Number(a.rule?.id)))
        .slice(0, 100)
        .map((a, i) => {
          const level = a.rule?.level ?? 0;
          const actor = a.agent?.name || a.agent?.id || 'manager';
          return {
            id: `${a.id ?? i}`,
            timestamp: new Date(a.timestamp).toLocaleString(),
            actor,
            actorInitial: actor.slice(0, 2).toUpperCase(),
            action: a.rule?.description ?? `Rule ${a.rule?.id}`,
            resource: byRule.get(Number(a.rule?.id)) ?? '',
            risk: level >= 12 ? 'High' : level >= 7 ? 'Medium' : level >= 4 ? 'Low' : 'Informational',
            status: level >= 7 ? 'Fail' : 'Review Needed',
          } as AuditLogItem;
        })),
      error: () => this.auditLogs.set([])
    });
  }

  private ago(iso: string): string {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  /** Opens the audit settings with the saved profile as the draft. */
  openSettings() {
    this.settingsOpen.set(true);
    this.settingsMsg.set(null);
    this.settingsLoading.set(true);
    this.siem.getComplianceProfile().subscribe({
      next: (res) => {
        const all = res.frameworks.map(f => f.name);
        this.settings.set(res);
        this.draftFrameworks.set(new Set(res.profile.frameworks.length ? res.profile.frameworks : all));
        this.draftScope.set({ ...res.profile.scope });
        this.draftExcluded.set(new Set(res.profile.excluded_checks));
        this.settingsLoading.set(false);
      },
      error: (e) => {
        this.settingsLoading.set(false);
        this.settingsMsg.set({ ok: false, text: e?.error?.message || 'The audit settings could not be loaded.' });
      }
    });
  }

  toggleFramework(name: string) {
    const s = new Set(this.draftFrameworks());
    s.has(name) ? s.delete(name) : s.add(name);
    this.draftFrameworks.set(s);
  }

  inScope(fw: string, group: string): boolean {
    return (this.draftScope()[fw] ?? []).includes(group);
  }

  toggleScope(fw: string, group: string) {
    const cur = this.draftScope()[fw] ?? [];
    const next = cur.includes(group) ? cur.filter(g => g !== group) : [...cur, group];
    this.draftScope.set({ ...this.draftScope(), [fw]: next });
  }

  scopeAgents(fw: string): number | null {
    const groups = this.draftScope()[fw] ?? [];
    if (!groups.length) return null;
    return (this.settings()?.groups ?? []).filter(g => groups.includes(g.name)).reduce((n, g) => n + g.agents, 0);
  }

  isRequired(c: ComplianceProfileCheck): boolean {
    return !this.draftExcluded().has(c.check_id);
  }

  setRequired(ids: string[], required: boolean) {
    const s = new Set(this.draftExcluded());
    for (const id of ids) required ? s.delete(id) : s.add(id);
    this.draftExcluded.set(s);
  }

  /** Every check the filters show (not only the rows rendered so far). */
  setShownRequired(required: boolean) {
    this.setRequired(this.filteredChecks().map(c => c.check_id), required);
  }

  saveSettings() {
    const res = this.settings();
    if (!res) return;
    const chosen = res.frameworks.map(f => f.name).filter(n => this.draftFrameworks().has(n));
    if (!chosen.length) {
      this.settingsMsg.set({ ok: false, text: 'Choose at least one framework to report on.' });
      return;
    }
    const scope: Record<string, string[]> = {};
    for (const n of chosen) if (this.draftScope()[n]?.length) scope[n] = this.draftScope()[n];
    this.savingSettings.set(true);
    this.siem.saveComplianceProfile({
      // every framework chosen: saved as "all", so new frameworks show up too
      frameworks: chosen.length === res.frameworks.length ? [] : chosen,
      scope,
      excluded_checks: [...this.draftExcluded()],
    }).subscribe({
      next: () => {
        this.savingSettings.set(false);
        this.settingsOpen.set(false);
        this.remediationFeedback.set('Audit settings saved. Scores now use them.');
        setTimeout(() => this.remediationFeedback.set(null), 4000);
        this.loadCompliance();
      },
      error: (e) => {
        this.savingSettings.set(false);
        this.settingsMsg.set({ ok: false, text: e?.status === 403 ? 'Only a tenant admin can change the audit settings.' : (e?.error?.message || 'The audit settings were not saved.') });
      }
    });
  }

  selectFramework(fw: ExtendedFramework) {
    this.selectedFramework.set(fw);
  }

  /** Shows the requirement behind a queue item (its framework, filtered to it). */
  resolveRemediation(item: RemediationItem) {
    const fw = this.frameworks().find(f => f.name === item.fw);
    if (fw) this.selectedFramework.set(fw);
    this.controlStatusFilter.set('all');
    this.controlSearch.set(item.reqId);
    this.remediationFeedback.set(`Showing ${item.fw} ${item.reqId} in the requirements below`);
    setTimeout(() => this.remediationFeedback.set(null), 3500);
  }

  generateReport() {
    this.generatingReport.set(true);
    this.reportFeedback.set(null);

    setTimeout(() => {
      const type = this.reportType();
      const format = this.reportFormat();
      const dateStr = new Date().toISOString().split('T')[0];

      if (format === 'csv') {
        const rows: string[] = [];
        rows.push('Framework,Requirement ID,Status,Source,Failing check results,Passing check results,Alerts,Title');
        for (const fw of this.frameworks()) {
          for (const req of fw.requirements) {
            rows.push(`"${fw.name}","${req.id}","${req.status}","${req.source}",${req.checks_failed},${req.checks_passed},${req.alerts_count},"${req.title.replace(/"/g, '""')}"`);
          }
        }
        downloadText(`Compliance_${type.replace(/\s+/g, '_')}_${dateStr}.csv`, rows.join('\n'), 'text/csv');
      } else {
        // PDF / HTML formatted document
        const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${type} - Regulatory Compliance & Audit Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 40px; margin: 0; }
    h1 { color: #38bdf8; font-size: 24px; border-bottom: 2px solid #1e293b; padding-bottom: 12px; }
    .meta { font-size: 13px; color: #94a3b8; margin-bottom: 24px; }
    .score-box { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; margin-bottom: 24px; display: inline-block; }
    .score { font-size: 32px; font-weight: bold; color: #10b981; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
    th { text-align: left; background: #1e293b; color: #e2e8f0; padding: 10px; border: 1px solid #334155; }
    td { padding: 10px; border: 1px solid #1e293b; }
    .badge-passed { color: #10b981; font-weight: bold; }
    .badge-warning { color: #f59e0b; font-weight: bold; }
    .badge-failed { color: #f43f5e; font-weight: bold; }
  </style>
</head>
<body>
  <h1>ProVigil AI — ${type}</h1>
  <div class="meta">Generated: ${new Date().toUTCString()} | Overall Mapped Compliance: ${this.overallMappedPercent()}%</div>
  <div class="score-box">
    <div>Overall System Compliance Score</div>
    <div class="score">${this.overallMappedPercent()}%</div>
  </div>
  <h2>Framework Summaries</h2>
  <table>
    <thead>
      <tr><th>Framework</th><th>Mapping</th><th>Configuration score</th><th>Requirements passed</th><th>Alerts (24 h)</th></tr>
    </thead>
    <tbody>
      ${this.frameworks().map(f => `<tr><td>${f.name}</td><td>${f.version}</td><td>${f.score_percent === null ? 'no configuration score' : f.score_percent + '%'}</td><td>${f.passed_count}/${f.total_requirements}</td><td>${f.alert_count}</td></tr>`).join('')}
    </tbody>
  </table>
  <p style="margin-top: 30px; font-size: 11px; color: #64748b;">This document is generated automatically by ProVigil SIEM Security & Regulatory Compliance Engine.</p>
</body>
</html>`;
        downloadText(`Compliance_${type.replace(/\s+/g, '_')}_${dateStr}.html`, html, 'text/html');
      }

      this.generatingReport.set(false);
      this.reportFeedback.set(`✓ ${type} generated and exported successfully!`);
      setTimeout(() => this.reportFeedback.set(null), 4000);
    }, 800);
  }
}
