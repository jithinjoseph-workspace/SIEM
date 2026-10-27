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
import { ComplianceFramework, ComplianceRequirement } from '../../../services/siem/siem.models';
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

  /** The requirements that fail or need review, worst first (from the compliance evaluation). */
  remediations = computed<RemediationItem[]>(() =>
    this.frameworks()
      .flatMap(fw => fw.requirements
        .filter(r => r.status !== 'passed')
        .map(r => ({
          id: `${fw.name}-${r.id}`,
          title: r.title,
          framework: `${fw.name} ${r.id} • ${r.alerts_count} alert(s)`,
          category: fw.name,
          priority: (r.status === 'failed' ? 'critical' : 'warning') as RemediationItem['priority'],
          iconType: 'shield' as const,
          fw: fw.name,
          reqId: r.id,
        })))
      .sort((a, b) => (a.priority === 'critical' ? 0 : 1) - (b.priority === 'critical' ? 0 : 1)));
  remediationFeedback = signal<string | null>(null);

  /** The tenant's recent alerts whose rule a requirement maps (the evidence behind the scores). */
  auditLogs = signal<AuditLogItem[]>([]);

  auditSearch = signal<string>('');
  auditStatusFilter = signal<'all' | 'pass' | 'fail' | 'review'>('all');

  // Computed metrics
  overallMappedPercent = computed(() => {
    const list = this.frameworks();
    if (list.length === 0) return 0;
    const avg = list.reduce((acc, f) => acc + f.score_percent, 0) / list.length;
    return Math.round(avg);
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
  unmappedControlsCount = computed(() => this.requirements().filter(r => !r.rule_ids?.length).length);

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

  loadCompliance() {
    this.loading.set(true);
    this.siem.getCompliance().subscribe({
      next: (res) => {
        const synced = res.last_updated ? this.ago(res.last_updated) : undefined;
        const enriched: ExtendedFramework[] = (res.frameworks || []).map(f => {
          let color: 'cyan' | 'amber' | 'emerald' | 'rose' | 'indigo' = 'cyan';
          if (f.score_percent >= 90) color = 'emerald';
          else if (f.score_percent >= 75) color = 'cyan';
          else if (f.score_percent >= 60) color = 'amber';
          else color = 'rose';
          return { ...f, lastSync: synced, color };
        });

        this.frameworks.set(enriched);
        if (enriched.length > 0 && !this.selectedFramework()) {
          this.selectedFramework.set(enriched[0]);
        }
        this.loading.set(false);
        this.loadEvidence(enriched);
      },
      error: () => this.loading.set(false)
    });
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
        rows.push('Framework,Requirement ID,Title,Status,Alerts Count');
        for (const fw of this.frameworks()) {
          for (const req of fw.requirements) {
            rows.push(`"${fw.name}","${req.id}","${req.title.replace(/"/g, '""')}","${req.status}",${req.alerts_count}`);
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
      <tr><th>Framework</th><th>Version</th><th>Score</th><th>Passed</th><th>Alerts</th></tr>
    </thead>
    <tbody>
      ${this.frameworks().map(f => `<tr><td>${f.name}</td><td>${f.version}</td><td>${f.score_percent}%</td><td>${f.passed_count}/${f.total_requirements}</td><td>${f.alert_count}</td></tr>`).join('')}
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
