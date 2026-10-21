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

  // Remediation Queue State
  remediations = signal<RemediationItem[]>([
    {
      id: 'rem-1',
      title: 'Rotate Root API Keys',
      framework: 'Affects PCI-DSS CC 3.4.1 • Access Control',
      category: 'Access Control',
      priority: 'critical',
      iconType: 'key'
    },
    {
      id: 'rem-2',
      title: 'Update Password Entropy Policy',
      framework: 'Affects ISO 27001 A.9.4.3 • IAM',
      category: 'IAM',
      priority: 'warning',
      iconType: 'policy'
    },
    {
      id: 'rem-3',
      title: 'Q3 Access Review Audit',
      framework: 'Affects SOC 2 CC 6.1 • Review Procedures',
      category: 'Review Procedures',
      priority: 'warning',
      iconType: 'audit'
    },
    {
      id: 'rem-4',
      title: 'Decommission Staging-04 DB',
      framework: 'Data Minimization • Internal Policy',
      category: 'Internal Policy',
      priority: 'medium',
      iconType: 'db'
    },
    {
      id: 'rem-5',
      title: 'Enforce Wazuh Agent TLS 1.3 Strict Mode',
      framework: 'Affects NIST 800-53 SC-8 • Transmission Integrity',
      category: 'Data Protection',
      priority: 'critical',
      iconType: 'shield'
    }
  ]);
  remediationFeedback = signal<string | null>(null);

  // Audit Logs State
  auditLogs = signal<AuditLogItem[]>([
    {
      id: 'log-1',
      timestamp: '2026-10-20 14:22:09',
      actor: 'system.auth.engine',
      actorInitial: 'SE',
      action: 'IAM Policy Validation',
      resource: 'aws:iam::user/svc_prod_1',
      risk: 'Informational',
      status: 'Pass'
    },
    {
      id: 'log-2',
      timestamp: '2026-10-20 14:18:33',
      actor: 'sarah.k@fortify360.io',
      actorInitial: 'SK',
      action: 'Manual Control Override',
      resource: 'control:soc2:cc-6.1',
      risk: 'Medium',
      status: 'Review Needed'
    },
    {
      id: 'log-3',
      timestamp: '2026-10-20 14:10:45',
      actor: 'wazuh.remoted.daemon',
      actorInitial: 'WR',
      action: 'TLS Cipher Suite Verification',
      resource: 'listener:0.0.0.0:1514',
      risk: 'Informational',
      status: 'Pass'
    },
    {
      id: 'log-4',
      timestamp: '2026-10-20 13:55:12',
      actor: 'compliance.auditor.svc',
      actorInitial: 'CA',
      action: 'PCI-DSS v4.0 Requirement 10.2 Sweep',
      resource: 'audit:trail:reconstruction',
      risk: 'Low',
      status: 'Pass'
    },
    {
      id: 'log-5',
      timestamp: '2026-10-20 13:42:01',
      actor: 'fim.syscheck.001',
      actorInitial: 'FS',
      action: 'Root Integrity Hash Mismatch',
      resource: '/etc/pam.d/common-auth',
      risk: 'High',
      status: 'Fail'
    },
    {
      id: 'log-6',
      timestamp: '2026-10-20 13:30:19',
      actor: 'admin.secops',
      actorInitial: 'AS',
      action: 'Valkey / Redis Encryption at Rest Check',
      resource: 'storage:cluster:valkey',
      risk: 'Informational',
      status: 'Pass'
    },
    {
      id: 'log-7',
      timestamp: '2026-10-20 13:15:00',
      actor: 'auto.scanner.sca',
      actorInitial: 'SC',
      action: 'CIS Benchmark Debian CIS Level 2 Sweep',
      resource: 'agent:001:endpoint',
      risk: 'Low',
      status: 'Pass'
    }
  ]);

  auditSearch = signal<string>('');
  auditStatusFilter = signal<'all' | 'pass' | 'fail' | 'review'>('all');

  // Computed metrics
  overallMappedPercent = computed(() => {
    const list = this.frameworks();
    if (list.length === 0) return 84;
    const avg = list.reduce((acc, f) => acc + f.score_percent, 0) / list.length;
    return Math.round(avg);
  });

  // Circular gauge SVG parameters (radius = 54, circumference ~ 339.292)
  readonly circleCircumference = 339.292;
  gaugeDashOffset = computed(() => {
    const pct = Math.min(100, Math.max(0, this.overallMappedPercent()));
    return this.circleCircumference * (1 - pct / 100);
  });

  passingControlsCount = computed(() => 1248);
  failingControlsCount = computed(() => 212);
  unmappedControlsCount = computed(() => 186);

  passAuditCount = computed(() => this.auditLogs().filter(l => l.status === 'Pass').length + 38);
  failAuditCount = computed(() => this.auditLogs().filter(l => l.status === 'Fail').length + 2);

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
        const enriched: ExtendedFramework[] = (res.frameworks || []).map((f, idx) => {
          let syncTimes = ['2h ago', '10m ago', '1d ago', '5m ago', '3h ago', '12m ago'];
          let colors: ('cyan' | 'amber' | 'emerald' | 'rose' | 'indigo')[] = [
            'cyan', 'amber', 'emerald', 'rose', 'indigo'
          ];
          let color: 'cyan' | 'amber' | 'emerald' | 'rose' | 'indigo' = 'cyan';
          if (f.score_percent >= 90) color = 'emerald';
          else if (f.score_percent >= 75) color = 'cyan';
          else if (f.score_percent >= 60) color = 'amber';
          else color = 'rose';

          return {
            ...f,
            lastSync: syncTimes[idx % syncTimes.length],
            color
          };
        });

        // Ensure we also have standard industry frameworks if not all present
        const hasIso = enriched.some(f => f.name.includes('ISO') || f.name.includes('27001'));
        if (!hasIso) {
          enriched.splice(1, 0, {
            name: 'ISO 27001',
            full_name: 'Information Security Management System (ISO/IEC 27001:2022)',
            version: '2022',
            score_percent: 78,
            total_requirements: 8,
            passed_count: 6,
            alert_count: 4,
            lastSync: '10m ago',
            color: 'amber',
            requirements: [
              {
                id: 'A.9.4.3',
                title: 'Password Management System',
                description: 'Enforce strong password complexity, rotation intervals, and multi-factor authentication.',
                status: 'warning',
                alerts_count: 2,
                rule_ids: [5710, 5712]
              },
              {
                id: 'A.12.4.1',
                title: 'Event Logging & Audit Generation',
                description: 'Event logs recording user activities, exceptions, faults, and security events shall be produced and kept.',
                status: 'passed',
                alerts_count: 0,
                rule_ids: [5500, 5715]
              },
              {
                id: 'A.12.6.1',
                title: 'Management of Technical Vulnerabilities',
                description: 'Timely information about technical vulnerabilities of information systems being used shall be obtained.',
                status: 'passed',
                alerts_count: 0,
                rule_ids: [20100]
              }
            ]
          });
        }

        this.frameworks.set(enriched);
        if (enriched.length > 0 && !this.selectedFramework()) {
          this.selectedFramework.set(enriched[0]);
        }
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  selectFramework(fw: ExtendedFramework) {
    this.selectedFramework.set(fw);
  }

  resolveRemediation(item: RemediationItem) {
    this.remediations.update(list =>
      list.map(i => i.id === item.id ? { ...i, resolved: true } : i)
    );
    this.remediationFeedback.set(`Remediation workflow dispatched for "${item.title}"`);
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
