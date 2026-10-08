import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';

export interface UnifiedAlert {
  alert_id: string;
  tenant_id: string;
  source: 'ndr' | 'siem' | 'corroborated' | 'threat_intel';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  rule_name: string;
  title: string;
  description: string;
  affected_hosts: string[];
  mitre_techniques: string[];
  status: string;
  created_at: string;
  ai_summary?: string;
}

@Component({
  selector: 'app-xdr-alerts',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './xdr-alerts.html',
  styleUrls: ['./xdr-alerts.css'],
})
export class XdrAlerts implements OnInit, OnDestroy {
  alerts: UnifiedAlert[] = [];
  loading = true;
  error: string | null = null;

  filterSource: string = 'all';
  filterSeverity: string = 'all';
  filterStatus: string = 'all';

  private sub?: Subscription;
  private pollTimer?: ReturnType<typeof setInterval>;

  readonly sources = ['all', 'ndr', 'siem', 'corroborated'];
  readonly severities = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  readonly statuses = ['all', 'New', 'Investigating', 'Escalated', 'Resolved'];

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.load();
    this.pollTimer = setInterval(() => this.load(), 30_000);
  }

  ngOnDestroy() {
    this.sub?.unsubscribe();
    if (this.pollTimer) clearInterval(this.pollTimer);
  }

  load() {
    const params: Record<string, string> = {};
    if (this.filterSource !== 'all') params['source'] = this.filterSource;
    if (this.filterSeverity !== 'all') params['severity'] = this.filterSeverity;
    if (this.filterStatus !== 'all') params['status'] = this.filterStatus;

    this.sub?.unsubscribe();
    this.sub = this.http.get<{ alerts: UnifiedAlert[]; total: number }>(
      '/api/xdr/alerts', { params }
    ).subscribe({
      next: res => {
        this.alerts = res.alerts ?? [];
        this.loading = false;
        this.error = null;
      },
      error: () => {
        this.loading = false;
        this.error = 'Failed to load alerts';
      }
    });
  }

  get criticalCount(): number {
    return this.alerts.filter(a => a.severity === 'CRITICAL').length;
  }

  get filteredAlerts(): UnifiedAlert[] {
    return this.alerts;
  }

  severityClass(s: string): string {
    return ({
      CRITICAL: 'sev-critical',
      HIGH: 'sev-high',
      MEDIUM: 'sev-medium',
      LOW: 'sev-low',
      INFO: 'sev-info',
    } as Record<string, string>)[s] ?? 'sev-info';
  }

  sourceLabel(s: string): string {
    return ({ ndr: 'NDR', siem: 'SIEM', corroborated: 'XDR: NDR+SIEM', threat_intel: 'Threat Intel' } as Record<string, string>)[s] ?? s;
  }

  sourceClass(s: string): string {
    return ({ ndr: 'src-ndr', siem: 'src-siem', corroborated: 'src-xdr', threat_intel: 'src-ti' } as Record<string, string>)[s] ?? '';
  }
}
