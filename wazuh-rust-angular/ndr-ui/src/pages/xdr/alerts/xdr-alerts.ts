import { Component, OnInit, OnDestroy, computed, signal } from '@angular/core';
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
  // signals: the page redraws when the answer arrives (the app has no zone.js)
  alerts = signal<UnifiedAlert[]>([]);
  /** All items matching the filters (the list shows the newest page). */
  total = signal(0);
  loading = signal(true);
  error = signal<string | null>(null);

  filterSource: string = 'all';
  filterSeverity: string = 'all';
  filterStatus: string = 'all';

  private sub?: Subscription;
  private pollTimer?: ReturnType<typeof setInterval>;

  readonly sources = ['all', 'ndr', 'siem', 'corroborated'];
  /** The queue holds high and critical items only (medium and low stay on each module's alert pages). */
  readonly severities = ['all', 'CRITICAL', 'HIGH'];
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
        this.alerts.set(res.alerts ?? []);
        this.total.set(res.total ?? res.alerts?.length ?? 0);
        this.loading.set(false);
        this.error.set(null);
      },
      error: () => {
        this.loading.set(false);
        this.error.set('Failed to load alerts');
      }
    });
  }

  criticalCount = computed(() => this.alerts().filter(a => a.severity === 'CRITICAL').length);

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
