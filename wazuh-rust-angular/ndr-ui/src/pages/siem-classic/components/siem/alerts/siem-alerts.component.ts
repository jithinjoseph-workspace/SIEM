import { Component, OnInit, OnDestroy, inject, signal, computed, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, ShieldAlert, AlertTriangle, ShieldCheck, Search, RefreshCw, Radio, Terminal, ExternalLink, Filter, X, Shield, Lock, Activity, Check } from 'lucide-angular';
import { Subscription } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { SiemAlertsService } from '../../../services/siem/siem-alerts.service';
import { SiemAgentsService } from '../../../services/siem/siem-agents.service';
import { Alert } from '../../../models/siem.models';

@Component({
  selector: 'app-siem-alerts',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-alerts.component.html',
  styleUrl: './siem-alerts.component.css'
})
export class SiemAlertsComponent implements OnInit, OnDestroy {
  private alertsService = inject(SiemAlertsService);
  private agentsService = inject(SiemAgentsService);
  private http = inject(HttpClient);
  private subs: Subscription[] = [];

  @Input() compactMode = false;

  alerts = signal<Alert[]>([]);
  loading = signal<boolean>(true);
  searchQuery = signal<string>('');
  severityFilter = signal<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  selectedAlert = signal<Alert | null>(null);
  actionFeedback = signal<string | null>(null);
  wsActive = signal<boolean>(false);

  ShieldAlertIcon = ShieldAlert;
  AlertTriangleIcon = AlertTriangle;
  ShieldCheckIcon = ShieldCheck;
  CheckIcon = Check;
  SearchIcon = Search;
  RefreshIcon = RefreshCw;
  RadioIcon = Radio;
  TerminalIcon = Terminal;
  ExternalLinkIcon = ExternalLink;
  FilterIcon = Filter;
  XIcon = X;
  ShieldIcon = Shield;
  LockIcon = Lock;
  ActivityIcon = Activity;

  filteredAlerts = computed(() => {
    const query = this.searchQuery().toLowerCase().trim();
    const sev = this.severityFilter();

    return this.alerts().filter(a => {
      const matchQuery = !query ||
        a.rule.description.toLowerCase().includes(query) ||
        a.agent.name.toLowerCase().includes(query) ||
        a.agent.ip.includes(query) ||
        (a.rule.mitre?.tactic && a.rule.mitre.tactic.toLowerCase().includes(query)) ||
        (a.rule.mitre?.technique && a.rule.mitre.technique.toLowerCase().includes(query)) ||
        (a.decoded.src_ip && a.decoded.src_ip.includes(query));

      let matchSev = true;
      if (sev === 'critical') matchSev = a.rule.level >= 12;
      else if (sev === 'high') matchSev = a.rule.level >= 8 && a.rule.level < 12;
      else if (sev === 'medium') matchSev = a.rule.level >= 4 && a.rule.level < 8;
      else if (sev === 'low') matchSev = a.rule.level < 4;

      return matchQuery && matchSev;
    });
  });

  criticalCount = computed(() => this.alerts().filter(a => a.rule.level >= 12).length);
  highCount = computed(() => this.alerts().filter(a => a.rule.level >= 8 && a.rule.level < 12).length);
  mediumCount = computed(() => this.alerts().filter(a => a.rule.level >= 4 && a.rule.level < 8).length);
  lowCount = computed(() => this.alerts().filter(a => a.rule.level < 4).length);

  ngOnInit() {
    this.loadAlerts();

    // Subscribe to live alert stream
    this.subs.push(
      this.alertsService.getAlertStream().subscribe(newAlert => {
        this.alerts.update(current => [newAlert, ...current.slice(0, 199)]);
      })
    );

    this.subs.push(
      this.alertsService.getWsConnected().subscribe(connected => {
        this.wsActive.set(connected);
      })
    );
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }

  loadAlerts() {
    this.loading.set(true);
    this.alertsService.getAlerts(100).subscribe({
      next: (data) => {
        // Real alerts of the tenant only (no sample data).
        this.alerts.set(data || []);
        this.loading.set(false);
      },
      error: () => {
        this.alerts.set([]);
        this.loading.set(false);
      }
    });
  }

  getSeverityBadge(level: number): { label: string; class: string } {
    if (level >= 12) return { label: 'CRITICAL', class: 'badge-critical' };
    if (level >= 8) return { label: 'HIGH', class: 'badge-high' };
    if (level >= 4) return { label: 'MEDIUM', class: 'badge-medium' };
    return { label: 'LOW', class: 'badge-low' };
  }

  formatTimestamp(ts: string): string {
    if (!ts) return new Date().toLocaleTimeString();
    try {
      const d = new Date(ts);
      return isNaN(d.getTime()) ? ts : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  }

  selectAlert(alert: Alert) {
    this.selectedAlert.set(alert);
  }

  closeModal() {
    this.selectedAlert.set(null);
    this.actionFeedback.set(null);
  }

  /** The agents have no network-isolation action yet: say so instead of pretending. */
  /** Quarantines the agent's host through the tenant's switch / cloud integration (guardrails apply). */
  isolateHost(alert: Alert) {
    const ip = alert.agent?.ip;
    if (!ip || ip === 'any' || ip === '0.0.0.0') {
      this.actionFeedback.set(`Agent ${alert.agent?.id} has no known IP address to isolate.`);
      return;
    }
    if (!confirm(`Isolate ${alert.agent.name} (${ip}) from the network?`)) return;
    this.actionFeedback.set(`Isolating ${ip}…`);
    this.http.post<{ status: string; message?: string }>('/api/isolate', { target_ip: ip, reason: `Alert ${alert.rule?.id}: ${alert.rule?.description}` }).subscribe({
      next: () => this.actionFeedback.set(`${ip} isolated. Release it from SOAR > Isolations.`),
      error: (e) => this.actionFeedback.set(e.error?.message || (e.status === 403 ? 'Isolation needs the SOAR permission.' : 'Isolation failed.'))
    });
  }
}
