import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { LucideAngularModule, Server, ShieldAlert, Activity, ShieldCheck, Database, HardDrive, Cpu, Radio, ArrowRight, RefreshCw } from 'lucide-angular';
import { SiemStatsService } from '../../../services/siem/siem-stats.service';
import { SiemStats } from '../../../models/siem.models';

const TACTIC_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#3b82f6'];

@Component({
  selector: 'app-siem-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './siem-dashboard.component.html',
  styleUrl: './siem-dashboard.component.css'
})
export class SiemDashboardComponent implements OnInit {
  private statsService = inject(SiemStatsService);
  private http = inject(HttpClient);

  stats = signal<SiemStats>({
    total_events: 0,
    total_alerts: 0,
    critical_alerts: 0,
    high_alerts: 0,
    medium_alerts: 0,
    low_alerts: 0,
    active_agents: 0,
    total_agents: 0
  });

  loading = signal<boolean>(true);
  error = signal<string | null>(null);

  ServerIcon = Server;
  ShieldAlertIcon = ShieldAlert;
  ActivityIcon = Activity;
  ShieldCheckIcon = ShieldCheck;
  DatabaseIcon = Database;
  HardDriveIcon = HardDrive;
  CpuIcon = Cpu;
  RadioIcon = Radio;
  ArrowRightIcon = ArrowRight;
  RefreshIcon = RefreshCw;

  /** The four tactics with the most alerts (from the tenant's MITRE matrix). */
  mitreTactics = signal<{ name: string; count: number; pct: number; color: string }[]>([]);
  /** The tenant's latest alerts. */
  recentHostIncidents = signal<{ host: string; alert: string; severity: string; time: string }[]>([]);

  ngOnInit() {
    this.loadStats();
  }

  loadStats() {
    this.loading.set(true);
    this.error.set(null);
    this.statsService.getStats().subscribe({
      next: (data) => {
        this.stats.set(data);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
        this.error.set('Could not load the SIEM statistics.');
      }
    });
    this.http.get<{ matrix: { name: string; techniques: { alert_count: number }[] }[] }>('/api/v1/mitre/matrix').subscribe({
      next: (m) => {
        const counts = (m.matrix ?? [])
          .map(t => ({ name: t.name, count: (t.techniques ?? []).reduce((n, x) => n + (x.alert_count || 0), 0) }))
          .filter(t => t.count > 0)
          .sort((a, b) => b.count - a.count);
        const total = counts.reduce((n, t) => n + t.count, 0);
        this.mitreTactics.set(counts.slice(0, 4).map((t, i) => ({ ...t, pct: total ? Math.round(t.count * 100 / total) : 0, color: TACTIC_COLORS[i] })));
      },
      error: () => this.mitreTactics.set([])
    });
    this.http.get<{ recent_alerts: { title: string; severity: string; source: string; created_at: string }[] }>('/api/siem/dashboard').subscribe({
      next: (d) => this.recentHostIncidents.set((d.recent_alerts ?? []).slice(0, 5).map(a => ({
        host: a.source, alert: a.title, severity: a.severity, time: this.ago(a.created_at)
      }))),
      error: () => this.recentHostIncidents.set([])
    });
  }

  private ago(iso: string): string {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }
}
