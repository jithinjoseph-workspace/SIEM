import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { LucideAngularModule, Server, ShieldAlert, Activity, ShieldCheck, Database, HardDrive, Cpu, Radio, ArrowRight, RefreshCw } from 'lucide-angular';
import { SiemStatsService } from '../../../services/siem/siem-stats.service';
import { SiemStats } from '../../../models/siem.models';

@Component({
  selector: 'app-siem-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule],
  templateUrl: './siem-dashboard.component.html',
  styleUrl: './siem-dashboard.component.css'
})
export class SiemDashboardComponent implements OnInit {
  private statsService = inject(SiemStatsService);

  stats = signal<SiemStats>({
    total_events: 42800,
    total_alerts: 6,
    critical_alerts: 2,
    high_alerts: 3,
    medium_alerts: 1,
    low_alerts: 0,
    active_agents: 1,
    total_agents: 5
  });

  loading = signal<boolean>(true);

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

  mitreTactics = [
    { name: 'Credential Access', count: 4, pct: 45, color: '#ef4444' },
    { name: 'Privilege Escalation', count: 3, pct: 30, color: '#f97316' },
    { name: 'Defense Evasion', count: 2, pct: 20, color: '#f59e0b' },
    { name: 'Persistence', count: 1, pct: 10, color: '#3b82f6' }
  ];

  recentHostIncidents = [
    { host: 'prod-gateway-dc01', ip: '192.168.1.10', alert: 'SSH Brute Force from 185.220.101.5', severity: 'CRITICAL', time: '2m ago' },
    { host: 'win-ad-controller', ip: '192.168.1.20', alert: 'Mimikatz memory injection detected', severity: 'CRITICAL', time: '14m ago' },
    { host: 'k8s-node-worker-01', ip: '192.168.1.30', alert: 'FIM integrity altered for /etc/sudoers', severity: 'HIGH', time: '38m ago' }
  ];

  ngOnInit() {
    this.loadStats();
  }

  loadStats() {
    this.loading.set(true);
    this.statsService.getStats().subscribe({
      next: (data) => {
        this.stats.set(data);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
      }
    });
  }
}
