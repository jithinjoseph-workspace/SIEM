import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import {
  LucideAngularModule,
  Sun,
  CloudSun,
  CloudRain,
  CloudLightning,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  FilePlus,
  TrendingUp,
  TrendingDown,
  Activity,
  Sparkles,
  Clock,
  Server,
  AlertTriangle,
  Bug,
  Sliders,
  Layers,
  ArrowUpRight,
  CheckCircle2,
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

interface Components {
  threat: number;
  vulnerabilities: number;
  hardening: number;
  progression: number;
  hygiene: number;
}
interface Driver {
  component: string;
  points: number;
  text: string;
  agent?: string | null;
}
interface HostScore {
  agent_id: string;
  agent_name: string;
  score: number;
}
interface Posture {
  score: number;
  band: string;
  components: Components;
  drivers: Driver[];
  hosts: HostScore[];
  notes: string[];
}
interface Forecast {
  score: number;
  low: number;
  high: number;
  band: string;
  components: Components;
  model: string;
  accuracy_mae: number | null;
}
interface Today {
  day: string;
  posture: Posture;
  forecast_next: Forecast;
  forecast_for_this_day: number | null;
  computed_at: string;
}
interface HistoryDay {
  day: string;
  score: number;
  band: string;
  forecast: number | null;
}

@Component({
  selector: 'app-siem-posture',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, RouterLink],
  templateUrl: './siem-posture.html',
  styleUrl: './siem-posture.css',
})
export class SiemPosture implements OnInit {
  private siem = inject(SiemService);

  // Icons
  RefreshIcon = RefreshCw;
  ShieldIcon = ShieldCheck;
  ShieldAlertIcon = ShieldAlert;
  CaseIcon = FilePlus;
  TrendingUpIcon = TrendingUp;
  TrendingDownIcon = TrendingDown;
  ActivityIcon = Activity;
  SparklesIcon = Sparkles;
  ClockIcon = Clock;
  ServerIcon = Server;
  AlertTriangleIcon = AlertTriangle;
  BugIcon = Bug;
  SlidersIcon = Sliders;
  LayersIcon = Layers;
  ArrowUpRightIcon = ArrowUpRight;
  CheckCircleIcon = CheckCircle2;

  today = signal<Today | null>(null);
  yesterday = signal<{ day: string; score: number; band: string; forecast: number | null } | null>(null);
  history = signal<HistoryDay[]>([]);
  loading = signal(false);
  error = signal<string | null>(null);
  message = signal<string | null>(null);

  // Score comparison vs yesterday
  scoreDelta = computed(() => {
    const t = this.today()?.posture.score;
    const y = this.yesterday()?.score;
    if (t == null || y == null) return null;
    return Number((t - y).toFixed(1));
  });

  components = computed(() => {
    const c = this.today()?.posture.components;
    return c
      ? [
          {
            key: 'Threat Activity',
            value: c.threat,
            weight: 30,
            icon: ShieldAlert,
            color: 'rose',
            desc: 'Real-time alert volume, high-severity detections, and malicious indicators',
          },
          {
            key: 'Vulnerability Exposure',
            value: c.vulnerabilities,
            weight: 25,
            icon: Bug,
            color: 'amber',
            desc: 'Unpatched CVEs, zero-day exposure, and host package vulnerabilities',
          },
          {
            key: 'Configuration Hardening',
            value: c.hardening,
            weight: 20,
            icon: Sliders,
            color: 'cyan',
            desc: 'CIS benchmark compliance, security baselines, and configuration audits',
          },
          {
            key: 'Attack Progression',
            value: c.progression,
            weight: 15,
            icon: Layers,
            color: 'violet',
            desc: 'Multi-stage MITRE ATT&CK kill-chain progression and lateral movement',
          },
          {
            key: 'Coverage & Hygiene',
            value: c.hygiene,
            weight: 10,
            icon: Activity,
            color: 'emerald',
            desc: 'Agent fleet connectivity, health heartbeats, and audit log telemetry completeness',
          },
        ]
      : [];
  });

  /** Trend chart points & closed area path */
  chart = computed(() => {
    const days = this.history();
    const w = 700,
      h = 180,
      n = Math.max(days.length - 1, 1);
    const x = (i: number) => 36 + (i * (w - 56)) / n;
    const y = (s: number) => 15 + ((100 - s) * (h - 40)) / 100;
    const line = (vals: (number | null)[]) =>
      vals
        .map((v, i) => (v == null ? null : `${x(i).toFixed(1)},${y(v).toFixed(1)}`))
        .filter(Boolean)
        .join(' ');

    const actualPoints = days.map((d, i) => ({ x: x(i), y: y(d.score), day: d.day, score: d.score, band: d.band }));
    
    // Compute SVG polygon for gradient area fill under actual line
    let areaPolygon = '';
    if (actualPoints.length > 0) {
      const bottomY = h - 20;
      const startX = actualPoints[0].x.toFixed(1);
      const endX = actualPoints[actualPoints.length - 1].x.toFixed(1);
      const pts = actualPoints.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
      areaPolygon = `${startX},${bottomY} ${pts} ${endX},${bottomY}`;
    }

    return {
      w,
      h,
      actual: line(days.map(d => d.score)),
      forecast: line(days.map(d => d.forecast)),
      area: areaPolygon,
      dots: actualPoints,
      grid: [100, 80, 60, 40, 20, 0].map(s => ({ y: y(s), s })),
      first: days[0]?.day ?? '',
      last: days[days.length - 1]?.day ?? '',
    };
  });

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getPosture().subscribe({
      next: r => {
        this.loading.set(false);
        this.error.set(null);
        this.today.set(r?.today ?? null);
        this.yesterday.set(r?.yesterday ?? null);
      },
      error: e => {
        this.loading.set(false);
        this.error.set(
          e?.status === 403
            ? 'You do not have permission to view the security posture.'
            : 'Security posture service is currently unreachable.'
        );
      },
    });
    this.siem.getPostureHistory(30).subscribe({
      next: r => this.history.set(r?.days ?? []),
      error: () => {},
    });
  }

  runNow() {
    this.loading.set(true);
    this.siem.runPosture().subscribe({
      next: r => {
        if (r?.status === 'error') {
          this.loading.set(false);
          this.error.set(r.message);
          return;
        }
        this.message.set('Security posture recalculated successfully.');
        setTimeout(() => this.message.set(null), 4000);
        this.load();
      },
      error: e => {
        this.loading.set(false);
        this.error.set(e?.error?.message || 'Posture recalculation failed.');
      },
    });
  }

  /** Radial gauge stroke dashoffset: radius = 54, circumference ~ 339.292 */
  gaugeOffset(score: number): number {
    const c = 339.292;
    const clamped = Math.max(0, Math.min(100, score));
    return c - (clamped / 100) * c;
  }

  icon(band?: string) {
    return band === 'Good' ? Sun : band === 'Fair' ? CloudSun : band === 'At Risk' ? CloudRain : CloudLightning;
  }

  bandClass(band?: string): string {
    return band === 'Good'
      ? 'text-emerald-400'
      : band === 'Fair'
      ? 'text-cyan-400'
      : band === 'At Risk'
      ? 'text-amber-400'
      : 'text-rose-400';
  }

  bandBorderClass(band?: string): string {
    return band === 'Good'
      ? 'border-emerald-500/30'
      : band === 'Fair'
      ? 'border-cyan-500/30'
      : band === 'At Risk'
      ? 'border-amber-500/30'
      : 'border-rose-500/30';
  }

  bandBadgeClass(band?: string): string {
    return band === 'Good'
      ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
      : band === 'Fair'
      ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
      : band === 'At Risk'
      ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
      : 'bg-rose-500/15 text-rose-300 border-rose-500/30';
  }

  bandStrokeColor(band?: string): string {
    return band === 'Good'
      ? '#10b981'
      : band === 'Fair'
      ? '#06b6d4'
      : band === 'At Risk'
      ? '#f59e0b'
      : '#f43f5e';
  }

  barGradient(v: number): string {
    return v >= 80
      ? 'from-emerald-500 to-teal-400'
      : v >= 60
      ? 'from-cyan-500 to-blue-400'
      : v >= 40
      ? 'from-amber-500 to-orange-400'
      : 'from-rose-500 to-red-600';
  }

  modelText(m?: string): string {
    return m === 'learning'
      ? 'Learning Phase (under 3 days of baseline telemetry)'
      : m === 'weekly'
      ? 'Multi-Variate Weekly & Diurnal Trend Model'
      : 'Adaptive AR-Moving Average Trend Model';
  }

  when(t?: string): string {
    if (!t) return '—';
    try {
      const d = new Date(t);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ', ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return t;
    }
  }
}
