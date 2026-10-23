import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, TrendingUp, TrendingDown, Minus, RefreshCw, Crosshair, Bot } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

/** One prediction (siem-predict): the next likely MITRE ATT&CK stage. */
interface Prediction {
  id: string;
  attack_type: string;
  probability: number;
  confidence: number;
  trend: 'rising' | 'stable' | 'falling';
  trend_delta: number;
  exposure_score: number;
  internal_hit_count: number;
  explanation: string;
  recommendations: string[];
  aria_briefing: string;
  ai_model: string;
  alert_level: string;
  predicted_at: string;
  agents: string[];
}

/**
 * SIEM Threat Predictions: from the order of MITRE tactics in each host's Wazuh
 * alerts (24 h), the attack stage likely to come next, with the reason and what
 * to do (siem-api /api/v1/siem/predictions, crate siem-predict).
 */
@Component({
  selector: 'app-siem-predictions',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './siem-predictions.html',
})
export class SiemPredictions implements OnInit {
  private siem = inject(SiemService);

  UpIcon = TrendingUp;
  DownIcon = TrendingDown;
  FlatIcon = Minus;
  RefreshIcon = RefreshCw;
  TargetIcon = Crosshair;
  BotIcon = Bot;

  predictions = signal<Prediction[]>([]);
  history = signal<Prediction[]>([]);
  open = signal<string | null>(null);
  loading = signal(false);
  error = signal<string | null>(null);
  message = signal<string | null>(null);

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getSiemPredictions().subscribe({
      next: r => { this.loading.set(false); this.error.set(null); this.predictions.set(r.predictions ?? []); },
      error: e => { this.loading.set(false); this.error.set(e?.status === 403 ? 'You do not have access to MITRE data.' : 'Predictions are not available.'); },
    });
    this.siem.getSiemPredictionHistory().subscribe({ next: r => this.history.set(r.predictions ?? []) });
  }

  runNow() {
    this.loading.set(true);
    this.siem.runSiemPredictions().subscribe({
      next: r => {
        if (r?.status === 'error') {
          this.loading.set(false);
          this.error.set(r.message);
          return;
        }
        this.message.set(r.predictions ? `${r.predictions} prediction(s) updated.` : 'No attack progression in the last 24 h.');
        setTimeout(() => this.message.set(null), 4000);
        this.load();
      },
      error: () => { this.loading.set(false); this.error.set('Predictions could not be updated.'); },
    });
  }

  /** The earlier predictions of the same attack type, oldest first. */
  historyOf(type: string): Prediction[] {
    return this.history().filter(p => p.attack_type === type).slice(0, 20).reverse();
  }

  pct(x: number): number {
    return Math.round((x || 0) * 100);
  }

  levelClass(l: string): string {
    return l === 'critical' ? 'bg-rose-950/60 text-rose-300 border-rose-800'
      : l === 'high' ? 'bg-orange-950/60 text-orange-300 border-orange-800'
      : l === 'medium' ? 'bg-amber-950/50 text-amber-300 border-amber-800'
      : 'bg-slate-800 text-slate-300 border-slate-700';
  }

  barClass(p: number): string {
    return p >= 0.75 ? 'bg-rose-500' : p >= 0.5 ? 'bg-orange-500' : p >= 0.25 ? 'bg-amber-500' : 'bg-slate-500';
  }

  when(t: string): string {
    return t ? new Date(t).toLocaleString() : '—';
  }
}
