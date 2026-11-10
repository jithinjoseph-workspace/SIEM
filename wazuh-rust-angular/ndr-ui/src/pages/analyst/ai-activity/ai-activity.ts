import { Component, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { interval, merge, of, Subject } from 'rxjs';
import { catchError, map, startWith, switchMap } from 'rxjs/operators';
import { Api } from '../../../services/api/api';
import { LucideAngularModule, Bot, ShieldOff, FileText, ChevronDown, ChevronUp, TrendingUp, TrendingDown, Minus, Shield, AlertTriangle, Activity } from 'lucide-angular';
import { AuthService } from '../../../services/auth/auth';


import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-ai-activity',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './ai-activity.html',
  styleUrl: './ai-activity.css',
})
export class AiActivity {
  private api = inject(Api);
  private router = inject(Router);
  private auth = inject(AuthService);

  /** Sensor IDs this user is scoped to (from JWT). */
  readonly sensorIds = this.auth.getSensorIds();

  BotIcon           = Bot;
  ShieldOffIcon     = ShieldOff;
  FileIcon          = FileText;
  ChevronDownIcon   = ChevronDown;
  ChevronUpIcon     = ChevronUp;
  TrendingUpIcon    = TrendingUp;
  TrendingDownIcon  = TrendingDown;
  MinusIcon         = Minus;
  ShieldIcon        = Shield;
  AlertIcon         = AlertTriangle;
  ActivityIcon      = Activity;

  activeTab: 'analyses' | 'suppressions' | 'predictions' = 'analyses';
  selectedAnalysisId = signal<string | null>(null);
  expandedPrediction = signal<string | null>(null);
  historicalPredictions = signal<any[]>([]);

  private refresh$ = new Subject<void>();

  private data = toSignal(
    merge(interval(15_000), this.refresh$).pipe(
      startWith(0),
      switchMap(() =>
        this.api.getAiActivity().pipe(
          map((d: any) => ({ analyses: d.analyses || [], suppressions: d.suppressions || [], error: '' })),
          catchError(() => of({ analyses: [], suppressions: [], error: 'Failed to load AI activity.' }))
        )
      )
    ),
    { initialValue: { analyses: [], suppressions: [], error: '' } }
  );

  private predData = toSignal(
    interval(60_000).pipe(
      startWith(0),
      switchMap(() =>
        this.api.getThreatPredictions().pipe(
          map((d: any) => d.predictions || []),
          catchError(() => of([]))
        )
      )
    ),
    { initialValue: [] as any[] }
  );

  analyses     = computed(() => this.data()?.analyses    ?? []);
  suppressions = computed(() => this.data()?.suppressions ?? []);
  error        = computed(() => this.data()?.error       ?? '');
  loading      = computed(() => this.data() === null);
  predictions  = computed(() => this.predData() ?? []);

  selectedAnalysis = computed(() => this.analyses().find((a: any) => a.id === this.selectedAnalysisId()));
  selectedPrediction = computed(() => this.predictions().find((p: any) => p.attack_type === this.expandedPrediction()));

  toggleAnalysis(id: string) {
    if (this.selectedAnalysisId() === id) this.selectedAnalysisId.set(null);
    else this.selectedAnalysisId.set(id);
  }

  isExpanded(id: string) { return this.selectedAnalysisId() === id; }

  togglePrediction(type: string) {
    if (this.expandedPrediction() === type) {
      this.expandedPrediction.set(null);
      this.historicalPredictions.set([]);
    } else {
      this.expandedPrediction.set(type);
      this.api.getThreatPredictionsHistory().subscribe({
        next: data => {
          if (data && data.predictions) {
            const history = data.predictions.filter((p: any) => p.attack_type === type);
            this.historicalPredictions.set(history);
          }
        },
        error: reportRxjsError
      });
    }
  }

  isPredExpanded(type: string) { return this.expandedPrediction() === type; }

  sevClass(s: string) { return 'sev-' + (s || 'info').toLowerCase(); }

  alertLevelClass(level: string) { return 'alert-' + (level || 'info').toLowerCase(); }

  probBar(p: number) { return Math.round((p || 0) * 100); }

  probColor(p: number): string {
    const pct = (p || 0) * 100;
    if (pct >= 75) return '#ff2a5f';
    if (pct >= 50) return '#ff9900';
    if (pct >= 25) return '#ffea00';
    return '#69f6b8';
  }

  trendIcon(trend: string) {
    if (trend === 'rising')  return this.TrendingUpIcon;
    if (trend === 'falling') return this.TrendingDownIcon;
    return this.MinusIcon;
  }

  trendClass(trend: string) {
    if (trend === 'rising')  return 'trend-up';
    if (trend === 'falling') return 'trend-down';
    return 'trend-stable';
  }

  suppressTypeLabel(t: string) {
    const map: Record<string, string> = {
      by_dst: 'By Destination IP',
      by_src: 'By Source IP',
      by_sid: 'By Signature ID',
    };
    return map[t] || t;
  }

  formatTime(ts: string) {
    if (!ts) return '';
    const d = new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z');
    return isNaN(d.getTime()) ? ts : d.toLocaleString();
  }

  deactivateSuppression(id: string) {
    this.api.deactivateAiSuppression(id).subscribe({
      next: () => this.refresh$.next(),
      error: () => {},
    });
  }

  deleteSuppression(id: string) {
    if (!confirm('Delete this suppression rule permanently?')) return;
    this.api.deleteAiSuppression(id).subscribe({
      next: () => this.refresh$.next(),
      error: () => {},
    });
  }

  openAiReport() {
    this.router.navigate(['/analyst/ai-report']);
  }
}
