import { Component, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { forkJoin, of } from 'rxjs';
import { catchError, finalize } from 'rxjs/operators';
import { Api } from '../../../services/api/api';
import { AriaService } from '../../../services/aria/aria.service';
import {
  LucideAngularModule,
  Bot, FileText, Download, RefreshCw, Shield, AlertTriangle,
  Activity, TrendingUp, TrendingDown, Minus, ShieldOff,
  Server, Zap, ChevronLeft, Clock, CheckCircle2, LoaderCircle,
  BarChart3, Eye, Lock, Globe, List, Target, GripVertical
} from 'lucide-angular';

/** MITRE ATT&CK mapping for a single analysis */
export interface MitreEntry {
  analysis_id: string;
  tactics:     string[];
  techniques:  { id: string; name: string }[];
}

/** Table of Contents entry */
export interface TocSection {
  id:    string;
  num:   string;
  title: string;
}

export type ReportPeriod = '24h' | '7d' | '30d';

@Component({
  selector: 'app-ai-report',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './ai-report.html',
  styleUrl:    './ai-report.css',
})
export class AiReport {

  // ── Icons ────────────────────────────────────────────────────────────────
  BotIcon       = Bot;
  FileIcon      = FileText;
  DownloadIcon  = Download;
  RefreshIcon   = RefreshCw;
  ShieldIcon    = Shield;
  AlertIcon     = AlertTriangle;
  ActivityIcon  = Activity;
  TrendUpIcon   = TrendingUp;
  TrendDownIcon = TrendingDown;
  MinusIcon     = Minus;
  SuppressIcon  = ShieldOff;
  ServerIcon    = Server;
  ZapIcon       = Zap;
  BackIcon      = ChevronLeft;
  ClockIcon     = Clock;
  CheckIcon     = CheckCircle2;
  LoadingIcon   = LoaderCircle;
  ChartIcon     = BarChart3;
  EyeIcon       = Eye;
  LockIcon      = Lock;
  GlobeIcon     = Globe;
  ListIcon      = List;
  TargetIcon    = Target;
  GripIcon      = GripVertical;

  // ── Report metadata ──────────────────────────────────────────────────────
  reportPeriod = signal<ReportPeriod>('24h');
  reportId     = signal('');
  reportDate   = signal('');

  // ── UI state ─────────────────────────────────────────────────────────────
  generating  = signal(false);
  generated   = signal(false);
  globalError = signal('');

  // ── Raw data from APIs ────────────────────────────────────────────────────
  stats        = signal<any>(null);
  severity     = signal<any>(null);
  analyses     = signal<any[]>([]);
  suppressions = signal<any[]>([]);
  predictions  = signal<any[]>([]);
  topIps       = signal<any>(null);
  protocols    = signal<any[]>([]);
  health       = signal<any>(null);

  // ── ARIA-generated narrative signals ──────────────────────────────────────
  execSummary     = signal('');
  threatNarrative = signal('');
  recommendations = signal('');
  execLoading     = signal(false);
  threatLoading   = signal(false);
  recoLoading     = signal(false);

  // ── MITRE ATT&CK mapping ──────────────────────────────────────────────────
  /** Map of analysis_id → MitreEntry (populated by single ARIA call) */
  mitreMap     = signal<Record<string, MitreEntry>>({});
  mitreLoading = signal(false);

  // ── Report Builder — section registry ────────────────────────────────────
  readonly sectionDefs = [
    { id: 'section-exec',            num: '01', title: 'Executive Summary',              required: true  },
    { id: 'section-kpis',            num: '02', title: 'Key Performance Indicators',     required: false },
    { id: 'section-threat',          num: '03', title: 'Threat Landscape Overview',      required: false },
    { id: 'section-analyses',        num: '04', title: 'AI Threat Analyses & MITRE',     required: false },
    { id: 'section-predictions',     num: '05', title: 'Predictive Threat Intelligence', required: false },
    { id: 'section-suppressions',    num: '06', title: 'Autonomous Suppression',         required: false },
    { id: 'section-recommendations', num: '07', title: 'Recommendations & Remediation',  required: false },
    { id: 'section-appendix',        num: 'A',  title: 'Appendix — System Health',       required: false },
  ];

  private readonly DEFAULT_ORDER = this.sectionDefs.map(s => s.id);

  sectionOrder    = signal<string[]>([...this.sectionDefs.map(s => s.id)]);
  enabledSections = signal<Set<string>>(new Set(this.sectionDefs.map(s => s.id)));
  customMode      = signal(false);
  dragSrcIdx      = signal<number | null>(null);
  dragOverIdx     = signal<number | null>(null);

  enabledCount = computed(() => this.enabledSections().size);

  sectionNumbers = computed(() => {
    const nums: Record<string, string> = {};
    let counter = 1;
    
    for (const id of this.sectionOrder()) {
      if (id === 'section-appendix') {
        nums[id] = 'A';
      } else if (this.enabledSections().has(id)) {
        nums[id] = String(counter++).padStart(2, '0');
      } else {
        nums[id] = '--';
      }
    }
    return nums;
  });

  activeTocSections = computed(() =>
    this.sectionOrder()
      .filter(id => this.enabledSections().has(id))
      .map(id => {
        const def = this.sectionDefs.find(d => d.id === id)!;
        return { ...def, num: this.sectionNumbers()[id] };
      })
      .filter(Boolean)
  );

  // ── Computed risk values ──────────────────────────────────────────────────
  totalAlerts = computed(() => {
    const s = this.severity();
    if (!s) return 0;
    return (s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0);
  });

  riskLevel = computed(() => {
    const s = this.severity();
    if (!s) return 'UNKNOWN';
    if ((s.critical || 0) > 0) return 'CRITICAL';
    if ((s.high || 0) > 5)    return 'HIGH';
    if ((s.medium || 0) > 10) return 'MEDIUM';
    return 'LOW';
  });

  riskClass = computed(() => 'risk-' + this.riskLevel().toLowerCase());

  // ── KPIs — all computed from real data, never hardcoded ──────────────────
  /**
   * False-Positive Suppression Rate:
   *   Active AI suppressions / Total correlation hits × 100
   *   Measures how much noise ARIA is removing from the alert queue.
   */
  kpiFpRate = computed(() => {
    const hits = this.stats()?.hits_total ?? 0;
    const activeSups = this.suppressions().filter(s => s.active).length;
    if (hits === 0) return null;
    return ((activeSups / hits) * 100).toFixed(1);
  });

  /**
   * AI Detection Coverage:
   *   Analyses generated / Total correlation hits × 100
   *   Measures the percentage of hits that received AI deep-dive analysis.
   */
  kpiAiCoverage = computed(() => {
    const hits = this.stats()?.hits_total ?? 0;
    if (hits === 0) return null;
    return Math.min(100, (this.analyses().length / hits) * 100).toFixed(1);
  });

  /**
   * Avg AI Suppression Confidence:
   *   Mean ai_confidence across all suppression decisions.
   *   Higher = ARIA is more certain about its false-positive classifications.
   */
  kpiAvgConfidence = computed(() => {
    const sups = this.suppressions();
    if (!sups.length) return null;
    const avg = sups.reduce((sum, s) => sum + (s.ai_confidence || 0), 0) / sups.length;
    return avg.toFixed(1);
  });

  /**
   * Active Suppression Rate:
   *   Active suppressions / Total suppressions × 100
   *   Shows what fraction of ARIA's suppression rules are still enforced.
   */
  kpiActiveSuppressionRate = computed(() => {
    const sups = this.suppressions();
    if (!sups.length) return null;
    const active = sups.filter(s => s.active).length;
    return ((active / sups.length) * 100).toFixed(1);
  });

  /**
   * Critical Alert Rate:
   *   Critical alerts / Total alerts × 100
   *   Measures severity concentration at the top tier.
   */
  kpiCriticalRate = computed(() => {
    const total = this.totalAlerts();
    if (total === 0) return null;
    return (((this.severity()?.critical || 0) / total) * 100).toFixed(1);
  });

  /**
   * Agent-Z/Agent-S ratio:
   *   Shows sensor contribution split from real stats data.
   */
  kpiAgentZRatio = computed(() => {
    const st = this.stats();
    if (!st) return null;
    const z = st.agent_z_events || 0;
    const s = st.agent_s_events || 0;
    const total = z + s;
    if (total === 0) return null;
    return `${Math.round((z / total) * 100)}% / ${Math.round((s / total) * 100)}%`;
  });

  // ── Period display label ───────────────────────────────────────────────────
  periodLabel = computed(() => {
    const m: Record<ReportPeriod, string> = { '24h': 'Last 24 Hours', '7d': 'Last 7 Days', '30d': 'Last 30 Days' };
    return m[this.reportPeriod()];
  });

  constructor(
    private api:   Api,
    private aria:  AriaService,
    private router: Router
  ) {}

  // ── Period selection ──────────────────────────────────────────────────────
  setPeriod(p: ReportPeriod) {
    this.reportPeriod.set(p);
    // If already generated, auto-regenerate with new period
    if (this.generated()) this.generateReport();
  }

  // ── Main generation ───────────────────────────────────────────────────────
  generateReport() {
    this.generating.set(true);
    this.generated.set(false);
    this.globalError.set('');
    this.execSummary.set('');
    this.threatNarrative.set('');
    this.recommendations.set('');
    this.mitreMap.set({});

    forkJoin({
      stats:       this.api.getStats().pipe(catchError(() => of(null))),
      severity:    this.api.getSeverity().pipe(catchError(() => of(null))),
      aiActivity:  this.api.getAiActivity().pipe(catchError(() => of({ analyses: [], suppressions: [] }))),
      predictions: this.api.getThreatPredictions().pipe(catchError(() => of({ predictions: [] }))),
      topIps:      this.api.getTopIps().pipe(catchError(() => of(null))),
      protocols:   this.api.getProtocols().pipe(catchError(() => of({ protocols: [] }))),
      health:      this.api.getDashboardStats().pipe(catchError(() => of(null))),
    }).pipe(
      finalize(() => this.generating.set(false))
    ).subscribe({
      next: (data: any) => {
        const now = new Date();

        // Set report metadata
        this.reportId.set(this.buildReportId(now));
        this.reportDate.set(now.toLocaleString('en-GB', {
          day: '2-digit', month: 'short', year: 'numeric',
          hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
        }));

        // Store raw data
        this.stats.set(data.stats);
        this.severity.set(data.severity);
        this.protocols.set(data.protocols?.protocols || []);
        this.topIps.set(data.topIps);
        this.health.set(data.health);

        // Filter AI activity by selected period
        const allAnalyses   = data.aiActivity?.analyses    || [];
        const allSuppressions = data.aiActivity?.suppressions || [];
        const allPredictions  = data.predictions?.predictions || [];

        this.analyses.set(this.filterByPeriod(allAnalyses));
        this.suppressions.set(this.filterByPeriod(allSuppressions));
        this.predictions.set(this.filterByPeriod(allPredictions));

        this.generated.set(true);
        this.generateNarratives(data);
        this.generateMitreMapping(this.analyses());
      },
      error: () => {
        this.globalError.set('Failed to fetch report data. Check API connectivity and retry.');
      }
    });
  }

  // ── Report ID ─────────────────────────────────────────────────────────────
  private buildReportId(now: Date): string {
    const d  = now.toISOString().slice(0, 10).replace(/-/g, '');
    const t  = now.toISOString().slice(11, 16).replace(':', '');
    const r  = Math.floor(1000 + Math.random() * 9000);
    return `NDR-${d}-${t}-${r}`;
  }

  // ── Period filter ─────────────────────────────────────────────────────────
  private cutoffDate(): Date {
    const hours = this.reportPeriod() === '24h' ? 24 : this.reportPeriod() === '7d' ? 168 : 720;
    return new Date(Date.now() - hours * 3_600_000);
  }

  private filterByPeriod<T extends { created_at?: string; predicted_at?: string }>(items: T[]): T[] {
    const cutoff = this.cutoffDate();
    return items.filter(item => {
      const raw = item.created_at || item.predicted_at;
      if (!raw) return true; // include if no timestamp available
      const d = new Date(raw.includes('T') ? raw : raw.replace(' ', 'T') + 'Z');
      return isNaN(d.getTime()) || d >= cutoff;
    });
  }

  // ── ARIA narrative generation ──────────────────────────────────────────────
  private generateNarratives(data: any) {
    const sev        = data.severity || {};
    const stats      = data.stats    || {};
    const total      = this.totalAlerts();
    const analyses   = this.analyses();
    const preds      = this.predictions();
    const period     = this.periodLabel();

    // ── Executive Summary ────────────────────────────────────────────────
    this.execLoading.set(true);
    const execPrompt =
`You are ARIA, the NDR system's AI threat analyst. Generate a professional 3-4 sentence executive summary for a ${period} security report.

Verified data:
- Report period: ${period}
- Total network events: ${stats.events_total?.toLocaleString() ?? 'N/A'}
- Total correlation hits: ${stats.hits_total?.toLocaleString() ?? 'N/A'}
- Agent-Z sensor events: ${stats.agent_z_events?.toLocaleString() ?? 'N/A'}
- Agent-S sensor events: ${stats.agent_s_events?.toLocaleString() ?? 'N/A'}
- Critical alerts: ${sev.critical ?? 0}, High: ${sev.high ?? 0}, Medium: ${sev.medium ?? 0}, Low: ${sev.low ?? 0}
- Total alerts: ${total}
- AI threat analyses generated: ${analyses.length}
- Active threat predictions: ${preds.length}
- AI suppression decisions: ${this.suppressions().filter(s => s.active).length} active
- Overall risk level: ${this.riskLevel()}

Write in formal authoritative prose suitable for a CISO briefing. No bullet points. No "I" or "ARIA" at the start.`;

    this.aria.chat(execPrompt, []).pipe(
      catchError(() => of({ reply: 'Executive summary unavailable — AI provider not configured.' }))
    ).subscribe({
      next: (r: any) => { this.execSummary.set(r.reply || r.message || ''); this.execLoading.set(false); },
      error: () => { this.execLoading.set(false); }
    });

    // ── Threat Landscape Narrative ────────────────────────────────────────
    this.threatLoading.set(true);
    const topAnalyses = analyses.slice(0, 4).map((a: any) =>
      `• ${a.severity} severity — ${a.src_ip} → ${a.dst_ip} (Bundle: ${a.bundle_id}): ${(a.analysis || '').slice(0, 150)}`
    ).join('\n');

    const topPreds = preds.slice(0, 3).map((p: any) =>
      `• ${p.attack_type}: ${Math.round((p.probability || 0) * 100)}% probability, ${p.trend} trend`
    ).join('\n');

    const threatPrompt =
`You are ARIA. Write a 2-paragraph threat landscape analysis for a ${period} security report.

Actual observed data:
${topAnalyses || '(No AI analyses recorded in this period)'}

Predicted threats:
${topPreds || '(No predictions available)'}

Overall stats: Critical=${sev.critical ?? 0}, High=${sev.high ?? 0}, Total events=${stats.events_total ?? 0}

Write formally. No bullets. Describe observed attack patterns and potential risks. Max 120 words total.`;

    this.aria.chat(threatPrompt, []).pipe(
      catchError(() => of({ reply: '' }))
    ).subscribe({
      next: (r: any) => { this.threatNarrative.set(r.reply || r.message || ''); this.threatLoading.set(false); },
      error: () => this.threatLoading.set(false)
    });

    // ── Recommendations ───────────────────────────────────────────────────
    this.recoLoading.set(true);
    const criticalAnalyses = analyses.filter((a: any) => a.severity === 'CRITICAL' || a.severity === 'HIGH')
      .slice(0, 3).map((a: any) => `• ${a.severity}: ${a.src_ip}→${a.dst_ip}: ${(a.analysis || '').slice(0, 100)}`).join('\n');

    const highProbPreds = preds.filter((p: any) => (p.probability || 0) > 0.5)
      .map((p: any) => `• ${p.attack_type} (${Math.round((p.probability || 0) * 100)}%)`).join('\n');

    const recoPrompt =
`You are ARIA. Generate exactly 6 prioritized operational security recommendations based on verified NDR data.

Data context (${period}):
- Risk level: ${this.riskLevel()}
- Critical/High threats observed:
${criticalAnalyses || '(none in period)'}
- High-probability upcoming threats:
${highProbPreds || '(none predicted)'}
- Active AI suppressions: ${this.suppressions().filter((s: any) => s.active).length}
- FP suppression rate: ${this.kpiFpRate() ?? 'N/A'}%

Format each as: "N. [Immediate Action] — [Technical rationale referencing actual observed data]"
Be specific and operational. Reference actual IPs or attack types where available.`;

    this.aria.chat(recoPrompt, []).pipe(
      catchError(() => of({ reply: '' }))
    ).subscribe({
      next: (r: any) => { this.recommendations.set(r.reply || r.message || ''); this.recoLoading.set(false); },
      error: () => this.recoLoading.set(false)
    });
  }

  // ── MITRE ATT&CK mapping via single ARIA call ──────────────────────────────
  private generateMitreMapping(analyses: any[]) {
    if (!analyses.length) return;
    this.mitreLoading.set(true);

    const analysisList = analyses.slice(0, 15).map((a: any) =>
      `ID: ${a.id}\nSeverity: ${a.severity}\nFlow: ${a.src_ip}→${a.dst_ip}\nText: ${(a.analysis || '').slice(0, 250)}`
    ).join('\n---\n');

    const mitrePrompt =
`You are ARIA. Map these NDR threat analyses to MITRE ATT&CK tactics and techniques.

Return ONLY a valid JSON array — no surrounding text, no markdown code blocks, just raw JSON:
[{"analysis_id":"<exact-id-from-input>","tactics":["<TacticName>"],"techniques":[{"id":"T<num>","name":"<TechniqueName>"}]}]

Rules:
- Use only real MITRE ATT&CK v14 tactic names and technique IDs
- If no clear mapping applies, use empty arrays (do not guess)
- Do not invent technique IDs
- Return one object per analysis

Analyses:
${analysisList}`;

    this.aria.chat(mitrePrompt, []).pipe(
      catchError(() => of({ reply: '[]' }))
    ).subscribe({
      next: (r: any) => {
        try {
          const text  = r.reply || r.message || '[]';
          // Extract the JSON array robustly (ARIA may wrap it in prose)
          const match = text.match(/\[[\s\S]*\]/);
          if (!match) { this.mitreLoading.set(false); return; }
          const parsed: MitreEntry[] = JSON.parse(match[0]);
          const map: Record<string, MitreEntry> = {};
          parsed.forEach(entry => {
            if (entry?.analysis_id) map[entry.analysis_id] = entry;
          });
          this.mitreMap.set(map);
        } catch {
          // Silently degrade — MITRE section shows "Mapping unavailable"
          this.mitreMap.set({});
        }
        this.mitreLoading.set(false);
      },
      error: () => this.mitreLoading.set(false)
    });
  }

  // ── Actions ───────────────────────────────────────────────────────────────
  downloadPdf() { window.print(); }
  goBack()      { this.router.navigate(['/analyst/dashboard']); }

  scrollToSection(id: string) {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  probBar(p: number)    { return Math.round((p || 0) * 100); }

  probColor(p: number): string {
    const pct = (p || 0) * 100;
    if (pct >= 75) return '#ff2a5f';
    if (pct >= 50) return '#ff9900';
    if (pct >= 25) return '#ffea00';
    return '#69f6b8';
  }

  sevClass(s: string) { return 'sev-' + (s || 'unknown').toLowerCase(); }

  trendIcon(t: string) {
    if (t === 'rising')  return this.TrendUpIcon;
    if (t === 'falling') return this.TrendDownIcon;
    return this.MinusIcon;
  }

  trendClass(t: string) {
    if (t === 'rising')  return 'trend-up';
    if (t === 'falling') return 'trend-down';
    return 'trend-stable';
  }

  suppressTypeLabel(t: string) {
    const m: Record<string, string> = {
      by_dst: 'By Destination IP',
      by_src: 'By Source IP',
      by_sid: 'By Signature ID',
    };
    return m[t] || t;
  }

  formatTime(ts: string) {
    if (!ts) return '—';
    const d = new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z');
    return isNaN(d.getTime()) ? ts : d.toLocaleString();
  }

  getMitreForAnalysis(id: string): MitreEntry | null {
    return this.mitreMap()[id] ?? null;
  }

  getHealthKeys(): string[] {
    const h = this.health();
    if (!h || typeof h !== 'object') return [];
    return Object.keys(h).filter(k => typeof h[k] !== 'object' && h[k] !== null).slice(0, 16);
  }

  // ── Report Builder methods ─────────────────────────────────────────────────
  getSectionDef(id: string) { return this.sectionDefs.find(d => d.id === id); }

  isSectionEnabled(id: string): boolean { return this.enabledSections().has(id); }

  sectionCssOrder(id: string): number { return this.sectionOrder().indexOf(id) + 10; }

  toggleSection(id: string) {
    const def = this.sectionDefs.find(d => d.id === id);
    if (def?.required) return;
    const s = new Set(this.enabledSections());
    if (s.has(id)) s.delete(id); else s.add(id);
    this.enabledSections.set(s);
  }

  onDragStart(idx: number, e: DragEvent) {
    this.dragSrcIdx.set(idx);
    e.dataTransfer?.setData('text/plain', String(idx));
  }

  onDragOver(idx: number, e: DragEvent) {
    e.preventDefault();
    this.dragOverIdx.set(idx);
  }

  onDrop(targetIdx: number, e: DragEvent) {
    e.preventDefault();
    const srcIdx = this.dragSrcIdx();
    if (srcIdx === null || srcIdx === targetIdx) { this.onDragEnd(); return; }
    const order = [...this.sectionOrder()];
    const [moved] = order.splice(srcIdx, 1);
    order.splice(targetIdx, 0, moved);
    this.sectionOrder.set(order);
    this.onDragEnd();
  }

  onDragEnd() {
    this.dragSrcIdx.set(null);
    this.dragOverIdx.set(null);
  }

  resetToDefault() {
    this.sectionOrder.set([...this.DEFAULT_ORDER]);
    this.enabledSections.set(new Set(this.DEFAULT_ORDER));
  }
}
