import { Component, computed, inject, signal, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { EMPTY, forkJoin, interval, merge, of, Subject, Subscription } from 'rxjs';
import { catchError, debounceTime, map, startWith, switchMap } from 'rxjs/operators';
import { Api } from '../../../services/api/api';
import { AriaService } from '../../../services/aria/aria.service';
import { EvidenceService } from '../../../services/evidence/evidence';
import {
  LucideAngularModule,
  Bot,
  ShieldOff,
  FileText,
  ChevronDown,
  ChevronUp,
  TrendingUp,
  TrendingDown,
  Minus,
  Shield,
  AlertTriangle,
  Activity,
  Search,
  RefreshCw,
  Copy,
  Check,
  ExternalLink,
  Sparkles,
  ArrowRight,
  Clock,
  Layers,
  SlidersHorizontal,
  CheckCircle,
  CheckCircle2,
  CircleDot,
  Eye,
  Code,
  Zap,
  ShieldAlert,
  Cpu,
  Info,
  Lock,
  Globe,
  Radio,
  Server,
  LayoutDashboard,
  ShieldCheck,
  X,
  BarChart2,
  Calendar,
  Filter
} from 'lucide-angular';
import { AuthService } from '../../../services/auth/auth';
import { reportRxjsError } from '../../../services/error-reporter/error-reporter';

export interface ParsedReport {
  threat: string | null;
  risk: string | null;
  actions: string[];
  raw: string;
}

export interface RoadmapMilestone {
  id: string;
  name: string;
  domain: string;
  target: string;
  status: string;
  risk: 'LOW' | 'MED' | 'HIGH';
  owner: string;
  description: string;
  progressPct: number;
  mitreRef?: string;
  budgetAllocated?: string;
  dependencies?: string[];
  flow?: string;
  communityId?: string;
  rawAnalysis?: any;
}

export interface RoadmapInitiativeBar {
  id: string;
  name: string;
  leftPct: number;
  widthPct: number;
  color: string;
  glowColor: string;
  milestoneTag?: string;
  milestoneType?: 'gate' | 'deployment';
  milestoneName?: string;
  milestoneId?: string;
  milestoneLeftPct?: number;
  item?: any;
}

export interface RoadmapSwimlane {
  id: string;
  title: string;
  lead: string;
  capex: string;
  color: string;
  tagColor: string;
  bars: RoadmapInitiativeBar[];
}

@Component({
  selector: 'app-ai-activity',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './ai-activity.html',
  styleUrl: './ai-activity.css',
})
export class AiActivity implements OnInit, OnDestroy {
  private api = inject(Api);
  private router = inject(Router);
  private auth = inject(AuthService);
  private aria = inject(AriaService);
  private evidence = inject(EvidenceService);

  /** Sensor IDs this user is scoped to (from JWT). */
  readonly sensorIds = this.auth.getSensorIds();

  // Lucide Icons
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
  SearchIcon        = Search;
  RefreshIcon       = RefreshCw;
  CopyIcon          = Copy;
  CheckIcon         = Check;
  ExternalLinkIcon  = ExternalLink;
  SparklesIcon      = Sparkles;
  ArrowRightIcon    = ArrowRight;
  ClockIcon         = Clock;
  LayersIcon        = Layers;
  FilterIcon        = SlidersHorizontal;
  CheckCircleIcon   = CheckCircle;
  CheckCircle2Icon  = CheckCircle2;
  CircleDotIcon     = CircleDot;
  EyeIcon           = Eye;
  CodeIcon          = Code;
  ZapIcon           = Zap;
  ShieldAlertIcon   = ShieldAlert;
  CpuIcon           = Cpu;
  InfoIcon          = Info;
  LockIcon          = Lock;
  GlobeIcon         = Globe;
  RadioIcon         = Radio;
  ServerIcon        = Server;
  DashboardIcon     = LayoutDashboard;
  ShieldCheckIcon   = ShieldCheck;
  CloseIcon         = X;
  BarChartIcon      = BarChart2;
  CalendarIcon      = Calendar;

  // View state: 'command-center' (Strategic Roadmap Control Tower) or deep inspection tabs
  private _tab: 'command-center' | 'analyses' | 'suppressions' | 'predictions' | 'soc-gpt' = 'command-center';
  get activeTab() { return this._tab; }
  set activeTab(v: 'command-center' | 'analyses' | 'suppressions' | 'predictions' | 'soc-gpt') {
    if (v === this._tab) return;
    this._tab = v;
    this.reloadOpenTab();
  }
  selectedAnalysisId = signal<string | null>(null);
  expandedPrediction = signal<string | null>(null);
  historicalPredictions = signal<any[]>([]);

  // Time range shown by the header picker (0 = all time); applied by the server to analyses
  readonly rangeOptions = [
    { hours: 0,   label: 'All time' },
    { hours: 24,  label: 'Last 24 hours' },
    { hours: 168, label: 'Last 7 days' },
    { hours: 720, label: 'Last 30 days' },
  ];
  rangeHours = signal<number>(0);
  private rangeCutoff = computed(() => this.rangeHours() ? Date.now() - this.rangeHours() * 3_600_000 : 0);
  private inRange = (ts: any) => { const c = this.rangeCutoff(); return !c || (this.tsMs(ts) ?? 0) >= c; };

  // Search & Filter state
  searchQuery = signal<string>('');
  selectedSeverity = signal<string>('ALL');
  suppressionSearch = signal<string>('');
  predictionSearch = signal<string>('');
  showRawAnalysis = signal<boolean>(false);
  copiedId = signal<string | null>(null);
  isRefreshing = signal<boolean>(false);
  isDossierOpen = signal<boolean>(false);

  // Strategic Roadmap Controls
  roadmapSearch = signal<string>('');
  selectedRegion = signal<string>('All Regions');
  selectedMilestoneStatus = signal<string>('ALL');
  roadmapPerspective = signal<'strategic' | 'threat-hunt'>('strategic');
  selectedRiskCell = signal<{ impact: string; likelihood: string } | null>(null);
  selectedDossierData = signal<any>(null);

  // UTC Real-time clock & Date
  currentUtcTime = signal<string>('');
  currentFormattedDate = signal<string>('');
  private timeSub?: Subscription;

  private refresh$ = new Subject<void>();

  // Control Tower data: only fetched while that tab is open
  private data = toSignal(
    merge(interval(15_000), this.refresh$).pipe(
      startWith(0),
      switchMap(() =>
        this.activeTab !== 'command-center' ? EMPTY :
        this.api.getAiActivity({ a_limit: 50, s_limit: 100, hours: this.rangeHours() }).pipe(
          map((d: any) => ({
            analyses: d.analyses || [], suppressions: d.suppressions || [],
            summary: d.analyses_by_severity ?? null, suppTotal: d.suppressions_total ?? null,
            suppActive: d.suppressions_active ?? null, error: '',
          })),
          catchError(() => of({ analyses: [], suppressions: [], summary: null, suppTotal: null, suppActive: null, error: 'Failed to load AI activity.' }))
        )
      )
    ),
    { initialValue: { analyses: [], suppressions: [], summary: null, suppTotal: null, suppActive: null, error: '' } as any }
  );

  analyses     = computed(() => this.data()?.analyses    ?? []);
  suppressions = computed(() => (this.data()?.suppressions ?? []).filter((s: any) => this.inRange(s.created_at)));
  error        = computed(() => this.data()?.error       ?? '');
  loading      = computed(() => this.data() === null);

  // ── AI briefing (Control Tower): facts from the API, worded by the AI when one is configured ──
  briefing = signal<any | null>(null);
  briefingLoading = signal<boolean>(false);
  private briefingReq = 0;

  loadBriefing(force = false) {
    const req = ++this.briefingReq;
    this.briefingLoading.set(true);
    this.api.getAiBriefing(this.rangeHours() || 24, force).subscribe({
      next: (b: any) => { if (req === this.briefingReq) { this.briefing.set(b?.error ? null : b); this.briefingLoading.set(false); } },
      error: () => { if (req === this.briefingReq) this.briefingLoading.set(false); },
    });
  }

  briefingNote = computed(() => {
    const reason = this.briefing()?.reason;
    return reason === 'not_configured' ? 'No AI provider is configured (Settings > AI Configuration), so this is a summary of the facts.'
      : reason === 'disabled' ? 'AI is switched off for your organization, so this is a summary of the facts.'
      : reason === 'rejected' ? "The AI's wording did not match the data, so the facts are shown instead."
      : '';
  });

  /** Jump to the analyses of one host from the briefing. */
  showHost(ip: string) {
    this.searchQuery.set(ip);
    this.analysesPage.set([]);
    this.activeTab = 'analyses';
  }

  // ── AI investigation of one analysis (reuses /api/aria/investigate and /api/aria/verdict) ──
  verdict = signal<any | null>(null);
  verdictState = signal<'idle' | 'loading' | 'running'>('idle');
  verdictError = signal<string>('');
  actionNote = signal<string>('');

  private setVerdict(v: any) {
    this.verdict.set(v && v.verdict ? {
      verdict: v.verdict, confidence: v.confidence, reasoning: v.reasoning,
      action: v.recommended_action, mitre: v.mitre_techniques || [], at: v.generated_at,
    } : null);
  }

  private loadVerdict(cid: string) {
    this.verdict.set(null);
    this.verdictError.set('');
    this.actionNote.set('');
    this.similarIncidents.set(null);
    if (!cid) { this.verdictState.set('idle'); return; }
    this.verdictState.set('loading');
    this.evidence.getVerdict(cid).subscribe({
      next: (r: any) => { this.setVerdict(r?.verdict); this.verdictState.set('idle'); },
      error: () => this.verdictState.set('idle'),
    });
    this.loadSimilarIncidents(cid);
  }

  investigate() {
    const cid = this.selectedDossierData()?.communityId;
    if (!cid || this.verdictState() === 'running') return;
    this.verdictState.set('running');
    this.verdictError.set('');
    this.evidence.runInvestigation(cid).subscribe({
      next: (r: any) => {
        if (r?.error) this.verdictError.set(r.error); else this.setVerdict(r);
        this.verdictState.set('idle');
        // A fresh investigation is indexed for similarity in the background on the server,
        // not necessarily ready the instant this response arrives — a short delay gives it
        // time to land, so "similar incidents" has a real chance of including this one later.
        setTimeout(() => this.loadSimilarIncidents(cid), 3000);
      },
      error: () => { this.verdictError.set('The investigation request failed.'); this.verdictState.set('idle'); },
    });
  }

  // ── Similar past incidents (RAG: this tenant's own past investigations) ──
  similarIncidents = signal<any[] | null>(null);
  similarLoading = signal<boolean>(false);

  private loadSimilarIncidents(cid: string) {
    this.similarLoading.set(true);
    this.evidence.getSimilarIncidents(cid, 5).subscribe({
      next: (r: any) => { this.similarIncidents.set(r?.incidents || []); this.similarLoading.set(false); },
      error: () => { this.similarIncidents.set([]); this.similarLoading.set(false); },
    });
  }

  // ── Ask your history: a question answered only from this tenant's past investigations ──
  askText = signal<string>('');
  askLoading = signal<boolean>(false);
  askResult = signal<any | null>(null);
  askError = signal<string>('');
  askedQuestion = '';

  askHistory() {
    const q = this.askText().trim();
    if (!q || this.askLoading()) return;
    this.askLoading.set(true);
    this.askError.set('');
    this.askResult.set(null);
    this.askedQuestion = q;
    this.evidence.askHistory(q).subscribe({
      next: (r: any) => {
        if (r?.error) this.askError.set(r.error); else this.askResult.set(r);
        this.askLoading.set(false);
      },
      error: () => { this.askError.set('The question could not be answered right now.'); this.askLoading.set(false); },
    });
  }

  askIntentText(intent: string): string {
    switch (intent) {
      case 'summary': return 'Period summary';
      case 'latest': return 'Newest records';
      case 'incident': return 'Incident lookup';
      case 'stats': return 'Platform counts';
      default: return 'Similar past incidents';
    }
  }

  /** Opens the answer as a plain page and prints it; "Save as PDF" in the print dialog makes the file. */
  printAnswer() {
    const r = this.askResult();
    if (r) this.printReport(this.askedQuestion, r, (msg) => this.askError.set(msg));
  }

  /** Shared by "Ask your history" and SOC GPT: opens one answer as a printable page. */
  private printReport(question: string, r: any, onBlocked: (msg: string) => void) {
    const esc = (v: unknown) => String(v ?? '').replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as Record<string, string>)[c]);
    const rows = (r.sources || []).map((s: any) =>
      `<tr><td>${esc(this.verdictLabel(s.verdict))}</td><td>${esc(s.src_ip)} → ${esc(s.dst_ip)}</td>` +
      `<td>${esc(this.outcomeLabel(s.outcome).text)}</td><td>${esc(s.generated_at)}</td>` +
      `<td>${esc(s.community_id)}</td><td>${esc(s.reasoning)}</td></tr>`).join('');
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>NDR answer</title><style>` +
      `body{font-family:Arial,sans-serif;color:#111;margin:24px;font-size:12px}h1{font-size:16px}` +
      `p{line-height:1.5;white-space:pre-line}.meta{color:#555}table{border-collapse:collapse;width:100%;margin-top:12px}` +
      `td,th{border:1px solid #bbb;padding:4px;vertical-align:top;text-align:left}</style></head><body>` +
      `<h1>NDR answer</h1>` +
      `<p class="meta">Question: ${esc(question)} · ${esc(this.askIntentText(r.intent))} · ${esc(new Date().toLocaleString())}</p>` +
      `<p>${esc(r.answer)}</p>` +
      (r.reason ? `<p class="meta">${esc(this.askReasonText(r.reason))}</p>` : '') +
      (rows ? `<table><tr><th>Verdict</th><th>Flow</th><th>Outcome</th><th>When</th><th>Session</th><th>Detail</th></tr>${rows}</table>` : '') +
      `</body></html>`;
    const w = window.open('', '_blank');
    if (!w) { onBlocked('Allow pop-ups for this site to save the answer as a PDF.'); return; }
    w.document.write(html);
    w.document.close();
    w.focus();
    w.print();
  }

  // ── SOC GPT: a running conversation over this tenant's own data, grounded the same way "Ask your
  // history" is. `socSubject` is the session/case the conversation is currently about — the backend
  // reads a vague follow-up against it and returns the next one, so this code never has to guess what
  // "it" or "this session" means. ──
  socMessages = signal<Array<{ role: 'user' | 'assistant'; text: string; result?: any }>>([]);
  socInput = signal<string>('');
  socLoading = signal<boolean>(false);
  socError = signal<string>('');
  private socSubject = '';

  socSend() {
    const q = this.socInput().trim();
    if (!q || this.socLoading()) return;
    this.socInput.set('');
    this.socError.set('');
    this.socMessages.update(m => [...m, { role: 'user', text: q }]);
    this.socLoading.set(true);
    const turns = this.socMessages().slice(-8).map(m => ({ role: m.role, text: m.text }));
    this.evidence.askPlatform(q, this.socSubject, turns).subscribe({
      next: (r: any) => {
        this.socLoading.set(false);
        if (r?.error) { this.socError.set(r.error); return; }
        this.socSubject = r.subject || this.socSubject;
        this.socMessages.update(m => [...m, { role: 'assistant', text: r.answer, result: { ...r, question: q } }]);
      },
      error: () => {
        this.socLoading.set(false);
        this.socError.set('SOC GPT could not answer right now.');
      },
    });
  }

  socPrint(msg: { result?: any }) {
    if (msg.result) this.printReport(msg.result.question, msg.result, (m) => this.socError.set(m));
  }

  socClear() {
    this.socMessages.set([]);
    this.socSubject = '';
    this.socError.set('');
  }

  askReasonText(reason: string): string {
    switch (reason) {
      case 'not_found': return 'Nothing with that case number or session id is in your scope.';
      case 'no_records': return 'Nothing comparable in your history yet.';
      case 'not_configured': return 'No AI provider is configured, so these are the records themselves.';
      case 'no_ai_answer': return 'The AI did not answer, so these are the records themselves.';
      case 'rejected': return 'The AI answer cited something outside these records, so it was not shown.';
      default: return '';
    }
  }

  /** How a comparable past investigation actually ended, once its case was closed. */
  outcomeLabel(outcome: string | null | undefined): { text: string; cls: string } {
    switch (outcome) {
      case 'true_positive':  return { text: 'Confirmed attack', cls: 'outcome-tp' };
      case 'false_positive': return { text: 'False positive', cls: 'outcome-fp' };
      case 'closed_unknown': return { text: 'Closed, no verdict', cls: 'outcome-unk' };
      default:               return { text: 'No outcome yet', cls: 'outcome-none' };
    }
  }

  similarPct(score: number): number {
    return Math.round((score || 0) * 100);
  }

  /** Opens the dossier for a past incident surfaced as "similar", if it's still in the loaded list. */
  openSimilarIncident(communityId: string) {
    const a = this.analyses().find((x: any) => x.community_id === communityId)
      || this.analysesPage().find((x: any) => x.community_id === communityId);
    if (a) { this.inspectAnalysis(a); return; }
    // Not in the currently loaded page — searching for it is the closest thing to "go there".
    this.searchQuery.set(communityId);
    this.analysesPage.set([]);
    this.activeTab = 'analyses';
  }

  verdictClass(v: string) {
    return 'verdict-' + (v || 'SUSPICIOUS').toLowerCase().replace(/_/g, '-');
  }

  verdictLabel(v: string) {
    return v === 'TRUE_POSITIVE' ? 'Likely real attack' : v === 'FALSE_POSITIVE' ? 'Likely false positive' : 'Suspicious, needs a look';
  }

  /** Opens the ARIA chat with a question about this session. ARIA is given the session's records. */
  askAboutThis() {
    const d = this.selectedDossierData();
    if (!d?.communityId) return;
    this.aria.ask(`Explain session ${d.communityId} (${d.flow || 'flow unknown'}). Is it a real threat? What should I do?`);
  }

  // ── Hide alerts like this: preview first, then an explicit choice ──
  hidePlan = signal<any | null>(null);
  hideState = signal<'closed' | 'loading' | 'open'>('closed');
  hideHours = signal<number>(24);
  readonly hideHourOptions = [{ h: 24, label: '24 hours' }, { h: 72, label: '3 days' }, { h: 168, label: '7 days' }];

  openHidePanel() {
    const cid = this.selectedDossierData()?.communityId;
    if (!cid) return;
    this.actionNote.set('');
    this.hidePlan.set(null);
    this.hideState.set('loading');
    this.api.getSuppressionPreview(cid).subscribe({
      next: (p: any) => {
        if (p?.error) { this.actionNote.set(p.error); this.hideState.set('closed'); return; }
        this.hidePlan.set(p);
        this.hideState.set('open');
      },
      error: () => { this.actionNote.set('Could not load the preview.'); this.hideState.set('closed'); },
    });
  }

  closeHidePanel() { this.hideState.set('closed'); }

  severitySummary(imp: any): string {
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];
    return order.filter(k => imp?.by_severity?.[k]).map(k => `${imp.by_severity[k]} ${k.toLowerCase()}`).join(', ');
  }

  hide(scope: 'session' | 'pattern') {
    const cid = this.selectedDossierData()?.communityId;
    if (!cid) return;
    this.api.applyAiSuppression(cid, scope, this.hideHours()).subscribe({
      next: (r: any) => {
        this.actionNote.set(`Hidden for ${r.hours} hours (${r.hidden_alerts} alert(s)).`);
        this.hideState.set('closed');
        this.reloadOpenTab();
      },
      error: (e: any) => this.actionNote.set(e?.message || 'Could not hide these alerts.'),
    });
  }

  // ── Server-side paging for the three list tabs: every "Load more" is a real API call ──
  readonly pageSize = 20;
  analysesPage = signal<any[]>([]);
  analysesTotal = signal<number>(0);
  analysesLoading = signal<boolean>(false);
  suppPage = signal<any[]>([]);
  suppTotal = signal<number>(0);
  suppLoading = signal<boolean>(false);
  predictions = signal<any[]>([]);
  predsTotal = signal<number>(0);
  predsLoading = signal<boolean>(false);
  private analysesReq = 0;
  private suppReq = 0;
  private predsReq = 0;

  /** Unfiltered totals, shown on the tab buttons. */
  analysesAll = signal<number | null>(null);
  suppAll = signal<number | null>(null);
  predsAll = signal<number | null>(null);
  analysesCountLabel = computed(() => this.analysesAll() ?? this.data()?.summary?.total ?? this.analyses().length);
  suppCountLabel = computed(() => this.rangeHours() ? this.suppressions().length : (this.suppAll() ?? this.data()?.suppTotal ?? this.suppressions().length));
  predsCountLabel = computed(() => this.predsAll() ?? this.live()?.preds?.total ?? this.predictions().length);

  onRangeChange(hours: number) {
    this.rangeHours.set(Number(hours));
    this.analysesAll.set(null);
    this.analysesPage.set([]);
    this.reloadOpenTab();
  }

  /** Sensors this view is scoped to (the global Sensor Scope bar sets it). */
  sensorLabel = computed(() => {
    const names = this.sensorIds.length ? this.sensorIds : this.sensors().map(s => s.name);
    return names.length === 1 ? names[0] : names.length ? `${names.length} sensors` : 'All sensors';
  });

  private searchInput$ = new Subject<void>();
  private pollSub?: Subscription;
  private searchSub?: Subscription;

  /** Loads (or refreshes) analyses. append=true fetches the next page; otherwise the pages already shown are re-read. */
  private fetchAnalyses(append: boolean) {
    const have = this.analysesPage().length;
    const req = ++this.analysesReq;
    this.analysesLoading.set(true);
    this.api.getAiActivity({
      a_limit: append ? this.pageSize : Math.max(this.pageSize, have),
      a_offset: append ? have : 0,
      s_limit: 0,
      severity: this.selectedSeverity(),
      q: this.searchQuery().trim(),
      hours: this.rangeHours(),
    }).subscribe({
      next: (d: any) => {
        if (req !== this.analysesReq) return; // an older request finished late
        const rows = d.analyses || [];
        this.analysesPage.set(append ? [...this.analysesPage(), ...rows] : rows);
        this.analysesTotal.set(d.analyses_total ?? rows.length);
        if (this.selectedSeverity() === 'ALL' && !this.searchQuery().trim()) this.analysesAll.set(d.analyses_total ?? rows.length);
        this.analysesLoading.set(false);
      },
      error: () => { if (req === this.analysesReq) this.analysesLoading.set(false); },
    });
  }

  private fetchSuppressions(append: boolean) {
    const have = this.suppPage().length;
    const req = ++this.suppReq;
    this.suppLoading.set(true);
    this.api.getAiActivity({
      a_limit: 0,
      s_limit: append ? this.pageSize : Math.max(this.pageSize, have),
      s_offset: append ? have : 0,
    }).subscribe({
      next: (d: any) => {
        if (req !== this.suppReq) return;
        const rows = d.suppressions || [];
        this.suppPage.set(append ? [...this.suppPage(), ...rows] : rows);
        this.suppTotal.set(d.suppressions_total ?? rows.length);
        this.suppAll.set(d.suppressions_total ?? rows.length);
        this.suppLoading.set(false);
      },
      error: () => { if (req === this.suppReq) this.suppLoading.set(false); },
    });
  }

  private fetchPredictions(append: boolean) {
    const have = this.predictions().length;
    const req = ++this.predsReq;
    this.predsLoading.set(true);
    this.api.getThreatPredictions(
      append ? this.pageSize : Math.max(this.pageSize, have),
      append ? have : 0,
    ).subscribe({
      next: (d: any) => {
        if (req !== this.predsReq) return;
        const rows = d.predictions || [];
        this.predictions.set(append ? [...this.predictions(), ...rows] : rows);
        this.predsTotal.set(d.total ?? rows.length);
        this.predsAll.set(d.total ?? rows.length);
        this.predsLoading.set(false);
      },
      error: () => { if (req === this.predsReq) this.predsLoading.set(false); },
    });
  }

  loadMoreAnalyses()    { this.fetchAnalyses(true); }
  loadMoreSuppressions() { this.fetchSuppressions(true); }
  loadMorePredictions() { this.fetchPredictions(true); }

  /** Filters changed: start again from the first page. */
  onSeverityChange(v: string) {
    this.selectedSeverity.set(v);
    this.analysesPage.set([]);
    this.fetchAnalyses(false);
  }
  onSearchChange(v: string) {
    this.searchQuery.set(v);
    this.searchInput$.next();
  }

  /** Refreshes whatever tab is open (also used by the 15 s timer and the refresh button). */
  private reloadOpenTab() {
    switch (this._tab) {
      case 'command-center': this.refresh$.next(); this.loadBriefing(); break;
      case 'analyses':       this.fetchAnalyses(false); break;
      case 'suppressions':   this.fetchSuppressions(false); break;
      case 'predictions':    this.fetchPredictions(false); break;
    }
  }

  // ── Live platform numbers from API ──
  private live = toSignal(
    merge(interval(15_000), this.refresh$).pipe(
      startWith(0),
      switchMap(() =>
        this.activeTab !== 'command-center' ? EMPTY :
        forkJoin({
          preds:    this.api.getThreatPredictions(1, 0).pipe(catchError(() => of(null))),
          stats:    this.api.getStats().pipe(catchError(() => of(null))),
          severity: this.api.getSeverity().pipe(catchError(() => of(null))),
          cases:    this.api.getSoarCases().pipe(catchError(() => of(null))),
          timeline: this.api.getStatsTimeline().pipe(catchError(() => of([] as number[]))),
          ips:      this.api.getSensorRecentIps().pipe(catchError(() => of({} as Record<string, string>))),
          counts:   this.api.getSensorEventCounts().pipe(catchError(() => of({} as Record<string, number>))),
        })
      )
    ),
    { initialValue: null as any }
  );

  fmtNum(v: number | null | undefined): string {
    return typeof v === 'number' && isFinite(v) ? v.toLocaleString() : '—';
  }

  private num(v: any): number | null {
    return typeof v === 'number' && isFinite(v) ? v : null;
  }

  eventsTotal = computed(() => this.num(this.live()?.stats?.events_total));
  eventsHour  = computed(() => this.num(this.live()?.stats?.events_1h));
  alertsTotal = computed(() => this.num(this.live()?.stats?.hits_total));
  alertsHour  = computed(() => this.num(this.live()?.stats?.hits_1h));

  /** Distinct IPs that appear in the AI analyses. */
  hostsInvolvedCount = computed(() => {
    const set = new Set<string>();
    for (const a of this.analyses()) {
      if (a.src_ip) set.add(a.src_ip);
      if (a.dst_ip) set.add(a.dst_ip);
    }
    return set.size;
  });

  // Case queue (SOAR)
  private caseList = computed<any[]>(() => (this.live()?.cases?.data ?? []).filter((c: any) => this.inRange(c.created_at)));
  openCasesCount = computed(() =>
    this.caseList().filter((c: any) => !/^(closed|resolved)$/i.test(c.status || '')).length
  );
  closedCasesCount = computed(() =>
    this.caseList().filter((c: any) => /^(closed|resolved)$/i.test(c.status || '')).length
  );

  // Alerts by severity
  sevTotal = computed(() => {
    const s = this.live()?.severity;
    if (!s) return 0;
    return (s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0);
  });

  seriousShare = computed<number | null>(() => {
    const total = this.sevTotal();
    if (!total) return null;
    const s = this.live()?.severity;
    return Math.round((((s?.critical || 0) + (s?.high || 0)) / total) * 100);
  });

  // Sensors of this tenant
  sensors = computed(() => {
    const ips: Record<string, string> = this.live()?.ips ?? {};
    const counts: Record<string, number> = this.live()?.counts ?? {};
    const names = Array.from(new Set([...Object.keys(ips), ...Object.keys(counts)])).sort();
    return names.map(n => ({ name: n, ip: ips[n] || '—', events1h: counts[n] ?? 0 }));
  });

  // ══════════════════════════════════════════════════════════════════════════
  // CONTROL TOWER: every number, bar and row below comes from the API
  // (AI analyses, predictions, suppressions, alerts, cases, sensors)
  // ══════════════════════════════════════════════════════════════════════════

  private tsMs(ts: any): number | null {
    if (ts === null || ts === undefined || ts === '') return null;
    if (typeof ts === 'number') return ts < 1e12 ? ts * 1000 : ts;
    const s = String(ts);
    const d = new Date(s.includes('T') ? s : s.replace(' ', 'T') + 'Z');
    return isNaN(d.getTime()) ? null : d.getTime();
  }

  private sevRank(s: string): number {
    const v = (s || '').toLowerCase();
    return v === 'critical' ? 4 : v === 'high' ? 3 : v === 'medium' ? 2 : 1;
  }

  private caseByCommunity = computed(() => {
    const m = new Map<string, any>();
    for (const c of this.caseList()) if (c.community_id) m.set(c.community_id, c);
    return m;
  });

  private isClosed(c: any): boolean {
    return /^(closed|resolved)$/i.test(c?.status || '');
  }

  summaryCritHigh = computed(() => {
    const s = this.data()?.summary;
    return s ? (s.critical || 0) + (s.high || 0) : this.criticalAnalysesCount() + this.highAnalysesCount();
  });

  analysesToday = computed(() => {
    const since = Date.now() - 86_400_000;
    return this.analyses().filter((a: any) => (this.tsMs(a.created_at) ?? 0) >= since).length;
  });

  // 1. KPI cards
  fmtPct(v: number | null): string {
    return v === null ? '—' : `${v}%`;
  }

  /** Share of cases that are closed or resolved. */
  kpiProgressPct = computed<number | null>(() => {
    const n = this.caseList().length;
    return n ? Math.round((this.closedCasesCount() / n) * 1000) / 10 : null;
  });
  kpiProgressSubtext = computed(() =>
    `${this.closedCasesCount()} of ${this.caseList().length} cases closed · ${this.analysesCountLabel()} AI analyses`
  );

  /** Alerts as a share of stored events. */
  kpiAlertRatePct = computed<number>(() => {
    const e = this.eventsTotal(), a = this.alertsTotal();
    return e && a !== null ? Math.min(100, Math.round((a / e) * 1000) / 10) : 0;
  });
  kpiEventsSubtext = computed(() =>
    `${this.fmtNum(this.alertsTotal())} alerts · ${this.suppressions().length} AI suppressions`
  );

  private openCases = computed(() => this.caseList().filter((c: any) => !this.isClosed(c)));
  kpiCasesLow  = computed(() => this.openCases().filter((c: any) => this.sevRank(c.severity) <= 1).length);
  kpiCasesMed  = computed(() => this.openCases().filter((c: any) => this.sevRank(c.severity) === 2).length);
  kpiCasesHigh = computed(() => this.openCases().filter((c: any) => this.sevRank(c.severity) >= 3).length);

  /** 100 minus the share of stored alerts that are critical or high. */
  kpiReadinessScore = computed<number | null>(() => {
    const s = this.seriousShare();
    return s === null ? null : 100 - s;
  });
  kpiReadinessSubtext = computed(() => {
    const s = this.seriousShare();
    return s === null ? 'No alerts stored yet' : `${s}% of ${this.fmtNum(this.sevTotal())} alerts are critical or high`;
  });

  // 2. Time axis: oldest AI item → now, split into 4 equal periods
  private timeRange = computed(() => {
    const ts: number[] = [];
    for (const a of this.analyses()) { const t = this.tsMs(a.created_at); if (t) ts.push(t); }
    for (const c of this.caseList()) { const t = this.tsMs(c.created_at); if (t) ts.push(t); }
    for (const s of this.suppressions()) { const t = this.tsMs(s.created_at); if (t) ts.push(t); }
    if (!ts.length) return null;
    const min = Math.min(...ts);
    const max = Math.max(Date.now(), ...ts);
    return { min, max: max > min ? max : min + 1 };
  });

  private fmtStamp(ms: number, spanMs: number): string {
    const d = new Date(ms);
    if (spanMs < 2 * 86_400_000) {
      return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });
    }
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  periodLabels = computed<string[]>(() => {
    const r = this.timeRange();
    if (!r) return ['—', '—', '—', '—'];
    const span = r.max - r.min;
    return [0, 1, 2, 3].map(i =>
      `${this.fmtStamp(r.min + (span * i) / 4, span)} – ${this.fmtStamp(r.min + (span * (i + 1)) / 4, span)}`
    );
  });

  // Swimlane bars: older half / newer half of the period, with real counts
  private laneFrom(
    id: string, title: string, lead: string, summary: string, color: string, tagColor: string, glow: string,
    unit: string, items: Array<{ t: number; title: string; sev: number; kind: string; raw: any }>
  ): RoadmapSwimlane {
    const r = this.timeRange();
    const mid = r ? (r.min + r.max) / 2 : 0;
    const halves = [items.filter(i => i.t < mid), items.filter(i => i.t >= mid)];
    const bars: RoadmapInitiativeBar[] = [];
    halves.forEach((h, idx) => {
      if (!h.length) return;
      const top = [...h].sort((a, b) => b.sev - a.sev || b.t - a.t)[0];
      const span = r ? r.max - r.min : 1;
      const from = this.fmtStamp(Math.min(...h.map(x => x.t)), span);
      const to = this.fmtStamp(Math.max(...h.map(x => x.t)), span);
      const first = bars.length === 0;
      bars.push({
        id: `${id}-${idx}`,
        name: `${h.length} ${unit} (${from}${from === to ? '' : ' – ' + to})`,
        leftPct: idx === 0 ? 0 : 50,
        widthPct: 44,
        color,
        glowColor: glow,
        milestoneTag: first ? (top.title.length > 26 ? top.title.slice(0, 24) + '…' : top.title) : undefined,
        milestoneType: first ? (top.sev >= 3 ? 'gate' : 'deployment') : undefined,
        item: top,
      });
    });
    return { id, title, lead, capex: summary, color, tagColor, bars };
  }

  private analysisItems(list: any[]) {
    return list.map((a: any) => ({
      t: this.tsMs(a.created_at) ?? 0, title: this.getAnalysisSnippet(a.analysis),
      sev: this.sevRank(a.severity), kind: 'analysis', raw: a,
    })).filter(i => i.t);
  }

  strategicSwimlanes = computed<RoadmapSwimlane[]>(() => {
    const an = this.analyses();
    const cases = this.caseList();
    const supp = this.suppressions();
    return [
      this.laneFrom('l-ai', 'AI Analyses', 'ARIA', `${this.analysesCountLabel()} analyses · ${this.summaryCritHigh()} crit/high`,
        '#00e5ff', 'rgba(0, 229, 255, 0.15)', 'rgba(0, 229, 255, 0.4)', 'latest analyses', this.analysisItems(an)),
      this.laneFrom('l-case', 'Case Queue', 'SOAR', `${this.openCasesCount()} open · ${this.closedCasesCount()} closed`,
        '#a855f7', 'rgba(168, 85, 247, 0.15)', 'rgba(168, 85, 247, 0.4)', 'cases',
        cases.map((c: any) => ({ t: this.tsMs(c.created_at) ?? 0, title: this.agent(c.title) || c.case_number || 'Case', sev: this.sevRank(c.severity), kind: 'case', raw: c })).filter(i => i.t)),
      this.laneFrom('l-evi', 'Evidence Captured', 'PCAP', `${an.filter((a: any) => a.bundle_id).length} of latest ${an.length} analyses`,
        '#10b981', 'rgba(16, 185, 129, 0.15)', 'rgba(16, 185, 129, 0.4)', 'latest bundles', this.analysisItems(an.filter((a: any) => a.bundle_id))),
      this.laneFrom('l-sup', 'AI Suppressions', 'ARIA', `${this.rangeHours() ? this.activeSuppressionsCount() : (this.data()?.suppActive ?? this.activeSuppressionsCount())} active · ${this.suppCountLabel()} total`,
        '#f59e0b', 'rgba(245, 158, 11, 0.15)', 'rgba(245, 158, 11, 0.4)', 'rules',
        supp.map((s: any) => ({ t: this.tsMs(s.created_at) ?? 0, title: this.agent(s.signature_name) || s.suppress_ip || 'Suppression rule', sev: 1, kind: 'suppression', raw: s })).filter((i: any) => i.t)),
    ];
  });

  threatHuntSwimlanes = computed<RoadmapSwimlane[]>(() => {
    const an = this.analyses();
    const bySev = (rank: number) => an.filter((a: any) => Math.min(this.sevRank(a.severity), 4) === rank);
    const mk = (id: string, title: string, rank: number, color: string, tag: string, glow: string) => {
      const l = bySev(rank);
      return this.laneFrom(id, title, 'ARIA', `${l.length} analyses`, color, tag, glow, 'analyses', this.analysisItems(l));
    };
    return [
      mk('t-crit', 'Critical', 4, '#ef4444', 'rgba(239, 68, 68, 0.15)', 'rgba(239, 68, 68, 0.4)'),
      mk('t-high', 'High', 3, '#f59e0b', 'rgba(245, 158, 11, 0.15)', 'rgba(245, 158, 11, 0.4)'),
      mk('t-med', 'Medium', 2, '#a855f7', 'rgba(168, 85, 247, 0.15)', 'rgba(168, 85, 247, 0.4)'),
      mk('t-low', 'Low', 1, '#10b981', 'rgba(16, 185, 129, 0.15)', 'rgba(16, 185, 129, 0.4)'),
    ];
  });

  currentSwimlanes = computed(() =>
    this.roadmapPerspective() === 'strategic' ? this.strategicSwimlanes() : this.threatHuntSwimlanes()
  );

  // 3. Registry: the newest real AI findings and where each stands in the case queue
  allMilestones = computed<RoadmapMilestone[]>(() => {
    const byCid = this.caseByCommunity();
    return this.analyses().slice(0, 6).map((a: any) => {
      const c = a.community_id ? byCid.get(a.community_id) : undefined;
      const sev = (a.severity || '').toUpperCase();
      const rank = this.sevRank(a.severity);
      return {
        id: (a.id || '').slice(0, 8).toUpperCase(),
        name: this.getAnalysisSnippet(a.analysis),
        domain: c ? c.case_number : 'No case',
        target: this.formatRelativeTime(a.created_at) || '—',
        status: c ? (this.isClosed(c) ? 'RESOLVED' : 'OPEN CASE') : 'NEW',
        risk: (rank >= 3 ? 'HIGH' : rank === 2 ? 'MED' : 'LOW') as 'LOW' | 'MED' | 'HIGH',
        owner: c?.assigned_to || 'Unassigned',
        description: a.analysis || '',
        progressPct: 0,
        flow: this.flowOf(a),
        communityId: a.community_id,
        rawAnalysis: a,
      } as RoadmapMilestone;
    });
  });

  filteredMilestones = computed(() => {
    const q = this.searchQuery().toLowerCase().trim();
    const st = this.selectedMilestoneStatus().toUpperCase();
    return this.allMilestones().filter((m) => {
      const matchStatus = st === 'ALL' || m.status.toUpperCase() === st;
      const matchText = !q || m.name.toLowerCase().includes(q) || m.id.toLowerCase().includes(q) ||
        m.domain.toLowerCase().includes(q) || (m.flow || '').toLowerCase().includes(q);
      return matchStatus && matchText;
    });
  });

  // 4. Risk matrix: analysis severity (rows) x case state (columns)
  riskHeatmap = computed(() => {
    const byCid = this.caseByCommunity();
    const grid: Record<string, number[]> = { High: [0, 0, 0], Med: [0, 0, 0], Low: [0, 0, 0] };
    for (const a of this.analyses()) {
      const rank = this.sevRank(a.severity);
      const row = rank >= 3 ? 'High' : rank === 2 ? 'Med' : 'Low';
      const c = a.community_id ? byCid.get(a.community_id) : undefined;
      grid[row][c ? (this.isClosed(c) ? 0 : 1) : 2]++;
    }
    const style = [
      [['amber', 'rgba(217, 119, 6, 0.45)', '#fbbf24'], ['orange', 'rgba(234, 88, 12, 0.65)', '#f97316'], ['red', 'rgba(239, 68, 68, 0.45)', '#f87171']],
      [['green', 'rgba(16, 185, 129, 0.45)', '#34d399'], ['amber', 'rgba(245, 158, 11, 0.55)', '#fbbf24'], ['orange', 'rgba(234, 88, 12, 0.65)', '#f97316']],
      [['green', 'rgba(16, 185, 129, 0.45)', '#34d399'], ['green', 'rgba(16, 185, 129, 0.45)', '#34d399'], ['amber', 'rgba(245, 158, 11, 0.55)', '#fbbf24']],
    ];
    const cols = ['Closed case', 'Open case', 'No case'];
    return ['High', 'Med', 'Low'].map((impact, ri) => ({
      impact,
      cells: grid[impact].map((count, ci) => ({
        likelihood: cols[ci], count, level: style[ri][ci][0], bg: style[ri][ci][1], color: style[ri][ci][2],
        text: `${count} ${impact.toLowerCase()}-severity analyses · ${cols[ci].toLowerCase()}`,
      })),
    }));
  });

  riskSummaryTopThreat = computed(() => {
    const worst = [...this.openCases()].sort((a: any, b: any) => this.sevRank(b.severity) - this.sevRank(a.severity))[0];
    if (worst) return worst.title || worst.case_number;
    const a = this.analyses()[0];
    return a ? this.getAnalysisSnippet(a.analysis) : 'Nothing open';
  });
  latestAnalysisAge = computed(() => {
    const a = this.analyses()[0];
    return a ? this.formatRelativeTime(a.created_at) : '—';
  });

  // 5. Severity donut (all stored alerts)
  pillarsDistribution = computed(() => {
    const circumference = 240;
    const s = this.live()?.severity || {};
    const total = this.sevTotal();
    const rows = [
      { name: 'Critical', count: s.critical || 0, color: '#ef4444' },
      { name: 'High',     count: s.high     || 0, color: '#f59e0b' },
      { name: 'Medium',   count: s.medium   || 0, color: '#a855f7' },
      { name: 'Low',      count: s.low      || 0, color: '#10b981' },
    ];
    let used = 0;
    return {
      total,
      pillars: rows.map(r => {
        const share = total ? r.count / total : 0;
        const dash = share * circumference;
        const out = { ...r, pct: Math.round(share * 100), dash, gap: circumference - dash, offset: -used };
        used += dash;
        return out;
      }),
    };
  });

  // Stacked bars: AI analyses per period, by severity
  periodBars = computed(() => {
    const r = this.timeRange();
    const labels = this.periodLabels();
    const buckets = [0, 1, 2, 3].map(() => ({ high: 0, med: 0, low: 0 }));
    if (r) {
      for (const a of this.analyses()) {
        const t = this.tsMs(a.created_at);
        if (!t) continue;
        const i = Math.min(3, Math.floor(((t - r.min) / (r.max - r.min)) * 4));
        const rank = this.sevRank(a.severity);
        buckets[i][rank >= 3 ? 'high' : rank === 2 ? 'med' : 'low']++;
      }
    }
    const max = Math.max(1, ...buckets.map(b => b.high + b.med + b.low));
    return buckets.map((b, i) => {
      const total = b.high + b.med + b.low;
      return { quarter: labels[i], total, ...b, heightPct: total ? Math.max(8, Math.round((total / max) * 95)) : 0 };
    });
  });
  periodBarMax = computed(() => Math.max(1, ...this.periodBars().map(b => b.total)));

  // Response pipeline (replaces the stage gates)
  pipelineSteps = computed(() => {
    const alerts = this.alertsTotal() ?? 0;
    const an = this.analyses().length;
    const open = this.openCasesCount();
    const rules = this.activeSuppressionsCount();
    return [
      { gate: 'Step 1', title: 'Detect: alerts stored', status: `${this.fmtNum(this.alertsTotal())} alerts`, state: alerts > 0 ? 'passed' : 'pending' },
      { gate: 'Step 2', title: 'Analyse: AI triage', status: `${an} analyses`, state: an > 0 ? 'passed' : 'pending' },
      { gate: 'Step 3', title: 'Respond: case queue', status: `${open} open`, state: open > 0 ? 'active' : this.caseList().length ? 'passed' : 'pending' },
      { gate: 'Step 4', title: 'Tune: AI suppressions', status: `${rules} active`, state: rules > 0 ? 'passed' : 'pending' },
    ];
  });

  // Dedicated Tab Data & Filters
  criticalAnalysesCount = computed(() =>
    this.analyses().filter((a: any) => (a.severity || '').toLowerCase() === 'critical').length
  );
  highAnalysesCount = computed(() =>
    this.analyses().filter((a: any) => (a.severity || '').toLowerCase() === 'high').length
  );
  mediumAnalysesCount = computed(() =>
    this.analyses().filter((a: any) => (a.severity || '').toLowerCase() === 'medium').length
  );
  lowAnalysesCount = computed(() =>
    this.analyses().filter((a: any) => {
      const s = (a.severity || '').toLowerCase();
      return s === 'low' || s === 'info';
    }).length
  );
  activeSuppressionsCount = computed(() =>
    this.suppressions().filter((s: any) => s.active).length
  );
  highRiskPredictionsCount = computed(() =>
    this.predictions().filter((p: any) => {
      const lvl = (p.alert_level || '').toLowerCase();
      return lvl === 'critical' || lvl === 'high' || (p.probability || 0) >= 0.5;
    }).length
  );

  selectedAnalysis = computed(() => {
    const id = this.selectedAnalysisId();
    const list = this.analyses();
    if (id) {
      const match = list.find((a: any) => a.id === id);
      if (match) return match;
    }
    const filtered = this.analysesPage();
    if (filtered.length > 0) return filtered[0];
    return list.length > 0 ? list[0] : null;
  });

  selectedPrediction = computed(() =>
    this.predictions().find((p: any) => p.attack_type === this.expandedPrediction())
  );

  ngOnInit() {
    this.updateUtcTime();
    this.timeSub = interval(1000).subscribe(() => this.updateUtcTime());
    // the Control Tower refreshes itself; the list tabs re-read what is on screen every 15 s
    this.loadBriefing();
    this.pollSub = interval(15_000).subscribe(() => { if (this._tab !== 'command-center') this.reloadOpenTab(); });
    this.searchSub = this.searchInput$.pipe(debounceTime(300)).subscribe(() => {
      if (this._tab !== 'analyses') return; // the other tabs pick the search up when opened
      this.analysesPage.set([]);
      this.fetchAnalyses(false);
    });
  }

  ngOnDestroy() {
    this.timeSub?.unsubscribe();
    this.pollSub?.unsubscribe();
    this.searchSub?.unsubscribe();
  }

  private updateUtcTime() {
    const now = new Date();
    const h = String(now.getUTCHours()).padStart(2, '0');
    const m = String(now.getUTCMinutes()).padStart(2, '0');
    const s = String(now.getUTCSeconds()).padStart(2, '0');
    this.currentUtcTime.set(`${h}:${m}:${s} UTC`);
    this.currentFormattedDate.set(
      now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    );
  }

  // Dossier actions
  openMilestoneDossier(m: RoadmapMilestone) {
    if (m.rawAnalysis) this.inspectAnalysis(m.rawAnalysis);
  }

  openInitiativeDossier(bar: RoadmapInitiativeBar, _lane: RoadmapSwimlane) {
    const it = bar.item;
    if (!it) return;
    if (it.kind === 'analysis') return this.inspectAnalysis(it.raw);
    if (it.kind === 'suppression') { this.activeTab = 'suppressions'; return; }
    const c = it.raw;
    this.selectedDossierData.set({
      type: 'case',
      title: this.agent(c.title) || c.case_number,
      id: c.case_number,
      domain: 'Case queue',
      target: this.formatRelativeTime(this.isoOf(c.created_at)),
      status: this.isClosed(c) ? 'RESOLVED' : 'OPEN CASE',
      risk: (c.severity || '').toUpperCase(),
      owner: c.assigned_to || 'Unassigned',
      description: c.description || '',
      flow: c.src_ip || c.dst_ip ? `${c.src_ip || '?'} ➔ ${c.dst_ip || '?'}` : '',
      communityId: c.community_id,
    });
    this.isDossierOpen.set(true);
  }

  private isoOf(ts: any): string {
    const ms = this.tsMs(ts);
    return ms ? new Date(ms).toISOString() : '';
  }

  inspectAnalysis(a: any) {
    if (!a) return;
    this.selectedAnalysisId.set(a.id);
    const parsed = this.parseAnalysis(a.analysis);
    this.loadVerdict(a.community_id);
    this.hideState.set('closed');
    this.selectedDossierData.set({
      type: 'analysis',
      title: parsed.threat ? parsed.threat.slice(0, 75) + '...' : `Threat Analysis ${a.id.slice(0, 8)}`,
      id: a.id,
      domain: 'AI analysis',
      target: this.formatRelativeTime(a.created_at),
      status: (a.severity || 'CRITICAL').toUpperCase(),
      risk: (a.severity || 'HIGH').toUpperCase(),
      owner: 'ARIA AI',
      description: a.analysis,
      flow: this.flowOf(a),
      communityId: a.community_id,
      bundleId: a.bundle_id,
      parsed: parsed,
      raw: a
    });
    this.isDossierOpen.set(true);
  }

  closeDossier() {
    this.isDossierOpen.set(false);
  }

  onRiskCellClick(cell: any, impact: string) {
    if (this.selectedRiskCell()?.impact === impact && this.selectedRiskCell()?.likelihood === cell.likelihood) {
      this.selectedRiskCell.set(null);
    } else {
      this.selectedRiskCell.set({ impact, likelihood: cell.likelihood });
    }
  }

  statusClass(status: string): string {
    const s = (status || '').toUpperCase();
    const map: Record<string, string> = {
      'RESOLVED': 'st-done', 'OPEN CASE': 'st-slow', 'NEW': 'st-on-track',
      'CRITICAL': 'st-at-risk', 'HIGH': 'st-delayed', 'MEDIUM': 'st-slow', 'LOW': 'st-on-track',
    };
    return map[s] || 'st-' + s.toLowerCase().replace(/\s+/g, '-');
  }

  riskClass(risk: string): string {
    const r = (risk || '').toLowerCase();
    return 'risk-' + r;
  }

  sevClass(s: string) {
    return 'sev-' + (s || 'unknown').toLowerCase();
  }

  alertLevelClass(level: string) {
    return 'alert-' + (level || 'info').toLowerCase();
  }

  probBar(p: number) {
    return Math.round((p || 0) * 100);
  }

  probColor(p: number): string {
    const pct = (p || 0) * 100;
    if (pct >= 75) return '#ff2a5f';
    if (pct >= 50) return '#ff9900';
    if (pct >= 25) return '#ffea00';
    return '#10b981';
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

  formatEndpoint(asset: any, ip?: string, fallback: string = '—'): string {
    if (asset?.hostname) return asset.hostname;
    if (ip && ip.trim().length > 0) return ip;
    return fallback;
  }

  formatHash(hash: string): string {
    if (!hash) return 'N/A';
    return hash.length > 20 ? `${hash.slice(0, 18)}…` : hash;
  }

  formatTime(ts: string) {
    if (!ts) return '';
    const d = new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z');
    return isNaN(d.getTime()) ? ts : d.toLocaleString();
  }

  formatRelativeTime(ts: string): string {
    if (!ts) return '';
    const d = new Date(ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z');
    if (isNaN(d.getTime())) return ts;

    const diffMs = Date.now() - d.getTime();
    if (diffMs < 0) return 'Just now';
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHr = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHr / 24);

    if (diffSec < 60) return 'Just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    if (diffDay < 7) return `${diffDay}d ago`;
    return d.toLocaleDateString();
  }

  flowOf(a: any): string {
    const src = a.src_asset?.hostname || a.src_ip || '';
    const dst = a.dst_asset?.hostname || a.dst_ip || '';
    return src || dst ? `${src || '?'} ➔ ${dst || '?'}` : '—';
  }

  parseAnalysis(rawText: string): ParsedReport {
    if (!rawText) {
      return { threat: null, risk: null, actions: [], raw: '' };
    }

    const text = rawText.trim();

    const threatMatch = text.match(
      /(?:THREAT|SUMMARY|ASSESSMENT|DETECTION|FINDINGS):\s*([\s\S]*?)(?=(?:\n\s*(?:RISK|IMPACT|ACTION|RECOMMENDATION|PLAYBOOK):)|$)/i
    );

    const riskMatch = text.match(
      /(?:RISK|IMPACT|SEVERITY ASSESSMENT):\s*([\s\S]*?)(?=(?:\n\s*(?:ACTION|RECOMMENDATION|PLAYBOOK|NEXT STEPS):)|$)/i
    );

    const actionMatch = text.match(
      /(?:ACTION|ACTIONS|RECOMMENDATIONS?|PLAYBOOK|NEXT STEPS|MITIGATION):\s*([\s\S]*?)$/i
    );

    const threat = threatMatch ? threatMatch[1].trim() : null;
    const risk = riskMatch ? riskMatch[1].trim() : null;
    const actions: string[] = [];

    if (actionMatch) {
      const rawActionText = actionMatch[1].trim();
      const lines = rawActionText.split(/\n+/);
      let currentAction = '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (/^[-*•]\s+/.test(trimmed) || /^\d+[\.)]\s+/.test(trimmed)) {
          if (currentAction) actions.push(currentAction);
          currentAction = trimmed.replace(/^[-*•\d.)]+\s*/, '').trim();
        } else if (currentAction) {
          currentAction += ' ' + trimmed;
        } else if (trimmed) {
          currentAction = trimmed;
        }
      }
      if (currentAction) {
        actions.push(currentAction);
      }
    }

    if (!threat && !risk && actions.length === 0) {
      return { threat: text, risk: null, actions: [], raw: text };
    }

    return { threat, risk, actions, raw: text };
  }

  /** Engines are shown by their product names: Suricata is agent-s, Zeek is agent-z. */
  agent(text: any): string {
    return typeof text === 'string' ? text.replace(/suricata/gi, 'agent-s').replace(/zeek/gi, 'agent-z') : text;
  }

  getAnalysisSnippet(rawText: string): string {
    return this.agent(this.snippetOf(rawText));
  }

  private snippetOf(rawText: string): string {
    if (!rawText) return 'No analysis text stored for this session.';
    const parsed = this.parseAnalysis(rawText);
    const src = parsed.threat || rawText;
    const firstSentence = src.split(/[.\n]/)[0]?.trim();
    if (firstSentence && firstSentence.length > 8) {
      return firstSentence.length > 70 ? firstSentence.slice(0, 67) + '...' : firstSentence + '.';
    }
    return src.length > 70 ? src.slice(0, 67) + '...' : src;
  }

  /** Each prediction is its own card, keyed by the indicator it is about (URL or IP). Two cards
   *  of the same attack type must not open together or share a history. */
  predKey(p: any): string {
    if (p?.indicator) return p.indicator;
    // Older predictions have no indicator. Several can share one timestamp, so the key also
    // carries the explanation text, which is what makes each row its own card.
    return `row:${p?.attack_type}|${p?.predicted_at}|${(p?.explanation || '').slice(0, 300)}`;
  }

  togglePrediction(key: string) {
    if (this.expandedPrediction() === key) {
      this.expandedPrediction.set(null);
      this.historicalPredictions.set([]);
    } else {
      this.expandedPrediction.set(key);
      this.historicalPredictions.set([]);
      // a card with no indicator has no history of its own; it only shows its own row
      this.api.getThreatPredictionsHistory(key.startsWith('row:') ? undefined : key).subscribe({
        next: (data: any) => {
          if (data && data.predictions) {
            this.historicalPredictions.set(data.predictions.filter((p: any) => this.predKey(p) === key));
          }
        },
        error: reportRxjsError,
      });
    }
  }

  isPredExpanded(key: string) {
    return this.expandedPrediction() === key;
  }

  copyToClipboard(text: string, id: string) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      this.copiedId.set(id);
      setTimeout(() => {
        if (this.copiedId() === id) {
          this.copiedId.set(null);
        }
      }, 2000);
    });
  }

  manualRefresh() {
    this.isRefreshing.set(true);
    this.reloadOpenTab();
    setTimeout(() => this.isRefreshing.set(false), 800);
  }

  openEvidence(bundleId?: string) {
    if (bundleId) {
      this.router.navigate(['/analyst/evidence'], { queryParams: { bundle: bundleId } });
    } else {
      this.router.navigate(['/analyst/evidence']);
    }
  }

  deactivateSuppression(id: string) {
    this.api.deactivateAiSuppression(id).subscribe({
      next: () => this.reloadOpenTab(),
      error: () => {},
    });
  }

  deleteSuppression(id: string) {
    if (!confirm('Delete this suppression rule permanently?')) return;
    this.api.deleteAiSuppression(id).subscribe({
      next: () => this.reloadOpenTab(),
      error: () => {},
    });
  }

  openAiReport() {
    this.router.navigate(['/analyst/ai-report']);
  }
}
