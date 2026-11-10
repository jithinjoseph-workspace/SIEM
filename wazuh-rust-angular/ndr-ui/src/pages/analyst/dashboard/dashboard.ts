import { Component, OnInit, OnDestroy, ViewChild, ElementRef, HostListener, signal, computed, effect, untracked, viewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { ConfigService } from '../../../services/config/config.service';
import { Websocket } from '../../../services/websocket/websocket';
import { ChartDataService } from '../../../services/chart-data/chart-data';
import { Subscription, interval, of } from 'rxjs';
import { startWith, switchMap, catchError } from 'rxjs/operators';
import { toSignal } from '@angular/core/rxjs-interop';
import {
  LucideAngularModule,
  TrendingUp, TriangleAlert, Shield, Activity, ArrowUpRight, RefreshCw, Bot, X, ChevronRight, Zap, Map, Network
} from 'lucide-angular';
import { Router } from '@angular/router';
import * as d3 from 'd3';
import { SiemDashboard } from '../../siem/dashboard/siem-dashboard';
import { ThreatMap } from '../threat-map/threat-map';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, SiemDashboard, ThreatMap],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class Dashboard implements OnInit, OnDestroy {

  // ── Stat card values ──────────────────────────────────────────────────────
  totalEvents = signal(0);
  totalHits = signal(0);
  eventsLastHour = signal(0);
  hitsLastHour = signal(0);
  zeekEvents = signal(0);
  suricataEvents = signal(0);
  protocols = signal<any[]>([]);
  critical = signal(0);
  high = signal(0);
  medium = signal(0);
  low = signal(0);
  topSrcIps = signal<any[]>([]);
  topDstIps = signal<any[]>([]);

  // ── Chart state ───────────────────────────────────────────────────────────
  chartLoading = signal(true);   // shows skeleton shimmer
  chartError = signal(false);  // shows error + retry UI

  // ── Threat Prediction State ───────────────────────────────────────────────
  activePredictions = signal<any[]>([]);
  historicalPredictions = signal<any[]>([]);
  showPredictionModal = signal(false);
  selectedPrediction = signal<any>(null);

  /** Cosmetic bar heights for the skeleton shimmer. */
  readonly skeletonBars = ['30%', '55%', '40%', '70%', '50%', '85%', '60%', '45%', '75%', '35%'];

  // ── Icons ─────────────────────────────────────────────────────────────────
  TrendingUpIcon = TrendingUp;
  AlertIcon = TriangleAlert;
  ShieldIcon = Shield;
  ActivityIcon = Activity;
  ArrowIcon = ArrowUpRight;
  RefreshIcon = RefreshCw;
  BotIcon = Bot;
  XIcon = X;
  ChevronRightIcon = ChevronRight;
  ZapIcon = Zap;
  MapIcon = Map;
  NetworkIcon = Network;

  liveEventStreamRef = viewChild<ElementRef>('liveEventStream');
  @ViewChild('severityDonutChart') severityDonutChartRef!: ElementRef;
  @ViewChild('topDstIpsChart') topDstIpsChartRef!: ElementRef;
  protocolPieChartRef = viewChild<ElementRef>('protocolPieChart');

  chartDataSnapshot = signal<{ labels: string[], data: number[], critical: number[], high: number[], medium: number[], low: number[] }>({ labels: [], data: [], critical: [], high: [], medium: [], low: [] });

  private subs: Subscription[] = [];

  // Tracks unique incidents to deduplicate live stat card increments
  private seenIncidents = new Set<string>();

  // Derived signal for total severity count to use in calculations
  totalSeverityCount = computed(() => (this.critical() + this.high() + this.medium() + this.low()) || 1);

  /** Sensor IDs this user is scoped to (from JWT). Empty = unrestricted. */
  sensorIds: string[] = [];

  hasNdr  = false;
  hasSiem = false;
  activeTab = signal<'ndr' | 'siem'>('ndr');

  // ── Unified KPI strip (only when hasNdr && hasSiem) ───────────────────────
  uNdrEvents   = signal(0);
  uSiemLogs    = signal(0);
  uSiemEps     = signal(0);
  uCorrHits    = signal(0);
  uCritical    = signal(0);
  uHigh        = signal(0);
  uMedium      = signal(0);

  constructor(
    private api: Api,
    private ws: Websocket,
    private chartService: ChartDataService,
    private router: Router,
    private auth: AuthService,
    private config: ConfigService,
  ) {
    // ── Effects for D3 re-rendering ───────────────────────────────────────
    effect(() => {
      const snap = this.chartDataSnapshot();
      const el = this.liveEventStreamRef(); // Safely wait for the DOM element
      if (snap.labels.length > 0 && el) {
        untracked(() => this.drawLiveEventStream());
      }
    });

    effect(() => {
      // Re-run donut draw when any severity changes
      this.critical(); this.high(); this.medium(); this.low();
      untracked(() => this.drawSeverityDonut());
    });

    effect(() => {
      this.topDstIps();
      untracked(() => this.drawTopDstIpsChart());
    });

    effect(() => {
      this.protocols();
      untracked(() => this.drawProtocolPie());
    });
  }

  ngOnInit() {
    // Tab visible only when tenant has the feature AND analyst has the page permission
    this.hasNdr  = this.auth.hasFeature('ndr')  && this.auth.hasPermission('dashboard');
    this.hasSiem = this.auth.hasFeature('siem') && this.auth.hasPermission('siem-dashboard');
    this.sensorIds = this.auth.getSensorIds();

    // Unified KPI strip — poll every 30s when both features active
    if (this.hasNdr && this.hasSiem) {
      this.subs.push(
        interval(30_000).pipe(
          startWith(0),
          // catchError inside switchMap's inner observable (not just an error:
          // callback on subscribe) - without it, a single failed poll (401,
          // network blip) terminates this whole subscription and the KPI strip
          // silently stops refreshing for the rest of the page session.
          switchMap(() => this.api.getUnifiedStats().pipe(catchError(() => of(null))))
        ).subscribe({ next: (r: any) => {
            if (!r) return;
            this.uNdrEvents.set(r.ndr_events_today  ?? 0);
            this.uSiemLogs.set(r.siem_logs_today    ?? 0);
            this.uSiemEps.set(r.siem_eps            ?? 0);
            this.uCorrHits.set(r.correlation_hits_1h ?? 0);
            this.uCritical.set(r.critical_alerts    ?? 0);
            this.uHigh.set(r.high_alerts            ?? 0);
            this.uMedium.set(r.medium_alerts        ?? 0);
          }})
      );
    }

    // Kick off the single background fetch loop in the service.
    // /api/stats is now called ONCE every 30s — result shared with stat cards.
    this.chartService.start();

    // ── Chart: loading state ─────────────────────────────────────────────
    this.subs.push(
      this.chartService.isLoading$.subscribe(loading => {
        this.chartLoading.set(loading);
      })
    );

    // ── Chart: data (SWR pattern) ────────────────────────────────────────
    // Warm start  → BehaviorSubject replays cached value synchronously here,
    //               chart renders on first paint with zero delay.
    // Cold start  → fires once API responds (~1 s), skeleton disappears.
    this.subs.push(
      this.chartService.chart$.subscribe(snapshot => {
        this.chartLoading.set(false);
        this.chartError.set(false);
        this.chartDataSnapshot.set(snapshot);
      })
    );

    // ── Stat cards: driven by the same /api/stats fetch as the chart ─────
    // No duplicate network call — service shares the payload via stats$.
    this.subs.push(
      this.chartService.stats$.subscribe(stats => {
        this.totalEvents.set(stats.events_total);
        this.totalHits.set(stats.hits_total);
        this.eventsLastHour.set(stats.events_1h);
        this.hitsLastHour.set(stats.hits_1h);
        this.zeekEvents.set(stats.agent_z_events);
        this.suricataEvents.set(stats.agent_s_events);
      })
    );

    // ── Chart: error state ───────────────────────────────────────────────
    this.subs.push(
      this.chartService.hasError$.subscribe(hasError => {
        if (hasError) {
          this.chartLoading.set(false);
          this.chartError.set(true);
        }
      })
    );

    // ── Cold start: fetch supporting data once on load ───────────────────
    // After this, WebSocket telemetry takes over — no more HTTP polling.
    this.loadSupportingStats();

    // ── WebSocket: authoritative counts + supporting data every 30s ──────
    this.subs.push(
      this.ws.telemetry$.subscribe(t => {
        this.totalEvents.set(t.total_events);
        this.zeekEvents.set(t.agent_z_events);
        this.suricataEvents.set(t.agent_s_events);
        this.totalHits.set(t.correlation_hits);
        this.eventsLastHour.set(t.events_1h);
        if (t.severity) {
          this.critical.set(t.severity.critical || 0);
          this.high.set(t.severity.high || 0);
          this.medium.set(t.severity.medium || 0);
          this.low.set(t.severity.low || 0);
        }
        if (t.top_src_ips) this.topSrcIps.set(t.top_src_ips);
        if (t.top_dst_ips) this.topDstIps.set(t.top_dst_ips);
        if (t.protocols) this.protocols.set(t.protocols);
      })
    );

    // ── WebSocket: real-time increments (between telemetry pushes) ────────
    this.subs.push(
      this.ws.events$.subscribe(() => {
        this.eventsLastHour.update(v => v + 1);
        this.totalEvents.update(v => v + 1);
      })
    );

    this.subs.push(
      this.ws.hits$.subscribe(hit => {
        this.totalHits.update(v => v + 1);
        this.hitsLastHour.update(v => v + 1);

        const severity = (hit.severity ?? '').toUpperCase() || 'LOW';
        const srcIp = hit.src || hit['agent-z']?.src || hit['agent-s']?.src || '-';
        const dstIp = hit.dst || hit['agent-z']?.dst || hit['agent-s']?.dst || '-';
        const incidentId = `${srcIp}|${dstIp}|${severity}`;

        // ── Real-time severity counter sync ─────────────────────────────────
        if (!this.seenIncidents.has(incidentId)) {
          this.seenIncidents.add(incidentId);
          switch (severity) {
            case 'CRITICAL': this.critical.update(v => v + 1); break;
            case 'HIGH': this.high.update(v => v + 1); break;
            case 'MEDIUM': this.medium.update(v => v + 1); break;
            default: this.low.update(v => v + 1); break;
          }
        }
      })
    );
  }

  // ── Public actions ─────────────────────────────────────────────────────────

  retryChart() {
    this.chartError.set(false);
    this.chartLoading.set(true);
    this.chartService.retry();
  }

  exportReport(format: string) { this.api.exportReport(format); }

  openAlerts(queryParams: Record<string, string> = {}) {
    this.router.navigate(['/analyst/alerts'], { queryParams });
  }

  openNetworkMap() { this.router.navigate(['/analyst/network-map']); }

  openThreatMap() { this.router.navigate(['/analyst/threat-map']); }

  openAiReport() { this.router.navigate(['/analyst/ai-report']); }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Fetches severity breakdown and top IPs — the only remaining periodic
   * API calls in this component. /api/stats is handled entirely by
   * ChartDataService to avoid duplicate requests.
   */
  private loadSupportingStats() {
    this.api.getSeverity().subscribe({
      next: data => {
        this.seenIncidents.clear(); // Reset live deduplication baseline
        this.critical.set(data.critical || 0);
        this.high.set(data.high || 0);
        this.medium.set(data.medium || 0);
        this.low.set(data.low || 0);
      },
      error: reportRxjsError
    });

    this.api.getTopIps().subscribe({
      next: data => {
        this.topSrcIps.set(data.top_src_ips || []);
        this.topDstIps.set(data.top_dst_ips || []);
      },
      error: reportRxjsError
    });

    this.api.getProtocols().subscribe({
      next: data => { this.protocols.set(data.protocols || []); },
      error: reportRxjsError
    });

    // Fetch active threat predictions for the alert banner every 60s
    this.subs.push(
      interval(60_000).pipe(
        startWith(0),
        switchMap(() => this.api.getThreatPredictions())
      ).subscribe({
        next: data => {
          if (data && data.predictions) {
            this.activePredictions.set(data.predictions);
          }
        },
        error: reportRxjsError
      })
    );
  }

  // ── Threat Prediction Logic ─────────────────────────────────────────────────

  openPredictionModal(prediction: any) {
    this.selectedPrediction.set(prediction);
    this.showPredictionModal.set(true);
    
    // Fetch historical data for context
    this.api.getThreatPredictionsHistory().subscribe({
      next: data => {
        if (data && data.predictions) {
          const history = data.predictions.filter((p: any) => p.attack_type === prediction.attack_type);
          this.historicalPredictions.set(history);
        }
      },
      error: reportRxjsError
    });
  }

  closePredictionModal() {
    this.showPredictionModal.set(false);
    setTimeout(() => {
      this.selectedPrediction.set(null);
      this.historicalPredictions.set([]);
    }, 300); // Wait for transition
  }

  private throttle(func: Function, limit: number) {
    let lastFunc: any;
    let lastRan: any;
    return (...args: any[]) => {
      if (!lastRan) {
        func.apply(this, args);
        lastRan = Date.now();
      } else {
        clearTimeout(lastFunc);
        const remaining = limit - (Date.now() - lastRan);
        lastFunc = setTimeout(() => {
          if ((Date.now() - lastRan) >= limit) {
            func.apply(this, args);
            lastRan = Date.now();
          }
        }, remaining > 0 ? remaining : 0);
      }
    };
  }

  drawLiveEventStream = this.throttle(() => this.drawLiveEventStreamRaw(), 300);
  drawSeverityDonut = this.throttle(() => this.drawSeverityDonutRaw(), 300);
  drawProtocolPie = this.throttle(() => this.drawProtocolPieRaw(), 300);
  drawTopDstIpsChart = this.throttle(() => this.drawTopDstIpsChartRaw(), 300);

  @HostListener('window:resize')
  onResize() {
    this.drawLiveEventStream();
    this.drawSeverityDonut();
    this.drawTopDstIpsChart();
    this.drawProtocolPie();
  }

  private drawLiveEventStreamRaw() {
    const snap = this.chartDataSnapshot();
    const liveStreamEl = this.liveEventStreamRef();
    if (!liveStreamEl || !snap.labels.length) return;
    const el = liveStreamEl.nativeElement;

    // Clear previous SVG
    d3.select(el).selectAll('*').remove();

    const width = el.clientWidth || 600;
    const height = el.clientHeight || 250;
    const margin = { top: 20, right: 40, bottom: 30, left: 40 };

    const svg = d3.select(el).append("svg")
      .attr("width", width)
      .attr("height", height);

    const x = d3.scaleLinear()
      .domain([0, Math.max(0, snap.labels.length - 1)])
      .range([margin.left, width - margin.right]);

    // X Axis
    svg.append("g")
      .attr("transform", `translate(0,${height - margin.bottom})`)
      .call(d3.axisBottom(x)
        .tickValues(d3.range(snap.labels.length).filter(i => !(i % Math.max(1, Math.floor(snap.labels.length / 5)))))
        .tickFormat(d => snap.labels[d as number])
      )
      .call(g => g.select(".domain").remove())
      .call(g => g.selectAll("text").attr("fill", "#a4abbf").style("font-family", "var(--font-mono)"));

    // Left Y Axis (Events Volume)
    const maxEvents = d3.max(snap.data) || 0;
    const yEventsDomainMax = maxEvents > 0 ? maxEvents * 1.1 : 2;
    const yLeft = d3.scaleLinear()
      .domain([0, yEventsDomainMax])
      .range([height - margin.bottom, margin.top]);

    // Right Y Axis (Alerts)
    const allAlertVals = [...snap.critical, ...snap.high, ...snap.medium, ...snap.low];
    const maxAlerts = d3.max(allAlertVals) || 0;
    const yAlertsDomainMax = Math.max(5, maxAlerts * 1.2);
    const yRight = d3.scaleLinear()
      .domain([0, yAlertsDomainMax])
      .range([height - margin.bottom, margin.top]);

    // Left Axis (Grid lines)
    svg.append("g")
      .attr("transform", `translate(${margin.left},0)`)
      .call(d3.axisLeft(yLeft).ticks(5).tickSize(-width + margin.left + margin.right))
      .call(g => g.select(".domain").remove())
      .call(g => g.selectAll(".tick line")
        .attr("stroke", "rgba(255,255,255,0.05)")
        .attr("stroke-dasharray", "4,4"))
      .call(g => g.selectAll(".tick text")
        .attr("fill", "#69f6b8")
        .style("font-family", "var(--font-mono)")
        .attr("dx", "-10"));

    // Right Axis
    svg.append("g")
      .attr("transform", `translate(${width - margin.right},0)`)
      .call(d3.axisRight(yRight).ticks(5).tickSize(0))
      .call(g => g.select(".domain").remove())
      .call(g => g.selectAll(".tick text")
        .attr("fill", "#94a3b8")
        .style("font-family", "var(--font-mono)")
        .attr("dx", "10"));

    // Generators
    const area = d3.area<number>()
      .x((d, i) => x(i)!)
      .y0(height - margin.bottom)
      .y1(d => yLeft(d))
      .curve(d3.curveBasis);

    const lineLeft = d3.line<number>()
      .x((d, i) => x(i)!)
      .y(d => yLeft(d))
      .curve(d3.curveBasis);

    const lineRight = (dataArr: number[]) => d3.line<number>()
      .x((d, i) => x(i)!)
      .y(d => yRight(d))
      .curve(d3.curveBasis)(dataArr);

    // Defs & Gradients
    const defs = svg.append("defs");
    const gradient = defs.append("linearGradient")
      .attr("id", "area-gradient")
      .attr("x1", "0%").attr("y1", "0%")
      .attr("x2", "0%").attr("y2", "100%");
    gradient.append("stop").attr("offset", "0%").attr("stop-color", "rgba(105, 246, 184, 0.15)");
    gradient.append("stop").attr("offset", "100%").attr("stop-color", "rgba(105, 246, 184, 0)");

    // Blur filter for glowing lines
    const filter = defs.append("filter").attr("id", "glow");
    filter.append("feGaussianBlur").attr("stdDeviation", "2.5").attr("result", "coloredBlur");
    const feMerge = filter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "coloredBlur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Draw Event Volume Area (Background)
    svg.append("path")
      .datum(snap.data)
      .attr("fill", "url(#area-gradient)")
      .attr("d", area);

    svg.append("path")
      .datum(snap.data)
      .attr("fill", "none")
      .attr("stroke", "rgba(105, 246, 184, 0.3)")
      .attr("stroke-width", 2)
      .attr("d", lineLeft);

    // Draw Alert Lines (Foreground)
    const colors = {
      critical: "#ef4444",
      high: "#f59e0b",
      medium: "#38bdf8",
      low: "#34d399"
    };

    const drawGlowingLine = (dataArr: number[], color: string) => {
      svg.append("path")
        .datum(dataArr)
        .attr("fill", "none")
        .attr("stroke", color)
        .attr("stroke-width", 2.5)
        .attr("filter", "url(#glow)")
        .attr("d", lineRight(dataArr));
    };

    drawGlowingLine(snap.low, colors.low);
    drawGlowingLine(snap.medium, colors.medium);
    drawGlowingLine(snap.high, colors.high);
    drawGlowingLine(snap.critical, colors.critical);

    // Tooltip & Interactive Elements
    let tooltip = d3.select("body").select<HTMLDivElement>(".chart-tooltip");
    if (tooltip.empty()) {
      tooltip = d3.select("body").append("div")
        .attr("class", "chart-tooltip")
        .style("position", "absolute")
        .style("opacity", 0)
        .style("background", "rgba(15, 23, 42, 0.95)")
        .style("backdrop-filter", "blur(8px)")
        .style("color", "#f8fafc")
        .style("padding", "14px 18px")
        .style("border-radius", "10px")
        .style("font-size", "13px")
        .style("pointer-events", "none")
        .style("box-shadow", "0 10px 30px -5px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.08) inset")
        .style("z-index", "9999")
        .style("min-width", "220px");
    }

    const crosshair = svg.append("line")
      .attr("y1", margin.top)
      .attr("y2", height - margin.bottom)
      .attr("stroke", "rgba(255,255,255,0.3)")
      .attr("stroke-width", 1)
      .attr("stroke-dasharray", "4,4")
      .style("opacity", 0);

    // Transparent overlay for hover detection
    svg.append("rect")
      .attr("class", "overlay")
      .attr("width", width)
      .attr("height", height)
      .style("fill", "none")
      .style("pointer-events", "all")
      .on("mousemove", (event) => {
        const [mouseX] = d3.pointer(event);
        
        // Since x is a linear scale mapping [0, length-1] to [margin.left, width-margin.right],
        // we can invert the pixel coordinate directly to get the closest data index!
        const exactIndex = x.invert(mouseX);
        const closestIndex = Math.max(0, Math.min(snap.labels.length - 1, Math.round(exactIndex)));
        
        if (closestIndex >= 0 && closestIndex < snap.labels.length) {
          const currentLabel = snap.labels[closestIndex];
          const cx = x(closestIndex)!;
          
          crosshair
            .attr("x1", cx)
            .attr("x2", cx)
            .style("opacity", 1);
          
          const evVal = snap.data[closestIndex] || 0;
          const cVal = snap.critical[closestIndex] || 0;
          const hVal = snap.high[closestIndex] || 0;
          const mVal = snap.medium[closestIndex] || 0;
          const lVal = snap.low[closestIndex] || 0;

          tooltip.transition().duration(50).style("opacity", 1);
          tooltip.html(`
            <div style="font-family: var(--font-display); font-size: 15px; font-weight: 700; color: #f8fafc; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 8px; margin-bottom: 8px;">${currentLabel}</div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; background: rgba(105, 246, 184, 0.1); padding: 6px 10px; border-radius: 6px; border: 1px solid rgba(105, 246, 184, 0.2);">
              <span style="color: #69f6b8; font-family: var(--font-mono); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em;">Event Vol</span>
              <strong style="color: #ffffff; font-size: 16px;">${evVal.toLocaleString()}</strong>
            </div>
            <div style="display: flex; flex-direction: column; gap: 6px;">
              <div style="display: flex; justify-content: space-between; gap: 24px; align-items: center;">
                <div style="display: flex; align-items: center; gap: 6px;">
                  <span style="width: 8px; height: 8px; border-radius: 50%; background: ${colors.critical}; box-shadow: 0 0 8px ${colors.critical};"></span>
                  <span style="color: #cbd5e1; font-weight: 500;">Critical</span>
                </div>
                <strong style="color: #ffffff;">${cVal.toLocaleString()}</strong>
              </div>
              <div style="display: flex; justify-content: space-between; gap: 24px; align-items: center;">
                <div style="display: flex; align-items: center; gap: 6px;">
                  <span style="width: 8px; height: 8px; border-radius: 50%; background: ${colors.high}; box-shadow: 0 0 8px ${colors.high};"></span>
                  <span style="color: #cbd5e1; font-weight: 500;">High</span>
                </div>
                <strong style="color: #ffffff;">${hVal.toLocaleString()}</strong>
              </div>
              <div style="display: flex; justify-content: space-between; gap: 24px; align-items: center;">
                <div style="display: flex; align-items: center; gap: 6px;">
                  <span style="width: 8px; height: 8px; border-radius: 50%; background: ${colors.medium}; box-shadow: 0 0 8px ${colors.medium};"></span>
                  <span style="color: #cbd5e1; font-weight: 500;">Medium</span>
                </div>
                <strong style="color: #ffffff;">${mVal.toLocaleString()}</strong>
              </div>
              <div style="display: flex; justify-content: space-between; gap: 24px; align-items: center;">
                <div style="display: flex; align-items: center; gap: 6px;">
                  <span style="width: 8px; height: 8px; border-radius: 50%; background: ${colors.low}; box-shadow: 0 0 8px ${colors.low};"></span>
                  <span style="color: #cbd5e1; font-weight: 500;">Low</span>
                </div>
                <strong style="color: #ffffff;">${lVal.toLocaleString()}</strong>
              </div>
            </div>
          `)
            .style("left", (event.pageX + 20) + "px")
            .style("top", (event.pageY - 100) + "px");
        }
      })
      .on("mouseout", () => {
        crosshair.style("opacity", 0);
        tooltip.transition().duration(200).style("opacity", 0);
      });
  }

  private drawSeverityDonutRaw() {
    if (!this.severityDonutChartRef) return;
    const el = this.severityDonutChartRef.nativeElement;
    d3.select(el).selectAll('*').remove();

    const width = el.clientWidth || 300;
    const height = el.clientHeight || 220;
    const radius = Math.min(width, height) / 2 - 10;

    const svg = d3.select(el).append("svg")
      .attr("width", width)
      .attr("height", height)
      .append("g")
      .attr("transform", `translate(${width / 2},${height / 2})`);

    // Gradients for each severity
    const defs = svg.append("defs");

    const gradients = [
      { id: "grad-Critical", colors: ["#ef4444", "#991b1b"] },
      { id: "grad-High", colors: ["#f59e0b", "#b45309"] },
      { id: "grad-Medium", colors: ["#38bdf8", "#0369a1"] },
      { id: "grad-Low", colors: ["#34d399", "#047857"] }
    ];

    gradients.forEach(g => {
      const grad = defs.append("linearGradient")
        .attr("id", g.id)
        .attr("x1", "0%").attr("y1", "0%")
        .attr("x2", "100%").attr("y2", "100%");
      grad.append("stop").attr("offset", "0%").attr("stop-color", g.colors[0]);
      grad.append("stop").attr("offset", "100%").attr("stop-color", g.colors[1]);
    });

    const data = {
      Critical: this.critical(),
      High: this.high(),
      Medium: this.medium(),
      Low: this.low()
    };

    // Use gradients instead of flat colors
    const color = d3.scaleOrdinal<string>()
      .domain(["Critical", "High", "Medium", "Low"])
      .range(["url(#grad-Critical)", "url(#grad-High)", "url(#grad-Medium)", "url(#grad-Low)"]);

    // Flat colors for tooltip borders
    const solidColor = d3.scaleOrdinal<string>()
      .domain(["Critical", "High", "Medium", "Low"])
      .range(["#ef4444", "#f59e0b", "#38bdf8", "#34d399"]);

    const pie = d3.pie<{ key: string, value: number }>()
      .value(d => d.value)
      .sort(null)
      .padAngle(0.04); // Give natural padding

    const data_ready = pie(Object.entries(data).map(([key, value]) => ({ key, value })));

    const arc = d3.arc<d3.PieArcDatum<{ key: string, value: number }>>()
      .innerRadius(radius * 0.65) // thinner donut
      .outerRadius(radius * 0.90)
      .cornerRadius(6); // rounded slices

    const arcHover = d3.arc<d3.PieArcDatum<{ key: string, value: number }>>()
      .innerRadius(radius * 0.60)
      .outerRadius(radius * 1.0)
      .cornerRadius(6);

    let tooltip = d3.select("body").select<HTMLDivElement>(".chart-tooltip");

    const paths = svg.selectAll('path')
      .data(data_ready)
      .enter()
      .append('path')
      .attr('d', arc)
      .attr('fill', d => color(d.data.key))
      .attr("stroke", "rgba(255, 255, 255, 0.05)")
      .style("stroke-width", "1px")
      .style("cursor", "pointer");

    paths.on("mouseover", function (event, d) {
      d3.select(this).transition().duration(250).ease(d3.easeCubicOut).attr("d", arcHover as any);
      tooltip.transition().duration(200).style("opacity", .95);
      tooltip.html(`
          <div style="font-family: var(--font-display); font-size: 14px; font-weight: 700; margin-bottom: 2px;">${d.data.key}</div>
          <div style="font-family: var(--font-mono); color: #cbd5e1;">Count: ${d.data.value}</div>
        `)
        .style("left", (event.pageX + 15) + "px")
        .style("top", (event.pageY - 35) + "px")
        .style("border-left", `4px solid ${solidColor(d.data.key)}`);
    })
      .on("mouseout", function (event, d) {
        d3.select(this).transition().duration(300).ease(d3.easeCubicOut).attr("d", arc as any);
        tooltip.transition().duration(500).style("opacity", 0);
      });

    // Center text background
    svg.append("circle")
      .attr("r", radius * 0.5)
      .attr("fill", "rgba(105, 246, 184, 0.03)");

    svg.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", "-0.1em")
      .style("fill", "#ffffff")
      .style("font-size", "28px")
      .style("font-family", "var(--font-display)")
      .style("font-weight", "800")
      .style("text-shadow", "0px 2px 10px rgba(255,255,255,0.3)")
      .text(this.critical() + this.high() + this.medium() + this.low());

    svg.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", "1.6em")
      .style("fill", "#64748b")
      .style("font-size", "10px")
      .style("text-transform", "uppercase")
      .style("letter-spacing", "0.15em")
      .text("Alerts");
  }

  private drawProtocolPieRaw() {
    const protoData = this.protocols();
    const chartEl = this.protocolPieChartRef();
    if (!chartEl || !protoData.length) return;
    const el = chartEl.nativeElement;
    d3.select(el).selectAll('*').remove();

    const width = el.clientWidth || 300;
    const height = el.clientHeight || 220;
    const radius = Math.min(width, height) / 2 - 10;

    const svg = d3.select(el).append("svg")
      .attr("width", width)
      .attr("height", height)
      .append("g")
      .attr("transform", `translate(${width / 2},${height / 2})`);

    // Bold, intense solid colors
    const colorRange = ["#ef4444", "#3b82f6", "#22c55e", "#eab308", "#f97316", "#a855f7"];
    const color = d3.scaleOrdinal<string>()
      .domain(protoData.map(d => d.proto))
      .range(colorRange);

    const pie = d3.pie<any>()
      .value(d => d.count)
      .sort(null)
      .padAngle(0.05);

    const data_ready = pie(protoData);

    const arc = d3.arc<d3.PieArcDatum<any>>()
      .innerRadius(radius * 0.4)
      .outerRadius(radius * 0.9)
      .cornerRadius(6);

    const arcHover = d3.arc<d3.PieArcDatum<any>>()
      .innerRadius(radius * 0.35)
      .outerRadius(radius * 1.0)
      .cornerRadius(6);

    let tooltip = d3.select("body").select<HTMLDivElement>(".chart-tooltip");
    if (tooltip.empty()) {
      tooltip = d3.select("body").append("div")
        .attr("class", "chart-tooltip")
        .style("position", "absolute")
        .style("opacity", 0)
        .style("background", "#1e293b")
        .style("color", "#f8fafc")
        .style("padding", "8px 12px")
        .style("border-radius", "6px")
        .style("pointer-events", "none")
        .style("font-size", "12px")
        .style("box-shadow", "0 4px 6px -1px rgba(0, 0, 0, 0.1)")
        .style("z-index", "1000")
        .style("border", "1px solid #334155");
    }

    const paths = svg.selectAll('path')
      .data(data_ready)
      .enter()
      .append('path')
      .attr('d', arc)
      .attr('fill', d => color(d.data.proto))
      .attr("stroke", "#1e293b")
      .style("stroke-width", "2px")
      .style("cursor", "pointer");

    paths.on("mouseover", function (event, d) {
      d3.select(this).transition().duration(250).ease(d3.easeCubicOut).attr("d", arcHover as any);
      tooltip.transition().duration(200).style("opacity", .95);
      tooltip.html(`
          <div style="font-family: var(--font-display); font-size: 14px; font-weight: 700; margin-bottom: 2px;">${d.data.proto.toUpperCase()}</div>
          <div style="font-family: var(--font-mono); color: #cbd5e1;">Traffic: ${d.data.count.toLocaleString()}</div>
        `)
        .style("left", (event.pageX + 15) + "px")
        .style("top", (event.pageY - 35) + "px")
        .style("border-left", `4px solid ${color(d.data.proto)}`);
    })
      .on("mouseout", function (event, d) {
        d3.select(this).transition().duration(300).ease(d3.easeCubicOut).attr("d", arc as any);
        tooltip.transition().duration(500).style("opacity", 0);
      });
  }

  private drawTopDstIpsChartRaw() {
    const topIps = this.topDstIps();
    if (!this.topDstIpsChartRef || !topIps.length) return;
    const el = this.topDstIpsChartRef.nativeElement;
    d3.select(el).selectAll('*').remove();

    const width = el.clientWidth || 300;
    const height = el.clientHeight || 220;
    const margin = { top: 10, right: 20, bottom: 20, left: 100 };

    const svg = d3.select(el).append("svg")
      .attr("width", width)
      .attr("height", height)
      .append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    const ips = topIps.slice(0, 5);

    const x = d3.scaleLinear()
      .domain([0, d3.max(ips, d => d.count) || 0])
      .range([0, width - margin.left - margin.right]);

    const y = d3.scaleBand()
      .domain(ips.map(d => d.ip))
      .range([0, height - margin.top - margin.bottom])
      .padding(0.4);

    const defs = svg.append("defs");

    // Add glowing gradient for bars
    const barGrad = defs.append("linearGradient")
      .attr("id", "bar-gradient")
      .attr("x1", "0%").attr("y1", "0%")
      .attr("x2", "100%").attr("y2", "0%");
    barGrad.append("stop").attr("offset", "0%").attr("stop-color", "rgba(56, 189, 248, 0.2)");
    barGrad.append("stop").attr("offset", "100%").attr("stop-color", "#38bdf8");

    const barGradHover = defs.append("linearGradient")
      .attr("id", "bar-gradient-hover")
      .attr("x1", "0%").attr("y1", "0%")
      .attr("x2", "100%").attr("y2", "0%");
    barGradHover.append("stop").attr("offset", "0%").attr("stop-color", "rgba(105, 246, 184, 0.3)");
    barGradHover.append("stop").attr("offset", "100%").attr("stop-color", "#69f6b8");

    // Y Axis without a line, just glowing text
    svg.append("g")
      .call(d3.axisLeft(y).tickSize(0))
      .call(g => g.select(".domain").remove())
      .call(g => g.selectAll("text")
        .attr("fill", "#94a3b8")
        .style("font-family", "var(--font-mono)")
        .style("font-size", "11px")
        .style("font-weight", "500"));

    let tooltip = d3.select("body").select<HTMLDivElement>(".chart-tooltip");

    // Track Backgrounds
    svg.selectAll(".bg-rect")
      .data(ips)
      .enter()
      .append("rect")
      .attr("class", "bg-rect")
      .attr("y", d => y(d.ip)!)
      .attr("height", y.bandwidth())
      .attr("x", 0)
      .attr("width", width - margin.left - margin.right)
      .attr("fill", "rgba(255,255,255,0.03)")
      .attr("rx", 4);

    // Glowing Foreground Bars
    svg.selectAll(".fg-rect")
      .data(ips)
      .enter()
      .append("rect")
      .attr("class", "fg-rect")
      .attr("y", d => y(d.ip)!)
      .attr("height", y.bandwidth())
      .attr("x", 0)
      .attr("width", 0) // start at 0 for animation
      .attr("fill", "url(#bar-gradient)")
      .attr("rx", 4)
      .style("cursor", "pointer")
      .on("mouseover", function (event, d) {
        d3.select(this).attr("fill", "url(#bar-gradient-hover)");
        tooltip.transition().duration(200).style("opacity", .95);
        tooltip.html(`
          <div style="font-family: var(--font-display); font-size: 14px; font-weight: 700; margin-bottom: 2px;">${d.ip}</div>
          <div style="font-family: var(--font-mono); color: #cbd5e1;">Traffic Volume: ${d.count.toLocaleString()}</div>
        `)
          .style("left", (event.pageX + 15) + "px")
          .style("top", (event.pageY - 35) + "px")
          .style("border-left", "4px solid #69f6b8");
      })
      .on("mouseout", function () {
        d3.select(this).attr("fill", "url(#bar-gradient)");
        tooltip.transition().duration(500).style("opacity", 0);
      })
      .transition()
      .duration(1000)
      .ease(d3.easeCubicOut)
      .attr("width", d => x(d.count));

    // Text Labels on Bars
    svg.selectAll(".fg-label")
      .data(ips)
      .enter()
      .append("text")
      .attr("class", "fg-label")
      .attr("y", d => y(d.ip)! + y.bandwidth() / 2)
      .attr("x", 0)
      .attr("dy", "0.35em")
      .style("fill", "#ffffff")
      .style("font-family", "var(--font-mono)")
      .style("font-size", "10px")
      .style("font-weight", "600")
      .style("pointer-events", "none")
      .style("opacity", 0)
      .text(d => d.count.toLocaleString())
      .transition()
      .delay(400)
      .duration(600)
      .attr("x", d => Math.max(10, x(d.count) - 5))
      .attr("text-anchor", "end")
      .style("opacity", 1);
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
    d3.select("body").selectAll(".chart-tooltip").remove();
  }
}
