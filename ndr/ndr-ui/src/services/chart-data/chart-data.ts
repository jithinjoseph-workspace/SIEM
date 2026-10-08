import { Injectable, OnDestroy } from '@angular/core';
import { Api } from '../api/api';
import { Observable, BehaviorSubject, Subscription, forkJoin } from 'rxjs';
import { filter, map, distinctUntilChanged } from 'rxjs/operators';

// ── Public interfaces ─────────────────────────────────────────────────────────

export interface ChartSnapshot {
  labels: string[];
  data:   number[];
  critical: number[];
  high: number[];
  medium: number[];
  low: number[];
}

export interface StatsSnapshot {
  events_total:    number;
  hits_total:      number;
  events_1h:       number;
  hits_1h:         number;
  agent_z_events:     number;
  agent_s_events: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const CACHE_TTL_MS = 20 * 60 * 1000;   // 20 minutes
const MAX_POINTS   = 20;                // sliding window size
const REFRESH_MS   = 30_000;           // poll interval

// ── Service ───────────────────────────────────────────────────────────────────

@Injectable({ providedIn: 'root' })
export class ChartDataService implements OnDestroy {

  // ── Internal mutable state ─────────────────────────────────────────────────
  private labels: string[] = [];
  private data:   number[] = [];
  private critical: number[] = [];
  private high: number[] = [];
  private medium: number[] = [];
  private low: number[] = [];
  private started = false;
  private refreshInterval: any  = null;
  private statsSub: Subscription | null = null;
  private lastEventsTotal: number | null = null;
  private lastCriticalTotal: number | null = null;
  private lastHighTotal: number | null = null;
  private lastMediumTotal: number | null = null;
  private lastLowTotal: number | null = null;

  // ── State atoms ────────────────────────────────────────────────────────────

  /**
   * Chart snapshot atom.
   *  null  = no data yet (cold start, cache empty/stale)
   *  value = ready (from cache OR fresh API response)
   *
   * Initialised synchronously from localStorage — warm starts get data
   * before the first Angular change-detection cycle (zero flat-line delay).
   */
  private readonly _chart$ = new BehaviorSubject<ChartSnapshot | null>(
    this.loadFromCache()
  );

  /**
   * Full /api/stats payload, shared with the dashboard stat cards.
   * Eliminates the duplicate /api/stats call that previously ran in
   * both this service and Dashboard.loadAllStats().
   */
  private readonly _stats$ = new BehaviorSubject<StatsSnapshot | null>(null);

  /** True only when API failed and there is no cached chart data to show. */
  private readonly _hasError$ = new BehaviorSubject<boolean>(false);

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Emits a valid chart snapshot the instant data is available.
   * On warm starts fires synchronously inside ngOnInit — chart renders on
   * the very first paint with no skeleton visible.
   */
  public readonly chart$: Observable<ChartSnapshot> = this._chart$.pipe(
    filter((s): s is ChartSnapshot => s !== null),
    distinctUntilChanged((a, b) =>
      a.data.length === b.data.length &&
      a.data[a.data.length - 1] === b.data[b.data.length - 1]
    )
  );

  /**
   * Full stats payload for the dashboard stat cards.
   * Updated every 30 s from the same fetch that drives the chart —
   * no duplicate /api/stats calls.
   */
  public readonly stats$: Observable<StatsSnapshot> = this._stats$.pipe(
    filter((s): s is StatsSnapshot => s !== null),
    distinctUntilChanged((a, b) =>
      a.events_total === b.events_total &&
      a.hits_total   === b.hits_total   &&
      a.events_1h    === b.events_1h
    )
  );

  /** True only during a genuine cold start (no cache, API not yet responded). */
  public readonly isLoading$: Observable<boolean> = this._chart$.pipe(
    map(s => s === null),
    distinctUntilChanged()
  );

  /** True when the API call failed AND no cached snapshot is available. */
  public readonly hasError$: Observable<boolean> = this._hasError$.pipe(
    distinctUntilChanged()
  );

  constructor(private api: Api) {}

  private getStorageKey(): string {
    try {
      const u = localStorage.getItem('ndr_user');
      if (u) {
        const user = JSON.parse(u);
        if (user.username) return `ndr_chart_data_${user.username}`;
      }
    } catch (_) {}
    return 'ndr_chart_data_v2';
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  /** Start data accumulation. Idempotent — safe to call multiple times. */
  start(): void {
    if (this.started) return;
    this.started = true;
    this.fetchAndPush();
    this.refreshInterval = setInterval(() => this.fetchAndPush(), REFRESH_MS);
  }

  /** Manually retry after an error (triggered by the Retry button in the UI). */
  retry(): void {
    this._hasError$.next(false);
    this.fetchAndPush();
  }

  ngOnDestroy(): void {
    if (this.refreshInterval) clearInterval(this.refreshInterval);
    this.statsSub?.unsubscribe();
    this._chart$.complete();
    this._stats$.complete();
    this._hasError$.complete();
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Single /api/stats fetch that drives BOTH the chart and the stat cards.
   * Called immediately on start() and then every REFRESH_MS.
   */
  private fetchAndPush(): void {
    this.statsSub?.unsubscribe();
    this.statsSub = forkJoin({
      stats: this.api.getStats(),
      severity: this.api.getSeverity()
    }).subscribe({
      next: ({ stats: raw, severity: sevRaw }) => {
        this._hasError$.next(false);

        // 1. Push full stats payload for the dashboard stat cards
        this._stats$.next({
          events_total:    raw.events_total    || 0,
          hits_total:      raw.hits_total      || 0,
          events_1h:       raw.events_1h       || 0,
          hits_1h:         raw.hits_1h         || 0,
          agent_z_events:     raw.agent_z_events     || 0,
          agent_s_events: raw.agent_s_events || 0,
        });

        // 2. Append a chart data point (events in this interval)
        const currentTotal = raw.events_total || 0;
        let delta = 0;
        const wasNull = this.lastEventsTotal === null;
        if (!wasNull) {
          delta = Math.max(0, currentTotal - this.lastEventsTotal!);
        }
        this.lastEventsTotal = currentTotal;

        // Freeze chart if no new events arrived (sensors stopped), unless it's the very first point
        if (!wasNull && delta === 0) {
          return;
        }

        // 3. Severities absolute
        const curCrit = sevRaw.critical || 0;
        const curHigh = sevRaw.high || 0;
        const curMed = sevRaw.medium || 0;
        const curLow = sevRaw.low || 0;
        
        this.lastCriticalTotal = curCrit;
        this.lastHighTotal = curHigh;
        this.lastMediumTotal = curMed;
        this.lastLowTotal = curLow;

        this.pushPoint(delta, curCrit, curHigh, curMed, curLow);
      },
      error: () => {
        // Surface error UI only when there is no cached data to fall back on.
        if (this._chart$.getValue() === null) {
          this._hasError$.next(true);
        }
      }
    });
  }

  private pushPoint(value: number, crit: number, high: number, med: number, low: number): void {
    const now = new Date().toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit'
    });
    if (this.labels.length >= MAX_POINTS) {
      this.labels.shift();
      this.data.shift();
      this.critical.shift();
      this.high.shift();
      this.medium.shift();
      this.low.shift();
    }
    this.labels.push(now);
    this.data.push(value);
    this.critical.push(crit);
    this.high.push(high);
    this.medium.push(med);
    this.low.push(low);
    
    this.saveToCache();
    // Push to all chart subscribers immediately — no polling needed in components.
    this._chart$.next({ 
      labels: [...this.labels], 
      data: [...this.data],
      critical: [...this.critical],
      high: [...this.high],
      medium: [...this.medium],
      low: [...this.low]
    });
  }

  private saveToCache(): void {
    try {
      localStorage.setItem(this.getStorageKey(), JSON.stringify({
        labels:    this.labels,
        data:      this.data,
        critical:  this.critical,
        high:      this.high,
        medium:    this.medium,
        low:       this.low,
        lastEventsTotal: this.lastEventsTotal,
        lastCriticalTotal: this.lastCriticalTotal,
        lastHighTotal: this.lastHighTotal,
        lastMediumTotal: this.lastMediumTotal,
        lastLowTotal: this.lastLowTotal,
        timestamp: Date.now()
      }));
    } catch (_) { /* storage full — silently ignore */ }
  }

  /**
   * Restore chart data from localStorage synchronously.
   * Called once during field initialisation so BehaviorSubject starts
   * with real data on warm starts (no spinner, no flat-line delay).
   */
  private loadFromCache(): ChartSnapshot | null {
    try {
      const raw = localStorage.getItem(this.getStorageKey());
      if (!raw) return null;

      const stored = JSON.parse(raw);
      if (Date.now() - (stored.timestamp || 0) > CACHE_TTL_MS) {
        localStorage.removeItem(this.getStorageKey());
        return null;
      }
      if (
        Array.isArray(stored.labels) &&
        Array.isArray(stored.data)   &&
        stored.data.length > 0
      ) {
        this.labels = [...stored.labels];
        this.data   = [...stored.data];
        this.critical = Array.isArray(stored.critical) ? [...stored.critical] : new Array(stored.labels.length).fill(0);
        this.high = Array.isArray(stored.high) ? [...stored.high] : new Array(stored.labels.length).fill(0);
        this.medium = Array.isArray(stored.medium) ? [...stored.medium] : new Array(stored.labels.length).fill(0);
        this.low = Array.isArray(stored.low) ? [...stored.low] : new Array(stored.labels.length).fill(0);
        
        this.lastEventsTotal = typeof stored.lastEventsTotal === 'number' ? stored.lastEventsTotal : null;
        this.lastCriticalTotal = typeof stored.lastCriticalTotal === 'number' ? stored.lastCriticalTotal : null;
        this.lastHighTotal = typeof stored.lastHighTotal === 'number' ? stored.lastHighTotal : null;
        this.lastMediumTotal = typeof stored.lastMediumTotal === 'number' ? stored.lastMediumTotal : null;
        this.lastLowTotal = typeof stored.lastLowTotal === 'number' ? stored.lastLowTotal : null;
        
        return { 
          labels: [...stored.labels], 
          data: [...stored.data],
          critical: [...this.critical],
          high: [...this.high],
          medium: [...this.medium],
          low: [...this.low]
        };
      }
      return null;
    } catch (_) {
      return null;
    }
  }
}
