import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef, ViewEncapsulation } from '@angular/core';
import { CommonModule, DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
import { RulesBase } from '../../shared/rules/rules-base';
import {
  LucideAngularModule,
  Search, ChevronDown,
} from 'lucide-angular';

@Component({
  selector: 'app-admin-rules',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, DecimalPipe, LucideAngularModule, FormsModule],
  templateUrl: './rules.html',
  styleUrl: './rules.css',
})
export class AdminRules extends RulesBase implements OnInit {
  // Server-side paging (same approach as the analyst Rules page): `rules` only
  // ever holds the pages fetched so far for the current search. It used to
  // download all 1,200+ rules (~460 KB) on every visit, and "Load more" just
  // revealed more of what was already in the browser.
  rules: any[]         = [];
  readonly pageSize    = 20;
  rulesTotal           = 0;   // matches for the current search (X-Total-Count)
  rulesActiveTotal     = 0;
  allRulesTotal        = 0;   // whole rule set, only updated when not searching
  allRulesActive       = 0;
  loadingMore          = false;
  loadError            = false;
  isSearching          = false;
  searchQuery          = '';
  private requestSeq   = 0;
  private hitCounts: { [k: string]: number } = {};

  get filteredRules()   { return this.rules; }
  get displayedRules()  { return this.rules; }
  get hasMore()         { return this.rules.length < this.rulesTotal; }
  get shownCount()      { return this.rules.length; }
  get remainingCount()  { return Math.max(this.rulesTotal - this.rules.length, 0); }
  get totalRuleCount()  { return this.allRulesTotal; }

  templates = [
    { label: 'Agent-S Alert',   field: 'event_type',    value: 'alert',      matcher: 'equals',     title: 'Agent-S Alert Detected',  severity: 'high',     description: 'Detects any Agent-S alert' },
    { label: 'Port Scan',       field: 'conn_state',    value: 'S0',         matcher: 'equals',     title: 'Port Scan Detection',     severity: 'medium',   description: 'Detects port scans via unanswered connections' },
    { label: 'HTTP Monitor',    field: 'event_type',    value: 'http',       matcher: 'equals',     title: 'HTTP Traffic Monitor',    severity: 'low',      description: 'Monitors HTTP traffic' },
    { label: 'Critical Alert',  field: 'alert.severity',value: '1',          matcher: 'equals',     title: 'Critical Agent-S Alert',  severity: 'critical', description: 'Detects highest severity Agent-S alerts' },
    { label: 'Exec from /tmp',  field: 'Image',         value: '/tmp/',      matcher: 'startswith', title: 'Execution from /tmp',     severity: 'high',     description: 'Detects process execution from /tmp' },
    { label: 'Reverse Shell',   field: 'CommandLine',   value: 'nc -e',      matcher: 'contains',   title: 'Netcat Reverse Shell',    severity: 'critical', description: 'Detects netcat reverse shell' },
    { label: 'Cron Persistence',field: 'TargetFilename',value: '/etc/cron',  matcher: 'startswith', title: 'Cron Persistence Attempt',severity: 'high',     description: 'Detects writes to cron directories' },
    { label: 'Root Execution',  field: 'User',          value: 'root',       matcher: 'equals',     title: 'Root Process Execution',  severity: 'medium',   description: 'Detects any process executed as root' },
  ];

  SearchIcon  = Search;
  ChevronIcon = ChevronDown;

  constructor(api: Api, cdr: ChangeDetectorRef) {
    super(api, cdr);
  }

  get activeRulesCount() { return this.allRulesActive; }

  ngOnInit() { this.loadRules(); }

  private mapRule(r: any) {
    return {
      name:        r.title || 'Unknown',
      type:        'SIGMA',
      severity:    (r.severity || 'medium').toUpperCase(),
      status:      r.enabled ? 'ACTIVE' : 'INACTIVE',
      id:          r.id,
      description: r.description || '',
      tags:        r.tags || [],
      conditions:  r.conditions || 0,
      hits:        this.hitCounts[r.title || 'Unknown'] || 0,
    };
  }

  loadRules() {
    this.rules = [];
    this.rulesTotal = 0;
    this.searchQuery = '';
    this.fetchPage(false);

    // Hit counts are one cheap aggregate over all rules (not paged) - fetch
    // once and apply to every page as it arrives.
    this.api.getRuleHitCounts().subscribe({
      next: (hitCounts: { [k: string]: number }) => {
        this.hitCounts = hitCounts;
        this.totalHits = Object.values(hitCounts).reduce((a, b) => a + b, 0);
        this.rules = this.rules.map(r => ({ ...r, hits: hitCounts[r.name] || 0 }));
        this.cdr.detectChanges();
      },
      error: reportRxjsError,
    });
  }

  /** Fetches one page from the server: the first page (replacing the list) or
   *  the next one (appending). The current search text is sent to the server
   *  as well, so paging and searching cover the whole rule set. */
  private fetchPage(append: boolean) {
    const q = this.searchQuery.trim();
    if (append)      this.loadingMore = true;
    else if (q)      this.isSearching = true;
    else             this.loading = true;
    this.loadError = false;

    // A newer request (fast typing, another click) makes older answers stale.
    const seq = ++this.requestSeq;
    const offset = append ? this.rules.length : 0;

    this.api.getRulesPage(this.pageSize, offset, q || undefined, 'desc').subscribe({
      next: res => {
        if (seq !== this.requestSeq) return;
        const mapped = res.rules.map((r: any) => this.mapRule(r));
        if (append) {
          // A rule deleted since the last page shifts the offset by one;
          // de-duplicate so it can't show twice.
          const seen = new Set(this.rules.map(r => r.id));
          this.rules = [...this.rules, ...mapped.filter((r: any) => !seen.has(r.id))];
        } else {
          this.rules = mapped;
        }
        this.rulesTotal = res.total;
        this.rulesActiveTotal = res.activeTotal;
        if (!q) {
          this.allRulesTotal = res.total;
          this.allRulesActive = res.activeTotal;
        }
        this.loading = this.isSearching = this.loadingMore = false;
        this.cdr.detectChanges();
      },
      error: err => {
        if (seq !== this.requestSeq) return;
        this.loading = this.isSearching = this.loadingMore = false;
        this.loadError = true;
        this.cdr.detectChanges();
        reportRxjsError(err);
      },
    });
  }

  private searchDebounce: any;

  onSearch() {
    clearTimeout(this.searchDebounce);
    if (!this.searchQuery.trim()) {
      this.fetchPage(false);
      return;
    }
    // Debounced so a fast typist doesn't fire one request per keystroke.
    this.isSearching = true;
    this.cdr.detectChanges();
    this.searchDebounce = setTimeout(() => this.fetchPage(false), 350);
  }

  loadMore() {
    if (this.loadingMore || !this.hasMore) return;
    this.fetchPage(true);
  }

  retryLoad() {
    if (this.searchQuery.trim()) this.fetchPage(false);
    else this.loadRules();
  }

  applyTemplate(t: any) {
    this.ruleForm = { ...this.ruleForm, field: t.field, value: t.value,
      matcher: t.matcher, title: t.title, severity: t.severity, description: t.description };
  }

  getSeverityClass(sev: string) {
    const map: Record<string, string> = {
      CRITICAL: 'sev-critical', HIGH: 'sev-high', MEDIUM: 'sev-medium', LOW: 'sev-low',
    };
    return map[sev?.toUpperCase()] || 'sev-low';
  }

  getTagClass(tag: string): string {
    const t = (tag || '').toLowerCase();
    if (t.includes('exfiltration') || t.includes('initial'))      return 'tag--amber';
    if (t.includes('command') || t.includes('c2') || t.includes('impact')) return 'tag--red';
    if (t.includes('privilege') || t.includes('escalation'))      return 'tag--violet';
    if (t.includes('lateral') || t.includes('movement'))          return 'tag--blue';
    if (t.includes('persist'))                                     return 'tag--orange';
    if (t.includes('discover'))                                    return 'tag--cyan';
    if (t.includes('stealth') || t.includes('evasion') || t.includes('defense')) return 'tag--indigo';
    if (t.includes('recon'))                                       return 'tag--teal';
    if (t.includes('execut') || t.includes('collection'))         return 'tag--green';
    return 'tag--blue';
  }
}
