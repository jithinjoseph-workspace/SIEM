import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { AuthService } from '../../../services/auth/auth';
import { LucideAngularModule, ShieldCheck, Activity, Target } from 'lucide-angular';
import { RulesBase } from '../../shared/rules/rules-base';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-rules',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule],
  templateUrl: './rules.html',
  styleUrl: './rules.css'
})
export class Rules extends RulesBase implements OnInit {
  ShieldCheckIcon = ShieldCheck;
  ActivityIcon = Activity;
  TargetIcon = Target;

  rules: any[] = [];

  categoryFilter: string = '';
  severityFilter: string = '';
  activeTab: 'all' | 'agent-z' | 'agent-s' = 'all';
  agentSRules: any[] = [];

  // ── Pagination (Agent-Z / SIGMA rules — the large set) ─────────────────────
  pageSize = 20;
  rulesOffset = 0;
  rulesTotal = 0;
  rulesActiveTotal = 0;
  loadingMore = false;
  /** First page failed to load - shown instead of "No SIGMA rules loaded" so a failed request is not mistaken for an empty list. */
  loadError = false;
  private hitCountsCache: { [ruleName: string]: number } = {};

  get hasMoreRules(): boolean {
    return this.rules.length < this.rulesTotal;
  }

  // ── Search (checks what's already loaded first; falls back to a DB query
  //    only when nothing loaded matches, so we can say for sure whether a
  //    rule exists at all rather than just "not in the first page") ─────────
  searchTerm = '';
  searching = false;
  dbSearchActive = false;
  dbSearchChecked = false;
  dbSearchResults: any[] = [];
  private searchDebounce: any;

  get topCategories(): { tag: string; label: string; count: number }[] {
    const counts: { [key: string]: number } = {};
    for (const rule of this.rules) {
      for (const tag of (rule.tags || [])) {
        if (/^attack\.t\d+/i.test(tag)) continue;
        if (!tag.startsWith('attack.')) continue;
        counts[tag] = (counts[tag] || 0) + 1;
      }
    }
    return Object.entries(counts)
      .map(([tag, count]) => ({ tag, label: this.catLabel(tag), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 9);
  }

  get severityCounts(): { [key: string]: number } {
    const counts: { [key: string]: number } = {};
    for (const rule of this.rules) {
      const s = (rule.severity || 'MEDIUM').toUpperCase();
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }

  get allRules(): any[] {
    if (this.activeTab === 'agent-z') return this.rules;
    if (this.activeTab === 'agent-s') return this.agentSRules;
    return [...this.rules, ...this.agentSRules];
  }

  get displayRules(): any[] {
    if (this.dbSearchActive) return this.dbSearchResults;
    const term = this.searchTerm.trim().toLowerCase();
    return this.allRules.filter(rule => {
      const catOk = !this.categoryFilter || (rule.tags || []).includes(this.categoryFilter);
      const sevOk = !this.severityFilter || rule.severity.toUpperCase() === this.severityFilter;
      const searchOk = !term
        || (rule.name || '').toLowerCase().includes(term)
        || (rule.tags || []).some((t: string) => t.toLowerCase().includes(term));
      return catOk && sevOk && searchOk;
    });
  }

  setCategory(tag: string) {
    this.categoryFilter = this.categoryFilter === tag ? '' : tag;
  }

  setSeverity(sev: string) {
    this.severityFilter = this.severityFilter === sev ? '' : sev;
  }

  clearFilters() {
    this.categoryFilter = '';
    this.severityFilter = '';
  }

  private catLabel(tag: string): string {
    const name = tag.replace('attack.', '').replace(/-/g, ' ');
    return name.charAt(0).toUpperCase() + name.slice(1);
  }

  constructor(api: Api, private auth: AuthService, cdr: ChangeDetectorRef) {
    super(api, cdr);
  }

  get isAdmin() { return this.auth.isAdmin(); }

  get activeRulesCount() {
    // rulesActiveTotal comes from the backend (X-Active-Count) so this stays
    // correct even though only one page of `rules` is actually loaded.
    return this.rulesActiveTotal + this.agentSRules.filter(r => r.status === 'ACTIVE').length;
  }

  ngOnInit() { this.loadRules(); }

  loadRules() {
    this.rules = [];
    this.rulesOffset = 0;
    this.rulesTotal = 0;
    this.rulesActiveTotal = 0;
    this.dbSearchActive = false;
    this.dbSearchChecked = false;

    this.fetchRulesPage(false);

    // Hit counts are a cheap aggregate over ALL rules (not paginated) —
    // fetch once, cache it, and apply to whichever page(s) get loaded.
    this.api.getRuleHitCounts().subscribe({
      next: (hitCounts: { [ruleName: string]: number }) => {
        this.hitCountsCache = hitCounts;
        this.totalHits = Object.values(hitCounts).reduce((a, b) => a + b, 0)
          + this.agentSRules.reduce((s: number, r: any) => s + r.hits, 0);
        this.rules = this.rules.map(r => ({ ...r, hits: hitCounts[r.name] || 0 }));
        this.cdr.detectChanges();
      },
      error: () => { }
    });

    // Load Agent-S fired rules from ndr_hits.sigma_hits — a small set (single
    // digits typically), so no pagination needed here.
    this.api.getFiredRules().subscribe({
      next: (r: any) => {
        const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        this.agentSRules = (r.rules ?? [])
          .filter((x: any) => x.name && !UUID_RE.test(x.name))  // exclude Sigma UUIDs — those appear in sigma rules
          .map((x: any) => ({
            name: x.name,
            type: 'Agent-S',
            severity: (x.severity || 'HIGH').toUpperCase(),
            status: 'ACTIVE',
            id: x.name,
            description: 'Agent-S detection rule (managed by the sensor)',
            tags: [],
            conditions: 0,
            hits: x.hit_count || 0,
          }));
        this.totalHits = this.totalHits + this.agentSRules.reduce((s: number, r: any) => s + r.hits, 0);
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });
  }

  private mapAgentZRule(r: any): any {
    return {
      name: r.title || 'Unknown',
      type: 'Agent-Z',
      severity: (r.severity || 'medium').toUpperCase(),
      status: r.enabled ? 'ACTIVE' : 'INACTIVE',
      id: r.id,
      description: r.description || '',
      tags: r.tags || [],
      conditions: r.conditions || 0,
      hits: this.hitCountsCache[r.title] || 0,
    };
  }

  private fetchRulesPage(append: boolean) {
    if (append) this.loadingMore = true; else { this.loading = true; this.loadError = false; }
    this.api.getRulesPage(this.pageSize, this.rulesOffset).subscribe({
      next: (res) => {
        const mapped = res.rules.map((r: any) => this.mapAgentZRule(r));
        this.rules = append ? [...this.rules, ...mapped] : mapped;
        this.rulesOffset = this.rules.length;
        this.rulesTotal = res.total;
        this.rulesActiveTotal = res.activeTotal;
        this.loading = false;
        this.loadingMore = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.loadingMore = false;
        if (append) this.showMessage("Couldn't load more rules - try again", 'error');
        else this.loadError = true;
        this.cdr.detectChanges();
      }
    });
  }

  loadMoreRules() {
    if (this.loadingMore || !this.hasMoreRules) return;
    this.fetchRulesPage(true);
  }

  // ── Search: filter what's loaded first; only hit the backend when that
  // comes up empty, so we can tell the analyst whether the rule genuinely
  // doesn't exist or just isn't in the pages fetched so far. ────────────────
  onSearchInput() {
    clearTimeout(this.searchDebounce);
    this.dbSearchActive = false;
    this.dbSearchChecked = false;
    const term = this.searchTerm.trim();
    if (!term) return;
    this.searchDebounce = setTimeout(() => this.runSearch(term), 350);
  }

  private runSearch(term: string) {
    const lower = term.toLowerCase();
    const localMatch = this.allRules.some(r =>
      (r.name || '').toLowerCase().includes(lower) ||
      (r.tags || []).some((t: string) => t.toLowerCase().includes(lower))
    );
    if (localMatch) return; // already covered by displayRules' client-side filter

    this.searching = true;
    this.api.searchRules(term).subscribe({
      next: (res: any[]) => {
        this.searching = false;
        this.dbSearchChecked = true;
        this.dbSearchResults = (res || []).map(r => this.mapAgentZRule(r));
        this.dbSearchActive = true;
        this.cdr.detectChanges();
      },
      error: () => {
        this.searching = false;
        this.dbSearchChecked = true;
        this.dbSearchResults = [];
        this.dbSearchActive = true;
        this.cdr.detectChanges();
      }
    });
  }

  clearSearch() {
    this.searchTerm = '';
    this.dbSearchActive = false;
    this.dbSearchChecked = false;
    this.dbSearchResults = [];
  }

  getSeverityClass(severity: string): string {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'yaml-sev yaml-sev-critical';
      case 'high':     return 'yaml-sev yaml-sev-high';
      case 'medium':   return 'yaml-sev yaml-sev-medium';
      default:         return 'yaml-sev yaml-sev-low';
    }
  }

  getSeverityBadgeClass(severity: string): string {
    return 'sev-badge sev-' + (severity || 'low').toLowerCase();
  }

  sanitizeRuleName(name: string): string {
    return (name || '')
      .replace(/\bSURICATA\b/gi, 'Agent-S')
      .replace(/\bZEEK\b/gi, 'Agent-Z');
  }
}
