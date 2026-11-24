import { Component, OnInit, ChangeDetectorRef, HostListener } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { LucideAngularModule, RotateCcw, Play, RefreshCw, ChevronDown, ChevronRight, Search, X } from 'lucide-angular';

interface RetroScan {
  id:           string;
  rule_id:      string;
  rule_name:    string;
  rule_content: string;
  hours_back:   number;
  status:       'pending' | 'running' | 'done' | 'failed';
  started_at:   string;
  completed_at: string | null;
  match_count:  number;
  matches?:     any[];
}

@Component({
  selector: 'app-retrospective',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './retrospective.html',
  styleUrl: './retrospective.scss',
})
export class Retrospective implements OnInit {
  RetroIcon    = RotateCcw;
  PlayIcon     = Play;
  RefreshIcon  = RefreshCw;
  ChevronDown  = ChevronDown;
  ChevronRight = ChevronRight;
  SearchIcon   = Search;
  XIcon        = X;

  // Scan list
  scans: RetroScan[]     = [];
  selectedScan: RetroScan | null = null;
  selectedMatches: any[] = [];
  loading   = false;
  scanning  = false;
  error     = '';
  success   = '';

  // Rule picker — two sources merged
  firedRules: any[] = [];  // from ndr_hits.sigma_hits (Agent-S + fired Sigma UUIDs)
  sigmaRules: any[] = [];  // all Sigma rules from sigma_rules table (Agent-Z)
  rulesLoading      = false;
  ruleQuery         = '';
  showDropdown      = false;
  selectedRuleId    = '';
  selectedRuleName  = '';

  // Keyword fallback
  ruleContent = '';
  hoursBack   = 24;
  hoursOptions = [24, 48, 72, 168];

  constructor(private api: Api, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.loadScans();
    this.loadRules();
  }

  // ── Rule picker ───────────────────────────────────────────────

  loadRules(): void {
    this.rulesLoading = true;
    let done = 0;
    const finish = () => { if (++done === 2) { this.rulesLoading = false; this.cdr.markForCheck(); } };

    // Source 1: rules that have actual history in ndr_hits
    this.api.getFiredRules().subscribe({
      next: (r: any) => {
        this.firedRules = (r.rules ?? []).filter((x: any) => x.name);
        finish();
      },
      error: () => finish(),
    });

    // Source 2: full Sigma rule library (Agent-Z), even rules with 0 hits
    this.api.getRules().subscribe({
      next: (data: any[]) => {
        this.sigmaRules = (data ?? []).map((r: any) => ({
          name: r.title || r.name || r.id,
          id:   r.id,
          hit_count: 0,
          engine: 'Agent-Z',
        }));
        finish();
      },
      error: () => finish(),
    });
  }

  get filteredFired(): any[] {
    if (!this.ruleQuery.trim()) return this.firedRules;
    const q = this.ruleQuery.toLowerCase();
    return this.firedRules.filter(r => (r.name || '').toLowerCase().includes(q));
  }

  get filteredSigma(): any[] {
    if (!this.ruleQuery.trim()) return this.sigmaRules.slice(0, 40);
    const q = this.ruleQuery.toLowerCase();
    return this.sigmaRules.filter(r => (r.name || '').toLowerCase().includes(q)).slice(0, 40);
  }

  openDropdown(): void { this.showDropdown = true; }

  selectRule(rule: any): void {
    // Agent-Z Sigma rules: use UUID (that's what sigma_hits stores when they fire)
    // Agent-S rules: use full alert name string (that's what sigma_hits stores)
    this.selectedRuleId   = rule.id ?? rule.name;
    this.selectedRuleName = rule.name;
    this.ruleQuery        = '';
    this.showDropdown     = false;
    this.error            = '';
    this.cdr.markForCheck();
  }

  // UUID pattern = Agent-Z (Sigma), anything else = Agent-S
  private UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  ruleEngine(name: string): 'Agent-S' | 'Agent-Z' {
    return this.UUID_RE.test(name) ? 'Agent-Z' : 'Agent-S';
  }

  clearRule(): void {
    this.selectedRuleId   = '';
    this.selectedRuleName = '';
    this.ruleQuery        = '';
    this.showDropdown     = false;
    this.cdr.markForCheck();
  }

  @HostListener('document:click', ['$event'])
  onDocClick(e: MouseEvent): void {
    const target = e.target as HTMLElement;
    if (!target.closest('.retro-picker-wrap')) {
      this.showDropdown = false;
      this.cdr.markForCheck();
    }
  }

  // ── Scan actions ───────────────────────────────────────────────

  startScan(): void {
    if (!this.selectedRuleId && !this.ruleContent.trim()) {
      this.error = 'Select a rule from the list, or enter a keyword to search';
      return;
    }
    this.scanning = true;
    this.error    = '';
    this.api.startRetroScan(
      this.selectedRuleId,
      this.selectedRuleName,
      this.ruleContent,
      this.hoursBack
    ).subscribe({
      next: (r: any) => {
        this.scanning = false;
        this.success  = `Scan started — results will appear below`;
        setTimeout(() => { this.loadScans(); }, 2000);
        setTimeout(() => { this.success = ''; this.cdr.markForCheck(); }, 5000);
        this.cdr.markForCheck();
      },
      error: (e: any) => {
        this.error    = e?.error?.message ?? 'Failed to start scan';
        this.scanning = false;
        this.cdr.markForCheck();
      },
    });
  }

  loadScans(): void {
    this.loading = true;
    this.api.listRetroScans().subscribe({
      next: (r: any) => {
        const fresh: RetroScan[] = (r.scans ?? []).sort((a: RetroScan, b: RetroScan) =>
          new Date(b.started_at).getTime() - new Date(a.started_at).getTime());

        // Carry cached matches forward so re-open after Refresh doesn't flash empty
        for (const s of fresh) {
          const prev = this.scans.find(p => p.id === s.id);
          if (prev?.matches !== undefined) s.matches = prev.matches;
        }

        this.scans = fresh;

        // Keep selectedScan pointing at the new object for the same ID
        if (this.selectedScan) {
          const updated = fresh.find(s => s.id === this.selectedScan!.id);
          this.selectedScan = updated ?? null;
          if (!this.selectedScan) {
            this.selectedMatches = [];
          } else if (updated!.matches !== undefined) {
            this.selectedMatches = updated!.matches;
          }
        }

        this.loading = false;
        this.cdr.markForCheck();
      },
      error: (e: any) => {
        this.error   = e?.error?.message ?? 'Failed to load scans';
        this.loading = false;
        this.cdr.markForCheck();
      },
    });
  }

  viewScan(scan: RetroScan): void {
    // Toggle: clicking the open card collapses it
    if (this.selectedScan?.id === scan.id) {
      this.selectedScan = null;
      return;
    }
    this.selectedScan = scan;

    if (scan.status !== 'done') return;

    // Use cached matches — no second API call on re-open
    if (scan.matches !== undefined) {
      this.selectedMatches = scan.matches ?? [];
      return;
    }

    // First open: fetch and cache on the scan object
    this.selectedMatches = [];
    this.api.getRetroScan(scan.id).subscribe({
      next: (r: any) => {
        scan.matches         = r.scan?.matches ?? [];
        this.selectedMatches = scan.matches ?? [];
        this.cdr.markForCheck();
      },
      error: () => {
        scan.matches         = [];
        this.selectedMatches = [];
      },
    });
  }

  scanLabel(scan: RetroScan): string {
    if (scan.rule_name) return scan.rule_name;
    if (scan.rule_content) return `"${scan.rule_content}"`;
    return scan.rule_id || '—';
  }
}
