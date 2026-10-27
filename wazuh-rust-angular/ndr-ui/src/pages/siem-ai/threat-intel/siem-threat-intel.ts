import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { LucideAngularModule, Globe, Search, RefreshCw } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

/**
 * SIEM Threat Intel: the provigil-common feeds (abuse.ch, Spamhaus, Emerging
 * Threats, CISA KEV...), an IOC lookup, and the attacker IPs in this tenant's
 * alerts that the feeds list (siem-api /api/v1/siem/intel/*).
 */
@Component({
  selector: 'app-siem-threat-intel',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, LucideAngularModule],
  templateUrl: './siem-threat-intel.html',
})
export class SiemThreatIntel implements OnInit {
  private siem = inject(SiemService);
  GlobeIcon = Globe;
  SearchIcon = Search;
  RefreshIcon = RefreshCw;

  status = signal<any>(null);
  matches = signal<any[]>([]);
  result = signal<any>(null);
  loading = signal(false);
  error = signal<string | null>(null);
  q = '';
  /** The tenant's own indicators: they count as threat intel in its alerts, SOAR and decisions. */
  watchlist = signal<any[]>([]);
  watchError = signal<string | null>(null);
  newValue = '';
  newGroup = '';

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getIntelStatus().subscribe({ next: s => this.status.set(s), error: () => this.error.set('Threat intel is not available.') });
    this.siem.getIntelMatches().subscribe({
      next: r => { this.loading.set(false); this.matches.set(r.matches ?? []); },
      error: e => { this.loading.set(false); this.error.set(e?.status === 403 ? 'You do not have access to SIEM alerts.' : 'Threat intel is not available.'); },
    });
    this.siem.getWatchlist().subscribe({ next: r => this.watchlist.set(r.watchlist ?? []), error: () => {} });
  }

  addWatched() {
    const v = this.newValue.trim();
    if (!v) return;
    this.watchError.set(null);
    this.siem.addWatched(v, this.newGroup.trim()).subscribe({
      next: r => { this.watchlist.update(l => [r.entry, ...l]); this.newValue = ''; this.newGroup = ''; },
      error: e => this.watchError.set(e?.error?.message || 'Could not add it.'),
    });
  }

  removeWatched(w: any) {
    if (!confirm(`Remove ${w.value} from the watchlist?`)) return;
    this.siem.removeWatched(w.id).subscribe({
      next: () => this.watchlist.update(l => l.filter(x => x.id !== w.id)),
      error: e => this.watchError.set(e?.error?.message || 'Could not remove it.'),
    });
  }

  lookup() {
    const q = this.q.trim();
    if (!q) return;
    this.siem.lookupIntel(q).subscribe({ next: r => this.result.set(r), error: () => this.error.set('The lookup failed.') });
  }

  types(t: Record<string, number>) { return Object.entries(t ?? {}).map(([k, v]) => `${v.toLocaleString()} ${k}`).join(' · '); }
  sources(hits: any[]) { return [...new Set(hits.map(h => h.source))].join(', '); }
  when(ts: number) { return ts ? new Date(ts > 1e12 ? ts : ts * 1000).toLocaleString() : 'not yet'; }
}
