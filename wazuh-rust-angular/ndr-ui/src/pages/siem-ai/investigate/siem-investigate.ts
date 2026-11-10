import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { LucideAngularModule, Search, ScanSearch } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

type EntryType = 'alert' | 'case' | 'playbook' | 'decision' | 'swarm';

/**
 * Investigation: one IP, host, user, file hash or domain across alerts, log
 * events, threat intel, the swarm, SOAR cases and playbook runs, AI decisions,
 * triage, suppressions, the host's inventory and vulnerabilities, and security
 * memory, on one timeline (siem-api /api/v1/siem/investigate).
 */
@Component({
  selector: 'app-siem-investigate',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, LucideAngularModule],
  templateUrl: './siem-investigate.html',
})
export class SiemInvestigate implements OnInit {
  private siem = inject(SiemService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  SearchIcon = Search;
  ScanIcon = ScanSearch;

  q = '';
  days = 7;
  data = signal<any>(null);
  loading = signal(false);
  error = signal<string | null>(null);
  show = signal<'all' | EntryType>('all');
  showEvents = signal(false);
  types: { key: 'all' | EntryType; label: string }[] = [
    { key: 'all', label: 'All' }, { key: 'alert', label: 'Alerts' }, { key: 'case', label: 'Cases' },
    { key: 'playbook', label: 'Playbooks' }, { key: 'decision', label: 'AI decisions' }, { key: 'swarm', label: 'Swarm' },
  ];
  timeline = computed(() => {
    const t = this.data()?.timeline ?? [];
    return this.show() === 'all' ? t : t.filter((e: any) => e.type === this.show());
  });

  ngOnInit() {
    this.route.queryParamMap.subscribe(p => {
      const q = p.get('q');
      if (q && q !== this.data()?.query) {
        this.q = q;
        this.days = Number(p.get('days')) || this.days;
        this.run();
      }
    });
  }

  submit() {
    if (!this.q.trim()) return;
    // the URL carries the query, so it can be shared and the back button works
    this.router.navigate([], { relativeTo: this.route, queryParams: { q: this.q.trim(), days: this.days } });
    if (this.q.trim() === this.data()?.query) this.run();
  }

  run() {
    this.loading.set(true);
    this.error.set(null);
    this.siem.investigate(this.q.trim(), this.days).subscribe({
      next: r => {
        this.loading.set(false);
        if (r.status === 'error') { this.error.set(r.message); this.data.set(null); return; }
        this.data.set(r);
        this.show.set('all');
      },
      error: e => { this.loading.set(false); this.error.set(e?.status === 403 ? 'You do not have access to SIEM alerts.' : 'The investigation failed.'); },
    });
  }

  pivot(value: string) {
    this.q = value;
    this.submit();
  }

  count(type: EntryType) { return (this.data()?.timeline ?? []).filter((e: any) => e.type === type).length; }
  techniques(t: Record<string, number>) { return Object.entries(t ?? {}).sort((a, b) => b[1] - a[1]); }
  sources(hits: any[]) { return [...new Set(hits.map(h => h.source))].join(', '); }
  when(ts?: number) { return ts ? new Date(ts * 1000).toLocaleString() : '—'; }
  verdictCls(v: string) {
    return v === 'malicious' ? 'text-rose-300 border-rose-700 bg-rose-950/40' : v === 'suspicious' ? 'text-amber-300 border-amber-700 bg-amber-950/40' : v === 'no activity' ? 'text-slate-400 border-slate-700' : 'text-cyan-300 border-cyan-800 bg-cyan-950/30';
  }
  typeCls(t: string) {
    return { alert: 'bg-rose-500', case: 'bg-amber-400', playbook: 'bg-violet-400', decision: 'bg-cyan-400', swarm: 'bg-emerald-400' }[t] ?? 'bg-slate-500';
  }
}
