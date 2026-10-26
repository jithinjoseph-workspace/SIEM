import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { LucideAngularModule, FileSearch, RefreshCw } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { AuthService } from '../../../services/auth/auth';

/**
 * Sigma Detection: the SigmaHQ community rules (provigil-common's engine) the SIEM
 * runs on every archived event besides the Wazuh rules, and what they caught
 * (siem-api /api/v1/siem/sigma).
 */
@Component({
  selector: 'app-siem-sigma',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, LucideAngularModule],
  templateUrl: './siem-sigma.html',
})
export class SiemSigma implements OnInit {
  private siem = inject(SiemService);
  private auth = inject(AuthService);
  RuleIcon = FileSearch;
  RefreshIcon = RefreshCw;
  canSync = this.auth.isAdmin();

  data = signal<any>(null);
  loading = signal(false);
  syncing = signal(false);
  error = signal<string | null>(null);
  message = signal<string | null>(null);
  q = signal('');
  shown = computed(() => {
    const q = this.q().trim().toLowerCase();
    const rules = this.data()?.rules ?? [];
    return (q ? rules.filter((r: any) => `${r.title} ${r.product} ${r.category} ${r.service} ${(r.tags ?? []).join(' ')}`.toLowerCase().includes(q)) : rules).slice(0, 200);
  });

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getSigma().subscribe({
      next: r => { this.loading.set(false); this.error.set(null); this.data.set(r); },
      error: e => { this.loading.set(false); this.error.set(e?.status === 403 ? 'You do not have access to SIEM rules.' : 'Sigma detection is not available.'); },
    });
  }

  sync() {
    this.syncing.set(true);
    this.siem.syncSigma().subscribe({
      next: r => {
        this.syncing.set(false);
        if (r.status === 'ok') { this.message.set(`${r.saved} new rule(s) from SigmaHQ; ${r.loaded} loaded.`); this.load(); }
        else this.error.set(r.message);
      },
      error: () => { this.syncing.set(false); this.error.set('The sync failed.'); },
    });
  }

  products(p: Record<string, number>) { return Object.entries(p ?? {}).sort((a, b) => b[1] - a[1]); }
  when(ts: number) { return ts ? new Date(ts * 1000).toLocaleString() : '—'; }
  sevCls(s: string) {
    return { critical: 'text-rose-300', high: 'text-orange-300', medium: 'text-amber-300', low: 'text-sky-300' }[(s || '').toLowerCase()] ?? 'text-slate-400';
  }
}
