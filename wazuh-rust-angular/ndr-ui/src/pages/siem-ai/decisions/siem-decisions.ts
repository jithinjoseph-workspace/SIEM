import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Scale, RefreshCw, ShieldCheck, Download } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { ACTION_LABEL, DecisionDetail, OUTCOME } from './decision-detail';

/**
 * AI Decision Audit: every high-impact decision (SOAR blocks, hiding alerts on an
 * AI verdict), approvals and policy changes, with the reasoning that produced
 * them; the chain can be re-verified and exported (siem-api /api/v1/siem/decisions).
 */
@Component({
  selector: 'app-siem-decisions',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, DecisionDetail],
  templateUrl: './siem-decisions.html',
})
export class SiemDecisions implements OnInit {
  private siem = inject(SiemService);

  ScaleIcon = Scale;
  RefreshIcon = RefreshCw;
  CheckIcon = ShieldCheck;
  DownloadIcon = Download;
  actionLabel = ACTION_LABEL;
  outcomes = OUTCOME;

  decisions = signal<any[]>([]);
  pending = signal<any[]>([]);
  selected = signal<any>(null);
  selectedVerified = signal<string | null | undefined>(undefined);
  verify = signal<any>(null);
  loading = signal(false);
  error = signal<string | null>(null);

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getDecisions().subscribe({
      next: r => { this.loading.set(false); this.error.set(null); this.decisions.set(r.decisions ?? []); this.pending.set(r.pending ?? []); },
      error: e => { this.loading.set(false); this.error.set(e?.status === 403 ? 'You do not have access to SIEM alerts.' : 'Decisions are not available.'); },
    });
  }

  open(d: any) {
    if (this.selected()?.id === d.id) { this.selected.set(null); return; }
    this.siem.getDecision(d.id).subscribe({
      next: r => { this.selected.set(r.record); this.selectedVerified.set(r.verified ?? null); },
      error: () => this.error.set('This decision could not be loaded.'),
    });
  }

  runVerify() {
    this.verify.set({ running: true });
    this.siem.verifyDecisions().subscribe({ next: v => this.verify.set(v), error: () => this.verify.set({ valid: false, reason: 'The check could not run.' }) });
  }

  exportChain() {
    this.siem.exportDecisions().subscribe({
      next: blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `decision-chain-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
      },
      error: () => this.error.set('The export failed.'),
    });
  }

  when(ts: number) { return new Date(ts * 1000).toLocaleString(); }
  outcome(d: any) {
    if (d.action === 'policy_change') return { label: 'Recorded', cls: 'text-slate-300 border-slate-700' };
    if (d.action === 'review') return d.outcome === 'allowed' ? { label: 'Approved', cls: OUTCOME['allowed'].cls } : { label: 'Rejected', cls: OUTCOME['denied'].cls };
    if (d.review) return { label: d.review === 'approved' ? 'Approved' : 'Rejected', cls: d.review === 'approved' ? OUTCOME['allowed'].cls : OUTCOME['denied'].cls };
    if (d.outcome === 'needs_approval' && this.pending().some(p => p.id === d.id)) return OUTCOME['needs_approval'];
    if (d.outcome === 'needs_approval') return { label: 'Expired', cls: 'text-slate-400 border-slate-700' };
    return OUTCOME[d.outcome] ?? { label: d.outcome, cls: '' };
  }
}
