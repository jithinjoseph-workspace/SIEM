import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, Scale, Lock } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { ACTION_LABEL, DecisionDetail } from '../../siem-ai/decisions/decision-detail';

/**
 * AI Guardrails (tenant admin): approve or reject held high-impact actions, set the
 * thresholds and protected assets, and see the guardrails that are always on
 * (siem-api /api/v1/siem/decisions/policy, /:id/approve, /:id/reject).
 */
@Component({
  selector: 'app-ai-guardrails',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule, DecisionDetail],
  templateUrl: './ai-guardrails.html',
})
export class AiGuardrails implements OnInit {
  private siem = inject(SiemService);

  ScaleIcon = Scale;
  LockIcon = Lock;
  actionLabel = ACTION_LABEL;

  pending = signal<any[]>([]);
  rules = signal<any>(null);
  open = signal<any>(null);
  error = signal<string | null>(null);
  message = signal<string | null>(null);
  saving = signal(false);
  form: any = { max_blocks_per_hour: 10, min_level_auto_block: 10, max_auto_block_hours: 24, max_suppress_hours: 72, min_ai_confidence: 70, max_isolations_per_hour: 2, min_level_auto_isolate: 12 };
  protectedText = '';
  groups = [
    { key: 'block_ip', label: 'Automatic IP blocks (SOAR)' },
    { key: 'isolate_host', label: 'Automatic host isolation (SOAR)' },
    { key: 'manual_block', label: 'Blocks and isolations by an operator' },
    { key: 'suppress', label: 'Hiding alerts on an AI triage verdict' },
    { key: 'review', label: 'Approvals' },
  ];

  ngOnInit() {
    this.load();
  }

  load() {
    this.siem.getDecisions().subscribe({ next: r => this.pending.set(r.pending ?? []), error: () => this.error.set('Decisions are not available.') });
    this.siem.getDecisionPolicy().subscribe({
      next: r => {
        this.rules.set(r.rules);
        const { protected: p, updated_by, updated_at, ...rest } = r.settings;
        this.form = rest;
        this.protectedText = (p ?? []).join('\n');
      },
      error: () => this.error.set('The policy is not available.'),
    });
  }

  private ok(m: string) {
    this.error.set(null);
    this.message.set(m);
    setTimeout(() => this.message.set(null), 6000);
  }

  save() {
    this.saving.set(true);
    const body = { ...this.form, protected: this.protectedText.split(/[\n,]/).map(s => s.trim()).filter(Boolean) };
    this.siem.putDecisionPolicy(body).subscribe({
      next: () => { this.saving.set(false); this.ok('Saved. The change is recorded in the decision chain.'); this.load(); },
      error: e => { this.saving.set(false); this.error.set(e?.error?.message || 'Could not save.'); },
    });
  }

  show(p: any) {
    if (this.open()?.id === p.id) { this.open.set(null); return; }
    this.siem.getDecision(p.id).subscribe({ next: r => this.open.set(r.record) });
  }

  review(p: any, approve: boolean) {
    this.siem.reviewDecision(p.id, approve).subscribe({
      next: r => {
        const ran = r.result ? (r.result.ok ? ` Done: ${r.result.detail}.` : ` It could not run: ${r.result.detail}.`) : '';
        this.ok(`${approve ? 'Approved' : 'Rejected'}.${ran}`);
        this.open.set(null);
        this.load();
      },
      error: e => this.error.set(e?.error?.message || 'Could not record the review.'),
    });
  }

  effect(e: string) { return e === 'deny' ? 'Deny' : e === 'require_approval' ? 'Needs approval' : 'Allow'; }
  when(ts: number) { return new Date(ts * 1000).toLocaleString(); }
}
