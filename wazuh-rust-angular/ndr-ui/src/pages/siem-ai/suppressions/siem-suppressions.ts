import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, EyeOff, RefreshCw, Plus, Trash2, PauseCircle, Bot } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

/**
 * SIEM Suppressions & AI activity: the tenant's alert suppressions (from triage
 * or added here) and the AI's triage decisions (siem-api /api/v1/siem/suppressions,
 * /api/v1/siem/ai-activity; crate siem-suppression).
 */
@Component({
  selector: 'app-siem-suppressions',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-suppressions.html',
})
export class SiemSuppressions implements OnInit {
  private siem = inject(SiemService);

  HideIcon = EyeOff;
  RefreshIcon = RefreshCw;
  PlusIcon = Plus;
  TrashIcon = Trash2;
  PauseIcon = PauseCircle;
  BotIcon = Bot;

  suppressions = signal<any[]>([]);
  analyses = signal<any[]>([]);
  loading = signal(false);
  saving = signal(false);
  error = signal<string | null>(null);
  message = signal<string | null>(null);
  showInactive = signal(false);
  form = { rule_id: '', agent_id: '', src_ip: '', hours: 24, reason: '', field_path: '', field_contains: '', permanent: false };
  hourChoices = [1, 8, 24, 72, 168];

  shown = computed(() => this.showInactive() ? this.suppressions() : this.suppressions().filter(s => s.active));

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getSiemAiActivity().subscribe({
      next: r => {
        this.loading.set(false);
        this.error.set(null);
        this.suppressions.set(r.suppressions ?? []);
        this.analyses.set(r.analyses ?? []);
      },
      error: e => {
        this.loading.set(false);
        this.error.set(e?.status === 403 ? 'You do not have access to SIEM alerts.' : 'Suppressions are not available.');
      },
    });
  }

  private done(r: any, ok: string) {
    if (r?.error) {
      this.error.set(r.error);
      return;
    }
    this.error.set(null);
    this.message.set(ok);
    setTimeout(() => this.message.set(null), 4000);
    this.load();
  }

  add() {
    const rule = this.form.rule_id.trim();
    if (rule && !/^\d+$/.test(rule)) {
      this.error.set('The rule id is a number (e.g. 5710).');
      return;
    }
    if (!rule && !this.form.src_ip.trim()) {
      this.error.set('Give a rule id, a source IP or both.');
      return;
    }
    const field = this.form.field_path.trim();
    if (field && !this.form.field_contains.trim()) {
      this.error.set('Give the text the field must contain.');
      return;
    }
    if (this.form.permanent && (!rule || !field)) {
      this.error.set('Only an exception (a rule and a field condition) can be permanent.');
      return;
    }
    this.saving.set(true);
    this.siem.createSiemSuppression({
      rule_id: rule ? Number(rule) : undefined,
      agent_id: this.form.agent_id.trim() || undefined,
      src_ip: this.form.src_ip.trim(),
      duration_hours: this.form.hours,
      reason: this.form.reason.trim(),
      field_path: field || undefined,
      field_contains: field ? this.form.field_contains.trim() : undefined,
      permanent: this.form.permanent || undefined,
    }).subscribe({
      next: r => {
        this.saving.set(false);
        if (!r?.error) this.form = { rule_id: '', agent_id: '', src_ip: '', hours: 24, reason: '', field_path: '', field_contains: '', permanent: false };
        this.done(r, 'Suppression added.');
      },
      error: () => { this.saving.set(false); this.error.set('The suppression could not be saved.'); },
    });
  }

  deactivate(s: any) {
    this.siem.deactivateSiemSuppression(s.id).subscribe({ next: r => this.done(r, 'Suppression stopped; the alerts show again.') });
  }

  remove(s: any) {
    if (!confirm(`Delete the suppression of ${s.signature_name}?`)) return;
    this.siem.deleteSiemSuppression(s.id).subscribe({ next: r => this.done(r, 'Suppression deleted.') });
  }

  when(ts: number): string {
    return ts ? new Date(ts * 1000).toLocaleString() : '—';
  }

  scope(s: any): string {
    const parts = [];
    if (s.dst_ip) parts.push(`host ${s.dst_ip}`);
    if (s.src_ip) parts.push(`source ${s.src_ip}`);
    if (s.field_path) parts.push(`${s.field_path} contains "${s.field_contains}"`);
    return parts.length ? parts.join(', ') : 'all hosts and sources';
  }
}
