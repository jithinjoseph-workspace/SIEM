import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, ListFilter, RefreshCw, EyeOff, Eye, X, Bot, Gavel, Gauge } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

/** One group of identical Wazuh alerts (same rule, agent and source) and its verdict. */
interface Rec {
  id: string;
  rule_id: number;
  rule_description: string;
  agent_id: string;
  agent_name: string;
  src_ip: string;
  verdict: 'benign' | 'suspicious' | 'unknown';
  source: 'rule' | 'ai';
  confidence: number;
  reason: string;
  alert_count: number;
  max_level: number;
  first_seen: number;
  last_seen: number;
}

/**
 * SIEM Alert Triage: groups of the tenant's Wazuh alerts that are likely harmless,
 * decided by rules first and the AI for the rest. Nothing is hidden until a person
 * applies a recommendation (siem-api /api/v1/siem/triage, crate siem-triage).
 */
@Component({
  selector: 'app-siem-triage',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-triage.html',
})
export class SiemTriage implements OnInit {
  private siem = inject(SiemService);

  FilterIcon = ListFilter;
  RefreshIcon = RefreshCw;
  HideIcon = EyeOff;
  XIcon = X;
  BotIcon = Bot;
  RuleIcon = Gavel;
  EyeIcon = Eye;
  GaugeIcon = Gauge;

  data = signal<any>(null);
  loading = signal(false);
  busyId = signal<string | null>(null);
  message = signal<string | null>(null);
  error = signal<string | null>(null);
  filter = signal<'all' | 'benign' | 'unknown' | 'suspicious'>('all');
  hours: Record<string, number> = {};
  hourChoices = [1, 8, 24, 72, 168];

  /** How the page adapts for this analyst (workload & AI-trust calibration); null when off. */
  cal = computed<any>(() => this.data()?.calibration ?? null);
  depth = computed<'brief' | 'standard' | 'detailed'>(() => this.cal()?.depth ?? 'standard');
  /** Groups whose alerts this analyst opened (this visit). */
  looked = signal<Set<string>>(new Set());
  openId = signal<string | null>(null);
  samples = signal<Record<string, any[]>>({});

  recs = computed<Rec[]>(() => (this.data()?.recommendations ?? []) as Rec[]);
  shown = computed(() => {
    const list = this.filter() === 'all' ? this.recs() : this.recs().filter(r => r.verdict === this.filter());
    // under high workload: the biggest groups first
    return this.cal()?.summaries_first ? [...list].sort((a, b) => b.alert_count - a.alert_count) : list;
  });

  /** The AI's verdict waits until the analyst has looked (no anchoring). */
  verdictHidden(r: Rec): boolean {
    return !!this.cal()?.hide_ai_verdict_until_inspect && r.source === 'ai' && !this.looked().has(r.id);
  }

  mustLook(r: Rec): boolean {
    return !!this.cal()?.require_inspect && !this.looked().has(r.id);
  }

  view(r: Rec) {
    if (this.openId() === r.id) {
      this.openId.set(null);
      return;
    }
    this.siem.inspectSiemTriage(r.id).subscribe({
      next: x => {
        if (x?.status === 'error') { this.error.set(x.message); return; }
        this.samples.set({ ...this.samples(), [r.id]: x.alerts ?? [] });
        this.looked.set(new Set([...this.looked(), r.id]));
        this.openId.set(r.id);
      },
      error: e => this.fail(e),
    });
    // what was decided before about similar activity (organizational memory)
    this.siem.getTriagePrecedents(r.id).subscribe({
      next: x => this.precedents.set({ ...this.precedents(), [r.id]: x?.precedents ?? [] }),
      error: () => this.precedents.set({ ...this.precedents(), [r.id]: [] }),
    });
  }

  precedents = signal<Record<string, any[]>>({});

  outcomeClass(o: string): string {
    return o === 'true_positive' ? 'text-rose-300' : o === 'false_positive' || o === 'benign' ? 'text-emerald-300' : 'text-slate-300';
  }

  when(ts: number): string {
    return new Date(ts > 1e11 ? ts : ts * 1000).toLocaleString();
  }

  ngOnInit() {
    this.load();
  }

  private take(r: any, ok?: string) {
    this.busyId.set(null);
    this.loading.set(false);
    if (r?.status === 'error') {
      this.error.set(r.message);
      return;
    }
    this.error.set(null);
    this.data.set(r);
    if (ok) {
      this.message.set(ok);
      setTimeout(() => this.message.set(null), 4000);
    }
  }

  private fail(e: any) {
    this.busyId.set(null);
    this.loading.set(false);
    this.error.set(e?.status === 403 ? 'You do not have access to SIEM alerts.' : 'Triage is not available.');
  }

  load() {
    this.loading.set(true);
    this.siem.getSiemTriage().subscribe({ next: r => this.take(r), error: e => this.fail(e) });
  }

  runNow() {
    this.loading.set(true);
    this.siem.runSiemTriage().subscribe({
      next: r => this.take(r, r?.info?.throttled ? 'Triage ran less than a minute ago; showing the last run.' : 'Triage updated (rules and earlier AI answers).'),
      error: e => this.fail(e),
    });
  }

  apply(r: Rec) {
    const h = this.hours[r.id] ?? 24;
    this.busyId.set(r.id);
    this.siem.applySiemTriage(r.id, h).subscribe({ next: x => this.take(x, `Rule ${r.rule_id} on ${r.agent_name || r.agent_id} hidden for ${h} h.`), error: e => this.fail(e) });
  }

  dismiss(r: Rec) {
    this.busyId.set(r.id);
    this.siem.dismissSiemTriage(r.id).subscribe({ next: x => this.take(x, 'Kept visible; it will not be recommended again.'), error: e => this.fail(e) });
  }

  verdictClass(v: string): string {
    return v === 'benign' ? 'bg-emerald-950/50 text-emerald-300 border-emerald-800'
      : v === 'suspicious' ? 'bg-rose-950/50 text-rose-300 border-rose-800'
      : 'bg-amber-950/40 text-amber-300 border-amber-800';
  }

  verdictLabel(v: string): string {
    return v === 'benign' ? 'Likely benign' : v === 'suspicious' ? 'Suspicious' : 'Needs review';
  }

  ago(ts: number): string {
    if (!ts) return '—';
    const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }
}
