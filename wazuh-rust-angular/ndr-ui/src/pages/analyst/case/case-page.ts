import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { SiemService } from '../../../services/siem/siem.service';
import { Api } from '../../../services/api/api';

type Tab = 'overview' | 'evidence' | 'journey' | 'sequence' | 'raw' | 'ai' | 'related' | 'notes';

/** AI verdict label -> the disposition a human accepts with one click (needs_review has none). */
const ACCEPT: Record<string, string> = {
  compromised: 'True Positive', malicious: 'True Positive', attack_attempt: 'True Positive', likely_benign: 'Benign',
};

/**
 * The full case page, shared by SIEM and NDR cases: disposition, resolve, category, SLA,
 * entities with risk, alerts, the AI assessment and its challenge, journey, attachments, notes
 * (siem-api case_detail.rs, case_ai.rs, soar.rs).
 */
@Component({
  selector: 'app-case-page',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './case-page.html',
})
export class CasePage implements OnInit {
  private siem = inject(SiemService);
  private api = inject(Api);
  private route = inject(ActivatedRoute);

  id = '';
  tab = signal<Tab>('overview');
  tabs: { key: Tab; label: string }[] = [
    { key: 'overview', label: 'Overview' }, { key: 'evidence', label: 'Supporting Evidence' }, { key: 'journey', label: 'Journey' },
    { key: 'sequence', label: 'Sequence' }, { key: 'raw', label: 'Raw JSON' }, { key: 'ai', label: 'Ask AI' },
    { key: 'related', label: 'Related' }, { key: 'notes', label: 'Notes' },
  ];
  d = signal<any>(null);
  inv = signal<any>(null);
  comments = signal<any[]>([]);
  error = signal('');
  message = signal('');
  busy = signal(false);
  explanation = signal<{ text: string; model: string } | null>(null);

  // dialogs
  dialog = signal<'' | 'resolve' | 'disposition' | 'edit'>('');
  form: any = {};
  newNote = '';
  question = '';
  answers = signal<{ q: string; a: string }[]>([]);
  private conversation: string | null = null;

  c = computed(() => this.d()?.case);
  verdict = computed(() => this.inv()?.verdict);
  acceptAs = computed(() => ACCEPT[this.verdict()?.label] || '');
  closed = computed(() => ['Closed', 'Resolved', 'False Positive'].includes(this.c()?.status));
  rawJson = computed(() => JSON.stringify({ detail: this.d(), investigation: this.inv() }, null, 2));

  ngOnInit() {
    this.id = this.route.snapshot.paramMap.get('id') || '';
    this.load();
  }

  load() {
    this.siem.getCaseDetail(this.id).subscribe({
      next: r => { this.d.set(r); this.error.set(''); },
      error: e => this.error.set(e?.error?.message || 'The case could not be loaded.'),
    });
    this.siem.getCaseInvestigation(this.id).subscribe({ next: r => this.inv.set(r?.investigation || null), error: () => {} });
    this.api.getSoarCaseComments(this.id).subscribe({ next: (r: any) => r?.status === 'success' && this.comments.set(r.data || []) });
  }

  private done(text: string) {
    return {
      next: (r: any) => {
        this.busy.set(false);
        if (r?.status === 'error') { this.error.set(r.message || 'Failed.'); return; }
        this.dialog.set(''); this.message.set(text); this.error.set(''); this.load();
      },
      error: (e: any) => { this.busy.set(false); this.error.set(e?.error?.message || 'Failed.'); },
    };
  }

  open(kind: 'resolve' | 'disposition' | 'edit', disposition?: string) {
    const c = this.c();
    this.form = kind === 'edit'
      ? { title: c.title, description: c.description, priority: c.priority || 'P2', severity: c.severity || 'MEDIUM', assigned_to: c.assigned_to,
          category: this.d().details?.category || '', subcategory: this.d().details?.subcategory || '' }
      : { disposition: disposition || this.d().details?.disposition || '', text: '' };
    this.dialog.set(kind);
  }

  save() {
    const f = this.form, k = this.dialog();
    this.busy.set(true);
    if (k === 'resolve') this.siem.resolveCase(this.id, f.disposition, f.text).subscribe(this.done('Case resolved.'));
    else if (k === 'disposition') this.siem.setCaseDisposition(this.id, f.disposition, f.text).subscribe(this.done('Disposition changed.'));
    else if (k === 'edit') {
      const { category, subcategory, ...c } = f;
      this.api.updateSoarCase(this.id, c).subscribe({
        next: () => this.siem.setCaseDetails(this.id, { category, subcategory }).subscribe(this.done('Case saved.')),
        error: (e: any) => { this.busy.set(false); this.error.set(e?.error?.message || 'Failed.'); },
      });
    }
  }

  explain() {
    const d = this.d();
    this.busy.set(true);
    this.siem.explain('case', { case: d.case, details: d.details, sla: d.sla, alerts: d.alerts.slice(0, 60), entities: d.entities, investigation: this.inv() }).subscribe({
      next: r => { this.busy.set(false); r?.status === 'ok' ? this.explanation.set({ text: r.explanation, model: r.model }) : this.error.set(r?.message || 'The AI did not answer.'); },
      error: e => { this.busy.set(false); this.error.set(e?.error?.message || 'The AI did not answer.'); },
    });
  }

  reinvestigate() {
    this.busy.set(true);
    this.siem.runCaseInvestigation(this.id).subscribe(this.done('Investigated again.'));
  }

  addNote() {
    const n = this.newNote.trim();
    if (!n) return;
    this.api.addSoarCaseComment(this.id, n).subscribe({ next: () => { this.newNote = ''; this.load(); } });
  }

  upload(ev: Event) {
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) { this.error.set('Attachments are limited to 10 MB.'); return; }
    const rd = new FileReader();
    rd.onload = () => {
      const data = String(rd.result).split(',')[1] || '';
      this.busy.set(true);
      this.siem.addCaseAttachment(this.id, file.name, file.type, data).subscribe(this.done(`${file.name} attached.`));
    };
    rd.readAsDataURL(file);
  }

  download(a: any) {
    this.siem.caseAttachment(this.id, a.id).subscribe(b => {
      const url = URL.createObjectURL(b), el = document.createElement('a');
      el.href = url; el.download = a.name; el.click(); URL.revokeObjectURL(url);
    });
  }

  ask() {
    const q = this.question.trim();
    if (!q) return;
    const c = this.c();
    // the first question carries the case so the copilot's tools look at the right hosts and addresses
    const msg = this.conversation ? q : `About SOAR case ${c.case_number} "${c.title}" (source ${c.src_ip || '-'}, destination ${c.dst_ip || '-'}, alerts ${(c.hit_ids || []).length}): ${q}`;
    this.question = ''; this.busy.set(true);
    this.siem.copilotAsk(msg, this.conversation).subscribe({
      next: r => {
        this.busy.set(false);
        if (r?.status !== 'ok') { this.error.set(r?.message || 'The AI did not answer.'); return; }
        this.conversation = r.conversation_id;
        this.answers.update(a => [...a, { q, a: r.turn?.answer || '' }]);
      },
      error: e => { this.busy.set(false); this.error.set(e?.error?.message || 'The AI did not answer.'); },
    });
  }

  sla(): { text: string; cls: string } {
    const s = this.d()?.sla;
    if (!s) return { text: '', cls: '' };
    const left = s.due - Date.now() / 1000, h = Math.floor(Math.abs(left) / 3600), m = Math.floor((Math.abs(left) % 3600) / 60);
    const cls = s.state === 'Breached' ? 'text-rose-300 border-rose-800 bg-rose-950/40'
      : s.state === 'At Risk' ? 'text-amber-300 border-amber-800 bg-amber-950/40' : 'text-emerald-300 border-emerald-800 bg-emerald-950/40';
    const text = s.state === 'Met' || s.state === 'Missed' ? s.state : left >= 0 ? `${h}h ${m}m left` : `Breached ${h}h ${m}m ago`;
    return { text, cls };
  }

  riskCls(r: number | null | undefined) {
    return r == null ? 'text-slate-400' : r >= 70 ? 'text-rose-300' : r >= 40 ? 'text-amber-300' : 'text-emerald-300';
  }
  date(t: any) { return t == null || t === '' ? '' : new Date(typeof t === 'number' ? t * 1000 : t).toLocaleString(); }
  label(s: string) { return (s || '').replace(/_/g, ' '); }
}
