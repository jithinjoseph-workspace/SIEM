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

  /** An incident opened automatically and closed as a false positive: the exception it suggests
   *  (its most frequent rule and agent, and its process or user), created only when a person asks
   *  (specs/alert-lifecycle.md, phase 6). */
  /** The hosts of the case's alerts, for an endpoint case without network addresses. */
  hosts = computed(() => [...new Set((this.d()?.alerts || []).map((a: any) => a.agent_name ? `${a.agent_name} (${a.agent_id})` : ''))].filter(Boolean).join(', '));
  /** The ATT&CK tactics of the case's alerts: a category hint when none is set. */
  tactics = computed(() => [...new Set((this.d()?.alerts || []).map((a: any) => a.mitre_tactic).filter(Boolean))].join(', '));

  exception = computed(() => {
    const d = this.d();
    // judged a false positive either way: the disposition (Resolve) or the status (the case list's workflow)
    const falsePositive = d?.details?.disposition === 'False Positive' || d?.case?.status === 'False Positive';
    return falsePositive ? this.exceptionDraft() : null;
  });

  /** The exception this case would give (null without alerts), offered in the Resolve dialog when
   *  the disposition is False Positive, and on the page once the case is one. */
  exceptionDraft = computed(() => {
    const d = this.d();
    const tags: string[] = d?.case?.tags || [];
    if (!d?.alerts?.length) return null;
    const most = (key: string) => {
      const n = new Map<any, number>();
      for (const a of d.alerts) n.set(a[key], (n.get(a[key]) || 0) + 1);
      return [...n.entries()].sort((x, y) => y[1] - x[1])[0]?.[0];
    };
    // one process or user: a permanent exception on it; several: the rule on the agent for 7 days
    const entities = tags.includes('auto-incident') ? tags.filter(t => t.startsWith('process:') || t.startsWith('user:')) : [];
    const entity = entities.length === 1 ? entities[0] : '';
    const [kind, value] = entity ? [entity.slice(0, entity.indexOf(':')), entity.slice(entity.indexOf(':') + 1)] : ['', ''];
    // the field the incident's entity came from (tag field:<path>); older incidents: the usual one
    const recorded = tags.find(t => t.startsWith('field:'))?.slice(6) || '';
    const field_path = !kind ? '' : recorded || (kind === 'process' ? 'data.win.eventdata.image' : 'data.win.eventdata.targetUserName');
    // level 12+ is never hidden (the suppression safety rule): say so instead of offering a button that cannot work
    const critical = d.alerts.some((a: any) => Number(a.rule_level) >= 12);
    return { rule_id: Number(most('rule_id')), agent_id: String(most('agent_id') || ''), field_path, field_contains: value, permanent: !!field_path, critical };
  });

  makeException() {
    const x = this.exceptionDraft();
    if (!x || x.critical) return;
    this.busy.set(true);
    this.siem.createSiemSuppression({
      rule_id: x.rule_id, agent_id: x.agent_id || undefined, duration_hours: 168,
      field_path: x.field_path || undefined, field_contains: x.field_path ? x.field_contains : undefined, permanent: x.permanent || undefined,
      reason: `Incident ${this.d()?.case?.case_number} closed as a false positive`,
    }).subscribe({
      next: (r: any) => { this.busy.set(false); if (r?.error) this.error.set(r.error); else this.message.set('Exception created: these alerts no longer reach the queue (Suppressions page to stop it).'); },
      error: () => { this.busy.set(false); this.error.set('The exception could not be created.'); },
    });
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
      : { disposition: disposition || this.d().details?.disposition || '', text: '', exception: true };
    this.dialog.set(kind);
  }

  save() {
    const f = this.form, k = this.dialog();
    this.busy.set(true);
    // a false positive with "also create an exception" ticked: the exception follows once the case is saved
    const withException = (r: any) => {
      const x = this.exceptionDraft();
      if (r?.status !== 'error' && f.disposition === 'False Positive' && f.exception && x && !x.critical) this.makeException();
    };
    const then = (text: string) => { const d = this.done(text); return { next: (r: any) => { d.next(r); withException(r); }, error: d.error }; };
    if (k === 'resolve') this.siem.resolveCase(this.id, f.disposition, f.text).subscribe(then('Case resolved.'));
    else if (k === 'disposition') this.siem.setCaseDisposition(this.id, f.disposition, f.text).subscribe(then('Disposition changed.'));
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
