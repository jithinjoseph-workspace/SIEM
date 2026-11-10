import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { LucideAngularModule, ShieldCheck, ShieldAlert, Search, RefreshCcw, ListChecks, Bot } from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { reportRxjsError } from '../../../services/error-reporter/error-reporter';

/**
 * Alert Triage. Groups similar alerts, marks the ones rules (or, within a
 * budget, the AI) judge harmless, and lets the person decide. Nothing is hidden
 * until "Hide" is pressed. All state is signals: this app has no zone.js, so
 * plain fields changed in an HTTP callback would not redraw the view.
 */
@Component({
  selector: 'app-triage',
  standalone: true,
  imports: [CommonModule, RouterLink, LucideAngularModule],
  templateUrl: './triage.html',
  styleUrl: './triage.css',
})
export class Triage implements OnInit {
  private api = inject(Api);

  ListIcon    = ListChecks;
  OkIcon      = ShieldCheck;
  AlertIcon   = ShieldAlert;
  UnsureIcon  = Search;   
  RefreshIcon = RefreshCcw; 
  BotIcon     = Bot;

  data       = signal<any | null>(null);
  loading    = signal(true);
  running    = signal(false);
  error      = signal('');
  notice     = signal('');
  busyId     = signal<string | null>(null);
  confirmAll = signal(false);
  bulkBusy   = signal(false);

  private recs = computed<any[]>(() => this.data()?.recommendations ?? []);
  attention = computed(() => this.recs().filter(r => r.verdict === 'suspicious'));
  unsure    = computed(() => this.recs().filter(r => r.verdict === 'unknown'));
  harmless  = computed(() => this.recs().filter(r => r.verdict === 'benign'));
  summary   = computed(() => this.data()?.summary ?? null);
  ai        = computed(() => this.data()?.ai ?? null);
  anyBusy   = computed(() => !!this.busyId() || this.bulkBusy() || this.running());

  /** What hiding this group really hides: the server suppresses a tag for a whole
   *  source, so every pending group with the same source and tag goes with it. */
  impact(rec: any): { groups: number; alerts: number; blocked: boolean } {
    const same = this.recs().filter(r => r.src_ip === rec.src_ip && r.tag === rec.tag);
    return {
      groups:  same.length,
      alerts:  same.reduce((n, r) => n + r.alert_count, 0),
      blocked: same.some(r => r.verdict === 'suspicious'),
    };
  }

  ngOnInit() { this.load(); }

  private accept(d: any) {
    if (d?.status === 'ok') {
      this.data.set(d);
      this.error.set('');
    } else {
      this.error.set(d?.message || 'Could not load alert triage.');
    }
  }

  load() {
    this.loading.set(true);
    this.api.getTriage().subscribe({
      next: d => { this.accept(d); this.loading.set(false); },
      error: e => { this.error.set('Could not load alert triage.'); this.loading.set(false); reportRxjsError(e); },
    });
  }

  run() {
    if (this.anyBusy()) return;
    this.running.set(true);
    this.notice.set('');
    this.api.runTriage().subscribe({
      next: d => {
        this.accept(d);
        this.running.set(false);
        if (d?.info?.throttled) this.notice.set('Checked a moment ago - showing the latest result.');
      },
      error: e => { this.error.set('Could not re-check alerts.'); this.running.set(false); reportRxjsError(e); },
    });
  }

  hide(rec: any) {
    if (this.anyBusy()) return;
    this.busyId.set(rec.id);
    this.notice.set('');
    this.api.applyTriage(rec.id, 24).subscribe({
      next: d => {
        this.busyId.set(null);
        if (d?.status === 'ok') {
          this.data.set(d);
          const more = d?.info?.also_covered_groups || 0;
          this.notice.set(`Hidden for 24 hours: "${rec.tag}" from ${rec.src_ip}` + (more ? ` (${more} other group${more > 1 ? 's' : ''} with the same source and tag too).` : '.'));
        } else {
          this.error.set(d?.message || 'Could not hide this group.');
        }
      },
      error: e => { this.busyId.set(null); this.error.set('Could not hide this group.'); reportRxjsError(e); },
    });
  }

  dismiss(rec: any) {
    if (this.anyBusy()) return;
    this.busyId.set(rec.id);
    this.notice.set('');
    this.api.dismissTriage(rec.id).subscribe({
      next: d => { this.busyId.set(null); if (d?.status === 'ok') this.data.set(d); else this.error.set(d?.message || 'Could not dismiss.'); },
      error: e => { this.busyId.set(null); this.error.set('Could not dismiss.'); reportRxjsError(e); },
    });
  }

  /** Two-step on purpose: the first press only reveals what will happen. */
  askHideAll() { if (!this.anyBusy() && this.harmless().length) this.confirmAll.set(true); }
  cancelHideAll() { if (!this.bulkBusy()) this.confirmAll.set(false); }

  async hideAll() {
    if (this.bulkBusy()) return;
    this.bulkBusy.set(true);
    this.notice.set('');
    this.error.set('');
    const total = this.harmless().length;
    let done = 0;
    // Re-read the list each time: hiding one group can also cover others.
    for (let guard = 0; guard < 500; guard++) {
      const next = this.harmless().find(r => !this.impact(r).blocked);
      if (!next) break;
      try {
        const d = await firstValueFrom(this.api.applyTriage(next.id, 24));
        if (d?.status !== 'ok') { this.error.set(d?.message || 'Stopped: the server refused one group.'); break; }
        this.data.set(d);
        done++;
      } catch (e) {
        this.error.set('Stopped: a request failed.');
        reportRxjsError(e);
        break;
      }
    }
    this.bulkBusy.set(false);
    this.confirmAll.set(false);
    if (!this.error()) this.notice.set(`Hid ${done} of ${total} likely-harmless groups for 24 hours.`);
  }

  sevList(rec: any): { name: string; n: number }[] {
    return Object.entries(rec.severities || {}).map(([name, n]) => ({ name, n: n as number }));
  }

  ago(ts: number): string {
    if (!ts) return '';
    const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
    if (s < 90) return 'just now';
    if (s < 5400) return `${Math.round(s / 60)} min ago`;
    if (s < 129600) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  }

  trackRec = (_: number, r: any) => r.id;
}
