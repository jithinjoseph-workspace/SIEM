import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { LucideAngularModule, Ban } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

/** One rule as siem-api keeps it (provigil-agent-server endpoint_policy::Rule). */
interface Rule {
  id: string;
  name: string;
  kind: 'site' | 'app' | 'safe_search';
  mode: 'monitor' | 'enforce';
  targets: string[];
  groups: string[];
  os: 'any' | 'windows' | 'linux';
  message: string;
  strict: boolean;
  enabled: boolean;
  updated_by?: string;
  updated_at?: number;
  note?: string;
}

/**
 * Endpoint policies (tenant admin): the organisation's own site and application rules, in monitor
 * (alert only) or enforce (block and alert) mode, pushed to the agents with their group settings
 * (siem-api /api/v1/endpoint-policies; specs/compliance-and-endpoint-policy.md part B).
 */
@Component({
  selector: 'app-endpoint-policies',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './endpoint-policies.html',
})
export class EndpointPolicies implements OnInit {
  private http = inject(HttpClient);
  private siem = inject(SiemService);
  BanIcon = Ban;

  rules = signal<Rule[]>([]);
  presets = signal<Rule[]>([]);
  agents = signal<any[]>([]);
  groups = signal<string[]>([]);
  canEdit = signal(false);
  error = signal<string | null>(null);
  message = signal<string | null>(null);
  saving = signal(false);
  /** the rule being edited (a copy), with its targets as one entry per line */
  draft = signal<(Rule & { text: string }) | null>(null);
  failing = computed(() => this.agents().filter(a => a.state !== 'applied'));
  /** "Ask AI": the request, the drafts that came back */
  askText = '';
  asking = signal(false);
  suggestion = signal<any>(null);
  /** what the rules caught, per rule, for the chosen period */
  activity = signal<any>(null);
  days = signal(7);
  openRule = signal<string | null>(null);
  readonly breakdowns = [
    { key: 'by_group', label: 'Agent group' },
    { key: 'by_network', label: 'Network (subnet)' },
    { key: 'by_device', label: 'Device' },
    { key: 'by_user', label: 'Person' },
    { key: 'by_target', label: 'Site or program' },
  ];

  readonly kinds: Record<string, string> = { site: 'Websites', app: 'Applications', safe_search: 'Safe search' };

  ngOnInit() {
    this.load();
    this.siem.getGroups().subscribe({ next: g => this.groups.set(g.map(x => x.name)), error: () => {} });
  }

  loadActivity() {
    this.http.get<any>(`/api/v1/endpoint-policies/activity?days=${this.days()}`).subscribe({
      next: r => this.activity.set(r),
      error: () => this.activity.set(null),
    });
  }

  setDays(d: number) {
    this.days.set(d);
    this.loadActivity();
  }

  /** Drafts rules from a sentence ("block ChatGPT and WhatsApp"); nothing is saved. */
  ask() {
    const text = this.askText.trim();
    if (text.length < 3) return;
    this.asking.set(true);
    this.suggestion.set(null);
    this.http.post<any>('/api/v1/endpoint-policies/suggest', { text }).subscribe({
      next: r => { this.asking.set(false); this.suggestion.set(r); },
      error: e => { this.asking.set(false); this.error.set(e?.error?.message || 'No draft could be made.'); },
    });
  }

  /** Bar width of a count against the largest in its list. */
  width(list: any[], n: number) {
    const max = Math.max(1, ...list.map(x => x.count));
    return Math.max(4, Math.round((n / max) * 100));
  }

  load() {
    this.loadActivity();
    this.http.get<any>('/api/v1/endpoint-policies').subscribe({
      next: r => {
        this.rules.set(r.rules ?? []);
        this.presets.set(r.presets ?? []);
        this.agents.set(r.agents ?? []);
        this.canEdit.set(!!r.can_edit);
      },
      error: e => this.error.set(e?.error?.message || 'Endpoint policies are not available.'),
    });
  }

  edit(r: Partial<Rule>) {
    this.message.set(null);
    this.error.set(null);
    const base: Rule = { id: 'new', name: '', kind: 'site', mode: 'monitor', targets: [], groups: [], os: 'any', message: '', strict: false, enabled: true };
    const rule = { ...base, ...r, groups: [...(r.groups ?? [])], targets: [...(r.targets ?? [])] } as Rule;
    if (!r.id) rule.id = 'new';
    this.draft.set({ ...rule, text: rule.targets.join('\n') });
  }

  toggleGroup(g: string) {
    const d = this.draft();
    if (!d) return;
    d.groups = d.groups.includes(g) ? d.groups.filter(x => x !== g) : [...d.groups, g];
    this.draft.set({ ...d });
  }

  /** A pasted or uploaded list: one entry per line (commas and spaces split too; # starts a comment). */
  lines(text: string): string[] {
    return text.split(/[\r\n,;\s]+/).map(l => l.replace(/#.*/, '').trim()).filter(l => l.length > 0);
  }

  upload(ev: Event) {
    const f = (ev.target as HTMLInputElement).files?.[0];
    const d = this.draft();
    if (!f || !d) return;
    if (f.size > 2_000_000) {
      this.error.set('The list is larger than 2 MB.');
      return;
    }
    f.text().then(t => {
      // a hosts-format list ("0.0.0.0 site.com") gives its names
      const names = this.lines(t.split(/\r?\n/).map(l => l.replace(/^\s*(0\.0\.0\.0|127\.0\.0\.1|::1?)\s+/, '')).join('\n'));
      this.draft.set({ ...d, text: [...this.lines(d.text), ...names].join('\n') });
      this.message.set(`${names.length} entries read from ${f.name}.`);
    });
  }

  save() {
    const d = this.draft();
    if (!d) return;
    const { text, note, ...rule } = d;
    rule.targets = d.kind === 'safe_search' ? [] : this.lines(text);
    this.saving.set(true);
    this.http.put<any>(`/api/v1/endpoint-policies/${encodeURIComponent(d.id)}`, rule).subscribe({
      next: () => {
        this.saving.set(false);
        this.draft.set(null);
        this.message.set(`"${rule.name}" saved. Agents apply it within 5 minutes.`);
        this.load();
      },
      error: e => {
        this.saving.set(false);
        this.error.set(e?.error?.message || 'The rule could not be saved.');
      },
    });
  }

  setEnabled(r: Rule, enabled: boolean) {
    this.http.put<any>(`/api/v1/endpoint-policies/${encodeURIComponent(r.id)}`, { ...r, enabled }).subscribe({
      next: () => this.load(),
      error: e => this.error.set(e?.error?.message || 'The rule could not be changed.'),
    });
  }

  remove(r: Rule) {
    if (!confirm(`Delete the rule "${r.name}"? Agents stop applying it within 5 minutes.`)) return;
    this.http.delete<any>(`/api/v1/endpoint-policies/${encodeURIComponent(r.id)}`).subscribe({
      next: () => {
        this.message.set(`"${r.name}" deleted.`);
        this.load();
      },
      error: e => this.error.set(e?.error?.message || 'The rule could not be deleted.'),
    });
  }

  when(t?: number) {
    return t ? new Date(t * 1000).toLocaleString() : '';
  }

  summary(r: Rule) {
    if (r.kind === 'safe_search') return 'Google, Bing and YouTube restricted in Edge and Chrome';
    const shown = r.targets.slice(0, 4).join(', ');
    return r.targets.length > 4 ? `${shown} and ${r.targets.length - 4} more` : shown;
  }
}
