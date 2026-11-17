import { Component, ElementRef, OnInit, ViewChild, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import {
  LucideAngularModule, Bot, Send, Plus, Trash2, MessageSquare, CheckCircle2, XCircle, FileText,
  FolderOpen, ScanSearch, BarChart3, Sparkles, PanelLeft, AlertTriangle,
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

interface Turn {
  at: string;
  user: string;
  answer: string;
  /** ai: planned by the AI; steps: a case or report from fixed evidence steps; rules: the built-in planner */
  mode: 'ai' | 'steps' | 'rules';
  model?: string;
  note?: string | null;
  steps: { tool: string; args: any; ok: boolean; summary: string }[];
  artifacts: Record<string, any>;
}

/**
 * AI Copilot: plain-language requests ("the latest critical alert", "open a case
 * for it, collect the evidence and tell me why", "make a report") run with the
 * SIEM's own tools (siem-api copilot.rs). Conversations are kept per user.
 */
@Component({
  selector: 'app-siem-copilot',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, LucideAngularModule],
  templateUrl: './siem-copilot.html',
  styleUrl: './siem-copilot.css',
})
export class SiemCopilot implements OnInit {
  private siem = inject(SiemService);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  @ViewChild('thread') thread?: ElementRef<HTMLElement>;

  BotIcon = Bot; SendIcon = Send; PlusIcon = Plus; TrashIcon = Trash2; ChatIcon = MessageSquare;
  OkIcon = CheckCircle2; FailIcon = XCircle; ReportIcon = FileText; CaseIcon = FolderOpen;
  InvestigateIcon = ScanSearch; StatsIcon = BarChart3; SparkIcon = Sparkles; PanelIcon = PanelLeft; WarnIcon = AlertTriangle;

  status = signal<any>(null);
  conversations = signal<{ id: string; title: string; updated_at: number }[]>([]);
  conversationId = signal<string | null>(null);
  turns = signal<Turn[]>([]);
  pending = signal<string | null>(null);
  error = signal<string | null>(null);
  showList = signal(false);
  input = '';

  readonly suggestions = [
    'Find the latest critical alert',
    'How many alerts today, and which rules fire most?',
    'Any login failures or account changes in the last 3 days?',
    'What is the oldest log from my agent?',
    'Show high alerts from the last hour',
    'Open a case for the latest critical alert, collect the evidence and tell me why it happened',
    'Make an incident report for that case',
  ];

  title = computed(() => this.conversations().find(c => c.id === this.conversationId())?.title || 'New conversation');

  ngOnInit() {
    this.siem.copilotStatus().subscribe({ next: s => this.status.set(s), error: () => this.status.set(null) });
    this.loadConversations();
    // other pages hand a request over (?ask=: sent once) or a conversation (?c=)
    const q = this.route.snapshot.queryParamMap;
    const ask = q.get('ask'), c = q.get('c');
    if (c) this.open(c);
    if (ask) this.send(ask.slice(0, 2000));
    if (ask || c) this.router.navigate([], { relativeTo: this.route, queryParams: {}, replaceUrl: true });
  }

  loadConversations() {
    this.siem.copilotConversations().subscribe({ next: r => this.conversations.set(r?.conversations ?? []), error: () => {} });
  }

  open(id: string) {
    this.showList.set(false);
    this.error.set(null);
    this.siem.copilotConversation(id).subscribe({
      next: r => { this.conversationId.set(id); this.turns.set(r?.conversation?.turns ?? []); this.scroll(); },
      error: () => this.error.set('That conversation could not be loaded.'),
    });
  }

  newChat() {
    this.conversationId.set(null);
    this.turns.set([]);
    this.error.set(null);
    this.showList.set(false);
  }

  remove(id: string, ev: Event) {
    ev.stopPropagation();
    if (!confirm('Delete this conversation?')) return;
    this.siem.copilotDeleteConversation(id).subscribe({
      next: () => { if (this.conversationId() === id) this.newChat(); this.loadConversations(); },
      error: () => this.error.set('The conversation was not deleted.'),
    });
  }

  send(text?: string) {
    const message = (text ?? this.input).trim();
    if (!message || this.pending()) return;
    this.input = '';
    this.error.set(null);
    this.pending.set(message);
    this.scroll();
    this.siem.copilotAsk(message, this.conversationId()).subscribe({
      next: r => {
        this.pending.set(null);
        if (r?.status !== 'ok') { this.error.set(r?.message || 'The copilot did not answer.'); return; }
        const isNew = this.conversationId() !== r.conversation_id;
        this.conversationId.set(r.conversation_id);
        this.turns.update(t => [...t, r.turn]);
        if (isNew) this.loadConversations();
        this.scroll();
      },
      error: e => {
        this.pending.set(null);
        this.input = message;
        this.error.set(e?.error?.message || 'The copilot is not reachable. Try again.');
      },
    });
  }

  onKey(ev: KeyboardEvent) {
    if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); this.send(); }
  }

  openReport(id: string) {
    window.open(this.siem.copilotReportUrl(id), '_blank', 'noopener');
  }

  private scroll() {
    setTimeout(() => this.thread?.nativeElement.scrollTo({ top: this.thread.nativeElement.scrollHeight, behavior: 'smooth' }), 50);
  }

  /** The answer's markdown (headings, tables, bold, italics, inline code, lists, line breaks) after escaping. */
  render(md: string): string {
    const esc = (md || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const inline = (s: string) => s
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[\s(])[*_]([^*_\s][^*_]*?)[*_](?=[\s).,;:!?]|$)/g, '$1<em>$2</em>')
      .replace(/`([^`]+)`/g, '<code>$1</code>');
    let html = '', list = false, table = 0; // table: rows written so far
    for (const raw of esc.split('\n')) {
      const item = /^\s*[-*•]\s+(.*)$/.exec(raw);
      const row = /^\s*\|(.*)\|\s*$/.exec(raw);
      if (list && !item) { html += '</ul>'; list = false; }
      if (table && !row) { html += '</tbody></table></div>'; table = 0; }
      if (row) {
        if (/^[\s|:-]+$/.test(row[1])) continue; // the |---| line under the header
        const cells = row[1].split('|').map(c => inline(c.trim()));
        html += table ? `<tr>${cells.map(c => `<td>${c}</td>`).join('')}</tr>`
          : `<div class="md-table"><table><thead><tr>${cells.map(c => `<th>${c}</th>`).join('')}</tr></thead><tbody>`;
        table++;
        continue;
      }
      const head = /^(#{1,4})\s+(.*)$/.exec(raw);
      if (head) { html += `<h${head[1].length + 2}>${inline(head[2])}</h${head[1].length + 2}>`; continue; }
      if (item && !list) { html += '<ul>'; list = true; }
      const text = inline(item ? item[1] : raw);
      html += item ? `<li>${text}</li>` : (text.trim() ? `<p>${text}</p>` : '');
    }
    return html + (list ? '</ul>' : '') + (table ? '</tbody></table></div>' : '');
  }

  sevClass(sev: string): string {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL': return 'sev sev-critical';
      case 'HIGH': return 'sev sev-high';
      case 'MEDIUM': return 'sev sev-medium';
      default: return 'sev sev-low';
    }
  }

  toolLabel(t: string): string {
    return ({
      search_alerts: 'Searched alerts', search_events: 'Searched logs', agent_info: 'Read agents', get_alert: 'Read alert', alert_stats: 'Counted alerts', investigate: 'Investigated',
      create_case: 'Opened case', investigate_case: 'Investigated case', add_case_note: 'Added note', make_report: 'Wrote report',
      case_info: 'Read case', set_verdict: 'Set disposition',
    } as Record<string, string>)[t] || t;
  }

  verdictClass(label: string): string {
    if (label === 'compromised' || label === 'malicious') return 'verdict verdict-bad';
    if (label === 'attack_attempt') return 'verdict verdict-warn';
    if (label === 'likely_benign') return 'verdict verdict-ok';
    return 'verdict verdict-review';
  }
}
