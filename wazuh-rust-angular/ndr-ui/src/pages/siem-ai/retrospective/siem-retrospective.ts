import { Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, RotateCcw, Play, RefreshCw } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

interface Scan {
  id: string;
  rule_id: string;
  rule_name: string;
  rule_content: string;
  hours_back: number;
  status: 'running' | 'done' | 'failed';
  started_at: string;
  completed_at: string | null;
  match_count: number;
  events_scanned: number;
  error?: string;
  matches?: any[];
}

/**
 * SIEM Retrospective: would a Wazuh rule have caught anything in the last hours?
 * The tenant's stored events go again through the running analysisd (the current
 * ruleset decides), or are searched for a keyword (siem-api
 * /api/v1/siem/retrospective, crate siem-retro).
 */
@Component({
  selector: 'app-siem-retrospective',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-retrospective.html',
})
export class SiemRetrospective implements OnInit, OnDestroy {
  private siem = inject(SiemService);

  RetroIcon = RotateCcw;
  PlayIcon = Play;
  RefreshIcon = RefreshCw;

  rules = signal<{ id: string; name: string; hit_count: number }[]>([]);
  scans = signal<Scan[]>([]);
  selected = signal<Scan | null>(null);
  error = signal<string | null>(null);
  message = signal<string | null>(null);
  starting = signal(false);
  mode: 'rule' | 'keyword' = 'rule';
  ruleId = '';
  keyword = '';
  hours = 24;
  hourChoices = [24, 48, 72, 168];
  private timer: any = null;

  running = computed(() => this.scans().some(s => s.status === 'running'));

  ngOnInit() {
    this.siem.getSiemFiredRules().subscribe({ next: r => this.rules.set(r.rules ?? []) });
    this.loadScans();
    this.timer = setInterval(() => { if (this.running()) this.loadScans(); }, 3000);
  }

  ngOnDestroy() {
    clearInterval(this.timer);
  }

  loadScans() {
    this.siem.listSiemRetroScans().subscribe({
      next: r => {
        const list: Scan[] = (r.scans ?? []).sort((a: Scan, b: Scan) => b.started_at.localeCompare(a.started_at));
        this.scans.set(list);
        const sel = this.selected();
        if (sel) {
          const now = list.find(s => s.id === sel.id);
          if (now && now.status !== sel.status) this.open(now, true);
        }
      },
      error: e => this.error.set(e?.status === 403 ? 'You do not have access to SIEM rules.' : 'Scans are not available.'),
    });
  }

  start() {
    const rule = this.ruleId.trim();
    if (this.mode === 'rule' && !/^\d+$/.test(rule)) {
      this.error.set('Pick a rule or type a Wazuh rule id (a number).');
      return;
    }
    if (this.mode === 'keyword' && this.keyword.trim().length < 3) {
      this.error.set('Type a keyword of at least 3 characters.');
      return;
    }
    const name = this.rules().find(r => r.id === rule)?.name ?? `Rule ${rule}`;
    this.starting.set(true);
    this.error.set(null);
    this.siem.startSiemRetroScan({
      rule_id: this.mode === 'rule' ? rule : '',
      rule_name: this.mode === 'rule' ? name : '',
      rule_content: this.mode === 'keyword' ? this.keyword.trim() : '',
      hours_back: this.hours,
    }).subscribe({
      next: r => {
        this.starting.set(false);
        if (r?.status === 'error') {
          this.error.set(r.message);
          return;
        }
        this.message.set('Scan started; results appear below.');
        setTimeout(() => this.message.set(null), 4000);
        this.loadScans();
      },
      error: () => { this.starting.set(false); this.error.set('The scan could not be started.'); },
    });
  }

  open(s: Scan, refresh = false) {
    if (!refresh && this.selected()?.id === s.id) {
      this.selected.set(null);
      return;
    }
    this.selected.set(s);
    if (s.status === 'running') return;
    this.siem.getSiemRetroScan(s.id).subscribe({ next: r => { if (r.scan) this.selected.set(r.scan); } });
  }

  title(s: Scan): string {
    return s.rule_id ? (s.rule_name || `Rule ${s.rule_id}`) : `Keyword: ${s.rule_content}`;
  }

  when(t: string | null): string {
    return t ? new Date(t).toLocaleString() : '—';
  }

  sevClass(s: string): string {
    return s === 'CRITICAL' ? 'text-rose-300' : s === 'HIGH' ? 'text-orange-300' : s === 'MEDIUM' ? 'text-amber-300' : 'text-slate-300';
  }
}
