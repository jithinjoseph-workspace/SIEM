import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Zap, RefreshCw, ShieldAlert, ShieldCheck, Play, Trash2, Clock
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { ActiveResponseRecord, Agent } from '../../../services/siem/siem.models';

@Component({
  selector: 'app-active-response',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './active-response.html',
  styleUrl: './active-response.css',
})
export class ActiveResponse implements OnInit {
  private siem = inject(SiemService);

  // Icons
  ZapIcon = Zap;
  RefreshIcon = RefreshCw;
  ShieldAlertIcon = ShieldAlert;
  ShieldCheckIcon = ShieldCheck;
  PlayIcon = Play;
  TrashIcon = Trash2;
  ClockIcon = Clock;

  // State
  records = signal<ActiveResponseRecord[]>([]);
  totalActive = signal<number>(0);
  loading = signal<boolean>(false);
  isBlocking = signal<boolean>(false);

  // Form
  agents = signal<Agent[]>([]);
  agentId = signal<string>('');
  feedback = signal<string | null>(null);
  targetIp = signal<string>('');
  durationSeconds = signal<number>(3600);
  reason = signal<string>('SOC Analyst manual containment: Suspicious SSH activity');

  ngOnInit() {
    this.loadRecords();
    this.siem.getAgents().subscribe(list => {
      this.agents.set(list);
      if (!this.agentId() && list.length) this.agentId.set((list.find(a => a.status === 'active') || list[0]).id);
    });
  }

  /** Blocks sent to Wazuh agents expire on the agent; they cannot be removed earlier. */
  autoExpires(r: ActiveResponseRecord): boolean {
    return /^(firewall-drop|netsh)\d+$/.test((r as any).command || '');
  }

  loadRecords() {
    this.loading.set(true);
    this.siem.getActiveResponses().subscribe({
      next: (res) => {
        this.records.set(res.records);
        this.totalActive.set(res.active_blocks);
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  blockIp() {
    const ip = this.targetIp().trim();
    if (!ip || !this.agentId()) return;
    this.isBlocking.set(true);
    this.feedback.set(null);
    this.siem.blockIp(ip, +this.durationSeconds(), this.reason(), this.agentId()).subscribe({
      next: (r: any) => {
        this.isBlocking.set(false);
        this.feedback.set(`✓ ${r?.message || 'Block sent'}`);
        this.loadRecords();
      },
      error: (err) => {
        this.isBlocking.set(false);
        this.feedback.set(`✗ ${err?.error?.message || 'request failed'}`);
        this.loadRecords();
      }
    });
  }

  unblockIp(ip: string) {
    this.siem.unblockIp(ip).subscribe({
      next: () => this.loadRecords(),
      error: () => this.loadRecords()
    });
  }
}
