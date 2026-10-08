import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Zap, RefreshCw, ShieldAlert, ShieldCheck, Play, Trash2, Clock
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { ActiveResponseRecord } from '../../../services/siem/siem.models';

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
  targetIp = signal<string>('198.51.100.42');
  durationSeconds = signal<number>(3600);
  reason = signal<string>('SOC Analyst manual containment: Suspicious SSH activity');

  ngOnInit() {
    this.loadRecords();
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
    if (!ip) return;
    this.isBlocking.set(true);
    this.siem.blockIp(ip, this.durationSeconds(), this.reason()).subscribe({
      next: () => {
        this.isBlocking.set(false);
        this.loadRecords();
      },
      error: () => {
        this.isBlocking.set(false);
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
