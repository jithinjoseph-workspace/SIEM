import { Component, OnDestroy, OnInit, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';

/** GET /api/v1/manager/status: the Wazuh manager's daemons and the remoted / analysisd state files. */
interface ManagerStatus {
  enabled: boolean;
  daemons: { name: string; pid: number }[];
  remoted: Record<string, number | string>;
  analysisd: Record<string, number | string>;
  agents: { total: number; active: number };
}

@Component({
  selector: 'app-siem-manager',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './siem-manager.html',
})
export class SiemManager implements OnInit, OnDestroy {
  private http = inject(HttpClient);
  status = signal<ManagerStatus | null>(null);
  error = signal<string | null>(null);
  /** Events per second from the last two readings. */
  eps = signal<number | null>(null);
  private last: { t: number; received: number } | null = null;
  private timer: any = null;

  num(group: 'remoted' | 'analysisd', key: string): number {
    const v = this.status()?.[group]?.[key];
    return typeof v === 'number' ? v : Number(v ?? 0) || 0;
  }

  /** remoted input queue fill, 0..100 */
  remotedQueue = computed(() => {
    const total = this.num('remoted', 'total_queue_size');
    return total ? Math.round((100 * this.num('remoted', 'queue_size')) / total) : 0;
  });

  /** analysisd queues (the *_queue_usage values are fractions 0..1). */
  analysisdQueues = computed(() => {
    const a = this.status()?.analysisd ?? {};
    return Object.keys(a)
      .filter(k => k.endsWith('_queue_usage'))
      .map(k => ({ name: k.replace('_queue_usage', '').replace(/_/g, ' '), pct: Math.round(100 * (Number(a[k]) || 0)) }));
  });

  ngOnInit() {
    this.load();
    this.timer = setInterval(() => this.load(), 5000);
  }

  ngOnDestroy() {
    clearInterval(this.timer);
  }

  load() {
    this.http.get<ManagerStatus>('/api/v1/manager/status').subscribe({
      next: (s) => {
        this.error.set(null);
        this.status.set(s);
        const received = Number(s.analysisd?.['events_received'] ?? 0) || 0;
        const now = Date.now();
        if (this.last && received >= this.last.received) {
          this.eps.set(Math.round((received - this.last.received) / ((now - this.last.t) / 1000)));
        }
        this.last = { t: now, received };
      },
      error: (e) => this.error.set(e?.status === 403 ? 'Only the platform admin can see the manager status.' : 'The manager status is not available.'),
    });
  }
}
