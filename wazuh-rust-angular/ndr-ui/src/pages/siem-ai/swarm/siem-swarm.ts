import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Share2, RefreshCw } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { SwarmText } from './swarm-text';

/**
 * Swarm Matches: this tenant's alerts whose attacker IP, malicious file or attack
 * chain other organisations in the threat swarm saw too (siem-api /api/v1/swarm).
 */
@Component({
  selector: 'app-siem-swarm',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './siem-swarm.html',
})
export class SiemSwarm implements OnInit {
  private siem = inject(SiemService);

  ShareIcon = Share2;
  RefreshIcon = RefreshCw;
  t = SwarmText;

  status = signal<any>(null);
  matches = signal<any[]>([]);
  loading = signal(false);
  error = signal<string | null>(null);

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getSwarmStatus().subscribe({ next: s => this.status.set(s), error: () => {} });
    this.siem.getSwarmMatches().subscribe({
      next: r => {
        this.loading.set(false);
        this.error.set(null);
        this.matches.set((r.matches ?? []).sort((a: any, b: any) => b.seen_at - a.seen_at));
      },
      error: e => { this.loading.set(false); this.error.set(e?.status === 403 ? 'You do not have access to SIEM alerts.' : 'Swarm matches are not available.'); },
    });
  }
}
