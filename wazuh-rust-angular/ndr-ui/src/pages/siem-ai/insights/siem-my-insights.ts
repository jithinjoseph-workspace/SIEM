import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Gauge, RefreshCw } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { InsightText } from './insight-text';

/**
 * My Workload & AI Use: the analyst's own numbers from the SIEM triage page and how
 * triage adapts for them (siem-api /api/v1/siem/insights/me, crate siem-analyst-insight).
 * Only the analyst and their tenant admin see these.
 */
@Component({
  selector: 'app-siem-my-insights',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './siem-my-insights.html',
})
export class SiemMyInsights implements OnInit {
  private siem = inject(SiemService);

  GaugeIcon = Gauge;
  RefreshIcon = RefreshCw;
  t = InsightText;

  data = signal<any>(null);
  error = signal<string | null>(null);
  loading = signal(false);

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getMyInsights().subscribe({
      next: r => { this.loading.set(false); this.error.set(null); this.data.set(r); },
      error: e => { this.loading.set(false); this.error.set(e?.error?.message || 'Insights are not available.'); },
    });
  }
}
