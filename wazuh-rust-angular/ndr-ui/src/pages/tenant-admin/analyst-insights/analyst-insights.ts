import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Gauge, RefreshCw } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { InsightText } from '../../siem-ai/insights/insight-text';

/**
 * Analyst Insights (tenant admin): each analyst's workload and use of AI suggestions
 * on SIEM Alert Triage, and the switch for the whole feature. The tenant admin sees
 * their own tenant only; the platform super admin does not see this data
 * (siem-api /api/v1/siem/insights/team, /settings).
 */
@Component({
  selector: 'app-analyst-insights',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './analyst-insights.html',
})
export class AnalystInsights implements OnInit {
  private siem = inject(SiemService);

  GaugeIcon = Gauge;
  RefreshIcon = RefreshCw;
  t = InsightText;

  analysts = signal<any[]>([]);
  enabled = signal(true);
  loading = signal(false);
  saving = signal(false);
  error = signal<string | null>(null);

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.getTeamInsights().subscribe({
      next: r => {
        this.loading.set(false);
        this.error.set(null);
        this.enabled.set(r.settings?.enabled ?? true);
        // the analysts who need attention first
        const rank = (c: any) => (c.trust === 'over_reliance' ? 0 : c.workload !== 'normal' ? 1 : c.trust === 'under_use' ? 2 : 3);
        this.analysts.set((r.analysts ?? []).sort((a: any, b: any) => rank(a) - rank(b)));
      },
      error: e => { this.loading.set(false); this.error.set(e?.error?.message || 'Analyst insights are not available.'); },
    });
  }

  toggle() {
    const next = !this.enabled();
    if (!next && !confirm('Turn off analyst insights? Activity stops being recorded and triage stops adapting to each analyst.')) return;
    this.saving.set(true);
    this.siem.putInsightSettings(next).subscribe({
      next: () => { this.saving.set(false); this.load(); },
      error: e => { this.saving.set(false); this.error.set(e?.error?.message || 'The setting could not be saved.'); },
    });
  }
}
