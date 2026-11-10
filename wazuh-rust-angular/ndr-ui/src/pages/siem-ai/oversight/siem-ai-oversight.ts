import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { SiemDecisions } from '../decisions/siem-decisions';
import { SiemMyInsights } from '../insights/siem-my-insights';
import { SiemMemory } from '../memory/siem-memory';

type Tab = 'decisions' | 'usage' | 'memory';

/**
 * AI Oversight: what the AI decided and on what evidence (Decision Audit), how the
 * analyst uses its suggestions (My AI Use) and what the team decided before
 * (Security Memory), on one page. ?tab= selects one (the old pages redirect here).
 */
@Component({
  selector: 'app-siem-ai-oversight',
  standalone: true,
  imports: [SiemDecisions, SiemMyInsights, SiemMemory],
  template: `
    <div class="px-4 sm:px-6 pt-5 w-full max-w-[1400px] mx-auto">
      <nav class="flex gap-1 overflow-x-auto border-b border-slate-800" role="tablist" aria-label="AI oversight">
        @for (t of tabs; track t.id) {
          <button type="button" role="tab" [attr.aria-selected]="tab() === t.id" (click)="select(t.id)"
            class="px-4 py-2.5 text-sm font-medium border-b-2 whitespace-nowrap transition"
            [class.border-cyan-400]="tab() === t.id" [class.text-cyan-300]="tab() === t.id"
            [class.border-transparent]="tab() !== t.id" [class.text-slate-400]="tab() !== t.id">{{ t.label }}</button>
        }
      </nav>
    </div>
    @switch (tab()) {
      @case ('decisions') { <app-siem-decisions></app-siem-decisions> }
      @case ('usage') { <app-siem-my-insights></app-siem-my-insights> }
      @case ('memory') { <app-siem-memory></app-siem-memory> }
    }
  `,
})
export class SiemAiOversight {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  readonly tabs: { id: Tab; label: string }[] = [
    { id: 'decisions', label: 'AI Decision Audit' },
    { id: 'usage', label: 'My Workload & AI Use' },
    { id: 'memory', label: 'Security Memory' },
  ];
  tab = signal<Tab>((['decisions', 'usage', 'memory'] as Tab[]).find(t => t === this.route.snapshot.queryParamMap.get('tab')) ?? 'decisions');

  select(t: Tab) {
    this.tab.set(t);
    this.router.navigate([], { relativeTo: this.route, queryParams: { tab: t }, replaceUrl: true });
  }
}
