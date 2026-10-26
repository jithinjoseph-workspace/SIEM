import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LucideAngularModule, Lock } from 'lucide-angular';

export const ACTION_LABEL: Partial<Record<string, string>> = {
  block_ip: 'Block IP', manual_block: 'Manual block', suppress: 'Hide alerts', review: 'Review', policy_change: 'Policy change',
};

export const OUTCOME: Record<string, { label: string; cls: string }> = {
  allowed: { label: 'Allowed', cls: 'text-emerald-300 border-emerald-700 bg-emerald-950/40' },
  needs_approval: { label: 'Needs approval', cls: 'text-amber-300 border-amber-700 bg-amber-950/40' },
  denied: { label: 'Denied', cls: 'text-rose-300 border-rose-700 bg-rose-950/40' },
};

/** One decision's reasoning: the facts (by origin), every rule and comparison, and the hashes. */
@Component({
  selector: 'app-decision-detail',
  standalone: true,
  imports: [CommonModule, LucideAngularModule],
  template: `
    <div *ngIf="record as r" class="space-y-4 text-sm">
      <div class="flex flex-wrap items-center gap-2">
        <span class="px-2 py-0.5 rounded border text-xs font-semibold" [ngClass]="outcome(r.outcome).cls">{{ outcome(r.outcome).label }}</span>
        <span class="font-semibold text-white">{{ action(r.action) }}</span>
        <span class="font-mono text-cyan-300 break-all">{{ r.target }}</span>
        <span class="text-slate-500">· #{{ r.seq }} · {{ when(r.ts) }} · by {{ r.requested_by }}</span>
        <span *ngIf="verified !== undefined" class="ml-auto text-xs" [class.text-emerald-300]="!verified" [class.text-rose-300]="verified">
          {{ verified ? 'Fails verification: ' + verified : 'Re-derived and verified' }}
        </span>
      </div>
      <p class="text-slate-200">{{ r.summary }}</p>

      <div>
        <h3 class="text-xs font-bold uppercase text-slate-400 mb-1">Evidence (facts)</h3>
        <table class="w-full text-xs">
          <tbody>
            <tr *ngFor="let f of facts(r)" class="border-t border-slate-800/60 align-top">
              <td class="py-1 pr-2 font-mono text-slate-300 whitespace-nowrap">{{ f.key }}</td>
              <td class="py-1 pr-2 font-mono text-white break-all">{{ show(f.value.value) }}</td>
              <td class="py-1 pr-2"><span class="px-1.5 rounded border text-[10px] uppercase" [ngClass]="originCls(f.value.origin)">{{ f.value.origin }}</span></td>
              <td class="py-1 text-slate-500">{{ f.value.note }}</td>
            </tr>
          </tbody>
        </table>
        <p class="text-[11px] text-slate-500 mt-1">neural = an AI model's output · symbolic = fixed logic · context = from the alert or request · human = a person</p>
      </div>

      <div *ngIf="r.policy.length">
        <h3 class="text-xs font-bold uppercase text-slate-400 mb-1">Rules evaluated</h3>
        <div *ngFor="let p of r.policy; let i = index" class="border-t border-slate-800/60 py-1.5">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-mono text-slate-300">{{ p.id }}</span>
            <lucide-angular *ngIf="p.hard" [img]="LockIcon" class="w-3 h-3 text-slate-400" aria-label="hard guardrail"></lucide-angular>
            <span class="text-slate-200">{{ p.title }}</span>
            <span class="text-[11px] text-slate-500">→ {{ effect(p.effect) }}</span>
            <span class="ml-auto text-xs font-semibold" [ngClass]="stepCls(r.steps[i], p.effect)">{{ stepLabel(r.steps[i], p.effect) }}</span>
          </div>
          <div class="font-mono text-[11px] text-slate-400 pl-4">
            <span *ngFor="let c of r.steps[i].checks; let last = last">
              {{ c.fact }} {{ c.op }} {{ show(c.expected) }} <span class="text-slate-500">(is {{ c.actual === null || c.actual === undefined ? 'missing' : show(c.actual) }})</span>
              <span [class.text-emerald-400]="c.holds" [class.text-slate-500]="!c.holds">{{ c.holds ? '✓' : '✗' }}</span><span *ngIf="!last"> · </span>
            </span>
          </div>
          <div *ngIf="p.reference" class="text-[10px] text-slate-500 pl-4">{{ p.reference }}</div>
        </div>
      </div>

      <div class="font-mono text-[10px] text-slate-500 break-all space-y-0.5">
        <div *ngIf="r.policy_hash">policy {{ r.policy_hash }}</div>
        <div>prev {{ r.prev_hash || '(first record)' }}</div>
        <div>hash {{ r.hash }}</div>
        <div *ngIf="r.ref_id">reviews {{ r.ref_id }}</div>
      </div>
    </div>
  `,
})
export class DecisionDetail {
  @Input() record: any;
  /** null = verified; a string = why it fails; undefined = not checked. */
  @Input() verified?: string | null;
  LockIcon = Lock;

  action(a: string) { return ACTION_LABEL[a] ?? a; }
  outcome(o: string) { return OUTCOME[o] ?? { label: o, cls: '' }; }
  effect(e: string) { return e === 'deny' ? 'deny' : e === 'require_approval' ? 'needs approval' : 'allow'; }
  facts(r: any) { return Object.entries(r.facts ?? {}).map(([key, value]) => ({ key, value: value as any })); }
  show(v: any) { return typeof v === 'string' ? `"${v}"` : String(v); }
  when(ts: number) { return new Date(ts * 1000).toLocaleString(); }
  originCls(o: string) {
    return o === 'neural' ? 'text-fuchsia-300 border-fuchsia-800' : o === 'symbolic' ? 'text-cyan-300 border-cyan-800' : o === 'human' ? 'text-amber-300 border-amber-800' : 'text-slate-300 border-slate-700';
  }
  stepLabel(s: any, effect: string) { return s.matched ? (effect === 'deny' ? 'fired: deny' : effect === 'require_approval' ? 'fired: approval' : 'fired') : s.incomplete ? 'missing evidence' : 'passed'; }
  stepCls(s: any, effect: string) { return s.matched ? (effect === 'deny' ? 'text-rose-300' : 'text-amber-300') : s.incomplete ? 'text-amber-300' : 'text-emerald-400'; }
}
