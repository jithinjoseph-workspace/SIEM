import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, Brain, Search } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';

/**
 * Security Memory: the tenant's past investigations and analyst decisions (closed
 * cases, triage decisions) with their reasons, kept 7 years, so the knowledge
 * stays when people leave (siem-api /api/v1/siem/memory, crate siem-org-memory).
 */
@Component({
  selector: 'app-siem-memory',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-memory.html',
})
export class SiemMemory implements OnInit {
  private siem = inject(SiemService);

  BrainIcon = Brain;
  SearchIcon = Search;

  data = signal<any>(null);
  loading = signal(false);
  error = signal<string | null>(null);
  q = '';
  outcome = '';
  outcomes = [
    ['', 'All'],
    ['true_positive', 'Confirmed incidents'],
    ['false_positive', 'False positives'],
    ['benign', 'Hidden as noise'],
    ['kept_for_review', 'Kept for review'],
    ['resolved', 'Closed'],
  ];

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading.set(true);
    this.siem.searchSecurityMemory(this.q.trim(), this.outcome).subscribe({
      next: r => { this.loading.set(false); this.error.set(null); this.data.set(r); },
      error: e => { this.loading.set(false); this.error.set(e?.status === 403 ? 'You do not have access to SIEM alerts.' : 'Security memory is not available.'); },
    });
  }

  pick(o: string) {
    this.outcome = o;
    this.load();
  }

  when(ts: number): string {
    return ts ? new Date(ts * 1000).toLocaleDateString() : '—';
  }

  outcomeClass(o: string): string {
    return o === 'true_positive' ? 'border-rose-800 text-rose-300' : o === 'false_positive' || o === 'benign' ? 'border-emerald-800 text-emerald-300' : 'border-slate-700 text-slate-300';
  }
}
