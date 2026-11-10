import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Shield, Search, RefreshCw, AlertTriangle, ExternalLink, X, Info
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { MitreTacticColumn, MitreTechniqueSummary } from '../../../services/siem/siem.models';

@Component({
  selector: 'app-mitre',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './mitre.html',
  styleUrl: './mitre.css',
})
export class MitreMatrix implements OnInit {
  private siem = inject(SiemService);

  // Icons
  ShieldIcon = Shield;
  SearchIcon = Search;
  RefreshIcon = RefreshCw;
  AlertIcon = AlertTriangle;
  ExternalIcon = ExternalLink;
  CloseIcon = X;
  InfoIcon = Info;

  // State
  matrix = signal<MitreTacticColumn[]>([]);
  loading = signal<boolean>(false);
  searchQuery = signal<string>('');
  selectedTechnique = signal<MitreTechniqueSummary | null>(null);
  /** Only the techniques the tenant's alerts hit. */
  onlyDetected = signal<boolean>(false);
  totalTechniques = signal<number>(0);
  totalAlerts = signal<number>(0);
  unmapped = signal<{ id: string; alert_count: number; max_level: number }[]>([]);
  detectedCount = computed(() => new Set(this.matrix().flatMap(c => c.techniques.filter(t => t.alert_count > 0).map(t => t.id))).size);

  filteredMatrix = computed(() => {
    const q = this.searchQuery().toLowerCase().trim();
    const only = this.onlyDetected();
    if (!q && !only) return this.matrix();
    return this.matrix().map(col => ({
      ...col,
      techniques: col.techniques.filter(t =>
        (!only || t.alert_count > 0) && (!q ||
        t.name.toLowerCase().includes(q) ||
        t.id.toLowerCase().includes(q) ||
        t.subtechniques.some(s => s.toLowerCase().includes(q)) ||
        t.description.toLowerCase().includes(q))
      )
    })).filter(col => col.techniques.length > 0);
  });

  ngOnInit() {
    this.loadMatrix();
  }

  loadMatrix() {
    this.loading.set(true);
    this.siem.getMitreMatrix().subscribe({
      next: (res) => {
        this.matrix.set(res.matrix);
        this.totalTechniques.set(res.total_techniques ?? 0);
        this.totalAlerts.set(res.total_mitre_alerts ?? 0);
        this.unmapped.set(res.unmapped ?? []);
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  selectTechnique(tech: MitreTechniqueSummary) {
    this.selectedTechnique.set(tech);
  }

  closeModal() {
    this.selectedTechnique.set(null);
  }
}
