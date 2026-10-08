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

  filteredMatrix = computed(() => {
    const list = this.matrix();
    const q = this.searchQuery().toLowerCase().trim();
    if (!q) return list;

    return list.map(col => ({
      ...col,
      techniques: col.techniques.filter(t =>
        t.name.toLowerCase().includes(q) ||
        t.id.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q)
      )
    }));
  });

  ngOnInit() {
    this.loadMatrix();
  }

  loadMatrix() {
    this.loading.set(true);
    this.siem.getMitreMatrix().subscribe({
      next: (res) => {
        this.matrix.set(res.matrix);
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
