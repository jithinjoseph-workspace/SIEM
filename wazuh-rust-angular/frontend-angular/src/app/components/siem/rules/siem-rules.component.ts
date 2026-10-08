import { Component, OnInit, inject, signal, computed, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, ShieldAlert, Search, RefreshCw, Filter, Layers, Code } from 'lucide-angular';
import { SiemRulesService } from '../../../services/siem/siem-rules.service';
import { Rule } from '../../../models/siem.models';

@Component({
  selector: 'app-siem-rules',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-rules.component.html',
  styleUrl: './siem-rules.component.css'
})
export class SiemRulesComponent implements OnInit {
  private rulesService = inject(SiemRulesService);

  @Input() compactMode = false;

  rules = signal<Rule[]>([]);
  loading = signal<boolean>(true);
  searchQuery = signal<string>('');
  selectedLevel = signal<string>('all');
  selectedRule = signal<Rule | null>(null);

  ShieldAlertIcon = ShieldAlert;
  SearchIcon = Search;
  RefreshIcon = RefreshCw;
  FilterIcon = Filter;
  LayersIcon = Layers;
  CodeIcon = Code;

  filteredRules = computed(() => {
    const query = this.searchQuery().toLowerCase().trim();
    const lvl = this.selectedLevel();
    return this.rules().filter(r => {
      const matchQuery = !query ||
        r.id.toString().includes(query) ||
        r.description.toLowerCase().includes(query) ||
        r.groups.some(g => g.toLowerCase().includes(query)) ||
        (r.mitre && (r.mitre.id.toLowerCase().includes(query) || r.mitre.technique.toLowerCase().includes(query)));

      const matchLvl = lvl === 'all' ||
        (lvl === 'critical' && r.level >= 12) ||
        (lvl === 'high' && r.level >= 8 && r.level < 12) ||
        (lvl === 'medium' && r.level >= 4 && r.level < 8) ||
        (lvl === 'low' && r.level < 4);

      return matchQuery && matchLvl;
    });
  });

  ngOnInit() {
    this.loadRules();
  }

  loadRules() {
    this.loading.set(true);
    this.rulesService.getRules().subscribe({
      next: (data) => {
        this.rules.set(data);
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  selectRule(rule: Rule) {
    this.selectedRule.set(rule);
  }

  closeModal() {
    this.selectedRule.set(null);
  }

  getLevelClass(level: number): string {
    if (level >= 12) return 'lvl-critical';
    if (level >= 8) return 'lvl-high';
    if (level >= 4) return 'lvl-medium';
    return 'lvl-low';
  }
}
