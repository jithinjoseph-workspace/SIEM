import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  ShieldCheck, RefreshCw, CheckCircle2, AlertTriangle, XCircle, Info, Layers
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { ComplianceFramework } from '../../../services/siem/siem.models';

@Component({
  selector: 'app-compliance',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './compliance.html',
  styleUrl: './compliance.css',
})
export class Compliance implements OnInit {
  private siem = inject(SiemService);

  // Icons
  ShieldCheckIcon = ShieldCheck;
  RefreshIcon = RefreshCw;
  CheckIcon = CheckCircle2;
  AlertIcon = AlertTriangle;
  ErrorIcon = XCircle;
  InfoIcon = Info;
  LayersIcon = Layers;

  // State
  frameworks = signal<ComplianceFramework[]>([]);
  selectedFramework = signal<ComplianceFramework | null>(null);
  loading = signal<boolean>(false);

  ngOnInit() {
    this.loadCompliance();
  }

  loadCompliance() {
    this.loading.set(true);
    this.siem.getCompliance().subscribe({
      next: (res) => {
        this.frameworks.set(res.frameworks);
        if (res.frameworks.length > 0 && !this.selectedFramework()) {
          this.selectedFramework.set(res.frameworks[0]);
        }
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  selectFramework(fw: ComplianceFramework) {
    this.selectedFramework.set(fw);
  }
}
