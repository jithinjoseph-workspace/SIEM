import { Component, OnInit, signal, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  FileCheck, RefreshCw, FileText, Plus, Edit, Trash2, Shield
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { FimSummaryRecord } from '../../../services/siem/siem.models';

@Component({
  selector: 'app-fim',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './fim.html',
  styleUrl: './fim.css',
})
export class Fim implements OnInit {
  private siem = inject(SiemService);

  // Icons
  FileCheckIcon = FileCheck;
  RefreshIcon = RefreshCw;
  FileTextIcon = FileText;
  PlusIcon = Plus;
  EditIcon = Edit;
  TrashIcon = Trash2;
  ShieldIcon = Shield;

  // State
  records = signal<FimSummaryRecord[]>([]);
  stats = signal<{ total: number; added: number; modified: number; deleted: number }>({
    total: 0,
    added: 0,
    modified: 0,
    deleted: 0
  });
  loading = signal<boolean>(false);

  ngOnInit() {
    this.loadFim();
  }

  loadFim() {
    this.loading.set(true);
    this.siem.getFimSummary().subscribe({
      next: (res) => {
        this.records.set(res.recent_changes);
        this.stats.set({
          total: res.total_monitored_files,
          added: res.added_count,
          modified: res.modified_count,
          deleted: res.deleted_count
        });
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }
}
