import { Component, OnInit, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  AlertTriangle, RefreshCw, Play, ShieldAlert, CheckCircle2,
  Filter, Search, Bug, Database, Layers
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { AuthService } from '../../../services/auth/auth';
import { VulnerabilityDetectionItem } from '../../../services/siem/siem.models';

@Component({
  selector: 'app-vulnerabilities',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './vulnerabilities.html',
  styleUrl: './vulnerabilities.css',
})
export class Vulnerabilities implements OnInit {
  private siem = inject(SiemService);
  /** The CVE feed is shared by every tenant: platform admins replace it. */
  isPlatformAdmin = inject(AuthService).isAdmin();
  scanMessage = signal<string | null>(null);

  // Icons
  AlertIcon = AlertTriangle;
  RefreshIcon = RefreshCw;
  PlayIcon = Play;
  ShieldIcon = ShieldAlert;
  CheckIcon = CheckCircle2;
  FilterIcon = Filter;
  SearchIcon = Search;
  BugIcon = Bug;
  DbIcon = Database;
  LayersIcon = Layers;

  // State
  vulnItems = signal<VulnerabilityDetectionItem[]>([]);
  vulnStats = signal<{ total: number; critical: number; high: number; medium: number; low: number }>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  severityFilter = signal<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  searchQuery = signal<string>('');
  loading = signal<boolean>(false);
  isScanning = signal<boolean>(false);

  filteredVulns = computed(() => {
    let list = this.vulnItems();
    const sev = this.severityFilter();
    const q = this.searchQuery().toLowerCase().trim();

    if (sev !== 'all') {
      list = list.filter(v => v.severity.toLowerCase() === sev);
    }
    if (q) {
      list = list.filter(v =>
        v.cve.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.package_name.toLowerCase().includes(q) ||
        v.agent_id.toLowerCase().includes(q)
      );
    }
    return list;
  });

  ngOnInit() {
    this.loadVulnerabilities();
  }

  loadVulnerabilities() {
    this.loading.set(true);
    this.siem.getVulnerabilities().subscribe({
      next: (res) => {
        this.vulnItems.set(res.vulnerabilities);
        this.vulnStats.set({
          total: res.total,
          critical: res.critical_count,
          high: res.high_count,
          medium: res.medium_count,
          low: res.low_count
        });
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  triggerScanNow() {
    this.isScanning.set(true);
    this.scanMessage.set(null);
    this.siem.triggerVulnScan().subscribe({
      next: (r: any) => {
        this.isScanning.set(false);
        const skipped = (r?.agents_without_inventory || []).length;
        this.scanMessage.set(`✓ ${r?.scanned_agents ?? 0} agent(s) checked against the CVE feed` + (skipped ? `; ${skipped} without a package inventory yet` : ''));
        this.loadVulnerabilities();
      },
      error: (err) => {
        this.isScanning.set(false);
        this.scanMessage.set(`✗ ${err?.error?.message || 'scan failed'}`);
        this.loadVulnerabilities();
      }
    });
  }

  /** Replace the CVE feed with an uploaded JSON feed file. */
  uploadFeed(ev: Event) {
    const input = ev.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    file.text().then(text => {
      this.scanMessage.set('Importing the CVE feed…');
      this.siem.syncVulnerabilityFeed(text).subscribe({
        next: (r: any) => {
          this.scanMessage.set(`✓ ${r?.message || 'Feed imported'}`);
          input.value = '';
        },
        error: (err) => {
          this.scanMessage.set(`✗ ${err?.error?.message || 'import failed'}`);
          input.value = '';
        },
      });
    });
  }
}
