import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { LucideAngularModule, Plus, Radio, RefreshCw, CheckCircle, XCircle, AlertTriangle } from 'lucide-angular';

interface SiemSource {
  source_id:    string;
  name:         string;
  source_type:  string;
  status:       string;
  last_seen_at: string;
  /** Events per second over the last 5 minutes. */
  eps:          number;
}

/**
 * The tenant's log sources: its Wazuh agents and syslog devices, with their
 * real event rate. Sources are added by deploying an agent or registering a
 * syslog device; there is no other ingest path.
 */
@Component({
  selector: 'app-siem-sources',
  standalone: true,
  imports: [CommonModule, RouterLink, LucideAngularModule],
  templateUrl: './siem-sources.html',
  styleUrl: './siem-sources.css',
})
export class SiemSources implements OnInit {
  sources   = signal<SiemSource[]>([]);
  loading   = signal(true);
  error     = signal<string | null>(null);
  showModal = signal(false);

  readonly PlusIcon    = Plus;
  readonly RadioIcon   = Radio;
  readonly RefreshIcon = RefreshCw;
  readonly OkIcon      = CheckCircle;
  readonly ErrIcon     = XCircle;
  readonly WarnIcon    = AlertTriangle;

  constructor(private http: HttpClient) {}

  ngOnInit() { this.load(); }

  load() {
    this.loading.set(true);
    this.error.set(null);
    this.http.get<{ sources: SiemSource[] }>('/api/siem/sources').subscribe({
      next: res => { this.sources.set(res.sources ?? []); this.loading.set(false); },
      error: () => { this.error.set('Failed to load sources'); this.loading.set(false); }
    });
  }

  openModal()  { this.showModal.set(true); }
  closeModal() { this.showModal.set(false); }

  statusIcon(s: string) {
    return s === 'active' ? this.OkIcon : s === 'error' ? this.ErrIcon : this.WarnIcon;
  }

  statusClass(s: string): string {
    return ({ active: 'status-ok', error: 'status-err', paused: 'status-warn' } as any)[s] ?? 'status-warn';
  }

  sourceTypeLabel(t: string): string {
    return ({ windows: 'Wazuh agent (Windows)', linux: 'Wazuh agent (Linux)', macos: 'Wazuh agent (macOS)', network: 'Syslog device' } as Record<string, string>)[t] ?? t;
  }
}
