import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
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

/** A log source that sends with an ingest key (Beats, Windows Event Collector, REST). */
interface IngestSource {
  source_id:  string;
  name:       string;
  active:     boolean;
  created_at: string;
}

/**
 * The tenant's log sources: its ProVigil agents and syslog devices, with their
 * real event rate. Sources are added by deploying an agent, registering a
 * syslog device, or creating an ingest key (Beats, Windows Event Collector, REST).
 */
@Component({
  selector: 'app-siem-sources',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink, LucideAngularModule],
  templateUrl: './siem-sources.html',
  styleUrl: './siem-sources.css',
})
export class SiemSources implements OnInit {
  sources   = signal<SiemSource[]>([]);
  loading   = signal(true);
  error     = signal<string | null>(null);
  showModal = signal(false);
  /** Ingest-key sources: listed for tenant admins (the server refuses others). */
  ingest      = signal<IngestSource[]>([]);
  canIngest   = signal(false);
  beatsPort   = signal(9201);
  newName     = '';
  created     = signal<{ key: string; name: string } | null>(null);
  ingestError = signal<string | null>(null);
  readonly host = location.hostname;

  readonly PlusIcon    = Plus;
  readonly RadioIcon   = Radio;
  readonly RefreshIcon = RefreshCw;
  readonly OkIcon      = CheckCircle;
  readonly ErrIcon     = XCircle;
  readonly WarnIcon    = AlertTriangle;

  constructor(private http: HttpClient) {}

  ngOnInit() { this.load(); this.loadIngest(); }

  load() {
    this.loading.set(true);
    this.error.set(null);
    this.http.get<{ sources: SiemSource[] }>('/api/siem/sources').subscribe({
      next: res => { this.sources.set(res.sources ?? []); this.loading.set(false); },
      error: () => { this.error.set('Failed to load sources'); this.loading.set(false); }
    });
  }

  openModal()  { this.showModal.set(true); }
  closeModal() { this.showModal.set(false); this.created.set(null); this.ingestError.set(null); }

  loadIngest() {
    this.http.get<{ sources: IngestSource[]; beats_port: number }>('/api/siem/ingest-keys').subscribe({
      next: res => { this.ingest.set(res.sources ?? []); this.beatsPort.set(res.beats_port || 9201); this.canIngest.set(true); },
      error: () => this.canIngest.set(false),
    });
  }

  createKey() {
    const name = this.newName.trim();
    if (!name) return;
    this.ingestError.set(null);
    this.http.post<{ key: string; name: string; beats_port: number }>('/api/siem/ingest-keys', { name }).subscribe({
      next: res => { this.created.set({ key: res.key, name: res.name }); this.newName = ''; this.loadIngest(); },
      error: e => this.ingestError.set(e?.error?.error || 'The key could not be created'),
    });
  }

  revoke(src: IngestSource) {
    if (!confirm(`Revoke the key of "${src.name}"? That source stops being able to send logs.`)) return;
    this.http.delete(`/api/siem/ingest-keys/${encodeURIComponent(src.source_id)}`).subscribe({ next: () => this.loadIngest() });
  }

  copy(text: string) { navigator.clipboard?.writeText(text); }

  winlogbeatConfig(key: string): string {
    return `output.elasticsearch:\n  hosts: ["http://${this.host}:${this.beatsPort()}"]\n  headers:\n    Authorization: "Bearer ${key}"`;
  }

  restExample(key: string): string {
    return `curl -X POST https://${this.host}/api/siem/ingest -H "Authorization: Bearer ${key}" -H "Content-Type: application/json" -d '{"source_type":"syslog","raw_log":"<your log line>"}'`;
  }

  statusIcon(s: string) {
    return s === 'active' ? this.OkIcon : s === 'error' ? this.ErrIcon : this.WarnIcon;
  }

  statusClass(s: string): string {
    return ({ active: 'status-ok', error: 'status-err', paused: 'status-warn' } as any)[s] ?? 'status-warn';
  }

  sourceTypeLabel(t: string): string {
    return ({ windows: 'ProVigil agent (Windows)', linux: 'ProVigil agent (Linux)', macos: 'ProVigil agent (macOS)', network: 'Syslog device' } as Record<string, string>)[t] ?? t;
  }
}
