import { Component, OnDestroy, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';

/** GET /api/cluster/nodes: the AI and data lake boxes joined to this master (specs/provigil-nodes.md). */
export interface ClusterNode {
  id: string;
  name: string;
  role: 'ai' | 'datalake';
  address: string;
  platform: string;
  version: string;
  cpus: number;
  mem_total: number;
  disk_total: number;
  joined: number;
  state: 'joining' | 'ready' | 'down';
  last_seen: number | null;
  mem_used: number | null;
  disk_used: number | null;
  load: number | null;
  detail: { service_up?: boolean } | null;
}

@Component({
  selector: 'app-nodes',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './nodes.html',
})
export class Nodes implements OnInit, OnDestroy {
  private http = inject(HttpClient);
  nodes = signal<ClusterNode[]>([]);
  error = signal<string | null>(null);
  role = signal<'ai' | 'datalake' | ''>('ai');
  token = signal<{ token: string; role: string; expires: number } | null>(null);
  copied = signal(false);
  private timer: any = null;

  readonly master = window.location.origin;

  ngOnInit() {
    this.load();
    this.timer = setInterval(() => this.load(), 10000);
  }

  ngOnDestroy() {
    clearInterval(this.timer);
  }

  load() {
    this.http.get<{ nodes: ClusterNode[] }>('/api/cluster/nodes').subscribe({
      next: (r) => { this.error.set(null); this.nodes.set(r.nodes ?? []); },
      error: (e) => this.error.set(e?.status === 403 ? 'Only the platform admin can see the nodes.' : 'The node list is not available.'),
    });
  }

  addNode() {
    this.copied.set(false);
    this.http.post<{ token: string; role: string; expires: number }>('/api/cluster/tokens', { role: this.role() }).subscribe({
      next: (t) => this.token.set(t),
      error: (e) => this.error.set(e?.error?.message ?? 'The join token could not be created.'),
    });
  }

  /** The commands to run on the new box (as root). */
  command(): string {
    const t = this.token();
    if (!t) return '';
    const role = t.role || 'ai';
    return `sudo bash provigil-node.sh join --master ${this.master} --token ${t.token} --role ${role}\nsudo bash provigil-node.sh install-service`;
  }

  copy() {
    navigator.clipboard.writeText(this.command()).then(() => this.copied.set(true));
  }

  remove(n: ClusterNode) {
    if (!confirm(`Remove node ${n.name}? It stops being used and its key stops working.`)) return;
    this.http.delete(`/api/cluster/nodes/${encodeURIComponent(n.id)}`).subscribe({
      next: () => this.load(),
      error: () => this.error.set(`Node ${n.name} could not be removed.`),
    });
  }

  gb(bytes: number | null | undefined): string {
    return bytes == null ? '–' : (bytes / 1024 ** 3).toFixed(bytes >= 100 * 1024 ** 3 ? 0 : 1);
  }

  roleName(r: string): string {
    return r === 'datalake' ? 'Data lake' : r === 'ai' ? 'AI' : r;
  }

  ago(t: number | null): string {
    if (!t) return 'never';
    const s = Math.max(0, Math.round(Date.now() / 1000 - t));
    return s < 60 ? `${s} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
  }
}
