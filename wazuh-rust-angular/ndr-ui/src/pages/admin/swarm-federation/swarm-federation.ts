import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SiemService } from '../../../services/siem/siem.service';

/**
 * Swarm Federation (super admin): join a threat-swarm hub, and/or run this
 * deployment as a hub for others (member tokens). Tenants still opt in one by
 * one (siem-api /api/v1/swarm/config, /members, /sync).
 */
@Component({
  selector: 'app-swarm-federation',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './swarm-federation.html',
})
export class SwarmFederation implements OnInit {
  private siem = inject(SiemService);

  cfg = signal<any>(null);
  members = signal<any[]>([]);
  error = signal<string | null>(null);
  message = signal<string | null>(null);
  newToken = signal<string | null>(null);
  saving = signal(false);
  form = { enabled: false, hub_url: '', member_token: '', community_key: '', epsilon: 1, hub_enabled: false, k: 2, fast_track_critical: true };
  memberName = '';

  ngOnInit() {
    this.load();
  }

  load() {
    this.siem.getSwarmConfig().subscribe({
      next: r => {
        const c = r.config;
        this.cfg.set(c);
        this.members.set(r.members ?? []);
        this.form = { enabled: c.enabled, hub_url: c.hub_url, member_token: '', community_key: '', epsilon: c.epsilon, hub_enabled: c.hub_enabled, k: c.k, fast_track_critical: c.fast_track_critical };
      },
      error: e => this.error.set(e?.error?.message || 'The federation settings are not available.'),
    });
  }

  private ok(m: string) {
    this.error.set(null);
    this.message.set(m);
    setTimeout(() => this.message.set(null), 5000);
  }

  save() {
    this.saving.set(true);
    this.siem.putSwarmConfig(this.form).subscribe({
      next: () => { this.saving.set(false); this.ok('Saved.'); this.load(); },
      error: e => { this.saving.set(false); this.error.set(e?.error?.message || 'Could not save.'); },
    });
  }

  generateKey() {
    const b = new Uint8Array(24);
    crypto.getRandomValues(b);
    this.form.community_key = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
  }

  addMember() {
    if (!this.memberName.trim()) return;
    this.siem.addSwarmMember(this.memberName.trim()).subscribe({
      next: r => { this.newToken.set(`${r.name}: ${r.token}`); this.memberName = ''; this.load(); },
      error: e => this.error.set(e?.error?.message || 'Could not add the member.'),
    });
  }

  removeMember(m: any) {
    if (!confirm(`Remove ${m.name}? Its token stops working.`)) return;
    this.siem.removeSwarmMember(m.id).subscribe({ next: () => this.load() });
  }

  syncNow() {
    this.siem.syncSwarm().subscribe({
      next: r => r.status === 'ok' ? this.ok(`Round done: ${r.sent} sent, ${r.feed} in the feed, ${r.matched} match(es).`) : this.error.set(r.message),
      error: () => this.error.set('The round failed.'),
    });
  }

  when(ts: number): string {
    return ts ? new Date(ts * 1000).toLocaleString() : 'never';
  }
}
