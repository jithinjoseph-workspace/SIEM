import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { LucideAngularModule, Server } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { Agent } from '../../../services/siem/siem.models';
import { defaultManagerUrl } from '../../../services/siem/agent-deploy';
import { AgentDeploy } from '../../../components/agent-deploy/agent-deploy';

/**
 * Agent Deployment (tenant admin): enroll endpoint agents into this tenant, and
 * see the fleet. Analysts can do it too once given "Deploy Agents" on Users.
 */
@Component({
  selector: 'app-agent-deployment',
  standalone: true,
  imports: [CommonModule, RouterModule, LucideAngularModule, AgentDeploy],
  templateUrl: './agent-deployment.html',
})
export class AgentDeployment implements OnInit {
  private siem = inject(SiemService);
  ServerIcon = Server;

  agents = signal<Agent[]>([]);
  error = signal<string | null>(null);
  active = computed(() => this.agents().filter(a => a.status === 'active').length);

  /** The agent version this server publishes (`/api/server-info`). */
  published = signal<string | null>(null);
  /** Per agent: the last upgrade answer shown under it. */
  upgradeNote = signal<Record<string, string>>({});

  ngOnInit() {
    fetch(`${defaultManagerUrl()}/api/server-info`).then(r => r.ok ? r.json() : null)
      .then(i => this.published.set(i?.agent_version ?? null)).catch(() => {});
    this.load();
  }

  /** A ProVigil agent not on the published version. */
  outdated(a: Agent): boolean {
    const p = this.published();
    return !!p && (a.version || '').startsWith('ProVigil') && a.version !== `ProVigil v${p}`;
  }

  upgrade(a: Agent) {
    const p = this.published();
    if (!confirm(`Upgrade ${a.name} (${a.id}) to ProVigil v${p ?? 'the published version'}?

The agent installs it, restarts, and rolls back by itself if the new version does not start.`)) return;
    const note = (m: string) => this.upgradeNote.update(n => ({ ...n, [a.id]: m }));
    note('Sending…');
    this.siem.upgradeAgent(a.id, {}).subscribe({
      next: r => {
        note(r?.status === 'queued' ? 'Sent: installs with the next keepalive, then restarts (1–2 min).' : (r?.message || 'Sent.'));
        // the new version shows once the agent is back
        setTimeout(() => this.load(), 120_000);
      },
      error: e => note('✗ ' + (e?.error?.message || e?.error?.error || 'The upgrade could not be sent.')),
    });
  }

  load() {
    this.siem.getAgents().subscribe({
      next: list => this.agents.set([...list].sort((a, b) => a.name.localeCompare(b.name))),
      error: () => this.error.set('The agent list is not available.'),
    });
  }

  when(s?: string) {
    if (!s) return '—';
    const d = new Date(s);
    return isNaN(d.getTime()) ? s : d.toLocaleString();
  }
}
