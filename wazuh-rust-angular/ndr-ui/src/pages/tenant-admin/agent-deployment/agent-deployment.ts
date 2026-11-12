import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, Server } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { Agent, TamperStatus } from '../../../services/siem/siem.models';
import { defaultManagerUrl, downloadText } from '../../../services/siem/agent-deploy';
import { AgentDeploy } from '../../../components/agent-deploy/agent-deploy';

/**
 * Agent Deployment (tenant admin): enroll endpoint agents into this tenant, and
 * see the fleet. Analysts can do it too once given "Deploy Agents" on Users.
 */
@Component({
  selector: 'app-agent-deployment',
  standalone: true,
  imports: [CommonModule, RouterModule, FormsModule, LucideAngularModule, AgentDeploy],
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

  /** Mass deployment: tokens a deployment kit enrolls PCs with (expire, limited, revocable). */
  tokens = signal<any[]>([]);
  tokenForm = { label: '', days: 7, max: 550, groups: '' };
  newToken = signal<string | null>(null);
  tokenError = signal<string | null>(null);
  /** The tenant's agent groups: a token may only name one that exists. */
  groupNames = signal<string[]>([]);
  newGroup = '';

  loadGroups() {
    this.siem.getGroups().subscribe(g => this.groupNames.set(g.map(x => x.name).filter(n => n !== 'default')));
  }

  createGroup() {
    const name = this.newGroup.trim();
    if (!name) return;
    this.tokenError.set(null);
    this.siem.createGroup(name).subscribe({
      next: () => { this.newGroup = ''; this.tokenForm.groups = name; this.loadGroups(); },
      error: e => this.tokenError.set(e?.error?.message || e?.error?.error || 'The group could not be created.'),
    });
  }

  loadTokens() {
    this.siem.deployTokens().subscribe({
      next: r => this.tokens.set(r?.tokens ?? []),
      error: e => this.tokenError.set(e?.status === 403 ? null : 'Deployment tokens are not available.'),
    });
  }

  createToken() {
    this.tokenError.set(null);
    this.siem.createDeployToken({ ...this.tokenForm, label: this.tokenForm.label.trim() }).subscribe({
      next: r => {
        if (r?.status !== 'ok') { this.tokenError.set(r?.message || 'The token was not created.'); return; }
        this.newToken.set(r.token);
        this.tokenForm.label = '';
        this.loadTokens();
      },
      error: e => this.tokenError.set(e?.error?.message || 'The token was not created.'),
    });
  }

  revokeToken(t: any) {
    if (!confirm(`Revoke "${t.label}"? No new PC can enroll with it; PCs already enrolled keep working.`)) return;
    this.siem.revokeDeployToken(t.id).subscribe({ next: () => this.loadTokens(), error: e => this.tokenError.set(e?.error?.message || 'Not revoked.') });
  }

  /** The kit (C8): built for the token just created, while the console still has it. */
  kitOptions = { sysmon: false, audit_policy: true, ps_logging: true };
  kitBusy = signal(false);

  downloadKit() {
    const token = this.newToken();
    if (!token) return;
    // the agents reach the gateway at the host this console is reached at; other PCs cannot reach "localhost"
    let host = location.hostname;
    if (/^(localhost|127\.|\[?::1\]?$)/.test(host)) {
      host = (prompt('This console is opened at localhost, which other PCs cannot reach. Enter the address (IP or name) the PCs reach this server at:') || '').trim();
      if (!host) return;
    }
    this.kitBusy.set(true);
    this.tokenError.set(null);
    this.siem.deployKit({ token, host, options: this.kitOptions }).subscribe({
      next: blob => {
        this.kitBusy.set(false);
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'ProVigilDeploy.zip';
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      },
      error: async e => {
        this.kitBusy.set(false);
        let m = 'The kit could not be built.';
        try { m = JSON.parse(await (e?.error as Blob).text())?.message || m; } catch { /* not JSON */ }
        this.tokenError.set(m);
      },
    });
  }

  /** Results of one deployment (C7): every PC its runs reported, and the agents it enrolled. */
  results = signal<{ token: any; targets: any[]; enrolled: any[] } | null>(null);
  resultFilter = signal('');
  shownTargets = computed(() => {
    const f = this.resultFilter();
    return (this.results()?.targets ?? []).filter(t => !f || t.outcome === f);
  });
  outcomes = computed(() => {
    const c: Record<string, number> = {};
    for (const t of this.results()?.targets ?? []) c[t.outcome] = (c[t.outcome] ?? 0) + 1;
    return Object.entries(c).sort((a, b) => b[1] - a[1]);
  });

  showResults(t: any) {
    this.resultFilter.set('');
    this.siem.deployTargets(t.id).subscribe({
      next: r => this.results.set({ token: r?.token ?? t, targets: r?.targets ?? [], enrolled: r?.enrolled ?? [] }),
      error: e => this.tokenError.set(e?.error?.message || 'The results are not available.'),
    });
  }

  exportResults() {
    const r = this.results();
    if (!r) return;
    const cols = ['computer', 'address', 'os', 'method', 'outcome', 'reason', 'agent_id', 'from', 'at'];
    const q = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const rows = r.targets.map(t => cols.map(c => q(c === 'at' ? new Date(t.at * 1000).toISOString() : t[c])).join(','));
    downloadText(`deployment-${r.token.label || r.token.id}.csv`.replace(/[^\w.-]+/g, '_'), [cols.join(','), ...rows].join('\r\n'), 'text/csv');
  }

  copyToken() {
    const t = this.newToken();
    if (t) navigator.clipboard?.writeText(t).catch(() => {});
  }

  /** Tamper protection: the tenant admin opens maintenance windows here (analysts cannot). */
  tamper = signal<TamperStatus | null>(null);
  tamperMinutes: Record<string, number | undefined> = {};
  tamperReason: Record<string, string> = {};
  tamperNote = signal<Record<string, string>>({});
  loadTamper() {
    this.siem.getTamper().subscribe({ next: t => this.tamper.set(t), error: () => this.tamper.set(null) });
  }
  tamperAction(agentId: string, name: string, action: 'lock' | 'maintenance') {
    const minutes = this.tamperMinutes[agentId] ?? 60;
    if (action === 'maintenance' && !confirm(`Open a ${minutes >= 1440 ? '24-hour' : minutes + '-minute'} maintenance window on ${name}?\n\nAdministrators on it can stop, change or remove the agent until the window ends. It is recorded as a decision.`)) return;
    const note = (m: string) => this.tamperNote.update(n => ({ ...n, [agentId]: m }));
    this.siem.tamperAgent(agentId, action, minutes, (this.tamperReason[agentId] ?? '').trim() || undefined).subscribe({
      next: r => { note(`✓ ${r.message}`); this.loadTamper(); },
      error: e => note(`✗ ${e?.error?.message || 'not sent'}`),
    });
  }

  ngOnInit() {
    this.loadTamper();
    this.loadTokens();
    this.loadGroups();
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

  when(s?: string | number) {
    if (!s) return '—';
    const d = new Date(s);
    return isNaN(d.getTime()) ? s : d.toLocaleString();
  }
}
