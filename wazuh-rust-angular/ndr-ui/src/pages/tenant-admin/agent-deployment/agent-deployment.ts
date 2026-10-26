import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { LucideAngularModule, Server } from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import { Agent } from '../../../services/siem/siem.models';
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

  ngOnInit() {
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
