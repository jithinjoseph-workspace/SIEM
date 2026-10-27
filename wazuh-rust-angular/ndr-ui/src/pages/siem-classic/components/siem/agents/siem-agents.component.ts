import { Component, OnInit, inject, signal, computed, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, Server, Shield, Search, RefreshCw, CheckCircle, AlertTriangle, Monitor, HardDrive, Cpu, Terminal } from 'lucide-angular';
import { HttpClient } from '@angular/common/http';
import { SiemAgentsService } from '../../../services/siem/siem-agents.service';
import { Agent, AgentInventory, ScaCheckResult } from '../../../models/siem.models';

@Component({
  selector: 'app-siem-agents',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-agents.component.html',
  styleUrl: './siem-agents.component.css'
})
export class SiemAgentsComponent implements OnInit {
  private agentsService = inject(SiemAgentsService);
  private http = inject(HttpClient);

  @Input() compactMode = false;

  agents = signal<Agent[]>([]);
  loading = signal<boolean>(true);
  searchQuery = signal<string>('');
  osFilter = signal<'all' | 'windows' | 'linux' | 'macos'>('all');
  selectedAgent = signal<Agent | null>(null);
  activeTab = signal<'specs' | 'sca' | 'fim' | 'actions'>('specs');
  actionFeedback = signal<string | null>(null);
  /** The opened agent's latest SCA scan and FIM entries (wazuh-db). */
  sca = signal<{ policy_name?: string; policy_id?: string; score: number; passed: number; failed: number; checks: ScaCheckResult[] } | null>(null);
  fim = signal<{ total: number; entries: { full_path: string; type: string; date: string | null }[] } | null>(null);

  ServerIcon = Server;
  ShieldIcon = Shield;
  SearchIcon = Search;
  RefreshIcon = RefreshCw;
  CheckIcon = CheckCircle;
  AlertIcon = AlertTriangle;
  MonitorIcon = Monitor;
  HardDriveIcon = HardDrive;
  CpuIcon = Cpu;
  TerminalIcon = Terminal;

  filteredAgents = computed(() => {
    const query = this.searchQuery().toLowerCase().trim();
    const os = this.osFilter();
    return this.agents().filter(a => {
      const matchQuery = !query || a.name.toLowerCase().includes(query) || a.ip.includes(query) || a.id.toLowerCase().includes(query);
      const matchOs = os === 'all' || a.os_type === os;
      return matchQuery && matchOs;
    });
  });

  activeCount = computed(() => this.agents().filter(a => a.status === 'active').length);
  disconnectedCount = computed(() => this.agents().filter(a => a.status !== 'active').length);

  ngOnInit() {
    this.loadAgents();
  }

  loadAgents() {
    this.loading.set(true);
    this.agentsService.getAgents().subscribe({
      next: (data) => {
        this.agents.set(data);
        this.loading.set(false);
      },
      error: () => this.loading.set(false)
    });
  }

  selectAgent(agent: Agent) {
    this.selectedAgent.set(agent);
    this.activeTab.set('specs');
    this.sca.set(null);
    this.fim.set(null);
    const id = encodeURIComponent(agent.id);
    this.http.get<any>(`/api/v1/agents/${id}/sca`).subscribe({ next: r => this.selectedAgent()?.id === agent.id && this.sca.set(r), error: () => {} });
    this.http.get<any>(`/api/v1/agents/${id}/fim`).subscribe({ next: r => this.selectedAgent()?.id === agent.id && this.fim.set(r), error: () => {} });
  }

  closeModal() {
    this.selectedAgent.set(null);
  }

  executeAction(action: 'isolate_host' | 'block_ip' | 'restart_agent') {
    const agent = this.selectedAgent();
    if (!agent) return;
    const done = (m: string) => { this.actionFeedback.set(m); setTimeout(() => this.actionFeedback.set(null), 6000); };
    const failed = (e: any) => done(e?.error?.message || `The ${action.replace('_', ' ')} request failed.`);
    if (action === 'isolate_host') {
      if (!agent.ip || agent.ip === 'any' || agent.ip === '0.0.0.0') return done(`Agent ${agent.name} has no known IP address to isolate.`);
      if (!confirm(`Isolate ${agent.name} (${agent.ip}) from the network?`)) return;
      this.actionFeedback.set(`Isolating ${agent.ip}…`);
      this.http.post('/api/isolate', { target_ip: agent.ip, reason: `Agent ${agent.id} isolated from the agent list` })
        .subscribe({ next: () => done(`${agent.ip} isolated. Release it from SOAR > Isolations.`), error: failed });
      return;
    }
    let target = 'all';
    if (action === 'block_ip') {
      const ip = (prompt(`IP address to block on ${agent.name}:`) || '').trim();
      if (!ip) return;
      target = ip;
    }
    this.actionFeedback.set(`Sending ${action.replace('_', ' ')} to ${agent.name}…`);
    this.agentsService.sendAgentCommand(agent.id, action, target).subscribe({
      next: (r: any) => done(`✓ ${r?.message || 'Sent to ' + agent.name}`),
      error: failed
    });
  }
}
