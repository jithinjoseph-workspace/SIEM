import { Component, OnInit, inject, signal, computed, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, Server, Shield, Search, RefreshCw, CheckCircle, AlertTriangle, Monitor, HardDrive, Cpu, Terminal } from 'lucide-angular';
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

  @Input() compactMode = false;

  agents = signal<Agent[]>([]);
  loading = signal<boolean>(true);
  searchQuery = signal<string>('');
  osFilter = signal<'all' | 'windows' | 'linux' | 'macos'>('all');
  selectedAgent = signal<Agent | null>(null);
  activeTab = signal<'specs' | 'sca' | 'fim' | 'actions'>('specs');
  actionFeedback = signal<string | null>(null);

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
  }

  closeModal() {
    this.selectedAgent.set(null);
  }

  executeAction(action: string) {
    const agent = this.selectedAgent();
    if (!agent) return;
    this.actionFeedback.set(`Sending ${action} command to agent ${agent.name}...`);
    this.agentsService.sendAgentCommand(agent.id, action).subscribe({
      next: () => {
        this.actionFeedback.set(`✓ Command '${action}' successfully delivered to ${agent.id}`);
        setTimeout(() => this.actionFeedback.set(null), 3000);
      },
      error: () => {
        this.actionFeedback.set(`Command '${action}' queued.`);
        setTimeout(() => this.actionFeedback.set(null), 3000);
      }
    });
  }
}
