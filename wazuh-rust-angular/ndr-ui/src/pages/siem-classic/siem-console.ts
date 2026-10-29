import { Component, OnInit, OnDestroy, inject, signal, computed } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { SiemService } from './core/services/siem.service';
import { Agent, Alert, RawEvent, Rule, SiemStats, AiAnalysisResponse, AiAnalysisRequest, AiChatMessage, ProcessNode } from './core/models/siem.models';
import { CyberThreatGlobeComponent } from './components/cyber-threat-globe/cyber-threat-globe.component';

/** The console's own tabs; agents, MITRE, vulnerabilities, compliance, FIM, logtest,
 *  active response and parsers are their own pages (the analyst menu). */
type ActiveTab = 'dashboard' | 'alerts' | 'telemetry' | 'rules' | 'simulator' | 'copilot';

/** Route path of each console tab (see app.routes.ts). */
export const CONSOLE_TAB_PATHS: Record<string, string> = {
  dashboard: 'overview', alerts: 'alerts', telemetry: 'telemetry', rules: 'rules', simulator: 'simulator', copilot: 'copilot',
};

@Component({
  selector: 'app-siem-console',
  standalone: true,
  imports: [CommonModule, FormsModule, CyberThreatGlobeComponent],
  templateUrl: './siem-console.html',
  styleUrls: ['./siem-console.css']
})
export class SiemConsole implements OnInit, OnDestroy {
  private siemService = inject(SiemService);
  private http = inject(HttpClient);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  /** Opened as a single ndr-ui page (route data `tab`): no banner, no tab bar. */
  embedded = signal<boolean>(false);
  private subs = new Subscription();

  // State signals
  activeTab = signal<ActiveTab>('dashboard');
  stats = signal<SiemStats>({
    total_events: 0,
    total_alerts: 0,
    critical_alerts: 0,
    high_alerts: 0,
    medium_alerts: 0,
    low_alerts: 0,
    active_agents: 0,
    total_agents: 0
  });

  alerts = signal<Alert[]>([]);
  agents = signal<Agent[]>([]);
  rules = signal<Rule[]>([]);
  rawEvents = signal<RawEvent[]>([]);
  isConnected = signal<boolean>(false);

  // Telemetry signals
  selectedSource = signal<string>('all');
  telemetryQuery = signal<string>('');
  selectedRawEvent = signal<RawEvent | null>(null);
  autoRefreshTelemetry = signal<boolean>(true);

  // Filters & Search
  searchQuery = signal<string>('');
  selectedSeverity = signal<string>('all');
  selectedAlert = signal<Alert | null>(null);

  // Simulator status
  simulating = signal<boolean>(false);
  lastSimResult = signal<string | null>(null);

  // AI SOC Analyst & Copilot State (Powered by Groq)
  isAnalyzingAi = signal<boolean>(false);
  currentAiAnalysis = signal<AiAnalysisResponse | null>(null);
  aiAnalysisError = signal<string | null>(null);
  selectedAiModel = signal<string>('openai/gpt-oss-120b');
  aiAvailableModels = ['openai/gpt-oss-120b', 'groq/compound', 'groq/compound-mini', 'llama-3.3-70b-versatile'];
  
  aiCopilotMessages = signal<AiChatMessage[]>([
    {
      sender: 'ai',
      text: "Greetings. I am your Wazuh AI SOC Analyst powered by Groq and `openai/gpt-oss-120b`. I can analyze real-time Windows eventchannel logs, evaluate Defender/Firewall posture on your laptop 'EVOFOX', and generate instant PowerShell remediation scripts. How can I assist your investigation?",
      time: new Date().toLocaleTimeString(),
      model: 'openai/gpt-oss-120b'
    }
  ]);
  aiCopilotInput = signal<string>('');
  isCopilotThinking = signal<boolean>(false);
  copiedCmdIndex = signal<number | null>(null);
  activeResponseStatus = signal<string | null>(null);

  // Computed filtered alerts
  filteredAlerts = computed(() => {
    const list = this.alerts();
    const query = this.searchQuery().toLowerCase().trim();
    const severity = this.selectedSeverity();

    return list.filter(alert => {
      // Filter by severity
      if (severity === 'critical' && alert.rule.level < 12) return false;
      if (severity === 'high' && (alert.rule.level < 8 || alert.rule.level >= 12)) return false;
      if (severity === 'medium' && (alert.rule.level < 4 || alert.rule.level >= 8)) return false;
      if (severity === 'low' && alert.rule.level >= 4) return false;

      // Filter by text
      if (!query) return true;
      return (
        alert.rule.description.toLowerCase().includes(query) ||
        alert.rule.id.toString().includes(query) ||
        alert.agent.name.toLowerCase().includes(query) ||
        alert.agent.ip.includes(query) ||
        alert.full_log.toLowerCase().includes(query) ||
        (alert.rule.mitre?.technique.toLowerCase().includes(query) ?? false)
      );
    });
  });

  // --- Wazuh Parity Computed Properties ---

  filteredRawEvents = computed(() => {
    const list = this.rawEvents();
    const src = this.selectedSource();
    const q = this.telemetryQuery().toLowerCase().trim();

    return list.filter(ev => {
      if (src !== 'all') {
        const sourceStr = typeof ev.source === 'string' ? ev.source : JSON.stringify(ev.source);
        if (!sourceStr.toLowerCase().includes(src.toLowerCase())) return false;
      }
      if (!q) return true;
      return (
        ev.message.toLowerCase().includes(q) ||
        ev.agent_id.toLowerCase().includes(q) ||
        ev.location.toLowerCase().includes(q) ||
        (ev.metadata ? JSON.stringify(ev.metadata).toLowerCase().includes(q) : false)
      );
    });
  });

  ngOnInit() {
    const tab = this.route.snapshot.data?.['tab'] as ActiveTab | undefined;
    if (tab) {
      this.embedded.set(true);
      this.switchTab(tab);
    }
    this.fetchData();

    // Subscribe to real-time WebSocket connection status
    this.subs.add(
      this.siemService.getConnectionStatus().subscribe(connected => {
        this.isConnected.set(connected);
      })
    );

    // Subscribe to live incoming alerts via WebSocket
    this.subs.add(
      this.siemService.getAlertStream().subscribe(alert => {
        // Prepend new alert; the newest 500 only, so a tab left open does not grow without end
        this.alerts.update(prev => [alert, ...prev].slice(0, 500));

        // Refresh stats
        this.refreshStats();
      })
    );

    // Periodic refresh
    const intervalId = setInterval(() => {
      this.fetchData();
      if (this.autoRefreshTelemetry()) {
        this.loadRawEvents();
      }
    }, 4000);
    this.subs.add({ unsubscribe: () => clearInterval(intervalId) });
  }

  ngOnDestroy() {
    this.subs.unsubscribe();
  }

  fetchData() {
    this.refreshStats();

    this.siemService.getAlerts(100).subscribe({
      next: (data) => this.alerts.set(data),
      error: (e) => console.warn('Could not fetch alerts', e)
    });

    this.siemService.getAgents().subscribe({
      next: (data) => this.agents.set(data),
      error: (e) => console.warn('Could not fetch agents', e)
    });

    this.siemService.getRules().subscribe({
      next: (data) => this.rules.set(data),
      error: (e) => console.warn('Could not fetch rules', e)
    });

    this.loadRawEvents();
  }

  loadRawEvents() {
    this.siemService.getRawEvents(150, this.selectedSource()).subscribe({
      next: (data) => this.rawEvents.set(data),
      error: (e) => console.warn('Could not fetch raw events', e)
    });
  }

  openRawEventDetails(event: RawEvent) {
    this.selectedRawEvent.set(event);
  }

  closeRawEventDetails() {
    this.selectedRawEvent.set(null);
  }

  getSourceBadgeClass(source: any): string {
    const s = (typeof source === 'string' ? source : JSON.stringify(source)).toLowerCase();
    if (s.includes('window') || s.includes('security') || s.includes('system') || s.includes('application')) return 'badge-windows';
    if (s.includes('syscollector')) return 'badge-syscollector';
    if (s.includes('sca')) return 'badge-sca';
    if (s.includes('registry')) return 'badge-registry';
    if (s.includes('fim') || s.includes('syscheck')) return 'badge-fim';
    return 'badge-generic';
  }

  getSourceLabel(source: any): string {
    if (typeof source === 'string') return source.toUpperCase();
    return JSON.stringify(source).toUpperCase();
  }

  refreshStats() {
    this.siemService.getStats().subscribe({
      next: (data) => this.stats.set(data),
      error: (e) => console.warn('Could not fetch stats', e)
    });
  }

  switchTab(tab: ActiveTab) {
    // As a single page, links to another tab open that tab's ndr-ui page.
    if (this.embedded() && this.route.snapshot.data?.['tab'] !== tab) {
      this.router.navigate(['/analyst/siem-classic/console', CONSOLE_TAB_PATHS[tab] ?? tab]);
      return;
    }
    this.activeTab.set(tab);
  }

  openAlertDetails(alert: Alert) {
    this.selectedAlert.set(alert);
    this.loadProcessTree(alert);
  }

  closeAlertDetails() {
    this.selectedAlert.set(null);
    this.processTree.set(null);
  }

  /** The alert's process tree (EDR): null = none for this alert (not a Sysmon process event). */
  processTree = signal<ProcessNode[] | null>(null);
  processTreeState = signal<'idle' | 'loading' | 'error' | 'not-found'>('idle');
  expandedProcess = signal<string | null>(null);

  /** The Sysmon process the alert is about (its event's ProcessGuid, or the source process's). */
  alertProcessGuid(alert: Alert): string | null {
    const ed = alert.data?.['win']?.['eventdata'] ?? {};
    const g = ed.processGuid || ed.sourceProcessGuid;
    return typeof g === 'string' && /^\{?[0-9a-fA-F-]{32,38}\}?$/.test(g) ? g : null;
  }

  loadProcessTree(alert: Alert) {
    this.processTree.set(null);
    this.expandedProcess.set(null);
    const guid = this.alertProcessGuid(alert);
    if (!guid) { this.processTreeState.set('idle'); return; }
    this.processTreeState.set('loading');
    this.siemService.getProcessTree(alert.agent.id, guid, new Date(alert.timestamp).getTime() || Date.now()).subscribe({
      next: r => {
        if (this.selectedAlert()?.id !== alert.id) return;
        this.processTree.set(r.nodes ?? []);
        this.processTreeState.set(r.found ? 'idle' : 'not-found');
      },
      error: () => this.processTreeState.set('error'),
    });
  }

  processName(path: string): string {
    return (path || '').split('\\').pop() || path || '(unknown)';
  }

  activityKinds(n: ProcessNode): [string, number][] {
    return Object.entries(n.activity?.counts ?? {});
  }

  /** The alert's process (from the tree, else its own event data): what Terminate acts on. */
  alertProcess(alert: Alert): { pid: number; image: string } | null {
    const f = this.processTree()?.find(n => n.role === 'focal' && n.pid);
    if (f?.pid) return { pid: f.pid, image: f.image };
    const ed = alert.data?.['win']?.['eventdata'] ?? {};
    const pid = Number(ed.processId);
    return pid > 4 ? { pid, image: String(ed.image ?? '').replace(/\\\\/g, '\\') } : null;
  }

  runSimulation(scenario: string) {
    this.simulating.set(true);
    this.lastSimResult.set(`Executing scenario: ${scenario}...`);

    this.siemService.simulateAttack(scenario).subscribe({
      next: (res) => {
        this.simulating.set(false);
        this.lastSimResult.set(
          `Success: Scenario '${res.scenario}' fired! ${res.triggered_alerts.length} security alerts generated by Rust engine.`
        );
        this.fetchData();
      },
      error: (err) => {
        this.simulating.set(false);
        this.lastSimResult.set(`Simulation request failed: ${err.message}`);
      }
    });
  }

  getLevelBadgeClass(level: number): string {
    if (level >= 12) return 'badge-critical';
    if (level >= 8) return 'badge-high';
    if (level >= 4) return 'badge-medium';
    return 'badge-low';
  }

  getLevelLabel(level: number): string {
    if (level >= 12) return 'CRITICAL';
    if (level >= 8) return 'HIGH';
    if (level >= 4) return 'MEDIUM';
    return 'LOW';
  }

  triggerAiAnalyzeForRawEvent(event: RawEvent, customPrompt?: string) {
    this.selectedRawEvent.set(event);
    this.currentAiAnalysis.set(null);
    this.aiAnalysisError.set(null);
    this.isAnalyzingAi.set(true);

    const req: AiAnalysisRequest = {
      event_id: event.id,
      model: this.selectedAiModel(),
      source: event.source,
      message: event.message,
      location: event.location,
      agent_id: event.agent_id,
      metadata: event.metadata,
      custom_prompt: customPrompt
    };

    this.siemService.analyzeEvent(req).subscribe({
      next: (res) => {
        this.currentAiAnalysis.set(res);
        this.isAnalyzingAi.set(false);
      },
      error: (err) => {
        console.error('AI Analysis failed', err);
        this.aiAnalysisError.set(err?.error?.message || err?.message || 'Groq AI analysis request failed');
        this.isAnalyzingAi.set(false);
      }
    });
  }

  triggerAiAnalyzeForAlert(alert: Alert, customPrompt?: string) {
    this.selectedAlert.set(alert);
    this.currentAiAnalysis.set(null);
    this.aiAnalysisError.set(null);
    this.isAnalyzingAi.set(true);

    const req: AiAnalysisRequest = {
      alert_id: alert.id,
      model: this.selectedAiModel(),
      source: 'AlertEngine',
      message: alert.full_log,
      location: alert.location,
      agent_id: alert.agent.name,
      custom_prompt: customPrompt
    };

    this.siemService.analyzeEvent(req).subscribe({
      next: (res) => {
        this.currentAiAnalysis.set(res);
        this.isAnalyzingAi.set(false);
      },
      error: (err) => {
        console.error('AI Analysis failed', err);
        this.aiAnalysisError.set(err?.error?.message || err?.message || 'Groq AI analysis request failed');
        this.isAnalyzingAi.set(false);
      }
    });
  }

  /** A host on the globe: its page in the Agent Fleet. */
  onGlobeInspect(agentId: string) {
    this.router.navigate(['/analyst/agents'], { queryParams: { agent: agentId } });
  }

  /** `extra`: the action's own fields (kill_process: pid + image, quarantine_file: path). */
  executeActiveResponse(action: 'block_ip' | 'kill_process' | 'quarantine_file' | 'yara_scan' | 'restart_agent' | 'unblock_ip', target: string, agentId = '001', extra: Record<string, unknown> = {}) {
    if (!target) return;
    this.activeResponseStatus.set(`Dispatching ${action} against ${target} to Agent ${agentId}...`);

    fetch(`/api/v1/agent/commands`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command_id: 'ar-' + Date.now(),
        agent_id: agentId,
        action: action,
        target: target,
        ...extra
      })
    })
      .then(async res => {
        const body = await res.json().catch(() => ({}));
        // the manager's own answer (sent, refused by the decision gate, invalid...)
        this.activeResponseStatus.set(res.ok ? `✓ ${body.message || `${action} sent to Agent ${agentId}`}` : `[REFUSED] ${body.message || `HTTP ${res.status}`}`);
        setTimeout(() => this.activeResponseStatus.set(null), 8000);
      })
      .catch(err => {
        this.activeResponseStatus.set(`[ERROR] Failed to queue active response: ${err}`);
        setTimeout(() => this.activeResponseStatus.set(null), 5000);
      });
  }

  sendCopilotMessage(promptText?: string) {
    const text = (promptText || this.aiCopilotInput()).trim();
    if (!text || this.isCopilotThinking()) return;

    this.aiCopilotMessages.update(msgs => [
      ...msgs,
      { sender: 'user', text, time: new Date().toLocaleTimeString() }
    ]);
    this.aiCopilotInput.set('');
    this.isCopilotThinking.set(true);

    const history = this.aiCopilotMessages()
      .slice(-6)
      .map(m => ({ role: m.sender === 'user' ? 'user' : 'assistant', content: m.text }));

    this.siemService.chatWithAi({
      message: text,
      model: this.selectedAiModel(),
      history
    }).subscribe({
      next: (res) => {
        this.isCopilotThinking.set(false);
        this.aiCopilotMessages.update(msgs => [
          ...msgs,
          {
            sender: 'ai',
            text: res.response,
            time: new Date().toLocaleTimeString(),
            model: res.model_used
          }
        ]);
      },
      error: (err) => {
        this.isCopilotThinking.set(false);
        this.aiCopilotMessages.update(msgs => [
          ...msgs,
          {
            sender: 'ai',
            text: `[ERROR] Unable to reach Groq AI: ${err?.message || 'Check connection to SIEM API.'}`,
            time: new Date().toLocaleTimeString()
          }
        ]);
      }
    });
  }

  copyCommand(cmd: string, idx: number) {
    navigator.clipboard?.writeText(cmd);
    this.copiedCmdIndex.set(idx);
    setTimeout(() => this.copiedCmdIndex.set(null), 2000);
  }

}
