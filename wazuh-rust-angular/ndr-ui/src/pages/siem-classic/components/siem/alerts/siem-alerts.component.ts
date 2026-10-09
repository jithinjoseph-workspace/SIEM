import { Component, OnInit, OnDestroy, inject, signal, computed, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule, ShieldAlert, AlertTriangle, ShieldCheck, Search, RefreshCw, Radio, Terminal, ExternalLink, Filter, X, Shield, Lock, Activity, Check } from 'lucide-angular';
import { Subscription } from 'rxjs';
import { SiemAlertsService } from '../../../services/siem/siem-alerts.service';
import { SiemAgentsService } from '../../../services/siem/siem-agents.service';
import { Alert } from '../../../models/siem.models';

@Component({
  selector: 'app-siem-alerts',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-alerts.component.html',
  styleUrl: './siem-alerts.component.css'
})
export class SiemAlertsComponent implements OnInit, OnDestroy {
  private alertsService = inject(SiemAlertsService);
  private agentsService = inject(SiemAgentsService);
  private subs: Subscription[] = [];

  @Input() compactMode = false;

  alerts = signal<Alert[]>([]);
  loading = signal<boolean>(true);
  searchQuery = signal<string>('');
  severityFilter = signal<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  selectedAlert = signal<Alert | null>(null);
  actionFeedback = signal<string | null>(null);
  wsActive = signal<boolean>(false);

  ShieldAlertIcon = ShieldAlert;
  AlertTriangleIcon = AlertTriangle;
  ShieldCheckIcon = ShieldCheck;
  CheckIcon = Check;
  SearchIcon = Search;
  RefreshIcon = RefreshCw;
  RadioIcon = Radio;
  TerminalIcon = Terminal;
  ExternalLinkIcon = ExternalLink;
  FilterIcon = Filter;
  XIcon = X;
  ShieldIcon = Shield;
  LockIcon = Lock;
  ActivityIcon = Activity;

  filteredAlerts = computed(() => {
    const query = this.searchQuery().toLowerCase().trim();
    const sev = this.severityFilter();

    return this.alerts().filter(a => {
      const matchQuery = !query ||
        a.rule.description.toLowerCase().includes(query) ||
        a.agent.name.toLowerCase().includes(query) ||
        a.agent.ip.includes(query) ||
        (a.rule.mitre?.tactic && a.rule.mitre.tactic.toLowerCase().includes(query)) ||
        (a.rule.mitre?.technique && a.rule.mitre.technique.toLowerCase().includes(query)) ||
        (a.decoded.src_ip && a.decoded.src_ip.includes(query));

      let matchSev = true;
      if (sev === 'critical') matchSev = a.rule.level >= 12;
      else if (sev === 'high') matchSev = a.rule.level >= 8 && a.rule.level < 12;
      else if (sev === 'medium') matchSev = a.rule.level >= 4 && a.rule.level < 8;
      else if (sev === 'low') matchSev = a.rule.level < 4;

      return matchQuery && matchSev;
    });
  });

  criticalCount = computed(() => this.alerts().filter(a => a.rule.level >= 12).length);
  highCount = computed(() => this.alerts().filter(a => a.rule.level >= 8 && a.rule.level < 12).length);
  mediumCount = computed(() => this.alerts().filter(a => a.rule.level >= 4 && a.rule.level < 8).length);
  lowCount = computed(() => this.alerts().filter(a => a.rule.level < 4).length);

  ngOnInit() {
    this.loadAlerts();

    // Subscribe to live alert stream
    this.subs.push(
      this.alertsService.getAlertStream().subscribe(newAlert => {
        this.alerts.update(current => [newAlert, ...current.slice(0, 199)]);
      })
    );

    this.subs.push(
      this.alertsService.getWsConnected().subscribe(connected => {
        this.wsActive.set(connected);
      })
    );
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }

  loadAlerts() {
    this.loading.set(true);
    this.alertsService.getAlerts(100).subscribe({
      next: (data) => {
        // Real alerts of the tenant only (no sample data).
        this.alerts.set(data || []);
        this.loading.set(false);
      },
      error: () => {
        this.alerts.set([]);
        this.loading.set(false);
      }
    });
  }

  getSeverityBadge(level: number): { label: string; class: string } {
    if (level >= 12) return { label: 'CRITICAL', class: 'badge-critical' };
    if (level >= 8) return { label: 'HIGH', class: 'badge-high' };
    if (level >= 4) return { label: 'MEDIUM', class: 'badge-medium' };
    return { label: 'LOW', class: 'badge-low' };
  }

  formatTimestamp(ts: string): string {
    if (!ts) return new Date().toLocaleTimeString();
    try {
      const d = new Date(ts);
      return isNaN(d.getTime()) ? ts : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  }

  selectAlert(alert: Alert) {
    this.selectedAlert.set(alert);
  }

  closeModal() {
    this.selectedAlert.set(null);
    this.actionFeedback.set(null);
  }

  /** The agents have no network-isolation action yet: say so instead of pretending. */
  isolateHost(agentId: string) {
    this.actionFeedback.set(`Host isolation is not supported by the agent yet (agent ${agentId}). Use Block IP or Kill Process.`);
    setTimeout(() => this.actionFeedback.set(null), 5000);
  }

  private getDefaultAlerts(): Alert[] {
    return [
      {
        id: 'wazuh-alt-001',
        timestamp: new Date().toISOString(),
        rule: {
          id: 5710,
          level: 14,
          description: 'SSH brute force attack detected (multiple authentication failures)',
          groups: ['syslog', 'sshd', 'authentication_failures'],
          mitre: { id: 'T1110.001', tactic: 'Credential Access', technique: 'Password Guessing' }
        },
        agent: { id: '001', name: 'prod-gateway-dc01', ip: '192.168.1.10' },
        full_log: 'sshd[12480]: Failed password for root from 185.220.101.5 port 42318 ssh2',
        decoded: {
          decoder_name: 'sshd',
          src_ip: '185.220.101.5',
          dst_ip: '192.168.1.10',
          dst_port: 22,
          user: 'root',
          program_name: 'sshd',
          action: 'failed_login'
        },
        location: '/var/log/auth.log'
      },
      {
        id: 'wazuh-alt-002',
        timestamp: new Date(Date.now() - 180000).toISOString(),
        rule: {
          id: 60105,
          level: 10,
          description: 'Windows Defender quarantined malicious payload (Mimikatz memory dump)',
          groups: ['windows', 'antivirus'],
          mitre: { id: 'T1003.001', tactic: 'Credential Access', technique: 'LSASS Memory' }
        },
        agent: { id: '002', name: 'win-ad-controller', ip: '192.168.1.20' },
        full_log: 'Microsoft-Windows-Windows Defender: Threat detected: HackTool:Win32/Mimikatz!dha',
        decoded: {
          decoder_name: 'windows-defender',
          user: 'SYSTEM',
          file_path: 'C:\\Users\\admin\\Downloads\\mimi.exe',
          action: 'quarantine'
        },
        location: 'EventChannel: Microsoft-Windows-Windows Defender/Operational'
      },
      {
        id: 'wazuh-alt-003',
        timestamp: new Date(Date.now() - 450000).toISOString(),
        rule: {
          id: 550,
          level: 7,
          description: 'Integrity checksum altered for system binary: /etc/sudoers',
          groups: ['syscheck', 'fim'],
          mitre: { id: 'T1548.003', tactic: 'Privilege Escalation', technique: 'Sudo and Sudo Caching' }
        },
        agent: { id: '003', name: 'k8s-node-worker-01', ip: '192.168.1.30' },
        full_log: 'syscheck: File /etc/sudoers was modified. Old md5: e5b6..., New md5: a1f2...',
        decoded: {
          decoder_name: 'syscheck',
          file_path: '/etc/sudoers',
          action: 'checksum_changed'
        },
        location: 'syscheck'
      }
    ];
  }
}
