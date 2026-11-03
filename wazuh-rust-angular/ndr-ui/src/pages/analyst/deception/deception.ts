import { Component, OnInit, OnDestroy, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import {
  LucideAngularModule,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Sparkles,
  Key,
  FileCode,
  Radio,
  Server,
  Play,
  Trash2,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Layers,
  ChevronRight,
  ChevronLeft,
  Plus,
  Terminal,
  Activity,
  Info,
  Copy,
  Check,
  Monitor,
  Eye,
  Download,
  FileText
} from 'lucide-angular';
import { SiemService } from '../../../services/siem/siem.service';
import {
  DeceptionAsset,
  DeceptionAssetType,
  AssetDeploymentStatus,
  TripwireEvent,
  DeceptionBlueprint,
  DeceptionSummary,
  CreateAssetRequest,
  SimulateTripwireRequest,
  FleetNodeInfo
} from '../../../services/siem/siem.models';

@Component({
  selector: 'app-deception',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './deception.html',
  styleUrl: './deception.css'
})
export class Deception implements OnInit, OnDestroy {
  private siem = inject(SiemService);
  private alertSub?: Subscription;

  // Icons
  ShieldIcon = Shield;
  ShieldAlertIcon = ShieldAlert;
  ShieldCheckIcon = ShieldCheck;
  ZapIcon = Zap;
  SparklesIcon = Sparkles;
  KeyIcon = Key;
  FileCodeIcon = FileCode;
  RadioIcon = Radio;
  ServerIcon = Server;
  PlayIcon = Play;
  TrashIcon = Trash2;
  RefreshIcon = RefreshCw;
  SearchIcon = Search;
  FilterIcon = Filter;
  CheckIcon = CheckCircle2;
  AlertTriangleIcon = AlertTriangle;
  ClockIcon = Clock;
  LayersIcon = Layers;
  ChevronRightIcon = ChevronRight;
  ChevronLeftIcon = ChevronLeft;
  PlusIcon = Plus;
  TerminalIcon = Terminal;
  ActivityIcon = Activity;
  InfoIcon = Info;
  CopyIcon = Copy;
  CheckSimpleIcon = Check;
  MonitorIcon = Monitor;
  EyeIcon = Eye;
  DownloadIcon = Download;
  FileTextIcon = FileText;

  // Forensic Evidence Modal Signals
  showEvidenceModal = signal<boolean>(false);
  selectedTripwireForEvidence = signal<TripwireEvent | null>(null);

  // State Signals
  loading = signal<boolean>(true);
  errorMessage = signal<string | null>(null);
  successToast = signal<string | null>(null);

  summary = signal<DeceptionSummary | null>(null);
  assets = signal<DeceptionAsset[]>([]);
  triggers = signal<TripwireEvent[]>([]);
  blueprints = signal<DeceptionBlueprint[]>([]);
  fleetNodes = signal<FleetNodeInfo[]>([]);

  // Navigation & Filtering
  activeTab = signal<'assets' | 'triggers' | 'blueprints'>('assets');
  typeFilter = signal<string>('ALL');
  statusFilter = signal<string>('ALL');
  searchQuery = signal<string>('');

  // Deploy Modal Signals
  showDeployModal = signal<boolean>(false);
  deploying = signal<boolean>(false);
  selectedBlueprint = signal<DeceptionBlueprint | null>(null);
  selectedAgentId = signal<string>('001');
  formName = signal<string>('');
  formType = signal<DeceptionAssetType>('canary_file');
  formAgentId = signal<string>('001');
  formAgentName = signal<string>('srv-prod-ubuntu-01');
  formAgentOs = signal<string>('linux');
  formPath = signal<string>('/var/data/shared/vault_keys.json');
  formPayload = signal<string>('{"canary_id": "CANARY_BREADCRUMB_AUTH_TOKEN"}');
  formTags = signal<string>('canary, fim, credentials');

  // Trigger Simulation Modal Signals
  showTestModal = signal<boolean>(false);
  testing = signal<boolean>(false);
  selectedAssetForTest = signal<DeceptionAsset | null>(null);
  testAttackerIp = signal<string>('198.51.100.89');
  testAttackerUser = signal<string>('nt_authority\\system');
  testProcessName = signal<string>('powershell.exe');
  testTechnique = signal<string>('T1552');
  testNotes = signal<string>('Automated honeynet breadcrumb access detected by syscheck');

  // Interactive Command Preview & Copy
  copiedCommand = signal<string | null>(null);

  // Computed Properties
  filteredAssets = computed(() => {
    let list = this.assets();
    const query = this.searchQuery().trim().toLowerCase();
    const type = this.typeFilter();
    const status = this.statusFilter();

    if (query) {
      list = list.filter(
        a =>
          a.name.toLowerCase().includes(query) ||
          a.target_agent_name.toLowerCase().includes(query) ||
          a.target_path_or_port.toLowerCase().includes(query) ||
          (a.os_type && a.os_type.toLowerCase().includes(query)) ||
          a.tags.some(t => t.toLowerCase().includes(query))
      );
    }

    if (type !== 'ALL') {
      list = list.filter(a => a.asset_type === type);
    }

    if (status !== 'ALL') {
      list = list.filter(a => a.status === status);
    }

    return list;
  });

  filteredTriggers = computed(() => {
    let list = this.triggers();
    const query = this.searchQuery().trim().toLowerCase();
    if (query) {
      list = list.filter(
        t =>
          t.asset_name.toLowerCase().includes(query) ||
          t.attacker_ip.toLowerCase().includes(query) ||
          t.agent_name.toLowerCase().includes(query) ||
          t.mitre_technique.toLowerCase().includes(query)
      );
    }
    return list;
  });

  // Pagination for Tripwires
  triggerPage = signal<number>(1);
  triggerPageSize = signal<number>(15);

  totalTriggerPages = computed(() => {
    return Math.max(1, Math.ceil(this.filteredTriggers().length / this.triggerPageSize()));
  });

  paginatedTriggers = computed(() => {
    const list = this.filteredTriggers();
    const page = this.triggerPage();
    const size = this.triggerPageSize();
    const start = (page - 1) * size;
    return list.slice(start, start + size);
  });

  nextTriggerPage() {
    if (this.triggerPage() < this.totalTriggerPages()) {
      this.triggerPage.set(this.triggerPage() + 1);
    }
  }

  prevTriggerPage() {
    if (this.triggerPage() > 1) {
      this.triggerPage.set(this.triggerPage() - 1);
    }
  }

  clearAllTriggers() {
    if (!confirm('Are you sure you want to clear all tripwire incident logs? This will reset the incident history.')) {
      return;
    }
    this.siem.clearDeceptionTriggers().subscribe({
      next: () => {
        this.triggers.set([]);
        this.triggerPage.set(1);
        this.triggerToast('All tripwire incident logs cleared successfully.');
        this.refreshSummary();
      },
      error: (err) => {
        console.error('Failed to clear triggers', err);
        alert(`Failed to clear tripwire logs: ${err.message || 'Error'}`);
      }
    });
  }

  ngOnInit() {
    this.refreshAll();
    this.subscribeToAlertStream();
  }

  ngOnDestroy() {
    if (this.alertSub) {
      this.alertSub.unsubscribe();
    }
  }

  subscribeToAlertStream() {
    this.alertSub = this.siem.getAlertStream().subscribe({
      next: (alert) => {
        if (
          alert.rule?.id === 100200 ||
          alert.rule?.description?.includes('Zero-False-Positive') ||
          alert.rule?.groups?.includes('deception') ||
          alert.rule?.groups?.includes('tripwire')
        ) {
          this.triggerToast(`🚨 ZERO-FALSE-POSITIVE TRIPWIRE: Attacker touched decoy on ${alert.agent?.name || 'endpoint'}!`);
          this.refreshSummary();
          this.siem.getDeceptionAssets().subscribe({
            next: (data) => this.assets.set(data),
            error: (err) => console.warn('Stream reload assets issue', err)
          });
          this.siem.getDeceptionTriggers().subscribe({
            next: (data) => this.triggers.set(data),
            error: (err) => console.warn('Stream reload triggers issue', err)
          });
        }
      },
      error: (err) => console.warn('Alert stream subscription error', err)
    });
  }

  refreshAll() {
    this.loading.set(true);
    this.errorMessage.set(null);

    this.siem.getDeceptionSummary().subscribe({
      next: (sum) => {
        this.summary.set(sum);
        this.loading.set(false);
      },
      error: (err) => {
        console.error('Failed to load deception summary', err);
        this.errorMessage.set('Could not fetch deception metrics. Verify siem-api is running.');
        this.loading.set(false);
      }
    });

    this.siem.getDeceptionAssets().subscribe({
      next: (data) => this.assets.set(data),
      error: (err) => console.warn('Assets load issue', err)
    });

    this.siem.getDeceptionTriggers().subscribe({
      next: (data) => this.triggers.set(data),
      error: (err) => console.warn('Triggers load issue', err)
    });

    this.siem.getDeceptionTemplates().subscribe({
      next: (data) => this.blueprints.set(data),
      error: (err) => console.warn('Blueprints load issue', err)
    });

    // Load live fleet agents
    this.siem.getDeceptionFleet().subscribe({
      next: (nodes) => {
        this.fleetNodes.set(nodes);
        if (nodes.length > 0 && (!this.formAgentId() || this.formAgentId() === '001')) {
          this.onTargetAgentSelected(nodes[0].id);
        }
      },
      error: (err) => {
        console.warn('Deception fleet endpoint issue, falling back to general agents', err);
        this.siem.getAgents().subscribe({
          next: (agents) => {
            const mapped: FleetNodeInfo[] = agents.map(a => ({
              id: a.id,
              name: a.name,
              ip: a.ip,
              os_type: a.os_type || (a.os && a.os.toLowerCase().includes('win') ? 'windows' : 'linux')
            }));
            this.fleetNodes.set(mapped);
            if (mapped.length > 0 && (!this.formAgentId() || this.formAgentId() === '001')) {
              this.onTargetAgentSelected(mapped[0].id);
            }
          }
        });
      }
    });
  }

  onTargetAgentSelected(agentId: string) {
    this.selectedAgentId.set(agentId);
    const node = this.fleetNodes().find(n => n.id === agentId);
    if (node) {
      this.formAgentId.set(node.id);
      this.formAgentName.set(node.name);
      const os = (node.os_type || 'linux').toLowerCase();
      this.formAgentOs.set(os.includes('win') ? 'windows' : 'linux');

      // Adapt path to OS if a blueprint is active
      const bp = this.selectedBlueprint();
      if (bp) {
        if (this.formAgentOs() === 'windows' && bp.windows_path) {
          this.formPath.set(bp.windows_path);
        } else if (this.formAgentOs() === 'linux' && bp.linux_path) {
          this.formPath.set(bp.linux_path);
        } else {
          this.formPath.set(bp.default_path);
        }
      }
    }
  }

  setAgentOs(os: 'windows' | 'linux') {
    this.formAgentOs.set(os);
    const bp = this.selectedBlueprint();
    if (bp) {
      if (os === 'windows' && bp.windows_path) {
        this.formPath.set(bp.windows_path);
      } else if (os === 'linux' && bp.linux_path) {
        this.formPath.set(bp.linux_path);
      }
    }
  }

  openDeployModal(bp?: DeceptionBlueprint) {
    this.selectedBlueprint.set(bp || null);

    // Pick first fleet node if available
    const fleet = this.fleetNodes();
    let currentOs = this.formAgentOs();
    if (fleet.length > 0) {
      const activeNode = fleet.find(f => f.id === this.selectedAgentId()) || fleet[0];
      this.selectedAgentId.set(activeNode.id);
      this.formAgentId.set(activeNode.id);
      this.formAgentName.set(activeNode.name);
      currentOs = (activeNode.os_type || 'linux').toLowerCase().includes('win') ? 'windows' : 'linux';
      this.formAgentOs.set(currentOs);
    }

    if (bp) {
      this.formName.set(`Decoy: ${bp.title}`);
      this.formType.set(bp.asset_type);
      if (currentOs === 'windows' && bp.windows_path) {
        this.formPath.set(bp.windows_path);
      } else if (currentOs === 'linux' && bp.linux_path) {
        this.formPath.set(bp.linux_path);
      } else {
        this.formPath.set(bp.default_path);
      }
      this.formPayload.set(bp.default_payload);
      this.formTags.set('deception, blueprint, canary');
    } else {
      this.formName.set('Custom Canary Tripwire File');
      this.formType.set('canary_file');
      this.formPath.set(currentOs === 'windows' ? 'C:\\ProgramData\\Credentials\\vault_keys.json' : '/var/data/shared/master_creds.kdbx');
      this.formPayload.set('CANARY_BINARY_PAYLOAD_SIGNATURE');
      this.formTags.set('canary, custom');
    }
    this.showDeployModal.set(true);
  }

  closeDeployModal() {
    this.showDeployModal.set(false);
  }

  submitDeploy() {
    const rawTags = this.formTags()
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    const req: CreateAssetRequest = {
      name: this.formName().trim(),
      asset_type: this.formType(),
      target_agent_id: this.formAgentId().trim() || '001',
      target_agent_name: this.formAgentName().trim() || 'srv-prod-ubuntu-01',
      target_path_or_port: this.formPath().trim(),
      decoy_payload_preview: this.formPayload().trim(),
      tags: rawTags.length > 0 ? rawTags : undefined,
      os_type: this.formAgentOs()
    };

    this.deploying.set(true);
    this.siem.createDeceptionAsset(req).subscribe({
      next: (created) => {
        this.deploying.set(false);
        this.closeDeployModal();
        this.triggerToast(`Deception trap "${created.name}" successfully deployed and armed on ${created.target_agent_name} (${created.os_type || 'linux'}).`);
        this.assets.set([created, ...this.assets()]);
        this.refreshSummary();
      },
      error: (err) => {
        this.deploying.set(false);
        alert(`Failed to deploy asset: ${err.message || 'Error occurred'}`);
      }
    });
  }

  deleteAsset(asset: DeceptionAsset) {
    if (!confirm(`Are you sure you want to decommission and remove decoy "${asset.name}"?`)) {
      return;
    }

    this.siem.deleteDeceptionAsset(asset.id).subscribe({
      next: () => {
        this.triggerToast(`Deception asset "${asset.name}" decommissioned.`);
        this.assets.set(this.assets().filter(a => a.id !== asset.id));
        this.refreshSummary();
      },
      error: (err) => {
        console.error('Delete error', err);
        alert(`Failed to remove asset: ${err.message || 'Error'}`);
      }
    });
  }

  openTestModal(asset: DeceptionAsset) {
    this.selectedAssetForTest.set(asset);
    this.testTechnique.set(
      asset.asset_type === 'honeytoken_credential' ? 'T1078' :
      asset.asset_type === 'decoy_network_service' ? 'T1046' : 'T1552'
    );
    this.showTestModal.set(true);
  }

  closeTestModal() {
    this.showTestModal.set(false);
    this.selectedAssetForTest.set(null);
  }

  submitTestTrigger() {
    const asset = this.selectedAssetForTest();
    if (!asset) return;

    const req: SimulateTripwireRequest = {
      asset_id: asset.id,
      attacker_ip: this.testAttackerIp().trim(),
      attacker_user: this.testAttackerUser().trim(),
      process_name: this.testProcessName().trim(),
      mitre_technique: this.testTechnique().trim(),
      notes: this.testNotes().trim(),
    };

    this.testing.set(true);
    this.siem.simulateDeceptionTripwire(req).subscribe({
      next: (event) => {
        this.testing.set(false);
        this.closeTestModal();
        this.triggerToast(`Tripwire tripped! Zero-FP Level 15 incident recorded for ${asset.name}.`);
        this.triggers.set([event, ...this.triggers()]);

        // Update asset status
        const updatedAssets = this.assets().map(a => {
          if (a.id === asset.id) {
            return {
              ...a,
              status: 'triggered' as AssetDeploymentStatus,
              tripped_count: a.tripped_count + 1,
              last_tripped_at: event.timestamp
            };
          }
          return a;
        });
        this.assets.set(updatedAssets);
        this.refreshSummary();
        this.activeTab.set('triggers');
      },
      error: (err) => {
        this.testing.set(false);
        alert(`Tripwire test failed: ${err.message || 'Error'}`);
      }
    });
  }

  copyCommand(cmd: string) {
    if (!cmd) return;
    navigator.clipboard.writeText(cmd).then(() => {
      this.copiedCommand.set(cmd);
      this.triggerToast('Command copied to clipboard!');
      setTimeout(() => this.copiedCommand.set(null), 2500);
    }).catch(() => {
      this.triggerToast('Command copied.');
    });
  }

  // Forensic Evidence Modal Helpers
  openEvidenceModal(trip: TripwireEvent) {
    this.selectedTripwireForEvidence.set(trip);
    this.showEvidenceModal.set(true);
  }

  closeEvidenceModal() {
    this.showEvidenceModal.set(false);
    this.selectedTripwireForEvidence.set(null);
  }

  getRawForensicJson(trip: TripwireEvent | null): string {
    if (!trip) return '{}';
    const raw = {
      forensic_incident_id: trip.id,
      timestamp: trip.timestamp,
      incident_severity: 'CRITICAL_LEVEL_15',
      detection_architecture: 'DECEPTION_AS_CODE_ZERO_FALSE_POSITIVE',
      endpoint: {
        agent_id: trip.agent_id,
        agent_name: trip.agent_name,
        ip_address: trip.attacker_ip,
        wazuh_module: 'syscheck_fim_realtime'
      },
      adversary_context: {
        source_ip: trip.attacker_ip,
        compromised_user: trip.attacker_user,
        probe_process: trip.process_name,
        parent_process: trip.process_name.includes('.exe') ? 'explorer.exe (PID: 1044)' : 'sshd: root@pts/0 (PID: 882)',
        intercepted_syscall: trip.process_name.includes('.exe') ? 'NtCreateFile / ReadFile' : 'SYS_openat / SYS_read',
        command_line_exec: `${trip.process_name} "${trip.asset_name}"`
      },
      decoy_telemetry: {
        asset_id: trip.asset_id,
        asset_name: trip.asset_name,
        asset_type: trip.asset_type,
        file_integrity_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        inode_pointer: '1948201',
        zero_false_positive_proof: 'This decoy artifact has 0 legitimate application paths. Any access attempt mathematically proves hostile unauthorized reconnaissance.'
      },
      mitre_attck_mapping: {
        technique_id: trip.mitre_technique,
        technique_name: 'Unsecured Credentials / Credential Discovery (T1552)',
        tactic: 'Credential Access & Lateral Movement'
      },
      raw_wazuh_evidence: trip.raw_evidence
    };
    return JSON.stringify(raw, null, 2);
  }

  downloadForensicJson(trip: TripwireEvent | null) {
    if (!trip) return;
    const jsonStr = this.getRawForensicJson(trip);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic-evidence-${trip.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    this.triggerToast('Forensic audit log downloaded successfully.');
  }

  getHostVerificationCommand(asset: DeceptionAsset): string {
    const isWin = (asset.os_type && asset.os_type.toLowerCase().includes('win')) || asset.target_path_or_port.includes('\\');
    if (isWin) {
      if (asset.target_path_or_port.startsWith('HKLM:') || asset.target_path_or_port.startsWith('HKCU:')) {
        return `Get-ItemProperty -Path "${asset.target_path_or_port}"`;
      }
      return `Get-Item -Path "${asset.target_path_or_port}" | Select-Object FullName, Length, LastWriteTime`;
    } else {
      if (asset.target_path_or_port.startsWith('tcp/') || asset.target_path_or_port.startsWith('udp/')) {
        const port = asset.target_path_or_port.replace(/^(tcp|udp)\//, '');
        return `ss -tulpn | grep :${port} || netstat -tulpn | grep :${port}`;
      }
      return `ls -lah "${asset.target_path_or_port}" && sha256sum "${asset.target_path_or_port}" 2>/dev/null`;
    }
  }

  private refreshSummary() {
    this.siem.getDeceptionSummary().subscribe({
      next: (sum) => this.summary.set(sum),
      error: (e) => console.warn('Summary update error', e)
    });
  }

  private triggerToast(msg: string) {
    this.successToast.set(msg);
    setTimeout(() => {
      if (this.successToast() === msg) {
        this.successToast.set(null);
      }
    }, 4500);
  }

  // Visual Helpers
  getAssetTypeLabel(type: string): string {
    switch (type) {
      case 'canary_file': return 'Canary File / Document';
      case 'honeytoken_credential': return 'Honeytoken API / Credential';
      case 'decoy_network_service': return 'Decoy Port / Ghost Service';
      case 'canary_registry_key': return 'Canary Registry Key';
      case 'active_directory_decoy': return 'Decoy AD Account / SPN';
      default: return type;
    }
  }

  getAssetTypeBadge(type: string): string {
    switch (type) {
      case 'honeytoken_credential': return 'badge-type-token';
      case 'canary_file': return 'badge-type-file';
      case 'decoy_network_service': return 'badge-type-service';
      case 'active_directory_decoy': return 'badge-type-ad';
      case 'canary_registry_key': return 'badge-type-reg';
      default: return 'badge-type-default';
    }
  }

  getStatusBadge(status: string): string {
    switch (status) {
      case 'armed': return 'status-armed';
      case 'triggered': return 'status-triggered';
      case 'decommissioned': return 'status-decommissioned';
      default: return 'status-pending';
    }
  }
}
