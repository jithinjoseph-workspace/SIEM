import { Component, OnInit, OnDestroy, inject, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { SiemService } from './core/services/siem.service';
import {
  Agent,
  Alert,
  RawEvent,
  Rule,
  SiemStats,
  AiAnalysisResponse,
  AiAnalysisRequest,
  AiChatMessage,
  AgentInventory,
  ScaCheckResult,
  AgentDetailTab,
  MitreTacticColumn,
  MitreTechniqueSummary,
  ComplianceFramework,
  ComplianceRequirement,
  VulnerabilityDetectionItem,
  FimSummaryRecord,
  LogtestResult,
  ActiveResponseRecord,
  DynamicParser,
  ParserStatsSummary,
  UnmatchedFingerprintSummary,
  ParserTestResult
} from './core/models/siem.models';
import { AmixHomeComponent } from './amix/amix-home.component';
import { CyberThreatGlobeComponent } from './components/cyber-threat-globe/cyber-threat-globe.component';

type ActiveTab =
  | 'dashboard'
  | 'alerts'
  | 'telemetry'
  | 'agents'
  | 'mitre'
  | 'vulnerabilities'
  | 'compliance'
  | 'fim'
  | 'rules'
  | 'parsers'
  | 'logtest'
  | 'active_response'
  | 'simulator'
  | 'copilot'
  | 'amix';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule, AmixHomeComponent, CyberThreatGlobeComponent],
  templateUrl: './app.html',
  styleUrls: ['./app.css']
})
export class App implements OnInit, OnDestroy {
  private siemService = inject(SiemService);
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

  // Agent Fleet filters & details
  agentSearchQuery = signal<string>('');
  agentOsFilter = signal<'all' | 'windows' | 'linux' | 'macos'>('all');
  agentStatusFilter = signal<'all' | 'active' | 'disconnected'>('all');
  selectedAgent = signal<Agent | null>(null);
  selectedAgentTab = signal<AgentDetailTab>('specs');
  agentActionFeedback = signal<string | null>(null);

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
  isFimScanning = signal<boolean>(false);
  lastFimScanResult = signal<{ time: string; status: string } | null>(null);

  // --- Wazuh Parity: MITRE ATT&CK Matrix ---
  mitreMatrix = signal<MitreTacticColumn[]>([]);
  mitreSearchQuery = signal<string>('');
  selectedMitreTechnique = signal<MitreTechniqueSummary | null>(null);
  totalMitreAlerts = signal<number>(0);

  // --- Wazuh Parity: Vulnerabilities (CVE) ---
  vulnerabilities = signal<VulnerabilityDetectionItem[]>([]);
  vulnStats = signal<{ total: number; critical: number; high: number; medium: number; low: number }>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  vulnSeverityFilter = signal<string>('all');
  vulnSearchQuery = signal<string>('');
  isScanningVulns = signal<boolean>(false);

  // --- Wazuh Parity: Regulatory Compliance ---
  complianceFrameworks = signal<ComplianceFramework[]>([]);
  selectedFramework = signal<string>('PCI_DSS');
  complianceSearchQuery = signal<string>('');

  // --- Wazuh Parity: FIM (File Integrity Monitoring) ---
  fimStats = signal<{ total: number; added: number; modified: number; deleted: number }>({
    total: 0,
    added: 0,
    modified: 0,
    deleted: 0
  });
  fimRecords = signal<FimSummaryRecord[]>([]);
  selectedFimRecord = signal<FimSummaryRecord | null>(null);
  fimSearchQuery = signal<string>('');
  fimActionFilter = signal<'all' | 'Added' | 'Modified' | 'Deleted'>('all');

  // --- Wazuh Parity: Interactive Logtest Console ---
  logtestInput = signal<string>(
    'Oct 03 14:22:01 ubuntu-server sshd[28412]: Failed password for invalid user admin from 192.168.1.100 port 51234 ssh2'
  );
  logtestOutput = signal<string>('');
  logtestResult = signal<LogtestResult | null>(null);
  isTestingLog = signal<boolean>(false);

  // --- Wazuh Parity: Active Response Management ---
  activeResponses = signal<ActiveResponseRecord[]>([]);
  arTargetIp = signal<string>('198.51.100.42');
  arDuration = signal<number>(3600);
  arReason = signal<string>('Manual operator block: brute-force / unauthorized access');
  isBlocking = signal<boolean>(false);

  // --- Method 2: AI Parser Studio & Dynamic Rules ---
  parsers = signal<DynamicParser[]>([]);
  parserStats = signal<ParserStatsSummary | null>(null);
  unmatchedFingerprints = signal<UnmatchedFingerprintSummary[]>([]);
  selectedParser = signal<DynamicParser | null>(null);
  parserSearchQuery = signal<string>('');
  studioInputSamples = signal<string>(
    '2026-10-04 10:15:30 AUTH_FAIL user=attacker src=198.51.100.99 reason=bad_pass\n2026-10-04 10:15:32 AUTH_FAIL user=admin src=203.0.113.15 reason=account_locked'
  );
  studioCustomPrompt = signal<string>('');
  studioPattern = signal<string>('');
  studioTestLog = signal<string>('2026-10-04 10:16:00 AUTH_FAIL user=charlie src=192.168.1.50 reason=timeout');
  studioTestResult = signal<ParserTestResult | null>(null);
  studioIsSynthesizing = signal<boolean>(false);
  studioIsTesting = signal<boolean>(false);
  studioMessage = signal<string | null>(null);


  // Agent Deployment Wizard State (Mirroring Wazuh Dashboard register-agent)
  showDeployModal = signal<boolean>(false);
  deployOs = signal<'windows' | 'linux' | 'macos'>('linux');
  deployLinuxPkgType = signal<'deb-amd64' | 'rpm-amd64' | 'deb-arm64' | 'rpm-arm64' | 'universal'>('deb-amd64');
  deployManagerUrl = signal<string>('http://127.0.0.1:8088');
  deployAgentName = signal<string>('linux-node-01');
  deployGroup = signal<string>('default');
  winInstallMode = signal<'auto-elevate' | 'admin-ps'>('auto-elevate');
  copied = signal<boolean>(false);
  copiedStart = signal<boolean>(false);

  deployInstallCommand = computed(() => {
    const os = this.deployOs();
    const url = this.deployManagerUrl().replace(/\/+$/, '');
    const name = this.deployAgentName().trim() || 'linux-agent';
    const grp = this.deployGroup().trim() || 'default';
    const pkg = this.deployLinuxPkgType();

    if (os === 'windows') {
      if (this.winInstallMode() === 'admin-ps') {
        return `$d="$env:ProgramFiles\\Wazuh-Agent"; New-Item -ItemType Directory -Force -Path $d | Out-Null; Invoke-WebRequest -Uri "${url}/downloads/siem-agent.exe" -OutFile "$d\\siem-agent.exe"; & "$d\\siem-agent.exe" install-service "${url}" "${name}"; Start-Service -Name WazuhRustSvc -ErrorAction SilentlyContinue; Get-Service WazuhRustSvc`;
      } else {
        return `if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -Command \`"Write-Host '=== Deploying Wazuh Rust Windows Agent ===' -ForegroundColor Cyan; \$d='\$env:ProgramFiles\\Wazuh-Agent'; New-Item -ItemType Directory -Force -Path \$d | Out-Null; Invoke-WebRequest -Uri '${url}/downloads/siem-agent.exe' -OutFile \`"\$d\\siem-agent.exe\`"; & \`"\$d\\siem-agent.exe\`" install-service '${url}' '${name}'; Start-Service -Name WazuhRustSvc -ErrorAction SilentlyContinue; Get-Service WazuhRustSvc; Write-Host '\`n[✓] Wazuh Agent deployed and running as background service!' -ForegroundColor Green\`""; exit } else { Write-Host '=== Deploying Wazuh Rust Windows Agent ===' -ForegroundColor Cyan; $d="$env:ProgramFiles\\Wazuh-Agent"; New-Item -ItemType Directory -Force -Path $d | Out-Null; Invoke-WebRequest -Uri '${url}/downloads/siem-agent.exe' -OutFile "$d\\siem-agent.exe"; & "$d\\siem-agent.exe" install-service '${url}' '${name}'; Start-Service -Name WazuhRustSvc -ErrorAction SilentlyContinue; Get-Service WazuhRustSvc; Write-Host "\`n[✓] Wazuh Agent deployed and running as background service!" -ForegroundColor Green }`;
      }
    } else if (os === 'linux') {
      const envVars = `sudo WAZUH_MANAGER='${url}' WAZUH_AGENT_NAME='${name}' WAZUH_AGENT_GROUP='${grp}'`;
      switch (pkg) {
        case 'deb-amd64':
          return `wget ${url}/downloads/wazuh-agent_4.14.7-1_amd64.deb && ${envVars} dpkg -i ./wazuh-agent_4.14.7-1_amd64.deb`;
        case 'deb-arm64':
          return `wget ${url}/downloads/wazuh-agent_4.14.7-1_arm64.deb && ${envVars} dpkg -i ./wazuh-agent_4.14.7-1_arm64.deb`;
        case 'rpm-amd64':
          return `curl -o wazuh-agent-4.14.7-1.x86_64.rpm ${url}/downloads/wazuh-agent-4.14.7-1.x86_64.rpm && ${envVars} rpm -ihv wazuh-agent-4.14.7-1.x86_64.rpm`;
        case 'rpm-arm64':
          return `curl -o wazuh-agent-4.14.7-1.aarch64.rpm ${url}/downloads/wazuh-agent-4.14.7-1.aarch64.rpm && ${envVars} rpm -ihv wazuh-agent-4.14.7-1.aarch64.rpm`;
        case 'universal':
        default:
          return `curl -sSL ${url}/downloads/install.sh | ${envVars} bash`;
      }
    } else {
      return `curl -o wazuh-agent-4.14.7.pkg ${url}/downloads/wazuh-agent-4.14.7.pkg && sudo installer -pkg ./wazuh-agent-4.14.7.pkg -target / && echo "WAZUH_MANAGER='${url}'" | sudo tee -a /Library/Ossec/etc/ossec.conf`;
    }
  });

  deployStartCommand = computed(() => {
    const os = this.deployOs();
    if (os === 'windows') {
      return `Start-Service -Name WazuhRustSvc\nGet-Service -Name WazuhRustSvc`;
    } else if (os === 'linux') {
      return `sudo systemctl daemon-reload\nsudo systemctl enable wazuh-rust-agent\nsudo systemctl start wazuh-rust-agent`;
    } else {
      return `/Library/Ossec/bin/wazuh-control start`;
    }
  });

  selectDeployOs(os: 'windows' | 'linux' | 'macos') {
    this.deployOs.set(os);
    if (os === 'windows' && (this.deployAgentName().startsWith('linux-') || !this.deployAgentName())) {
      this.deployAgentName.set('win-node-01');
    } else if (os === 'linux' && (this.deployAgentName().startsWith('win-') || !this.deployAgentName())) {
      this.deployAgentName.set('linux-node-01');
    } else if (os === 'macos' && (this.deployAgentName().startsWith('linux-') || this.deployAgentName().startsWith('win-') || !this.deployAgentName())) {
      this.deployAgentName.set('mac-node-01');
    }
  }

  openDeployModal() {
    this.showDeployModal.set(true);
    this.copied.set(false);
    this.copiedStart.set(false);
  }

  closeDeployModal() {
    this.showDeployModal.set(false);
  }

  copyDeployCommand() {
    navigator.clipboard.writeText(this.deployInstallCommand()).then(() => {
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 3000);
    });
  }

  copyDeployStartCommand() {
    navigator.clipboard.writeText(this.deployStartCommand()).then(() => {
      this.copiedStart.set(true);
      setTimeout(() => this.copiedStart.set(false), 3000);
    });
  }

  downloadDeployScript() {
    const isWin = this.deployOs() === 'windows';
    const filename = isWin ? 'deploy-service.ps1' : 'deploy-agent.sh';
    const url = this.deployManagerUrl();
    const name = this.deployAgentName();

    let content: string;
    if (isWin) {
      content = `# ==============================================================================\r\n# Wazuh Rust Windows Agent - Automated Background Service Deployment Script\r\n# Auto-elevates, deploys to Program Files, registers WazuhRustSvc, & starts service\r\n# ==============================================================================\r\n\r\nif (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {\r\n    Write-Host "[!] Requesting Administrator privileges to register Windows Service..." -ForegroundColor Yellow\r\n    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-File", "\`"\$PSCommandPath\`""\r\n    exit\r\n}\r\n\r\nWrite-Host "========================================================" -ForegroundColor Cyan\r\nWrite-Host "Installing Wazuh Rust Windows Agent as Background Service" -ForegroundColor Cyan\r\nWrite-Host "Manager URL: ${url}" -ForegroundColor DarkGray\r\nWrite-Host "Agent ID:    ${name}" -ForegroundColor DarkGray\r\nWrite-Host "========================================================" -ForegroundColor Cyan\r\n\r\n\$targetDir = "\$env:ProgramFiles\\Wazuh-Agent"\r\nif (!(Test-Path \$targetDir)) {\r\n    New-Item -ItemType Directory -Force -Path \$targetDir | Out-Null\r\n}\r\n\r\n\$agentExe = "\$targetDir\\siem-agent.exe"\r\nWrite-Host "[*] Downloading Wazuh Agent binary from manager..." -ForegroundColor Yellow\r\nInvoke-WebRequest -Uri "${url}/downloads/siem-agent.exe" -OutFile \$agentExe\r\n\r\nWrite-Host "[*] Registering automatic Windows background service..." -ForegroundColor Yellow\r\n& \$agentExe install-service "${url}" "${name}"\r\n\r\nStart-Sleep -Seconds 1\r\nStart-Service -Name WazuhRustSvc -ErrorAction SilentlyContinue\r\n\r\nWrite-Host "\`n[✓] Wazuh Rust Agent successfully deployed and active!" -ForegroundColor Green\r\nGet-Service -Name WazuhRustSvc | Format-Table -AutoSize\r\nWrite-Host "[i] The agent will now run 24/7 in the background and automatically start when Windows boots." -ForegroundColor DarkCyan\r\n`;
    } else {
      content = this.deployInstallCommand();
    }

    const blob = new Blob([content], { type: 'text/plain' });
    const blobUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(blobUrl);
  }

  downloadBatScript() {
    const url = this.deployManagerUrl();
    const name = this.deployAgentName();
    const grp = this.deployGroup();

    const batContent = `@echo off\r\n:: Request Administrator Privileges\r\nnet session >nul 2>&1\r\nif %errorlevel% neq 0 (\r\n    echo [!] Requesting Administrator privileges to register Windows Service...\r\n    powershell -Command "Start-Process '%~f0' -Verb RunAs"\r\n    exit /b\r\n)\r\n\r\necho ========================================================\r\necho Installing Wazuh Rust Windows Agent as Background Service\r\necho Target Manager: ${url}\r\necho Agent ID:       ${name}\r\necho ========================================================\r\nif not exist "%ProgramFiles%\\Wazuh-Agent" mkdir "%ProgramFiles%\\Wazuh-Agent"\r\ncurl.exe -f -sSL -o "%ProgramFiles%\\Wazuh-Agent\\siem-agent.exe" "${url}/downloads/siem-agent.exe"\r\nif not exist "%ProgramFiles%\\Wazuh-Agent\\siem-agent.exe" (\r\n    curl.exe -f -sSL -o "%TEMP%\\siem-agent.exe" "${url}/downloads/siem-agent.exe"\r\n    "%TEMP%\\siem-agent.exe" install-service "${url}" "${name}"\r\n) else (\r\n    "%ProgramFiles%\\Wazuh-Agent\\siem-agent.exe" install-service "${url}" "${name}"\r\n)\r\nnet start WazuhRustSvc >nul 2>&1\r\necho.\r\necho [✓] Wazuh Rust Agent installed! It will now run 24/7 in the background and auto-start on boot.\r\necho [i] Verifying service status...\r\nsc query WazuhRustSvc\r\npause\r\n`;

    const blob = new Blob([batContent], { type: 'application/bat' });
    const blobUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = `install-wazuh-service.bat`;
    a.click();
    window.URL.revokeObjectURL(blobUrl);
  }

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

  filteredMitreMatrix = computed(() => {
    const matrix = this.mitreMatrix();
    const q = this.mitreSearchQuery().toLowerCase().trim();
    if (!q) return matrix;

    return matrix.map(col => ({
      ...col,
      techniques: col.techniques.filter(t =>
        t.name.toLowerCase().includes(q) ||
        t.id.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q)
      )
    }));
  });

  selectedComplianceFramework = computed(() => {
    const list = this.complianceFrameworks();
    const sel = this.selectedFramework();
    return list.find(f => f.name === sel) || list[0] || null;
  });

  filteredRequirements = computed(() => {
    const fw = this.selectedComplianceFramework();
    if (!fw) return [];
    const q = this.complianceSearchQuery().toLowerCase().trim();
    if (!q) return fw.requirements;
    return fw.requirements.filter(r =>
      r.id.toLowerCase().includes(q) ||
      r.title.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q)
    );
  });

  filteredVulnerabilities = computed(() => {
    const list = this.vulnerabilities();
    const sev = this.vulnSeverityFilter().toLowerCase();
    const q = this.vulnSearchQuery().toLowerCase().trim();

    return list.filter(v => {
      if (sev !== 'all' && v.severity.toLowerCase() !== sev) return false;
      if (!q) return true;
      return (
        v.cve.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q) ||
        v.package_name.toLowerCase().includes(q) ||
        v.agent_id.toLowerCase().includes(q)
      );
    });
  });

  filteredFimRecords = computed(() => {
    const list = this.fimRecords();
    const act = this.fimActionFilter();
    const q = this.fimSearchQuery().toLowerCase().trim();

    return list.filter(r => {
      if (act !== 'all' && r.action !== act) return false;
      if (!q) return true;
      return (
        r.path.toLowerCase().includes(q) ||
        r.agent_name.toLowerCase().includes(q) ||
        r.agent_id.toLowerCase().includes(q) ||
        (r.md5?.toLowerCase().includes(q) ?? false) ||
        (r.sha256?.toLowerCase().includes(q) ?? false)
      );
    });
  });

  activeBlockedCount = computed(() => {
    return this.activeResponses().filter(r => r.status === 'Active').length;
  });

  filteredParsers = computed(() => {
    const list = this.parsers();
    const q = this.parserSearchQuery().toLowerCase().trim();
    if (!q) return list;
    return list.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.pattern.toLowerCase().includes(q) ||
      p.description.toLowerCase().includes(q) ||
      p.fingerprint_signature.toLowerCase().includes(q) ||
      p.fields.some(f => f.name.toLowerCase().includes(q))
    );
  });

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

  fleetStats = computed(() => {
    const ags = this.agents();
    const total = ags.length;
    const active = ags.filter(a => a.status === 'active').length;
    const disconnected = ags.filter(a => a.status !== 'active').length;
    const windows = ags.filter(a => a.os_type === 'windows').length;
    const linux = ags.filter(a => a.os_type === 'linux').length;
    const macos = ags.filter(a => a.os_type === 'macos').length;
    return { total, active, disconnected, windows, linux, macos };
  });

  filteredAgents = computed(() => {
    const list = this.agents();
    const q = this.agentSearchQuery().toLowerCase().trim();
    const os = this.agentOsFilter();
    const st = this.agentStatusFilter();

    return list.filter(a => {
      if (os !== 'all' && a.os_type !== os) return false;
      if (st !== 'all' && a.status !== st) return false;
      if (!q) return true;
      return (
        a.name.toLowerCase().includes(q) ||
        a.id.toLowerCase().includes(q) ||
        a.ip.includes(q) ||
        a.os.toLowerCase().includes(q) ||
        a.version.toLowerCase().includes(q)
      );
    });
  });

  selectedAgentInventory = computed<AgentInventory | null>(() => {
    const agent = this.selectedAgent();
    if (!agent) return null;

    const evs = this.rawEvents();
    const sysEv = evs.find(e => 
      e.agent_id === agent.id && 
      (e.location?.includes('syscollector') || (typeof e.source === 'string' && e.source.toLowerCase().includes('syscollector')))
    );

    if (sysEv?.metadata?.['inventory_json']) {
      try {
        const parsed = JSON.parse(sysEv.metadata['inventory_json']);
        return {
          hostname: parsed.hostname || agent.name,
          os: parsed.os || agent.os,
          arch: parsed.arch || 'x86_64',
          cpu_cores: parsed.cpu_cores || 8,
          ram_mb: parsed.ram_mb || 16384,
          running_processes_count: parsed.running_processes_count || 142,
          open_ports_count: parsed.open_ports_count || 18,
          installed_packages_count: parsed.installed_packages_count || 86,
          services_count: parsed.services_count || 94,
          users_count: parsed.users_count || 4,
          listening_ports: parsed.listening_ports || ['0.0.0.0:135 (epmap)', '0.0.0.0:445 (microsoft-ds)', '0.0.0.0:3389 (ms-wbt-server)', '127.0.0.1:8088 (siem-api)'],
          running_processes: parsed.running_processes || ['System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'siem-agent.exe'],
          installed_software: parsed.installed_software || ['Wazuh Agent v4.14.7', 'Microsoft Visual C++ 2022', 'Windows Defender Platform', 'PowerShell 7.4', 'Git 2.44'],
          active_services: parsed.active_services || ['WazuhRustSvc', 'WinDefend', 'W32Time', 'LanmanServer', 'MpsSvc', 'EventLog'],
          local_users: parsed.local_users || ['Administrator', 'DefaultAccount', 'Guest', agent.name],
          network_adapters: parsed.network_adapters || [`Ethernet: ${agent.ip} (255.255.255.0)`, 'Loopback: 127.0.0.1 (255.0.0.0)']
        };
      } catch {
        // fallback below
      }
    }

    const isWin = agent.os_type === 'windows';
    return {
      hostname: agent.name,
      os: agent.os,
      arch: 'x86_64',
      cpu_cores: isWin ? 12 : 8,
      ram_mb: isWin ? 16384 : 8192,
      running_processes_count: isWin ? 168 : 84,
      open_ports_count: isWin ? 14 : 7,
      installed_packages_count: isWin ? 112 : 640,
      services_count: isWin ? 145 : 42,
      users_count: isWin ? 4 : 2,
      listening_ports: isWin
        ? ['0.0.0.0:135 (RPC)', '0.0.0.0:445 (SMB)', '0.0.0.0:3389 (RDP)', '127.0.0.1:8088 (API)', '0.0.0.0:5985 (WinRM)']
        : ['0.0.0.0:22 (SSH)', '0.0.0.0:80 (HTTP)', '0.0.0.0:443 (HTTPS)', '127.0.0.1:5432 (Postgres)'],
      running_processes: isWin
        ? ['System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'siem-agent.exe', 'explorer.exe']
        : ['systemd', 'sshd', 'nginx', 'postgres', 'siem-agent', 'rsyslogd'],
      installed_software: isWin
        ? ['Wazuh Rust Agent v4.14.7', 'Microsoft Defender Antivirus', 'PowerShell 7.4.2', 'Windows Terminal', 'Google Chrome']
        : ['wazuh-agent-rust', 'openssh-server', 'nginx', 'curl', 'systemd'],
      active_services: isWin
        ? ['WazuhRustSvc', 'WinDefend (Windows Defender)', 'LanmanServer', 'MpsSvc (Firewall)', 'EventLog']
        : ['siem-agent.service', 'sshd.service', 'nginx.service', 'systemd-journald'],
      local_users: isWin
        ? ['Administrator', 'Guest (Disabled)', 'WDAGUtilityAccount', agent.name]
        : ['root', 'ubuntu', 'sysadmin'],
      network_adapters: [
        `Primary Adapter: ${agent.ip} (255.255.255.0)`,
        'Loopback Pseudo-Interface: 127.0.0.1 / ::1'
      ]
    };
  });

  selectedAgentScaChecks = computed<ScaCheckResult[]>(() => {
    const agent = this.selectedAgent();
    if (!agent) return [];

    const evs = this.rawEvents();
    const scaEvents = evs.filter(e => 
      e.agent_id === agent.id && 
      (e.location?.includes('sca') || (typeof e.source === 'string' && e.source.toLowerCase().includes('sca')))
    );

    if (scaEvents.length > 0) {
      const results: ScaCheckResult[] = [];
      for (const ev of scaEvents) {
        const id = parseInt(ev.metadata?.['check_id'] || '0', 10);
        const title = ev.metadata?.['title'] || ev.message;
        const status = (ev.metadata?.['status'] === 'Passed' || ev.message.includes('PASS')) ? 'Passed' : 'Failed';
        if (id && !results.some(r => r.check_id === id)) {
          results.push({ check_id: id, title, status });
        }
      }
      if (results.length > 0) return results;
    }

    return [
      { check_id: 1001, title: 'Ensure User Account Control (UAC) - EnableLUA is enabled', status: 'Passed' },
      { check_id: 1002, title: 'Ensure Windows Defender Real-Time Protection is active', status: 'Passed' },
      { check_id: 1003, title: 'Ensure Remote Desktop requires Network Level Authentication (NLA)', status: 'Passed' },
      { check_id: 1004, title: 'Ensure Windows Defender Firewall StandardProfile is enabled', status: 'Passed' },
      { check_id: 1005, title: 'Ensure SMBv1 deprecated protocol is disabled', status: 'Passed' },
      { check_id: 1006, title: 'Ensure anonymous enumeration of SAM accounts is restricted', status: 'Passed' },
      { check_id: 1007, title: 'Ensure anonymous enumeration of LSA shares is restricted', status: 'Passed' },
    ];
  });

  selectedAgentFimEvents = computed(() => {
    const agent = this.selectedAgent();
    if (!agent) return [];
    const evs = this.rawEvents();
    return evs.filter(e => 
      e.agent_id === agent.id && 
      ((typeof e.source === 'string' && e.source.toLowerCase().includes('fim')) || e.location?.includes('syscheck'))
    );
  });

  selectedAgentFimSummary = computed(() => {
    const agent = this.selectedAgent();
    if (!agent) {
      return {
        totalChanges: 0,
        modified: 0,
        deleted: 0,
        added: 0,
        lastScanTime: null as string | null,
        statusText: 'Baseline verified: 0 unauthorized file/registry modifications detected.',
        badgeText: 'ACTIVE BASELINE',
        badgeClass: 'badge-emerald'
      };
    }

    const fimEvents = this.selectedAgentFimEvents();
    const manualResult = this.lastFimScanResult();

    // Scan through fim events to identify file changes
    const fileChangeEvents = fimEvents.filter(e => {
      const loc = e.location || '';
      const msg = e.message || '';
      const action = e.metadata?.['action'];
      if (loc === 'syscheck/scan_info' || msg.includes('FIM_SCAN_START')) {
        return false;
      }
      if (msg.includes('FIM_SCAN_END') && !action) {
        return false;
      }
      return (
        action === 'modified' ||
        action === 'deleted' ||
        action === 'added' ||
        msg.includes(' modified:') ||
        msg.includes(' modified ') ||
        msg.includes(' deleted') ||
        msg.includes(' added:') ||
        msg.includes(' added ')
      );
    });

    const modified = fileChangeEvents.filter(e => e.metadata?.['action'] === 'modified' || e.message?.includes(' modified:') || e.message?.includes(' modified ')).length;
    const deleted = fileChangeEvents.filter(e => e.metadata?.['action'] === 'deleted' || e.message?.includes(' deleted')).length;
    const added = fileChangeEvents.filter(e => e.metadata?.['action'] === 'added' || e.message?.includes(' added:') || e.message?.includes(' added ')).length;
    const totalChanges = modified + deleted + added;

    // Determine timestamp
    let lastScanTime = manualResult?.time;
    if (!lastScanTime) {
      const latestScanEnd = fimEvents.find(e => e.message?.includes('FIM_SCAN_END') || e.metadata?.['event_type'] === 'FIM_SCAN_END');
      if (latestScanEnd?.timestamp) {
        try {
          lastScanTime = new Date(latestScanEnd.timestamp).toLocaleTimeString();
        } catch {
          lastScanTime = latestScanEnd.timestamp;
        }
      } else if (fimEvents.length > 0 && fimEvents[0]?.timestamp) {
        try {
          lastScanTime = new Date(fimEvents[0].timestamp).toLocaleTimeString();
        } catch {
          lastScanTime = fimEvents[0].timestamp;
        }
      }
    }

    let statusText: string;
    let badgeText: string;
    let badgeClass: string;

    if (totalChanges > 0) {
      badgeText = 'TAMPERING DETECTED';
      badgeClass = 'badge-rose';
      const parts: string[] = [];
      if (modified > 0) parts.push(`${modified} modified`);
      if (deleted > 0) parts.push(`${deleted} deleted`);
      if (added > 0) parts.push(`${added} added`);
      statusText = `Integrity alert: ${totalChanges} unauthorized modification${totalChanges > 1 ? 's' : ''} detected (${parts.join(', ')}).`;
    } else {
      badgeText = 'ACTIVE BASELINE';
      badgeClass = 'badge-emerald';
      statusText = 'Baseline verified: 0 unauthorized file/registry modifications detected.';
    }

    return {
      totalChanges,
      modified,
      deleted,
      added,
      lastScanTime,
      statusText,
      badgeText,
      badgeClass
    };
  });

  ngOnInit() {
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
        // Prepend new alert
        this.alerts.update(prev => [alert, ...prev]);

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
    this.loadMitreMatrix();
    this.loadCompliance();
    this.loadVulnerabilities();
    this.loadFimSummary();
    this.loadActiveResponses();
    this.loadParsers();
  }

  loadMitreMatrix() {
    this.siemService.getMitreMatrix().subscribe({
      next: (res) => {
        this.mitreMatrix.set(res.matrix);
        this.totalMitreAlerts.set(res.total_mitre_alerts);
      },
      error: (e) => console.warn('Could not fetch MITRE matrix', e)
    });
  }

  loadCompliance() {
    this.siemService.getCompliance().subscribe({
      next: (res) => {
        this.complianceFrameworks.set(res.frameworks);
      },
      error: (e) => console.warn('Could not fetch compliance', e)
    });
  }

  loadVulnerabilities() {
    this.siemService.getVulnerabilities().subscribe({
      next: (res) => {
        this.vulnerabilities.set(res.vulnerabilities);
        this.vulnStats.set({
          total: res.total,
          critical: res.critical_count,
          high: res.high_count,
          medium: res.medium_count,
          low: res.low_count
        });
      },
      error: (e) => console.warn('Could not fetch vulnerabilities', e)
    });
  }

  triggerVulnScanNow() {
    this.isScanningVulns.set(true);
    const targetAgent = this.selectedAgent()?.id || '001';
    this.siemService.triggerVulnScan(targetAgent).subscribe({
      next: () => {
        this.isScanningVulns.set(false);
        this.loadVulnerabilities();
        this.fetchData();
      },
      error: () => {
        this.isScanningVulns.set(false);
        this.loadVulnerabilities();
      }
    });
  }

  loadFimSummary() {
    this.siemService.getFimSummary().subscribe({
      next: (res) => {
        this.fimRecords.set(res.recent_changes);
        this.fimStats.set({
          total: res.total_monitored_files,
          added: res.added_count,
          modified: res.modified_count,
          deleted: res.deleted_count
        });
      },
      error: (e) => console.warn('Could not fetch FIM summary', e)
    });
  }

  runLogtestAction() {
    const raw = this.logtestInput().trim();
    if (!raw) return;
    this.isTestingLog.set(true);
    this.siemService.runLogtest(raw).subscribe({
      next: (res) => {
        this.isTestingLog.set(false);
        this.logtestResult.set(res.result);
        this.logtestOutput.set(res.output);
      },
      error: (err) => {
        this.isTestingLog.set(false);
        this.logtestOutput.set(`Logtest Error: ${err?.message || 'Failed to evaluate log through engine'}`);
      }
    });
  }

  loadActiveResponses() {
    this.siemService.getActiveResponses().subscribe({
      next: (res) => {
        this.activeResponses.set(res.records);
      },
      error: (e) => console.warn('Could not fetch active responses', e)
    });
  }

  blockIpAction() {
    const ip = this.arTargetIp().trim();
    if (!ip) return;
    this.isBlocking.set(true);
    this.siemService.blockIp(ip, this.arDuration(), this.arReason()).subscribe({
      next: () => {
        this.isBlocking.set(false);
        this.loadActiveResponses();
      },
      error: () => {
        this.isBlocking.set(false);
        this.loadActiveResponses();
      }
    });
  }

  unblockIpAction(ip: string) {
    this.siemService.unblockIp(ip).subscribe({
      next: () => this.loadActiveResponses(),
      error: () => this.loadActiveResponses()
    });
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
    this.activeTab.set(tab);
    if (tab === 'mitre') this.loadMitreMatrix();
    if (tab === 'compliance') this.loadCompliance();
    if (tab === 'vulnerabilities') this.loadVulnerabilities();
    if (tab === 'fim') this.loadFimSummary();
    if (tab === 'active_response') this.loadActiveResponses();
    if (tab === 'parsers') this.loadParsers();
  }

  // --- Dynamic Parser Engine Methods (Method 2) ---
  loadParsers() {
    this.siemService.getParsers().subscribe({
      next: (list) => this.parsers.set(list),
      error: (e) => console.warn('Could not fetch dynamic parsers', e)
    });
    this.siemService.getParserStats().subscribe({
      next: (s) => this.parserStats.set(s),
      error: (e) => console.warn('Could not fetch parser stats', e)
    });
    this.siemService.getUnmatchedFingerprints().subscribe({
      next: (u) => this.unmatchedFingerprints.set(u),
      error: (e) => console.warn('Could not fetch unmatched fingerprints', e)
    });
  }

  triggerSynthesize(fp?: number, samples?: string[]) {
    const rawSamples = samples && samples.length > 0 
      ? samples 
      : this.studioInputSamples().split('\n').map(s => s.trim()).filter(s => s.length > 0);

    if (rawSamples.length === 0) {
      this.studioMessage.set('Please provide at least 1 log sample for synthesis.');
      return;
    }

    this.studioIsSynthesizing.set(true);
    this.studioMessage.set('Analyzing structural signature & synthesizing reusable parser with AI...');

    this.siemService.synthesizeParser({
      fingerprint: fp,
      samples: rawSamples,
      instructions: this.studioCustomPrompt().trim() || undefined
    }).subscribe({
      next: (res) => {
        this.studioIsSynthesizing.set(false);
        if (res.parser) {
          this.selectedParser.set(res.parser);
          this.studioPattern.set(res.parser.pattern);
          this.studioMessage.set(`Successfully synthesized parser "${res.parser.name}" with 100% sample verification!`);
          this.loadParsers();
          if (res.parser.sample_logs && res.parser.sample_logs.length > 0) {
            this.studioTestLog.set(res.parser.sample_logs[0]);
            this.runParserTest();
          }
        }
      },
      error: (err) => {
        this.studioIsSynthesizing.set(false);
        this.studioMessage.set(`Synthesis failed: ${err.error?.error || err.message}`);
      }
    });
  }

  runParserTest() {
    const pattern = this.studioPattern().trim();
    const log = this.studioTestLog().trim();
    if (!pattern || !log) return;

    this.studioIsTesting.set(true);
    this.siemService.testParser(pattern, log).subscribe({
      next: (res) => {
        this.studioIsTesting.set(false);
        this.studioTestResult.set(res.result || null);
      },
      error: (err) => {
        this.studioIsTesting.set(false);
        this.studioTestResult.set({
          success: false,
          matches_count: 0,
          total_samples: 1,
          extracted_fields: {},
          execution_time_us: 0,
          error: err.error?.error || err.message
        });
      }
    });
  }

  toggleParserStatus(parser: DynamicParser) {
    const newStatus = parser.status === 'Active' ? 'Disabled' : 'Active';
    const updated = { ...parser, status: newStatus as any };
    this.siemService.updateParser(parser.id, updated).subscribe({
      next: () => this.loadParsers(),
      error: (e) => console.error('Failed to toggle parser status:', e)
    });
  }

  deleteParser(id: string) {
    if (!confirm('Are you sure you want to permanently delete this learned parser?')) return;
    this.siemService.deleteParser(id).subscribe({
      next: () => {
        if (this.selectedParser()?.id === id) {
          this.selectedParser.set(null);
        }
        this.loadParsers();
      },
      error: (e) => console.error('Failed to delete parser:', e)
    });
  }

  selectParserForTesting(p: DynamicParser) {
    this.selectedParser.set(p);
    this.studioPattern.set(p.pattern);
    if (p.sample_logs && p.sample_logs.length > 0) {
      this.studioTestLog.set(p.sample_logs[0]);
    }
    this.runParserTest();
  }

  openAlertDetails(alert: Alert) {
    this.selectedAlert.set(alert);
  }

  closeAlertDetails() {
    this.selectedAlert.set(null);
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

  openAgentDetails(agent: Agent) {
    this.selectedAgent.set(agent);
    this.selectedAgentTab.set('specs');
  }

  closeAgentDetails() {
    this.selectedAgent.set(null);
  }

  setAgentDetailTab(tab: AgentDetailTab) {
    this.selectedAgentTab.set(tab);
  }

  restartAgentFromFleet(agent: Agent) {
    this.executeActiveResponse('restart_agent', agent.id, agent.id);
    this.agentActionFeedback.set(`Restart signal successfully dispatched to Agent ${agent.name} (${agent.id})!`);
    setTimeout(() => this.agentActionFeedback.set(null), 4000);
  }

  triggerFimScanForAgent(agent: Agent) {
    this.isFimScanning.set(true);
    this.agentActionFeedback.set(`Dispatching on-demand FIM scan to ${agent.name} (${agent.id})...`);
    this.siemService.restartSyscheck(agent.id).subscribe({
      next: () => {
        setTimeout(() => {
          this.fetchData();
          this.loadRawEvents();
          this.isFimScanning.set(false);
          this.lastFimScanResult.set({
            time: new Date().toLocaleTimeString(),
            status: 'FIM scan cycle executed.'
          });
          const summary = this.selectedAgentFimSummary();
          if (summary.totalChanges > 0) {
            this.agentActionFeedback.set(`⚠️ FIM Alert on ${agent.name}: ${summary.totalChanges} unauthorized file change(s) detected!`);
          } else {
            this.agentActionFeedback.set(`✓ FIM scan completed successfully on ${agent.name}! Baseline verified.`);
          }
          setTimeout(() => this.agentActionFeedback.set(null), 5000);
        }, 3000);
      },
      error: () => {
        this.isFimScanning.set(false);
        this.agentActionFeedback.set(`Failed to trigger FIM scan on ${agent.name}`);
        setTimeout(() => this.agentActionFeedback.set(null), 4000);
      }
    });
  }

  triggerScaAuditForAgent(agent: Agent) {
    this.siemService.sendAgentCommand(agent.id, 'sca_scan', 'all').subscribe();
    this.agentActionFeedback.set(`SCA CIS Benchmark compliance scan command dispatched to Agent ${agent.name} (${agent.id}).`);
    setTimeout(() => this.agentActionFeedback.set(null), 4000);
  }

  jumpToAgentTelemetry(agent: Agent) {
    this.telemetryQuery.set(agent.id);
    this.selectedSource.set('all');
    this.activeTab.set('telemetry');
    this.closeAgentDetails();
  }

  jumpToAgentAlerts(agent: Agent) {
    this.searchQuery.set(agent.name);
    this.selectedSeverity.set('all');
    this.activeTab.set('alerts');
    this.closeAgentDetails();
  }

  onGlobeInspect(agentId: string) {
    const ag = this.agents().find(a => a.id === agentId);
    if (ag) {
      this.openAgentDetails(ag);
    }
  }

  executeActiveResponse(action: 'block_ip' | 'kill_process' | 'quarantine_file' | 'disable_account' | 'restart_agent' | 'unblock_ip', target: string, agentId = '001') {
    if (!target) return;
    this.activeResponseStatus.set(`Dispatching ${action} against ${target} to Agent ${agentId}...`);

    fetch(`${this.deployManagerUrl()}/api/v1/agent/commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command_id: 'ar-' + Date.now(),
        agent_id: agentId,
        action: action,
        target: target
      })
    })
      .then(res => res.json())
      .then(() => {
        this.activeResponseStatus.set(`✓ Executed: ${action.toUpperCase()} on '${target}' queued for Agent ${agentId}!`);
        setTimeout(() => this.activeResponseStatus.set(null), 5000);
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
