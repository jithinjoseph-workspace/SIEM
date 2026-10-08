export interface GameSpec {
  engine: string;
  playMode: string;
  resolution: string;
  releaseYear: string;
}

export interface Game {
  id: string;
  number: string;
  category: string;
  title: string;
  subtitle: string;
  description: string;
  engine: string;
  playMode: string;
  accentColor: string; // Neon hex code
  glowColorRgb: string; // RGB for rgba() box-shadow
  ctaLabel: string;
  previewAsset: string;
  neonSign: string;
  specs: GameSpec;
  tags: string[];
  targetTab?: 'dashboard' | 'alerts' | 'telemetry' | 'agents' | 'rules' | 'simulator' | 'copilot';
}

export const GAMES_DATA: Game[] = [
  {
    id: 'ransomware-sentinel',
    number: '01',
    category: 'RANSOMWARE DEFENSE',
    title: 'RANSOMWARE SHADOW KILL',
    subtitle: 'Zero-Day Canary Decoys & Sub-Millisecond Process Intercept',
    description: 'Deploys intelligent trap file canaries across monitored directory trees and intercepts Windows CryptoAPI & volume shadow copy deletions (vssadmin) in real time. Automatically isolates infected network sockets and terminates malicious process trees within 400 microseconds before mass encryption begins.',
    engine: 'WAZUH ACTIVE RESPONSE // RUST',
    playMode: 'ZERO-TOUCH AUTONOMOUS QUARANTINE',
    accentColor: '#ff0055', // Electric Neon Crimson (Danger)
    glowColorRgb: '255, 0, 85',
    ctaLabel: 'Simulate Ransomware Attack →',
    previewAsset: 'assets/amix/ransomware.webp',
    neonSign: 'ACTIVE RESPONSE // ANTI-RANSOMWARE',
    specs: {
      engine: 'Windows ReadDirectoryChangesW + Rust Syscall Hook',
      playMode: 'Real-Time Volume Shadow Protection',
      resolution: 'Instant Process Termination (< 0.4ms)',
      releaseYear: 'MITRE T1486 (Data Encrypted for Impact)'
    },
    tags: ['ANTI-RANSOMWARE', 'ACTIVE-RESPONSE', 'CANARY-TRAP', 'VSS-PROTECT'],
    targetTab: 'simulator'
  },
  {
    id: 'apt-hunter-zeroday',
    number: '02',
    category: 'THREAT HUNTING',
    title: 'APT HUNTER: ZERO-DAY PURGE',
    subtitle: 'Deep Memory Forensics & C2 Beacon Disruption',
    description: 'Hunts stealth nation-state adversary groups living off the land (LotL). Detects reflective DLL injection, process hollowing, hidden rootkits, and anomalous DNS/HTTPS beaconing channels before unauthorized data exfiltration occurs across the corporate enterprise.',
    engine: 'TOKIO CORRELATION CORE 4.0',
    playMode: 'AUTONOMOUS BEHAVIORAL GRAPH',
    accentColor: '#00f0ff', // Cyber Cyan
    glowColorRgb: '0, 240, 255',
    ctaLabel: 'Inspect Live Threat Alerts →',
    previewAsset: 'assets/amix/apt_hunter.webp',
    neonSign: 'THREAT MATRIX // ZERO-DAY PURGE',
    specs: {
      engine: 'Graph-Based Process Ancestry Analyzer',
      playMode: 'Kernel-Level Telemetry & Memory Scan',
      resolution: 'Sub-Second C2 Beacon Severance',
      releaseYear: 'MITRE T1059 / T1055 (Process Injection)'
    },
    tags: ['APT-DETECTION', 'MEMORY-FORENSICS', 'C2-HUNTER', 'ZERO-DAY'],
    targetTab: 'alerts'
  },
  {
    id: 'fim-sentinel-core',
    number: '03',
    category: 'FILE INTEGRITY',
    title: 'FIM SENTINEL: CIPHER CORE',
    subtitle: 'Nanosecond SHA-256 Kernel Inode & Registry Sentinel',
    description: 'Continuous nanosecond monitoring of system critical binaries, Windows System32 drivers, SAM hives, PAM configurations, and boot sectors. Instantly alerts and generates forensic diff audits whenever unauthorized file modifications or DLL hijacking attempts occur.',
    engine: 'WAZUH FIM ENGINE // SHA-256 MESH',
    playMode: 'CONTINUOUS REAL-TIME AUDIT',
    accentColor: '#ff7700', // Radiant Neon Amber
    glowColorRgb: '255, 119, 0',
    ctaLabel: 'View Telemetry & Integrity Logs →',
    previewAsset: 'assets/amix/fim_core.webp',
    neonSign: 'FIM SENTINEL // REGISTRY LOCK',
    specs: {
      engine: 'Windows Change Journal API + Inotify',
      playMode: 'Real-Time SHA-256 & Who-Data Tracking',
      resolution: 'Microsecond Hash Delta Verification',
      releaseYear: 'MITRE T1565 (Data Manipulation)'
    },
    tags: ['FIM-AUDIT', 'ROOTKIT-DETECTOR', 'REGISTRY-LOCK', 'WHO-DATA'],
    targetTab: 'telemetry'
  },
  {
    id: 'neural-soc-copilot',
    number: '04',
    category: 'COGNITIVE AI AGENT',
    title: 'NEURAL SOC COPILOT 120B',
    subtitle: 'Groq LPU Ultra-Fast Threat Reasoning & Auto-Triage',
    description: 'Harnesses ultra-fast Groq LPU hardware acceleration to correlate thousands of disparate endpoint telemetry events in real time. Generates tactical MITRE ATT&CK breakdowns, computes false positive probability, and drafts automated PowerShell & Bash mitigation playbooks in seconds.',
    engine: 'GROQ LPU CLUSTER // 120B REASONING',
    playMode: 'AUTONOMOUS INCIDENT INVESTIGATOR',
    accentColor: '#a855f7', // Electric Purple
    glowColorRgb: '168, 85, 247',
    ctaLabel: 'Consult AI SOC Copilot →',
    previewAsset: 'assets/amix/copilot.webp',
    neonSign: 'AI COPILOT // GROQ 120B ENGINE',
    specs: {
      engine: 'Groq LPU Hardware Acceleration Engine',
      playMode: 'Natural Language SOC Query & Auto-Triage',
      resolution: '< 800ms End-to-End Threat Reasoning',
      releaseYear: 'SOC AUTOMATION // 2099 MATRIX'
    },
    tags: ['AI-COPILOT', 'GROQ-120B', 'AUTO-TRIAGE', 'INCIDENT-REPORT'],
    targetTab: 'copilot'
  },
  {
    id: 'adversary-simulation-suite',
    number: '05',
    category: 'ADVERSARY EMULATION',
    title: 'RED TEAM ATTACK SIMULATOR',
    subtitle: 'Live Multi-Stage Cyber War-Room Simulation Suite',
    description: 'Simulates high-fidelity adversary tactics directly against monitored fleet endpoints — injecting credential dumping (Mimikatz), lateral SMB worm propagation, encoded PowerShell execution, and brute-force authentication attacks to rigorously validate detection posture.',
    engine: 'RED-TEAM SYNTHESIS CORE',
    playMode: 'CONTAINED ADVERSARY EMULATION',
    accentColor: '#00ff66', // Toxic Matrix Green
    glowColorRgb: '0, 255, 102',
    ctaLabel: 'Launch Attack Simulator →',
    previewAsset: 'assets/amix/simulator.webp',
    neonSign: 'RED TEAM // ATTACK SIMULATOR',
    specs: {
      engine: 'Atomic Red Team + Wazuh Attack Injector',
      playMode: 'Multi-Stage Attack Scenarios (1-Click)',
      resolution: 'Live Real-Time Telemetry Feed',
      releaseYear: 'MITRE ATT&CK Automated Validation'
    },
    tags: ['RED-TEAM', 'BRUTE-FORCE', 'CREDENTIAL-THEFT', 'LATERAL-MOVE'],
    targetTab: 'simulator'
  },
  {
    id: 'hyperscale-telemetry-mesh',
    number: '06',
    category: 'DISTRIBUTED INGESTION',
    title: 'TOKIO HYPERSCALE TELEMETRY',
    subtitle: '100,000+ EPS Non-Blocking Distributed Ingestion Engine',
    description: 'Ultra high-throughput security event stream collector built on pure Rust Tokio and Axum. Ingests Windows Security Event Logs (Event IDs 4624, 4625, 4688), Sysmon process lineage, Linux auditd streams, and raw network NetFlows with sub-5% CPU footprint and zero packet drop.',
    engine: 'RUST AXUM // TOKIO ASYNC MESH',
    playMode: 'DISTRIBUTED AGENT INGESTION',
    accentColor: '#ffcc00', // Radiant Solar Gold
    glowColorRgb: '255, 204, 0',
    ctaLabel: 'View Active Agent Fleet →',
    previewAsset: 'assets/amix/telemetry_mesh.webp',
    neonSign: 'RUST CORE // 100K EPS PIPELINE',
    specs: {
      engine: 'Zero-Copy Rust Deserializer (Serde-JSON)',
      playMode: 'Scalable to 50,000+ Distributed Agents',
      resolution: '100,000+ EPS Ingestion (< 5% CPU)',
      releaseYear: 'ENTERPRISE HIGH-SCALE XDR'
    },
    tags: ['RUST-CORE', 'WINDOWS-SYSMON', '100K-EPS', 'HIGH-THROUGHPUT'],
    targetTab: 'agents'
  }
];
