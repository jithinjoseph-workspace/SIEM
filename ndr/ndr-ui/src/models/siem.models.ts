export interface MitreAttack {
  id: string;
  tactic: string;
  technique: string;
}

export interface RuleAlertInfo {
  id: number;
  level: number;
  description: string;
  groups: string[];
  mitre?: MitreAttack;
}

export interface AgentAlertInfo {
  id: string;
  name: string;
  ip: string;
}

export interface DecodedFields {
  decoder_name: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  user?: string;
  program_name?: string;
  process_id?: number;
  file_path?: string;
  action?: string;
  status?: string;
  extra?: Record<string, string>;
}

export interface Alert {
  id: string;
  timestamp: string;
  rule: RuleAlertInfo;
  agent: AgentAlertInfo;
  full_log: string;
  decoded: DecodedFields;
  location: string;
}

export interface Agent {
  id: string;
  name: string;
  ip: string;
  os: string;
  version: string;
  status: 'active' | 'disconnected' | 'pending';
  last_keepalive: string;
  os_type: 'linux' | 'windows' | 'macos';
}

export interface Rule {
  id: number;
  level: number;
  description: string;
  regex_pattern: string;
  groups: string[];
  mitre?: MitreAttack;
}

export interface SiemStats {
  total_events: number;
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  active_agents: number;
  total_agents: number;
}

export interface RawEvent {
  id: string;
  timestamp: string;
  agent_id: string;
  source: string;
  location: string;
  message: string;
  metadata?: Record<string, string>;
}

export interface ScaCheckResult {
  id: number;
  title: string;
  description: string;
  status: 'passed' | 'failed';
  rationale: string;
  remediation: string;
}

export interface FimEntry {
  path: string;
  event: 'modified' | 'added' | 'deleted';
  timestamp: string;
  hash: string;
  user?: string;
}

export interface AgentInventory {
  agent_id: string;
  hostname: string;
  os: string;
  ram_total_gb: number;
  ram_used_gb: number;
  cpu_cores: number;
  cpu_usage_pct: number;
  disk_total_gb: number;
  disk_free_gb: number;
  ip_addresses: string[];
  installed_packages_count: number;
  open_ports: number[];
  sca_score: number;
  sca_checks: ScaCheckResult[];
  fim_events: FimEntry[];
}
