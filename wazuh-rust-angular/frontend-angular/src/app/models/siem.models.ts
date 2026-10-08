export interface MitreAttack {
  id: string;
  tactic: string;
  technique: string;
}

export interface RuleAlertInfo {
  id: number;
  level: number; // 1 to 15
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

export interface MitreMappingInfo {
  tactic: string;
  technique_id: string;
  technique_name: string;
}

export interface AiAnalysisRequest {
  event_id?: string;
  alert_id?: string;
  model?: string;
  source?: string;
  message?: string;
  location?: string;
  agent_id?: string;
  metadata?: Record<string, string>;
  custom_prompt?: string;
}

export interface AiAnalysisResponse {
  classification: string;
  confidence_score: number;
  severity: string;
  summary: string;
  mitre_attack?: MitreMappingInfo;
  indicators: string[];
  impact: string;
  remediation_commands: string[];
  explanation: string;
  model_used: string;
}

export interface AiChatMessage {
  sender: 'user' | 'ai';
  text: string;
  time: string;
  model?: string;
}

export interface AgentInventory {
  hostname: string;
  os: string;
  arch: string;
  cpu_cores: number;
  ram_mb: number;
  running_processes_count: number;
  open_ports_count: number;
  installed_packages_count: number;
  services_count: number;
  users_count: number;
  listening_ports: string[];
  running_processes: string[];
  installed_software: string[];
  active_services: string[];
  local_users: string[];
  network_adapters: string[];
}

export interface ScaCheckResult {
  check_id: number;
  title: string;
  status: 'Passed' | 'Failed';
  reason?: string;
}

export type AgentDetailTab = 'specs' | 'network_ports' | 'users_services' | 'sca' | 'fim' | 'actions';

// --- MITRE ATT&CK Matrix ---
export interface MitreTechniqueSummary {
  id: string;
  name: string;
  description: string;
  alert_count: number;
  max_level: number;
  subtechniques: string[];
}

export interface MitreTacticColumn {
  tactic_id: string;
  name: string;
  techniques: MitreTechniqueSummary[];
}

export interface MitreMatrixResponse {
  matrix: MitreTacticColumn[];
  total_tactics: number;
  total_mitre_alerts: number;
  last_updated: string;
}

// --- Regulatory Compliance ---
export interface ComplianceRequirement {
  id: string;
  title: string;
  description: string;
  status: 'passed' | 'warning' | 'failed';
  alerts_count: number;
  rule_ids: number[];
}

export interface ComplianceFramework {
  name: string;
  full_name: string;
  version: string;
  score_percent: number;
  total_requirements: number;
  passed_count: number;
  alert_count: number;
  requirements: ComplianceRequirement[];
}

export interface ComplianceResponse {
  frameworks: ComplianceFramework[];
  total_alerts_evaluated: number;
  last_updated: string;
}

// --- Vulnerabilities (CVE) ---
export interface VulnerabilityDetectionItem {
  cve: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cvss_score: number;
  package_name: string;
  installed_version: string;
  fixed_version: string;
  agent_id: string;
  status: 'active' | 'resolved';
  detected_at: string;
}

export interface VulnerabilitiesResponse {
  total: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  vulnerabilities: VulnerabilityDetectionItem[];
}

// --- File Integrity Monitoring (FIM) ---
export interface FimSummaryRecord {
  timestamp: string;
  agent_id: string;
  agent_name: string;
  path: string;
  action: 'Added' | 'Modified' | 'Deleted';
  size_bytes?: number;
  md5?: string;
  sha256?: string;
  diff?: string;
}

export interface FimSummaryResponse {
  total_monitored_files: number;
  added_count: number;
  modified_count: number;
  deleted_count: number;
  recent_changes: FimSummaryRecord[];
}

// --- Wazuh Logtest Console ---
export interface LogtestResult {
  raw_event: string;
  predecoded_timestamp?: string;
  predecoded_hostname?: string;
  predecoded_program_name?: string;
  predecoded_log: string;
  decoder_name: string;
  extracted_fields: Record<string, string>;
  matched_rule_id?: number;
  matched_rule_level?: number;
  matched_rule_description?: string;
  matched_rule_groups: string[];
  mitre_attack?: MitreAttack;
}

export interface LogtestResponse {
  result: LogtestResult;
  output: string;
}

// --- Active Response ---
export interface ActiveResponseRecord {
  id: string;
  command: string;
  target_ip: string;
  agent_id: string;
  reason: string;
  triggered_at: string;
  duration_seconds: number;
  status: 'Active' | 'Expired' | 'Released';
}

export interface ActiveResponseListResponse {
  total: number;
  active_blocks: number;
  records: ActiveResponseRecord[];
}

// --- Dynamic Parser Generator (Method 2) ---
export interface ParserFieldDefinition {
  name: string;
  field_type: string;
  example: string;
  ecs_target?: string;
}

export interface DynamicParser {
  id: string;
  fingerprint: number;
  fingerprint_signature: string;
  name: string;
  description: string;
  parser_type: 'Regex' | 'Grok' | 'JsonPath';
  pattern: string;
  fields: ParserFieldDefinition[];
  normalization: Record<string, string>;
  confidence: number;
  version: number;
  status: 'Active' | 'Draft' | 'NeedsReview' | 'Disabled';
  sample_logs: string[];
  hit_count: number;
  success_count: number;
  created_at: string;
  last_used?: string;
}

export interface ParserStatsSummary {
  total_learned_parsers: number;
  active_parsers: number;
  pending_novel_fingerprints: number;
  total_parses_executed: number;
  average_latency_us: number;
}

export interface UnmatchedFingerprintSummary {
  fingerprint: number;
  signature: string;
  sample_count: number;
  first_seen: string;
  last_seen: string;
  ready_for_synthesis: boolean;
  sample_previews: string[];
}

export interface ParserTestResult {
  success: boolean;
  matches_count: number;
  total_samples: number;
  extracted_fields: Record<string, string>;
  execution_time_us: number;
  error?: string;
}

