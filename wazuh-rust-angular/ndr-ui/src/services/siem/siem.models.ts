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
  data?: Record<string, any>;
  risk_fabric?: RiskFabricScore;
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
  status: 'Passed' | 'Failed' | 'Not applicable';
  reason?: string;
  description?: string;
  rationale?: string;
  remediation?: string;
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
  /** Techniques of the full ATT&CK Enterprise catalog (the manager's mitre.db). */
  total_techniques?: number;
  total_mitre_alerts: number;
  /** Technique ids in alerts that the catalog does not have (revoked, or a rule's typo). */
  unmapped?: { id: string; alert_count: number; max_level: number }[];
  last_updated: string;
}

// --- Regulatory Compliance ---
/** One CIS / SCA check a requirement maps (the agent's own text and results). */
export interface ComplianceCheck {
  check_id: string;
  title: string;
  failed_agents: number;
  passed_agents: number;
  failing_on: string[];
  remediation: string;
  rationale: string;
}

export interface ComplianceRequirement {
  id: string;
  /** its most failing check's title (or its top alert's): no hand-written text */
  title: string;
  description: string;
  /** failed: a mapped check fails; warning: alerts only; passed: its checks pass */
  status: 'passed' | 'warning' | 'failed';
  source: 'configuration' | 'alerts' | 'both';
  alerts_count: number;
  max_level: number;
  rule_ids: number[];
  alerts: { rule_id: number; description: string }[];
  checks_passed: number;
  checks_failed: number;
  checks: ComplianceCheck[];
}

export interface ComplianceFramework {
  name: string;
  full_name: string;
  version: string;
  /** passed share of its configuration check results; null when no check maps it (GDPR) */
  score_percent: number | null;
  total_requirements: number;
  passed_count: number;
  alert_count: number;
  checks_passed: number;
  checks_failed: number;
  requirements: ComplianceRequirement[];
}

/** A failing check and the requirements it breaks, with the agent's fix. */
export interface ComplianceRemediation {
  check_id: string;
  title: string;
  remediation: string;
  rationale: string;
  failed_agents: number;
  requirements: string[];
}

/** A recent alert whose Wazuh rule carries compliance groups. */
export interface ComplianceEvidence {
  timestamp: number;
  agent_id: string;
  agent_name: string;
  rule_id: number;
  level: number;
  description: string;
  requirements: string[];
}

export interface ComplianceResponse {
  frameworks: ComplianceFramework[];
  remediations: ComplianceRemediation[];
  evidence: ComplianceEvidence[];
  window_hours: number;
  agents: number;
  total_alerts_evaluated: number;
  last_updated: string;
}

// --- Vulnerabilities (CVE) ---
export interface VulnerabilityDetectionItem {
  cve: string;
  title: string;
  /** '-' while the CVE is under evaluation (no score yet) */
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | '-';
  /** -1 while under evaluation */
  cvss_score: number;
  package_name: string;
  installed_version: string;
  fixed_version: string | null;
  agent_id: string;
  agent_name?: string;
  status: 'active' | 'resolved';
  detected_at: string;
  description?: string;
  reference?: string;
  category?: string;
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
  /** scheduled, realtime or whodata */
  mode?: string;
  /** whodata: who made the change and with which program */
  user?: string;
  process?: string;
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

export interface TenantRecord {
  id: string;
  name: string;
  active: boolean;
  plan: string;
  max_sensors: number;
  features: string[];
  created_at?: string;
}

export interface UserRecord {
  id: string;
  username: string;
  role: 'superadmin' | 'tenant_admin' | 'analyst';
  tenant_id: string;
  active: boolean;
  permissions: string[];
  created_at?: string;
  last_login?: string;
}

export interface AuthSession {
  token: string;
  user: UserRecord;
}

export interface RiskFabricScore {
  business_process: string;
  process_criticality: string;
  asset_weight: number;
  identity_weight: number;
  time_window_multiplier: number;
  active_window_name?: string;
  technical_severity: number;
  dynamic_risk_score: number;
  dynamic_risk_tier: 'Catastrophic' | 'Critical' | 'High' | 'Medium' | 'Low';
  executive_impact: string;
  evaluated_at: string;
}

export interface BusinessProcessDefinition {
  id: string;
  name: string;
  description: string;
  criticality: string;
  asset_weight: number;
  identity_weight: number;
  asset_patterns: string[];
  identity_patterns: string[];
  impact_template: string;
  enabled: boolean;
}

export interface BusinessTimeWindow {
  id: string;
  name: string;
  description: string;
  multiplier: number;
  window_type: string;
  start_date?: string;
  end_date?: string;
  active: boolean;
  target_processes: string[];
}

export interface ProcessRiskStat {
  name: string;
  criticality: string;
  alerts_count: number;
  max_risk_score: number;
}

export interface RiskFabricSummary {
  total_processes: number;
  active_time_windows: number;
  average_dynamic_risk: number;
  catastrophic_alerts_count: number;
  critical_alerts_count: number;
  high_alerts_count: number;
  medium_alerts_count: number;
  low_alerts_count: number;
  top_critical_processes: ProcessRiskStat[];
}

export interface RiskEvaluationRequest {
  rule_level: number;
  rule_id?: number;
  rule_description?: string;
  agent_name: string;
  agent_ip: string;
  user?: string;
}

// ── Red Swarm & Purple Team Console Models ──

export type SwarmExecutionMode = 'safe_telemetry_only' | 'controlled_live' | 'full_live';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type DetectionVerdict = 'defended' | 'soft_gap' | 'hard_gap';
export type CleanupStatus = 'not_applicable' | 'succeeded' | 'failed' | 'pending';
export type DraftRuleStatus = 'pending_approval' | 'approved_and_deployed' | 'rejected' | 'rolled_back';

export interface CommandPayload {
  command: string;
  timeout_seconds: number;
  requires_elevation: boolean;
}

export interface VerificationEvidence {
  verdict: DetectionVerdict;
  matched_alert_id?: string;
  matched_rule_id?: number;
  matched_rule_description?: string;
  matched_alert?: Alert;
  retry_count?: number;
  evaluated_signals?: string[];
  reason: string;
  latency_ms: number;
}

export interface SynthesizedRuleDraft {
  id: string;
  execution_id: string;
  technique_id: string;
  technique_name: string;
  rule_xml: string;
  logtest_passed: boolean;
  logtest_output: string;
  hardening_recommendation: string;
  created_at: string;
  status: DraftRuleStatus;
}

export interface SwarmExecutionRecord {
  id: string;
  campaign_id: string;
  tenant_id: string;
  timestamp: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  mode: SwarmExecutionMode;
  target_agent_id: string;
  target_agent_name: string;
  target_agent_ip: string;
  target_os: string;
  execution_success: boolean;
  execution_output: string;
  cleanup_status: CleanupStatus;
  cleanup_output?: string;
  verification: VerificationEvidence;
  draft_rule?: SynthesizedRuleDraft;
}

export interface RulesOfEngagement {
  allowed_agent_tags: string[];
  denied_agent_ids: string[];
  max_attacks_per_hour: number;
  allowed_tactics: string[];
  banned_techniques: string[];
  max_risk_level: RiskLevel;
}

export interface SwarmCampaign {
  id: string;
  name: string;
  description: string;
  mode: SwarmExecutionMode;
  enabled: boolean;
  interval_seconds: number;
  roe: RulesOfEngagement;
  last_run_at?: string;
  total_executed: number;
  total_defended: number;
  total_gaps: number;
}

export interface SwarmStatusReport {
  running: boolean;
  kill_switch_active: boolean;
  default_mode: SwarmExecutionMode;
  active_campaigns_count: number;
  attacks_last_24h: number;
  defense_rate_percent: number;
  open_gaps_count: number;
  approved_rules_count: number;
  current_risk_budget_used: number;
  max_risk_budget_per_hour: number;
}

export interface TacticCoverage {
  tactic: string;
  total_techniques: number;
  tested: number;
  defended: number;
  soft_gaps: number;
  hard_gaps: number;
  coverage_percent: number;
}

export interface HeatmapTechniqueNode {
  technique_id: string;
  technique_name: string;
  tactic: string;
  status: 'defended' | 'soft_gap' | 'hard_gap' | 'untested';
  last_tested_at?: string;
}

export interface PurpleHeatmapData {
  tactics: TacticCoverage[];
  techniques: HeatmapTechniqueNode[];
  overall_defense_rate: number;
}

// ── Feature 5: Intent Prediction Engine Models ──

export interface IntentHypothesisScore {
  intent_type: string;
  display_name: string;
  probability: number;
  confidence: number;
  impact_severity: string;
  key_indicators: string[];
  projected_impact: string;
}

export interface KillChainMilestone {
  stage_index: number;
  stage_name: string;
  status: 'observed' | 'current' | 'predicted_next' | 'unreached';
  observed_techniques: string[];
  first_observed_at?: string;
  prediction_reason?: string;
}

export interface PreemptiveAction {
  id: string;
  title: string;
  action_type: 'host_isolation' | 'process_termination' | 'identity_stepup' | 'canary_tripwire' | 'firewall_block' | string;
  target_agent_id: string;
  target_agent_name: string;
  target_entity: string;
  urgency: 'Immediate' | 'Elevated' | 'Advisory' | string;
  risk_reduction_percent: number;
  description: string;
  execution_command?: string;
  status: 'pending_approval' | 'executed' | 'dismissed' | 'simulated' | string;
  created_at: string;
}

export interface EntityIntentDossier {
  id: string;
  entity_id: string;
  entity_name: string;
  entity_ip: string;
  primary_intent: string;
  primary_probability: number;
  confidence_score: number;
  kill_chain_velocity: string;
  progression_percent: number;
  hypotheses: IntentHypothesisScore[];
  milestones: KillChainMilestone[];
  recommended_actions: PreemptiveAction[];
  alerts_analyzed: number;
  last_updated_at: string;
}

export interface IntentSummaryReport {
  total_dossiers_monitored: number;
  critical_intent_count: number;
  ransomware_risk_count: number;
  exfiltration_risk_count: number;
  espionage_risk_count: number;
  wiper_risk_count: number;
  top_dossiers: EntityIntentDossier[];
  pending_preemptive_actions: PreemptiveAction[];
  average_advance_warning_hours: number;
}

export interface SimulationIntentRequest {
  agent_id: string;
  agent_name: string;
  agent_ip: string;
  observed_techniques: string[];
  user?: string;
  custom_context?: string;
}

export interface ExecuteActionRequest {
  action_id: string;
  dry_run?: boolean;
}

// Feature 9: Deception-as-Code & Adaptive Honeynet
export type DeceptionAssetType =
  | 'canary_file'
  | 'honeytoken_credential'
  | 'decoy_network_service'
  | 'canary_registry_key'
  | 'active_directory_decoy';

export type AssetDeploymentStatus = 'armed' | 'triggered' | 'decommissioned' | 'pending_deploy';

export interface DeceptionAsset {
  id: string;
  name: string;
  asset_type: DeceptionAssetType;
  target_agent_id: string;
  target_agent_name: string;
  target_path_or_port: string;
  decoy_payload_preview: string;
  status: AssetDeploymentStatus;
  tripped_count: number;
  last_tripped_at?: string;
  created_at: string;
  tags: string[];
  risk_reduction_score: number;
}

export interface TripwireEvent {
  id: string;
  asset_id: string;
  asset_name: string;
  asset_type: DeceptionAssetType;
  agent_id: string;
  agent_name: string;
  attacker_ip: string;
  attacker_user: string;
  process_name: string;
  mitre_technique: string;
  raw_evidence: string;
  severity: string;
  timestamp: string;
}

export interface DeceptionBlueprint {
  template_id: string;
  title: string;
  description: string;
  asset_type: DeceptionAssetType;
  category: string;
  recommended_target: string;
  default_path: string;
  default_payload: string;
  threat_mitigation: string;
}

export interface DeceptionSummary {
  total_assets: number;
  armed_assets: number;
  triggered_assets: number;
  decommissioned_assets: number;
  total_trips: number;
  high_fidelity_alerts: number;
  recent_triggers: TripwireEvent[];
  fleet_coverage_percentage: number;
}

export interface CreateAssetRequest {
  name: string;
  asset_type: DeceptionAssetType;
  target_agent_id: string;
  target_agent_name: string;
  target_path_or_port: string;
  decoy_payload_preview?: string;
  tags?: string[];
}

export interface SimulateTripwireRequest {
  asset_id: string;
  attacker_ip?: string;
  attacker_user?: string;
  process_name?: string;
  mitre_technique?: string;
  notes?: string;
}

