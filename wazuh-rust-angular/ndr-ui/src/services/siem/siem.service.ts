import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, catchError, Subject, map } from 'rxjs';
import {
  Agent,
  Alert,
  Rule,
  SiemStats,
  RawEvent,
  AgentInventory,
  MitreMatrixResponse,
  ComplianceResponse,
  VulnerabilitiesResponse,
  FimSummaryResponse,
  LogtestResponse,
  ActiveResponseListResponse,
  DynamicParser,
  ParserStatsSummary,
  UnmatchedFingerprintSummary,
  ParserTestResult,
  TenantRecord,
  UserRecord,
  RiskFabricSummary,
  BusinessProcessDefinition,
  BusinessTimeWindow,
  RiskEvaluationRequest,
  RiskFabricScore,
  SwarmStatusReport,
  SwarmCampaign,
  SwarmExecutionRecord,
  SynthesizedRuleDraft,
  PurpleHeatmapData,
  SwarmExecutionMode,
  IntentSummaryReport,
  EntityIntentDossier,
  SimulationIntentRequest,
  PreemptiveAction,
  ExecuteActionRequest,
  DeceptionAsset,
  TripwireEvent,
  DeceptionBlueprint,
  DeceptionSummary,
  CreateAssetRequest,
  SimulateTripwireRequest, ComplianceProfile, ComplianceProfileResponse, LiveResponseRequest, TamperStatus } from './siem.models';

@Injectable({
  providedIn: 'root'
})
export class SiemService {
  private http = inject(HttpClient);
  // Through Angular proxy or directly to Rust backend
  private apiUrl = '';

  private alertStream$ = new Subject<Alert>();
  private wsConnected = false;
  private ws: WebSocket | null = null;

  constructor() {
    this.initWebSocket();
  }

  private initWebSocket() {
    if (typeof window === 'undefined') return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
    try {
      this.ws = new WebSocket(wsUrl);
      this.ws.onopen = () => {
        this.wsConnected = true;
      };
      this.ws.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
          this.alertStream$.next(alert);
        } catch {}
      };
      this.ws.onclose = () => {
        this.wsConnected = false;
        setTimeout(() => this.initWebSocket(), 5000);
      };
      this.ws.onerror = () => {
        this.wsConnected = false;
      };
    } catch {}
  }

  getAlertStream(): Observable<Alert> {
    return this.alertStream$.asObservable();
  }

  getWsConnected(): Observable<boolean> {
    return of(this.wsConnected);
  }

  getStats(): Observable<SiemStats> {
    return this.http.get<SiemStats>(`${this.apiUrl}/api/v1/stats`).pipe(
      catchError(() => of({
        total_events: 142850,
        total_alerts: 42,
        critical_alerts: 5,
        high_alerts: 12,
        medium_alerts: 18,
        low_alerts: 7,
        active_agents: 4,
        total_agents: 4
      }))
    );
  }

  getAlerts(limit: number = 50, minLevel: number = 0): Observable<Alert[]> {
    return this.http.get<Alert[]>(`${this.apiUrl}/api/v1/alerts?limit=${limit}&min_level=${minLevel}`).pipe(
      map(alerts => alerts.map(a => {
        if (!a.risk_fabric && a.data && a.data['risk_fabric']) {
          a.risk_fabric = a.data['risk_fabric'];
        }
        return a;
      })),
      catchError(() => of([]))
    );
  }

  getRawEvents(limit: number = 200, source?: string): Observable<RawEvent[]> {
    const url = source ? `${this.apiUrl}/api/v1/events?limit=${limit}&source=${source}` : `${this.apiUrl}/api/v1/events?limit=${limit}`;
    return this.http.get<RawEvent[]>(url).pipe(
      catchError(() => of([]))
    );
  }

  getAgents(): Observable<Agent[]> {
    return this.http.get<Agent[]>(`${this.apiUrl}/api/v1/agents`).pipe(
      catchError(() => of([]))
    );
  }

  getAgentInventory(agentId: string): Observable<AgentInventory | null> {
    return this.http.get<AgentInventory>(`${this.apiUrl}/api/v1/agents/${agentId}/inventory`).pipe(
      catchError(() => of(null))
    );
  }

  getRules(): Observable<Rule[]> {
    return this.http.get<Rule[]>(`${this.apiUrl}/api/v1/rules`).pipe(
      catchError(() => of([]))
    );
  }

  sendAgentCommand(agentId: string, action: string, target: string = 'all', durationSeconds?: number, method?: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/agent/commands`, {
      command_id: 'cmd-' + Date.now(),
      agent_id: agentId,
      action,
      target,
      ...(durationSeconds ? { duration_seconds: durationSeconds } : {}),
      ...(method ? { method } : {}),
    });
  }

  /** EDR action on a Windows agent: kill_process {pid, image?}, quarantine_file {path},
   *  restore_file {quarantine_id}, isolate_host, release_host. */
  sendEdrAction(agentId: string, action: string, params: Record<string, string | number> = {}): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/agent/commands`, { command_id: 'cmd-' + Date.now(), agent_id: agentId, action, ...params });
  }

  /** EDR live response on a Windows agent: processes | connections | services | dir {path} | file {path}. */
  startLiveResponse(agentId: string, action: string, path?: string): Observable<{ status: string; message: string; request: LiveResponseRequest }> {
    return this.http.post<{ status: string; message: string; request: LiveResponseRequest }>(`${this.apiUrl}/api/v1/agents/${encodeURIComponent(agentId)}/live-response`, { action, path });
  }

  getLiveResponses(agentId: string): Observable<{ requests: LiveResponseRequest[] }> {
    return this.http.get<{ requests: LiveResponseRequest[] }>(`${this.apiUrl}/api/v1/agents/${encodeURIComponent(agentId)}/live-response`);
  }

  /** The request and, for a finished listing, its result. */
  getLiveResponse(agentId: string, id: string): Observable<{ request: LiveResponseRequest; result?: any; error?: string }> {
    return this.http.get<{ request: LiveResponseRequest; result?: any; error?: string }>(`${this.apiUrl}/api/v1/agents/${encodeURIComponent(agentId)}/live-response/${id}`);
  }

  /** A collected file's bytes. */
  downloadLiveResponseFile(agentId: string, id: string): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/api/v1/agents/${encodeURIComponent(agentId)}/live-response/${id}/download`, { responseType: 'blob' });
  }

  /** EDR tamper protection: the tenant's setting and each Windows agent's lock state. */
  getTamper(): Observable<TamperStatus> {
    return this.http.get<TamperStatus>(`${this.apiUrl}/api/v1/edr/tamper`);
  }

  setTamper(enabled: boolean): Observable<{ status: string; message: string }> {
    return this.http.put<{ status: string; message: string }>(`${this.apiUrl}/api/v1/edr/tamper`, { enabled });
  }

  /** lock | maintenance {minutes: 10 | 60 | 1440, reason} */
  tamperAgent(agentId: string, action: 'lock' | 'maintenance', minutes?: number, reason?: string): Observable<{ status: string; message: string }> {
    return this.http.post<{ status: string; message: string }>(`${this.apiUrl}/api/v1/agents/${encodeURIComponent(agentId)}/tamper`, { action, minutes, reason });
  }

  /** FIM entries of an agent (wazuh-db fim_entry). */
  getAgentFim(agentId: string): Observable<{ total: number; entries: any[] }> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/agents/${agentId}/fim`).pipe(
      catchError(() => of({ total: 0, entries: [] }))
    );
  }

  /** Rootcheck findings of an agent (wazuh-db pm_event). */
  getAgentRootcheck(agentId: string): Observable<{ total: number; events: any[] }> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/agents/${agentId}/rootcheck`).pipe(
      catchError(() => of({ total: 0, events: [] }))
    );
  }

  /** Starts a rootcheck (and FIM) scan on the agent. */
  runRootcheck(agentId: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/agents/${agentId}/rootcheck/scan`, {});
  }

  /** Upgrade an agent (WPK from the repository, or a custom WPK with file_path). */
  upgradeAgent(agentId: string, body: { target_version?: string; force?: boolean; use_http?: boolean; wpk_repo?: string; package_type?: string; file_path?: string; installer?: string }): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/agents/${agentId}/upgrade`, body);
  }

  /** The agent's last upgrade task. */
  getAgentUpgrade(agentId: string): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/agents/${agentId}/upgrade`).pipe(
      catchError((e) => of({ error: -1, data: [], message: e?.error?.error || e?.error?.message || 'unavailable' }))
    );
  }

  /** New agent key for the caller's tenant (agents enrolled before keep working). */
  rotateTenantAgentKey(): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/tenant/agent-key/rotate`, {});
  }

  /** Agent groups of the tenant (centralized agent.conf). */
  getGroups(): Observable<{ name: string; agents: number; agent_ids: string[]; editable: boolean }[]> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/groups`).pipe(
      map(r => r?.groups || []),
      catchError(() => of([]))
    );
  }

  createGroup(name: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/groups`, { name });
  }

  deleteGroup(name: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/api/v1/groups/${encodeURIComponent(name)}`);
  }

  getGroupConf(name: string): Observable<string> {
    return this.http.get(`${this.apiUrl}/api/v1/groups/${encodeURIComponent(name)}/agent.conf`, { responseType: 'text' });
  }

  saveGroupConf(name: string, conf: string): Observable<any> {
    return this.http.put(`${this.apiUrl}/api/v1/groups/${encodeURIComponent(name)}/agent.conf`, conf, { headers: { 'Content-Type': 'text/plain' } });
  }

  setAgentGroups(agentId: string, groups: string[]): Observable<any> {
    return this.http.put(`${this.apiUrl}/api/v1/agents/${agentId}/groups`, { groups });
  }


  /** Deactivate: the agent is kept (not deleted), stops reporting and is told to stop. */
  deactivateAgent(agentId: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/agents/${agentId}/deactivate`, {});
  }

  /** Reactivate a deactivated agent: it resumes on its next state check (within a minute). */
  activateAgent(agentId: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/agents/${agentId}/activate`, {});
  }

  /** Deactivated agents of the caller's tenant. */
  getDeactivatedAgents(): Observable<{ id: string; name: string; os_type: string; groups: string; enrolled_at: string }[]> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/agents/deactivated`).pipe(
      map((r: any) => r?.agents ?? []),
      catchError(() => of([]))
    );
  }

  /** Delete an agent permanently (its id is never reused). */
  deleteAgent(agentId: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/api/v1/agents/${agentId}`);
  }

  /** SCA policy results stored for an agent. */
  /** Per agent, the Sysmon events of the last 24 h (`last` in ms); null when it cannot be read. */
  getAgentsTelemetry(): Observable<{ sysmon: Record<string, { events_24h: number; last: number }> } | null> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/agents/telemetry`).pipe(
      catchError(() => of(null))
    );
  }

  getAgentSca(agentId: string): Observable<{ policy_id?: string; score?: number; passed?: number; failed?: number; checks?: any[] } | null> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/agents/${agentId}/sca`).pipe(
      catchError(() => of(null))
    );
  }


  runLogtest(log: string): Observable<LogtestResponse> {
    return this.http.post<LogtestResponse>(`${this.apiUrl}/api/v1/logtest`, { log });
  }

  /** `refresh`: the agents' latest SCA results are copied first (Re-evaluate). */
  getCompliance(refresh = false): Observable<ComplianceResponse> {
    return this.http.get<ComplianceResponse>(`${this.apiUrl}/api/v1/compliance${refresh ? '?refresh=1' : ''}`);
  }

  /** What the tenant's compliance audits count: frameworks, their agent-group scope, checks not needed. */
  getComplianceProfile(): Observable<ComplianceProfileResponse> {
    return this.http.get<ComplianceProfileResponse>(`${this.apiUrl}/api/v1/compliance/profile`);
  }

  saveComplianceProfile(profile: ComplianceProfile): Observable<{ status: string; profile: ComplianceProfile }> {
    return this.http.put<{ status: string; profile: ComplianceProfile }>(`${this.apiUrl}/api/v1/compliance/profile`, profile);
  }

  getMitreMatrix(): Observable<MitreMatrixResponse> {
    return this.http.get<MitreMatrixResponse>(`${this.apiUrl}/api/v1/mitre/matrix`);
  }

  getVulnerabilities(severity?: string): Observable<VulnerabilitiesResponse> {
    const url = severity ? `${this.apiUrl}/api/v1/vulnerabilities?severity=${severity}` : `${this.apiUrl}/api/v1/vulnerabilities`;
    return this.http.get<VulnerabilitiesResponse>(url);
  }

  /** Checks the packages the agents reported against the CVE feed again (all agents of the tenant without an id). */
  triggerVulnScan(agentId?: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/vulnerabilities`, agentId ? { agent_id: agentId } : {});
  }

  getFimSummary(): Observable<FimSummaryResponse> {
    return this.http.get<FimSummaryResponse>(`${this.apiUrl}/api/v1/fim/summary`);
  }

  getActiveResponses(): Observable<ActiveResponseListResponse> {
    return this.http.get<ActiveResponseListResponse>(`${this.apiUrl}/api/v1/active-response/actions`);
  }

  /** method (Windows agents): 'netsh' (firewall rule, default) or 'route-null'. */
  blockIp(ip: string, durationSeconds: number = 3600, reason: string = 'Manual SOC action', agentId?: string, method?: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/active-response/actions`, {
      ip,
      agent_id: agentId,
      duration_seconds: durationSeconds,
      reason,
      ...(method ? { command: method } : {}),
    });
  }

  unblockIp(ip: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/active-response/unblock`, { ip });
  }

  // --- Dynamic Parser Studio (Method 2) ---
  getParsers(): Observable<DynamicParser[]> {
    return this.http.get<DynamicParser[]>(`${this.apiUrl}/api/v1/parsers`);
  }

  getParserStats(): Observable<ParserStatsSummary> {
    return this.http.get<ParserStatsSummary>(`${this.apiUrl}/api/v1/parsers/stats`);
  }

  getUnmatchedFingerprints(): Observable<UnmatchedFingerprintSummary[]> {
    return this.http.get<UnmatchedFingerprintSummary[]>(`${this.apiUrl}/api/v1/parsers/unmatched`);
  }

  synthesizeParser(payload: { fingerprint?: number; samples: string[]; instructions?: string }): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/parsers/synthesize`, payload);
  }

  testParser(pattern: string, raw_log: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/parsers/test`, { pattern, raw_log });
  }

  updateParser(id: string, parser: DynamicParser): Observable<any> {
    return this.http.put(`${this.apiUrl}/api/v1/parsers/${id}`, parser);
  }

  deleteParser(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/api/v1/parsers/${id}`);
  }

  // --- Multi-Tenant & Identity Engine ---
  login(payload: { username: string; password: string; tenant_id?: string }): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/auth/login`, payload);
  }

  logout(): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/auth/logout`, {});
  }

  getMe(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/auth/me`);
  }

  getTenants(): Observable<TenantRecord[]> {
    return this.http.get<TenantRecord[]>(`${this.apiUrl}/api/v1/auth/tenants`);
  }

  createTenant(tenant: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/auth/tenants`, tenant);
  }

  updateTenantFeatures(tenantId: string, features: string[]): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/auth/tenants/${tenantId}/features`, features);
  }

  getUsers(): Observable<UserRecord[]> {
    return this.http.get<UserRecord[]>(`${this.apiUrl}/api/v1/auth/users`);
  }

  createUser(user: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/auth/users`, user);
  }

  // --- Feature 6: Business-Process Risk Fabric ---
  getRiskFabricSummary(): Observable<RiskFabricSummary> {
    return this.http.get<RiskFabricSummary>(`${this.apiUrl}/api/v1/risk-fabric/summary`);
  }

  getRiskFabricProcesses(): Observable<BusinessProcessDefinition[]> {
    return this.http.get<BusinessProcessDefinition[]>(`${this.apiUrl}/api/v1/risk-fabric/processes`);
  }

  saveRiskFabricProcess(proc: BusinessProcessDefinition): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/risk-fabric/processes`, proc);
  }

  deleteRiskFabricProcess(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/api/v1/risk-fabric/processes/${id}`);
  }

  getRiskFabricWindows(): Observable<BusinessTimeWindow[]> {
    return this.http.get<BusinessTimeWindow[]>(`${this.apiUrl}/api/v1/risk-fabric/windows`);
  }

  saveRiskFabricWindow(win: BusinessTimeWindow): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/risk-fabric/windows`, win);
  }

  deleteRiskFabricWindow(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/api/v1/risk-fabric/windows/${id}`);
  }

  evaluateRisk(req: RiskEvaluationRequest): Observable<RiskFabricScore> {
    return this.http.post<RiskFabricScore>(`${this.apiUrl}/api/v1/risk-fabric/evaluate`, req);
  }

  // ── Red Swarm & Perpetual Purple-Team Engine APIs ──

  getRedSwarmStatus(): Observable<SwarmStatusReport> {
    return this.http.get<SwarmStatusReport>(`${this.apiUrl}/api/v1/redswarm/status`);
  }

  getRedSwarmCampaigns(): Observable<SwarmCampaign[]> {
    return this.http.get<SwarmCampaign[]>(`${this.apiUrl}/api/v1/redswarm/campaigns`);
  }

  saveRedSwarmCampaign(campaign: SwarmCampaign): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/redswarm/campaigns`, campaign);
  }

  toggleRedSwarmCampaign(campaignId: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/redswarm/campaigns/${campaignId}/toggle`, {});
  }

  runRedSwarmSingleRound(payload: { technique_id?: string; target_agent_id?: string; mode?: SwarmExecutionMode }): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/redswarm/run-once`, payload);
  }

  getRedSwarmHistory(): Observable<SwarmExecutionRecord[]> {
    return this.http.get<SwarmExecutionRecord[]>(`${this.apiUrl}/api/v1/redswarm/history`);
  }

  getRedSwarmGaps(): Observable<SynthesizedRuleDraft[]> {
    return this.http.get<SynthesizedRuleDraft[]>(`${this.apiUrl}/api/v1/redswarm/gaps`);
  }

  approveAndDeployRule(draftId: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/redswarm/gaps/${draftId}/apply-rule`, {});
  }

  rejectRedSwarmRule(draftId: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/redswarm/gaps/${draftId}/reject`, {});
  }

  rollbackRedSwarmRule(ruleId: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/redswarm/rules/${ruleId}/rollback`, {});
  }

  toggleRedSwarmKillSwitch(engage: boolean): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/redswarm/kill-switch`, { engage });
  }

  getRedSwarmHeatmap(): Observable<PurpleHeatmapData> {
    return this.http.get<PurpleHeatmapData>(`${this.apiUrl}/api/v1/redswarm/heatmap`);
  }

  // ── SIEM analyst AI (siem-api /api/v1/siem/*: triage, suppressions, predictions, retrospective) ──

  getSiemTriage(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/triage`);
  }

  runSiemTriage(): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/triage/run`, {});
  }

  applySiemTriage(id: string, hours: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/triage/${encodeURIComponent(id)}/apply`, { hours });
  }

  dismissSiemTriage(id: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/triage/${encodeURIComponent(id)}/dismiss`, {});
  }

  /** The group's latest alerts (also records that the analyst looked at them). */
  inspectSiemTriage(id: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/triage/${encodeURIComponent(id)}/inspect`, {});
  }

  /** Past decisions about similar activity (organizational security memory). */
  getTriagePrecedents(id: string): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/triage/${encodeURIComponent(id)}/precedents`);
  }

  searchSecurityMemory(q: string, outcome: string, limit = 100): Observable<any> {
    const p = new URLSearchParams({ q, outcome, limit: String(limit) });
    return this.http.get(`${this.apiUrl}/api/v1/siem/memory?${p.toString()}`);
  }

  // ── Federated threat swarm (/api/v1/swarm/*) ──
  getSwarmStatus(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/swarm/status`); }
  setSwarmLevel(level: 'off' | 'receive' | 'share'): Observable<any> { return this.http.put(`${this.apiUrl}/api/v1/swarm/tenant`, { level }); }
  getSwarmPreview(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/swarm/preview`); }
  getSwarmMatches(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/swarm/matches`); }
  getSwarmConfig(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/swarm/config`); }
  putSwarmConfig(body: any): Observable<any> { return this.http.put(`${this.apiUrl}/api/v1/swarm/config`, body); }
  addSwarmMember(name: string): Observable<any> { return this.http.post(`${this.apiUrl}/api/v1/swarm/members`, { name }); }
  removeSwarmMember(id: string): Observable<any> { return this.http.delete(`${this.apiUrl}/api/v1/swarm/members/${encodeURIComponent(id)}`); }
  syncSwarm(): Observable<any> { return this.http.post(`${this.apiUrl}/api/v1/swarm/sync`, {}); }

  // ── Neurosymbolic decisions: reasoning records, guardrails, approvals ──
  getDecisions(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/decisions`); }
  getDecision(id: string): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/decisions/${encodeURIComponent(id)}`); }
  verifyDecisions(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/decisions/verify`); }
  exportDecisions(): Observable<Blob> { return this.http.get(`${this.apiUrl}/api/v1/siem/decisions/export`, { responseType: 'blob' }); }
  getDecisionPolicy(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/decisions/policy`); }
  putDecisionPolicy(settings: any): Observable<any> { return this.http.put(`${this.apiUrl}/api/v1/siem/decisions/policy`, settings); }
  // ── Threat intel (provigil-common feeds) and investigation ──
  getIntelStatus(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/intel/status`); }
  lookupIntel(q: string): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/intel/lookup`, { params: { q } }); }
  /** The tenant's own indicators (IP, hash, domain) that count as threat intel. */
  getWatchlist(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/intel/watchlist`); }
  addWatched(value: string, group = ''): Observable<any> { return this.http.post(`${this.apiUrl}/api/v1/siem/intel/watchlist`, { value, group }); }
  /** The SOAR case's investigation (evidence and verdict); POST runs it again. */
  getCaseInvestigation(caseId: string): Observable<any> { return this.http.get(`${this.apiUrl}/api/soar/cases/${encodeURIComponent(caseId)}/investigation`); }
  runCaseInvestigation(caseId: string): Observable<any> { return this.http.post(`${this.apiUrl}/api/soar/cases/${encodeURIComponent(caseId)}/investigation`, {}); }
  removeWatched(id: string): Observable<any> { return this.http.delete(`${this.apiUrl}/api/v1/siem/intel/watchlist/${encodeURIComponent(id)}`); }
  getIntelMatches(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/intel/matches`); }
  getSigma(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/sigma`); }
  syncSigma(): Observable<any> { return this.http.post(`${this.apiUrl}/api/v1/siem/sigma/sync`, {}); }
  investigate(q: string, days: number): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/investigate`, { params: { q, days } }); }

  // AI Copilot (siem-api copilot.rs): plain-language requests run with the SIEM's tools
  copilotAsk(message: string, conversationId?: string | null): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/copilot`, { message, conversation_id: conversationId || null });
  }
  copilotStatus(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/copilot/status`); }
  copilotConversations(): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/copilot/conversations`); }
  copilotConversation(id: string): Observable<any> { return this.http.get(`${this.apiUrl}/api/v1/siem/copilot/conversations/${encodeURIComponent(id)}`); }
  copilotDeleteConversation(id: string): Observable<any> { return this.http.delete(`${this.apiUrl}/api/v1/siem/copilot/conversations/${encodeURIComponent(id)}`); }
  /** The report page (same origin; the session cookie authorizes it). */
  copilotReportUrl(id: string): string { return `${this.apiUrl}/api/v1/siem/copilot/reports/${encodeURIComponent(id)}`; }

  reviewDecision(id: string, approve: boolean): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/decisions/${encodeURIComponent(id)}/${approve ? 'approve' : 'reject'}`, {});
  }

  /** The caller's own workload and AI-trust calibration. */
  getMyInsights(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/insights/me`);
  }

  /** Every analyst of the tenant (tenant admin only). */
  getTeamInsights(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/insights/team`);
  }

  putInsightSettings(enabled: boolean): Observable<any> {
    return this.http.put(`${this.apiUrl}/api/v1/siem/insights/settings`, { enabled });
  }

  getSiemAiActivity(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/ai-activity`);
  }

  createSiemSuppression(body: { rule_id?: number; agent_id?: string; src_ip?: string; duration_hours: number; reason?: string }): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/suppressions`, body);
  }

  deactivateSiemSuppression(id: string): Observable<any> {
    return this.http.patch(`${this.apiUrl}/api/v1/siem/suppressions/${encodeURIComponent(id)}/deactivate`, {});
  }

  deleteSiemSuppression(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/api/v1/siem/suppressions/${encodeURIComponent(id)}`);
  }

  getSiemPredictions(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/predictions`);
  }

  getSiemPredictionHistory(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/predictions/history`);
  }

  runSiemPredictions(): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/predictions/run`, {});
  }

  getSiemFiredRules(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/retrospective/fired-rules`);
  }

  startSiemRetroScan(body: { rule_id: string; rule_name: string; rule_content: string; hours_back: number }): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/siem/retrospective/scan`, body);
  }

  listSiemRetroScans(): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/retrospective/scans`);
  }

  getSiemRetroScan(id: string): Observable<any> {
    return this.http.get(`${this.apiUrl}/api/v1/siem/retrospective/scans/${encodeURIComponent(id)}`);
  }

  // Feature 5: Intent Prediction Engine API
  getIntentSummary(): Observable<IntentSummaryReport> {
    return this.http.get<IntentSummaryReport>(`${this.apiUrl}/api/v1/intent/summary`);
  }

  getIntentHypotheses(): Observable<EntityIntentDossier[]> {
    return this.http.get<EntityIntentDossier[]>(`${this.apiUrl}/api/v1/intent/hypotheses`);
  }

  getIntentHypothesis(id: string): Observable<EntityIntentDossier> {
    return this.http.get<EntityIntentDossier>(`${this.apiUrl}/api/v1/intent/hypotheses/${encodeURIComponent(id)}`);
  }

  evaluateIntentSimulation(req: SimulationIntentRequest): Observable<EntityIntentDossier> {
    return this.http.post<EntityIntentDossier>(`${this.apiUrl}/api/v1/intent/evaluate`, req);
  }

  executePreemptiveAction(req: ExecuteActionRequest): Observable<PreemptiveAction> {
    return this.http.post<PreemptiveAction>(`${this.apiUrl}/api/v1/intent/actions/execute`, req);
  }

  getIntentCatalog(): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/intent/catalog`);
  }

  // Feature 9: Deception-as-Code & Adaptive Honeynet
  getDeceptionSummary(): Observable<DeceptionSummary> {
    return this.http.get<DeceptionSummary>(`${this.apiUrl}/api/v1/deception/summary`);
  }

  getDeceptionAssets(): Observable<DeceptionAsset[]> {
    return this.http.get<DeceptionAsset[]>(`${this.apiUrl}/api/v1/deception/assets`);
  }

  createDeceptionAsset(req: CreateAssetRequest): Observable<DeceptionAsset> {
    return this.http.post<DeceptionAsset>(`${this.apiUrl}/api/v1/deception/assets`, req);
  }

  deleteDeceptionAsset(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/api/v1/deception/assets/${encodeURIComponent(id)}`);
  }

  getDeceptionTriggers(): Observable<TripwireEvent[]> {
    return this.http.get<TripwireEvent[]>(`${this.apiUrl}/api/v1/deception/triggers`);
  }

  simulateDeceptionTripwire(req: SimulateTripwireRequest): Observable<TripwireEvent> {
    return this.http.post<TripwireEvent>(`${this.apiUrl}/api/v1/deception/test-trigger`, req);
  }

  getDeceptionTemplates(): Observable<DeceptionBlueprint[]> {
    return this.http.get<DeceptionBlueprint[]>(`${this.apiUrl}/api/v1/deception/templates`);
  }
}

