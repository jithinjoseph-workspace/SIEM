import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, catchError } from 'rxjs';
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
  ParserTestResult
} from '../../models/siem.models';
import { SiemAgentsService } from './siem-agents.service';
import { SiemRulesService } from './siem-rules.service';
import { SiemLogsService } from './siem-logs.service';
import { SiemAlertsService } from './siem-alerts.service';
import { SiemStatsService } from './siem-stats.service';

/**
 * Unified full SIEM service aggregating individual specialized sub-services.
 * Supports direct access or delegation to separated services:
 * - agentsService (fleet & commands)
 * - rulesService (detection rules)
 * - logsService (ClickHouse raw telemetry & Syslog)
 * - alertsService (security alerts & WebSocket stream)
 * - statsService (KPIs & metrics)
 * - Wazuh parity services (Logtest, Compliance, MITRE, FIM, Vulnerabilities, Active Response)
 */
@Injectable({
  providedIn: 'root'
})
export class SiemService {
  private http = inject(HttpClient);
  private apiUrl = '';

  readonly agentsService = inject(SiemAgentsService);
  readonly rulesService = inject(SiemRulesService);
  readonly logsService = inject(SiemLogsService);
  readonly alertsService = inject(SiemAlertsService);
  readonly statsService = inject(SiemStatsService);

  getStats(): Observable<SiemStats> {
    return this.statsService.getStats();
  }

  getAlerts(limit: number = 50, minLevel: number = 0): Observable<Alert[]> {
    return this.alertsService.getAlerts(limit, minLevel);
  }

  getRawEvents(limit: number = 200, source?: string): Observable<RawEvent[]> {
    return this.logsService.getRawEvents(limit, source);
  }

  getAgents(): Observable<Agent[]> {
    return this.agentsService.getAgents();
  }

  getAgentInventory(agentId: string): Observable<AgentInventory | null> {
    return this.agentsService.getAgentInventory(agentId);
  }

  getRules(): Observable<Rule[]> {
    return this.rulesService.getRules();
  }

  sendAgentCommand(agentId: string, action: string, target: string = 'all'): Observable<any> {
    return this.agentsService.sendAgentCommand(agentId, action, target);
  }

  getAlertStream(): Observable<Alert> {
    return this.alertsService.getAlertStream();
  }

  getWsConnected(): Observable<boolean> {
    return this.alertsService.getWsConnected();
  }

  getConnectionStatus(): Observable<boolean> {
    return this.getWsConnected();
  }

  /** Runs a simulation scenario on the manager (POST /api/v1/simulate). */
  simulateAttack(scenario: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/simulate`, { scenario });
  }

  /** AI analysis of an event or alert (POST /api/v1/ai/analyze, needs GROQ_API_KEY on the manager). */
  analyzeEvent(req: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/ai/analyze`, req);
  }

  /** On-demand FIM scan on the agent (agents accept 'fim_scan' / 'syscheck restart'). */
  restartSyscheck(agentId: string): Observable<any> {
    return this.sendAgentCommand(agentId, 'fim_scan');
  }

  /** AI copilot chat (POST /api/v1/ai/chat, needs GROQ_API_KEY on the manager). */
  chatWithAi(req: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/ai/chat`, req);
  }

  // --- Wazuh Parity Modules ---

  runLogtest(log: string): Observable<LogtestResponse> {
    return this.http.post<LogtestResponse>(`${this.apiUrl}/api/v1/logtest`, { log });
  }

  getCompliance(): Observable<ComplianceResponse> {
    return this.http.get<ComplianceResponse>(`${this.apiUrl}/api/v1/compliance`);
  }

  getMitreMatrix(): Observable<MitreMatrixResponse> {
    return this.http.get<MitreMatrixResponse>(`${this.apiUrl}/api/v1/mitre/matrix`);
  }

  getVulnerabilities(severity?: string): Observable<VulnerabilitiesResponse> {
    const url = severity ? `${this.apiUrl}/api/v1/vulnerabilities?severity=${severity}` : `${this.apiUrl}/api/v1/vulnerabilities`;
    return this.http.get<VulnerabilitiesResponse>(url);
  }

  triggerVulnScan(agentId: string = '001'): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/vulnerabilities`, { agent_id: agentId });
  }

  getFimSummary(): Observable<FimSummaryResponse> {
    return this.http.get<FimSummaryResponse>(`${this.apiUrl}/api/v1/fim/summary`);
  }

  getActiveResponses(): Observable<ActiveResponseListResponse> {
    return this.http.get<ActiveResponseListResponse>(`${this.apiUrl}/api/v1/active-response/actions`);
  }

  blockIp(ip: string, durationSeconds: number = 3600, reason: string = 'Manual SOC action'): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/active-response/actions`, {
      ip,
      duration_seconds: durationSeconds,
      reason
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

  getTenants(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/api/v1/auth/tenants`);
  }

  createTenant(tenant: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/auth/tenants`, tenant);
  }

  updateTenantFeatures(tenantId: string, features: string[]): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/auth/tenants/${tenantId}/features`, features);
  }

  getUsers(): Observable<any[]> {
    return this.http.get<any[]>(`${this.apiUrl}/api/v1/auth/users`);
  }

  createUser(user: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/auth/users`, user);
  }
}


