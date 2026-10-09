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
  UserRecord
} from './siem.models';

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

  sendAgentCommand(agentId: string, action: string, target: string = 'all'): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/agent/commands`, {
      command_id: 'cmd-' + Date.now(),
      agent_id: agentId,
      action,
      target
    });
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
  getAgentSca(agentId: string): Observable<{ policy_id?: string; score?: number; passed?: number; failed?: number; checks?: any[] } | null> {
    return this.http.get<any>(`${this.apiUrl}/api/v1/agents/${agentId}/sca`).pipe(
      catchError(() => of(null))
    );
  }

  /** Runs a simulation scenario on the manager (POST /api/v1/simulate). */
  simulateAttack(scenario: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/simulate`, { scenario });
  }

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
}
