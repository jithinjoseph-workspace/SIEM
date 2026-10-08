import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { map, Observable } from 'rxjs';

export interface SensorAssignment {
  user_id: string;
  sensor_id: string;
}

export interface SensorKey {
  id: string;
  key_prefix: string;
  key?: string;
  tenant_id: string;
  name: string;
  hostname?: string;
  interface?: string;
  os?: string;
  'agent-z'?: string;
  'agent-s'?: string;
  vector?: string;
  arkime?: string;
  arkime_url?: string;
  active: boolean;
  created_at: string;
  last_seen: string;
}

export type SensorControlCommand = 'start' | 'stop' | 'restart';

export interface Announcement {
  id: string;
  title: string;
  message: string;
  type: 'info' | 'maintenance' | 'update' | 'critical';
  audience: 'all' | 'tenant_admins' | 'tenant';
  tenant_id?: string;
  starts_at?: string;
  ends_at?: string;
  start_at?: string;
  end_at?: string;
  active: boolean;
  read?: boolean;
  status?: string;
  target_roles?: string[];
  target_tenants?: string[];
  created_at: string;
  updated_at?: string;
}

export interface SupportMessage {
  id: string;
  tenant_id: string;
  sender_username: string;
  sender_role: string;
  subject: string;
  category: string;
  message: string;
  status: string;
  admin_reply: string;
  replied_by: string;
  forwarded: number;
  forwarded_by: string;
  deleted: number;
  created_at: string;
  updated_at: string;
  replied_at: string;
  forwarded_at: string;
}

interface AnnouncementListResponse {
  status?: string;
  announcements?: Announcement[];
  message?: string;
}

interface SensorKeyListResponse {
  status?: string;
  keys?: SensorKey[];
  message?: string;
}

interface SupportMessageListResponse {
  status?: string;
  messages?: SupportMessage[];
  message?: string;
}

@Injectable({
  providedIn: 'root'
})
export class Api {
  // Relative base so requests route correctly in every environment:
  // - Dev: Angular CLI proxy forwards /api → localhost:3000
  // - Production: nginx proxies /api → ndr_engines upstream
  // Never use an absolute URL here — it breaks remote browser access.
  private readonly baseUrl = '/api';

  constructor(private http: HttpClient) { }

  getDashboardStats(): Observable<any> {
    return this.http.get(`${this.baseUrl}/health`);
  }

  getAlerts(srcIp?: string): Observable<any[]> {
    const params = srcIp ? { params: { src_ip: srcIp } } : {};
    return this.http.get<any[]>(`${this.baseUrl}/hits`, params);
  }

  getInterfaces(): Observable<string[]> {
    return this.http.get<string[]>(`${this.baseUrl}/interfaces`);
  }

  getAgentStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/agent-status`);
  }

  getInterface(): Observable<any> {
    return this.http.get(`${this.baseUrl}/interface`);
  }

  setInterface(iface: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/interface`, { interface: iface });
  }

  startServices(): Observable<any> {
    return this.http.post(`${this.baseUrl}/start`, {});
  }

  stopServices(): Observable<any> {
    return this.http.post(`${this.baseUrl}/stop`, {});
  }

  getStats(): Observable<any> {
    return this.http.get(`${this.baseUrl}/stats`);
  }

  getUnifiedStats(): Observable<any> {
    return this.http.get(`${this.baseUrl}/stats/unified`);
  }

  getRecentEvents(hours?: number): Observable<any[]> {
    let url = `${this.baseUrl}/events`;
    if (hours) {
      url += `?hours=${hours}`;
    }
    return this.http.get<any[]>(url);
  }

  getTopIps(): Observable<any> {
    return this.http.get(`${this.baseUrl}/top-ips`);
  }

  getSeverity(): Observable<any> {
    return this.http.get(`${this.baseUrl}/severity`);
  }

  // Platform-wide totals across every tenant — super admin only.
  getSeverityAllTenants(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/severity-all-tenants`);
  }

  getStatsAllTenants(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/stats-all-tenants`);
  }

  getTopIpsAllTenants(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/top-ips-all-tenants`);
  }

  getProtocolsAllTenants(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/protocols-all-tenants`);
  }

  getThreatIntelAllTenants(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/threat-intel-all-tenants`);
  }

  getThreatMapAllTenants(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/threat-map-all-tenants`);
  }

  getEntityScores(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/entity-scores`);
  }

  getNetworkMap(mode?: string, limit?: number): Observable<any> {
    let url = `${this.baseUrl}/network-map`;
    const params: string[] = [];
    if (mode) params.push(`mode=${encodeURIComponent(mode)}`);
    if (limit !== undefined) params.push(`limit=${limit}`);
    if (params.length) url += '?' + params.join('&');
    return this.http.get(url);
  }

  getNetworkMapNode(ip: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/network-map/node/${encodeURIComponent(ip)}`);
  }

  searchNetworkMap(query: string): Observable<string[]> {
    return this.http.get<string[]>(`${this.baseUrl}/network-map/search?q=${encodeURIComponent(query)}`);
  }

  getScaleStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/scale-status`);
  }
  getRules(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/rules`);
  }

  searchRules(q: string): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/rules?q=${encodeURIComponent(q)}`);
  }

  // Paginated rule listing — used by the analyst Rules page so it doesn't
  // pull the entire (1000+ row) rule set on every load. X-Total-Count /
  // X-Active-Count let the caller show accurate summary stats even though
  // only one page of rows actually came back.
  getRulesPage(limit: number, offset: number, q?: string, order?: 'desc'): Observable<{ rules: any[]; total: number; activeTotal: number }> {
    let url = `${this.baseUrl}/rules?limit=${limit}&offset=${offset}`;
    if (q) url += `&q=${encodeURIComponent(q)}`;
    if (order) url += `&order=${order}`;
    return this.http.get<any[]>(url, { observe: 'response' }).pipe(
      map(resp => ({
        rules: resp.body || [],
        total: parseInt(resp.headers.get('X-Total-Count') || '0', 10),
        activeTotal: parseInt(resp.headers.get('X-Active-Count') || '0', 10),
      }))
    );
  }



  createRule(rule: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/rules`, rule);
  }

  deleteRule(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/rules/${id}`);
  }



  getThreatIntel(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat-intel`);
  }

  getThreatIntelMap(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat-intel-map`);
  }

  lookupIoc(ip: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat-intel/${ip}`);
  }

  getWatchlistIocs(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat-intel/watchlist`);
  }

  deleteWatchlistIoc(value: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/threat-intel/watchlist/${encodeURIComponent(value)}`);
  }

  getThreatMap(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat-map`);
  }
  reloadRules(): Observable<any> {
    return this.http.post(`${this.baseUrl}/rules/reload`, {});
  }
  syncCommunityRules(): Observable<any> {
    return this.http.post(`${this.baseUrl}/rules/sync-community`, {});
  }

  getRuleHitCounts(): Observable<{ [ruleName: string]: number }> {
    return this.http.get<{ [ruleName: string]: number }>(`${this.baseUrl}/rules/hit-counts`);
  }

  getRuleById(id: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/rules/${id}`);
  }

  toggleRule(id: string, enabled: boolean): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/rules/${id}/toggle`,
      { enabled }
    );
  }

  exportReport(format: string, hours: number = 24): void {
    const url = `${this.baseUrl}/export?format=${format}&hours=${hours}`;

    this.http.get(url, { responseType: 'blob', observe: 'response' })
      .subscribe(response => {
        const blob = response.body;
        if (!blob) return;

        const contentDisposition = response.headers.get('content-disposition');
        const filename = contentDisposition?.match(/filename="(.+)"/)?.[1]
          ?? `ndr-report.${format}`;

        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(objectUrl);
      });
  }

  exportNetworkLogs(format: string, hours: number = 24): void {
    const url = `${this.baseUrl}/export-logs?format=${format}&hours=${hours}`;

    this.http.get(url, { responseType: 'blob', observe: 'response' })
      .subscribe(response => {
        const blob = response.body;
        if (!blob) return;

        const contentDisposition = response.headers.get('content-disposition');
        const filename = contentDisposition?.match(/filename="(.+)"/)?.[1]
          ?? `ndr-logs.${format}`;

        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(objectUrl);
      });
  }

  getPlaybooks(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/status`);
  }

  getSettings(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings`);
  }

  updateSettings(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings`, data);
  }

  getGlobalSmtp(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings/smtp`);
  }

  updateGlobalSmtp(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/smtp`, data);
  }

  getAiConfig(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings/ai`);
  }

  updateAiConfig(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/ai`, data);
  }

  listAiProviders(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings/ai/providers`);
  }

  saveAiProvider(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/ai/providers`, data);
  }

  deleteAiProvider(name: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/settings/ai/providers/${encodeURIComponent(name)}`);
  }

  testAiProvider(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/ai/providers/test`, data);
  }

  getTrustedCloudSettings(): Observable<any> {
    return this.http.get(`${this.baseUrl}/settings/trusted-cloud`);
  }

  updateTrustedCloudSettings(data: {keywords?: string[], domains?: string[]}): Observable<any> {
    return this.http.put(`${this.baseUrl}/settings/trusted-cloud`, data);
  }

  approveTrustedCloudSuggestion(org: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/trusted-cloud/suggestions/approve`, { org });
  }

  rejectTrustedCloudSuggestion(org: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/settings/trusted-cloud/suggestions/reject`, { org });
  }

  suppressAlert(srcIp: string, dstIp: string, communityId: string, tag: string, durationHours = 24): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/ai-suppressions`, {
      src_ip: srcIp, dst_ip: dstIp, community_id: communityId, tag, duration_hours: durationHours
    }).pipe(map(res => {
      // The engine reports a failed save as HTTP 200 with {"error": ...}; without this the
      // caller would treat it as saved and the alert would come back on the next refresh.
      if (!res || res.error || res.ok !== true) throw new Error(res?.error || 'Suppression was not saved');
      return res;
    }));
  }

  // Alert triage (new): rule + AI review that produces recommendations only.
  getTriage(): Observable<any>            { return this.http.get(`${this.baseUrl}/triage`); }
  runTriage(): Observable<any>            { return this.http.post(`${this.baseUrl}/triage/run`, {}); }
  applyTriage(id: string, hours = 24): Observable<any> { return this.http.post(`${this.baseUrl}/triage/${id}/apply`, { hours }); }
  dismissTriage(id: string): Observable<any> { return this.http.post(`${this.baseUrl}/triage/${id}/dismiss`, {}); }

  getActiveSuppressions(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/ai-suppressions`);
  }

  listTrustedDomains(): Observable<any> {
    return this.http.get(`${this.baseUrl}/trusted-domains`);
  }

  addTrustedDomain(domain: string, category: string, tenantId: string, note: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/trusted-domains`, {
      domain, category, tenant_id: tenantId, note
    });
  }

  deleteTrustedDomain(domain: string, tenantId: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/trusted-domains/delete`, {
      domain, tenant_id: tenantId
    });
  }

  aiSuggestTrustedDomains(): Observable<any> {
    return this.http.post(`${this.baseUrl}/trusted-domains/ai-suggest`, {});
  }

  getAssets(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/assets`);
  }

  getIpamSubnets(): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/ipam/subnets`);
  }

  updateAsset(ip: string, payload: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/assets/${ip}`, payload);
  }

  setAssetTrusted(ip: string, trusted: boolean): Observable<any> {
    return this.http.patch(`${this.baseUrl}/assets/${ip}/trusted`, { trusted });
  }

  togglePlaybook(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/playbook/toggle`, data);
  }
  createPlaybook(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/playbook/create`, data);
  }

  getIntegrations(): Observable<any> {
    return this.http.get(
      `${this.baseUrl}/soar/integrations`);
  }

  saveIntegration(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/integrations`, data);
  }

  testIntegration(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/integrations/test`, data);
  }

  toggleIntegration(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/integrations/toggle`, data);
  }

  deleteIntegration(data: any): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/soar/integrations/delete`, data);
  }

  // User management
  getUsers(): Observable<any> {
    return this.http.get(`${this.baseUrl}/auth/users`);
  }

  createUser(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/users`, data);
  }

  updateUser(id: string, data: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/auth/users/${id}`, data);
  }

  updateProfileGmail(gmail: string): Observable<any> {
    return this.http.put(`${this.baseUrl}/auth/me/gmail`, { gmail });
  }

  regenerateSecretCode(): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/me/regenerate-secret`, {});
  }

  setUserStatus(id: string, active: boolean): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/users/${id}/status`, { active });
  }

  updateUserPermissions(id: string, permissions: string[]): Observable<any> {
    return this.http.put(`${this.baseUrl}/auth/users/${id}/permissions`, { permissions });
  }

  resetUserPassword(id: string, password: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/users/${id}/password`, { password });
  }

  // Forgot password flow
  forgotVerifySecret(username: string, secret_code: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/forgot/verify-secret`, { username, secret_code });
  }

  forgotSendOtp(username: string, gmail: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/forgot/send-otp`, { username, gmail });
  }

  forgotResetPassword(username: string, otp: string, new_password: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/forgot/reset-password`, { username, otp, new_password });
  }

  /** Self-service password change — verifies old_password server-side, no session required.
   *  Used to force a real password onto the default seed accounts on first login. */
  selfResetPassword(username: string, tenant_id: string, old_password: string, new_password: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/reset-password`, { username, tenant_id, old_password, new_password });
  }


  deleteUser(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/auth/users/${id}`);
  }

  // Tenant management
  getTenants(): Observable<any> {
    return this.http.get(`${this.baseUrl}/auth/tenants`);
  }

  createTenant(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/tenants`, data);
  }

  updateTenant(id: string, data: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/auth/tenants/${id}`, data);
  }

  setTenantStatus(id: string, active: boolean): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/tenants/${id}/status`, { active });
  }

  setTenantAiEnabled(id: string, enabled: boolean): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/tenants/${id}/ai-enabled`, { enabled });
  }

  getTenantFeatures(): Observable<any> {
    return this.http.get(`${this.baseUrl}/tenant/features`);
  }

  setTenantFeatures(tenantId: string, features: string[]): Observable<any> {
    return this.http.post(`${this.baseUrl}/auth/tenants/${tenantId}/features`, { features });
  }

  generateLicense(payload: {
    tenant_id: string; tenant_name: string;
    features: string[]; max_sensors: number; expires_days: number;
    admin_user?: string;
  }): Observable<any> {
    return this.http.post(`${this.baseUrl}/license/generate`, payload);
  }

  getLicensePublicKey(): Observable<any> {
    return this.http.get(`${this.baseUrl}/license/public-key`);
  }

  getLicenses(tenantId?: string): Observable<any> {
    const url = tenantId
      ? `${this.baseUrl}/licenses?tenant_id=${encodeURIComponent(tenantId)}`
      : `${this.baseUrl}/licenses`;
    return this.http.get(url);
  }

  deleteLicense(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/licenses/${encodeURIComponent(id)}`);
  }

  getAnnouncements(): Observable<Announcement[]> {
    return this.http
      .get<AnnouncementListResponse>(`${this.baseUrl}/announcements`)
      .pipe(map(response => {
        if (response.status && response.status !== 'ok') {
          throw new Error(response.message || 'Failed to load announcements');
        }
        return response.announcements || [];
      }));
  }

  getActiveAnnouncements(): Observable<Announcement[]> {
    return this.http
      .get<AnnouncementListResponse>(`${this.baseUrl}/announcements/active`)
      .pipe(map(response => {
        if (response.status && response.status !== 'ok') {
          throw new Error(response.message || 'Failed to load active announcements');
        }
        return response.announcements || [];
      }));
  }

  createAnnouncement(data: Partial<Announcement>): Observable<any> {
    return this.http.post(`${this.baseUrl}/announcements`, data);
  }

  updateAnnouncement(id: string, data: Partial<Announcement>): Observable<any> {
    return this.http.put(`${this.baseUrl}/announcements/${id}`, data);
  }

  markAnnouncementRead(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/announcements/${id}/read`, {});
  }

  deleteAnnouncement(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/announcements/${id}`);
  }

  getEngines(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/engines`);
  }

  getPlatformTelemetry(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/telemetry`);
  }

  getClientErrors(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/client-errors`);
  }


  getKafkaStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/monitor/kafka`);
  }

  getLeaderStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/leader-status`);
  }

  scaleEngines(action: string, engine?: string): Observable<any> {
    return this.http.post(
      `${this.baseUrl}/admin/engines/scale`,
      { action, engine }
    );
  }

  getSensorKeys(): Observable<SensorKey[]> {
    return this.http
      .get<SensorKeyListResponse | SensorKey[]>(`${this.baseUrl}/sensor-keys`)
      .pipe(map(response => {
        if (Array.isArray(response)) {
          return response;
        }
        if (response.status && response.status !== 'ok') {
          throw new Error(response.message || 'Failed to load sensor keys');
        }
        return response.keys || [];
      }));
  }

  // Real per-sensor event counts (last 1h) for the caller's own tenant,
  // keyed by sensor_id (== key_prefix). Used to show actual sensor
  // throughput instead of a placeholder online/offline flag.
  getSensorEventCounts(): Observable<Record<string, number>> {
    return this.http
      .get<{ status?: string; counts?: Record<string, number>; message?: string }>(`${this.baseUrl}/sensor-keys/event-counts`)
      .pipe(map(response => response.counts || {}));
  }

  // Real per-minute event counts (last 60 minutes) for the caller's own
  // tenant — a genuine history for an ingestion sparkline, not simulated.
  getStatsTimeline(): Observable<number[]> {
    return this.http
      .get<{ status?: string; points?: number[]; message?: string }>(`${this.baseUrl}/stats/timeline`)
      .pipe(map(response => response.points || []));
  }

  // Real IP most recently seen from each sensor's own traffic (no IP is
  // stored on sensor_keys itself — this is derived from actual events).
  getSensorRecentIps(): Observable<Record<string, string>> {
    return this.http
      .get<{ status?: string; ips?: Record<string, string>; message?: string }>(`${this.baseUrl}/sensor-keys/recent-ips`)
      .pipe(map(response => response.ips || {}));
  }

  createSensorKey(tenantId: string, name: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensor-keys`, {
      tenant_id: tenantId,
      name,
    });
  }

  revokeSensorKey(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/sensor-keys/${id}`);
  }

  reactivateSensorKey(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensor-keys/${id}/reactivate`, {});
  }

  controlSensor(command: SensorControlCommand, tenantId: string, sensorId: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensor/control`, {
      command,
      tenant_id: tenantId,
      sensor_id: sensorId,
    });
  }

  getSupportMessages(): Observable<SupportMessage[]> {
    return this.http
      .get<SupportMessageListResponse>(`${this.baseUrl}/support/messages`)
      .pipe(map(response => {
        if (response.status && response.status !== 'ok') {
          throw new Error(response.message || 'Failed to load support messages');
        }
        return response.messages || [];
      }));
  }

  createSupportMessage(data: { subject: string; category: string; message: string }): Observable<any> {
    return this.http.post(`${this.baseUrl}/support/messages`, data);
  }

  reviewSupportMessage(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/support/messages/${id}/review`, {});
  }

  replySupportMessage(id: string, reply: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/support/messages/${id}/reply`, { reply });
  }

  forwardSupportMessage(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/support/messages/${id}/forward`, {});
  }

  deleteSupportMessage(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/support/messages/${id}`);
  }

  // --- Native SOAR ---
  getNativePlaybooks(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/native/playbooks`);
  }
  createNativePlaybook(data: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/native/playbooks`, data);
  }
  updateNativePlaybook(id: string, data: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/soar/native/playbooks/${id}`, data);
  }
  deleteNativePlaybook(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/soar/native/playbooks/${id}`);
  }
  getSoarCases(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/cases`);
  }
  getActiveBlocks(): Observable<any> {
    return this.http.get(`${this.baseUrl}/blocks`);
  }
  createSoarCase(payload: any): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/cases`, payload);
  }
  updateSoarCase(id: string, payload: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/soar/cases/${id}`, payload);
  }
  updateSoarCaseStatus(id: string, status: string): Observable<any> {
    return this.http.put(`${this.baseUrl}/soar/cases/${id}/status`, { status });
  }
  getSoarCaseComments(id: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/cases/${id}/comments`);
  }
  addSoarCaseComment(id: string, comment: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/cases/${id}/comments`, { comment });
  }
  getSoarRuns(): Observable<any> {
    return this.http.get(`${this.baseUrl}/soar/runs`);
  }

  getEventsByCid(cid: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/events/by-cid?cid=${encodeURIComponent(cid)}`);
  }

  triggerEvidenceCapture(communityId: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/evidence/trigger`, { community_id: communityId });
  }

  getAiActivity(): Observable<any> {
    return this.http.get(`${this.baseUrl}/ai-activity`);
  }

  deactivateAiSuppression(id: string): Observable<any> {
    return this.http.patch(`${this.baseUrl}/ai-suppressions/${id}/deactivate`, {});
  }

  deleteAiSuppression(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/ai-suppressions/${id}`);
  }

  getProtocols(): Observable<any> {
    return this.http.get(`${this.baseUrl}/protocols`);
  }

  updateIntegration(id: string, data: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/soar/integrations/${id}`, data);
  }

  getThreatPredictions(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat/predictions`);
  }

  getThreatPredictionsHistory(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat/predictions/history`);
  }

  getThreatPatterns(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat/patterns`);
  }

  getThreatExposure(): Observable<any> {
    return this.http.get(`${this.baseUrl}/threat/exposure`);
  }

  getSubnetRoles(): Observable<any> {
    return this.http.get(`${this.baseUrl}/assets/subnet-roles`);
  }

  setSubnetRoles(roles: any): Observable<any> {
    return this.http.put(`${this.baseUrl}/assets/subnet-roles`, roles);
  }

  addManualIoc(type: string, value: string, attacker_group?: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/threat-intel/add`, { type, value, attacker_group: attacker_group || '' });
  }

  getJiraTickets(config: { url: string; email: string; token: string; project_key: string }): Observable<any> {
    return this.http.post(`${this.baseUrl}/soar/jira/tickets`, config);
  }

  // ── Sensor Assignments ────────────────────────────────────────────────────

  getSensorAssignments(): Observable<{ assignments: SensorAssignment[] }> {
    return this.http.get<{ assignments: SensorAssignment[] }>(`${this.baseUrl}/sensors/assignments`);
  }

  assignSensor(user_id: string, sensor_id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sensors/assign`, { user_id, sensor_id });
  }

  unassignSensor(user_id: string, sensor_id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/sensors/assign`, { body: { user_id, sensor_id } });
  }

  // ── Active Blocks ─────────────────────────────────────────────────────────

  listActiveBlocks(): Observable<any> {
    return this.http.get(`${this.baseUrl}/blocks`);
  }

  manualBlock(data: {
    src_ip: string;
    src_port?: number;
    duration_hours?: number;
    enforcement?: string;
    reason?: string;
  }): Observable<any> {
    return this.http.post(`${this.baseUrl}/blocks/manual`, data);
  }

  revokeBlock(id: string, sensor_id?: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/blocks/revoke`, { id, sensor_id });
  }

  // ── Device Isolations ─────────────────────────────────────────────────────

  listIsolations(): Observable<any> {
    return this.http.get(`${this.baseUrl}/isolations`);
  }

  isolateDevice(data: {
    target_ip: string;
    gateway_ip?: string;
    enforcement?: string;
    quarantine_vlan?: number;
    reason?: string;
  }): Observable<any> {
    return this.http.post(`${this.baseUrl}/isolate`, data);
  }

  unisolateDevice(id: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/unisolate`, { id });
  }

  getIncidents(): Observable<any> {
    return this.http.get(`${this.baseUrl}/incidents`);
  }

  updateIncidentStatus(id: string, status: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/incidents/${id}/status/${status}`, {});
  }

  getVersionStatus(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/version`);
  }

  applyUpdate(): Observable<any> {
    return this.http.post(`${this.baseUrl}/admin/apply-update`, {});
  }

  getActiveSessions(): Observable<any> {
    return this.http.get(`${this.baseUrl}/admin/active-sessions`);
  }

  forceLogoutUser(username: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/admin/sessions/${encodeURIComponent(username)}`);
  }

  forceLogoutDevice(username: string, ip: string, device: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/admin/sessions/${encodeURIComponent(username)}/device`, { body: { ip, device } });
  }

  geoLookup(ips: string[]): Observable<any> {
    return this.http.post(`${this.baseUrl}/geo-lookup`, { ips });
  }

  // ── Honeypots ──────────────────────────────────────────────────────────────

  getHoneypots(): Observable<any> {
    return this.http.get(`${this.baseUrl}/honeypots`);
  }

  addHoneypot(name: string, cidr: string, description: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/honeypots`, { name, cidr, description });
  }

  deleteHoneypot(id: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/honeypots/${encodeURIComponent(id)}`);
  }

  // ── Retrospective Detection ─────────────────────────────────────────────

  getFiredRules(): Observable<any> {
    return this.http.get(`${this.baseUrl}/retrospective/fired-rules`);
  }

  startRetroScan(rule_id: string, rule_name: string, rule_content: string, hours_back: number): Observable<any> {
    return this.http.post(`${this.baseUrl}/retrospective/scan`, { rule_id, rule_name, rule_content, hours_back });
  }

  listRetroScans(): Observable<any> {
    return this.http.get(`${this.baseUrl}/retrospective/scans`);
  }

  getRetroScan(id: string): Observable<any> {
    return this.http.get(`${this.baseUrl}/retrospective/scans/${encodeURIComponent(id)}`);
  }
}
