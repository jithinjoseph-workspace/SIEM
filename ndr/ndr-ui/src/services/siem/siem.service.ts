import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { Agent, Alert, Rule, SiemStats, RawEvent, AgentInventory } from '../../models/siem.models';
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
 */
@Injectable({
  providedIn: 'root'
})
export class SiemService {
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
}
