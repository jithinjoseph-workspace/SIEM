import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, of } from 'rxjs';
import { Agent, AgentInventory } from '../../models/siem.models';

@Injectable({
  providedIn: 'root'
})
export class SiemAgentsService {
  private http = inject(HttpClient);
  private apiUrl = typeof window !== 'undefined' && window.location.port === '4200' ? 'http://127.0.0.1:8088' : '';

  getAgents(): Observable<Agent[]> {
    return this.http.get<Agent[]>(`${this.apiUrl}/api/v1/agents`).pipe(
      catchError(() => of([]))
    );
  }

  sendAgentCommand(agentId: string, action: string, target: string = 'all'): Observable<any> {
    return this.http.post(`${this.apiUrl}/api/v1/agent/commands`, {
      command_id: 'cmd-' + Date.now(),
      agent_id: agentId,
      action,
      target
    }).pipe(
      catchError(() => of({ status: 'queued' }))
    );
  }

  getAgentInventory(agentId: string): Observable<AgentInventory | null> {
    return this.http.get<AgentInventory>(`${this.apiUrl}/api/v1/agents/${agentId}/inventory`).pipe(
      catchError(() => of(null))
    );
  }
}
