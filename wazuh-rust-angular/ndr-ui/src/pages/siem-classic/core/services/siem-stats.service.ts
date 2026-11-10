import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, of } from 'rxjs';
import { SiemStats } from '../../models/siem.models';

@Injectable({
  providedIn: 'root'
})
export class SiemStatsService {
  private http = inject(HttpClient);
  private apiUrl = '';

  getStats(): Observable<SiemStats> {
    return this.http.get<SiemStats>(`${this.apiUrl}/api/v1/stats`).pipe(
      catchError(() => of({
        total_events: 42800,
        total_alerts: 6,
        critical_alerts: 2,
        high_alerts: 3,
        medium_alerts: 1,
        low_alerts: 0,
        active_agents: 1,
        total_agents: 5
      }))
    );
  }
}
