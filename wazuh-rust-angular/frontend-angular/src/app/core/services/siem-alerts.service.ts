import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, Subject, BehaviorSubject, catchError, of } from 'rxjs';
import { Alert } from '../../models/siem.models';

@Injectable({
  providedIn: 'root'
})
export class SiemAlertsService {
  private http = inject(HttpClient);
  private apiUrl = typeof window !== 'undefined' && window.location.port === '4200' ? 'http://127.0.0.1:8088' : '';
  private wsUrl = typeof window !== 'undefined'
    ? (window.location.port === '4200' ? 'ws://127.0.0.1:8088/ws/alerts' : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/alerts`)
    : 'ws://127.0.0.1:8088/ws/alerts';

  private alertStream$ = new Subject<Alert>();
  private wsConnected$ = new BehaviorSubject<boolean>(false);
  private socket?: WebSocket;

  constructor() {
    this.initWebSocket();
  }

  getAlerts(limit: number = 50, minLevel: number = 0): Observable<Alert[]> {
    return this.http.get<Alert[]>(`${this.apiUrl}/api/v1/alerts?limit=${limit}&min_level=${minLevel}`).pipe(
      catchError(() => of([]))
    );
  }

  getAlertStream(): Observable<Alert> {
    return this.alertStream$.asObservable();
  }

  getWsConnected(): Observable<boolean> {
    return this.wsConnected$.asObservable();
  }

  private initWebSocket() {
    if (typeof window === 'undefined') return;
    try {
      this.socket = new WebSocket(this.wsUrl);
      this.socket.onopen = () => {
        this.wsConnected$.next(true);
      };
      this.socket.onmessage = (event) => {
        try {
          const alert: Alert = JSON.parse(event.data);
          this.alertStream$.next(alert);
        } catch {}
      };
      this.socket.onclose = () => {
        this.wsConnected$.next(false);
        setTimeout(() => this.initWebSocket(), 5000);
      };
      this.socket.onerror = () => {
        this.wsConnected$.next(false);
      };
    } catch {}
  }
}
