import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, interval, Subject } from 'rxjs';
import { switchMap, takeUntil } from 'rxjs/operators';

export interface AriaMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  emotion?: string;
  alertCard?: any;
  actions?: string[];
}

@Injectable({ providedIn: 'root' })
export class AriaService {

  private destroy$ = new Subject<void>();

  constructor(private http: HttpClient) {}

  chat(message: string, history: any[]): Observable<any> {
    return this.http.post('/api/aria/chat', { message, history });
  }

  getStatus(): Observable<any> {
    return this.http.get('/api/aria/status');
  }

  pollStatus(intervalMs = 30000): Observable<any> {
    return interval(intervalMs).pipe(
      switchMap(() => this.getStatus()),
      takeUntil(this.destroy$)
    );
  }

  destroy() {
    this.destroy$.next();
    this.destroy$.complete();
  }
}
