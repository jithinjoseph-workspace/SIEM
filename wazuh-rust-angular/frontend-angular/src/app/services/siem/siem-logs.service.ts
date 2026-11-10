import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, of } from 'rxjs';
import { RawEvent } from '../../models/siem.models';

@Injectable({
  providedIn: 'root'
})
export class SiemLogsService {
  private http = inject(HttpClient);
  private apiUrl = typeof window !== 'undefined' && window.location.port === '4200' ? 'http://127.0.0.1:8088' : '';

  getRawEvents(limit: number = 200, source?: string): Observable<RawEvent[]> {
    let url = `${this.apiUrl}/api/v1/events?limit=${limit}`;
    if (source && source !== 'all') {
      url += `&source=${source}`;
    }
    return this.http.get<RawEvent[]>(url).pipe(
      catchError(() => of([]))
    );
  }
}
