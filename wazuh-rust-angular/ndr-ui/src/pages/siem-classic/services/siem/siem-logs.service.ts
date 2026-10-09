import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, of } from 'rxjs';
import { RawEvent } from '../../models/siem.models';

@Injectable({
  providedIn: 'root'
})
export class SiemLogsService {
  private http = inject(HttpClient);
  private apiUrl = '';

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
