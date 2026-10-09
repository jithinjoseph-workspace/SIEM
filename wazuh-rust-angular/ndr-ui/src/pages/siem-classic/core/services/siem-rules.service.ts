import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, of } from 'rxjs';
import { Rule } from '../../models/siem.models';

@Injectable({
  providedIn: 'root'
})
export class SiemRulesService {
  private http = inject(HttpClient);
  private apiUrl = '';

  getRules(): Observable<Rule[]> {
    return this.http.get<Rule[]>(`${this.apiUrl}/api/v1/rules`).pipe(
      catchError(() => of([]))
    );
  }

  getRuleById(id: number): Observable<Rule | null> {
    return this.http.get<Rule>(`${this.apiUrl}/api/v1/rules/${id}`).pipe(
      catchError(() => of(null))
    );
  }
}
