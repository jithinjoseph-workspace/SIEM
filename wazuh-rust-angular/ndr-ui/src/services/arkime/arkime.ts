import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

@Injectable({ providedIn: 'root' })
export class ArkimeService {
  constructor(private http: HttpClient) {}

  getStatus(): Observable<any> {
    return this.http.get('/api/arkime/status');
  }

  getSessions(params?: { cid?: string; ip?: string; src_ip?: string; dst_ip?: string; limit?: number }): Observable<any> {
    let query = `/api/arkime/sessions?limit=${params?.limit ?? 50}`;
    if (params?.cid)    query += `&cid=${encodeURIComponent(params.cid)}`;
    if (params?.ip)     query += `&ip=${encodeURIComponent(params.ip)}`;
    if (params?.src_ip) query += `&src_ip=${encodeURIComponent(params.src_ip)}`;
    if (params?.dst_ip) query += `&dst_ip=${encodeURIComponent(params.dst_ip)}`;
    return this.http.get(query);
  }

  getSessionLink(communityId: string): Observable<any> {
    return this.http.get(`/api/arkime/link/${encodeURIComponent(communityId)}`);
  }

  private buildPcapParams(node: string, session?: any): string {
    const p = new URLSearchParams();
    if (node)                      p.set('node',     node);
    if (session?.src_ip)           p.set('src_ip',   session.src_ip);
    if (session?.dst_ip)           p.set('dst_ip',   session.dst_ip);
    if (session?.src_port)         p.set('src_port', String(session.src_port));
    if (session?.dst_port)         p.set('dst_port', String(session.dst_port));
    const s = p.toString();
    return s ? `?${s}` : '';
  }

  downloadPcap(sessionId: string, node = '', session?: any): void {
    const qs = this.buildPcapParams(node, session);
    window.open(`/api/pcap/${encodeURIComponent(sessionId)}${qs}`, '_blank');
  }

  fetchPcapRaw(sessionId: string, node = '', session?: any): Observable<ArrayBuffer> {
    const qs = this.buildPcapParams(node, session);
    return this.http.get(`/api/pcap/${encodeURIComponent(sessionId)}${qs}`, {
      responseType: 'arraybuffer',
      observe: 'response',
    }).pipe(
      map(resp => resp.body as ArrayBuffer)
    );
  }
}
