import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class EvidenceService {
  constructor(private http: HttpClient) {}

  // Download ZIP bundle — fetches with cookie auth then triggers browser download
  downloadBundle(communityId: string): void {
    this.http.get(`/api/evidence/${encodeURIComponent(communityId)}`, {
      responseType: 'blob'
    }).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `evidence_${communityId.replace(/[:/+]/g, '_')}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      },
      error: (err) => console.error('Evidence download failed:', err)
    });
  }

  listBundles(limit = 50): Observable<any> {
    return this.http.get(`/api/evidence/bundles?limit=${limit}`);
  }

  getBundle(bundleId: string): Observable<any> {
    return this.http.get(`/api/evidence/bundle/${bundleId}`);
  }

  verifyBundle(bundleId: string): Observable<any> {
    return this.http.get(`/api/evidence/bundle/${bundleId}/verify`);
  }

  setLegalHold(bundleId: string, hold: boolean, reason: string): Observable<any> {
    return this.http.post(`/api/evidence/bundle/${bundleId}/hold`, { hold, reason });
  }

  annotate(bundleId: string, communityId: string, note: string, tag: string): Observable<any> {
    return this.http.post(`/api/evidence/bundle/${bundleId}/annotate`,
      { community_id: communityId, note, tag });
  }

  getAnnotations(bundleId: string): Observable<any> {
    return this.http.get(`/api/evidence/bundle/${bundleId}/annotations`);
  }

  getTimeline(communityId: string): Observable<any> {
    return this.http.get(`/api/evidence/${encodeURIComponent(communityId)}/timeline`);
  }

  getLog(communityId: string): Observable<any> {
    return this.http.get(`/api/evidence/${encodeURIComponent(communityId)}/log`);
  }

  checkIoc(value: string): Observable<any> {
    return this.http.get(`/api/evidence/iocs/check?value=${encodeURIComponent(value)}`);
  }

  getBundleContents(bundleId: string): Observable<any> {
    return this.http.get(`/api/evidence/bundle/${bundleId}/contents`);
  }

  runInvestigation(communityId: string): Observable<any> {
    return this.http.post('/api/aria/investigate', { community_id: communityId });
  }

  getVerdict(communityId: string): Observable<any> {
    return this.http.get(`/api/aria/verdict?cid=${encodeURIComponent(communityId)}`);
  }

  /** Past AI investigations (this tenant's own) whose circumstances were closest to this one. */
  getSimilarIncidents(communityId: string, limit = 5): Observable<any> {
    return this.http.get(`/api/aria/similar?cid=${encodeURIComponent(communityId)}&limit=${limit}`);
  }

  /** Answers a question from this tenant's own past investigations and how they ended. */
  askHistory(question: string): Observable<any> {
    return this.http.post('/api/aria/ask-history', { question });
  }

  /**
   * SOC GPT: answers a question from this tenant's own data — cases, analyses, and past
   * investigations. `subject` is the session/case the conversation is currently about (from the
   * previous answer); `history` is the last few turns, so the backend can read a follow-up the way a
   * person reading the chat would.
   */
  askPlatform(question: string, subject: string, history: Array<{ role: string; text: string }>): Observable<any> {
    return this.http.post('/api/aria/ask-history', { question, subject, history });
  }
}
