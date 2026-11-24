import { Injectable, NgZone } from '@angular/core';
import { Subject, BehaviorSubject, filter } from 'rxjs';

const HIGH_VOLUME_TYPES = new Set(['hit', 'agent-s', 'agent-z']);
const FLUSH_INTERVAL_MS = 300;

@Injectable({
  providedIn: 'root'
})
export class Websocket {
  private socket: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private updateTimeout: any = null;

  public messages$ = new Subject<any>();
  public lastAgentStatus$ = new BehaviorSubject<any>(null);
  public lastInterfaces$ = new BehaviorSubject<any>(null);
  public lastTelemetry$ = new BehaviorSubject<any>(null);

  public agentStatus$ = this.messages$.pipe(filter(m => m.type === 'agent_status'));
  public interfaces$ = this.messages$.pipe(filter(m => m.type === 'interfaces'));
  public hits$ = this.messages$.pipe(filter(m => m.type === 'hit'));
  public telemetry$ = this.messages$.pipe(filter(m => m.type === 'telemetry'));
  public events$ = this.messages$.pipe(
    filter(m => m.type === 'agent-z' || m.type === 'agent-s')
  );

  private hitsHistory: any[] = [];
  public continuousHits$ = new BehaviorSubject<any[]>([]);

  // Buffer for high-volume events; flushed into zone every FLUSH_INTERVAL_MS
  private pendingBatch: any[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private zone: NgZone) {
    try {
      const stored = sessionStorage.getItem('ndr_live_hits');
      if (stored) {
        this.hitsHistory = JSON.parse(stored);
        this.continuousHits$.next(this.hitsHistory);
      }
    } catch (e) {
      console.warn('Failed to parse cached live hits', e);
    }
  }

  connect() {
    // ── Guard: do not open a second connection if one is already live ──────
    if (
      this.socket &&
      (this.socket.readyState === WebSocket.OPEN ||
       this.socket.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    // ── Cancel any pending reconnect timer ────────────────────────────────
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    // ── Cleanly close the old socket so its onclose cannot fire ──────────
    if (this.socket) {
      const stale = this.socket;
      stale.onclose = null;
      stale.onerror = null;
      stale.close();
      this.socket = null;
    }

    // ── Start batch flush timer outside Angular zone ──────────────────────
    if (!this.flushTimer) {
      this.flushTimer = setInterval(() => this.flushBatch(), FLUSH_INTERVAL_MS);
    }

    try {
      const wsProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${location.host}/ws`;

      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => this.zone.run(() => {
        // Cookie is sent in the HTTP upgrade request (same-origin, SameSite=Strict).
        // The backend authenticates via cookie before the first message.
        // No app-level auth message needed.
      });

      // Message handler runs OUTSIDE zone; only critical events enter zone immediately
      this.socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (HIGH_VOLUME_TYPES.has(data.type)) {
            // Queue for batched zone entry
            this.pendingBatch.push(data);
            return;
          }

          // Critical events enter zone immediately
          this.zone.run(() => {
            this.messages$.next(data);
            if (data.type === 'agent_status') this.lastAgentStatus$.next(data);
            if (data.type === 'interfaces')  this.lastInterfaces$.next(data);
            if (data.type === 'telemetry')   this.lastTelemetry$.next(data);
            if (data.type === 'force_logout') {
              const me = JSON.parse(localStorage.getItem('ndr_user') || '{}')?.username;
              // Respect target_username if present — only kick the right user
              if (!data.target_username || data.target_username === me) {
                this.disconnect();
                localStorage.removeItem('ndr_user');
                localStorage.removeItem('ndr_token');
                sessionStorage.clear();
                // Expire the httpOnly cookie server-side before redirecting
                fetch('/api/auth/logout', { method: 'POST', credentials: 'include' })
                  .finally(() => { window.location.href = '/login'; });
              }
            }
          });
        } catch (e) {
          console.warn('Invalid WS message:', event.data);
        }
      };

      this.socket.onerror = (e) => console.error('WebSocket Error:', e);

      this.socket.onclose = () => {
        console.warn('WebSocket closed, reconnecting in 3s...');
        this.socket = null;
        this.reconnectTimer = setTimeout(() => {
          this.reconnectTimer = null;
          this.connect();
        }, 3000);
      };
    } catch (e) {
      console.warn('WebSocket failed, retrying in 3s...');
      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        this.connect();
      }, 3000);
    }
  }

  private flushBatch() {
    if (this.pendingBatch.length === 0) return;
    const batch = this.pendingBatch.splice(0);
    this.zone.run(() => {
      for (const data of batch) {
        this.messages$.next(data);
        if (data.type === 'hit') {
          this.hitsHistory.unshift(data);
          if (this.hitsHistory.length > 100) this.hitsHistory.pop();
        }
      }
      if (batch.some(d => d.type === 'hit')) {
        this.continuousHits$.next([...this.hitsHistory]);
        if (!this.updateTimeout) {
          this.updateTimeout = setTimeout(() => {
            this.updateTimeout = null;
            try {
              sessionStorage.setItem('ndr_live_hits', JSON.stringify(this.hitsHistory));
            } catch (e) {}
          }, 250);
        }
      }
    });
  }

  disconnect() {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.updateTimeout !== null) {
      clearTimeout(this.updateTimeout);
      this.updateTimeout = null;
    }
    if (this.flushTimer !== null) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    this.pendingBatch = [];
    if (this.socket) {
      this.socket.onclose = null;
      this.socket.onerror = null;
      this.socket.close();
      this.socket = null;
    }
  }

  send(data: any) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(data));
    }
  }
}
