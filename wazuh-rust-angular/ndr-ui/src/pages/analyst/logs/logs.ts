import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../../../services/api/api';
import { Websocket } from '../../../services/websocket/websocket';
import { Subscription } from 'rxjs';
import { LucideAngularModule, Search, Terminal, RefreshCw, FileText, Activity, Download } from 'lucide-angular';
import { ActivatedRoute } from '@angular/router';
import { Live } from '../live/live';
import { AuthService } from '../../../services/auth/auth';


@Component({
  selector: 'app-logs',
  standalone: true,
  imports: [CommonModule, LucideAngularModule, FormsModule, Live],
  templateUrl: './logs.html',
  styleUrl: './logs.css'
})
export class Logs implements OnInit, OnDestroy {
  logs: any[] = [];
  filteredLogs: any[] = [];
  searchText: string = '';
  totalCount: number = 0;
  loading: boolean = true;
  activeTab: 'logs' | 'live' = 'logs';
  timeRange: number = 24;
  exportFormat: string = 'csv';

  TerminalIcon = Terminal;
  SearchIcon = Search;
  RefreshIcon = RefreshCw;
  FileTextIcon = FileText;
  ActivityIcon = Activity;
  DownloadIcon = Download;

  /** Sensor IDs this user is scoped to (from JWT). */
  sensorIds: string[] = [];

  private subs: Subscription[] = [];

  private updateScheduled = false;
  private scheduleUpdate() {
    if (this.updateScheduled) return;
    this.updateScheduled = true;
    setTimeout(() => {
      this.applyFilter();
      this.cdr.detectChanges();
      this.updateScheduled = false;
    }, 0);
  }

  constructor(
    private api: Api,
    private ws: Websocket,
    private cdr: ChangeDetectorRef,
    private route: ActivatedRoute,
    private auth: AuthService
  ) { }

  ngOnInit() {
    this.sensorIds = this.auth.getSensorIds();

    this.route.queryParams.subscribe(params => {
      if (params['search']) {
        this.searchText = params['search'];
        this.onSearch();
      }
    });

    this.loadLogs();

    // Real-time new events via WebSocket
    this.subs.push(
      this.ws.events$.subscribe((event: any) => {
        const evtTime = event.ts
          ? new Date(event.ts * 1000).toLocaleTimeString('en-US', {
              hour: '2-digit', minute: '2-digit', second: '2-digit'
            })
          : new Date().toLocaleTimeString('en-US', {
              hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        const log = {
          ts: evtTime,
          proto: event.proto?.toUpperCase() || '',
          src: event.src || '',
          dst: event.dst || '',
          source: event.type || '',
          action: 'ALLOW',
          event_type: this.normalizeEventType(event.event_type),
        };
        this.logs.unshift(log);
        if (this.logs.length > 200) this.logs.pop();
        this.scheduleUpdate();
      })
    );
  }

  loadLogs() {
    this.loading = true;
    this.api.getRecentEvents(this.timeRange).subscribe({
      next: (data: any[]) => {
        this.logs = data.map(e => ({
          ts: new Date(e.timestamp * 1000).toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', second: '2-digit'
          }),
          proto: e.proto?.toUpperCase() || '',
          src: e.src_ip || '',
          dst: e.dst_ip || '',
          source: e.source || '',
          action: 'ALLOW',
          event_type: this.normalizeEventType(e.event_type),
        }));
        this.totalCount = data.length;
        this.applyFilter();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: () => {
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  applyFilter() {
    const MAX_DISPLAY = 100;
    const hasEndpoint = (l: any) => {
      const src = l.src?.trim();
      const dst = l.dst?.trim();
      return (src && src !== '-') || (dst && dst !== '-');
    };
    if (!this.searchText) {
      this.filteredLogs = this.logs.filter(hasEndpoint).slice(0, MAX_DISPLAY);
    } else {
      const s = this.searchText.toLowerCase();
      this.filteredLogs = this.logs
        .filter(hasEndpoint)
        .filter(l =>
          l.src?.toLowerCase().includes(s) ||
          l.dst?.toLowerCase().includes(s) ||
          l.proto?.toLowerCase().includes(s) ||
          l.source?.toLowerCase().includes(s)
        ).slice(0, MAX_DISPLAY);
    }
  }

  trackByLog(_: number, log: any): string {
    // Composite key: timestamp + src + dst gives a stable identity per entry.
    return `${log.ts}|${log.src}|${log.dst}|${log.proto}`;
  }

  onSearch() {
    this.applyFilter();
    this.cdr.detectChanges();
  }

  onTimeRangeChange() {
    this.loadLogs();
  }

  exportLogs() {
    this.api.exportNetworkLogs(this.exportFormat, this.timeRange);
  }

  getRowClass(log: any): string {
    const t = this.evtSlug(log.event_type);
    return `log-grid log-row evt-${t}`;
  }

  getEventBadgeClass(eventType: string): string {
    return `event-badge evt-${this.evtSlug(eventType)}`;
  }

  getSourceClass(source: string): string {
    const s = (source || '').toLowerCase();
    if (s === 'agent-s') return 'source-badge src-s';
    if (s === 'agent-z') return 'source-badge src-z';
    return 'source-badge';
  }

  getProtoClass(proto: string): string {
    return `proto-badge proto-${(proto || '').toLowerCase()}`;
  }

  private normalizeEventType(t: string | null | undefined): string {
    return (t && t !== '-') ? t : 'conn';
  }

  private evtSlug(t: string): string {
    return (t || 'conn').toLowerCase().replace(/[^a-z0-9]/g, '') || 'conn';
  }

  ngOnDestroy() {
    this.subs.forEach(s => s.unsubscribe());
  }
}
