import { Component, OnInit, OnDestroy, inject, signal, computed, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { interval, Subscription } from 'rxjs';
import { LucideAngularModule, ScrollText, Search, Play, Pause, RefreshCw, Filter, Terminal } from 'lucide-angular';
import { SiemLogsService } from '../../../services/siem/siem-logs.service';
import { RawEvent } from '../../../models/siem.models';

@Component({
  selector: 'app-siem-logs',
  standalone: true,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './siem-logs.component.html',
  styleUrl: './siem-logs.component.css'
})
export class SiemLogsComponent implements OnInit, OnDestroy {
  private logsService = inject(SiemLogsService);
  private timerSub?: Subscription;

  @Input() compactMode = false;

  logs = signal<RawEvent[]>([]);
  loading = signal<boolean>(true);
  searchQuery = signal<string>('');
  selectedSource = signal<string>('all');
  isStreaming = signal<boolean>(true);
  selectedEvent = signal<RawEvent | null>(null);

  ScrollTextIcon = ScrollText;
  SearchIcon = Search;
  PlayIcon = Play;
  PauseIcon = Pause;
  RefreshIcon = RefreshCw;
  FilterIcon = Filter;
  TerminalIcon = Terminal;

  filteredLogs = computed(() => {
    const query = this.searchQuery().toLowerCase().trim();
    const src = this.selectedSource();
    return this.logs().filter(e => {
      const matchQuery = !query ||
        e.message.toLowerCase().includes(query) ||
        e.agent_id.toLowerCase().includes(query) ||
        e.location.toLowerCase().includes(query);
      const matchSrc = src === 'all' || e.source === src;
      return matchQuery && matchSrc;
    });
  });

  ngOnInit() {
    this.fetchLogs();
    this.startStreaming();
  }

  ngOnDestroy() {
    this.timerSub?.unsubscribe();
  }

  startStreaming() {
    this.timerSub = interval(3000).subscribe(() => {
      if (this.isStreaming()) {
        this.fetchLogs(true);
      }
    });
  }

  toggleStreaming() {
    this.isStreaming.update(v => !v);
  }

  fetchLogs(silent = false) {
    if (!silent) this.loading.set(true);
    this.logsService.getRawEvents(150, this.selectedSource()).subscribe({
      next: (data) => {
        this.logs.set(data);
        if (!silent) this.loading.set(false);
      },
      error: () => {
        if (!silent) this.loading.set(false);
      }
    });
  }

  selectEvent(event: RawEvent) {
    this.selectedEvent.set(event);
  }

  closeModal() {
    this.selectedEvent.set(null);
  }

  getSourceBadgeClass(source: string): string {
    switch (source) {
      case 'syslog': return 'src-syslog';
      case 'windows_event': return 'src-windows';
      case 'fim': return 'src-fim';
      case 'sca': return 'src-sca';
      case 'syscollector': return 'src-syscol';
      default: return 'src-default';
    }
  }
}
