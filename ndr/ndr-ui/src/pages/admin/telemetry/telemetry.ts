import { Component, OnInit, OnDestroy, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  LucideAngularModule,
  Cpu, MemoryStick, RefreshCw, HardDrive, Server, Activity, ShieldCheck,
  Clock, Layers, Zap, Radio, CheckCircle2, AlertTriangle, Database, TrendingUp, Gauge, Terminal
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { ClockService } from '../../../services/clock/clock';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-telemetry',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, LucideAngularModule],
  templateUrl: './telemetry.html',
  styleUrl: './telemetry.css',
})
export class Telemetry implements OnInit, OnDestroy {
  Math = Math;

  CpuIcon          = Cpu;
  MemoryStickIcon  = MemoryStick;
  RefreshIcon      = RefreshCw;
  HardDriveIcon    = HardDrive;
  ServerIcon       = Server;
  ActivityIcon     = Activity;
  ShieldCheckIcon  = ShieldCheck;
  ClockIcon        = Clock;
  LayersIcon       = Layers;
  ZapIcon            = Zap;
  RadioIcon        = Radio;
  CheckCircle2Icon = CheckCircle2;
  AlertTriangleIcon= AlertTriangle;
  DatabaseIcon     = Database;
  TrendingUpIcon   = TrendingUp;
  GaugeIcon        = Gauge;
  TerminalIcon     = Terminal;

  telemetryData: any = null;
  kafkaData: any = null;
  engines: any[] = [];
  sensorKeys: any[] = [];
  clientErrors: any[] = [];
  loadingClientErrors = false;
  isLoading = true;
  isRefreshing = false;

  lastUpdatedTime = '';

  private pollInterval: any = null;

  constructor(private api: Api, private cdr: ChangeDetectorRef, public clock: ClockService) {}

  ngOnInit() {
    this.loadAllTelemetry();
    this.loadClientErrors();
    this.pollInterval = setInterval(() => this.pollLiveMetrics(), 10000);
  }

  loadClientErrors() {
    this.loadingClientErrors = true;
    this.api.getClientErrors().subscribe({
      next: (res: any) => {
        this.clientErrors = res?.errors || [];
        this.loadingClientErrors = false;
        this.cdr.detectChanges();
      },
      error: (e: any) => {
        this.loadingClientErrors = false;
        this.cdr.detectChanges();
        reportRxjsError(e);
      }
    });
  }

  ngOnDestroy() {
    if (this.pollInterval) clearInterval(this.pollInterval);
  }

  loadAllTelemetry() {
    this.isLoading = true;
    this.pollLiveMetrics(() => {
      this.isLoading = false;
      this.cdr.detectChanges();
    });
    this.loadSupportingClusterData();
  }

  triggerManualRefresh() {
    this.isRefreshing = true;
    this.pollLiveMetrics(() => {
      this.loadSupportingClusterData();
      setTimeout(() => {
        this.isRefreshing = false;
        this.cdr.detectChanges();
      }, 400);
    });
  }

  pollLiveMetrics(onComplete?: () => void) {
    this.api.getPlatformTelemetry().subscribe({
      next: (data: any) => {
        this.telemetryData = data;
        const now = new Date();
        this.lastUpdatedTime = now.toTimeString().split(' ')[0];
        if (onComplete) onComplete();
        this.cdr.detectChanges();
      },
      error: () => {
        if (onComplete) onComplete();
        this.cdr.detectChanges();
      }
    });
  }

  loadSupportingClusterData() {
    this.api.getKafkaStatus().subscribe({
      next: (res: any) => {
        this.kafkaData = res;
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });

    this.api.getEngines().subscribe({
      next: (res: any) => {
        this.engines = res?.engines || (Array.isArray(res) ? res : []);
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });

    this.api.getSensorKeys().subscribe({
      next: (res: any) => {
        this.sensorKeys = Array.isArray(res) ? res : (res?.keys || []);
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });
  }

  get cpuPercent(): number {
    return Math.round(this.telemetryData?.cpu_usage_percent || 0);
  }

  get memoryPercent(): number {
    return Math.round(this.telemetryData?.memory_percent || 0);
  }

  get memoryUsedGb(): number {
    return this.telemetryData?.memory_used_gb || 0;
  }

  get memoryTotalGb(): number {
    return this.telemetryData?.memory_total_gb || 0;
  }

  get memoryFreeGb(): number {
    const total = this.memoryTotalGb;
    const used = this.memoryUsedGb;
    return Math.max(0, total - used);
  }

  get eventsPerSec(): number {
    return this.telemetryData?.events_per_sec || 0;
  }

  get events1h(): number {
    return this.telemetryData?.events_1h || 0;
  }

  get activeEnginesCount(): number {
    return this.engines.filter(e =>
      (e.status || '').toLowerCase().includes('up') ||
      (e.status || '').toLowerCase().includes('run') ||
      (e.status || '').toLowerCase().includes('health')
    ).length;
  }

  get totalEnginesCount(): number {
    return this.engines.length;
  }

  get activeSensorsCount(): number {
    return this.sensorKeys.filter(s => s.active).length;
  }

  get totalSensorsCount(): number {
    return this.sensorKeys.length;
  }

  get kafkaLag(): number {
    return this.kafkaData?.total_lag ?? 0;
  }

  get kafkaPartitions(): number {
    return this.kafkaData?.partition_count || this.kafkaData?.partitions?.length || 0;
  }

  get kafkaInSyncPartitions(): number {
    return (this.kafkaData?.partitions || []).filter((p: any) => p.in_sync).length;
  }
}
