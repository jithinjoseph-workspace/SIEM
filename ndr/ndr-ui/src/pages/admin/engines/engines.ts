import { Component, OnInit, OnDestroy, ChangeDetectorRef, ChangeDetectionStrategy, ViewEncapsulation } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  LucideAngularModule,
  Download, Plus, RefreshCw, X,
  Activity, Server, Database, ShieldCheck, Clock, Layers, Zap, HardDrive, CheckCircle2, AlertTriangle
} from 'lucide-angular';
import { Api } from '../../../services/api/api';
import { ClockService } from '../../../services/clock/clock';

import { reportRxjsError } from '../../../services/error-reporter/error-reporter';
@Component({
  selector: 'app-engines',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, LucideAngularModule],
  templateUrl: './engines.html',
  styleUrl: './engines.css',
})
export class Engines implements OnInit, OnDestroy {
  DownloadIcon     = Download;
  PlusIcon         = Plus;
  RefreshIcon      = RefreshCw;
  XIcon            = X;
  ActivityIcon     = Activity;
  ServerIcon       = Server;
  DatabaseIcon     = Database;
  ShieldCheckIcon  = ShieldCheck;
  ClockIcon        = Clock;
  LayersIcon       = Layers;
  ZapIcon          = Zap;
  HardDriveIcon    = HardDrive;
  CheckCircleIcon  = CheckCircle2;
  AlertTriangleIcon = AlertTriangle;

  engines: any[]    = [];
  loadingEngines    = false;
  scaling           = false;
  pendingStopEngine = '';
  lastEngineRefresh: Date | null = null;

  kafkaData: any    = null;
  kafkaLoading      = false;
  private kafkaInterval: any = null;

  syncingRules  = false;
  syncMessage   = '';
  syncError     = false;

  Math = Math;

  msg     = '';
  msgType = '';

  // Real telemetry
  eventsPerSec = 0;
  events1h = 0;
  cpuUsage = 0;
  memoryUsedGb = 0;
  private telemetryTimer: any = null;

  constructor(private api: Api, private cdr: ChangeDetectorRef, public clock: ClockService) {}

  get activeEngines(): number {
    return this.engines.filter(e =>
      e.status?.toLowerCase().includes('up') ||
      e.status?.toLowerCase().includes('run') ||
      e.status?.toLowerCase().includes('health')
    ).length;
  }

  get clusterAvailability(): number {
    if (!this.engines.length) return 100;
    return Math.round((this.activeEngines / this.engines.length) * 100);
  }

  get totalPartitions(): number {
    return this.kafkaData?.partition_count || this.kafkaData?.partitions?.length || 0;
  }

  get inSyncPartitions(): number {
    return (this.kafkaData?.partitions || []).filter((p: any) => p.in_sync).length;
  }

  get totalLag(): number {
    return this.kafkaData?.total_lag ?? 0;
  }

  ngOnInit() {
    this.loadEngines();
    this.loadKafkaStatus();
    this.loadPlatformTelemetry();

    this.kafkaInterval = setInterval(() => this.loadKafkaStatus(), 10000);
    this.telemetryTimer = setInterval(() => this.loadPlatformTelemetry(), 10000);
  }

  loadPlatformTelemetry() {
    this.api.getPlatformTelemetry().subscribe({
      next: (data: any) => {
        this.eventsPerSec = Number(data.events_per_sec) || 0;
        this.events1h = Number(data.events_1h) || 0;
        this.cpuUsage = Math.round(Number(data.cpu_usage_percent) || 0);
        this.memoryUsedGb = Number(data.memory_used_gb) || 0;
        this.cdr.detectChanges();
      },
      error: reportRxjsError
    });
  }

  ngOnDestroy() {
    if (this.kafkaInterval) clearInterval(this.kafkaInterval);
    if (this.telemetryTimer) clearInterval(this.telemetryTimer);
  }

  loadEngines() {
    this.loadingEngines = true;
    this.api.getEngines().subscribe({
      next: (data: any) => {
        this.engines = data.engines || [];
        this.loadingEngines = false;
        this.lastEngineRefresh = new Date();
        this.cdr.detectChanges();
      },
      error: () => { this.loadingEngines = false; this.showMsg('Failed to load engines', 'error'); this.cdr.detectChanges(); },
    });
  }

  scaleUp() {
    this.scaling = true;
    this.api.scaleEngines('up').subscribe({
      next: (data: any) => {
        this.scaling = false;
        this.showMsg(data.message, 'success');
        setTimeout(() => this.loadEngines(), 3000);
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.scaling = false;
        this.showMsg(err.error?.message || 'Failed to scale up', 'error');
        this.cdr.detectChanges();
      },
    });
  }

  requestStopEngine(engine: string) { this.pendingStopEngine = engine; }
  cancelStopEngine()                { this.pendingStopEngine = ''; }

  confirmStopEngine() {
    if (!this.pendingStopEngine) return;
    const engine = this.pendingStopEngine;
    this.api.scaleEngines('down', engine).subscribe({
      next: (data: any) => {
        this.pendingStopEngine = '';
        this.showMsg(data.message, 'success');
        setTimeout(() => this.loadEngines(), 2000);
      },
      error: (err: any) => { this.showMsg(err.error?.message || 'Failed to scale down', 'error'); },
    });
  }

  loadKafkaStatus() {
    this.kafkaLoading = !this.kafkaData;
    this.api.getKafkaStatus().subscribe({
      next: (data: any) => { this.kafkaData = data; this.kafkaLoading = false; this.cdr.detectChanges(); },
      error: () => { this.kafkaLoading = false; this.cdr.detectChanges(); },
    });
  }

  getEngineForPartition(partition: number): string {
    const c = (this.kafkaData?.consumers || []).find((c: any) => c.partition === partition);
    return c?.engine || '-';
  }

  getLagForPartition(partition: number): number {
    const c = (this.kafkaData?.consumers || []).find((c: any) => c.partition === partition);
    return c?.lag ?? 0;
  }

  syncCommunityRules() {
    this.syncingRules = true;
    this.syncMessage  = '';
    this.syncError    = false;
    this.api.syncCommunityRules().subscribe({
      next: (res: any) => {
        this.syncingRules = false;
        this.syncMessage  = res.message || `${res.new_rules ?? 0} community rules synced from SigmaHQ`;
        this.syncError    = false;
        this.cdr.detectChanges();
      },
      error: (err: any) => {
        this.syncingRules = false;
        this.syncMessage  = err?.error?.error || 'Sync failed';
        this.syncError    = true;
        this.cdr.detectChanges();
      },
    });
  }

  showMsg(msg: string, type: string) {
    this.msg = msg; this.msgType = type;
    setTimeout(() => { this.msg = ''; this.cdr.detectChanges(); }, 5000);
  }
}
