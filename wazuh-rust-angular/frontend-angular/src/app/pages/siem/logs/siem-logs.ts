import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SiemLogsComponent } from '../../../components/siem/logs/siem-logs.component';

@Component({
  selector: 'app-siem-logs-page',
  standalone: true,
  imports: [CommonModule, SiemLogsComponent],
  template: `
    <div class="siem-page-shell" style="padding: 1.5rem; max-width: 1600px; margin: 0 auto;">
      <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; margin: 0 0 0.25rem 0;">Host &amp; Syslog Telemetry</h1>
        <p style="color: #94a3b8; font-size: 0.875rem; margin: 0;">ClickHouse raw event stream, syslog receivers (UDP 514 / TCP 601), and field query explorer</p>
      </div>
      <app-siem-logs></app-siem-logs>
    </div>
  `
})
export class SiemLogsPage {}
