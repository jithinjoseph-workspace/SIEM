import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SiemAlertsComponent } from '../../../components/siem/alerts/siem-alerts.component';

@Component({
  selector: 'app-siem-alerts-page',
  standalone: true,
  imports: [CommonModule, SiemAlertsComponent],
  template: `
    <div class="siem-page-shell" style="padding: 1.5rem; max-width: 1600px; margin: 0 auto;">
      <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; margin: 0 0 0.25rem 0;">Wazuh Host Security Alerts</h1>
        <p style="color: #94a3b8; font-size: 0.875rem; margin: 0;">Real-time host security alerts, MITRE ATT&amp;CK mappings, and forensic triage</p>
      </div>
      <app-siem-alerts></app-siem-alerts>
    </div>
  `
})
export class SiemAlertsPage {}
