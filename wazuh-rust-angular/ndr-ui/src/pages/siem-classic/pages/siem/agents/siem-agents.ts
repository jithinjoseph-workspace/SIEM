import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SiemAgentsComponent } from '../../../components/siem/agents/siem-agents.component';

@Component({
  selector: 'app-siem-agents-page',
  standalone: true,
  imports: [CommonModule, SiemAgentsComponent],
  template: `
    <div class="siem-page-shell" style="padding: 1.5rem; max-width: 1600px; margin: 0 auto;">
      <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; margin: 0 0 0.25rem 0;">Host Agents Fleet</h1>
        <p style="color: #94a3b8; font-size: 0.875rem; margin: 0;">Wazuh endpoint agents, active response management, SCA baseline, and FIM integrity</p>
      </div>
      <app-siem-agents></app-siem-agents>
    </div>
  `
})
export class SiemAgentsPage {}
