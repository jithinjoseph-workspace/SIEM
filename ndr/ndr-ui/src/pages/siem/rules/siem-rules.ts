import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SiemRulesComponent } from '../../../components/siem/rules/siem-rules.component';

@Component({
  selector: 'app-siem-rules-page',
  standalone: true,
  imports: [CommonModule, SiemRulesComponent],
  template: `
    <div class="siem-page-shell" style="padding: 1.5rem; max-width: 1600px; margin: 0 auto;">
      <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; margin: 0 0 0.25rem 0;">SIEM Detection Rules</h1>
        <p style="color: #94a3b8; font-size: 0.875rem; margin: 0;">Wazuh XML/YAML detection rules, regex inspection, and MITRE ATT&amp;CK mappings</p>
      </div>
      <app-siem-rules></app-siem-rules>
    </div>
  `
})
export class SiemRulesPage {}
