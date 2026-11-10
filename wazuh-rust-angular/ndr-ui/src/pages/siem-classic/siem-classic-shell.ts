import { Component, ViewEncapsulation } from '@angular/core';
import { RouterOutlet } from '@angular/router';

/**
 * Hosts the pages copied from frontend-angular (SIEM console, dashboard,
 * agents, alerts, logs, rules, sources) inside the analyst layout.
 * frontend-angular's global stylesheet is applied only below
 * `.siem-classic-root`, so it does not restyle the rest of ndr-ui.
 */
@Component({
  selector: 'app-siem-classic-shell',
  standalone: true,
  imports: [RouterOutlet],
  template: `<div class="siem-classic-root"><router-outlet /></div>`,
  styleUrls: ['./siem-classic-global.css'],
  encapsulation: ViewEncapsulation.None,
})
export class SiemClassicShell {}
