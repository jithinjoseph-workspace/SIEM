import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-amix-header',
  standalone: true,
  imports: [CommonModule],
  template: `
    <header class="amix-header">
      <!-- Left: Logo & Navigation back to SOC -->
      <div class="header-left">
        <div class="logo-wrap" (click)="scrollToTop()">
          <span class="logo-glitch" data-text="AMIX">AMIX</span>
          <span class="logo-sub">SIEM XDR // 2099</span>
        </div>

        <button class="btn-soc-switch" (click)="onBackToSoc.emit()" title="Return to Wazuh SIEM Operations Center">
          <span class="soc-dot"></span>
          <span class="soc-text">WAZUH SOC OPERATIONS</span>
        </button>
      </div>

      <!-- Right: 3D Toggle & Defense Arsenal CTA -->
      <div class="header-right">
        <!-- 3D Background On/Off Toggle -->
        <div class="toggle-container" [title]="is3dEnabled ? 'Disable 3D Background for battery/performance' : 'Enable WebGL 3D Background'">
          <span class="toggle-label mono">3D MATRIX</span>
          <button
            class="toggle-switch"
            [class.active]="is3dEnabled"
            (click)="onToggle3d.emit(!is3dEnabled)"
            role="switch"
            [attr.aria-checked]="is3dEnabled"
          >
            <span class="toggle-handle"></span>
          </button>
          <span class="toggle-status mono" [class.on]="is3dEnabled">{{ is3dEnabled ? 'ON' : 'OFF' }}</span>
        </div>

        <!-- Defense Arsenal Quick Jump Button -->
        <button class="btn-gallery" (click)="scrollToGallery()">
          <span>DEFENSE ARSENAL</span>
        </button>
      </div>
    </header>
  `,
  styleUrls: ['./amix-header.component.css']
})
export class AmixHeaderComponent {
  @Input() is3dEnabled = true;
  @Output() onToggle3d = new EventEmitter<boolean>();
  @Output() onBackToSoc = new EventEmitter<void>();

  scrollToTop(): void {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  scrollToGallery(): void {
    const el = document.getElementById('amix-gallery');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  }
}
