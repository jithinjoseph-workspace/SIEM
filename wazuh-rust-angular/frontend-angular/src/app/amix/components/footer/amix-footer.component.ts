import { Component, EventEmitter, Output } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-amix-footer',
  standalone: true,
  imports: [CommonModule],
  template: `
    <footer class="amix-footer">
      <div class="footer-container">
        <!-- Giant Cyber Glitch Wordmark -->
        <div class="footer-hero-wordmark">
          <h1 class="glitch-wordmark" data-text="AMIX SIEM">AMIX SIEM</h1>
          <span class="wordmark-sub mono">NEXT-GEN DISTRIBUTED XDR CYBER DEFENSE &bull; SYSTEM MATRIX</span>
        </div>

        <!-- Navigation Links Row -->
        <div class="footer-nav-row">
          <a class="footer-link" (click)="scrollToGallery()">DEFENSE ARSENAL</a>
          <a class="footer-link" (click)="scrollToTop()">TOP OF MATRIX</a>
          <a class="footer-link" (click)="onBackToSoc.emit()">WAZUH SOC PORTAL</a>
          <a class="footer-link" href="https://github.com/wazuh/wazuh" target="_blank" rel="noopener">WAZUH OPEN SOURCE</a>
          <a class="footer-link" href="https://attack.mitre.org" target="_blank" rel="noopener">MITRE ATT&CK FRAMEWORK</a>
        </div>

        <div class="footer-divider"></div>

        <!-- Credit Lines -->
        <div class="footer-credits">
          <p class="credit-tech mono text-xs">
            ENGINEERED WITH ANGULAR 18+ &bull; RUST TOKIO / AXUM EVENT INGESTION &bull; THREE.JS 3D CYBER MATRIX &bull; GROQ 120B AI REASONING
          </p>
          <p class="credit-designer text-xs text-muted">
            Designed for Autonomous Enterprise Defense &bull; Integrated Live with Wazuh Windows & Linux Agent Fleet &copy; 2099 AMIX SIEM Syndicate
          </p>
        </div>
      </div>
    </footer>
  `,
  styleUrls: ['./amix-footer.component.css']
})
export class AmixFooterComponent {
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
