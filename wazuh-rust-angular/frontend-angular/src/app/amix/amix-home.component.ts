import {
  Component,
  OnInit,
  AfterViewInit,
  OnDestroy,
  EventEmitter,
  Output,
  ViewChild,
  ElementRef,
  signal,
  HostListener,
  NgZone
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { GAMES_DATA, Game } from './data/games';
import { ThreeBackgroundComponent } from './components/three-background/three-background.component';
import { AmixHeaderComponent } from './components/header/amix-header.component';
import { GameCardComponent } from './components/game-card/game-card.component';
import { FaqAccordionComponent } from './components/faq-accordion/faq-accordion.component';
import { AmixFooterComponent } from './components/footer/amix-footer.component';

@Component({
  selector: 'app-amix-home',
  standalone: true,
  imports: [
    CommonModule,
    ThreeBackgroundComponent,
    AmixHeaderComponent,
    GameCardComponent,
    FaqAccordionComponent,
    AmixFooterComponent
  ],
  template: `
    <div class="amix-root">
      <!-- 1. Full-page fixed Three.js WebGL 3D Background with Highway Camera Flight -->
      <app-three-background
        [is3dEnabled]="is3dEnabled()"
        [galleryProgress]="galleryScrollProgress()"
      ></app-three-background>

      <!-- 2. Fixed Header Navigation -->
      <app-amix-header
        [is3dEnabled]="is3dEnabled()"
        (onToggle3d)="is3dEnabled.set($event)"
        (onBackToSoc)="backToSoc.emit()"
      ></app-amix-header>

      <!-- 3. Foreground Scrollable Page Content -->
      <main class="amix-content">
        <!-- Hero Section -->
        <section class="hero-section">
          <div class="hero-inner">
            <div class="hero-badge mono">
              <span class="pulse-dot"></span>
              <span>WAZUH RUST-POWERED DEFENSE MATRIX // ONLINE</span>
            </div>

            <h1 class="hero-title">
              <span class="hero-line-1">AUTONOMOUS SIEM</span>
              <span class="hero-line-2">DEFENSE MATRIX</span>
            </h1>

            <p class="hero-desc">
              Explore the next-generation cyber warfare matrix. Six distributed threat mitigation engines powered by native Wazuh agent telemetry, sub-millisecond Rust Axum ingestion, kernel-level file integrity sentinels, and Groq 120B cognitive threat reasoning.
            </p>

            <div class="hero-actions">
              <button class="btn-hero-primary" (click)="scrollToGallery()">
                <span>EXPLORE DEFENSE ARSENAL</span>
                <span class="btn-arrow">➔</span>
              </button>
              <button class="btn-hero-secondary" (click)="backToSoc.emit()">
                <span>WAZUH SOC DASHBOARD</span>
              </button>
            </div>

            <!-- SIEM Metrics Bar -->
            <div class="hero-metrics-bar">
              <div class="metric-item">
                <span class="metric-val mono text-pink">100k+</span>
                <span class="metric-lbl mono">EPS INGESTION</span>
              </div>
              <div class="metric-divider"></div>
              <div class="metric-item">
                <span class="metric-val mono text-cyan">&lt; 0.4 ms</span>
                <span class="metric-lbl mono">DETECT LATENCY</span>
              </div>
              <div class="metric-divider"></div>
              <div class="metric-item">
                <span class="metric-val mono text-green">MITRE</span>
                <span class="metric-lbl mono">ATT&CK MAPPED</span>
              </div>
              <div class="metric-divider"></div>
              <div class="metric-item">
                <span class="metric-val mono text-purple">120B AI</span>
                <span class="metric-lbl mono">GROQ COPILOT</span>
              </div>
            </div>
          </div>
        </section>

        <!-- SIEM Defense Highway Stream (Alternating Left/Right with 3D Cabinets in WebGL) -->
        <section id="amix-gallery" class="gallery-highway-stream" #gallerySection>
          <!-- Sticky HUD Tracker -->
          <div class="sticky-hud-tracker">
            <div class="hud-left">
              <span class="hud-pill mono">// 3D XDR DEFENSE HIGHWAY</span>
              <span class="hud-module-title mono">{{ games[activeModuleIndex()].title }}</span>
            </div>

            <div class="hud-indicators">
              <span class="hud-counter mono">{{ activeModuleIndex() + 1 }} / {{ games.length }}</span>
              <div class="dots-list">
                <button
                  *ngFor="let g of games; let i = index"
                  class="dot-btn"
                  [class.active]="i === activeModuleIndex()"
                  (click)="scrollToModule(i)"
                  [title]="g.title"
                >
                  <span class="dot-inner"></span>
                </button>
              </div>
            </div>
          </div>

          <!-- 6 Natural Scrolling Module Sections -->
          <div
            *ngFor="let g of games; let idx = index"
            class="module-highway-row"
            [class.row-left]="idx % 2 === 0"
            [class.row-right]="idx % 2 !== 0"
            [id]="'module-row-' + idx"
          >
            <div class="card-column">
              <app-game-card
                [game]="g"
                [index]="idx"
                (navigateTab)="handleTabNavigate($event)"
              ></app-game-card>
            </div>
          </div>
        </section>

        <!-- FAQ Accordion Section -->
        <app-faq-accordion></app-faq-accordion>

        <!-- Glitch Footer -->
        <app-amix-footer (onBackToSoc)="backToSoc.emit()"></app-amix-footer>
      </main>
    </div>
  `,
  styleUrls: ['./amix-home.component.css']
})
export class AmixHomeComponent implements OnInit, AfterViewInit, OnDestroy {
  @Output() backToSoc = new EventEmitter<void>();
  @Output() navigateTab = new EventEmitter<string>();

  @ViewChild('gallerySection') galleryRef!: ElementRef<HTMLElement>;

  games: Game[] = GAMES_DATA;
  is3dEnabled = signal<boolean>(true);
  galleryScrollProgress = signal<number>(0);
  activeModuleIndex = signal<number>(0);

  private targetProgress = 0;
  private currentProgress = 0;
  private animFrameId: number | null = null;
  private isDestroyed = false;

  constructor(private ngZone: NgZone) {}

  ngOnInit(): void {}

  ngAfterViewInit(): void {
    this.updateTargetScroll();
    this.currentProgress = this.targetProgress;
    this.galleryScrollProgress.set(this.currentProgress);

    // Run smooth momentum lerp loop outside Angular zone
    this.ngZone.runOutsideAngular(() => {
      this.startSmoothLoop();
    });
  }

  ngOnDestroy(): void {
    this.isDestroyed = true;
    if (this.animFrameId) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
  }

  @HostListener('window:scroll', [])
  onWindowScroll(): void {
    this.updateTargetScroll();
  }

  private updateTargetScroll(): void {
    const gallery = this.galleryRef?.nativeElement;
    if (!gallery) return;

    const rect = gallery.getBoundingClientRect();
    const totalScroll = gallery.offsetHeight - window.innerHeight;

    if (totalScroll > 0) {
      const rawProgress = -rect.top / totalScroll;
      const clampedProgress = Math.min(Math.max(rawProgress, 0), 1);
      this.targetProgress = clampedProgress;

      const moduleIdx = Math.min(
        Math.floor(clampedProgress * this.games.length),
        this.games.length - 1
      );
      if (moduleIdx !== this.activeModuleIndex()) {
        this.activeModuleIndex.set(moduleIdx);
      }
    }
  }

  private startSmoothLoop(): void {
    const loop = () => {
      if (this.isDestroyed) return;

      const diff = this.targetProgress - this.currentProgress;
      if (Math.abs(diff) > 0.0002) {
        this.currentProgress += diff * 0.12;
        this.galleryScrollProgress.set(this.currentProgress);
      }

      this.animFrameId = requestAnimationFrame(loop);
    };

    this.animFrameId = requestAnimationFrame(loop);
  }

  scrollToGallery(): void {
    const gallery = this.galleryRef?.nativeElement;
    if (gallery) {
      const targetY = gallery.getBoundingClientRect().top + window.scrollY - 80;
      window.scrollTo({ top: targetY, behavior: 'smooth' });
    }
  }

  scrollToModule(index: number): void {
    const row = document.getElementById('module-row-' + index);
    if (row) {
      const targetY = row.getBoundingClientRect().top + window.scrollY - 110;
      window.scrollTo({ top: targetY, behavior: 'smooth' });
    }
  }

  handleTabNavigate(tab: string): void {
    this.navigateTab.emit(tab);
  }
}
