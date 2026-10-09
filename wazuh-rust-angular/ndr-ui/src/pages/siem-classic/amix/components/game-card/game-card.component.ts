import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Game } from '../../data/games';

@Component({
  selector: 'app-game-card',
  standalone: true,
  imports: [CommonModule],
  template: `
    <article
      class="game-cabinet-card"
      [style.--accent]="game.accentColor"
      [style.--accent-rgb]="game.glowColorRgb"
    >
      <!-- Marquee Neon Sign Header -->
      <div class="cabinet-marquee">
        <div class="marquee-sign">
          <span class="marquee-glow-dot"></span>
          <span class="marquee-text mono">{{ game.neonSign }}</span>
          <span class="marquee-glow-dot"></span>
        </div>
        <div class="marquee-line"></div>
      </div>

      <!-- Main Tactical Panel -->
      <div class="glass-text-panel">
        <div class="panel-header">
          <span class="game-number mono">DEFENSE MODULE {{ game.number }}</span>
          <span class="category-pill">{{ game.category }}</span>
        </div>

        <h3 class="game-title">{{ game.title }}</h3>
        <h4 class="game-subtitle mono">{{ game.subtitle }}</h4>

        <p class="game-desc">{{ game.description }}</p>

        <div class="panel-divider"></div>

        <!-- Spec Rows -->
        <div class="specs-container">
          <div class="spec-row">
            <span class="spec-label mono">DEFENSE ENGINE</span>
            <span class="spec-val mono">{{ game.specs.engine }}</span>
          </div>
          <div class="spec-row">
            <span class="spec-label mono">OPERATIONAL MODE</span>
            <span class="spec-val mono">{{ game.specs.playMode }}</span>
          </div>
          <div class="spec-row">
            <span class="spec-label mono">RESPONSE SLA</span>
            <span class="spec-val mono text-accent">{{ game.specs.resolution }}</span>
          </div>
          <div class="spec-row">
            <span class="spec-label mono">TACTIC MAPPED</span>
            <span class="spec-val mono">{{ game.specs.releaseYear }}</span>
          </div>
        </div>

        <!-- Action CTA Button -->
        <div class="cta-wrapper">
          <button class="btn-cabinet-cta" (click)="onPlayClick()">
            <span class="cta-text">{{ game.ctaLabel }}</span>
            <span class="cta-arrow">➔</span>
          </button>
          <span class="cta-tip mono text-xs">JUMP DIRECTLY TO SOC WORKFLOW</span>
        </div>
      </div>
    </article>
  `,
  styleUrls: ['./game-card.component.css']
})
export class GameCardComponent {
  @Input({ required: true }) game!: Game;
  @Input({ required: true }) index!: number;
  @Output() navigateTab = new EventEmitter<string>();

  onPlayClick(): void {
    if (this.game.targetTab) {
      this.navigateTab.emit(this.game.targetTab);
    } else {
      alert(`[AMIX SIEM DEFENSE MATRIX]\nExecuting '${this.game.title}'...\n\nEngine: ${this.game.engine}\nAction: Active Response Quarantine Initiated.`);
    }
  }
}
