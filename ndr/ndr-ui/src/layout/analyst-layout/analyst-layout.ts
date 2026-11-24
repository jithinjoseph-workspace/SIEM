import { Component, ChangeDetectionStrategy, ViewEncapsulation, OnInit, OnDestroy, Renderer2, Inject } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { RouterModule } from '@angular/router';
import { Sidebar } from '../sidebar/sidebar';

@Component({
  selector: 'app-analyst-layout',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  encapsulation: ViewEncapsulation.None,
  imports: [RouterModule, Sidebar],
  templateUrl: './analyst-layout.html',
  styleUrl: './analyst-layout.css',
})
export class AnalystLayout implements OnInit, OnDestroy {
  constructor(private renderer: Renderer2, @Inject(DOCUMENT) private document: Document) {}

  ngOnInit() {
    this.renderer.addClass(this.document.body, 'has-analyst-sidebar');
  }

  ngOnDestroy() {
    this.renderer.removeClass(this.document.body, 'has-analyst-sidebar');
  }
}
