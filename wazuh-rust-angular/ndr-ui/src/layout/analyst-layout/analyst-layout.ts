import { Component, ChangeDetectionStrategy, ViewEncapsulation, OnInit, OnDestroy, Renderer2, Inject, signal, inject } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { Subscription, filter } from 'rxjs';
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
  /** The sidebar on small screens (it is always shown from 1024px). */
  navOpen = signal(false);
  private nav?: Subscription;
  private router = inject(Router);

  constructor(private renderer: Renderer2, @Inject(DOCUMENT) private document: Document) {}

  ngOnInit() {
    this.renderer.addClass(this.document.body, 'has-analyst-sidebar');
    this.nav = this.router.events.pipe(filter(e => e instanceof NavigationEnd)).subscribe(() => this.navOpen.set(false));
  }

  ngOnDestroy() {
    this.renderer.removeClass(this.document.body, 'has-analyst-sidebar');
    this.nav?.unsubscribe();
  }
}
