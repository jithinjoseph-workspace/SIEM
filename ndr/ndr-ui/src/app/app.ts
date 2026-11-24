import { Component, OnInit, ViewEncapsulation, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterOutlet, NavigationEnd, NavigationStart } from '@angular/router';
import { Navbar } from '../layout/navbar/navbar';
import { Websocket } from '../services/websocket/websocket';
import { AuthService } from '../services/auth/auth';
import { ToastContainer } from '../components/toast-container/toast-container';
import { AriaBot } from '../components/aria-bot/aria-bot';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, Navbar, ToastContainer, AriaBot],
  templateUrl: './app.html',
  styleUrl: './app.css',
  encapsulation: ViewEncapsulation.None
})
export class App implements OnInit {
  showShell = false;

  constructor(
    private wsService: Websocket,
    private router: Router,
    private auth: AuthService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.router.events.subscribe((e: any) => {
      if (e instanceof NavigationStart) {
        // Update shell state NOW — before guards run and before the router
        // activates the component into an outlet. This ensures the correct
        // <router-outlet> is in the DOM when the component gets placed into it.
        // Without this, the component lands in the loginView outlet, which then
        // gets destroyed when NavigationEnd fires and showShell flips to true.
        const url: string = e.url;
        const goingToLogin = url === '/login' || url.startsWith('/login?') || url === '/';
        if (!goingToLogin && this.auth.isLoggedIn()) {
          this.showShell = true;
          this.cdr.detectChanges();
        } else if (goingToLogin) {
          this.showShell = false;
          this.cdr.detectChanges();
        }
        return;
      }

      if (e instanceof NavigationEnd) {
        const url: string = e.urlAfterRedirects || e.url;
        const isLoginPage = url === '/login' || url.startsWith('/login?');
        this.showShell = !isLoginPage && this.auth.isLoggedIn();
        if (isLoginPage) {
          this.auth.stopSessionPoll();
        }
      }
    });

    // Initial check (before first NavigationEnd fires)
    const url = this.router.url;
    const isLoginPage = url === '/login' || url.startsWith('/login?');
    this.showShell = !isLoginPage && this.auth.isLoggedIn();

    // Connect WebSocket only when authenticated
    if (this.auth.isLoggedIn()) {
      this.wsService.connect();

      // Start background session-validity poll so that blocked analyst/viewer
      // accounts are evicted within SESSION_POLL_MS (30 s) even if they never
      // navigate away from their current page.
      this.auth.startSessionPoll();
    }
  }
}
