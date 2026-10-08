import { ErrorHandler, Injectable } from '@angular/core';

/**
 * Sends a real error report to the backend so it's queryable later instead
 * of vanishing into a browser console nobody is watching. Deliberately
 * uses raw fetch() (not Angular's HttpClient) so a DI/interceptor problem
 * can never prevent an error from being reported, and never throws itself
 * — a broken error reporter must not become a second failure.
 */
export function reportClientError(message: string, stack: string, url: string): void {
  try {
    fetch('/api/client-errors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      keepalive: true, // request survives page unload/navigation
      body: JSON.stringify({ message, stack, url }),
    }).catch(() => {});
  } catch {
    // Reporting itself must never throw.
  }
}

/**
 * 401s are never useful signal here: the auth interceptor synthesizes one
 * client-side for every in-flight request the instant a session ends
 * (logout, force-logout, expired token) - by design, to stop those requests
 * from hitting the wire. A page can have a dozen+ independent polling
 * subscriptions alive at once (e.g. the super_admin overview page), so one
 * logout used to flood this endpoint with a near-duplicate report per
 * subscription for the exact same expected event, not an application bug.
 */
function isIgnorable401(err: any): boolean {
  return err?.status === 401;
}

/**
 * Drop-in for RxJS `.subscribe({ error: ... })` callbacks that previously
 * swallowed the error silently (`() => {}`). RxJS marks such errors as
 * "handled", so they never reach GlobalErrorHandler on their own — this
 * routes them into the same /api/client-errors pipeline explicitly.
 */
export function reportRxjsError(err: any): void {
  if (isIgnorable401(err)) return;
  const message = err?.error?.message || err?.message || String(err);
  const stack = err?.stack || '';
  reportClientError(message, stack, window.location.href);
}

@Injectable()
export class GlobalErrorHandler implements ErrorHandler {
  constructor() {
    // ErrorHandler only catches errors inside Angular's zone — a rejected
    // Promise that's never awaited/caught (e.g. a stray .then() with no
    // .catch()) doesn't go through it, so it's covered separately here.
    window.addEventListener('unhandledrejection', (event) => {
      const reason = event.reason;
      console.error('Unhandled promise rejection:', reason);
      if (isIgnorable401(reason)) return;
      const message = reason?.message || String(reason);
      const stack = reason?.stack || '';
      reportClientError(message, stack, window.location.href);
    });
  }

  handleError(error: unknown): void {
    const err = error as { message?: string; stack?: string } | undefined;
    const message = err?.message || String(error);
    const stack = err?.stack || '';
    // Keep the normal devtools console experience — this is additive, not a replacement.
    console.error(error);
    reportClientError(message, stack, window.location.href);
  }
}
