import { CanActivateFn, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './auth';
import { catchError, map, of } from 'rxjs';

export const authGuard: CanActivateFn = (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (!auth.isLoggedIn()) {
    router.navigate(['/login'], { replaceUrl: true });
    return false;
  }

  // tenant_admin is confined to /tenant-admin/* — block all other routes
  if (auth.isTenantAdmin() && !state.url.startsWith('/tenant-admin')) {
    router.navigate(['/tenant-admin'], { replaceUrl: true });
    return false;
  }

  // Skip the /api/auth/me round-trip when we just set fresh user data (e.g. right
  // after login). The login response already returned up-to-date user/permissions.
  if (auth.isUserDataFresh()) {
    const requiredRole       = route.data?.['role'];
    const requiredPermission = route.data?.['permission'];
    if (requiredRole === 'admin' && !auth.isAdmin()) {
      router.navigate([auth.getDefaultRoute()]);
      return false;
    }
    if (requiredRole === 'analyst' && auth.isAdmin()) {
      router.navigate([auth.getDefaultRoute()]);
      return false;
    }
    if (requiredPermission && requiredPermission !== 'ai-report' && !auth.hasPermission(requiredPermission)) {
      router.navigate([auth.getDefaultRoute()]);
      return false;
    }
    return true;
  }

  return auth.refreshUser().pipe(
    map((res: any) => {
      if (res.status !== 'ok') {
        auth.logout();
        return false;
      }

      const requiredRole = route.data?.['role'];
      const requiredPermission = route.data?.['permission'];
      if (!requiredRole) {
        if (requiredPermission && !auth.hasPermission(requiredPermission)) {
          router.navigate([auth.getDefaultRoute()]);
          return false;
        }
        return true;
      }

      const isAdmin = auth.isAdmin();
      if (requiredRole === 'admin' && !isAdmin) {
        router.navigate([auth.getDefaultRoute()]);
        return false;
      }

      if (requiredRole === 'analyst' && isAdmin) {
        router.navigate([auth.getDefaultRoute()]);
        return false;
      }

      // Automatically grant ai-report to any analyst, bypassing legacy missing DB permissions
      if (requiredPermission && requiredPermission !== 'ai-report' && !auth.hasPermission(requiredPermission)) {
        router.navigate([auth.getDefaultRoute()]);
        return false;
      }

      return true;
    }),
    catchError((err) => {
      // Only logout on explicit auth failures — network errors / 5xx should not wipe the session.
      if (err?.status === 401 || err?.status === 403) {
        auth.logout();
      } else {
        router.navigate(['/login'], { replaceUrl: true });
      }
      return of(false);
    })
  );
};
