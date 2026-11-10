import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth/auth';

export const homeGuard: CanActivateFn = () => {
  const auth   = inject(AuthService);
  const router = inject(Router);

  if (!auth.isLoggedIn()) {
    return router.createUrlTree(['/login']);
  }

  // Admins → admin console regardless of product mode
  if (auth.isAdmin()) {
    return router.createUrlTree(['/admin']);
  }

  if (auth.isTenantAdmin()) {
    return router.createUrlTree(['/tenant-admin']);
  }

  // All analysts go to the unified dashboard (shows NDR/SIEM sections based on product mode)
  // Analysts work in the SIEM pages only.
  return router.createUrlTree([auth.siemHomeRoute()]);
};

/** The NDR analyst dashboard is hidden: send analysts to their SIEM home page. */
export const siemHomeRedirect: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  return router.createUrlTree([auth.siemHomeRoute()]);
};
