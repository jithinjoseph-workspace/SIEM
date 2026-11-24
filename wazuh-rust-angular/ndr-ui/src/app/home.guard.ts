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

  // NDR clients: the combined dashboard; SIEM-only clients: their first SIEM page
  return router.createUrlTree([auth.analystHomeRoute()]);
};

/** The combined dashboard is for clients with NDR (licence feature); SIEM-only clients go to their SIEM home. */
export const siemHomeRedirect: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  if (auth.hasFeature('ndr')) return true;
  return router.createUrlTree([auth.siemHomeRoute()]);
};
