import { APP_INITIALIZER, ApplicationConfig, ErrorHandler } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { routes } from './app.routes';
import { authInterceptor } from '../services/auth/auth-interceptor';
import { ConfigService } from '../services/config/config.service';
import { GlobalErrorHandler } from '../services/error-reporter/error-reporter';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(withInterceptors([authInterceptor])),
    // ng2-charts is provided per-route (see app.routes.ts) instead of here,
    // so its global Chart.js registration only runs when a chart-using page
    // is actually opened, not on every app bootstrap.
    { provide: ErrorHandler, useClass: GlobalErrorHandler },
    {
      provide: APP_INITIALIZER,
      useFactory: (config: ConfigService) => () => config.load(),
      deps: [ConfigService],
      multi: true,
    },
  ]
};