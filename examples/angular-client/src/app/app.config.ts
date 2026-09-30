import { ApplicationConfig } from '@angular/core';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { provideAuth } from '@awesome-lang-auth/angular';
import { routes } from './app.routes';

/**
 * Tutta la configurazione che serve per parlare con lo stack.
 *
 * `apiPrefix` è **relativo**, ed è il punto dell'intero demo: la pagina e le
 * route di auth stanno sulla stessa origin, perché Amplify riscrive `/auth/*`
 * verso l'API Gateway. Da qui discende tutto il resto — i cookie `__Host-`
 * restano validi, `SameSite=Lax` non ostacola nulla, il CORS non serve, e
 * soprattutto `__Host-csrf-token` finisce in `document.cookie`, che è dove
 * l'interceptor della libreria lo va a leggere per il double-submit.
 *
 * Se qui comparisse un URL assoluto verso execute-api, il login continuerebbe
 * a rispondere 200 ma ogni richiesta di scrittura successiva prenderebbe
 * 403 CSRF_INVALID: il token non sarebbe leggibile dalla pagina.
 *
 * `loginUrl` va sovrascritto perché il default della libreria è
 * `<apiPrefix>/ui/login`, cioè l'interfaccia servita dal backend; qui la pagina
 * di login è dell'app.
 */
export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes, withComponentInputBinding()),
    provideAuth({
      apiPrefix: '/auth',
      loginUrl: '/login',
      homeUrl: '/profile',
    }),
  ],
};
