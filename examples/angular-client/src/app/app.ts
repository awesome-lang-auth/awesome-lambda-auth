import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '@awesome-lang-auth/angular';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <header>
      <h1>awesome-lambda-auth</h1>
      <p class="sub">
        demo Angular — libreria ufficiale <code>@awesome-lang-auth/angular</code>, non modificata
      </p>

      @if (auth.isAuthenticated()) {
        <nav>
          <a routerLink="/profile" routerLinkActive="on">Profilo</a>
          <a routerLink="/sessions" routerLinkActive="on">Sessioni</a>
          <a routerLink="/two-factor" routerLinkActive="on">2FA</a>
          <button type="button" class="link" (click)="auth.logout()">Esci</button>
        </nav>
      } @else {
        <nav>
          <a routerLink="/login" routerLinkActive="on">Accedi</a>
          <a routerLink="/register" routerLinkActive="on">Registrati</a>
        </nav>
      }
    </header>

    <main>
      <router-outlet />
    </main>

    <footer>
      <p>
        Le route di auth stanno su <code>/auth/*</code> della stessa origin: le serve
        l'API Gateway attraverso una regola di rewrite di Amplify.
      </p>
    </footer>
  `,
})
export class App {
  readonly auth = inject(AuthService);
}
