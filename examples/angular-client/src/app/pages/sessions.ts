import { Component, OnInit, inject, signal } from '@angular/core';
import { AuthService, SessionInfo } from '@awesome-lang-auth/angular';

/**
 * Elenco delle sessioni attive e revoca per handle.
 *
 * Revocare la sessione corrente è il modo più diretto per far comparire
 * `401 {"code":"SESSION_REVOKED"}`: l'interceptor della libreria lo riconosce e
 * chiama `logout()` invece di tentare un refresh, che è la differenza fra
 * disconnettersi e ciclare all'infinito.
 */
@Component({
  selector: 'app-sessions',
  template: `
    <h2>Sessioni attive</h2>

    @if (loading()) {
      <p>Caricamento…</p>
    } @else if (!sessions().length) {
      <p>Nessuna sessione elencata.</p>
    } @else {
      <ul class="sessions">
        @for (s of sessions(); track s.sessionHandle) {
          <li>
            <code>{{ s.sessionHandle }}</code>
            <span class="meta">
              creata {{ s.createdAt }}
              @if (s.userAgent) {
                · {{ s.userAgent }}
              }
            </span>
            <button type="button" (click)="revoke(s.sessionHandle)">Revoca</button>
          </li>
        }
      </ul>
    }

    <button type="button" (click)="load()">Ricarica</button>

    @if (message()) {
      <p class="note">{{ message() }}</p>
    }
  `,
})
export class SessionsPage implements OnInit {
  private readonly auth = inject(AuthService);

  readonly sessions = signal<SessionInfo[]>([]);
  readonly loading = signal(false);
  readonly message = signal('');

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.auth.getActiveSessions().subscribe((list) => {
      this.sessions.set(list);
      this.loading.set(false);
    });
  }

  revoke(handle: string): void {
    this.message.set('');
    this.auth.revokeSession(handle).subscribe((res) => {
      this.message.set(res.success ? 'Sessione revocata.' : (res.error ?? 'Revoca non riuscita'));
      this.load();
    });
  }
}
