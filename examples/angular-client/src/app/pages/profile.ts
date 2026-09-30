import { Component, inject, signal } from '@angular/core';
import { AuthService } from '@awesome-lang-auth/angular';

/**
 * Il profilo che `GET /me` restituisce, mostrato campo per campo.
 *
 * `sub` ha una riga tutta sua perché è il campo che mancava su uno stack vivo
 * fino a awesome-go-auth#46: entrambi i client di famiglia lo castano
 * non-nullable, quindi la sua assenza non degradava il client, lo faceva
 * terminare. Vederlo qui è la verifica più economica che il fix regge.
 */
@Component({
  selector: 'app-profile',
  template: `
    <h2>Profilo</h2>

    @let user = auth.user();
    @if (user) {
      <dl>
        <dt>sub</dt>
        <dd><code>{{ user.sub }}</code></dd>
        <dt>email</dt>
        <dd>{{ user.email }}</dd>
        <dt>email verificata</dt>
        <dd>{{ user.isEmailVerified ? 'sì' : 'no' }}</dd>
        <dt>2FA</dt>
        <dd>{{ user.isTotpEnabled ? 'attivo' : 'non attivo' }}</dd>
        @if (user.role) {
          <dt>ruolo</dt>
          <dd>{{ user.role }}</dd>
        }
      </dl>

      <h3>Refresh</h3>
      <p class="note">
        Rinnova la sessione con <code>POST /refresh</code> a corpo vuoto: i cookie
        ruotano e la pagina resta autenticata.
      </p>
      <button type="button" (click)="refresh()" [disabled]="busy()">
        {{ busy() ? 'In corso…' : 'Rinnova la sessione' }}
      </button>
      @if (message()) {
        <p [class.error]="failed()">{{ message() }}</p>
      }
    } @else {
      <p>Nessuna sessione.</p>
    }
  `,
})
export class ProfilePage {
  readonly auth = inject(AuthService);
  readonly busy = signal(false);
  readonly message = signal('');
  readonly failed = signal(false);

  refresh(): void {
    this.busy.set(true);
    this.message.set('');
    this.auth.refreshToken().subscribe((res) => {
      this.busy.set(false);
      this.failed.set(!res.success);
      this.message.set(
        res.success ? 'Sessione rinnovata.' : (res.error ?? 'Rinnovo non riuscito'),
      );
    });
  }
}
