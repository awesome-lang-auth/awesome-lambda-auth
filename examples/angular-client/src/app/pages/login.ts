import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '@awesome-lang-auth/angular';

/**
 * Login con la sfida di secondo fattore inclusa.
 *
 * La sfida è la parte che vale la pena avere in un demo: `login()` risponde
 * `requires2fa` insieme a un `tempToken`, e il TOTP si presenta a `/2fa/verify`
 * con quel token. È il giro che upstream #42 aveva rotto — il 403 arrivava
 * senza `tempToken`, quindi il client sapeva che serviva un secondo fattore e
 * non aveva nulla con cui presentarlo. Qui si vede se è davvero chiuso.
 */
@Component({
  selector: 'app-login',
  imports: [FormsModule, RouterLink],
  template: `
    <h2>Accedi</h2>

    @if (!challenge()) {
      <form (ngSubmit)="submit()">
        <label>
          Email
          <input name="email" type="email" autocomplete="username" required [(ngModel)]="email" />
        </label>
        <label>
          Password
          <input
            name="password"
            type="password"
            autocomplete="current-password"
            required
            [(ngModel)]="password"
          />
        </label>
        <button type="submit" [disabled]="busy()">
          {{ busy() ? 'Accesso…' : 'Accedi' }}
        </button>
      </form>
      <p>Non hai un account? <a routerLink="/register">Registrati</a></p>
    } @else {
      <form (ngSubmit)="submitTotp()">
        <p class="note">
          Questo account ha il secondo fattore attivo.
          @if (methods().length) {
            Metodi disponibili: <strong>{{ methods().join(', ') }}</strong
            >.
          }
        </p>
        <label>
          Codice TOTP
          <input
            name="totp"
            inputmode="numeric"
            autocomplete="one-time-code"
            required
            [(ngModel)]="totp"
          />
        </label>
        <button type="submit" [disabled]="busy()">
          {{ busy() ? 'Verifica…' : 'Verifica' }}
        </button>
        <button type="button" class="link" (click)="cancel()">Annulla</button>
      </form>
    }

    @if (error()) {
      <p class="error">{{ error() }}</p>
    }
  `,
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  email = '';
  password = '';
  totp = '';

  readonly busy = signal(false);
  readonly error = signal('');
  /** Il tempToken della sfida: presente solo fra login e verifica del TOTP. */
  readonly challenge = signal('');
  readonly methods = signal<string[]>([]);

  submit(): void {
    this.busy.set(true);
    this.error.set('');
    this.auth.login(this.email, this.password).subscribe((res) => {
      this.busy.set(false);
      if (res.requires2fa) {
        // Senza tempToken la sfida è un vicolo cieco: meglio dirlo qui che
        // lasciare un form che non può funzionare.
        if (!res.token) {
          this.error.set(
            'Il server chiede un secondo fattore ma non ha inviato un tempToken: la sfida non è completabile.',
          );
          return;
        }
        this.challenge.set(res.token);
        this.methods.set(res.availableMethods ?? []);
        return;
      }
      if (!res.success) {
        this.error.set(res.error ?? 'Accesso non riuscito');
        return;
      }
      void this.router.navigate(['/profile']);
    });
  }

  submitTotp(): void {
    this.busy.set(true);
    this.error.set('');
    this.auth.validate2fa(this.challenge(), this.totp).subscribe((res) => {
      this.busy.set(false);
      if (!res.success) {
        this.error.set(res.error ?? 'Codice non valido');
        return;
      }
      void this.router.navigate(['/profile']);
    });
  }

  cancel(): void {
    this.challenge.set('');
    this.methods.set([]);
    this.totp = '';
    this.error.set('');
  }
}
