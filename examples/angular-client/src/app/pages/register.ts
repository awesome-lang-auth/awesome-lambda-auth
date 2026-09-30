import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { AuthService } from '@awesome-lang-auth/angular';

@Component({
  selector: 'app-register',
  imports: [FormsModule, RouterLink],
  template: `
    <h2>Registrati</h2>
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
          autocomplete="new-password"
          required
          [(ngModel)]="password"
        />
      </label>
      <label>
        Nome
        <input name="firstName" autocomplete="given-name" [(ngModel)]="firstName" />
      </label>
      <label>
        Cognome
        <input name="lastName" autocomplete="family-name" [(ngModel)]="lastName" />
      </label>
      <button type="submit" [disabled]="busy()">
        {{ busy() ? 'Creazione…' : 'Crea account' }}
      </button>
    </form>
    <p>Hai già un account? <a routerLink="/login">Accedi</a></p>

    @if (error()) {
      <p class="error">{{ error() }}</p>
    }
  `,
})
export class RegisterPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  email = '';
  password = '';
  firstName = '';
  lastName = '';

  readonly busy = signal(false);
  readonly error = signal('');

  submit(): void {
    this.busy.set(true);
    this.error.set('');
    this.auth.register(this.email, this.password, this.firstName, this.lastName).subscribe((res) => {
      if (!res.success) {
        this.busy.set(false);
        this.error.set(res.error ?? 'Registrazione non riuscita');
        return;
      }
      // La registrazione su questo port autentica già (difetto noto, upstream
      // #21: la reference non emette credenziali qui e il client chiama
      // /login subito dopo). Il demo non ci si appoggia — chiede al server chi
      // siamo, così funziona sia col difetto sia una volta chiuso.
      this.auth.checkSession().subscribe((user) => {
        this.busy.set(false);
        void this.router.navigate([user ? '/profile' : '/login']);
      });
    });
  }
}
