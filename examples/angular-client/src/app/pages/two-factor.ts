import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { AuthService } from '@awesome-lang-auth/angular';

/**
 * Iscrizione e disattivazione del TOTP.
 *
 * Il port non manda `qrCode` — è una deviazione registrata
 * (`totp-setup-omits-qrcode`): un encoder QR non sta né nella stdlib né in
 * golang.org/x/crypto, quindi tocca al client disegnarlo. La reference
 * protegge il proprio rendering con `if (setupData.qrCode)` e degrada al
 * segreto scritto a mano.
 *
 * Il server manda `otpauthUrl`, da cui un QR si genera. Fino a
 * ng-awesome-node-auth 1.9 `AuthService.setup2fa()` lo scartava per strada
 * (ng#7); @awesome-lang-auth/angular 1.10.0 lo espone, e il demo lo mostra
 * accanto al segreto, da incollare in un'app di autenticazione o in un
 * generatore di QR. Il demo non aggiunge un encoder QR suo.
 *
 * I nomi dei campi sono asimmetrici anche lato server e la libreria lo
 * nasconde bene: `/2fa/verify-setup` vuole `token` e `secret`, `/2fa/verify`
 * vuole `tempToken` e `totpCode`.
 */
@Component({
  selector: 'app-two-factor',
  imports: [FormsModule],
  template: `
    <h2>Secondo fattore</h2>

    @let user = auth.user();

    @if (user?.isTotpEnabled) {
      <p>Il TOTP è <strong>attivo</strong> su questo account.</p>
      <button type="button" (click)="disable()" [disabled]="busy()">Disattiva</button>
    } @else if (!secret()) {
      <p>Il TOTP non è attivo.</p>
      <button type="button" (click)="start()" [disabled]="busy()">
        {{ busy() ? 'Preparazione…' : 'Attiva il TOTP' }}
      </button>
    } @else {
      <p>Aggiungi questo segreto alla tua app di autenticazione, poi conferma con un codice.</p>
      <p class="secret"><code>{{ secret() }}</code></p>
      @if (otpauthUrl()) {
        <p>URI di provisioning:</p>
        <p class="secret"><code>{{ otpauthUrl() }}</code></p>
      }
      <p class="note">
        Nessun QR: il port non invia <code>qrCode</code> (deviazione registrata), quindi
        il segreto va inserito a mano, oppure l'URI incollato in un generatore di QR.
      </p>
      <form (ngSubmit)="confirm()">
        <label>
          Codice a 6 cifre
          <input
            name="code"
            inputmode="numeric"
            autocomplete="one-time-code"
            required
            [(ngModel)]="code"
          />
        </label>
        <button type="submit" [disabled]="busy()">Conferma</button>
      </form>
    }

    @if (message()) {
      <p [class.error]="failed()">{{ message() }}</p>
    }
  `,
})
export class TwoFactorPage {
  readonly auth = inject(AuthService);

  code = '';
  readonly secret = signal('');
  readonly otpauthUrl = signal('');
  readonly busy = signal(false);
  readonly message = signal('');
  readonly failed = signal(false);

  start(): void {
    this.busy.set(true);
    this.reset();
    this.auth.setup2fa().subscribe((res) => {
      this.busy.set(false);
      if (!res.success || !res.secret) {
        this.fail(res.error ?? 'Impossibile avviare l’iscrizione');
        return;
      }
      this.secret.set(res.secret);
      this.otpauthUrl.set(res.otpauthUrl ?? '');
    });
  }

  confirm(): void {
    this.busy.set(true);
    this.auth.verify2faSetup(this.code, this.secret()).subscribe((res) => {
      this.busy.set(false);
      if (!res.success) {
        this.fail(res.error ?? 'Codice non valido');
        return;
      }
      this.secret.set('');
      this.otpauthUrl.set('');
      this.code = '';
      this.failed.set(false);
      this.message.set('TOTP attivato.');
    });
  }

  disable(): void {
    this.busy.set(true);
    this.auth.disable2fa().subscribe((res) => {
      this.busy.set(false);
      if (!res.success) {
        this.fail(res.error ?? 'Disattivazione non riuscita');
        return;
      }
      this.failed.set(false);
      this.message.set('TOTP disattivato.');
    });
  }

  private reset(): void {
    this.message.set('');
    this.failed.set(false);
  }

  private fail(text: string): void {
    this.failed.set(true);
    this.message.set(text);
  }
}
