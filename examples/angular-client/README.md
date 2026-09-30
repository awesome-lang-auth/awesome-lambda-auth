# Demo Angular

SPA che consuma **[`@awesome-lang-auth/angular`](https://github.com/awesome-lang-auth/awesome-angular-auth) dal registro, non modificata** (fino alla 1.9 si chiamava `ng-awesome-node-auth`), contro uno stack `awesome-lambda-auth` vivo.

Non è una vetrina: è la verifica che il client ufficiale funziona davvero contro questo port. La suite in [`test/contract/`](../../test/contract/) ne è un surrogato — utile, ma parla HTTP, non parla Angular.

## Il vincolo che ne determina la forma

Un demo ospitato altrove che chiama direttamente `https://<id>.execute-api…` **non può autenticarsi**, e non per una configurazione da sistemare:

- I cookie sono `SameSite=Lax`, quindi il browser non li manda cross-site.
- L'interceptor della libreria legge il token CSRF da `document.cookie` ([`auth.interceptor.ts:125`](https://github.com/awesome-lang-auth/awesome-angular-auth/blob/develop/projects/awesome-angular-auth/src/lib/auth.interceptor.ts)), e un cookie impostato dall'origin `execute-api` **non esiste** in `document.cookie` su un'altra pagina. L'header non viene allegato e ogni scrittura prende `403 CSRF_INVALID`.
- Il bearer non è una via d'uscita: questa libreria non ha una riga di codice bearer.

Quindi: **una sola origin**. La pagina è servita da Amplify, che riscrive `/auth/*` verso l'API Gateway. Il browser vede un solo host, i cookie `__Host-` restano validi, il CORS non serve, e `__Host-csrf-token` è leggibile dalla pagina.

Tutta la configurazione che serve, in [`app.config.ts`](src/app/app.config.ts):

```ts
provideAuth({ apiPrefix: '/auth', loginUrl: '/login', homeUrl: '/profile' })
```

`apiPrefix` **relativo**. Se qui comparisse un URL assoluto, l'origin non sarebbe una sola e la forma non reggerebbe.

## Costruire

Toolchain in container, come il resto del repo — niente installato sull'host:

```bash
./scripts/node-toolchain.sh examples/angular-client npm ci
```

```bash
./scripts/node-toolchain.sh examples/angular-client npm run build
```

L'output sta in `dist/browser`.

## Ospitare

Due regole, **in quest'ordine** — sono valutate in sequenza, e invertirle riscriverebbe ogni chiamata di auth su `index.html`, facendo arrivare HTML al posto di JSON:

| # | source | target | status |
|---|---|---|---|
| 1 | `/auth/<*>` | `https://<api-id>.execute-api.<region>.amazonaws.com/auth/<*>` | `200` |
| 2 | `</^[^.]+$\|\.(?!(css\|gif\|ico\|jpg\|js\|png\|txt\|svg\|woff\|woff2\|ttf\|map\|json\|webp)$)([^.]+$)/>` | `/index.html` | `200` |

La seconda è il fallback SPA: senza, un accesso diretto a `/sessions` darebbe 404.

## Cosa esercita

- Registrazione, accesso, `GET /me`, uscita.
- **Il giro 2FA completo**: iscrizione TOTP, poi accesso con la sfida — `requiresTwoFactor` + `tempToken` + `available2faMethods` — e `POST /2fa/verify`. È il giro che [awesome-go-auth#42](https://github.com/nik2208/awesome-go-auth/issues/42) aveva rotto.
- **Il double-submit CSRF attraverso il proxy**: qualsiasi POST lo esercita.
- Sessioni attive e revoca per handle, che è il modo di far comparire `401 {"code":"SESSION_REVOKED"}`.

## Cose che il demo mostra invece di nascondere

- **Niente QR nell'iscrizione TOTP.** Il port non manda `qrCode` (deviazione registrata: un encoder QR non sta né nella stdlib né in `golang.org/x/crypto`). La pagina mostra il segreto da inserire a mano, che è anche il ripiego della reference, e l'URI `otpauthUrl` da cui un QR si genera: la libreria lo scartava ([ng#7](https://github.com/awesome-lang-auth/awesome-angular-auth/issues/7)), chiuso in 1.10.0.
- **La registrazione autentica già.** La reference non emette credenziali su `POST /register` e il client chiama `/login` subito dopo; questo port emette una sessione — [awesome-go-auth#21](https://github.com/nik2208/awesome-go-auth/issues/21). Il demo non ci si appoggia: chiede al server chi sia, così funziona in entrambi i casi.
- **Una sessione revocata continua a valere fino alla scadenza dell'access token.** Non è un difetto del port: è la reference a costruire il proprio middleware senza sessionStore, quindi `SESSION_REVOKED` arriva solo da `POST /refresh` (`docs/spec/wire-contract.md:131`).
