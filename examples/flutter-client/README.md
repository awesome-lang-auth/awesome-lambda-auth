# Demo Flutter

Consuma **[`awesome_flutter_auth`](https://pub.dev/packages/awesome_flutter_auth) da pub.dev, non modificato**, contro uno stack `awesome-lambda-auth` vivo. Si costruisce in due forme, e la coppia è il punto:

| | trasporto | prefisso |
|---|---|---|
| **Web** | cookie di sessione + double-submit CSRF | relativo — `/auth` |
| **Android** | `X-Auth-Strategy: bearer` + `TokenStorage` | assoluto — `https://…/auth` |

La scelta del trasporto **non è di questo codice**: `AuthClient` risolve l'implementazione con un conditional import su `dart.library.js_interop`. Il demo cambia solo il prefisso, e per un motivo preciso — su web serve una sola origin perché i cookie `__Host-` e il token CSRF leggibile dalla pagina lo esigono; su nativo non c'è pagina né origin, e senza browser il CORS non tocca nulla.

L'APK è scaricabile dalla pagina web del demo, così i due rami si provano partendo dallo stesso posto. Il ramo bearer non era mai stato esercitato dal vivo con il client vero.

## Costruire

**Web** — prefisso relativo, serve dietro lo stesso rewrite proxy del demo Angular:

```bash
flutter build web --dart-define=AUTH_API_PREFIX=/auth --dart-define=APK_URL=https://…/app-release.apk
```

**Android** — prefisso assoluto:

```bash
flutter build apk --release --dart-define=AUTH_API_PREFIX=https://<origin>/auth
```

L'APK lo costruisce [`.github/workflows/flutter-demo-apk.yml`](../../.github/workflows/flutter-demo-apk.yml) su tag `flutter-demo-v*` e lo pubblica come release asset. L'origin arriva dalla variabile di repository `DEMO_BASE_URL`: nel repo non finisce mai un dominio reale.

Non è in Amplify perché l'immagine di build predefinita non ha l'SDK Android, e personalizzarla allungherebbe *ogni* build del web per un artefatto che cambia di rado.

### Dove vive l'APK servito

Il file sta **accanto al sito**, su `/app-release.apk` della stessa origin, non su un host esterno. Due motivi:

- La richiesta era «scaricabile dalla pagina web stessa», e same-origin è letteralmente questo — nessun salto verso un altro dominio.
- La regola di fallback SPA esclude già `.apk` fra le estensioni, quindi il file viene servito com'è (`application/vnd.android.package-archive`) invece di essere riscritto su `index.html`. **Se si tocca quella regola, va tenuta l'esclusione**, altrimenti il download restituisce silenziosamente HTML.

Il workflow resta il percorso di build riproducibile e versionato; il file servito è una copia dello stesso artefatto.

### Il permesso INTERNET

`main/AndroidManifest.xml` dichiara `android.permission.INTERNET` a mano. Il template di Flutter lo mette solo nei manifest di debug e profile: un APK di release generato così com'è **non raggiungerebbe la rete**, e ogni chiamata di auth fallirebbe senza che sia ovvio il perché.

## Due difetti del client, chiusi in 1.10.1

Costruendo questo demo sono emersi due difetti del client, della stessa famiglia del campo `sub` mancante chiuso da [awesome-go-auth#46](https://github.com/awesome-lang-auth/awesome-go-auth/pull/46): un cast non-nullable su un campo che non arriva non degrada un client, lo termina.

- [awesome-flutter-auth#21](https://github.com/awesome-lang-auth/awesome-flutter-auth/issues/21) — `SessionInfo.fromJson` leggeva `handle` invece di `sessionHandle`, e `getActiveSessions()` lanciava.
- [awesome-flutter-auth#22](https://github.com/awesome-lang-auth/awesome-flutter-auth/issues/22) — `TotpSetupData.fromJson` pretendeva `qrCode`, che questo port non manda (deviazione registrata), e `setup2fa()` lanciava.

Entrambi sono chiusi in `awesome_flutter_auth` 1.10.1: `qrCode` è nullable e il modello espone `otpauthUrl`. Il demo non li aggira più; l'iscrizione TOTP mostra il segreto e l'URI `otpauth://` da inserire a mano, e [`test/client_defects_test.dart`](test/client_defects_test.dart) fissa il comportamento corretto.
