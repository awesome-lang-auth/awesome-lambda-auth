# Esempi

I client ufficiali della famiglia, **non modificati**, puntati a uno stack `awesome-lambda-auth` vivo.

| | libreria | trasporto |
|---|---|---|
| [`angular-client/`](angular-client/) | [`@awesome-lang-auth/angular`](https://github.com/awesome-lang-auth/awesome-angular-auth) da npm | cookie di sessione |
| [`flutter-client/`](flutter-client/) | `awesome_node_auth_flutter` da pub.dev | cookie su web, bearer su Android |

## Perché esistono

La suite in [`test/contract/`](../test/contract/) verifica il contratto HTTP e basta. Non sa nulla di come un client lo consuma davvero: quali campi casta non-nullabili, dove legge il token CSRF, come reagisce a un `401 SESSION_REVOKED`. Questi demo lo esercitano.

Il ritorno è già arrivato: costruendoli sono emersi tre difetti dei client che nessun test HTTP poteva vedere — [flutter#21](https://github.com/nik2208/awesome-node-auth-flutter/issues/21), [flutter#22](https://github.com/nik2208/awesome-node-auth-flutter/issues/22), [ng#7](https://github.com/nik2208/ng-awesome-node-auth/issues/7). I primi due fanno **terminare** il client, non degradare, ed è la stessa causa del campo `sub` mancante chiuso da [awesome-go-auth#46](https://github.com/nik2208/awesome-go-auth/pull/46).

## La forma di ospitalità che entrambi richiedono

**Una sola origin.** Non è una preferenza:

- I cookie sono `SameSite=Lax`, quindi non attraversano i siti.
- Il double-submit CSRF esige che la pagina possa **leggere** `__Host-csrf-token` da `document.cookie`; un cookie impostato da un'altra origin non c'è.
- Il client Angular non ha alcun percorso bearer, e il ramo web di Flutter è cookie-only per costruzione.

Quindi il sito è servito da Amplify e `/auth/*` è riscritto verso l'API Gateway con una regola **200 (Rewrite)**, non un redirect. Verificato: i tre `__Host-` attraversano il proxy intatti, attributi compresi.

L'app nativa Android non ha questo vincolo — fuori dal browser non ci sono né cookie né CORS — e infatti usa un URL assoluto e il bearer.
