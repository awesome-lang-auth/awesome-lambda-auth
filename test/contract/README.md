# Contract suite

Black-box checks of the wire contract in `docs/spec/wire-contract.md`, run over
HTTP against a *running* stack.

The port's correctness claim is that the family's shipped clients
(`ng-awesome-node-auth`, `awesome-node-auth-flutter`, the served `auth.js`) work
against it with only a base-URL change. Everything else that supports that claim
is a unit test somewhere inside a library — the auth core's `adapter/internal/wiretest`
is Go-`internal` to `adapter/`, so this repository cannot even import it — or a
one-off curl. Neither runs against a deployment, and a deployment is where the
claim is actually made: cookie prefixes depend on `cookies.secure`, the CSRF
double-submit depends on `security.csrf.enabled`, and half the routes depend on
which stores the operator switched on.

So this suite is parametrised on a base URL, and the identical assertions run
against a deployed stack and against the reference Express app.

## Running it

```sh
# a deployed stack
AWESOME_AUTH_CONTRACT_BASE_URL=https://<api-id>.execute-api.<region>.amazonaws.com \
  ./scripts/toolchain.sh go test ./test/contract/... -v

# the reference implementation, for a side-by-side (see below)
AWESOME_AUTH_CONTRACT_BASE_URL=http://localhost:3000 \
  ./scripts/toolchain.sh go test ./test/contract/... -v
```

| Variable | Meaning |
|---|---|
| `AWESOME_AUTH_CONTRACT_BASE_URL` | Origin of the stack under test — scheme and host, no path, no trailing slash. **Unset means skip**: `go test ./...` in a plain checkout stays green and CI needs no deployment. Under `-v` the skip prints a `[contract] SKIPPED:` banner; unset *while* `…_REQUIRE` is set is a failure, not a skip (see below). |
| `AWESOME_AUTH_CONTRACT_API_PREFIX` | Router mount point. Default `/auth`, the same default the reference uses. |
| `AWESOME_AUTH_CONTRACT_REQUIRE` | Capabilities this deployment claims to offer: comma-separated (`register,csrf,secure-cookies,sessions,totp,linked-accounts,oauth-google,idp,docs,ui,rate-limit,admin,admin-session,admin-credential`) or `all`. A listed capability the probe cannot find is a **failure**, not a skip. |
| `AWESOME_AUTH_CONTRACT_RATE_LIMIT` | Declares this deployment's rate limiter as `<keyBy>:<max>`, e.g. `email:10`. **Opt-in and unset by default**, because a limiter cannot be probed without spending the budget it protects. Only `email:` runs the case; `ip:` is recorded absent, and anything unparseable is a fault. See below. |
| `AWESOME_AUTH_CONTRACT_ADMIN_PATH` | Where the admin console is mounted, as an absolute path. Default `/admin`, the same default the reference's swagger base and this product's `admin.basePath` use. |
| `AWESOME_AUTH_CONTRACT_ADMIN_EMAIL` + `AWESOME_AUTH_CONTRACT_ADMIN_PASSWORD` | An account the console admits — the configured root user, or a user the operator promoted. **Opt-in and unset by default**, because the suite cannot mint an administrator. Both or neither: one without the other is a fault. See below. |

All of them are passed through `scripts/toolchain.sh` into the container.

**Set `AWESOME_AUTH_CONTRACT_REQUIRE` for anything that is supposed to be
complete.** Absence is unfalsifiable from outside: a session store the operator
never wired and a session store that regressed into answering `NOT_IMPLEMENTED`
are the same three bytes on the wire, and the skip that is right for the first
is a silent green run for the second. Only the operator knows which deployment
they pointed the suite at, so the operator says. For the current stack:

```sh
AWESOME_AUTH_CONTRACT_BASE_URL=https://<api-id>.execute-api.eu-west-1.amazonaws.com \
AWESOME_AUTH_CONTRACT_REQUIRE=register,csrf,secure-cookies,sessions,totp \
  ./scripts/toolchain.sh go test ./test/contract/... -v
```

(`linked-accounts` and `oauth-google` are left out because they really are
switched off there: the stores are off and no `oauth.providers.google` block is
configured.)

`…_REQUIRE` doubles as the guard on the suite's own plumbing: setting it while
`…_BASE_URL` is empty is a **failure**, because a caller who named the
capabilities to verify meant to run against something, and a CI job whose base
URL arrived empty must not report success for checks that never happened. This
is the only such guard the exit code can carry — `cmd/go` buffers a passing
package's stdout *and* stderr and prints neither, so no banner a green test
binary writes survives a non-verbose `go test`.

Against a named API Gateway stage the base URL includes the stage segment
(`https://<id>.execute-api.<region>.amazonaws.com/<stage>`); the quickstart
template deploys to `$default`, which serves at the domain root.

## Pointing it at the reference Express app

```sh
cd ../awesome-node-auth/demo/express-vanilla
npm install && npm start          # listens on :3000, mounts the router at /auth
```

then run the suite with `AWESOME_AUTH_CONTRACT_BASE_URL=http://localhost:3000`.
That demo passes `onRegister`, so the suite can provision accounts; it runs with
`cookieOptions.secure` off and CSRF disabled, so the cookies come back
unprefixed and the CSRF cases skip themselves. Both are deployment differences,
not contract differences, and the suite reports them as such — see below.

## What it will not do

**It imports nothing.** No `awesome-go-auth`, no `internal/…` from this
repository, nothing beyond the standard library. Every header name, error code,
cookie name and message is written out as a literal at the point it is asserted,
because the failure this suite exists to catch is *a change in that literal* —
importing the constant would make the test agree with the change and stay green.
For the same reason it never reads DynamoDB and never calls AWS: a client cannot,
so neither can the thing that claims to speak for clients.

**It provisions itself.** It cannot seed a store it is not allowed to reach, so
it registers the accounts it needs through `POST <prefix>/register` and throws
them away. Addresses are random under `@contract.invalid` — a reserved TLD
(RFC 2606) — so a stack with a live mailer cannot be made to send real mail by
running this. If registration is not mounted, the whole suite skips with that
reason rather than failing.

**It reads the deployment instead of assuming one.** A probe runs once at the
start and reports what this stack offers:

```
deployment under test: https://… (router mounted at /auth)
  AWESOME_AUTH_CONTRACT_REQUIRE=register,csrf,secure-cookies,sessions,totp
  csrf             on      auto-init cookie "__Host-csrf-token" observed
  docs             on      …/auth/openapi.json answered 200
  linked-accounts  absent  …/auth/linked-accounts answered 501 NOT_IMPLEMENTED — the store is switched off
  oauth-google     absent  …/auth/oauth/google answered the reference's 404 stub — no Google provider is configured
  register         on      POST /auth/register answered 201
  secure-cookies   on      csrf cookie Secure=true
  sessions         on      …/auth/sessions answered 200
  totp             on      …/auth/2fa/setup answered 200
```

**`off` is two different things, and the probe keeps them apart.** A capability
is `absent` only when the deployment declares it in one of the two documented
ways — the reference's Express 404 fall-through for an unmounted route, or this
port's 5xx with `code:"NOT_IMPLEMENTED"`. Anything else (a 500, a 403, a 501
without that code) is `BROKEN`, and a broken capability **fails** the cases that
need it instead of skipping them, and fails the probe besides. A fault must
never be able to switch a case off; that is how a contract suite goes green
against a broken deployment.

`oauth-google` is probed by its own classifier, because its two documented
answers are neither of the two above: `GET <prefix>/oauth/google` is `on` when
it answers a 302 to the provider carrying a `state`, and `absent` only on the
reference's own per-provider stub, `404 {"error":"Google OAuth not
configured"}`. A 500 from a half-wired provider is `BROKEN`, not "nobody
configured Google".

The same rule guards the suite's own footing: `POST /register` answering
anything but 2xx or 404 aborts the run. It used to skip, which meant a stack
answering 500 to every request produced the same green `ok` as a healthy one.

Cases declare what they need and are skipped, with that reason, when it is
genuinely absent — and every skip is listed on stdout at the end of the run, so
a suite that quietly stopped checking half the contract does not read like one
that checked all of it. Where a route's answer is *legitimately*
configuration-dependent — `/magic-link/send` is 200 with a mailer and 500
`EMAIL_NOT_CONFIGURED` without one, `/linked-accounts` is the
`{linkedAccounts:[…]}` wrapper with a store and a declared `NOT_IMPLEMENTED`
without one — the case accepts either and then **asserts the full shape of
whichever branch it took**, absence branches included: an absence must not carry
the payload it says it hasn't got, must not smuggle a bare array, and must not
contradict what the probe saw on that same route seconds earlier. A branch that
only logs is a corruption's way in. A suite that fails because the operator has
not configured mail is a broken suite; a suite that stops asserting because of
it is a useless one.

The one thing deliberately asserted *without* consulting configuration is the
cookie name-prefix rule, restated so it needs no configuration: a cookie that is
`Secure` with `Path=/` and no `Domain` must be named `__Host-…`, one that is
`Secure` otherwise must be `__Secure-…`, and one that is not `Secure` must be
bare. That is the same rule on every deployment, which is why the identical
assertion holds on a hardened stack and on the demo over plain http.

**The email flows need no mailer, and `…_REQUIRE` has no capability for one.**
`cases_email_test.go` covers what a suite with no mailbox can see: the gates and
shapes decided before a message would leave. They are deployment-dependent in
the sense above — the answers hold whether or not the operator wired mail — but
not forked: the reference's three token routes (`/forgot-password`,
`/send-verification-email`, `/change-email/request`) check nothing about
delivery and answer `200 {"success":true}` with or without a sender (§2, "Mailer
dispatch order"), so there is no mailer branch to accept and nothing a mailer's
absence could switch off. A `500` on those routes is a transport that failed
after the token was stored — a fault, and the suite reports it as one. Only
`/magic-link/send` and `/sms/send` refuse up front, and they keep their coded
`…_NOT_CONFIGURED` branches in `cases_deployment_dependent_test.go`.

| Case | Pins | Needs |
|---|---|---|
| `verify-email/get-always-json` | `GET /verify-email?token=<never issued>` is `400 {"error":"Invalid verification token"}` with no `code`, as JSON for `Accept: application/json` *and* `Accept: text/html`; never a redirect, never markup (the static UI page fetches this route and renders the JSON) | — |
| `change-email/request-requires-auth-and-csrf` | bare request → `403 {"error":"No access token provided"}` (no `code`); cookie session without `X-CSRF-Token` → `403 CSRF_INVALID`; both → `200 {"success":true}`, against a fresh address so the route's deliberate `409` oracle cannot fire | `csrf` |
| `send-verification-email/requires-auth` | bare, body-less request → `403 {"error":"No access token provided"}` (no `code`), the way the Flutter client and the served `auth.js` call it | — |
| `forgot-password/unknown-address-is-a-plain-success` | (extended) the optional `emailLang` body field is accepted: `{"email":…,"emailLang":"it"}` is the same plain `200 {"success":true}` | — |

**The token itself is pinned in one place, and only there.** Everywhere else a
token is opaque, which is right — the family's clients are handed one and send
it back, and none of them parses it. `cases_token_test.go` is the exception,
because `security.jwt.extraClaims` and `security.jwt.claimsWebhook` make the
token the carrier of whatever a deployment configured, and the consumer reading
those claims is outside this repository and outside the family. It decodes the
payload the way such a consumer does — split on `.`, unpadded base64url, JSON —
and verifies nothing: this suite holds no signing secret and must not pretend
to. No new capability: it needs an account and a bearer login, which every
deployment that mounts `register` can give it.

| Case | Pins | Needs |
|---|---|---|
| `token/bearer-access-token-is-a-jws-with-the-session-claims` | a bearer access token is a three-part compact JWS; its payload carries `sub`, `sid`, `typ: "access"`, `iss`, and numeric `iat`/`exp`; the refresh token is the same shape with `typ: "refresh"`; no credential material is inside a payload anyone holding the token can read | — |
| `2fa/temp-token-is-not-accepted-by-me` | a `tempToken` from a 2FA login challenge does not open `GET /me`, and the refusal is the ordinary `403 {"error":"Invalid or expired access token"}` with no `code` rather than a 2FA-flavoured one | `totp` |
| `2fa/verify-wrong-code-is-uniform` | `POST /2fa/verify` answers the same `401 INVALID_ACCESS_TOKEN` for an absent, empty, malformed or unsigned `tempToken` — the route has no missing-token branch, so it is no oracle for which half of a guess was right — and the challenge the user holds still completes afterwards | `totp` |

`2fa/temp-token-is-not-accepted-by-me` fails against the reference by design:
the reference mints its `tempToken` as an ordinary access token with a
five-minute life and nothing distinguishing it, so there the token *does* open
`/me`. The typed temp token is the registered core deviation
`temp-token-is-typed-not-an-access-token`, and the five-minute bypass it closes
is worth the divergence. `2fa/verify-wrong-code-is-uniform` pins the other half
of that route's oddity — it answers `INVALID_ACCESS_TOKEN` where its magic-link
and SMS siblings answer `INVALID_TEMP_TOKEN` for the same failure, which is the
reference's own inconsistency, reproduced rather than harmonised.

**The OIDC surface is the one area with no reference wire to cite, and `idp` is
its capability.** `awesome-node-auth`'s `idProvider` block is RS256 signing and
JWKS publication and nothing else — no `/authorize`, `/token`, `/userinfo` or
discovery document exists anywhere in its source
([parity-gap-node-vs-go.md](../../docs/spec/parity-gap-node-vs-go.md) #27) — so
`cases_idp_test.go` checks the JWKS route against the reference, down to its
`Cache-Control: public, max-age=3600`, and everything else against
[docs/oidc.md](../../docs/oidc.md) and the RFCs it commits to.

The probe is `GET <prefix>/.well-known/jwks.json`, fetched **anonymously**: that
route is public by construction, so probing it with a session would hide a
deployment that had put it behind one. A deployment with no `idProvider` block
answers 404, which is the documented absence, and the four cases skip.

None of them needs a registered client — a deployment may enable the IdP purely
to publish a signing key — and the two error cases accept the core's own bodies
rather than the family `{error,code}` envelope, because these endpoints have no
family client to stay compatible with. That boundary is stated in
[docs/oidc.md](../../docs/oidc.md) §6.

| Case | Pins | Needs |
|---|---|---|
| `idp/jwks-document-shape` | 200 with `Cache-Control: public, max-age=3600`; every key carries **exactly** `kty,use,alg,kid,n,e` (a private member here would publish the signing key itself), `kty:"RSA"`, `use:"sig"`, `alg:"RS256"`, `kid` non-empty and unique across the document, `n`/`e` unpadded base64url (RFC 7518 §6.3.1); no `Set-Cookie` on a route served from a shared cache | `idp` |
| `idp/discovery-document-shape` | an absolute `issuer`; `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` and `jwks_uri` all rooted at it; `RS256`, `code`, `public` and `client_secret_post` advertised; and the advertised `jwks_uri` really serves the JWKS document | `idp` |
| `idp/token-refuses-a-code-nobody-issued` | `POST /token` with a well-formed `authorization_code` grant and an unissued code is a refusal naming `invalid_grant` (or `invalid_client`, since the suite cannot know which clients are registered) and never contains a token | `idp` |
| `idp/authorize-refuses-an-unknown-client` | an unregistered `client_id` is refused **without a redirect** — an unvalidated `client_id` has no validated `redirect_uri` to send an error to, so a redirect there is an open one — and the refusal does not echo the requested URI back | `idp` |

`me/known-gaps-against-the-reference` changed with awesome-go-auth v0.4.0: the
profile now carries `loginProvider` unconditionally (`"local"` for a password
account, the reference's `?? 'local'`), and the case that used to record its
absence now fails on its absence. `role` stays presence-optional, as it is in
the reference.

**The documentation surface is `docs`, and one option mounts both of its
routes.** `GET <prefix>/openapi.json` is the generated OpenAPI document and
`GET <prefix>/docs` is the Swagger UI page that reads it; the reference
registers them at the very end of its auth router under a single `swagger`
option (`auth.router.ts:1651-1677`, pinned at `tests/swagger.test.ts:228-260`),
and this port mounts them from `docs.swagger` — `true`, `false`, or `auto`,
which is on outside production and off in it. `auto` is the default here and
`production` is the default environment, so an unconfigured stack answers 404 on
both and the three cases skip.

The probe is `GET <prefix>/openapi.json`, fetched **anonymously**. Neither route
carries a guard of its own — no auth middleware, no session, nothing to present
a credential to — so probing with a session would hide a deployment that had put
them behind one. It is the document and not the page because the document is the
machine-readable half, and because one option mounts both: a deployment serving
one and 404ing the other is a fault, so the page's own case fails on it rather
than skipping.

| Case | Pins | Needs |
|---|---|---|
| `docs/openapi-document-is-served-anonymously` | `200 application/json`, `openapi: "3.0.3"`, a non-empty `paths`; every path item under the one base the `/login` item sits under (read off the document, because `docs.basePath` may legitimately move it behind a proxy); and the only cookie the response may set is the CSRF auto-init one | `docs` |
| `docs/swagger-page-points-at-the-document-beside-it` | `200 text/html; charset=utf-8` carrying a Swagger UI shell, and the spec `url:` it hands `SwaggerUIBundle` is fetched from this same deployment and really serves an OpenAPI document — the half of the route that can be wrong while the status code is right | `docs` |
| `docs/documentation-routes-carry-no-guard` | both routes answer `200` identically to a bare caller and to one presenting a bogus bearer token and a bogus `X-CSRF-Token`: they have no auth gate, and the CSRF middleware in front of them passes every non-mutating method through | `docs` |

The product's own `Content-Security-Policy` on those two responses is
deliberately **not** here. It is a registered deviation
(`docs-page-carries-a-content-security-policy`, [deviations.md](../../docs/deviations.md)),
the reference sets no such header, and the identical assertions have to run
against both — so it is pinned in `cmd/auth/docs_test.go`, where the middleware
that sends it lives.


**The hosted UI** is the whole of the reference's `ui` router, mounted at
`<prefix>/ui` (`auth.router.ts:1640`, `src/router/ui.router.ts`): the config
document, the server-rendered pages, the vendored assets under them. One flag
mounts all of it — `config.ui.enabled` there, `ui.enabled` here — and it
defaults to **off**, so an unconfigured stack answers 404 on the whole subtree
and the three cases skip.

The probe is `GET <prefix>/ui/config`, fetched **anonymously**: it is the first
request a login page makes, before any session exists, so a probe holding one
would hide a deployment that had put the UI behind a session. It is the document
rather than a page for two reasons. Every page path falls through to the SSR
catch-all, so a deployment serving a stray `index.html` would answer 200 to a
page probe while being no UI at all; and the document is the only part of the
surface a **headless** deployment still serves, so probing a page would report a
legitimate SPA posture as an absent feature. A 200 that is not JSON is recorded
as a fault rather than as the feature: the config route lives *inside* the UI
handler, with the catch-all behind it, so a route that stopped answering would
serve HTML with a perfectly good 200.

| Case | Pins | Needs |
|---|---|---|
| `ui/config-document-is-served-anonymously` | `200 application/json` with no credential; `apiPrefix` is the prefix this deployment actually serves; the three branding members that have defaults behind them (`primaryColor`, `secondaryColor`, `siteName`) are never empty; `translations` is an object and never `null`; `lang` is non-empty; `features` carries `register`; and the only cookie the response may set is the CSRF auto-init one | `ui` |
| `ui/login-page-is-server-rendered` | `200 text/html; charset=utf-8`, `Cache-Control` carrying `no-store` and `max-age=0` because the document embeds a per-request config object, `window.__AUTH_CONFIG__` injected so the page boots without waiting for `/ui/config`, that injected object agreeing with the fetched one, and the readiness splash injected with it | `ui` |
| `ui/mount-root-and-unknown-pages-render-the-login-page` | `<prefix>/ui`, `<prefix>/ui/` and an extensionless path with no page of its own all answer `200` with a rendered page and **no redirect** — the mount root is one page in Express and was two patterns here, and the catch-all fallback is what makes a client-side route deep-linkable | `ui` |

Two things are deliberately not asserted, for the reason the docs section gives.
`Cache-Control: no-store` on `/ui/config` is this port's own addition — the
reference sets no header there, and `adapter/nethttp/ui.go` says so; the SSR
pages' `no-store` *is* the reference's (`ui.router.ts:284`) and is asserted. And
the escaping of the injected config object is the upstream deviation
`ui-ssr-config-json-is-html-escaped`, the one place the port is stricter than
the reference: the bytes differ, the value `JSON.parse` yields does not, so every
case parses the object rather than matching it.

Not covered here: the uploaded-asset paths, which answer 404 on this product in
every configuration — the product deviation `ui-uploaded-assets-are-not-served`
([deviations.md](../../docs/deviations.md)) — and headless mode, which is a
deployment posture the suite cannot tell from an absent one without being told.


**Rate limiting is the one capability that is declared rather than probed, and
the one case that is opt-in.** The built-in limiter is net-new to this product —
`awesome-node-auth` has none, `RouterOptions.rateLimiter` being an empty slot
(`auth.router.ts:46`) that collapses to `rl = []` absent (`:468`) — so there is
no reference behaviour to compare against, and, unlike every other capability
here, it cannot be observed by a harmless request. A limiter answers nothing
until it refuses, and making it refuse means spending the budget it exists to
protect: a probe that did that would flake, because the budget may already be
part-spent by real traffic or a parallel run, and it would leave the deployment
throttled for whoever called next.

So the operator declares it, with `AWESOME_AUTH_CONTRACT_RATE_LIMIT=email:10`,
and the case runs only then. Only `email:` is honoured. Under an account-keyed
limiter the case spends the budget of one random never-registered address under
`@contract.invalid` and leaves the stack exactly as it found it; under an
address-keyed one the budget it would spend is the suite's own source address,
shared with everyone behind the same egress, which is the state the case exists
not to leave behind. An `ip:` declaration is therefore recorded `absent` and the
case skips, while a declaration nobody can parse is `BROKEN` and fails — a
malformed declaration is a fault, not a deployment without a limiter.

**The case asserts the shape, not the timing.** It never asserts that the
refusal arrives on request `max+1`: a fixed window can roll mid-run and hand back
a fresh budget, and another caller may have spent part of the first one. It
sends at most `2×max+2` requests, stops at the first `429`, and asserts what that
response *is*.

| Case | Pins | Needs |
|---|---|---|
| `rate-limit/refusal-shape` | the refusal is `429` with the body `{"error":"Too many requests","code":"RATE_LIMITED"}` verbatim, `Content-Type: application/json` and a `Retry-After` that parses as a positive integer; it carries **no `Set-Cookie`**, not even the CSRF auto-init one, because the limiter sits ahead of the middleware that distributes it and a refused request cost nothing downstream; and **no `RateLimit-*` header** on it or on the last allowed response, since `RateLimit-Remaining` under an account-keyed counter is an oracle about somebody else's traffic | `rate-limit` |

This case fails against the reference by design, in the sense that it can never
run there: the reference has no limiter to declare. It pins the product
deviation `rate-limited-routes-answer-429`
([deviations.md](../../docs/deviations.md)) rather than a clause of the wire
contract, which is why its `Doc` cites the register.

**The admin console is `admin`, and the credential to enter it is the
operator's to declare.** The reference's admin router
(`src/router/admin.router.ts`) is mounted by the host *beside* the auth router
— `/admin` by default, `AWESOME_AUTH_CONTRACT_ADMIN_PATH` to move it — and
guarded by an access policy the operator chose (`admin.accessPolicy` here). It
has no family client of its own: the client it must stay compatible with is
the reference's `admin.js`, which the console serves itself, and the cases
drive the routes that script calls with the bodies it sends.

The probe is `GET <admin>/api/ping`, fetched **anonymously**, and it reads
three answers rather than two. `401` is a mounted, guarded console and is
`on`. `404` is no console — `admin.enabled` off — and is `absent`. And `200`
to a caller holding nothing is the `open` policy, the reference's own default
and the one configuration an authentication product must not report as
healthy: the probe records it as **`BROKEN`**, says the console is open in as
many words, and fails the run. A suite that treated an unguarded console as a
capability would pass every case below against a deployment that admits the
world.

The credential is declared, not provisioned. The suite provisions ordinary
accounts through `POST /register` and nothing a client can do turns one of
them into an administrator: under `is-admin-flag` the flag is set by the
console itself, under `first-user` the first account on a shared stack belongs
to somebody else, and under `rbac:<role>` the role is assigned by an
administrator. So `AWESOME_AUTH_CONTRACT_ADMIN_EMAIL` and
`AWESOME_AUTH_CONTRACT_ADMIN_PASSWORD` name an account the console admits —
the stack's configured root user (`AdminRootEmail`, whose hash lives in Secrets
Manager) is the honest choice, because it exists precisely to bootstrap the
first administrator — and they settle `admin-credential`, which the four
credentialed cases need. Unset, those four skip with that reason; half-set is
a fault. The login itself is `POST <admin>/login` as JSON with no CSRF header,
because the admin router sits outside the auth router's CSRF chain, and the
policy is not consulted at login: a user it will refuse logs in and is answered
403 by the next request, exactly as in the reference.

The same probe also settles **`admin-session`**, off the anonymous shell.
Two conforming consoles answer the ping 401: one guarded by a policy, whose
shell injects `sessionBased: true` and whose `/login` and `/logout` routes
exist, and one guarded by the legacy bootstrap secret alone, whose shell
injects `sessionBased: false`, registers no `/login`, and whose SPA holds the
secret in `sessionStorage` (`admin.router.ts:516-541`). The ping cannot tell
them apart; the shell can, so the probe reads it — a `302` carrying
`?redirect=` settles it `on` too, because only the session guard redirects to
a host-configured `loginPath`. Every case that logs in, or asserts the login
form, needs `admin-session`; against a secret-only console they skip with
that reason instead of failing on a form the deployment never serves.

| Case | Pins | Needs |
|---|---|---|
| `admin/ping-refuses-an-anonymous-caller` | `401 {"error":"Unauthorized"}` — the admin envelope, no `code` — with no credential and with a bogus bearer token alike | `admin` |
| `admin/shell-serves-the-login-form-anonymously` | an HTML `GET <admin>/` is `200 text/html` carrying `window.__ADMIN_CONFIG__` with `base` equal to the mount, `sessionBased: true` and an absolute `authApiPrefix` (the reference emits the host's option, not the mount it observes, so equality with the prefix the suite drives is logged, not asserted); or `302` to `<loginPath>?redirect=<mount>` when the host configured a login path; `admin.js` and `admin.css` are public either way | `admin`, `admin-session` |
| `admin/login-sets-the-session-and-ping-reads-it` | `POST <admin>/login {email,password}` is `200 {"success":true}` with a `Set-Cookie`; `GET <admin>/api/ping` with it is `200 {ok:true, features:{…}}` carrying all eleven flags `admin.js` reads; the wrong password is `401 {"error":"Invalid credentials"}`; `POST <admin>/logout` makes the next ping anonymous again | `admin`, `admin-session`, `admin-credential` |
| `admin/users-listing-has-the-reference-shape` | `GET <admin>/api/users` is `200 {users:[{id,email,…}], total:n}` with a lister, or `501 {error:'IUserStore.listUsers is not implemented', users:[], total:0}` without one; never a bare array, never a `passwordHash`; `total ≥ 1` after this run registered an account — an unswept DynamoDB table under-reports here, which is what `migrate backfill-users` fixes | `admin`, `admin-session`, `admin-credential` |
| `admin/settings-round-trip` | `GET <admin>/api/settings` is the settings object unwrapped; a write is observed — `PUT` flips `require2FA` when the store holds that key, else `PATCH /api/settings/ui` changes `siteName` when it holds a `ui` block — answering `200 {"success":true}` with the next `GET` reflecting it, and a cleanup restores exactly what was there, keys included: on this product a key's presence carries meaning (`runtime-settings-seed-only-fills-absent-keys`), so the case never materialises one and skips the write half when nothing restorable is stored; `404 {error:'Settings store not configured'}` on a deployment with no settings store, which skips | `admin`, `admin-session`, `admin-credential` |

Three things are deliberately not asserted here, for the reason the docs and
UI sections give: they are upstream deviations the reference does not share,
pinned in the core's own tests. The admin token being typed and the 2FA
step-up token being refused (`admin-guard-accepts-only-typed-session-tokens`);
an unauthenticated HTML `GET` reaching only the shell and never a guarded route
(`admin-unauthenticated-get-serves-only-the-login-form`, pinned in
`cmd/auth/admin_test.go` `TestAdminConsoleIsMountedGuardedAndServed` — every
anonymous guarded request this suite makes carries `Accept: application/json`,
the branch the reference answers 401 on too); and the cookie's `Secure` flag
coming from configuration rather than `X-Forwarded-Proto`. The console's
documentation pair, `GET <admin>/api/openapi.json` and `/api/docs`, is not
covered by this suite at all: no case requests it, and its status and its
`Content-Security-Policy` are pinned in `cmd/auth/admin_test.go`
`TestAdminDocsPairFollowsDocsSwaggerAndCarriesThePolicy`.

## Adding a case

Adding a route to the covered surface is adding a `Case`, never editing the
harness:

```go
// cases_whatever_test.go
func init() {
	register(Case{
		Name:  "area/what-it-pins",
		Doc:   "§n — the clause of docs/spec/wire-contract.md this pins",
		Needs: []Capability{CapSessions},        // optional
		Run: func(t *testing.T, e *Env) {
			c, acct := e.LoginCookie(t)
			c.POST(t, "/route", body{"field": acct.Email}, CSRF()).
				mustError(t, 400, "SOME_CODE", "Some message")
		},
	})
}
```

`Doc` is logged before the case runs, so a failure names the clause that broke
without anyone opening the spec.

## Adding a capability

A capability is likewise one declaration and never an edit to the harness. It is
registered in `capabilities_test.go`, or in a file of its own, and carries its
own name, the point in the probe pass it belongs to, and the probe:

```go
// CapWhatever is what the deployment either offers or does not.
const CapWhatever Capability = "whatever"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapWhatever,
		Stage: stageProbed,                     // see probeStage
		Probe: func(t *testing.T, p *probeRun) {
			// Say which client and why: p.Anon holds no session until the
			// register probe runs and the provisioned account's afterwards,
			// p.LoggedIn(t) is a separate identity with its own jar.
			p.Set(CapWhatever, classify(p.LoggedIn(t).GET(t, "/whatever")))
		},
	})
}
```

Everything else follows from that one declaration: the probe order, the names
`AWESOME_AUTH_CONTRACT_REQUIRE` accepts, the report, and the "report every fault
once" loop. A probe that settles two capabilities out of one response — as the
CSRF one does, since the `Secure` flag can only be read off a cookie — names the
second in `Settles`. `TestCapabilityRegistryIsWellFormed` runs without a
deployment and catches a duplicate name, a missing probe, and a `Case` that needs
a capability nobody registers.

The pieces: `harness_test.go` (env, registry machinery, probe pass, runner),
`capabilities_test.go` (the capability declarations), `client_test.go` (client,
request options, response assertions, provisioning), `cookies_test.go` (cookie
parsing and the prefix rule), `totp_test.go` (RFC 6238, so the suite can mint its
own second factor rather than shell out).

Everything lives in `_test.go` files: nothing here compiles into the deployable,
and nothing here can be imported by it.

## Scope

Covered: the contract hard points — cookie vs bearer mode, cookie names and
attributes, CSRF double-submit, unwrapped `/me` (with `loginProvider`),
empty-body refresh, the `{sessions:[…]}` and `{linkedAccounts:[…]}` wrappers,
`SESSION_REVOKED`, the TOTP round trip end to end, the step-up token's limits
and the shape of the access token itself, the documented error shapes
including the paths that carry no `code`, the mailbox-free half of the email
flows (the auth and CSRF gates on `/change-email/request` and
`/send-verification-email`, `GET /verify-email` answering JSON and never
redirecting, `/forgot-password` accepting `emailLang`), and the browser-visible
half of OAuth: the authorization redirect and its query, the unknown-provider
404, and the callback's JSON-not-a-redirect failure shape.

The OIDC surface joins that list as far as it can be seen without a registered
client: the JWKS document's shape and caching, the discovery document, and the
two refusals that must not leak a token or a redirect.

The documentation surface joins it too: the served OpenAPI document, the Swagger
page and the url it points at, and the fact that neither route asks for a
credential.

So does the hosted UI, as far as a black-box client can see it: the config
document the pages boot from, the server-rendered login page with its injected
configuration and its readiness splash, and the two path shapes that are one
page in Express and had to be made one page here — the mount root with and
without its trailing slash, and an extensionless path with no file of its own.

The rate limiter joins it on the operator's say-so only, and only as far as the
shape of one refusal: that a `429` is the registered body, carries a usable
`Retry-After`, sets no cookie and leaks no budget. The timing is deliberately
not covered — a suite that had to exhaust a live limiter to pass would flake and
would leave the deployment throttled for the next caller — and neither is the
counter's atomicity, which is pinned against a real DynamoDB in
`internal/store/dynamodb/rate_limit_test.go` instead.

The admin console joins it as far as the operator lets it: the guard's refusal
and the login shell without a credential, and — with one declared — the login,
the ping and its feature flags, the users listing in both of its documented
shapes, and a settings round trip that observes a write and restores exactly
what was there. The promote, role, tenant, API-key, webhook and upload routes
are not covered, because each one changes the deployment for whoever calls
next. `cmd/auth/admin_test.go` drives the promote and upload routes end to end
against a synthetic deployment, reads the role, tenant, API-key, webhook and
per-user metadata routes once each behind their handed-over stores, and
creates an API key and a webhook through the console to assert that neither
credential reaches the log; it does not exercise every route of those tabs.

Not covered: the OAuth round trip itself — the suite cannot consent at a real
provider — so the exchange, the provisioning policy and the account-conflict
redirect are pinned against an httptest provider in `cmd/auth/oauth_test.go`
instead; the OIDC authorization round trip, which needs a client id and secret
the suite cannot register for itself (`cmd/auth/idp_test.go` drives that one end
to end against a synthetic deployment instead); and the tools/SSE router and
the email/SMS token round trips — a token minted by one route and spent by
another — because the suite has no mailbox to read it from. Nothing stops a
case being added for them the day the deployment has what they need.
