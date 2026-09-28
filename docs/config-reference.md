# Configuration reference

What the deployed binary reads, in the order it reads it, and what every knob of
the `email` and `oauth` domains does once it is read.

This page is operator-facing. The schema's provenance — every default traced to
the line of `awesome-node-auth` that sets it, and the refuse-to-start rules —
is [`docs/spec/config-schema.md`](spec/config-schema.md); where the two differ,
the spec is the contract and this page is the deployment. Behaviour that
deliberately departs from the reference is registered in
[`docs/deviations.md`](deviations.md).

## 1. The two sources

Configuration comes from a JSON **document** and from `AWESOME_AUTH_*`
**environment variables**, layered at cold start in this order
(`internal/config/load.go`):

1. **Defaults** — `config.Defaults()`. A deployment that sets nothing still
   starts, in the product's safe posture: `deployment.environment: production`,
   CSRF on, secure cookies.
2. **The document**, over the defaults.
3. **The environment**, over the document. One variable per knob; the variable
   always wins, which is what lets a stack template override a baked document
   without rebuilding the artifact.
4. **Derived values** that depend on the layered result.
5. **Secrets**, resolved from their stores (§3). After both override layers,
   because a rule such as RS-1 needs the value's length and not its reference.
6. **Validation**: types, ranges and enums, then the §2 refuse-to-start rules,
   then the phase gate (§4). All three run to completion — an operator fixing a
   broken deploy gets the whole list, not the first line of it.

A failure at step 6 aborts the cold start. The Lambda service reports an init
failure the deployment can see, rather than a 500 per request that looks like an
outage.

### Where the document comes from

| Variable | Meaning |
|---|---|
| `AWESOME_AUTH_CONFIG_FILE` | path to a JSON document inside the artifact, normally `/var/task/awesome-auth.json` |
| `AWESOME_AUTH_CONFIG_JSON` | the JSON document inline |

Setting both refuses to start: picking one silently would make the deployment
depend on which variable a template happened to set last. Setting neither means
defaults plus the environment, which is how a minimal development stack runs.

Every document needs `"schemaVersion": 1` at its root. It is checked before
anything else is trusted, because a document written for another major version
may mean something different by the very keys this build is about to read.

### Environment variable conventions

- One variable per knob, named in the tables below and in the spec.
- A list knob takes a comma-separated value; entries are trimmed and empties
  dropped (`AWESOME_AUTH_EMAIL_SITE_URLS=https://a.example.com,https://b.example.com`).
- A boolean takes `true` or `false`.
- `stores.enable.<store>` is generated from the store list:
  `AWESOME_AUTH_STORES_ENABLE_TEMPLATES`, `..._LINKED_ACCOUNTS`, and so on.
- Some knobs are **file-only** by design, `email.templatesDir` among them: a
  directory baked into the artifact is not something an environment variable
  should be able to move. Those knobs have no variable and the tables say so
  with a dash.

## 2. What a cold start tells you

Three kinds of line, all JSON, all on the deployment's log group:

- `configuration warning` — the document loaded, and something in it deserves
  saying out loud (a production secret in a plain environment variable, for
  one).
- `configured knob is not wired to the auth core` — a knob inside a wired domain
  that the imported core cannot honour, reported with its path and a remedy
  (`unwiredKnobs`, `cmd/auth/app.go`). It is never silently ignored.
- `credential delivery wired`, `email flows wired` and `oauth wiring` — one line
  each an operator can read the whole delivery, email and federated-login
  posture off: which transport each seam uses, the canonical site URL, how many
  origins are allowlisted, what the templates directory seeded, and which
  providers, provisioning policy and linking stores the OAuth block came up
  with.

## 3. Secrets

A secret-valued knob never holds a value in the document. It holds a reference:

```json
{
  "email": {
    "deliveryWebhook": {
      "secret": {"secretsManager": "awesome-auth/prod/delivery-webhook"}
    }
  }
}
```

The three forms, highest priority first:

| Form | Resolved from |
|---|---|
| `{"secretsManager": "<id-or-arn>[#<jsonKey>]"}` | Secrets Manager; `#<jsonKey>` selects one key of a JSON secret document |
| `{"ssmParameter": "<name>"}` | SSM Parameter Store, `SecureString` |
| `{"envVar": "<NAME>"}` | that environment variable — development only |

Without a document, the environment can name a store too: the knob's documented
variable with `_SECRETSMANAGER` or `_SSM_PARAMETER` appended carries a reference
rather than a value (`AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET_SECRETSMANAGER`).
The bare variable carries the value itself and is development-grade: in
production it loads and warns, because a Lambda environment variable is visible
to anyone who can describe the function.

A plaintext secret written straight into the document refuses to start, with the
knob's dotted path.

## 4. Domains this build does not act on yet

A domain the schema accepts but the binary does not wire is **refused at start**
(rule `PHASE`), never silently ignored: a document that configures it would
otherwise describe behaviour the deployment does not have. The live list is
`unwiredDomains()` in `internal/config/phases.go`.

The whole `email` domain now loads, and so does the whole `oauth` domain.
`email.siteUrls`, `email.templatesDir` and `email.deliveryWebhook` were the last
three of the former to leave that list; `oauth.providers` and
`oauth.provisioning` (§8) are the latest to go, secret prefix included — a
provider's `clientSecret` supplied through its documented environment variable
no longer trips the gate, because it is read.

So do `twoFactor`, `security.jwt.extraClaims` and `security.jwt.claimsWebhook`
(§6, §7). Nothing under `security.` is refused any more either.

`idProvider` and `resourceServer` left it too (§9 and §10). Configuring either is
now a deployment that behaves differently rather than one that refuses: the first
mounts the OIDC surface and publishes a JWKS document, the second unmounts the
credential surface and verifies another issuer's tokens.

`runtimeSettings` left the list before it (§11). Configuring it now seeds the
runtime-mutable layer instead of refusing the deployment, and
`runtimeSettings.require2fa` reaches a route: `POST <prefix>/2fa/disable` answers
`403` `2FA_REQUIRED` on it.

`docs` left it in the round before (§12). `docs.swagger` now decides whether the
imported adapter mounts `GET <prefix>/openapi.json` and `GET <prefix>/docs`, and
`auto` — the default — is resolved against `deployment.environment`, so an
unconfigured deployment answers 404 on both. `docs.basePath` reaches the core
unchanged and moves what the document describes, never where it is served.

`rateLimit` is the latest to go (§13), and it is the first domain to leave this
list whose behaviour has no counterpart upstream at all: the reference ships no
limiter, so there was nothing to inherit and every default is this product's.
Configuring the block now changes what a deployment does instead of refusing it —
and, because `rateLimit.enabled` defaults to `true`, so does configuring nothing.

`ui` is the latest to go (§15), and it is the first domain to leave this list
that adds a *surface* rather than changing one: with `ui.enabled` set, the
imported adapter mounts the reference's whole UI router at `<prefix>/ui` — the
config document, the server-rendered pages and the vendored assets — and the
same flag re-points every emailed link at a hosted page. It is also the first
whose surface reads the settings store on every request rather than once at cold
start; §15.1 says what that costs and what a store failure looks like from
outside.

`admin` is the latest to go (§16), secret prefix included, and it is the first
whose surface is mounted *beside* the api prefix rather than under it: with
`admin.enabled` set, the imported adapter mounts the core's console at
`admin.basePath`. `admin.bootstrapSecret` and `admin.rootUser.passwordHash`
supplied through their documented variables no longer trip the gate, because
they are read. What refuses an admin block now is the block's own rules, which
the gate used to pre-empt: RS-6 for a console enabled with neither a policy nor
a bootstrap secret, or with a bootstrap secret too short to be one; RS-17 for
`first-user` on every driver, and RS-10 for it on a driver that cannot list
users at all; RS-18 for a session console beside `cookies.sameSite: none`; and
the `stores.enable.rbac` requirement behind `rbac:<role>` and
`permission:<perm>`. Two of its knobs are reported rather than honoured (§16.8),
which is the other mechanism and not this one. **The one left on the list is
`tools`.**

`stores.migration` (§13) never appeared on that list and never will: it is new in
this release and is wired by the same change that declared it, so there was never
a build that validated it and did nothing.

`email.templatesDir` needs a template store and `runtimeSettings` needs a
settings store, and both drivers now back both: the DynamoDB store keeps mail
templates and UI translations on its `TEMPLATES` partition and the settings on
its `SETTINGS` one, the memory driver holds both per execution environment (§5.3,
§11). A driver that backs neither is still refused by `checkStoreSupport` at cold
start, by name — a store gap rather than a phase gap.


### 4.1 Five `stores.enable.*` flags are real switches now, and one still refuses

`stores.enable.metadata`, `.rbac`, `.tenants`, `.apiKeys` and `.webhooks` are
accepted on both drivers since the admin surface, and each one now changes what
the deployment does: the `admin` slot of the composition root hands the flagged
store to the core by name (`auth.WithMetadataProvider`, `WithRBACProvider`,
`WithTenantProvider`, `WithAPIKeyStore`, `WithWebhookStore`), and the console's
tab for it is drawn — `GET <admin>/api/ping` reports `roles`, `tenants`,
`metadata`, `apiKeys` and `webhooks` true exactly when the flag is (§16.4). One
of them reaches an auth route too: with `stores.enable.metadata` on, the profile
`GET <prefix>/me` renders carries the user's metadata, which is the reference's
own behaviour with a metadata store passed. The flags default to **off**, so a
document that says nothing draws no extra tab and reads no extra store.

`stores.enable.telemetry` is still refused by `checkStoreSupport` on both
drivers, on the same rule the other five used to fall under: the DynamoDB store
implements it, but the telemetry store reaches a route only through the tools
router's `ToolsOptions.TelemetryStore`, which the `tools` block hands over. Until
it does, the flag would validate, start cleanly and do nothing — the exact
misconfiguration §1.17 exists to refuse — so `driverStores` keeps answering the
narrower question it has always answered, "does turning the flag on change what
the deployment does", and the refusal names the driver rather than shrugging.

The three admin listers and the two profile flag writers need no flag at all
and have none: `AdminUserStore`, `SessionLister`, `RoleLister`,
`UserAdminFlagStore` and `UserTwoFactorPolicyStore` are found by type-asserting
the user, session and RBAC stores the core was already given, so they are live
wherever those are. The two writers arrived with the admin surface, because it
is the first block with a route that writes either flag (§16.2).

## 5. `email.*`, knob by knob

| Path | Type | Default | Env var |
|---|---|---|---|
| `email.siteUrls` | string[] | none; `deployment.publicUrl` stands in | `AWESOME_AUTH_EMAIL_SITE_URLS` |
| `email.mailer.endpoint` | string | none | `AWESOME_AUTH_MAILER_ENDPOINT` |
| `email.mailer.apiKey` | secret | none | `AWESOME_AUTH_MAILER_API_KEY` |
| `email.mailer.from` | string | none | `AWESOME_AUTH_MAILER_FROM` |
| `email.mailer.fromName` | string | none | `AWESOME_AUTH_MAILER_FROM_NAME` |
| `email.mailer.provider` | string | none | `AWESOME_AUTH_MAILER_PROVIDER` |
| `email.mailer.defaultLang` | `en`\|`it` | `en` | `AWESOME_AUTH_MAILER_DEFAULT_LANG` |
| `email.verification.mode` | `none`\|`lazy`\|`strict` | `none` | `AWESOME_AUTH_EMAIL_VERIFICATION_MODE` |
| `email.templatesDir` | string (directory) | none | — (file-only) |
| `email.deliveryWebhook.url` | string (https) | none | `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_URL` |
| `email.deliveryWebhook.timeoutMs` | integer 1–10000 | `5000` | `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_TIMEOUT_MS` |
| `email.deliveryWebhook.secret` | secret | none; **required** with a url | `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET` |

### 5.1 `email.siteUrls` — where an emailed link points

Two things at once, and they are the reference's two
(`src/router/auth.router.ts:202-246`):

- **The canonical site.** The first entry is the base every emailed link is
  built on: `<siteUrl><apiPrefix><route>?token=…`. With no entry at all the
  canonical site is `deployment.publicUrl` — a product addition, because a
  relative link is dead in a mailbox and this deployment always knows the origin
  it is reached at.
- **The allowlist.** Every entry, followed by every `http.cors.origins` entry,
  deduplicated with the first occurrence's position kept. A request's `Origin`
  (else its `Referer`) is matched against that list exactly; a match becomes the
  base of the link in *that* mail, and anything else falls back to the canonical
  site.

That fallback is the security property. A password-reset link is a credential:
if any `Origin` a caller cared to send steered where the link points, anyone
could have a victim's reset link built against a host they control.

The same two values are what OAuth redirects resolve against, so an emailed link
and an OAuth redirect can never disagree about a request's origin.

```json
{"email": {"siteUrls": ["https://app.example.com", "https://admin.example.com"]},
 "http": {"cors": {"origins": ["https://console.example.com"]}}}
```

Canonical site `https://app.example.com`; a request from any of the three gets
its links built on its own origin.

### 5.2 `email.mailer.*` — the mail transport

`email.mailer.from` is the switch: a `from` address means mail delivery is
wanted, and the four mail seams go through Amazon SES. The schema also requires
`email.mailer.endpoint`, which describes the reference's HTTP gateway; SES is
reached through the AWS API and authorised by the execution role, so the
endpoint and `apiKey` address and authenticate nothing here. Both are reported
at cold start as knobs this build cannot honour rather than quietly dropped.

`email.mailer.defaultLang` is the default only: a request that carries an
`emailLang` body field of `en` or `it` renders in that language instead.

### 5.3 `email.templatesDir` — shipped templates

A directory of JSON files baked into the artifact, read once at cold start and
written into the template store. It requires `stores.enable.templates`: a
directory that seeds a store nobody enabled would be read and discarded, which
the loader treats as a misconfiguration rather than a no-op.

> **Both drivers back this.** On `dynamodb` the templates live on the table's
> `TEMPLATES` partition, so a template seeded from the artifact outlives the
> execution environment and an edit made through the store survives the next
> redeploy — which is the whole point of seeding absent ids only. On `memory`
> each execution environment holds its own copy and loses it on every cold
> start, which is what the development driver is for (§1.17). A driver that
> backs no template store is refused at cold start by name, so nothing is
> silently ignored.

Layout — one file per template at the top level, nothing recursive:

| File | Contents |
|---|---|
| `<id>.json` | a mail template: `{"baseHtml": …, "baseText": …, "translations": {…}}` |
| `<page>.ui.json` | one UI page's translations: `{"translations": {"<lang>": {"<key>": …}}}` |

Anything that is not a `.json` file is ignored, so a README can sit beside them.
The ids the mail routes render are the reference's six: `password-reset`,
`magic-link`, `welcome`, `verify-email`, `email-changed`, `invitation`. A
template stored under any other id is seeded and then rendered by nothing, which
the cold-start log says.

Inside a stored body, `{{T.key}}` is looked up in the translations for the
rendering language and `{{key}}` in the data the route supplies (`link`,
`token`, `newEmail`, …). `translations.<lang>.subject` is the subject.

Two rules, both of which fail the deployment rather than ship something inert:

- `baseHtml` and `baseText` must both be non-empty, or the core keeps rendering
  its built-in template and the seed does nothing.
- an `id` or `page` field, when present, must agree with the file name.

**The store wins.** A file whose id the store already holds is skipped, on this
and on every later cold start, so a template edited at runtime survives the next
redeploy. That precedence is the registered deviation
`templates-dir-only-seeds-absent-ids`.

A directory that is missing or unreadable **refuses to start in production** —
the artifact is supposed to contain what the document names — and **warns in
development**, where a stack may come up and render the built-ins.

The template store itself has to exist on the selected driver, and today exactly
one does — see the note above. With `stores.enable.templates` on and a driver
whose store does not provide one, the cold start refuses and names the driver,
rather than advertising admin routes whose every write goes nowhere:

```json
{"level":"ERROR","msg":"cold start failed, refusing to serve",
 "error":"config: refusing to start: 1 problem(s) in stores.enable\nstores.enable.templates is on but the dynamodb driver does not implement that store, so the feature would return NOT_IMPLEMENTED on the wire -- turn it off until the driver grows it"}
```

### 5.4 `email.deliveryWebhook.*` — delivering credentials yourself

Set `email.deliveryWebhook.url` and it becomes **the** sender for all five
credential seams: magic link, password reset, email verification, email change
and SMS code. Each one is POSTed to that receiver and nothing goes through SES
or SNS for those routes, even when the mailer and sms blocks are also
configured. It is what a deployment whose transport is neither mail nor SMS — or
is not reachable from a Lambda — wires, and it replaces the reference's
in-process send-callback functions, which a configuration document cannot
express.

The request:

```
POST <url>
Content-Type:        application/json
X-Webhook-Event:     delivery.<kind>
X-Webhook-Delivery:  <a fresh UUID per request>
X-Webhook-Timestamp: <ISO 8601 UTC, milliseconds>
X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the exact body>

{"kind": "<kind>", "delivery": { … }}
```

`<kind>` is one of `magic-link`, `password-reset`, `email-verification`,
`email-change`, `sms-code`. `delivery` carries the recipient, the token or code,
its expiry, and `linkBase` — the base this request resolved (§5.1), which the
receiver should build the link on. Any 2xx is a delivery; anything else, a
transport failure or the timeout is an error, which each route handles under its
existing contract (`/forgot-password` still answers 200 whatever happens).

**`email.deliveryWebhook.secret` is required when the url is set.** The body of
every request is a credential, so a receiver that cannot verify
`X-Webhook-Signature` cannot tell a replayed or forged delivery from a real one
— it would mint sessions for whoever posts to it. A url without a secret is
refused; a secret without a url is refused as the dead configuration it is, and
when the secret arrives through its plain environment variable with no url to
switch it on, the cold-start log reports it. The secret is never sent, only
proof of it.

`email.deliveryWebhook.timeoutMs` bounds one request, connect to last byte. The
route that minted the credential is waiting on the answer inside a Lambda
invocation, so this is what keeps a slow receiver from turning every password
reset into a function timeout. It is capped at 10000, the same ceiling
`security.jwt.claimsWebhook.timeoutMs` has and for the same reason: a deadline
longer than the invocation bounds nothing, because the function times out first
and the route then answers nothing at all rather than the 500 the deadline
exists to produce.

Two mails stay with the mailer, and are sent only when one is configured: the
notice `POST /change-email/confirm` sends to the address an account just moved
away from, and the OAuth account-linking mail of `POST /link-request`. The
reason is the seam, not the payload: `auth.DeliveryWebhook` posts the five
credential kinds above and has no method for either of these. The notice indeed
carries nothing worth signing — the link-token mail does, a single-use account
link token, and it still goes out by mail, so a deployment that moved to a
webhook to keep credentials off SES should know this one did not move with it.

```json
{"email": {"deliveryWebhook": {
  "url": "https://hooks.example.com/auth-delivery",
  "timeoutMs": 2000,
  "secret": {"secretsManager": "awesome-auth/prod/delivery-webhook"}}}}
```

## 6. `security.jwt.extraClaims` and `security.jwt.claimsWebhook` — what a token carries

| Path | Type | Default | Env var |
|---|---|---|---|
| `security.jwt.extraClaims` | map of `{fromUserField}` \| `{const}` | none | — (file-only) |
| `security.jwt.claimsWebhook.url` | string (https) | none | `AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_URL` |
| `security.jwt.claimsWebhook.timeoutMs` | integer 1–10000 | `2000` | `AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_TIMEOUT_MS` |
| `security.jwt.claimsWebhook.secret` | secret | none; **required** with a url | `AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET` |

Every token this deployment mints carries six base claims — `sub`, `email`,
`role`, `loginProvider`, `isEmailVerified`, `isTotpEnabled` — and seven session
claims: `sid`, `tid`, `jti`, `typ`, `iss`, `iat`, `exp`. These two knobs add to
that set. They replace the reference's `buildTokenPayload(user)` callback, which
is in-process code a configuration document cannot carry: the table covers
"copy a field" and "write a constant", the webhook covers everything that has to
be computed.

### 6.1 `security.jwt.extraClaims` — the mapping table

A map from claim name to exactly one of two forms:

```json
{"security": {"jwt": {"extraClaims": {
  "tenant":  {"fromUserField": "tenantId"},
  "plan":    {"const": "enterprise"},
  "seats":   {"const": 25}
}}}}
```

It is file-only: a map of objects has no sensible environment form, so it
arrives in the configuration document (`AWESOME_AUTH_CONFIG_FILE`).

`fromUserField` reads one field of the user, spelled as `GET /me` spells it:
`id`, `email`, `role`, `tenantId`, `firstName`, `lastName`, `phoneNumber`,
`isEmailVerified`, `isTotpEnabled`, `loginProvider`. Anything else is refused at
start with the claim's dotted path. The credential columns are deliberately not
on that list, and neither are the enriched collections — a mint sees the stored
row, and a collection is not a claim value.

A mapped claim is emitted on every token with whatever the field holds: an empty
`firstName` becomes an empty-string claim, not an absent one. A mapping declares
that a claim exists, and a consumer must be able to tell "not configured" from
"empty". `const` lands verbatim, keeping its JSON type.

**Three classes of name are refused at start, each naming the knob to edit:**

| Refused | Why |
|---|---|
| the six base claims | the family's clients read them off every token; redefining one changes what every client in the family sees |
| the seven session claims | the library writes them *after* the merge, so the entry could never reach a token — a claim that is silently discarded on every mint is worse than one that does not exist |
| a `fromUserField` outside the list above | a mapping is configuration, and a typo in configuration must fail at startup rather than turn every login into a 500 |

### 6.2 `security.jwt.claimsWebhook.*` — claims that are computed

With a url set, every mint — login, refresh, the 2FA step-up token — and every
`GET /me` POSTs one request:

```
POST <url>
Content-Type:        application/json
X-Webhook-Event:     claims.build
X-Webhook-Delivery:  <a fresh UUID per request>
X-Webhook-Timestamp: <ISO 8601 UTC, milliseconds>
X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the exact body>

{"user": { …the profile exactly as GET /me renders it… }}
```

and expects `200 {"claims": {…}}`. The claims object is merged last, so it wins
over the table on a shared name — the table says the same thing for everybody,
the receiver computed its answer for this user.

**A session is two tokens and the builder runs per token, so one login is two
requests.** A `GET /me` is one. An authenticated request to any other route is
**zero**: the middleware verifies the token and never runs the hook, because
what the hook computed is already inside the token the request carried.

**`security.jwt.claimsWebhook.secret` is required when the url is set.** The
request body is the user's profile and the answer decides what the token
authorises, so an unsigned receiver can neither tell this deployment's question
from anybody else's nor be told apart from a receiver that is not it. A url
without a secret is refused; a secret without a url is refused as the dead
configuration it is. The secret is never sent, only proof of it.

`timeoutMs` bounds one request, connect to last byte. A login is waiting on the
answer inside a Lambda invocation, so this is what turns a slow receiver into a
fast 500 rather than a function timeout. It must be between 1 and 10000: the
loader refuses anything above that ceiling however the value arrives, because a
deadline longer than the invocation bounds nothing — the function times out
first and the route answers nothing at all. The `ClaimsWebhookTimeoutMs` CFN
parameter carries the same `MaxValue`, and the loader enforces it for the two
routes CloudFormation cannot see: the environment variable set some other way,
and `timeoutMs` written into the configuration document.

**It fails closed (decision D-10), and the core already does it.** A non-2xx
answer, a transport failure, the timeout, a body over 64 KiB, a body that is not
JSON, a missing or non-object `claims` member: each aborts the mint, and login,
refresh and 2FA step-up answer `500 {"error":"Internal server error"}` — the
generic envelope, deliberately code-less, deliberately describing nothing. A
token minted without the claims the deployment configured would authorise less,
or more, than the deployment decided.

`GET /me` is the one deliberate exception: a builder failure there is logged and
leaves `customClaims` out of the body rather than failing the read. So a
receiver outage costs logins and refreshes and leaves the profile answering.

That log line names the receiver's **origin only**, never its path or query, and
so does the cold-start line and every refusal the loader writes about either
webhook url. A receiver behind a gateway that cannot verify an HMAC is commonly
given a capability token in its path instead; an outage must not then copy that
token into CloudWatch once per `/me` for as long as it lasts. The same holds for
`email.deliveryWebhook.url`, whose failures `POST /forgot-password` can only
report to the log.

**The receiver cannot retype a token or rebind its session.** `sid`, `tid`,
`jti`, `typ`, `iss`, `iat` and `exp` are written after the merge and a returned
value under those names is discarded. It *can* override the six base claims, as
the reference's callback can — so point this only at a receiver you own.

```json
{"security": {"jwt": {"claimsWebhook": {
  "url": "https://claims.example.com/token",
  "timeoutMs": 2000,
  "secret": {"secretsManager": "awesome-auth/prod/claims-webhook"}}}}}
```

## 7. `twoFactor.appName` — the TOTP issuer

| Path | Type | Default | Env var |
|---|---|---|---|
| `twoFactor.appName` | string, non-empty | `awesome-node-auth` | `AWESOME_AUTH_2FA_APP_NAME` |

The name an authenticator app prints above the six digits. It is the issuer in
the `otpauth://` URI `POST /2fa/setup` returns, in both places the URI carries
one — the label prefix and the `issuer` parameter — and it is the only part of
TOTP a user ever reads. Set it to the product name they know; an empty value is
refused at start, because it produces a URI no app can label.

It is passed unconditionally, so the core's fallback to its own issuer never
applies and a deployment that configures nothing gets the reference's own
default. The `iss` claim is a different thing and is not this knob: it is not
configurable in this build, and it becomes one with the identity-provider block.

## 8. `oauth.*`, knob by knob

| Path | Type | Default | Env var |
|---|---|---|---|
| `oauth.providers.<name>.clientId` | string | none; **required** per provider | `AWESOME_AUTH_OAUTH_<NAME>_CLIENT_ID` (google, github) |
| `oauth.providers.<name>.clientSecret` | secret | none; **required** per provider | `AWESOME_AUTH_OAUTH_<NAME>_CLIENT_SECRET` |
| `oauth.providers.<name>.callbackUrl` | string (absolute URL) | none; **required** per provider | `AWESOME_AUTH_OAUTH_<NAME>_CALLBACK_URL` (google, github) |
| `oauth.providers.<name>.authorizationUrl` | string (https, or http on loopback) | none; required for a generic provider, refused on a built-in one | — (file-only) |
| `oauth.providers.<name>.tokenUrl` | string (https, or http on loopback) | as above | — (file-only) |
| `oauth.providers.<name>.userInfoUrl` | string (https, or http on loopback) | as above | — (file-only) |
| `oauth.providers.<name>.scope` | string (space-separated) | the preset's, for a built-in provider | — (file-only) |
| `oauth.providers.<name>.additionalAuthParams` | map | none; layered over the preset's | — (file-only) |
| `oauth.providers.<name>.profileMap` | map | none; the default mapping | — (file-only) |
| `oauth.providers.<name>.projectId` | string | none | `AWESOME_AUTH_OAUTH_<NAME>_PROJECT_ID` (google, github) |
| `oauth.provisioning.autoCreate` | boolean | `true` | `AWESOME_AUTH_OAUTH_PROVISIONING_AUTO_CREATE` |
| `oauth.provisioning.onEmailMatch` | `link`\|`conflict`\|`reject` | `link` | `AWESOME_AUTH_OAUTH_PROVISIONING_ON_EMAIL_MATCH` |
| `oauth.provisioning.requireVerifiedEmail` | boolean | `false` | `AWESOME_AUTH_OAUTH_PROVISIONING_REQUIRE_VERIFIED_EMAIL` |
| `oauth.provisioning.allowedEmailDomains` | string[] | none — every domain | `AWESOME_AUTH_OAUTH_PROVISIONING_ALLOWED_EMAIL_DOMAINS` |
| `oauth.provisioning.fieldMap` | map | none | — (file-only) |

### 8.1 Providers

A provider entry under its own name is the whole switch: configure one and
`GET <apiPrefix>/oauth/<name>` starts a flow, configure none and every provider
answers the reference's `404 {"error":"<Provider> OAuth not configured"}`.

**`google` and `github` are the reference's two hard-coded strategies** and
arrive as presets: the endpoints, the scopes and Google's `access_type=offline`
come from the imported core, and a document that tries to point either of them
at another authorization server is refused by name. Three fields are still
yours, because none of them is an endpoint: `scope` (a deployment that needs one
more consent scope should not have to fork a provider), `additionalAuthParams`
(layered over the preset, so an entry replaces the preset's key of the same
name) and `profileMap`.

**Any other name is a generic OIDC/OAuth2 provider** and must bring
`authorizationUrl`, `tokenUrl` and `userInfoUrl`. They must be `https`, with one
carve-out: **outside production**, a loopback host (`127.0.0.1`, `::1`,
`localhost`) may use plain `http`, because such a request never leaves the
machine and an identity provider running beside the process has no name to hold
a certificate for. That is the carve-out RFC 8252 §8.3 makes for the same
reason. It stops at `deployment.environment: production`, where the premise
fails: nothing can run beside a Lambda, and `127.0.0.1` there is the runtime
API — so a production document pointing `tokenUrl` at loopback would POST the
client secret to the execution environment's own control plane, and is refused.

`clientSecret` is a secret-tagged knob like the signing secrets: a
`{"secretsManager": …}` / `{"ssmParameter": …}` reference in the document, or
`AWESOME_AUTH_OAUTH_<NAME>_CLIENT_SECRET` (development) — never a value in the
document.

`callbackUrl` is what the provider redirects back to, and it must be the URL you
registered with that provider. The SAM template derives it —
`<PublicUrl><ApiPrefix>/oauth/<provider>/callback` — and refuses a provider with
no `PublicUrl` to derive it from.

**A provider needs `stores.enable.linkedAccounts`, and it is not on by default.**
The linked-accounts store is where a provider identity is bound to an account,
and the core's callback refuses before it does anything without it: the
authorization redirect still goes out, the person still consents, and the
callback answers `501 {"error":"Feature not supported by the configured stores",
"code":"NOT_IMPLEMENTED"}`. A half-wired login nobody is told about is exactly
what `RS-11` exists to prevent, so **a configured provider with the store off
refuses to start**, naming `stores.enable.linkedAccounts`. The SAM template sets
`AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS=true` whenever a provider parameter
is set, so a stack deployed from it never meets this; a document-configured
deployment has to say so itself:

```json
{"stores": {"enable": {"linkedAccounts": true, "pendingLinks": true}}}
```

`pendingLinks` in that snippet is the second store and a separate decision:
§8.2 covers what `onEmailMatch: conflict` needs it for, and §8.3 what the state
nonce uses it for.

`projectId` is accepted because the reference carries it and nothing reads it;
it is reported at cold start as a knob this build cannot honour, the same way
the mailer's endpoint is.

**`profileMap`** replaces the reference's `mapProfile` function with
expressions, and is what makes a provider whose userinfo document is not
OIDC-shaped configurable rather than code. The keys are `id` (required),
`email`, `emailVerified`, `name` and `picture`; a value is a `??` chain of
`$.path` segments with an optional quoted literal last, evaluated like
JavaScript's `??` — the first alternative that resolves to something other than
missing or null wins:

```json
{"oauth": {"providers": {"contoso": {
  "clientId": "…",
  "clientSecret": {"secretsManager": "awesome-auth/prod/contoso"},
  "callbackUrl": "https://auth.example.com/auth/oauth/contoso/callback",
  "authorizationUrl": "https://login.contoso.example/oauth2/v2.0/authorize",
  "tokenUrl": "https://login.contoso.example/oauth2/v2.0/token",
  "userInfoUrl": "https://graph.contoso.example/v1.0/me",
  "scope": "openid email profile",
  "profileMap": {
    "id": "$.id",
    "email": "$.mail ?? $.userPrincipalName",
    "name": "$.displayName"
  }}}}}
```

An expression that does not compile **refuses the cold start**, naming the
provider and the field, rather than producing a provider that 500s on its first
callback.

### 8.2 The provisioning policy

The reference has no policy: `findOrCreateUser` is abstract and every integrator
writes the function (`generic-oauth.strategy.ts:169-172`). A deployable product
cannot ask for a function, so the policy is declared. The defaults reproduce
what a permissive `findOrCreateUser` does — create missing accounts, link a
matching address — so a deployment that configures only a provider behaves the
way the family's demos do.

| Knob | What it decides |
|---|---|
| `autoCreate` | May the callback create an account for a provider identity nothing here knows yet? With `false`, the answer is `403 OAUTH_USER_NOT_PROVISIONED` and accounts come from `/register`, an invitation or an admin. |
| `onEmailMatch` | The provider account is unknown, but some account already holds the address it asserts. `link` signs that account in and records the binding; `conflict` raises the reference's `OAUTH_ACCOUNT_CONFLICT` — a 302 to `/account-conflict` where the front end drives `/link-request` and `/link-verify`, so the link is made only after an emailed token proves the address; `reject` refuses outright. **`conflict` needs `stores.enable.pendingLinks`** — see below. |
| `requireVerifiedEmail` | Refuse a profile whose `emailVerified` is not positively true (`403 OAUTH_EMAIL_NOT_VERIFIED`). Most providers send no claim at all, so turning this on for one of them refuses every login through it. |
| `allowedEmailDomains` | Bare domains, matched case-insensitively on the part after the last `@`, with no subdomain matching. Empty admits every address; non-empty refuses a profile with no address at all. |
| `fieldMap` | Fills `firstName`, `lastName`, `phoneNumber` and `role` on an account the callback **creates**, with `profileMap` expressions over the same userinfo document. A key outside that list, or a value that does not compile, refuses the cold start. |

**`onEmailMatch` is a knob rather than a constant on purpose.** Linking by
address is the account-takeover shape the reference's own store interface warns
about — two providers can assert one address without representing one person —
and the imported core's default is to link. Hardcoding either answer would put a
security posture in a binary where no operator can see it;
[`docs/spec/decisions.md`](spec/decisions.md) D-20 argues the default.

**`conflict` is the one mode with a store dependency.** Its entire answer to a
conflict is to *stash* it — address, provider, provider account id — so that the
`/link-request` the front end makes next can resolve who is being linked to
what. That stash lives in `stores.enable.pendingLinks`, which is off by default
(only `users`, `sessions` and `tokens` are on). With the store off the core
skips the stash silently: the browser is still sent to
`/account-conflict?provider=…&code=OAUTH_ACCOUNT_CONFLICT&email=…`, and
`/link-request` then has nothing to identify. So **`onEmailMatch: conflict` with
`stores.enable.pendingLinks` off refuses to start** (`RS-11`), naming the mode
and pointing at the store. `link` and `reject` have no such dependency — but see
§8.3 for the other thing that store buys.

### 8.3 Redirects, and the one rule that refuses to start

Where the callback sends the browser is decided by the same two values every
emailed link is built from (§5.1): the canonical site, and the allowlist
`email.siteUrls` ∪ `http.cors.origins`. The flow carries the origin it started
from inside a signed `state`, and the callback honours it only if it is still
allowlisted; anything else falls back to the canonical site.

**A configured provider with an empty allowlist refuses to start** (rule
`RS-11`). The callback answers with a fresh session in a `Set-Cookie`, so where
it sends the browser is a credential-bearing redirect, and with nothing
allowlisted the reference honours whatever origin the state names
(`docs/spec/reference-issues.md` N1). The core signs its states, which is why it
can reproduce that behaviour safely for an embedder; a deployment also has to
survive the day the signing secret is what went wrong, and an allowlist is the
defence that does not depend on the signature holding.

**The state's other defence is a store key.** `stores.enable.pendingLinks` is
also where the flow records the state's nonce on the way out and consumes it on
the way back, which is what makes a state single-use rather than replayable for
the whole of its TTL. With the key off — the default — the core skips both
halves and falls back to the reference's behaviour: signed and time-bounded,
replayable in between. That is not refused, because it is not a broken
deployment; it is reported at every cold start on the `configured knob is not
wired to the auth core` line (§2), with the path and the remedy. Turn it on and
the nonce becomes single-use.

### 8.4 What the callback does not do yet

The reference's callback is 2FA-aware: an account with a second factor is
redirected to `${redirectTo}/auth/2fa?tempToken=…&methods=…` instead of being
handed a session (`auth.router.ts:1298-1313`). The imported core has no such
branch — it issues a session for every account it resolves — and this product
does not fork the core, so **a federated login skips the second factor a
password login demands**. A deployment that requires 2FA and also configures an
OAuth provider should know that before it turns one on.

It is not silent. It is registered as the product deviation
`oauth-callback-skips-the-second-factor`, so every cold start announces it
([`docs/deviations.md`](deviations.md)), and `cmd/auth/oauth_test.go` pins both
halves — that `POST /login` on such an account does answer the challenge, and
that the callback does not — so the test fails the day upstream grows the
branch, which is the signal to delete this paragraph and the register entry.

## 9. `idProvider.*`, knob by knob

Identity-provider mode makes the deployment an OIDC issuer. The full surface —
what it serves, what it deliberately does not do, and how a key is rotated — is
[docs/oidc.md](oidc.md); this section is the knobs.

| Path | Type | Default | Env var |
|---|---|---|---|
| `idProvider.enabled` | boolean | `false` | `AWESOME_AUTH_IDP_ENABLED` |
| `idProvider.kmsKeyId` | string | none | `AWESOME_AUTH_IDP_KMS_KEY_ID` |
| `idProvider.kmsPreviousKeyIds` | string[] | none | `AWESOME_AUTH_IDP_KMS_PREVIOUS_KEY_IDS` |
| `idProvider.privateKey` | secret (PEM) | none | `AWESOME_AUTH_IDP_PRIVATE_KEY` |
| `idProvider.issuer` | string (https) | `deployment.publicUrl` + `http.apiPrefix` | `AWESOME_AUTH_IDP_ISSUER` |
| `idProvider.jwksPath` | absolute path | `/.well-known/jwks.json` | `AWESOME_AUTH_IDP_JWKS_PATH` |
| `idProvider.jwksCorsOrigins` | string \| string[] | `"*"` | `AWESOME_AUTH_IDP_JWKS_CORS_ORIGINS` |
| `idProvider.clients[]` | object[] | none | — (file-only) |
| `idProvider.accessTokenTtl` | ms-syntax | `30d` | reported as unwired, see below |
| `idProvider.refreshTokenTtl` | ms-syntax | `90d` | reported as unwired, see below |
| `idProvider.publicKey` | PEM | none | reported as unwired, see below |

**The switch is the same one the reference uses.** Mode is on when `enabled` is
true *or* key material is present, so a document that names a key and forgets the
flag does not come up with the IdP silently off. `kmsKeyId` counts as key
material for the same reason `privateKey` does.

### 9.1 The signing key: `kmsKeyId` or `privateKey`, never both

Rule RS-4 refuses a deployment that sets both, in every environment — nothing
would decide which key signs, and the `kid` in a token, the key in the JWKS
document and the key that actually signed could all disagree. In production it
refuses a deployment that sets neither; in development the core generates an
ephemeral key and the cold-start log says what that costs (every token becomes
unverifiable at the next cold start).

`kmsKeyId` is the production path, and the reason is not ceremony: a PEM is a
value the function reads and holds, so anything that can make it emit a string
takes the issuer's identity with it. A KMS key cannot be exported — the function
holds `kms:Sign` on one ARN, `kms:GetPublicKey` on that one and on the keys being
retired (§9.2), and nothing else at all. The SAM template creates one and
scopes the policy to it; the key costs **USD 1.00 per month**, plus about USD
3.00 per million tokens signed.

Identity-provider mode and `resourceServer.enabled` are mutually exclusive (§10).

### 9.2 `kmsPreviousKeyIds` — rotating without a flag day

Keys listed here sign nothing and are published in the JWKS document after the
current one, so a token minted before a rotation keeps verifying until it
expires. The `kid` is derived from the key material rather than being the
reference's fixed constant, which is what makes the whole rotation additive; the
procedure is [oidc.md](oidc.md) §3, and the divergence is registered as
`idp-kid-derived-from-key-material`.

Each id here is read with `kms:GetPublicKey` at cold start, so the function's
policy has to cover it: an ARN listed but not granted fails the init naming
`idProvider.kmsPreviousKeyIds`, rather than serving an incomplete document. On
the SAM stack, one parameter does both halves (`IdpPreviousKmsKeyArns`).

### 9.3 `idProvider.clients[]` — the relying parties

File-only: a client is an array of objects and no environment variable expresses
one.

```json
{"idProvider": {
  "enabled": true,
  "kmsKeyId": "arn:aws:kms:eu-west-1:000000000000:key/11111111-2222-3333-4444-555555555555",
  "clients": [{
    "clientId": "console",
    "name": "Ops console",
    "clientSecret": {"secretsManager": "awesome-auth/prod/idp-console"},
    "redirectUris": ["https://console.example.com/callback"]
  }]
}}
```

Each client's secret is an ordinary secret knob keyed by **client id**, not by
position: `AWESOME_AUTH_IDP_CLIENT_CONSOLE_SECRET`, or its `_SECRETSMANAGER`
form. Inserting a client at the top of the list therefore does not move any other
client's variable.

Refused at start: a client with no secret, a client with no redirect URI, a
duplicate client id, and a redirect URI that is neither https nor http on a
loopback host. [oidc.md](oidc.md) §5 says what each of those would otherwise
break. No clients at all is a **warning**, not a refusal — publishing a signing
key and nothing else is exactly what the reference's `idProvider` block is for.

### 9.4 The three knobs that are reported rather than honoured

`idProvider.accessTokenTtl` and `idProvider.refreshTokenTtl` govern the RS256
token pair `auth.IssueIdPTokenPair` mints, and no mounted route calls it — the
OIDC token endpoint returns the HS256 session pair, which is decision D-3 and the
reference's own posture. Set `security.jwt.accessTokenTtl` instead; that is the
lifetime `/token` reports as `expires_in` and the one the token really has.
`idProvider.publicKey` is never read because the JWKS document is built from the
signing key's own public half. All three are named, with their paths, in the
cold-start log.

## 10. `resourceServer.*`, knob by knob

The mirror image: this deployment mints nothing and verifies tokens another
issuer signed.

| Path | Type | Default | Env var |
|---|---|---|---|
| `resourceServer.enabled` | boolean | `false` | `AWESOME_AUTH_RS_ENABLED` |
| `resourceServer.jwksUrl` | string (https) | none; **required** when enabled (RS-8) | `AWESOME_AUTH_RS_JWKS_URL` |
| `resourceServer.issuer` | string | none; unset means `iss` is not checked | `AWESOME_AUTH_RS_ISSUER` |
| `resourceServer.jwksCacheTtlMs` | integer > 0 | `3600000` | `AWESOME_AUTH_RS_JWKS_CACHE_TTL_MS` |
| `resourceServer.jwksFetchTimeoutMs` | integer > 0 | `5000` | `AWESOME_AUTH_RS_JWKS_FETCH_TIMEOUT_MS` |

**Turning it on unmounts the credential surface.** All nineteen routes that
create, prove, deliver or change a credential — `/register` and `/login` among
them — answer 404. Do not turn it on for a stack that is supposed to log people
in.

**Not together with identity-provider mode.** Both on is refused at cold start by
rule `IDENTITY`, naming `resourceServer.enabled` and the three knobs that make
the IdP active. The identity provider mounts `POST <prefix>/authorize`, which
takes an email and a password, so the combination would serve a credential route
from a deployment whose configuration says it has none. To publish a signing key
without logging anyone in, run the identity provider with no clients (§9.3).

**The verifier guards your routes, not these** — and in this artifact, nothing.
It is built at cold start with the cache and timeout above and exposed as
`App.ResourceServerGuard`, and the auth routes that remain keep verifying this
instance's own HS256 session, because the commonest resource-server deployment is
the hybrid that needs exactly that. `cmd/auth` mounts the guard on nothing: every
route it serves is the imported adapter's, and there is no second binary and no
SAM wiring that consults it. So on a deployed stack this knob removes nineteen
routes and adds no verification; the export is for a host that embeds this
package, and the cold-start log line says exactly that. [oidc.md](oidc.md) §4 has
the reasoning.

**`security.jwt.accessTokenSecret` is still required**, even though RS-1 exempts
it here: the auth core needs one to build, and the verifier's cookie path reads
it. The cold start refuses by name rather than letting the core complain about a
knob you were told to leave out.

## 11. `runtimeSettings.*`, knob by knob

The one block of this document that an administrator changes without a
deployment. Everything else here is fixed at cold start; these three keys are
seeds for a store the admin surface patches at run time.

| Path | Type | Default | Env var |
|---|---|---|---|
| `runtimeSettings.require2fa` | boolean | `false` | `AWESOME_AUTH_RUNTIME_SETTINGS_REQUIRE_2FA` |
| `runtimeSettings.enabledWebhookActions` | string[] | none (absent, which is not the same as `[]`) | `AWESOME_AUTH_RUNTIME_SETTINGS_ENABLED_WEBHOOK_ACTIONS` |
| `runtimeSettings.lazyEmailVerificationGracePeriodDays` | integer | `7` | `AWESOME_AUTH_RUNTIME_SETTINGS_LAZY_EMAIL_VERIFICATION_GRACE_PERIOD_DAYS` |

Any of them needs `stores.enable.settings`, and a document that declares one
without it is refused by name (rule `STORE_REQUIRED`). Both drivers back the
store: the DynamoDB one keeps it as a single item on its own `SETTINGS`
partition ([data-model.md](spec/data-model.md) §1.8), the memory driver holds it
per execution environment — which for this block is worse than for the others,
since an administrator's toggle is then invisible to every other environment and
gone on the next cold start. RS-12 already refuses the memory driver in
production.

The store may also be switched on with no `runtimeSettings` block at all. That
is a normal deployment: the settings start empty and the admin surface fills
them.

### 11.1 The seed is a seed, and the store wins forever after

The document is applied **once per key, and only to keys the store does not
already hold**. A value an administrator saves through the admin surface is
never overwritten by a redeploy — not on the next cold start, and not on any
later one. Registered as the deviation
`runtime-settings-seed-only-fills-absent-keys` ([deviations.md](deviations.md)),
the sibling of `templates-dir-only-seeds-absent-ids`.

Two consequences worth knowing before you write the block.

**Changing a seeded value in the document does nothing.** Once the key is in the
store, the document has no further say. Change it through the admin surface, or
delete the key from the store.

**A key left at its default is not seeded**, and that is what keeps the block
usable over time: adding `require2fa: true` to a document months from now is
applied on the next cold start, because nothing ever wrote that key. Had the
schema's own `false` been seeded on day one, the later declaration would have
arrived inert. "Declared" therefore means *moved off the default*, which is the
same test that decides whether the block requires the store.

A corollary for `enabledWebhookActions`: **absent and `[]` are different
declarations.** Absent says nothing and seeds nothing; `[]` is the administrator
switching every inbound-webhook action off, and it is seeded, stored and served
as an explicit empty list. The core carries a custom encoder to keep that
difference alive, and so does the store.

### 11.2 What this build actually reads

One key, on one route. `require2fa` is consulted by
`POST <prefix>/2fa/disable`, which answers `403` `2FA_REQUIRED` when it is true —
the reference's behaviour at `auth.router.ts:890-896`. It is a *system policy*
term, so it refuses the disable regardless of whether that account has a second
factor enabled.

The other two are stored and handed back, and nothing in this build acts on
them. Both are named, with their paths, in the cold-start log:

- `enabledWebhookActions` is the global allowlist the inbound-webhook sandbox
  intersects with each webhook's own `allowedActions`. No tools router is
  mounted here yet (P7), so the list is stored and read by nothing.
- `lazyEmailVerificationGracePeriodDays` is read by nothing **here or in the
  reference**: the reference's admin UI displays it and its server never computes
  a verification deadline from it ([config-schema.md](spec/config-schema.md)
  §1.19 `[MISMATCH]`), and the imported core stores it and hands it back
  unchanged. Seed it if you want the admin surface to show a declared value; do
  not expect a login to be refused on it.

Leave both set if the same document is deployed to another port in the family —
nothing in this build reads them, and both become live here without the document
changing.

**Two keys the reference's settings store has and this block does not.**
`requireEmailVerification` and `emailVerificationMode` are storable through the
admin surface and are §1.19's other `[MISMATCH]` row: no login path reads them,
in the reference or here. The knob that does decide a login on this deployment is
`email.verification.mode` (§5), and it is deliberately not copied into the
settings store — a second place for the same non-effect to be discovered from is
worse than none. The branding keys under `ui.*` belong to the settings store too
and arrive with the hosted UI.

## 12. `docs.*`, knob by knob

The two documentation routes: `GET <prefix>/openapi.json`, the generated OpenAPI
document, and `GET <prefix>/docs`, the Swagger UI page that reads it. Both come
from the imported adapter — nothing in this binary mounts a route under the api
prefix — and both are unguarded, exactly as the reference registers them
(`src/router/auth.router.ts:1651-1677`).

| Path | Type | Default | Env var |
|---|---|---|---|
| `docs.swagger` | `true` \| `false` \| `auto` | `auto` | `AWESOME_AUTH_DOCS_SWAGGER` |
| `docs.basePath` | absolute path | `http.apiPrefix` (so `/auth` unless you moved it) | `AWESOME_AUTH_DOCS_BASE_PATH` |

### 12.1 What `auto` resolves to

`auto` is **on outside production and off in it**, resolved against
`deployment.environment`:

| `docs.swagger` | `deployment.environment` | Both routes |
|---|---|---|
| `true` | anything | mounted |
| `false` | anything | 404 |
| `auto` | `development` | mounted |
| `auto` | `production` | 404 |

That reproduces the reference's `swagger === true || (swagger !== false &&
NODE_ENV !== 'production')` (`src/router/auth.router.ts:1652-1654`) with one
substitution: a configuration knob in place of a process variable. The
substitution is not this product's idea — the imported core takes a plain
boolean and says why, that a library whose routes appear and disappear with a
variable it never sees configured is one nobody can reason about from its own
configuration — so resolving `auto` is the host's job, and `cmd/auth/docs.go` is
where it happens.

**The consequence is that a deployment which says nothing gets neither route.**
`auto` is the default here and `production` is the default environment, so
silence is 404 on both; the reference reads an unset `NODE_ENV` as "not
production" and serves both. That is the `production-by-default` deviation
([deviations.md](deviations.md)), whose text names swagger as one of the three
things the default tightens. Say `deployment.environment: development` and the
routes appear.

The cold-start log says which way it went, on every start: `documentation routes
mounted` with both paths, or `documentation routes not mounted` with the knob and
the environment that decided it.

### 12.2 `docs.basePath` moves the description, never the mount

It is the reference's `swaggerBasePath` (`src/router/auth.router.ts:133-139`,
read at `:1657`) and the core's `DocsOptions.BasePath`, and all three mean one
thing: the base the served document writes its path items under, and the base of
the spec URL the Swagger page fetches. **The two routes are always served under
`http.apiPrefix`.** The reference's own doc comment — "Base path where the auth
router is mounted" — is the misleading one; nothing mounts anything from this
value, there or here.

Unset, it is the resolved `http.apiPrefix`, so the document describes the paths
this deployment actually answers and no one has to think about it. Set it only
when a reverse proxy makes this stack reachable from outside under some other
path, so that a reader who fetches what the document names gets a real response.
Set it to anything else and the deployment publishes a document describing paths
it does not serve — which is why a base path that differs from the mount is
called out by name in the cold-start log rather than quietly honoured.

### 12.3 The page puts a third-party script on the auth origin

The Swagger page is the reference's, reproduced byte for byte by the core, and
it loads `swagger-ui-dist@5` from the **unpkg CDN with no subresource
integrity** (`src/router/openapi.ts:1646-1669`). Whatever unpkg serves then
executes same-origin with this deployment's cookies — the CSRF cookie included,
which is readable from JavaScript by design, because the double-submit pattern
requires the client to read it. A bad day at that CDN is a credential-reading
script on your auth origin.

**This is not a refuse-to-start rule, and that is a decision.** The core's
`DocsOptions.Enabled` is one switch for the page *and* for the machine-readable
document; every adapter mounts both under it; this binary may add no route under
the api prefix and does not fork the core. So a refusal aimed at the page would
take the document with it and refuse a production deployment for wanting the one
artefact in the pair that carries no script at all — leaving one move, turning
both off, which is the state the operator was trying to leave. The house rule
that "forgetting to name the environment should tighten, not loosen" is already
satisfied by §12.1: reaching this takes two deliberate statements,
`docs.swagger: "true"` and `deployment.environment: "production"`, in one
document. The fix that would let the product be stricter is upstream's — a
spec-only mode, or a page served from assets the library vendors — and it is
recorded as an upstream ask rather than worked around here.

**What the deployment does instead**, in three parts:

- **It warns at deploy time.** `docs.swagger: true` in production raises a
  configuration warning naming the CDN and the cookie it can read. It is a
  warning and not a log line so that the deployment tooling, which reads
  `Config.Warnings()` before an upload, shows it before the stack has it.
- **It sends a `Content-Security-Policy`** on both documentation responses,
  together with `X-Content-Type-Options: nosniff` and `Referrer-Policy:
  no-referrer`. The page's policy allows the one CDN origin its own HTML names
  and denies everything else: no `fetch` or XHR off this origin, no image
  beacon, no form action, no nested frame, no rewritten `<base>`, and no framing
  of the page itself. The document's is `default-src 'none'` with the same two
  denials. Registered as the deviation
  `docs-page-carries-a-content-security-policy` ([deviations.md](deviations.md)),
  since the reference sends no header of the kind.
- **It keeps the two routes together.** The served document describes both paths,
  so a deployment answering one and 404ing the other would publish a document
  that lies about its own surface.

**Be clear about what the policy buys.** It narrows the hazard; it does not
close it. A compromised bundle still executes same-origin, can still read
`document.cookie`, and can still put what it read into a top-level navigation,
which no CSP directive in any shipping browser prevents. What goes are the quiet
channels. If that is not good enough for your deployment — and on anything
facing the internet it should not be — the answer is `docs.swagger: false`, or
`auto` with `deployment.environment: production`, and reading the document from
a checkout instead.
## 13. `stores.migration.*` — where your users are coming from

The one block in this schema with no counterpart anywhere in the reference: the
reference is a library mounted in front of a store somebody already populated,
and a deployable product has to answer the question of how the users got there.
With the block unset — the default — nothing here is constructed and every route
answers exactly what it answered before the block existed.

| Path | Type | Default | Env var |
|---|---|---|---|
| `stores.migration.source` | `cognito` | none — **empty is the off switch** | `AWESOME_AUTH_STORES_MIGRATION_SOURCE` |
| `stores.migration.userPoolId` | string | none; **required** with a source (RS-13) | `AWESOME_AUTH_STORES_MIGRATION_USER_POOL_ID` |
| `stores.migration.region` | string | none; **required** with a pool id (RS-13) | `AWESOME_AUTH_STORES_MIGRATION_REGION` |
| `stores.migration.clientId` | string | none — no client id, no login-path dependency | `AWESOME_AUTH_STORES_MIGRATION_CLIENT_ID` |
| `stores.migration.mode` | `import-only`\|`dual-read` | `import-only` | `AWESOME_AUTH_STORES_MIGRATION_MODE` |

**`source` is the switch, and nothing else is.** A pool id, an app client or a
mode written without one is refused (`RS-13`), because a block that reads as
configured and does nothing is the shape of an operator who turned the migration
off by deleting the wrong line.

**`region` is not inherited** from `stores.connection.region`. The commonest
migration is out of a pool in another region or another account, and a pool
addressed in the wrong region answers "no such user" for every single person —
indistinguishable from an empty pool. It is demanded rather than guessed.

**`clientId` is the second switch, and the one you clear first.** It names an
app client in the pool, and it is what makes just-in-time password migration
possible: `AdminInitiateAuth` is a client-scoped call. The app client must allow
`ADMIN_USER_PASSWORD_AUTH` and must have **no client secret** — one with a secret
needs a `SECRET_HASH` this product does not compute, and the failure is reported
by name in the log rather than as "wrong password" on every login. With the
client id empty the deployment still imports and still dual-reads; it simply
never calls the pool from a login. That is the posture of a stack whose bulk
import has finished.

**`mode: dual-read` costs one `AdminGetUser` per lookup miss**, on
unauthenticated routes, and is bounded per address and globally by a token
bucket per execution environment. Use it while the bulk import is incomplete and
turn it back to `import-only` afterwards.
[cognito-migration.md](cognito-migration.md) §4 has the numbers and the
reasoning.

**Only the `dynamodb` driver.** The migration marker is a profile attribute, and
there is nowhere else in this build it survives a cold start; `RS-13` refuses any
other driver rather than letting a memory-backed stack re-provision the same
person from Cognito on every execution environment, forever, on an
unauthenticated route.

**Nothing about the migration reaches the wire.** The marker is store-private: it
never enters `auth.User`, so `GET <prefix>/me` cannot disclose it, and no
deviation is registered for it. The one thing a migrated account does carry in
its `metadata` is `imported` — the source attributes the import mapped there,
which is your data and is opt-out per attribute in the map (§3 of the runbook).
[cognito-comparison.md](cognito-comparison.md) §5 has the detail.

The bulk import is `cmd/migrate`, an operator command and not part of the
deployed artifact. The whole procedure, including what happens on a user that
already exists, a paging failure halfway through and a record with no email, is
[cognito-migration.md](cognito-migration.md).

```json
{
  "stores": {
    "driver": "dynamodb",
    "connection": {"tableName": "awesome-auth", "region": "eu-west-1"},
    "enable": {"users": true, "sessions": true, "tokens": true},
    "migration": {
      "source": "cognito",
      "userPoolId": "<region>_XXXXXXXXX",
      "region": "<pool region>",
      "clientId": "<an app client with no secret>",
      "mode": "dual-read"
    }
  }
}
```

## 14. `rateLimit.*`, knob by knob

The built-in rate limiter. It is **net-new to this product**: the reference has
no rate limiting at all — `RouterOptions.rateLimiter`
(`src/router/auth.router.ts:46`) is an empty slot for a host-supplied Express
middleware, and absent it the router collapses the slot to an empty list
(`rl = []`, `:468`) and ships no algorithm. So there is no upstream default to
inherit, every value below is a product decision, and this section is where each
one is argued rather than merely stated.

| Path | Type | Default | Env var |
|---|---|---|---|
| `rateLimit.enabled` | boolean | `true` | `AWESOME_AUTH_RATE_LIMIT_ENABLED` |
| `rateLimit.windowSeconds` | integer > 0 | `60` | `AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS` |
| `rateLimit.max` | integer > 0 | `10` | `AWESOME_AUTH_RATE_LIMIT_MAX` |
| `rateLimit.keyBy` | `ip` \| `email` | `email` | `AWESOME_AUTH_RATE_LIMIT_KEY_BY` |
| `rateLimit.scope` | endpoint names | `login, forgot-password, magic-link, sms-code, 2fa-verify` | `AWESOME_AUTH_RATE_LIMIT_SCOPE` (comma-separated) |

**A deployment that says nothing is rate limited**, and that is the whole point
of the default. It is the same house rule `csrf-enabled-by-default` and
`production-by-default` state: a library can leave the choice to whoever embeds
it, a product has to be safe with an empty configuration, and an auth stack that
ships with unlimited login attempts is one that gets credential-stuffed. The
`429` that follows is the registered wire deviation
`rate-limited-routes-answer-429` ([deviations.md](deviations.md)), because it is
a refusal the reference never makes. Set `rateLimit.enabled: false` and you have
the reference's behaviour exactly.

### 14.1 What `scope` names, and which routes each name covers

A scope name is a flow, not a path, because several flows are two routes and an
operator who wants one almost never wants only one half. `internal/config`
validates the vocabulary; `cmd/auth/ratelimit.go` holds the table below, and
`TestEveryScopeNameMapsToRoutes` fails if the two ever disagree.

| Name | Routes | Subject under `keyBy: email` |
|---|---|---|
| `login` | `POST <prefix>/login` | body `email` |
| `register` | `POST <prefix>/register` | body `email` |
| `forgot-password` | `POST <prefix>/forgot-password` | body `email` |
| `magic-link` | `POST <prefix>/magic-link/send`, `POST <prefix>/magic-link/verify` | body `email`, else `sha256(tempToken)`, else the client address |
| `sms-code` | `POST <prefix>/sms/send`, `POST <prefix>/sms/verify` | body `email` or `userId`, else `sha256(tempToken)`, else the client address |
| `2fa-verify` | `POST <prefix>/2fa/verify` | `sha256(tempToken)`, else the client address |
| `refresh` | `POST <prefix>/refresh` | the client address |
| `reset-password` | `POST <prefix>/reset-password` | the client address |
| `verify-email` | `GET <prefix>/verify-email` | the client address |
| `resend-verification` | `POST <prefix>/send-verification-email` | the client address |

The default scope is the five flows `docs/spec/data-model.md` §1.5 row #61 names
— the ones where a guess costs an attacker nothing and where there is no session
to lose. The other five are nameable and deliberately off: `refresh` and
`verify-email` are spent by a client holding a token it was given, and limiting
them by default would throttle ordinary use of a working deployment to defend
against guessing a 256-bit value.

**Nothing here mounts a route.** The limiter is a middleware over the whole mux
that matches on the resolved `http.apiPrefix` plus a path suffix, so moving the
prefix moves the limiter with it and the adapter still owns every path under it.

### 14.2 `keyBy`, and why the default is not `ip`

`keyBy: email` makes the budget **per account**. `keyBy: ip` makes it **per
source address**, on every route.

The default is `email`, and the argument is about who gets hurt when the limiter
fires:

* The threat these routes face is credential stuffing and password spraying
  against accounts. That is account-shaped, and an account-keyed counter hits it
  exactly: ten attempts a minute against one address is invisible to a real
  person and is six seconds per guess to an attacker.
* An address-keyed default punishes the wrong people. A corporate NAT or a mobile
  carrier's egress is one address for thousands of users, so one abuser behind it
  spends everybody's budget — and, because the counter is one DynamoDB partition
  key capped at 1 000 WCU, it also concentrates the writes
  (`docs/spec/data-model.md` §2.3, whose own conclusion is that per-IP windows
  must be short and the account-scoped limiter must be the primary control).
* Volumetric defence by source address is a real need and belongs at the edge,
  where a WAF or CloudFront can do it with the whole request rate in view. Doing
  it here would be a worse copy of it, one DynamoDB write at a time.

What `keyBy: email` does **not** do is bound an attacker who names a million
different addresses; each gets its own budget. That is the known limit of
account-keyed limiting, it is the layer above's job, and it is the reason
`keyBy: ip` exists as a choice rather than being removed.

**The subject never comes from a header.** It is the source address the Lambda
event reported, not `X-Forwarded-For`, which the client writes: a limiter whose
subject the caller chooses hands out a fresh budget with every request and is not
a limiter at all.

#### When `keyBy: email` meets a route with no email

Three of the ten scopes carry no address in the body, and `POST /2fa/verify`
carries no identity at all. Each route declares an ordered chain (the table in
§14.1) and every chain ends at the client address. Two alternatives were
rejected: one shared sentinel subject would put every such request in the
deployment into a single budget and a single partition — a self-inflicted outage
an attacker triggers by sending an empty body — and skipping the limiter would
leave a six-digit TOTP code unlimited, which is the single route a limiter is
most obviously for.

Where a `tempToken` is present it is preferred over the address, because it names
the challenge: an attacker brute-forcing the six digits holds one token and
presents it with every guess, so the counter is exactly per challenge, and one
who rotates tokens has to log in again for each, which `login` limits. It is
hashed because it is a bearer credential and must not become a partition key in
the clear. Nothing in the chain verifies anything or reads a store — a hash is
not a check — so a refusal still costs nothing downstream.

### 14.3 What a refused request looks like

Byte for byte:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 43
Content-Type: application/json
Cache-Control: no-store

{"error":"Too many requests","code":"RATE_LIMITED"}
```

`Retry-After` is delta-seconds (RFC 9110 §10.2.3), rounded up and never below 1,
and is the time left in the current window.

**No `Set-Cookie`, not even the CSRF one.** The limiter is the outermost
middleware — `RateLimiter`, then CSRF, then the auth middleware, which is the
order the reference uses and the core's adapters reproduce — so a refused request
reaches nothing that verifies a token, reads a store, compares a CSRF value or
distributes the auto-init cookie. A client whose very first request is refused
therefore has no `csrf-token` cookie yet. That is correct rather than an
oversight: a refused request is one the deployment did no work for.

**No `RateLimit-Limit`, `RateLimit-Remaining` or `RateLimit-Reset`**, on the
refusal or on a successful response. The obvious objection to those headers — that
they tell an attacker the limit — is weak on its own, since anyone willing to
spend requests finds the limit by reaching it. The decisive one is
`RateLimit-Remaining` on a **successful** response under an account-keyed
counter: it would be an oracle about somebody else's traffic, letting anyone who
can name `victim@example.com` read from a `200` whether that person has been
logging in. The headers would add a side channel the `429` does not have, in
exchange for something `Retry-After` already gives.

### 14.4 The window is fixed, and what that costs

The counter is a fixed window: the window index is part of the item's key, so
each window is a new item that starts at zero and there is nothing to reset.
Windows are aligned to the Unix epoch, not to a subject's first request.

**The boundary is a seam.** A subject can spend its whole budget in the last
instant of one window and its whole budget again in the first instant of the
next, so the true worst case over any sliding window of the same length is
**twice `max`** — 20 per minute on the defaults, not 10. This is accepted, not
overlooked. Closing it means a sliding window or a token bucket, which needs the
request history or a timestamp plus a fractional balance, which means a
read-modify-write on the login path forever; and a factor of two does not change
what a 10-per-minute limit does to a credential stuffing run. Size `max` for the
bound you want doubled.

The other consequence of a fixed window is the ceiling on a false positive: a
legitimate user who trips the limiter waits at most `windowSeconds`. That is why
60 is the default — long enough to be a real bound, short enough that being wrong
about someone costs them a minute.

### 14.5 What it costs per request, and what happens when the store is down

The limit lives in DynamoDB, in the same table as everything else
(`docs/spec/data-model.md` §1.5 row #61). One limited request is **one
conditional `UpdateItem`, so 1 WCU** — and that is true of a refused request too,
because DynamoDB bills a conditional write whose condition fails. Unlimited
routes cost nothing at all; the limiter does not look at them beyond a map
lookup.

Two things reduce that. A refused request does not increment the counter, so the
stored number is bounded by `max` however long a flood lasts. And each execution
environment keeps a small in-process pre-filter holding the same budget over the
same window, so once an environment has watched a subject exhaust its budget it
refuses locally and writes nothing — under a sustained flood only the first `max`
requests per environment per window cost a write.

**The in-process tier is a pre-filter, never the limit.** A Lambda execution
environment serves one request at a time and AWS runs as many as the arrival rate
demands, so an in-process counter alone would limit each environment separately
and the real ceiling would be `max` times a concurrency nobody chose. The shared
counter is the limit; the local tier only ever refuses what the shared counter
would have refused, because both hold the same budget over the same
epoch-aligned window.

**When the shared counter is unreachable, the limiter allows the request.** It
fails open, deliberately. The counter is in the same table as the user store, so
on this product "the limiter cannot count" and "the route cannot serve" are the
same event: every route in the default scope reads or writes that table
immediately after the limiter. Failing closed would refuse requests that were
going to fail anyway, turn a partial DynamoDB degradation into a total outage on
exactly the routes people need during one, and replace a `500` naming the store
with a `429` blaming the caller.

The cost of that choice is stated rather than hidden: during such a window the
only remaining bound is the in-process pre-filter, which is **per execution
environment**, so the effective ceiling is `max` per subject per window
multiplied by however many environments AWS is running. It is a floor, not the
limit. The degradation is logged once per cold start at `WARN` — once, not per
request, because a limiter that logged every failed write during a DynamoDB
incident would add its own load to the incident.

With `stores.driver: memory` there is no shared counter at all and the in-process
tier is the whole limiter. The cold-start log says so in as many words. That
driver is refused in production (RS-12), so this is a development posture and
never a deployed one.

### 14.6 Reading it from outside

You cannot see a limiter without tripping it, which is why the cold-start log is
where its resolved shape is written: `rate limiting is on` with `keyBy`, `max`,
`windowSeconds` and the full list of watched `METHOD /path` patterns, or `rate
limiting is off` with what that means. Two warnings are worth knowing: `rate
limiting is on but its scope is empty`, which is a document that enabled the
block and pointed it at nothing, and `rate limiting has no shared counter`, which
is the memory driver above.

The contract suite's `rate-limit` capability is **opt-in and off by default**,
for the reason a probe cannot be written any other way: discovering a limiter
costs the budget it protects, and a suite that exhausted a live one would flake
and would leave the deployment throttled for whoever called next. See
[test/contract/README.md](../test/contract/README.md).

## 15. `ui.*`, knob by knob

The hosted UI: everything under `GET <prefix>/ui` — the config document the
pages boot from, the server-rendered pages themselves, and the static assets
under them. It is the whole of the reference's `ui` router
(`src/router/ui.router.ts`), mounted where the reference mounts it
(`src/router/auth.router.ts:1640`), and it comes from the imported adapter:
nothing in this binary mounts a route under the api prefix.

The pages are the reference's own fourteen browser assets, vendored byte for
byte by `awesome-go-auth` and compiled into the binary. There is no bucket to
deploy them to, no second origin and no build step — which is the point of §15.3
below.

| Path | Type | Default | Env var |
|---|---|---|---|
| `ui.enabled` | boolean | `false` | `AWESOME_AUTH_UI_ENABLED` |
| `ui.headless` | boolean | `false` | `AWESOME_AUTH_UI_HEADLESS` |
| `ui.customCss` | string | none | — (file-only) |
| `ui.assetsDir` | string (directory) | none; the vendored assets | — (file-only) |
| `ui.uploadDir` | `s3://<bucket>[/<prefix>]` (a filesystem path loads and is reported by `unwiredKnobs`) | none, see §15.4 and §16.5 | `AWESOME_AUTH_UI_UPLOAD_DIR` |
| `ui.branding.siteName` | string | `Awesome Node Auth` | `AWESOME_AUTH_UI_SITE_NAME` |
| `ui.branding.primaryColor` | string | `#4a90d9` | `AWESOME_AUTH_UI_PRIMARY_COLOR` |
| `ui.branding.secondaryColor` | string | `#6c757d` | `AWESOME_AUTH_UI_SECONDARY_COLOR` |
| `ui.branding.logoUrl` | string | none | `AWESOME_AUTH_UI_LOGO_URL` |
| `ui.branding.bgColor` / `.bgImage` / `.cardBg` | string | none | `AWESOME_AUTH_UI_BG_COLOR`, `…_BG_IMAGE`, `…_CARD_BG` |

`ui.enabled` is one switch for two things, and the second is easy to miss: it
also changes the shape of **every emailed link**. With it on, a password-reset
mail points at `<siteUrl><prefix>/ui/reset-password?token=…`, the hosted page for
it; with it off, at `<siteUrl><prefix>/reset-password?token=…`, the API route
itself (`HTTPConfig.UILink`, the reference's `buildUiLink`,
`auth.router.ts:261-271`). Turning the UI off on a deployment whose users have
unspent reset links in their inbox invalidates the *destination* of those links,
not the tokens.

There is no `features` knob and there will not be one. The eight flags in the
config document — `register`, `magicLink`, `sms`, `google`, `github`,
`forgotPassword`, `verifyEmail`, `twoFactor` — are derived from what this
deployment is actually wired to do, so they cannot claim a flow it cannot
perform. `config-schema.md` §1.12 records that as a rule rather than an omission.

### 15.1 What the cold start tells you, and what the settings store now costs

`hosted UI mounted` names the mount, the asset source, the language, the site
name and whether the settings store is behind the branding. `hosted UI not
mounted` — the default — says that the whole subtree answers 404 and that
emailed links therefore point at the API routes.

The line worth reading twice is `the settings store is on the UI render path`.
**This is the first block whose surface reads the settings store per request.**
The core builds the config document by reading that store first (the reference's
own order, `ui.router.ts:99`) and then the template store for the `config` page's
translations — so with the UI on and both stores enabled, **every SSR page render
and every `GET <prefix>/ui/config` is two DynamoDB reads**. Before this, the
settings store was read once at cold start by the seed (§11) and once per
`POST <prefix>/2fa/disable`.

And a settings store that fails does not fail the request. The core catches it
and serves the reference's fallback document — default branding, English, no
translations, and a **shorter** `features` object carrying three of the eight
flags, which is upstream's bug reproduced rather than fixed. A client cannot tell
that from success. So an unreachable store degrades every page of the hosted UI
to the reference's default look, silently; the cold-start line is the notice you
get in advance.

One thing that interaction does *not* change: what §11's seed writes.
`runtimeSettings` has no `ui` member, so the stored branding an administrator
will eventually save is written by the admin surface and by nothing in this
build. Until then the store's `ui` block is absent on every read and the branding
falls straight through to `ui.branding.*`.

### 15.2 `ui.headless` serves no HTML at all

Headless is a different product, not a degraded one. With it on, the router
serves the config document and the static assets and **no page** — every page
path 404s (`ui.router.ts:172-183`; the return is the behaviour, and the uploaded
asset mounts are on the far side of it, so they are not mounted either).

That is the posture for a hosting SPA: your application provides its own login
UI, loads `<prefix>/ui/auth.js` from this origin, and reads `headless: true` out
of the config document to stop redirecting to a login page that is not there. It
is the right answer when you already have a design system and the wrong one if
you wanted the built-in pages, and the two are indistinguishable from a status
code — which is why the cold start says which it is.

### 15.3 What a hosting page has to allow, and what the pages load

There is no `Content-Security-Policy` on these responses, and that is not an
oversight — the reference sets none, and a header this port invented would be a
deviation on a surface whose whole purpose is to be the family's page. What
matters instead is what the pages *do*, because that is what a hosting
application's own policy has to permit:

- **An inline `<script>`, always.** The SSR injection writes
  `window.__AUTH_CONFIG__ = {…}` into the document (`ui.router.ts:273`) so the
  page boots without waiting for a fetch. A policy with no `script-src
  'unsafe-inline'`, and no nonce, breaks every page.
- **An inline `<style>`, always, twice.** The branding variables go into a
  `:root` block ahead of any stylesheet, which is what prevents a flash of
  unstyled content, and the readiness splash brings its own.
- **`ui.customCss` is injected unescaped**, in a `<style>` of its own
  (`ui.router.ts:216`). It is stylesheet source and there is nothing to escape it
  into; a `</style>` inside it closes the block, here exactly as there. It is
  readable only from the static configuration — no settings store can reach it —
  so the string is always your own code.
- **`ui.branding.logoUrl` is written into `src="…"` unescaped**, which is the
  reference's sink reproduced. A value containing a double quote escapes the
  attribute. Today that value can only come from this document or from a settings
  store nothing in this build writes; the core names it explicitly so that the
  admin surface has to decide about it rather than inherit it.
- **Everything else is same-origin.** The assets are served from
  `<prefix>/ui/…` by this deployment. No CDN, no external font, nothing to
  allowlist — which is the opposite of the documentation surface (§12.3) and
  worth the contrast.

The injected object itself is serialised with Go's default escaping, so `<`, `>`
and `&` leave as `<`, `>` and `&`. The bytes differ from
`JSON.stringify`'s and the parsed value does not; it is the upstream deviation
`ui-ssr-config-json-is-html-escaped` ([deviations.md](deviations.md)), and it is
the one place the port is *stricter* than the reference — a `</script>` inside a
branding string cannot end the block.

**Headless and a hosting SPA.** If your application serves its own pages, none of
the above applies to it: it loads `auth.js` from this origin and writes its own
markup, so its CSP is its own. What it does need from this origin is the config
document, which is a plain `GET` with no credential, and the cookies the auth
routes set — which means the SPA and this deployment want to be the same origin,
or the cookies want a shared parent domain and `cookies.sameSite` set
accordingly. `infra/sam/template.yaml`'s `EnableCloudFront` exists for exactly
that: one hostname in front of both.

### 15.4 `ui.assetsDir`, and `ui.uploadDir` which names an S3 location

**`ui.assetsDir`** replaces the built-in pages with your own. It is file-only —
a path inside the deployment artifact, the same position `email.templatesDir` is
in — because a Lambda's only readable filesystem is the package it was deployed
with.

It is all-or-nothing. The core takes a supplied asset set at its word and never
falls back to the vendored one, on the grounds that a half-replaced UI is worse
than a missing one, so a page your directory lacks is a 404 rather than the
built-in page. A directory that is not there, or that holds none of the three
pages the handler falls back to — `login.html`, `index.html`, `index.csr.html`,
tried in that order — **refuses the deployment at cold start**, naming the three.
That refusal exists because the alternative is a stack that 404s every page while
every health check passes.

**`ui.uploadDir` names an S3 location on this product, `s3://<bucket>[/<prefix>]`,
and is honoured as one.** It is the reference's single upload-location knob —
the directory its admin router writes into and its UI router serves from — and
`config-schema.md` §1.12 recorded that the serverless target would be S3. With an
S3 location set, one `auth.UploadStore` is built over that bucket and prefix
(`internal/integration/aws/s3_uploads.go`) and handed to the core; the console's
four upload routes write through it, and `GET <prefix>/ui/assets/logo/*` and
`GET <prefix>/ui/assets/uploads/*` serve the same objects back from it, through
the core's own `UploadFS` composition, with `UIOptions.Uploads` left nil. §16.5
carries the knob, the bucket the stack creates for it and what each request
costs. The former deviation `ui-uploaded-assets-are-not-served` is retired and
indexed under "Retired" in [deviations.md](deviations.md).

**A plain path is accepted and honoured by nothing**, and is reported at cold
start as a knob this runtime cannot act on, with the `s3://` form as the remedy.
`/var/task` is read-only and `/tmp` is per execution environment, so a directory
would hold a logo for one cold start and lose it by the next; the value is
accepted rather than refused so a document written for another port in the
family still loads here. With no location, or a path, the two asset paths answer
404 — the reference's own behaviour with `uploadDir` unset — and a logo is set
with `ui.branding.logoUrl`, which the SSR injection writes into every page.

### 15.5 `ui.enabled` is safe to turn on

**The caveat this section used to carry is closed.** It said to leave
`ui.enabled` off on a deployed stack because the vendored assets are the
reference's complete set — `admin.js` and `admin.css` among them — and the admin
dashboard would load and then fail against `/admin/*` routes this build did not
mount. Those routes are mounted now, from the `admin` block (§16), so a
deployment that turns the UI on gets the auth pages *and* a console that works,
under whichever access policy the document names.

The other half of the old caveat turned out not to exist. The vendored auth pages
and `auth.js` call `${apiPrefix}/…` and nothing else, and `admin.js` calls
`<admin>/…` and nothing else: nothing in the fourteen vendored assets references
a `/tools/*` route (`awesome-go-auth/ui/upstream/assets`, grepped rather than
assumed). So `ui.enabled` waits on nothing in the `tools` block; the hosted UI is
complete with the admin surface alone.

## 16. `admin.*`, knob by knob

The admin console: the reference's `createAdminRouter`
(`src/router/admin.router.ts`), mounted by the imported adapter at
`admin.basePath` as a **sibling** of the api prefix — the reference's own layout,
where the host mounts the admin router beside the auth router and tells it where
the auth router lives (`admin.router.ts:152-157`) — and guarded by the access
policy the document names. Everything under it comes from the adapter; nothing
in this binary adds a route there. `cmd/auth/admin.go` builds the value and
argues every field; this section is the same map from the operator's side.

| Path | Type | Default | Env var |
|---|---|---|---|
| `admin.enabled` | boolean | `false` | `AWESOME_AUTH_ADMIN_ENABLED` |
| `admin.accessPolicy` | `is-admin-flag` \| `open` \| `rbac:<role>` \| `permission:<perm>` \| `first-user` (parses, **refused at start**, RS-17) | unset | `AWESOME_AUTH_ADMIN_ACCESS_POLICY` |
| `admin.bootstrapSecret` | secret | unset | `AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET` (+ `_SECRETSMANAGER` / `_SSM_PARAMETER`) |
| `admin.rootUser.email` | email | unset | `AWESOME_AUTH_ADMIN_ROOT_EMAIL` |
| `admin.rootUser.passwordHash` | secret, a bcrypt hash | unset | `AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH` (+ `_SECRETSMANAGER` / `_SSM_PARAMETER`) |
| `admin.cookiePrefix` | string | unset | `AWESOME_AUTH_ADMIN_COOKIE_PREFIX` |
| `admin.loginPath` | absolute path or URL | unset | `AWESOME_AUTH_ADMIN_LOGIN_PATH` |
| `admin.basePath` | absolute path | `/admin` | `AWESOME_AUTH_ADMIN_BASE_PATH` |
| `admin.sessionTtl` | duration | `24h` — **reported, not honoured** (§16.8) | `AWESOME_AUTH_ADMIN_SESSION_TTL` |
| `admin.upload.maxFileSizeMb` | integer 1–50 | `5` — **reported, not honoured** (§16.8) | `AWESOME_AUTH_ADMIN_UPLOAD_MAX_FILE_SIZE_MB` |

**`admin.enabled` alone mounts nothing.** The core mounts the console only when
it is enabled *and* an access decision exists (`HTTPConfig.AdminMounted`), and
refuses to serve the reference's third arm — enabled, no policy, no secret, a
stderr warning and every route open (`admin.router.ts:530-536`) — which is the
upstream deviation `admin-console-requires-an-explicit-policy`. The product
refuses the same document one layer earlier, at load, with rule RS-6. The two
agree, and the effect is that no deployment of this product can come up serving
an unguarded console by omission; the open console is one named policy away, and
the name is `open`.

### 16.1 The four policies, and what each one grants

The guard runs on every route under the mount except the two documentation
routes (§16.3) and the two static assets, and it decides on every request — the
login route establishes *who* the caller is, and the guard decides *whether that
person may use the console* the next time they call. A user the policy will
refuse therefore logs in successfully and is answered `403 {"error":"Forbidden"}`
by the very next request, exactly as in the reference.

- **`open`** grants every request: no token is read, no store is consulted, no
  principal is established. It is the reference's own default and its own
  advice for it — "use only behind a VPN or IP allow-list" (`admin.router.ts:29`).
  The contract suite reports a console that answers a bare `GET <admin>/api/ping`
  with 200 as a fault, in as many words.
- **`first-user`** is **refused at start on every driver** (RS-17), and the
  schema keeps the spelling only so a document written for another port parses
  here and meets the refusal rather than a schema error. The reference grants
  "the first registered user", meaning whoever `listUsers(1, 0)` returns first
  (`admin.router.ts:372-374`), and that is the first registered user only under
  monotonic ids. On this product ids are 128 random bits (the core's `newID`),
  the listers order by id — `(tenant, id)` ascending on the DynamoDB driver —
  and so the policy would admit **whoever holds the lowest random id**, which
  changes hands every time a later registrant draws a lower one: with one
  existing account a single `POST <prefix>/register` takes the console with
  probability one half, and the register route is public. RS-10 still refuses
  the policy on a driver that cannot enumerate users at all. The way in is the
  root user (§16.2) and `is-admin-flag`. Registered as
  `admin-first-user-policy-is-refused`; it retires the day the core's listing
  is creation-ordered or its ids are monotonic.
- **`is-admin-flag`** grants a user whose `isAdmin` flag is set, and reads
  nothing else — not `role`, not RBAC. Nobody is flagged on day one; the
  console's own `POST <admin>/users/{id}/promote` with `{"method":"flag"}` sets
  it, which is what the root user (§16.2) exists to reach. The DynamoDB store
  gained the writer for this flag with this block; before it, the policy admitted
  exactly the users somebody had flagged by editing the table.
- **`rbac:<role>`** and **`permission:<perm>`** are this product's sugar over the
  reference's custom-predicate arm (`admin.router.ts:41`, `:376`). The first
  grants a user holding `<role>` in their own tenant (`GetRolesForUser(user.id,
  user.tenantId)` contains it); the second grants a user holding `<perm>` through
  any of their roles (`UserHasPermission`). Both need `stores.enable.rbac`, which
  the loader requires beside them. **A store error is a denial, never a 500**:
  the reference wraps the whole evaluation in a `try/catch` whose catch sets
  `granted = false` (`:378-380`), the core keeps that on its predicate seam, and
  a console whose role store is unreachable answers 403 to everyone rather than
  failing open. The tenant is the user's own because a role is a tenant-scoped
  assignment in the store's vocabulary; a single-tenant deployment passes `""`.

A predicate that cannot reach its store is the one case where "denial" is the
product's decision rather than the reference's transcription, and it is the same
direction the rate limiter's fail-open argument runs in reverse: a guard that
fails open is not a guard.

### 16.2 How you get in: two credentials, one secret, and the fix you inherit

The guard reads a bearer token, then a cookie, and accepts exactly two kinds:

- **an ordinary access token** minted by `POST <prefix>/login` — cookie or
  bearer — for a user the policy admits. This is why there is no
  `admin.jwtSecret` knob. The core's `AdminOptions.JWTSecret` is left empty, which
  it reads as `security.jwt.accessTokenSecret`; that is what the reference's
  "must match `AuthConfig.accessTokenSecret`" (`admin.router.ts:70-78`) asks a
  host to arrange by hand, what `config-schema.md` §1.13 folded into RS-7, and
  the arrangement under which a session on the auth router opens the console.
- **an admin token** minted by `POST <admin>/login`, which accepts three things
  in order: the root user, the bootstrap secret, and an ordinary user's
  email and password looked up in the empty tenant (`admin.router.ts:552-573`).
  The route is JSON, sits outside the auth router's CSRF chain, and sets the
  session under the **same cookie name as the auth access token**, which is the
  reference's deliberate arrangement and has the reference's consequence:
  logging into the console replaces the browser's auth session cookie until the
  next `/refresh`.

**The console's own login does not enforce the second factor.** Its third arm
is a password check and nothing else: no TOTP or SMS step, no look at the
account's enrolment, no look at the settings store's `require2FA`. An account
that `POST <prefix>/login` challenges is signed into the console by
`POST <admin>/login` on its password alone, with a 24-hour admin token, and
the policy then judges that token like any other. That is the reference's
behaviour, the core reproduces it, and this binary cannot close it without a
route it may not add — so it is registered
(`admin-login-skips-the-second-factor`, pinned by
`TestAdminLoginSkipsTheSecondFactor`) and mitigated two ways. The route is
**rate limited** under the same `rateLimit` block as the auth login (§16.7);
before this it was an unlimited password oracle for every user in the empty
tenant and, for the bootstrap secret, a constant-time compare with no bcrypt
cost per guess. And **`admin.loginPath`, pointed at the hosted login**
(`<prefix>/ui/login`), sends a browser through the flow that does enforce the
second factor: the ordinary access token it ends with is the first credential
above, and the guard judges it. A deployment that requires 2FA sets it.

**Neither credential is revocable through the session store.** The guard
verifies signature, `typ`, issuer and expiry and never consults the store, so
`sessions.checkOn: allcalls` does not reach the console: an access token whose
session was revoked or logged out stays an admin credential until it expires,
and the admin token — a `sid`-less JWT — lives its 24 hours whatever happens to
the account. `POST <admin>/logout` only clears the cookie. The one kill switch
is rotating `security.jwt.accessTokenSecret`, which ends every session in the
deployment. And there is no route on either line that *clears* an `isAdmin`
flag: demoting an administrator is a table edit
(`internal/store/dynamodb/user_flags.go`).

**What the shared secret does not do here.** In the reference a bare
`jwt.verify` over that secret makes *every* token the secret signs an admin
credential — a refresh token, and the typed step-up token a user holds after a
password and before a second factor, so the console can be entered without the
second factor the deployment requires by presenting the wrong kind of token.
The core types the admin token and accepts only `typ:"admin"` and
`typ:"access"`, honouring `isRoot` only on the first: the upstream deviation
`admin-guard-accepts-only-typed-session-tokens`. This product inherits that fix
by construction, because it never signs a token with anything but the core, and
it is why a different `JWTSecret` would be a loss and not a hardening — it would
sever the first credential without buying back anything the second lacks. It
closes the typed-token hole and nothing else: the paragraph two above is the
route where the factor is skipped by never being asked.

**The root user** (`admin.rootUser.email` and `.passwordHash`) is a credential
that lives in configuration rather than in the user table, for "environments
without local users": compared by exact email at `POST <admin>/login`, verified
against a **bcrypt hash** that is a secret reference and never sits in the
document, and minting a token that carries `isRoot` — the one claim that skips
the store lookup and the policy alike. It is the most privileged credential the
console has and is as strong as the hash and the access-token secret together.
An email with no resolvable hash **refuses the cold start**: it would be a login
form that is served and always answers "Invalid credentials", which is the
silent shape this product refuses everywhere else. A value that is not a bcrypt
hash is refused for the same reason. Hash the password yourself with a tool
that prompts for it — `htpasswd -nBC 12 x | cut -d: -f2`, never the `-b` form,
which puts the root administrator's password on the command line and so in
shell history and the process list — and store the hash.

**The bootstrap secret** (`admin.bootstrapSecret`) is the reference's deprecated
`adminSecret`, kept because the reference keeps it and because it is an honest
bootstrap. With no policy it is the legacy guard — a bearer token compared
against the `Authorization` header, 401 absent and 403 wrong — and the shell is
served unguarded with the SPA holding the secret in `sessionStorage`. Beside a
policy it is also a *password* the login route accepts for the empty email or
the literal `admin`, minting an `isRoot` token — compared in constant time with
no bcrypt cost per guess, which is why RS-6 refuses one shorter than 32
characters (the HS256 floor) and why the login is rate limited. Prefer a policy
and a root user.

**The console has no CSRF check, and `SameSite` is its whole defence.** The
vendored SPA posts to `<admin>/login` as JSON with no CSRF header, so a
double-submit check would refuse every login it makes; the guard accepts the
ordinary access-token cookie; and the promote handler decodes its body loosely
with no `Content-Type` check. What keeps a cross-site `<form method=POST>` from
reaching `POST <admin>/users/{id}/promote` is the `SameSite` attribute on the
cookie — `lax`, the reference's own default and this product's. RS-18 therefore
**refuses the console beside `cookies.sameSite: none`**, and the SAM Rule
`AdminConsoleNeedsSameSiteCookies` refuses the same pair at changeset time. The
product's CORS layer is kept off the admin mount for the same reason the
reference never puts one there (`cmd/auth/app.go`, `corsExemptMounts`).

**`admin.cookiePrefix`, and the empty string.** The core's field is a `*string`
because the reference distinguishes an explicit empty prefix — the bare name
`accessToken` — from no prefix at all, which derives the name from the cookie
options on the way out and tries `__Host-accessToken`, `__Secure-accessToken`
and `accessToken` in that order on the way in. The product schema is a plain
string and cannot spell the difference, so this build decides it: **empty is
unset.** The name is then derived from `cookies.secure`, `cookies.path` and
`cookies.domain` exactly as the auth routes derive theirs, which keeps the admin
cookie and the session cookies from disagreeing about the deployment — and the
one deployment where the bare name is *wanted*, a non-`Secure` one, is the one
where derivation already yields it. An explicit `""` has no use case the
derivation does not cover and is not expressible. A non-empty value is an
explicit override, as there. The `Secure` flag comes from `cookies.secure` and
never from `X-Forwarded-Proto` (`admin-cookie-secure-flag-is-configured-not-forwarded`).

**`admin.loginPath`** redirects an unauthenticated *browser* — a GET that
accepts `text/html` — to `<loginPath>?redirect=<admin path>` instead of serving
the built-in form. It is emitted as given; the redirect parameter is the
router's own mount and never anything read off the request.

### 16.3 The unauthenticated GET, narrowed, and the documentation pair

In the reference an unauthenticated GET carrying `Accept: text/html` is let
through to *every* guarded route when no `loginPath` is configured
(`admin.router.ts:318-325`): `curl -H 'Accept: text/html' <admin>/api/users`
reads the user table with no credential, because the handler behind the guard
never looks at the marker. The core lets that branch reach exactly one route —
the HTML shell, whose whole job in that state is to render the login form with
every feature flag emptied — and answers 401 everywhere else
(`admin-unauthenticated-get-serves-only-the-login-form`). This product inherits
it; the narrowed branch — an HTML `GET` of a guarded route answering 401 — is
pinned in `cmd/auth/admin_test.go` `TestAdminConsoleIsMountedGuardedAndServed`
and in the core's own tests, not in the contract suite, whose every anonymous
guarded request carries `Accept: application/json` and so exercises the branch
the reference answers 401 on too.

**The console's own documentation pair** — `GET <admin>/api/openapi.json` and
`GET <admin>/api/docs` — follows `docs.swagger` exactly as the auth router's pair
does (§12): `true`, `false`, or `auto`, which is on outside production and off in
it, resolved by the same function so the two pairs cannot disagree. There is one
thing to weigh before leaving it on that the auth router's pair does not carry:
**these two are the only routes under `<admin>/api` the reference registers with
no guard** (`admin.router.ts:1499`, `:1517`), so an anonymous caller reads the
whole documented admin surface — every path, every body — and, because the
document's path items follow the configured stores, learns which optional
features this deployment wired. The core reproduces the asymmetry rather than
tidying it away and says why (`AdminOptions.Docs`); the product adds the same
`Content-Security-Policy` the auth router's page gets, because the console's
Swagger page is the same HTML loading the same unpinned CDN bundle onto the same
origin (`docs-page-carries-a-content-security-policy`). The cold-start log warns
when the pair is mounted.

### 16.4 The stores behind the tabs

The console draws a tab for each store it was handed, and hands nothing it was
not: the `admin` slot of `coreOptionSets` passes the five stores the core takes
by name, each behind its `stores.enable` flag (§4.1), and the feature object
`GET <admin>/api/ping` answers with — the same object the shell injects — says
which are on. `sessions`, `templates` and `control` follow the session,
template and settings stores other blocks handed over; `twoFAPolicy` needs a
user lister and the 2FA-policy writer, both of which the DynamoDB store has now;
`linkedAccounts` follows the OAuth block; `upload` follows §16.5.

The DynamoDB store implements all of them (D6) and the memory driver carries the
core's own in-memory implementations, so the same document draws the same tabs
on both — with the memory driver's usual caveat that every store is per
execution environment, so a role assigned through one cold start is unknown to
the next. RS-12 already refuses that driver in production.

**One route of the users tab is single-tenant, and that is the pinned core's, not
a decision made here.** `GET <admin>/api/users` lists every user in every tenant,
because `AdminUserStore.ListUsers` reads `""` as a wildcard; the detail route
beside it, `GET <admin>/api/users/{id}`, asks `GetUserByID(id, "")`, where `""` is
the literal single tenant (`admin_read.go` `adminGetUser` at `v0.11.0`, whose
comment says as much). On a table whose users all live in the empty tenant —
every account this binary registers, since it never turns the store's
multi-tenant mode on — the two agree. On a table that holds users under a
tenant, which `migrate cognito --tenant` can produce, the listing links to rows
whose detail answers `404 User not found`. The reference's `findById(id)` carries
no tenant at all (`admin.router.ts:789-800`), so a by-id lookup that spans
tenants is what closing it takes, and that is a store seam the core has to grow:
the fix is written upstream (`UserLookupStore`) and **not tagged**, so this build
stays on `v0.11.0` and serves what `v0.11.0` serves. Nothing here works around
it — a product-side route would be a route under the admin path, and this binary
adds none (§12.3 says why) — and the DynamoDB store's half, an item keyed on the
id alone, lands with the pin that can call it. It is registered as
`admin-user-detail-is-single-tenant`, because the product register's scope
includes a divergence a core route causes that this product cannot fix without
forking the core; `TestAdminUserDetailIsSingleTenant` fails the day the pin
moves to a core whose detail route spans tenants.

### 16.5 Uploads: `ui.uploadDir` as an S3 location, and what a logo costs

The console's file picker — `POST <admin>/api/upload/logo`, `/bg-image`,
`GET /api/upload/files`, `DELETE /api/upload/{name}` — is registered only when
an upload store is configured, and the store is built from `ui.uploadDir`
spelled as `s3://<bucket>[/<prefix>]` (§15.4). The stack creates such a bucket
with `EnableAdminUploads=true`: private, SSE-S3 encrypted, every public-access
block on, ACLs disabled, a bucket policy that refuses any request not made over
TLS, and the function granted exactly the store's five calls: the object calls on
the `uploads/` prefix and `s3:ListBucket` on the bucket itself, with **no
`s3:prefix` condition** — deliberately, because S3 answers a `GetObject` or
`HeadObject` for an absent key with 404 only to a caller that holds
`s3:ListBucket` for that request and with 403 to everyone else, and a listing
grant conditioned on a prefix does not apply to a `GetObject`, which carries no
prefix. The store reads a 403 as the failure it is and never as "not found", so
a conditioned grant would turn every missing logo into a 500
(`s3_uploads.go` `isS3NotFound`, `TestS3AccessDeniedIsAFailureNotAMiss`).
Nothing else in S3 (`infra/sam/README.md`, "Admin console"). The objects are
served to browsers by
the function under `<prefix>/ui/assets/uploads/<name>` — the URL the upload
routes answer with, derived from the mount
(`admin-upload-base-url-is-derived-from-the-mount`) — and by nothing else; the
bucket has no website configuration and no public read.

What it costs, in the shape §14.5 uses: **one `PutObject` per upload, one
`ListObjectsV2` per files listing, one `HeadObject` plus one `DeleteObject` per
delete, and one `GetObject` per page view that fetches the logo — misses
included**, because a miss is a `GetObject` that answers 404. Storage is
~USD 0.023 per GB-month, cents for a handful of images; requests are
~USD 0.0004 per thousand `GET`s. [cost-model.md §2.6](cost-model.md) carries the
arithmetic. Every stored object records its `Content-Type` from the key's
extension at write time, because an S3 object stored without one is served as
`binary/octet-stream` forever after and no browser paints a logo under that type.

**Every response under the two asset paths carries a header the reference does
not send**: `Content-Security-Policy: default-src 'none'; style-src
'unsafe-inline'; sandbox` and `X-Content-Type-Options: nosniff`. The reference's
upload filter admits `.svg` by name, and an SVG is a document that may carry
script; served same-origin it would run with the auth cookies, on the origin
where the CSRF cookie is JavaScript-readable and the admin API has no CSRF
layer. The core names the trade and hands it to the host; this product takes
the header rather than dropping `svg`, because a console that offers it would
break. `sandbox` makes a top-level SVG an opaque-origin document with scripts
off, and `nosniff` keeps a `logo.png` that holds HTML from being sniffed into
one. Registered as `uploaded-assets-carry-a-content-security-policy`; with no
store both paths answer 404 with no header, as the reference does.

**The size bound.** The core refuses a file over `UploadMaxBytes` — a constant
carrying the reference's multer limit of 5 MiB — with its own 413
`{"error":"File too large"}`, and `admin.upload.maxFileSizeMb` reaches it only
when it says 5 (§16.8). **That bound is not the one a client meets here.** A
multipart body reaches this function base64-encoded inside a synchronous
invocation event, and the event is capped at 6 MB, so a file past roughly
**4.4 MiB** never reaches the core: API Gateway refuses it with its own 413 and
its own body, `{"message":"Request Entity Too Large"}`, not the admin envelope.
Between 4.4 and 5 MiB the reference accepts and this product does not; above
5 MiB both refuse, with different bodies. The effective ceiling is the
platform's, the knob-gap text for `admin.upload.maxFileSizeMb` says so, and a
deployment that needs larger logos puts them in the bucket by another route.

### 16.6 The backfill you owe before the users tab is right

`GET <admin>/api/users` reads `AdminUserStore.ListUsers`, which on the DynamoDB
driver is a Query over a **sparse** index — a constant partition key and a
`<tenant>#<id>` sort key that `CreateUser` has written since the D6 release, and
nothing before it wrote at all. A profile written earlier is found by every
other route and is invisible to exactly this one: the users tab under-reports,
and the failure does not look like one from outside. (The `first-user` policy
read the same index and would have been wrong here for a second reason; RS-17
refuses it, §16.1.) D6 declared the debt; this block ships the job that pays it:

```sh
./scripts/toolchain.sh go run ./cmd/migrate backfill-users \
  --table <stores.connection.tableName> --region <region> --profile <yours> [--dry-run]
```

One page per iteration, resumable from the key an interrupted run prints
(`--start-key`), idempotent — a swept table matches nothing and writes nothing —
and safe while the table is serving, because every write is a conditional
`UpdateItem` naming the two index attributes and guarded by
`attribute_exists(PK) AND attribute_not_exists(GSI1PK)`: a profile registered or
deleted mid-sweep is skipped, never overwritten and never resurrected. It is an
operator command and not something the function does because it is a `Scan`,
which the execution role deliberately does not grant. **Run it once against a
table that predates D6 before turning `admin.enabled` on there**; the cold-start
log says so whenever the console mounts on the DynamoDB driver, because it is
the only place this deployment can.

### 16.7 The promote route's own limiter, and the login's

The core's `AdminOptions.RateLimiter` is a second limiter slot, separate from the
auth router's, spread onto **exactly one route**: `POST <admin>/users/{id}/promote`,
the route that changes who is an administrator. The admin login is not in that
slot on either line (`admin-promote-route-comes-from-the-development-line`), and
the reference leaves it unlimited; this product does not. **`POST <admin>/login`
is limited by a middleware over the mount** (`cmd/auth/ratelimit.go`,
`newAdminLoginLimiter`) — the core's own comment says a host that wants one
wraps the handler the adapter mounts, and a middleware matching one route adds
no route — on the same `rateLimit.max` and `rateLimit.windowSeconds`, the same
switch, the same counter and the same `keyBy` rule as `POST <prefix>/login`: the
body's normalised email under `email`, the client address under `ip` and
whenever the body names none (the bootstrap arm's empty email). Its counter
scope is its own, so the console's login cannot spend a user's budget on the
auth router or the other way round. §16.2 says why the route needed one.
The reference's default for the promote slot is nil — an empty middleware list — and this product
fills the slot anyway, under the rule that fills the auth router's (§14): with
`rateLimit.enabled` on, the promote route shares `rateLimit.max` and
`rateLimit.windowSeconds`, runs its limiter *ahead of the guard* so an
over-budget caller is refused before a token is verified or a policy evaluated,
and is keyed by the **client address under either `keyBy`** — its body names how
to promote and its path names the person being promoted, and neither is a
subject a caller should be able to mint budgets with. The refusal is the same
429 §14.3 describes, and the register entry `rate-limited-routes-answer-429`
names the route. With `rateLimit.enabled: false` the slot is nil, which is the
reference exactly.

### 16.8 What the cold start tells you, and the two knobs it reports

`admin console mounted` names the mount, the policy and what it grants, which
credentials the guard accepts (and that the console's login skips the second
factor and that neither credential is revocable), whether a root user and a
bootstrap secret are configured (`bootstrapSecretConfigured`, a boolean — the
value itself is never logged), and whether the documentation pair is on — with
a `Warn` for the pair, a `Warn` naming the backfill on the DynamoDB driver, and
the whole line at `Warn` rather than `Info` under the `open` policy, which the
loader also warns about. `admin console not mounted` says why: the block is
off, or (for a document that bypassed the loader) it is on with no access
decision. `admin stores wired` lists which of the five stores were handed over
and whether an upload store was built.

Two knobs of the block are **reported rather than honoured**, by `unwiredKnobs`,
and only when they differ from the value the core applies. `admin.sessionTtl`:
the core signs the admin token with the reference's fixed `expiresIn: '24h'`
and the cookie with the matching `maxAge` (`admin.router.ts:585`, `:610`), and
exposes no option for either, so the deployed lifetime is 24h whatever the
document says. `admin.upload.maxFileSizeMb`: the upload routes bound a file at
`UploadMaxBytes`, a constant carrying the reference's multer limit of 5 MiB,
with no option beside it. Both knobs are `[new]` in the schema — inventions over
values the reference hard-codes — and their defaults are those values, so a
document that leaves them alone reports nothing. `ui.uploadDir` in its
filesystem spelling is the third report (§15.4).

## 17. Two worked postures

**Mail through SES, templates from the artifact.** Every key that is not
`email.*` here is load-bearing: `stores.enable.templates` needs a driver that
backs a template store (§5.3), and the `stores` block has to name that driver,
because the default is `memory` and rule RS-12 refuses it in production.

```json
{
  "schemaVersion": 1,
  "deployment": {"environment": "development", "publicUrl": "https://auth.example.com"},
  "email": {
    "siteUrls": ["https://app.example.com"],
    "mailer": {"endpoint": "https://unused.invalid", "from": "no-reply@example.com", "fromName": "Example"},
    "templatesDir": "/var/task/templates"
  },
  "stores": {"driver": "memory", "enable": {"users": true, "sessions": true, "tokens": true, "templates": true}}
}
```

For production today, drop `templatesDir` and `stores.enable.templates`, keep
`stores.driver: dynamodb`, and the built-in `en`/`it` templates render.

**Every credential posted to a receiver you own.** A production document: no
mailer block at all, so nothing is sent through SES or SNS, and the
email-changed notice and the account-linking mail are not sent either. The
`stores` block is what makes it a production document rather than a refusal —
the default driver is `memory`, which RS-12 forbids in production.

```json
{
  "schemaVersion": 1,
  "deployment": {"environment": "production", "publicUrl": "https://auth.example.com"},
  "email": {
    "siteUrls": ["https://app.example.com"],
    "deliveryWebhook": {
      "url": "https://hooks.example.com/auth-delivery",
      "timeoutMs": 2000,
      "secret": {"secretsManager": "awesome-auth/prod/delivery-webhook"}
    }
  },
  "stores": {
    "driver": "dynamodb",
    "connection": {"tableName": "awesome-auth", "region": "eu-west-1"},
    "enable": {"users": true, "sessions": true, "tokens": true}
  }
}
```
