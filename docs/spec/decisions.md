# Decisions register

Every entry records a fork in the road that the reference source does not settle, the option taken, and what it would cost to reverse it. The rule during the 2026-09 build-out is: decide, record here, continue. A later reversal by the project owner is a new block of work, never a stop.

## D-0 — Rules of the non-stop run (2026-09-11)

- The owner asked for the whole programme, Go port and Lambda product, to be completed in one autonomous run. The former "stop at each phase boundary" rule is replaced by "write the phase summary in `docs/PROGRESS.md` and continue".
- Pull requests on both repositories are merged by the author account after CI is green (squash, one concern each); milestone tags are cut without a separate review.
- Deployments target only the CloudFormation stack `awesome-lambda-auth` in `eu-west-1`, always through the AWS CLI profile named `lambda-auth`. The profile name is the invariant: a pre-flight check refuses to run when that profile resolves to the same account as `default`, or when the stack is missing or in a rollback state. Nothing is ever deleted.
- On-demand resources may be created without asking (KMS keys, S3 buckets, SQS queues, EventBridge buses, Function URLs, CloudFront distributions, additional Lambda functions, CloudWatch alarms). Provisioned capacity, WAF, NAT, VPC attachments, real domains and anything in the demo account beyond reading are `blocked-owner` items.
- Reversal cost: none; this is process.

## D-1 — Configuration format

The document is JSON, baked into the artifact (`AWESOME_AUTH_CONFIG_FILE=/var/task/awesome-auth.json`) or supplied inline (`AWESOME_AUTH_CONFIG_JSON`), with the `AWESOME_AUTH_*` environment layer on top and the runtime settings store above that. No SSM parameter tree. YAML is a front-end for later. `cookies.allowInsecureCookieMode` is honoured in every environment and warned about in production. Reversal cost: low, the loader already takes a `Document`.

## D-2 — Rate-limit wire shape

There is nothing to inherit: the reference ships no limiter. Every limited outcome is `429` with the family error shape, `{"error":"Too many requests","code":"RATE_LIMITED"|"TOO_MANY_FAILURES"|"ACCOUNT_LOCKED","retryAfter":<seconds>}`, plus `Retry-After` and the IETF draft `RateLimit-*` headers. No server-side sleep; a progressive delay is expressed through `Retry-After`. Reversal cost: trivial before the first release.

## D-3 — What identity-provider mode signs

Only the OIDC surface: `id_token` and the OIDC `access_token` from `/oidc/token`, RS256 through KMS or an injected PEM key. Session tokens from `/login` and `/refresh` stay HS256, exactly as in the reference (`reference-issues.md` N35). Version 1 issues no OIDC `refresh_token`; clients are configured, not registered dynamically. Reversal cost: medium, but the reference points the same way.

Amended when it was wired (P5), on three points the entry above left open or got wrong.

- **The token endpoint's `access_token` is the HS256 session token, not an RS256 one.** The core's `/token` answers with `newSessionTokens` plus an RS256 `id_token` (`idp.go`), and that is the right shape for this product: the `access_token` it returns is the credential every route of this deployment already accepts, so a client completing an OIDC flow ends up with a session it can actually use against `/me` and the account routes. The RS256 pair the entry above imagined is `auth.IssueIdPTokenPair`, a host-level API no mounted route calls. `idProvider.accessTokenTtl` and `idProvider.refreshTokenTtl` govern only that unreachable pair, so both are reported by `unwiredKnobs` at cold start rather than left to look wired, and `expires_in` is `security.jwt.accessTokenTtl`.
- **The endpoints are mounted under the api prefix, not at `/oidc/*`.** They are the core's own: `<prefix>/.well-known/openid-configuration`, `<prefix>/authorize`, `<prefix>/token`, `<prefix>/userinfo`, plus the JWKS document at `<prefix><idProvider.jwksPath>`. Nothing is invented and nothing is renamed. All five are mounted by the adapter as of `awesome-go-auth` v0.7.0, which moved the four OIDC endpoints off `RegisterHandlers` and onto every adapter; the core's deprecated `<prefix>/jwks` alias, which no adapter mounts, went with the mux this binary used to keep beside the adapter's (`cmd/auth/idp.go`, `idpMountedEndpoints`).
- **The `kid` is derived from the key material** — `base64url(sha256(SPKI DER))[:16]` — rather than being the reference's constant `provisioner-key-1`, because a rotation has to be additive. Registered as `idp-kid-derived-from-key-material` (`deviations.md`). KMS is the production key source and the PEM stays supported; RS-4 refuses a deployment that configures both, in any environment.

The rest of D-3 stands: no OIDC `refresh_token` in v1, and clients come from the configuration document rather than dynamic registration. The whole surface is specified in `docs/oidc.md`, including what it deliberately does not do.

## D-4 — Temporary 2FA token

Kept as the upstream registered deviation `temp-token-is-typed-not-an-access-token`: a five-minute HS256 JWT with `typ: "temp"`, refused as a session credential by every protected route, `INVALID_TEMP_TOKEN` everywhere. Reversal cost: low.

Amended when 2FA was wired (P3), on the last three words. `INVALID_TEMP_TOKEN` is the code the *sibling* step-up routes answer; the two surfaces this block put under contract answer something else, and both were read out of the source rather than assumed.

- **`POST /2fa/verify` answers `401 {"error":"Invalid or expired access token","code":"INVALID_ACCESS_TOKEN"}`** for every way of getting the token wrong — missing, empty, unparseable, or well-formed and signed by nobody. It is not a port decision: the reference verifies the tempToken on this route through `verifyAccessToken` and lets that error through unchanged (`auth.router.ts:862`, against the `INVALID_TEMP_TOKEN` its siblings raise at `:1096`), so the same mistake has two codes depending on the 2FA method. The core reproduces it (`passwordless.go` `HTTPErrInvalidStepUpToken`, passed for both the missing and the bad token by `adapter/nethttp/passwordless.go`). Pinned rather than harmonised: a client that special-cases TOTP today would break if this route started agreeing with the others.
- **The authenticated middleware answers the ordinary code-less `403 {"error":"Invalid or expired access token"}`** when a tempToken is presented as a session credential. No 2FA-flavoured refusal, and deliberately so — a distinguishable answer would tell a caller what the token it is holding actually is.

Contract cases `2fa/verify-wrong-code-is-uniform` and `2fa/temp-token-is-not-accepted-by-me` pin the two. The deviation itself is unchanged: what the typed token *refuses* is the decision, and it still refuses everything a session token opens.

## D-5 — Offset pagination on DynamoDB

Admin list endpoints emulate `limit`/`offset` by walking query pages and discarding `offset` items, capped at `offset + limit ≤ 1000` (`400 OFFSET_TOO_LARGE` beyond); `total` reproduces the reference's heuristic; an additive `nextCursor` is returned for clients that can use it. Reversal cost: low.

## D-6 — Hosted UI

The reference's UI assets are vendored byte for byte upstream and pinned by a SHA test, served embedded under `<apiPrefix>/ui/*`. CloudFront in front of the stack is the production front door (same origin for `/auth`, static assets from S3, the SSE Function URL), enabled on the development stack. Reversal cost: medium.

## D-7 — `deleted:0` and refresh-token families

Both signed off as registered deviations: `POST /sessions/cleanup` answers `{deleted:0}` because expiry is DynamoDB TTL; a replayed refresh token revokes its whole session. Reversal cost: high for the count (needs an index and a scan), and the family design is security-positive, so it stays.

## D-8 — Server-sent events on Lambda

`/tools/stream` is served by its own function behind a Function URL with response streaming. The DynamoDB event log (`SSE#<topic>` / `E#<ulid>`) is the distributor: publishers append, the streaming handler long-polls with an adaptive interval. `Last-Event-ID` replays from the log within a 24-hour window, which the reference never offered. Reversal cost: medium.

## D-9 — Swagger UI

Upstream serves the reference HTML verbatim (swagger-ui-dist from unpkg). In the product, docs are off in production unless `docs.swagger: true`. Reversal cost: trivial.

## D-10 — Claims webhook failure

Fails closed: a webhook error or timeout fails token issuance. The auth middleware uses a verification path that never calls the claims builder, so the webhook fires on token issuance only. Reversal cost: trivial.

Amended when it was wired (P3), on two points of fact:

- **There is no `CLAIMS_WEBHOOK_FAILED` code, and this port does not invent one.** The core already fails the mint — `Config.BuildTokenClaims` returning an error aborts `issueToken` — and the adapters answer a broken host hook with `HTTPErrInternal`: `500 {"error":"Internal server error"}`, deliberately code-less and deliberately describing nothing. The error envelope belongs to the shared wire layer every port in the family emits, so adding a code here would make this deployment answer something no sibling answers, for a failure a client cannot act on anyway. The behaviour D-10 asked for is exactly what ships; only the spelling in this entry was wrong.
- **`GET /me` deliberately does not fail closed.** It runs the builder too — its body is the profile and `customClaims` is rendered in it — but `Service.Me` logs a builder failure and leaves `customClaims` empty rather than failing the read. A read should not go dark because a mint-time hook is down, so a receiver outage costs logins and refreshes and leaves the profile answering. The middleware path runs the builder zero times, as the entry says.

Nothing was re-implemented for either point: cmd/auth builds the hook out of the core's own `StaticClaims`, `UserFieldClaims`, `ChainClaims` and `ClaimsWebhook`, and the tests verify the failure contract rather than producing it.

## D-11 — Delivery webhook

Synchronous within the request, bounded by `timeoutMs`. Moves to the SQS queue once the P7 event plane exists. Reversal cost: trivial.

Amended when it was wired (P2): the failure contract is each seam's own rather than "never fails the route", because the seams do not agree and the webhook must not make them. `POST /forgot-password` answers 200 whatever the receiver does, as it does with every other sender; the other four surface the reference's generic 500 and leave the minted token stored. The webhook also takes *all five* credential seams when its url is set — SES and SNS are not called for those routes at all — and `email.deliveryWebhook.secret` is required alongside the url (config-schema.md §1.5 addendum).

## D-12 — `first-user` admin policy

An atomic election item (`SETTINGS` / `adminFirstUser`, `attribute_not_exists`) written on the first admin login, instead of "position 0 of an unordered list". Reversal cost: low.

## D-13 — Runtime settings at login

As the reference: the settings store's `require2FA` is read where the reference reads it (`/2fa/disable` and the two-factor policy), and `emailVerificationMode` from the store is not consulted at login (`reference-issues.md` N36, documented rather than fixed). Reversal cost: low.

## D-14 — Rate limiter design

Fixed window counter per `RL#<scope>#<subject>#<window>` with one conditional `UpdateItem`; lockout and progressive delay on the credential-guessable scopes; `keyBy` in `ip|email|tenant`; fail-open on store errors with a metric; scope vocabulary is the eleven names in `internal/config/validate.go`. Reversal cost: low.

## D-15 — Backup codes

Out of scope: absent from the reference, the specs and the clients. Reversal cost: none.

## D-16 — Event plane

The core `Service` publishes to the in-process bus; the tools facade subscribes to `*` and performs the reference's fan-out order (telemetry → bus → SSE → webhooks). The product plugs EventBridge or SNS as the transport and SQS as the webhook deliverer. Reversal cost: low.

## D-17 — Templates from the artifact (2026-09-11)

`email.templatesDir` is read once, at cold start, and seeds only the ids and UI pages the template store does not already hold; a template saved through the store wins over the file of the same id, on this and on every later cold start. A Lambda has no writable filesystem and no deploy step that runs code, so the artifact is the only place a shipped template can live and cold start the only moment it can be read — and a runtime edit has to survive the next redeploy, or the admin API would be undone by every cold start. A directory that is missing or unreadable refuses to start in production, where the artifact is supposed to contain what the document names, and warns in development. Registered as the product deviation `templates-dir-only-seeds-absent-ids`. Reversal cost: low — "the directory always wins" is one branch in `seedTemplates`, but it would make a runtime edit unstable, which is why it is not the default.

## D-18 — The delivery webhook requires a secret

`email.deliveryWebhook` is a transport, not a notification: the core's `auth.NewDeliveryWebhook(url, secret)` (v0.4.0) is handed the magic link, the reset token, the verification token, the email-change token and the SMS code, and POSTs them to the operator's endpoint so a transport the product does not ship (Postmark, a queue, an on-premises relay) can carry them. The body therefore carries the credential itself, and the receiver has to be able to tell the product's POST from anyone else's — the core signs each request with `X-Webhook-Signature` only when a secret is set, and leaves the choice to the integrator. The product does not: a `deliveryWebhook.url` with no secret refuses to start, in every environment, as a refuse-to-start rule beside RS-1…RS-12. The secret is a secret-tagged knob like the JWT secrets (`{"secretsManager": …}`, `{"ssmParameter": …}`, or `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET`), never a value in the document. Not a wire deviation — the reference has no webhook to compare against; it replaces the reference's five send-callback functions (`config-schema.md` §3.8) — so it is recorded here rather than in a register. D-11's "synchronous, bounded by `timeoutMs`, never fails the route" still applies to the call. Reversal cost: trivial in code (drop one validation rule), but it would ship a product that mails credentials to an endpoint nothing authenticates, so it is not expected to be reversed.

## D-19 — The claims webhook requires a secret (2026-09-12)

`security.jwt.claimsWebhook` gains a `secret`, required whenever the url is set, on the same terms as D-18's and for a different reason. The spec specified this block as a url and a timeout (`config-schema.md` §1.1, §3.1) and the core's `auth.NewClaimsWebhook(url, secret)` accepts an empty secret, sending the request unsigned — the integrator's choice, which a library is right to leave open and a deployable product is not.

D-18's argument does not transfer: the claims request hands over no credential. Two others do, and either is sufficient.

- **The request body is the user's profile.** It is `PublicUser`, the same object `GET /me` renders — address, names, phone number, tenant, roles — for every login, every refresh and every `/me`. An unsigned receiver has no way to tell this deployment's question from anyone else's, so anything that can reach the endpoint can ask it about a user and read the answer; and a receiver that logs what it was asked accumulates the profile of everyone who logs in, keyed by nothing.
- **The answer decides what the token authorises.** Claims from this receiver go into the token every downstream consumer makes decisions on. Unsigned, the deployment cannot tell the configured receiver from anything that can answer on that address first — a DNS or routing compromise becomes a claims-injection primitive, bounded only by the seven session claims the core refuses to let any builder set.

So: a `claimsWebhook.url` with no secret refuses to start, in every environment, and a secret reference with no url is refused as the dead configuration it is. It is a secret-tagged knob (`{"secretsManager": …}`, `{"ssmParameter": …}`, or `AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET`), never a value in the document, and the SAM template passes it as `ClaimsWebhookSecretArn` with its own IAM statement scoped to that ARN. Not a wire deviation — the reference has no claims webhook to compare against, only the in-process `buildTokenPayload` callback this replaces — so it is recorded here rather than in a register.

Both webhooks now carry the same three fields, so `config.DeliveryWebhook` was folded back into `config.Webhook` rather than kept as a second identical struct.

Reversal cost: trivial in code (drop one validation rule), but it would ship a product that hands its users' profiles to an endpoint nothing authenticates and takes authorisation claims back from it, so it is not expected to be reversed.

## D-20 — `oauth.provisioning.onEmailMatch`, and why its default is `link` (2026-09-12)

The OAuth callback's hardest question has no knob in the extracted schema, because the reference never answers it: `findOrCreateUser` is abstract (`generic-oauth.strategy.ts:169-172`) and every integrator writes what happens when a provider authenticates somebody whose address an existing local account already holds. The imported core made it declarative (`OAuthProvisioning.OnEmailMatch`) with three modes, so the product's real choice was whether to expose it. It is exposed, as `oauth.provisioning.onEmailMatch` (`link` | `conflict` | `reject`, validated, default `link`), because the alternative was to hardcode a security posture no operator could see in their own document: linking by address is the account-takeover shape the reference's own store interface warns about — two providers can assert one address without representing one person (`user-store.interface.ts:105-119`) — and a deployment that admits `@gmail.com` addresses through a provider that does not verify them is one misconfiguration away from an unauthenticated sign-in as any user.

The default is `link` for the same reason every other default in this schema reproduces the reference: it is what a permissive `findOrCreateUser` does, what the family's demos do, and what the core does with no policy at all, so wiring the block changed no behaviour for anyone. `conflict` is the reference's own richer answer — it raises `OAUTH_ACCOUNT_CONFLICT`, stashes `(email, provider, providerAccountId)` and redirects to `/account-conflict`, where `/link-request` and `/link-verify` make the link only after an emailed token proves the address — and it is what a deployment holding anything sensitive should set. `reject` refuses outright, with no linking flow offered.

Not a wire deviation: all three outcomes are the core's, the conflict redirect is byte-for-byte the reference's, and the two refusals are already registered upstream as `oauth-provisioning-is-a-policy-not-a-function`. What is recorded here is the product decision to make the term configurable and to leave the permissive mode as the default. Reversal cost: low — changing the default is one line in `Defaults()` and one row in the defaults test — but it would change how existing deployments resolve an address collision, so it is a schema-version-worthy change rather than a tidy-up.

## D-21 — `tools.auth` has no default (2026-09-19)

An enabled tools block has to name who may reach `POST <tools>/track`, `POST <tools>/notify` and `GET <tools>/telemetry`: a document with `tools.enabled: true` and no `tools.auth` refuses to start (RS-16), naming the four spellings. The reference's default is the open door — `authMiddleware` unset leaves the router public (`src/router/tools.router.ts:135`) — and §1.14 and §3.7 recorded that as this product's default too, warned at deploy time. That was the wrong reading of "reproduce the reference": the imported core had already declined the same default (`tools-router-requires-an-explicit-guard-decision`) for the reason its tools file states — a configuration that silently degrades from guarded to open is the failure it exists to prevent — and the product's own house rule is that forgetting tightens rather than loosens. `none` stays available, by name and only by name, and warns at load and at cold start. Defaulting to `session` instead was rejected twice over: the posture decides whether a server-to-server caller can reach `track` at all, so a silent default is a silent `403` for the deployment that meant `apiKey`; and `session` is not a value safe to guess — `POST <prefix>/register` is always mounted, so under it any self-registered user reads the store-wide telemetry the bridge fills and attributes events to anyone (`config-reference.md` §17.6). For the same reason the SAM template's `ToolsAuth` defaults to `apiKey`, does not offer `none`, and says that its value overrides a `ConfigFile` document's. Not a wire deviation: which guard the host passes is the host's choice in both trees, and every route behind it is the core's. Reversal cost: one branch in `validateTools` and one row in the rules list, but it would reopen the door by omission, so it is not expected to be reversed.
