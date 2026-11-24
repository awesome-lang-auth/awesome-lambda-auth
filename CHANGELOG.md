# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The project has not tagged a release yet; until it does, every change is listed
under [Unreleased].

## [Unreleased]

### Added

- **The four options of `awesome-go-auth` `v0.16.0` are configurable**, each off
  or at the core's default unless set, so a document that sets none of them
  builds what the previous pin built (`docs/config-reference.md` §5.5, §7.4,
  §22). None has a SAM parameter: set them in the `ConfigFile`, or through the
  variable.
  - `email.languages` (`AWESOME_AUTH_EMAIL_LANGUAGES`, comma separated) — the
    languages a request's `emailLang` may select for its mail; anything else
    reaches the sender as no language. Each entry is held to the core's
    language-tag shape and refused at load by index.
  - `security.forgotPassword.minResponseMs`
    (`AWESOME_AUTH_SECURITY_FORGOT_PASSWORD_MIN_RESPONSE_MS`, 0–5000) — every
    answer of `POST <prefix>/forgot-password` held to a floor, so the time no
    longer tells a known address from an unknown one. Warned whenever on — held
    invocations cost concurrency the per-address limiter does not bound, so a
    per-client limit or reserved concurrency belongs in front — and when it is
    below the delivery webhook's timeout plus 250 ms, or in front of SES.
  - `twoFactor.enrolmentTokenTtlMinutes`
    (`AWESOME_AUTH_2FA_ENROLMENT_TOKEN_TTL_MINUTES`, `0` or 1–30) — the
    enrolment token's lifetime under `twoFactor.enrolOnLogin`, refused without
    it. Warned above five minutes: a copy of the token is worth a session for as
    long as it lives, and the factor's secret beyond that.
  - `sessions.revokeOnPasswordReset`
    (`AWESOME_AUTH_SESSIONS_REVOKE_ON_PASSWORD_RESET`) — a successful reset ends
    every session of the account. Refused at load under `STORE` on a driver
    that cannot end every session of an account (`postgres`).
- **The DynamoDB store implements `auth.UserSessionRevoker`** with a
  per-account session epoch: one item, `USER#<t>#<u> / EPOCH`, that a revoking
  reset raises with one write, stamped on every new session and honoured
  wherever a session is read (refresh, lookup by id, both listings, the check
  after a rotation). It reaches every session whose creation had returned
  before the reset, whatever the account's count and whatever GSI1 has caught up
  with, and it orders by a counter of the store's own rather than a clock. **The
  reads are paid with the option off too** — one consistent read per session
  created, one item more per refresh read, one read after each rotation, one per
  lookup by id (every protected request under `sessions.checkOn: allcalls`) —
  because a marker that stopped being read when the option was turned off
  would bring ended sessions back (`docs/cost-model.md` §2.9). **A rollback to a
  build before this one ignores the epoch**: a session a reset ended works again
  there until it expires. The store also keeps `AuthCode.Credential` on the
  authorization-code item, which `/token` checks under the option, and its
  `ClearResetToken` succeeds with nothing outstanding, through the migration
  wrapper too.

- **Staff invitations** (awesome-go-auth **v0.15.0**; `invitations.enabled`, off
  by default; `AWESOME_AUTH_INVITATIONS_ENABLED`; SAM `InvitationsEnabled`). How a
  closed realm gets its accounts over HTTP: an administrator — or a back office
  through `admin.machineAccess` — calls `POST <admin>/api/users/invitations`
  `{email, role?, tenantId?, metadata?, emailLang?}`, which creates a pending
  account (no password, address unverified) and a single-use token valid
  `invitations.ttl` (`72h` by default, at most `30d`); `GET` lists the outstanding
  invitations and `DELETE <admin>/api/users/invitations/{id}` revokes one, taking
  its account with it if nobody used it. The invitee redeems the token once at the
  public `POST <prefix>/invitations/accept` `{token, password}` — mounted under
  `registration.closed` too — which sets the password, marks the address verified
  and answers what the login would: under `twoFactor.required` the
  `2FA_SETUP_REQUIRED` challenge, whose `tempToken` enrols TOTP and opens the
  session with `twoFactor.enrolOnLogin`. `invitations.reinvite` lets a
  still-pending address be invited again. The token travels by the transport that
  carries the other credential mails — the mailer (the reference's `invitation`
  template) or the delivery webhook (kind `invitation`) — or, with neither,
  `admin.revealInvitationToken` hands it to the admin caller (see Security).
  The loader refuses invitations without the console, behind an open console
  (`admin.accessPolicy: open`), in resource-server mode, or with no way to
  deliver a token. It warns about invitations under `twoFactor.required`
  without `twoFactor.enrolOnLogin`. That realm loads, but no invitee can
  enrol alone: each waits for an out-of-band enrolment after accepting, and
  enrolling before the acceptance makes it spend and refuse the token. The
  SAM template refuses at changeset time every one of these refusals that its
  parameters reach: six Rules, and an `InvitationsTtl` pattern that admits
  `1m` to `30d`. A mistyped parameter then fails the changeset, not every
  cold start (`docs/config-reference.md` §21.1).
- **DynamoDB `InvitationStore`** (`internal/store/dynamodb/invitations.go`) in
  the single table: `INV#<id>` (the record; the token's SHA-256 only),
  `INVTOKEN#<hash>` (the pointer the consume finds it by) and
  `INVUSER#<userId>` (one membership item per pending invitation — the
  consistent per-user read a re-invitation, a revocation and `/forgot-password`
  depend on), with the pending listing on the sparse GSI1 partition `INVITATION`.
  Consume, revoke and release are each one transaction whose condition carries the
  whole state, so of any number of concurrent accepts exactly one wins. A pending
  invitation carries no `ttl`, expired or not, so DynamoDB TTL never reaps one:
  only the transaction that ends it (accept or revoke) gives the record a `ttl`,
  30 days past its expiry or its end, whichever is later, and deletes the token
  pointer and the membership item. No new IAM action: the existing
  `AuthTableItems` and `AuthTableIndexQuery` grants cover every call. The user
  store reads the acceptance depends on (`GetUserByID`, `GetUserByEmail`) were
  already `ConsistentRead`.
- **`rateLimit.scope` accepts `accept-invitation`**: `POST
  <prefix>/invitations/accept`, keyed by client address like `reset-password`.
  It is not in the default scope, so a realm that turns invitations on names
  it (`docs/config-reference.md` §21.6). The SAM template has no scope
  parameter, so that is done in `ConfigFile`. The token cannot be guessed. The
  budget bounds a flood from one address, each call of which costs a
  consistent read before the token is known to be bad.

- **Closed registration** (`registration.closed`, off by default;
  `AWESOME_AUTH_REGISTRATION_CLOSED`; SAM `ClosedRegistration`).
  `POST <prefix>/register` is not mounted and answers `404`, `GET <prefix>/ui/config`
  reports `features.register: false`, and the served OpenAPI document leaves the
  path out. New refuse-to-start rule **RS-19**: a closed realm beside an OAuth
  provider whose callback still creates accounts for anyone
  (`oauth.provisioning.autoCreate`, on by default, with no `allowedEmailDomains`),
  or narrowed by a domain list while `oauth.provisioning.requireVerifiedEmail` is
  off — the domain is matched on the address the provider asserts, so without
  verification it narrows nothing; with both it loads and warns. The SAM Rule
  `ClosedRegistrationRefusesOAuthSignUp` refuses the same at changeset time when no
  `ConfigFile` is supplied. New refuse-to-start rule **RS-21**: a closed realm
  beside `stores.migration.mode: dual-read`, which creates the local account for
  any address the migration source holds the first time a login or a password
  reset names it, without reading whether the source still has the user enabled
  or confirmed; the SAM Rule `ClosedRegistrationRefusesDualRead` refuses it at
  changeset time. No route creates an account on a closed realm — the
  admin console has none — so accounts come from `cmd/migrate`, a domain-narrowed
  OAuth callback or a tool on the store. The earlier advice to keep registration
  open and put an `AWS_IAM` route for `POST <prefix>/register` in front of the
  function is withdrawn: the function serves percent-encoded spellings of that
  path (`/auth/%72egister`), and whether API Gateway routes them to the IAM route
  is unverified (`docs/config-reference.md` §20).
- **A TOTP code required of every session** (`twoFactor.required`, off by
  default; `AWESOME_AUTH_2FA_REQUIRED`; SAM `TwoFactorRequired`). TOTP is the only
  second factor under the policy. A password login opens no session: an account
  with TOTP gets the challenge, which offers `totp` alone; an account without it
  gets `403 {"requires2FASetup":true,"tempToken":…,"code":"2FA_SETUP_REQUIRED"}`,
  whatever transports are wired; `POST <prefix>/2fa/disable` is refused. The
  emailed link and the texted code are not second factors: the magic-link and
  SMS-code senders are not handed to the core (`GET <prefix>/ui/config` reports
  both off), and `/magic-link/{send,verify}` and `/sms/{send,verify}` answer
  `403 2FA_REQUIRED` in every mode, the step-up (`mode: "2fa"`) included — so a
  phone number never opens a session on its own, and a mailbox, which also
  receives the reset link, opens one only under `twoFactor.enrolOnLogin`, for an
  account that has not enrolled TOTP yet (trust on first use, warned), or by
  guessing the TOTP code of one that has, which `twoFactor.lockout` holds to 10
  wrong codes per account per day by default (below). The
  password reset still works and opens no session; the next login still asks
  for TOTP. `/link-verify` with `loginAfterLinking`
  answers the same `403` (linking alone works as before), and `POST <admin>/login`
  answers `404` — the console admits a session from `POST <prefix>/login` and its
  TOTP code, and machine access (product deviation
  `two-factor-required-refuses-one-factor-sign-ins`). New refuse-to-start rule
  **RS-20**: the policy beside `oauth.providers` (the callback opens a session with
  no second-factor step), or, on a mounted console, beside `admin.rootUser`,
  `admin.bootstrapSecret` or `admin.accessPolicy: open`; SAM Rules
  `TwoFactorRequiredRefusesOAuthSignIn` and `TwoFactorRequiredRefusesTheRootUser`
  (the template offers no open console). The loader warns when the policy meets a
  mailer, the delivery webhook or an SMS transport, saying what is refused and
  what the transport still carries, and when it meets the identity provider,
  whose `/authorize` then refuses every account. Not retroactive: sessions opened
  before it is switched on keep refreshing, so rotate the refresh secret in the
  same deploy. Distinct from `runtimeSettings.require2fa`, which reaches
  `/2fa/disable` alone (`docs/config-reference.md` §7.1,
  `docs/spec/decisions.md` D-27).
- **Forced enrolment at login** (`twoFactor.enrolOnLogin`, off by default;
  `AWESOME_AUTH_2FA_ENROL_ON_LOGIN`; SAM `TwoFactorEnrolOnLogin`). The
  `2FA_SETUP_REQUIRED` token enrols TOTP through `/2fa/setup` and
  `/2fa/verify-setup`, which opens the session. Trust on first use: the loader
  warns whenever it is on, and, with the reset mail wired, that the mailbox alone
  can set the password of an account that has not enrolled yet and then bind the
  factor (`docs/config-reference.md` §7.2).
- **Machine access to the admin API** (`admin.machineAccess.iam.principals`;
  `AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS`; SAM
  `AdminMachinePrincipalArns`, empty by default). IAM roles and users admitted to
  every guarded admin route with no session, when API Gateway verified the caller
  on an `AWS_IAM` route; a role matches every session of it. The SAM template
  creates the route on an internal HTTP API of its own, `AdminMachineApi`
  (`ANY /admin/{proxy+}`), that CloudFront never routes, with outputs
  `AdminMachineApiEndpoint` and `AdminMachineApiInvokeArn` and the Rule
  `AdminMachineAccessNeedsTheConsole`. Each grant is audited as
  `identity.admin.machine.access`. The trust boundary is `lambda:InvokeFunction` on
  the auth function — whoever may invoke it directly can forge the IAM caller —
  so keep that permission to API Gateway alone. `AdminMachinePrincipalArns`'
  `AllowedPattern` is the loader's grammar, so a value the function would refuse
  is refused at changeset time. It does not lift `http.originVerify`: with that
  on, a machine caller sends the front door's header too; whether to exempt the
  internal API instead is an open owner decision (`docs/config-reference.md`
  §16.9, `docs/spec/decisions.md` D-26).
- **Contract suite realm modes.** `AWESOME_AUTH_CONTRACT_REGISTRATION=closed` and
  `AWESOME_AUTH_CONTRACT_2FA=required` declare an invite-only realm, checked through
  a declared, enrolled account (`AWESOME_AUTH_CONTRACT_REALM_EMAIL`, `_PASSWORD`,
  `_TOTP_SECRET`); new capabilities `registration-closed`, `2fa-required`,
  `2fa-enrol-on-login`, and eight cases, two of them the one-factor sign-ins the
  policy refuses (`test/contract/README.md`, *Realm modes*).

- **Origin verification** (`http.originVerify`, off by default). With
  `http.originVerify.secretArn` naming a Secrets Manager secret, the auth
  function and the SSE function refuse every request that does not carry
  exactly one value of `http.originVerify.header` (default `X-Origin-Verify`)
  equal to the secret's `AWSCURRENT` or `AWSPREVIOUS` value. The refusal is a
  bare `403` — no body, no headers — written by the outermost handler, before
  the CORS layer (preflights included), the rate limiters, the access log and
  every route; `GET /healthz` is checked too unless
  `http.originVerify.exemptHealthz` is `true`. The value is compared as a
  SHA-256 digest in constant time, the header is removed before the routes
  see the request — from its headers and from the raw Lambda event the
  request carries for handlers (`lambdahttp.EventFrom`, via the new
  `lambdahttp.WithoutEventHeader`) — and its name is on the logging
  deny-list. The secret is read at cold start — a missing, unreadable or
  unusable value (shorter than 32 characters, or outside visible ASCII)
  refuses to start — and re-read every five minutes, so a rotation needs no
  redeploy; a failed re-read keeps the values already read, which means a
  value the last rotation retired stays accepted while re-reads fail: each
  failure is a WARN, and from the third in a row an ERROR with
  `consecutiveFailures` to alarm on (§19.3). The header may not name one the
  auth surface, a proxy or the platform sets (`Authorization`, `Cookie`,
  `X-Forwarded-For`, `Forwarded`, `X-Amzn-Trace-Id`, `Accept-Language` and
  others). Variables
  `AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN`, `..._HEADER` and
  `..._EXEMPT_HEALTHZ`; SAM parameters `OriginVerifySecretArn`,
  `OriginVerifyHeader` and `OriginVerifyExemptHealthz`, with a scoped
  `secretsmanager:GetSecretValue` on both roles and a Rule refusing the check
  beside `EnableCloudFront`, whose distribution does not send the header.
  New product deviation `origin-verify-refusal-is-a-bare-403`;
  `docs/config-reference.md` §19.

### Changed

- **BREAKING — refresh tokens are signed with `security.jwt.refreshTokenSecret`,
  and the deploy that brings this signs every session out once.** RS-1 has
  always required a distinct refresh secret, but nothing signed with it: the
  imported core fell back to the access secret (`refresh-secret-falls-back-to-secret`)
  and the cold-start log reported the knob as unwired. It now reaches the core
  (`auth.WithRefreshSecret`), so every refresh token outstanding when the new
  release starts serving — signed with the access secret — is refused with `401`,
  and each client signs in again once its access token expires (15 minutes by
  default). Rolling back is a second sign-out. Afterwards a component holding the
  access secret can no longer mint refresh tokens, and the refresh secret rotates
  on its own (`docs/config-reference.md` §3.1, `docs/spec/decisions.md` D-25). A
  resource server is not affected: it verifies no refresh token, so its refresh
  secret is neither checked nor wired, and one shorter than 32 characters still
  starts (the cold start reports it as unwired).
- **Pinned to `awesome-go-auth` `v0.16.0`** (password reset and login
  hardening). Four changes act on upgrade, with no configuration change:
  `POST <prefix>/forgot-password` sends before it stores, so a refused or failed
  delivery no longer kills the link mailed before it (a sender that spends the
  token from inside the call now gets `ErrInvalidToken`); the ten public
  credential routes (`/forgot-password`, `/reset-password`, `/magic-link/send`,
  `/magic-link/verify`, `/sms/send`, `/sms/verify`, `/change-email/confirm`,
  `/invitations/accept`, `/link-request`, `/link-verify`) answer a body over
  16 KiB with `413 BODY_TOO_LARGE` before anything reads it, the rate limiter
  included; `POST <prefix>/change-password` ends an outstanding reset link; and
  every refused password login — an unknown address's included — runs one
  bcrypt comparison at `security.password.bcryptSaltRounds`, on
  `POST <prefix>/login`, the identity provider's login form and
  `POST <admin>/login` alike, so the answer's time no longer tells which
  addresses have accounts. **That last one costs CPU per refused login, and the
  default `rateLimit` (`keyBy: email`) does not bound it: every new address is
  a budget of its own. Put a per-client limit in front of the login routes — a
  WAF rate rule — or a ceiling on the function (`ReservedConcurrentExecutions`)
  before taking this release to a deployment that is reachable from the
  internet.** Three core deviations are
  indexed: `change-password-ends-the-reset-link`,
  `credential-route-bodies-are-bounded` and `reset-password-can-revoke-sessions`
  (opt-in: `sessions.revokeOnPasswordReset`, see Added), and `forgot-password-succeeds-on-delivery-failure`
  says what a failed send now leaves behind.
- **Pinned to `awesome-go-auth` `v0.14.0`** (closed registration, enforced second
  factor with opt-in forced enrolment, admin machine access). Two core deviations
  are indexed, `forced-enrolment-opens-a-session` and
  `admin-machine-access-is-a-host-seam`.
- **BREAKING (security) — the console's user writes reach every tenant.** With
  the pin, `DELETE <admin>/api/users/{id}` and `POST <admin>/users/{id}/promote`
  (`method=flag`) resolve the user's tenant through the lookup the detail route
  already used, so they reach a user stored under a tenant where they answered
  `500`. This widens what an administrator can write with no configuration
  change: a policy that admits per-tenant administrators — `is-admin-flag` on a
  tenant's row, or `rbac:<role>` held in one tenant — now lets them delete and
  promote across every tenant. **A deployment with per-tenant administrators
  reads `docs/config-reference.md` §16.4 before upgrading.**

### Security

- **`admin.revealInvitationToken` moves the trust an invitation rests on.**
  Accepting marks the address verified because the token reached that mailbox; a
  revealed token reaches whoever called the admin API instead — a machine
  principal, its logs, the channel it forwards the link through. It is off by
  default, refused beside a mailer or the delivery webhook, refused without
  `invitations.enabled`, and the loader warns whenever it is on.
- **Invitations are refused behind an open console.** Under
  `admin.accessPolicy: open` the invite route admits anonymous callers. Anyone
  could invite their own mailbox with a role of their choosing, accept the
  invitation and sign in, which turns `registration.closed` into
  self-registration. The loader refuses `invitations.enabled` there.
- **An expired invitation nobody revoked keeps reserving its account** — listed
  as `expired`, revocable, its account passwordless and unverified, reachable by
  magic link — until it is revoked; no store lets it lapse by itself. An offer
  that is meant to lapse is revoked (`DELETE <admin>/api/users/invitations/{id}`,
  which also removes the untouched account), not left to expire.

- **Counting windows have a one-year ceiling.** `twoFactor.lockout.windowSeconds` and `rateLimit.windowSeconds` above 31,536,000 seconds are refused at start: a window is multiplied by `time.Second`, and a value above ~292 years overflowed and turned the cap into a sub-second window.
- **Rate-limit subject canonicalisation** (`rateLimit.keyBy: email`, the
  default). The limiter read a request's subject from the body by rules of its
  own rather than the way the route reads the same body, so a request could be
  counted against a different subject from the one the route then acted on,
  and a per-account or per-challenge budget did not reliably bound the
  requests made against that account or challenge. The limiter now decodes the
  body with the routes' own decoder (`encoding/json`, the first JSON value,
  into the routes' own member names) and chooses the member the way each route
  does, `mode` included, on every route it reads a body on: `POST
  <prefix>/login`, `/register`, `/forgot-password`, `/magic-link/send`,
  `/magic-link/verify`, `/sms/send`, `/sms/verify` and `/2fa/verify`, and
  `POST <admin>/login`. It reads the body to the end of that first value, as
  the route does, rather than at most 8 KiB of it. Two subjects change with
  it: `POST <prefix>/sms/send` without an email is now keyed by its `userId`,
  where it was keyed by the client address, and `POST
  <prefix>/magic-link/verify` outside `mode: "2fa"` by the client address
  whatever else its body holds. `keyBy: ip`, the address fallback and the
  response are unchanged. Deployments on the default `keyBy` should redeploy;
  no configuration change is needed. `docs/config-reference.md` §14.1–14.2.
- **Failed second-factor checks are capped per account** (`twoFactor.lockout`,
  on by default; `AWESOME_AUTH_2FA_LOCKOUT_MAX_FAILURES`,
  `AWESOME_AUTH_2FA_LOCKOUT_WINDOW_SECONDS`). The `rateLimit` budget of
  `POST <prefix>/2fa/verify` is per challenge, and every login mints a new
  challenge with a new budget, so an account's TOTP code could be guessed at
  some 500 times a minute by logging in again and again — under
  `twoFactor.required` with the reset mail wired, from the mailbox alone. The
  checks are now also counted against the account the token names, read only
  after the core has verified the token's signature, type and lifetime, across
  every challenge, login and source address: `POST <prefix>/2fa/verify`,
  `/magic-link/verify` and `/sms/verify` in `mode: "2fa"`, and
  `/2fa/verify-setup` with an enrolment token. Each check is reserved on the
  shared counter before it runs, so concurrent guesses cannot slip under the
  cap, and a success clears the count. Past `maxFailures` (default `10`) in a
  window of `windowSeconds` (default `86400`, turning at 00:00 UTC) the check
  answers the rate limiter's `429` with `Retry-After` until the window ends:
  about 310 wrong codes a month at most, a chance of about 1 in 1 000 against
  a code the core accepts at three time steps. A token that does not verify is
  counted against nobody, so a forged one cannot lock anyone out. Its own
  switch, independent of `rateLimit.enabled`; `maxFailures: 0` turns it off,
  and the cold start warns when it is off. The DynamoDB store gains
  `ResetRateLimit` (one `DeleteItem`, already granted). `docs/config-reference.md`
  §7.3.
