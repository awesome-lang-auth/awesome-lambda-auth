# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The project has not tagged a release yet; until it does, every change is listed
under [Unreleased].

## [Unreleased]

### Added

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
