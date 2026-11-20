# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The project has not tagged a release yet; until it does, every change is listed
under [Unreleased].

## [Unreleased]

### Added

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
  see the request, and its name is on the logging deny-list. The secret is
  read at cold start — a missing, unreadable or unusable value (shorter than
  32 characters, or outside visible ASCII) refuses to start — and re-read
  every five minutes, so a rotation needs no redeploy; a failed re-read keeps
  the values already read. Variables
  `AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN`, `..._HEADER` and
  `..._EXEMPT_HEALTHZ`; SAM parameters `OriginVerifySecretArn`,
  `OriginVerifyHeader` and `OriginVerifyExemptHealthz`, with a scoped
  `secretsmanager:GetSecretValue` on both roles and a Rule refusing the check
  beside `EnableCloudFront`, whose distribution does not send the header.
  New product deviation `origin-verify-refusal-is-a-bare-403`;
  `docs/config-reference.md` §19.
