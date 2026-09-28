# awesome-lambda-auth

The serverless-native member of the [awesome-node-auth](https://github.com/nik2208/awesome-node-auth) family: an open-source, self-hosted alternative to AWS Cognito, deployed as a stack in your own AWS account. MIT, no per-MAU pricing, no phone-home.

Unlike the other ports in the family, this is **not a language port**: it imports the auth core from [awesome-go-auth](https://github.com/nik2208/awesome-go-auth) unchanged, keeps the wire contract byte-compatible with the reference, and replaces every long-lived-process assumption with a serverless-native primitive. It is a **deployable product** (configured by file and environment, extended through webhooks and OIDC), not a library you compile against.

## Status

The stack deploys and the two official clients, unmodified, register, log in, refresh with CSRF, enrol TOTP, complete a 2FA login and revoke sessions against it. What is wired today, what is still gated, and where the work is going is tracked in [docs/PROGRESS.md](docs/PROGRESS.md).

| Area | State |
|---|---|
| Event normalisation (`internal/lambdahttp`) | API Gateway HTTP v2 and REST v1, Function URL, ALB; multi-cookie round trips tested per shape |
| Declarative configuration (`internal/config`) | JSON document + `AWESOME_AUTH_*` environment, refuse-to-start rules RS-1…RS-12 plus the product rules `PHASE` and `IDENTITY`, secrets from Secrets Manager → SSM → env |
| Stores (`internal/store/dynamodb`) | users, sessions with refresh-token families, single-use tokens, TOTP, linked accounts, pending links, on one table with TTL |
| Credential delivery (`internal/integration/aws`) | SES for mail, SNS for SMS, behind the core's sender seams; or a signed delivery webhook that takes every credential seam instead |
| Email flows (`cmd/auth/email.go`) | `email.siteUrls` resolves every emailed link per request against the allowlist it forms with `http.cors.origins`; `email.templatesDir` seeds the template store from the artifact without ever overwriting a runtime edit |
| Token claims (`cmd/auth/claims.go`) | `security.jwt.extraClaims` maps user fields and constants into every minted token; `security.jwt.claimsWebhook` asks a signed https receiver for the rest and fails the mint closed when it cannot answer |
| Second factor (`cmd/auth/twofactor.go`) | `twoFactor.appName` is the issuer an authenticator app labels a TOTP enrolment with |
| OAuth (`cmd/auth/oauth.go`) | `oauth.providers` builds the registry — Google and GitHub over the core's presets, any other name as a generic provider with its own endpoints and a declarative `profileMap` — with signed state, PKCE S256 and a redirect allowlist RS-11 refuses to start without; `oauth.provisioning` decides create, link, conflict or refuse |
| Auth surface | every route `awesome-go-auth` mounts: register, login, refresh, logout, me (now carrying `loginProvider`), sessions, password and email flows, magic link, SMS OTP, TOTP, account linking |
| Identity provider (`cmd/auth/idp.go`) | OIDC issuer: JWKS, discovery, authorize, token, userinfo under the api prefix, signed by an AWS KMS asymmetric key (or a PEM), with additive key rotation and authorization codes in DynamoDB. Session tokens stay HS256 — see [docs/oidc.md](docs/oidc.md) |
| Resource server (`cmd/auth/idp.go`) | unmounts this deployment's whole credential surface, and builds an RS256 verifier for another issuer's tokens — stale-while-revalidate JWKS cache, exported as `App.ResourceServerGuard` for a host that embeds this package, mounted on nothing here. Refused alongside the identity provider (rule `IDENTITY`) |
| Documentation (`cmd/auth/docs.go`) | `docs.swagger` — `true`, `false` or `auto`, which is on outside production and off in it — mounts the adapter's `GET <prefix>/openapi.json` and `GET <prefix>/docs`, both unguarded as the reference registers them; `docs.basePath` moves what the document describes and never the mount. Both responses carry a `Content-Security-Policy`, because the reference's Swagger page loads an unpinned CDN bundle onto the auth origin — [docs/config-reference.md](docs/config-reference.md) §12 |
| Rate limiting (`cmd/auth/ratelimit.go`) | net-new to this product — the reference ships no limiter at all. On by default: 10 requests per 60-second window, keyed by account rather than by source address, over the five credential flows, refused with `429 RATE_LIMITED` and a `Retry-After`. The limit is a conditional DynamoDB write every execution environment shares; the in-process tier is a pre-filter in front of it and never the limit, and the whole thing fails open because its counter lives in the same table as the user store — [docs/config-reference.md](docs/config-reference.md) §14 |
| Admin console (`cmd/auth/admin.go`) | the reference's admin console, mounted by the adapter at `admin.basePath` (`/admin`) beside the auth routes and guarded by `admin.accessPolicy` — `is-admin-flag`, `rbac:<role>`, `permission:<perm>`, or `open` for a stack behind a network boundary; `first-user` is refused (RS-17). The five stores behind its tabs follow their `stores.enable` flags; uploads go to S3 (`ui.uploadDir` as `s3://…`) and are served back by the hosted UI under a sandboxing policy; the login is rate limited and does not enforce a second factor; `migrate backfill-users` fills the user directory on a table that predates it — [docs/config-reference.md](docs/config-reference.md) §16 |
| Infrastructure (`infra/sam`) | HTTP API + Lambda (`provided.al2023`, arm64) + DynamoDB + Secrets Manager, deployed with the plain AWS CLI |
| Observability (`infra/sam`, `cmd/auth/logging.go`) | Nine CloudWatch alarms — errors, throttles, duration approaching the timeout, concurrency, DynamoDB throttles and consumed capacity both ways, log ingestion — inside CloudWatch's always-free ten, with an SNS target that is a parameter and creates nothing when empty. Log retention is 14 days on an explicit group per function, enforced by `infra/sam/template_test.go` because a group Lambda creates for itself never expires. Structured JSON logs with a deny-list of credential keys and the caller's `X-Correlation-Id` on every line of a request and on every webhook it causes, read from the core's event-context carrier and never parsed twice — [docs/cost-model.md](docs/cost-model.md) |
| Contract suite (`test/contract`) | black-box, parametrised on a base URL, runs against this stack or the reference Express app |
| Examples | `examples/angular-client` (ng-awesome-node-auth from npm) and `examples/flutter-client` (awesome_node_auth_flutter from pub.dev), unmodified |

Configuration domains the schema accepts but the binary does not act on yet are **refused at start** (rule `PHASE`), never silently ignored. The list is `unwiredDomains()` in [internal/config/phases.go](internal/config/phases.go); at the time of writing: `tools`. `admin` is the latest to leave it: the console is mounted beside the api prefix from the `admin` block ([docs/config-reference.md](docs/config-reference.md) §16). Each lands with the phase that wires it. `rateLimit` is the latest to leave it, and the first whose behaviour has no counterpart upstream at all: the reference ships no limiter, so every default is this product's and an unconfigured deployment is now rate limited. `docs` left it in the round before: `docs.swagger` now decides whether the adapter mounts `GET <prefix>/openapi.json` and `GET <prefix>/docs`, and `auto` — the default — resolves against `deployment.environment`. `runtimeSettings` left it in the round before: the block is the boot-time seed of the settings store, and `runtimeSettings.require2fa` decides what `POST <prefix>/2fa/disable` answers. Six entries left it in the round before: `twoFactor`, `security.jwt.extraClaims` and `security.jwt.claimsWebhook` with the token-claims block; the whole `oauth` domain — `oauth.providers` and `oauth.provisioning`, secret prefix included — with the OAuth block; and `idProvider` and `resourceServer`, secret prefix included, with the identity surface. The whole `email` and `security` domains now load too; `email.siteUrls`, `email.templatesDir` and `email.deliveryWebhook` were the three before them.

## Configuration

Two sources, layered:

1. A JSON document, from `AWESOME_AUTH_CONFIG_FILE=<path>` or inline in `AWESOME_AUTH_CONFIG_JSON`. Neither set means defaults.
2. `AWESOME_AUTH_*` environment variables, one per knob, on top of the document. The SAM template sets only these.

Secrets are never values in the document. A secret-tagged knob is a reference (`{"secretsManager": "<arn>#<jsonKey>"}`, `{"ssmParameter": "<name>"}`, or its environment variable), resolved at cold start in that order; the template passes them as `AWESOME_AUTH_JWT_ACCESS_SECRET_SECRETSMANAGER` and friends. A plaintext secret in the document refuses to start.

What the binary reads, in the order it reads it, plus the `email` and `oauth` domains knob by knob, is in [docs/config-reference.md](docs/config-reference.md). The schema behind it — every default with its reference citation, and the refuse-to-start rules — is in [docs/spec/config-schema.md](docs/spec/config-schema.md).

## Toolchain

Nothing is installed on the host. Every tool runs in a pinned container against the bind-mounted repo:

```bash
./scripts/toolchain.sh go test -race ./...
```

Requires Docker (WSL2 on Windows). Module and build caches live in named volumes, so only source crosses the bind mount.

The DynamoDB store tests run against DynamoDB Local and skip when it is unreachable. To run them, start it on a Docker network and point the container at it by name:

```bash
docker network create awesome-auth-test
docker run -d --name ddblocal --network awesome-auth-test amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory -sharedDb
DYNAMODB_ENDPOINT=http://ddblocal:8000 TOOLCHAIN_NETWORK=awesome-auth-test ./scripts/toolchain.sh go test -race ./...
```

CI (`.github/workflows/go.yml`) runs the same gate with a DynamoDB Local service container, then builds the Lambda zip and enforces its size budget.

## Deploy

```bash
./scripts/build-lambda.sh                                   # dist/auth-lambda.zip, reproducible
./scripts/deploy.sh --profile <profile> --region <region>   # package + deploy with the AWS CLI, no SAM CLI
```

`--profile` and `--region` are required and have no defaults, on purpose. The template, its parameters, the IAM policy (written from the store's exact call list) and the measured cold-start numbers are documented in [infra/sam/README.md](infra/sam/README.md). `scripts/teardown.sh` removes the stack and names what outlives it.

## Verifying a deployment

```bash
AWESOME_AUTH_CONTRACT_BASE_URL=https://<api-id>.execute-api.<region>.amazonaws.com \
AWESOME_AUTH_CONTRACT_REQUIRE=register,csrf,secure-cookies,sessions,totp \
./scripts/toolchain.sh go test -count=1 -v ./test/contract/...
```

`REQUIRE` turns "capability absent" from a skip into a failure, so a deployment that lost a feature cannot pass by skipping it. See [test/contract/README.md](test/contract/README.md).

## Documents

| Document | Purpose |
|---|---|
| [docs/PROGRESS.md](docs/PROGRESS.md) | task board and per-block ledger of the build-out |
| [docs/deviations.md](docs/deviations.md) | index of the three deviation registers (product, store, core), pinned by a test |
| [docs/oidc.md](docs/oidc.md) | the OIDC surface: what identity-provider and resource-server mode serve, how a signing key is rotated, and what v1 deliberately does not do |
| [docs/spec/decisions.md](docs/spec/decisions.md) | decisions the reference does not settle, with reversal cost |
| [docs/spec/wire-contract.md](docs/spec/wire-contract.md) | the HTTP contract extracted from the reference source, which this port is forbidden to break |
| [docs/spec/config-schema.md](docs/spec/config-schema.md) | declarative configuration schema and refuse-to-start rules |
| [docs/spec/data-model.md](docs/spec/data-model.md) | DynamoDB single-table design, access patterns, conditional writes |
| [docs/spec/serverless-gap-analysis.md](docs/spec/serverless-gap-analysis.md) | per-module: survives, adapt, or re-architect under Lambda |
| [docs/spec/parity-gap-node-vs-go.md](docs/spec/parity-gap-node-vs-go.md) | verified capability diff between the reference and awesome-go-auth |
| [docs/spec/reference-issues.md](docs/spec/reference-issues.md) | doc-vs-code disagreements and defects found in the family |
| [docs/spec/recon-manifest.md](docs/spec/recon-manifest.md) | pinned commits and method; every spec claim is reproducible |
| [docs/spec/_extract/](docs/spec/_extract/) | the raw extraction the specs were built from |

## Family

| Repo | Role |
|---|---|
| [awesome-node-auth](https://github.com/nik2208/awesome-node-auth) | Reference implementation and source of truth |
| [awesome-go-auth](https://github.com/nik2208/awesome-go-auth) | Go port; the core this product imports |
| [awesome-rust-auth](https://github.com/nik2208/awesome-rust-auth) | Rust port |
| [awesome-python-auth](https://github.com/nik2208/awesome-python-auth) / [awesome-dart-auth](https://github.com/nik2208/awesome-dart-auth) | Python / Dart ports |
| [ng-awesome-node-auth](https://github.com/nik2208/ng-awesome-node-auth) / [awesome-node-auth-flutter](https://github.com/nik2208/awesome-node-auth-flutter) | Clients that must keep working unmodified |

License: MIT
