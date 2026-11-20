# The OIDC surface

This page is the specification of the one part of `awesome-lambda-auth` that has
no counterpart in the reference. Everything else in this product reproduces
`awesome-node-auth` including its quirks, because the family's shipped clients
are pinned to it; identity-provider mode is different, and the difference is
worth stating before anything else.

**In the reference, `idProvider` is RS256 signing and JWKS publication and
nothing else.** There is no `/authorize`, no `/token`, no `/userinfo` and no
discovery document anywhere in its source: the block exists so that another
service can verify tokens the reference signed
([parity-gap-node-vs-go.md](spec/parity-gap-node-vs-go.md) #27). The imported
core, `awesome-go-auth`, adds a small authorization server on top. So the JWKS
route below is a reproduction — down to its `Cache-Control` — and the other four
endpoints are net-new. No family client calls them, because in the reference they
do not exist.

Two consequences follow, and both are deliberate:

- The wire shapes of the four new endpoints are the core's and the RFCs', not
  the family's. In particular their error bodies are **not** the family's
  `{"error": …, "code": …}` envelope. §6 says exactly what they are.
- Enabling this changes nothing about the rest of the deployment. `/login`,
  `/refresh` and every other route answer byte for byte what they answered
  before ([decisions.md](spec/decisions.md) D-3).

---

## 1. What you get

With `idProvider.enabled: true` (or any key material configured — the schema's
`active` predicate is the reference's own), the deployment serves:

| Route | What it is |
|---|---|
| `GET <prefix>/.well-known/jwks.json` | the signing keys, as a JWKS document. The path is `idProvider.jwksPath`. **Reproduced from the reference**, including `Cache-Control: public, max-age=3600` |
| `GET <prefix>/.well-known/openid-configuration` | the discovery document |
| `GET/POST <prefix>/authorize` | the authorization endpoint: `GET` renders a minimal login form, `POST` authenticates and redirects with a code |
| `POST <prefix>/token` | the token endpoint: `authorization_code` grant, `client_secret_basic` or `client_secret_post` authentication, S256 PKCE (required of a public client), `redirect_uri` required, RFC 6749 §5.2 JSON refusals |
| `GET <prefix>/userinfo` | `sub`, `email`, `name` for a bearer token |

All five are mounted by the imported adapter, public and ahead of every
middleware — the JWKS document exactly where the reference registers it, the
other four at the core's own paths, which is where `(*auth.IDP).RegisterHandlers`
puts them too. None of the five is a route this product invented, and this
binary registers none of them itself.

The one path that arrangement costs a deployment is `<prefix>/jwks`, the core's
deprecated alias of the JWKS document: `RegisterHandlers` serves it, no adapter
does, and so it is not served here. `idpMountedEndpoints` in `cmd/auth/idp.go`
records why, and a test pins it.

## 2. The signing key

Two sources, and RS-4 allows exactly one
([config-schema.md](spec/config-schema.md) §1.10 addendum):

```jsonc
// production: a KMS asymmetric key. The private half never exists outside KMS.
{"idProvider": {"enabled": true, "kmsKeyId": "arn:aws:kms:…:key/…"}}

// the reference's own configuration: a PEM from a secret store.
{"idProvider": {"enabled": true, "privateKey": {"secretsManager": "…"}}}
```

**Why KMS is the production path.** A PEM is a value the function reads at cold
start and holds in memory for the life of the execution environment: anything
that can make the function emit a string — a log line, a stack trace, a
compromised dependency — takes the identity provider's identity with it, for as
long as the key lives. A KMS key cannot be exported. The function holds
`kms:Sign` and `kms:GetPublicKey` on the current key ARN, and `kms:GetPublicKey`
alone on the keys being retired (§3) — nothing else in the account, and nothing
at all that lets a retired key sign again. Every signature is a CloudTrail event,
and revoking the capability is an IAM edit rather than a key rotation.
`infra/sam/template.yaml` creates the key, scopes the policy to it, and states
its monthly cost.

**What leaves the process per signature: 32 bytes.** RS256 is RSASSA-PKCS1-v1_5
over the SHA-256 of the signing input, the core computes that digest itself, and
the signer sends `MessageType: DIGEST`. The token's header and claims — the
subject's id, their email — never reach AWS. The alternative, `MessageType: RAW`,
would put every token's payload into a KMS request and into whatever logs sit
between the function and the service.

**With no key at all**, in development only, the core generates an ephemeral
RSA-2048 key and the cold-start log says what that means: every token minted
becomes unverifiable at the next cold start, and two concurrent execution
environments never share a key, so a JWKS document fetched from one instance does
not describe the tokens another one signs. RS-4 refuses it in production.

## 3. Rotation

The `kid` is `base64url(sha256(SPKI DER))[:16]` — derived from the key material,
where the reference hardcodes `provisioner-key-1`. That is a registered
deviation (`idp-kid-derived-from-key-material`,
[deviations.md](deviations.md)) and it exists so that a rotation is additive:

1. Create the new key. Add the **old** key ARN to `idProvider.kmsPreviousKeyIds`
   and point `idProvider.kmsKeyId` at the new one. Deploy.
2. The JWKS document now publishes both, each under its own `kid`. New tokens
   name the new key; tokens minted before the deploy still name the old one and
   still verify.
3. One access-token lifetime later, drop the old ARN from
   `kmsPreviousKeyIds`. Deploy. Nothing in flight is affected.

**Step 1 is an IAM change as well as a configuration change**, and forgetting
that half is a failed deployment rather than a degraded one: the JWKS document is
built by calling `kms:GetPublicKey` on every retired id, at cold start, so an ARN
the function's policy does not cover fails the init with
`idProvider.kmsPreviousKeyIds: kms: get public key with key <arn> failed:
AccessDeniedException`. On the SAM stack the two halves are one parameter —
`IdpPreviousKmsKeyArns` sets `AWESOME_AUTH_IDP_KMS_PREVIOUS_KEY_IDS` **and** adds
the retired ARNs to the policy's `kms:GetPublicKey` resources — so there is
nothing to keep in sync. On a hand-rolled deployment, extend the policy first.
Retired keys never get `kms:Sign` back.

There is no window in which a token names a `kid` the document does not carry.
With a single constant `kid` the same rotation is a flag day: the document can
only ever describe one key, so the moment it changes, every token in flight
becomes unverifiable.

Retired keys sign nothing. They are published, in the order configured, after the
current key. A key id that resolves to the same public key as the current one is
refused at cold start rather than published twice under one `kid`.

## 4. Resource-server mode

The mirror image: `resourceServer.enabled` makes this deployment a consumer of
another issuer's tokens. It does two things.

**It unmounts the credential surface.** All nineteen routes that create, prove,
deliver or change a credential — `/register`, `/login`, `/refresh`, the password
and email flows, magic link, SMS, 2FA — answer 404. The reference unmounts six of
them and leaves the other thirteen mounted to fail at runtime against a database
that is not there; gating all nineteen is the core deviation
`resource-server-gates-all-credential-routes`
([reference-issues.md](spec/reference-issues.md) N26).

**It builds the RS256 verifier**, once, at cold start, with
`resourceServer.jwksCacheTtlMs` and `resourceServer.jwksFetchTimeoutMs` applied —
and exposes it as `App.ResourceServerGuard` rather than mounting it on the auth
routes. That is a deliberate line, and the reason is worth having: `/me` and the
account routes verify **this** instance's HS256 session and read its store, and
the commonest resource-server deployment is the hybrid — a full instance that
also accepts another issuer's bearer tokens — where those routes must keep
working exactly as they do. So the verifier guards the deployment's *own* routes,
which is what the reference's `createJwksAuthMiddleware` is for too.

**Nothing in this artifact consults that verifier.** `cmd/` holds one binary,
`auth`, and `infra/sam` deploys one function, whose surface is the imported
adapter's route table and nothing else — every route on it belongs to the core.
There is no authorizer binary here and the SAM template wires none, so in a
deployed stack this knob does exactly one thing: it removes nineteen routes. The
guard is an export, for a host that embeds this package and has routes of its own
to protect; mounting it in front of somebody else's API behind an API Gateway or
an ALB would be a second deliverable, and this block does not ship one. The
cold-start log line says so in those terms rather than announcing a verifier on
duty. It is still built at cold start, because a misconfigured JWKS URL is then a
failed deployment instead of a 401 on every request of whatever does eventually
mount it.

**Not together with identity-provider mode.** The two describe opposite
deployments and the combination is refused at cold start by rule `IDENTITY`,
which names both knob paths. The reason is the sentence above about the
credential surface: the IdP mounts `POST <prefix>/authorize`, which takes an email
and a password and performs a full login, and `POST <prefix>/token`, which hands
back this deployment's own session pair — so a stack with both would serve two
credential routes while every document here, and the knob's own description, says
it has none. A deployment that only wants to publish a signing key for others to
verify against is an identity provider with no clients, which §5 allows and warns
about; it is not a resource server.

The cache is stale-while-revalidate: a document past its TTL is still served
while a refresh runs behind it, and a refresh that fails changes nothing, so an
issuer that is briefly unreachable does not take this deployment down with it. An
unknown `kid` forces at most one refetch per `MinRefreshInterval`, which is what
keeps a flood of junk tokens from turning this server into a client of its own
issuer (`jwks-unknown-kid-refetch-is-rate-limited`).

One knob the schema marks optional is required anyway:
`security.jwt.accessTokenSecret`. RS-1 exempts the signing secrets in
resource-server mode because the deployment mints nothing; the auth core requires
one to build at all, and the verifier's cookie path verifies this instance's own
access-token cookie with it. `cmd/auth` refuses at cold start naming that knob,
rather than letting the core answer "secret must be at least 32 characters" for a
knob the operator was told to leave out.

## 5. Clients

A client is configured, never registered dynamically:

```jsonc
{"idProvider": {
  "clients": [{
    "clientId": "console",
    "name": "Ops console",
    "clientSecret": {"secretsManager": "awesome-auth/prod/idp-console"},
    "redirectUris": ["https://console.example.com/callback"]
  }]
}}
```

File-only, because a client is an array of objects and the `AWESOME_AUTH_*` layer
cannot express one. The secret is an ordinary secret knob, keyed by client id
rather than by position in the list —
`AWESOME_AUTH_IDP_CLIENT_CONSOLE_SECRET`, or its `_SECRETSMANAGER` form — so
inserting a client at the top of the list does not silently move every other
client's variable.

Validation refuses, at cold start: a client with no secret (the token endpoint
compares the posted `client_secret` against the configured one, and an empty
configured value is satisfied by an empty posted one), a client with no redirect
URI (the authorization endpoint matches `redirect_uri` against an exact-match
allowlist, so every request would be refused), a duplicate client id (the registry
is a map and the last entry would silently win), and a redirect URI that is
neither https nor http on a loopback host (the authorization code travels in that
URL's query string; the loopback exception is RFC 8252 §7.3).

**Identity-provider mode with no clients is legitimate**, and is warned about
rather than refused: a deployment may enable it purely to publish a signing key
for a resource server elsewhere in the estate, which is precisely what the
reference's `idProvider` block is for.

## 6. What this deliberately does not do

Each of these is a decision, not an omission.

- **No `refresh_token` from `/token`.** The response carries an HS256 session
  access token and an RS256 `id_token`, and nothing a relying party can refresh
  with. Since awesome-go-auth v0.13.0 the session's own refresh token stays
  inside the session: it is no longer in the response, so a relying party cannot
  spend it at `POST <prefix>/refresh` or `POST <prefix>/logout` as it could
  before. The core's rotating `refresh_token` grant for `offline_access` is
  turned off here (`DisableRefreshTokenGrant`, `cmd/auth/idp.go`), because with
  no shared store it keeps its tokens in one execution environment's memory. It
  comes back with a DynamoDB `IDPRefreshTokenStore`. Until then a relying party
  runs `/authorize` again when its access token expires (D-3).
- **No dynamic client registration** (RFC 7591), and no client-registration
  endpoint. Clients come from the configuration document, which means adding one
  is a deploy. That is the right trade for a stack whose relying parties are
  counted in single digits, and it keeps an unauthenticated write path out of the
  surface entirely.
- **No PKCE verification yet.** `code_challenge` and `code_challenge_method` are
  recorded with the authorization code and handed back at redemption; the core
  does not yet check them. The store persists them precisely so that it can start
  to without a schema change. Until it does, a public client gains nothing from
  sending them — use a confidential client with a secret.
- **No consent screen, no scope enforcement.** `scope` is recorded and not acted
  on; the `id_token` carries `sub`, `aud`, `nonce`, `email` and the two
  timestamps whatever was asked for.
- **No `client_secret_basic`, no `private_key_jwt`, no `none`.** The discovery
  document advertises `client_secret_post` and that is the only method accepted.
- **No family error envelope on the four new endpoints.** They answer the core's
  own bodies — a `400` naming `invalid_grant` for a code nobody issued, a `401`
  naming `invalid_client`, a `400` for an unknown client at `/authorize` — rather
  than `{"error": …, "code": …}`. This is the documented boundary of the family
  contract: those endpoints have no family client to keep compatible, and the
  clients they do have read RFC 6749 shapes. The contract suite pins the status
  and the `invalid_grant` token while accepting either the plain-text body or the
  RFC 6749 JSON object, so an upstream change to the richer shape is not a
  regression (`test/contract/cases_idp_test.go`).
- **No multi-tenant issuer.** One deployment, one issuer, one key set.

## 7. Operating it

**Authorization codes live in the store, not in memory.** The core's default is a
process-local map, and its own documentation says why that is not enough here: on
Lambda `/authorize` and `/token` routinely land in different execution
environments, so a code minted by one would be unknown to the other and `/token`
would answer `invalid_grant` for every flow that crossed instances. The DynamoDB
store keeps them at `OIDC#<sha256(code)>`
([data-model.md](spec/data-model.md) §1.7); redemption is a conditional delete,
so exactly one of any number of concurrent redemptions wins. A code that was
never issued, one already redeemed and one past its deadline all answer the same
thing, because any difference between them is an oracle for somebody holding a
code they should not have.

**The issuer must be the URL the discovery document is served from.** Set
`idProvider.issuer` when the deployment is reached at anything other than
`deployment.publicUrl` + the api prefix, which is what it derives to. On a raw
`execute-api` URL the function cannot know its own endpoint — the template
explains the circular dependency — so deploy once, read the `ApiEndpoint` output,
and set `IdpIssuer`. The stack's `IssuerUrl` and `JwksUrl` outputs are what to
configure a relying party with.

**What to watch.** `kms:Sign` throttling (the signature is on the request path of
every token), the JWKS fetch timeout in resource-server mode, and the cold-start
log line `identity provider wired`, which names the issuer, the key source, the
`kid`, how many keys are published and how many clients are registered.
