package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
	"github.com/nik2208/awesome-go-auth/adapter/nethttp"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// The identity surface: idProvider, which makes this deployment an OIDC issuer,
// and resourceServer, which makes it a consumer of somebody else's. Together
// they are the P5 block of the schema, and internal/config/phases.go no longer
// refuses either.
//
// Never both at once: the two describe opposite deployments, and the
// combination is refused at cold start by the IDENTITY rule
// (internal/config/rules.go, checkIdentityModeConflict). Resource-server mode
// unmounts every route that can take a credential; identity-provider mode
// mounts POST <prefix>/authorize, which takes an email and a password and logs
// the user in. Mounted together, the knob that promises no password can be
// presented here would serve one that takes one, and every document in this
// product says the opposite. So the code below may assume that at most one of
// the two is active.
//
// ── what identity-provider mode is, and is not ───────────────────────────────
//
// In the reference, `idProvider` is RS256 signing plus JWKS publication and
// nothing else: there is no /authorize, no /token, no /userinfo and no discovery
// document anywhere in src/ (parity-gap-node-vs-go.md #27). The imported core
// adds all four, so this port has strictly more surface than the reference here
// — which is the one place in the product where that is true, and it is net-new
// rather than divergent: no family client calls these endpoints, because in the
// reference they do not exist. docs/oidc.md is the spec for the addition and
// says what it deliberately does not do.
//
// What does NOT change is the session pair. /login and /refresh keep issuing the
// HS256 tokens every family client reads, and so does the OIDC token endpoint
// (the core's /token answers with newSessionTokens plus an RS256 id_token). That
// is decision D-3, and it is the reference's own posture: its
// generateIdProviderTokenPair is called from nothing in src/ (reference-issues
// N35). Enabling the IdP adds an issuer; it does not re-sign the product.
//
// ── where the signing key lives ──────────────────────────────────────────────
//
// Two sources, and RS-4 allows exactly one:
//
//   - idProvider.kmsKeyId — an AWS KMS asymmetric key. The function holds
//     kms:Sign on one key ARN and can never read the key itself, so a leaked log
//     line, a dumped environment or a compromised dependency cannot take the
//     issuer's identity with it. This is the production path
//     (internal/integration/aws/kms.go).
//   - idProvider.privateKey — a PEM from Secrets Manager, which is the
//     reference's own configuration and what a stack without a KMS key uses.
//
// With neither, in development only, the core generates an ephemeral RSA-2048
// key and this file says so loudly: every token minted becomes unverifiable at
// the next cold start, and two concurrent execution environments never share a
// key, so a JWKS document fetched from one instance does not describe the tokens
// another one signs. RS-4 refuses that in production.
//
// ── the kid ─────────────────────────────────────────────────────────────────
//
// base64url(sha256(SPKI DER))[:16], for the KMS key and the PEM alike, where the
// reference hardcodes "provisioner-key-1" (jwks.service.ts:184). Derived from the
// key material, a kid is stable for a key and different for a different key,
// which is what makes a rotation additive: publish the new key alongside the old
// one, start signing with it, and retire the old id once the last token it signed
// has expired. With one constant kid the same rotation is a flag day. It is
// wire-visible — the kid is in every token header and in the JWKS document — so
// it is registered as idp-kid-derived-from-key-material (deviations.go).
//
// ── resource-server mode ─────────────────────────────────────────────────────
//
// The mirror image: this deployment mints nothing and verifies tokens another
// issuer signed, against that issuer's JWKS. Two things follow, and the second
// one is the part a reader should not have to guess at.
//
// The core's HTTPConfig.ResourceServer unmounts the whole credential surface —
// nineteen routes, everything that creates, proves, delivers or changes a
// credential (auth.ResourceServerGatedRoutes). That is real, immediate, and it
// is the whole of what the knob does to this artifact.
//
// The verifier itself guards the deployment's OWN routes, and this binary has
// none: every route under the api prefix belongs to the imported adapter, and
// wrapping those in the RS256 verifier would be wrong twice over — /me and the
// account routes read a local store and verify the local HS256 session, and the
// commonest resource-server deployment is the hybrid that keeps doing exactly
// that. So the guard is built here, once, with the cache and the timeout the
// configuration asks for, and exposed as App.ResourceServerGuard.
//
// And there it stops. NOTHING IN THIS ARTIFACT CONSULTS IT: cmd/ holds one
// binary, this one, and infra/sam deploys one function, which is the adapter's
// route table and nothing else. The guard is an export for a host that embeds
// this package and has routes of its own to protect; an authorizer binary that
// mounted it in front of somebody else's API would be a second deliverable, and
// this block does not ship one. The cold-start log says so in those terms, so
// that an operator who turns the knob on is not told a verifier is on duty when
// what actually happened is that nineteen routes went away.
//
// Building it at cold start is still worth it: a misconfigured JWKS URL is then
// a failed deployment rather than a 401 on every request of whatever does
// eventually mount it.

// idpOptions returns the core options that put this deployment in
// identity-provider mode, or nothing at all when it is off.
//
// The enable signal is cfg.IDProviderActive(), which is validation's own: the
// schema says identity-provider mode is on when `enabled` is true or key
// material is present (config.IDProvider.active, the reference's
// token.service.ts:42 / auth.router.ts:473), and RS-4 is written against exactly
// that predicate. Deriving the signal from it rather than adding a knob means
// the rule that refuses a production deployment with no key and the code that
// wires the signer can never disagree about whether the IdP is on.
//
// It can do I/O: a KMS signer resolves its public key here, at cold start, so
// that a missing key, a denied kms:GetPublicKey or a key of the wrong type fails
// the deployment instead of every token request (KMSSigner.Resolve).
func idpOptions(ctx context.Context, cfg *config.Config, users auth.UserStore, newKeySource IDPKeySourceFactory, log *slog.Logger) ([]auth.Option, error) {
	if !cfg.IDProviderActive() {
		return nil, nil
	}

	signer, keyID, publicKeys, keySource, err := idpSigner(ctx, cfg, newKeySource, log)
	if err != nil {
		return nil, err
	}

	codes, codeStore, err := idpAuthCodes(cfg, users)
	if err != nil {
		return nil, err
	}

	clients := idpClients(cfg, log)
	issuer := idpIssuer(cfg)
	if issuer == "" {
		// Not fatal — the core leaves iss off the tokens it mints and the
		// reference does the same with no issuer configured
		// (token.service.ts:74-77) — but the discovery document is then a set of
		// relative-looking endpoints rooted at nothing, and a relying party
		// cannot use it. internal/config warns about the same thing from the
		// other side, when there is nothing to derive an issuer from.
		log.Warn("identity-provider mode is on with no issuer and nothing to derive one from, so minted tokens carry no iss claim and the discovery document points at no host",
			slog.String("path", "idProvider.issuer"),
			slog.String("remedy", "set idProvider.issuer to the public https URL this deployment is reached at, including the api prefix, or set deployment.publicUrl"))
	}

	idpConfig := auth.IDPConfig{
		Issuer:         issuer,
		AccessTokenTTL: cfg.IDProvider.AccessTokenTTL.Duration(),
		// RefreshTokenTTL governs the same pair AccessTokenTTL does, and no
		// mounted route issues it; both are reported by unwiredKnobs rather than
		// left to look wired. It is passed anyway so that the day a route does
		// issue that pair, the configured lifetime is already the one in force.
		RefreshTokenTTL: cfg.IDProvider.RefreshTokenTTL.Duration(),
		Signer:          signer,
		KeyID:           keyID,
		PublicKeys:      publicKeys,
		JWKSPath:        cfg.IDProvider.JWKSPath,
		JWKSCORSOrigins: jwksCORSOrigins(cfg),
		Codes:           codes,
		// The JWKS document is served by the adapter at <prefix><jwksPath>, and
		// the discovery document has to point at the same place. The core
		// derives exactly that from Issuer + JWKSPath when this is empty, and
		// the issuer above already carries the api prefix, so the default is
		// right and naming it again here would be a second definition of one
		// URL.
		JWKSURL: "",
		Logger: func(format string, args ...any) {
			log.Warn("auth core idp", slog.String("message", fmt.Sprintf(format, args...)))
		},
	}

	// A nil Service: the IDP adopts the one auth.New is building around it,
	// which is the only order a host can write (WithIDP, auth.go).
	idp, err := auth.NewIDP(idpConfig, nil, clients...)
	if err != nil {
		return nil, fmt.Errorf("identity provider: %w", err)
	}

	log.Info("identity provider wired",
		slog.String("issuer", issuer),
		slog.String("keySource", keySource),
		slog.String("kid", keyID),
		slog.Int("publishedKeys", 1+len(publicKeys)),
		slog.String("jwksPath", idp.JWKSPath()),
		slog.String("authorizationCodeStore", codeStore),
		slog.Int("clients", len(clients)))

	return []auth.Option{auth.WithIDP(idp)}, nil
}

// IDPKeySourceFactory builds the identity provider's signing key from the three
// values the configuration supplies for it. awsintegration.NewKMSKeySource is
// the production implementation; Options.IDPKeySource injects another.
//
// A factory rather than a built key, so that the configuration is still what
// decides which key is used: an injected source is handed the same key id and
// retired list a KMS-backed one would resolve, and a test that got them wrong
// fails rather than quietly signing with whatever it was constructed around.
type IDPKeySourceFactory func(keyID string, previousKeyIDs []string, region string) (awsintegration.IDPKeySource, error)

// idpSigner selects the RS256 signing key and the keys the JWKS document
// publishes beside it.
//
// The three branches are RS-4's three cases, in its order: a KMS key, a PEM, or
// neither in a development stack. "Neither" returns a nil signer, which is how
// the core is asked for its ephemeral key — the same value its own documentation
// gives that meaning.
func idpSigner(ctx context.Context, cfg *config.Config, newKeySource IDPKeySourceFactory, log *slog.Logger) (crypto.Signer, string, []auth.JWK, string, error) {
	if keyID := strings.TrimSpace(cfg.IDProvider.KMSKeyID); keyID != "" {
		if newKeySource == nil {
			newKeySource = awsintegration.NewKMSKeySource
		}
		signer, err := newKeySource(keyID, cfg.IDProvider.KMSPreviousKeyIDs, cfg.Stores.Connection.Region)
		if err != nil {
			return nil, "", nil, "", err
		}
		// Both calls are cold-start I/O and both must fail the init rather than
		// a request: Resolve fetches the signing key's public half (without
		// which crypto.Signer.Public is nil and the core refuses the signer
		// anyway, with a worse message), and JWKS fetches the retired keys.
		kid, err := signer.Resolve(ctx)
		if err != nil {
			return nil, "", nil, "", fmt.Errorf("idProvider.kmsKeyId: %w", err)
		}
		published, err := signer.JWKS(ctx)
		if err != nil {
			return nil, "", nil, "", fmt.Errorf("idProvider.kmsPreviousKeyIds: %w", err)
		}
		// The head of the document is the signer's own key, which the core adds
		// itself from Signer.Public under KeyID (IDP.JWKS); passing it again
		// here would publish it twice.
		return signer, kid, published[1:], "kms", nil
	}

	if pem := cfg.SecretValue("idProvider.privateKey"); pem != "" {
		key, err := auth.ParseRSAPrivateKeyPEM(pem)
		if err != nil {
			// The PEM itself is never echoed: ParseRSAPrivateKeyPEM's messages
			// name the block type and the parse failure, never the bytes.
			return nil, "", nil, "", fmt.Errorf("idProvider.privateKey: %w", err)
		}
		kid, err := publicKeyFingerprint(key.Public())
		if err != nil {
			return nil, "", nil, "", fmt.Errorf("idProvider.privateKey: %w", err)
		}
		return key, kid, nil, "pem", nil
	}

	// Development only: RS-4 refuses this in production. The core generates the
	// key inside NewIDP and logs its own warning through IDPConfig.Logger; this
	// one is here because the core's says what happened and this one says what
	// it means for a deployment.
	log.Warn("identity-provider mode is on with no signing key, so the auth core generates an ephemeral one: every token it signs becomes unverifiable at the next cold start, and two execution environments never share a key",
		slog.String("path", "idProvider.kmsKeyId"),
		slog.String("remedy", "set idProvider.kmsKeyId to an RSA SIGN_VERIFY key, or reference a PEM from idProvider.privateKey; RS-4 refuses this configuration in production"))
	return nil, "", nil, "ephemeral (development only)", nil
}

// publicKeyFingerprint derives the kid of a PEM-configured key the same way the
// KMS signer derives its own: from the DER SubjectPublicKeyInfo, which is the
// one encoding both paths have in common (kms:GetPublicKey returns exactly
// this). Deriving it in one place is what keeps a key that is moved from a PEM
// into KMS — the expected migration — keeping its kid, so the tokens it already
// signed stay verifiable across the move.
func publicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("derive key id: %w", err)
	}
	return awsintegration.KeyFingerprint(der), nil
}

// jwksCORSOrigins maps idProvider.jwksCorsOrigins onto the core's field.
//
// The two spellings the schema allows — the string "*" and a list — arrive here
// as a StringList, and the core reads a one-element {"*"} as the wildcard
// (jwks-cors-wildcard-string-form, an already-registered core deviation). Nil
// and {"*"} mean the same thing to it, and the product default is {"*"}, so this
// is a pass-through with one job: not to invent an empty allowlist, which would
// mean "no origin may read the document" rather than "every origin may".
func jwksCORSOrigins(cfg *config.Config) []string {
	values := cfg.IDProvider.JWKSCorsOrigins.Values
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

// authCodeStoreProvider is what this binary needs from a store to back the OIDC
// authorization codes: a shared, atomic, single-use code store.
//
// A structural assertion on the user store, for the reason oauthStoreProvider
// and templateStoreProvider give — the composition root is the only place that
// knows which driver is in play — and with one extra consequence that makes the
// refusal below non-negotiable. IDPConfig.Codes is an ordinary field, and a nil
// one is not an error: the core quietly substitutes an in-process map. On a
// long-lived server that is merely a limitation; on Lambda it is a broken
// deployment that comes up clean, because /authorize and /token routinely land
// in different execution environments and every code minted by one is unknown to
// the other.
type authCodeStoreProvider interface {
	AuthCodes() auth.AuthCodeStore
}

// idpAuthCodes resolves the authorization-code store, refusing a driver that has
// none rather than letting the core fall back to its map.
func idpAuthCodes(cfg *config.Config, users auth.UserStore) (auth.AuthCodeStore, string, error) {
	provider, ok := users.(authCodeStoreProvider)
	if !ok || provider.AuthCodes() == nil {
		return nil, "", fmt.Errorf(
			"config: refusing to start: identity-provider mode is on, but the %s driver provides no authorization-code store in this build, "+
				"so the auth core would fall back to a process-local map and POST /token would answer invalid_grant for every code minted by another execution environment "+
				"-- turn idProvider off, or select a driver that has one",
			cfg.Stores.Driver)
	}
	return provider.AuthCodes(), cfg.Stores.Driver, nil
}

// idpClients maps the configured client registry onto the core's.
//
// Validation has already refused a client with no id, no secret, no redirect URI
// or a duplicate id, so everything reaching here is complete; the only decision
// left is what to do with none at all, and the answer is a warning rather than a
// refusal. Identity-provider mode in the reference is JWKS publication and
// nothing else, so a deployment that enables it purely to publish a signing key
// — for a resource server elsewhere in the estate to verify against — is
// legitimate and needs no clients. What it must not be is silent: with no
// clients the authorization endpoint answers "unknown client" to everything, and
// an operator who configured a relying party and mistyped the block would
// otherwise have nothing to read.
func idpClients(cfg *config.Config, log *slog.Logger) []auth.IDPClient {
	if len(cfg.IDProvider.Clients) == 0 {
		log.Warn("identity-provider mode is on with no clients configured, so the JWKS and discovery documents are served but GET <prefix>/authorize answers 400 for every client_id",
			slog.String("path", "idProvider.clients"),
			slog.String("remedy", "add a client with its clientId, clientSecret and redirectUris, or leave it empty if this deployment only publishes a signing key"))
		return nil
	}
	out := make([]auth.IDPClient, 0, len(cfg.IDProvider.Clients))
	for _, client := range cfg.IDProvider.Clients {
		id := strings.TrimSpace(client.ClientID)
		out = append(out, auth.IDPClient{
			ClientID:     id,
			ClientSecret: cfg.SecretValue("idProvider.clients." + id + ".clientSecret"),
			RedirectURIs: append([]string(nil), client.RedirectURIs...),
			Name:         client.Name,
		})
	}
	return out
}

// idpIssuer is the iss claim and the base of every endpoint in the discovery
// document.
//
// idProvider.issuer wins when it is set. Otherwise it is derived, and the order
// is what the document has to be true about: an issuer is not a branding URL, it
// is where <issuer>/.well-known/openid-configuration is actually served (RFC
// 8414 §3), so the base is this deployment's own public origin —
// deployment.publicUrl — and not email.siteUrls, which is the front end the
// emailed links point at and may be a different host entirely. The canonical
// site URL stands in when there is no public URL, because a single-host
// deployment has both set to the same thing and it is better than nothing.
//
// The api prefix is appended because that is where the endpoints are mounted:
// the adapter serves the JWKS document at <prefix><jwksPath> and this file
// mounts discovery, authorize, token and userinfo alongside it.
func idpIssuer(cfg *config.Config) string {
	if issuer := strings.TrimSpace(cfg.IDProvider.Issuer); issuer != "" {
		return strings.TrimSuffix(issuer, "/")
	}
	base := strings.TrimSuffix(strings.TrimSpace(cfg.Deployment.PublicURL), "/")
	if base == "" {
		base, _ = siteURLs(cfg)
	}
	if base == "" {
		return ""
	}
	return base + httpConfig(cfg).Prefix()
}

// idpMountedEndpoints is the OIDC surface a deployment with an identity
// provider answers on. Nothing in this binary registers it: the adapter does,
// for every Auth built WithIDP, and this list exists so a test can drive the
// whole surface and catch an endpoint that stops being served.
//
// It used to be a mount list. Until awesome-go-auth v0.7.0 the adapter mounted
// only the canonical JWKS route and left discovery, authorize, token and
// userinfo to (*IDP).RegisterHandlers on a mux the host owned, so this binary
// registered them itself. v0.7.0 moved all four onto the adapters, which is
// what finally put them under the upstream conformance suite, and a host that
// kept registering them saw the second registration refuse the cold start.
// That refusal is the intended tripwire and it fired here; the answer is to
// stop mounting, not to keep two owners of one pattern.
//
// The one path that change costs this deployment is <prefix>/jwks, the core's
// deprecated alias of the JWKS document: RegisterHandlers serves it and the
// adapters do not, so it stopped being served here and is gone from this list.
// It is the alias the core itself removes in v1.0.0, the reference has no such
// path, no client in the family requests it, and the canonical route answers
// the identical document — while keeping it would mean keeping a mux of this
// binary's own beside the adapter's, which is the arrangement that just broke.
// Dropping it now also means this product does not have to drop it later, when
// the core does. Not a deviation from the reference, so not in that register:
// it is a path neither the reference nor the adapters ever served.
//
// TestIDPEndpointsAreMounted drives every endpoint the discovery document
// advertises; an endpoint added upstream shows up there as a 404.
var idpMountedEndpoints = []string{
	"/.well-known/openid-configuration",
	"/authorize",
	"/token",
	"/userinfo",
}

// mountAuthSurface mounts the imported adapter, which since awesome-go-auth
// v0.7.0 is the whole HTTP surface of this deployment, OIDC included — see
// idpMountedEndpoints.
//
// The recover is for one failure mode with one cause. http.ServeMux panics when
// the same pattern is registered twice, and idProvider.jwksPath is the only knob
// in the schema that can provoke it: point it at a path the adapter already
// serves under the same method — "/me", say — and the process dies inside the
// Lambda's init phase with a stack trace and no mention of the knob that caused
// it. The core refuses the four paths its own RegisterHandlers uses (NewIDP,
// validateJWKSPath); the adapter's thirty are not its business to enumerate, and
// duplicating that list here would be a second definition of the route table
// free to drift from the first.
//
// So the panic becomes the cold-start refusal every other configuration mistake
// gets. The guard is installed only when an IdP exists, which is what keeps the
// message honest: with no IdP the adapter mounts exactly what it always mounts,
// and a panic there is a bug that should look like one.
//
// rl is the rate limiter, and it arrives as a parameter rather than through
// httpConfig because it is the one field of auth.HTTPConfig that is not a
// function of the document: it captures a store handle and a counter, which only
// the composition root has. nil means no limiter, which the core reads as a
// pass-through. This is also the only place the value is needed — the adapter
// calls it once per route from here — so passing it down one call is cheaper
// than making every other caller of httpConfig say it has none.
//
// adminRL is the same thing for the console's own slot, AdminOptions.RateLimiter,
// which the core applies to exactly one route — POST <admin>/users/{id}/promote
// — and which the auth router's limiter cannot serve because it matches paths
// under the api prefix (ratelimit.go, newAdminPromoteLimiter). Two parameters
// rather than one, because they are two budgets with two subjects, and nil
// means the same thing for both.
func mountAuthSurface(mux *http.ServeMux, core *auth.Auth, cfg *config.Config, rl, adminRL func(http.Handler) http.Handler) (err error) {
	hc := httpConfig(cfg)
	hc.RateLimiter = rl
	hc.Admin.RateLimiter = adminRL
	if core.IDP() == nil {
		nethttp.MountWithConfig(mux, core, hc)
		return nil
	}
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if !isPatternCollision(r) {
			// Not the failure this guard exists for. A nil dereference or a
			// future bug in the adapter reported as "your jwksPath collides"
			// would send an operator to edit a knob that is not the cause, so it
			// is re-raised exactly as it arrived.
			panic(r)
		}
		err = fmt.Errorf(
			"config: refusing to start: idProvider.jwksPath %q collides with a route this deployment already mounts, so the JWKS document and that route would claim one pattern: %v",
			jwksPathOf(cfg), r)
	}()
	nethttp.MountWithConfig(mux, core, hc)
	return nil
}

// isPatternCollision reports whether a recovered value is http.ServeMux
// refusing a duplicate registration.
//
// Matched on the message because that is all ServeMux gives: it panics with a
// plain string, and the two spellings below are the two it uses — "conflicts
// with pattern" for a method-bearing pattern and "multiple registrations for"
// for a bare path. Matching them is narrower than "any panic", which is the
// point; a spelling change upstream turns this back into a crash with the
// original stack trace, which is the right failure for something this file no
// longer understands.
func isPatternCollision(r any) bool {
	message := fmt.Sprint(r)
	return strings.Contains(message, "conflicts with pattern") ||
		strings.Contains(message, "multiple registrations for")
}

// jwksPathOf reports the path the JWKS document is served at, applying the same
// default the core does, so a diagnostic names what is deployed rather than what
// was written.
func jwksPathOf(cfg *config.Config) string {
	if path := strings.TrimSpace(cfg.IDProvider.JWKSPath); path != "" {
		return path
	}
	return auth.DefaultJWKSPath
}

// resourceServerConfig maps the resourceServer block onto the core's.
//
// Three of the four fields are the reference's own knobs with the reference's
// own defaults (jwks.service.ts:40-41), which internal/config already supplies,
// so this is a translation and not a policy. The fourth, Client, is this
// binary's outbound HTTP client, shared with the delivery webhook: a test points
// it at a TLS httptest server, and a deployment behind a proxy or a pinned CA
// pool has one place to configure.
//
// MinRefreshInterval is left at the core's default, which rate-limits the
// refetch an unknown kid forces (the jwks-unknown-kid-refetch-is-rate-limited
// core deviation). It is not a knob in this schema and inventing one would be a
// knob the rest of the family does not have.
func resourceServerConfig(cfg *config.Config, client *http.Client) auth.ResourceServerConfig {
	return auth.ResourceServerConfig{
		JWKSURL:      strings.TrimSpace(cfg.ResourceServer.JWKSURL),
		Issuer:       strings.TrimSpace(cfg.ResourceServer.Issuer),
		CacheTTL:     time.Duration(cfg.ResourceServer.JWKSCacheTTLMs) * time.Millisecond,
		FetchTimeout: time.Duration(cfg.ResourceServer.JWKSFetchTimeoutMs) * time.Millisecond,
		Client:       client,
	}
}

// checkResourceServerSupport refuses the one resource-server configuration that
// would otherwise fail deep inside the auth core with a message about a knob the
// operator never touched.
//
// RS-1 exempts the HS256 signing secrets in resource-server mode, and correctly:
// a deployment that only verifies tokens signed elsewhere mints none. The auth
// core disagrees — Config.validate requires a secret of at least 32 characters
// whatever mode it is in, because the Service it builds can always be asked to
// verify a local session — and the resource-server middleware itself needs one,
// since its cookie path verifies this instance's own access-token cookie
// (resource_server.go, verifyLocalAccessToken). So the secret is required here
// too, and saying so with the knob's name beats letting auth.New answer "secret
// must be at least 32 characters" for a configuration whose author was told the
// secret was optional.
func checkResourceServerSupport(cfg *config.Config) error {
	if !cfg.ResourceServer.Enabled {
		return nil
	}
	if cfg.AccessTokenSecret() != "" {
		return nil
	}
	return fmt.Errorf(
		"config: refusing to start: resourceServer.enabled is on and security.jwt.accessTokenSecret is unset. " +
			"RS-1 does not require it in resource-server mode because this deployment mints no tokens, but the auth core requires one to build at all, " +
			"and the resource-server verifier reads it for the access-token cookie path -- set it, or turn resourceServer.enabled off")
}

// newResourceServerGuard builds the RS256 verification middleware, once, at cold
// start.
//
// Once, and here, for the cache: the JWKS client IS the cache, and one per
// process means a burst of requests on a cold start costs one outbound fetch
// rather than one each. auth.ResourceServerMiddleware would build its own client
// per call, which the core's own documentation says to avoid when a host wants a
// shared cache; ResourceServerPrincipal is the seam it offers instead, and this
// is the middleware it is meant for.
//
// NewJWKSClient panics on a URL it cannot use, deliberately (the core: "a
// resource server whose issuer endpoint is misconfigured cannot verify a single
// bearer token, so the failure belongs at startup"). RS-8 has already refused an
// absent or non-https URL, so the panic is unreachable through the configuration
// layer; it is turned into an error anyway, because a cold start that dies with
// a stack trace tells an operator far less than one that names the knob.
func newResourceServerGuard(core *auth.Auth, cfg auth.ResourceServerConfig, log *slog.Logger) (guard func(http.Handler) http.Handler, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("resourceServer.jwksUrl: %v", r)
		}
	}()

	client := auth.NewJWKSClient(cfg)
	issuer := cfg.Issuer
	log.Info("resource-server mode wired",
		slog.String("jwksUrl", client.URL()),
		slog.String("expectedIssuer", issuer),
		slog.Duration("cacheTtl", cfg.CacheTTL),
		slog.Duration("fetchTimeout", cfg.FetchTimeout),
		slog.Int("unmountedCredentialRoutes", len(auth.ResourceServerGatedRoutes())),
		// The honest half. What this deployment does with the knob is unmount
		// the routes counted above; the verifier is built and exported, and no
		// request in this artifact passes through it. Saying "wired" and
		// stopping would let an operator believe their API is being guarded by
		// something that is not in front of it.
		slog.Bool("verifierMountedOnAnyRoute", false),
		slog.String("verifier", "built and exposed as App.ResourceServerGuard; no route in this deployment is verified by it -- it is for a host that embeds this package and has routes of its own"))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, httpErr, ok := auth.ResourceServerPrincipal(r, core, client, issuer)
			if !ok {
				auth.WriteHTTPError(w, httpErr)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.ContextWithUser(r.Context(), user)))
		})
	}, nil
}

// idpKnobGaps reports the idProvider knobs the imported core cannot act on, in
// the shape unwiredKnobs uses for every other domain.
//
// All three are inert for one reason: the OIDC token endpoint returns the HS256
// session pair (decision D-3), so the RS256 pair IDPConfig's two lifetimes
// govern is minted by auth.IssueIdPTokenPair, which is a host-level API no
// mounted route calls — in this port or in the reference, whose own
// generateIdProviderTokenPair is likewise called from nothing (reference-issues
// N35). Reporting them is the alternative to an operator setting
// idProvider.accessTokenTtl to an hour, watching tokens live for fifteen
// minutes, and having nothing to read that explains it.
func idpKnobGaps(cfg *config.Config) []knobGap {
	if !cfg.IDProviderActive() {
		return nil
	}
	defaults := config.Defaults()
	var gaps []knobGap

	const pairProblem = "the OIDC token endpoint returns the HS256 session pair, so the RS256 pair this lifetime governs is minted only by the core's IssueIdPTokenPair, which no mounted route calls (decisions.md D-3, reference-issues N35)"
	if cfg.IDProvider.AccessTokenTTL != defaults.IDProvider.AccessTokenTTL {
		gaps = append(gaps, knobGap{
			Path:    "idProvider.accessTokenTtl",
			Problem: pairProblem,
			Remedy:  "set security.jwt.accessTokenTtl instead: it is the lifetime POST <prefix>/token reports as expires_in and the one the access token actually has",
		})
	}
	if cfg.IDProvider.RefreshTokenTTL != defaults.IDProvider.RefreshTokenTTL {
		gaps = append(gaps, knobGap{
			Path:    "idProvider.refreshTokenTtl",
			Problem: pairProblem + "; OIDC v1 issues no refresh_token of its own",
			Remedy:  "set security.jwt.refreshTokenTtl instead, which is the lifetime of the refresh token POST <prefix>/token actually returns",
		})
	}
	if strings.TrimSpace(cfg.IDProvider.PublicKey) != "" {
		gaps = append(gaps, knobGap{
			Path:    "idProvider.publicKey",
			Problem: "the JWKS document is built from the signing key's own public half, which the core derives from the signer, so a separately supplied public key is never read and could silently disagree with what actually signs",
			Remedy:  "remove it; to publish a second key, list it in idProvider.kmsPreviousKeyIds, which is checked against the key material rather than trusted",
		})
	}
	return gaps
}
