package config

import (
	"fmt"
	"net/url"
	"strings"
)

// minHS256SecretLength is the product floor for an HS256 signing secret.
//
// The reference has no floor at all — it never validates the secret and an empty
// one surfaces as a 500 inside the first jwt.sign
// (src/services/token.service.ts:22,145). 32 bytes matches the HMAC-SHA256 block
// output: below that, the secret is the weakest part of the construction.
const minHS256SecretLength = 32

// checkRules evaluates the refuse-to-start table of spec §2.
//
// Every rule reports with its §2 identifier, because the identifier is how an
// operator gets from a log line to the documentation. Rules are evaluated
// independently and all of them run: a deployment with three problems should
// name three problems.
//
// RS-7 has no function of its own. The spec folds it into RS-1: the admin guard
// reuses security.jwt.accessTokenSecret, so "accessPolicy is not open and there
// is no usable JWT secret" is the same condition as "the access secret is
// missing", and reporting it twice would just be noise.
func checkRules(c *Config, capabilities func(string) StoreCapabilities, d *diagnostics) {
	checkRS1Secrets(c, d)
	checkRS2InsecureCookieMode(c, d)
	checkRS3CSRF(c, d)
	checkRS4IDProviderKeys(c, d)
	checkRS5SameSite(c, d)
	checkRS6AdminGuard(c, d)
	checkRS8ResourceServerJWKS(c, d)
	checkIdentityModeConflict(c, d)
	checkRS10FirstUser(c, capabilities, d)
	checkRS11OAuthProviders(c, d)
	checkRS12MemoryStore(c, d)
	checkRS13Migration(c, capabilities, d)
	checkRS17FirstUserRandomIDs(c, d)
	checkRS18AdminCrossSiteCookie(c, d)
	checkStoreRequirements(c, d)
}

// checkRS17FirstUserRandomIDs: the first-user policy does not elect the first
// user here, so it is refused on every driver.
//
// The reference's evaluation is `listUsers(1, 0)` and compare the first id
// (src/router/admin.router.ts:372-374), which the core reproduces (admin.go
// evaluate), and its doc string calls the result "the first registered user".
// That is true under monotonic ids and false under these: the core's newID is
// prefix + "_" + hex(16 random bytes) (security.go), the DynamoDB lister orders
// by its <tenant>#<id> sort key and the memory lister by id, so the account the
// policy admits is whoever holds the lowest random id today. Every registration
// redraws: with one existing user a single POST <prefix>/register takes the
// console with probability one half, and the incumbent is locked out of it in
// the same moment. The register route is public and the guard accepts the
// newcomer's ordinary access token, so this is not a misconfiguration an
// operator could compensate for -- it is a policy whose premise the store does
// not provide, and the honest answer is to refuse it and name the way in.
//
// Not conditioned on admin.enabled, like RS-10: a policy that would be wrong
// the day the switch is flipped is wrong in the document today.
func checkRS17FirstUserRandomIDs(c *Config, d *diagnostics) {
	if c.Admin.AccessPolicy != AdminAccessPolicyFirstUser {
		return
	}
	d.errf(RuleFirstUserRandomIDs, "admin.accessPolicy",
		"accessPolicy first-user admits the user whose id sorts first in ListUsers(1, 0), and on this product ids are 128 random bits, "+
			"so the console goes to whoever holds the lowest random id and changes hands whenever a later registrant draws a lower one -- "+
			"any caller of POST <prefix>/register can take it",
		"use is-admin-flag, get the first administrator in with admin.rootUser (or admin.bootstrapSecret) and flag the next with "+
			"POST <admin>/users/{id}/promote {\"method\":\"flag\"}; or rbac:<role> / permission:<perm> beside stores.enable.rbac")
}

// checkRS18AdminCrossSiteCookie: the console and SameSite=None are exclusive.
//
// The admin router is mounted outside the auth router's CSRF chain, by the
// reference's design and the core's (admin.go, "What is not wrapped around
// it"): the vendored admin.js posts to <admin>/login as JSON with no CSRF
// header, so a double-submit check there would refuse every login the shipped
// SPA makes. The guard accepts the ordinary access-token cookie as an admin
// credential, and the promote handler decodes its body loosely with no
// Content-Type check and a default method (core admin_promote.go), so a plain
// cross-site <form method=POST> needs no preflight. What stands between that
// form and a new administrator is the SameSite attribute on the cookie, and
// cookies.sameSite is a knob. RS-5 already makes `none` require Secure; this
// rule says that, with a console mounted under a session policy, `none` is not
// available at all. The legacy bootstrap-secret guard reads only the
// Authorization header and `open` reads nothing, so neither is in scope.
func checkRS18AdminCrossSiteCookie(c *Config, d *diagnostics) {
	if !c.Admin.Enabled || c.Cookies.SameSite != SameSiteNone {
		return
	}
	policy := strings.TrimSpace(c.Admin.AccessPolicy)
	if policy == "" || policy == AdminAccessPolicyOpen {
		return
	}
	d.errf(RuleAdminCrossSiteCookie, "cookies.sameSite",
		"the admin console is mounted under a session policy and sameSite is none: the console sits outside the CSRF chain by design "+
			"(the vendored SPA posts to <admin>/login with no CSRF header) and its guard accepts the ordinary access-token cookie, "+
			"so SameSite is the only thing that keeps a cross-site form post from reaching every admin write, POST <admin>/users/{id}/promote included",
		"set cookies.sameSite to lax or strict; a deployment whose own clients need sameSite none cannot also host the console on those cookies")
}

// checkRS13Migration: a migration block must describe a migration that can
// actually happen.
//
// Not a §2 rule, because §2 was extracted from a reference that has no
// migration of any kind; it takes the next free identifier for the reason
// RuleMigrationIncomplete gives. Every clause below is a combination of
// individually valid values whose failure would otherwise be discovered from a
// person's failed login rather than from a failed deploy, which is the test
// every rule in this table has to pass.
//
// The clauses, and what each of them is actually preventing:
//
//   - A knob set with no source. The source is the off switch, so a pool id, an
//     app client or dual-read written without one is a block that reads as
//     configured and does nothing. This is the shape of an operator who turned
//     the migration off by deleting the wrong line, and the one clause where the
//     deployment would otherwise come up looking healthy while the migration it
//     was redeployed to perform is silently not running.
//
//   - A source with no pool id, and a pool id with no region. Both are the same
//     failure seen twice: a directory this deployment cannot address. Without a
//     region in particular, the SDK resolves AWS_REGION — this stack's own
//     region — and a pool that lives in the account being migrated out of would
//     answer "no such user" for every person, indistinguishably from an empty
//     pool. The region is therefore demanded rather than inherited from
//     stores.connection.region: they are the same value only by coincidence.
//
//   - dual-read on a driver that cannot hold the marker. Falling a miss through
//     to the source is only worth anything if the row it creates is still there
//     on the next request, and on the memory driver it is not: each execution
//     environment would re-provision the same person from Cognito, forever, on
//     an unauthenticated route. That is the amplifier the whole marker design
//     exists to prevent, reintroduced by a store choice.
//
//   - A verifier configured with no store that can adopt the password. This is
//     the clause the upstream seam asks for by name. With a client id set, a
//     login reaches the verifier, the verifier answers ok=true migrated=true,
//     and the core then requires the user store to be a UserPasswordStore or it
//     answers a generic 500 (awesome-go-auth/password_verifier.go). It also
//     requires the marker to have survived the write, which is the same
//     capability. Refusing here turns a 500 per migrating login into a failed
//     deploy.
func checkRS13Migration(c *Config, capabilities func(string) StoreCapabilities, d *diagnostics) {
	m := c.Stores.Migration

	if !m.Active() {
		// Only the knobs an operator has to have written by hand count as
		// evidence of intent. The mode has a default, so it cannot distinguish
		// "configured" from "untouched" and is compared against that default
		// rather than against emptiness.
		configured := make([]string, 0, 3)
		if strings.TrimSpace(m.UserPoolID) != "" {
			configured = append(configured, "stores.migration.userPoolId")
		}
		if strings.TrimSpace(m.ClientID) != "" {
			configured = append(configured, "stores.migration.clientId")
		}
		if m.Mode != "" && m.Mode != MigrationModeImportOnly {
			configured = append(configured, "stores.migration.mode")
		}
		if len(configured) > 0 {
			d.errf(RuleMigrationIncomplete, "stores.migration.source",
				fmt.Sprintf("the migration block is configured (%s) but names no source, and the source is the switch: nothing would be imported, no lookup would fall through and no password would be migrated",
					strings.Join(configured, ", ")),
				"set stores.migration.source: cognito, or remove the rest of the block")
		}
		return
	}

	if strings.TrimSpace(m.UserPoolID) == "" {
		d.errf(RuleMigrationIncomplete, "stores.migration.userPoolId",
			fmt.Sprintf("stores.migration.source is %q and no user pool is named, so there is no directory to migrate from", m.Source),
			"set stores.migration.userPoolId to the pool being migrated away from, e.g. <region>_XXXXXXXXX")
	} else if strings.TrimSpace(m.Region) == "" {
		d.errf(RuleMigrationIncomplete, "stores.migration.region",
			"a user pool is named with no region, so the calls would be addressed at this stack's own region and every lookup in a pool that lives elsewhere would answer \"no such user\" -- indistinguishable from an empty pool",
			"set stores.migration.region to the region the pool lives in; it is not inherited from stores.connection.region, which is where this stack's table lives")
	}

	marker := capabilities(c.Stores.Driver).MigrationMarker

	if m.DualRead() && !marker {
		d.errf(RuleMigrationIncomplete, "stores.migration.mode",
			fmt.Sprintf("dual-read needs to write the row it provisions somewhere that outlives the request, and the %q store driver cannot hold a migration marker -- every execution environment would re-provision the same person from the source, on an unauthenticated route",
				c.Stores.Driver),
			"use stores.driver: dynamodb, or set stores.migration.mode: import-only")
	}

	if m.VerifierConfigured() && !marker {
		d.errf(RuleMigrationIncomplete, "stores.migration.clientId",
			fmt.Sprintf("an app client is configured, so a login would ask the source about the password and the core would then adopt it locally, and the %q store driver cannot hold the marker that decides which accounts are asked about",
				c.Stores.Driver),
			"use stores.driver: dynamodb, or clear stores.migration.clientId to keep the import without the login-path dependency")
	}
}

// checkRS1Secrets: the HS256 signing secrets must exist, be long enough, and
// differ from one another.
//
// Resource-server mode exempts them because it never mints a token: it only
// validates tokens signed elsewhere, against a JWKS. The one thing it does not
// exempt is the admin guard, which verifies the access token with
// security.jwt.accessTokenSecret — that is RS-7, which the spec folds in here
// precisely because the two knobs are one knob. Without the carve-out an admin
// surface in resource-server mode comes up authenticating nobody, which is the
// silent failure §2 records against the reference.
func checkRS1Secrets(c *Config, d *diagnostics) {
	paths := []string{"security.jwt.accessTokenSecret", "security.jwt.refreshTokenSecret"}
	if c.ResourceServer.Enabled {
		if !c.adminGuardVerifiesTokens() {
			return
		}
		// Only the access secret is needed: nothing in this deployment mints or
		// verifies a refresh token, so demanding a second one would be noise.
		paths = paths[:1]
	}

	access := c.SecretValue("security.jwt.accessTokenSecret")
	refresh := c.SecretValue("security.jwt.refreshTokenSecret")

	for _, path := range paths {
		if c.secretFailed(path) {
			// The resolution failure has already been reported against this knob;
			// adding "and it is missing" would bury the cause.
			continue
		}
		value := c.SecretValue(path)
		switch {
		case value == "":
			d.errf(RuleSecrets, path,
				"the HS256 signing secret is missing, so the first login would fail with a 500 instead of signing a token",
				"reference it from a store -- "+path+": {secretsManager: <id>} -- or set "+envNameFor(c, path)+" for development")
		case len(value) < minHS256SecretLength:
			d.errf(RuleSecrets, path,
				fmt.Sprintf("the HS256 signing secret is %d characters, below the %d-character minimum", len(value), minHS256SecretLength),
				fmt.Sprintf("generate one with: openssl rand -base64 %d", minHS256SecretLength+16))
		}
	}

	if len(paths) == 2 && access != "" && access == refresh {
		d.errf(RuleSecrets, "security.jwt.refreshTokenSecret",
			"the access and refresh signing secrets are identical, which makes a refresh token accepted anywhere an access token is",
			"generate a second, independent secret for security.jwt.refreshTokenSecret")
	}
}

// checkRS2InsecureCookieMode: cookies on a shared AWS domain.
//
// __Host- and __Secure- prefixes, the Path-scoped refresh cookie and the CSRF
// double-submit all assume the deployment controls its own host. On
// <id>.execute-api.<region>.amazonaws.com or <id>.lambda-url.<region>.on.aws it
// does not: the stage segment breaks Path scoping, and every other AWS account's
// API shares the registrable domain, so a cookie without a Domain attribute is
// still host-only but the surrounding assumptions no longer hold. The spec names
// execute-api; lambda-url is included because the hazard is identical.
func checkRS2InsecureCookieMode(c *Config, d *diagnostics) {
	if !c.CookieDeliveryActive() || c.Cookies.AllowInsecureCookieMode {
		return
	}

	if c.Deployment.PublicURL == "" {
		d.errf(RuleInsecureCookieMode, "deployment.publicUrl",
			"cookie delivery is active but the deployment does not declare its public URL, so it cannot be checked for a custom domain",
			"set deployment.publicUrl to the origin clients reach; set cookies.allowInsecureCookieMode: true only for a dev stage")
		return
	}

	host := hostOf(c.Deployment.PublicURL)
	if !isSharedAWSDomain(host) {
		return
	}
	d.errf(RuleInsecureCookieMode, "deployment.publicUrl",
		fmt.Sprintf("cookie delivery is active on the shared AWS domain %q, where cookie scoping, the __Host- prefix and the CSRF double-submit assumptions break", host),
		"attach a custom domain and set deployment.publicUrl to it; for a dev stage set cookies.allowInsecureCookieMode: true")
}

// checkRS3CSRF: CSRF cannot be off while cookies are being issued.
//
// The reference defaults CSRF off (src/middleware/auth.middleware.ts:35); the
// product default is on and this rule refuses the reference's default outright.
// A cookie-authenticated, state-changing endpoint with no double-submit token is
// cross-site forgeable, and the whole point of shipping this as a product is
// that the operator does not get to make that mistake by omission.
func checkRS3CSRF(c *Config, d *diagnostics) {
	if !c.CookieDeliveryActive() || c.Security.CSRF.Enabled {
		return
	}
	d.errf(RuleCSRFDisabled, "security.csrf.enabled",
		"CSRF protection is disabled while auth cookies are being issued, which leaves every state-changing endpoint cross-site forgeable",
		"remove the override so it stays true; bearer clients (X-Auth-Strategy: bearer) already bypass the check and need nothing here")
}

// checkRS4IDProviderKeys: identity-provider mode needs externally supplied key
// material in production, and never more than one source of it.
//
// The reference generates an ephemeral RSA keypair and warns that "all tokens
// will be invalidated on restart"
// (src/services/token.service.ts:50-63). Under Lambda a restart is every cold
// start, and there are many concurrently, so the warning describes a service that
// does not work rather than one that is inconvenient.
//
// The product adds a second source — idProvider.kmsKeyId, a KMS asymmetric key
// that signs without ever handing the private key to the function — and with two
// sources the rule grows a second half. Exactly one of them may be set, in every
// environment: two keys and no rule for which signs would mean the kid in a
// token, the key in the JWKS document and the key that actually signed could all
// disagree, and the failure would surface as a relying party rejecting valid
// tokens rather than as a misconfiguration.
//
// Neither is refused in production only. In development the core generates an
// ephemeral RSA-2048 key and warns, once, through the cold-start log (cmd/auth
// idp.go): every token minted becomes unverifiable on the next cold start, which
// is exactly right for `sam local` and a test stack and exactly wrong for
// anything with users.
func checkRS4IDProviderKeys(c *Config, d *diagnostics) {
	if !c.IDProvider.active() {
		return
	}
	pem := c.SecretValue("idProvider.privateKey") != ""
	kms := strings.TrimSpace(c.IDProvider.KMSKeyID) != ""

	if pem && kms {
		d.errf(RuleIDProviderKeys, "idProvider.kmsKeyId",
			"identity-provider mode is configured with both a PEM private key and a KMS key, and nothing decides which of the two signs",
			"keep exactly one: idProvider.kmsKeyId for a key the function can only ask to sign, or idProvider.privateKey for a PEM it reads at cold start")
		return
	}
	if pem || kms {
		return
	}
	if !c.IsProduction() {
		return
	}
	d.errf(RuleIDProviderKeys, "idProvider.privateKey",
		"identity-provider mode is active in production with no signing key supplied, and generating an ephemeral one would invalidate every token on each cold start",
		"set idProvider.kmsKeyId to an RSA SIGN_VERIFY key, or reference a stored RSA private key -- idProvider.privateKey: {secretsManager: <id>} -- or turn idProvider.enabled off")
}

// checkRS5SameSite: SameSite=None requires Secure.
//
// Browsers reject a SameSite=None cookie that is not Secure, so the reference's
// silence here means an entire login succeeds server-side and sets nothing
// client-side (no check exists anywhere in
// src/services/token.service.ts:174-210).
func checkRS5SameSite(c *Config, d *diagnostics) {
	if c.Cookies.SameSite != SameSiteNone || c.Cookies.Secure {
		return
	}
	d.errf(RuleSameSiteNone, "cookies.sameSite",
		"sameSite is none without secure, and every browser rejects such a cookie outright, so login would appear to succeed and set nothing",
		"set cookies.secure: true, or use sameSite: lax if the clients are same-site")
}

// checkRS6AdminGuard: a deployed admin surface must have a guard, and a guard
// made of a secret must be a secret.
//
// With neither an access policy nor a bootstrap secret, the reference logs to
// stderr and leaves the admin routes fully open
// (src/router/admin.router.ts:516-537). Operators of a deployed product do not
// read stderr, so the same situation refuses to start.
//
// The second clause is the product's. The reference accepts adminSecret at any
// length, and so did this loader, while it holds the JWT secrets to
// minHS256SecretLength. The bootstrap secret deserves the same floor and for a
// sharper reason: beside a policy it is a *password* POST <admin>/login accepts
// for the empty email or the literal "admin" (core admin.go adminLogin, arm 2),
// compared in constant time with no bcrypt cost per guess, and a hit mints an
// isRoot token that skips the store and the policy alike. A short value there is
// not a weak guard but a guessable one.
func checkRS6AdminGuard(c *Config, d *diagnostics) {
	if !c.Admin.Enabled {
		return
	}
	const path = "admin.bootstrapSecret"
	secret := c.SecretValue(path)
	if secret != "" && len(secret) < minHS256SecretLength && !c.secretFailed(path) {
		d.errf(RuleAdminUnguarded, path,
			fmt.Sprintf("the bootstrap secret is %d characters, below the %d-character minimum; beside a policy it is a password POST <admin>/login accepts for the empty email or \"admin\", "+
				"compared with no bcrypt cost per guess, and a hit mints a root token that skips the store and the policy", len(secret), minHS256SecretLength),
			fmt.Sprintf("generate one with: openssl rand -base64 %d, or remove it and get in with admin.rootUser", minHS256SecretLength+16))
	}
	if c.Admin.AccessPolicy != "" || secret != "" {
		return
	}
	d.errf(RuleAdminUnguarded, "admin.accessPolicy",
		"the admin surface is enabled with neither an access policy nor a bootstrap secret, which would leave every admin endpoint open to anyone",
		"set admin.accessPolicy (is-admin-flag, rbac:<role>, permission:<perm>) or reference admin.bootstrapSecret from a store")
}

// checkRS8ResourceServerJWKS: resource-server mode needs a well-formed https
// JWKS URL at startup.
//
// The reference only discovers a bad URL at the first token verification
// (src/services/jwks.service.ts:111), which turns a deployment-time typo into a
// production 500. Reachability is deliberately not probed: the identity provider
// may legitimately come up after this stack.
func checkRS8ResourceServerJWKS(c *Config, d *diagnostics) {
	if !c.ResourceServer.Enabled {
		return
	}
	raw := c.ResourceServer.JWKSURL
	if raw == "" {
		d.errf(RuleResourceServerJWKS, "resourceServer.jwksUrl",
			"resource-server mode is on with no JWKS URL, so every token verification would fail at request time",
			"set resourceServer.jwksUrl to the https JWKS endpoint of the identity provider")
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		d.errf(RuleResourceServerJWKS, "resourceServer.jwksUrl",
			fmt.Sprintf("%q is not a well-formed https URL, and the reference would only discover that at the first token verification", raw),
			"use the full https URL, e.g. https://idp.example.com/.well-known/jwks.json")
	}
}

// checkIdentityModeConflict: a deployment is an identity provider or a resource
// server, never both.
//
// Not a §2 rule — the reference wires neither mode to anything that could
// conflict — but a product refusal with the same posture, because the
// combination is a deployment that contradicts its own configuration in the one
// direction that matters.
//
// Resource-server mode exists to remove the credential surface: all nineteen
// routes that create, prove, deliver or change a credential answer 404, and
// every document in this product says so in those words. Identity-provider mode
// mounts POST <prefix>/authorize, which takes an email and a password and
// performs a full login, and POST <prefix>/token, which hands back this
// deployment's own session pair. Both mounted, the knob that promises no
// credential can be presented here serves two routes that take one — and
// nothing in the product's own documentation would warn the operator, because
// every sentence of it says the opposite.
//
// The combination is refused rather than trimmed (mounting the JWKS document
// and the discovery document while dropping the other three) because a
// discovery document that advertises an authorization endpoint answering 404 is
// a second way to be untrue, and because the deployment that wants to publish a
// signing key for others to verify against is an identity provider: it just has
// no clients, which idProvider allows and warns about (cmd/auth/idp.go,
// idpClients).
func checkIdentityModeConflict(c *Config, d *diagnostics) {
	if !c.ResourceServer.Enabled || !c.IDProvider.active() {
		return
	}
	d.errf(RuleIdentityModeConflict, "resourceServer.enabled",
		"resourceServer.enabled is on and identity-provider mode is active as well (idProvider.enabled, or key material in idProvider.kmsKeyId or idProvider.privateKey), "+
			"and the two describe opposite deployments: resource-server mode unmounts every credential route so that no password can be presented here, "+
			"while the identity provider mounts POST <prefix>/authorize, which takes an email and a password and logs the user in, and POST <prefix>/token, which returns this deployment's session pair",
		"keep exactly one: turn resourceServer.enabled off for a stack that issues credentials, "+
			"or turn idProvider.enabled off and clear idProvider.kmsKeyId and idProvider.privateKey for one that only verifies another issuer's tokens")
}

// checkRS10FirstUser: the first-user policy needs a driver that can list users.
//
// The reference fails at request time with a 500 saying exactly this
// (src/router/admin.router.ts:372-379). The capability comes from the store
// layer, which owns the truth about what each driver implements.
func checkRS10FirstUser(c *Config, capabilities func(string) StoreCapabilities, d *diagnostics) {
	if c.Admin.AccessPolicy != AdminAccessPolicyFirstUser {
		return
	}
	if capabilities(c.Stores.Driver).ListUsers {
		return
	}
	d.errf(RuleFirstUserListUsers, "admin.accessPolicy",
		fmt.Sprintf("accessPolicy first-user needs to enumerate users, and the %q store driver cannot", c.Stores.Driver),
		"use is-admin-flag or rbac:<role>, or select a driver that supports listing users")
}

// checkRS11OAuthProviders: a provider block must be complete, the deployment
// that configures one must have somewhere to send the browser back to, and it
// must have the stores the flow it just switched on writes to.
//
// The completeness half is the one misconfiguration the reference already fails
// fast on, throwing OAUTH_NOT_CONFIGURED from the strategy constructor
// (src/strategies/oauth/google.strategy.ts:15-17).
//
// The store half is this product's, and it exists because the two stores the
// OAuth callback needs are off by default (Defaults enables users, sessions and
// tokens, and nothing else). With stores.enable.linkedAccounts off the core's
// OAuthComplete returns errStoreNotConfigured before it does anything at all
// (oauth_wire.go), which the wire layer answers as 501 NOT_IMPLEMENTED — so the
// authorize route still 302s the browser to Google, the person consents, and the
// callback tells them the feature is not supported. Half a flow that nothing
// refuses is exactly the silent misconfiguration this table exists to eliminate,
// so a provider without its store is a refusal rather than a 501 discovered by
// the first person who tries to sign in.
//
// stores.enable.pendingLinks is demanded only by onEmailMatch: conflict, which
// is the mode whose whole answer to a conflict is "stash it and let
// /link-request resolve it later". Without the store the core's
// stashAccountConflict returns immediately, the 302 to /account-conflict is
// still sent, and the front end lands on a page whose follow-up call can never
// identify anybody. For the other two modes the store is optional — it also
// carries the single-use-nonce replay defence, which is reported as an unwired
// knob at cold start rather than refused, because a replayable-inside-its-TTL
// signed state is the reference's own behaviour and not a broken deployment.
//
// The allowlist half is this product's, and it closes the second half of
// reference-issues N1. The callback decides where to send the browser by
// reading the origin out of the `state` it is handed and checking it against
// the redirect allowlist — email.siteUrls merged with http.cors.origins
// (buildAllowedOrigins, auth.router.ts:213-219). An *empty* allowlist accepts
// any origin the state carries (originAllowed, :327 and the core's transcription
// of it), which is an open redirect: the OAuth callback is precisely the route
// that carries a fresh session in a Set-Cookie, so a state pointing at an
// attacker's origin turns a successful login into a redirect the victim's
// browser follows with the flow's own credentials already in the jar.
//
// The core signs its states, which is why it can reproduce the reference's
// empty-allowlist behaviour safely for an embedder. A deployment is a different
// thing: it also has to survive the day the signing secret is the thing that
// went wrong, and an allowlist is the defence that does not depend on the
// signature holding. So a configured provider with nothing to allowlist is
// refused here rather than left to be discovered from a phishing report.
func checkRS11OAuthProviders(c *Config, d *diagnostics) {
	names := sortedKeys(c.OAuth.Providers)
	if len(names) == 0 {
		return
	}

	if !c.Stores.Enable.LinkedAccounts {
		d.errf(RuleOAuthIncomplete, "stores.enable.linkedAccounts",
			fmt.Sprintf("the OAuth provider(s) %s are configured and the linked-accounts store is disabled, so the authorization redirect would be sent, the person would consent, and the callback would answer 501 NOT_IMPLEMENTED -- the store is where a provider identity is bound to an account, and the callback refuses before it does anything without it",
				strings.Join(names, ", ")),
			"switch the linked-accounts store on (AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS=true) or remove the oauth.providers block")
	}

	if c.OAuth.Provisioning.OnEmailMatch == OAuthEmailMatchConflict && !c.Stores.Enable.PendingLinks {
		d.errf(RuleOAuthIncomplete, "oauth.provisioning.onEmailMatch",
			"onEmailMatch is \"conflict\", whose whole answer to a conflict is to stash it for the link flow, and the pending-links store is disabled -- the browser would still be redirected to /account-conflict, but nothing would be stashed and POST /link-request could never resolve the identity",
			"enable stores.enable.pendingLinks (AWESOME_AUTH_STORES_ENABLE_PENDING_LINKS=true), or choose oauth.provisioning.onEmailMatch: link or reject")
	}

	allowlistEmpty := len(c.RedirectOrigins()) == 0
	for _, name := range names {
		p := c.OAuth.Providers[name]
		base := "oauth.providers." + name

		if allowlistEmpty {
			// Reported under the provider that triggers it: the operator was
			// working in oauth.providers.<name>, and the allowlist knobs belong
			// in the remedy, where they say what to do rather than where to look.
			d.errf(RuleOAuthIncomplete, base,
				fmt.Sprintf("the %q provider is configured and the redirect allowlist is empty, so the callback would honour whatever origin the state it is handed names, unverified", name),
				"list the front-end origins the callback may send a browser back to in email.siteUrls (they are also the base of every emailed link), or in http.cors.origins")
		}

		secretPath := base + ".clientSecret"
		missing := make([]string, 0, 3)
		if p.ClientID == "" {
			missing = append(missing, "clientId")
		}
		if c.SecretValue(secretPath) == "" {
			missing = append(missing, "clientSecret")
		}
		if p.CallbackURL == "" {
			missing = append(missing, "callbackUrl")
		}
		if len(missing) == 0 {
			continue
		}
		d.errf(RuleOAuthIncomplete, base,
			fmt.Sprintf("the %q provider block is present but incomplete: %s missing", name, strings.Join(missing, ", ")),
			"supply the missing values, or remove the whole "+base+" block to disable the provider")
	}
}

// checkRS12MemoryStore: no in-memory store in production.
//
// Every Lambda execution environment would get its own copy, so sessions, tokens
// and rate-limit counters would depend on which one happened to serve the
// request.
func checkRS12MemoryStore(c *Config, d *diagnostics) {
	if c.Stores.Driver != StoreDriverMemory || !c.IsProduction() {
		return
	}
	d.errf(RuleMemoryStore, "stores.driver",
		"the memory driver is selected in a production deployment, and each execution environment would hold its own disconnected copy of every session",
		"use dynamodb or postgres, or set deployment.environment: development if this really is a throwaway stage")
}

// checkStoreRequirements enforces the cross-store requirements of spec §1.17: a
// feature switched on whose backing store is disabled would fail at request
// time, which is exactly the class of silent misconfiguration the product is
// meant to eliminate.
func checkStoreRequirements(c *Config, d *diagnostics) {
	requireStore := func(enabled bool, storePath string, storeEnabled bool, because, remedy string) {
		if !enabled || storeEnabled {
			return
		}
		d.errf(RuleStoreRequired, storePath,
			"the "+storePath+" store is disabled but "+because,
			remedy)
	}

	requireStore(c.Sessions.CheckOn != SessionCheckOnNone, "stores.enable.sessions", c.Stores.Enable.Sessions,
		fmt.Sprintf("sessions.checkOn is %q, which needs to read session state", c.Sessions.CheckOn),
		"enable stores.enable.sessions, or set sessions.checkOn: none")

	rbacPolicy := strings.HasPrefix(c.Admin.AccessPolicy, AdminAccessPolicyRBACPrefix) ||
		strings.HasPrefix(c.Admin.AccessPolicy, AdminAccessPolicyPermPrefix)
	requireStore(rbacPolicy, "stores.enable.rbac", c.Stores.Enable.RBAC,
		fmt.Sprintf("admin.accessPolicy is %q, which is evaluated against roles and permissions", c.Admin.AccessPolicy),
		"enable stores.enable.rbac, or use the is-admin-flag policy")

	requireStore(strings.TrimSpace(c.Email.TemplatesDir) != "", "stores.enable.templates", c.Stores.Enable.Templates,
		"email.templatesDir names a directory to seed it from, so the templates would be read and then have nowhere to go",
		"enable stores.enable.templates, or remove email.templatesDir")

	requireStore(c.Tools.Enabled && c.Tools.InboundWebhooks.Enabled, "stores.enable.webhooks", c.Stores.Enable.Webhooks,
		"inbound webhooks are enabled and their per-provider rows and mapping scripts live in that store",
		"enable stores.enable.webhooks, or set tools.inboundWebhooks.enabled: false")

	requireStore(runtimeSettingsConfigured(c),
		"stores.enable.settings", c.Stores.Enable.Settings,
		"runtimeSettings seeds are configured and the runtime-mutable layer has nowhere to live",
		"enable stores.enable.settings, or remove the runtimeSettings block")

	requireStore(c.Tools.Enabled && c.Tools.Telemetry.Enabled, "stores.enable.telemetry", c.Stores.Enable.Telemetry,
		"the telemetry query endpoint is enabled and has no store to query",
		"enable stores.enable.telemetry, or set tools.telemetry.enabled: false")
}

// runtimeSettingsConfigured reports whether the operator declared any
// runtimeSettings seed, which is the condition under which stores.enable.settings
// stops being optional.
//
// It is "the block differs from its defaults", the same test domainConfigured
// applies to an unwired domain and the same one cmd/auth applies key by key when
// it decides what to seed. The three agreeing is what makes the guarantee usable:
// a declared seed always has a store to go into, so the composition root never
// has to decide what to do with one that does not.
//
// It used to be `Require2FA || len(EnabledWebhookActions) > 0`, which was
// narrower than the block in two ways that both ended in silence once the domain
// was wired. A lazyEmailVerificationGracePeriodDays moved off its default would
// not have required the store, so the seed would have had nowhere to go and
// nothing would have said so; and an explicitly empty enabledWebhookActions —
// the administrator switching every inbound-webhook action off, which the core
// keeps distinct from "unset" all the way to the stored document — has length
// zero and would have counted as unconfigured.
func runtimeSettingsConfigured(c *Config) bool {
	defaults := Defaults().RuntimeSettings
	return c.RuntimeSettings.Require2FA != defaults.Require2FA ||
		c.RuntimeSettings.EnabledWebhookActions != nil ||
		c.RuntimeSettings.LazyEmailVerificationGracePeriodDays != defaults.LazyEmailVerificationGracePeriodDays
}

// sharedAWSHostSuffixes are the AWS-owned domains where several accounts' APIs
// share a registrable domain and the path carries a stage segment.
var sharedAWSHostSuffixes = []string{
	".amazonaws.com",
	".on.aws",
}

// isSharedAWSDomain reports whether a host is a default AWS-issued endpoint
// rather than a domain the deployment controls.
func isSharedAWSDomain(host string) bool {
	host = strings.ToLower(host)
	for _, suffix := range sharedAWSHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func hostOf(raw string) string {
	host := ""
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		host = u.Hostname()
	} else {
		// A bare host with no scheme parses with an empty Host; deployment.publicUrl
		// is validated separately, so treat the whole value as the host here rather
		// than silently passing the check.
		host = strings.SplitN(raw, "/", 2)[0]
	}
	// A fully-qualified name may carry the root label as a trailing dot, which
	// names the same host and which every browser and API Gateway accepts. Left in
	// place it would slip straight past the suffix match and turn RS-2 off.
	return strings.TrimSuffix(host, ".")
}

// envNameFor returns the documented AWESOME_AUTH_* variable for a secret path, so
// a diagnostic can tell the operator exactly what to set in development.
//
// The slots are built from the *configured* document rather than from Defaults,
// because two families of them do not exist until something is configured: one
// slot per OAuth provider and one per OIDC client. Reading them off Defaults
// would answer "the documented AWESOME_AUTH_* variable" for exactly the knobs
// whose variable name an operator cannot guess.
func envNameFor(c *Config, path string) string {
	for _, slot := range secretSlots(c) {
		if slot.path == path {
			return slot.env
		}
	}
	return "the documented AWESOME_AUTH_* variable"
}
