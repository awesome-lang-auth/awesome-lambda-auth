package main

import (
	"log/slog"

	auth "github.com/nik2208/awesome-go-auth"
)

// WireDeviation is one place this product knowingly answers differently from
// the reference at the configuration layer: a default, a refusal or a policy
// that no store and no core route owns, and that a client can observe.
//
// The other two registers live where their behaviour lives — the imported core
// publishes auth.CompatibilityNotes() and the DynamoDB store publishes
// (*Store).CompatibilityNotes() — and docs/deviations.md indexes all three.
// deviations_test.go fails when an entry of any register is missing from that
// index, so a deviation cannot quietly stop being documented.
//
// One kind of entry sits outside that division and is here because nowhere else
// can carry it: a divergence that belongs to a core route, that this product
// cannot fix without forking the core, and that a deployment only becomes able
// to reach because this product wired the block it lives in. The rule that a
// deviation has to be announced at cold start does not stop applying because
// the code that causes it is imported, and the core's own register is not ours
// to write. Such an entry says so in Why, and names the test that will fail the
// day upstream closes it.
type WireDeviation struct {
	// ID is the stable handle. It never changes once published.
	ID string
	// Surface is the knob or route affected.
	Surface string
	// Behaviour is what this product does.
	Behaviour string
	// Reference is what awesome-node-auth does instead.
	Reference string
	// Why is the reason the reproduce-the-reference rule was set aside.
	Why string
	// Spec names the document and section that argues the decision.
	Spec string
}

// WireDeviations returns the product-level register, freshly built on every
// call.
func WireDeviations() []WireDeviation {
	return []WireDeviation{
		{
			ID:      "csrf-enabled-by-default",
			Surface: "security.csrf.enabled, every cookie-authenticated unsafe request",
			Behaviour: "Double-submit CSRF is enforced unless the operator turns it off, " +
				"and turning it off in production is refused (RS-3).",
			Reference: "csrf.enabled defaults to false (src/middleware/auth.middleware.ts:35), " +
				"so a deployment that never mentions CSRF runs without it.",
			Why: "A deployable product has to be safe with an empty configuration; a " +
				"library can leave the choice to the integrator.",
			Spec: "docs/spec/config-schema.md §1.3 and §2 RS-3",
		},
		{
			ID:      "production-by-default",
			Surface: "deployment.environment",
			Behaviour: "The environment defaults to production, which is the strict side of " +
				"every rule that distinguishes the two: memory stores are refused, " +
				"env-sourced secrets are warned about, swagger is off.",
			Reference: "There is no environment knob; behaviour that depends on one reads " +
				"NODE_ENV, which is unset in a fresh process and therefore not production.",
			Why: "A stack deployed by someone who forgot to say which environment it is " +
				"should get the stricter rules, not the looser ones.",
			Spec: "docs/spec/config-schema.md §1 (deployment) and §2",
		},
		{
			ID:      "refresh-token-families",
			Surface: "POST <prefix>/refresh",
			Behaviour: "Refresh tokens form a family per session: a replayed refresh token " +
				"revokes the whole session, and every later refresh on it answers 401 " +
				"SESSION_REVOKED.",
			Reference: "Rotation replaces the token; a replay fails as an invalid token and " +
				"the session stays alive.",
			Why: "A replay is the signature of a stolen refresh token, and on a serverless " +
				"stack the store is the only place the theft can be acted on.",
			Spec: "docs/spec/data-model.md §4.3; docs/spec/decisions.md D-7 (signed off 2026-09-11)",
		},
		{
			ID:      "idp-kid-derived-from-key-material",
			Surface: "the kid header of every RS256 token the IdP signs, and the kid of every key in GET <prefix>/.well-known/jwks.json",
			Behaviour: "The kid is base64url(sha256(SPKI DER))[:16] of the key that signed — derived from the " +
				"key material, so it is stable for a key, different for a different key, and identical " +
				"whether the key is held in KMS or supplied as a PEM.",
			Reference: "The kid is the constant \"provisioner-key-1\" for every deployment and every key " +
				"(src/services/token.service.ts:78, src/services/jwks.service.ts:184).",
			Why: "A rotation has to be additive. With a derived kid the old and new keys are published " +
				"together under different kids and a token minted before the rotation still selects the " +
				"key that signed it; with one constant kid the JWKS document can only ever describe one " +
				"key, so every rotation invalidates every token in flight. A relying party reads the kid " +
				"out of the token and looks it up in the document, so nothing that follows the protocol " +
				"can tell the difference — only something that hardcoded the reference's constant could.",
			Spec: "docs/oidc.md; docs/spec/config-schema.md §1.10 addendum; docs/spec/decisions.md D-3",
		},
		{
			ID:      "templates-dir-only-seeds-absent-ids",
			Surface: "email.templatesDir, and the body and subject of every mail rendered from a stored template",
			Behaviour: "The directory is read once, at cold start, and writes only the template ids " +
				"and UI pages the template store does not already hold; a template saved " +
				"through the store wins over the file of the same id, on every cold start.",
			Reference: "There is no templates directory: config.templateStore is the only " +
				"override source and its contents come from whoever writes to it " +
				"(src/interfaces/template-store.interface.ts:13-43, memory-template.store.ts).",
			Why: "A Lambda has no writable filesystem and no deploy step that runs code, so " +
				"the artifact is the only place a shipped template can live and cold start " +
				"the only moment it can be read; and a runtime edit must survive the next " +
				"redeploy, or the admin API would be undone by every cold start.",
			Spec: "docs/spec/config-schema.md §1.5, §3.8 and §3.10; docs/spec/decisions.md D-17",
		},
		{
			ID:      "runtime-settings-seed-only-fills-absent-keys",
			Surface: "runtimeSettings.*, and every route that reads the settings store — today POST <prefix>/2fa/disable",
			Behaviour: "The runtimeSettings block is a cold-start seed, applied key by key and only to the keys the " +
				"settings store does not already hold; a key an administrator has set at run time wins over the " +
				"document, on every cold start, for good. A key the document leaves at its schema default is not " +
				"seeded at all.",
			Reference: "There is no seed. routerOptions.settingsStore is whatever the host app passes and its " +
				"contents come from whoever writes to it (src/interfaces/settings-store.interface.ts:28-40); the " +
				"reference ships no implementation of the interface and no configuration path into one.",
			Why: "A Lambda has no deploy step that runs code, so cold start is the only moment a declared seed can be " +
				"applied — the same position email.templatesDir is in, and templates-dir-only-seeds-absent-ids is the " +
				"same decision. Two things make it sharper here. Cold start recurs: a Lambda cold-starts on every " +
				"scale-out and after every idle period, so a seed that overwrote would revert an administrator's " +
				"toggle not at the next deployment but at an unpredictable moment in between. And the unit is a key " +
				"rather than an item: the settings are one document, so seeding it whole on the first cold start " +
				"would freeze every key at once, including the ones no block has a knob for yet — AuthSettings' " +
				"nil-means-absent gives the right granularity for free. Seeding only declared keys follows from the " +
				"same argument: writing a schema default into a runtime-mutable store is not starting from a declared " +
				"state but inventing one, and it would make a seed added to the document later inert on arrival.",
			Spec: "docs/spec/config-schema.md §1.19; docs/config-reference.md §11; docs/spec/decisions.md D-17 (the templates sibling)",
		},
		{
			ID: "docs-page-carries-a-content-security-policy",
			Surface: "the response headers of GET <prefix>/docs and GET <prefix>/openapi.json, and -- with admin.enabled and tools.enabled -- " +
				"of GET <admin>/api/docs, GET <admin>/api/openapi.json, GET <tools>/docs and GET <tools>/openapi.json",
			Behaviour: "Both documentation responses carry a Content-Security-Policy, X-Content-Type-Options: nosniff " +
				"and Referrer-Policy: no-referrer. The page's policy pins the one CDN origin the reference's HTML " +
				"loads from and denies everything else -- no fetch or XHR off this origin, no image beacon, no form " +
				"action, no nested frame, no framing of the page itself, no rewritten base URL. The document's policy " +
				"is default-src 'none' with the same framing and base-URI denial. The routes, their bodies and their " +
				"status codes are untouched. The tools router's own pair is the same page under the same docs.swagger knob, " +
				"and carries the same two policies: a mitigation that covered one Swagger page and not the other would " +
				"be bypassable one path over.",
			Reference: "Neither route sets any header beyond Content-Type (auth.router.ts:1658-1677; tools.router.ts:332-352 for the tools pair), so the Swagger " +
				"page runs swagger-ui-dist@5 from the unpkg CDN, unpinned and without subresource integrity, with " +
				"no policy of any kind (openapi.ts:1646-1669).",
			Why: "That script runs same-origin with this deployment's auth cookies, and the CSRF cookie is readable " +
				"from JavaScript by design, because the double-submit pattern requires the client to read it -- so a " +
				"bad day at the CDN is a credential-reading script on the auth origin. The honest fix is not ours to " +
				"make: the core mounts the page and the machine-readable document under one bool, this binary may add " +
				"no route under the api prefix, and the core is not forked, so the product can neither serve the " +
				"document without the page nor replace the page's HTML. A header middleware adds no route and is what " +
				"is left. It is narrowing, not closure, and the entry says so: a compromised bundle can still read a " +
				"cookie and still leak it through a top-level navigation, which no CSP directive in any shipping " +
				"browser prevents. What it removes are the silent channels. cmd/auth/docs_test.go " +
				"TestDocsPolicyCoversEveryOriginTheCorePageLoads fails the day the core's page loads from anywhere " +
				"else, which is when this policy would otherwise break the page instead of protecting it, and " +
				"cmd/auth/tools_test.go TestToolsDocsPairCarriesTheDocsPolicy fails the day the tools pair is served without it. " +
				"The admin console's pair joined the surface with the admin block for the same reason and with the same two " +
				"policies: the core serves the console's page with SwaggerUIHandler unchanged -- the same HTML, the " +
				"same CDN -- and its document describes the most privileged surface in the deployment; both follow " +
				"docs.swagger, so one switch turns both pairs and both policies on.",
			Spec: "docs/spec/config-schema.md §1.18; docs/config-reference.md §12, §16 and §17; upstream deviation docs-routes-are-opt-in",
		},
		{
			ID:      "oauth-callback-skips-the-second-factor",
			Surface: "GET <prefix>/oauth/{provider}/callback, for an account with a second factor enabled",
			Behaviour: "The callback issues a session and redirects, for every account it resolves. " +
				"An account whose POST /login answers the second-factor challenge is signed in " +
				"through a provider without presenting one.",
			Reference: "The callback is 2FA-aware: such an account is redirected to " +
				"${redirectTo}/auth/2fa?tempToken=<jwt>&methods=<list> with no session issued " +
				"(src/router/auth.router.ts:1298-1313).",
			Why: "Not a decision this product made: the imported core's OAuthComplete has no " +
				"second-factor branch, and the rule against forking the core stands. It is " +
				"registered rather than left in a comment because wiring oauth.providers is what " +
				"makes it reachable at all -- before P4 the route answered the not-configured stub -- " +
				"and an operator who requires 2FA has to learn this from the cold-start log rather " +
				"than from an incident. cmd/auth/oauth_test.go " +
				"TestOAuthCallbackIssuesASessionEvenForATwoFactorAccount fails the day upstream " +
				"grows the branch, which is when this entry is retired.",
			Spec: "docs/spec/wire-contract.md §3 (the tempToken) and §4; docs/config-reference.md §8.4",
		},
		{
			ID: "rate-limited-routes-answer-429",
			Surface: "every route named in rateLimit.scope -- by default POST <prefix>/login, POST <prefix>/forgot-password, " +
				"POST <prefix>/magic-link/send, POST <prefix>/magic-link/verify, POST <prefix>/sms/send, " +
				"POST <prefix>/sms/verify and POST <prefix>/2fa/verify -- and, with the admin console mounted, " +
				"POST <admin>/users/{id}/promote, the one route the console's own limiter slot covers -- " +
				// D9d
				"and, with the inbound-webhook route mounted, POST <tools>/webhook/{provider}",
			Behaviour: "A deployment that configures nothing is rate limited. Over budget, the route answers, byte for byte, " +
				"429 Too Many Requests with Retry-After: <integer seconds, at least 1>, Content-Type: application/json, " +
				"Cache-Control: no-store and the body {\"error\":\"Too many requests\",\"code\":\"RATE_LIMITED\"} -- and no " +
				"Set-Cookie, not even the CSRF auto-init one, because the limiter is outermost and nothing that sets a cookie " +
				"has run. No RateLimit-Limit, RateLimit-Remaining or RateLimit-Reset header is sent, on this response or on a " +
				"successful one. The default budget is 10 requests per 60-second fixed window per subject per scope, and the " +
				"default subject is the normalised email in the request body, falling back to the sha256 of a presented " +
				"tempToken and then to the client address the event reported. The promote route shares the budget, the window " +
				"and the switch, runs its limiter ahead of the admin guard, and is keyed by the client address under either " +
				"keyBy: its body names how to promote and its path names the person being promoted, and neither is a subject " +
				"a caller should be able to mint budgets with. The admin login is deliberately not limited, on either line. " +
				// D9d
				"The inbound-webhook route shares the budget, the window and the switch, runs its limiter before the core looks the " +
				"provider up, and is keyed by the client address and a hash of the provider under either keyBy, because every request " +
				"naming a provider with a stored script invokes the script runner and nothing about the caller is verified; a provider " +
				"sending more than the budget from one address is answered this 429 and redelivers.",
			Reference: "There is no rate limiting anywhere. RouterOptions.rateLimiter (src/router/auth.router.ts:46) is an " +
				"empty slot for a host-supplied Express handler; absent, the router collapses it to an empty middleware list " +
				"(rl = [], :468) and the package ships no algorithm, no default, no status and no body. Every one of these " +
				"routes answers its ordinary 200, 400 or 401 however often it is called.",
			Why: "This is net-new surface rather than a divergence from something: there is no upstream behaviour to reproduce, so " +
				"the question was never whether to match the reference but what a deployable product should do when nobody says. " +
				"The answer is this product's house rule, the one csrf-enabled-by-default and production-by-default already state: " +
				"a library may leave the choice to its integrator, a product has to be safe with an empty configuration. An auth " +
				"stack that ships unlimited is one that gets credential-stuffed, and the scope is exactly the flows where a guess " +
				"costs an attacker nothing -- login, the three credential-minting sends, and the two six-digit codes. An operator " +
				"who wants the reference's behaviour sets rateLimit.enabled to false and gets it exactly.\n\n" +
				"Four properties of the refusal are decisions in their own right. **The budget is per account, not per address.** " +
				"keyBy defaults to email because the threat is account-shaped and because an address-keyed default would put a " +
				"corporate NAT's whole office in one bucket and one DynamoDB partition, making the limiter the outage for the " +
				"people it is not aimed at (data-model.md §2.3, whose own conclusion is that the account-scoped limiter must be the " +
				"primary control); volumetric defence by source address belongs at the edge. **No RateLimit-* headers.** The usual " +
				"objection, that they hand an attacker the limit, is weak -- anyone willing to spend requests finds it by reaching " +
				"it. The decisive one is that RateLimit-Remaining on a successful response would be an oracle about somebody else's " +
				"traffic under an account-keyed counter: whoever can name victim@example.com could read from a 200 whether that " +
				"person has been logging in. Retry-After stays, because it tells a caller only what the refusal already told them " +
				"and a client that backs off is better for everyone. **The window is fixed**, so the worst case over any sliding " +
				"window of the same length is twice the budget; closing that seam means a read-modify-write on the login path " +
				"forever, and a factor of two does not change what a limit does to a stuffing run. **It fails open.** The counter " +
				"lives in the same DynamoDB table as the user store, so on this product a limiter that cannot count and a route " +
				"that cannot serve are one event: refusing would convert a partial degradation into a total outage and would " +
				"replace a 500 naming the store with a 429 blaming the caller. During such a window the remaining bound is the " +
				"in-process pre-filter, which is per execution environment and is stated as such rather than sold as a limit.\n\n" +
				"One 429 in this surface is not ours and is deliberately not restated here. GET <prefix>/oauth/{provider} and its " +
				"callback, for a provider nobody configured, are bare 404 stubs registered outside the limiter slot in the " +
				"reference (:1361-1362, :1407-1408) and one always-guarded handler here, so behind a limiter at its limit they " +
				"answer 429 where the reference answers 404. That belongs to the imported core, whose HTTPConfig.RateLimiter " +
				"comment names it and whose register carries it; duplicating it as a product entry would give one divergence two " +
				"owners and two places to retire it from. It is also unreachable without an operator naming an OAuth route in " +
				"rateLimit.scope, which the vocabulary does not offer. " +
				"cmd/auth/ratelimit_test.go TestRateLimitResponseIsExactlyThis and " +
				"TestTheShippedDefaultsAreTheOnesTheRegisterClaims fail the day this entry stops describing the product.",
			Spec: "docs/spec/config-schema.md §1.16; docs/spec/data-model.md §1.5 row #61 and §2.3; docs/config-reference.md §14 and §16",
		},
		{
			ID:      "admin-login-skips-the-second-factor",
			Surface: "POST <admin>/login, for an account with a second factor enabled or a deployment whose settings require one",
			Behaviour: "The route mints a 24-hour admin token on email and password alone. It consults neither the account's " +
				"enrolment nor the settings store's require2FA, so an account that POST <prefix>/login would challenge for a " +
				"TOTP or SMS code is signed into the console without one. The product puts the rateLimit block in front of the " +
				"route -- same budget, same window, same keyBy rule as POST <prefix>/login, its own counter scope -- and " +
				"documents admin.loginPath, pointed at the hosted login, as the way a browser reaches the console through the " +
				"flow that does enforce the second factor.",
			Reference: "The same: the login's third arm is findByEmail(email) and a password compare and nothing else " +
				"(src/router/admin.router.ts:566-573), and the route is unlimited (:543). The reference also leaves the route " +
				"outside every limiter it has, which is none.",
			Why: "Not a decision this product made: the core reproduces the reference's login as written (admin.go adminLogin), " +
				"and the rule against forking the core stands. It is registered because this product's own docs and cold-start " +
				"log say the 2FA-bypass class is closed by admin-guard-accepts-only-typed-session-tokens -- which closes the " +
				"typed-token hole, where a step-up tempToken opened the console -- and this route is the exception that " +
				"paragraph would otherwise hide: the second factor is skipped not by presenting the wrong token but by never " +
				"being asked. It is reachable at all because wiring the admin block mounts the route, so an operator who " +
				"requires 2FA has to learn it from the register and not from an incident. What the product can add without a " +
				"route it adds: the limiter, because the route was otherwise an unlimited password oracle for every user in " +
				"the empty tenant, and for the bootstrap secret a constant-time compare with no bcrypt cost at all; and RS-6's " +
				"length floor on that secret. cmd/auth/admin_test.go TestAdminLoginSkipsTheSecondFactor fails the day upstream " +
				"makes the login honour TwoFactorPolicy, which is when this entry is retired.",
			Spec: "docs/config-reference.md §16.2 and §16.7; upstream deviation admin-guard-accepts-only-typed-session-tokens",
		},
		{
			ID:      "uploaded-assets-carry-a-content-security-policy",
			Surface: "the response headers of GET <prefix>/ui/assets/uploads/* and GET <prefix>/ui/assets/logo/*, when an upload store is built",
			Behaviour: "Every response under the two paths carries Content-Security-Policy: default-src 'none'; style-src " +
				"'unsafe-inline'; sandbox and X-Content-Type-Options: nosniff. The bytes, the Content-Type, the Cache-Control " +
				"and the status codes are untouched; with no upload store the two paths answer 404 with no header, as the " +
				"reference does with uploadDir unset.",
			Reference: "express.static serves the upload directory with no header beyond its own Content-Type and caching " +
				"(src/router/ui.router.ts:185-191), and the upload filter admits .svg by name (admin.router.ts:1018-1022).",
			Why: "An SVG is an XML document that may carry script, and served same-origin it runs with the auth cookies, on the " +
				"origin where the CSRF cookie is readable from JavaScript by design and where the admin API has no CSRF layer. " +
				"The author is an administrator -- the upload routes are behind the guard -- but an administrator's browser " +
				"can be handed a file, and the core says this is the host's trade to take: \"serves the upload prefix from a " +
				"separate origin, or behind a Content-Security-Policy, or drops 'svg' by wrapping the store\" " +
				"(upload_store.go UploadNameAllowed). This product has one origin and will not break a console that offers " +
				"svg, so it takes the middle one. `sandbox` makes a top-level SVG an opaque-origin document with scripts, " +
				"forms and navigation off; default-src 'none' closes every fetch; style-src 'unsafe-inline' keeps an honest " +
				"SVG's own <style> rendering. nosniff is the core's other warning on the same seam: the filter tests the name " +
				"and nothing else, so a file called logo.png holding HTML is stored and served as image/png, and without " +
				"nosniff a browser may decide otherwise. A header middleware adds no route, which is what keeps this inside " +
				"the rule that this binary registers nothing under the api prefix. cmd/auth/admin_test.go " +
				"TestUploadedAssetsAreServedFromTheUploadStore pins both headers on a served asset and their absence on the " +
				"auth routes.",
			Spec: "docs/config-reference.md §16.5; docs-page-carries-a-content-security-policy (the same shape, on the documentation pair)",
		},
		{
			ID:      "admin-user-detail-is-single-tenant",
			Surface: "GET <admin>/api/users/{id}, for a user who lives under a tenant",
			Behaviour: "Answers 404 {\"error\":\"User not found\"} for a row the listing beside it, GET <admin>/api/users, shows: " +
				"the listing spans every tenant and the detail looks the id up in the empty tenant only.",
			Reference: "findById(id) carries no tenant at all (src/router/admin.router.ts:789-800), so the detail spans tenants " +
				"exactly as the listing does.",
			Why: "Core-caused and not fixable here: the pinned core's adminGetUser calls GetUserByID(id, \"\") with the empty " +
				"tenant as a literal (admin_read.go:396), because the UserStore seam has no tenant-free lookup; the fix is " +
				"written upstream as UserLookupStore (awesome-go-auth PR #92) and not tagged, so this build stays on v0.11.0 " +
				"and serves what v0.11.0 serves. Every account this binary registers lives in the empty tenant, so the two " +
				"routes agree on a table this deployment filled itself; migrate cognito --tenant is what produces the rows " +
				"they disagree on. A product-side route would be a route under the admin path, and this binary adds none. " +
				"cmd/auth/admin_test.go TestAdminUserDetailIsSingleTenant fails the day the pin moves to a core whose detail " +
				"route spans tenants, which is when this entry is retired.",
			Spec: "docs/config-reference.md §16.4; upstream awesome-go-auth PR #92 (UserLookupStore)",
		},
		{
			ID:      "admin-first-user-policy-is-refused",
			Surface: "admin.accessPolicy: first-user, and therefore who the console admits",
			Behaviour: "The policy is refused at start on every store driver (RS-17). The spelling stays in the schema so a " +
				"document written for another port parses and meets the refusal, which names the way in: admin.rootUser " +
				"or admin.bootstrapSecret, then POST <admin>/users/{id}/promote {\"method\":\"flag\"} under is-admin-flag.",
			Reference: "accessPolicy: 'first-user' grants whoever listUsers(1, 0) returns first, documented as \"the first " +
				"registered user\" (src/router/admin.router.ts:372-374), and the core reproduces the evaluation as written " +
				"(admin.go evaluate).",
			Why: "The policy's premise is monotonic ids, and this product does not have them. The core's newID is prefix + " +
				"\"_\" + hex(16 random bytes) (security.go), the DynamoDB lister orders by its <tenant>#<id> sort key and the " +
				"memory lister by id, so \"first\" is whoever holds the lowest random id today -- and every registration " +
				"redraws: with one existing account a single POST <prefix>/register takes the console with probability one " +
				"half, and the incumbent is locked out in the same moment. The register route is public and the guard " +
				"accepts the newcomer's ordinary access token, so no operator setting compensates. Repairing it would mean " +
				"a creation-ordered listing, which is a store seam the core would have to grow (the lister's order is a " +
				"contract, AdminUserStore) -- an upstream change, and one to file. Until then the honest answer is to refuse " +
				"the policy and say why, rather than ship a knob whose documented meaning is not what it does. " +
				"internal/config/rules_test.go TestRefuseToStartRules (the RS-17 case) pins the refusal; it retires the day " +
				"the pinned core lists by creation time or mints monotonic ids.",
			Spec: "docs/config-reference.md §16.1; docs/spec/config-schema.md §2 RS-17",
		},
		// ui-uploaded-assets-are-not-served was registered by the hosted-UI
		// block and retired by the admin surface. Its three reasons -- no
		// writer, a directory is the wrong noun, an fs.FS over S3 costs a
		// GetObject per page -- are each answered in cmd/auth/ui.go
		// (uiUploadsFollowTheUploadStore) and cmd/auth/admin.go; the retired
		// entry is kept in docs/deviations.md under "Retired" so the id keeps
		// resolving, and nothing replaces it here because a deployment with no
		// S3 location behaves exactly as the reference does with uploadDir
		// unset.
		{
			ID:      "tools-stream-is-not-mounted-on-api-gateway",
			Surface: "GET <tools>/stream, and the tools.stream.enabled and tools.sse.distributor knobs behind it",
			Behaviour: "The stream route is not mounted, in every configuration: HTTPConfig.Tools.DisableStream is set " +
				"unconditionally, so GET <tools>/stream answers 404 whatever tools.stream.enabled says, and the knob is " +
				"reported at cold start as one this runtime cannot honour. A tools.sse.distributor of any type but none is " +
				"refused at cold start (RS-14). tools.sse.enabled is honoured as far as it goes -- the in-process manager " +
				"is built and Track and Notify broadcast into it -- and the cold start says that nothing is listening. The " +
				"tools OpenAPI document describes the routes that are mounted and not this one.",
			Reference: "GET /stream is registered whenever the stream feature is on (tools.router.ts:184-221), which is the " +
				"default, and serves text/event-stream through SseManager.connect for as long as the client holds the " +
				"socket; the distributor is an object the host constructs and passes (sse-manager.ts:110-112).",
			Why: "API Gateway -- the REST API and the HTTP API alike -- buffers the integration response and enforces a " +
				"29-second integration timeout, so behind it the route would be a response that ends every 29 seconds with " +
				"whatever had been buffered. EventSource, the client the reference wrote the route for, reconnects on a " +
				"dropped connection automatically and forever, so the steady state would be a reconnect loop delivering " +
				"frames late and in batches while billing a held-open invocation per client per 29 seconds " +
				"(docs/cost-model.md §3.1: USD 0.024 per connection-hour at 512 MB). That is not SSE and not a degraded SSE; " +
				"it is a spinner that bills. 404 is the reference's own answer for a route the host did not mount, and it is " +
				"the one status EventSource treats as terminal -- the specification fails the connection on anything but " +
				"200 and does not reconnect -- so a client learns the absence at once. The distributor is refused rather " +
				"than ignored because on Lambda it is the whole feature and not an optimisation: every concurrent " +
				"invocation is its own process, so a manager without one reaches only the environment that happened to " +
				"serve the tracking request, silently. The transport that makes the route real is a Lambda Function URL " +
				"with response streaming and a distributor, mandatory there, which is D9c's; that block clears " +
				"DisableStream, adds WithSseDistributor, retires RS-14 and retires this entry. " +
				"cmd/auth/tools_test.go TestToolsRoutesComeFromTheAdapter fails the day the route answers.",
			Spec: "docs/spec/config-schema.md §1.14; docs/config-reference.md §17.3; docs/cost-model.md §3.1; docs/spec/serverless-gap-analysis.md §1.5",
		},
		{
			ID:      "library-events-are-bridged-into-the-tools-fan-out",
			Surface: "every identity.* event the auth core raises; the telemetry store, GET <tools>/telemetry and every outgoing webhook subscribed to one of those names",
			Behaviour: "With tools.enabled, every event the core publishes -- a login, a failed login, a logout, a rotation, an " +
				"account created or deleted, and the rest of the twenty-three -- is fanned out exactly as a tracked event is: " +
				"persisted to the telemetry store when one is enabled, broadcast to the SSE manager when one is built, and " +
				"delivered to every matching outgoing webhook with the same envelope, headers and signature a tracked " +
				"event gets. One login is one telemetry row and one delivery per matching subscription. A tracked event is " +
				"fanned out once as well.",
			Reference: "AuthTools is fed by the host calling track and by nothing else: the routers publish onto the event " +
				"bus and stop, and no part of the package subscribes the bus back into the telemetry store, the stream or " +
				"the webhooks (src/tools/auth-tools.ts:199-269 against the development line's auth.router.ts:418-433). " +
				"The published reference publishes no identity events at all. The imported core reproduces that default " +
				"-- silence -- and exposes AuthTools.Bridge as the opt-in.",
			Why: "This is a deployment and not a library. An operator who configures an outgoing webhook on " +
				"identity.auth.login.success expects logins to reach it, and one who enables the telemetry store expects " +
				"GET <tools>/telemetry to show them; the core names the alternative the monitoring gap -- a deployment can " +
				"believe it is receiving login failures and not be -- and a product whose documented remedy is one line " +
				"in the source is not a product. The core's own Bridge is deliberately not used, and the reason is the " +
				"hazard the core documents on the type, verified here rather than assumed: Bridge is a wildcard " +
				"subscription on the facade's own bus, the one Track publishes on at step 2, so it hears Track's own " +
				"publication and records every tracked event twice with two ids -- not merely events tracked under an " +
				"identity.* name, every event POST <tools>/track ever tracks. The product therefore keeps two buses: the " +
				"core is handed one, the facade is built on a private one nothing subscribes to, and a single wildcard " +
				"subscription on the core's bus calls Track with the event's own name, payload and six identifiers. A " +
				"bridged event and a tracked one are then one kind of thing to every sink, no loop is possible because " +
				"the only bus with a subscriber is the one Track never publishes on, and nothing is doubled because the " +
				"only path to the sinks is that subscription. What it gives up is stated: App.Events carries the " +
				"library's events and App.Tools.Events carries everything fanned out, and the record's timestamp is " +
				"the fan-out instant rather than the publication instant, microseconds apart on one synchronous chain. " +
				"What the store then holds is also stated, because the bridge is what puts it there: every identity.* " +
				"payload -- the email an account was created with, both addresses of an email change, whatever was typed " +
				"into the email field of a failed login -- with the IP address, user agent and session id of each, and " +
				"GET <tools>/telemetry reads all of it, store-wide, to whoever passes tools.auth. Under `session` that " +
				"is any self-registered user (docs/config-reference.md §17.6), which is why the SAM template defaults " +
				"to `apiKey` and the cold start warns. cmd/auth/tools_test.go TestBridgeDeliversEachLoginOnce fails the " +
				"day a login is delivered zero times or twice, or arrives without the caller's X-Correlation-Id.",
			Spec: "docs/config-reference.md §17.2; docs/cost-model.md §2.8; upstream auth_tools.go (the AuthTools type comment)",
		},
		{
			ID:      "outgoing-webhook-delivery-races-the-response",
			Surface: "every outgoing webhook delivery, whether the event was tracked or bridged, while tools.outboundWebhooks.queueUrl is unset -- which is the default, and the SAM template's unless EnableWebhookQueue is \"true\"",
			Behaviour: "Deliveries are made in process by the core's HTTP deliverer, on a goroutine detached from the request, " +
				"and the response is written without waiting for them. On Lambda the execution environment is frozen the " +
				"moment the response is written, so a delivery that has not completed by then completes -- if the same " +
				"environment is ever thawed -- during some later invocation, and the retry schedule of one, two and four " +
				"seconds between attempts is almost never honoured. A delivery is therefore best-effort: an endpoint that " +
				"answers within the request's own lifetime receives it, one that does not may receive it late, once, or " +
				"not at all, and no record of the outcome is kept anywhere.",
			Reference: "The same code shape on a long-lived process: send is not awaited (src/tools/auth-tools.ts:266) and " +
				"retries with exponential back-off (src/tools/webhook-sender.ts:18-46), and a Node process that stays up " +
				"finishes them all.",
			Why: "Not a decision this product made: the core's WebhookEmitter reproduces the reference's fire-and-forget " +
				"exactly and its comment says a process that exits drops whatever is in flight; a Lambda freezes rather " +
				"than exits, which is the same thing on a shorter clock. It is registered rather than left in a comment " +
				"because wiring the tools block is what makes a delivery happen at all, and an operator reading a " +
				"receiver's log must be able to learn from the cold-start line why a delivery arrived a minute late or " +
				"never. The seam the core built for this is WebhookDeliverer, which receives a fully built, signed, numbered " +
				"attempt with no secret in it; D9b implements it as an SQS enqueue with a dead-letter queue and a worker " +
				"that reproduces the schedule from Retries() and RetryDelay(), behind tools.outboundWebhooks.queueUrl. " +
				"The entry is not retired by that: the queue is opt-in, because it is two AWS resources and a second " +
				"function, and an empty parameter adds no resource and no cost -- so the default deployment is still this " +
				"one, and queued-webhooks-are-delivered-at-least-once is the entry for the other. " +
				"Delivering synchronously on the request goroutine instead was considered and rejected: it would make a " +
				"slow receiver a slow login, times the retry schedule, and would still lose the deliveries of the " +
				"invocation that hit the function timeout.",
			Spec: "docs/config-reference.md §17.4; docs/cost-model.md §2.8; upstream webhook_sender.go (WebhookEmitter.Emit, WebhookDeliverer)",
		},
		// ── D9b: outgoing webhooks from a queue ──
		{
			ID: "queued-webhooks-are-delivered-at-least-once",
			Surface: "every outgoing webhook delivery with tools.outboundWebhooks.queueUrl set (the SAM template's " +
				"EnableWebhookQueue), and the receiver's view of it",
			Behaviour: "The response waits (at most two seconds) until each matching delivery is stored on SQS, and " +
				"cmd/webhook-worker then POSTs it with the headers and body the core built and signed. A delivery " +
				"survives the auth function's execution environment being frozen or recycled, is retried on the " +
				"reference's schedule -- at most Retries() further attempts, the first after RetryDelay(), each wait " +
				"twice the last -- and, when the attempts are spent, is moved to a dead-letter queue kept fourteen " +
				"days, with an alarm on its depth when EnableAlarms is on. Delivery is at-least-once, and a receiver " +
				"can see one event twice in two ways: a worker that stops after the receiver answered and before " +
				"the ledger recorded it (data-model.md §1.9) is retried, and the receiver sees the same request -- " +
				"same X-Webhook-Delivery -- twice; and an enqueue that fails ambiguously (the two-second deadline " +
				"expires after SQS has stored the message) is enqueued again by the core under a fresh delivery " +
				"id, so the receiver sees two deliveries with two ids, which no key the receiver holds can join. " +
				"Four limits of the transport shape the schedule: a wait is whole seconds, rounded up, and is set " +
				"on one copy of the message, so an SQS duplicate copy can make an attempt early; no wait exceeds " +
				"just under twelve hours (SQS's visibility maximum); the queue's maxReceiveCount (template default " +
				"12) caps receives, and a receive that made no request -- a duplicate bounced off a live claim, the " +
				"ledger unreachable -- counts against it as much as an attempt, so a subscription can be " +
				"dead-lettered at that ceiling with attempts left (reasons receive-ceiling, busy-at-ceiling, " +
				"ledger-unavailable); and an enqueue that fails spends one attempt of the subscription's budget, " +
				"because the core numbers attempts before the transport sees them. A failing message near the " +
				"queue's fourteen-day retention is dead-lettered as expiring; one never received within it is " +
				"deleted by SQS unseen. An envelope over 256 KiB with its attributes cannot be queued at all and " +
				"is reported through the fan-out log.",
			Reference: "Delivery is at-most-once and in process: send is not awaited (src/tools/auth-tools.ts:266), " +
				"retries run on setTimeout in the same process (src/tools/webhook-sender.ts:18-46), a process that " +
				"exits drops them, the final failure is swallowed (.catch(() => {}), auth-tools.ts:280) and nothing " +
				"records that a delivery gave up.",
			Why: "A guarantee the reference does not give is a difference as much as one it gives and this product " +
				"withholds, and this one is visible from the receiver's side: a receiver written against the reference " +
				"may never have seen a duplicate, and here it can. The core's contract names at-least-once as the " +
				"host's to buy, by making the enqueue durable before returning nil (webhook_sender.go, " +
				"WebhookDeliverer), and on Lambda durable before return also means before the response, which is why " +
				"App.Handle waits for the enqueue. Deduplication at the receiver is not possible on the reference's " +
				"own header (a fresh X-Webhook-Delivery per attempt), so the worker keeps a ledger keyed on the id the " +
				"core minted and makes one successful POST per queued message the normal case; exactly-once over " +
				"HTTP to a third party is not available to anyone, and an idempotent enqueue is not available on a " +
				"standard queue. The ceiling exists because SQS has one maxReceiveCount per queue and the " +
				"reference's retry count is per subscription; the worker enforces the subscription's count itself, " +
				"dead-letters with a reason whenever the queue's count runs out first, and leaves SQS's own redrive " +
				"for a receive it did not finish (a crash, a timeout, a failed hand-off).",
			Spec: "docs/config-reference.md §17.4; docs/cost-model.md §3.3; docs/spec/data-model.md §1.9; " +
				"internal/integration/aws/sqs.go; cmd/webhook-worker/worker.go",
		},
		{
			ID:      "queued-webhook-retries-reuse-the-delivery-id",
			Surface: "the X-Webhook-Delivery header of every retry of a queued outgoing webhook (tools.outboundWebhooks.queueUrl set)",
			Behaviour: "Every attempt at one queued message carries the same X-Webhook-Delivery: the id the core minted " +
				"for the attempt it handed the queue. A receiver sees one id per queued message, however many times " +
				"the worker retries it. That is one id per event and subscription in the normal case and not always: " +
				"an enqueue the core retried after an ambiguous failure (queued-webhooks-are-delivered-at-least-once) " +
				"is a second queued message with a second id.",
			Reference: "A fresh randomUUID() per attempt, minted inside the retry loop (src/tools/webhook-sender.ts:27), " +
				"so two attempts at one event carry two ids.",
			Why: "The core's WebhookDeliverer contract tells a host that redelivers from a queue to resend the header it " +
				"was handed rather than mint one of its own, so that the identifiers a receiver sees are ones the core " +
				"issued; the worker cannot mint a core id, and minting its own would be exactly what that forbids. The " +
				"id also becomes a key the worker's ledger can deduplicate on. The difference is observable only to a " +
				"receiver that compared the ids of two retries. A receiver deduplicating on the header -- which the " +
				"reference makes impossible -- now catches the worker's retries and duplicates, but not a re-enqueue, " +
				"which only a key in the payload it chose itself could join.",
			Spec: "docs/config-reference.md §17.4; upstream webhook_sender.go (WebhookDeliverer, Idempotency; " +
				"WebhookAttempt.DeliveryID)",
		},
		// ── end D9b ──
		// D9d: the four entries of the inbound-webhook runner.
		{
			ID:      "inbound-webhooks-are-refused-without-a-runner",
			Surface: "POST <tools>/webhook/{provider}, and the tools.inboundWebhooks.enabled and .scriptRunnerFunction knobs behind it",
			Behaviour: "A tools block with tools.inboundWebhooks.enabled on -- its default -- and no tools.inboundWebhooks.scriptRunnerFunction " +
				"naming the script-runner Lambda is refused at cold start (RS-15); the document has to name the runner or write " +
				"tools.inboundWebhooks.enabled: false to load. With it off the route is not mounted and answers 404. With a runner named, " +
				"a row's jsScript runs in that Lambda (inbound-webhook-scripts-run-on-goja), and a row with no script is acknowledged and " +
				"tracks nothing, because OnWebhook is a host callback this product has no configuration path into.",
			Reference: "The route is mounted by default whenever a webhook store answering findByProvider or an onWebhook " +
				"callback exists (tools.router.ts:250), and a row's jsScript runs in an in-process vm with a five-second " +
				"timeout on its synchronous prefix (:269-292). There is nothing to name.",
			Why: "The core runs no script in process -- inbound-webhook-script-runs-out-of-process -- and fails closed " +
				"without an InboundScriptRunner: 400, nothing tracked. That is right for the core and wrong as a deployed " +
				"outcome, because every webhook provider treats a non-2xx as undelivered and redelivers, for hours and " +
				"some for days, so a deployment that came up with the route mounted and no runner would answer a retry " +
				"storm from the first event onwards. D9a wrote this as a blanket refusal because no runner existed; D9d " +
				"brings cmd/script-runner and narrows the rule to the configuration that still has none, keeping the id and " +
				"the RS number because the failure is the same one. The default is not silently overridden to false because " +
				"a document that says one thing and deploys another is the failure the phase mechanism this rule descends " +
				"from exists to prevent. internal/config/rules_test.go pins both halves of the refusal and cmd/auth's " +
				"TestRS15AcceptsANamedRunner the acceptance.",
			Spec: "docs/spec/config-schema.md §1.15; docs/config-reference.md §17.5; docs/inbound-webhooks.md; upstream tools_webhook.go",
		},
		{
			ID:      "inbound-webhook-scripts-are-awaited",
			Surface: "every inbound webhook whose stored WebhookConfig carries a jsScript that awaits anything",
			Behaviour: "The runner awaits the script: it drains the engine's job queue until the async wrapper's promise settles, and " +
				"only then reads result. So (a) a result assigned after an await -- including after `await actions[...]` -- is " +
				"tracked; (b) a script whose await can never settle is answered at once as no result, even when it assigned a " +
				"result before that await; (c) an asynchronous rejection is caught, logged and acknowledged like a synchronous " +
				"throw, with a result assigned before it still tracked.",
			Reference: "The code means to await -- it keeps vm.runInContext's return value, attaches .catch \"synchronously " +
				"before any await\" and awaits it (tools.router.ts:289-298), and its documented example is `await " +
				"actions['billing.cancelSubscription'](...); result = {...}` (webhook-store.interface.ts:63-68) -- but it does " +
				"not: the async IIFE is compiled in the vm context, so the promise it returns belongs to that context's realm, " +
				"and `returnValue instanceof Promise` (:290), tested against the outer realm's Promise, is false. The await is " +
				"skipped and result is read synchronously (:304), before the script's first await settles. Verified in Node " +
				"24.21.0 (vm.runInContext of an async IIFE: instanceof Promise false, result null when read, set one turn of the " +
				"event loop later), identical at v1.9.0 and v1.10.8. So there (a) tracks nothing, (b) tracks the early result, " +
				"and (c) is an unhandled rejection the route's catch never sees.",
			Why: "Awaiting is what the reference's code and documentation say it does, and it is the only reading under which an " +
				"awaiting script -- every script that calls an action -- does anything: reproducing the realm bug would make " +
				"actions callable and their outcome unobservable. The core's own reading of the route (upstream tools_webhook.go, " +
				"DefaultInboundScriptTimeout, \"the route then awaits the rest\") is the intended behaviour, not the actual one, " +
				"and is reported upstream together with the reference's one-line fix (util.types.isPromise, or a thenable check, " +
				"in place of instanceof). internal/scriptrunner TestTheLanguageAScriptUsesIsThere and TestActionsAreNeverWidened " +
				"pin (a), TestAPromiseNothingCanSettleIsTheScriptsOwnFailure (b), TestAScriptThatThrowsIsNoResultNotAnError (c).",
			Spec: "docs/inbound-webhooks.md §2; upstream tools_webhook.go (DefaultInboundScriptTimeout)",
		},
		{
			ID:      "inbound-webhook-scripts-run-on-goja",
			Surface: "every inbound webhook whose stored WebhookConfig carries a jsScript",
			Behaviour: "The script runs in cmd/script-runner, a Lambda of its own invoked synchronously by the auth function, on the goja " +
				"engine: a fresh runtime per run holding exactly body, actions, result and console, the script wrapped in the " +
				"reference's own async IIFE and awaited (inbound-webhook-scripts-are-awaited). What a client can observe " +
				"differently: (1) the deadline -- tools.inboundWebhooks.scriptTimeoutMs, 5000 by default, cut short to what the " +
				"auth invocation has left -- bounds the WHOLE run, and a script that reaches it is interrupted and the webhook " +
				"refused 400, so the provider redelivers; (2) a promise nothing in the sandbox can settle is reported at once as no " +
				"result and acknowledged; (3) goja has no Intl, WebAssembly or SharedArrayBuffer, so a script using them throws, " +
				"is logged and is acknowledged -- a result assigned before the throw is still tracked, as in the reference; " +
				"(4) result.data is kept only when it is a JSON object, and userId and tenantId only when they are strings -- and " +
				"a result whose members throw when read, or whose data JSON cannot encode, fails the run and is refused 400, which " +
				"is the reference's answer too; (5) `actions` holds the runner's compiled manifest, which ships empty, intersected " +
				"with the core's resolved allowlist -- so on this build every action call is a TypeError -- and an action's value " +
				"reaches the script as JSON data, its failure as a plain Error with the message alone; (6) an action can reach only " +
				"what the runner's IAM role grants, which is its own log group and nothing else; (7) the sandbox console writes JSON " +
				"records to the runner's log group, not prefixed lines to stderr.",
			Reference: "node:vm in the API process (tools.router.ts:269-304): the same four variables and the same wrapper, and " +
				"{ timeout: 5_000 } bounds the synchronous part of the run, so a synchronous loop is caught, logged and " +
				"acknowledged (:299-302); the promise is not awaited (inbound-webhook-scripts-are-awaited); V8's Intl is there; " +
				"result is read, and result.data handed to track, inside the route's outer try (:253, :304-320), whose catch " +
				"answers 400 (:322-323); actions are whatever the host decorated with @webhookAction (webhook-action.ts:104-115), " +
				"running with the API process's own credentials and returning whatever they return; console writes " +
				"`[webhook:<provider>] ...` to stderr outside production (:270-279).",
			Why: "The owner decided on 2026-09-12 that no JavaScript engine enters the auth function, which holds the signing keys, " +
				"the session store and the password hashes; the runner is a separate function and its IAM role is the sandbox. goja " +
				"rather than a Node.js runner because it keeps one language, one pinned build image and byte-reproducible artifacts, " +
				"and its differences are few and pinned (internal/scriptrunner/engine_test.go); cmd/auth's " +
				"TestTheAuthBinaryLinksNoJavaScriptEngine fails the day the auth binary links any engine. The whole-run deadline is " +
				"the core's contract (a timeout is (zero, false, err)), and it trades the reference's acknowledged-and-lost loop " +
				"for a redelivery an operator can see and fix; it is cut to the auth invocation's remaining time because the core " +
				"drops that deadline (context.WithoutCancel) and an auth function killed mid-Invoke would answer the provider a " +
				"gateway 5xx and orphan the run. A never-settling promise is answered at once because with no timers and " +
				"synchronous actions nothing could settle it, and a redelivery would hang the same way. The type rules on the " +
				"result are the core's InboundScriptResult. An action's result crosses as data because goja would otherwise hand " +
				"the script a reflection-backed Go object whose methods it can call. The manifest ships empty because which effects " +
				"a webhook may cause is the deployment's decision and each one is paid for in IAM.",
			Spec: "docs/inbound-webhooks.md; docs/config-reference.md §17.5; upstream tools_webhook.go (InboundScriptRunner)",
		},
		{
			ID:      "admin-actions-list-omits-the-runner-manifest",
			Surface: "GET <admin>/api/actions",
			Behaviour: "Answers an empty list whatever the script runner's manifest holds, so the admin console's action toggles " +
				"never show an action added to it; the ids are enabled by writing them into the settings' enabledWebhookActions " +
				"(runtimeSettings.enabledWebhookActions, or PUT <admin>/api/settings) and into a webhook's allowedActions " +
				"(PATCH <admin>/api/webhooks/{id}). With the shipped manifest, which is empty, the answer is the reference's for an " +
				"empty registry.",
			Reference: "Answers ActionRegistry.getAllMeta() (admin.router.ts:946-948): every decorated action's id, label, " +
				"category, description and dependsOn.",
			Why: "Not a choice this product made: the imported core's adminListActions answers [] unconditionally and exposes no " +
				"seam to be told about a registry, and the registry lives in another binary by design -- the auth function must " +
				"not link the runner's code. Serving the list from here would be a route this binary adds under the admin path, " +
				"which the product's rules forbid. The fix is upstream: an AdminOptions field carrying action metadata, which " +
				"the product would fill from a metadata-only half of the manifest. internal/scriptrunner " +
				"TestTheShippedManifestIsEmpty fails the day an action ships, which is the day this entry becomes observable.",
			Spec: "docs/inbound-webhooks.md (\"Adding an action\"); upstream admin_read.go (adminListActions)",
		},
		{
			ID:      "tools-api-key-refusal-is-the-cores-bare-401",
			Surface: "every refusal of POST <tools>/track, POST <tools>/notify and GET <tools>/telemetry under tools.auth: apiKey",
			Behaviour: "A request the API-key guard refuses is answered 401 with the text/plain body `unauthorized`, " +
				"whatever the reason: no key, an unknown key, a revoked or expired one, a caller outside the key's IP " +
				"allowlist. There is no JSON envelope, no code, and no 403.",
			Reference: "createApiKeyMiddleware answers res.status(err.statusCode).json({ error, code }) " +
				"(src/middleware/api-key.middleware.ts:50), and the strategy tells the reasons apart: 401 API_KEY_MISSING, " +
				"API_KEY_INVALID, API_KEY_REVOKED and API_KEY_EXPIRED, and 403 API_KEY_IP_BLOCKED " +
				"(src/strategies/api-key/api-key.strategy.ts:80-112).",
			Why: "Not a choice this product made: the refusal is written by the imported core's APIKeyMiddleware " +
				"(api_keys.go), which answers http.Error(w, \"unauthorized\", 401) for a missing key and for every " +
				"verification failure alike, and the core is not forked. It is registered here because selecting " +
				"tools.auth: apiKey is what puts that response on a deployment's wire -- nothing in this product mounted " +
				"the middleware before the tools block. Rewriting it in a product middleware was considered and " +
				"rejected: the core's guard does not say why it refused, so the reference's five codes could only be " +
				"recovered by verifying the key a second time beside it, which doubles a bcrypt comparison per refused " +
				"request and puts a second copy of the key check beside the one that decides, where the two can drift. Collapsing the reasons is also the safer half of the difference: the " +
				"reference tells a caller whether a key exists but is revoked. A client written against the reference " +
				"must therefore treat any 401 from these routes as the whole family of refusals and must not parse the " +
				"body. The fix is upstream's (an envelope and a 403 in APIKeyMiddleware), and this entry retires with it. " +
				"cmd/auth/tools_test.go TestToolsAccessPostures pins the status and the body.",
			Spec: "docs/config-reference.md §17.6; upstream api_keys.go (APIKeyMiddleware)",
		},
		{
			ID:      "tools-admin-login-redirect-points-into-the-admin-mount",
			Surface: "every tools route under tools.auth: admin, with a session admin.accessPolicy and admin.loginPath set, for an unauthenticated request whose Accept names text/html",
			Behaviour: "Answered 302 with Location <admin.loginPath>?redirect=<admin mount><tools path> -- for GET /tools/telemetry " +
				"at the default mounts, redirect=%2Fadmin%2Ftools%2Ftelemetry -- a path no router serves, so a browser that opens a " +
				"tools URL, signs in and is sent back lands on a 404. The same request without text/html is the console's 401.",
			Reference: "Since 1.10.0 the session guard answers 401 {\"error\":\"Unauthorized\"} on every route but the console's " +
				"HTML panel, whatever the Accept header: only the guard built with loginFormFallback redirects " +
				"(src/router/admin.router.ts:439-458 and :684 on origin/main, v1.10.8; CHANGELOG [1.10.0]). The 1.9.0 working " +
				"tree still redirects any text/html request, but builds redirect= from the router the guard is mounted on, " +
				"req.baseUrl + req.path (admin.router.ts:311-314), which here would be /tools/telemetry.",
			Why: "Core-caused and not fixable here: the redirect is the imported core's AdminGuard, which reproduces the 1.9.0 " +
				"branch for every request it guards (admin.go:597-607) and builds redirect= from AdminPath() plus " +
				"adminRouterPath, whose default arm returns the path unchanged for a request outside the admin mount " +
				"(admin.go:1097-1105), so the tools path is appended to the admin mount. It is reachable at all because " +
				"tools.auth: admin puts the tools routes behind that guard. Refusing admin.loginPath beside this posture was " +
				"rejected, because the config reference recommends admin.loginPath at the hosted login as the way into the " +
				"console that enforces the second factor (admin-login-skips-the-second-factor), and rewriting the request or " +
				"the response would be a second copy of the guard's decision. Nothing is admitted by the redirect: it is a " +
				"refusal with the wrong address on it, and every non-browser caller gets the 401. The fix is upstream's -- " +
				"answer 401 outside the panel, as the reference does since 1.10.0 -- and this entry retires with it. " +
				"cmd/auth/tools_test.go TestToolsAdminPostureRedirectsIntoTheAdminMount pins the 302 and its Location and " +
				"fails the day the core answers 401 there.",
			Spec: "docs/config-reference.md §17.6; upstream admin.go (AdminGuard.authorise, adminRelativePath)",
		},
	}
}

// logDeviations writes every register to the cold-start log, so a deployment
// announces the ways it differs from the reference instead of leaving them to
// be discovered from a client's bug report. storeNotes is nil for a driver
// that publishes none.
func logDeviations(log *slog.Logger, storeNotes []string) {
	for _, d := range WireDeviations() {
		log.Info("wire deviation", slog.String("id", d.ID), slog.String("surface", d.Surface))
	}
	for _, d := range auth.CompatibilityNotes().KnownDeviations {
		log.Info("core deviation", slog.String("id", d.ID), slog.String("surface", d.Surface))
	}
	for _, note := range storeNotes {
		log.Info("store compatibility note", slog.String("note", note))
	}
}
