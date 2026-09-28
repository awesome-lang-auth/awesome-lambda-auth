package config

import (
	"reflect"
	"sort"
	"strings"
)

// A domain is one top-level block of the schema, paired with the phase that
// wires it up. The whole schema is defined and validated from P1 onwards, but
// only part of it is connected to anything, and a knob that validates cleanly
// and then does nothing is worse than one that does not exist: the operator has
// no way to tell the difference from the outside.
//
// So every domain that is not yet wired is enumerated here, and configuring it
// refuses the deployment with the phase it lands in. That is the whole mechanism:
// there is no code path in which a configured-but-inert block is silently
// accepted.
type domain struct {
	// path is the top-level dotted key, e.g. "idProvider".
	path string

	// phase names the phase that wires the domain, for the error message.
	phase string

	// get selects the domain's sub-tree out of a Config, so a configured domain
	// can be detected by comparing it against the same sub-tree of Defaults.
	get func(*Config) any

	// secretPrefix, when set, also treats a resolved secret under that dotted
	// prefix as evidence the domain was configured. Needed because a secret
	// supplied through its documented environment variable leaves no trace in
	// the Config tree.
	secretPrefix string
}

// unwiredDomains lists every domain whose types and validation exist but whose
// behaviour does not.
//
// P1 wires: schemaVersion, deployment, security.jwt secrets and TTLs,
// security.password, security.csrf, tokens, cookies, sessions,
// email.verification.mode, stores, http.
//
// Credential delivery added `email.mailer` and `sms`: they select and configure
// the transports the five credential-minting routes send through (cmd/auth
// delivery.go, internal/integration/aws ses.go and sns.go).
//
// The email flows (P2) closed the rest of the email block. `email.siteUrls` is
// the canonical base of every emailed link and, merged with http.cors.origins,
// the allowlist a request's Origin or Referer is matched against;
// `email.templatesDir` seeds the template store at cold start; and
// `email.deliveryWebhook` selects a signed https receiver as the sender for
// every credential seam in place of SES and SNS (cmd/auth email.go and
// delivery.go). None of the three is refused any more.
//
// Token claims and the TOTP issuer (P3) closed three more. `twoFactor.appName`
// is the issuer an authenticator app labels an enrolment with, handed to the
// core as WithTwoFactorAppName (cmd/auth twofactor.go).
// `security.jwt.extraClaims` is the declarative form of the reference's
// buildTokenPayload callback and `security.jwt.claimsWebhook` the escape hatch
// for a claim that has to be computed; both become one TokenClaimsBuilder built
// out of the core's own StaticClaims, UserFieldClaims, ChainClaims and
// ClaimsWebhook (cmd/auth claims.go). The claims webhook gained a required
// signing secret with the wiring, for the reason the Webhook type gives.
//
// OAuth (P4) closed the `oauth` block, secret prefix included: every entry of
// `oauth.providers` becomes a provider in the core's registry — the two built-in
// names over the core's presets, any other name over the endpoints the document
// supplies — and `oauth.provisioning` becomes the policy the callback resolves
// an identity under (cmd/auth oauth.go). A clientSecret supplied through its
// documented environment variable therefore no longer needs a secretPrefix to
// be noticed: it is read, and RS-11 refuses the provider that has none.
//
// The identity surface (P5) closed the last two of the token domains.
// `idProvider` mounts the core's OIDC endpoints — discovery, authorize, token,
// userinfo — and publishes a JWKS document signed either by an AWS KMS
// asymmetric key (`idProvider.kmsKeyId`, internal/integration/aws kms.go) or by
// a PEM from `idProvider.privateKey`; `resourceServer` points this deployment at
// another issuer's JWKS, unmounts the whole credential surface and exposes the
// RS256 verifier the deployment's own routes are guarded with (cmd/auth idp.go).
// Neither is refused any more, and `idProvider.`'s secretPrefix goes with them:
// the private key and every client secret belong to a wired domain now.
//
// Runtime settings (P6's first block) closed `runtimeSettings`. The block is the
// boot-time seed of the one runtime-mutable layer this product has: with
// `stores.enable.settings` on, the composition root hands the core a
// SettingsStore — the DynamoDB SETTINGS singleton or the development driver's
// in-memory one — and applies the declared seeds to the keys that store does not
// already hold (cmd/auth settings.go, internal/store/dynamodb settings.go).
// `runtimeSettings.require2fa` therefore reaches a route: POST <prefix>/2fa/disable
// answers 403 2FA_REQUIRED on it, which is what a phase gap here used to
// prevent an operator from ever getting. The other two keys are seeded, stored,
// and reported by cmd/auth's unwiredKnobs as read by nothing this build mounts
// — which is the distinction this gate exists to preserve: a domain is refused
// while it does nothing at all, and a knob inside a wired domain is reported
// while the core cannot act on it.
//
// The documentation surface (P6's second block) closed `docs`. `docs.swagger`
// — true, false or auto — decides whether the imported adapter mounts
// GET <prefix>/openapi.json and GET <prefix>/docs, and `auto`, which is the
// schema default, is resolved against `deployment.environment`: on outside
// production, off in it (cmd/auth docs.go, which argues why the resolution
// belongs to the host and not to the core). `docs.basePath` reaches the core's
// DocsOptions.BasePath unchanged and moves what the served document describes,
// never where the two routes are mounted. Neither knob is refused any more and
// neither is reported as unwired: the whole block is honoured. What survives of
// the old refusal is a warning, on the one configuration that is a hazard rather
// than a mistake — the Swagger page served in production, which puts an unpinned
// CDN bundle on the auth origin (collectWarnings, load.go).
//
// Rate limiting (P6's third block) closed `rateLimit`, and it is the first
// domain to leave this list whose defaults are not the reference's, because the
// reference has none: it ships no limiter at all, `RouterOptions.rateLimiter`
// being an empty slot that collapses to `rl = []` when nothing fills it
// (auth.router.ts:46, :468). So the block does not merely reach behaviour now,
// it reaches behaviour this product invented — `rateLimit.enabled` defaults to
// true, and a deployment that never mentions the block answers 429 on the five
// credential flows where the reference answers 200 (cmd/auth ratelimit.go,
// internal/store/dynamodb rate_limit.go; the deviation is
// rate-limited-routes-answer-429). That is also why the gate mattered more here
// than usual: the alternative to refusing a configured-but-inert block was an
// operator who set a budget, watched nothing be limited, and had no way to tell
// from outside.
//
// The hosted UI (P6's fourth block) closed `ui`, and it is the first domain to
// leave this list that adds a *surface* rather than changing one. With
// `ui.enabled` set, the imported adapter mounts the whole of the reference's ui
// router at <prefix>/ui — the config document, the server-rendered pages with
// their injected branding and configuration, and the reference's own fourteen
// browser assets, which awesome-go-auth vendors byte for byte and compiles in
// (cmd/auth ui.go, which builds HTTPConfig.UI). The same flag re-points every
// emailed link at a hosted page rather than at the API route itself
// (HTTPConfig.UILink), which is why httpConfig has followed `ui.enabled` since
// P2 even while this gate made it unreachable: the link shape and the UI switch
// could not be allowed to drift apart on the day the UI landed.
//
// Two knobs of the block behave differently from the rest and neither is a
// phase gap. `ui.assetsDir` is honoured and *refuses* the cold start when it
// names a directory that cannot render a page, because the core never falls
// back to the vendored assets for a host that supplied its own — so the
// alternative to refusing is a stack that 404s every page while every health
// check passes. `ui.uploadDir` is accepted and honoured by nothing: the writer
// is an admin route no build mounts yet, a Lambda has no directory that
// survives a request, and an fs.FS over S3 is a GetObject on the path every
// page requests. That one is a registered deviation
// (ui-uploaded-assets-are-not-served) and is reported by logUISurface, which is
// the distinction this gate exists to preserve — a domain is refused while it
// does nothing at all, and a knob inside a wired domain is reported while
// nothing can act on it.
//
// The admin console (P6's fifth and last block) closed `admin`, secret prefix
// included, and it is the first domain to leave this list whose surface is
// mounted *beside* the api prefix rather than under it: with `admin.enabled`
// set, the imported adapter mounts the core's fifty-one console routes at
// `admin.basePath` from HTTPConfig.Admin, which cmd/auth admin.go builds out of
// the block knob by knob. `admin.accessPolicy` becomes the core's
// AdminAccessPolicy — three of the five spellings are the core's own
// constructors, and `rbac:<role>` and `permission:<perm>` compile to an
// AdminPredicate over the RBAC store in which a store error is a denial, the
// reference's `catch { granted = false }` (admin.router.ts:378-380).
// `admin.bootstrapSecret` and `admin.rootUser.passwordHash` are read now, so a
// secret supplied through its documented environment variable no longer needs
// a secretPrefix to be noticed — the same end `oauth.` and `idProvider.` came
// to. The refusal that outlives the gate is RS-6 (rules.go): an enabled console
// with neither a policy nor a bootstrap secret still refuses the cold start,
// because the reference serves that configuration unguarded.
//
// The block is also what made five `stores.enable` flags mean something
// (metadata, rbac, tenants, apiKeys, webhooks: the `admin` slot of
// coreOptionSets hands each flagged store to the core by name), and what
// closed the `ui.uploadDir` paragraph above: the four upload routes are the
// writer that paragraph said did not exist, `ui.uploadDir` names an S3 location
// one auth.UploadStore is built from, and the deviation it cites is retired in
// the register rather than deleted from it. Two knobs of this block are
// reported rather than honoured, by the rule the next paragraph states:
// `admin.sessionTtl` and `admin.upload.maxFileSizeMb` both reach constants in
// the core — the reference's fixed `expiresIn: '24h'` (admin.router.ts:585) and
// its 5 MiB multer limit — so unwiredKnobs names either one that differs from
// the value the core applies.
//
// A knob inside a wired domain that the imported core cannot honour is a
// different thing again, and is reported by cmd/auth's unwiredKnobs at cold
// start rather than refused here — which is where the mailer's endpoint and API
// key end up, since SES is reached by API and not by URL, and where
// `oauth.providers.<name>.projectId` ends up, since the core's provider has no
// field for it, and where `idProvider.refreshTokenTtl` ends up, since the
// OIDC token endpoint issues no refresh token of its own in v1 (decisions.md
// D-3).
//
// Everything below is defined, validated and refused.
func unwiredDomains() []domain {
	return []domain{
		{
			path:         "tools",
			phase:        "P7 (tools, telemetry, SSE, webhooks)",
			get:          func(c *Config) any { return c.Tools },
			secretPrefix: "tools.",
		},
	}
}

// UnwiredDomains returns the dotted paths of the domains this build validates but
// does not act on, with the phase that wires each. Exported so the deployment
// tooling can warn about them before an upload rather than after a rollback.
func UnwiredDomains() map[string]string {
	out := make(map[string]string)
	for _, dom := range unwiredDomains() {
		out[dom.path] = dom.phase
	}
	return out
}

// checkPhaseGaps reports every unwired domain the operator has actually
// configured. allow downgrades the report to a warning, for tests that need to
// exercise a later phase's validation and for a staged rollout where the operator
// has accepted the gap.
func checkPhaseGaps(c *Config, allow bool, d *diagnostics) {
	defaults := Defaults()
	// derive() has already run on the real Config, so the baseline has to go
	// through it too or every derived value would read as operator intent. It
	// also inherits the wired http block, because derived values are computed
	// from it: docs.basePath derives from http.apiPrefix, and without this line
	// customising the api prefix — which P1 does wire — reported the docs domain
	// as configured. That domain is wired now, and nothing left on the list
	// derives from the http block, so today the line changes no answer. It stays
	// because the next gated domain that gains a derived value would be a silent
	// false positive, and this is the line that prevents it.
	defaults.HTTP = c.HTTP
	derive(defaults)

	for _, dom := range unwiredDomains() {
		if !domainConfigured(c, defaults, dom) {
			continue
		}
		problem := "this block is validated but not yet wired to anything, so configuring it has no effect at runtime"
		remedy := "remove it until " + dom.phase + " lands; it is accepted by the schema so that a document written today keeps working"
		if allow {
			c.warn(dom.path, problem, remedy)
			continue
		}
		d.errf(RuleUnimplemented, dom.path, problem, remedy+", or set AllowUnimplemented to accept the gap deliberately")
	}
}

// domainConfigured reports whether the operator moved a domain away from its
// defaults, through the document, an environment override or a secret.
//
// Comparing sub-trees rather than tracking per-knob writes means a knob added to
// a domain in future is covered without anyone remembering to update this file.
func domainConfigured(c, defaults *Config, dom domain) bool {
	if !reflect.DeepEqual(dom.get(c), dom.get(defaults)) {
		return true
	}
	if dom.secretPrefix == "" {
		return false
	}
	for path, resolved := range c.secrets {
		if strings.HasPrefix(path, dom.secretPrefix) && resolved.value != "" {
			return true
		}
	}
	return false
}

// sortedDomains is used by the tests to keep their expectations stable.
func sortedDomainPaths() []string {
	out := make([]string, 0, len(unwiredDomains()))
	for _, dom := range unwiredDomains() {
		out = append(out, dom.path)
	}
	sort.Strings(out)
	return out
}
