package main

import (
	"log/slog"
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The documentation surface: GET <prefix>/openapi.json and GET <prefix>/docs.
//
// Both routes come from the imported adapter and nothing in this file mounts
// either of them. awesome-go-auth v0.7.0 added HTTPConfig.Docs (DocsOptions);
// with Enabled set, all four adapters register the generated OpenAPI document
// and the reference's Swagger UI page — neither guarded, both behind
// CSRFMiddleware — exactly where the reference registers them
// (auth.router.ts:1651-1677; adapter/nethttp/nethttp.go:144-154). What this file
// does is build that DocsOptions out of the product's `docs` block, and nothing
// else.
//
// That division is not a matter of taste. Until v0.7.0 this binary mounted four
// OIDC endpoints of its own; the adapter took them over and the duplicate
// registration killed the cold start inside http.ServeMux. A route that exists
// here and not in the other ports of the family is a wire divergence by
// construction, so the rule is absolute: every path under the api prefix
// belongs to the adapter. The one thing added here is a middleware, which
// registers no pattern — see docsSecurityHeaders.
//
// ── the three-valued knob, and where `auto` is resolved ──────────────────────
//
// `docs.swagger` is `true`, `false` or `auto`, reproducing the reference's
//
//	options.swagger === true || (options.swagger !== false && NODE_ENV !== 'production')
//
// (auth.router.ts:123-131, :1652-1654). DocsOptions.Enabled is a plain bool, and
// the core's own comment says why: "a library whose routes appear and disappear
// with a variable it never sees configured is a library nobody can reason about
// from its own configuration" (awesome-go-auth docs.go), and Go has no NODE_ENV
// to read. Deciding what the ambient environment means is the host's call. This
// binary is the host, so `auto` is resolved here — against
// `deployment.environment`, which this product carries as a first-class knob
// rather than as a process variable, and which defaults to `production`:
//
//	true   both routes mounted, in every environment
//	false  neither route mounted, in every environment
//	auto   mounted if and only if deployment.environment is not "production"
//
// `auto` is also the schema default (internal/config Defaults), so a document
// that mentions neither knob gets neither route: `deployment.environment` is
// `production` until something says otherwise, and `auto` in production is off.
//
// The difference from the reference is exactly that default, and it is already
// registered. NODE_ENV is unset in a fresh Node process and therefore "not
// production", so the reference serves both routes on a stack nobody
// configured, while this product serves neither. That is the
// production-by-default deviation, whose text names swagger as one of the three
// things the default tightens (deviations.go).
//
// ── docs.basePath and DocsOptions.BasePath are the same thing ────────────────
//
// Both are the reference's `swaggerBasePath` (auth.router.ts:133-139, read at
// :1657): the base the served document writes its path items under, and the base
// of the spec URL the Swagger page fetches. Neither moves the mount. The core
// says so in as many words — "It moves the description, never the mount: the two
// routes are always served at HTTPConfig.Prefix(), because that is where the
// adapter is" (awesome-go-auth docs.go) — and it is the *reference's* own doc
// comment, "Base path where the auth router is mounted", that misleads: that
// value never mounts anything there either, it only builds spec paths and the
// page's url.
//
// So this is a pass-through and not a translation, and the defaults agree as
// well. internal/config derives `docs.basePath` from `http.apiPrefix` when the
// document leaves it unset (load.go, derive — which is why checkPhaseGaps has to
// inherit the http block, as phases.go records), and the core reads an empty
// BasePath as HTTPConfig.Prefix(). Both sides normalise through
// HTTPConfig.Prefix(), so "/auth", "/auth/" and "auth" are one value on either
// side of the seam.
//
// What a pass-through cannot check is whether the operator meant it. A base path
// that differs from the api prefix makes this deployment serve a document
// describing paths it does not answer: correct behind a reverse proxy that maps
// one onto the other, and a silent lie anywhere else. logDocsSurface names it at
// cold start rather than refusing it, because the proxy case is the reason the
// knob exists.
//
// ── the Swagger page puts a third-party script on the auth origin ────────────
//
// The page is the reference's, reproduced byte for byte by the core, and it
// loads swagger-ui-dist@5 from the unpkg CDN with no subresource integrity
// (swaggerUIHTML in awesome-go-auth docs.go; openapi.ts:1646-1669). Whatever
// unpkg serves then runs same-origin with this deployment's cookies — the CSRF
// cookie included, which is readable from JavaScript by design, because the
// double-submit pattern requires the client to read it. Upstream registered
// docs-routes-are-opt-in partly for this, and its advice is "Keep the routes off
// in production, or serve them behind a Content-Security-Policy that pins that
// CDN".
//
// Three things follow, and one that deliberately does not.
//
// **This product does not refuse to start.** The obvious rule — `docs.swagger:
// true` with `deployment.environment: production` is an RS-13 — was written and
// then thrown away, over what the core's switch actually controls. Serving a
// spec document and serving a Swagger page are separable things: the first is a
// machine-readable description that a client generator or a gateway consumes and
// that carries no script at all; the second is the page with the CDN on it.
// DocsOptions.Enabled is one bool for both, and every adapter mounts both under
// it (adapter/nethttp/nethttp.go:151-154). This binary cannot mount the spec
// route on its own, because nothing here may add a route under the api prefix,
// and it will not fork the core to split the flag. A refusal aimed at the page
// would therefore take the document with it and refuse a production deployment
// for wanting the harmless half of an inseparable pair — leaving the operator
// with one move, turning both off, which is the state they were trying to leave.
//
// The house rule that would otherwise apply — "forgetting to name the
// environment should tighten, not loosen" — is already satisfied, and satisfied
// by the part of the design that handles *forgetting*: `production` is the
// default environment and `auto` is the default knob, so silence gets neither
// route. Reaching the hazard takes two deliberate statements in one document.
// RS-3 and RS-12 refuse configurations that are broken; this one works, and is a
// risk an operator may knowingly take on an internal stack. The upstream fix is
// a second field — a spec-only mode, or a page served from assets the library
// vendors instead of a CDN — and it is reported as such rather than worked
// around here.
//
// **It warns, once, at deploy time.** internal/config's collectWarnings raises
// `docs.swagger` when the page is served in production, naming the CDN and the
// cookie it can read. A warning there rather than a log line here because
// Config.Warnings() is what the deployment tooling reads *before* an upload, so
// the operator hears it before the stack has it.
//
// **It sends a Content-Security-Policy on both routes**, which is the one thing
// this binary can do about the hazard without touching a route. See
// docsSecurityHeaders for what that buys and — more important — what it does
// not.
//
// **And it keeps the two routes together.** The product does not gate them
// separately even though it could refuse one in middleware, because the served
// document describes both paths (OpenAPIInfo.Docs), so a deployment answering
// one and 404ing the other would publish a document that lies about its own
// surface.

// docsCDNOrigin is the single third-party origin the reference's Swagger page
// loads from. It is a transcription of a literal in the core's HTML, not a knob:
// the page is the reference's byte for byte, so there is nothing here to
// configure and nothing upstream to negotiate with.
//
// TestDocsPolicyCoversEveryOriginTheCorePageLoads renders that HTML and fails if
// it ever names an origin this constant does not, which is the tripwire for an
// upstream change that would otherwise turn the policy below into a silently
// broken page.
const docsCDNOrigin = "https://unpkg.com"

// docsPageCSP is the policy sent with GET <prefix>/docs.
//
// 'unsafe-inline' is unavoidable on both script and style. The page carries an
// inline <script> that calls SwaggerUIBundle (openapi.ts:1655-1666) and
// swagger-ui injects stylesheets at runtime; a nonce or a hash would mean
// rewriting the core's HTML, and a page that differs from the reference's is a
// page whose behaviour a deployment has to re-verify. The CDN origin is listed
// on img-src and font-src for the same reason: swagger-ui.css resolves its own
// assets relative to itself, and a policy that breaks the page is a policy an
// operator turns off.
const docsPageCSP = "default-src 'none'; " +
	"script-src " + docsCDNOrigin + " 'unsafe-inline'; " +
	"style-src " + docsCDNOrigin + " 'unsafe-inline'; " +
	"img-src 'self' " + docsCDNOrigin + " data:; " +
	"font-src " + docsCDNOrigin + " data:; " +
	"connect-src 'self'; " +
	"form-action 'none'; " +
	"frame-src 'none'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'"

// docsSpecCSP is the policy sent with GET <prefix>/openapi.json. The document is
// JSON and executes nothing, so the policy is the empty one plus the two
// directives that matter for a resource a browser might be tricked into
// rendering: it may not be framed, and it may not rewrite a base URL.
const docsSpecCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

// docsEnabled resolves the three-valued `docs.swagger` knob against
// `deployment.environment`. See the file header for why the resolution happens
// here and not in the core.
//
// The default branch is `auto` and, for a Config that never went through
// validate(), anything else: `auto` is the schema default and the reference's,
// so an unrecognised spelling behaves as the value the operator most likely
// meant. A document carrying one never reaches this function — validate.go
// refuses `docs.swagger` outside the three spellings.
func docsEnabled(cfg *config.Config) bool {
	switch cfg.Docs.Swagger {
	case config.SwaggerTrue:
		return true
	case config.SwaggerFalse:
		return false
	default:
		return !cfg.IsProduction()
	}
}

// docsOptions builds HTTPConfig.Docs. BasePath is passed through unchanged
// because the two fields mean the same thing and normalise the same way; see the
// file header.
func docsOptions(cfg *config.Config) auth.DocsOptions {
	return auth.DocsOptions{
		Enabled:  docsEnabled(cfg),
		BasePath: cfg.Docs.BasePath,
	}
}

// docsSecurityHeaders decorates the two documentation responses with a
// Content-Security-Policy and the two headers that go with it.
//
// It is a middleware over the whole mux that acts on exactly two paths, and that
// shape is the point: it registers no pattern, so the adapter still owns the
// surface and the rule against adding a route under the api prefix is untouched.
// It matches on the resolved prefix and the core's own path constants, so a
// customised http.apiPrefix moves the policy with the routes, and an upstream
// change to either path moves it too.
//
// **What the policy buys, exactly.** It does not make an untrusted CDN safe. A
// compromised bundle still executes same-origin, can still read document.cookie,
// and can still put what it read into a top-level navigation, which no CSP
// directive in any shipping browser prevents. What the policy removes are the
// quiet channels: fetch and XHR to anywhere but this origin, an image beacon, a
// form post, a nested frame, a rewritten <base>. It also refuses to be framed,
// which closes the other half of the hazard — a docs page embedded in a hostile
// document. So it turns a silent exfiltration into one that navigates the
// operator's own browser away from the page: noisier, and far less useful
// against a route only an operator visits. The fix that would actually close it
// is upstream, and is named in the file header.
//
// Off when the routes are not mounted, because a policy on a 404 is a claim
// about a surface this deployment does not have, and because an operator reading
// headers should be able to tell the two states apart.
//
// The admin console's own pair — GET <admin>/api/openapi.json and
// GET <admin>/api/docs — gets the same two policies when the console is mounted
// with its documentation on, because it is the same hazard on the same origin:
// the core serves the console's page with SwaggerUIHandler unchanged, the very
// HTML that loads swagger-ui-dist@5 from the CDN this file pins, and the
// console's document describes the most privileged surface this deployment has.
// It follows docs.swagger exactly as the auth router's pair does (admin.go,
// adminHTTPOptions), so one switch turns both pairs and both policies on.
func docsSecurityHeaders(cfg *config.Config) func(http.Handler) http.Handler {
	if !docsEnabled(cfg) {
		return func(next http.Handler) http.Handler { return next }
	}

	prefix := httpConfig(cfg).Prefix()
	policies := map[string]string{
		prefix + auth.DocsSpecPath: docsSpecCSP,
		prefix + auth.DocsUIPath:   docsPageCSP,
	}
	if spec, page, ok := adminDocsPaths(cfg); ok {
		policies[spec] = docsSpecCSP
		policies[page] = docsPageCSP
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if policy, ok := policies[r.URL.Path]; ok {
				setDocsHeaders(w, policy)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// setDocsHeaders writes the policy and its two companions.
//
// nosniff matters on both routes and for the same reason: a browser that
// MIME-sniffs a JSON document or an HTML page into something else would be
// choosing a content type this deployment never declared. no-referrer keeps the
// documentation URL — which carries the api prefix, and on a stage URL the stage
// — out of the Referer of anything the page loads.
func setDocsHeaders(w http.ResponseWriter, policy string) {
	h := w.Header()
	h.Set("Content-Security-Policy", policy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// logDocsSurface announces what the documentation block resolved to, so an
// operator can tell from the cold-start log whether the two routes exist on this
// deployment and under which described base.
//
// The production hazard is not repeated here: internal/config raises it as a
// configuration warning and New logs every warning before anything else can bury
// it. What is only visible from here is the base path, because only the
// composition root knows the prefix the adapter was actually mounted at.
func logDocsSurface(cfg *config.Config, log *slog.Logger) {
	prefix := httpConfig(cfg).Prefix()
	if !docsEnabled(cfg) {
		log.Info("documentation routes not mounted",
			slog.String("path", "docs.swagger"),
			slog.String("swagger", cfg.Docs.Swagger),
			slog.String("environment", cfg.Deployment.Environment),
			slog.String("effect", "GET "+prefix+auth.DocsSpecPath+" and GET "+prefix+auth.DocsUIPath+" answer 404"))
		return
	}

	base := auth.HTTPConfig{APIPrefix: cfg.Docs.BasePath}.Prefix()
	log.Info("documentation routes mounted",
		slog.String("swagger", cfg.Docs.Swagger),
		slog.String("environment", cfg.Deployment.Environment),
		slog.String("spec", prefix+auth.DocsSpecPath),
		slog.String("page", prefix+auth.DocsUIPath),
		slog.String("describedBasePath", base),
		slog.String("note", "both routes are unguarded, as the reference registers them; the page loads swagger-ui-dist@5 from "+docsCDNOrigin))

	if base != prefix {
		log.Warn("the served OpenAPI document describes a base path this deployment does not serve",
			slog.String("path", "docs.basePath"),
			slog.String("describedBasePath", base),
			slog.String("mountedAt", prefix),
			slog.String("problem", "docs.basePath moves the description, never the mount, so every path item and the page's spec URL point at "+base+" while the routes answer under "+prefix),
			slog.String("remedy", "leave docs.basePath unset unless a reverse proxy really does serve this deployment under "+base+"; it defaults to http.apiPrefix"))
	}
}
