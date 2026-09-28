package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// The admin console: everything under <admin>/ — the login and logout routes,
// the shell that loads the vendored SPA, the fifty-one routes behind the guard
// — built out of the product's `admin` block and served, like every other
// surface of this deployment, by the imported adapter.
//
// Nothing in this file mounts a route. The rule is the one docs.go and ui.go
// state and it is absolute: the whole HTTP surface comes from
// nethttp.MountWithConfig, which registers the console at HTTPConfig.AdminPath()
// when HTTPConfig.AdminMounted() is true (adapter/nethttp/nethttp.go:165-179)
// and registers nothing there otherwise. What this file does is three things:
// build auth.AdminOptions out of `admin.*` and say why each field is set the
// way it is; hand the core the stores the console's tabs are drawn from, which
// is the first time the `admin` slot of coreOptionSets holds anything; and
// build the upload store the console writes through and the hosted UI reads
// back, which is what retires a deviation D7 registered.
//
// ── where it mounts, and why not under the api prefix ────────────────────────
//
// The reference's admin router is a sibling of the auth router, not a child:
// the host mounts createAdminRouter beside the auth router, the SPA is told
// where the auth router lives through apiPrefix (admin.router.ts:152-157), and
// the console's own OpenAPI document defaults its base to '/admin'
// (admin.router.ts:190). The core reproduces that shape — AdminOptions.Path is a
// path on the same router, beside HTTPConfig.APIPrefix, and `admin.basePath`
// defaults to "/admin" here as it does there. The consequence is stated in the
// core and repeated here because it decides what wraps the console: the six
// routes of the skeleton and every route behind the guard sit *outside* the
// auth router's CSRF and rate-limit chain, exactly as the reference's separate
// Express router does (core admin.go, "What is not wrapped around it"). The
// vendored admin.js posts to <admin>/login as JSON with no CSRF header, so a
// double-submit check there would refuse every login the shipped SPA makes.
// Two consequences follow and both are the product's to state. With no CSRF
// check, the SameSite attribute of the cookie the guard accepts is the only
// thing between a cross-site form post and every admin write; RS-18 therefore
// refuses the console beside cookies.sameSite: none. And the product's own CORS
// layer, which the reference mounts INSIDE the auth router
// (auth.router.ts:512-527) and never on the admin router, is kept off the admin
// mount (app.go corsExemptMounts): an allow-listed SPA origin gets the
// reference's credentialed CORS on the auth routes and nothing on the console.
//
// ── what POST <admin>/login does not do, and what the product adds to it ─────
//
// The console's own login is password-only. Its third arm looks the email up
// in the empty tenant and verifies the password (core admin.go adminLogin,
// admin.router.ts:566-573), and that is the whole check: no TOTP or SMS step,
// no consultation of the account's enrolment or of the settings store's
// require2FA. An account that POST <prefix>/login would challenge for a second
// factor is signed into the console on its password alone, with a 24h admin
// token. That is the reference's behaviour, the core reproduces it, and this
// binary cannot close it without a route it may not add -- so it is registered
// as a product deviation (admin-login-skips-the-second-factor), stated in
// config-reference §16.2 beside the paragraph that used to read as if the
// 2FA-bypass class were closed, and mitigated two ways. The rateLimit block
// is put in front of the route by a middleware over the mount (ratelimit.go
// newAdminLoginLimiter), on the same budget and the same keyBy rule as
// POST <prefix>/login, because the route was otherwise an unlimited password
// oracle for every user in the empty tenant and a constant-time compare
// against the bootstrap secret. And admin.loginPath, pointed at the hosted
// login, sends a browser through the flow that does enforce the second factor;
// the ordinary access token it ends with is an admin credential the guard
// judges. A deployment that requires 2FA sets it.
//
// ── the mapping, field by field ──────────────────────────────────────────────
//
// **Enabled ← admin.enabled.** The switch, and on its own not enough:
// AdminMounted() also wants an access decision, which RS-6 already guarantees
// at load time — a document with admin.enabled and neither an access policy nor
// a bootstrap secret is refused before this file runs. That is the upstream
// deviation admin-console-requires-an-explicit-policy meeting the product's
// own RS-6 from the other side; the two agree, and the effect is that a
// deployment can never come up serving the reference's unguarded console.
//
// **Path ← admin.basePath.** Passed as written; the core normalises it the way
// it normalises the api prefix.
//
// **AccessPolicy ← admin.accessPolicy**, through adminAccessPolicy. The three
// named policies map onto the core's three constructors. The two string forms
// — rbac:<role> and permission:<perm> — are this product's sugar, invented by
// config-schema.md §1.13 over the reference's custom-predicate arm
// (admin.router.ts:41, :376), and they become an auth.AdminPredicate evaluated
// against the RBAC store the core holds. adminRBACPredicate says what each one
// grants and what an error means; the short version is that a predicate error
// is a *denial*, never a 500, because the reference wraps the whole policy
// evaluation in a try/catch whose catch sets granted = false (:378-380) and the
// core keeps that (AdminPolicyFunc). internal/config already requires
// stores.enable.rbac for either form (rules.go, checkStoreRequirements), so
// the store the predicate reads is never nil in a document that loaded.
//
// **Secret ← admin.bootstrapSecret.** The reference's deprecated adminSecret,
// kept because the reference keeps it and because it is the honest bootstrap
// for a deployment with no local users yet: under a policy it is also a
// password the login route accepts for the empty email or "admin"
// (admin.router.ts:557-562), minting a token that carries isRoot. Empty when
// the knob is unconfigured, and the core reads empty as unset.
//
// **JWTSecret is left empty, deliberately, and that is the integration.** The
// core reads an empty JWTSecret as Config.Secret — the access-token secret —
// which is what the reference's "must match AuthConfig.accessTokenSecret"
// (admin.router.ts:70-78) asks a host to arrange by hand, and what
// config-schema.md §1.13 folded AdminOptions.jwtSecret into (RS-7). It is the
// arrangement under which an ordinary access token is a valid admin credential
// for the policy to judge, so a user signed in through <prefix>/login can open
// the console without a second login. What it is *not* is the reference's
// hazard. There, a bare jwt.verify over that shared secret makes every token
// the secret signs an admin credential — a refresh token, and the typed step-up
// token a user holds after a password and before a second factor, so 2FA can
// be bypassed on the console. The core types the admin token and accepts
// exactly two typ values, "admin" and "access", honouring isRoot only on the
// first; that is the upstream deviation admin-guard-accepts-only-typed-session-tokens,
// and this product inherits the fix by construction, because it never signs a
// token with anything but the core. Setting a *different* JWTSecret would sever
// the integration without buying any of that back, which is why there is no
// knob for it.
//
// **LoginPath ← admin.loginPath.** Set, the guard answers 302 to
// <loginPath>?redirect=<admin path> for an unauthenticated browser instead of
// serving the built-in form. Emitted as given; validate.go already requires an
// absolute path or a URL.
//
// **CookiePrefix ← admin.cookiePrefix, as "unset" when empty.** The core's
// field is a *string because the reference distinguishes an explicit empty
// prefix (the bare cookie name "accessToken") from no prefix at all (derive it
// from CookieOptions on the way out, try three names on the way in). The
// product schema is a plain string and cannot spell the difference, so this
// file decides it: empty is unset, and the core then derives the name from
// `cookies.secure`, `cookies.path` and `cookies.domain` exactly as the auth
// routes derive theirs. That is the arrangement that keeps the admin cookie and
// the session cookies from disagreeing about the deployment, and it is also the
// only one in which the bare name is ever *wanted* — a non-Secure deployment —
// where derivation already yields it. An explicit "" therefore has no use case
// the derivation does not already cover, and is not expressible. A non-empty
// value is an explicit override, as there.
//
// **RootUser ← admin.rootUser.** The bootstrap credential that lives in
// configuration rather than in the user store: an email and a bcrypt hash, the
// hash a Secret so it is fetched from a store and never sits in the document.
// Half of it is refused: an email with no resolvable hash is a login that can
// never succeed, silently, so adminOptions refuses the cold start rather than
// serve a form that will always say "Invalid credentials".
//
// **AuthAPIPrefix is left empty.** The core resolves it to HTTPConfig.Prefix(),
// which *is* http.apiPrefix, normalised once rather than twice; the reference
// needs to be told because its admin router is a separate Express router with
// no way to ask, and this deployment configures both from one document.
//
// **UploadBaseURL is left empty.** The core derives it from the mount —
// <prefix>/ui/assets/uploads — which is where UIHandler serves the objects back
// (upstream deviation admin-upload-base-url-is-derived-from-the-mount). A
// deployment that serves the bucket from a CDN would set it; nothing in this
// product does, and the CloudFront front door caches nothing, so the derived
// URL is the right one behind it too.
//
// **Docs ← docs.swagger, resolved the way D4 resolved it.** The console's own
// documentation pair, GET <admin>/api/openapi.json and GET <admin>/api/docs,
// follows the same three-valued knob as the auth router's: `auto` resolves
// against deployment.environment through docsEnabled, on outside production
// and off in it, and the two pairs cannot come up disagreeing. There is one
// thing to know before turning it on that the auth router's pair does not
// carry: these two routes are the only routes under <admin>/api that the
// reference registers with no guard (admin.router.ts:1499, :1517), so an
// anonymous caller reads the whole documented admin surface — every path,
// every body, and which optional stores this deployment wired. The core
// reproduces the asymmetry rather than tidying it away and says why
// (AdminOptions.Docs); the product's contribution is the same
// Content-Security-Policy the auth router's page gets (docsSecurityHeaders),
// because the console's Swagger page loads the same unpinned CDN bundle onto
// the same origin. BasePath is left empty: the core defaults it to the mount.
//
// **RateLimiter ← the promote route's own limiter**, set in mountAuthSurface
// beside the auth router's for the reason that one is set there — it captures
// the counter only the composition root holds. See newAdminPromoteLimiter in
// ratelimit.go for why the slot is filled rather than left nil, and for why
// its subject is the client address. The login's limiter is not in this slot,
// which the core spreads onto the promote route alone; it is a middleware over
// the mount (newAdminLoginLimiter, applied by assembleHandler).
//
// **sessionTtl and upload.maxFileSizeMb reach nothing, and say so.** The core
// signs the admin token with the reference's fixed expiresIn: '24h' and the
// cookie with the matching maxAge (admin.go adminSessionTTL, admin.router.ts:585,
// :610) and exposes no option for either; the upload routes bound a file at
// auth.UploadMaxBytes, a constant carrying the reference's own multer limit of
// 5 MiB. Both knobs are [new] in the schema — inventions of the product over
// values the reference hard-codes — and neither reaches the core, so both are
// reported by unwiredKnobs at cold start when they differ from the value the
// core actually applies, rather than silently ignored. Their defaults are
// those values, so a document that leaves them alone reports nothing.
//
// ── the stores, and what the admin slot finally holds ────────────────────────
//
// The core takes five stores by name that it cannot discover on the user store:
// auth.WithMetadataProvider, WithRBACProvider, WithTenantProvider,
// WithAPIKeyStore and WithWebhookStore. The DynamoDB store has implemented all
// five since D6, reachable through accessors, and D6 deliberately did not list
// their stores.enable flags in driverStores — a flag that validates and hands
// nothing to the core is a knob that does nothing (config-reference §4.1). This
// block is where each flag becomes a real switch: adminOptions hands the store
// over when its flag is on, and driverStores now lists the five. The
// consequence is visible on the console's feature object — GET <admin>/api/ping
// reports roles, tenants, metadata, apiKeys and webhooks true exactly when the
// flag is — and on one auth route: with stores.enable.metadata on, the profile
// GET <prefix>/me renders carries the user's metadata (core service.go:1295),
// which is the reference's own behaviour with a metadata store passed.
//
// stores.enable.telemetry stays out of this slot and out of driverStores. The
// telemetry store reaches a route only through ToolsOptions.TelemetryStore,
// which is the tools block's and D9a's to hand over; listing it here would be
// the very knob-that-does-nothing D6 refused.
//
// ── uploads, and the deviation this retires ──────────────────────────────────
//
// `ui.uploadDir` is the reference's one upload-location knob, read by the admin
// router as the directory to write into and by the UI router as the directory
// to serve from (admin.router.ts:656, ui.router.ts:185-191). D7 accepted it and
// honoured nothing, registering ui-uploaded-assets-are-not-served with three
// reasons, and this block answers all three. *There is a writer now*: the four
// upload routes. *The noun is decided*: on this product the knob names an S3
// location, `s3://<bucket>[/<prefix>]`, which is what config-schema.md §1.12
// said the serverless target would be, and a plain path — the reference's
// meaning — is accepted for portability and reported by unwiredKnobs as one
// this runtime cannot honour, with the s3:// form as the remedy. *And the read
// path is built beside the write path*: one auth.UploadStore, handed to the core
// through auth.WithUploadStore, serves both — the admin routes write through
// it, and UIHandler serves <prefix>/ui/assets/logo/ and /assets/uploads/ from
// it through auth.UploadFS when UIOptions.Uploads is nil, which ui.go leaves it.
// The cost D7 named is real and is now paid knowingly: every request for an
// uploaded asset is one GetObject, misses included, and docs/cost-model.md
// carries the number. With no S3 location configured there is no store, the
// console draws no file picker, the four routes are not registered, and the two
// UI paths answer 404 — which is the reference's own behaviour with uploadDir
// unset, so nothing is registered for it.
//
// What is registered is the header the read path adds. The reference's
// allow-list admits .svg by name, and an SVG served same-origin is a document
// that may carry script, running with the auth cookies; the core states the
// trade and hands it to the host (upload_store.go UploadNameAllowed).
// uploadAssetHeaders below takes it: a sandboxing Content-Security-Policy and
// nosniff on the two asset paths, in the shape docsSecurityHeaders has, so no
// route is added (uploaded-assets-carry-a-content-security-policy).
//
// One bound the docs used to call "deployed" is not reachable here and is
// stated in config-reference §16.5 instead: the core refuses a file over
// UploadMaxBytes (5 MiB) with its own 413 envelope, but a multipart body reaches
// this function base64-encoded inside a synchronous invocation event capped at
// 6 MB (internal/lambdahttp/request.go), so a file past roughly 4.4 MiB never
// reaches the core and is refused by the platform with its own 413 body. The
// effective ceiling is the platform's, and the knob-gap text says so.
//
// ── what the console cannot see, and the backfill it depends on ──────────────
//
// GET <admin>/api/users reads AdminUserStore.ListUsers, which on the DynamoDB
// driver is a Query over a sparse index that only profiles written since D6
// are in. A table with older rows under-reports, and the failure is not visible
// from outside. `migrate backfill-users` is the one-time sweep that closes it
// (cmd/migrate, internal/store/dynamodb backfill.go); logAdminSurface names it
// at cold start whenever the console mounts on that driver, because the log is
// the only place this deployment can say it.
//
// The 'first-user' policy read the same lister and is refused at load on every
// driver (RS-17), for a reason the backfill cannot fix: the lister orders by
// id, ids are random, and "the first user" is whoever drew the lowest one.
// adminAccessPolicy keeps the mapping for a Config that bypassed the loader,
// and logAdminSurface says what that Config gets. The register entry is
// admin-first-user-policy-is-refused (deviations.go).

// adminStoreProvider is what the composition root asks of the driver's store,
// structurally, the way settingsStoreProvider asks for the settings store:
// the five accessors the DynamoDB store and the memory bundle both expose. The
// migrating wrapper embeds the concrete store, so the methods are promoted and
// one lookup serves every driver.
type adminStoreProvider interface {
	Metadata() auth.UserMetadataStore
	Roles() auth.RolesPermissionsStore
	Tenants() auth.TenantStore
	APIKeys() auth.APIKeyStore
	Webhooks() auth.WebhookStore
}

// adminOptions is the `admin` slot of coreOptionSets: the five named stores,
// behind their flags, and the upload store.
//
// It refuses for two things a document can say and the core would otherwise
// serve wrongly. A flag on for a store the driver's value does not expose is
// refused by name, the way settingsOptions refuses — driverStores has already
// refused the driver, so this is the guard behind the guard, for a factory a
// test injects. And a root user with an email and no resolvable hash is refused
// rather than mounted as a login that always fails.
//
// It contributes options whether or not admin.enabled is set, and that is the
// meaning of the flags: stores.enable.metadata says "hand the metadata store to
// the core", which changes GET <prefix>/me today and the console tomorrow.
// Gating the hand-over on admin.enabled would make the flag mean two things.
func adminOptions(cfg *config.Config, opts Options, users auth.UserStore, log *slog.Logger) ([]auth.Option, error) {
	var out []auth.Option

	enable := cfg.Stores.Enable
	wanted := enable.Metadata || enable.RBAC || enable.Tenants || enable.APIKeys || enable.Webhooks
	provider, ok := users.(adminStoreProvider)
	if wanted && !ok {
		return nil, fmt.Errorf(
			"config: refusing to start: a stores.enable flag for the admin console's stores is on, but the %s driver's store exposes none of them in this build, "+
				"so the flag would validate and hand nothing to the core -- turn it off until the driver grows the store",
			cfg.Stores.Driver)
	}
	handed := make([]string, 0, 5)
	add := func(on bool, name string, build func() (auth.Option, bool)) error {
		if !on {
			return nil
		}
		opt, present := build()
		if !present {
			return fmt.Errorf(
				"config: refusing to start: stores.enable.%s is on, but the %s driver does not provide that store in this build, "+
					"so the console's tab would be drawn over a route that answers 404 -- turn it off until the driver grows it",
				name, cfg.Stores.Driver)
		}
		out = append(out, opt)
		handed = append(handed, name)
		return nil
	}
	for _, row := range []struct {
		on    bool
		name  string
		build func() (auth.Option, bool)
	}{
		{enable.Metadata, "metadata", func() (auth.Option, bool) {
			s := provider.Metadata()
			return auth.WithMetadataProvider(s), s != nil
		}},
		{enable.RBAC, "rbac", func() (auth.Option, bool) {
			s := provider.Roles()
			return auth.WithRBACProvider(s), s != nil
		}},
		{enable.Tenants, "tenants", func() (auth.Option, bool) {
			s := provider.Tenants()
			return auth.WithTenantProvider(s), s != nil
		}},
		{enable.APIKeys, "apiKeys", func() (auth.Option, bool) {
			s := provider.APIKeys()
			return auth.WithAPIKeyStore(s), s != nil
		}},
		{enable.Webhooks, "webhooks", func() (auth.Option, bool) {
			s := provider.Webhooks()
			return auth.WithWebhookStore(s), s != nil
		}},
	} {
		if err := add(row.on, row.name, row.build); err != nil {
			return nil, err
		}
	}

	uploads, err := newUploadStore(cfg, opts.UploadStore)
	if err != nil {
		return nil, err
	}
	if uploads != nil {
		out = append(out, auth.WithUploadStore(uploads))
	}

	if cfg.Admin.Enabled {
		if err := checkAdminRootUser(cfg); err != nil {
			return nil, err
		}
	}

	log.Info("admin stores wired",
		slog.String("handedToTheCore", strings.Join(handed, ",")),
		slog.Bool("uploadStore", uploads != nil),
		slog.String("note", "each store reaches a console tab when admin.enabled is on; the metadata store also reaches GET <prefix>/me"))
	return out, nil
}

// newUploadStore builds the auth.UploadStore for `ui.uploadDir`, or nil when
// the knob names no S3 location.
//
// injected is the Options.UploadStore seam, and like Mail and SMS it switches
// nothing on: it is consulted only when the document names an S3 location, so a
// test cannot exercise a composition the binary would never build. A plain
// path is not an error here — it is reported by adminKnobGaps — and a
// malformed s3:// value is, because it is neither a path nor a location.
func newUploadStore(cfg *config.Config, injected auth.UploadStore) (auth.UploadStore, error) {
	bucket, prefix, isS3, err := awsintegration.ParseS3Location(cfg.UI.UploadDir)
	if err != nil {
		return nil, fmt.Errorf("config: refusing to start: ui.uploadDir: %w", err)
	}
	if !isS3 {
		return nil, nil
	}
	if injected != nil {
		return injected, nil
	}
	store, err := awsintegration.NewS3UploadStore(awsintegration.S3UploadOptions{
		Bucket: bucket,
		Prefix: prefix,
		Region: cfg.Stores.Connection.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("config: refusing to start: ui.uploadDir: %w", err)
	}
	return store, nil
}

// checkAdminRootUser refuses a root user that can never log in.
//
// validate.go checks the email's shape and nothing about the pair, because the
// hash is a Secret resolved at load time and the pairing is only knowable
// here. An email with no hash is not "no root user": the login route compares
// the presented password against an empty hash and refuses, so the form is
// served and always answers "Invalid credentials" — the silent shape this
// product refuses elsewhere. A hash with no email is inert and is left alone;
// it is the shape a template carries when the operator has not yet chosen the
// address.
func checkAdminRootUser(cfg *config.Config) error {
	email := strings.TrimSpace(cfg.Admin.RootUser.Email)
	hash := cfg.SecretValue("admin.rootUser.passwordHash")
	if email != "" && hash == "" {
		return errors.New("config: refusing to start: admin.rootUser.email is set but admin.rootUser.passwordHash resolves to nothing, " +
			"so the root login would be served and could never succeed -- reference a bcrypt hash from a secret store, or remove the email")
	}
	if hash != "" && !strings.HasPrefix(hash, "$2") {
		return errors.New("config: refusing to start: admin.rootUser.passwordHash does not resolve to a bcrypt hash (it must begin with $2a$, $2b$ or $2y$), " +
			"so the root login could never succeed -- store the hash, never the password")
	}
	return nil
}

// adminHTTPOptions builds HTTPConfig.Admin out of the `admin` block. It is total
// and does no I/O, for the reason uiOptions and docsOptions are: httpConfig has
// callers that want nothing but Prefix(), and every refusal this block can make
// is made by adminOptions at cold start. The rate limiter is not here; see the
// file header and mountAuthSurface.
func adminHTTPOptions(cfg *config.Config) auth.AdminOptions {
	out := auth.AdminOptions{
		Enabled:      cfg.Admin.Enabled,
		Path:         cfg.Admin.BasePath,
		AccessPolicy: adminAccessPolicy(cfg),
		Secret:       cfg.SecretValue("admin.bootstrapSecret"),
		// Empty on purpose: Config.Secret, i.e. security.jwt.accessTokenSecret.
		// See the file header.
		JWTSecret: "",
		LoginPath: cfg.Admin.LoginPath,
		// Empty on purpose: HTTPConfig.Prefix(), which is http.apiPrefix.
		AuthAPIPrefix: "",
		// Empty on purpose: derived from the mount by the core.
		UploadBaseURL: "",
		Docs: auth.DocsOptions{
			Enabled: docsEnabled(cfg),
			// Empty on purpose: the core defaults the described base to the
			// mount, which is the reference's own `swaggerBasePath ?? '/admin'`.
			BasePath: "",
		},
	}
	if prefix := cfg.Admin.CookiePrefix; prefix != "" {
		out.CookiePrefix = &prefix
	}
	if email := strings.TrimSpace(cfg.Admin.RootUser.Email); email != "" {
		if hash := cfg.SecretValue("admin.rootUser.passwordHash"); hash != "" {
			out.RootUser = &auth.AdminRootUser{Email: email, PasswordHash: hash}
		}
	}
	return out
}

// adminAccessPolicy maps admin.accessPolicy onto the core's policy value.
//
// An empty policy is nil, which is "not set" to the core, and is the state RS-6
// only permits alongside a bootstrap secret — the legacy bearer guard, and the
// second arm of the reference's selection at admin.router.ts:516-537. An
// unrecognised spelling cannot reach here: validate.go refuses it with the
// knob's path.
func adminAccessPolicy(cfg *config.Config) *auth.AdminAccessPolicy {
	policy := strings.TrimSpace(cfg.Admin.AccessPolicy)
	switch {
	case policy == "":
		return nil
	case policy == config.AdminAccessPolicyOpen:
		return auth.AdminOpen()
	case policy == config.AdminAccessPolicyFirstUser:
		return auth.AdminFirstUser()
	case policy == config.AdminAccessPolicyIsAdmin:
		return auth.AdminIsAdminFlag()
	case strings.HasPrefix(policy, config.AdminAccessPolicyRBACPrefix):
		return auth.AdminPredicate(adminRBACPredicate(adminPredicateRole, strings.TrimPrefix(policy, config.AdminAccessPolicyRBACPrefix)))
	case strings.HasPrefix(policy, config.AdminAccessPolicyPermPrefix):
		return auth.AdminPredicate(adminRBACPredicate(adminPredicatePermission, strings.TrimPrefix(policy, config.AdminAccessPolicyPermPrefix)))
	default:
		// Unreachable for a Config that went through validate(); for one that
		// did not, a zero policy is the core's "a string nobody matched",
		// which refuses every request 403 rather than admitting anybody.
		return &auth.AdminAccessPolicy{}
	}
}

// The two shapes of RBAC predicate the product's string forms compile to.
type adminPredicateKind int

const (
	// adminPredicateRole grants a user who holds the named role in their own
	// tenant: `rbac:<role>` is `getRolesForUser(user.id, user.tenantId)`
	// containing <role>.
	adminPredicateRole adminPredicateKind = iota
	// adminPredicatePermission grants a user who holds the named permission
	// through any of their roles: `permission:<perm>` is
	// `userHasPermission(user.id, <perm>, user.tenantId)`.
	adminPredicatePermission
)

// adminRBACPredicate builds the auth.AdminPolicyFunc for one string form.
//
// Three things about it are decisions rather than transcriptions, because the
// reference has no such string forms — it has an arbitrary host function
// (admin.router.ts:41) — and the schema invented these over it.
//
// The tenant is the user's own. The guard resolved the principal by id and
// tenant off the token, and a role or permission is a tenant-scoped assignment
// in the store's own vocabulary (AddRoleToUser carries a tenant), so the only
// tenant that can be meant is the one the user was found in. A single-tenant
// deployment passes "", which is the store's single tenant.
//
// A nil store is a denial with an error, not a panic and not a grant. The core
// hands the predicate whatever RBAC store it holds, and internal/config
// requires stores.enable.rbac for either string form, so it is never nil in a
// document that loaded; a test that bypasses the loader gets a refusal that
// names the cause.
//
// And an error from the store is a denial, which is the seam's contract and
// the reference's `catch { granted = false }` (:378-380): a console whose role
// store is unreachable answers 403 to everyone, not 500 — the same direction
// the rate limiter's fail-open argument runs in reverse, and deliberately so,
// because a guard that fails open is not a guard.
func adminRBACPredicate(kind adminPredicateKind, name string) auth.AdminPolicyFunc {
	return func(ctx context.Context, user auth.User, rbac auth.RolesPermissionsStore) (bool, error) {
		if rbac == nil {
			return false, errors.New("admin access policy needs the RBAC store and none is wired (stores.enable.rbac)")
		}
		switch kind {
		case adminPredicatePermission:
			return rbac.UserHasPermission(ctx, user.ID, name, user.TenantID)
		default:
			roles, err := rbac.GetRolesForUser(ctx, user.ID, user.TenantID)
			if err != nil {
				return false, err
			}
			for _, r := range roles {
				if r == name {
					return true, nil
				}
			}
			return false, nil
		}
	}
}

// adminSessionTTL is the reference's expiresIn: '24h' (admin.router.ts:585),
// transcribed because the core keeps it unexported (admin.go adminSessionTTL)
// and this file has to know what the deployed value is in order to report a
// knob that differs from it. TestAdminSessionTTLMatchesTheCore holds the two
// together.
const adminSessionTTL = 24 * time.Hour

// adminKnobGaps reports the three knobs of the console's surface the core
// cannot act on: the two [new] ones the schema invented over reference
// constants, and ui.uploadDir in its filesystem spelling.
//
// The first two are reported only when they differ from the value the core
// applies, because their defaults *are* those values and a warning for a
// document that changed nothing would be noise. The third is reported
// whenever it is set and is not an S3 location: on this runtime a path names
// nothing durable, the reference's meaning cannot be honoured, and the remedy
// is the spelling that can.
func adminKnobGaps(cfg *config.Config) []knobGap {
	var gaps []knobGap

	if ttl := cfg.Admin.SessionTTL.Duration(); ttl != 0 && ttl != adminSessionTTL {
		gaps = append(gaps, knobGap{
			Path: "admin.sessionTtl",
			Problem: fmt.Sprintf("the auth core signs the admin session with the reference's fixed 24h (admin.router.ts:585) and exposes no option for it, "+
				"so the deployed lifetime stays 24h and not the configured %s", ttl),
			Remedy: "remove the override until the core exports an option for it; the schema marks the knob [new] over a value the reference hard-codes",
		})
	}

	if mb := cfg.Admin.Upload.MaxFileSizeMb; mb != 0 && int64(mb)<<20 != auth.UploadMaxBytes {
		gaps = append(gaps, knobGap{
			Path: "admin.upload.maxFileSizeMb",
			Problem: fmt.Sprintf("the auth core bounds an upload at UploadMaxBytes, a constant carrying the reference's multer limit of %d MiB (admin.router.ts:1016), "+
				"so the bound the core applies stays %d MiB and not the configured %d -- and the bound a client actually meets is lower still: "+
				"a multipart body reaches this function base64-encoded inside a 6 MB invocation event, so a file past roughly 4.4 MiB is refused by API Gateway "+
				"with its own 413 body before the core sees it", auth.UploadMaxBytes>>20, auth.UploadMaxBytes>>20, mb),
			Remedy: "remove the override until the core exports an option for it; the schema marks the knob [new] over a value the reference hard-codes",
		})
	}

	if dir := strings.TrimSpace(cfg.UI.UploadDir); dir != "" {
		if _, _, isS3, _ := awsintegration.ParseS3Location(dir); !isS3 {
			gaps = append(gaps, knobGap{
				Path: "ui.uploadDir",
				Problem: fmt.Sprintf("%q is a filesystem path, and a Lambda has no directory that survives a request (/var/task is read-only, /tmp is per execution environment), "+
					"so no upload store is built: the console draws no file picker, the four upload routes are not registered, and GET <prefix>/ui/assets/uploads/* answers 404", dir),
				Remedy: "name an S3 location instead, s3://<bucket>[/<prefix>], which this build honours for both the console's uploads and the UI's asset paths " +
					"(infra/sam/template.yaml creates one with EnableAdminUploads=true); leave the path set only if the same document is deployed to another port in the family",
			})
		}
	}
	return gaps
}

// logAdminSurface announces what the `admin` block resolved to, and says the
// three things a deployment can get wrong while looking healthy that are
// visible from nowhere else: that the console is not mounted and why, which
// policy decides who gets in, and that the user directory on the DynamoDB
// driver is only as complete as the backfill.
func logAdminSurface(cfg *config.Config, hc auth.HTTPConfig, log *slog.Logger) {
	mount := hc.AdminPath()

	if !hc.AdminMounted() {
		why := "admin.enabled is off"
		if cfg.Admin.Enabled {
			why = "admin.enabled is on but neither admin.accessPolicy nor admin.bootstrapSecret is set (the core refuses to mount an unguarded console; RS-6 refuses the document first)"
		}
		log.Info("admin console not mounted",
			slog.String("path", "admin.enabled"),
			slog.String("why", why),
			slog.String("effect", "every path under "+mount+" answers 404"))
		return
	}

	policy := cfg.Admin.AccessPolicy
	grants := ""
	switch {
	case policy == config.AdminAccessPolicyOpen:
		grants = "EVERY request, with no token read and no store consulted -- the reference's own default, for use only behind a network boundary this stack does not provide"
	case policy == config.AdminAccessPolicyFirstUser:
		// Unreachable for a Config that went through the loader: RS-17 refuses
		// the policy on every driver, because ids are random here and the
		// "first" user is whoever drew the lowest one. Said plainly for the
		// Config that bypassed it.
		grants = "the user whose id sorts first in ListUsers(1, 0) -- the LOWEST RANDOM id, not the first registered account; RS-17 refuses this policy at load and this deployment bypassed the loader"
	case policy == config.AdminAccessPolicyIsAdmin:
		grants = "a user whose isAdmin flag is set; POST " + mount + "/users/{id}/promote with method=flag sets it"
	case strings.HasPrefix(policy, config.AdminAccessPolicyRBACPrefix):
		grants = "a user holding the role " + strings.TrimPrefix(policy, config.AdminAccessPolicyRBACPrefix) + " in their own tenant; a store error is a denial"
	case strings.HasPrefix(policy, config.AdminAccessPolicyPermPrefix):
		grants = "a user holding the permission " + strings.TrimPrefix(policy, config.AdminAccessPolicyPermPrefix) + " through any role in their own tenant; a store error is a denial"
	default:
		policy = "(legacy bootstrap secret)"
		grants = "any caller presenting admin.bootstrapSecret as a bearer token; the shell is served unguarded and the SPA holds the secret in sessionStorage"
	}

	credentials := "an access token minted by POST " + hc.Prefix() + "/login (cookie or bearer), or an admin token from POST " + mount + "/login -- " +
		"the latter on a password alone, with no second factor (product deviation admin-login-skips-the-second-factor), and neither revocable by the session store"
	if policy == config.AdminAccessPolicyOpen {
		credentials = "none required"
	}

	// Info, except for the one policy that is a hazard rather than a choice:
	// an open console on a stack whose every front door is internet-facing is
	// announced at Warn, as the unguarded documentation pair below is.
	level := slog.LevelInfo
	if policy == config.AdminAccessPolicyOpen {
		level = slog.LevelWarn
	}
	// The attribute is bootstrapSecretConfigured and not bootstrapSecret: the
	// bare name is on the redaction list (logging.go), so a boolean under it
	// would print as [REDACTED] and the line could never say what it is for.
	log.Log(context.Background(), level, "admin console mounted",
		slog.String("mount", mount),
		slog.String("accessPolicy", policy),
		slog.String("grants", grants),
		slog.String("credentials", credentials),
		slog.Bool("rootUser", hc.Admin.RootUser != nil),
		slog.Bool("bootstrapSecretConfigured", strings.TrimSpace(hc.Admin.Secret) != ""),
		slog.String("loginPath", hc.Admin.LoginPath),
		slog.Bool("docs", hc.Admin.Docs.Enabled),
		slog.String("note", "an unauthenticated GET that accepts text/html reaches only the login shell, never a guarded route (upstream deviation admin-unauthenticated-get-serves-only-the-login-form); "+
			"the 2FA step-up token is not an admin credential (admin-guard-accepts-only-typed-session-tokens); "+
			"sessions.checkOn does not reach this surface, and an admin token lives its 24h whatever happens to the account -- rotating security.jwt.accessTokenSecret is the one kill switch"))

	if hc.Admin.Docs.Enabled {
		log.Warn("the admin console's documentation pair is mounted unguarded",
			slog.String("path", "docs.swagger"),
			slog.String("spec", mount+auth.AdminOpenAPIPath),
			slog.String("page", mount+auth.AdminDocsPath),
			slog.String("problem", "these are the only two routes under "+mount+"/api the reference registers with no guard: an anonymous caller reads the whole documented admin surface and which stores this deployment wired"),
			slog.String("remedy", "set docs.swagger to false, or accept it on an internal stack; both responses carry the documentation Content-Security-Policy"))
	}

	if cfg.Stores.Driver == config.StoreDriverDynamoDB {
		log.Warn("the admin user directory is only as complete as the backfill",
			slog.String("path", "stores.driver"),
			slog.String("problem", "GET "+mount+"/api/users reads a sparse index that only profiles written since the D6 release are in; "+
				"older profiles are found by every other method and missing from this one"),
			slog.String("remedy", "run `migrate backfill-users --table "+cfg.Stores.Connection.TableName+" --region <region>` once against this table (idempotent, safe while serving); "+
				"nothing in this function can do it, because the sweep is a Scan the execution role does not grant"))
	}
}

// adminDocsPaths are the two documentation routes of the console, as mounted,
// for docsSecurityHeaders — or none when the console or the pair is off.
func adminDocsPaths(cfg *config.Config) (spec, page string, ok bool) {
	hc := httpConfig(cfg)
	if !hc.AdminMounted() || !hc.Admin.Docs.Enabled {
		return "", "", false
	}
	return hc.AdminPath() + auth.AdminOpenAPIPath, hc.AdminPath() + auth.AdminDocsPath, true
}

// checkAdminMounted is the assertion the core recommends a host make at
// startup — `if cfg.Admin.Enabled && !cfg.AdminMounted() { fatal }` — which
// turns an unexpected 404 on the console into a message. RS-6 makes it
// unreachable for a document that loaded; it stays as the refusal a bypassed
// loader would meet.
func checkAdminMounted(cfg *config.Config, hc auth.HTTPConfig) error {
	if cfg.Admin.Enabled && !hc.AdminMounted() {
		return errors.New("config: refusing to start: admin.enabled is on and no access decision is configured, so the core would mount nothing and every admin path would answer 404 " +
			"-- set admin.accessPolicy or reference admin.bootstrapSecret from a store (RS-6)")
	}
	return nil
}

// uploadAssetCSP is the policy every uploaded asset is served under. It is
// aimed at one file type on the reference's allow-list: an SVG is an XML
// document that may carry script, and served same-origin it would run with
// the auth cookies — where the CSRF cookie is readable from JavaScript by
// design and the admin API has no CSRF layer. `sandbox` makes a top-level SVG
// an opaque-origin document with scripts, forms and navigation off;
// `default-src 'none'` closes every fetch; `style-src 'unsafe-inline'` is
// what lets an honest SVG's own <style> render. The core names the trade and
// hands it to the host (upload_store.go UploadNameAllowed: "behind a
// Content-Security-Policy, or drops 'svg'"); this is the first of those, taken
// because dropping svg would break a console that offers it and would be a
// different product from the reference.
const uploadAssetCSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"

// uploadAssetHeaders decorates the two paths the hosted UI serves uploaded
// assets from — <prefix>/ui/assets/logo/* and <prefix>/ui/assets/uploads/* —
// with uploadAssetCSP and X-Content-Type-Options: nosniff.
//
// The shape is docsSecurityHeaders': a middleware over the whole mux that
// registers no pattern, so the adapter still owns the surface. It matches on
// the resolved prefix and the core's UIRoute, so a customised api prefix moves
// the headers with the routes. nosniff is the other half of the core's warning
// on the same seam: the allow-list tests the file's name and nothing else, so
// a file named logo.png holding HTML is stored and served as image/png, and a
// host serving the prefix without nosniff "is relying on the type header
// alone".
//
// Identity when no store is built — a plain-path ui.uploadDir, or none — or the
// UI is off, because then both paths answer 404 and a policy on a 404 is a
// claim about a surface this deployment does not have. With a store built the
// headers go on every response under the two paths, misses included, because
// a 404 body is a document too. Registered as
// uploaded-assets-carry-a-content-security-policy (deviations.go).
func uploadAssetHeaders(cfg *config.Config) func(http.Handler) http.Handler {
	identity := func(next http.Handler) http.Handler { return next }
	if !cfg.UI.Enabled {
		return identity
	}
	if _, _, isS3, _ := awsintegration.ParseS3Location(cfg.UI.UploadDir); !isS3 {
		return identity
	}
	mount := httpConfig(cfg).Prefix() + auth.UIRoute
	paths := [...]string{mount + "/assets/logo/", mount + "/assets/uploads/"}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range paths {
				if strings.HasPrefix(r.URL.Path, p) {
					h := w.Header()
					h.Set("Content-Security-Policy", uploadAssetCSP)
					h.Set("X-Content-Type-Options", "nosniff")
					break
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// adminPromoteScope is the counter scope of the promote route's limiter. It is
// not a rateLimit.scope name — that vocabulary is the auth router's
// unauthenticated flows, and this route is neither — but a name the shared
// counter keys on, distinct from every scope a document can spell.
const adminPromoteScope = "admin-promote"
