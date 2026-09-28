package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	"github.com/nik2208/awesome-lambda-auth/internal/lambdahttp"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// Where the configuration document comes from.
//
// §4 of docs/spec/config-schema.md leaves the format decision open (YAML file
// vs SSM tree vs both), so this binary commits to the smallest thing that keeps
// every option available: it reads a JSON document, from a file or from the
// environment, and does not care who produced it. A YAML front end or an SSM
// compiler plugs in later by writing that JSON, and neither the loader nor this
// entrypoint changes.
const (
	// ConfigFileEnv names a path to a JSON configuration document. In a Lambda
	// that is a file baked into the deployment package or mounted from EFS.
	ConfigFileEnv = "AWESOME_AUTH_CONFIG_FILE"

	// ConfigJSONEnv carries a JSON configuration document inline. Convenient for
	// a small stack and for tests; secrets never appear in it, because
	// secret-valued knobs hold a store reference and not a value.
	ConfigJSONEnv = "AWESOME_AUTH_CONFIG_JSON"
)

// StoreFactory builds the persistence layer for a validated configuration.
// Injected so that the composition can be tested without an AWS account: the
// production factory is defaultStoreFactory.
type StoreFactory func(ctx context.Context, cfg *config.Config, log *slog.Logger) (auth.UserStore, auth.SessionStore, error)

// Options configures New. The zero value is what main uses: the real
// environment, the real filesystem, a JSON logger on stdout and the real
// stores.
type Options struct {
	Getenv   func(string) (string, bool)
	ReadFile func(string) ([]byte, error)
	Logger   *slog.Logger
	Stores   StoreFactory

	// Secrets are the stores consulted for secret-valued knobs. The zero value
	// wires the real AWS-backed resolvers; a test injects fakes.
	Secrets config.Resolvers

	// Mail and SMS inject the credential-delivery transports, for the same
	// reason Stores is injectable: the composition has to be provable without an
	// AWS account. Nil — the zero value — builds the real SES and SNS transports.
	//
	// Injecting one does NOT switch delivery on. Whether a sender is wired at
	// all stays a question about the configuration (see mailConfigured and
	// smsConfigured in delivery.go), so a test cannot accidentally exercise a
	// composition the binary would never build.
	Mail auth.MailerTransport
	SMS  auth.SMSTransport

	// IDPKeySource injects the identity provider's signing key, for the same
	// reason Mail and SMS are injectable: a composition that signs with a key
	// held in AWS has to be provable without an AWS account. Nil builds the real
	// KMS-backed one (awsintegration.NewKMSKeySource), lazily. Injecting it
	// switches nothing on — whether an RS256 signer is built at all is a
	// question about idProvider.kmsKeyId (idp.go).
	//
	// It is a factory of a crypto.Signer, and deliberately not the KMS client
	// itself: awsintegration.KMSAPI speaks the AWS SDK's types, and the product
	// rule is that the SDK appears only under internal/integration/aws and
	// internal/store/dynamodb. A seam typed in SDK terms would export that
	// dependency to every implementor, this package's tests included — which is
	// why Mail and SMS are auth.MailerTransport and auth.SMSTransport rather
	// than SESAPI and SNSAPI, and why this one is IDPKeySource.
	IDPKeySource IDPKeySourceFactory

	// Cognito injects the directory the migration block reads, for the same
	// reason Mail, SMS and IDPKeySource are injectable: a composition that talks
	// to somebody else's user pool has to be provable without an account in it.
	// Nil builds the real one, lazily. Injecting it switches nothing on — whether
	// a migration is wired at all is a question about stores.migration.source
	// (migration.go).
	//
	// It is awsintegration.CognitoDirectory and not CognitoAPI for the reason
	// IDPKeySource is not KMSAPI: the SDK belongs under internal/integration/aws
	// and internal/store/dynamodb, and a seam spelled in SDK types would export
	// that dependency to this package's tests.
	Cognito awsintegration.CognitoDirectory

	// HTTPClient issues every outbound HTTP request this binary makes on a
	// route's behalf: the delivery webhook, the claims webhook, and the JWKS
	// fetch of resource-server mode. Nil, the zero value, is http.DefaultClient.
	// Injected so a test can point any of them at a TLS httptest server it
	// trusts; like Mail and SMS, injecting it switches nothing on.
	HTTPClient *http.Client

	// UploadStore injects the store the admin console's upload routes write
	// through and the hosted UI serves uploaded assets from, for the reason
	// Mail and SMS are injectable: a composition that keeps logos in a bucket
	// has to be provable without one. Nil builds the real S3-backed store
	// (awsintegration.NewS3UploadStore), lazily. Injecting it switches nothing
	// on — whether an upload store is built at all is a question about
	// ui.uploadDir naming an S3 location (admin.go, newUploadStore).
	//
	// It is auth.UploadStore and not awsintegration.S3API, for the reason
	// IDPKeySource is not KMSAPI: the SDK stays under internal/integration/aws.
	UploadStore auth.UploadStore
}

// App is one cold start's worth of state.
//
// Everything expensive is built here, once, and read-only afterwards: the
// configuration document, the resolved secrets, the AWS client and its
// connection pool, the store, the auth core and the routing table. Handle then
// does nothing but adapt an event and dispatch it. Getting that split wrong is
// the classic serverless performance bug — a store constructed per invocation
// pays a fresh credential chain and TLS handshake on every login — and it is
// also a correctness bug here, because a refuse-to-start rule would surface as
// a 500 per request instead of a failed deployment.
type App struct {
	// Config is the validated configuration this instance came up with.
	Config *config.Config

	// Logger is the process logger. Per-request loggers derive from it.
	Logger *slog.Logger

	// Handler is the fully wrapped HTTP surface, exposed so a test can drive it
	// directly as well as through a synthetic Lambda event.
	Handler http.Handler

	// ResourceServerGuard verifies an RS256 bearer token against the issuer's
	// JWKS — or this instance's own access-token cookie — and puts the principal
	// on the request context. Nil unless resourceServer.enabled.
	//
	// NOTHING IN THIS ARTIFACT MOUNTS IT. It guards the routes of whatever
	// serves alongside it, and this binary has none of those: every route under
	// the api prefix belongs to the imported adapter, which verifies the local
	// HS256 session, and the commonest resource-server deployment is the hybrid
	// that keeps doing exactly that. So the guard is an export — for a host that
	// embeds this package, or for a future authorizer binary — and not a
	// middleware this cold start installs. See the header of idp.go.
	//
	// What resource-server mode does do to the deployed artifact is subtract:
	// HTTPConfig.ResourceServer unmounts all nineteen credential routes. That is
	// immediate and total, and it is the whole of the knob's effect here.
	ResourceServerGuard func(http.Handler) http.Handler

	adapter *lambdahttp.Adapter
}

// New performs the whole cold start and returns an App ready to serve, or an
// error that must abort the init.
//
// It never returns a partially usable App: a configuration problem, an
// unsupported store or an unbuildable auth core all fail here, where the
// Lambda service reports an init failure the deployment can see, rather than
// per request where it looks like an outage.
func New(ctx context.Context, opts Options) (*App, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.LookupEnv
	}
	readFile := opts.ReadFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	log := opts.Logger
	if log == nil {
		log = newLogger(os.Stdout, logLevel(getenv))
	}
	newStores := opts.Stores
	if newStores == nil {
		newStores = defaultStoreFactory
	}
	// Every outbound request this binary makes on a route's behalf carries the
	// caller's correlation id from here on. It is done once, on the way in,
	// rather than at each of the three consumers (delivery webhook, claims
	// webhook, resource-server JWKS fetch), because the fourth consumer has not
	// been written yet and the property should hold for it too. See
	// correlatingClient: it copies, so Options.HTTPClient is not mutated.
	opts.HTTPClient = correlatingClient(opts.HTTPClient)

	doc, err := loadDocument(getenv, readFile)
	if err != nil {
		return nil, err
	}

	// The AWS-backed secret resolvers are constructed here and injected, because
	// internal/config must not import the AWS SDK: the loader defines the
	// SecretResolver interface and this entrypoint is the one place allowed to
	// know which cloud the deployment runs in. Building them costs nothing —
	// the SDK client is created on the first reference that actually needs one,
	// so a stack whose secrets all come from the environment pays no cold-start
	// penalty for the capability.
	secrets := opts.Secrets
	if secrets.SecretsManager == nil && secrets.SSM == nil {
		secrets = awsintegration.NewSecretResolvers(awsintegration.SecretResolverOptions{})
	}

	cfg, err := config.Load(ctx, config.Options{Document: doc, Getenv: getenv, Secrets: secrets})
	if err != nil {
		return nil, err
	}

	// Warnings are not failures, but they are the only notice an operator gets
	// that a production secret is sitting in a plain environment variable, so
	// they are logged before anything else can bury them.
	for _, w := range cfg.Warnings() {
		log.Warn("configuration warning",
			slog.String("path", w.Path),
			slog.String("source", w.Source),
			slog.String("problem", w.Problem),
			slog.String("remedy", w.Remedy))
	}
	for _, gap := range unwiredKnobs(cfg) {
		log.Warn("configured knob is not wired to the auth core",
			slog.String("path", gap.Path),
			slog.String("problem", gap.Problem),
			slog.String("remedy", gap.Remedy))
	}

	if err := checkStoreSupport(cfg); err != nil {
		return nil, err
	}
	// Before the core is built, because the core is what would otherwise fail,
	// with a message about a knob resource-server mode told the operator to
	// leave unset. See checkResourceServerSupport.
	if err := checkResourceServerSupport(cfg); err != nil {
		return nil, err
	}
	// Before the stores are opened, because this one needs none of them: it
	// reads the deployment artifact, and a `ui.assetsDir` that is not there is a
	// UI that 404s every page on a stack every health check calls healthy. See
	// checkUIAssets.
	if err := checkUISupport(cfg); err != nil {
		return nil, err
	}

	users, sessions, err := newStores(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	// Migration off another identity provider (migration.go). It sits here
	// rather than only in coreOptionSets because it does something no option set
	// does: it WRAPS the user store, which has to happen before coreOptions hands
	// that store to auth.WithUserStore and before every later set is handed the
	// same value. The option half — the password verifier — is an ordinary entry
	// in coreOptionSets, which derives it from the wrapper this line installed.
	// With stores.migration unset it constructs nothing and returns the store it
	// was given.
	users, err = migrationWiring(cfg, users, opts.Cognito, log)
	if err != nil {
		return nil, err
	}

	// Credential delivery. Built before the core because every sender option is
	// derived from it, and it performs no I/O: both AWS clients are deferred to
	// the first message actually sent (delivery.go).
	deliver, err := newDelivery(cfg, opts.Mail, opts.SMS, opts.HTTPClient, log)
	if err != nil {
		return nil, err
	}

	core, err := buildCore(ctx, cfg, opts, users, sessions, deliver, log)
	if err != nil {
		return nil, err
	}

	// The core recommends this assertion to every host, and RS-6 makes it
	// unreachable for a document the loader accepted; it stays because a test
	// that bypasses the loader should meet a message and not a 404 (admin.go).
	if err := checkAdminMounted(cfg, httpConfig(cfg)); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	// The auth surface comes entirely from the imported adapter. Nothing in this
	// binary may add a route under the api prefix: a route that exists here and
	// not in the other family ports is a wire divergence by construction.
	// In identity-provider mode the adapter mounts the OIDC surface too, all
	// five endpoints of it, as of awesome-go-auth v0.7.0; this binary used to
	// mount four of them itself and no longer does. What is left here is the
	// guard: mountAuthSurface returns an error rather than panicking on the one
	// configuration that can still register a pattern twice, an
	// idProvider.jwksPath pointed at a route the adapter already serves (idp.go).
	// The rate limiter. It is built here, before the mount, because
	// auth.HTTPConfig.RateLimiter is a constructor the adapter calls once per
	// route: whatever it counts with has to exist before the first of those
	// thirty calls and be captured by all of them, or every route would get a
	// private budget instead of the one shared with the rest (ratelimit.go).
	//
	// The shared counter is found structurally on whatever the driver returned,
	// the way the settings store is. A driver without one is not a refusal: it
	// is the development driver, where a per-process bound is the honest
	// maximum and RS-12 already refuses the driver in production.
	// logRateLimitSurface says so at cold start.
	var counter rateLimitCounter
	if provider, ok := users.(rateLimitCounter); ok {
		counter = provider
	}
	logRateLimitSurface(cfg, counter, log)
	// Two limiters from one block and one counter: the auth router's, over the
	// routes rateLimit.scope names, and the console's, over the one route the
	// core's AdminOptions.RateLimiter covers (ratelimit.go,
	// newAdminPromoteLimiter). Both are built here for the reason above.
	if err := mountAuthSurface(mux, core, cfg, newRateLimiter(cfg, counter, log), newAdminPromoteLimiter(cfg, counter, log)); err != nil {
		return nil, err
	}
	logDocsSurface(cfg, log)
	logUISurface(cfg, log)
	logAdminSurface(cfg, httpConfig(cfg), log)

	// The middleware chain is one function, assembleHandler, so that the test
	// harness (admin_test.go newAdminSurface) builds the very chain New builds
	// and a header this binary adds -- or must not add -- is seen where it is
	// asserted. The console's login limiter is built here for the reason the
	// other two are: it counts with the shared counter.
	handler := assembleHandler(cfg, log, mux, newAdminLoginLimiter(cfg, counter, log))

	app := &App{Config: cfg, Logger: log, Handler: handler}

	// Resource-server mode. Built after the core because the verifier's cookie
	// path needs it, and built at cold start so a JWKS endpoint the client
	// cannot use is a failed deployment rather than a 401 per request.
	if cfg.ResourceServer.Enabled {
		guard, err := newResourceServerGuard(core, resourceServerConfig(cfg, opts.HTTPClient), log)
		if err != nil {
			return nil, err
		}
		app.ResourceServerGuard = guard
	}

	app.adapter = lambdahttp.New(handler, lambdahttp.Options{
		// deployment.stage exists precisely so the event layer can strip the
		// stage segment an execute-api URL puts in front of every path
		// (see config.Deployment.Stage). Empty means strip nothing.
		StagePrefix: cfg.Deployment.Stage,
		OnError: func(ctx context.Context, err error) {
			loggerFrom(ctx, log).Error("event adapter", slog.String("error", err.Error()))
		},
	})

	log.Info("cold start complete",
		slog.String("environment", cfg.Deployment.Environment),
		slog.String("storeDriver", cfg.Stores.Driver),
		slog.String("apiPrefix", cfg.HTTP.APIPrefix),
		slog.Bool("csrfEnabled", cfg.Security.CSRF.Enabled),
		slog.Bool("cookiesSecure", cfg.Cookies.Secure),
		slog.String("sessionCheckOn", cfg.Sessions.CheckOn),
		slog.Bool("identityProvider", core.IDP() != nil),
		slog.Bool("resourceServer", cfg.ResourceServer.Enabled),
		slog.Bool("adminConsole", httpConfig(cfg).AdminMounted()))

	return app, nil
}

// assembleHandler wraps the mounted mux in every middleware this binary adds,
// in the order New has always applied them. It is a function of the same
// document and the same mux so that a test can build the exact handler the
// binary serves — admin_test.go's newAdminSurface used to omit the CORS layer
// and could not see that the console had been put behind it (review finding #1).
//
// Innermost to outermost:
//
//   - The console's login limiter, matching one route (POST <admin>/login) and
//     nothing else; identity when the console or the block is off.
//   - The two header middlewares. Neither registers a pattern, so the adapter
//     still owns every path under the api prefix — that is the only thing this
//     binary can do about the reference's Swagger page loading an unpinned
//     third-party bundle onto the auth origin (docs.go), and about the
//     reference serving uploaded SVGs same-origin with the auth cookies
//     (admin.go, uploadAssetHeaders). Both are the identity wrapper when their
//     routes are not mounted.
//   - Refresh-token rotation replay detection needs a per-request precondition
//     carrier installed on the request context: the DynamoDB store fills it in
//     GetSessionByRefreshTokenHash and consumes it in UpdateSession so that two
//     concurrent refreshes of one token resolve to a single winner and a replay
//     is revoked immediately instead of one request later. rotation.go
//     documents this as "the HTTP layer must call it once per request"; without
//     it the store logs warnDegradedRotation and falls back to
//     attribute_not_exists(revokedAt). Only the DynamoDB store consumes the
//     scope, so the wrap is gated on the driver.
//   - The migration marker travels from the store's profile read to the
//     password verifier through a second per-request carrier of the same shape:
//     a ctx cannot be mutated by the callee, so the HTTP layer installs an empty
//     scope and the two ends fill and consume it. See migrationScopeMiddleware.
//   - CORS, everywhere but the admin mount (corsExemptMounts).
//   - The observability pair, whose order is the argument: the carrier has to
//     exist before anything can read it, and the access log is one of the
//     things that reads it. So correlationScope sits between them, and
//     auth.EventContextMiddleware ends up outermost — ahead of CORS, ahead of
//     the access log, ahead of everything. EventContextMiddleware is the core's,
//     and httpConfig(cfg) is the same pure function of the same document that
//     mountAuthSurface hands the adapter. The adapter installs the carrier again
//     inside its own guard chain (awesome-go-auth adapter/nethttp/nethttp.go:257)
//     for the routes it owns; that install recomputes the identical value, so
//     this one costs a context value on those routes and buys the carrier on the
//     ones the adapter does not own — GET /healthz today, whatever a later block
//     mounts outside the api prefix tomorrow. See the correlation section of
//     logging.go for why this binary never reads the header itself.
func assembleHandler(cfg *config.Config, log *slog.Logger, mux http.Handler, adminLoginRL func(http.Handler) http.Handler) http.Handler {
	handler := mux
	if adminLoginRL != nil {
		handler = adminLoginRL(handler)
	}
	handler = docsSecurityHeaders(cfg)(handler)
	handler = uploadAssetHeaders(cfg)(handler)
	if cfg.Stores.Driver == config.StoreDriverDynamoDB {
		handler = rotationScopeMiddleware(handler)
	}
	if cfg.Stores.Migration.Active() {
		handler = migrationScopeMiddleware(handler)
	}
	handler = corsMiddleware(cfg.HTTP.CORS.Origins, corsExemptMounts(cfg)...)(handler)
	handler = accessLog(log, handler)
	handler = correlationScope(log)(handler)
	handler = auth.EventContextMiddleware(httpConfig(cfg))(handler)
	return handler
}

// corsExemptMounts names the mounts the CORS layer must not touch: today the
// admin console, when it is mounted.
//
// The reference's CORS layer is `router.use(cors(...))` INSIDE the auth router
// (auth.router.ts:512-527); createAdminRouter is a separate Express router
// (admin.router.ts:503-510) and sets no Access-Control header of any kind. A
// product-wide layer would therefore have put the console behind credentialed
// CORS the reference never grants it — and the console has no CSRF check, so an
// allow-listed SPA origin would have gained readable, credentialed cross-origin
// access to the most privileged API in the deployment, with any origin able to
// use a bearer. Exempting the mount rather than narrowing the layer to the api
// prefix keeps every other path where it was (GET /healthz, and an
// idProvider.jwksPath a document may place outside the prefix, whose discovery
// document a browser client does fetch). The tools router is the reference's
// other sibling router and will want the same exemption when its block lands.
func corsExemptMounts(cfg *config.Config) []string {
	hc := httpConfig(cfg)
	if !hc.AdminMounted() {
		return nil
	}
	return []string{hc.AdminPath()}
}

// buildCore turns the validated configuration and the opened stores into the
// auth core: the base options, then every option set in coreOptionSets' order.
//
// It is split out of New for one reason: so that a test can build the core the
// binary builds — every slot, in order — from a Config it loaded itself, which
// is how a block still behind the phase gate is exercised end to end before
// the gate comes down (config.Options.AllowUnimplemented; the gate removal is
// its own last commit by convention). Nothing about the composition is
// different from New's: it is New's middle, named.
func buildCore(ctx context.Context, cfg *config.Config, opts Options, users auth.UserStore, sessions auth.SessionStore, deliver *delivery, log *slog.Logger) (*auth.Auth, error) {
	coreOpts := coreOptions(cfg, users, sessions, log)
	for _, set := range coreOptionSets(ctx, cfg, opts, users, deliver, log) {
		if set.build == nil {
			// A reserved slot. See coreOptionSets.
			continue
		}
		sub, err := set.build()
		if err != nil {
			return nil, err
		}
		coreOpts = append(coreOpts, sub...)
	}

	core, err := auth.New(coreOpts...)
	if err != nil {
		return nil, fmt.Errorf("auth core: %w", err)
	}
	return core, nil
}

// Handle is the lambda.Start entrypoint.
//
// Its only per-request work is attaching the request id, so a log line can be
// traced back to an invocation, and handing the payload to the adapter.
func (a *App) Handle(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	log := a.Logger
	if lc, ok := lambdacontext.FromContext(ctx); ok && lc.AwsRequestID != "" {
		log = log.With(slog.String("requestId", lc.AwsRequestID))
	}
	return a.adapter.Handle(withLogger(ctx, log), payload)
}

// rotationScopeMiddleware installs the DynamoDB refresh-rotation precondition
// carrier on every request context. See internal/store/dynamodb/rotation.go:
// the store reads the scope out of the request context, so it must be installed
// on the *request's* context (r.Context()) rather than the cold-start context.
func rotationScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(ddbstore.WithRotationScope(r.Context())))
	})
}

// healthz is a readiness probe that costs nothing: it answers from memory and
// never touches a store, so a health check cannot itself consume DynamoDB
// capacity or wake a throttled table. Reaching it at all already proves the
// cold start succeeded, since a failed init never gets to serve.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// loadDocument reads the configuration document, if there is one. Returning a
// nil Document is legitimate and means "defaults plus AWESOME_AUTH_* overrides",
// which is how a minimal development stack runs.
func loadDocument(getenv func(string) (string, bool), readFile func(string) ([]byte, error)) (config.Document, error) {
	path, hasPath := getenv(ConfigFileEnv)
	inline, hasInline := getenv(ConfigJSONEnv)
	path, inline = strings.TrimSpace(path), strings.TrimSpace(inline)
	hasPath, hasInline = hasPath && path != "", hasInline && inline != ""

	switch {
	case hasPath && hasInline:
		// Picking one silently would make the deployment depend on which
		// variable a template happened to set last.
		return nil, fmt.Errorf("config: %s and %s are both set; supply the configuration document exactly once", ConfigFileEnv, ConfigJSONEnv)
	case hasPath:
		data, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %s=%s: %w", ConfigFileEnv, path, err)
		}
		return config.ParseJSON(data)
	case hasInline:
		return config.ParseJSON([]byte(inline))
	default:
		return nil, nil
	}
}

// coreOptions maps the validated configuration onto the auth core's option set.
//
// Only knobs the core actually accepts appear here. The ones it does not are
// reported by unwiredKnobs rather than quietly dropped.
func coreOptions(cfg *config.Config, users auth.UserStore, sessions auth.SessionStore, log *slog.Logger) []auth.Option {
	return []auth.Option{
		auth.WithSecret(cfg.AccessTokenSecret()),
		auth.WithTokenTTLs(cfg.Security.JWT.AccessTokenTTL.Duration(), cfg.Security.JWT.RefreshTokenTTL.Duration()),
		// The cost every password this deployment hashes is written at. It
		// cannot fail here: WithBcryptCost refuses anything outside bcrypt's
		// 4..31, and validate.go has already refused anything outside 10..15,
		// which is the narrower range — so the option and the schema cannot
		// disagree about a value that loaded.
		auth.WithBcryptCost(cfg.Security.Password.BcryptSaltRounds),
		auth.WithSessionCheckOn(cfg.Sessions.CheckOn),
		auth.WithUserStore(users),
		auth.WithSessionStore(sessions),
		// The core logs through a printf callback; funnelling it into slog keeps
		// every line in the deployment one JSON format.
		auth.WithLogger(func(format string, args ...any) {
			log.Warn("auth core", slog.String("message", fmt.Sprintf(format, args...)))
		}),
	}
}

// coreOptionSet is one contributor to the core's option list: the block it
// wires, and the builder that turns that block's configuration into options or
// refuses the cold start.
//
// A slot with no builder contributes nothing and costs nothing — New skips it —
// and is not a stub: there is no function to call, no option to append and no
// branch to evaluate. It is a reservation, so that the block which fills it
// edits one line of the slice and no other line in this file.
type coreOptionSet struct {
	// name is the configuration block this set wires, spelled as the document
	// spells it. It is what TestCoreOptionSetsAreOrderedAndReserved reads, which
	// is what makes the reserved order a fact about the build rather than a
	// comment about it.
	name string

	// build returns this set's options, or the error that must abort the init.
	// Nil means the slot is reserved and unfilled.
	build func() ([]auth.Option, error)
}

// coreOptionSets is the ordered list of option sets New appends after
// coreOptions, and the only place that order is written down.
//
// **The order is the contract, not the arrangement.** Four of these can refuse
// the cold start, and which one refuses first is observable: a document with
// both a bad claims mapping and a bad OAuth profileMap reports the claims fault,
// and a test says so. Appending is also not commutative for the core itself —
// a later WithX of the same knob wins — so reordering these would be a silent
// behaviour change even where nothing refuses.
//
// **Two of them do I/O at cold start** and are marked below. That is the reason
// this is a list of builders rather than a list of already-built option slices:
// a slice would do every set's work before the first one's refusal, which for
// these two means a filesystem walk and a KMS round trip on a deployment that
// was going to fail anyway.
//
// The five slots after the wired sets are reserved in the order the remaining
// blocks fill them: settings, docs, ui, admin, tools. Each block fills its own
// and touches nothing else, which is what makes them mergeable in any order —
// before this, every one of them appended to the same place and therefore
// conflicted with every other.
//
// A reserved slot may also turn out to have nothing to hold, and `docs` is the
// first: its block reaches the core entirely through HTTPConfig.Docs, so it
// stays empty on purpose rather than being filled with an option invented to
// fill it. That is a decision and not an omission, which is why the entry below
// says so and why TestCoreOptionSetsAreOrderedAndReserved still lists it.
// `admin` is the first of the reserved slots to turn out genuinely non-empty:
// the console's tabs are drawn from five stores the core takes by name and
// cannot discover, and the upload store is a sixth (admin.go).
func coreOptionSets(
	ctx context.Context,
	cfg *config.Config,
	opts Options,
	users auth.UserStore,
	deliver *delivery,
	log *slog.Logger,
) []coreOptionSet {
	return []coreOptionSet{
		{
			// Credential delivery: the senders behind the five credential-minting
			// routes. No I/O — both AWS clients are deferred to the first message
			// actually sent (delivery.go) — and nothing here can refuse, because
			// newDelivery has already done the refusing, before the core is built.
			name:  "delivery",
			build: func() ([]auth.Option, error) { return deliveryOptions(deliver, log), nil },
		},
		{
			// The email flows: site URLs and the template store, seeded from the
			// artifact. This is the one option set that can do I/O at cold start —
			// reading email.templatesDir — and the first that can refuse for a store
			// the driver lacks.
			name:  "email",
			build: func() ([]auth.Option, error) { return emailOptions(ctx, cfg, users, deliver, log) },
		},
		{
			// The TOTP issuer label. One string, no I/O, nothing to refuse.
			name:  "twoFactor",
			build: func() ([]auth.Option, error) { return twoFactorOptions(cfg), nil },
		},
		{
			// Token claims. Like emailOptions this one can refuse: a claim mapped from
			// a field the core does not expose, or named after a reserved session
			// claim, is a document fault and has to stop the deployment rather than
			// turn every login into a 500.
			name:  "claims",
			build: func() ([]auth.Option, error) { return claimsOptions(cfg, opts.HTTPClient, log) },
		},
		{
			// OAuth: the provider registry and the provisioning policy. It refuses for
			// a profileMap or a fieldMap that does not compile, so a mapping expression
			// is a failed deployment rather than a provider that 500s on its first
			// callback.
			name:  "oauth",
			build: func() ([]auth.Option, error) { return oauthOptions(cfg, users, deliver, log) },
		},
		{
			// Identity-provider mode. The second option set that can do I/O at cold
			// start — a KMS signer fetches its public key here — and it refuses for a
			// driver with no authorization-code store, for the same reason emailOptions
			// refuses for one with no template store.
			name:  "idp",
			build: func() ([]auth.Option, error) { return idpOptions(ctx, cfg, users, opts.IDPKeySource, log) },
		},
		{
			// Migration off another identity provider: the password-verifier seam.
			//
			// Last of the wired sets, and deliberately not earlier. It is the only
			// one whose subject is the store every other set was handed rather than
			// a route's behaviour, and it cannot refuse for anything a document
			// says, because RS-13 has already refused every unusable combination —
			// so it has no business competing for refusal precedence with the sets
			// that can, and appending it here moves none of theirs. The reserved
			// tail below keeps its declared order; only its starting index shifts,
			// which is invisible to a block that finds its slot by name.
			//
			// It takes no argument of its own: `users` is already the wrapper New
			// installed before the delivery transports, and the verifier is a
			// method on it.
			name:  "migration",
			build: func() ([]auth.Option, error) { return migrationOptions(cfg, users) },
		},

		// ── The reserved slots ───────────────────────────────────────────────
		//
		// Filling one is replacing that entry's nil build with a builder, and
		// nothing else. Leaving one empty costs nothing at runtime.
		{
			// Runtime settings: the store the admin surface mutates at run time,
			// seeded from runtimeSettings. The third set that can do I/O at cold
			// start — and only when the document declares a seed, since with
			// nothing declared there is nothing to compare against — and the
			// third that refuses for a driver that lacks the store.
			name:  "settings",
			build: func() ([]auth.Option, error) { return settingsOptions(ctx, cfg, users, log) },
		},
		// docs.* — the OpenAPI document and the Swagger page. Wired, and
		// deliberately empty: there is no auth.Option for either route.
		// awesome-go-auth puts the whole surface on HTTPConfig.Docs, which the
		// adapter reads at mount time (docs.go, httpConfig), so the block is
		// fully honoured without contributing anything to auth.New. Filling
		// this slot would mean inventing an option for the sake of the slot.
		// The slot itself stays, because it is the landing site the roadmap
		// promised and moving it would move every later block's.
		{name: "docs"},
		// ui.* — the hosted UI, its config document and its assets. Wired, and
		// deliberately empty for exactly the reason `docs` is: the whole block
		// reaches the core through HTTPConfig.UI, which the adapter reads at
		// mount time to register one handler for the entire <prefix>/ui subtree
		// (ui.go, httpConfig). There is no auth.Option for a branding colour, a
		// headless flag or an asset filesystem, and the two stores the config
		// document is actually built from — settings and templates — were handed
		// to the core by the `settings` slot and by emailOptions long before
		// this block existed, so the UI reads them without asking for anything
		// of its own. The slot stays, recording that it was filled with nothing
		// on purpose.
		{name: "ui"},
		{
			// admin.* — the admin console. The router itself, its access
			// policy, its cookie and its documentation pair all reach the core
			// through HTTPConfig.Admin, the way `docs` and `ui` do; what this
			// slot holds is the part that cannot: the five stores the console's
			// tabs are drawn from and the core takes by name behind their
			// stores.enable flags — metadata, rbac, tenants, apiKeys, webhooks —
			// and the upload store the file picker writes through. No I/O: the
			// S3 client is built on the first upload. It refuses for a flag the
			// driver's store cannot honour and for a root user that could never
			// log in (admin.go, adminOptions).
			name:  "admin",
			build: func() ([]auth.Option, error) { return adminOptions(cfg, opts, users, log) },
		},
		// tools.* — telemetry, SSE and the inbound-webhook sandbox.
		{name: "tools"},
	}
}

// httpConfig maps the cookie, CSRF and prefix knobs onto the shared wire layer.
//
// Cookie Max-Age is deliberately left at zero: HTTPConfig.resolve derives it
// from the token TTLs, which is what keeps a cookie from outliving the token it
// carries when an operator changes security.jwt.accessTokenTtl. The cookie
// *name* prefix is likewise derived by the core (CookieOptions.CookieName) and
// is not a knob in either layer.
//
// UI is the whole `ui` block, and it is the one field here that changes two
// surfaces at once. UIOptions.Enabled makes the adapter register a handler for
// the entire <prefix>/ui subtree — the config document, the SSR pages, the
// assets — and it is also what points every emailed link at
// <site><prefix>/ui/<path>, the hosted UI's page for it, instead of at the bare
// API route (UILink, buildUiLink, auth.router.ts:261-271). The two have followed
// one another since P2 precisely so they could not drift apart on the day the UI
// landed, which is this one. ui.go builds the value.
//
// **The deprecated alias is deliberately not set.** HTTPConfig.UIEnabled is the
// older spelling of UI.Enabled, from when the flag decided nothing but the shape
// of a link, and the core treats the two as one switch: resolve() sets both from
// either, uiEnabled() reads both, and an adapter mounts on UI.Enabled. This
// function used to set the alias and now sets the field it was renamed to, which
// is the one arrangement in which the two cannot be assigned from different
// expressions and come to disagree. A caller holding an *unresolved* config —
// delivery.go, which asks it for UILink — is unaffected, because UILink is one
// of the callers that reads both.
//
// Docs is where the whole documentation surface lives: the two routes the
// adapter mounts under it are the entirety of what the `docs` block does, which
// is why that block fills no core option slot. docs.go builds the value — it is
// the one field here that is not a straight copy, because `docs.swagger` is
// three-valued and DocsOptions.Enabled is a bool.
//
// Admin is the whole `admin` block bar its stores: the mount, the access
// policy, the bootstrap credentials, the cookie prefix and the console's own
// documentation pair. admin.go builds the value and argues every field; the
// one to know about here is JWTSecret, which is left empty so that the core
// verifies the console's tokens with the access-token secret — the integration
// the reference documents and config-schema.md §1.13 folds into RS-7. The
// adapter mounts the console at AdminPath(), beside the api prefix, when
// AdminMounted() is true, and nothing when it is not.
//
// RateLimiter is the one field of HTTPConfig this function deliberately leaves
// nil, and the reason is that it is not a function of the document. It is a
// middleware constructor closing over a shared counter and an in-process table,
// so building it needs the store the composition root opened, which this
// function does not have and should not take — half a dozen callers here want
// nothing but Prefix() or UILink(). mountAuthSurface takes it as a parameter and
// sets it on the way to the adapter, which is the only place it is read
// (ratelimit.go, idp.go). A nil RateLimiter is exactly "no limiter" to the core,
// which composes a pass-through for it, so the omission is also the correct
// value for every caller that is not mounting. Admin.RateLimiter is left nil
// for the same reason and filled in the same place.
func httpConfig(cfg *config.Config) auth.HTTPConfig {
	return auth.HTTPConfig{
		APIPrefix: cfg.HTTP.APIPrefix,
		Cookies: auth.CookieOptions{
			Secure:           cfg.Cookies.Secure,
			SameSite:         sameSite(cfg.Cookies.SameSite),
			Path:             cfg.Cookies.Path,
			Domain:           cfg.Cookies.Domain,
			RefreshTokenPath: cfg.Cookies.RefreshTokenPath,
		},
		CSRF: auth.CSRFConfig{Enabled: cfg.Security.CSRF.Enabled},
		UI:   uiOptions(cfg),
		// Resource-server mode: the adapter registers none of the nineteen
		// routes that create, prove, deliver or change a credential, so each of
		// them answers 404 rather than reaching a handler with no issuer behind
		// it (auth.ResourceServerGatedRoutes). This is the half of the knob that
		// changes the mounted surface; the verifier is App.ResourceServerGuard.
		ResourceServer: cfg.ResourceServer.Enabled,
		// The documentation surface: GET <prefix>/openapi.json and
		// GET <prefix>/docs, both unguarded and both behind the CSRF
		// middleware, registered by the adapter and by nothing here. docs.go
		// resolves the three-valued docs.swagger knob onto this bool.
		Docs: docsOptions(cfg),
		// The admin console, mounted by the adapter at AdminPath() — a sibling
		// of the api prefix, as the reference's separate router is — when
		// admin.enabled is on and an access decision exists. admin.go.
		Admin: adminHTTPOptions(cfg),
	}
}

func sameSite(v string) http.SameSite {
	switch v {
	case config.SameSiteStrict:
		return http.SameSiteStrictMode
	case config.SameSiteNone:
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// defaultStoreFactory builds the real persistence layer.
func defaultStoreFactory(ctx context.Context, cfg *config.Config, log *slog.Logger) (auth.UserStore, auth.SessionStore, error) {
	switch cfg.Stores.Driver {
	case config.StoreDriverDynamoDB:
		client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{
			Region:   cfg.Stores.Connection.Region,
			Endpoint: cfg.Stores.Connection.Endpoint,
		})
		if err != nil {
			return nil, nil, err
		}
		store, err := ddbstore.New(client, ddbstore.Options{
			TableName: cfg.Stores.Connection.TableName,
			Logger:    log,
		})
		if err != nil {
			return nil, nil, err
		}
		// Every register is logged once, at cold start, so the deviations show up
		// in the deployment log rather than being discovered from a client's bug
		// report. The memory driver announces the product and core registers only.
		logDeviations(log, store.CompatibilityNotes())
		return store, store, nil

	case config.StoreDriverMemory:
		// RS-12 already refuses this driver in production, so reaching it means
		// a development stack. Each cold start gets its own empty store, and
		// concurrent execution environments do not share one.
		log.Warn("using the in-memory store: state is per execution environment and is lost on every cold start",
			slog.String("path", "stores.driver"))
		logDeviations(log, nil)
		return newMemoryStoreBundle(), auth.NewMemorySessionStore(), nil

	default:
		return nil, nil, fmt.Errorf("stores.driver: %q is not implemented in this build; use %q or %q",
			cfg.Stores.Driver, config.StoreDriverDynamoDB, config.StoreDriverMemory)
	}
}

// memoryStoreBundle is the in-memory user store plus the stores the core cannot
// find by type assertion — the two OAuth stores, the template store, the
// settings store, the authorization-code store, and the five the admin console
// is drawn from — so that the development driver reaches the account-linking
// routes, the stored templates and the console's tabs the same way the
// DynamoDB one does.
//
// The embedded pointer is what keeps the rest working: every optional interface
// the core *does* discover on the user store — MagicLinkStore, SMSStore,
// TOTPStore, the admin listers and the two profile flag writers — is satisfied
// by method promotion, so wrapping it cannot quietly narrow the feature set.
type memoryStoreBundle struct {
	*auth.MemoryUserStore
	links     auth.LinkedAccountStore
	pending   auth.PendingLinkStore
	templates auth.TemplateStore
	settings  auth.SettingsStore
	codes     auth.AuthCodeStore

	// The five stores behind the console's tabs, each the core's own in-memory
	// implementation and each per execution environment like everything else
	// on this driver: a role assigned through one environment is unknown to
	// the next, so an rbac:<role> policy on the memory driver admits a user on
	// one cold start and refuses them on another. RS-12 already refuses this
	// driver in production; internal/store/dynamodb is what makes the console
	// consistent across instances.
	metadata auth.UserMetadataStore
	rbac     auth.RolesPermissionsStore
	tenants  auth.TenantStore
	apiKeys  auth.APIKeyStore
	webhooks auth.WebhookStore
}

// newMemoryStoreBundle is the one place the development driver's bundle is
// assembled, shared by defaultStoreFactory and the test harness so the two
// cannot drift into different compositions.
func newMemoryStoreBundle() memoryStoreBundle {
	return memoryStoreBundle{
		MemoryUserStore: auth.NewMemoryUserStore(),
		links:           auth.NewMemoryLinkedAccounts(),
		pending:         auth.NewMemoryPendingLinks(),
		templates:       auth.NewMemoryTemplateStore(),
		// Per execution environment, with the consequence that a runtime settings
		// edit made through one is invisible to the next and is lost on its next
		// cold start — where it would also be re-seeded from the document, since
		// an empty store holds none of the declared keys. RS-12 already refuses
		// this driver in production; internal/store/dynamodb/settings.go is what
		// makes an administrator's toggle outlive the execution environment.
		settings: auth.NewMemorySettingsStore(),
		// Per execution environment, like everything else on this driver, and
		// with a consequence worth knowing on Lambda even in development: an
		// authorization code minted by one environment is unknown to the next,
		// so an OIDC round trip only completes when /authorize and /token land
		// on the same one. RS-12 already refuses this driver in production; the
		// dynamodb store (internal/store/dynamodb/auth_codes.go) is what makes
		// the flow work across instances.
		codes: auth.NewMemoryAuthCodeStore(),
		// The console's five, so that the same document that draws a tab on
		// the DynamoDB driver draws it here (driverStores lists the flags for
		// both drivers, and adminOptions hands each store over by accessor).
		metadata: auth.NewMemoryMetadataStore(),
		rbac:     auth.NewMemoryRolesPermissionsStore(),
		tenants:  auth.NewMemoryTenantStore(),
		apiKeys:  auth.NewMemoryAPIKeyStore(),
		webhooks: auth.NewMemoryWebhookStore(),
	}
}

func (m memoryStoreBundle) LinkedAccounts() auth.LinkedAccountStore { return m.links }
func (m memoryStoreBundle) PendingLinks() auth.PendingLinkStore     { return m.pending }
func (m memoryStoreBundle) Templates() auth.TemplateStore           { return m.templates }
func (m memoryStoreBundle) Settings() auth.SettingsStore            { return m.settings }
func (m memoryStoreBundle) AuthCodes() auth.AuthCodeStore           { return m.codes }
func (m memoryStoreBundle) Metadata() auth.UserMetadataStore        { return m.metadata }
func (m memoryStoreBundle) Roles() auth.RolesPermissionsStore       { return m.rbac }
func (m memoryStoreBundle) Tenants() auth.TenantStore               { return m.tenants }
func (m memoryStoreBundle) APIKeys() auth.APIKeyStore               { return m.apiKeys }
func (m memoryStoreBundle) Webhooks() auth.WebhookStore             { return m.webhooks }

// driverStores lists the stores.enable.<store> keys each driver can actually
// back. A key that is enabled and absent from its driver's set is a knob that
// validates and then does nothing, which spec §1.17 treats as a
// misconfiguration rather than a no-op.
func driverStores(driver string) (map[string]bool, bool) {
	switch driver {
	case config.StoreDriverDynamoDB:
		// "templates" joined the set when the store gained its TEMPLATES
		// partition: mail templates and UI translations are readable and
		// patchable on this driver, so email.templatesDir seeds a store that
		// outlives the execution environment. "settings" joined it the same way,
		// with the SETTINGS singleton (data-model.md §1.8): a require2FA an
		// administrator switches on is seen by every execution environment and
		// survives a redeploy.
		//
		// **This set answers a narrower question than "what does the driver
		// implement".** It answers "does enabling the flag change what the
		// deployment does", and a flag is listed only once the composition root
		// hands its store to the core. D6 implemented UserMetadataStore,
		// RolesPermissionsStore, TenantStore, APIKeyStore, the three webhook
		// stores and TelemetryStore, and deliberately listed none of them,
		// because the core takes each by name and nothing handed them over.
		// The admin surface is what hands five of them over (admin.go,
		// adminOptions), so those five are listed now: metadata reaches
		// GET <prefix>/me and the console's metadata tab, rbac reaches the
		// roles tab and the rbac:/permission: access policies, tenants the
		// tenants tab, apiKeys and webhooks the two credential tabs.
		//
		// "telemetry" is still absent, on the same rule. The telemetry store
		// reaches a route only through ToolsOptions.TelemetryStore, which the
		// tools block hands over; until it does, the flag would validate and
		// do nothing. That block adds the key here.
		//
		// The three v0.8.0 admin listers and the two profile flag writers need
		// no flag: AdminUserStore, SessionLister, RoleLister,
		// UserAdminFlagStore and UserTwoFactorPolicyStore are discovered by
		// type assertion on the user, session and RBAC stores, so they are live
		// the moment those are, and there is no separate stores.enable key for
		// them.
		return map[string]bool{
			"users": true, "sessions": true, "tokens": true,
			"linkedAccounts": true, "pendingLinks": true, "templates": true,
			"settings": true,
			"metadata": true, "rbac": true, "tenants": true,
			"apiKeys": true, "webhooks": true,
		}, true
	case config.StoreDriverMemory:
		// awesome-go-auth ships an in-memory implementation of every one of
		// these — MemoryLinkedAccounts, MemoryPendingLinks, MemoryTemplateStore,
		// MemorySettingsStore, MemoryMetadataStore, MemoryRolesPermissionsStore,
		// MemoryTenantStore, MemoryAPIKeyStore and MemoryWebhookStore — and
		// newMemoryStoreBundle hangs all of them off the user store, so the
		// development driver backs the same set as the production one. A driver
		// that backs fewer is still refused by name in emailOptions,
		// settingsOptions and adminOptions, which is why those refusals exist.
		return map[string]bool{
			"users": true, "sessions": true, "tokens": true,
			"linkedAccounts": true, "pendingLinks": true, "templates": true,
			"settings": true,
			"metadata": true, "rbac": true, "tenants": true,
			"apiKeys": true, "webhooks": true,
		}, true
	default:
		return nil, false
	}
}

// checkStoreSupport refuses a stores.enable set the selected driver cannot
// honour, and refuses the two stores nothing works without.
func checkStoreSupport(cfg *config.Config) error {
	supported, known := driverStores(cfg.Stores.Driver)
	if !known {
		return fmt.Errorf("stores.driver: %q is not implemented in this build; use %q or %q",
			cfg.Stores.Driver, config.StoreDriverDynamoDB, config.StoreDriverMemory)
	}

	var problems []string
	enabled := enabledStores(cfg.Stores.Enable)
	for _, name := range enabled {
		if !supported[name] {
			problems = append(problems, fmt.Sprintf(
				"stores.enable.%s is on but the %s driver does not implement that store, so the feature would return NOT_IMPLEMENTED on the wire -- turn it off until the driver grows it",
				name, cfg.Stores.Driver))
		}
	}

	on := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		on[name] = true
	}
	for _, required := range []string{"users", "sessions"} {
		if !on[required] {
			problems = append(problems, fmt.Sprintf(
				"stores.enable.%s is off, but the auth core requires it and would fall back to an in-process store that loses every write on the next cold start -- turn it on",
				required))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("config: refusing to start: %d problem(s) in stores.enable\n%s",
		len(problems), strings.Join(problems, "\n"))
}

// enabledStores returns the names of the stores.enable.<store> keys that are
// true, read reflectively from the struct's json tags rather than from a copy
// of the field list. A store added to config.StoreEnable is then covered here
// without anyone remembering to update this file — which is the same reason the
// config package generates its own env bindings from one table.
func enabledStores(e config.StoreEnable) []string {
	rv := reflect.ValueOf(e)
	rt := rv.Type()
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		name := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		if rv.Field(i).Kind() == reflect.Bool && rv.Field(i).Bool() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// knobGap is one configured knob this build validates but cannot act on,
// because the imported auth core exposes no way to set it.
//
// These are not phase gaps — internal/config/phases.go already refuses a whole
// domain that is not wired yet, and every knob below sits inside a domain that
// phases.go declares wired in P1. They are upstream gaps: the core's exported
// option set (awesome-go-auth auth.go) is narrower than its own Config struct,
// and *Auth cannot be built from a *Service, so there is no way to reach the
// remaining fields without forking the core, which this port does not do.
//
// They are warnings rather than refusals because refusing would make the
// product's own defaults unstartable — the shipped bcryptSaltRounds is 12 and
// the core is fixed at 10 — but every one of them is logged loudly at cold
// start, with the path, so nobody has to discover it from behaviour.
type knobGap struct {
	Path    string
	Problem string
	Remedy  string
}

// unwiredKnobs reports every knob the operator set that the core cannot honour.
//
// security.password.bcryptSaltRounds used to head this list, because the core
// hashed at a fixed cost and exposed no option for it. v0.6.0 exports
// WithBcryptCost, coreOptions passes it, and the gap is gone — the configured
// cost is now the deployed cost. Nothing replaced it: the only other candidate
// P3 looked at was the iss claim, and there is no knob in a wired domain that
// asks for one, so there is nothing being ignored to report (twofactor.go).
func unwiredKnobs(cfg *config.Config) []knobGap {
	defaults := config.Defaults()
	var gaps []knobGap

	if cfg.RefreshTokenSecret() != "" {
		gaps = append(gaps, knobGap{
			Path: "security.jwt.refreshTokenSecret",
			Problem: "the auth core signs access and refresh tokens with one HS256 secret and tells them apart by the typ claim, " +
				"so security.jwt.accessTokenSecret is the only secret in use and this one signs nothing",
			Remedy: "keep it set — RS-1 requires it and it becomes live as soon as the core takes a second secret — but do not " +
				"rely on rotating it to invalidate refresh tokens today",
		})
	}

	if cfg.Email.Verification.Mode != defaults.Email.Verification.Mode {
		gaps = append(gaps, knobGap{
			Path: "email.verification.mode",
			Problem: fmt.Sprintf("the auth core accepts this in its Config but exposes no functional option for it, so the deployed mode stays %q",
				defaults.Email.Verification.Mode),
			Remedy: "remove the override until the core exports an option for it",
		})
	}

	// The tokens.* lifetimes have core counterparts (ResetTokenTTL,
	// MagicLinkTTL, EmailVerificationTTL, EmailChangeTTL) whose defaults happen
	// to equal the product defaults, so only a deviation is a gap.
	for _, row := range []struct {
		path       string
		configured int
		coreValue  int
	}{
		{"tokens.passwordResetTtlMinutes", cfg.Tokens.PasswordResetTTLMinutes, defaults.Tokens.PasswordResetTTLMinutes},
		{"tokens.emailVerificationTtlMinutes", cfg.Tokens.EmailVerificationTTLMinutes, defaults.Tokens.EmailVerificationTTLMinutes},
		{"tokens.emailChangeTtlMinutes", cfg.Tokens.EmailChangeTTLMinutes, defaults.Tokens.EmailChangeTTLMinutes},
		{"tokens.magicLinkTtlMinutes", cfg.Tokens.MagicLinkTTLMinutes, defaults.Tokens.MagicLinkTTLMinutes},
	} {
		if row.configured == row.coreValue {
			continue
		}
		gaps = append(gaps, knobGap{
			Path: row.path,
			Problem: fmt.Sprintf("the auth core exposes no functional option for this lifetime, so the deployed value stays %d minutes and not the configured %d",
				row.coreValue, row.configured),
			Remedy: "remove the override until the core exports an option for it",
		})
	}

	gaps = append(gaps, deliveryKnobGaps(cfg)...)
	gaps = append(gaps, oauthKnobGaps(cfg)...)
	gaps = append(gaps, idpKnobGaps(cfg)...)
	gaps = append(gaps, runtimeSettingsKnobGaps(cfg)...)
	gaps = append(gaps, adminKnobGaps(cfg)...)

	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Path < gaps[j].Path })
	return gaps
}

// deliveryKnobGaps reports the knobs of email.mailer and sms that this build's
// transports cannot honour.
//
// Both blocks describe the reference's transports, which are HTTP gateways: a
// mailer is an endpoint you POST to with an X-API-Key, and an SMS gateway is a
// URL you GET with the credentials in the query string. This port sends through
// SES and SNS instead, which are reached by AWS API and authorised by the
// execution role, so those knobs address nothing and authenticate nothing.
//
// They are reported rather than refused, and rather than ignored. Refusing
// would make a document that is valid for every other port in the family
// unstartable here, for knobs that are required by the schema. Ignoring them is
// the failure mode this whole mechanism exists to prevent — an operator who
// rotates an SMS gateway password and sees nothing change has no way to learn
// from the outside that the password was never used. So each one is named, with
// its path, in the cold-start log.
//
// Note in particular what happens to sms.username and sms.password. The schema
// models them as secrets and its own comment says the transport "must move them
// off the URL" because the reference appends them as query parameters on a GET,
// writing credentials into every access log between here and the gateway. An
// SNS sender does not move them off the URL — it has no URL. The credentials-in-
// URL hazard is gone, and so is any use for the credentials.
//
// The gaps are reported whether or not the block they belong to is switched on,
// and the second case is the one that needs saying out loud. A credential is the
// part of these blocks that lives in Secrets Manager, so it is the part an
// operator sets first and the part a stack template carries; the switch — a from
// address for mail, an endpoint for SMS — is the part that is easy to forget.
// Set the credential alone and internal/config sees nothing to validate (a
// Secret resolved from its plain environment variable leaves no reference in the
// tree for validateSMS's `configured` to find), mailConfigured and smsConfigured
// are both false, and delivery is off. Before this port wired the two blocks
// that combination was refused outright by the phase gap, whose secretPrefix
// covered exactly these paths. Removing the domains removed that cover too, so
// the report has to replace it, or an SMS gateway password in the environment
// buys total silence: no mail, no text, no warning, and a 500 on the first
// /sms/send that nothing in the log accounts for.
//
// Every one of those sentences changes when email.deliveryWebhook.url is set,
// so each message that asserts something about what does or does not get
// delivered branches on webhookConfigured. Under a webhook the five credential
// seams are the webhook's (deliveryOptions), SES carries at most the
// email-changed notice and the account-linking mail, and SNS carries nothing at
// all — so "no mail is sent" and "POST /sms/send answers 500
// SMS_NOT_CONFIGURED" would both be false. A wrong line here is worse than no
// line: this report is the product's own anti-silent-misconfiguration
// mechanism, and an operator who acts on it has no second source.
func deliveryKnobGaps(cfg *config.Config) []knobGap {
	var gaps []knobGap
	hook := webhookConfigured(cfg)

	// The credentials, reported wherever they appear. Each one names the switch
	// its block is missing when the block is off, because "this key is unused"
	// and "no mail is sent at all" are different things for an operator to read.
	mailOn, smsOn := mailConfigured(cfg), smsConfigured(cfg)
	const (
		portable = "leave it set if the same document is deployed to another port in the family; nothing in this build reads it. "
		// The hazard config-schema.md §1.6 records against the SMS gateway
		// credentials: the reference appends them as query parameters on a GET,
		// writing them into every access log on the way. An SNS publish has no URL
		// to move them off, so the hazard retires with the credential.
		smsHazard = " — which also retires the credentials-in-URL hazard the schema records for it, since there is no URL"
	)
	// The "the block is off" texts, in the two postures. Without a webhook,
	// switching the block off means the credential is not delivered at all and
	// the route answers a coded 500; with one, the webhook already carries every
	// credential and the block is genuinely optional, so telling an operator to
	// set the switch would be telling them to wire a transport they do not need.
	smsOff := "sms.endpoint is unset, so no SMS transport is wired at all and POST /sms/send answers 500 SMS_NOT_CONFIGURED: set it to turn SMS delivery on, or delete the credential"
	mailOff := "email.mailer.from is unset, so no mail transport is wired at all and no mail is sent: set it to turn mail delivery on, or delete the key"
	if hook {
		smsOff = "sms.endpoint is unset, so no SNS transport is wired, but the delivery webhook carries the SMS code instead and POST /sms/send works: delete the credential, or set sms.endpoint only if you want the email-changed half of this document to be portable to a port that has no webhook"
		mailOff = "email.mailer.from is unset, so no SES transport is wired, but the delivery webhook carries all five credential deliveries instead: delete the key, or set email.mailer.from only to turn on the two mails the webhook has no seam for — the email-changed notice and the account-linking mail"
	}
	for _, row := range []struct{ path, service, action, hazard, on, off string }{
		{
			path: "email.mailer.apiKey", service: "SES", action: "ses:SendEmail",
			on:  "Deleting the secret it points at costs nothing here, and removes one credential from the blast radius",
			off: mailOff,
		},
		{
			path: "sms.apiKey", service: "SNS", action: "sns:Publish", hazard: smsHazard,
			on:  "Retiring the gateway credential removes it from the blast radius entirely",
			off: smsOff,
		},
		{
			path: "sms.username", service: "SNS", action: "sns:Publish", hazard: smsHazard,
			on:  "Retiring the gateway credential removes it from the blast radius entirely",
			off: smsOff,
		},
		{
			path: "sms.password", service: "SNS", action: "sns:Publish", hazard: smsHazard,
			on:  "Retiring the gateway credential removes it from the blast radius entirely",
			off: smsOff,
		},
	} {
		if cfg.SecretValue(row.path) == "" {
			continue
		}
		blockOn := smsOn
		if strings.HasPrefix(row.path, "email.") {
			blockOn = mailOn
		}
		problem := fmt.Sprintf(
			"%s authorises the call with the Lambda execution role's %s permission, so this credential is never presented to anything",
			row.service, row.action) + row.hazard
		remedy := portable + row.on
		if !blockOn {
			problem += ", and this deployment sends nothing through that half at all"
			remedy = row.off
		}
		gaps = append(gaps, knobGap{Path: row.path, Problem: problem, Remedy: remedy})
	}

	if mailOn {
		const sesRemedy = "leave it set if the same document is deployed to another port in the family; nothing in this build reads it"

		// What SES actually carries, which is the whole mailer only without a
		// webhook. Under one it carries the two mails auth.DeliveryWebhook has no
		// seam for, and saying "this build delivers mail through Amazon SES"
		// would tell an operator the reset mail went out by mail when it did not.
		sesCarries := "this build delivers mail through Amazon SES"
		if hook {
			sesCarries = "email.deliveryWebhook.url is set, so the five credential deliveries are POSTed to that receiver and Amazon SES carries only the email-changed notice and the account-linking mail"
		}

		// Always present when the mailer is on: validate.go requires an endpoint
		// for any configured mailer block, and SES never has one.
		gaps = append(gaps, knobGap{
			Path:    "email.mailer.endpoint",
			Problem: sesCarries + "; either way SES is called through the AWS API and not by posting to a URL, so no request is ever made to this endpoint",
			Remedy:  sesRemedy + ". The schema requires it, which is why configuring a mailer at all means configuring one",
		})
		// provider is free-form in the schema and the reference passes it to its
		// gateway to select a backend. Naming ses is honoured — it is what this
		// build does — so only a different value is a gap.
		if p := strings.TrimSpace(cfg.Email.Mailer.Provider); p != "" && !strings.EqualFold(p, "ses") {
			gaps = append(gaps, knobGap{
				Path:    "email.mailer.provider",
				Problem: fmt.Sprintf("%s, and there is no second mail transport to select, so the configured provider %q selects nothing", sesCarries, p),
				Remedy:  `set it to "ses" to describe what is actually deployed, or remove it`,
			})
		}
	}

	if smsOn {
		const snsRemedy = "leave it set if the same document is deployed to another port in the family; nothing in this build reads it"

		// Without a webhook the knob still has one job — it is the switch that
		// wires SNS at all. With one it has none: the SMS code is POSTed to the
		// receiver whether or not this block is configured, and SNS publishes
		// nothing.
		problem := "this build sends text messages with an SNS Publish to the recipient's number, so no request is ever made to this gateway; the knob's only remaining job is to say that SMS delivery should be wired at all"
		remedy := snsRemedy + ", and keep it set: an empty sms block leaves POST /sms/send answering 500 SMS_NOT_CONFIGURED"
		if hook {
			problem = "email.deliveryWebhook.url is set, so the SMS code is POSTed to that receiver and nothing is published through SNS: no request is made to this gateway either, and the knob has no remaining job in this deployment"
			remedy = snsRemedy + ". Removing the whole sms block changes nothing here — POST /sms/send keeps working through the webhook — so keep it only for a document that is also deployed without one"
		}
		gaps = append(gaps, knobGap{Path: "sms.endpoint", Problem: problem, Remedy: remedy})
	}

	// The delivery webhook's secret is the same shape of hazard as the four
	// credentials above: a Secrets Manager entry the template carries, whose
	// switch — the url — is the part that gets forgotten. A secret *referenced*
	// from the document without a url is refused by validate.go; a value that
	// arrived through its plain environment variable leaves no reference to
	// refuse, so it is reported here instead of being silently unused.
	if cfg.SecretValue("email.deliveryWebhook.secret") != "" && strings.TrimSpace(cfg.Email.DeliveryWebhook.URL) == "" {
		gaps = append(gaps, knobGap{
			Path:    "email.deliveryWebhook.secret",
			Problem: "the delivery webhook's signing secret resolves to a value, but email.deliveryWebhook.url is unset, so no webhook is wired and the secret signs nothing; credentials go through SES and SNS as if it were absent",
			Remedy:  "set email.deliveryWebhook.url to the https receiver that should get every delivery, or delete the secret",
		})
	}

	return gaps
}

// fatal reports a cold-start failure as structured JSON and aborts the init.
//
// A *ValidationError is expanded into one line per diagnostic: each line is
// self-contained by design, so whichever one an operator happens to see in
// CloudWatch is actionable on its own.
func fatal(log *slog.Logger, err error) {
	var verr *config.ValidationError
	if errors.As(err, &verr) {
		for _, d := range verr.Diagnostics {
			log.Error("configuration error",
				slog.String("rule", d.Rule),
				slog.String("path", d.Path),
				slog.String("source", d.Source),
				slog.String("problem", d.Problem),
				slog.String("remedy", d.Remedy))
		}
	}
	log.Error("cold start failed, refusing to serve", slog.String("error", err.Error()))

	// slog's handler writes synchronously to the underlying io.Writer, but the
	// runtime may still exit before a buffered stdout drains on some hosts.
	_ = os.Stdout.Sync()
	os.Exit(1)
}

// startTimeout bounds the cold-start work. The Lambda init phase gets 10
// seconds before the runtime restarts it, so a hung SSM or STS call must fail
// inside that window with a message rather than be killed without one.
const startTimeout = 8 * time.Second
