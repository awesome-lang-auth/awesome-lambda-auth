// Package config loads, layers and validates the declarative configuration
// document that replaces the reference implementation's in-code
// AuthConfigurator.
//
// awesome-lambda-auth is a deployable product, not a library: the operator
// writes configuration and deploys a stack, and never gets to inject a
// callback. Every knob awesome-node-auth exposes programmatically therefore
// needs a declarative equivalent, and an insecure combination has to refuse to
// start rather than degrade into a silent misconfiguration nobody notices until
// a login half-succeeds in production. docs/spec/config-schema.md is the
// specification this package implements; §1 is the knob inventory (with the
// reference's code defaults and their file:line evidence) and §2 is the
// refuse-to-start table, whose rule IDs (RS-1 … RS-12) appear verbatim in the
// errors produced here.
//
// # Layering
//
// Load applies, in order:
//
//  1. Defaults, which are the reference's *code* defaults wherever one exists.
//  2. The configuration document, whatever decoded it (see Document).
//  3. AWESOME_AUTH_* environment overrides.
//
// A later layer wins over an earlier one, per knob. The runtime settings store
// (§1.19) is a fourth layer that only ever applies to the handful of
// runtime-mutable keys; it is not implemented here and is deliberately not a
// general override channel — everything outside §1.19 is immutable once the
// stack is up.
//
// # Errors
//
// Load never returns a bare "invalid configuration". Every problem is a
// Diagnostic naming the offending knob by its dotted path, where the value came
// from, what is wrong with it and what to do about it, and all of them are
// reported at once so an operator fixes one deploy's worth of mistakes per
// deploy. The target reader is someone looking at a single CloudWatch log line
// at 3am who does not have the source open.
//
// # Format
//
// §4 of the spec leaves the on-disk format open (YAML file vs SSM parameter
// tree vs both), so this package deliberately does not own decoding. It
// consumes a Document — a decoded, JSON-compatible tree — and ships ParseJSON
// for the stdlib case. A YAML or SSM front end plugs in by producing the same
// tree, which keeps the format decision reversible.
//
// # Cloud-agnostic by construction
//
// Secret-valued knobs resolve through the SecretResolver interface in the
// documented order (Secrets Manager, then SSM SecureString, then a plain
// environment variable). Only the environment resolver ships here: this package
// must not import the AWS SDK, because the core has to stay deployable
// somewhere other than AWS. The AWS-backed resolvers live under
// internal/integration/aws and are injected.
package config

import (
	"fmt"
	"sort"
	"strings"
)

// CurrentSchemaVersion is the only document major version this build
// understands. Additive knobs with defaults do not bump it; renames, removals
// and semantic changes do, and an unknown value refuses to start rather than
// guessing what the operator meant (spec §4).
const CurrentSchemaVersion = 1

// Document is a decoded configuration document: the parsed form of whatever
// file or parameter tree the deployment carries, before it is mapped onto
// Config. Keys are the camelCase names of spec §1 and values must be
// JSON-compatible (string, float64, bool, nil, []any, map[string]any), which is
// what both encoding/json and a YAML v3 decode into a map[string]any produce.
type Document map[string]any

// Config is the fully layered, validated configuration. Obtain one from Load;
// the zero value is not usable and Defaults alone is not valid either, because
// a deployable stack has to declare at least its public URL and its store
// driver.
//
// Secret-valued knobs hold a *reference* here, never a value: resolved
// plaintext lives outside the tree and is read with SecretValue, so that
// logging or marshalling a Config cannot leak a signing key.
type Config struct {
	// SchemaVersion is the document's declared major version. Required in the
	// document; see CurrentSchemaVersion.
	SchemaVersion int `json:"schemaVersion"`

	Deployment      Deployment      `json:"deployment"`
	Security        Security        `json:"security"`
	Tokens          Tokens          `json:"tokens"`
	Cookies         Cookies         `json:"cookies"`
	Sessions        Sessions        `json:"sessions"`
	Email           Email           `json:"email"`
	SMS             SMS             `json:"sms"`
	OAuth           OAuth           `json:"oauth"`
	TwoFactor       TwoFactor       `json:"twoFactor"`
	IDProvider      IDProvider      `json:"idProvider"`
	ResourceServer  ResourceServer  `json:"resourceServer"`
	UI              UI              `json:"ui"`
	Admin           Admin           `json:"admin"`
	Tools           Tools           `json:"tools"`
	RateLimit       RateLimit       `json:"rateLimit"`
	Stores          Stores          `json:"stores"`
	HTTP            HTTP            `json:"http"`
	Docs            Docs            `json:"docs"`
	RuntimeSettings RuntimeSettings `json:"runtimeSettings"`

	// secrets holds every resolved secret keyed by its dotted path. Kept out of
	// the exported tree on purpose: %v on a Config, or a debug endpoint that
	// marshals it, must not be able to print a signing key.
	secrets map[string]resolvedSecret

	// sources records where each dotted path's value came from, so diagnostics
	// can say "you set this in the document" versus "an env var overrode it".
	sources map[string]string

	warnings []Diagnostic
}

// Deployment describes the deployed stack itself.
//
// [new] — the whole block is product-only. The reference is a library embedded
// in someone else's server, so it has no notion of a stage, a public URL or a
// production/development distinction. Spec §2 nonetheless leans on all three:
// RS-2 asks whether cookies are being served from a raw execute-api stage URL,
// and RS-4 and RS-12 are qualified "in production". Those rules cannot be
// evaluated without these knobs, so they are defined here.
type Deployment struct {
	// Environment is production or development. It defaults to production
	// deliberately: an operator who forgets to declare it gets the strict rules
	// and a loud failure, not an in-memory store quietly serving real users.
	Environment string `json:"environment"`

	// Stage is the API Gateway stage name ("prod"), used by the event
	// normalisation layer to strip the stage segment from request paths. Empty
	// for HTTP APIs and Function URLs served at the root.
	Stage string `json:"stage"`

	// PublicURL is the origin clients actually reach, e.g.
	// https://auth.example.com or https://abc123.execute-api.eu-west-1.amazonaws.com/prod.
	//
	// This is how "no custom domain" is expressed: a host under a shared AWS
	// domain (execute-api or lambda-url) means the deployment does not have one,
	// which is what RS-2 turns on. There is deliberately no separate
	// customDomain knob — two knobs would need to be kept consistent, and only
	// the effective URL matters.
	PublicURL string `json:"publicUrl"`
}

// Security groups the token, password and CSRF knobs of spec §1.1 and §1.3.
type Security struct {
	JWT      JWT      `json:"jwt"`
	Password Password `json:"password"`
	CSRF     CSRF     `json:"csrf"`
}

// JWT covers security.jwt.* (spec §1.1).
type JWT struct {
	// AccessTokenSecret is the HS256 signing secret. The reference never
	// validates it and an absent secret surfaces as a 500 inside the first
	// jwt.sign (src/services/token.service.ts:22,145); RS-1 makes it a
	// startup failure with a 32-character floor instead.
	AccessTokenSecret Secret `json:"accessTokenSecret"`

	// RefreshTokenSecret must differ from AccessTokenSecret: reusing one secret
	// for both makes a refresh token a valid access token (RS-1).
	RefreshTokenSecret Secret `json:"refreshTokenSecret"`

	// AccessTokenTTL defaults to 15m (src/services/token.service.ts:23).
	AccessTokenTTL Duration `json:"accessTokenTtl"`

	// RefreshTokenTTL defaults to 7d (src/services/token.service.ts:28). The
	// reference silently falls back to 7d for the session expiry when the value
	// does not parse (src/router/auth.router.ts:357-360); RS-9 refuses instead.
	RefreshTokenTTL Duration `json:"refreshTokenTtl"`

	// ExtraClaims is the declarative replacement for the reference's
	// buildTokenPayload callback (spec §3.1). Keys must not collide with the six
	// base claims.
	ExtraClaims map[string]Claim `json:"extraClaims"`

	// ClaimsWebhook is the escape hatch for claims that need computation
	// (spec §3.1). Its signing secret is required alongside its url, for the
	// reason the Webhook type gives.
	ClaimsWebhook Webhook `json:"claimsWebhook"`
}

// Claim is one entry of security.jwt.extraClaims: either a copy of a user field
// or a constant. Exactly one of the two must be set.
type Claim struct {
	FromUserField string `json:"fromUserField"`
	Const         any    `json:"const"`
}

// Webhook is an outbound HTTP escape hatch: the two the schema has are
// security.jwt.claimsWebhook (spec §1.1, §3.1) and email.deliveryWebhook
// (§1.5, §3.8). Timeouts are strict by design — an auth request must not hang
// on someone else's server — and the signing secret is a product addition over
// the spec's url-and-timeout knob, required in both.
//
// Required, because the two requests carry different things and each is a
// reason on its own. A delivery hands the receiver the credential itself — a
// reset token, a magic link, a one-time code — and a receiver that cannot
// verify X-Webhook-Signature would mint sessions for whoever posts to it. A
// claims request hands it the user profile as GET /me renders it, and takes
// back claims that go into the token every client authorises on: unsigned, the
// receiver cannot tell this deployment's question from anybody else's, and
// answering the wrong asker leaks the profile while answering as the wrong
// receiver decides authorisation. validate.go refuses a url without a secret
// and a secret without a url, in both blocks.
type Webhook struct {
	URL       string `json:"url"`
	TimeoutMs int    `json:"timeoutMs"`
	Secret    Secret `json:"secret"`
}

// Password covers security.password.* (spec §1.1).
type Password struct {
	// BcryptSaltRounds defaults to 12, the default parameter of
	// PasswordService.hash (src/services/password.service.ts:4).
	BcryptSaltRounds int `json:"bcryptSaltRounds"`
}

// CSRF covers security.csrf.* (spec §1.3).
type CSRF struct {
	// Enabled defaults to true, which is a deliberate hardening deviation: the
	// reference defaults to false (src/middleware/auth.middleware.ts:35). RS-3
	// rejects false while cookie delivery is active, so the product default and
	// the rule agree.
	Enabled bool `json:"enabled"`
}

// Tokens covers the single-use token lifetimes of spec §1.1, every one of which
// is hardcoded in the reference.
type Tokens struct {
	PasswordResetTTLMinutes     int `json:"passwordResetTtlMinutes"`
	EmailVerificationTTLMinutes int `json:"emailVerificationTtlMinutes"`
	EmailChangeTTLMinutes       int `json:"emailChangeTtlMinutes"`
	AccountLinkTTLMinutes       int `json:"accountLinkTtlMinutes"`
	MagicLinkTTLMinutes         int `json:"magicLinkTtlMinutes"`
}

// Cookies covers cookies.* (spec §1.2).
//
// Cookie names are derived, not configured: plain when Secure is false,
// __Host- when Secure and Path "/" and no Domain, __Secure- otherwise
// (src/services/token.service.ts:161-172). Every client in the family depends
// on that, so it is preserved exactly and exposed as no knob. Max-Age is
// likewise derived from the JWT TTLs, fixing the reference's hardcoded
// 15m/7d Max-Age that desynchronises from non-default TTLs.
type Cookies struct {
	Secure                  bool   `json:"secure"`
	SameSite                string `json:"sameSite"`
	Domain                  string `json:"domain"`
	Path                    string `json:"path"`
	RefreshTokenPath        string `json:"refreshTokenPath"`
	AllowInsecureCookieMode bool   `json:"allowInsecureCookieMode"`
}

// Sessions covers sessions.* (spec §1.4).
type Sessions struct {
	// CheckOn is allcalls, refresh or none. The middleware acts only on the
	// literal "allcalls" (src/middleware/auth.middleware.ts:47), so unset is
	// equivalent to "refresh". Clients that rely on the SESSION_REVOKED 401 for
	// instant logout implicitly require "allcalls".
	CheckOn string `json:"checkOn"`
}

// Email covers email.* (spec §1.5).
type Email struct {
	// SiteURLs is the redirect allowlist; the first entry is canonical.
	SiteURLs     []string          `json:"siteUrls"`
	Mailer       Mailer            `json:"mailer"`
	Verification EmailVerification `json:"verification"`
	TemplatesDir string            `json:"templatesDir"`

	// DeliveryWebhook covers email.deliveryWebhook.* (spec §1.5, §3.8): the
	// https receiver that is handed every minted credential instead of SES and
	// SNS. It is the Webhook type, which carries the signing secret this block
	// and the claims webhook both require; see there.
	DeliveryWebhook Webhook `json:"deliveryWebhook"`
}

// Mailer covers email.mailer.* (spec §1.5).
type Mailer struct {
	Endpoint    string `json:"endpoint"`
	APIKey      Secret `json:"apiKey"`
	From        string `json:"from"`
	FromName    string `json:"fromName"`
	Provider    string `json:"provider"`
	DefaultLang string `json:"defaultLang"`
}

// EmailVerification covers email.verification.* (spec §1.5). It folds in the
// reference's deprecated requireEmailVerification boolean.
type EmailVerification struct {
	// Mode is none, lazy or strict. Effective reference default is "none"
	// (src/strategies/local/local.strategy.ts:32-35).
	Mode string `json:"mode"`
}

// SMS covers sms.* (spec §1.6).
//
// The reference appends the SMS username and password as query parameters on a
// GET (src/services/sms.service.ts:19-20,28), which writes credentials into
// every access log between here and the gateway. They are modelled as secrets
// here and the transport must move them off the URL.
type SMS struct {
	Endpoint       string `json:"endpoint"`
	APIKey         Secret `json:"apiKey"`
	Username       Secret `json:"username"`
	Password       Secret `json:"password"`
	CodeTTLMinutes int    `json:"codeTtlMinutes"`
}

// OAuth covers oauth.* (spec §1.7).
type OAuth struct {
	// Providers is keyed by provider name. "google" and "github" are built in
	// and need no endpoint URLs; any other key is a generic OIDC/OAuth2 provider
	// and must supply them.
	Providers map[string]OAuthProvider `json:"providers"`

	// Provisioning replaces the abstract findOrCreateUser the reference forces
	// integrators to implement (spec §3.3).
	Provisioning OAuthProvisioning `json:"provisioning"`
}

// OAuthProvider is one entry of oauth.providers.
type OAuthProvider struct {
	ClientID     string `json:"clientId"`
	ClientSecret Secret `json:"clientSecret"`
	CallbackURL  string `json:"callbackUrl"`
	ProjectID    string `json:"projectId"`

	AuthorizationURL string `json:"authorizationUrl"`
	TokenURL         string `json:"tokenUrl"`
	UserInfoURL      string `json:"userInfoUrl"`
	Scope            string `json:"scope"`

	AdditionalAuthParams map[string]string `json:"additionalAuthParams"`

	// ProfileMap replaces the mapProfile callback with fallback-chain
	// expressions, e.g. email: "$.mail ?? $.userPrincipalName".
	ProfileMap map[string]string `json:"profileMap"`
}

// OAuthProvisioning covers oauth.provisioning.*.
type OAuthProvisioning struct {
	AutoCreate          bool     `json:"autoCreate"`
	AllowedEmailDomains []string `json:"allowedEmailDomains"`

	// OnEmailMatch decides what the callback does when the provider account is
	// unknown but some account already holds the address it asserts: link the
	// two (the default), raise the reference's OAUTH_ACCOUNT_CONFLICT so the
	// link is made only after an emailed token proves the address, or refuse.
	//
	// It has no counterpart in the schema extract because the reference has no
	// provisioning at all — the integrator writes findOrCreateUser and decides
	// this in code (spec §3.3). The imported core does have the knob, and its
	// default is "link", which is the account-takeover shape the reference's own
	// store interface warns about: two providers can assert one address without
	// representing one person. A policy that consequential must be visible in
	// the document rather than hardcoded here, which is why it is a knob and not
	// a constant (docs/spec/decisions.md D-20).
	OnEmailMatch string `json:"onEmailMatch"`

	FieldMap             map[string]string `json:"fieldMap"`
	RequireVerifiedEmail bool              `json:"requireVerifiedEmail"`
}

// TwoFactor covers twoFactor.* (spec §1.8). The 2FA feature flag itself stays
// derived from the presence of this block, as in the reference.
type TwoFactor struct {
	// AppName is the TOTP issuer in the otpauth URI; the reference default is
	// the literal "awesome-node-auth" (src/router/auth.router.ts:830).
	AppName string `json:"appName"`
}

// IDProvider covers idProvider.* (spec §1.10).
type IDProvider struct {
	Enabled bool `json:"enabled"`

	// PrivateKey must be supplied externally. The reference generates an
	// ephemeral RSA keypair and warns when it is missing
	// (src/services/token.service.ts:50-63) — under Lambda that means every cold
	// start invalidates every token, so RS-4 refuses instead.
	PrivateKey Secret `json:"privateKey"`

	// PublicKey is derived from PrivateKey when omitted.
	PublicKey string `json:"publicKey"`

	JWKSPath        string     `json:"jwksPath"`
	Issuer          string     `json:"issuer"`
	AccessTokenTTL  Duration   `json:"accessTokenTtl"`
	RefreshTokenTTL Duration   `json:"refreshTokenTtl"`
	JWKSCorsOrigins StringList `json:"jwksCorsOrigins"`

	// KMSKeyID names an AWS KMS asymmetric key (RSA, SIGN_VERIFY) that signs
	// every RS256 token instead of PrivateKey. Product addition, §1.10
	// addendum: the reference has no notion of a signer that keeps the private
	// key elsewhere, and a Lambda has nowhere safe to keep one — a PEM in
	// Secrets Manager is a key the function can read, copy and leak, while a KMS
	// key is one it can only ask to sign.
	//
	// A key id, an alias (alias/awesome-auth-idp) or a full ARN; an ARN is what
	// a cross-account or cross-region key needs. RS-4 refuses a deployment that
	// sets both this and PrivateKey — two keys and no rule for which one signs
	// is worse than neither.
	KMSKeyID string `json:"kmsKeyId"`

	// KMSPreviousKeyIDs are keys whose tokens are still in circulation. They
	// sign nothing; they are published in the JWKS document after the primary
	// key so that a token minted before a rotation keeps verifying until it
	// expires. A rotation is therefore additive — add the new key, make it
	// primary, and drop the old id one access-token lifetime later.
	KMSPreviousKeyIDs []string `json:"kmsPreviousKeyIds"`

	// Clients is the OIDC client registry. File-only, because a client is a
	// redirect-URI allowlist and a secret rather than a scalar, and because
	// dynamic client registration is deliberately out of scope for v1
	// (decisions.md D-3). Each entry's clientSecret is a secret reference like
	// every other, under idProvider.clients.<clientId>.clientSecret.
	Clients []IDPClient `json:"clients"`
}

// IDPClient is one registered OIDC relying party (spec §1.10 addendum).
//
// The shape is the core's auth.IDPClient, which is the reference's absence
// rather than its presence: awesome-node-auth publishes a JWKS and signs, and
// has no authorization server, so there is no reference client registry to
// reproduce. What the core needs is exactly these four values.
type IDPClient struct {
	// ClientID is the public identifier the relying party sends as client_id.
	// It is also the key of the client's secret slot, so it has to be stable:
	// renaming it renames the environment variable the secret can arrive in.
	ClientID string `json:"clientId"`

	// ClientSecret authenticates the relying party at the token endpoint
	// (client_secret_post, the only method the core advertises). Required: the
	// core compares the posted secret against this one, so an empty value would
	// let anyone holding a stolen authorization code redeem it.
	ClientSecret Secret `json:"clientSecret"`

	// RedirectURIs is the exact-match allowlist the authorization endpoint
	// resolves redirect_uri against. At least one is required, and each must be
	// https or a loopback http URL (RFC 8252 §7.3).
	RedirectURIs []string `json:"redirectUris"`

	// Name is what a consent screen would show. Cosmetic today.
	Name string `json:"name"`
}

// active reports whether identity-provider mode is on. The reference activates
// it when the private key is present *or* enabled is true
// (src/services/token.service.ts:42, src/router/auth.router.ts:473), and that
// implicit activation is preserved so a config that only supplies a key still
// trips RS-4's sibling checks.
//
// kmsKeyId counts as key material for the same reason privateKey does: it is
// the operator saying which key signs, and a document that names one and
// forgets `enabled` must not come up with the IdP silently off.
func (i IDProvider) active() bool {
	return i.Enabled || i.PrivateKey.configured() || strings.TrimSpace(i.KMSKeyID) != ""
}

// ResourceServer covers resourceServer.* (spec §1.11). When enabled the product
// only validates tokens minted elsewhere, so the auth-flow routes and the local
// signing secrets are not needed.
type ResourceServer struct {
	Enabled bool   `json:"enabled"`
	JWKSURL string `json:"jwksUrl"`
	Issuer  string `json:"issuer"`

	JWKSCacheTTLMs     int `json:"jwksCacheTtlMs"`
	JWKSFetchTimeoutMs int `json:"jwksFetchTimeoutMs"`
}

// UI covers ui.* (spec §1.12). The derived /ui/config feature flags stay
// derived and are deliberately not knobs.
type UI struct {
	Enabled   bool     `json:"enabled"`
	Headless  bool     `json:"headless"`
	CustomCSS string   `json:"customCss"`
	Branding  Branding `json:"branding"`
	AssetsDir string   `json:"assetsDir"`
	UploadDir string   `json:"uploadDir"`
}

// Branding covers ui.branding.*. Every field here is runtime-mutable: the
// settings store wins over these boot-time seeds (spec §1.19).
type Branding struct {
	LogoURL        string `json:"logoUrl"`
	PrimaryColor   string `json:"primaryColor"`
	SecondaryColor string `json:"secondaryColor"`
	SiteName       string `json:"siteName"`
	BgColor        string `json:"bgColor"`
	BgImage        string `json:"bgImage"`
	CardBg         string `json:"cardBg"`
}

// Admin covers admin.* (spec §1.13).
type Admin struct {
	// Enabled decides whether the admin surface is deployed at all.
	//
	// [new] — the reference mounts the admin router when the integrator calls
	// createAdminRouter, which is not something a config document can express.
	// RS-6 ("admin surface deployed with neither accessPolicy nor
	// bootstrapSecret") needs a definition of "deployed", and this is it.
	Enabled bool `json:"enabled"`

	// AccessPolicy is first-user, is-admin-flag or open, or the string forms
	// rbac:<role> / permission:<perm>. Unset plus no bootstrap secret leaves the
	// reference's admin routes fully open behind a stderr warning
	// (src/router/admin.router.ts:516-537); RS-6 refuses.
	AccessPolicy string `json:"accessPolicy"`

	// BootstrapSecret is the legacy bearer guard, kept only for bootstrap.
	BootstrapSecret Secret `json:"bootstrapSecret"`

	RootUser AdminRootUser `json:"rootUser"`

	CookiePrefix string   `json:"cookiePrefix"`
	LoginPath    string   `json:"loginPath"`
	BasePath     string   `json:"basePath"`
	SessionTTL   Duration `json:"sessionTtl"`
	Upload       Upload   `json:"upload"`
}

// AdminRootUser covers admin.rootUser.*.
type AdminRootUser struct {
	Email string `json:"email"`
	// PasswordHash is a bcrypt hash, never a plaintext password.
	PasswordHash Secret `json:"passwordHash"`
}

// Upload covers admin.upload.*.
type Upload struct {
	MaxFileSizeMb int `json:"maxFileSizeMb"`
}

// Tools covers tools.* (spec §1.14 and §1.15).
type Tools struct {
	// Enabled decides whether the tools surface is deployed.
	//
	// [new], for the same reason as Admin.Enabled: the reference mounts the
	// tools router when the integrator calls createToolsRouter, and the
	// cross-store requirements of spec §1.17 ("inbound webhooks require the
	// webhooks store") only make sense once something is asking for the routes.
	Enabled bool `json:"enabled"`

	Telemetry Feature `json:"telemetry"`
	Notify    Feature `json:"notify"`
	Stream    Feature `json:"stream"`

	// Auth is none, session, apiKey or admin. The reference leaves the tools
	// router unauthenticated when no middleware is injected (spec §3.7), so
	// "none" reproduces that and earns a deploy-time warning.
	Auth     string `json:"auth"`
	BasePath string `json:"basePath"`

	SSE              SSE              `json:"sse"`
	InboundWebhooks  InboundWebhooks  `json:"inboundWebhooks"`
	OutboundWebhooks OutboundWebhooks `json:"outboundWebhooks"`
}

// Feature is a bare on/off block.
type Feature struct {
	Enabled bool `json:"enabled"`
}

// SSE covers tools.sse.*.
type SSE struct {
	Enabled bool `json:"enabled"`
	// HeartbeatIntervalMs of zero or less disables the heartbeat, matching
	// src/tools/sse-manager.ts:105,156.
	HeartbeatIntervalMs int         `json:"heartbeatIntervalMs"`
	Deduplicate         bool        `json:"deduplicate"`
	Distributor         Distributor `json:"distributor"`
}

// Distributor covers tools.sse.distributor.*. Without one, events fan out only
// within a single process — which under Lambda means a single concurrent
// execution environment, i.e. almost nobody.
type Distributor struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
	TopicARN string `json:"topicArn"`
	Username string `json:"username"`
	Password Secret `json:"password"`
}

// InboundWebhooks covers tools.inboundWebhooks.*. The per-webhook rows
// themselves are data in the webhooks store, not configuration.
type InboundWebhooks struct {
	Enabled bool `json:"enabled"`
	// ScriptTimeoutMs bounds the sandboxed mapping script; the reference
	// hardcodes 5000 (src/router/tools.router.ts:289).
	ScriptTimeoutMs int `json:"scriptTimeoutMs"`
}

// OutboundWebhooks covers tools.outboundWebhooks.*.
type OutboundWebhooks struct {
	PayloadVersion string                  `json:"payloadVersion"`
	Defaults       OutboundWebhookDefaults `json:"defaults"`

	// QueueURL (D9b) is the SQS queue outgoing webhooks are enqueued on
	// instead of being POSTed in process.
	//
	// [new] — the reference delivers in process and has no transport knob
	// (webhook-sender.ts:36). Empty, the default, keeps the core's in-process
	// HTTP deliverer, which on Lambda races the response (deviation
	// outgoing-webhook-delivery-races-the-response); set, the auth function
	// enqueues each signed attempt and cmd/webhook-worker delivers it on the
	// reference's schedule. The SAM template sets it from EnableWebhookQueue.
	// docs/config-reference.md §17.4 says which deliverer is in force.
	QueueURL string `json:"queueUrl"`
}

// OutboundWebhookDefaults covers tools.outboundWebhooks.defaults.*; per-webhook
// rows may override them.
type OutboundWebhookDefaults struct {
	MaxRetries   int `json:"maxRetries"`
	RetryDelayMs int `json:"retryDelayMs"`
}

// RateLimit covers rateLimit.* (spec §1.16).
//
// The reference has no rate limiting at all unless the integrator injects
// Express middleware (src/router/auth.router.ts:46,468), so every value here is
// a product decision. The spec marked them all TBD in Phase 0 and they are
// decided now, in Defaults() below; docs/config-reference.md argues each one to
// an operator and cmd/auth/ratelimit.go implements them.
type RateLimit struct {
	Enabled       bool     `json:"enabled"`
	WindowSeconds int      `json:"windowSeconds"`
	Max           int      `json:"max"`
	KeyBy         string   `json:"keyBy"`
	Scope         []string `json:"scope"`
}

// Stores covers stores.* (spec §1.17). The reference has the integrator inject
// thirteen store interfaces and toggles features on their presence; the product
// ships the implementations and toggles the same features here.
type Stores struct {
	Driver     string          `json:"driver"`
	Connection StoreConnection `json:"connection"`
	Enable     StoreEnable     `json:"enable"`
	Migration  Migration       `json:"migration"`
}

// Migration covers stores.migration.*: where this deployment's users are coming
// from, while they are still coming.
//
// It has no counterpart anywhere in the reference and no section in the
// extracted schema, because the reference is a library an integrator mounts in
// front of a store they already populated. A deployable product is the other
// shape: somebody already has users, in somebody else's system, and the only
// interesting question about the first month of a deployment is how they get
// across without being asked to choose a new password. Nothing here is parity
// and nothing here is a wire deviation — with the whole block unset, which is
// the default, every route answers exactly what it answered before the block
// existed.
//
// The block is deliberately a sub-block of `stores` rather than a domain of its
// own. What it configures is where a user record comes from when the store does
// not have one, and what a stored record's migration marker means; both are
// statements about the store, and putting them anywhere else would have made
// `stores.driver` and the marker's home into two unrelated knobs that have to
// agree.
type Migration struct {
	// Source names the system being migrated away from. Empty — the default —
	// is the whole off switch: no verifier is wired, no fall-through happens,
	// and the binary is byte-for-byte the one that shipped before X1.
	//
	// "cognito" is the only value this build knows. It is an enum rather than a
	// boolean because the second source (Auth0, Firebase) is a different set of
	// three API calls and a different marker payload, and a boolean would have
	// to be replaced rather than extended.
	Source string `json:"source"`

	// UserPoolID is the Cognito user pool. Required with a source, refused
	// without one (RS-13). It is not a secret and is not secret-tagged: a pool
	// id is in every Cognito-hosted login URL, and treating it as a secret would
	// only mean an operator could not read it back out of the diagnostics that
	// name it.
	UserPoolID string `json:"userPoolId"`

	// ClientID is an app client in that pool, and it is what makes just-in-time
	// password migration possible at all: AdminInitiateAuth is a client-scoped
	// call. The app client must allow ADMIN_USER_PASSWORD_AUTH and must have no
	// client secret (internal/integration/aws/cognito.go,
	// ErrCognitoClientHasSecret).
	//
	// Optional, and the distinction is the useful one: with a pool id and no
	// client id the deployment reads the pool but signs nobody in through it,
	// which is exactly a stack that has finished its bulk import and wants the
	// dual-read safety net without the login-path dependency.
	ClientID string `json:"clientId"`

	// Region is where the pool lives. Required with a pool id (RS-13) rather
	// than inherited from stores.connection.region, because the commonest
	// migration is out of a pool in another region or another account entirely,
	// and silently addressing the wrong region would surface as "the pool holds
	// no such user" for every single person.
	Region string `json:"region"`

	// Mode is import-only (the default) or dual-read.
	//
	// import-only means the local store is the only place a user is looked for:
	// a miss is a miss. Every user reaches this deployment through cmd/migrate,
	// and the only thing the source is still consulted for is a password.
	//
	// dual-read additionally falls a GetUserByEmail miss through to the source
	// and lazily creates the local row. It is the safety net for the window in
	// which the bulk import is incomplete, and it is not free: see
	// internal/store/migrating for what a miss costs on an unauthenticated route
	// and what bounds it.
	Mode string `json:"mode"`
}

// Active reports whether the migration block is switched on. The source is the
// switch, so that every other knob can be present and inert on a deployment
// that has finished migrating and has not yet deleted its configuration.
func (m Migration) Active() bool { return strings.TrimSpace(m.Source) != "" }

// DualRead reports whether a lookup miss falls through to the source. False for
// an inactive block, so the mode cannot act on its own.
func (m Migration) DualRead() bool { return m.Active() && m.Mode == MigrationModeDualRead }

// VerifierConfigured reports whether the deployment can ask the source about a
// password. Without an app client id the block still imports and still
// dual-reads; it just never reaches the login path.
func (m Migration) VerifierConfigured() bool {
	return m.Active() && strings.TrimSpace(m.ClientID) != ""
}

// StoreConnection covers stores.connection.*; which fields matter depends on
// the driver.
type StoreConnection struct {
	TableName string `json:"tableName"`
	DSN       string `json:"dsn"`
	Region    string `json:"region"`
	Endpoint  string `json:"endpoint"`
	Username  string `json:"username"`
	Password  Secret `json:"password"`
}

// StoreEnable covers stores.enable.<store>. A disabled store makes its feature
// routes and admin tabs absent, exactly as an absent injected store does in the
// reference.
type StoreEnable struct {
	// Users is always on: IUserStore is a required constructor argument in the
	// reference and nothing works without it.
	Users          bool `json:"users"`
	Sessions       bool `json:"sessions"`
	Metadata       bool `json:"metadata"`
	RBAC           bool `json:"rbac"`
	Tenants        bool `json:"tenants"`
	LinkedAccounts bool `json:"linkedAccounts"`
	PendingLinks   bool `json:"pendingLinks"`
	Settings       bool `json:"settings"`
	APIKeys        bool `json:"apiKeys"`
	Webhooks       bool `json:"webhooks"`
	Templates      bool `json:"templates"`
	Telemetry      bool `json:"telemetry"`
	Tokens         bool `json:"tokens"`
}

// storeNames lists the stores in stores.enable.<store> order, paired with the
// pointer accessor the env layer and the cross-store checks use. Keeping one
// table means a new store cannot be added to the struct and forgotten by the
// env overrides.
func storeFields(e *StoreEnable) []struct {
	name string
	ptr  *bool
} {
	return []struct {
		name string
		ptr  *bool
	}{
		{"users", &e.Users},
		{"sessions", &e.Sessions},
		{"metadata", &e.Metadata},
		{"rbac", &e.RBAC},
		{"tenants", &e.Tenants},
		{"linkedAccounts", &e.LinkedAccounts},
		{"pendingLinks", &e.PendingLinks},
		{"settings", &e.Settings},
		{"apiKeys", &e.APIKeys},
		{"webhooks", &e.Webhooks},
		{"templates", &e.Templates},
		{"telemetry", &e.Telemetry},
		{"tokens", &e.Tokens},
	}
}

// HTTP covers http.* (spec §1.18).
type HTTP struct {
	APIPrefix string `json:"apiPrefix"`
	CORS      CORS   `json:"cors"`
}

// CORS covers http.cors.*. The allowed headers, methods and the 204 preflight
// status are hardcoded in the reference and stay that way.
type CORS struct {
	Origins []string `json:"origins"`
}

// Docs covers docs.* (spec §1.18).
type Docs struct {
	// Swagger is true, false or auto. Auto reproduces the reference's
	// NODE_ENV-sensitive behaviour: on outside production, off in it.
	Swagger  string `json:"swagger"`
	BasePath string `json:"basePath"`
}

// RuntimeSettings holds the boot-time seeds for the runtime-mutable keys of
// spec §1.19. The settings store wins over these once the stack is up; they are
// listed here so a fresh deployment starts from a declared state instead of
// whatever the store happens to contain.
type RuntimeSettings struct {
	Require2FA            bool     `json:"require2fa"`
	EnabledWebhookActions []string `json:"enabledWebhookActions"`

	// LazyEmailVerificationGracePeriodDays is display-only in the reference —
	// the server never computes emailVerificationDeadline from it
	// (spec §1.19 [MISMATCH]). It is seeded here so the product can actually
	// honour it once lazy verification is wired.
	LazyEmailVerificationGracePeriodDays int `json:"lazyEmailVerificationGracePeriodDays"`
}

// Defaults returns the configuration with every knob at its documented default.
//
// Wherever the reference has a code default, that value is used verbatim, with
// the file:line evidence recorded on the field. Two defaults deviate on purpose
// and are called out in the spec: security.csrf.enabled is true (the reference
// defaults to false) and deployment.environment is production.
//
// Defaults alone is not a valid configuration — Load still refuses it, because
// a deployable stack must declare its public URL and its signing secrets.
func Defaults() *Config {
	return &Config{
		SchemaVersion: CurrentSchemaVersion,
		Deployment: Deployment{
			Environment: EnvironmentProduction,
		},
		Security: Security{
			JWT: JWT{
				AccessTokenTTL:  mustDuration("15m"),
				RefreshTokenTTL: mustDuration("7d"),
				ClaimsWebhook:   Webhook{TimeoutMs: 2000},
			},
			Password: Password{BcryptSaltRounds: 12},
			CSRF:     CSRF{Enabled: true},
		},
		Tokens: Tokens{
			PasswordResetTTLMinutes:     60,
			EmailVerificationTTLMinutes: 24 * 60,
			EmailChangeTTLMinutes:       60,
			AccountLinkTTLMinutes:       60,
			MagicLinkTTLMinutes:         15,
		},
		Cookies: Cookies{
			Secure:   false,
			SameSite: SameSiteLax,
			Path:     "/",
		},
		Sessions: Sessions{CheckOn: SessionCheckOnRefresh},
		Email: Email{
			Mailer:          Mailer{DefaultLang: "en"},
			Verification:    EmailVerification{Mode: EmailVerificationNone},
			DeliveryWebhook: Webhook{TimeoutMs: 5000},
		},
		SMS: SMS{CodeTTLMinutes: 10},
		// The provisioning policy defaults to what the imported core does with
		// no policy at all (auth.DefaultOAuthProvisioning): create an account
		// for an identity nothing knows yet, and link an address a provider
		// asserts to the account that already holds it. Spelling it out here
		// rather than leaving the zero value is what keeps "configure a
		// provider and nothing else" working: an explicit policy is taken at
		// its word by the core, and a zero AutoCreate would turn every first
		// login into 403 OAUTH_USER_NOT_PROVISIONED.
		OAuth: OAuth{
			Provisioning: OAuthProvisioning{
				AutoCreate:   true,
				OnEmailMatch: OAuthEmailMatchLink,
			},
		},
		TwoFactor: TwoFactor{
			AppName: "awesome-node-auth",
		},
		IDProvider: IDProvider{
			JWKSPath:        "/.well-known/jwks.json",
			AccessTokenTTL:  mustDuration("30d"),
			RefreshTokenTTL: mustDuration("90d"),
			JWKSCorsOrigins: StringList{Values: []string{"*"}},
		},
		ResourceServer: ResourceServer{
			JWKSCacheTTLMs:     3_600_000,
			JWKSFetchTimeoutMs: 5000,
		},
		UI: UI{
			Branding: Branding{
				PrimaryColor:   "#4a90d9",
				SecondaryColor: "#6c757d",
				SiteName:       "Awesome Node Auth",
			},
		},
		Admin: Admin{
			BasePath:   "/admin",
			SessionTTL: mustDuration("24h"),
			Upload:     Upload{MaxFileSizeMb: 5},
		},
		Tools: Tools{
			Telemetry: Feature{Enabled: true},
			Notify:    Feature{Enabled: true},
			Stream:    Feature{Enabled: true},
			BasePath:  "/tools",
			SSE: SSE{
				HeartbeatIntervalMs: 30_000,
				Deduplicate:         true,
				Distributor:         Distributor{Type: DistributorNone},
			},
			InboundWebhooks: InboundWebhooks{
				Enabled:         true,
				ScriptTimeoutMs: 5000,
			},
			OutboundWebhooks: OutboundWebhooks{
				PayloadVersion: "1",
				Defaults: OutboundWebhookDefaults{
					MaxRetries:   3,
					RetryDelayMs: 1000,
				},
			},
		},
		// Rate limiting. The reference has none and therefore no defaults to
		// inherit; every value here is a product decision and each is argued in
		// docs/config-reference.md §13. The short form:
		//
		// Enabled is true because this product's house rule is that forgetting
		// tightens rather than loosens — the same rule that makes CSRF on by
		// default and the environment production by default, and the same
		// reasoning: a deployable product has to be safe with an empty
		// configuration where a library can leave the choice to its integrator.
		// A deployment that never mentions the block gets a limiter, and the 429
		// it can then answer where the reference answers 200 is the registered
		// wire deviation rate-limited-routes-answer-429.
		//
		// KeyBy is email and not ip. The threat these routes face is credential
		// stuffing and password spraying against accounts, which is
		// account-shaped; an IP-keyed default would put a corporate NAT's whole
		// office in one bucket and one DynamoDB partition, so the limiter would
		// become the outage for exactly the people it is not aimed at
		// (data-model.md §2.3, whose own conclusion is that the account-scoped
		// limiter must be the primary control). Volumetric defence by source
		// address belongs at the edge, where a WAF can do it properly.
		//
		// Max 10 in a 60-second window, per subject per scope. A real person
		// mistypes a password a few times a minute and no more; ten leaves room
		// for that plus a client retry, and holds an attacker to six seconds per
		// guess against one account. Sixty seconds is also the longest a false
		// positive can cost someone, because Retry-After can never exceed the
		// window.
		//
		// Scope is the five flows data-model.md §1.5 row #61 names — the ones
		// that mint or spend a credential without a session to lose. Nothing
		// else is in by default: `refresh`, `verify-email` and the rest are
		// nameable, and an operator who wants them says so.
		RateLimit: RateLimit{
			Enabled:       true,
			WindowSeconds: 60,
			Max:           10,
			KeyBy:         RateLimitKeyByEmail,
			Scope:         []string{"login", "forgot-password", "magic-link", "sms-code", "2fa-verify"},
		},
		Stores: Stores{
			Driver: StoreDriverMemory,
			Enable: StoreEnable{
				Users:    true,
				Sessions: true,
				Tokens:   true,
			},
			// The mode has a default and the source does not, which is the whole
			// shape of the block: with no source nothing here runs, and an
			// operator who switches a source on without saying which mode they
			// want gets the one that reads nobody else's directory on the login
			// path. Defaulting to dual-read would mean a typo'd address in a
			// login request became a call to Cognito.
			Migration: Migration{Mode: MigrationModeImportOnly},
		},
		HTTP: HTTP{APIPrefix: "/auth"},
		Docs: Docs{Swagger: SwaggerAuto},
		RuntimeSettings: RuntimeSettings{
			LazyEmailVerificationGracePeriodDays: 7,
		},
	}
}

// Enumerated values. They are exported because the deployment tooling validates
// documents against the same vocabulary before anything is uploaded.
const (
	EnvironmentProduction  = "production"
	EnvironmentDevelopment = "development"

	SameSiteStrict = "strict"
	SameSiteLax    = "lax"
	SameSiteNone   = "none"

	SessionCheckOnAllCalls = "allcalls"
	SessionCheckOnRefresh  = "refresh"
	SessionCheckOnNone     = "none"

	EmailVerificationNone   = "none"
	EmailVerificationLazy   = "lazy"
	EmailVerificationStrict = "strict"

	// The oauth.provisioning.onEmailMatch modes, spelled as the imported core
	// spells them (auth.OAuthEmailMatchLink and friends).
	OAuthEmailMatchLink     = "link"
	OAuthEmailMatchConflict = "conflict"
	OAuthEmailMatchReject   = "reject"

	AdminAccessPolicyFirstUser  = "first-user"
	AdminAccessPolicyIsAdmin    = "is-admin-flag"
	AdminAccessPolicyOpen       = "open"
	AdminAccessPolicyRBACPrefix = "rbac:"
	AdminAccessPolicyPermPrefix = "permission:"

	ToolsAuthNone    = "none"
	ToolsAuthSession = "session"
	ToolsAuthAPIKey  = "apiKey"
	ToolsAuthAdmin   = "admin"

	DistributorNone  = "none"
	DistributorRedis = "redis"
	DistributorSNS   = "sns"

	RateLimitKeyByIP    = "ip"
	RateLimitKeyByEmail = "email"

	StoreDriverDynamoDB = "dynamodb"
	StoreDriverPostgres = "postgres"
	StoreDriverMemory   = "memory"

	// The stores.migration.source vocabulary. One entry, and an enum rather than
	// a boolean so the second source can be added rather than swapped in.
	MigrationSourceCognito = "cognito"

	// The stores.migration.mode vocabulary. See Migration.Mode.
	MigrationModeImportOnly = "import-only"
	MigrationModeDualRead   = "dual-read"

	SwaggerTrue  = "true"
	SwaggerFalse = "false"
	SwaggerAuto  = "auto"
)

// IsProduction reports whether the deployment declared itself production, which
// is what the "in production" qualifier of RS-4 and RS-12 keys off.
func (c *Config) IsProduction() bool {
	return c.Deployment.Environment == EnvironmentProduction
}

// RedirectOrigins is the deployment's redirect allowlist: every email.siteUrls
// entry followed by every http.cors.origins entry, deduplicated with the first
// occurrence's position kept — the reference's
// [...new Set([...siteUrls, ...corsOrigins])] (buildAllowedOrigins,
// src/router/auth.router.ts:213-219).
//
// One list, two consumers, which is why it lives here rather than in whichever
// of them needed it first: it is the allowlist an emailed link's per-request
// origin is matched against, and the allowlist an OAuth callback's state origin
// has to be in to be redirected to. RS-11 refuses a configured OAuth provider
// when it is empty, and cmd/auth hands the same list to the core, so an emailed
// link and an OAuth redirect cannot disagree about a request's origin.
//
// Entries are returned exactly as written: the core matches a request's Origin
// against them with an exact comparison, as the reference's includes does.
func (c *Config) RedirectOrigins() []string {
	var out []string
	seen := make(map[string]struct{}, len(c.Email.SiteURLs)+len(c.HTTP.CORS.Origins))
	for _, list := range [][]string{c.Email.SiteURLs, c.HTTP.CORS.Origins} {
		for _, origin := range list {
			if origin == "" {
				continue
			}
			if _, dup := seen[origin]; dup {
				continue
			}
			seen[origin] = struct{}{}
			out = append(out, origin)
		}
	}
	return out
}

// IDProviderActive reports whether identity-provider mode is on, by the same
// predicate RS-4 and the phase table use. Exported because the composition root
// decides whether to build a signer, an authorization-code store and the OIDC
// endpoints from it, and a second definition of "is the IdP on" in cmd/auth
// could drift away from the rule that refuses a keyless production deployment.
func (c *Config) IDProviderActive() bool { return c.IDProvider.active() }

// CookieDeliveryActive reports whether the stack issues auth cookies at all.
// Bearer versus cookie is a per-request client choice (X-Auth-Strategy), so the
// only configuration that switches the auth-flow cookies off entirely is
// resource-server mode, where those routes are not mounted.
//
// The admin surface is a second, independent cookie issuer: its login sets a
// session cookie of its own (src/router/admin.router.ts:591-611), and it is the
// most privileged surface in the deployment. Resource-server mode therefore does
// not exempt a stack that also deploys admin from RS-2 or RS-3 — those two rules
// exist to protect exactly this cookie.
func (c *Config) CookieDeliveryActive() bool {
	return !c.ResourceServer.Enabled || c.Admin.Enabled
}

// adminGuardVerifiesTokens reports whether the deployed admin surface has to
// verify an access token to authenticate anyone. The guard reuses
// security.jwt.accessTokenSecret (spec §1.13 folds AdminOptions.jwtSecret into
// it), so this is the condition under which RS-7 — "accessPolicy other than open
// with no usable JWT secret" — needs the secret to exist. The reference never
// throws here; the guard simply authenticates nobody
// (src/router/admin.router.ts:274-305).
func (c *Config) adminGuardVerifiesTokens() bool {
	return c.Admin.Enabled && c.Admin.AccessPolicy != AdminAccessPolicyOpen
}

// SecretValue returns the resolved plaintext for a secret-valued knob,
// identified by its dotted path (e.g. "security.jwt.accessTokenSecret"). It
// returns the empty string for a knob that was never configured.
//
// Values live here rather than in the Config tree so that printing or
// marshalling a Config cannot leak them.
func (c *Config) SecretValue(path string) string {
	return c.secrets[path].value
}

// SecretSource names the store a secret came from ("secretsmanager", "ssm",
// "env"), or the empty string when the knob was never configured. Diagnostics
// use it, and so does the production warning about secrets served from a plain
// environment variable.
func (c *Config) SecretSource(path string) string {
	return c.secrets[path].source
}

// secretFailed reports that a knob's secret reference was read and the read
// failed, as opposed to the knob never having been configured. The rules use it
// to avoid reporting "the secret is missing" on top of "the read was denied".
func (c *Config) secretFailed(path string) bool {
	return c.secrets[path].failed
}

// AccessTokenSecret is a convenience accessor for the knob every request path
// needs.
func (c *Config) AccessTokenSecret() string {
	return c.SecretValue("security.jwt.accessTokenSecret")
}

// RefreshTokenSecret is a convenience accessor for the refresh signing secret.
func (c *Config) RefreshTokenSecret() string {
	return c.SecretValue("security.jwt.refreshTokenSecret")
}

// Source reports where the value at a dotted path came from: SourceDefault, the
// document, or the name of the AWESOME_AUTH_* variable that overrode it.
func (c *Config) Source(path string) string {
	if s, ok := c.sources[path]; ok {
		return s
	}
	return SourceDefault
}

// Warnings returns the non-fatal deploy-time diagnostics collected during Load,
// in a stable order. They are things the operator should see in the deployment
// log but that do not justify refusing to start.
func (c *Config) Warnings() []Diagnostic {
	out := make([]Diagnostic, len(c.warnings))
	copy(out, c.warnings)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (c *Config) warn(path, problem, remedy string) {
	c.warnings = append(c.warnings, Diagnostic{
		Severity: SeverityWarning,
		Path:     path,
		Source:   c.Source(path),
		Problem:  problem,
		Remedy:   remedy,
	})
}

// String redacts the whole tree. Config carries no plaintext secrets, but it
// does carry secret store references and a URL surface that has no business in
// a log line by accident.
func (c *Config) String() string {
	return fmt.Sprintf("config.Config{schemaVersion:%d environment:%s driver:%s}",
		c.SchemaVersion, c.Deployment.Environment, c.Stores.Driver)
}

// normalizeEnum lowercases and trims an enum value so that "Lax" and " lax "
// are accepted. Enum values are operator-typed, and a case mismatch is not a
// misconfiguration worth a failed deploy.
func normalizeEnum(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
