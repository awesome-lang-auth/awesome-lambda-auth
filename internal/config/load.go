package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
)

// Options controls one Load pass.
type Options struct {
	// Document is the decoded configuration document. A nil Document means
	// "configure entirely from defaults and the environment", which is how a
	// minimal development stack and most tests run.
	Document Document

	// Getenv defaults to os.LookupEnv. Injected so that a Load can be tested,
	// and so the deployment tooling can validate a template's environment block
	// without exporting it.
	Getenv func(string) (string, bool)

	// Secrets are the stores consulted for secret-valued knobs. A zero value
	// wires only the environment resolver (over Getenv) and leaves Secrets
	// Manager and SSM as UnavailableResolver, so a document that references them
	// fails with an actionable message rather than an empty signing key.
	Secrets Resolvers

	// Capabilities reports what a store driver can do. It exists for RS-10,
	// which depends on whether the selected driver implements a user listing.
	// nil selects the built-in table.
	Capabilities func(driver string) StoreCapabilities

	// AllowUnimplemented downgrades "configured but not wired in this phase"
	// from a refusal to a warning. It is for tests that need to exercise a later
	// phase's validation, and for a staged rollout where the operator has
	// accepted that a block is inert; it is not a general escape hatch, and it
	// does not affect any §2 rule.
	AllowUnimplemented bool
}

// StoreCapabilities describes what the selected store driver implements. It is
// supplied by the store layer at wiring time, because that layer owns the truth;
// the built-in table here is only a default so that Load works standalone.
type StoreCapabilities struct {
	// ListUsers reports whether the driver can enumerate users, which
	// admin.accessPolicy: first-user requires (RS-10).
	ListUsers bool

	// MigrationMarker reports whether the driver can persist, read back and
	// clear the migration marker stores.migration keys on (RS-13).
	//
	// It is a capability rather than a driver comparison for the same reason
	// ListUsers is: the truth about what a driver implements belongs to the
	// store layer, and a rule written as `driver != "dynamodb"` would have to be
	// found and edited the day a second driver grows the marker.
	MigrationMarker bool

	// RevokeUserSessions reports whether the driver's session store can end
	// every session of an account at once, including the ones its listing
	// would miss — the contract of the core's UserSessionRevoker: every
	// session whose creation had returned when the call began.
	// sessions.revokeOnPasswordReset needs it (checkSessionRevocation).
	//
	// A capability for the reason MigrationMarker is one. A store whose
	// listing is complete and consistent has it without the interface — the
	// core's MemorySessionStore, whose listing the core revokes one by one —
	// and a store whose listing is capped, or read from an eventually
	// consistent index, has it only once it implements the interface: the
	// listing path would fail every reset of an account over the cap with
	// nothing revoked, and could miss a session opened just before the reset.
	RevokeUserSessions bool
}

// builtinCapabilities is the P1 capability table. It is a var, not a const map,
// so the store packages can register themselves as they land without this file
// growing a dependency on them.
var builtinCapabilities = map[string]StoreCapabilities{
	// Only the DynamoDB driver carries the migration marker. The marker is a
	// profile attribute (internal/store/dynamodb/users.go) and there is nowhere
	// else in this build that it survives a cold start: the memory driver's
	// store is per execution environment, so an imported row written by
	// cmd/migrate would simply not be there, and the postgres driver is a
	// declared driver with no implementation behind it.
	//
	// The DynamoDB driver lists an account's sessions from GSI1, which is
	// eventually consistent, and refuses past its MaxSessionsPerUser (1000 by
	// default) — so it revokes on a password reset through
	// auth.UserSessionRevoker instead: one raise of the account's session
	// epoch, honoured wherever a session is read
	// (internal/store/dynamodb/session_epoch.go). The memory driver's session
	// store is the core's MemorySessionStore, whose listing is complete.
	StoreDriverDynamoDB: {ListUsers: true, MigrationMarker: true, RevokeUserSessions: true},
	StoreDriverPostgres: {ListUsers: true},
	StoreDriverMemory:   {ListUsers: true, RevokeUserSessions: true},
}

// ParseJSON decodes a JSON configuration document.
//
// It is the only decoder this package ships. §4 of the spec leaves the format
// open, so a YAML file or an SSM parameter tree plugs in by producing a Document
// and calling Load directly; this keeps the format decision out of the loader.
// Numbers decode as json.Number so that a large millisecond value cannot lose
// precision through float64 on its way into an int knob.
func ParseJSON(data []byte) (Document, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("config: parse configuration document: %w", err)
	}
	if doc == nil {
		// A document of "null" decodes to a nil map, and Load reads a nil Document
		// as "there is no document" — so the schemaVersion gate and every key the
		// operator wrote would be skipped in silence. A shipped document that says
		// nothing has to fail instead.
		return nil, fmt.Errorf("config: parse configuration document: the document is null; it must be an object with at least a schemaVersion")
	}
	return doc, nil
}

// Load layers defaults, the document and the environment, resolves secrets,
// validates everything and evaluates the refuse-to-start rules of spec §2.
//
// The returned error, when non-nil, is always a *ValidationError carrying every
// problem found, each naming its knob by dotted path. A non-nil *Config is never
// returned alongside an error: a half-valid configuration is exactly what this
// package exists to prevent from reaching a request.
func Load(ctx context.Context, opts Options) (*Config, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.LookupEnv
	}

	cfg := Defaults()
	cfg.sources = make(map[string]string)
	d := &diagnostics{cfg: cfg}

	// 1. schemaVersion, before anything else is trusted. A document written for
	// a different major version may mean something different by the very keys
	// this build is about to read.
	if opts.Document != nil {
		checkSchemaVersion(opts.Document, d)
	}

	// 2. the document, over the defaults.
	if opts.Document != nil {
		applyDocument(cfg, opts.Document, d)
	}

	// 3. the environment, over the document.
	applyEnv(cfg, getenv, d)

	// 4. derived values that depend on the layered result.
	derive(cfg)

	// 5. secrets. RS-1 needs the actual value's length, so this happens before
	// the rules and after both override layers.
	resolveSecrets(ctx, cfg, defaultedResolvers(opts.Secrets, getenv), getenv, d)

	// 6. types, ranges and enums, then the §2 rules, then the phase gaps. All
	// three run unconditionally: an operator fixing a broken deploy wants the
	// whole list, and suppressing later checks because an earlier one failed
	// turns one bad deploy into four.
	validate(cfg, d)
	checkRules(cfg, capabilitiesFor(opts), d)
	checkPhaseGaps(cfg, opts.AllowUnimplemented, d)

	collectWarnings(cfg)

	if err := d.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultedResolvers wires the environment resolver over the injected Getenv and
// leaves the two AWS-backed stores explicitly unavailable. Explicitly
// unavailable matters: a nil resolver plus a reference to it would otherwise be
// indistinguishable from "not configured", and the deployment would come up with
// no signing secret.
func defaultedResolvers(r Resolvers, getenv func(string) (string, bool)) Resolvers {
	if r.Env == nil {
		r.Env = EnvSecretResolver{Lookup: getenv}
	}
	if r.SecretsManager == nil {
		r.SecretsManager = UnavailableResolver{
			StoreName: ResolverSecretsManager,
			Reason:    "this build has no Secrets Manager resolver wired; inject one from internal/integration/aws",
		}
	}
	if r.SSM == nil {
		r.SSM = UnavailableResolver{
			StoreName: ResolverSSM,
			Reason:    "this build has no SSM resolver wired; inject one from internal/integration/aws",
		}
	}
	return r
}

func capabilitiesFor(opts Options) func(string) StoreCapabilities {
	if opts.Capabilities != nil {
		return opts.Capabilities
	}
	return func(driver string) StoreCapabilities { return builtinCapabilities[driver] }
}

// checkSchemaVersion requires the root schemaVersion and rejects a major version
// this build does not know. Rejecting is the point: a document that migrates
// cleanly or fails loudly is the same discipline the wire contract uses, and
// silently reinterpreting an old document is the failure mode being designed out.
func checkSchemaVersion(doc Document, d *diagnostics) {
	raw, present := doc["schemaVersion"]
	if !present {
		d.errf(RuleSchemaVersion, "schemaVersion",
			"the configuration document has no schemaVersion at its root",
			fmt.Sprintf("add \"schemaVersion: %d\" as a top-level key", CurrentSchemaVersion))
		return
	}
	v, ok := asInt(raw)
	if !ok {
		d.errf(RuleSchemaVersion, "schemaVersion",
			fmt.Sprintf("schemaVersion must be an integer, got %v", raw),
			fmt.Sprintf("set it to %d", CurrentSchemaVersion))
		return
	}
	if v != CurrentSchemaVersion {
		d.errf(RuleSchemaVersion, "schemaVersion",
			fmt.Sprintf("schemaVersion %d is not understood by this build, which reads version %d", v, CurrentSchemaVersion),
			fmt.Sprintf("migrate the document to version %d, or deploy a build that reads version %d", CurrentSchemaVersion, v))
	}
}

// applyDocument maps the document onto the Config that already holds the
// defaults, so an absent key keeps its default and a present one wins.
//
// The document is re-marshalled to JSON and decoded into the struct rather than
// walked by hand: encoding/json's "leave absent fields untouched" behaviour *is*
// the layering rule, and one round trip through it is cheaper than a hundred
// hand-written merges that each get to have their own bug. Unknown keys are
// detected separately, against the struct's tags, because the decoder's own
// error would name the field without its path.
func applyDocument(cfg *Config, doc Document, d *diagnostics) {
	// Both walkers below type-assert to map[string]any, and Document is a named
	// type: passing it directly would fail the assertion and silently skip the
	// whole document.
	root := map[string]any(doc)
	flattenDocument(root, "", cfg.sources)
	checkUnknownKeys(root, reflect.TypeOf(Config{}), "", d)

	raw, err := json.Marshal(doc)
	if err != nil {
		d.errf("", "",
			"the configuration document could not be re-encoded: "+err.Error(),
			"the document must contain only strings, numbers, booleans, nulls, arrays and objects")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(cfg); err != nil {
		d.errf("", "",
			"the configuration document does not match the schema: "+err.Error(),
			"check the type of the reported key against docs/spec/config-schema.md")
	}
}

// flattenDocument records the dotted path of every leaf in the document, so a
// diagnostic can distinguish a value the operator wrote from an inherited
// default. Container nodes are recorded too, because a map-valued knob such as
// security.jwt.extraClaims is itself the leaf as far as the operator is
// concerned.
func flattenDocument(node any, prefix string, out map[string]string) {
	m, ok := node.(map[string]any)
	if !ok {
		if prefix != "" {
			out[prefix] = SourceDocument
		}
		return
	}
	if prefix != "" {
		out[prefix] = SourceDocument
	}
	for k, v := range m {
		child := k
		if prefix != "" {
			child = prefix + "." + k
		}
		flattenDocument(v, child, out)
	}
}

// checkUnknownKeys walks the document against the struct tags and reports every
// key the schema does not define, with its dotted path.
//
// A typo in a security knob is the most dangerous kind of configuration error,
// because "csrf: {enabled: false}" misspelled as "csfr" leaves CSRF at its
// default and passes every other check. Naming the path is the difference
// between a five-second fix and an incident.
func checkUnknownKeys(node any, rt reflect.Type, prefix string, d *diagnostics) {
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}

	switch rt.Kind() {
	case reflect.Map:
		// An open-ended map (oauth.providers, extraClaims, profileMap): the keys
		// are operator-chosen, so only the value shape can be checked.
		for _, k := range sortedKeys(m) {
			checkUnknownKeys(m[k], rt.Elem(), joinPath(prefix, k), d)
		}
		return
	case reflect.Struct:
		fields := jsonFields(rt)
		for _, k := range sortedKeys(m) {
			ft, known := fields[k]
			if !known {
				d.errf("", joinPath(prefix, k),
					"unknown configuration key",
					"remove it, or correct the spelling against docs/spec/config-schema.md"+nearestHint(k, fields))
				continue
			}
			if isLeafType(ft) {
				continue
			}
			checkUnknownKeys(m[k], ft, joinPath(prefix, k), d)
		}
		return
	default:
		return
	}
}

// jsonFields maps a struct's json names to their types, skipping fields the
// decoder ignores.
func jsonFields(rt reflect.Type) map[string]reflect.Type {
	out := make(map[string]reflect.Type, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" || tag == "" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		out[name] = f.Type
	}
	return out
}

var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// isLeafType reports whether a type owns its own decoding and must not be walked
// into. Secret, Duration and StringList are structs that accept a scalar, so
// descending into them would report their document form as unknown keys.
func isLeafType(rt reflect.Type) bool {
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if reflect.PointerTo(rt).Implements(unmarshalerType) {
		return true
	}
	switch rt.Kind() {
	case reflect.Struct, reflect.Map:
		return false
	default:
		return true
	}
}

// nearestHint suggests a defined sibling key when the unknown one looks like a
// typo of it. Cheap, and it turns most unknown-key reports into a fix rather than
// a search through the schema.
//
// The tolerance scales with the length of the name, because a fixed edit distance
// either misses realistic typos in long camelCase keys ("sameSight" is three
// edits from "sameSite") or suggests nonsense for short ones.
func nearestHint(got string, fields map[string]reflect.Type) string {
	best, bestDist := "", -1
	for _, name := range sortedKeys(fields) {
		dist := editDistance(strings.ToLower(got), strings.ToLower(name))
		if bestDist < 0 || dist < bestDist {
			best, bestDist = name, dist
		}
	}
	if best == "" {
		return ""
	}
	if bestDist > (max(len(got), len(best))+2)/3 {
		return ""
	}
	return " (did you mean " + best + "?)"
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, min(cur[j-1]+1, prev[j-1]+cost))
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// derive fills in the values the reference computes rather than configures.
func derive(cfg *Config) {
	// The reference mutates the refresh cookie path to `${apiPrefix}/refresh` at
	// router construction (src/router/auth.router.ts:461-464), falling back to
	// the literal '/auth/refresh' inside TokenService. Deriving it keeps the
	// cookie's Path scoped to the endpoint that needs it even when the prefix is
	// customised, which the reference's TokenService-level fallback silently gets
	// wrong.
	if cfg.Cookies.RefreshTokenPath == "" {
		cfg.Cookies.RefreshTokenPath = strings.TrimRight(cfg.HTTP.APIPrefix, "/") + "/refresh"
	}

	// docs.basePath defaults to the resolved api prefix, not to the literal
	// '/auth' the doc comment claims (src/router/auth.router.ts:1657).
	if cfg.Docs.BasePath == "" {
		cfg.Docs.BasePath = cfg.HTTP.APIPrefix
	}

	// Enum values are operator-typed; normalise before anything compares them.
	cfg.Deployment.Environment = normalizeEnum(cfg.Deployment.Environment)
	cfg.Cookies.SameSite = normalizeEnum(cfg.Cookies.SameSite)
	cfg.Sessions.CheckOn = normalizeEnum(cfg.Sessions.CheckOn)
	cfg.Email.Verification.Mode = normalizeEnum(cfg.Email.Verification.Mode)
	cfg.Email.Mailer.DefaultLang = normalizeEnum(cfg.Email.Mailer.DefaultLang)
	cfg.Stores.Driver = normalizeEnum(cfg.Stores.Driver)
	cfg.OAuth.Provisioning.OnEmailMatch = normalizeEnum(cfg.OAuth.Provisioning.OnEmailMatch)
	cfg.Tools.Auth = strings.TrimSpace(cfg.Tools.Auth)
	cfg.Tools.SSE.Distributor.Type = normalizeEnum(cfg.Tools.SSE.Distributor.Type)
	cfg.RateLimit.KeyBy = normalizeEnum(cfg.RateLimit.KeyBy)
	cfg.Docs.Swagger = normalizeEnum(cfg.Docs.Swagger)
	cfg.Admin.AccessPolicy = strings.TrimSpace(cfg.Admin.AccessPolicy)

	// The reference's sessions.checkOn is effectively 'refresh' when unset,
	// because the middleware only acts on the literal 'allcalls'
	// (src/middleware/auth.middleware.ts:47). Make that explicit rather than
	// leaving an empty string for every downstream comparison to re-derive.
	if cfg.Sessions.CheckOn == "" {
		cfg.Sessions.CheckOn = SessionCheckOnRefresh
	}

	// A document that writes oauth.provisioning.onEmailMatch: "" is asking for
	// the default rather than for an empty mode, exactly as an absent key is —
	// the core normalises the same way (OAuthProvisioning.normalized). Doing it
	// here means the enum check below never has to special-case the empty
	// string, and every consumer reads a real mode.
	if cfg.OAuth.Provisioning.OnEmailMatch == "" {
		cfg.OAuth.Provisioning.OnEmailMatch = OAuthEmailMatchLink
	}

	// The origin check's two strings are compared, not typed at, so a stray
	// space from a hand-edited template must not become part of a header name
	// or of an ARN. An empty header asks for the default, as an empty
	// onEmailMatch does; validateOriginVerify still sees that it was written.
	cfg.HTTP.OriginVerify.SecretARN = strings.TrimSpace(cfg.HTTP.OriginVerify.SecretARN)
	cfg.HTTP.OriginVerify.Header = strings.TrimSpace(cfg.HTTP.OriginVerify.Header)
	if cfg.HTTP.OriginVerify.Header == "" {
		cfg.HTTP.OriginVerify.Header = DefaultOriginVerifyHeader
	}

	// An email.languages entry is handed to the sender exactly as written
	// whenever a request's emailLang matches it, so a stray space from a
	// hand-edited document must not become part of the language a receiver is
	// told to render — nor make the core refuse to start, which it would: a
	// space is not part of a language tag. The variable's entries arrive
	// trimmed already (envList). Case is left alone, for the same reason the
	// core leaves it: the entry as configured is what reaches the sender.
	for i, lang := range cfg.Email.Languages {
		cfg.Email.Languages[i] = strings.TrimSpace(lang)
	}
}

// collectWarnings records the deploy-time warnings the spec asks for: things an
// operator should read in the deployment log but that do not justify refusing to
// start.
func collectWarnings(cfg *Config) {
	// The issuer is derivable: cmd/auth falls back to deployment.publicUrl, else
	// the canonical site URL, plus the api prefix (idpIssuer, cmd/auth/idp.go).
	// So the warning is about having nothing to derive it from, not about the
	// knob being unset — warning on the knob alone would fire on every
	// single-host deployment, which is the configuration that needs no issuer
	// written out at all.
	if cfg.IDProvider.active() && cfg.IDProvider.Issuer == "" &&
		strings.TrimSpace(cfg.Deployment.PublicURL) == "" && len(cfg.Email.SiteURLs) == 0 {
		cfg.warn("idProvider.issuer",
			"identity-provider mode is active with no issuer and nothing to derive one from, so minted tokens carry no iss claim and the discovery document points at no host",
			"set idProvider.issuer to the public https URL this deployment is reached at, including the api prefix, or set deployment.publicUrl")
	}
	if cfg.ResourceServer.Enabled && cfg.ResourceServer.Issuer == "" {
		cfg.warn("resourceServer.issuer",
			"resource-server mode is on with no expected issuer, so the iss claim is not validated",
			"set resourceServer.issuer to the issuer your identity provider mints")
	}
	// Only for the literal, and only with the block on. An unset tools.auth used
	// to be read as `none` here, which was harmless while the phase gate refused
	// the whole block and became the open door by omission the day it did not;
	// validateTools now refuses it under tools.enabled, so the one way to reach
	// this warning is to have written the word. With the block off no tools
	// endpoint exists, and a warning about one on every cold start of every
	// deployment taught operators to read past this line.
	if cfg.Tools.Enabled && normalizeEnum(cfg.Tools.Auth) == ToolsAuthNone {
		cfg.warn("tools.auth",
			"the tools endpoints are unauthenticated, reproducing the reference's default",
			"set tools.auth to session, apiKey or admin unless the endpoints are deliberately public")
	}
	// The open console. Not refused, because it is the reference's own default
	// and a stack really can sit behind a network boundary this loader cannot
	// see; but every front door the SAM template offers is internet-facing, so
	// the operator hears it here, where the deployment tooling reads before an
	// upload, and again at cold start (cmd/auth/admin.go logAdminSurface, at
	// Warn). The template no longer offers `open` as a parameter value at all.
	if cfg.Admin.Enabled && cfg.Admin.AccessPolicy == AdminAccessPolicyOpen {
		cfg.warn("admin.accessPolicy",
			"the admin console admits every request with no credential at all -- the user listing, the API-key and webhook-secret routes and promote included -- which is the reference's default and is only for a stack nobody outside your network can reach",
			"set admin.accessPolicy: is-admin-flag and get in with admin.rootUser, or accept this on a stack behind a network boundary of your own")
	}
	// tools.auth: admin behind that open console is `none` by another name: the
	// console's guard admits every request without reading a credential (core
	// admin.go, authorise), and the tools routes are behind that guard. The
	// literal `none` gets its warning above; this spelling of the same door
	// gets one too, naming the routes, so that it is not quieter for having
	// been written as a guard.
	if cfg.Tools.Enabled && normalizeEnum(cfg.Tools.Auth) == ToolsAuthAdmin &&
		cfg.Admin.Enabled && cfg.Admin.AccessPolicy == AdminAccessPolicyOpen {
		cfg.warn("tools.auth",
			"tools.auth is admin and admin.accessPolicy is open, so the tools endpoints -- track, notify and the store-wide telemetry query -- are unauthenticated exactly as under tools.auth: none",
			"set admin.accessPolicy: is-admin-flag, or tools.auth to session or apiKey, unless the endpoints are deliberately public")
	}
	// The session posture with cross-site cookies. The tools router sits
	// outside the auth router's CSRF chain — the core mounts it bare — and the
	// product's session guard performs the reference's double-submit for a
	// cookie caller in its place (cmd/auth/tools.go, toolsDoubleSubmit), so a
	// cross-site page cannot drive POST <tools>/track on a victim's cookie even
	// with SameSite=None. What SameSite=None does change is what a *legitimate*
	// cross-site front end has to do: it cannot read the csrf-token cookie of
	// another site, so it has to call the tools routes with the bearer token
	// rather than the cookie. A warning and not a refusal, because that is a
	// working configuration; RS-5 already refuses the half that is not.
	if cfg.Tools.Enabled && normalizeEnum(cfg.Tools.Auth) == ToolsAuthSession &&
		normalizeEnum(cfg.Cookies.SameSite) == SameSiteNone {
		cfg.warn("tools.auth",
			"tools.auth is session and cookies.sameSite is none, so the access-token cookie is sent to the tools routes from any site; a cookie-authenticated POST there still needs the X-CSRF-Token double-submit, which a page on another site cannot supply",
			"call the tools routes with the bearer access token from a cross-site front end, or choose tools.auth: apiKey")
	}
	if cfg.IsProduction() {
		for _, path := range sortedKeys(cfg.secrets) {
			resolved := cfg.secrets[path]
			if resolved.source != ResolverEnv || resolved.failed || resolved.value == "" {
				continue
			}
			cfg.warn(path,
				"a production secret is being read from a plain environment variable, which is visible to anyone who can describe the function",
				"move it to Secrets Manager or an SSM SecureString and reference it from the document")
		}
	}
	// The Swagger page served on purpose in production. It is not refused, and
	// cmd/auth/docs.go argues why at length: the core's DocsOptions.Enabled is
	// one switch for the page and for the machine-readable document, the product
	// may not mount either route itself, and a refusal aimed at the page would
	// take the document with it. What is left is to make sure the operator knows
	// what they asked for — here rather than only in the cold-start log, because
	// this is what the deployment tooling reads before an upload.
	//
	// Only the explicit "true" warns. "auto" is off in production by definition,
	// and it is the default, so silence never reaches this.
	if cfg.IsProduction() && cfg.Docs.Swagger == SwaggerTrue {
		cfg.warn("docs.swagger",
			"the Swagger UI page is served in production, and it loads swagger-ui-dist@5 from the unpkg CDN with no subresource integrity, "+
				"so whatever that CDN serves executes on the auth origin with the cookies -- the CSRF cookie included, which is readable from JavaScript by design",
			"set docs.swagger: auto to serve both documentation routes outside production and neither in it; "+
				"keep true only if the third-party script on the auth origin is a risk you are taking deliberately -- the deployment answers both routes behind a Content-Security-Policy that confines it, which narrows the exposure and does not remove it")
	}
	if cfg.Cookies.Domain != "" && cfg.Cookies.Secure {
		cfg.warn("cookies.domain",
			"setting a cookie domain forfeits the __Host- prefix, so cookies fall back to __Secure-",
			"leave cookies.domain unset unless subdomains genuinely need to share the session")
	}
	collectForgotPasswordWarnings(cfg)
	collectSessionRevocationWarnings(cfg)
	collectRealmWarnings(cfg)
}

// collectSessionRevocationWarnings says what sessions.revokeOnPasswordReset
// leaves alive under a sessions.checkOn that reads no session on a protected
// request. The revocation ends the refresh tokens at once; an access token
// already issued is refused at once only under allcalls, and under refresh or
// none it is honoured until it expires. Not refused: a short access-token
// lifetime is an answer too, and it is the operator's to size.
//
// A resource server mounts no /reset-password, and cmd/auth reports the key as
// unwired there (resourceServerCredentialKnobGaps); a warning about what the
// reset leaves alive would contradict that report.
func collectSessionRevocationWarnings(cfg *Config) {
	if !cfg.Sessions.RevokeOnPasswordReset || cfg.ResourceServer.Enabled || cfg.Sessions.CheckOn == SessionCheckOnAllCalls {
		return
	}
	cfg.warn("sessions.revokeOnPasswordReset",
		fmt.Sprintf("a password reset revokes the account's sessions, but under sessions.checkOn %q no protected request reads its session, "+
			"so an access token issued before the reset keeps working until it expires (security.jwt.accessTokenTtl, %s)",
			cfg.Sessions.CheckOn, cfg.Security.JWT.AccessTokenTTL),
		"set sessions.checkOn: allcalls so a revoked session's access tokens are refused at once, or shorten security.jwt.accessTokenTtl to the window you accept after a reset; "+
			"an access token on the admin console is honoured until it expires under every checkOn")
}

// collectForgotPasswordWarnings says what security.forgotPassword.minResponseMs
// costs and how much of the difference it hides. Neither is refused: the cost
// is the price of the floor and the coverage is the operator's to size, and
// both depend on things the loader cannot see — the traffic, the function's
// Timeout, what sits in front of the route.
func collectForgotPasswordWarnings(cfg *Config) {
	floor := cfg.Security.ForgotPassword.MinResponseMs
	// A resource server mounts no /forgot-password: cmd/auth reports the key
	// as unwired there (resourceServerCredentialKnobGaps), and that report is
	// the only thing to say about it.
	if floor <= 0 || cfg.ResourceServer.Enabled {
		return
	}
	const path = "security.forgotPassword.minResponseMs"

	// What it costs, whenever it is on: the same sentence the enrolment
	// warning makes about trust, made here about money and capacity.
	cfg.warn(path,
		fmt.Sprintf("every POST <prefix>/forgot-password is held at least %d ms inside its Lambda invocation, which bills the time and keeps an execution environment for it: "+
			"the route needs its request rate times the floor in concurrency, and the rateLimit budget does not bound that -- it counts per address, and a caller naming a new address each time is held every time",
			floor),
		"put a per-client limit in front of the route (a WAF rate-based rule) or a ceiling on the function (ReservedConcurrentExecutions), "+
			"and keep the floor well below the function's Timeout and DurationAlarmThresholdMs; the core ends the hold 100 ms before the invocation's deadline")

	// How much of the difference it hides: the slow branch is the lookup, the
	// delivery and the token write, and the delivery is what a floor has to
	// outlast. The webhook has a deadline of its own; SES does not.
	switch {
	case cfg.DeliveryWebhookConfigured():
		timeout := cfg.Email.DeliveryWebhook.TimeoutMs
		if floor >= timeout+forgotPasswordFloorAllowanceMs {
			return
		}
		// Raising the floor is offered only where the ceiling allows it: at the
		// webhook's default timeout (5000 ms) the floor it would need is above
		// MaxForgotPasswordMinResponseMs, and the one remedy left is the
		// timeout.
		var remedies []string
		if need := timeout + forgotPasswordFloorAllowanceMs; need <= MaxForgotPasswordMinResponseMs {
			remedies = append(remedies, fmt.Sprintf("raise the floor to at least %d ms", need))
		}
		if lower := floor - forgotPasswordFloorAllowanceMs; lower > 0 {
			remedies = append(remedies, fmt.Sprintf("lower email.deliveryWebhook.timeoutMs to at most %d ms", lower))
		}
		remedy := strings.Join(remedies, ", or ")
		if remedy == "" {
			remedy = fmt.Sprintf("lower email.deliveryWebhook.timeoutMs and raise the floor until the floor exceeds the timeout by about %d ms, within the ceiling of %d ms",
				forgotPasswordFloorAllowanceMs, MaxForgotPasswordMinResponseMs)
		}
		cfg.warn(path,
			fmt.Sprintf("the floor of %d ms is below email.deliveryWebhook.timeoutMs (%d ms) plus about %d ms for the account lookup and the token write, "+
				"so a delivery that runs toward its timeout is answered later than an unknown address is, and the time tells the two apart again",
				floor, timeout, forgotPasswordFloorAllowanceMs),
			remedy+"; the floor hides the difference only above the slow branch's worst case")
	case cfg.MailerConfigured():
		cfg.warn(path,
			"the reset mail goes out through Amazon SES, whose call has no deadline of its own here, only the invocation's: "+
				"a send that takes longer than the floor -- a slow SES answer, a retried request -- is answered later than an unknown address is, and the time shows it",
			"keep the floor comfortably above the SES latency this deployment sees, or deliver through email.deliveryWebhook, whose timeoutMs bounds the send and which the floor can then be sized against")
	}
}

// collectRealmWarnings says what the realm knobs do where they meet a surface
// that does not follow them. None of these is refused: each is a posture an
// operator can choose deliberately, and each is the kind a document can
// express without the operator noticing — so it is said here, where the
// deployment tooling reads before an upload, and again in the cold-start log.
//
// What twoFactor.required cannot be allowed to miss is not here: the OAuth
// callback, the two console credentials and an open console are refused
// (RS-20), and the passwordless routes, loginAfterLinking and
// POST <admin>/login are held to the policy at request time (cmd/auth
// secondFactorGate). What is here is what the policy changes about a
// transport the operator wired, because that is a change in what a
// configured block does, and it is said rather than discovered.
func collectRealmWarnings(cfg *Config) {
	// A closed realm whose OAuth callback still creates accounts, narrowed to
	// named domains and to addresses the provider verified. RS-19 refuses
	// every looser shape; this one is the "sign in with your company account"
	// realm, and it is a sign-up path all the same, exactly as strong as the
	// provider's verification of an address at those domains.
	p := cfg.OAuth.Provisioning
	if cfg.Registration.Closed && len(cfg.OAuth.Providers) > 0 && p.AutoCreate && len(p.AllowedEmailDomains) > 0 && p.RequireVerifiedEmail {
		cfg.warn("oauth.provisioning.allowedEmailDomains",
			fmt.Sprintf("registration.closed is on and the OAuth callback still creates an account for any identity at %s that no account holds yet and the provider reports as verified, "+
				"so anyone the provider will vouch for at those domains signs up through it -- the list is only as strong as the provider's own verification of an address",
				strings.Join(p.AllowedEmailDomains, ", ")),
			"keep it if that is the realm you mean, with a provider that verifies the addresses it asserts at those domains; otherwise set oauth.provisioning.autoCreate: false so the callback signs in only accounts that already exist")
	}

	// The password-reset mail travels by the mailer or by the delivery
	// webhook, and it hands a new password to whoever reads it.
	resetMail := cfg.MailerConfigured() || cfg.DeliveryWebhookConfigured()

	if cfg.Admin.RevealInvitationToken {
		cfg.warn("admin.revealInvitationToken",
			"POST <admin>/api/users/invitations answers the invitation's token and accept URL to its caller; accepting marks the address verified on the strength of the token having reached that mailbox, "+
				"so whoever handles the answer -- the machine principal, its logs, the channel it forwards the URL through -- holds a credential that activates the account",
			"deliver the token only to the invited mailbox, keep it out of logs, and prefer email.mailer or email.deliveryWebhook, which keep the token off the admin API entirely")
	}

	// Invitations under twoFactor.required without forced enrolment. Nothing
	// is refused: an operator can still enrol each invitee out of band once it
	// has accepted, which is the posture the realm without enrolOnLogin
	// already asks of every account. But no invitee can get there alone, and
	// the obvious workaround of enrolling the account first defeats itself,
	// because the core activates only a pending account: no password and no
	// factor (invitation.go, pendingAccount).
	if cfg.Invitations.Enabled && cfg.TwoFactor.Required && !cfg.TwoFactor.EnrolOnLogin {
		cfg.warn("invitations.enabled",
			"invitations are on under twoFactor.required without twoFactor.enrolOnLogin, so no invitee reaches a session alone: accepting spends the token, sets the password and answers 403 2FA_SETUP_REQUIRED "+
				"with a tempToken no route accepts, and every later login answers the same until the account is enrolled out of band; enrolling a factor before the acceptance does not help, "+
				"because the acceptance then spends the token and refuses it -- the core activates only an account with no password and no factor",
			"set twoFactor.enrolOnLogin: true, so the acceptance's tempToken enrols TOTP and opens the session (trust on first use, bounded here by the single-use token in the invited mailbox), "+
				"or enrol each invitee out of band after it has accepted")
	}

	if cfg.TwoFactor.EnrolOnLogin {
		scope := "an account under twoFactor.required"
		if !cfg.TwoFactor.Required {
			scope = "an account whose own require2FA flag is set (twoFactor.required is off)"
		}
		enough := "a leaked invitation or initial password, or the password of an account whose factor an administrator just reset, is enough"
		if resetMail {
			enough = "a leaked invitation or initial password, the password of an account whose factor an administrator just reset, " +
				"or -- with the password-reset mail wired -- the account's mailbox alone, through POST <prefix>/forgot-password and /reset-password, is enough"
		}
		cfg.warn("twoFactor.enrolOnLogin",
			"forced enrolment is trust on first use: when "+scope+" has no factor yet, whoever presents its password binds a factor of their choosing and gets a full session, "+
				"and the owner's next login is a challenge they cannot answer -- "+enough,
			"keep it only where the first sign-in with the password is the owner's by construction, and reset the password together with the factor; enrol out of band and leave it off otherwise")

		// The enrolment window, longer than the core's default. A shorter one
		// narrows every exposure below and says nothing; a longer one widens
		// it for every token minted, and that is what the operator has to hear.
		// Not on a resource server, which mounts no enrolment route and
		// reports the key as unwired (cmd/auth resourceServerCredentialKnobGaps).
		if ttl := cfg.TwoFactor.EnrolmentTokenTTLMinutes; ttl > DefaultEnrolmentTokenTTLMinutes && !cfg.ResourceServer.Enabled {
			cfg.warn("twoFactor.enrolmentTokenTtlMinutes",
				fmt.Sprintf("the enrolment token lives %d minutes rather than the default %d, and the window is the same for whoever holds a copy of the token: "+
					"for an account with no factor the token alone completes the enrolment and opens a session, and a copy that calls POST <prefix>/2fa/setup before the owner enrols with that token "+
					"learns the secret of the factor the owner then enrols, and keeps it after the token has expired",
					ttl, DefaultEnrolmentTokenTTLMinutes),
				"keep it as short as an invitee needs to install an authenticator app; treat a leaked enrolment token as a leaked factor -- change the password, then enrol a new factor in its place")
		}
	}

	// twoFactor.required beside a credential transport. Under the policy a
	// TOTP code is the only second factor: the core would otherwise offer the
	// emailed link as the second step to every challenged account, and the
	// texted code to every one with a number on file, and the same mailbox
	// receives the password-reset link — so a mailbox alone, or a phone
	// number, would answer both steps. cmd/auth therefore does not hand the
	// core the magic-link and SMS-code senders (the challenge lists "totp"
	// alone, and an account without TOTP is told to enrol), and its gate
	// refuses the four passwordless routes in every mode. That changes what
	// the operator's transport does, so it is said here; nothing is refused,
	// because what the transport still carries is wanted.
	if cfg.TwoFactor.Required && (resetMail || cfg.SMSConfigured()) {
		var wired []string
		if cfg.MailerConfigured() {
			wired = append(wired, "a mailer (email.mailer)")
		}
		if cfg.DeliveryWebhookConfigured() {
			wired = append(wired, "the delivery webhook (email.deliveryWebhook)")
		}
		if cfg.SMSConfigured() {
			wired = append(wired, "an SMS transport (sms)")
		}
		carries := "the SMS transport carries no credential at all: its one credential seam is the texted code, so a phone number alone never opens a session"
		if resetMail {
			carries = "the transport still carries the password-reset, email-verification and email-change mails, " +
				"and a reset changes the password and opens no session -- the next login still asks for TOTP -- so a phone number alone never opens one, " +
				"and a mailbox alone only by guessing the account's TOTP code"
			if lockout := cfg.TwoFactor.Lockout; lockout.MaxFailures > 0 {
				carries += fmt.Sprintf(", which twoFactor.lockout holds to %d wrong codes per account per %d seconds", lockout.MaxFailures, lockout.WindowSeconds)
			} else {
				carries += ", which nothing holds per account while twoFactor.lockout.maxFailures is 0: every login mints a new challenge, and the rateLimit budgets count per challenge"
			}
		}
		if resetMail && cfg.TwoFactor.EnrolOnLogin {
			carries += ", except for an account that has not enrolled yet, which twoFactor.enrolOnLogin lets whoever resets its password claim (see that warning)"
		}
		cfg.warn("twoFactor.required",
			fmt.Sprintf("twoFactor.required is on beside %s, and under the policy a TOTP code is the only second factor: "+
				"POST <prefix>/magic-link/send, /magic-link/verify, /sms/send and /sms/verify answer 403 2FA_REQUIRED in every mode, the second step (mode \"2fa\") included, "+
				"the magic-link and SMS-code senders are not handed to the core, so the login challenge offers totp alone and an account without TOTP is answered 2FA_SETUP_REQUIRED; %s",
				strings.Join(wired, " and "), carries),
			"nothing to change if that is the realm you mean; the emailed link or the texted code as a second step lets a mailbox -- which also receives the reset link -- or a phone number stand in for both factors, "+
				"and is available only with twoFactor.required off")
	}

	// The built-in identity provider's POST <prefix>/authorize signs a user in
	// with the core's Service.Login, which has no second-factor step to offer:
	// under the policy it answers ErrTwoFactorRequired for every account, and
	// the endpoint reports that as invalid credentials. It fails closed — no
	// authorization code, so no /token pair — and that is why it is a warning
	// and not a refusal; but no relying party can sign anyone in, and the
	// error a user sees says their password is wrong.
	if cfg.TwoFactor.Required && cfg.IDProviderActive() {
		cfg.warn("twoFactor.required",
			"the identity provider's POST <prefix>/authorize signs users in with a password and has no second-factor step, so under twoFactor.required it refuses every account "+
				"(answered as invalid credentials) and no relying party can complete an OIDC sign-in",
			"run the identity provider on a realm without twoFactor.required, or turn idProvider off on this one")
	}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// asInt reads an integer out of whatever the decoder produced for it:
// json.Number from ParseJSON, float64 from a plain json.Unmarshal, or an int
// from a Document built in Go.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	case float64:
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	default:
		return 0, false
	}
}
