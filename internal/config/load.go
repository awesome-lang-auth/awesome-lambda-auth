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
	StoreDriverDynamoDB: {ListUsers: true, MigrationMarker: true},
	StoreDriverPostgres: {ListUsers: true},
	StoreDriverMemory:   {ListUsers: true},
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
	if normalizeEnum(cfg.Tools.Auth) == ToolsAuthNone || cfg.Tools.Auth == "" {
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
