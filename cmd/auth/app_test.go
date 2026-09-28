package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// Secrets long enough for RS-1 (32 characters) and distinct from one another.
const (
	testAccessSecret  = "test-access-secret-0123456789abcdefgh"
	testRefreshSecret = "test-refresh-secret-0123456789abcdefgh"
	testPassword      = "correct-horse-battery-staple"
	testEmail         = "operator@example.test"
)

// baseEnv is the smallest environment that satisfies every refuse-to-start
// rule: development (RS-12 forbids the memory driver in production), a public
// URL on a domain of our own (RS-2 forbids cookie delivery on execute-api), and
// two distinct signing secrets (RS-1).
//
// Plus one knob that is not required and is here for time. Since
// security.password.bcryptSaltRounds became a wired knob, the product default
// of 12 is the cost every test in this package actually hashes at, four times
// the work of 10 — and under -race, with the store suite running beside it, the
// package went from half a minute to over three. The floor of the schema's own
// supported range is used instead, because the cost is orthogonal to everything
// these tests assert and paying for it in every one of them buys nothing.
// TestBcryptCostReachesTheCore is where the knob itself is pinned, at a value
// that is neither this nor the product default so that it cannot pass by
// coincidence.
func baseEnv() map[string]string {
	return map[string]string{
		"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT": "development",
		"AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL":  "https://auth.example.test",
		"AWESOME_AUTH_JWT_ACCESS_SECRET":      testAccessSecret,
		"AWESOME_AUTH_JWT_REFRESH_SECRET":     testRefreshSecret,
		"AWESOME_AUTH_BCRYPT_SALT_ROUNDS":     "10",
	}
}

// envFunc reads from a map instead of the process environment, so the tests
// never mutate global state and stay safe under -race and t.Parallel.
func envFunc(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func with(base map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(base)+len(kv)/2)
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func discardLogger() *slog.Logger { return newLogger(io.Discard, slog.LevelError) }

// memoryStores is the unit-test persistence layer. Most tests in this package
// talk to no store backend at all: the point of the store factory being
// injectable is that the composition can be proved without an account.
//
// It returns the same bundle defaultStoreFactory does for the memory driver, so
// the OAuth stores the core cannot discover by type assertion reach the wiring
// here too — otherwise every test in this file would be exercising a narrower
// composition than the binary builds.
func memoryStores(_ context.Context, _ *config.Config, _ *slog.Logger) (auth.UserStore, auth.SessionStore, error) {
	return newMemoryStoreBundle(), auth.NewMemorySessionStore(), nil
}

func newTestApp(t *testing.T, env map[string]string) *App {
	t.Helper()
	app, err := New(context.Background(), Options{
		Getenv: envFunc(env),
		Logger: discardLogger(),
		Stores: memoryStores,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app
}

// v2Event builds a synthetic API Gateway HTTP API payload format 2.0 event.
//
// A query string may be written inline in path, the way a caller thinks of a URL;
// it is split out into RawQueryString because that is where API Gateway puts it
// and where internal/lambdahttp reads it from. Leaving it in the path would make
// the mux see "/auth/verify-email?token=x" as a path and answer 404.
func v2Event(method, path string, headers map[string]string, cookies []string, body string) json.RawMessage {
	h := map[string]string{"host": "auth.example.test"}
	for k, v := range headers {
		h[strings.ToLower(k)] = v
	}
	path, rawQuery, _ := strings.Cut(path, "?")
	evt := events.APIGatewayV2HTTPRequest{
		Version:        "2.0",
		RouteKey:       "$default",
		RawPath:        path,
		RawQueryString: rawQuery,
		Headers:        h,
		Cookies:        cookies,
		Body:           body,
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			Stage:      "$default",
			DomainName: "auth.example.test",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method:   method,
				Path:     path,
				Protocol: "HTTP/1.1",
				SourceIP: "203.0.113.7",
			},
		},
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		panic(err)
	}
	return raw
}

// invoke drives the app exactly as the Lambda runtime would: a JSON event in,
// a JSON response out.
func invoke(t *testing.T, app *App, method, path string, headers map[string]string, cookies []string, body string) events.APIGatewayV2HTTPResponse {
	t.Helper()
	raw, err := app.Handle(context.Background(), v2Event(method, path, headers, cookies, body))
	if err != nil {
		t.Fatalf("Handle %s %s: %v", method, path, err)
	}
	var resp events.APIGatewayV2HTTPResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

func decodeBody(t *testing.T, resp events.APIGatewayV2HTTPResponse) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &out); err != nil {
		t.Fatalf("unmarshal body %q: %v", resp.Body, err)
	}
	return out
}

func jsonHeaders(extra ...string) map[string]string {
	h := map[string]string{"content-type": "application/json"}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = extra[i+1]
	}
	return h
}

func registerBody(email string) string {
	return fmt.Sprintf(`{"email":%q,"password":%q}`, email, testPassword)
}

// TestValidConfigServesBearerRoundTrip is the composition test: a valid
// configuration must produce a handler that answers a real Lambda event with a
// real auth response, all the way from event normalisation through the imported
// adapter to the store.
func TestValidConfigServesBearerRoundTrip(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())

	resp := invoke(t, app, http.MethodPost, "/auth/register",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, registerBody(testEmail))

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want %d (body %s)", resp.StatusCode, http.StatusCreated, resp.Body)
	}
	body := decodeBody(t, resp)
	if body["success"] != true {
		t.Errorf("register body success = %v, want true", body["success"])
	}
	accessToken, _ := body["accessToken"].(string)
	if accessToken == "" {
		t.Fatalf("register returned no top-level accessToken for a bearer caller: %s", resp.Body)
	}
	if body["refreshToken"] == nil {
		t.Errorf("register returned no top-level refreshToken for a bearer caller")
	}
	// A bearer caller must get no cookies at all, or a browser would end up
	// holding credentials the client never asked it to hold.
	if len(resp.Cookies) != 0 {
		t.Errorf("bearer register set %d cookies, want 0: %v", len(resp.Cookies), resp.Cookies)
	}

	me := invoke(t, app, http.MethodGet, "/auth/me",
		map[string]string{"authorization": "Bearer " + accessToken}, nil, "")
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d, want 200 (body %s)", me.StatusCode, me.Body)
	}
	meBody := decodeBody(t, me)
	// /me is unwrapped: the user object is the whole body.
	if meBody["email"] != testEmail {
		t.Errorf("me email = %v, want %q (body %s)", meBody["email"], testEmail, me.Body)
	}
	if meBody["success"] != nil {
		t.Errorf("me body carries a success envelope, but the family clients read it unwrapped: %s", me.Body)
	}
	for _, leaked := range []string{"password", "passwordHash", "accessToken"} {
		if _, present := meBody[leaked]; present {
			t.Errorf("me body leaks %q: %s", leaked, me.Body)
		}
	}
}

// TestCookieDeliverySetsAuthCookies proves the other delivery mode reaches the
// wire intact — three Set-Cookie headers on one response is the reason
// internal/lambdahttp exists at all.
func TestCookieDeliverySetsAuthCookies(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())

	resp := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(testEmail))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201 (body %s)", resp.StatusCode, resp.Body)
	}

	got := map[string]bool{}
	for _, c := range resp.Cookies {
		got[strings.SplitN(c, "=", 2)[0]] = true
	}
	// cookies.secure defaults to false, so the names carry no prefix.
	for _, want := range []string{auth.AccessTokenCookieName, auth.RefreshTokenCookieName, auth.CSRFTokenCookieName} {
		if !got[want] {
			t.Errorf("missing Set-Cookie %q; got %v", want, resp.Cookies)
		}
	}

	body := decodeBody(t, resp)
	for _, leaked := range []string{"accessToken", "refreshToken"} {
		if _, present := body[leaked]; present {
			t.Errorf("cookie-mode register put %q in the body: %s", leaked, resp.Body)
		}
	}
}

// TestInvalidConfigAbortsInit is the other half of the contract: a
// refuse-to-start rule must abort the cold start, not become a 500 per request.
func TestInvalidConfigAbortsInit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  map[string]string
		rule string
	}{
		{
			name: "no signing secrets",
			env: map[string]string{
				"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT": "development",
				"AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL":  "https://auth.example.test",
			},
			rule: config.RuleSecrets,
		},
		{
			name: "access and refresh secrets identical",
			env:  with(baseEnv(), "AWESOME_AUTH_JWT_REFRESH_SECRET", testAccessSecret),
			rule: config.RuleSecrets,
		},
		{
			name: "secret below the 32 character floor",
			env:  with(baseEnv(), "AWESOME_AUTH_JWT_ACCESS_SECRET", "short"),
			rule: config.RuleSecrets,
		},
		{
			name: "memory store in production",
			env: with(baseEnv(),
				"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT", "production",
				"AWESOME_AUTH_STORES_DRIVER", "memory"),
			rule: config.RuleMemoryStore,
		},
		{
			name: "csrf disabled while cookies are issued",
			env:  with(baseEnv(), "AWESOME_AUTH_CSRF_ENABLED", "false"),
			rule: config.RuleCSRFDisabled,
		},
		{
			name: "cookies on a shared aws domain",
			env: with(baseEnv(), "AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL",
				"https://abc123.execute-api.eu-west-1.amazonaws.com/prod"),
			rule: config.RuleInsecureCookieMode,
		},
		{
			name: "a configured but unwired domain",
			env:  with(baseEnv(), "AWESOME_AUTH_TOOLS_ENABLED", "true"),
			rule: config.RuleUnimplemented,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app, err := New(context.Background(), Options{
				Getenv: envFunc(tc.env),
				Logger: discardLogger(),
				Stores: memoryStores,
			})
			if err == nil {
				t.Fatalf("New succeeded on an invalid configuration")
			}
			if app != nil {
				t.Errorf("New returned a non-nil App alongside an error")
			}
			var verr *config.ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("error is %T, want *config.ValidationError: %v", err, err)
			}
			if !verr.HasRule(tc.rule) {
				t.Errorf("rule %s did not fire; paths = %v", tc.rule, verr.Paths())
			}
		})
	}
}

// TestStoreFactoryFailureAbortsInit covers the other init failure: a store that
// cannot be built must stop the cold start rather than be retried per request.
func TestStoreFactoryFailureAbortsInit(t *testing.T) {
	t.Parallel()
	want := errors.New("table does not exist")
	_, err := New(context.Background(), Options{
		Getenv: envFunc(baseEnv()),
		Logger: discardLogger(),
		Stores: func(context.Context, *config.Config, *slog.Logger) (auth.UserStore, auth.SessionStore, error) {
			return nil, nil, want
		},
	})
	if !errors.Is(err, want) {
		t.Fatalf("New error = %v, want it to wrap %v", err, want)
	}
}

// TestColdStartWorkHappensOnce is the guard against the classic serverless
// performance bug: the store, and everything else expensive, must be built in
// New and not per invocation.
func TestColdStartWorkHappensOnce(t *testing.T) {
	t.Parallel()
	var builds atomic.Int64
	app, err := New(context.Background(), Options{
		Getenv: envFunc(baseEnv()),
		Logger: discardLogger(),
		Stores: func(ctx context.Context, cfg *config.Config, log *slog.Logger) (auth.UserStore, auth.SessionStore, error) {
			builds.Add(1)
			return memoryStores(ctx, cfg, log)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("store built %d times during New, want 1", got)
	}

	for i := 0; i < 5; i++ {
		invoke(t, app, http.MethodGet, "/healthz", nil, nil, "")
	}
	if got := builds.Load(); got != 1 {
		t.Errorf("store built %d times after 5 invocations, want 1 — cold-start work leaked into the request path", got)
	}
}

// TestHealthz checks the readiness route answers without touching a store: the
// factory it is given would fail the test if it were called again.
func TestHealthz(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())

	resp := invoke(t, app, http.MethodGet, "/healthz", nil, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
	if body := decodeBody(t, resp); body["status"] != "ok" {
		t.Errorf("healthz body = %s, want status ok", resp.Body)
	}
}

// TestNoInventedAuthRoutes pins the rule that the auth surface comes entirely
// from the imported adapter. If a later change mounts a route here, the family
// ports diverge silently; this test makes that loud.
func TestNoInventedAuthRoutes(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())

	// Deliberately NOT a list of the adapter's routes: the adapter's surface grows
	// upstream, and a test that enumerates it fails on every upstream release
	// without finding a real defect. What must stay pinned is the direction of
	// ownership — the auth surface comes from the adapter, and this binary adds
	// only /healthz. So: sample what the adapter mounts to catch a wiring
	// regression, and assert 404 on paths the adapter is known not to mount.
	mounted := []string{"/auth/register", "/auth/login", "/auth/refresh", "/auth/logout", "/auth/me"}
	for _, path := range mounted {
		method := http.MethodPost
		if path == "/auth/me" {
			method = http.MethodGet
		}
		resp := invoke(t, app, method, path, jsonHeaders(), nil, "{}")
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("%s %s is not mounted, but the adapter mounts it", method, path)
		}
	}

	// The admin and tools routers are not implemented upstream, and the nonsense
	// path can never become real, so a non-404 here means this binary invented a
	// route or the mux is matching too broadly.
	neverMounted := []string{
		"/auth/admin/api/users",
		"/auth/tools/stream",
		"/auth/definitely-not-a-route",
	}
	for _, path := range neverMounted {
		resp := invoke(t, app, http.MethodPost, path, jsonHeaders(), nil, "{}")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s answered %d; this binary must not add auth routes the adapter does not mount",
				path, resp.StatusCode)
		}
	}
}

// TestAdapterSurfaceIsReachable checks the routes the adapter gained in
// awesome-go-auth v0.2.0 are actually served by this binary. A 405 counts as
// mounted (wrong method), and 401/403 counts as mounted (needs credentials);
// only 404 means the route never reached the mux. Without this, a dependency
// bump that failed to widen the surface would look identical to a successful one.
func TestAdapterSurfaceIsReachable(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())

	for _, path := range []string{
		"/auth/forgot-password", "/auth/reset-password", "/auth/change-password",
		"/auth/send-verification-email", "/auth/verify-email",
		"/auth/change-email/request", "/auth/change-email/confirm",
		"/auth/magic-link/send", "/auth/magic-link/verify",
		"/auth/sms/send", "/auth/sms/verify",
		"/auth/2fa/setup", "/auth/2fa/verify-setup", "/auth/2fa/verify", "/auth/2fa/disable",
		"/auth/sessions", "/auth/sessions/cleanup", "/auth/profile", "/auth/add-phone",
		"/auth/account", "/auth/linked-accounts", "/auth/link-request", "/auth/link-verify",
	} {
		resp := invoke(t, app, http.MethodPost, path, jsonHeaders(), nil, "{}")
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("POST %s answered 404; the adapter mounts it, so this binary is not serving the full surface", path)
		}
	}
}

// TestStagePrefixIsStripped covers the one event-layer knob this binary sets:
// deployment.stage exists so an execute-api path keeps matching the mux.
func TestStagePrefixIsStripped(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, with(baseEnv(),
		"AWESOME_AUTH_DEPLOYMENT_STAGE", "prod",
		// A stage in the path means a raw execute-api URL, which RS-2 refuses
		// unless the operator has accepted it for a dev stage.
		"AWESOME_AUTH_COOKIES_ALLOW_INSECURE_COOKIE_MODE", "true",
		"AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL", "https://abc123.execute-api.eu-west-1.amazonaws.com/prod"))

	if resp := invoke(t, app, http.MethodGet, "/prod/healthz", nil, nil, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("/prod/healthz status = %d, want 200 — the stage segment was not stripped", resp.StatusCode)
	}
}

func TestCORS(t *testing.T) {
	t.Parallel()
	const origin = "https://app.example.test"

	t.Run("no origins configured means no CORS layer", func(t *testing.T) {
		t.Parallel()
		app := newTestApp(t, baseEnv())
		resp := invoke(t, app, http.MethodOptions, "/auth/login",
			map[string]string{"origin": origin}, nil, "")
		if resp.Headers["Access-Control-Allow-Origin"] != "" {
			t.Errorf("unconfigured CORS still answered a preflight: %v", resp.Headers)
		}
	})

	t.Run("allowlisted origin is echoed and the preflight is 204", func(t *testing.T) {
		t.Parallel()
		app := newTestApp(t, with(baseEnv(), "AWESOME_AUTH_CORS_ORIGINS", origin+",https://other.example.test"))

		resp := invoke(t, app, http.MethodOptions, "/auth/login",
			map[string]string{"origin": origin}, nil, "")
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("preflight status = %d, want 204", resp.StatusCode)
		}
		if got := resp.Headers["Access-Control-Allow-Origin"]; got != origin {
			t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, origin)
		}
		if got := resp.Headers["Access-Control-Allow-Credentials"]; got != "true" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
		}
		if got := resp.Headers["Access-Control-Allow-Headers"]; got != corsAllowHeaders {
			t.Errorf("Access-Control-Allow-Headers = %q, want %q", got, corsAllowHeaders)
		}
		if got := resp.Headers["Vary"]; !strings.Contains(got, "Origin") {
			t.Errorf("Vary = %q, want it to contain Origin", got)
		}
	})

	t.Run("unlisted origin gets no allow header but still varies", func(t *testing.T) {
		t.Parallel()
		app := newTestApp(t, with(baseEnv(), "AWESOME_AUTH_CORS_ORIGINS", origin))
		resp := invoke(t, app, http.MethodGet, "/healthz",
			map[string]string{"origin": "https://evil.example.test"}, nil, "")
		if got := resp.Headers["Access-Control-Allow-Origin"]; got != "" {
			t.Errorf("Access-Control-Allow-Origin = %q for an unlisted origin, want none", got)
		}
		if got := resp.Headers["Vary"]; !strings.Contains(got, "Origin") {
			t.Errorf("Vary = %q, want it to contain Origin", got)
		}
	})
}

// TestUnsupportedStoreIsRefused: a stores.enable key the driver cannot back is
// a knob that would validate and then answer NOT_IMPLEMENTED on the wire.
func TestUnsupportedStoreIsRefused(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			// telemetry: implemented by the DynamoDB store, handed to the core
			// by nothing until the tools block, so the flag is refused rather
			// than accepted and inert. It replaced rbac here when the admin
			// surface made that flag a real switch.
			name: "a store nothing hands to the core",
			env:  with(baseEnv(), "AWESOME_AUTH_STORES_ENABLE_TELEMETRY", "true"),
			want: "stores.enable.telemetry",
		},
		{
			name: "users switched off",
			env:  with(baseEnv(), "AWESOME_AUTH_STORES_ENABLE_USERS", "false"),
			want: "stores.enable.users",
		},
		{
			name: "sessions switched off",
			env:  with(baseEnv(), "AWESOME_AUTH_STORES_ENABLE_SESSIONS", "false"),
			want: "stores.enable.sessions",
		},
		{
			// The loader accepts postgres — it is a documented driver — so the
			// refusal has to come from this binary, which has no implementation
			// for it. The DSN is supplied so the loader's own postgres checks
			// pass and the driver check is what fires.
			name: "a driver this build does not implement",
			env: with(baseEnv(),
				"AWESOME_AUTH_STORES_DRIVER", "postgres",
				"AWESOME_AUTH_STORES_CONNECTION_DSN", "postgres://auth@db.example.test:5432/auth"),
			want: "stores.driver",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(context.Background(), Options{
				Getenv: envFunc(tc.env),
				Logger: discardLogger(),
				Stores: memoryStores,
			})
			if err == nil {
				t.Fatalf("New succeeded, want a refusal naming %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err.Error(), tc.want)
			}
		})
	}
}

// TestUnwiredKnobsAreReportedLoudly: a knob the imported core cannot honour has
// to be visible in the deployment log, with its dotted path.
func TestUnwiredKnobsAreReportedLoudly(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	_, err := New(context.Background(), Options{
		Getenv: envFunc(baseEnv()),
		Logger: newLogger(&buf, slog.LevelDebug),
		Stores: memoryStores,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out := buf.String()
	// One HS256 secret signs both tokens, so this gap is present in every
	// deployment — RS-1 requires the second secret and nothing signs with it.
	for _, want := range []string{"security.jwt.refreshTokenSecret"} {
		if !strings.Contains(out, want) {
			t.Errorf("cold-start log does not mention the unwired knob %s:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "configured knob is not wired to the auth core") {
		t.Errorf("cold-start log carries no unwired-knob warning:\n%s", out)
	}
}

func TestUnwiredKnobs(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(baseEnv())})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	paths := map[string]bool{}
	for _, g := range unwiredKnobs(cfg) {
		paths[g.Path] = true
		if g.Problem == "" || g.Remedy == "" {
			t.Errorf("gap %s has an empty problem or remedy", g.Path)
		}
	}
	for _, want := range []string{"security.jwt.refreshTokenSecret"} {
		if !paths[want] {
			t.Errorf("unwiredKnobs did not report %s", want)
		}
	}
	// Knobs the core does honour must not be reported, or the warning becomes
	// noise nobody reads. bcryptSaltRounds is here rather than above because
	// v0.6.0 exports WithBcryptCost and coreOptions passes it: the configured
	// cost is the deployed cost, and a warning saying otherwise would send an
	// operator to lower a value that is actually in force.
	for _, unwanted := range []string{
		"security.jwt.accessTokenSecret",
		"security.password.bcryptSaltRounds",
		"sessions.checkOn",
		"http.apiPrefix",
	} {
		if paths[unwanted] {
			t.Errorf("unwiredKnobs reported %s, which is wired", unwanted)
		}
	}
}

func TestEnabledStoresTracksTheSchema(t *testing.T) {
	t.Parallel()

	got := enabledStores(config.Defaults().Stores.Enable)
	want := []string{"sessions", "tokens", "users"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("enabledStores(defaults) = %v, want %v", got, want)
	}
}

// TestCoreOptionSetsAreOrderedAndReserved pins the composition root's build
// order and the slots reserved after it.
//
// Both halves are load-bearing. The order of the wired sets is observable
// through their refusals — a document with two faults reports the first set that
// refuses, and TestInvalidConfigAbortsInit depends on which — and the core's own
// options are not commutative, so a reordering is a behaviour change that
// nothing else would catch. The reserved tail is pinned so that the blocks
// filling those slots find them where the roadmap says they are: a block that
// renamed or reordered one would silently move another block's landing site.
//
// It also pins which slots are still empty, so that filling one is a visible
// edit to this list rather than a line that appears in a diff nobody reads.
func TestCoreOptionSetsAreOrderedAndReserved(t *testing.T) {
	t.Parallel()

	sets := coreOptionSets(context.Background(), config.Defaults(), Options{}, nil, nil, discardLogger())

	var names []string
	var empty []string
	for _, s := range sets {
		if s.name == "" {
			t.Errorf("a core option set has no name; the name is what makes the reserved order checkable")
		}
		names = append(names, s.name)
		if s.build == nil {
			empty = append(empty, s.name)
		}
	}

	wantOrder := []string{
		"delivery", "email", "twoFactor", "claims", "oauth", "idp", "migration",
		"settings", "docs", "ui", "admin", "tools",
	}
	if strings.Join(names, ",") != strings.Join(wantOrder, ",") {
		t.Errorf("core option sets are %v, want %v", names, wantOrder)
	}

	// The slots that contribute no option. Filling one means deleting its name
	// from here in the same commit.
	//
	// **Two of these three are empty on purpose and one is still waiting**, and
	// the list cannot tell them apart, so this comment has to.
	//
	// `docs` and `ui` are the deliberate ones. Both blocks are wired, and both
	// reach the core entirely through HTTPConfig — DocsOptions for the two
	// documentation routes (docs.go), UIOptions for the whole <prefix>/ui
	// subtree (ui.go) — which the adapter reads at mount time. Neither has an
	// auth.Option to contribute and neither had one invented for it: the UI's
	// config document is built from the settings and template stores, and those
	// were handed to the core by the `settings` slot and by emailOptions, not by
	// this one. If either ever leaves this list it must be because upstream grew
	// an option, not because somebody read an empty slot as unfinished work.
	//
	// `admin` left the list with the admin surface, and it is the first reserved
	// slot to turn out genuinely non-empty: the console's router reaches the
	// core through HTTPConfig.Admin like the two above, but its tabs are drawn
	// from five stores the core takes by name and cannot discover, plus the
	// upload store, and adminOptions hands those over (admin.go).
	//
	// `tools` is the pending one: its domain is still refused by
	// internal/config/phases.go, and whether it contributes options is not yet
	// known.
	wantEmpty := []string{"docs", "ui", "tools"}
	if strings.Join(empty, ",") != strings.Join(wantEmpty, ",") {
		t.Errorf("unfilled core option slots are %v, want %v", empty, wantEmpty)
	}
}

func TestLoadDocument(t *testing.T) {
	t.Parallel()

	const doc = `{"schemaVersion":1,"http":{"apiPrefix":"/identity"}}`

	t.Run("inline json", func(t *testing.T) {
		t.Parallel()
		got, err := loadDocument(envFunc(map[string]string{ConfigJSONEnv: doc}), nil)
		if err != nil {
			t.Fatalf("loadDocument: %v", err)
		}
		if got["schemaVersion"] == nil {
			t.Errorf("document did not parse: %v", got)
		}
	})

	t.Run("file", func(t *testing.T) {
		t.Parallel()
		read := func(path string) ([]byte, error) {
			if path != "/etc/auth.json" {
				return nil, fmt.Errorf("unexpected path %q", path)
			}
			return []byte(doc), nil
		}
		got, err := loadDocument(envFunc(map[string]string{ConfigFileEnv: "/etc/auth.json"}), read)
		if err != nil {
			t.Fatalf("loadDocument: %v", err)
		}
		if got["schemaVersion"] == nil {
			t.Errorf("document did not parse: %v", got)
		}
	})

	t.Run("both sources set is refused", func(t *testing.T) {
		t.Parallel()
		_, err := loadDocument(envFunc(map[string]string{ConfigFileEnv: "/etc/auth.json", ConfigJSONEnv: doc}), nil)
		if err == nil {
			t.Fatal("loadDocument accepted two configuration sources")
		}
	})

	t.Run("neither source set means defaults plus env", func(t *testing.T) {
		t.Parallel()
		got, err := loadDocument(envFunc(nil), nil)
		if err != nil || got != nil {
			t.Fatalf("loadDocument = %v, %v; want nil, nil", got, err)
		}
	})
}

// TestDocumentDrivesTheMountPrefix proves the document layer actually reaches
// the mounted routes, not just the Config struct.
func TestDocumentDrivesTheMountPrefix(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, with(baseEnv(),
		ConfigJSONEnv, `{"schemaVersion":1,"http":{"apiPrefix":"/identity"}}`))

	if got := app.Config.HTTP.APIPrefix; got != "/identity" {
		t.Fatalf("apiPrefix = %q, want /identity", got)
	}
	if resp := invoke(t, app, http.MethodPost, "/identity/register", jsonHeaders(), nil, registerBody("prefix@example.test")); resp.StatusCode != http.StatusCreated {
		t.Errorf("/identity/register status = %d, want 201 (body %s)", resp.StatusCode, resp.Body)
	}
	if resp := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody("old@example.test")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("/auth/register status = %d, want 404 once the prefix moved", resp.StatusCode)
	}
}

func TestSameSiteMapping(t *testing.T) {
	t.Parallel()
	cases := map[string]http.SameSite{
		config.SameSiteStrict: http.SameSiteStrictMode,
		config.SameSiteLax:    http.SameSiteLaxMode,
		config.SameSiteNone:   http.SameSiteNoneMode,
		"":                    http.SameSiteLaxMode,
	}
	for in, want := range cases {
		if got := sameSite(in); got != want {
			t.Errorf("sameSite(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestTheUISwitchIsOneSwitchWithTwoSpellings pins the half of the UI wiring that
// is invisible from either side on its own: `ui.enabled` decides both whether
// the adapter mounts <prefix>/ui and whether every emailed link points at a UI
// page or at the bare API route (UILink, wire.go), and the core carries two
// names for that one switch.
//
// httpConfig sets UI.Enabled and deliberately leaves the deprecated UIEnabled
// alias alone, which is the arrangement in which the two cannot be assigned from
// different expressions and drift. This test is what makes that a fact about the
// build rather than a comment about it: it asserts the alias stays unset *and*
// that the link shape follows anyway, because the two together are the whole
// claim. Setting the alias as well would pass the second assertion and hide the
// day someone wired one of them from a different knob.
//
// It loads with AllowUnimplemented so that it says the same thing on both sides
// of the phase gate: before `ui` leaves unwiredDomains() the flag is a warning,
// after it is silence, and the wiring under test is identical either way.
func TestTheUISwitchIsOneSwitchWithTwoSpellings(t *testing.T) {
	t.Parallel()

	const site = "https://app.example.test"

	load := func(t *testing.T, env map[string]string) auth.HTTPConfig {
		t.Helper()
		cfg, err := config.Load(context.Background(), config.Options{
			Getenv:             envFunc(env),
			AllowUnimplemented: true,
		})
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		return httpConfig(cfg)
	}

	t.Run("off", func(t *testing.T) {
		t.Parallel()
		wire := load(t, baseEnv())
		if wire.UI.Enabled {
			t.Error("UI.Enabled is set for a document that does not enable the UI")
		}
		if got, want := wire.UILink(site, "/reset-password?token=t"), site+"/auth/reset-password?token=t"; got != want {
			t.Errorf("UILink = %q, want the bare API route %q", got, want)
		}
	})

	t.Run("on", func(t *testing.T) {
		t.Parallel()
		wire := load(t, with(baseEnv(), "AWESOME_AUTH_UI_ENABLED", "true"))
		if !wire.UI.Enabled {
			t.Error("UI.Enabled is not set for a document that enables the UI, so the adapter would mount no UI at all")
		}
		// The alias is the core's own deprecated spelling. Leaving it unset is
		// the point: one switch, assigned once.
		if wire.UIEnabled {
			t.Error("httpConfig set the deprecated UIEnabled alias as well; the two must come from one assignment, not two")
		}
		// And the link follows the switch regardless, because UILink reads both
		// spellings. This is what would silently regress if the alias were ever
		// wired from a second expression.
		if got, want := wire.UILink(site, "/reset-password?token=t"), site+"/auth/ui/reset-password?token=t"; got != want {
			t.Errorf("UILink = %q, want the hosted UI page %q", got, want)
		}
	})
}
