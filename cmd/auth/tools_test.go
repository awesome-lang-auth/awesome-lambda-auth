package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The tools surface, driven through the Lambda event path against the memory
// driver, the way every other block's composition is proved. What is asserted
// here is the composition — the routes the adapter mounts from the options
// tools.go builds, the posture each knob resolves to, the two decisions this
// runtime makes about the stream and the bridge — and not the routes' own
// behaviour, which is the core's and is pinned there.

// toolsEnv is baseEnv plus a tools block that loads on this build: the two
// stores the block consumes, the session posture, and inbound webhooks off,
// which RS-15 makes every tools document say explicitly.
func toolsEnv(kv ...string) map[string]string {
	return with(baseEnv(), append([]string{
		"AWESOME_AUTH_TOOLS_ENABLED", "true",
		"AWESOME_AUTH_TOOLS_AUTH", "session",
		"AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS", "false",
		"AWESOME_AUTH_STORES_ENABLE_TELEMETRY", "true",
		"AWESOME_AUTH_STORES_ENABLE_WEBHOOKS", "true",
	}, kv...)...)
}

// toolsBundle is the memory bundle with the tools stores held by the test, so a
// subscription can be added and a telemetry row read without going through a
// route that does not exist in this build (the admin API is D8's).
type toolsBundle struct {
	bundle memoryStoreBundle
}

func newToolsBundle() *toolsBundle { return &toolsBundle{bundle: newMemoryStoreBundle()} }

func (b *toolsBundle) factory(_ context.Context, _ *config.Config, _ *slog.Logger) (auth.UserStore, auth.SessionStore, error) {
	return b.bundle, auth.NewMemorySessionStore(), nil
}

func newToolsApp(t *testing.T, env map[string]string, bundle *toolsBundle) *App {
	t.Helper()
	opts := Options{Getenv: envFunc(env), Logger: discardLogger(), Stores: memoryStores}
	if bundle != nil {
		opts.Stores = bundle.factory
	}
	app, err := New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

// TestBridgeDeliversEachLoginOnce pins the bridge decision from the outside: one
// login produces exactly one delivery to each outgoing webhook subscribed to
// it and exactly one telemetry row — not zero, which is the core's default, and
// not two, which is the hazard the core documents for a facade that hears its
// own Track. It fails the day either tree changes the arrangement.
func TestBridgeDeliversEachLoginOnce(t *testing.T) {
	t.Parallel()

	type delivery struct{ event, correlation string }
	var (
		mu         sync.Mutex
		deliveries []delivery // X-Webhook-Event and X-Correlation-Id per POST
	)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		deliveries = append(deliveries, delivery{r.Header.Get("X-Webhook-Event"), r.Header.Get("X-Correlation-Id")})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	bundle := newToolsBundle()
	if _, err := bundle.bundle.webhooks.(*auth.MemoryWebhookStore).AddWebhook(context.Background(), auth.WebhookConfig{
		URL:    receiver.URL,
		Events: []string{auth.EventAuthLoginSuccess},
		Secret: "webhook-signing-secret",
	}); err != nil {
		t.Fatalf("add webhook: %v", err)
	}

	app := newToolsApp(t, toolsEnv(), bundle)
	invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(testEmail))
	// The login carries a correlation id, because the register promises a
	// bridged delivery "the same headers" a tracked one gets, and the one
	// header that has to be carried across from the request to the outbound
	// POST is this one (logging.go, correlatingTransport).
	const correlation = "bridge-test-7f3a"
	login := invoke(t, app, http.MethodPost, "/auth/login",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer, "x-correlation-id", correlation), nil, registerBody(testEmail))
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d (body %s)", login.StatusCode, login.Body)
	}

	// The delivery is on a detached goroutine (WebhookEmitter.Emit), so it is
	// awaited with a bound; the "exactly one" half then has to outwait a
	// second delivery that would arrive on the same schedule, which is what
	// the settle window is for.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(deliveries)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	got := append([]delivery(nil), deliveries...)
	mu.Unlock()
	if len(got) != 1 || got[0].event != auth.EventAuthLoginSuccess {
		t.Errorf("the login reached the webhook %d time(s) as %v, want exactly once as %q", len(got), got, auth.EventAuthLoginSuccess)
	}
	// A bridged delivery is made from the cold-start context, which has no
	// request carrier; the bridge rebuilds one from the event's own provenance
	// so the outbound request carries the caller's id like a tracked event's
	// does. Without that, this header would be empty.
	if len(got) == 1 && got[0].correlation != correlation {
		t.Errorf("the bridged delivery carried X-Correlation-Id %q, want the login's %q", got[0].correlation, correlation)
	}

	rows, err := bundle.bundle.telemetry.Query(context.Background(), auth.TelemetryFilter{EventName: auth.EventAuthLoginSuccess})
	if err != nil {
		t.Fatalf("telemetry query: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("the telemetry store holds %d row(s) for %s, want exactly one", len(rows), auth.EventAuthLoginSuccess)
	}
	// The row is the bridged event, provenance and all: the bridge hands the
	// bus event to the same fan-out Track uses, and the adapter's carrier gave
	// the service the client address the event was raised with.
	if len(rows) == 1 && rows[0].IP != "203.0.113.7" {
		t.Errorf("telemetry row IP = %q, want the event's source address", rows[0].IP)
	}
}

// TestToolsRoutesComeFromTheAdapter drives the four routes this build mounts
// and the one it does not, through the Lambda event path, in the session
// posture. The bodies asserted are the reference's (tools.router.ts:158, :177,
// :244) as the core reproduces them.
func TestToolsRoutesComeFromTheAdapter(t *testing.T) {
	t.Parallel()

	app := newToolsApp(t, toolsEnv(), nil)
	creds := registerAndToken(t, app, testEmail)
	bearer := jsonHeaders("authorization", "Bearer "+creds.accessToken)

	t.Run("track answers 202 and the event is queryable", func(t *testing.T) {
		resp := invoke(t, app, http.MethodPost, "/tools/track/order.paid", bearer, nil, `{"data":{"amount":12}}`)
		if resp.StatusCode != http.StatusAccepted || strings.TrimSpace(resp.Body) != `{"ok":true}` {
			t.Fatalf("track = %d %s, want 202 {\"ok\":true}", resp.StatusCode, resp.Body)
		}
		q := invoke(t, app, http.MethodGet, "/tools/telemetry?event=order.paid", bearer, nil, "")
		if q.StatusCode != http.StatusOK {
			t.Fatalf("telemetry = %d %s", q.StatusCode, q.Body)
		}
		data, _ := decodeBody(t, q)["data"].([]any)
		if len(data) != 1 {
			t.Fatalf("telemetry data = %v, want the one tracked event", data)
		}
		row, _ := data[0].(map[string]any)
		// The tracked event with no userId in the body is attributed to the
		// caller (tools.router.ts:147), which is the session posture's whole
		// point on this route.
		if row["event"] != "order.paid" || row["userId"] == "" || row["userId"] == nil {
			t.Errorf("telemetry row = %v, want event order.paid attributed to the caller", row)
		}
	})

	t.Run("notify answers 202", func(t *testing.T) {
		resp := invoke(t, app, http.MethodPost, "/tools/notify/user:someone", bearer, nil, `{"data":"hello","type":"greeting"}`)
		if resp.StatusCode != http.StatusAccepted || strings.TrimSpace(resp.Body) != `{"ok":true}` {
			t.Errorf("notify = %d %s, want 202 {\"ok\":true}", resp.StatusCode, resp.Body)
		}
	})

	t.Run("a wrongly typed member is a 400 in the tools envelope", func(t *testing.T) {
		resp := invoke(t, app, http.MethodPost, "/tools/track/order.paid", bearer, nil, `{"userId":5}`)
		if resp.StatusCode != http.StatusBadRequest || strings.TrimSpace(resp.Body) != `{"error":"Invalid request body"}` {
			t.Errorf("typed body = %d %s, want 400 {\"error\":\"Invalid request body\"} (tools-request-bodies-are-typed)", resp.StatusCode, resp.Body)
		}
	})

	t.Run("the session guard is the adapter's, on all three guarded routes", func(t *testing.T) {
		// Track, notify and the telemetry query — the query in particular,
		// because it is the one route that hands back stored PII and the one
		// a test that covered track alone would leave unpinned.
		for _, tc := range []struct{ method, path string }{
			{http.MethodPost, "/tools/track/order.paid"},
			{http.MethodPost, "/tools/notify/user:someone"},
			{http.MethodGet, "/tools/telemetry"},
		} {
			resp := invoke(t, app, tc.method, tc.path, jsonHeaders(), nil, `{}`)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("anonymous %s %s = %d %s, want the adapter's 403", tc.method, tc.path, resp.StatusCode, resp.Body)
				continue
			}
			if body := decodeBody(t, resp); body["error"] != "No access token provided" {
				t.Errorf("anonymous %s %s body = %v, want the adapter's refusal", tc.method, tc.path, body)
			}
		}
	})

	t.Run("the stream is not mounted on this runtime", func(t *testing.T) {
		resp := invoke(t, app, http.MethodGet, "/tools/stream", bearer, nil, "")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET /tools/stream = %d, want 404: the route is a spinner that bills behind API Gateway (tools-stream-is-not-mounted-on-api-gateway)", resp.StatusCode)
		}
	})

	t.Run("the documentation pair follows docs.swagger", func(t *testing.T) {
		// baseEnv is a development deployment and docs.swagger defaults to
		// auto, so both are on, exactly as the auth router's pair is.
		for _, path := range []string{"/tools/openapi.json", "/tools/docs"} {
			resp := invoke(t, app, http.MethodGet, path, nil, nil, "")
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET %s = %d, want 200 under docs.swagger: auto outside production", path, resp.StatusCode)
			}
		}
		spec := invoke(t, app, http.MethodGet, "/tools/openapi.json", nil, nil, "")
		paths, _ := decodeBody(t, spec)["paths"].(map[string]any)
		if _, ok := paths["/tools/stream"]; ok {
			t.Errorf("the tools document describes /tools/stream, which this runtime does not mount")
		}
		if _, ok := paths["/tools/track/{eventName}"]; !ok {
			t.Errorf("the tools document does not describe the track route: %v", paths)
		}
	})
}

// TestToolsOffMountsNothing: with the block off, no route under the tools path
// exists, no bus is built, and the App exposes no facade.
//
// Each route is probed on its own method. The core's router answers 404 to a
// POST on the four GET-only routes even when it is fully mounted, so a probe
// that POSTed everywhere would pass for those four whether or not the router
// existed — an assertion that cannot fail is not one.
func TestToolsOffMountsNothing(t *testing.T) {
	t.Parallel()

	app := newTestApp(t, baseEnv())
	if app.Tools != nil {
		t.Errorf("App.Tools is set with tools.enabled off")
	}
	if app.Events != nil {
		t.Errorf("App.Events is set with tools.enabled off: a bus was built that nothing consumes")
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/tools/track/x"},
		{http.MethodPost, "/tools/notify/x"},
		{http.MethodGet, "/tools/telemetry"},
		{http.MethodGet, "/tools/stream"},
		{http.MethodGet, "/tools/openapi.json"},
		{http.MethodGet, "/tools/docs"},
	} {
		resp := invoke(t, app, tc.method, tc.path, jsonHeaders(), nil, `{}`)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s = %d with tools.enabled off, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}
}

// TestSessionPostureDoubleSubmit: under tools.auth: session a cookie caller is
// held to the reference's CSRF double-submit (auth.middleware.ts:33-41) — a
// mutating request on the access-token cookie with no matching X-CSRF-Token is
// the reference's 403 CSRF_INVALID, not a 202 — while a bearer caller, a safe
// method and a caller with no credential at all pass through to the guard
// behind it. The core mounts the tools router outside its CSRF chain and says
// the host's auth middleware is where this belongs; this pins that the product
// is that host.
func TestSessionPostureDoubleSubmit(t *testing.T) {
	t.Parallel()

	app := newToolsApp(t, toolsEnv(), nil)
	reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(testEmail))
	if reg.StatusCode != http.StatusCreated {
		t.Fatalf("cookie-mode register = %d %s", reg.StatusCode, reg.Body)
	}
	jar := map[string]string{}
	for _, c := range reg.Cookies {
		name, rest, _ := strings.Cut(c, "=")
		value, _, _ := strings.Cut(rest, ";")
		jar[name] = value
	}
	access, csrf := jar[auth.AccessTokenCookieName], jar[auth.CSRFTokenCookieName]
	if access == "" || csrf == "" {
		t.Fatalf("register set no access-token or csrf-token cookie: %v", reg.Cookies)
	}
	accessCookie := auth.AccessTokenCookieName + "=" + access
	csrfCookie := auth.CSRFTokenCookieName + "=" + csrf

	t.Run("a cookie POST with no header is the reference's 403 CSRF_INVALID", func(t *testing.T) {
		for _, path := range []string{"/tools/track/order.paid", "/tools/notify/user:someone"} {
			resp := invoke(t, app, http.MethodPost, path, jsonHeaders(), []string{accessCookie, csrfCookie}, `{}`)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("cookie POST %s with no X-CSRF-Token = %d %s, want 403", path, resp.StatusCode, resp.Body)
				continue
			}
			body := decodeBody(t, resp)
			if body["error"] != "CSRF token validation failed" || body["code"] != "CSRF_INVALID" {
				t.Errorf("cookie POST %s refusal = %v, want the reference's CSRF_INVALID envelope", path, body)
			}
		}
	})

	t.Run("a mismatched header is refused too", func(t *testing.T) {
		resp := invoke(t, app, http.MethodPost, "/tools/track/order.paid",
			jsonHeaders(auth.CSRFHeaderName, "not-the-cookie"), []string{accessCookie, csrfCookie}, `{}`)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cookie POST with a wrong X-CSRF-Token = %d %s, want 403", resp.StatusCode, resp.Body)
		}
	})

	t.Run("the double-submit passes", func(t *testing.T) {
		resp := invoke(t, app, http.MethodPost, "/tools/track/order.paid",
			jsonHeaders(auth.CSRFHeaderName, csrf), []string{accessCookie, csrfCookie}, `{}`)
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("cookie POST with the matching X-CSRF-Token = %d %s, want 202", resp.StatusCode, resp.Body)
		}
	})

	t.Run("a safe method needs no header", func(t *testing.T) {
		resp := invoke(t, app, http.MethodGet, "/tools/telemetry", nil, []string{accessCookie}, "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("cookie GET /tools/telemetry = %d %s, want 200", resp.StatusCode, resp.Body)
		}
	})

	t.Run("a bearer caller is exempt", func(t *testing.T) {
		// The same token, presented as a bearer: a cross-site page cannot set
		// an Authorization header, which is why the reference exempts it.
		resp := invoke(t, app, http.MethodPost, "/tools/track/order.paid", jsonHeaders("authorization", "Bearer "+access), nil, `{}`)
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("bearer POST with no X-CSRF-Token = %d %s, want 202", resp.StatusCode, resp.Body)
		}
	})

	t.Run("no credential at all is the guard's refusal, not the CSRF one", func(t *testing.T) {
		// The reference answers "No access token provided" before it reaches
		// its CSRF branch; a caller with no cookie is passed through to the
		// authenticating guard for exactly that literal.
		resp := invoke(t, app, http.MethodPost, "/tools/track/order.paid", jsonHeaders(), nil, `{}`)
		if body := decodeBody(t, resp); resp.StatusCode != http.StatusForbidden || body["error"] != "No access token provided" {
			t.Errorf("anonymous POST = %d %v, want the adapter's 403 No access token provided", resp.StatusCode, body)
		}
	})
}

// TestToolsDocsPairCarriesTheDocsPolicy: the tools router's Swagger page and
// document are the same page under the same knob as the auth router's, and
// carry the same Content-Security-Policy and companion headers — registered as
// docs-page-carries-a-content-security-policy, whose surface names both pairs.
// A mitigation that covered one Swagger page on this origin and not the other
// would be bypassable one path over.
func TestToolsDocsPairCarriesTheDocsPolicy(t *testing.T) {
	t.Parallel()

	t.Run("at the default mount", func(t *testing.T) {
		t.Parallel()
		app := newToolsApp(t, toolsEnv(), nil)
		page := invoke(t, app, http.MethodGet, "/tools/docs", nil, nil, "")
		if page.StatusCode != http.StatusOK || page.Headers["Content-Security-Policy"] != docsPageCSP {
			t.Errorf("GET /tools/docs = %d with policy %q, want 200 with the page policy", page.StatusCode, page.Headers["Content-Security-Policy"])
		}
		assertDocsCompanionHeaders(t, page.Headers)
		spec := invoke(t, app, http.MethodGet, "/tools/openapi.json", nil, nil, "")
		if spec.StatusCode != http.StatusOK || spec.Headers["Content-Security-Policy"] != docsSpecCSP {
			t.Errorf("GET /tools/openapi.json = %d with policy %q, want 200 with the document policy", spec.StatusCode, spec.Headers["Content-Security-Policy"])
		}
		assertDocsCompanionHeaders(t, spec.Headers)
		// And no other tools route is decorated: the middleware matches the
		// two documentation paths and nothing else under the mount.
		track := invoke(t, app, http.MethodPost, "/tools/track/x", jsonHeaders(), nil, `{}`)
		if policy := track.Headers["Content-Security-Policy"]; policy != "" {
			t.Errorf("POST /tools/track/x carries a Content-Security-Policy (%q); the docs policy must decorate the documentation pair and nothing else", policy)
		}
	})

	t.Run("follows a moved tools.basePath", func(t *testing.T) {
		t.Parallel()
		app := newToolsApp(t, toolsEnv("AWESOME_AUTH_TOOLS_BASE_PATH", "/auth/tools"), nil)
		moved := invoke(t, app, http.MethodGet, "/auth/tools/docs", nil, nil, "")
		if moved.StatusCode != http.StatusOK || moved.Headers["Content-Security-Policy"] != docsPageCSP {
			t.Errorf("GET /auth/tools/docs = %d with policy %q, want 200 with the page policy", moved.StatusCode, moved.Headers["Content-Security-Policy"])
		}
		old := invoke(t, app, http.MethodGet, "/tools/docs", nil, nil, "")
		if old.StatusCode != http.StatusNotFound || old.Headers["Content-Security-Policy"] != "" {
			t.Errorf("GET /tools/docs = %d with policy %q after the mount moved, want a bare 404", old.StatusCode, old.Headers["Content-Security-Policy"])
		}
	})
}

// TestToolsAccessPostures resolves each spelling of tools.auth against a live
// composition. `none` is the reference's default and answers anyone; `apiKey`
// answers only a key minted against the deployment's store; `admin` is refused
// at cold start by name until D8's guard exists.
func TestToolsAccessPostures(t *testing.T) {
	t.Parallel()

	t.Run("none serves an anonymous caller", func(t *testing.T) {
		t.Parallel()
		app := newToolsApp(t, toolsEnv("AWESOME_AUTH_TOOLS_AUTH", "none"), nil)
		resp := invoke(t, app, http.MethodPost, "/tools/track/anything", jsonHeaders(), nil, `{"userId":"victim"}`)
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("anonymous track under none = %d, want 202 (auth.ToolsPublic)", resp.StatusCode)
		}
	})

	t.Run("apiKey verifies against the API-key store", func(t *testing.T) {
		t.Parallel()
		bundle := newToolsBundle()
		app := newToolsApp(t, toolsEnv(
			"AWESOME_AUTH_TOOLS_AUTH", "apiKey",
			"AWESOME_AUTH_STORES_ENABLE_API_KEYS", "true",
		), bundle)

		anonymous := invoke(t, app, http.MethodPost, "/tools/track/anything", jsonHeaders(), nil, `{}`)
		if anonymous.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous track under apiKey = %d, want 401", anonymous.StatusCode)
		}
		// Minted the way the admin API will mint one, against the same store
		// the guard verifies against. Cost 4 is bcrypt's floor: the test pays
		// for one hash and the guard for one verify.
		raw, _, err := auth.NewAPIKeyService(4).Create(context.Background(), bundle.bundle.apiKeys, "ops", "svc", nil, nil, nil)
		if err != nil {
			t.Fatalf("mint api key: %v", err)
		}
		keyed := invoke(t, app, http.MethodPost, "/tools/track/anything", jsonHeaders("x-api-key", raw), nil, `{}`)
		if keyed.StatusCode != http.StatusAccepted {
			t.Errorf("keyed track under apiKey = %d %s, want 202", keyed.StatusCode, keyed.Body)
		}
		forged := invoke(t, app, http.MethodPost, "/tools/track/anything", jsonHeaders("x-api-key", "ak_"+strings.Repeat("x", 48)), nil, `{}`)
		if forged.StatusCode != http.StatusUnauthorized {
			t.Errorf("forged key under apiKey = %d, want 401", forged.StatusCode)
		}
	})

	t.Run("admin is refused until the console exists", func(t *testing.T) {
		t.Parallel()
		_, err := New(context.Background(), Options{
			// admin.enabled is what validate.go demands for the posture; it is
			// still phase-gated here, so the document has to be allowed through
			// the gate by the environment the loader reads. That is not
			// possible from Options, so the refusal this test can reach is the
			// loader's own — which is the right one to assert: an admin posture
			// cannot come up on this build by any route.
			Getenv: envFunc(toolsEnv("AWESOME_AUTH_TOOLS_AUTH", "admin")),
			Logger: discardLogger(),
			Stores: memoryStores,
		})
		if err == nil {
			t.Fatal("tools.auth: admin came up with no admin console")
		}
		if !strings.Contains(err.Error(), "tools.auth") {
			t.Errorf("the refusal does not name the knob: %v", err)
		}
	})

	t.Run("an unset posture is refused at load, by RS-16", func(t *testing.T) {
		t.Parallel()
		env := toolsEnv()
		delete(env, "AWESOME_AUTH_TOOLS_AUTH")
		_, err := New(context.Background(), Options{Getenv: envFunc(env), Logger: discardLogger(), Stores: memoryStores})
		if err == nil {
			t.Fatal("a tools block with no tools.auth came up: silence resolved to a posture")
		}
		for _, want := range []string{config.RuleToolsAuthUnset, "tools.auth", "tools.auth: none"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not say %q:\n%v", want, err)
			}
		}
	})

	t.Run("checkToolsSupport names D8", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		cfg.Tools.Enabled = true
		cfg.Tools.Auth = config.ToolsAuthAdmin
		err := checkToolsSupport(cfg)
		if err == nil || !strings.Contains(err.Error(), "D8") {
			t.Errorf("checkToolsSupport(admin) = %v, want a refusal naming the block that brings the guard", err)
		}
		cfg.Tools.Auth = config.ToolsAuthSession
		if err := checkToolsSupport(cfg); err != nil {
			t.Errorf("checkToolsSupport(session) = %v, want nil", err)
		}
	})
}

// TestToolsAccessRefusesAnUnsetPosture is the second lock on the door RS-16
// closes: toolsAccess itself, handed an empty posture, returns an error and
// never auth.ToolsPublic(). internal/config refuses the document first, so this
// branch is not a code path a deployment can reach — which is exactly why it
// is pinned: a default branch that mounted the open door would be invisible
// until the day the validator was loosened.
func TestToolsAccessRefusesAnUnsetPosture(t *testing.T) {
	t.Parallel()

	for _, posture := range []string{"", "Session", "public"} {
		cfg := config.Defaults()
		cfg.Tools.Enabled = true
		cfg.Tools.Auth = posture
		access, err := toolsAccess(cfg, nil, auth.HTTPConfig{}, nil)
		if err == nil || access != nil {
			t.Errorf("toolsAccess(%q) = %v, %v; want a refusal and no guard", posture, access, err)
			continue
		}
		if !strings.Contains(err.Error(), "tools.auth") || !strings.Contains(err.Error(), "tools.auth: none") {
			t.Errorf("toolsAccess(%q) refusal does not name the knob and the spelling of the open door: %v", posture, err)
		}
	}
}

// TestInboundWebhooksAreRefusedByDefault: a tools document that says nothing
// about inbound webhooks is refused at cold start (RS-15), and the diagnostic
// names the line to write.
func TestInboundWebhooksAreRefusedByDefault(t *testing.T) {
	t.Parallel()

	env := toolsEnv()
	delete(env, "AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS")
	_, err := New(context.Background(), Options{Getenv: envFunc(env), Logger: discardLogger(), Stores: memoryStores})
	if err == nil {
		t.Fatal("a tools block with inbound webhooks on by default came up with no script runner")
	}
	for _, want := range []string{"RS-15", "tools.inboundWebhooks.enabled: false"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%v", want, err)
		}
	}
}

// TestWebhookDefaultsFillOnlyAbsentValues: tools.outboundWebhooks.defaults reach
// a row that carries no value of its own and leave one that does alone.
func TestWebhookDefaultsFillOnlyAbsentValues(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryWebhookStore()
	two, delay := 2, 250
	for _, cfg := range []auth.WebhookConfig{
		{URL: "https://a.example.test/hook", Events: []string{"e"}},
		{URL: "https://b.example.test/hook", Events: []string{"e"}, MaxRetries: &two, RetryDelayMs: &delay},
	} {
		if _, err := store.AddWebhook(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
	}
	decorated := webhookDefaults{WebhookStore: store, maxRetries: 7, retryDelayMs: 900}
	configs, err := decorated.FindByEvent(context.Background(), "e", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 {
		t.Fatalf("got %d configs, want 2", len(configs))
	}
	if got := configs[0].Retries(); got != 7 {
		t.Errorf("row without a value retries %d times, want the deployment default 7", got)
	}
	if got := configs[0].RetryDelay(); got != 900*time.Millisecond {
		t.Errorf("row without a value waits %v, want the deployment default 900ms", got)
	}
	if got := configs[1].Retries(); got != 2 {
		t.Errorf("row with its own value retries %d times, want its own 2", got)
	}
	if got := configs[1].RetryDelay(); got != 250*time.Millisecond {
		t.Errorf("row with its own value waits %v, want its own 250ms", got)
	}
}

// TestToolsColdStartLogSaysWhatTheRuntimeDoesNotDo: the two runtime gaps and
// the unguarded posture are named at cold start.
func TestToolsColdStartLogSaysWhatTheRuntimeDoesNotDo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	app, err := New(context.Background(), Options{
		Getenv: envFunc(toolsEnv("AWESOME_AUTH_TOOLS_AUTH", "none", "AWESOME_AUTH_SSE_ENABLED", "true")),
		Logger: newLogger(&buf, slog.LevelDebug),
		Stores: memoryStores,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	out := buf.String()
	for _, want := range []string{
		"tools surface mounted",
		"tools-stream-is-not-mounted-on-api-gateway",
		"outgoing-webhook-delivery-races-the-response",
		"the tools routes are unguarded",
		"the SSE manager reaches no connection on this runtime",
		// The two knob-gap rows, by their remedies. The knob paths alone would
		// not discriminate: logToolsSurface names both paths in its own lines,
		// so a report that dropped the rows would still contain them.
		"the stream lands on a Lambda Function URL",
		"nothing here is lost, and nothing here is delivered either",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the cold-start log does not say %q:\n%s", want, out)
		}
	}
}

// TestGuardedPosturesArePricedAtColdStart: the session posture's price — any
// self-registered user reads the store-wide telemetry and attributes events to
// anyone — is a cold-start warning naming the remedy, and the apiKey posture's
// two core-inherited facts are stated. A deployment must not have to discover
// either from behaviour.
func TestGuardedPosturesArePricedAtColdStart(t *testing.T) {
	t.Parallel()

	logOf := func(t *testing.T, env map[string]string) string {
		t.Helper()
		var buf bytes.Buffer
		app, err := New(context.Background(), Options{Getenv: envFunc(env), Logger: newLogger(&buf, slog.LevelDebug), Stores: memoryStores})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(app.Close)
		return buf.String()
	}

	t.Run("session", func(t *testing.T) {
		t.Parallel()
		out := logOf(t, toolsEnv())
		for _, want := range []string{
			`"level":"WARN"`,
			"the tools routes answer any signed-in user, and anyone can sign up",
			"read every user's rows",
			"any userId in the body",
			"tools.auth: apiKey",
			"X-CSRF-Token double-submit",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the session cold start does not say %q:\n%s", want, out)
			}
		}
	})

	t.Run("apiKey", func(t *testing.T) {
		t.Parallel()
		out := logOf(t, toolsEnv("AWESOME_AUTH_TOOLS_AUTH", "apiKey", "AWESOME_AUTH_STORES_ENABLE_API_KEYS", "true"))
		for _, want := range []string{
			"the tools routes answer any active API key",
			"no scope is required",
			"tools-api-key-refusal-is-the-cores-bare-401",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the apiKey cold start does not say %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "the tools routes answer any signed-in user") {
			t.Errorf("the apiKey cold start carries the session posture's warning:\n%s", out)
		}
	})
}

// TestUnwiredKnobsIsExactlyTheDocumentedList pins the whole of unwiredKnobs
// rather than a few members of it: the list is the product's own
// anti-silent-misconfiguration mechanism, and a knob that turns up in it
// unexplained — or drops out of it unnoticed — is the failure the mechanism
// exists to prevent. Each row says why the knob is there.
func TestUnwiredKnobsIsExactlyTheDocumentedList(t *testing.T) {
	t.Parallel()

	paths := func(cfg *config.Config) []string {
		var out []string
		for _, g := range unwiredKnobs(cfg) {
			if g.Problem == "" || g.Remedy == "" {
				t.Errorf("gap %s has an empty problem or remedy", g.Path)
			}
			out = append(out, g.Path)
		}
		return out
	}

	cases := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{
			// The one gap every deployment has: RS-1 requires the second
			// secret and the core signs both tokens with the first.
			name: "the defaults",
			env:  baseEnv(),
			want: []string{"security.jwt.refreshTokenSecret"},
		},
		{
			// The tools block on this runtime adds one: the stream knob, true
			// by default, which API Gateway cannot carry (tools.go).
			name: "the tools block",
			env:  toolsEnv(),
			want: []string{"security.jwt.refreshTokenSecret", "tools.stream.enabled"},
		},
		{
			// And a second when the manager is asked for: built, listened to
			// by nobody, until D9c.
			name: "the tools block with the SSE manager",
			env:  toolsEnv("AWESOME_AUTH_SSE_ENABLED", "true"),
			want: []string{"security.jwt.refreshTokenSecret", "tools.sse.enabled", "tools.stream.enabled"},
		},
		{
			// The stream knob written off is honoured — there is nothing to
			// report about a route the operator did not ask for.
			name: "the tools block with the stream off",
			env:  toolsEnv("AWESOME_AUTH_TOOLS_STREAM", "false"),
			want: []string{"security.jwt.refreshTokenSecret"},
		},
		{
			// A tools store switched on with the block off: driverStores lists
			// it as supported, so it validates, and nothing reads it. Reported,
			// not refused (toolsKnobGaps).
			name: "a tools store with the block off",
			env: with(baseEnv(),
				"AWESOME_AUTH_STORES_ENABLE_API_KEYS", "true",
				"AWESOME_AUTH_STORES_ENABLE_TELEMETRY", "true"),
			want: []string{"security.jwt.refreshTokenSecret", "stores.enable.apiKeys", "stores.enable.telemetry"},
		},
		{
			// The API-key store under a posture that never opens it.
			name: "the apiKey store under the session posture",
			env:  toolsEnv("AWESOME_AUTH_STORES_ENABLE_API_KEYS", "true"),
			want: []string{"security.jwt.refreshTokenSecret", "stores.enable.apiKeys", "tools.stream.enabled"},
		},
		{
			// And under the posture that does: consumed, so not a gap.
			name: "the apiKey store under the apiKey posture",
			env:  toolsEnv("AWESOME_AUTH_TOOLS_AUTH", "apiKey", "AWESOME_AUTH_STORES_ENABLE_API_KEYS", "true"),
			want: []string{"security.jwt.refreshTokenSecret", "tools.stream.enabled"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(tc.env)})
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			if got := paths(cfg); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("unwiredKnobs = %v, want exactly %v", got, tc.want)
			}
		})
	}
}

// TestDriversBackTheToolsStores: both drivers expose the three stores the
// tools block consumes, structurally, so the flags driverStores lists for them
// are flags that change what the deployment does.
func TestDriversBackTheToolsStores(t *testing.T) {
	t.Parallel()

	memory := any(newMemoryStoreBundle())
	ddb, err := ddbstore.New(stubDynamoAPI{}, ddbstore.Options{TableName: "unused", Logger: discardLogger()})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	for name, store := range map[string]any{"memory": memory, "dynamodb": ddb} {
		if !asserts[telemetryStoreProvider](store) {
			t.Errorf("%s: no Telemetry() accessor", name)
		}
		if !asserts[webhookStoreProvider](store) {
			t.Errorf("%s: no Webhooks() accessor", name)
		}
		if !asserts[apiKeyStoreProvider](store) {
			t.Errorf("%s: no APIKeys() accessor", name)
		}
		if p, ok := store.(webhookStoreProvider); ok {
			if _, ok := p.Webhooks().(auth.InboundWebhookStore); !ok {
				t.Errorf("%s: the webhook store does not answer FindByProvider, so D9d would have nothing to hand the inbound route", name)
			}
		}
	}
	for _, driver := range []string{config.StoreDriverDynamoDB, config.StoreDriverMemory} {
		supported, _ := driverStores(driver)
		for _, flag := range []string{"telemetry", "webhooks", "apiKeys"} {
			if !supported[flag] {
				t.Errorf("driverStores(%s) does not list %s", driver, flag)
			}
		}
	}
}

// TestDynamoDBTelemetryRoundTrip is the tools block against the production
// store: a login bridged into a telemetry row on the day-bucketed partition,
// read back through GET <tools>/telemetry with the event-name filter, on the
// untenanted tenant. It is the one place the composition and the store's key
// design meet, and the sweep in stores_test.go does not reach the tools path.
func TestDynamoDBTelemetryRoundTrip(t *testing.T) {
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run this round trip")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()
	table := "authtest_tools_" + randomSuffix(t)
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Skipf("cannot build a DynamoDB client for %s: %v", endpoint, err)
	}
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Skipf("cannot create %s at %s (%v)", table, endpoint, err)
	}

	app, err := New(ctx, Options{
		Getenv: envFunc(toolsEnv(
			"AWESOME_AUTH_STORES_DRIVER", config.StoreDriverDynamoDB,
			"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", table,
			"AWESOME_AUTH_STORES_CONNECTION_REGION", "us-east-1",
			"AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", endpoint,
		)),
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("New with the dynamodb driver: %v", err)
	}
	t.Cleanup(app.Close)

	creds := registerAndToken(t, app, testEmail)
	bearer := jsonHeaders("authorization", "Bearer "+creds.accessToken)
	login := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(), nil, registerBody(testEmail))
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login = %d %s", login.StatusCode, login.Body)
	}

	q := invoke(t, app, http.MethodGet, "/tools/telemetry?event="+auth.EventAuthLoginSuccess, bearer, nil, "")
	if q.StatusCode != http.StatusOK {
		t.Fatalf("telemetry = %d %s", q.StatusCode, q.Body)
	}
	data, _ := decodeBody(t, q)["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("telemetry holds %d row(s) for the login, want exactly one: %s", len(data), q.Body)
	}

	// And a tracked event, which is the route writing rather than the bridge.
	var n atomic.Int32
	for i := 0; i < 3; i++ {
		resp := invoke(t, app, http.MethodPost, "/tools/track/ddb.probe", bearer, nil, fmt.Sprintf(`{"data":{"i":%d}}`, i))
		if resp.StatusCode == http.StatusAccepted {
			n.Add(1)
		}
	}
	q = invoke(t, app, http.MethodGet, "/tools/telemetry?event=ddb.probe&limit=10", bearer, nil, "")
	data, _ = decodeBody(t, q)["data"].([]any)
	if int32(len(data)) != n.Load() || n.Load() != 3 {
		t.Errorf("tracked %d events and the store holds %d", n.Load(), len(data))
	}
	var rows []map[string]any
	_ = json.Unmarshal([]byte(q.Body), &struct {
		Data *[]map[string]any `json:"data"`
	}{Data: &rows})
	for _, row := range rows {
		if row["event"] != "ddb.probe" {
			t.Errorf("row %v is not the tracked event", row)
		}
	}
}

// lockedBuffer is a bytes.Buffer safe to read while a detached goroutine — an
// outgoing webhook delivery, here — is still writing log lines into it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
