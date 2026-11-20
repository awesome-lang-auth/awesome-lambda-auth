package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The origin check (origin_verify.go), driven through New and the Lambda event
// path, with the secret's two rotation stages served by a fake that stands in
// for Secrets Manager. Each value below is distinct and long enough for the
// 32-character floor, so a test that accepts one cannot pass on another.
const (
	testOriginARN      = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:auth/origin-verify-AbCdEf"
	testOriginCurrent  = "origin-current-7f3a9c1e5b2d4f6a8c0e2b4d6f8a1c3e"
	testOriginPrevious = "origin-previous-0a2c4e6f8b1d3f5a7c9e1b3d5f7a9c2e"
	testOriginWrong    = "origin-wrong-5e7a9c1b3d5f7a9c2e4b6d8f0a1c3e5f7a"
	testOriginRotated  = "origin-rotated-9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a"
)

// fakeOriginSecret serves SecretStages the way the Secrets Manager reader would,
// and can be rotated, broken and counted while an App is serving.
type fakeOriginSecret struct {
	mu     sync.Mutex
	stages awsintegration.SecretStages
	err    error
	reads  int
	arns   []string
}

func newFakeOriginSecret(current, previous string) *fakeOriginSecret {
	return &fakeOriginSecret{stages: awsintegration.SecretStages{Current: current, Previous: previous}}
}

func (f *fakeOriginSecret) read(_ context.Context, arn string) (awsintegration.SecretStages, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	f.arns = append(f.arns, arn)
	if f.err != nil {
		return awsintegration.SecretStages{}, f.err
	}
	return f.stages, nil
}

func (f *fakeOriginSecret) set(current, previous string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stages = awsintegration.SecretStages{Current: current, Previous: previous}
	f.err = err
}

func (f *fakeOriginSecret) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// originEnv is baseEnv with the check switched on.
func originEnv(kv ...string) map[string]string {
	return with(baseEnv(), append([]string{"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN", testOriginARN}, kv...)...)
}

func newOriginApp(t *testing.T, env map[string]string, secret *fakeOriginSecret, log *slog.Logger) *App {
	t.Helper()
	if log == nil {
		log = discardLogger()
	}
	app, err := New(context.Background(), Options{Getenv: envFunc(env), Logger: log, Stores: memoryStores, OriginSecret: secret.read})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

// assertBareRefusal is what origin-verify-refusal-is-a-bare-403 promises: the
// status, and nothing else at all — no body, no header of any kind, no cookie.
// A route's own 403 carries a JSON body, and the CORS layer would have added
// Vary, so either reaching the response is visible here.
func assertBareRefusal(t *testing.T, what string, resp events.APIGatewayV2HTTPResponse) {
	t.Helper()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("%s = %d, want the origin check's 403 (body %q)", what, resp.StatusCode, resp.Body)
		return
	}
	if resp.Body != "" || len(resp.Headers) != 0 || len(resp.MultiValueHeaders) != 0 || len(resp.Cookies) != 0 {
		t.Errorf("%s is a 403 that is not bare: body %q, headers %v, cookies %v", what, resp.Body, resp.Headers, resp.Cookies)
	}
}

// TestOriginVerifyIsOffByDefault: with no secretArn nothing is read, nothing is
// refused and a request carrying the header is served as any other, which is
// every deployment before this block.
func TestOriginVerifyIsOffByDefault(t *testing.T) {
	t.Parallel()
	read := func(context.Context, string) (awsintegration.SecretStages, error) {
		t.Error("the origin secret was read on a deployment that names none")
		return awsintegration.SecretStages{}, errors.New("unreachable")
	}
	app, err := New(context.Background(), Options{Getenv: envFunc(baseEnv()), Logger: discardLogger(), Stores: memoryStores, OriginSecret: read})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	if app.origin != nil {
		t.Error("an origin check was built with no secretArn")
	}
	for _, headers := range []map[string]string{nil, {"x-origin-verify": testOriginWrong}} {
		if resp := invoke(t, app, http.MethodGet, "/healthz", headers, nil, ""); resp.StatusCode != http.StatusOK {
			t.Errorf("GET /healthz with headers %v = %d, want 200", headers, resp.StatusCode)
		}
	}
}

// TestOriginVerifyRefusesWhatDidNotComeThroughTheFrontDoor is the check itself,
// through the event path the Lambda runtime drives: missing, empty, wrong,
// repeated and rotated-out values are a bare 403 on every route — a preflight,
// register and the readiness probe included — and the current and the previous
// value reach the route behind it, which answers in its own way.
func TestOriginVerifyRefusesWhatDidNotComeThroughTheFrontDoor(t *testing.T) {
	t.Parallel()
	const origin = "https://app.example.test"
	secret := newFakeOriginSecret(testOriginCurrent, testOriginPrevious)
	app := newOriginApp(t, originEnv("AWESOME_AUTH_CORS_ORIGINS", origin), secret, nil)
	if n := secret.readCount(); n != 1 || secret.arns[0] != testOriginARN {
		t.Fatalf("cold start read the secret %d time(s), as %v; want once, as %s", n, secret.arns, testOriginARN)
	}

	preflight := func(value string) map[string]string {
		h := map[string]string{"origin": origin, "access-control-request-method": http.MethodPost}
		if value != "" {
			h["x-origin-verify"] = value
		}
		return h
	}
	refused := []struct {
		name, method, path string
		headers            map[string]string
		body               string
	}{
		{"no header", http.MethodGet, "/healthz", nil, ""},
		{"an empty value", http.MethodGet, "/healthz", map[string]string{"x-origin-verify": ""}, ""},
		{"a wrong value", http.MethodGet, "/healthz", map[string]string{"x-origin-verify": testOriginWrong}, ""},
		{"the current value as a prefix", http.MethodGet, "/healthz", map[string]string{"x-origin-verify": testOriginCurrent[:40]}, ""},
		// API Gateway joins a repeated header into one comma-separated value.
		{"the current value twice", http.MethodGet, "/healthz", map[string]string{"x-origin-verify": testOriginCurrent + "," + testOriginCurrent}, ""},
		{"login with no header", http.MethodPost, "/auth/login", jsonHeaders(), `{"email":"a@example.test","password":"x"}`},
		{"register with no header", http.MethodPost, "/auth/register", jsonHeaders(), registerBody("front-door@example.test")},
		{"me with a wrong value", http.MethodGet, "/auth/me", map[string]string{"x-origin-verify": testOriginWrong}, ""},
		{"a preflight with no header", http.MethodOptions, "/auth/login", preflight(""), ""},
		{"a preflight with a wrong value", http.MethodOptions, "/auth/login", preflight(testOriginWrong), ""},
	}
	for _, tc := range refused {
		assertBareRefusal(t, tc.name+" ("+tc.method+" "+tc.path+")", invoke(t, app, tc.method, tc.path, tc.headers, nil, tc.body))
	}

	for _, value := range []string{testOriginCurrent, testOriginPrevious, " " + testOriginCurrent + "\t"} {
		h := map[string]string{"x-origin-verify": value}
		if resp := invoke(t, app, http.MethodGet, "/healthz", h, nil, ""); resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, `"ok"`) {
			t.Errorf("GET /healthz with an accepted value = %d %q, want the probe's 200", resp.StatusCode, resp.Body)
		}
		// A guarded route answers in its own way — its own 403, with its own
		// JSON body — which is what tells it apart from the bare refusal.
		if resp := invoke(t, app, http.MethodGet, "/auth/me", h, nil, ""); resp.Body == "" {
			t.Errorf("GET /auth/me with an accepted value = %d with no body: the request stopped at the origin check", resp.StatusCode)
		}
		pre := invoke(t, app, http.MethodOptions, "/auth/login", preflight(value), nil, "")
		if pre.StatusCode != http.StatusNoContent || pre.Headers["Access-Control-Allow-Origin"] != origin {
			t.Errorf("a preflight with an accepted value = %d %v, want the CORS layer's 204 for the allow-listed origin", pre.StatusCode, pre.Headers)
		}
	}
	// The register route is reached, and registers, with the header.
	reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders("x-origin-verify", testOriginCurrent), nil, registerBody("front-door@example.test"))
	if reg.StatusCode != http.StatusCreated {
		t.Errorf("register through the front door = %d %s, want 201", reg.StatusCode, reg.Body)
	}
	if n := secret.readCount(); n != 1 {
		t.Errorf("the secret was read %d times for one cold start and a handful of requests inside the refresh interval, want once", n)
	}
}

// TestOriginVerifyTakesExactlyOneValue: a request with two header lines is
// refused whatever they hold, and the name matches in any case.
func TestOriginVerifyTakesExactlyOneValue(t *testing.T) {
	t.Parallel()
	app := newOriginApp(t, originEnv(), newFakeOriginSecret(testOriginCurrent, testOriginPrevious), nil)
	for _, tc := range []struct {
		name   string
		values []string
		want   int
	}{
		{"current twice", []string{testOriginCurrent, testOriginCurrent}, http.StatusForbidden},
		{"current and previous", []string{testOriginCurrent, testOriginPrevious}, http.StatusForbidden},
		{"wrong and current", []string{testOriginWrong, testOriginCurrent}, http.StatusForbidden},
		{"current alone", []string{testOriginCurrent}, http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header["X-Origin-Verify"] = append(req.Header["X-Origin-Verify"], tc.values...)
		rec := httptest.NewRecorder()
		app.Handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("x-ORIGIN-verify", testOriginCurrent)
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("the header in another case = %d, want 200", rec.Code)
	}
}

// TestOriginVerifyExemptsHealthzOnlyWhenAsked: by default the probe is behind
// the front door like every route; with exemptHealthz, GET and HEAD /healthz —
// and nothing else — answer without the header.
func TestOriginVerifyExemptsHealthzOnlyWhenAsked(t *testing.T) {
	t.Parallel()
	secret := newFakeOriginSecret(testOriginCurrent, "")
	strict := newOriginApp(t, originEnv(), secret, nil)
	assertBareRefusal(t, "GET /healthz without exemptHealthz", invoke(t, strict, http.MethodGet, "/healthz", nil, nil, ""))

	exempt := newOriginApp(t, originEnv("AWESOME_AUTH_HTTP_ORIGIN_VERIFY_EXEMPT_HEALTHZ", "true"), secret, nil)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		if resp := invoke(t, exempt, method, "/healthz", nil, nil, ""); resp.StatusCode != http.StatusOK {
			t.Errorf("%s /healthz with exemptHealthz = %d, want 200", method, resp.StatusCode)
		}
	}
	assertBareRefusal(t, "POST /healthz with exemptHealthz", invoke(t, exempt, http.MethodPost, "/healthz", nil, nil, ""))
	assertBareRefusal(t, "GET /auth/me with exemptHealthz", invoke(t, exempt, http.MethodGet, "/auth/me", nil, nil, ""))
	assertBareRefusal(t, "GET /healthz/ with exemptHealthz", invoke(t, exempt, http.MethodGet, "/healthz/", nil, nil, ""))
}

// TestOriginVerifyStripsTheHeader: nothing behind the check sees the front
// door's secret, the exempt probe included, and the caller's request is not
// the one modified.
func TestOriginVerifyStripsTheHeader(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(originEnv(
		"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER", "X-Edge-Secret",
		"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_EXEMPT_HEALTHZ", "true"))})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v, err := newOriginVerifier(context.Background(), cfg, newFakeOriginSecret(testOriginCurrent, "").read, discardLogger())
	if err != nil {
		t.Fatalf("newOriginVerifier: %v", err)
	}
	var seen []string
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-Edge-Secret"))
		w.WriteHeader(http.StatusNoContent)
	})
	for _, path := range []string{"/auth/login", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Edge-Secret", testOriginCurrent)
		rec := httptest.NewRecorder()
		v.gate(probe).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("GET %s with the current value = %d, want the probe's 204", path, rec.Code)
		}
		if req.Header.Get("X-Edge-Secret") != testOriginCurrent {
			t.Errorf("GET %s: the caller's request lost its header; the check must strip a copy", path)
		}
	}
	for i, got := range seen {
		if got != "" {
			t.Errorf("request %d reached the handler with the header still on it", i)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("the probe saw %d requests, want 2", len(seen))
	}
}

// originClock is a clock a test moves by hand.
type originClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *originClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *originClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestOriginVerifyFollowsARotation walks two rotations, a failed refresh and a
// bad value through the refresh interval on a hand-moved clock: a new value is
// accepted from the first refresh after the rotation and not before, the
// value it replaced stays accepted as the previous one until the next
// rotation, and a refresh that cannot read the secret — or reads one that is
// not usable — keeps what was held, never less and never more, and tries again
// after the retry interval rather than on every request.
func TestOriginVerifyFollowsARotation(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(originEnv())})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	clock := &originClock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	secret := newFakeOriginSecret(testOriginCurrent, "")
	v, err := newOriginVerifierAt(context.Background(), cfg, secret.read, discardLogger(), clock.now)
	if err != nil {
		t.Fatalf("newOriginVerifier: %v", err)
	}
	ok := v.gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	status := func(value string) int {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set(config.DefaultOriginVerifyHeader, value)
		rec := httptest.NewRecorder()
		ok.ServeHTTP(rec, req)
		return rec.Code
	}
	expect := func(step string, reads int, accepted, refused []string) {
		t.Helper()
		for _, value := range accepted {
			if got := status(value); got != http.StatusNoContent {
				t.Errorf("%s: %s... = %d, want it accepted", step, value[:16], got)
			}
		}
		for _, value := range refused {
			if got := status(value); got != http.StatusForbidden {
				t.Errorf("%s: %s... = %d, want it refused", step, value[:16], got)
			}
		}
		if got := secret.readCount(); got != reads {
			t.Errorf("%s: the secret has been read %d times, want %d", step, got, reads)
		}
	}

	expect("cold start", 1, []string{testOriginCurrent}, []string{testOriginPrevious, testOriginRotated, testOriginWrong})

	// Rotated in Secrets Manager; this environment has not re-read it yet.
	// That is the window §19.3 asks the operator to wait out before the front
	// door switches.
	secret.set(testOriginRotated, testOriginCurrent, nil)
	clock.advance(originSecretRefreshInterval - time.Second)
	expect("rotated, inside the interval", 1, []string{testOriginCurrent}, []string{testOriginRotated})

	clock.advance(time.Second)
	expect("rotated, after the interval", 2, []string{testOriginRotated, testOriginCurrent}, []string{testOriginWrong})

	// The second rotation retires the first value.
	secret.set(testOriginPrevious, testOriginRotated, nil)
	clock.advance(originSecretRefreshInterval)
	expect("rotated again", 3, []string{testOriginPrevious, testOriginRotated}, []string{testOriginCurrent})

	// Secrets Manager is unreachable: what is held stays, and the next read is
	// one retry interval away, not one request away.
	secret.set("", "", errors.New("AccessDeniedException: not authorized"))
	clock.advance(originSecretRefreshInterval)
	expect("refresh failed", 4, []string{testOriginPrevious, testOriginRotated}, []string{testOriginCurrent, testOriginWrong})
	clock.advance(originSecretRetryInterval - time.Second)
	expect("inside the retry interval", 4, []string{testOriginPrevious}, nil)
	clock.advance(time.Second)
	expect("retried, still failing", 5, []string{testOriginPrevious, testOriginRotated}, []string{testOriginWrong})

	// A rotation to a value too short to accept is a failed refresh, too.
	secret.set("short", testOriginPrevious, nil)
	clock.advance(originSecretRetryInterval)
	expect("rotated to an unusable value", 6, []string{testOriginPrevious, testOriginRotated}, []string{"short-and-not-the-secret-padding-padding"})

	// Back: the refresh replaces both values at once.
	secret.set(testOriginWrong, testOriginPrevious, nil)
	clock.advance(originSecretRetryInterval)
	expect("recovered", 7, []string{testOriginWrong, testOriginPrevious}, []string{testOriginRotated})

	// A request with no header triggers no read, however stale the values.
	clock.advance(time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	ok.ServeHTTP(httptest.NewRecorder(), req)
	if got := secret.readCount(); got != 7 {
		t.Errorf("a request without the header read the secret (%d reads, want 7)", got)
	}
}

// TestOriginVerifyRefreshesOnTheWallClock: on the real clock, the refresh
// deadline carries no monotonic reading, so it is compared against elapsed
// wall time and not against a monotonic clock that need not advance while an
// idle execution environment is frozen. A failed refresh's retry deadline is
// held to the same rule. (originClock above uses time.Date, which has no
// monotonic reading either way, so only this test can see the difference.)
func TestOriginVerifyRefreshesOnTheWallClock(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(originEnv())})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	secret := newFakeOriginSecret(testOriginCurrent, "")
	v, err := newOriginVerifier(context.Background(), cfg, secret.read, discardLogger())
	if err != nil {
		t.Fatalf("newOriginVerifier: %v", err)
	}
	monotonic := func(when time.Time) bool { return strings.Contains(when.String(), " m=") }
	if at := v.secrets.Load().refreshAt; monotonic(at) || at.Before(time.Now().Add(originSecretRefreshInterval-time.Minute)) {
		t.Errorf("refreshAt = %s, want a wall-clock time one interval away", at)
	}

	// Due now, and the read fails: the retry deadline is wall-clock too.
	due := *v.secrets.Load()
	due.refreshAt = time.Now().Add(-time.Second).Round(0)
	v.secrets.Store(&due)
	secret.set("", "", errors.New("ThrottlingException: rate exceeded"))
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set(config.DefaultOriginVerifyHeader, testOriginCurrent)
	if ok, why := v.admits(req); !ok {
		t.Fatalf("the held value was refused during a failed refresh (%s)", why)
	}
	if at := v.secrets.Load().refreshAt; monotonic(at) || !at.After(time.Now()) {
		t.Errorf("after a failed refresh refreshAt = %s, want a wall-clock time in the future", at)
	}
	if n := secret.readCount(); n != 2 {
		t.Errorf("the secret was read %d times, want 2 (cold start, failed refresh)", n)
	}
}

// TestOriginVerifyRefusesToStartWithoutAUsableSecret: a current value that
// cannot be read, or cannot be accepted, fails the cold start with the knob's
// path and without the value; a previous value that cannot be accepted only
// costs the previous value, and says so.
func TestOriginVerifyRefusesToStartWithoutAUsableSecret(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		secret  *fakeOriginSecret
		wantErr string
		value   string
	}{
		{"unreadable", &fakeOriginSecret{err: errors.New("secretsmanager: reading the secret at AWSCURRENT failed: AccessDeniedException")}, "AccessDeniedException", ""},
		{"empty", newFakeOriginSecret("", ""), "at least 32", ""},
		{"too short", newFakeOriginSecret("short-front-door-secret", ""), "at least 32", "short-front-door-secret"},
		{"not visible ASCII", newFakeOriginSecret("origin current with spaces in the middle of it", ""), "visible ASCII", "origin current with spaces in the middle of it"},
		{"not ASCII at all", newFakeOriginSecret("origin-current-è-0f9e8d7c6b5a49382716051f2e", ""), "visible ASCII", "origin-current-è-0f9e8d7c6b5a49382716051f2e"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(context.Background(), Options{Getenv: envFunc(originEnv()), Logger: discardLogger(), Stores: memoryStores, OriginSecret: tc.secret.read})
			if err == nil {
				t.Fatal("New started with no usable origin secret")
			}
			for _, want := range []string{"http.originVerify.secretArn", "refusing to start", tc.wantErr} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want it to say %q", err, want)
				}
			}
			if tc.value != "" && strings.Contains(err.Error(), tc.value) {
				t.Errorf("the error carries the secret's value: %v", err)
			}
		})
	}

	t.Run("an unusable previous value", func(t *testing.T) {
		t.Parallel()
		for _, secret := range []*fakeOriginSecret{
			newFakeOriginSecret(testOriginCurrent, "too-short"),
			{stages: awsintegration.SecretStages{Current: testOriginCurrent, PreviousProblem: "AWSPREVIOUS: the stored value is not a JSON object"}},
		} {
			var buf bytes.Buffer
			app := newOriginApp(t, originEnv(), secret, newLogger(&buf, slog.LevelDebug))
			if resp := invoke(t, app, http.MethodGet, "/healthz", map[string]string{"x-origin-verify": testOriginCurrent}, nil, ""); resp.StatusCode != http.StatusOK {
				t.Errorf("the current value = %d, want 200", resp.StatusCode)
			}
			assertBareRefusal(t, "the unusable previous value", invoke(t, app, http.MethodGet, "/healthz", map[string]string{"x-origin-verify": "too-short"}, nil, ""))
			if !strings.Contains(buf.String(), "previous value is not accepted") {
				t.Errorf("the cold start did not say the previous value is refused:\n%s", buf.String())
			}
			if strings.Contains(buf.String(), `"too-short"`) {
				t.Errorf("the log carries the previous value:\n%s", buf.String())
			}
		}
	})
}

// TestOriginVerifyHoldsTheSSEFunctionToTheFrontDoor: the check is outermost on
// the SSE function too, so its Function URL refuses what did not come through
// the front door before the path gate, the guard or the event log see the
// request, and opens the stream for the current and the previous value.
func TestOriginVerifyHoldsTheSSEFunctionToTheFrontDoor(t *testing.T) {
	counter := &sseQueryCounter{}
	factory, table, endpoint := sseTableWith(t, func(api ddbstore.API) ddbstore.API { counter.API = api; return counter })
	authApp := newSseApp(t, sseEnv(table, endpoint), factory)
	token := registerAndToken(t, authApp, "sse-origin-"+randomSuffix(t)+"@example.test").accessToken

	secret := newFakeOriginSecret(testOriginCurrent, testOriginPrevious)
	streamApp, err := New(context.Background(), Options{
		Getenv: envFunc(sseEnv(table, endpoint,
			EntrypointEnv, entrypointStream,
			"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN", testOriginARN)),
		Logger:       discardLogger(),
		Stores:       factory,
		OriginSecret: secret.read,
	})
	if err != nil {
		t.Fatalf("New (SSE function): %v", err)
	}
	t.Cleanup(streamApp.Close)

	// The Function URL handler, as the Lambda runtime drives it.
	call := func(method, path, rawQuery string, headers map[string]string) (*events.LambdaFunctionURLStreamingResponse, string) {
		t.Helper()
		evt := &events.LambdaFunctionURLRequest{RawPath: path, RawQueryString: rawQuery, Headers: headers}
		evt.RequestContext.HTTP.Method = method
		evt.RequestContext.HTTP.Path = path
		evt.RequestContext.HTTP.SourceIP = "198.51.100.7"
		evt.RequestContext.DomainName = "sse.lambda-url.eu-west-1.on.aws"
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := streamApp.StreamHandler()(ctx, evt)
		if err != nil {
			t.Fatalf("stream handler: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	tools := toolsPath(streamApp.Config)
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"no header", nil},
		{"a wrong value", map[string]string{"x-origin-verify": testOriginWrong}},
		{"the current value twice", map[string]string{"x-origin-verify": testOriginCurrent + "," + testOriginCurrent}},
	} {
		resp, body := call(http.MethodGet, tools+"/stream", "token="+token, tc.headers)
		if resp.StatusCode != http.StatusForbidden || body != "" || len(resp.Headers) != 0 || len(resp.Cookies) != 0 {
			t.Errorf("GET %s/stream with %s = %d %q %v, want the bare 403", tools, tc.name, resp.StatusCode, body, resp.Headers)
		}
	}
	if n := counter.count(); n != 0 {
		t.Errorf("%d event-log Queries for streams the origin check refused: it ran after the guard", n)
	}

	// Through the check, the path gate behind it answers as it always has.
	if resp, _ := call(http.MethodPost, "/auth/login", "", map[string]string{"x-origin-verify": testOriginCurrent}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /auth/login on the SSE function with the current value = %d, want the path gate's 404", resp.StatusCode)
	}

	for _, value := range []string{testOriginCurrent, testOriginPrevious} {
		_, frames, stop := openStream(t, streamApp, "token="+token, map[string]string{"x-origin-verify": value})
		if f := nextFrame(t, frames, "the connected frame"); f.event != "connected" {
			t.Errorf("the stream opened with an accepted value began with %+v, want the connected frame", f)
		}
		stop()
	}
}

// TestNoOriginSecretReachesTheLog extends delivery_test.go's
// TestNoCredentialReachesTheLog to the credential this block introduces: the
// front door's secret, current and previous, a wrong value a caller presented,
// and the value a rotation brought in — through the cold start, refusals,
// admitted requests, a refresh that reads a rotation and a refresh that fails.
// The logger is at Debug, so the refusal's own line is written too. A renamed
// header is on the deny-list for every line the App writes from cold start on.
func TestNoOriginSecretReachesTheLog(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	secret := newFakeOriginSecret(testOriginCurrent, testOriginPrevious)
	app := newOriginApp(t, originEnv("AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER", "X-Edge-Secret"), secret, newLogger(&buf, slog.LevelDebug))

	for _, value := range []string{"", testOriginWrong, testOriginPrevious, testOriginCurrent} {
		h := jsonHeaders()
		if value != "" {
			h["x-edge-secret"] = value
		}
		invoke(t, app, http.MethodGet, "/healthz", h, nil, "")
		invoke(t, app, http.MethodPost, "/auth/login", h, nil, `{"email":"quiet-origin@example.test","password":"x"}`)
	}

	// A rotation, read by a refresh, and then a refresh that fails.
	clock := &originClock{t: time.Now()}
	app.origin.now = clock.now
	secret.set(testOriginRotated, testOriginCurrent, nil)
	clock.advance(originSecretRefreshInterval + time.Second)
	if resp := invoke(t, app, http.MethodGet, "/healthz", map[string]string{"x-edge-secret": testOriginRotated}, nil, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("the rotated value after a refresh = %d, want 200", resp.StatusCode)
	}
	secret.set("", "", errors.New("AccessDeniedException: not authorized to perform secretsmanager:GetSecretValue"))
	clock.advance(originSecretRefreshInterval + time.Second)
	invoke(t, app, http.MethodGet, "/healthz", map[string]string{"x-edge-secret": testOriginRotated}, nil, "")

	// Something downstream that logs the header by name gets it redacted,
	// however it spells the key and wherever it puts the attribute.
	const canary = "origin-canary-3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a"
	app.Logger.Info("probe", slog.String("X-Edge-Secret", canary), slog.Group("request", slog.String("x-edge-secret", canary)))
	app.Logger.With(slog.String("X-EDGE-SECRET", canary)).Info("probe")
	app.Logger.Info("probe", slog.String(config.DefaultOriginVerifyHeader, canary))

	out := buf.String()
	for _, line := range []string{
		"origin verification on",
		"origin verification refused a request",
		"could not be re-read",
		`"http request"`,
	} {
		if !strings.Contains(out, line) {
			t.Fatalf("the log has no %q line, so this test proves less than it claims:\n%s", line, out)
		}
	}
	for name, value := range map[string]string{
		"current": testOriginCurrent, "previous": testOriginPrevious,
		"wrong": testOriginWrong, "rotated": testOriginRotated, "canary": canary,
	} {
		if strings.Contains(out, value) {
			t.Errorf("the %s value appears in the log:\n%s", name, out)
		}
	}
	if !IsRedactedLogKey(config.DefaultOriginVerifyHeader) {
		t.Errorf("%s is not on the static deny-list", config.DefaultOriginVerifyHeader)
	}
}
