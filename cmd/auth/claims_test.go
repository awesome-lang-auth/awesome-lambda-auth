package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// The claims tests drive the real HTTP surface with a real receiver, for the
// reason the delivery tests do: what is interesting is not that claimsOptions
// returns an option, but that a claim written in a document comes back out of a
// token a client can decode, and that a receiver that is down takes the login
// down with it rather than issuing a token with fewer claims than the
// deployment configured.
//
// Nothing here imports the core's claim helpers to check its own expectation.
// The claim values are literals, the token is decoded by splitting on "." and
// base64url-decoding the middle segment the way any client does, and the
// webhook signature is recomputed from the secret and the exact bytes.

const (
	// The signing secret of the claims webhook. Distinctive enough that a log
	// assertion searching for it cannot match by accident.
	testClaimsSecret = "claims-webhook-signing-secret-0123456789"
	// A receiver nothing ever posts to, for the tests that only need a claims
	// webhook to be configured.
	testClaimsURL = "https://claims.example.test/hook"
)

// ── the receiver ─────────────────────────────────────────────────────────────

// claimsRequest is one request the receiver took, kept whole: the signature is
// over the exact bytes, so nothing here may be re-encoded.
type claimsRequest struct {
	body    []byte
	headers http.Header
}

// claimsReceiver is the endpoint security.jwt.claimsWebhook.url names. TLS,
// because the schema refuses a claims webhook that is not https — which is also
// why Options.HTTPClient exists: this certificate is trusted by this test and
// by nothing else.
type claimsReceiver struct {
	srv *httptest.Server

	hits atomic.Int64

	mu       sync.Mutex
	got      []claimsRequest
	claims   map[string]any
	hangFor  time.Duration
	status   int
	rawBody  []byte // when set, answered instead of the claims envelope
	padBytes int    // when >0, an oversized claims value
}

func newClaimsReceiver(t *testing.T, claims map[string]any) *claimsReceiver {
	t.Helper()
	r := &claimsReceiver{claims: claims, status: http.StatusOK}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.hits.Add(1)

		r.mu.Lock()
		r.got = append(r.got, claimsRequest{body: body, headers: req.Header.Clone()})
		hang, status, raw, pad := r.hangFor, r.status, r.rawBody, r.padBytes
		claims := r.claims
		r.mu.Unlock()

		if hang > 0 {
			select {
			case <-time.After(hang):
			case <-req.Context().Done():
				// The client gave up: its timeout is what that test is about.
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if raw != nil {
			_, _ = w.Write(raw)
			return
		}
		out := map[string]any{}
		for k, v := range claims {
			out[k] = v
		}
		if pad > 0 {
			out["padding"] = strings.Repeat("x", pad)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"claims": out})
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *claimsReceiver) requests() []claimsRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]claimsRequest(nil), r.got...)
}

func (r *claimsReceiver) set(mutate func(*claimsReceiver)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	mutate(r)
}

// claimsEnv turns the claims webhook on the way the schema requires it: the
// receiver's url and the secret that signs every request together, because
// internal/config refuses either without the other.
func claimsEnv(base map[string]string, url string, extra ...string) map[string]string {
	return with(with(base,
		"AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_URL", url,
		"AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET", testClaimsSecret,
	), extra...)
}

// extraClaimsDoc is the configuration document that carries an extraClaims
// table. The table is a map of objects, so it is file-only by design and there
// is no environment form of it (config-schema.md §1.1).
func extraClaimsDoc(entries string) string {
	return fmt.Sprintf(`{"schemaVersion": 1, "security": {"jwt": {"extraClaims": %s}}}`, entries)
}

// ── decoding a token the way a client does ───────────────────────────────────

// jwsPayload splits a compact JWS and decodes the claims segment. It is
// deliberately hand-rolled: the assertion is that a shipped client, which has
// no access to this repository, can read the claim out of the token, and a
// client does exactly this.
func jwsPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a three-part JWS (%d segments): %q", len(parts), token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("token payload is not base64url: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("token payload is not a JSON object: %v (%s)", err, raw)
	}
	return claims
}

// bearerTokens registers an account, logs it in in bearer mode and returns the
// pair of tokens the login's body carries.
func bearerTokens(t *testing.T, app *App, email string) (access, refresh string) {
	t.Helper()
	resp := registerAndLogin(t, app, jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), email)
	body := decodeBody(t, resp)
	access, _ = body["accessToken"].(string)
	refresh, _ = body["refreshToken"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("bearer login returned no token pair: %s", resp.Body)
	}
	return access, refresh
}

// ── the mapping table ────────────────────────────────────────────────────────

// TestExtraClaimsReachBothTokens is the whole claim of the declarative half:
// what a document says goes into a token comes back out of one, in both forms
// the table has, and on the refresh token as well as the access token.
//
// Both tokens matter because they are minted by the same call and a client
// keeps the refresh token far longer: a deployment whose authorisation depends
// on a claim would have it disappear at the first refresh if only the access
// token carried it. The core mints them through one issueToken, so this is a
// pin rather than a suspicion — but it is a pin on wire behaviour a client can
// see, which is the kind this suite keeps.
func TestExtraClaimsReachBothTokens(t *testing.T) {
	t.Parallel()

	doc := extraClaimsDoc(`{
		"tenant":   {"fromUserField": "tenantId"},
		"verified": {"fromUserField": "isEmailVerified"},
		"plan":     {"const": "enterprise"},
		"seats":    {"const": 25}
	}`)
	app := newTestApp(t, with(baseEnv(), ConfigJSONEnv, doc))

	access, refresh := bearerTokens(t, app, "claims@example.test")

	for _, tc := range []struct{ name, token string }{
		{"access", access},
		{"refresh", refresh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwsPayload(t, tc.token)

			// A constant lands verbatim, including its JSON type: a number
			// written as a number must not arrive as a string.
			if got := claims["plan"]; got != "enterprise" {
				t.Errorf("plan = %#v, want %q", got, "enterprise")
			}
			if got, ok := claims["seats"].(float64); !ok || got != 25 {
				t.Errorf("seats = %#v, want the number 25", claims["seats"])
			}
			// A mapped field is emitted whether or not it has a value: a
			// mapping declares that the claim exists, and a consumer must be
			// able to tell "not configured" from "empty".
			if _, present := claims["tenant"]; !present {
				t.Errorf("tenant is absent; a mapped claim is emitted on every token: %v", keysOfClaims(claims))
			}
			if got, ok := claims["verified"].(bool); !ok || !got {
				t.Errorf("verified = %#v, want the boolean true (this build registers verified accounts)", claims["verified"])
			}
			// And the session claims are still the core's own.
			for _, reserved := range []string{"sub", "sid", "typ", "iss", "iat", "exp"} {
				if _, present := claims[reserved]; !present {
					t.Errorf("%s is missing from the payload: %v", reserved, keysOfClaims(claims))
				}
			}
		})
	}

	if got := jwsPayload(t, access)["typ"]; got != "access" {
		t.Errorf("access token typ = %v, want \"access\"", got)
	}
	if got := jwsPayload(t, refresh)["typ"]; got != "refresh" {
		t.Errorf("refresh token typ = %v, want \"refresh\"", got)
	}
}

// TestExtraClaimsCannotNameABaseOrReservedClaim: a claim name that could never
// reach a token is a document fault, and a document fault refuses the
// deployment with the path to edit.
//
// The two halves are refused in different places and both are checked here,
// because an operator does not care which layer caught it and both must name
// the same dotted path:
//
//   - The six base claims are validate.go's: the family's clients read sub,
//     email, role, loginProvider, isEmailVerified and isTotpEnabled off every
//     token, so redefining one is refused even though the core would allow it.
//   - The seven session claims are claims.go's, by asking the core's own
//     UserFieldClaims about the name rather than keeping a copy of the list.
//     issueToken writes them after the merge, so such an entry would be
//     discarded silently on every mint — the exact failure the whole
//     unwired-knob machinery exists to prevent.
//
// A field outside the core's allowlist is the third case: the mapping is
// configuration and a typo in configuration must fail at startup rather than
// turn every login into a 500.
func TestExtraClaimsCannotNameABaseOrReservedClaim(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		entries string
		path    string
	}{
		{"a base claim", `{"email": {"const": "spoofed@example.test"}}`, "security.jwt.extraClaims.email"},
		{"a base claim from a user field", `{"role": {"fromUserField": "id"}}`, "security.jwt.extraClaims.role"},
		{"a reserved session claim as a constant", `{"typ": {"const": "access"}}`, "security.jwt.extraClaims.typ"},
		{"a reserved session claim from a user field", `{"sid": {"fromUserField": "id"}}`, "security.jwt.extraClaims.sid"},
		{"the issuer claim", `{"iss": {"const": "https://evil.example.test"}}`, "security.jwt.extraClaims.iss"},
		{"an unknown user field", `{"secretHash": {"fromUserField": "passwordHash"}}`, "security.jwt.extraClaims.secretHash"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app, err := New(context.Background(), Options{
				Getenv: envFunc(with(baseEnv(), ConfigJSONEnv, extraClaimsDoc(tc.entries))),
				Logger: discardLogger(),
				Stores: memoryStores,
			})
			if err == nil {
				t.Fatalf("a claim named %s was accepted, so it would be discarded on every mint instead", tc.path)
			}
			if app != nil {
				t.Errorf("New returned a non-nil App alongside an error")
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("the refusal does not name the knob to edit (%s):\n%v", tc.path, err)
			}
		})
	}
}

// TestEveryBadClaimIsNamedAtOnce follows the config layer's convention: a
// document with three bad mappings is fixed in one edit, not in three
// deployments.
func TestEveryBadClaimIsNamedAtOnce(t *testing.T) {
	t.Parallel()

	_, err := New(context.Background(), Options{
		Getenv: envFunc(with(baseEnv(), ConfigJSONEnv, extraClaimsDoc(`{
			"typ":  {"const": "access"},
			"jti":  {"const": "fixed"},
			"zzz":  {"fromUserField": "totpSecret"}
		}`))),
		Logger: discardLogger(),
		Stores: memoryStores,
	})
	if err == nil {
		t.Fatal("three unusable claims were accepted")
	}
	for _, path := range []string{
		"security.jwt.extraClaims.typ",
		"security.jwt.extraClaims.jti",
		"security.jwt.extraClaims.zzz",
	} {
		if !strings.Contains(err.Error(), path) {
			t.Errorf("the refusal does not name %s:\n%v", path, err)
		}
	}
}

// ── the webhook ──────────────────────────────────────────────────────────────

// TestClaimsWebhookRequestIsSignedAndCarriesTheUser is the envelope, verified
// the way a receiver written against the family's convention verifies it:
// HMAC-SHA256 over the exact request bytes, "sha256=" and the hex digest
// (webhook-sender.ts:54-56), computed here from the secret rather than read
// back from the core. A receiver that cannot check the signature independently
// cannot tell a forged request from a real one, and neither could this test.
func TestClaimsWebhookRequestIsSignedAndCarriesTheUser(t *testing.T) {
	t.Parallel()

	const email = "hooked-claims@example.test"
	rec := newClaimsReceiver(t, map[string]any{"tier": "gold"})
	app := newClaimsApp(t, claimsEnv(baseEnv(), rec.srv.URL), rec)

	access, _ := bearerTokens(t, app, email)

	reqs := rec.requests()
	if len(reqs) == 0 {
		t.Fatal("the receiver was never called, so this test proves nothing")
	}
	got := reqs[0]

	if ct := got.headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if event := got.headers.Get("X-Webhook-Event"); event != "claims.build" {
		t.Errorf("X-Webhook-Event = %q, want %q", event, "claims.build")
	}
	if got.headers.Get("X-Webhook-Delivery") == "" {
		t.Error("X-Webhook-Delivery is empty, so a receiver cannot deduplicate")
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z07:00", got.headers.Get("X-Webhook-Timestamp")); err != nil {
		t.Errorf("X-Webhook-Timestamp %q is not the family's ISO 8601 form: %v",
			got.headers.Get("X-Webhook-Timestamp"), err)
	}

	mac := hmac.New(sha256.New, []byte(testClaimsSecret))
	mac.Write(got.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if have := got.headers.Get("X-Webhook-Signature"); have != want {
		t.Errorf("X-Webhook-Signature = %q, want %q — an independent HMAC over the exact body", have, want)
	}
	// The secret is never sent, only proof of it.
	if bytes.Contains(got.body, []byte(testClaimsSecret)) {
		t.Error("the signing secret appears in the request body")
	}
	for name, values := range got.headers {
		if strings.Contains(strings.Join(values, " "), testClaimsSecret) {
			t.Errorf("the signing secret appears in header %s", name)
		}
	}

	// The body: {"user": <the profile as GET /me renders it>} and nothing else.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(got.body, &envelope); err != nil {
		t.Fatalf("the request body is not a JSON object: %v (%s)", err, got.body)
	}
	if len(envelope) != 1 {
		t.Errorf("the request carries %d members, want only \"user\": %s", len(envelope), got.body)
	}
	var user map[string]any
	if err := json.Unmarshal(envelope["user"], &user); err != nil {
		t.Fatalf("the user member is not an object: %v (%s)", err, got.body)
	}
	if user["email"] != email {
		t.Errorf("user.email = %v, want %q (%s)", user["email"], email, got.body)
	}
	// The profile is the response-safe projection, so no credential material is
	// handed to somebody else's network.
	for _, leaked := range []string{"passwordHash", "password", "totpSecret", "accessToken", "refreshToken"} {
		if _, present := user[leaked]; present {
			t.Errorf("the claims request leaks %q to the receiver: %s", leaked, got.body)
		}
	}

	// And the answer reached the token.
	if got := jwsPayload(t, access)["tier"]; got != "gold" {
		t.Errorf("tier = %#v, want %q — the receiver's claim did not reach the access token", got, "gold")
	}
}

// TestClaimsWebhookWinsOverTheTable pins the composition order: the table says
// the same thing for everybody, the receiver computed its answer for this user
// at this moment, and a deployment that configures both is paying for the round
// trip because it wants the computed value.
func TestClaimsWebhookWinsOverTheTable(t *testing.T) {
	t.Parallel()

	rec := newClaimsReceiver(t, map[string]any{"plan": "computed"})
	env := claimsEnv(with(baseEnv(), ConfigJSONEnv, extraClaimsDoc(`{
		"plan":   {"const": "from-the-table"},
		"tenant": {"fromUserField": "tenantId"}
	}`)), rec.srv.URL)
	app := newClaimsApp(t, env, rec)

	access, _ := bearerTokens(t, app, "both@example.test")
	claims := jwsPayload(t, access)

	if got := claims["plan"]; got != "computed" {
		t.Errorf("plan = %#v, want the webhook's %q — the webhook must be chained last", got, "computed")
	}
	// The table's other entry is untouched: last-wins is per claim name, not
	// per builder.
	if _, present := claims["tenant"]; !present {
		t.Errorf("tenant disappeared when the webhook answered: %v", keysOfClaims(claims))
	}
}

// TestClaimsWebhookCannotSetSessionClaims: the receiver is on somebody else's
// network, and this is what makes it safe to let it contribute to a credential
// at all. issueToken writes the seven session claims after the merge, so an
// endpoint that is compromised — or merely confused — cannot retype a token or
// rebind its session.
//
// typ is the one that matters: {"typ":"access"} from a receiver would have
// turned the 2FA step-up token into a full session credential.
func TestClaimsWebhookCannotSetSessionClaims(t *testing.T) {
	t.Parallel()

	rec := newClaimsReceiver(t, map[string]any{
		"typ": "access",
		"sid": "forged-session",
		"iss": "https://evil.example.test",
		"sub": "somebody-else",
		"exp": 9999999999,
	})
	app := newClaimsApp(t, claimsEnv(baseEnv(), rec.srv.URL), rec)

	access, _ := bearerTokens(t, app, "forger@example.test")
	claims := jwsPayload(t, access)

	if got := claims["typ"]; got != "access" {
		t.Errorf("typ = %v, want the token's own \"access\"", got)
	}
	if got := claims["sid"]; got == "forged-session" {
		t.Error("the receiver rebound the token to a session of its choosing")
	}
	if got := claims["iss"]; got == "https://evil.example.test" {
		t.Error("the receiver reissued the token under an issuer of its choosing")
	}
	if got := claims["exp"]; got == float64(9999999999) {
		t.Error("the receiver extended the token's lifetime")
	}
	// sub is a base claim, not a session claim: the reference lets the hook
	// override it and so does this port. Asserted as overridden so that a
	// change in either direction is visible here rather than discovered.
	if got := claims["sub"]; got != "somebody-else" {
		t.Errorf("sub = %v; the six base claims are overridable by design, and this one no longer is", got)
	}
}

// TestClaimsWebhookFailureFailsTheLoginClosed is decision D-10, verified rather
// than implemented: the core already fails the mint, and this pins what that
// looks like on the wire.
//
// It is not the code D-10's text predicted. A builder failure is a broken host
// hook, and the core answers it with its generic 500 envelope — "Internal
// server error", deliberately code-less, deliberately carrying nothing from the
// underlying error. The decision has been amended to say so; this test is why.
func TestClaimsWebhookFailureFailsTheLoginClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		arrange func(*claimsReceiver)
	}{
		{"a non-2xx answer", func(r *claimsReceiver) { r.status = http.StatusInternalServerError }},
		{"a body that is not JSON", func(r *claimsReceiver) { r.rawBody = []byte("<html>not json</html>") }},
		{"no claims member", func(r *claimsReceiver) { r.rawBody = []byte(`{"result":{}}`) }},
		{"claims is not an object", func(r *claimsReceiver) { r.rawBody = []byte(`{"claims":"gold"}`) }},
		// 64 KiB is the core's ceiling on a response body; a claims object is a
		// handful of members and an endpoint answering with megabytes must not
		// be able to make every login buffer them.
		{"an oversized body", func(r *claimsReceiver) { r.padBytes = 96 << 10 }},
		{"a receiver that never answers", func(r *claimsReceiver) { r.hangFor = 10 * time.Second }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := newClaimsReceiver(t, map[string]any{"tier": "gold"})
			env := claimsEnv(baseEnv(), rec.srv.URL, "AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_TIMEOUT_MS", "250")
			app := newClaimsApp(t, env, rec)

			// The account is created while the receiver is healthy, so the
			// failure below is the login's and not registration's.
			const password = testPassword
			email := "closed@example.test"
			if resp := invoke(t, app, http.MethodPost, "/auth/register",
				jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
				registerBody(email)); resp.StatusCode != http.StatusCreated {
				t.Fatalf("register status = %d (body %s)", resp.StatusCode, resp.Body)
			}
			before := rec.hits.Load()
			rec.set(tc.arrange)

			resp := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(), nil,
				fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))

			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("login status = %d, want 500 — a claims failure must not issue a token (body %s)",
					resp.StatusCode, resp.Body)
			}
			body := decodeBody(t, resp)
			if _, coded := body["code"]; coded {
				t.Errorf("the 500 carries a `code`, and the core's internal-error envelope is code-less: %s", resp.Body)
			}
			if got := body["error"]; got != "Internal server error" {
				t.Errorf("error = %v, want %q", got, "Internal server error")
			}
			// Nothing about the receiver, the secret or the user reaches the
			// caller: an unexpected failure must not describe itself.
			for _, leaked := range []string{testClaimsSecret, rec.srv.URL, "claims"} {
				if strings.Contains(strings.ToLower(resp.Body), strings.ToLower(leaked)) {
					t.Errorf("the 500 body describes the failure (%q): %s", leaked, resp.Body)
				}
			}
			// No session was issued: the whole point of failing closed. The
			// CSRF cookie is not a session cookie and the middleware
			// distributes it on every response, so the assertion names the two
			// that would be a login.
			for _, c := range resp.Cookies {
				name := strings.SplitN(c, "=", 2)[0]
				if name == auth.AccessTokenCookieName || name == auth.RefreshTokenCookieName {
					t.Errorf("a failed mint still set the %s cookie: %v", name, resp.Cookies)
				}
			}
			if rec.hits.Load() == before {
				t.Errorf("the receiver was never called, so the failure under test did not happen")
			}
		})
	}
}

// TestClaimsWebhookHonoursItsTimeout: the login that needed the claims is
// waiting on this request inside a Lambda invocation, so a receiver that stops
// answering must cost timeoutMs and not the core's two second default, let
// alone the function's whole timeout.
//
// Measured on the webhook rather than through POST /login, for the reason
// newClaimsWebhook exists: a login also verifies a bcrypt hash at the
// configured cost, which under -race on a loaded machine is itself seconds, and
// a deadline assertion made against that measurement would be pinning the
// builder's speed rather than the receiver's deadline.
func TestClaimsWebhookHonoursItsTimeout(t *testing.T) {
	t.Parallel()

	rec := newClaimsReceiver(t, map[string]any{"tier": "gold"})
	rec.set(func(r *claimsReceiver) { r.hangFor = 10 * time.Second })

	const timeoutMs = 250
	cfg := loadTestConfig(t, claimsEnv(baseEnv(), rec.srv.URL,
		"AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_TIMEOUT_MS", fmt.Sprint(timeoutMs)))
	hook, err := newClaimsWebhook(cfg, rec.srv.Client())
	if err != nil {
		t.Fatalf("newClaimsWebhook: %v", err)
	}
	if want := timeoutMs * time.Millisecond; hook.Timeout != want {
		t.Fatalf("claims webhook timeout = %v, want %v from security.jwt.claimsWebhook.timeoutMs", hook.Timeout, want)
	}

	start := time.Now()
	_, err = hook.Build(context.Background(), auth.User{ID: "u-1", Email: "slow@example.test"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a receiver that never answered reported claims")
	}
	// Comfortably under the core's own 2s default, which is what proves the
	// configured value is the one in force.
	if elapsed > 1500*time.Millisecond {
		t.Errorf("the request took %v, want it bounded by the configured %dms", elapsed, timeoutMs)
	}
	if strings.Contains(err.Error(), testClaimsSecret) {
		t.Errorf("the error carries the signing secret, and an error is logged:\n%v", err)
	}
}

// TestClaimsWebhookIsNotCalledByTheMiddlewarePath is the cost claim, and it is
// a security claim too: a builder behind a network round trip that ran on every
// authenticated request would put a third party in the path of every call, not
// just of minting.
//
// The core draws the line at Service.Authenticate, which the adapters'
// Middleware calls and which never runs the hook — what it computed is already
// inside the token the request carried. GET /me is the documented exception: it
// is mounted bare and authenticates through Service.Me, because its body is the
// profile and customClaims is rendered in it. So one /me is exactly one request
// to the receiver, and a protected route that is not /me is none.
func TestClaimsWebhookIsNotCalledByTheMiddlewarePath(t *testing.T) {
	t.Parallel()

	rec := newClaimsReceiver(t, map[string]any{"tier": "gold"})
	app := newClaimsApp(t, claimsEnv(baseEnv(), rec.srv.URL), rec)

	access, _ := bearerTokens(t, app, "counted@example.test")

	// A session is two tokens and the builder runs per token, so issuing one
	// costs two requests — worth knowing before pointing this at a receiver
	// with a per-call price, and worth pinning so that a change in either
	// direction is seen here rather than on a bill.
	if got := rec.hits.Load(); got != 2 {
		t.Fatalf("issuing a session made %d requests to the receiver, want 2 — one per minted token", got)
	}

	before := rec.hits.Load()
	me := invoke(t, app, http.MethodGet, "/auth/me", bearer(access), nil, "")
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d (body %s)", me.StatusCode, me.Body)
	}
	if got := rec.hits.Load() - before; got != 1 {
		t.Errorf("GET /me made %d requests to the receiver, want exactly 1", got)
	}
	// And the claim is in the body, which is why /me runs it at all.
	custom, _ := decodeBody(t, me)["customClaims"].(map[string]any)
	if custom["tier"] != "gold" {
		t.Errorf("GET /me does not render the webhook's claims: %s", me.Body)
	}

	// A protected route that is not /me authenticates through the middleware,
	// which never runs the hook.
	before = rec.hits.Load()
	sessions := invoke(t, app, http.MethodGet, "/auth/sessions", bearer(access), nil, "")
	if sessions.StatusCode != http.StatusOK {
		t.Fatalf("sessions status = %d (body %s)", sessions.StatusCode, sessions.Body)
	}
	if got := rec.hits.Load() - before; got != 0 {
		t.Errorf("GET /sessions made %d requests to the receiver; the middleware path must make none", got)
	}
}

// TestMeSurvivesAFailingClaimsWebhook is the one place the fail-closed rule
// deliberately does not apply, and it is worth pinning because it looks like an
// inconsistency until you see why: /me is a read, and a read should not go dark
// because a mint-time hook is down. The core logs the failure and leaves
// customClaims empty (Service.Me), so a receiver outage costs logins and
// refreshes but leaves the profile answering.
func TestMeSurvivesAFailingClaimsWebhook(t *testing.T) {
	t.Parallel()

	rec := newClaimsReceiver(t, map[string]any{"tier": "gold"})
	app := newClaimsApp(t, claimsEnv(baseEnv(), rec.srv.URL), rec)

	access, _ := bearerTokens(t, app, "me-open@example.test")
	rec.set(func(r *claimsReceiver) { r.status = http.StatusBadGateway })

	me := invoke(t, app, http.MethodGet, "/auth/me", bearer(access), nil, "")
	if me.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d, want 200 — a read must not fail on a mint-time hook (body %s)", me.StatusCode, me.Body)
	}
	if _, present := decodeBody(t, me)["customClaims"]; present {
		t.Errorf("customClaims is rendered from a receiver that failed: %s", me.Body)
	}
}

// TestClaimsWebhookRefusesAnUnusableURL: the url is a document fault, so it
// aborts the cold start where a deployment can see it.
func TestClaimsWebhookRefusesAnUnusableURL(t *testing.T) {
	t.Parallel()

	// internal/config already refuses anything that is not an absolute https
	// URL, so what is left for the core's own parser is a value that passes
	// that and still cannot be a request target. Both layers are checked by
	// path rather than by message.
	_, err := New(context.Background(), Options{
		Getenv: envFunc(claimsEnv(baseEnv(), "http://claims.example.test/hook")),
		Logger: discardLogger(),
		Stores: memoryStores,
	})
	if err == nil {
		t.Fatal("a plain-http claims receiver was accepted")
	}
	if !strings.Contains(err.Error(), "security.jwt.claimsWebhook.url") {
		t.Errorf("the refusal does not name the knob to edit:\n%v", err)
	}
}

// TestNoClaimsConfigurationWiresNoBuilder: with neither half configured the
// hook is nil and every token carries exactly the six base claims plus the
// session claims — which is what keeps a deployment that configures nothing
// paying nothing.
func TestNoClaimsConfigurationWiresNoBuilder(t *testing.T) {
	t.Parallel()

	cfg := loadTestConfig(t, baseEnv())
	opts, err := claimsOptions(cfg, nil, discardLogger())
	if err != nil {
		t.Fatalf("claimsOptions: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("claimsOptions returned %d options for an unconfigured deployment, want none", len(opts))
	}

	app := newTestApp(t, baseEnv())
	access, _ := bearerTokens(t, app, "plain@example.test")
	claims := jwsPayload(t, access)
	want := map[string]bool{
		"sub": true, "email": true, "role": true, "loginProvider": true,
		"isEmailVerified": true, "isTotpEnabled": true,
		"sid": true, "tid": true, "jti": true, "typ": true, "iss": true, "iat": true, "exp": true,
	}
	for name := range claims {
		if !want[name] {
			t.Errorf("an unconfigured deployment mints the claim %q: %v", name, keysOfClaims(claims))
		}
	}
}

// TestClaimsWiringIsLogged: the cold-start line an operator reads the posture
// off, including what happens when the receiver is down, and never the secret
// or the receiver's path.
func TestClaimsWiringIsLogged(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	_, err := New(context.Background(), Options{
		Getenv: envFunc(claimsEnv(with(baseEnv(), ConfigJSONEnv, extraClaimsDoc(`{"plan": {"const": "enterprise"}}`)), testClaimsURL)),
		Logger: newLogger(&buf, slog.LevelDebug),
		Stores: memoryStores,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"token claims wired", "https://claims.example.test", "constantClaims"} {
		if !strings.Contains(out, want) {
			t.Errorf("the cold-start log does not mention %q:\n%s", want, out)
		}
	}
	// The receiver's path is where an operator puts a capability token when the
	// receiver sits behind a gateway that cannot check an HMAC, so the log
	// stops at the origin — and the signing secret is never written at all.
	if strings.Contains(out, "claims.example.test/hook") {
		t.Errorf("the cold-start log carries the claims webhook's path:\n%s", out)
	}
	if strings.Contains(out, testClaimsSecret) {
		t.Errorf("the claims webhook's signing secret reached the log:\n%s", out)
	}
}

// newClaimsApp builds an App whose HTTP client trusts the receiver's
// certificate. Injecting the client switches nothing on, exactly as injecting a
// mail transport does not: whether a claims webhook is wired at all stays a
// question about the configuration.
func newClaimsApp(t *testing.T, env map[string]string, rec *claimsReceiver) *App {
	t.Helper()
	app, err := New(context.Background(), Options{
		Getenv:     envFunc(env),
		Logger:     discardLogger(),
		Stores:     memoryStores,
		HTTPClient: rec.srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app
}

func keysOfClaims(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
