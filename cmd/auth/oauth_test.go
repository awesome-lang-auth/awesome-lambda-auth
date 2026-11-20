package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The OAuth block, driven end to end: a real App built by New, a synthetic API
// Gateway v2 event per request, and an httptest server standing in for the
// identity provider's three endpoints.
//
// Nothing here fakes the core. The provider is a real HTTP server because the
// core's OAuthService owns its own http.Client and exposes no seam to replace
// it — which is also why the provider is reached over plain http on loopback
// (internal/config/validate.go, validateOAuth): a loopback request never leaves
// the host, so there is nothing for TLS to protect, and a self-signed
// certificate would be unverifiable by a client nothing can configure.
//
// That carve-out only holds outside production, which is what baseEnv declares
// (AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT=development). A production document
// pointing an endpoint at loopback is refused, and internal/config's
// TestGenericProviderEndpointsAllowLoopbackOverHTTP pins both halves.

// testSiteURL, testAltSiteURL and testEvilOrigin are the front ends every
// redirect case is written against; they live in email_test.go because the
// emailed links resolve against the same allowlist.
const (
	testProvider      = "acme"
	testOAuthClientID = "acme-client-id"
	testOAuthSecret   = "acme-client-secret"
	testOAuthEmail    = "oauth@example.test"
)

// flatProfile is the userinfo document a plain OIDC-shaped provider returns.
// `sub` rather than `id`, so the default mapping's second candidate is what the
// wire exercises.
const flatProfile = `{"sub":"acme-7","email":"` + testOAuthEmail + `","email_verified":true,"name":"OAuth User"}`

// nestedProfile buries the identity the way Microsoft Graph or a bespoke
// provider buries it: the id two levels down and numeric, the address split
// over a null `mail` and `userPrincipalName`, the verified flag as text, the
// picture inside an array. Only a profileMap can read it.
const nestedProfile = `{"data":{"user":{"id":7001,"mail":null,"userPrincipalName":"nested@example.test",` +
	`"verified":"true","profile":{"displayName":"Nested User","photos":[{"url":"https://img.example.test/n.png"}]}}}}`

// ── the identity provider ────────────────────────────────────────────────────

// fakeOAuthProvider serves the three endpoints a provider has to serve:
// /authorize, which 302s back to the callback the way a consent screen does,
// /token and /userinfo. It records the token-exchange form so the PKCE
// assertions can check what actually went over the wire.
type fakeOAuthProvider struct {
	srv *httptest.Server

	mu            sync.Mutex
	tokenForm     url.Values
	tokenStatus   int
	profileStatus int
	profile       string
}

func newFakeOAuthProvider(t *testing.T) *fakeOAuthProvider {
	t.Helper()
	p := &fakeOAuthProvider{
		tokenStatus:   http.StatusOK,
		profileStatus: http.StatusOK,
		profile:       flatProfile,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect := q.Get("redirect_uri")
		if redirect == "" {
			http.Error(w, "no redirect_uri", http.StatusBadRequest)
			return
		}
		// What a consent screen does once the person has said yes: bounce back
		// to the registered callback with an authorization code and the state it
		// was handed, untouched.
		back, err := url.Parse(redirect)
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		back.RawQuery = url.Values{"code": {"provider-authorization-code"}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.tokenForm = r.PostForm
		status := p.tokenStatus
		p.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"provider-access-token","token_type":"bearer"}`))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		status, profile := p.profileStatus, p.profile
		p.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(profile))
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeOAuthProvider) setProfile(doc string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.profile = doc
}

func (p *fakeOAuthProvider) failToken() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenStatus = http.StatusUnauthorized
}

func (p *fakeOAuthProvider) tokenExchangeForm() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenForm
}

// ── the deployment ───────────────────────────────────────────────────────────

// oauthStores is one persistence layer two Apps can share. Test 3 needs it: the
// callback's allowlist check is only observable when the state was minted by a
// deployment that allowed an origin this one does not, and the in-flight nonce
// lives in the pending-link store both of them have to see.
type oauthStores struct {
	users    memoryStoreBundle
	sessions auth.SessionStore
}

func newOAuthStores() *oauthStores {
	return &oauthStores{users: newMemoryStoreBundle(), sessions: auth.NewMemorySessionStore()}
}

func (s *oauthStores) factory() StoreFactory { return storeFactory(s.users, s.sessions) }

// oauthDoc is the configuration document a provider-backed deployment runs on:
// one generic provider pointed at the fake, and the site URL every redirect
// resolves against. Cases mutate the map before it is marshalled.
func oauthDoc(p *fakeOAuthProvider) map[string]any {
	return map[string]any{
		"schemaVersion": 1,
		"email":         map[string]any{"siteUrls": []any{testSiteURL}},
		"oauth": map[string]any{
			"providers": map[string]any{
				testProvider: map[string]any{
					"clientId":             testOAuthClientID,
					"callbackUrl":          "https://auth.example.test/auth/oauth/" + testProvider + "/callback",
					"authorizationUrl":     p.srv.URL + "/authorize",
					"tokenUrl":             p.srv.URL + "/token",
					"userInfoUrl":          p.srv.URL + "/userinfo",
					"scope":                "openid email profile",
					"additionalAuthParams": map[string]any{"prompt": "consent"},
				},
			},
		},
	}
}

// providerDoc reaches into a document built by oauthDoc.
func providerDoc(doc map[string]any, name string) map[string]any {
	providers := doc["oauth"].(map[string]any)["providers"].(map[string]any)
	entry, ok := providers[name].(map[string]any)
	if !ok {
		entry = map[string]any{}
		providers[name] = entry
	}
	return entry
}

func provisioningDoc(doc map[string]any) map[string]any {
	oauth := doc["oauth"].(map[string]any)
	p, ok := oauth["provisioning"].(map[string]any)
	if !ok {
		p = map[string]any{}
		oauth["provisioning"] = p
	}
	return p
}

// oauthEnv is baseEnv plus what an OAuth deployment needs: the client secret
// through its documented variable, the two linking stores switched on, and the
// document itself.
//
// The two store keys are not decoration. linkedAccounts is required — RS-11
// refuses a configured provider without it, because the core's callback answers
// 501 before it does anything at all — and pendingLinks is what makes the state
// nonce single-use and what the conflict flow stashes into. A deployment that
// leaves either off is a case of its own, not something to be assumed away:
// TestProviderWithoutTheLinkedAccountsStoreRefusesToStart drives the first.
func oauthEnv(t *testing.T, doc map[string]any, extra ...string) map[string]string {
	t.Helper()
	return with(oauthEnvWithoutStores(t, doc), append([]string{
		"AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS", "true",
		"AWESOME_AUTH_STORES_ENABLE_PENDING_LINKS", "true",
	}, extra...)...)
}

// oauthEnvWithoutStores is the same environment with neither linking store
// switched on, i.e. what stores.enable looks like by default.
func oauthEnvWithoutStores(t *testing.T, doc map[string]any, extra ...string) map[string]string {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal configuration document: %v", err)
	}
	return with(baseEnv(), append([]string{
		ConfigJSONEnv, string(raw),
		"AWESOME_AUTH_OAUTH_" + strings.ToUpper(testProvider) + "_CLIENT_SECRET", testOAuthSecret,
	}, extra...)...)
}

// newOAuthApp builds a real App on the given document and stores.
func newOAuthApp(t *testing.T, doc map[string]any, stores *oauthStores, extraEnv ...string) *App {
	t.Helper()
	app, err := New(context.Background(), Options{
		Getenv: envFunc(oauthEnv(t, doc, extraEnv...)),
		Logger: discardLogger(),
		Stores: stores.factory(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app
}

// ── driving the flow ─────────────────────────────────────────────────────────

// authorize drives GET <prefix>/oauth/{provider} and returns the provider URL
// the browser is sent to.
func authorize(t *testing.T, app *App, provider string, headers map[string]string) *url.URL {
	t.Helper()
	resp := invoke(t, app, http.MethodGet, "/auth/oauth/"+provider, headers, nil, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302 (body %s)", resp.StatusCode, resp.Body)
	}
	loc := location(t, resp)
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("authorize Location %q does not parse: %v", loc, err)
	}
	return u
}

// consent walks the provider's own authorize endpoint and returns the code and
// state it bounces back to the callback, which is what a browser would carry.
func consent(t *testing.T, authorizeURL *url.URL) (code, state string) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authorizeURL.String())
	if err != nil {
		t.Fatalf("GET the provider's authorize endpoint: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the provider answered %d, want a 302 back to the callback", resp.StatusCode)
	}
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the provider's Location does not parse: %v", err)
	}
	q := back.Query()
	return q.Get("code"), q.Get("state")
}

// callback drives GET <prefix>/oauth/{provider}/callback.
func callback(t *testing.T, app *App, provider, code, state string) events.APIGatewayV2HTTPResponse {
	t.Helper()
	q := url.Values{}
	if code != "" {
		q.Set("code", code)
	}
	if state != "" {
		q.Set("state", state)
	}
	return invoke(t, app, http.MethodGet, "/auth/oauth/"+provider+"/callback?"+q.Encode(), nil, nil, "")
}

// signIn is the whole flow: authorize, consent, callback.
func signIn(t *testing.T, app *App, p *fakeOAuthProvider, headers map[string]string) events.APIGatewayV2HTTPResponse {
	t.Helper()
	code, state := consent(t, authorize(t, app, testProvider, headers))
	return callback(t, app, testProvider, code, state)
}

func location(t *testing.T, resp events.APIGatewayV2HTTPResponse) string {
	t.Helper()
	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Location") {
			return v
		}
	}
	t.Fatalf("the response carries no Location header: %d %v %s", resp.StatusCode, resp.Headers, resp.Body)
	return ""
}

func hasLocation(resp events.APIGatewayV2HTTPResponse) bool {
	for k := range resp.Headers {
		if strings.EqualFold(k, "Location") {
			return true
		}
	}
	return false
}

// cookieValue reads one Set-Cookie off a v2 response by name.
func cookieValue(t *testing.T, resp events.APIGatewayV2HTTPResponse, name string) string {
	t.Helper()
	for _, c := range resp.Cookies {
		got, rest, ok := strings.Cut(c, "=")
		if !ok || got != name {
			continue
		}
		value, _, _ := strings.Cut(rest, ";")
		return value
	}
	return ""
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// registerAccount creates a local account and returns its id, so a case can
// arrange the "an account already holds this address" situations.
func registerAccount(t *testing.T, app *App, email string) string {
	t.Helper()
	resp := registerAndLogin(t, app, jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), email)
	token, _ := decodeBody(t, resp)["accessToken"].(string)
	if token == "" {
		t.Fatalf("login returned no access token: %s", resp.Body)
	}
	me := invoke(t, app, http.MethodGet, "/auth/me", bearer(token), nil, "")
	id, _ := decodeBody(t, me)["id"].(string)
	if id == "" {
		t.Fatalf("/me returned no id: %s", me.Body)
	}
	return id
}

// ── the cases ────────────────────────────────────────────────────────────────

// TestOAuthAuthorizeRedirectsWithSignedStateAndPKCE pins the authorization
// request: the provider's endpoint with the configured client and scope, the
// document's additionalAuthParams, a state that is signed rather than merely
// encoded (reference-issues N1), and the PKCE challenge the reference does not
// send at all.
func TestOAuthAuthorizeRedirectsWithSignedStateAndPKCE(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	app := newOAuthApp(t, oauthDoc(p), newOAuthStores())

	u := authorize(t, app, testProvider, nil)

	if got, want := u.Scheme+"://"+u.Host+u.Path, p.srv.URL+"/authorize"; got != want {
		t.Errorf("authorization endpoint = %q, want the configured %q", got, want)
	}
	q := u.Query()
	for _, tc := range []struct{ key, want string }{
		{"client_id", testOAuthClientID},
		{"redirect_uri", "https://auth.example.test/auth/oauth/" + testProvider + "/callback"},
		{"response_type", "code"},
		{"scope", "openid email profile"},
		{"prompt", "consent"},
		{"code_challenge_method", "S256"},
	} {
		if got := q.Get(tc.key); got != tc.want {
			t.Errorf("authorization query %s = %q, want %q", tc.key, got, tc.want)
		}
	}
	if q.Get("code_challenge") == "" {
		t.Error("the authorization request carries no code_challenge, so the exchange is not bound to this client")
	}
	if q.Get("client_secret") != "" {
		t.Error("the authorization request carries the client secret, which is a front-channel URL the browser and every log on the way can read")
	}

	// Signed, not just encoded. The reference packs {n,o,p} as bare base64url
	// and never verifies it (N1); the core appends "." + HMAC, which a base64url
	// payload can never contain.
	payload, signature, found := strings.Cut(q.Get("state"), ".")
	if !found || payload == "" || signature == "" {
		t.Fatalf("state %q is not <payload>.<signature>", q.Get("state"))
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("state payload is not base64url: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("state payload is not JSON: %v (%s)", err, raw)
	}
	// The reference's own field names, which a client or proxy may already
	// decode: n is the nonce, o the origin the flow started from.
	if decoded["n"] == "" || decoded["n"] == nil {
		t.Errorf("state carries no nonce: %s", raw)
	}
	if decoded["o"] != testSiteURL {
		t.Errorf("state origin = %v, want the canonical site %q: %s", decoded["o"], testSiteURL, raw)
	}
}

// TestOAuthCallbackSetsCookiesAndRedirectsToAllowlistedOrigin is the success
// path: the browser comes back with a code, the deployment exchanges it with
// the PKCE verifier, and the answer is a 302 to the origin the flow started
// from with the session in cookies — the reference ignores X-Auth-Strategy on
// redirect flows, so cookies are the only delivery.
func TestOAuthCallbackSetsCookiesAndRedirectsToAllowlistedOrigin(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	doc := oauthDoc(p)
	// Two allowlisted origins, so "redirected to the origin it started from" is
	// distinguishable from "redirected to the canonical site".
	doc["email"] = map[string]any{"siteUrls": []any{testSiteURL, testAltSiteURL}}
	app := newOAuthApp(t, doc, newOAuthStores())

	u := authorize(t, app, testProvider, map[string]string{"origin": testAltSiteURL})
	challenge := u.Query().Get("code_challenge")
	code, state := consent(t, u)
	resp := callback(t, app, testProvider, code, state)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body %s)", resp.StatusCode, resp.Body)
	}
	if got := location(t, resp); got != testAltSiteURL {
		t.Errorf("Location = %q, want the allowlisted origin the flow started from %q", got, testAltSiteURL)
	}
	for _, name := range []string{auth.AccessTokenCookieName, auth.RefreshTokenCookieName} {
		if cookieValue(t, resp, name) == "" {
			t.Errorf("no %s cookie on the callback response; the session is the whole point of it: %v", name, resp.Cookies)
		}
	}

	// The exchange carried the verifier the challenge was derived from, which is
	// what binds the code to the browser that started the flow.
	form := p.tokenExchangeForm()
	verifier := form.Get("code_verifier")
	if verifier == "" {
		t.Fatal("the token exchange sent no code_verifier, so the PKCE challenge bound nothing")
	}
	if got := s256(verifier); got != challenge {
		t.Errorf("S256(code_verifier) = %q, want the code_challenge sent at authorize %q", got, challenge)
	}
	for _, tc := range []struct{ key, want string }{
		{"grant_type", "authorization_code"},
		{"code", code},
		{"client_id", testOAuthClientID},
		{"client_secret", testOAuthSecret},
	} {
		if got := form.Get(tc.key); got != tc.want {
			t.Errorf("token exchange %s = %q, want %q", tc.key, got, tc.want)
		}
	}

	// The account the callback created is a real one, reachable with the cookie
	// it was handed.
	me := invoke(t, app, http.MethodGet, "/auth/me", nil,
		[]string{auth.AccessTokenCookieName + "=" + cookieValue(t, resp, auth.AccessTokenCookieName)}, "")
	if me.StatusCode != http.StatusOK {
		t.Fatalf("/me with the callback's cookie = %d, want 200 (body %s)", me.StatusCode, me.Body)
	}
	body := decodeBody(t, me)
	if body["email"] != testOAuthEmail {
		t.Errorf("/me email = %v, want the provider's %q", body["email"], testOAuthEmail)
	}
	if body["loginProvider"] != testProvider {
		t.Errorf("/me loginProvider = %v, want %q", body["loginProvider"], testProvider)
	}
}

// TestOAuthStateOriginOutsideAllowlistFallsBackToCanonical is reference-issues
// N1, from both ends.
//
// The callback answers with a fresh session in a Set-Cookie, so where it sends
// the browser is a credential-bearing redirect. The reference honours whatever
// origin the state names whenever the allowlist is empty (auth.router.ts:327),
// which is why RS-11 refuses an OAuth deployment that has no allowlist at all;
// with one, an origin outside it must never be reached — not on the way in,
// where the state is minted, and not on the way back, where a state minted
// under a wider allowlist can still turn up.
func TestOAuthStateOriginOutsideAllowlistFallsBackToCanonical(t *testing.T) {
	t.Parallel()

	t.Run("an origin outside the allowlist never enters the state", func(t *testing.T) {
		t.Parallel()
		p := newFakeOAuthProvider(t)
		app := newOAuthApp(t, oauthDoc(p), newOAuthStores())

		u := authorize(t, app, testProvider, map[string]string{"origin": testEvilOrigin, "referer": testEvilOrigin + "/login"})

		payload, _, _ := strings.Cut(u.Query().Get("state"), ".")
		raw, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			t.Fatalf("state payload is not base64url: %v", err)
		}
		if strings.Contains(string(raw), "evil.example.test") {
			t.Errorf("the state carries an origin that is not allowlisted: %s", raw)
		}
		resp := signIn(t, app, p, map[string]string{"origin": testEvilOrigin})
		if got := location(t, resp); got != testSiteURL {
			t.Errorf("Location = %q, want the canonical site %q", got, testSiteURL)
		}
	})

	t.Run("a state whose origin left the allowlist falls back to the canonical site", func(t *testing.T) {
		t.Parallel()
		p := newFakeOAuthProvider(t)
		stores := newOAuthStores()

		// The deployment that mints the state allows both origins.
		wide := oauthDoc(p)
		wide["email"] = map[string]any{"siteUrls": []any{testSiteURL, testAltSiteURL}}
		minting := newOAuthApp(t, wide, stores)

		// The one that completes it allows only the canonical site — the
		// allowlist an operator narrowed between the two halves of a flow, and
		// the shape an attacker gets by replaying a state from anywhere else.
		// Same signing secret and same stores, so the state verifies and the
		// nonce is found: the only thing that differs is the allowlist.
		narrow := oauthDoc(p)
		completing := newOAuthApp(t, narrow, stores)

		code, state := consent(t, authorize(t, minting, testProvider, map[string]string{"origin": testAltSiteURL}))
		resp := callback(t, completing, testProvider, code, state)

		if resp.StatusCode != http.StatusFound {
			t.Fatalf("callback status = %d, want 302 (body %s)", resp.StatusCode, resp.Body)
		}
		if got := location(t, resp); got != testSiteURL {
			t.Errorf("Location = %q, want the canonical site %q: the state named %q, which this deployment does not allowlist",
				got, testSiteURL, testAltSiteURL)
		}
	})
}

// TestOAuthAccountConflictStashesAndRedirects: with onEmailMatch conflict, a
// provider asserting an address a local account already holds is the
// reference's OAUTH_ACCOUNT_CONFLICT — a 302 to /account-conflict carrying the
// provider, the code and the address (auth.router.ts:1346-1355), with the
// (email, provider, providerAccountId) triple stashed so that /link-request can
// resolve the identity once an emailed token has proved the address.
func TestOAuthAccountConflictStashesAndRedirects(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	doc := oauthDoc(p)
	provisioningDoc(doc)["onEmailMatch"] = config.OAuthEmailMatchConflict
	stores := newOAuthStores()
	app := newOAuthApp(t, doc, stores)

	registerAccount(t, app, testOAuthEmail)

	resp := signIn(t, app, p, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want the conflict redirect 302 (body %s)", resp.StatusCode, resp.Body)
	}
	// The reference's literal query, in its order: provider, code, then the
	// address. Written out rather than built, because the point of the
	// assertion is to catch a change in it.
	want := testSiteURL + "/auth/account-conflict?provider=" + testProvider +
		"&code=OAUTH_ACCOUNT_CONFLICT&email=" + url.QueryEscape(testOAuthEmail)
	if got := location(t, resp); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if c := cookieValue(t, resp, auth.AccessTokenCookieName); c != "" {
		t.Errorf("the conflict redirect carries a session cookie, so the takeover it refuses happened anyway: %v", resp.Cookies)
	}

	// The stash the linking flow reads, under the key the reference uses:
	// (email, provider), with no tenant segment.
	meta, err := stores.users.PendingLinks().Get(context.Background(), "pending-link:"+testOAuthEmail+"|"+testProvider)
	if err != nil {
		t.Fatalf("nothing was stashed for the conflict, so POST /link-request has no identity to resolve: %v", err)
	}
	if meta.ProviderAccountID != "acme-7" {
		t.Errorf("stashed providerAccountId = %q, want the provider's subject %q", meta.ProviderAccountID, "acme-7")
	}
	if meta.Email != testOAuthEmail {
		t.Errorf("stashed email = %q, want %q", meta.Email, testOAuthEmail)
	}
}

// TestOAuthCallbackIssuesASessionEvenForATwoFactorAccount pins an upstream gap,
// deliberately and with the divergence stated.
//
// The reference's callback is 2FA-aware: an account with a second factor is
// 302'd to `${redirectTo}/auth/2fa?tempToken=<jwt>&methods=<list>` instead of
// being handed a session (auth.router.ts:1298-1313, wire-contract.md §3). The
// imported core has no such branch — OAuthComplete issues a session for every
// account it resolves — and this product does not fork the core, so a federated
// login skips the second factor that a password login demands.
//
// The test asserts both halves so the gap cannot be mistaken for a missing
// feature in this deployment: POST /login on the same account does answer the
// challenge, and the callback does not. When upstream grows the branch this
// fails, and that is the signal to delete it and the paragraph in oauth.go.
func TestOAuthCallbackIssuesASessionEvenForATwoFactorAccount(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	stores := newOAuthStores()
	app := newOAuthApp(t, oauthDoc(p), stores)

	userID := registerAccount(t, app, testOAuthEmail)
	if err := stores.users.UpdateTOTPSecret(context.Background(), userID, "", "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatalf("enable TOTP on the account: %v", err)
	}

	login := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(), nil, registerBody(testOAuthEmail))
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200 with the challenge (body %s)", login.StatusCode, login.Body)
	}
	if body := decodeBody(t, login); body["requiresTwoFactor"] != true {
		t.Fatalf("the account is not actually second-factor gated, so this test proves nothing: %s", login.Body)
	}

	resp := signIn(t, app, p, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body %s)", resp.StatusCode, resp.Body)
	}
	loc := location(t, resp)
	if strings.Contains(loc, "tempToken") {
		t.Fatalf(`the callback now redirects with a tempToken (%q).

That is the reference's 2FA branch (auth.router.ts:1298-1313), and it means the
imported core grew it. Delete this test and the "what the callback does not do"
paragraph in cmd/auth/oauth.go, and write the real assertion: 302 to
<redirectTo>/auth/2fa?tempToken=<jwt>&methods=<comma-joined>, no session
cookies.`, loc)
	}
	if loc != testSiteURL {
		t.Errorf("Location = %q, want %q", loc, testSiteURL)
	}
	if cookieValue(t, resp, auth.AccessTokenCookieName) == "" {
		t.Errorf("the callback issued no session cookie, which is neither this build's behaviour nor the reference's: %v", resp.Cookies)
	}
}

// TestOAuthCallbackErrorIsJSONNotRedirect is reference-issues N29, reproduced.
//
// Everything on the callback except the account conflict answers with a JSON
// error body rather than a redirect, which strands a browser mid-flow on a raw
// JSON page. It is the reference's own choice (auth.router.ts:1357), three
// shipped clients are built against it, and so it is what this deployment does.
func TestOAuthCallbackErrorIsJSONNotRedirect(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	app := newOAuthApp(t, oauthDoc(p), newOAuthStores())

	u := authorize(t, app, testProvider, nil)
	code, state := consent(t, u)
	p.failToken()

	resp := callback(t, app, testProvider, code, state)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("callback status = %d, want 401 (body %s)", resp.StatusCode, resp.Body)
	}
	if hasLocation(resp) {
		t.Errorf("the failed callback answered with a redirect; N29 is that it answers JSON: %v", resp.Headers)
	}
	body := decodeBody(t, resp)
	if body["code"] != auth.CodeOAuthTokenExchangeFail {
		t.Errorf("error code = %v, want %q (body %s)", body["code"], auth.CodeOAuthTokenExchangeFail, resp.Body)
	}
	if body["error"] != "OAuth token exchange failed" {
		t.Errorf("error message = %v, want %q (body %s)", body["error"], "OAuth token exchange failed", resp.Body)
	}
	// The CSRF cookie is distributed by the middleware on every request, so the
	// assertion is about the two that carry a session.
	for _, name := range []string{auth.AccessTokenCookieName, auth.RefreshTokenCookieName} {
		if cookieValue(t, resp, name) != "" {
			t.Errorf("a failed callback set %s: %v", name, resp.Cookies)
		}
	}
}

// TestGenericProviderProfileMapMapsANestedProfile: the declarative replacement
// for the reference's mapProfile function. The document's expressions are
// compiled at cold start and applied to the userinfo document, so a provider
// whose identity is buried two levels down and whose address is split over two
// fields needs no code.
func TestGenericProviderProfileMapMapsANestedProfile(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	p.setProfile(nestedProfile)

	doc := oauthDoc(p)
	providerDoc(doc, testProvider)["profileMap"] = map[string]any{
		"id":            "$.data.user.id",
		"email":         "$.data.user.mail ?? $.data.user.userPrincipalName",
		"emailVerified": "$.data.user.verified",
		"name":          "$.data.user.profile.displayName",
		"picture":       "$.data.user.profile.photos[0].url",
	}
	stores := newOAuthStores()
	app := newOAuthApp(t, doc, stores)

	resp := signIn(t, app, p, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body %s)", resp.StatusCode, resp.Body)
	}

	me := invoke(t, app, http.MethodGet, "/auth/me", nil,
		[]string{auth.AccessTokenCookieName + "=" + cookieValue(t, resp, auth.AccessTokenCookieName)}, "")
	if me.StatusCode != http.StatusOK {
		t.Fatalf("/me = %d, want 200 (body %s)", me.StatusCode, me.Body)
	}
	if got := decodeBody(t, me)["email"]; got != "nested@example.test" {
		t.Errorf("/me email = %v, want the address the ?? chain fell through to", got)
	}

	// The id the mapping read is what the linked account is keyed on: a numeric
	// JSON id renders the way JavaScript's String() renders it, without a
	// trailing ".0".
	link, err := stores.users.LinkedAccounts().FindByProvider(context.Background(), testProvider, "7001")
	if err != nil {
		t.Fatalf("no linked account under the mapped provider id: %v", err)
	}
	if link.Email != "nested@example.test" {
		t.Errorf("linked account email = %q, want the mapped address", link.Email)
	}
}

// TestOAuthProvisioningRefusesAnIdentityItMayNotCreate: the policy is wired, not
// decoration. autoCreate false means the callback will not provision, and the
// answer is the core's 403 rather than a redirect — a refusal a repeat of the
// flow cannot fix.
func TestOAuthProvisioningRefusesAnIdentityItMayNotCreate(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	doc := oauthDoc(p)
	provisioningDoc(doc)["autoCreate"] = false
	app := newOAuthApp(t, doc, newOAuthStores())

	resp := signIn(t, app, p, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback status = %d, want 403 (body %s)", resp.StatusCode, resp.Body)
	}
	if hasLocation(resp) {
		t.Errorf("the refusal answered with a redirect: %v", resp.Headers)
	}
	if body := decodeBody(t, resp); body["code"] != auth.CodeOAuthUserNotProvisioned {
		t.Errorf("error code = %v, want %q (body %s)", body["code"], auth.CodeOAuthUserNotProvisioned, resp.Body)
	}
}

// TestUnknownProviderIs404 pins the reference's absent-strategy stub, which is
// what every provider answers on a deployment that configured none: a 404 whose
// body carries a message and no code (wire-contract.md §4.4).
func TestUnknownProviderIs404(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)

	t.Run("a name no document mentions", func(t *testing.T) {
		t.Parallel()
		app := newOAuthApp(t, oauthDoc(p), newOAuthStores())

		resp := invoke(t, app, http.MethodGet, "/auth/oauth/nope", nil, nil, "")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", resp.StatusCode, resp.Body)
		}
		body := decodeBody(t, resp)
		if body["error"] != "nope OAuth not configured" {
			t.Errorf("error = %v, want %q (body %s)", body["error"], "nope OAuth not configured", resp.Body)
		}
		if _, coded := body["code"]; coded {
			t.Errorf("the stub carries a code; the reference's 404 has none: %s", resp.Body)
		}
		// The callback half answers the same way, so a browser that comes back
		// to a provider that was removed gets the stub rather than a 500.
		cb := invoke(t, app, http.MethodGet, "/auth/oauth/nope/callback?code=x&state=y", nil, nil, "")
		if cb.StatusCode != http.StatusNotFound {
			t.Errorf("callback status = %d, want 404 (body %s)", cb.StatusCode, cb.Body)
		}
	})

	t.Run("a built-in name on a deployment with no providers", func(t *testing.T) {
		t.Parallel()
		app := newTestApp(t, baseEnv())

		resp := invoke(t, app, http.MethodGet, "/auth/oauth/google", nil, nil, "")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", resp.StatusCode, resp.Body)
		}
		// The reference's own literal, which the contract suite's CapOAuthGoogle
		// probe reads on an unconfigured deployment.
		if got := decodeBody(t, resp)["error"]; got != "Google OAuth not configured" {
			t.Errorf("error = %v, want %q (body %s)", got, "Google OAuth not configured", resp.Body)
		}
	})
}

// TestBuiltInProvidersUseTheCorePresets: google and github are the reference's
// two hard-coded strategies, so the document supplies credentials and a
// callback and nothing else — the endpoints, the scopes and Google's
// access_type=offline come from the core's presets. A document may still add
// the three fields that are not an endpoint, and the one that matters most is
// scope: a deployment that needs one more consent scope must not have to fork a
// provider for it.
func TestBuiltInProvidersUseTheCorePresets(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"schemaVersion": 1,
		"email":         map[string]any{"siteUrls": []any{testSiteURL}},
		"oauth": map[string]any{
			"providers": map[string]any{
				"google": map[string]any{
					"clientId":    "123.apps.googleusercontent.com",
					"callbackUrl": "https://auth.example.test/auth/oauth/google/callback",
					"scope":       "openid email profile https://www.googleapis.com/auth/calendar.readonly",
				},
				"github": map[string]any{
					"clientId":    "Iv1.0123456789abcdef",
					"callbackUrl": "https://auth.example.test/auth/oauth/github/callback",
				},
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	app := newTestApp(t, with(baseEnv(),
		ConfigJSONEnv, string(raw),
		"AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET", "google-client-secret",
		"AWESOME_AUTH_OAUTH_GITHUB_CLIENT_SECRET", "github-client-secret",
		"AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS", "true",
		"AWESOME_AUTH_STORES_ENABLE_PENDING_LINKS", "true",
	))

	google := authorize(t, app, "google", nil)
	if got, want := google.Scheme+"://"+google.Host+google.Path, "https://accounts.google.com/o/oauth2/v2/auth"; got != want {
		t.Errorf("google authorization endpoint = %q, want the preset %q", got, want)
	}
	if got := google.Query().Get("access_type"); got != "offline" {
		t.Errorf("google access_type = %q, want the preset's %q (google.strategy.ts:29)", got, "offline")
	}
	if got, want := google.Query().Get("scope"), "openid email profile https://www.googleapis.com/auth/calendar.readonly"; got != want {
		t.Errorf("google scope = %q, want the document's %q", got, want)
	}

	github := authorize(t, app, "github", nil)
	if got, want := github.Scheme+"://"+github.Host+github.Path, "https://github.com/login/oauth/authorize"; got != want {
		t.Errorf("github authorization endpoint = %q, want the preset %q", got, want)
	}
	if got, want := github.Query().Get("scope"), "user:email"; got != want {
		t.Errorf("github scope = %q, want the preset's %q", got, want)
	}
}

// TestProfileMapThatDoesNotCompileRefusesToStart: a mapping expression is
// configuration, and configuration that cannot work is a failed deployment
// rather than a provider that 500s on its first callback. The message has to
// name the provider and the field, because that is what an operator needs to
// find the line in the document.
func TestProfileMapThatDoesNotCompileRefusesToStart(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	doc := oauthDoc(p)
	providerDoc(doc, testProvider)["profileMap"] = map[string]any{
		"id":    "$.sub",
		"email": "$.mail ?? $.userPrincipalName ?? ",
	}

	_, err := New(context.Background(), Options{
		Getenv: envFunc(oauthEnv(t, doc)),
		Logger: discardLogger(),
		Stores: newOAuthStores().factory(),
	})
	if err == nil {
		t.Fatal("a profileMap that does not compile was accepted, so the provider would fail at the first login instead")
	}
	for _, want := range []string{testProvider, "email", "profile map"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestProviderProjectIDIsReportedAsAnUnwiredKnob: projectId is in the schema
// because the reference carries it, and nothing in either flow reads it. The
// rule for such a knob is that it is reported at cold start, never silently
// dropped.
func TestProviderProjectIDIsReportedAsAnUnwiredKnob(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.OAuth.Providers = map[string]config.OAuthProvider{
		"google": {ClientID: "123.apps.googleusercontent.com", ProjectID: "my-gcp-project"},
		"github": {ClientID: "Iv1.0123456789abcdef"},
	}

	var found *knobGap
	for _, gap := range unwiredKnobs(cfg) {
		if gap.Path == "oauth.providers.google.projectId" {
			g := gap
			found = &g
		}
		if gap.Path == "oauth.providers.github.projectId" {
			t.Errorf("a provider with no projectId was reported anyway: %+v", gap)
		}
	}
	if found == nil {
		t.Fatalf("oauth.providers.google.projectId was not reported; gaps: %+v", unwiredKnobs(cfg))
	}
	if found.Problem == "" || found.Remedy == "" {
		t.Errorf("the gap has no problem or no remedy: %+v", *found)
	}
	if strings.Contains(fmt.Sprint(*found), "my-gcp-project") {
		t.Errorf("the report echoes the configured value rather than naming the knob: %+v", *found)
	}
}

// TestProviderWithoutTheLinkedAccountsStoreRefusesToStart: stores.enable
// defaults to users, sessions and tokens, so a deployment that configures a
// provider and nothing else has no linked-accounts store — and the core's
// OAuthComplete returns errStoreNotConfigured before it does anything, which
// the wire layer answers as 501 NOT_IMPLEMENTED.
//
// That 501 arrives after the authorization redirect has been sent and the
// person has consented at the provider, so it is not a feature quietly absent:
// it is a login nobody can finish, on a deployment that looks configured. RS-11
// refuses it at cold start instead, and this drives the real New to prove the
// refusal survives the whole composition rather than only the config package.
func TestProviderWithoutTheLinkedAccountsStoreRefusesToStart(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)

	_, err := New(context.Background(), Options{
		Getenv: envFunc(oauthEnvWithoutStores(t, oauthDoc(p))),
		Logger: discardLogger(),
		Stores: newOAuthStores().factory(),
	})
	if err == nil {
		t.Fatal("a provider with the linked-accounts store off was accepted, so the callback would 501 after the person consented")
	}
	for _, want := range []string{"stores.enable.linkedAccounts", "AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS", "RS-11"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// And with the store on, the same document builds — so the refusal is about
	// the store and not about anything else in the document.
	if _, err := New(context.Background(), Options{
		Getenv: envFunc(oauthEnv(t, oauthDoc(p))),
		Logger: discardLogger(),
		Stores: newOAuthStores().factory(),
	}); err != nil {
		t.Fatalf("the same document with the store on must build: %v", err)
	}
}

// TestOnEmailMatchConflictWithoutPendingLinksRefusesToStart: conflict's whole
// answer to a conflict is to stash it for POST /link-request to resolve, and
// the stash lives in the pending-links store. With the store off the core's
// stashAccountConflict returns immediately, the browser is still 302'd to
// /account-conflict, and the follow-up call can never identify anybody — a
// posture an operator selected deliberately, silently not applied.
func TestOnEmailMatchConflictWithoutPendingLinksRefusesToStart(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	doc := oauthDoc(p)
	provisioningDoc(doc)["onEmailMatch"] = "conflict"

	_, err := New(context.Background(), Options{
		Getenv: envFunc(oauthEnvWithoutStores(t, doc, "AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS", "true")),
		Logger: discardLogger(),
		Stores: newOAuthStores().factory(),
	})
	if err == nil {
		t.Fatal("onEmailMatch: conflict with the pending-links store off was accepted, so the conflict would be dropped silently")
	}
	for _, want := range []string{"oauth.provisioning.onEmailMatch", "stores.enable.pendingLinks", "RS-11"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// TestPendingLinksOffCostsTheReplayDefenceAndSaysSo: the store that backs the
// conflict flow also carries the state nonce — recorded at /oauth/{provider},
// consumed at the callback — which is what makes a state single-use instead of
// replayable for the whole of its TTL. RS-11 does not refuse that (it is the
// reference's own behaviour, signed and time-bounded), so the rule for a
// defence that disappears when a store key is left at its default is the rule
// for every unwired knob: it is announced at cold start, never silent.
func TestPendingLinksOffCostsTheReplayDefenceAndSaysSo(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.OAuth.Providers = map[string]config.OAuthProvider{
		"google": {ClientID: "123.apps.googleusercontent.com"},
	}
	cfg.Stores.Enable.LinkedAccounts = true

	var found *knobGap
	for _, gap := range unwiredKnobs(cfg) {
		if gap.Path == "stores.enable.pendingLinks" {
			g := gap
			found = &g
		}
	}
	if found == nil {
		t.Fatalf("the lost replay defence was not reported; gaps: %+v", unwiredKnobs(cfg))
	}
	if !strings.Contains(found.Problem, "replay") {
		t.Errorf("the report does not say what is lost: %+v", *found)
	}
	if found.Remedy == "" {
		t.Errorf("the gap has no remedy: %+v", *found)
	}

	// With the store on there is nothing to report, and with no provider at all
	// the knob is nobody's business.
	cfg.Stores.Enable.PendingLinks = true
	for _, gap := range unwiredKnobs(cfg) {
		if gap.Path == "stores.enable.pendingLinks" {
			t.Errorf("the store is on and it was still reported: %+v", gap)
		}
	}
	cfg.Stores.Enable.PendingLinks = false
	cfg.OAuth.Providers = nil
	for _, gap := range unwiredKnobs(cfg) {
		if gap.Path == "stores.enable.pendingLinks" {
			t.Errorf("no provider is configured and the store was still reported: %+v", gap)
		}
	}
}
