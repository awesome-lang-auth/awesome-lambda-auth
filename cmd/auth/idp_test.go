package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// idpKey is one RSA keypair with what the two signing paths need: a PKCS#8 PEM
// for idProvider.privateKey, and the kid both paths derive from the DER
// SubjectPublicKeyInfo, computed here independently of the code under test.
type idpKey struct {
	private *rsa.PrivateKey
	pem     string
	kid     string
}

func newIDPKey(t *testing.T) idpKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	sum := sha256.Sum256(spki)
	return idpKey{
		private: key,
		pem:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		kid:     base64.RawURLEncoding.EncodeToString(sum[:])[:16],
	}
}

// fakeKeyring is the key half of an AWS account: it holds the keypairs by id
// and hands out an IDPKeySource built over them, which signs with the real
// private key so a token it produced is verifiable by anything that fetches the
// JWKS document.
//
// It implements awsintegration.IDPKeySource — crypto.Signer plus Resolve and
// JWKS — and not the KMS client interface, which is the point: the seam
// cmd/auth is composed through is typed in crypto.Signer and auth.JWK, so this
// package and its tests never import the AWS SDK. The SDK-shaped fake, the one
// that asserts MessageType DIGEST and the 32-byte message, lives next to the
// code that speaks those types (internal/integration/aws/kms_test.go).
type fakeKeyring struct {
	mu   sync.Mutex
	keys map[string]idpKey
}

func newFakeKeyring(t *testing.T, ids ...string) *fakeKeyring {
	t.Helper()
	f := &fakeKeyring{keys: make(map[string]idpKey, len(ids))}
	for _, id := range ids {
		f.keys[id] = newIDPKey(t)
	}
	return f
}

func (f *fakeKeyring) key(t *testing.T, id string) idpKey {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.keys[id]
	if !ok {
		t.Fatalf("the fake holds no key %q", id)
	}
	return key
}

func (f *fakeKeyring) lookup(id string) (idpKey, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.keys[id]
	return key, ok
}

// source is an IDPKeySourceFactory: it is handed the key id and the retired
// list straight out of the configuration, exactly as the KMS-backed factory is,
// so a test proves the plumbing from the knob to the published document.
func (f *fakeKeyring) source(keyID string, previousKeyIDs []string, _ string) (awsintegration.IDPKeySource, error) {
	return &fakeKeySource{ring: f, keyID: keyID, previous: previousKeyIDs}, nil
}

type fakeKeySource struct {
	ring     *fakeKeyring
	keyID    string
	previous []string

	mu      sync.Mutex
	primary *idpKey
}

func (s *fakeKeySource) Resolve(_ context.Context) (string, error) {
	key, ok := s.ring.lookup(s.keyID)
	if !ok {
		return "", fmt.Errorf("no such key %q", s.keyID)
	}
	s.mu.Lock()
	s.primary = &key
	s.mu.Unlock()
	return key.kid, nil
}

// Public mirrors the real signer: nil until Resolve has run, which is what the
// core refuses at construction.
func (s *fakeKeySource) Public() crypto.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.primary == nil {
		return nil
	}
	return s.primary.private.Public()
}

func (s *fakeKeySource) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("RS256 signs a SHA-256 digest, got %v", opts)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("RS256 signs a %d-byte digest, got %d", sha256.Size, len(digest))
	}
	s.mu.Lock()
	primary := s.primary
	s.mu.Unlock()
	if primary == nil {
		return nil, fmt.Errorf("the signing key %q was never resolved", s.keyID)
	}
	return rsa.SignPKCS1v15(rand.Reader, primary.private, crypto.SHA256, digest)
}

func (s *fakeKeySource) JWKS(_ context.Context) ([]auth.JWK, error) {
	out := make([]auth.JWK, 0, 1+len(s.previous))
	for _, id := range append([]string{s.keyID}, s.previous...) {
		key, ok := s.ring.lookup(id)
		if !ok {
			return nil, fmt.Errorf("no such key %q", id)
		}
		jwk, err := auth.NewRSAJWK(&key.private.PublicKey, key.kid)
		if err != nil {
			return nil, err
		}
		out = append(out, jwk)
	}
	return out, nil
}

// newIDPApp builds an App in identity-provider mode with the fake key source
// injected.
func newIDPApp(t *testing.T, f *fakeKeyring, env map[string]string) *App {
	t.Helper()
	app, err := New(context.Background(), Options{
		Getenv:       envFunc(env),
		Logger:       discardLogger(),
		Stores:       memoryStores,
		IDPKeySource: f.source,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app
}

// newIDPAppLogging is newIDPApp with the log captured instead of discarded, at
// debug — for the assertions that are about what does NOT appear in it. It is a
// second constructor rather than a parameter on the first because every other
// identity test wants the log gone, and a writer threaded through forty call
// sites to be used by one of them is noise.
func newIDPAppLogging(t *testing.T, f *fakeKeyring, log io.Writer, env map[string]string) *App {
	t.Helper()
	app, err := New(context.Background(), Options{
		Getenv:       envFunc(env),
		Logger:       newLogger(log, slog.LevelDebug),
		Stores:       memoryStores,
		IDPKeySource: f.source,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app
}

// idpEnv is baseEnv plus identity-provider mode on a named KMS key. The public
// URL of baseEnv is what the issuer is derived from, so the derivation is
// exercised by every test that does not override it.
func idpEnv(kv ...string) map[string]string {
	return with(baseEnv(), append([]string{
		"AWESOME_AUTH_IDP_ENABLED", "true",
		"AWESOME_AUTH_IDP_KMS_KEY_ID", "current",
	}, kv...)...)
}

// jwtParts splits a compact JWS and decodes its header and payload. It refuses
// anything that is not three segments, because every assertion below is about a
// token and a two-segment string is not one.
func jwtParts(t *testing.T, token string) (header, payload map[string]any, signingInput string, signature []byte) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3: %q", len(parts), token)
	}
	decode := func(segment, what string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatalf("%s is not base64url: %v", what, err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s is not JSON: %v", what, err)
		}
		return m
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	return decode(parts[0], "header"), decode(parts[1], "payload"), parts[0] + "." + parts[1], sig
}

// jwks fetches the published document through the real event path, which is the
// only way to prove the route is mounted where a relying party will look.
func fetchJWKS(t *testing.T, app *App, path string) auth.JWKS {
	t.Helper()
	resp := invoke(t, app, http.MethodGet, path, nil, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (body %s)", path, resp.StatusCode, resp.Body)
	}
	if got := resp.Headers["Cache-Control"]; got != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q — the reference sets it and a relying party caches on it",
			got, "public, max-age=3600")
	}
	var document auth.JWKS
	if err := json.Unmarshal([]byte(resp.Body), &document); err != nil {
		t.Fatalf("JWKS body is not a JWKS: %v (%s)", err, resp.Body)
	}
	return document
}

// verifyWithJWKS is a relying party: find the key the token names, check the
// signature. Every rotation claim in this file rests on it.
func verifyWithJWKS(t *testing.T, document auth.JWKS, token string) {
	t.Helper()
	header, _, signingInput, signature := jwtParts(t, token)
	kid, _ := header["kid"].(string)
	if kid == "" {
		t.Fatal("the token names no kid, so a relying party cannot select a key")
	}
	for _, jwk := range document.Keys {
		if jwk.Kid != kid {
			continue
		}
		pub, err := jwk.RSAPublicKey()
		if err != nil {
			t.Fatalf("published JWK %q does not decode: %v", kid, err)
		}
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			t.Fatalf("the key published under %q does not verify a token signed under it: %v", kid, err)
		}
		return
	}
	t.Fatalf("the document publishes no key %q; it has %d keys", kid, len(document.Keys))
}

// ---------------------------------------------------------------------------
// JWKS and rotation
// ---------------------------------------------------------------------------

// TestJWKSListsEveryConfiguredKid is the rotation contract: while a key is
// listed, it is published, and every published key carries the six members the
// reference's JWK interface has.
func TestJWKSListsEveryConfiguredKid(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current", "previous-1", "previous-2")
	app := newIDPApp(t, f, idpEnv("AWESOME_AUTH_IDP_KMS_PREVIOUS_KEY_IDS", "previous-1,previous-2"))

	document := fetchJWKS(t, app, "/auth/.well-known/jwks.json")
	if len(document.Keys) != 3 {
		t.Fatalf("published %d keys, want 3 (the signing key and two retired ones)", len(document.Keys))
	}
	// The signing key first: a relying party with no kid to go on tries the head
	// of the list, and the reference publishes the active key there.
	want := []string{
		f.key(t, "current").kid,
		f.key(t, "previous-1").kid,
		f.key(t, "previous-2").kid,
	}
	for i, jwk := range document.Keys {
		if jwk.Kid != want[i] {
			t.Errorf("key %d has kid %q, want %q", i, jwk.Kid, want[i])
		}
		if jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" {
			t.Errorf("key %d is %+v, want kty RSA / use sig / alg RS256", i, jwk)
		}
		if jwk.N == "" || jwk.E == "" {
			t.Errorf("key %d publishes no modulus or exponent, so nothing can verify with it", i)
		}
	}
}

// TestRotatedKeyStillVerifies is the reason the retired list exists. A token
// signed by the previous key — a token minted before the rotation, still inside
// its lifetime — must keep verifying against the document served after it.
//
// The token is built with the retired key directly rather than by re-running the
// deployment, because that is what "a token minted before the rotation" is: a
// string a client is still holding.
func TestRotatedKeyStillVerifies(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current", "retired")
	app := newIDPApp(t, f, idpEnv("AWESOME_AUTH_IDP_KMS_PREVIOUS_KEY_IDS", "retired"))

	retired := f.key(t, "retired")
	old, err := auth.BuildRS256JWT(retired.private, retired.kid, map[string]any{
		"sub": "usr_before_the_rotation",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("build a token under the retired key: %v", err)
	}

	document := fetchJWKS(t, app, "/auth/.well-known/jwks.json")
	verifyWithJWKS(t, document, old)

	// And the new key is the one that signs now: an id_token minted by this
	// deployment names the current kid, not the retired one.
	current := f.key(t, "current")
	if document.Keys[0].Kid != current.kid {
		t.Errorf("the signing key is %q, want %q", document.Keys[0].Kid, current.kid)
	}
	if current.kid == retired.kid {
		t.Fatal("the two keys produced the same kid, so this test proves nothing")
	}
}

// TestJWKSPathIsConfigurable: the knob moves the route, and the discovery
// document has to follow it or every relying party looks in the wrong place.
func TestJWKSPathIsConfigurable(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current")
	app := newIDPApp(t, f, idpEnv("AWESOME_AUTH_IDP_JWKS_PATH", "/keys.json"))

	document := fetchJWKS(t, app, "/auth/keys.json")
	if len(document.Keys) != 1 {
		t.Fatalf("published %d keys, want 1", len(document.Keys))
	}
	if resp := invoke(t, app, http.MethodGet, "/auth/.well-known/jwks.json", nil, nil, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("the default JWKS path still answers %d after the knob moved it", resp.StatusCode)
	}
	if got := discovery(t, app)["jwks_uri"]; got != "https://auth.example.test/auth/keys.json" {
		t.Errorf("jwks_uri = %v, want the configured path", got)
	}
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func discovery(t *testing.T, app *App) map[string]any {
	t.Helper()
	resp := invoke(t, app, http.MethodGet, "/auth/.well-known/openid-configuration", nil, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery = %d, want 200 (body %s)", resp.StatusCode, resp.Body)
	}
	return decodeBody(t, resp)
}

// TestDiscoveryDocumentShape pins what a relying party's auto-configuration
// reads. Every endpoint must be absolute and rooted at the issuer, because a
// client resolves them without ever seeing this deployment's routing table.
func TestDiscoveryDocumentShape(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current")
	app := newIDPApp(t, f, idpEnv())

	doc := discovery(t, app)
	const issuer = "https://auth.example.test/auth"
	for key, want := range map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/authorize",
		"token_endpoint":         issuer + "/token",
		"userinfo_endpoint":      issuer + "/userinfo",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
	} {
		if doc[key] != want {
			t.Errorf("%s = %v, want %v", key, doc[key], want)
		}
	}
	for key, want := range map[string]string{
		"response_types_supported":              "code",
		"subject_types_supported":               "public",
		"id_token_signing_alg_values_supported": "RS256",
		"token_endpoint_auth_methods_supported": "client_secret_basic",
		"code_challenge_methods_supported":      "S256",
	} {
		list, ok := doc[key].([]any)
		if !ok || len(list) == 0 {
			t.Errorf("%s = %v, want a non-empty list", key, doc[key])
			continue
		}
		if list[0] != want {
			t.Errorf("%s[0] = %v, want %q", key, list[0], want)
		}
	}
	// Since awesome-go-auth v0.13.0 (#97) the token endpoint accepts both
	// RFC 6749 §2.3.1 methods, and advertises both.
	if methods, _ := doc["token_endpoint_auth_methods_supported"].([]any); len(methods) != 2 || methods[1] != "client_secret_post" {
		t.Errorf("token_endpoint_auth_methods_supported = %v, want [client_secret_basic client_secret_post]", methods)
	}
	// The issuer is where the discovery document is served from, which is what
	// makes it usable: <issuer>/.well-known/openid-configuration must be this
	// very route.
	if _, err := url.Parse(issuer); err != nil {
		t.Fatalf("issuer is not a URL: %v", err)
	}
}

// TestIdpIssuerDerivation covers the fallback order as a unit, because each step
// is a different deployment shape and driving four Apps would prove the same
// thing four times as slowly.
func TestIdpIssuerDerivation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "the configured issuer wins, trailing slash trimmed",
			env:  idpEnv("AWESOME_AUTH_IDP_ISSUER", "https://idp.example.test/issuer/"),
			want: "https://idp.example.test/issuer",
		},
		{
			name: "else the public URL plus the api prefix",
			env:  idpEnv(),
			want: "https://auth.example.test/auth",
		},
		{
			name: "the api prefix follows the knob",
			env:  idpEnv("AWESOME_AUTH_HTTP_API_PREFIX", "/identity"),
			want: "https://auth.example.test/identity",
		},
		{
			name: "else the canonical site URL",
			env: with(idpEnv(),
				"AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL", "",
				"AWESOME_AUTH_COOKIES_ALLOW_INSECURE_COOKIE_MODE", "true",
				"AWESOME_AUTH_EMAIL_SITE_URLS", "https://app.example.test"),
			want: "https://app.example.test/auth",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(tc.env)})
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			if got := idpIssuer(cfg); got != tc.want {
				t.Errorf("idpIssuer = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Mounting
// ---------------------------------------------------------------------------

// TestIDPEndpointsAreMounted drives all five OIDC endpoints. Since
// awesome-go-auth v0.7.0 the adapter mounts every one of them, so this is no
// longer a check on a split between two mounts but on the one mount: it is what
// tells a deployment of this binary that the surface the discovery document
// advertises is the surface it serves, without trusting the adapter to have
// kept mounting what it mounted at the tag before. A 404 is the failure;
// anything else means the route reached a handler.
func TestIDPEndpointsAreMounted(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current")
	app := newIDPApp(t, f, idpEnv())

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/auth/.well-known/jwks.json"},
		{http.MethodGet, "/auth/.well-known/openid-configuration"},
		{http.MethodGet, "/auth/authorize"},
		{http.MethodPost, "/auth/token"},
		{http.MethodGet, "/auth/userinfo"},
	} {
		resp := invoke(t, app, tc.method, tc.path, jsonHeaders(), nil, "")
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("%s %s answered 404; the discovery document advertises it", tc.method, tc.path)
		}
	}
}

// TestTheDeprecatedJWKSAliasIsNotServed pins a path this deployment stopped
// serving on purpose.
//
// <prefix>/jwks is the core's deprecated alias of the JWKS document. It is
// served by (*auth.IDP).RegisterHandlers and by no adapter, so it was reachable
// here only while this binary kept a mux of its own beside the adapter's — the
// arrangement awesome-go-auth v0.7.0 turned into a cold-start refusal by moving
// the four OIDC endpoints onto the adapters. The reasoning for letting the
// alias go with it is on idpMountedEndpoints.
//
// Asserted rather than left to happen so that the day something reintroduces a
// second mount — the alias or anything else — it is this test that says so,
// and not a pattern collision at cold start in a deployment.
func TestTheDeprecatedJWKSAliasIsNotServed(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current")
	app := newIDPApp(t, f, idpEnv())

	if resp := invoke(t, app, http.MethodGet, "/auth/jwks", jsonHeaders(), nil, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /auth/jwks = %d, want 404: the alias is the core's, mounted by no adapter, and this binary mounts nothing of its own", resp.StatusCode)
	}
}

// TestIDPIsOffByDefault: none of the five routes exists in a deployment that did
// not ask for identity-provider mode, so the surface cannot appear by accident.
func TestIDPIsOffByDefault(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())

	for _, path := range []string{
		"/auth/.well-known/jwks.json",
		"/auth/.well-known/openid-configuration",
		"/auth/authorize",
		"/auth/token",
		"/auth/userinfo",
	} {
		if resp := invoke(t, app, http.MethodGet, path, nil, nil, ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d with no idProvider block, want 404", path, resp.StatusCode)
		}
	}
}

// TestAJWKSPathThatCollidesIsRefusedNotPanicked: idProvider.jwksPath is the one
// knob that can make http.ServeMux register a pattern twice, and a panic inside
// the Lambda's init phase is a crash loop with a stack trace and no mention of
// the knob. The core refuses the four paths its own RegisterHandlers uses; the
// adapter's are caught here.
func TestAJWKSPathThatCollidesIsRefusedNotPanicked(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current")

	for _, path := range []string{
		"/me",       // an adapter route, mounted GET, like the JWKS document
		"/sessions", // another, to show it is not one special case
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			_, err := New(context.Background(), Options{
				Getenv:       envFunc(idpEnv("AWESOME_AUTH_IDP_JWKS_PATH", path)),
				Logger:       discardLogger(),
				Stores:       memoryStores,
				IDPKeySource: f.source,
			})
			if err == nil {
				t.Fatalf("New accepted a JWKS path of %q, which the adapter already mounts", path)
			}
			if !strings.Contains(err.Error(), "idProvider.jwksPath") {
				t.Errorf("the refusal does not name the knob:\n%v", err)
			}
		})
	}

	// And the core's own reserved paths are refused too, by the core, with the
	// knob's name in front of its message.
	_, err := New(context.Background(), Options{
		Getenv:       envFunc(idpEnv("AWESOME_AUTH_IDP_JWKS_PATH", "/token")),
		Logger:       discardLogger(),
		Stores:       memoryStores,
		IDPKeySource: f.source,
	})
	if err == nil {
		t.Fatal("New accepted a JWKS path of /token, which the OIDC token endpoint owns")
	}
}

// ---------------------------------------------------------------------------
// The OIDC round trip
// ---------------------------------------------------------------------------

// TestAuthorizationCodeFlowEndToEnd drives the whole net-new surface through
// synthetic Lambda events: a client authorizes, gets a code, exchanges it, and
// the id_token it receives verifies against the published JWKS.
//
// It also pins decision D-3 where it is observable: the access_token in that
// same response is the HS256 session token, not an RS256 one.
func TestAuthorizationCodeFlowEndToEnd(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current")
	app := newIDPApp(t, f, idpEnv(
		ConfigJSONEnv, clientDocument("console", "https://console.example.test/callback"),
		"AWESOME_AUTH_IDP_CLIENT_CONSOLE_SECRET", "console-client-secret",
	))

	const (
		email    = "oidc-user@example.test"
		redirect = "https://console.example.test/callback"
	)
	reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email))
	if reg.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d (%s)", reg.StatusCode, reg.Body)
	}

	// /authorize: the client is named in the query string and the credentials
	// are posted as a form, which is what the core's login form submits.
	form := url.Values{"email": {email}, "password": {testPassword}}
	authorize := invoke(t, app, http.MethodPost,
		"/auth/authorize?client_id=console&redirect_uri="+url.QueryEscape(redirect)+"&state=xyz&nonce=n-1",
		map[string]string{"content-type": "application/x-www-form-urlencoded"}, nil, form.Encode())
	if authorize.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d, want 302 (body %s)", authorize.StatusCode, authorize.Body)
	}
	location, err := url.Parse(authorize.Headers["Location"])
	if err != nil {
		t.Fatalf("Location is not a URL: %v", err)
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != redirect {
		t.Errorf("redirected to %q, want the registered %q", got, redirect)
	}
	if got := location.Query().Get("state"); got != "xyz" {
		t.Errorf("state = %q, want it echoed back", got)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", location)
	}

	// /token: client_secret_post, one of the two methods the discovery
	// document advertises. redirect_uri is required and must be the
	// authorization request's (RFC 6749 §4.1.3), which the core enforces since
	// awesome-go-auth v0.13.0 (#97).
	exchange := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {"console"},
		"client_secret": {"console-client-secret"},
	}
	tokenResp := invoke(t, app, http.MethodPost, "/auth/token",
		map[string]string{"content-type": "application/x-www-form-urlencoded"}, nil, exchange.Encode())
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token = %d, want 200 (body %s)", tokenResp.StatusCode, tokenResp.Body)
	}
	body := decodeBody(t, tokenResp)

	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatal("the token response carries no id_token")
	}
	document := fetchJWKS(t, app, "/auth/.well-known/jwks.json")
	verifyWithJWKS(t, document, idToken)

	header, claims, _, _ := jwtParts(t, idToken)
	if header["alg"] != "RS256" {
		t.Errorf("id_token alg = %v, want RS256", header["alg"])
	}
	if header["kid"] != f.key(t, "current").kid {
		t.Errorf("id_token kid = %v, want the signing key's %q", header["kid"], f.key(t, "current").kid)
	}
	if claims["aud"] != "console" {
		t.Errorf("id_token aud = %v, want the client id", claims["aud"])
	}
	if claims["nonce"] != "n-1" {
		t.Errorf("id_token nonce = %v, want it echoed from the authorization request", claims["nonce"])
	}
	if claims["iss"] != "https://auth.example.test/auth" {
		t.Errorf("id_token iss = %v, want the issuer the discovery document names", claims["iss"])
	}

	// D-3: the access token in the same response is the session token, HS256.
	accessHeader, _, _, _ := jwtParts(t, body["access_token"].(string))
	if accessHeader["alg"] != "HS256" {
		t.Errorf("access_token alg = %v, want HS256 — enabling the IdP must not re-sign the session pair (decisions.md D-3)", accessHeader["alg"])
	}

	// Single use: the code is spent, on this instance and on any other.
	replay := invoke(t, app, http.MethodPost, "/auth/token",
		map[string]string{"content-type": "application/x-www-form-urlencoded"}, nil, exchange.Encode())
	if replay.StatusCode != http.StatusBadRequest {
		t.Errorf("replaying the code = %d, want 400 invalid_grant (body %s)", replay.StatusCode, replay.Body)
	}
}

// clientDocument is the file-only half of the client registry: clients are an
// array of objects, which no environment variable can express.
func clientDocument(clientID string, redirectURIs ...string) string {
	doc := map[string]any{
		"schemaVersion": 1,
		"idProvider": map[string]any{
			"clients": []any{map[string]any{
				"clientId":     clientID,
				"name":         "Ops console",
				"redirectUris": redirectURIs,
			}},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// ---------------------------------------------------------------------------
// D-3: the session pair is untouched
// ---------------------------------------------------------------------------

// TestSessionTokensStayHS256InIdPMode is decision D-3 at the routes every family
// client uses. Enabling the IdP adds an issuer; it must not change a single byte
// of what /register, /login and /refresh hand back, or every shipped client in
// the family breaks on a configuration change they cannot see.
func TestSessionTokensStayHS256InIdPMode(t *testing.T) {
	t.Parallel()
	f := newFakeKeyring(t, "current")
	app := newIDPApp(t, f, idpEnv())

	const email = "hs256@example.test"
	bearer := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)

	reg := registerAndLogin(t, app, bearer, email)
	body := decodeBody(t, reg)

	for _, name := range []string{"accessToken", "refreshToken"} {
		token, _ := body[name].(string)
		if token == "" {
			t.Fatalf("login returned no %s", name)
		}
		header, _, _, _ := jwtParts(t, token)
		if header["alg"] != "HS256" {
			t.Errorf("%s alg = %v, want HS256", name, header["alg"])
		}
		if _, present := header["kid"]; present {
			t.Errorf("%s carries a kid, so a client may try to verify it against the JWKS document", name)
		}
	}

	login := invoke(t, app, http.MethodPost, "/auth/login", bearer, nil, registerBody(email))
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login = %d (%s)", login.StatusCode, login.Body)
	}
	header, _, _, _ := jwtParts(t, decodeBody(t, login)["accessToken"].(string))
	if header["alg"] != "HS256" {
		t.Errorf("login access token alg = %v, want HS256", header["alg"])
	}
}

// ---------------------------------------------------------------------------
// The PEM path
// ---------------------------------------------------------------------------

// TestPEMSignerPublishesTheSameDerivedKid: the reference's own configuration
// still works, and it derives its kid from the key material exactly as the KMS
// path does — which is what lets a deployment move a key into KMS without every
// token it already minted becoming unverifiable.
func TestPEMSignerPublishesTheSameDerivedKid(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	app := newTestApp(t, with(baseEnv(),
		"AWESOME_AUTH_IDP_ENABLED", "true",
		"AWESOME_AUTH_IDP_PRIVATE_KEY", key.pem))

	document := fetchJWKS(t, app, "/auth/.well-known/jwks.json")
	if len(document.Keys) != 1 {
		t.Fatalf("published %d keys, want 1", len(document.Keys))
	}
	if document.Keys[0].Kid != key.kid {
		t.Errorf("kid = %q, want the key-material fingerprint %q", document.Keys[0].Kid, key.kid)
	}

	token, err := auth.BuildRS256JWT(key.private, key.kid, map[string]any{"sub": "usr_1"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	verifyWithJWKS(t, document, token)
}

// TestAKeylessDevelopmentStackSaysSo: RS-4 lets a development stack run on an
// ephemeral key, and the one thing that must never happen is that it does so
// quietly — every token it mints dies at the next cold start.
func TestAKeylessDevelopmentStackSaysSo(t *testing.T) {
	t.Parallel()
	logged := captureLog(t, with(baseEnv(), "AWESOME_AUTH_IDP_ENABLED", "true"))
	for _, want := range []string{"ephemeral", "idProvider.kmsKeyId"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the cold-start log does not mention %q:\n%s", want, logged)
		}
	}
}

// ---------------------------------------------------------------------------
// Unwired knobs
// ---------------------------------------------------------------------------

// TestIDPKnobGapsAreReported: three idProvider knobs validate and then govern
// nothing, and the product's rule is that such a knob is named in the
// cold-start log rather than silently dropped.
func TestIDPKnobGapsAreReported(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	env := with(baseEnv(),
		"AWESOME_AUTH_IDP_ENABLED", "true",
		"AWESOME_AUTH_IDP_PRIVATE_KEY", key.pem,
		"AWESOME_AUTH_IDP_ACCESS_TTL", "1h",
		"AWESOME_AUTH_IDP_REFRESH_TTL", "14d",
		"AWESOME_AUTH_IDP_PUBLIC_KEY", "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----")

	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	paths := map[string]bool{}
	for _, gap := range unwiredKnobs(cfg) {
		paths[gap.Path] = true
		if gap.Problem == "" || gap.Remedy == "" {
			t.Errorf("gap %s has an empty problem or remedy", gap.Path)
		}
	}
	for _, want := range []string{"idProvider.accessTokenTtl", "idProvider.refreshTokenTtl", "idProvider.publicKey"} {
		if !paths[want] {
			t.Errorf("unwiredKnobs did not report %s", want)
		}
	}

	// And the knobs that ARE honoured must not be reported, or the warning turns
	// into noise nobody reads.
	for _, unwanted := range []string{"idProvider.kmsKeyId", "idProvider.issuer", "idProvider.jwksPath", "idProvider.clients"} {
		if paths[unwanted] {
			t.Errorf("unwiredKnobs reported %s, which is wired", unwanted)
		}
	}

	// A deployment with no IdP at all must report none of them: the gaps are
	// about a configured domain, not about the defaults.
	off, err := config.Load(context.Background(), config.Options{Getenv: envFunc(baseEnv())})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	for _, gap := range unwiredKnobs(off) {
		if strings.HasPrefix(gap.Path, "idProvider.") {
			t.Errorf("unwiredKnobs reported %s for a deployment with no identity provider", gap.Path)
		}
	}
}

// ---------------------------------------------------------------------------
// Resource-server mode
// ---------------------------------------------------------------------------

// jwksServer serves a JWKS document over TLS, which is what resource-server mode
// requires (RS-8 refuses a non-https URL). delay is how long the handler sleeps
// before answering, for the timeout case.
func jwksServer(t *testing.T, keys []idpKey, delay time.Duration) *httptest.Server {
	t.Helper()
	document := auth.JWKS{}
	for _, key := range keys {
		jwk, err := auth.NewRSAJWK(&key.private.PublicKey, key.kid)
		if err != nil {
			t.Fatalf("build JWK: %v", err)
		}
		document.Keys = append(document.Keys, jwk)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(document)
	}))
	t.Cleanup(server.Close)
	return server
}

func resourceServerApp(t *testing.T, server *httptest.Server, kv ...string) *App {
	t.Helper()
	env := with(baseEnv(), append([]string{
		"AWESOME_AUTH_RS_ENABLED", "true",
		"AWESOME_AUTH_RS_JWKS_URL", server.URL,
		"AWESOME_AUTH_RS_ISSUER", "https://idp.example.test",
	}, kv...)...)
	app, err := New(context.Background(), Options{
		Getenv:     envFunc(env),
		Logger:     discardLogger(),
		Stores:     memoryStores,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app
}

// TestResourceServerModeRejectsHS256AndUnmountsCredentialRoutes is both halves
// of the knob in one test, because they are one claim: this deployment issues no
// credentials and accepts only the tokens the configured issuer signed.
func TestResourceServerModeRejectsHS256AndUnmountsCredentialRoutes(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	server := jwksServer(t, []idpKey{key}, 0)
	app := resourceServerApp(t, server)

	// Half one: the credential surface is gone. Every route the core gates is
	// checked, not a sample, because the list is the security boundary.
	for path, method := range auth.ResourceServerGatedRoutes() {
		resp := invoke(t, app, method, "/auth"+path, jsonHeaders(), nil, "{}")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s /auth%s = %d in resource-server mode, want 404 — this deployment has no issuer behind it",
				method, path, resp.StatusCode)
		}
	}
	// And what stays: /me is still mounted, because the hybrid deployment that
	// also has a local store uses it.
	if resp := invoke(t, app, http.MethodGet, "/auth/me", nil, nil, ""); resp.StatusCode == http.StatusNotFound {
		t.Error("GET /auth/me was unmounted; resource-server mode gates credentials, not the account surface")
	}

	// Half two: the verifier. It is the deployment's own routes this guards, so
	// the test mounts it the way the authorizer will.
	if app.ResourceServerGuard == nil {
		t.Fatal("resource-server mode built no verifier")
	}
	guarded := app.ResourceServerGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := auth.UserFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": user.ID, "email": user.Email})
	}))

	// An HS256 token — the shape every other deployment in the family issues —
	// is refused: it is not signed by the issuer this server trusts, and the alg
	// allow-list refuses it before any key is even looked up.
	hs256 := hs256Token(t, testAccessSecret, map[string]any{"sub": "usr_local", "typ": "access"})
	rec := callGuarded(t, guarded, "Bearer "+hs256)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("an HS256 bearer = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "INVALID_TOKEN") {
		t.Errorf("body = %s, want the INVALID_TOKEN envelope", rec.Body.String())
	}

	// The issuer's own token is accepted, and the principal reaches the handler
	// from the claims alone — no store is read, which is the whole point of
	// resource-server mode.
	rs256, err := auth.BuildRS256JWT(key.private, key.kid, map[string]any{
		"sub":   "usr_remote",
		"email": "remote@example.test",
		"iss":   "https://idp.example.test",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rec = callGuarded(t, guarded, "Bearer "+rs256)
	if rec.Code != http.StatusOK {
		t.Fatalf("the issuer's own token = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var principal map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &principal); err != nil {
		t.Fatalf("handler body: %v", err)
	}
	if principal["sub"] != "usr_remote" || principal["email"] != "remote@example.test" {
		t.Errorf("principal = %v, want it built from the verified claims", principal)
	}

	// A token from another issuer, signed by a key nobody published, is refused.
	stranger := newIDPKey(t)
	forged, err := auth.BuildRS256JWT(stranger.private, stranger.kid, map[string]any{"sub": "usr_forged"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rec := callGuarded(t, guarded, "Bearer "+forged); rec.Code != http.StatusUnauthorized {
		t.Errorf("a token signed by an unpublished key = %d, want 401", rec.Code)
	}

	// And no credential at all is the code-less 403 the reference answers.
	if rec := callGuarded(t, guarded, ""); rec.Code != http.StatusForbidden {
		t.Errorf("no credential = %d, want 403", rec.Code)
	}
}

// TestIdentityProviderAndResourceServerAreMutuallyExclusive: the two knobs
// describe opposite deployments, and the combination is the one way the
// credential surface could come back after resource-server mode removed it —
// the core's POST <prefix>/authorize takes an email and a password and performs
// a full login, and POST <prefix>/token answers with this deployment's session
// pair. Every document in this product says resource-server mode unmounts the
// credential surface, so the pair is refused at cold start rather than served.
func TestIdentityProviderAndResourceServerAreMutuallyExclusive(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	server := jwksServer(t, []idpKey{key}, 0)

	both := func(t *testing.T, idp ...string) error {
		t.Helper()
		f := newFakeKeyring(t, "current")
		env := with(baseEnv(), append([]string{
			"AWESOME_AUTH_RS_ENABLED", "true",
			"AWESOME_AUTH_RS_JWKS_URL", server.URL,
		}, idp...)...)
		_, err := New(context.Background(), Options{
			Getenv:       envFunc(env),
			Logger:       discardLogger(),
			Stores:       memoryStores,
			IDPKeySource: f.source,
			HTTPClient:   server.Client(),
		})
		return err
	}

	for _, tc := range []struct {
		name string
		idp  []string
	}{
		{
			name: "the enable flag",
			idp:  []string{"AWESOME_AUTH_IDP_ENABLED", "true", "AWESOME_AUTH_IDP_KMS_KEY_ID", "current"},
		},
		{
			// The active predicate is "enabled, or key material present", so a
			// leftover key is the same deployment and must be refused the same
			// way; otherwise the hole reopens for the configuration least likely
			// to be noticed.
			name: "key material alone, with no enable flag",
			idp:  []string{"AWESOME_AUTH_IDP_KMS_KEY_ID", "current"},
		},
		{
			// The refusal is about the mode, not about where the key lives, so
			// the PEM path is refused exactly like the KMS one — with no fake
			// keyring anywhere near it. (The predicate's third arm is
			// PrivateKey.configured(), which is a *document* reference to a
			// store; the bare AWESOME_AUTH_IDP_PRIVATE_KEY carries the value
			// rather than a reference, so the flag is what turns the mode on
			// here, and RS-4 then reads the PEM out of the environment.)
			name: "a PEM private key",
			idp:  []string{"AWESOME_AUTH_IDP_ENABLED", "true", "AWESOME_AUTH_IDP_PRIVATE_KEY", key.pem},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := both(t, tc.idp...)
			if err == nil {
				t.Fatal("New accepted a deployment that is both an identity provider and a resource server")
			}
			for _, want := range []string{"resourceServer.enabled", "idProvider"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not name %s:\n%v", want, err)
				}
			}
		})
	}

	// And with the combination refused, the credential-taking OIDC routes are
	// simply absent from a resource server: nothing mounts them, which is the
	// property the refusal exists to keep true.
	t.Run("the OIDC credential routes are unmounted", func(t *testing.T) {
		t.Parallel()
		app := resourceServerApp(t, server)
		for _, tc := range []struct{ method, path string }{
			{http.MethodPost, "/auth/authorize"},
			{http.MethodGet, "/auth/authorize"},
			{http.MethodPost, "/auth/token"},
			{http.MethodGet, "/auth/userinfo"},
			{http.MethodGet, "/auth/.well-known/openid-configuration"},
			{http.MethodGet, "/auth/.well-known/jwks.json"},
		} {
			resp := invoke(t, app, tc.method, tc.path,
				map[string]string{"content-type": "application/x-www-form-urlencoded"}, nil, "email=a@example.test&password=x")
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s = %d in resource-server mode, want 404 — this deployment mints and takes no credential",
					tc.method, tc.path, resp.StatusCode)
			}
		}
	})
}

// TestResourceServerColdStartLogDoesNotClaimAMountedVerifier: the knob's whole
// effect on this artifact is subtraction — nineteen routes go away — and the
// verifier it builds is an export nothing here consults. An operator reading
// "resource-server mode wired" must not conclude that requests are being
// checked against the issuer's JWKS by this deployment.
func TestResourceServerColdStartLogDoesNotClaimAMountedVerifier(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	server := jwksServer(t, []idpKey{key}, 0)

	var buf bytes.Buffer
	if _, err := New(context.Background(), Options{
		Getenv: envFunc(with(baseEnv(),
			"AWESOME_AUTH_RS_ENABLED", "true",
			"AWESOME_AUTH_RS_JWKS_URL", server.URL)),
		Logger:     newLogger(&buf, slog.LevelDebug),
		Stores:     memoryStores,
		HTTPClient: server.Client(),
	}); err != nil {
		t.Fatalf("New: %v", err)
	}

	logged := buf.String()
	for _, want := range []string{
		"App.ResourceServerGuard",
		"no route in this deployment is verified by it",
		"unmountedCredentialRoutes",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("the cold-start log does not say %q:\n%s", want, logged)
		}
	}
}

// TestResourceServerIsOffByDefault: the guard is nil and the credential routes
// are mounted, so the knob cannot switch on by accident.
func TestResourceServerIsOffByDefault(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())
	if app.ResourceServerGuard != nil {
		t.Error("a deployment with no resourceServer block built a verifier")
	}
	if resp := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(), nil, "{}"); resp.StatusCode == http.StatusNotFound {
		t.Error("POST /auth/login is unmounted without resource-server mode")
	}
}

// TestJWKSFetchTimeoutIsBounded: an issuer that accepts the connection and then
// never answers must cost one request its timeout, not the whole function
// deadline.
//
// The assertion is on the wall clock, which is the only place the property is
// visible: a verifier with no timeout would sit on the read until API Gateway
// gave up at 29 seconds, and the caller would see a function timeout rather than
// a 401.
func TestJWKSFetchTimeoutIsBounded(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	const (
		timeout = 300 * time.Millisecond
		hang    = 10 * time.Second
	)
	server := jwksServer(t, []idpKey{key}, hang)
	app := resourceServerApp(t, server,
		"AWESOME_AUTH_RS_JWKS_FETCH_TIMEOUT_MS", "300")

	guarded := app.ResourceServerGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	token, err := auth.BuildRS256JWT(key.private, key.kid, map[string]any{"sub": "usr_remote"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	start := time.Now()
	rec := callGuarded(t, guarded, "Bearer "+token)
	elapsed := time.Since(start)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a request whose JWKS fetch timed out = %d, want 401", rec.Code)
	}
	// Generous, because the point is the order of magnitude: bounded by the
	// configured timeout rather than by the issuer's willingness to answer.
	if elapsed > hang/2 {
		t.Errorf("the request took %s with a %s fetch timeout; the fetch is not bounded", elapsed, timeout)
	}
}

// TestResourceServerNeedsTheAccessSecret: RS-1 tells the operator the signing
// secrets are not required in resource-server mode, and the auth core requires
// one anyway. The refusal has to name the knob, or the deployment fails with a
// message about something the operator was told to leave out.
func TestResourceServerNeedsTheAccessSecret(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	server := jwksServer(t, []idpKey{key}, 0)

	env := map[string]string{
		"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT": "development",
		"AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL":  "https://auth.example.test",
		"AWESOME_AUTH_RS_ENABLED":             "true",
		"AWESOME_AUTH_RS_JWKS_URL":            server.URL,
	}
	_, err := New(context.Background(), Options{
		Getenv:     envFunc(env),
		Logger:     discardLogger(),
		Stores:     memoryStores,
		HTTPClient: server.Client(),
	})
	if err == nil {
		t.Fatal("New succeeded with no access-token secret in resource-server mode")
	}
	if !strings.Contains(err.Error(), "security.jwt.accessTokenSecret") {
		t.Errorf("the refusal does not name the knob:\n%v", err)
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func callGuarded(t *testing.T, h http.Handler, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test/orders", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// hs256Token mints the shape this deployment's own session tokens have, so the
// resource-server refusal is tested against a real local credential rather than
// against a string that merely fails to parse.
func hs256Token(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// captureLog runs a cold start and returns everything it wrote, for the
// assertions that are about what an operator is told rather than about what the
// deployment answers.
func captureLog(t *testing.T, env map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := New(context.Background(), Options{
		Getenv: envFunc(env),
		Logger: newLogger(&buf, slog.LevelDebug),
		Stores: memoryStores,
	}); err != nil {
		t.Fatalf("New: %v", err)
	}
	return buf.String()
}
