package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// security.jwt.refreshTokenSecret reaches the core (auth.WithRefreshSecret).
// Through the v0.13.0 pin RS-1 required it and nothing signed with it: the
// core fell back to the access secret (refresh-secret-falls-back-to-secret)
// and unwiredKnobs said so on every cold start. These tests pin what the
// wiring changes on the wire, and the one-time cost of deploying it.

// hs256Verifies reports whether a compact JWS carries an HMAC-SHA256
// signature under secret over its first two segments.
func hs256Verifies(token, secret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(parts[2]))
}

// TestRefreshTokensAreSignedWithTheRefreshSecret: the access token is signed
// with security.jwt.accessTokenSecret, the refresh token with
// security.jwt.refreshTokenSecret and not with the access secret — the
// reference's separation (token.service.ts:20-29) — and POST /refresh
// verifies it under that key, on a login and on the pair a refresh mints.
func TestRefreshTokensAreSignedWithTheRefreshSecret(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	login := registerAndLogin(t, app, bearerJSON, "refresh-secret@example.test")

	check := func(t *testing.T, step string, body map[string]any) string {
		t.Helper()
		access, _ := body["accessToken"].(string)
		refresh, _ := body["refreshToken"].(string)
		if access == "" || refresh == "" {
			t.Fatalf("%s answered no token pair: %v", step, body)
		}
		if !hs256Verifies(access, testAccessSecret) {
			t.Errorf("%s: the access token does not verify under security.jwt.accessTokenSecret", step)
		}
		if !hs256Verifies(refresh, testRefreshSecret) {
			t.Errorf("%s: the refresh token does not verify under security.jwt.refreshTokenSecret", step)
		}
		if hs256Verifies(refresh, testAccessSecret) {
			t.Errorf("%s: the refresh token verifies under the ACCESS secret: the core is still falling back to it", step)
		}
		return refresh
	}
	refresh := check(t, "login", decodeBody(t, login))

	rotated := invoke(t, app, http.MethodPost, "/auth/refresh", bearerJSON, nil, fmt.Sprintf(`{"refreshToken":%q}`, refresh))
	if rotated.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/refresh with the login's refresh token answered %d %s, want 200", rotated.StatusCode, rotated.Body)
	}
	check(t, "refresh", decodeBody(t, rotated))
}

// TestTheDeployThatWiresTheRefreshSecretSignsEverySessionOut is the BREAKING
// half, stated as a test so nobody has to take the CHANGELOG's word for it. A
// refresh token minted by the build before — a core holding the access secret
// alone, which is what coreOptions built through the v0.13.0 pin — is refused
// by this build on the same stores, because it was signed with the access
// secret; the same token still refreshes on the build before, so the refusal
// is the key and not the session. That is the one global sign-out the deploy
// costs, and rolling back is a second one in the other direction.
func TestTheDeployThatWiresTheRefreshSecretSignsEverySessionOut(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users, sessions := newMemoryStoreBundle(), auth.NewMemorySessionStore()

	before, err := auth.New(
		auth.WithSecret(testAccessSecret),
		auth.WithBcryptCost(10),
		auth.WithUserStore(users),
		auth.WithSessionStore(sessions),
	)
	if err != nil {
		t.Fatalf("the build before: %v", err)
	}
	const email = "outstanding@example.test"
	if _, _, err := before.Register(ctx, auth.RegisterInput{Email: email, Password: testPassword}); err != nil {
		t.Fatalf("register on the build before: %v", err)
	}
	_, outstanding, err := before.Login(ctx, auth.LoginInput{Email: email, Password: testPassword})
	if err != nil {
		t.Fatalf("login on the build before: %v", err)
	}
	if !hs256Verifies(outstanding.RefreshToken, testAccessSecret) {
		t.Fatal("the build before did not sign its refresh token with the access secret, so this test proves nothing")
	}

	after, err := New(ctx, Options{
		Getenv: envFunc(baseEnv()),
		Logger: discardLogger(),
		Stores: storeFactory(users, sessions),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(after.Close)
	refused := invoke(t, after, http.MethodPost, "/auth/refresh", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"refreshToken":%q}`, outstanding.RefreshToken))
	if refused.StatusCode != http.StatusUnauthorized {
		t.Fatalf("this build answered %d %s to a refresh token the build before minted, want 401: the deploy no longer signs sessions out, so the CHANGELOG's BREAKING note is stale",
			refused.StatusCode, refused.Body)
	}
	// The access token handed out before the deploy runs to its expiry: it is
	// still signed with the key that signs access tokens.
	if me := invoke(t, after, http.MethodGet, "/auth/me", bearer(outstanding.AccessToken), nil, ""); me.StatusCode != http.StatusOK {
		t.Errorf("the access token minted before the deploy answered %d on GET /auth/me, want 200 until it expires", me.StatusCode)
	}
	if _, err := before.Refresh(ctx, outstanding.RefreshToken); err != nil {
		t.Errorf("the build before no longer refreshes its own token (%v), so the 401 above may not be the key", err)
	}
}

// TestAResourceServerWithNoRefreshSecretStarts: RS-1 asks a resource server for
// the access secret alone, because nothing there mints or verifies a refresh
// token, and auth.WithRefreshSecret refuses an empty value rather than reading
// it as "fall back". coreOptions passes the option only when the secret
// resolved to something, which is what keeps this composition starting.
func TestAResourceServerWithNoRefreshSecretStarts(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	server := jwksServer(t, []idpKey{key}, 0)
	app, err := New(context.Background(), Options{
		Getenv: envFunc(map[string]string{
			"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT": "development",
			"AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL":  "https://auth.example.test",
			"AWESOME_AUTH_JWT_ACCESS_SECRET":      testAccessSecret,
			"AWESOME_AUTH_RS_ENABLED":             "true",
			"AWESOME_AUTH_RS_JWKS_URL":            server.URL,
		}),
		Logger:     discardLogger(),
		Stores:     memoryStores,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("a resource server with no refresh secret refused to start: %v", err)
	}
	app.Close()
}

// TestAResourceServerWithAShortRefreshSecretStarts: RS-1 does not check a
// resource server's refresh secret, because no route there verifies a refresh
// token (config.VerifiesRefreshTokens), so coreOptions does not hand it to the
// core either — auth.WithRefreshSecret refuses one under 32 characters, and a
// resource server configured with one started before the secret was wired and
// must go on starting. The cold start reports the knob as unread instead. The
// same short secret off resource-server mode is RS-1's refusal, the control.
func TestAResourceServerWithAShortRefreshSecretStarts(t *testing.T) {
	t.Parallel()
	key := newIDPKey(t)
	server := jwksServer(t, []idpKey{key}, 0)
	for name, refresh := range map[string]string{
		"short":                      "too-short",
		"equal to the access secret": testAccessSecret,
		"one RS-1 would accept":      testRefreshSecret,
	} {
		env := map[string]string{
			"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT": "development",
			"AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL":  "https://auth.example.test",
			"AWESOME_AUTH_JWT_ACCESS_SECRET":      testAccessSecret,
			"AWESOME_AUTH_JWT_REFRESH_SECRET":     refresh,
			"AWESOME_AUTH_RS_ENABLED":             "true",
			"AWESOME_AUTH_RS_JWKS_URL":            server.URL,
		}
		app, err := New(context.Background(), Options{
			Getenv:     envFunc(env),
			Logger:     discardLogger(),
			Stores:     memoryStores,
			HTTPClient: server.Client(),
		})
		if err != nil {
			t.Errorf("a resource server with a %s refresh secret refused to start: %v", name, err)
			continue
		}
		app.Close()
		var reported bool
		for _, gap := range unwiredKnobs(loadTestConfig(t, env)) {
			reported = reported || gap.Path == "security.jwt.refreshTokenSecret"
		}
		if !reported {
			t.Errorf("a resource server's %s refresh secret is not reported as unread at cold start", name)
		}
	}

	_, err := config.Load(context.Background(), config.Options{Getenv: envFunc(with(baseEnv(), "AWESOME_AUTH_JWT_REFRESH_SECRET", "too-short"))})
	if err == nil || !strings.Contains(err.Error(), config.RuleSecrets) {
		t.Errorf("a short refresh secret off resource-server mode loaded (%v); RS-1 must refuse it", err)
	}
	for _, gap := range unwiredKnobs(loadTestConfig(t, baseEnv())) {
		if gap.Path == "security.jwt.refreshTokenSecret" {
			t.Errorf("the refresh secret is reported unread on a deployment that verifies refresh tokens: %s", gap.Problem)
		}
	}
}
