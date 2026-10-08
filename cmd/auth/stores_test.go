package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// This file answers one question end to end: with every store implemented, does
// any mounted route still report that its store is missing?
//
// It has to be asked of the routes and not of the compile-time assertions.
// interfaces.go proves the *shapes* are right, and cannot prove the store reached
// the core — the four single-use stores and TOTPStore arrive by type assertion on
// whatever was handed to auth.WithUserStore, and the two OAuth stores arrive
// through auth.WithOAuth, which nothing in the store package can do for itself. A
// composition that dropped either would build, pass every store test, and answer
// 501 on the wire.
//
// Two shapes of failure are looked for:
//
//   - 501 NOT_IMPLEMENTED, which is what auth.ErrFeatureNotSupported maps to
//     (wire.go:164) and therefore what an absent optional store produces;
//   - a 500 whose body says "UserStore does not implement …", the three literals
//     the password/email wire layer uses for an incapable user store
//     (wire_password_email.go:50-52).

// mountedRoute is one route of the adapter's surface, with enough of a request to
// get past the router and into the flow method that consults a store.
type mountedRoute struct {
	method string
	path   string
	body   string

	// bearer sends the registered user's access token. The routes behind the
	// access-token middleware answer 401 without it and never reach their store,
	// which would make this whole test vacuous for them.
	bearer bool

	// wantStatus, when non-zero, pins an answer this test wants to be explicit
	// about rather than merely "not 501".
	wantStatus int

	// why documents a pinned status.
	why string
}

// mountedRoutes is the adapter's full surface as of awesome-go-auth v0.3.1.
//
// Unlike TestNoInventedAuthRoutes, enumerating it here is the point: the question
// is whether every route can reach a store, and that cannot be sampled. When the
// upstream surface grows, this list is meant to fail until somebody has decided
// whether the new route needs a store this port does not have.
func mountedRoutes() []mountedRoute {
	return []mountedRoute{
		{method: http.MethodPost, path: "/auth/register", body: registerBody("sweep-register@example.test")},
		{method: http.MethodPost, path: "/auth/login", body: registerBody(testEmail)},
		{method: http.MethodPost, path: "/auth/refresh", body: `{}`},
		{method: http.MethodPost, path: "/auth/logout", body: `{}`},
		{method: http.MethodGet, path: "/auth/me", bearer: true},
		{method: http.MethodGet, path: "/auth/sessions", bearer: true},
		{method: http.MethodDelete, path: "/auth/sessions/nonexistent-handle", bearer: true,
			wantStatus: http.StatusNotFound,
			why:        "SessionAdminStore is wired and answers ErrSessionNotFound for a handle nobody owns; this 404 is the route's, not the router's"},
		{method: http.MethodPost, path: "/auth/sessions/cleanup", body: `{}`},
		{method: http.MethodPatch, path: "/auth/profile", bearer: true, body: `{"firstName":"Ada","lastName":"Lovelace"}`},
		{method: http.MethodPost, path: "/auth/add-phone", bearer: true, body: `{"phoneNumber":"+390123456789"}`},

		// OAuth. Both of these answer the reference's per-provider "not
		// configured" stub, because the sweep's environment configures no
		// oauth.providers entry: the registry is empty, so the route answers the
		// stub exactly as the reference does with no strategy passed. That is a
		// configuration gap and not a store gap, which is exactly why the status
		// is pinned here instead of merely being "not 501" — a provider-backed
		// deployment is driven end to end in oauth_test.go instead.
		{method: http.MethodGet, path: "/auth/oauth/google", wantStatus: http.StatusNotFound,
			why: "no oauth.providers entry is configured, so the registry is empty and the route answers the reference's 404 stub"},
		{method: http.MethodGet, path: "/auth/oauth/google/callback", wantStatus: http.StatusNotFound,
			why: "same 404 stub; OAuthComplete is never reached, so its LinkedAccounts check cannot 501"},

		// Account linking. These need no provider registry — only the two stores.
		{method: http.MethodGet, path: "/auth/linked-accounts", bearer: true, wantStatus: http.StatusOK,
			why: "LinkedAccountStore is wired, so the list renders instead of answering NOT_IMPLEMENTED"},
		{method: http.MethodDelete, path: "/auth/linked-accounts/google/sub-unknown", bearer: true, wantStatus: http.StatusOK,
			why: "unlinking an absent binding is success, as the reference answers unconditionally"},
		{method: http.MethodPost, path: "/auth/link-request", body: `{"email":"nobody@example.test","provider":"google"}`,
			wantStatus: http.StatusUnauthorized,
			why:        "PendingLinkStore is wired and consulted; there is simply no stashed conflict and no access token, which is the identity failure the reference answers 401 for"},
		{method: http.MethodPost, path: "/auth/link-verify", body: `{"token":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
			wantStatus: http.StatusBadRequest,
			why:        "PendingLinkStore is wired and answers not-found for a token nobody issued"},

		// Passwordless, 2FA, password and email flows.
		{method: http.MethodPost, path: "/auth/magic-link/send", body: `{"email":"` + testEmail + `"}`},
		{method: http.MethodPost, path: "/auth/magic-link/verify", body: `{"token":"nope"}`},
		{method: http.MethodPost, path: "/auth/sms/send", body: `{"email":"` + testEmail + `"}`},
		{method: http.MethodPost, path: "/auth/sms/verify", body: `{"email":"` + testEmail + `","code":"000000"}`},
		{method: http.MethodPost, path: "/auth/2fa/setup", bearer: true, body: `{}`, wantStatus: http.StatusOK,
			why: "enrolment is stateless: the secret is generated and handed to the client without a store"},
		{method: http.MethodPost, path: "/auth/2fa/verify-setup", bearer: true, body: `{"secret":"JBSWY3DPEHPK3PXP","code":"000000"}`,
			wantStatus: http.StatusBadRequest,
			why:        "TOTPStore is wired; the code simply does not validate, which is ErrInvalidCode and not NOT_IMPLEMENTED"},
		{method: http.MethodPost, path: "/auth/2fa/verify", body: `{"email":"` + testEmail + `","code":"000000"}`},
		{method: http.MethodPost, path: "/auth/2fa/disable", bearer: true, body: `{}`, wantStatus: http.StatusOK,
			why: "TOTPStore is wired, so disabling writes to the profile instead of answering NOT_IMPLEMENTED"},
		{method: http.MethodPost, path: "/auth/forgot-password", body: `{"email":"` + testEmail + `"}`},
		{method: http.MethodPost, path: "/auth/reset-password", body: `{"token":"nope","newPassword":"` + testPassword + `"}`},
		{method: http.MethodPost, path: "/auth/change-password", bearer: true,
			body: `{"currentPassword":"` + testPassword + `","newPassword":"another-` + testPassword + `"}`},
		{method: http.MethodPost, path: "/auth/send-verification-email", bearer: true, body: `{}`},
		{method: http.MethodGet, path: "/auth/verify-email?token=nope"},
		{method: http.MethodPost, path: "/auth/change-email/request", bearer: true, body: `{"newEmail":"moved@example.test"}`},
		{method: http.MethodPost, path: "/auth/change-email/confirm", body: `{"token":"nope"}`},
	}
}

// storeSweepEnv turns on the two stores.enable keys the account-linking routes
// are gated behind. Everything else is baseEnv.
func storeSweepEnv(extra ...string) map[string]string {
	return with(baseEnv(), append([]string{
		"AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS", "true",
		"AWESOME_AUTH_STORES_ENABLE_PENDING_LINKS", "true",
	}, extra...)...)
}

// sweepRoutes drives every mounted route through the Lambda event path and reports
// the ones whose store is missing.
func sweepRoutes(t *testing.T, app *App, creds sweepCredentials) {
	t.Helper()
	for _, route := range mountedRoutes() {
		headers := jsonHeaders()
		var cookies []string
		if route.bearer {
			// A request presenting a bearer token is exempt from the double-submit
			// check, which is the reference's own rule (csrf.go:204-215).
			headers["authorization"] = "Bearer " + creds.accessToken
		} else {
			// Everything else has to satisfy CSRF, or the request never reaches the
			// flow method and the sweep would prove nothing about its store. The
			// pair is what a browser client sends: the cookie the middleware
			// distributed, echoed in the header.
			headers[auth.CSRFHeaderName] = creds.csrfToken
			cookies = append(cookies, auth.CSRFTokenCookieName+"="+creds.csrfToken)
		}
		resp := invoke(t, app, route.method, route.path, headers, cookies, route.body)
		label := route.method + " " + route.path

		// A 404 from the mux is net/http's plain-text "404 page not found"; every
		// answer from the wire layer is a JSON envelope. That is what tells "this
		// binary is not serving the route" from "the route's own answer is 404",
		// which DELETE /sessions/{handle} legitimately gives for an unknown handle.
		if resp.StatusCode == http.StatusNotFound && !strings.HasPrefix(strings.TrimSpace(resp.Body), "{") {
			t.Errorf("%s is not routed: %q", label, resp.Body)
			continue
		}
		if resp.StatusCode == http.StatusNotImplemented {
			t.Errorf("%s answered 501 NOT_IMPLEMENTED, which means the core could not find a store for it: %s", label, resp.Body)
			continue
		}
		if strings.Contains(resp.Body, "does not implement") {
			t.Errorf("%s answered %d with an incapable-store error: %s", label, resp.StatusCode, resp.Body)
			continue
		}
		if strings.Contains(resp.Body, auth.CodeNotImplemented) {
			t.Errorf("%s answered %d carrying %s: %s", label, resp.StatusCode, auth.CodeNotImplemented, resp.Body)
			continue
		}
		if resp.StatusCode == http.StatusForbidden {
			// Nothing in this sweep should be answered by the CSRF layer; if one is,
			// the request never reached its store and the rest of the assertions
			// below are vacuous.
			t.Errorf("%s was rejected before reaching its store: %s", label, resp.Body)
			continue
		}
		if route.wantStatus != 0 && resp.StatusCode != route.wantStatus {
			t.Errorf("%s status = %d, want %d (%s); body %s", label, resp.StatusCode, route.wantStatus, route.why, resp.Body)
		}
	}
}

// sweepCredentials is what a caller needs to get past the auth gate and the CSRF
// gate respectively.
type sweepCredentials struct {
	accessToken string
	csrfToken   string
}

// registerAndToken registers the fixture user and harvests both credentials.
func registerAndToken(t *testing.T, app *App, email string) sweepCredentials {
	t.Helper()
	resp := invoke(t, app, http.MethodPost, "/auth/register",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, registerBody(email))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201 (body %s)", resp.StatusCode, resp.Body)
	}
	token, _ := decodeBody(t, resp)["accessToken"].(string)
	if token == "" {
		t.Fatalf("register returned no access token: %s", resp.Body)
	}

	// A bearer registration is sent no cookies at all, deliberately, so the CSRF
	// token has to come from a cookie-mode request. Any guarded route distributes
	// one; a login with no credentials is the cheapest.
	csrf := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(), nil, `{}`)
	var csrfToken string
	for _, c := range csrf.Cookies {
		if name, value, ok := strings.Cut(c, "="); ok && name == auth.CSRFTokenCookieName {
			csrfToken, _, _ = strings.Cut(value, ";")
		}
	}
	if csrfToken == "" {
		t.Fatalf("no %s cookie was distributed, so no unauthenticated route can be driven: %v",
			auth.CSRFTokenCookieName, csrf.Cookies)
	}
	return sweepCredentials{accessToken: token, csrfToken: csrfToken}
}

// TestEveryMountedRouteFindsItsStore is the memory-driver sweep. It runs in a
// plain checkout with no container, so the wiring regression it catches — an
// option dropped from the composition — is caught by everybody's `go test ./...`.
func TestEveryMountedRouteFindsItsStore(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, storeSweepEnv())
	sweepRoutes(t, app, registerAndToken(t, app, testEmail))
}

// TestLinkingRoutesAreGatedByTheirStoreKeys is the other half of the gate: with
// the two keys off, the account-linking routes must answer NOT_IMPLEMENTED rather
// than a 500 or a silent success. A disabled store makes its feature routes
// absent, which is what the schema promises (config.StoreEnable) and what the
// reference does with an absent injected store.
func TestLinkingRoutesAreGatedByTheirStoreKeys(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())
	creds := registerAndToken(t, app, testEmail)

	for _, route := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/auth/linked-accounts", ""},
		{http.MethodDelete, "/auth/linked-accounts/google/sub-1", ""},
		{http.MethodPost, "/auth/link-request", `{"email":"` + testEmail + `"}`},
		{http.MethodPost, "/auth/link-verify", `{"token":"nope"}`},
	} {
		// A bearer credential exempts every one of these from the CSRF check, so
		// the answer under test is the store gate and nothing else.
		resp := invoke(t, app, route.method, route.path,
			jsonHeaders("authorization", "Bearer "+creds.accessToken), nil, route.body)
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("%s %s with the store keys off = %d, want 501 (body %s)",
				route.method, route.path, resp.StatusCode, resp.Body)
		}
	}
}

// TestDynamoDBBackedRoutesFindEveryStore is the same sweep against the real
// DynamoDB store, which is the one that matters: the memory driver satisfies every
// optional interface upstream, so only this run can tell whether *this port's*
// seven implementations are the ones the core finds.
//
// It skips cleanly when DynamoDB Local is not reachable, like the store package's
// own suite:
//
//	docker run -d --name ddblocal -p 8000:8000 amazon/dynamodb-local
//	DYNAMODB_ENDPOINT=http://localhost:8000 go test -count=1 ./cmd/auth/...
func TestDynamoDBBackedRoutesFindEveryStore(t *testing.T) {
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run this end-to-end sweep")
	}
	// No t.Parallel: the AWS SDK reads its credentials from the environment and
	// t.Setenv forbids parallel tests. DynamoDB Local validates a signature's
	// shape, not its contents, so any non-empty pair will do.
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()
	table := "authtest_cmd_auth_" + randomSuffix(t)
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{
		Region:   "us-east-1",
		Endpoint: endpoint,
	})
	if err != nil {
		t.Skipf("cannot build a DynamoDB client for %s: %v", endpoint, err)
	}
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Skipf("cannot create %s at %s (%v); start DynamoDB Local with: "+
			"docker run -d --name ddblocal -p 8000:8000 amazon/dynamodb-local", table, endpoint, err)
	}

	// The real factory, reached through the real configuration path, so the
	// composition under test is the deployed one: nothing here injects a store.
	app, err := New(ctx, Options{
		Getenv: envFunc(storeSweepEnv(
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

	sweepRoutes(t, app, registerAndToken(t, app, testEmail))
}

// TestDynamoDBStoreSatisfiesTheOAuthWiring pins the assertion the sweep depends
// on but cannot make visible: the concrete store is what the composition root
// looks for, structurally.
func TestDynamoDBStoreSatisfiesTheOAuthWiring(t *testing.T) {
	t.Parallel()
	store, err := ddbstore.New(stubDynamoAPI{}, ddbstore.Options{TableName: "unused", Logger: discardLogger()})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	provider, ok := any(store).(oauthStoreProvider)
	if !ok {
		t.Fatal("*dynamodb.Store does not satisfy oauthStoreProvider, so auth.WithOAuth would never be called for it")
	}
	if provider.LinkedAccounts() == nil || provider.PendingLinks() == nil {
		t.Fatal("the OAuth store views are nil")
	}
	// Not OAuth, but discovered the same structural way and silent the same
	// way when it drifts: GET <admin>/api/users/{id} falls back to the empty
	// tenant without it.
	if !asserts[auth.UserLookupStore](store) {
		t.Error("*dynamodb.Store does not satisfy auth.UserLookupStore, so the admin detail route cannot span tenants")
	}
	// And the memory bundle, so the development driver cannot drift out of shape
	// either.
	if _, ok := any(memoryStoreBundle{MemoryUserStore: auth.NewMemoryUserStore()}).(oauthStoreProvider); !ok {
		t.Fatal("memoryStoreBundle does not satisfy oauthStoreProvider")
	}
	// The bundle must not narrow what the core finds on the user store.
	bundle := memoryStoreBundle{MemoryUserStore: auth.NewMemoryUserStore()}
	for name, satisfied := range map[string]bool{
		"MagicLinkStore":         asserts[auth.MagicLinkStore](bundle),
		"SMSStore":               asserts[auth.SMSStore](bundle),
		"EmailVerificationStore": asserts[auth.EmailVerificationStore](bundle),
		"EmailChangeStore":       asserts[auth.EmailChangeStore](bundle),
		"TOTPStore":              asserts[auth.TOTPStore](bundle),
		"UserPasswordStore":      asserts[auth.UserPasswordStore](bundle),
		// The admin detail route's tenant-spanning lookup (core v0.12.0):
		// hidden, the route quietly falls back to the empty tenant.
		"UserLookupStore": asserts[auth.UserLookupStore](bundle),
	} {
		if !satisfied {
			t.Errorf("memoryStoreBundle hides %s from the core's type assertion", name)
		}
	}
}

// TestDynamoDBStoreSatisfiesTheTemplateStore pins the other capability the
// core does not discover by type assertion. auth.TemplateStore is handed to it
// through auth.WithTemplateStore, so if the DynamoDB store drifted out of shape
// nothing would fail to build — the templates knob would simply do nothing, and
// every mail would keep rendering the built-in template. The concrete store
// must satisfy the interface directly (its methods are on *Store, see the
// package's interfaces.go) and expose it through Templates(), which is what the
// composition root looks for, structurally, the way it finds the OAuth views.
func TestDynamoDBStoreSatisfiesTheTemplateStore(t *testing.T) {
	t.Parallel()
	store, err := ddbstore.New(stubDynamoAPI{}, ddbstore.Options{TableName: "unused", Logger: discardLogger()})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if !asserts[auth.TemplateStore](store) {
		t.Fatal("*dynamodb.Store does not satisfy auth.TemplateStore, so auth.WithTemplateStore could never receive it")
	}
	templates := store.Templates()
	if templates == nil {
		t.Fatal("Templates() returned nil")
	}
	if templates != auth.TemplateStore(store) {
		t.Fatal("Templates() returned something other than the store itself; the methods are meant to be on *Store")
	}
}

func asserts[T any](v any) bool {
	_, ok := v.(T)
	return ok
}

// localDynamoDBEndpoint reads the same variable the store package's harness does,
// so one environment variable turns on both suites.
func localDynamoDBEndpoint() (string, bool) {
	endpoint := strings.TrimSpace(os.Getenv("DYNAMODB_ENDPOINT"))
	return endpoint, endpoint != ""
}

// randomSuffix keeps each run's table to itself.
func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// stubDynamoAPI satisfies dynamodb.API for the pure type-assertion test, which
// must not open a socket. Every method is promoted from a nil embedded interface
// and would panic if called, which is the point: nothing here calls one.
type stubDynamoAPI struct{ ddbstore.API }
