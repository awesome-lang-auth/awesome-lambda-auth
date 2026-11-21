package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	auth "github.com/nik2208/awesome-go-auth"
	"golang.org/x/crypto/bcrypt"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The realm knobs end to end: registration.closed, twoFactor.required and
// twoFactor.enrolOnLogin, each driven through the composition New builds and a
// synthetic API Gateway event, because each is one field on the way to the
// core and the only claim worth pinning is what the wire then answers.

// totpCodeNow is RFC 6238 with the reference's parameters — HMAC-SHA1, six
// digits, a 30-second step — for the current step, waiting out a step that is
// about to roll over so a slow request cannot turn a good code into a stale
// one. test/contract has the same function; a test package cannot import it.
func totpCodeNow(t *testing.T, secret string) string {
	t.Helper()
	const step = 30 * time.Second
	if left := step - time.Duration(time.Now().UnixNano())%step; left < 3*time.Second {
		time.Sleep(left + 200*time.Millisecond)
	}
	s := strings.ToUpper(strings.TrimSpace(secret))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("TOTP secret %q is not base32: %v", secret, err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix())/uint64(step.Seconds()))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

// sessionCookies is every access or refresh cookie a response set, whatever
// its prefix.
func sessionCookies(resp events.APIGatewayV2HTTPResponse) []string {
	var out []string
	for _, c := range resp.Cookies {
		name, _, _ := strings.Cut(c, "=")
		if strings.HasSuffix(name, "accessToken") || strings.HasSuffix(name, "refreshToken") {
			out = append(out, name)
		}
	}
	return out
}

// seedAccount writes an account straight into a memory bundle, the way an
// invitation flow or cmd/migrate would on a realm whose public route is closed.
func seedAccount(t *testing.T, users memoryStoreBundle, id, email string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if _, err := users.CreateUser(context.Background(), auth.User{ID: id, Email: email, PasswordHash: string(hash), IsEmailVerified: true}); err != nil {
		t.Fatalf("seed %s: %v", email, err)
	}
}

// ── registration.closed ──────────────────────────────────────────────────────

// TestClosedRegistrationUnmountsTheRouteAndNothingElse: with registration.closed
// the adapter does not register POST <prefix>/register, so it answers the
// router's 404 in both delivery modes and opens nothing; GET <prefix>/ui/config
// says features.register false and the served OpenAPI document leaves the path
// out (core v0.14.0, register-route-is-always-mounted). An account created by
// the deployment's own hand still logs in. The open default is the control:
// the same composition without the knob registers, reports true and documents
// the route, so the closed half cannot pass on a route that was never there.
func TestClosedRegistrationUnmountsTheRouteAndNothingElse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		closed bool
	}{
		{"closed", true},
		{"open, the default", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			users := newMemoryStoreBundle()
			const invited = "invited@example.test"
			seedAccount(t, users, "usr_00000000000000000000000invited", invited)
			env := with(baseEnv(), "AWESOME_AUTH_UI_ENABLED", "true", "AWESOME_AUTH_DOCS_SWAGGER", "true")
			if tc.closed {
				env = with(env, "AWESOME_AUTH_REGISTRATION_CLOSED", "true")
			}
			app, err := New(context.Background(), Options{
				Getenv: envFunc(env),
				Logger: discardLogger(),
				Stores: storeFactory(users, auth.NewMemorySessionStore()),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(app.Close)

			for i, mode := range []map[string]string{jsonHeaders(), jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)} {
				reg := invoke(t, app, http.MethodPost, "/auth/register", mode, nil, registerBody(fmt.Sprintf("stranger-%d@example.test", i)))
				switch {
				case tc.closed && reg.StatusCode != http.StatusNotFound:
					t.Errorf("POST /auth/register on a closed realm answered %d %s, want the router's 404", reg.StatusCode, reg.Body)
				case !tc.closed && reg.StatusCode != http.StatusCreated:
					t.Errorf("POST /auth/register on an open realm answered %d %s, want 201", reg.StatusCode, reg.Body)
				}
				if got := sessionCookies(reg); len(got) > 0 {
					t.Errorf("POST /auth/register set %v; registration opens no session on either realm", got)
				}
			}
			if tc.closed {
				if _, err := users.GetUserByEmail(context.Background(), "stranger-0@example.test", ""); err == nil {
					t.Error("a closed realm stored the account a refused registration named")
				}
			}

			login := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, loginBody(invited, testPassword))
			if login.StatusCode != http.StatusOK || decodeBody(t, login)["accessToken"] == nil {
				t.Errorf("the seeded account's login answered %d %s, want 200 with a session: closing registration closes nothing else", login.StatusCode, login.Body)
			}

			uiCfg := invoke(t, app, http.MethodGet, "/auth/ui/config", nil, nil, "")
			features, _ := decodeBody(t, uiCfg)["features"].(map[string]any)
			if got, want := features["register"], !tc.closed; got != want {
				t.Errorf("GET /auth/ui/config features.register = %v, want %v", got, want)
			}

			doc := invoke(t, app, http.MethodGet, "/auth/openapi.json", nil, nil, "")
			var spec struct {
				Paths map[string]any `json:"paths"`
			}
			if err := json.Unmarshal([]byte(doc.Body), &spec); err != nil || len(spec.Paths) == 0 {
				t.Fatalf("GET /auth/openapi.json answered %d with no paths: %v", doc.StatusCode, err)
			}
			if _, documented := spec.Paths["/auth/register"]; documented == tc.closed {
				t.Errorf("the served document lists /auth/register = %v on a realm with registration.closed = %v", documented, tc.closed)
			}
			if _, ok := spec.Paths["/auth/login"]; !ok {
				t.Error("the served document lost /auth/login, so the check above proves nothing")
			}
		})
	}
}

// ── twoFactor.required ───────────────────────────────────────────────────────

// TestTwoFactorRequiredAtLogin: under twoFactor.required (core
// Config.Require2FA, enforced at login since v0.14.0) a password alone opens
// no session. An account with no factor gets the reference's
// 403 {"requires2FASetup":true,"tempToken":…,"code":"2FA_SETUP_REQUIRED"},
// whose token opens nothing and — with twoFactor.enrolOnLogin off — enrols
// nothing; an enrolled account gets the challenge. The default is the control:
// a fresh account's password logs it straight in.
func TestTwoFactorRequiredAtLogin(t *testing.T) {
	t.Parallel()
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)

	t.Run("an account with no factor is told to enrol, and given nothing else", func(t *testing.T) {
		t.Parallel()
		app := newTestApp(t, with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true"))
		const email = "required@example.test"
		if reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email)); reg.StatusCode != http.StatusCreated {
			t.Fatalf("register answered %d %s", reg.StatusCode, reg.Body)
		}
		for _, mode := range []map[string]string{jsonHeaders(), bearerJSON} {
			login := invoke(t, app, http.MethodPost, "/auth/login", mode, nil, loginBody(email, testPassword))
			if login.StatusCode != http.StatusForbidden {
				t.Fatalf("login of an account with no factor answered %d %s, want 403 2FA_SETUP_REQUIRED", login.StatusCode, login.Body)
			}
			body := decodeBody(t, login)
			if body["requires2FASetup"] != true || body["code"] != "2FA_SETUP_REQUIRED" {
				t.Errorf("the refusal is not the reference's setup-required body: %s", login.Body)
			}
			temp, _ := body["tempToken"].(string)
			if temp == "" {
				t.Fatalf("the setup-required answer carries no tempToken: %s", login.Body)
			}
			if _, leaked := body["accessToken"]; leaked {
				t.Errorf("the setup-required answer carries an access token: %s", login.Body)
			}
			if got := sessionCookies(login); len(got) > 0 {
				t.Errorf("the setup-required answer set %v", got)
			}
			if me := invoke(t, app, http.MethodGet, "/auth/me", bearer(temp), nil, ""); me.StatusCode == http.StatusOK {
				t.Errorf("the setup-required tempToken opened GET /auth/me: %s", me.Body)
			}
			// Without twoFactor.enrolOnLogin the token is the step-up token,
			// and the enrolment routes take an access token only.
			if setup := invoke(t, app, http.MethodPost, "/auth/2fa/setup", jsonHeaders("authorization", "Bearer "+temp), nil, "{}"); setup.StatusCode == http.StatusOK {
				t.Errorf("POST /auth/2fa/setup accepted the setup-required token with twoFactor.enrolOnLogin off: %s", setup.Body)
			}
		}
	})

	t.Run("an enrolled account is challenged", func(t *testing.T) {
		t.Parallel()
		users := newMemoryStoreBundle()
		const id, email = "usr_0000000000000000000000enrolled", "enrolled@example.test"
		seedAccount(t, users, id, email)
		if err := users.UpdateTOTPSecret(context.Background(), id, "", "JBSWY3DPEHPK3PXP", true); err != nil {
			t.Fatalf("enable TOTP: %v", err)
		}
		app, err := New(context.Background(), Options{
			Getenv: envFunc(with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true")),
			Logger: discardLogger(),
			Stores: storeFactory(users, auth.NewMemorySessionStore()),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		login := invoke(t, app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(email, testPassword))
		if login.StatusCode != http.StatusOK || decodeBody(t, login)["requiresTwoFactor"] != true {
			t.Fatalf("login of an enrolled account answered %d %s, want the 200 challenge", login.StatusCode, login.Body)
		}
		done := invoke(t, app, http.MethodPost, "/auth/2fa/verify", bearerJSON, nil,
			fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, decodeBody(t, login)["tempToken"], totpCodeNow(t, "JBSWY3DPEHPK3PXP")))
		if done.StatusCode != http.StatusOK || decodeBody(t, done)["accessToken"] == nil {
			t.Fatalf("POST /auth/2fa/verify answered %d %s, want a session", done.StatusCode, done.Body)
		}
		// And the policy refuses the off-switch, with no settings store.
		token, _ := decodeBody(t, done)["accessToken"].(string)
		off := invoke(t, app, http.MethodPost, "/auth/2fa/disable", jsonHeaders("authorization", "Bearer "+token), nil, "{}")
		if off.StatusCode != http.StatusForbidden || decodeBody(t, off)["code"] != "2FA_REQUIRED" {
			t.Errorf("POST /auth/2fa/disable under twoFactor.required answered %d %s, want 403 2FA_REQUIRED", off.StatusCode, off.Body)
		}
	})

	t.Run("without the knob a password alone logs in", func(t *testing.T) {
		t.Parallel()
		app := newTestApp(t, baseEnv())
		login := registerAndLogin(t, app, bearerJSON, "default@example.test")
		if decodeBody(t, login)["accessToken"] == nil {
			t.Fatalf("the default realm's login opened no session: %s", login.Body)
		}
	})
}

// ── twoFactor.enrolOnLogin ───────────────────────────────────────────────────

// forcedEnrolment walks the flow twoFactor.enrolOnLogin opens on one App and
// asserts each step: the setup-required login, POST /2fa/setup with the
// enrolment token as the bearer credential (how a client written against the
// reference sends it), POST /2fa/verify-setup with the secret the server
// answered, the session that opens, the replay refused, and the next login
// challenged for the factor just bound.
func forcedEnrolment(t *testing.T, app *App, email string) {
	t.Helper()
	if reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email)); reg.StatusCode != http.StatusCreated {
		t.Fatalf("register answered %d %s", reg.StatusCode, reg.Body)
	}
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	login := invoke(t, app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(email, testPassword))
	if login.StatusCode != http.StatusForbidden || decodeBody(t, login)["code"] != "2FA_SETUP_REQUIRED" {
		t.Fatalf("login answered %d %s, want 403 2FA_SETUP_REQUIRED", login.StatusCode, login.Body)
	}
	temp, _ := decodeBody(t, login)["tempToken"].(string)
	withTemp := jsonHeaders("authorization", "Bearer "+temp, auth.AuthStrategyHeader, auth.AuthStrategyBearer)

	if me := invoke(t, app, http.MethodGet, "/auth/me", bearer(temp), nil, ""); me.StatusCode == http.StatusOK {
		t.Fatalf("the enrolment token opened GET /auth/me: %s", me.Body)
	}

	setup := invoke(t, app, http.MethodPost, "/auth/2fa/setup", withTemp, nil, "{}")
	if setup.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/2fa/setup with the enrolment token answered %d %s, want 200", setup.StatusCode, setup.Body)
	}
	secret, _ := decodeBody(t, setup)["secret"].(string)
	if secret == "" {
		t.Fatalf("setup answered no secret: %s", setup.Body)
	}

	verify := invoke(t, app, http.MethodPost, "/auth/2fa/verify-setup", withTemp, nil,
		fmt.Sprintf(`{"secret":%q,"token":%q}`, secret, totpCodeNow(t, secret)))
	if verify.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/2fa/verify-setup with the enrolment token answered %d %s, want 200 and a session", verify.StatusCode, verify.Body)
	}
	access, _ := decodeBody(t, verify)["accessToken"].(string)
	if access == "" || decodeBody(t, verify)["refreshToken"] == nil {
		t.Fatalf("verify-setup with the enrolment token opened no session: %s", verify.Body)
	}
	me := invoke(t, app, http.MethodGet, "/auth/me", bearer(access), nil, "")
	if me.StatusCode != http.StatusOK || decodeBody(t, me)["isTotpEnabled"] != true {
		t.Fatalf("GET /auth/me with the new session answered %d %s, want 200 with isTotpEnabled true", me.StatusCode, me.Body)
	}

	// The token dies the moment a factor exists, so a replay enrols nothing a
	// second time. As the body's tempToken it is the step-up routes' 401
	// INVALID_TEMP_TOKEN; as a bearer credential it is neither an enrolment
	// token nor an access token any more, and the gate answers the access
	// refusal it answers any dead bearer (core TOTPEnrolmentCaller).
	replay := invoke(t, app, http.MethodPost, "/auth/2fa/verify-setup", bearerJSON, nil,
		fmt.Sprintf(`{"tempToken":%q,"secret":%q,"token":%q}`, temp, secret, totpCodeNow(t, secret)))
	if replay.StatusCode != http.StatusUnauthorized || decodeBody(t, replay)["code"] != "INVALID_TEMP_TOKEN" {
		t.Errorf("a replayed enrolment (body tempToken) answered %d %s, want 401 INVALID_TEMP_TOKEN", replay.StatusCode, replay.Body)
	}
	replayBearer := invoke(t, app, http.MethodPost, "/auth/2fa/verify-setup", withTemp, nil,
		fmt.Sprintf(`{"secret":%q,"token":%q}`, secret, totpCodeNow(t, secret)))
	if replayBearer.StatusCode != http.StatusForbidden || decodeBody(t, replayBearer)["error"] != "Invalid or expired access token" {
		t.Errorf("a replayed enrolment (bearer) answered %d %s, want 403 Invalid or expired access token", replayBearer.StatusCode, replayBearer.Body)
	}

	again := invoke(t, app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(email, testPassword))
	if again.StatusCode != http.StatusOK || decodeBody(t, again)["requiresTwoFactor"] != true {
		t.Errorf("the next login answered %d %s, want the challenge for the factor just enrolled", again.StatusCode, again.Body)
	}
}

// TestForcedEnrolmentOpensTheSession is twoFactor.enrolOnLogin on the memory
// driver; TestForcedEnrolmentOnDynamoDB below is the same flow on the store a
// deployment runs, because "the token dies once a factor exists" is a read of
// the stored profile and its TOTP state, which only the real store can answer.
func TestForcedEnrolmentOpensTheSession(t *testing.T) {
	t.Parallel()
	forcedEnrolment(t, newTestApp(t, with(baseEnv(),
		"AWESOME_AUTH_2FA_REQUIRED", "true",
		"AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true",
	)), "forced@example.test")
}

func TestForcedEnrolmentOnDynamoDB(t *testing.T) {
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run forced enrolment on the deployed driver")
	}
	// No t.Parallel, for the reason TestDynamoDBBackedRoutesFindEveryStore gives.
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()
	table := "authtest_cmd_auth_" + randomSuffix(t)
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Skipf("cannot build a DynamoDB client for %s: %v", endpoint, err)
	}
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Skipf("cannot create %s at %s (%v)", table, endpoint, err)
	}
	app, err := New(ctx, Options{
		Getenv: envFunc(with(baseEnv(),
			"AWESOME_AUTH_STORES_DRIVER", config.StoreDriverDynamoDB,
			"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", table,
			"AWESOME_AUTH_STORES_CONNECTION_REGION", "us-east-1",
			"AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", endpoint,
			"AWESOME_AUTH_2FA_REQUIRED", "true",
			"AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true",
		)),
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("New with the dynamodb driver: %v", err)
	}
	t.Cleanup(app.Close)
	forcedEnrolment(t, app, "forced-ddb@example.test")
}

// TestTwoFactorOptionsCarryThePolicy: the two policy options reach the core as
// written, true and false alike, beside the issuer.
func TestTwoFactorOptionsCarryThePolicy(t *testing.T) {
	t.Parallel()
	for _, env := range []map[string]string{
		baseEnv(),
		with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true"),
		with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true", "AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true"),
	} {
		cfg := loadTestConfig(t, env)
		core, err := auth.New(append([]auth.Option{
			auth.WithSecret(testAccessSecret),
			auth.WithUserStore(auth.NewMemoryUserStore()),
			auth.WithSessionStore(auth.NewMemorySessionStore()),
		}, twoFactorOptions(cfg)...)...)
		if err != nil {
			t.Fatalf("auth.New with the two-factor options: %v", err)
		}
		policy, err := core.TwoFactorPolicy(context.Background())
		if err != nil {
			t.Fatalf("TwoFactorPolicy: %v", err)
		}
		if policy != cfg.TwoFactor.Required {
			t.Errorf("the core's policy is %v for twoFactor.required %v", policy, cfg.TwoFactor.Required)
		}
		if core.EnrolOnLogin() != cfg.TwoFactor.EnrolOnLogin {
			t.Errorf("the core's EnrolOnLogin is %v for twoFactor.enrolOnLogin %v", core.EnrolOnLogin(), cfg.TwoFactor.EnrolOnLogin)
		}
	}
}

// TestClosedRealmRefusesAnUnverifiedAddressAtAnAllowedDomain is RS-19's
// narrowed shape, end to end. On b20ef56 a closed realm narrowed to
// example.test signed up a stranger whose provider asserted
// stranger@example.test with email_verified false: the core matches the domain
// on the asserted address, and oauth.provisioning.requireVerifiedEmail is off
// by default. That configuration no longer starts. With verification required
// it does, the same assertion is refused and creates nobody, and a verified
// address at the domain still signs up — the realm the two knobs are for.
func TestClosedRealmRefusesAnUnverifiedAddressAtAnAllowedDomain(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	p.setProfile(`{"sub":"stranger-1","email":"stranger@example.test","email_verified":false,"name":"Stranger"}`)
	doc := oauthDoc(p)
	provisioningDoc(doc)["allowedEmailDomains"] = []any{"example.test"}

	_, err := New(context.Background(), Options{
		Getenv: envFunc(oauthEnv(t, doc, "AWESOME_AUTH_REGISTRATION_CLOSED", "true")),
		Logger: discardLogger(),
		Stores: newOAuthStores().factory(),
	})
	if err == nil {
		t.Fatal("a closed realm narrowed by domain, with requireVerifiedEmail off, started: its callback signs up any address the provider asserts there")
	}
	for _, want := range []string{config.RuleClosedRegistrationOAuth, "oauth.provisioning.requireVerifiedEmail", "example.test"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	stores := newOAuthStores()
	app := newOAuthApp(t, doc, stores, "AWESOME_AUTH_REGISTRATION_CLOSED", "true", "AWESOME_AUTH_OAUTH_PROVISIONING_REQUIRE_VERIFIED_EMAIL", "true")
	t.Cleanup(app.Close)
	refused := signIn(t, app, p, nil)
	if refused.StatusCode != http.StatusForbidden || len(sessionCookies(refused)) > 0 {
		t.Errorf("the unverified assertion answered %d %v, want 403 and no session", refused.StatusCode, refused.Cookies)
	}
	if u, err := stores.users.GetUserByEmail(context.Background(), "stranger@example.test", ""); err == nil {
		t.Errorf("a closed realm created %s for an address the provider did not verify", u.ID)
	}

	p.setProfile(`{"sub":"colleague-1","email":"colleague@example.test","email_verified":true,"name":"Colleague"}`)
	admitted := signIn(t, app, p, nil)
	if admitted.StatusCode != http.StatusFound || cookieValue(t, admitted, auth.AccessTokenCookieName) == "" {
		t.Errorf("a verified address at the allowed domain answered %d %v, want the 302 with a session", admitted.StatusCode, admitted.Cookies)
	}
}
