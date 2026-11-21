package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The per-account cap on failed second-factor checks (secondfactor_cap.go).
//
// Every case runs with rateLimit budgets far above the cap — 20 logins per
// email, 20 checks per challenge, a day long — and from a fresh source address
// per request, so that a 429 in them can only be the account's cap: no
// per-challenge, per-email or per-address budget is anywhere near spent.

const lockoutTestMax = 4

func lockoutTestEnv(base map[string]string) map[string]string {
	return with(base,
		"AWESOME_AUTH_RATE_LIMIT_MAX", "20",
		"AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS", "86400",
		"AWESOME_AUTH_2FA_LOCKOUT_MAX_FAILURES", fmt.Sprint(lockoutTestMax),
		"AWESOME_AUTH_2FA_LOCKOUT_WINDOW_SECONDS", "86400",
	)
}

// lockoutRig is where a case sends its requests: two Apps over one store on
// DynamoDB (two execution environments, so a refusal on one for checks made on
// the other is the shared counter's), one App twice on the memory driver.
type lockoutRig struct {
	apps     [2]*App
	register func(t *testing.T, email string) string // returns the user id
	enrolID  func(t *testing.T, id, secret string)
}

func lockoutMemoryRig(t *testing.T, env map[string]string) (lockoutRig, *deliveryApp, memoryStoreBundle) {
	t.Helper()
	users := newMemoryStoreBundle()
	d := newDeliveryAppWith(t, lockoutTestEnv(env), func(o *Options) {
		o.Stores = storeFactory(users, auth.NewMemorySessionStore())
		o.Logger = discardLogger()
	})
	t.Cleanup(d.app.Close)
	return lockoutRig{
		apps:     [2]*App{d.app, d.app},
		register: func(t *testing.T, email string) string { return registerForSubjectTest(t, d.app, email) },
		enrolID: func(t *testing.T, id, secret string) {
			t.Helper()
			if err := users.UpdateTOTPSecret(context.Background(), id, "", secret, true); err != nil {
				t.Fatalf("enrol %s in TOTP: %v", id, err)
			}
		},
	}, d, users
}

func lockoutDynamoDBRig(t *testing.T) lockoutRig {
	t.Helper()
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run the shared-counter case")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")
	ctx := context.Background()
	table := "authtest_2fa_lockout_" + randomSuffix(t)
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Fatalf("DynamoDB client for %s: %v", endpoint, err)
	}
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Fatalf("create %s at %s: %v", table, endpoint, err)
	}
	store, err := ddbstore.New(client, ddbstore.Options{TableName: table, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("ddbstore.New: %v", err)
	}
	env := lockoutTestEnv(with(baseEnv(),
		"AWESOME_AUTH_STORES_DRIVER", config.StoreDriverDynamoDB,
		"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", table,
		"AWESOME_AUTH_STORES_CONNECTION_REGION", "us-east-1",
		"AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", endpoint,
	))
	environment := func() *App {
		app, err := New(ctx, Options{Getenv: envFunc(env), Logger: discardLogger()})
		if err != nil {
			t.Fatalf("New with the dynamodb driver: %v", err)
		}
		t.Cleanup(app.Close)
		return app
	}
	a, b := environment(), environment()
	return lockoutRig{
		apps:     [2]*App{a, b},
		register: func(t *testing.T, email string) string { return registerForSubjectTest(t, a, email) },
		enrolID: func(t *testing.T, id, secret string) {
			t.Helper()
			if err := store.UpdateTOTPSecret(ctx, id, "", secret, true); err != nil {
				t.Fatalf("enrol %s in TOTP: %v", id, err)
			}
		},
	}
}

// sweepIsStoppedAtTheAccountCap is the review's sweep: many logins, several
// wrong codes on each challenge, every request from a new address. Without the
// cap each login mints a challenge with a budget of its own and every code is
// checked; with it exactly lockoutTestMax are checked for the account, the
// rest answer 429 — the right code on a fresh challenge included — and another
// account is untouched.
func sweepIsStoppedAtTheAccountCap(t *testing.T, rig lockoutRig) {
	owner, other := "sweep-owner@example.test", "sweep-other@example.test"
	rig.enrolID(t, rig.register(t, owner), subjectOwnerSecret)
	rig.enrolID(t, rig.register(t, other), subjectOtherSecret)
	addr := freshAddresses(t)
	n := 0
	post := func(path, body string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		n++
		return invokeFrom(t, rig.apps[n%2], addr(), http.MethodPost, path, body)
	}
	verify := func(challenge, code string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		return post("/auth/2fa/verify", fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, challenge, code))
	}

	const logins, codesPerLogin = 6, 3
	checked, refused := 0, 0
	for i := 0; i < logins; i++ {
		challenge := stepUpChallenge(t, post("/auth/login", loginBody(owner, testPassword)))
		for j := 0; j < codesPerLogin; j++ {
			switch resp := verify(challenge, wrongTOTP(t, subjectOwnerSecret)); {
			case resp.StatusCode == http.StatusUnauthorized && strings.Contains(resp.Body, "Invalid TOTP code"):
				checked++
			case resp.StatusCode == http.StatusTooManyRequests:
				if resp.Body != rateLimitBody || resp.Headers["Retry-After"] == "" {
					t.Errorf("the cap's refusal is not the rate limiter's 429: %v %s", resp.Headers, resp.Body)
				}
				refused++
			default:
				t.Fatalf("a wrong code answered %d %s", resp.StatusCode, resp.Body)
			}
		}
	}
	if checked != lockoutTestMax || refused != logins*codesPerLogin-lockoutTestMax {
		t.Fatalf("of %d wrong codes over %d logins, %d were checked and %d refused; want exactly %d checked (the account's cap) and the rest refused",
			logins*codesPerLogin, logins, checked, refused, lockoutTestMax)
	}

	// The right code, on a challenge nobody has guessed at, from an address
	// nobody has used: only the account's cap can refuse it.
	fresh := stepUpChallenge(t, post("/auth/login", loginBody(owner, testPassword)))
	if resp := verify(fresh, totpAt(t, subjectOwnerSecret, time.Now())); resp.StatusCode != http.StatusTooManyRequests || opensSession(resp) {
		t.Fatalf("the right code on a fresh challenge of the capped account answered %d %.160s, want 429 and no session", resp.StatusCode, resp.Body)
	}

	// Another account keeps its own count.
	otherChallenge := stepUpChallenge(t, post("/auth/login", loginBody(other, testPassword)))
	if resp := verify(otherChallenge, totpAt(t, subjectOtherSecret, time.Now())); resp.StatusCode != http.StatusOK || !opensSession(resp) {
		t.Fatalf("another account's right code answered %d %.160s, want 200 with a session", resp.StatusCode, resp.Body)
	}
}

func TestSecondFactorLockoutStopsTheSweep(t *testing.T) {
	t.Parallel()
	rig, _, _ := lockoutMemoryRig(t, baseEnv())
	sweepIsStoppedAtTheAccountCap(t, rig)
}

// TestSecondFactorLockoutSharedCounterStopsTheSweep is the same case on the
// production tier: the checks alternate between two execution environments
// over one table, so neither one has seen the account's whole count and every
// refusal is the shared counter's.
func TestSecondFactorLockoutSharedCounterStopsTheSweep(t *testing.T) {
	sweepIsStoppedAtTheAccountCap(t, lockoutDynamoDBRig(t))
}

// forgedTokensSpendNothing: a caller who cannot get a token minted for the
// victim cannot spend the victim's count. Tokens that name the victim but do
// not verify — signed with another key, unsigned, a real token of the
// attacker's with the victim put in its payload — are refused by the handler
// and counted against nobody, however many are sent; and the attacker's own
// real token spends the attacker's count, not the victim's. Afterwards the
// victim has the whole budget: cap-1 wrong codes are checked and the right one
// opens a session.
func forgedTokensSpendNothing(t *testing.T, rig lockoutRig) {
	victim, attacker := "forged-victim@example.test", "forged-attacker@example.test"
	victimID := rig.register(t, victim)
	rig.enrolID(t, victimID, subjectOwnerSecret)
	rig.enrolID(t, rig.register(t, attacker), subjectOtherSecret)
	addr := freshAddresses(t)
	n := 0
	post := func(path, body string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		n++
		return invokeFrom(t, rig.apps[n%2], addr(), http.MethodPost, path, body)
	}
	verify := func(challenge, code string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		return post("/auth/2fa/verify", fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, challenge, code))
	}

	own := stepUpChallenge(t, post("/auth/login", loginBody(attacker, testPassword)))
	parts := strings.Split(own, ".")
	if len(parts) != 3 {
		t.Fatalf("the challenge is not a compact JWS: %q", own)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode the challenge's payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("the challenge's payload: %v", err)
	}
	if claims["typ"] != "temp" || claims["sub"] == victimID {
		t.Fatalf("unexpected challenge claims %v", claims)
	}
	claims["sub"] = victimID
	victimPayload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	sign := func(header, body string, key string) string {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(header + "." + body))
		return enc(mac.Sum(nil))
	}
	h256 := enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	forged := map[string]string{
		"signed with another key":       h256 + "." + enc(victimPayload) + "." + sign(h256, enc(victimPayload), "not-the-deployment-secret-not-the-deployment-secret"),
		"unsigned":                      enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc(victimPayload) + ".",
		"a real token, payload swapped": parts[0] + "." + enc(victimPayload) + "." + parts[2],
	}
	for name, token := range forged {
		for i := 0; i < 2*lockoutTestMax; i++ {
			resp := verify(token, totpAt(t, subjectOwnerSecret, time.Now()))
			if resp.StatusCode != http.StatusUnauthorized || opensSession(resp) {
				t.Fatalf("a forged token naming the victim (%s) answered %d %.160s, want the handler's 401", name, resp.StatusCode, resp.Body)
			}
		}
	}
	// The attacker's own real token: its count is the attacker's.
	for i := 0; i < 2*lockoutTestMax; i++ {
		resp := verify(own, wrongTOTP(t, subjectOtherSecret))
		if want := http.StatusUnauthorized; i >= lockoutTestMax {
			want = http.StatusTooManyRequests
			if resp.StatusCode != want {
				t.Fatalf("the attacker's own check %d answered %d %s, want %d once the attacker's count is spent", i+1, resp.StatusCode, resp.Body, want)
			}
		} else if resp.StatusCode != want {
			t.Fatalf("the attacker's own check %d answered %d %s, want %d", i+1, resp.StatusCode, resp.Body, want)
		}
	}

	// The victim's budget is whole.
	challenge := stepUpChallenge(t, post("/auth/login", loginBody(victim, testPassword)))
	for i := 1; i < lockoutTestMax; i++ {
		if resp := verify(challenge, wrongTOTP(t, subjectOwnerSecret)); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the victim's wrong code %d answered %d %s, want 401: the forged tokens spent the victim's count", i, resp.StatusCode, resp.Body)
		}
	}
	if resp := verify(challenge, totpAt(t, subjectOwnerSecret, time.Now())); resp.StatusCode != http.StatusOK || !opensSession(resp) {
		t.Fatalf("the victim's right code answered %d %.160s, want 200 with a session", resp.StatusCode, resp.Body)
	}
}

func TestSecondFactorLockoutIgnoresForgedTokens(t *testing.T) {
	t.Parallel()
	rig, _, _ := lockoutMemoryRig(t, baseEnv())
	forgedTokensSpendNothing(t, rig)
}

func TestSecondFactorLockoutSharedCounterIgnoresForgedTokens(t *testing.T) {
	forgedTokensSpendNothing(t, lockoutDynamoDBRig(t))
}

// successClearsTheCount: a check that succeeds puts the account's count back
// at zero, so a person who mistypes and then gets in is not carrying the
// mistakes into the next login; and a cap reached afterwards is reached from
// zero.
func successClearsTheCount(t *testing.T, rig lockoutRig) {
	owner := "reset-owner@example.test"
	rig.enrolID(t, rig.register(t, owner), subjectOwnerSecret)
	addr := freshAddresses(t)
	n := 0
	post := func(path, body string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		n++
		return invokeFrom(t, rig.apps[n%2], addr(), http.MethodPost, path, body)
	}
	verify := func(challenge, code string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		return post("/auth/2fa/verify", fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, challenge, code))
	}
	wrongs := func(challenge string, k int) {
		t.Helper()
		for i := 0; i < k; i++ {
			if resp := verify(challenge, wrongTOTP(t, subjectOwnerSecret)); resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("wrong code %d of %d answered %d %s, want 401", i+1, k, resp.StatusCode, resp.Body)
			}
		}
	}
	first := stepUpChallenge(t, post("/auth/login", loginBody(owner, testPassword)))
	wrongs(first, lockoutTestMax-1)
	if resp := verify(first, totpAt(t, subjectOwnerSecret, time.Now())); resp.StatusCode != http.StatusOK || !opensSession(resp) {
		t.Fatalf("the right code after %d wrong ones answered %d %.160s, want 200 with a session", lockoutTestMax-1, resp.StatusCode, resp.Body)
	}
	second := stepUpChallenge(t, post("/auth/login", loginBody(owner, testPassword)))
	wrongs(second, lockoutTestMax)
	if resp := verify(second, totpAt(t, subjectOwnerSecret, time.Now())); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("the right code after the cap was reached from zero answered %d %.160s, want 429", resp.StatusCode, resp.Body)
	}
}

func TestSecondFactorLockoutClearsOnSuccess(t *testing.T) {
	t.Parallel()
	rig, _, _ := lockoutMemoryRig(t, baseEnv())
	successClearsTheCount(t, rig)
}

func TestSecondFactorLockoutSharedCounterClearsOnSuccess(t *testing.T) {
	successClearsTheCount(t, lockoutDynamoDBRig(t))
}

// TestSecondFactorLockoutCountsEveryStepUpCheck: the texted code checked as
// the second step (POST /sms/verify, mode "2fa") is a check for the same
// account and shares the count with POST /2fa/verify; the login branch of the
// same route checks no second factor and is not counted.
func TestSecondFactorLockoutCountsEveryStepUpCheck(t *testing.T) {
	t.Parallel()
	rig, d, users := lockoutMemoryRig(t, smsEnv(baseEnv()))
	owner := "stepup-owner@example.test"
	id := rig.register(t, owner)
	rig.enrolID(t, id, subjectOwnerSecret)
	if _, err := users.UpdatePhoneNumber(context.Background(), id, "", testPhone); err != nil {
		t.Fatalf("give the owner a phone: %v", err)
	}
	addr := freshAddresses(t)
	post := func(path, body string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		return invokeFrom(t, d.app, addr(), http.MethodPost, path, body)
	}
	digits := regexp.MustCompile(`\d{6}`)
	challenge := stepUpChallenge(t, post("/auth/login", loginBody(owner, testPassword)))
	if resp := post("/auth/sms/send", fmt.Sprintf(`{"mode":"2fa","tempToken":%q}`, challenge)); resp.StatusCode != http.StatusOK {
		t.Fatalf("step-up send answered %d %s", resp.StatusCode, resp.Body)
	}
	sent := d.sms.messages()
	if len(sent) == 0 {
		t.Fatal("no code was texted")
	}
	code := digits.FindString(sent[len(sent)-1].message)
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	// The login branch of /sms/verify names an account by userId and checks
	// a first factor: not counted here, however often it fails.
	for i := 0; i < 2*lockoutTestMax; i++ {
		if resp := post("/auth/sms/verify", fmt.Sprintf(`{"userId":%q,"code":%q}`, id, wrong)); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a wrong login code answered %d %s, want 401", resp.StatusCode, resp.Body)
		}
	}
	half := lockoutTestMax / 2
	for i := 0; i < half; i++ {
		if resp := post("/auth/sms/verify", fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"code":%q}`, challenge, wrong)); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a wrong step-up SMS code answered %d %s, want 401", resp.StatusCode, resp.Body)
		}
	}
	for i := half; i < lockoutTestMax; i++ {
		if resp := post("/auth/2fa/verify", fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, challenge, wrongTOTP(t, subjectOwnerSecret))); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a wrong TOTP code answered %d %s, want 401", resp.StatusCode, resp.Body)
		}
	}
	if resp := post("/auth/sms/verify", fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"code":%q}`, challenge, code)); resp.StatusCode != http.StatusTooManyRequests || opensSession(resp) {
		t.Fatalf("the right texted code after the account's cap answered %d %.160s, want 429", resp.StatusCode, resp.Body)
	}
	if resp := post("/auth/2fa/verify", fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, challenge, totpAt(t, subjectOwnerSecret, time.Now()))); resp.StatusCode != http.StatusTooManyRequests || opensSession(resp) {
		t.Fatalf("the right TOTP code after the account's cap answered %d %.160s, want 429", resp.StatusCode, resp.Body)
	}
}

// TestSecondFactorLockoutCountsTheForcedEnrolment: under twoFactor.enrolOnLogin
// the code checked by POST /2fa/verify-setup with an enrolment token is a
// check for that token's account and is counted like the others.
func TestSecondFactorLockoutCountsTheForcedEnrolment(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, lockoutTestEnv(with(baseEnv(),
		"AWESOME_AUTH_2FA_REQUIRED", "true",
		"AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true",
	)))
	email := "enrol-owner@example.test"
	if reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email)); reg.StatusCode != http.StatusCreated {
		t.Fatalf("register answered %d %s", reg.StatusCode, reg.Body)
	}
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	login := invoke(t, app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(email, testPassword))
	temp, _ := decodeBody(t, login)["tempToken"].(string)
	if login.StatusCode != http.StatusForbidden || temp == "" {
		t.Fatalf("login answered %d %s, want 403 2FA_SETUP_REQUIRED with a token", login.StatusCode, login.Body)
	}
	setup := invoke(t, app, http.MethodPost, "/auth/2fa/setup", bearerJSON, nil, fmt.Sprintf(`{"tempToken":%q}`, temp))
	secret, _ := decodeBody(t, setup)["secret"].(string)
	if setup.StatusCode != http.StatusOK || secret == "" {
		t.Fatalf("setup answered %d %s", setup.StatusCode, setup.Body)
	}
	withTemp := jsonHeaders("authorization", "Bearer "+temp, auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	for i := 0; i < lockoutTestMax; i++ {
		// Half as the body's tempToken, half as the bearer credential: both
		// are the forced path, and both count.
		headers, body := bearerJSON, fmt.Sprintf(`{"tempToken":%q,"secret":%q,"token":%q}`, temp, secret, wrongTOTP(t, secret))
		if i%2 == 1 {
			headers, body = withTemp, fmt.Sprintf(`{"secret":%q,"token":%q}`, secret, wrongTOTP(t, secret))
		}
		if resp := invoke(t, app, http.MethodPost, "/auth/2fa/verify-setup", headers, nil, body); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("a wrong enrolment code answered %d %s, want 400", resp.StatusCode, resp.Body)
		}
	}
	resp := invoke(t, app, http.MethodPost, "/auth/2fa/verify-setup", bearerJSON, nil,
		fmt.Sprintf(`{"tempToken":%q,"secret":%q,"token":%q}`, temp, secret, totpCodeNow(t, secret)))
	if resp.StatusCode != http.StatusTooManyRequests || opensSession(resp) {
		t.Fatalf("the right enrolment code after the cap answered %d %.160s, want 429 and no session", resp.StatusCode, resp.Body)
	}
}

// TestSecondFactorLockoutIsItsOwnSwitch: the cap is not the rate limiter's —
// with rateLimit off altogether the sweep is still stopped at the account's
// cap.
func TestSecondFactorLockoutIsItsOwnSwitch(t *testing.T) {
	t.Parallel()
	rig, _, _ := lockoutMemoryRig(t, with(baseEnv(), "AWESOME_AUTH_RATE_LIMIT_ENABLED", "false"))
	sweepIsStoppedAtTheAccountCap(t, rig)
}

// TestSecondFactorLockoutCanBeTurnedOff: maxFailures 0 is off, and the
// rateLimit budgets are then the only bound — every check up to them reaches
// the handler.
func TestSecondFactorLockoutCanBeTurnedOff(t *testing.T) {
	t.Parallel()
	users := newMemoryStoreBundle()
	d := newDeliveryAppWith(t, with(lockoutTestEnv(baseEnv()), "AWESOME_AUTH_2FA_LOCKOUT_MAX_FAILURES", "0"), func(o *Options) {
		o.Stores = storeFactory(users, auth.NewMemorySessionStore())
		o.Logger = discardLogger()
	})
	t.Cleanup(d.app.Close)
	owner := "off-owner@example.test"
	if err := users.UpdateTOTPSecret(context.Background(), registerForSubjectTest(t, d.app, owner), "", subjectOwnerSecret, true); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	addr := freshAddresses(t)
	for i := 0; i < 2; i++ {
		challenge := stepUpChallenge(t, invokeFrom(t, d.app, addr(), http.MethodPost, "/auth/login", loginBody(owner, testPassword)))
		for j := 0; j < lockoutTestMax; j++ {
			resp := invokeFrom(t, d.app, addr(), http.MethodPost, "/auth/2fa/verify", fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, challenge, wrongTOTP(t, subjectOwnerSecret)))
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("with the cap off, wrong code %d on login %d answered %d %s, want 401", j+1, i+1, resp.StatusCode, resp.Body)
			}
		}
	}
}

// TestAccountSubjectKeepsAccountsApart: the counter subject is the verified
// tenant and id, and the two cannot be shifted into one another.
func TestAccountSubjectKeepsAccountsApart(t *testing.T) {
	t.Parallel()
	a, b := accountSubject("t1", "usr_a"), accountSubject("t1usr_a", "")
	if a == "" || b != "" {
		t.Fatalf("accountSubject = %q, %q; want a subject for an id and none without one", a, b)
	}
	if accountSubject("t", "1usr_a") == accountSubject("t1", "usr_a") {
		t.Error("two accounts whose tenant and id concatenate alike share a subject")
	}
	if accountSubject("", "usr_a") == accountSubject("t1", "usr_a") {
		t.Error("the same id in two tenants shares a subject")
	}
}

// brokenCounter is a shared counter that cannot be reached.
type brokenCounter struct{ resets int }

func (*brokenCounter) AllowRequest(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
	return false, 0, errors.New("dynamodb: connection refused")
}

func (b *brokenCounter) ResetRateLimit(context.Context, string, string, time.Duration) error {
	b.resets++
	return errors.New("dynamodb: connection refused")
}

// TestSecondFactorLockoutKeepsAFloorWhenTheCounterIsDown: when the shared
// counter cannot be reached the check is not refused — the store the check
// reads is the same table — but it is not unbounded either: it is counted in
// process, per execution environment, the floor the rate limiter's local tier
// keeps for it. The degradation is logged once, at WARN.
func TestSecondFactorLockoutKeepsAFloorWhenTheCounterIsDown(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(lockoutTestEnv(baseEnv()))})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	core, err := auth.New(auth.WithSecret(testAccessSecret))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	token, err := core.IssueTempToken(context.Background(), auth.User{ID: "usr_floor"})
	if err != nil {
		t.Fatalf("IssueTempToken: %v", err)
	}
	var logs bytes.Buffer
	mw := newSecondFactorCap(cfg, &brokenCounter{}, core, newLogger(&logs, slog.LevelDebug))
	reached := 0
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	for i := 0; i < 2*lockoutTestMax; i++ {
		r := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", strings.NewReader(fmt.Sprintf(`{"tempToken":%q,"totpCode":"000000"}`, token)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if want := http.StatusUnauthorized; i >= lockoutTestMax {
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("check %d with the counter down answered %d, want 429 once the in-process count is spent", i+1, w.Code)
			}
		} else if w.Code != want {
			t.Fatalf("check %d with the counter down answered %d, want the handler's %d", i+1, w.Code, want)
		}
	}
	if reached != lockoutTestMax {
		t.Errorf("the handler ran %d times, want %d", reached, lockoutTestMax)
	}
	if n := strings.Count(logs.String(), "cannot reach its shared counter"); n != 1 {
		t.Errorf("the degradation was logged %d times, want once:\n%s", n, logs.String())
	}
}

// TestSecondFactorLockoutHoldsTheReviewedChain is the chain review 6 ran,
// under the configuration it ran it on: twoFactor.required with a mailer, a
// TOTP-enrolled account, and only its mailbox — POST /forgot-password, the
// link from the mail, POST /reset-password with a chosen password, then logins
// and a sweep of codes from fresh addresses. The sweep is checked at most
// maxFailures times; the right code, on a fresh challenge and under a
// percent-encoded spelling of the route, is then refused.
func TestSecondFactorLockoutHoldsTheReviewedChain(t *testing.T) {
	t.Parallel()
	rig, d, _ := lockoutMemoryRig(t, with(mailerEnv(baseEnv()), "AWESOME_AUTH_2FA_REQUIRED", "true"))
	owner := "chain-owner@example.test"
	rig.enrolID(t, rig.register(t, owner), subjectOwnerSecret)
	addr := freshAddresses(t)
	post := func(path, body string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		return invokeFrom(t, d.app, addr(), http.MethodPost, path, body)
	}
	if resp := post("/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, owner)); resp.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password answered %d %s", resp.StatusCode, resp.Body)
	}
	resetToken := tokenIn(t, linkIn(t, d.mail.only(t).Body))
	const chosen = "Chosen-by-the-mailbox-1!"
	if resp := post("/auth/reset-password", fmt.Sprintf(`{"token":%q,"password":%q}`, resetToken, chosen)); resp.StatusCode != http.StatusOK {
		t.Fatalf("reset-password answered %d %s", resp.StatusCode, resp.Body)
	}
	checked := 0
	for i := 0; i < 3; i++ {
		challenge := stepUpChallenge(t, post("/auth/login", loginBody(owner, chosen)))
		for j := 0; j < 3; j++ {
			resp := post("/auth/2fa/verify", fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, challenge, wrongTOTP(t, subjectOwnerSecret)))
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				checked++
			case http.StatusTooManyRequests:
			default:
				t.Fatalf("a wrong code answered %d %s", resp.StatusCode, resp.Body)
			}
		}
	}
	if checked != lockoutTestMax {
		t.Fatalf("%d wrong codes were checked for the account, want exactly %d", checked, lockoutTestMax)
	}
	fresh := stepUpChallenge(t, post("/auth/login", loginBody(owner, chosen)))
	for _, path := range []string{"/auth/2fa/verify", "/auth/2fa/%76erify"} {
		resp := post(path, fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, fresh, totpAt(t, subjectOwnerSecret, time.Now())))
		if resp.StatusCode != http.StatusTooManyRequests || opensSession(resp) {
			t.Errorf("the right code at %s after the sweep answered %d %.160s, want 429 and no session", path, resp.StatusCode, resp.Body)
		}
	}
}
