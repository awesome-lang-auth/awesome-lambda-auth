package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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

// The rate limiter's subject is only a limit if it is the subject the route's
// handler then acts on. These tests hold the two readings together: the unit
// table route by route, the end-to-end cases against the real handlers on the
// memory driver and on the DynamoDB shared counter. See the file header of
// ratelimit.go, "the limiter reads the body the way the handler does".

// subjectCase is one body for one handler shape and the subject the handler's
// own reading of it names.
type subjectCase struct {
	name, body, want string
}

// TestRateLimitSubjectFollowsTheHandler pins, for every route the limiter reads
// a body on, that the subject is the member the route's handler acts on, read
// as the handler reads it: encoding/json's Decoder into the handler's member
// names (case-insensitive and Unicode-folded, the last appearance of a member
// winning, a null leaving the value in place, bytes after the first value
// ignored, the whole first value read however long the body) and the handler's
// own auth.TwoFactorMode branch. Each expectation below is what the handler in
// adapter/nethttp reads from the same body.
//
// The table is reached through rateLimitRoutes, so it pins the wiring as well
// as the functions: a route that gains a body-read subject without cases here
// fails, and so does one wired to the wrong handler shape.
func TestRateLimitSubjectFollowsTheHandler(t *testing.T) {
	t.Parallel()

	const (
		addr   = "203.0.113.9"
		owner  = "Owner@Example.test"
		other  = "someone-else@example.test"
		token  = "eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl"
		userID = "usr_0000000000000000000000000000a1"
	)
	email := emailSubject(owner)
	challenge := challengeSubject(token)
	id := userIDSubject(userID)
	// Past the old 8 KiB peek and past any read-ahead a Decoder does, so a
	// member after it is only seen by reading the whole first value.
	pad := strings.Repeat("p", 64<<10)
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }

	byEmail := []subjectCase{
		{"plain", `{"email":` + q(owner) + `,"password":"x"}`, email},
		{"member name in another case", `{"EMAIL":` + q(owner) + `}`, email},
		{"exact spelling first, folded spelling last", `{"email":` + q(other) + `,"Email":` + q(owner) + `}`, email},
		{"folded spelling first, exact spelling last", `{"Email":` + q(other) + `,"email":` + q(owner) + `}`, email},
		{"null before the value", `{"email":null,"Email":` + q(owner) + `}`, email},
		{"null after the value", `{"Email":` + q(owner) + `,"email":null}`, email},
		{"a number before the value", `{"email":1,"Email":` + q(owner) + `}`, email},
		{"escaped member name", `{"email":` + q(owner) + `}`, email},
		{"a second value after the first", `{"email":` + q(owner) + `} {"email":` + q(other) + `}`, email},
		{"value past 64 KiB of padding", `{"pad":` + q(pad) + `,"email":` + q(owner) + `}`, email},
		{"value before 64 KiB of padding", `{"email":` + q(owner) + `,"pad":` + q(pad) + `}`, email},
		{"members the handler does not read", `{"email":` + q(owner) + `,"tempToken":` + q(token) + `,"userId":` + q(userID) + `,"mode":"2fa"}`, email},
		{"blank", `{"email":"   "}`, addr},
		{"not a string", `{"email":{"nested":true}}`, addr},
		{"truncated mid-value", `{"email":` + q(owner) + `,"password":`, addr},
		{"not JSON", `email=` + owner, addr},
		{"empty object", `{}`, addr},
		{"no body", ``, addr},
	}

	routes := map[string][]subjectCase{
		"/login":           byEmail,
		"/register":        byEmail,
		"/forgot-password": byEmail,

		// passwordless.go TwoFactorVerify: the tempToken, and nothing else.
		"/2fa/verify": {
			{"plain", `{"tempToken":` + q(token) + `,"totpCode":"123456"}`, challenge},
			{"member name in another case", `{"TEMPTOKEN":` + q(token) + `}`, challenge},
			{"member name folded through the Kelvin sign", `{"tempTo` + "K" + `en":` + q(token) + `}`, challenge},
			{"exact spelling first, folded spelling last", `{"tempToken":"x","TempToken":` + q(token) + `}`, challenge},
			{"null before the value", `{"tempToken":null,"TempToken":` + q(token) + `}`, challenge},
			{"surrounding whitespace", `{"tempToken":` + q(" "+token+" ") + `}`, challenge},
			{"members the handler does not read", `{"tempToken":` + q(token) + `,"email":` + q(other) + `,"userId":` + q(userID) + `,"mode":"login"}`, challenge},
			{"a second value after the first", `{"tempToken":` + q(token) + `} {"tempToken":"x"}`, challenge},
			{"value past 64 KiB of padding", `{"pad":` + q(pad) + `,"tempToken":` + q(token) + `}`, challenge},
			{"no token", `{"totpCode":"123456","email":` + q(owner) + `}`, addr},
		},

		// passwordless.go MagicLinkSend: the tempToken in mode "2fa", the email
		// otherwise; the member of the other mode is ignored.
		"/magic-link/send": {
			{"login mode", `{"email":` + q(owner) + `}`, email},
			{"login mode with a tempToken", `{"email":` + q(owner) + `,"tempToken":"x"}`, email},
			{"2fa mode", `{"mode":"2fa","tempToken":` + q(token) + `}`, challenge},
			{"2fa mode with an email", `{"mode":"2fa","tempToken":` + q(token) + `,"email":` + q(other) + `}`, challenge},
			{"2fa mode, member names in another case", `{"Mode":"2fa","TempToken":` + q(token) + `,"email":` + q(other) + `}`, challenge},
			{"mode spelled twice, 2fa last", `{"mode":"login","Mode":"2fa","tempToken":` + q(token) + `,"email":` + q(other) + `}`, challenge},
			{"mode 2FA is not mode 2fa to the handler", `{"mode":"2FA","email":` + q(owner) + `,"tempToken":"x"}`, email},
			{"2fa mode without a token", `{"mode":"2fa","email":` + q(owner) + `}`, addr},
		},

		// passwordless.go MagicLinkVerify: the tempToken in mode "2fa";
		// otherwise the link token alone, which names no account.
		"/magic-link/verify": {
			{"login mode", `{"token":"link"}`, addr},
			{"login mode with a tempToken", `{"token":"link","tempToken":"x"}`, addr},
			{"2fa mode", `{"token":"link","mode":"2fa","tempToken":` + q(token) + `}`, challenge},
			{"2fa mode, exact spelling first", `{"token":"link","mode":"2fa","tempToken":"x","TempToken":` + q(token) + `}`, challenge},
		},

		// passwordless.go SMSSend: the tempToken in mode "2fa"; otherwise a
		// non-blank email, and failing that the userId.
		"/sms/send": {
			{"email", `{"email":` + q(owner) + `}`, email},
			{"userId", `{"userId":` + q(userID) + `}`, id},
			{"an email outranks a userId", `{"email":` + q(owner) + `,"userId":"usr_x"}`, email},
			{"a blank email does not", `{"email":"  ","userId":` + q(userID) + `}`, id},
			{"login mode with a tempToken", `{"userId":` + q(userID) + `,"tempToken":"x"}`, id},
			{"userId folded through the long s", `{"u` + "ſ" + `erId":` + q(userID) + `}`, id},
			{"2fa mode", `{"mode":"2fa","tempToken":` + q(token) + `,"email":` + q(other) + `,"userId":"usr_x"}`, challenge},
			{"nothing", `{"mode":"login"}`, addr},
		},

		// passwordless.go SMSVerify: the tempToken in mode "2fa", the userId
		// otherwise.
		"/sms/verify": {
			{"userId", `{"userId":` + q(userID) + `,"code":"123456"}`, id},
			{"userId, exact spelling first", `{"userId":"usr_x","UserId":` + q(userID) + `}`, id},
			{"login mode with a tempToken", `{"userId":` + q(userID) + `,"tempToken":"x"}`, id},
			{"2fa mode", `{"mode":"2fa","tempToken":` + q(token) + `,"userId":"usr_x"}`, challenge},
			{"2fa mode, exact spelling first", `{"mode":"2fa","tempToken":"x","TempToken":` + q(token) + `,"userId":"usr_x"}`, challenge},
			{"no userId", `{"code":"123456"}`, addr},
		},
	}

	check := func(t *testing.T, label string, subject rateLimitSubjectFunc, c subjectCase) {
		t.Helper()
		for _, keyBy := range []string{config.RateLimitKeyByEmail, config.RateLimitKeyByIP} {
			want := c.want
			if keyBy == config.RateLimitKeyByIP {
				want = addr // keyBy ip never reads the body
			}
			r := httptest.NewRequest(http.MethodPost, "/auth/x", strings.NewReader(c.body))
			r.RemoteAddr = addr + ":443"
			if got := rateLimitSubject(r, keyBy, subject); got != want {
				t.Errorf("%s, %s, keyBy %s: subject = %q, want %q (the handler reads %s)", label, c.name, keyBy, got, want, describeSubject(want, addr))
			}
			rest, err := io.ReadAll(r.Body)
			if err != nil || string(rest) != c.body {
				t.Errorf("%s, %s, keyBy %s: the handler would read %d bytes (err %v), want the %d the client sent", label, c.name, keyBy, len(rest), err, len(c.body))
			}
		}
	}

	seen := map[string]bool{}
	for _, scope := range config.RateLimitEndpoints() {
		for _, rt := range rateLimitRoutes[scope] {
			label := rt.method + " " + rt.path
			if rt.subject == nil {
				// Keyed by the address whatever the body says.
				check(t, label, nil, subjectCase{"a body naming an account", `{"email":` + q(owner) + `,"tempToken":` + q(token) + `}`, addr})
				continue
			}
			cases, ok := routes[rt.path]
			if !ok {
				t.Errorf("%s reads its subject from the body and has no cases here", label)
				continue
			}
			seen[rt.path] = true
			for _, c := range cases {
				check(t, label, rt.subject, c)
			}
		}
	}
	for path := range routes {
		if !seen[path] {
			t.Errorf("cases for %s, which no rateLimit.scope name covers with a body-read subject", path)
		}
	}

	// POST <admin>/login is limited by newAdminLoginLimiter with the same
	// function; its handler decodes the same way and discards the error.
	for _, c := range byEmail {
		check(t, "POST <admin>/login", subjectFromEmail, c)
	}
}

func describeSubject(want, addr string) string {
	if want == addr {
		return "no account, so the client address is the subject"
	}
	return "the account or challenge this names"
}

// ── end to end ───────────────────────────────────────────────────────────────

// subjectTestMax is the budget the end-to-end cases run under: small, so a
// budget is spent in a few bcrypt-priced logins. The window is a day, so a
// case of a few seconds does not straddle an epoch-aligned boundary and see its
// budget reset half-way; the default scope and the default keyBy are untouched.
const subjectTestMax = 3

func subjectTestEnv(base map[string]string) map[string]string {
	return with(base,
		"AWESOME_AUTH_RATE_LIMIT_MAX", fmt.Sprint(subjectTestMax),
		"AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS", "86400",
	)
}

// freshAddresses hands out a new source address on every call. Every request in
// the end-to-end cases comes from one it alone uses, so the client-address
// budget never refuses anything there: a 429 can only be the budget of the
// subject the request named.
func freshAddresses(t *testing.T) func() string {
	n := 0
	return func() string {
		n++
		if n > 254 {
			t.Fatalf("more source addresses than 198.51.100.0/24 holds")
		}
		return fmt.Sprintf("198.51.100.%d", n)
	}
}

// invokeFrom is invoke with the source address the event reports set to addr.
func invokeFrom(t *testing.T, app *App, addr, method, path, body string) events.APIGatewayV2HTTPResponse {
	t.Helper()
	var evt events.APIGatewayV2HTTPRequest
	if err := json.Unmarshal(v2Event(method, path, jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, body), &evt); err != nil {
		t.Fatalf("build event: %v", err)
	}
	evt.RequestContext.HTTP.SourceIP = addr
	raw, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	out, err := app.Handle(context.Background(), raw)
	if err != nil {
		t.Fatalf("Handle %s %s: %v", method, path, err)
	}
	var resp events.APIGatewayV2HTTPResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

// stepUpChallenge is the tempToken of a login the handler answered with a
// second-factor challenge, which is how the cases know whose login it was.
func stepUpChallenge(t *testing.T, resp events.APIGatewayV2HTTPResponse) string {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login answered %d %s, want 200 with a second-factor challenge", resp.StatusCode, resp.Body)
	}
	body := decodeBody(t, resp)
	token, _ := body["tempToken"].(string)
	if body["requiresTwoFactor"] != true || token == "" {
		t.Fatalf("login answered no second-factor challenge: %s", resp.Body)
	}
	return token
}

// opensSession: the cases send X-Auth-Strategy: bearer, so a session is an
// access token in the body.
func opensSession(resp events.APIGatewayV2HTTPResponse) bool {
	return strings.Contains(resp.Body, `"accessToken"`)
}

// totpAt is the code an authenticator shows for secret at the given time, by
// the core's own parameters (auth.TOTPDigits, auth.TOTPPeriod, and HMAC-SHA-1
// as auth.TOTPAlgorithm names it).
func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("TOTP secret %q: %v", secret, err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/int64(auth.TOTPPeriod/time.Second)))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < auth.TOTPDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", auth.TOTPDigits, n%mod)
}

// wrongTOTP is a well-formed code the core refuses for secret now: it matches
// none of the steps the core's skew accepts, with a step to spare either side.
func wrongTOTP(t *testing.T, secret string) string {
	t.Helper()
	now := time.Now()
	valid := map[string]bool{}
	for k := -auth.TOTPSkew - 1; k <= auth.TOTPSkew+1; k++ {
		valid[totpAt(t, secret, now.Add(time.Duration(k)*auth.TOTPPeriod))] = true
	}
	for c := 0; ; c++ {
		if code := fmt.Sprintf("%0*d", auth.TOTPDigits, c); !valid[code] {
			return code
		}
	}
}

// subjectRig is where the end-to-end case sends its requests. spend is the
// deployment the budgets are spent on and probe the one the over-budget
// requests go to: the same App on the memory driver, a second App over the same
// table on DynamoDB, so that a refusal there can only come from the shared
// counter and not from an in-process pre-filter that watched the spending.
type subjectRig struct {
	spend, probe *App
	enrol        func(t *testing.T, email, secret string)
}

const (
	subjectOwner       = "owner@example.test"
	subjectOther       = "other@example.test"
	subjectOwnerSecret = "JBSWY3DPEHPK3PXP"
	subjectOtherSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

// countsTheSubjectTheHandlerActsOn is the end-to-end case. Requests whose body
// spells the subject's member more than once are answered by the handler for
// the spelling it reads — the last one, matched case-insensitively — and must
// be counted against that subject: they spend its budget, they are refused once
// it is spent, and they leave a different subject's budget alone.
func countsTheSubjectTheHandlerActsOn(t *testing.T, rig subjectRig) {
	rig.enrol(t, subjectOwner, subjectOwnerSecret)
	rig.enrol(t, subjectOther, subjectOtherSecret)
	addr := freshAddresses(t)
	post := func(app *App, path, body string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		return invokeFrom(t, app, addr(), http.MethodPost, path, body)
	}
	loginSpelledTwice := func(first, last string) string {
		return fmt.Sprintf(`{"email":%q,"Email":%q,"password":%q}`, first, last, testPassword)
	}
	verifySpelledTwice := func(first, last, code string) string {
		return fmt.Sprintf(`{"tempToken":%q,"TempToken":%q,"totpCode":%q}`, first, last, code)
	}
	pad := strings.Repeat("p", 64<<10)

	// POST /login. The budget is spent through bodies whose exact-case member
	// names a different address every time and whose last spelling names the
	// owner. The handler answers each with the owner's challenge.
	var challenge string
	for i := 1; i <= subjectTestMax; i++ {
		token := stepUpChallenge(t, post(rig.spend, "/auth/login", loginSpelledTwice(fmt.Sprintf("n%d@example.test", i), subjectOwner)))
		if challenge == "" {
			challenge = token
		}
	}
	for name, body := range map[string]string{
		"spelled twice":                  loginSpelledTwice("n-over@example.test", subjectOwner),
		"plain":                          loginBody(subjectOwner, testPassword),
		"member name in another case":    fmt.Sprintf(`{"EMAIL":%q,"password":%q}`, subjectOwner, testPassword),
		"null before the value":          fmt.Sprintf(`{"email":null,"Email":%q,"password":%q}`, subjectOwner, testPassword),
		"a second value after the first": loginBody(subjectOwner, testPassword) + ` {"email":"n-after@example.test"}`,
		"value past 64 KiB of padding":   fmt.Sprintf(`{"pad":%q,"email":%q,"password":%q}`, pad, subjectOwner, testPassword),
	} {
		if resp := post(rig.probe, "/auth/login", body); resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("login for the owner, %s, after the owner's budget was spent: %d %.120s, want 429", name, resp.StatusCode, resp.Body)
		}
	}

	// POST /2fa/verify. The challenge's budget is spent the same way, with a
	// wrong code: the handler's answer to each is its verdict on that
	// challenge. Over budget nothing reaches the handler, the right code
	// included.
	for i := 1; i <= subjectTestMax; i++ {
		resp := post(rig.spend, "/auth/2fa/verify", verifySpelledTwice(fmt.Sprintf("n%d", i), challenge, wrongTOTP(t, subjectOwnerSecret)))
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Body, "Invalid TOTP code") {
			t.Fatalf("a wrong code on the owner's challenge answered %d %s, want the handler's 401 Invalid TOTP code", resp.StatusCode, resp.Body)
		}
	}
	right := func() string { return totpAt(t, subjectOwnerSecret, time.Now()) }
	for name, body := range map[string]string{
		"spelled twice":                     verifySpelledTwice("n-over", challenge, right()),
		"plain":                             fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, challenge, right()),
		"member name folded":                fmt.Sprintf(`{"tempTo%sen":%q,"totpCode":%q}`, "K", challenge, right()),
		"null before the value":             fmt.Sprintf(`{"tempToken":null,"TempToken":%q,"totpCode":%q}`, challenge, right()),
		"members the handler does not read": fmt.Sprintf(`{"tempToken":%q,"email":"n-x@example.test","userId":"usr_x","totpCode":%q}`, challenge, right()),
		"a second value after the first":    fmt.Sprintf(`{"tempToken":%q,"totpCode":%q} {"tempToken":"x"}`, challenge, right()),
		"value past 64 KiB of padding":      fmt.Sprintf(`{"pad":%q,"tempToken":%q,"totpCode":%q}`, pad, challenge, right()),
	} {
		resp := post(rig.probe, "/auth/2fa/verify", body)
		if resp.StatusCode != http.StatusTooManyRequests || opensSession(resp) {
			t.Errorf("the right code on the owner's spent challenge, %s: %d %.120s, want 429 and no session", name, resp.StatusCode, resp.Body)
		}
	}

	// Control: the other account keeps budgets of its own, and requests are
	// counted against the subject the handler acts on even when the body also
	// names a spent one in the spelling the handler does not read.
	otherChallenge := stepUpChallenge(t, post(rig.probe, "/auth/login", loginSpelledTwice(subjectOwner, subjectOther)))
	resp := post(rig.probe, "/auth/2fa/verify", verifySpelledTwice(challenge, otherChallenge, totpAt(t, subjectOtherSecret, time.Now())))
	if resp.StatusCode != http.StatusOK || !opensSession(resp) {
		t.Errorf("the other account's right code on its own challenge, the owner's spent challenge spelled first: %d %.160s, want 200 with a session", resp.StatusCode, resp.Body)
	}
}

// subjectMemoryRig is the memory driver: one App, the in-process tier as the
// whole limiter, accounts enrolled in TOTP through the store.
func subjectMemoryRig(t *testing.T, env map[string]string) (subjectRig, *deliveryApp, memoryStoreBundle) {
	t.Helper()
	users := newMemoryStoreBundle()
	d := newDeliveryAppWith(t, subjectTestEnv(env), func(o *Options) {
		o.Stores = storeFactory(users, auth.NewMemorySessionStore())
		o.Logger = discardLogger()
	})
	t.Cleanup(d.app.Close)
	enrol := func(t *testing.T, email, secret string) {
		t.Helper()
		if err := users.UpdateTOTPSecret(context.Background(), registerForSubjectTest(t, d.app, email), "", secret, true); err != nil {
			t.Fatalf("enrol %s in TOTP: %v", email, err)
		}
	}
	return subjectRig{spend: d.app, probe: d.app, enrol: enrol}, d, users
}

// registerForSubjectTest creates the account through POST /register, which is
// outside the default scope, so it spends no budget, and returns its id.
func registerForSubjectTest(t *testing.T, app *App, email string) string {
	t.Helper()
	resp := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email))
	id, _ := decodeBody(t, resp)["userId"].(string)
	if resp.StatusCode != http.StatusCreated || id == "" {
		t.Fatalf("register %s answered %d %s, want 201 with a userId", email, resp.StatusCode, resp.Body)
	}
	return id
}

func TestRateLimitCountsTheSubjectTheHandlerActsOn(t *testing.T) {
	t.Parallel()
	rig, _, _ := subjectMemoryRig(t, baseEnv())
	countsTheSubjectTheHandlerActsOn(t, rig)
}

// TestRateLimitSharedCounterCountsTheSubjectTheHandlerActsOn is the same case
// against the production tier: two Apps — two execution environments — over
// one DynamoDB table. The budgets are spent on one and probed on the other,
// whose in-process pre-filter has seen none of the spending, so every refusal
// there is the shared counter's.
func TestRateLimitSharedCounterCountsTheSubjectTheHandlerActsOn(t *testing.T) {
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run the shared-counter case")
	}
	// No t.Parallel, for the reason TestDynamoDBBackedRoutesFindEveryStore gives.
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()
	table := "authtest_ratelimit_subject_" + randomSuffix(t)
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
	env := subjectTestEnv(with(baseEnv(),
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
	spend, probe := environment(), environment()
	enrol := func(t *testing.T, email, secret string) {
		t.Helper()
		if err := store.UpdateTOTPSecret(ctx, registerForSubjectTest(t, spend, email), "", secret, true); err != nil {
			t.Fatalf("enrol %s in TOTP: %v", email, err)
		}
	}
	countsTheSubjectTheHandlerActsOn(t, subjectRig{spend: spend, probe: probe, enrol: enrol})
}

// TestRateLimitCountsTheChallengeTheSMSHandlerActsOn: in mode "2fa" the SMS
// handlers act on the tempToken's account and ignore the body's email and
// userId, so those members must not name the subject either. The text the
// handler sends, and the session the code it carries opens, show whose
// challenge each request was.
func TestRateLimitCountsTheChallengeTheSMSHandlerActsOn(t *testing.T) {
	t.Parallel()
	rig, d, users := subjectMemoryRig(t, smsEnv(baseEnv()))
	addr := freshAddresses(t)
	post := func(path, body string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		return invokeFrom(t, d.app, addr(), http.MethodPost, path, body)
	}
	rig.enrol(t, subjectOwner, subjectOwnerSecret)
	owner, err := users.GetUserByEmail(context.Background(), subjectOwner, "")
	if err != nil {
		t.Fatalf("read the owner back: %v", err)
	}
	if _, err := users.UpdatePhoneNumber(context.Background(), owner.ID, "", testPhone); err != nil {
		t.Fatalf("give the owner a phone: %v", err)
	}
	digits := regexp.MustCompile(`\d{6}`)
	texted := func() string {
		t.Helper()
		sent := d.sms.messages()
		if len(sent) == 0 || sent[len(sent)-1].phone != testPhone {
			t.Fatalf("no code was texted to the owner's phone: %v", sent)
		}
		return digits.FindString(sent[len(sent)-1].message)
	}

	challenge := stepUpChallenge(t, post("/auth/login", loginBody(subjectOwner, testPassword)))
	if resp := post("/auth/sms/send", fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"email":"n0@example.test","userId":"usr_n0"}`, challenge)); resp.StatusCode != http.StatusOK {
		t.Fatalf("step-up send answered %d %s, want 200", resp.StatusCode, resp.Body)
	}
	code := texted()
	wrong := "000000"
	if code == wrong {
		wrong = "000001"
	}
	// The send spent one of the challenge's budget; wrong codes, each with a
	// different userId, spend the rest.
	for i := 2; i <= subjectTestMax; i++ {
		resp := post("/auth/sms/verify", fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"userId":"usr_n%d","code":%q}`, challenge, i, wrong))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a wrong code on the owner's challenge answered %d %s, want 401", resp.StatusCode, resp.Body)
		}
	}
	// A wrong code burns nothing, so the texted code is still good; over budget
	// it does not reach the handler, and no further text is sent.
	resp := post("/auth/sms/verify", fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"userId":"usr_over","code":%q}`, challenge, code))
	if resp.StatusCode != http.StatusTooManyRequests || opensSession(resp) {
		t.Errorf("the texted code on the owner's spent challenge answered %d %.120s, want 429 and no session", resp.StatusCode, resp.Body)
	}
	before := len(d.sms.messages())
	if resp := post("/auth/sms/send", fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"email":"n-over@example.test"}`, challenge)); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a step-up send on the owner's spent challenge answered %d %.120s, want 429", resp.StatusCode, resp.Body)
	}
	if after := len(d.sms.messages()); after != before {
		t.Errorf("a refused send texted the owner (%d texts, then %d)", before, after)
	}

	// Control: a second challenge has its own budget, and the code texted for
	// it opens a session through the same shape of body.
	second := stepUpChallenge(t, post("/auth/login", loginBody(subjectOwner, testPassword)))
	if resp := post("/auth/sms/send", fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"email":"n1@example.test"}`, second)); resp.StatusCode != http.StatusOK {
		t.Fatalf("step-up send on a fresh challenge answered %d %s, want 200", resp.StatusCode, resp.Body)
	}
	resp = post("/auth/sms/verify", fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"userId":"usr_n9","code":%q}`, second, texted()))
	if resp.StatusCode != http.StatusOK || !opensSession(resp) {
		t.Errorf("the texted code on a fresh challenge answered %d %.160s, want 200 with a session", resp.StatusCode, resp.Body)
	}
}

// TestAdminLoginLimitCountsTheMemberTheLoginReads: POST <admin>/login decodes
// its body with the same Decoder and discards the error, so the member it signs
// in with — the last spelling, matched case-insensitively, a wrong-typed later
// spelling leaving it in place — is the one its limiter counts.
func TestAdminLoginLimitCountsTheMemberTheLoginReads(t *testing.T) {
	t.Parallel()
	cfg := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_RATE_LIMIT_ENABLED", "true",
		"AWESOME_AUTH_RATE_LIMIT_MAX", "2",
		"AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS", "86400",
	))
	s := newAdminSurface(t, cfg, Options{}, nil)
	addr := freshAddresses(t)
	login := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		from := addr()
		return s.call(t, http.MethodPost, "/admin/login", json.RawMessage(body), func(r *http.Request) { r.RemoteAddr = from + ":4242" })
	}
	root := func(first, password string) string {
		return fmt.Sprintf(`{"email":%s,"Email":%q,"password":%q}`, first, testAdminRootEmail, password)
	}

	// Under budget the login reads the last spelling: the right password signs
	// the root user in, and a wrong one is the root user's 401.
	if rec := login(root(`"n1@example.test"`, testAdminRootPassword)); rec.Code != http.StatusOK {
		t.Fatalf("the root user's password, the root email spelled last, answered %d %s, want 200", rec.Code, rec.Body.String())
	}
	if rec := login(root(`1`, "not-the-password")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password, a number spelled first, answered %d %s, want 401", rec.Code, rec.Body.String())
	}
	// Both counted against the root email: its budget of two is spent.
	for name, body := range map[string]string{
		"spelled twice": root(`"n2@example.test"`, testAdminRootPassword),
		"null first":    root(`null`, testAdminRootPassword),
		"plain":         fmt.Sprintf(`{"email":%q,"password":%q}`, testAdminRootEmail, testAdminRootPassword),
	} {
		if rec := login(body); rec.Code != http.StatusTooManyRequests {
			t.Errorf("the root user's password, %s, after the budget was spent: %d %s, want 429", name, rec.Code, rec.Body.String())
		}
	}
	// Control: the same shape naming another account last is that account's
	// budget, not the spent one it names first.
	if rec := login(fmt.Sprintf(`{"email":%q,"Email":"someone-else@example.test","password":"x"}`, testAdminRootEmail)); rec.Code != http.StatusUnauthorized {
		t.Errorf("another account, the root email spelled first, answered %d %s, want 401", rec.Code, rec.Body.String())
	}
}

// TestRateLimiterHandsAPaddedBodyToTheHandlerIntact: the limiter now reads a
// body to the end of its first JSON value, however long, and a Decoder reads
// ahead of what it decodes. The handler below must still see every byte: the
// password is placed after 64 KiB of padding, so a login that succeeds read it.
func TestRateLimiterHandsAPaddedBodyToTheHandlerIntact(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())
	const email = "padded@example.test"
	if resp := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register answered %d %s", resp.StatusCode, resp.Body)
	}
	body := fmt.Sprintf(`{"email":%q,"pad":%q,"password":%q}`, email, strings.Repeat("p", 64<<10), testPassword)
	if resp := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(), nil, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("login through the limiter with a padded body answered %d %.200s; the handler did not get the whole body", resp.StatusCode, resp.Body)
	}

	// And at the unit: what readRateLimitFields consumed is put back in front of
	// what it did not, byte for byte, for a body that ends mid-value too.
	for _, raw := range []string{body, body + ` {"second":"value"}`, body[:len(body)/2]} {
		r := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte(raw)))
		readRateLimitFields(r)
		if got, err := io.ReadAll(r.Body); err != nil || string(got) != raw {
			t.Errorf("after the limiter read it, a %d-byte body reads back as %d bytes (err %v)", len(raw), len(got), err)
		}
	}
}
