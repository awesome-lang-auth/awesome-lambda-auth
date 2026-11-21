package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The deployment-level tests below run against baseEnv() and therefore against
// the **shipped defaults**, deliberately and not for convenience.
//
// The behaviour this block introduces is a behaviour an unconfigured deployment
// has: `rateLimit.enabled` defaults to true, the default scope is the five
// credential flows and the default budget is ten per minute per address. That is
// precisely what the wire deviation rate-limited-routes-answer-429 claims, so
// pinning it against a hand-tuned configuration would test a deployment nobody
// runs and leave the claim itself unpinned. It also means these tests fail the
// day someone changes a default without changing the register, which is the
// tripwire worth having.
//
// The knobs are exercised instead where they can be without a document —
// resolveRateLimit and newRateLimiter take a *config.Config directly — so no
// test here has to configure the block through the schema and trip the phase
// gate that the last commit of this branch removes.
var (
	rateLimitDefaultMax   = config.Defaults().RateLimit.Max
	rateLimitDefaultScope = config.Defaults().RateLimit.Scope
)

// TestRateLimitResponseIsExactlyThis pins the refusal down to the byte, because
// it is the wire deviation this block introduces and the register quotes it
// verbatim. A change here without a change there would leave the deviation
// register describing a response the product no longer sends.
//
// The unit under test is writeRateLimited rather than a live route, so the
// assertion is about the response and not about what provoked it.
func TestRateLimitResponseIsExactlyThis(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeRateLimited(rec, 17*time.Second)
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"error":"Too many requests","code":"RATE_LIMITED"}` {
		t.Errorf("body = %s, want the family envelope with code RATE_LIMITED", body)
	}
	if got := resp.Header.Get("Retry-After"); got != "17" {
		t.Errorf("Retry-After = %q, want %q (delta-seconds, RFC 9110 §10.2.3)", got, "17")
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: a shared cache must not serve one subject's refusal to another", got)
	}

	// The RateLimit-* family is deliberately absent. RateLimit-Remaining on a
	// *successful* response would be an oracle about somebody else's traffic
	// under an email-keyed limiter — anyone able to name victim@example.com
	// could read whether that person has been logging in — so the decision is to
	// send none of them at all, and it is pinned so it cannot be added as a
	// convenience by someone who has not read the argument in ratelimit.go.
	for _, h := range []string{"RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset", "X-RateLimit-Limit", "X-RateLimit-Remaining"} {
		if v := resp.Header.Get(h); v != "" {
			t.Errorf("%s = %q; this family is deliberately not sent, see writeRateLimited", h, v)
		}
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Errorf("the refusal carries a cookie; the limiter is outermost, so nothing that sets one should have run")
	}
}

// TestRetryAfterIsNeverZero: the header is rounded up and floored at one second.
// A Retry-After of 0 is an invitation to retry immediately, which is the
// behaviour the header exists to prevent, and a sub-second remainder is exactly
// when it would be emitted.
func TestRetryAfterIsNeverZero(t *testing.T) {
	t.Parallel()

	for _, remaining := range []time.Duration{0, time.Nanosecond, 400 * time.Millisecond, -time.Second} {
		rec := httptest.NewRecorder()
		writeRateLimited(rec, remaining)
		got := rec.Result().Header.Get("Retry-After")
		n, err := strconv.Atoi(got)
		if err != nil || n < 1 {
			t.Errorf("remaining %s produced Retry-After %q, want an integer of at least 1", remaining, got)
		}
	}
}

// TestTheShippedDefaultsAreTheOnesTheRegisterClaims pins the four values an
// unconfigured deployment gets.
//
// They are a product decision with no upstream to appeal to — the reference has
// no limiter and the spec left every one of them TBD — so the only thing keeping
// them honest is that they are written down in three places that have to agree:
// here, docs/config-reference.md §13, and the deviation register, which tells an
// operator that a stack they never configured now answers 429 where the
// reference answers 200. A default changed without those changed is the failure
// this test exists to cause.
func TestTheShippedDefaultsAreTheOnesTheRegisterClaims(t *testing.T) {
	t.Parallel()

	d := config.Defaults().RateLimit
	if !d.Enabled {
		t.Errorf("rateLimit.enabled defaults to false; the house rule is that forgetting tightens, and the register says an unconfigured deployment is limited")
	}
	if d.KeyBy != config.RateLimitKeyByEmail {
		t.Errorf("rateLimit.keyBy defaults to %q, want %q: an address-keyed default puts a NAT's whole office in one bucket and one DynamoDB partition",
			d.KeyBy, config.RateLimitKeyByEmail)
	}
	if d.Max != 10 || d.WindowSeconds != 60 {
		t.Errorf("the default budget is %d per %ds, want 10 per 60s", d.Max, d.WindowSeconds)
	}

	want := []string{"login", "forgot-password", "magic-link", "sms-code", "2fa-verify"}
	if len(rateLimitDefaultScope) != len(want) {
		t.Fatalf("the default scope is %v, want the five flows data-model.md §1.5 #61 names: %v", rateLimitDefaultScope, want)
	}
	got := map[string]bool{}
	for _, s := range rateLimitDefaultScope {
		got[s] = true
	}
	for _, s := range want {
		if !got[s] {
			t.Errorf("the default scope does not name %q", s)
		}
	}
}

// TestEveryScopeNameMapsToRoutes holds the two halves of the scope vocabulary
// together. internal/config says which names a document may use; this package
// says what each one covers on the wire. A name in only one of them is either a
// knob that validates and limits nothing, or a limiter nobody can switch on.
func TestEveryScopeNameMapsToRoutes(t *testing.T) {
	t.Parallel()

	known := map[string]bool{}
	for _, name := range config.RateLimitEndpoints() {
		known[name] = true
		routes, ok := rateLimitRoutes[name]
		if !ok || len(routes) == 0 {
			t.Errorf("rateLimit.scope accepts %q and rateLimitRoutes covers no route for it: the knob would validate and limit nothing", name)
		}
	}
	for name := range rateLimitRoutes {
		if !known[name] {
			t.Errorf("rateLimitRoutes covers %q, which rateLimit.scope will not accept: nothing can switch it on", name)
		}
	}

	// Every default the schema ships has to be a name this table covers, or an
	// unconfigured deployment would advertise a limiter over routes it does not
	// watch.
	for _, name := range config.Defaults().RateLimit.Scope {
		if len(rateLimitRoutes[name]) == 0 {
			t.Errorf("the default scope names %q, which covers no route", name)
		}
	}
}

// TestRateLimitedRoutesAreMountedByTheAdapter is the tripwire for the one
// coupling this package has to the adapter's route table.
//
// The paths in rateLimitRoutes are literals, because the core exports no
// constants for them. A literal that drifted — a route renamed upstream, a
// method changed — would not fail to build: it would silently stop limiting that
// route, and nothing about the deployment would look different. So every path in
// the table is driven through a real mount and must not answer 404.
//
// 404 is the only failure. These routes legitimately answer 400, 401, 403, 500
// and more to a bodyless request, and asserting anything narrower would make
// this test about the routes rather than about their existence.
func TestRateLimitedRoutesAreMountedByTheAdapter(t *testing.T) {
	t.Parallel()

	// Every scope name, not merely the default ones: the table is what an
	// operator may point the limiter at, so all of it has to be real. The
	// deployment's own scope is irrelevant here — the limiter mounts nothing,
	// so which routes it watches has no bearing on which routes exist — and the
	// sweep sends one request per path, which no budget refuses.
	//
	// The deployment has invitations on, because accept-invitation's route is
	// mounted only then. Registration stays open, because a closed realm
	// answers 404 on /register.
	scopes := config.RateLimitEndpoints()
	app := newTestApp(t, with(baseEnv(),
		"AWESOME_AUTH_ADMIN_ENABLED", "true",
		"AWESOME_AUTH_ADMIN_ACCESS_POLICY", config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS", testMachineRole,
		"AWESOME_AUTH_INVITATIONS_ENABLED", "true",
		"AWESOME_AUTH_ADMIN_REVEAL_INVITATION_TOKEN", "true",
	))

	prefix := config.Defaults().HTTP.APIPrefix
	for _, name := range scopes {
		for _, rt := range rateLimitRoutes[name] {
			t.Run(name+" "+rt.method+" "+rt.path, func(t *testing.T) {
				resp := invoke(t, app, rt.method, prefix+rt.path, jsonHeaders(), nil, "{}")
				if resp.StatusCode == http.StatusNotFound {
					t.Errorf("%s %s answered 404: the limiter watches a path this deployment does not serve, so the scope %q limits nothing",
						rt.method, prefix+rt.path, name)
				}
			})
		}
	}
}

// TestRateLimiterRefusesOverTheBudgetAndPassesUnder is the end-to-end shape: the
// budget is spent, the next request is the registered 429, and a route outside
// the scope is untouched by any of it.
//
// It runs on the memory driver, so the counting is the in-process pre-filter's.
// That is the right unit for this assertion — what is being checked is the
// middleware's decision and its response, not the store's atomicity, which
// internal/store/dynamodb tests against a real DynamoDB.
func TestRateLimiterRefusesOverTheBudgetAndPassesUnder(t *testing.T) {
	t.Parallel()

	app := newTestApp(t, baseEnv())
	prefix := config.Defaults().HTTP.APIPrefix
	const body = `{"email":"budget@example.test","password":"nope"}`

	for i := 1; i <= rateLimitDefaultMax; i++ {
		resp := invoke(t, app, http.MethodPost, prefix+"/login", jsonHeaders(), nil, body)
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d of the default budget of %d was refused", i, rateLimitDefaultMax)
		}
	}

	resp := invoke(t, app, http.MethodPost, prefix+"/login", jsonHeaders(), nil, body)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request %d of a budget of %d answered %d, want 429", rateLimitDefaultMax+1, rateLimitDefaultMax, resp.StatusCode)
	}
	if resp.Body != `{"error":"Too many requests","code":"RATE_LIMITED"}` {
		t.Errorf("body = %s, want the registered refusal", resp.Body)
	}
	if resp.Headers["Retry-After"] == "" {
		t.Errorf("no Retry-After on the refusal; headers were %v", resp.Headers)
	}

	// A route outside the scope keeps working while the limited one is refusing.
	// This is the assertion that says the limiter is scoped at all: a middleware
	// that matched everything would pass every other test in this file. POST
	// /refresh is nameable in rateLimit.scope and deliberately not in the
	// default, so it is also the assertion that the default is the default.
	for i := 0; i <= rateLimitDefaultMax; i++ {
		if resp := invoke(t, app, http.MethodPost, prefix+"/refresh", jsonHeaders(), nil, "{}"); resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("POST /refresh was refused on request %d, and it is not in the default scope; the limiter is matching more than it was pointed at", i)
		}
	}
}

// TestRateLimiterKeysBySubjectNotByRoute: with keyBy: email, one address
// exhausting its budget must leave another address unaffected. That is the whole
// argument for the email default — a limiter that could not do this would punish
// an office NAT for one abuser — so it is pinned rather than assumed.
func TestRateLimiterKeysBySubjectNotByRoute(t *testing.T) {
	t.Parallel()

	app := newTestApp(t, baseEnv())
	prefix := config.Defaults().HTTP.APIPrefix
	login := func(email string) int {
		return invoke(t, app, http.MethodPost, prefix+"/login", jsonHeaders(), nil,
			`{"email":"`+email+`","password":"nope"}`).StatusCode
	}

	for i := 1; i <= rateLimitDefaultMax; i++ {
		if got := login("spent@example.test"); got == http.StatusTooManyRequests {
			t.Fatalf("request %d of a budget of %d was refused", i, rateLimitDefaultMax)
		}
	}
	if got := login("spent@example.test"); got != http.StatusTooManyRequests {
		t.Fatalf("request %d for the spent address answered %d, want 429", rateLimitDefaultMax+1, got)
	}
	if got := login("other@example.test"); got == http.StatusTooManyRequests {
		t.Errorf("a second address was refused on the first request; the budget is not per subject")
	}

	// Case is not a free reset: the core normalises addresses on the way into
	// the store (service.go:58) and the limiter has to normalise the same way,
	// or SPENT@Example.test would be a fresh budget for the same account.
	if got := login("SPENT@Example.test"); got != http.StatusTooManyRequests {
		t.Errorf("the spent address in a different case answered %d, want 429: case is a free reset", got)
	}
}

// TestRateLimiterIgnoresForwardedHeaders: the subject may never come from a
// header the client writes.
//
// X-Forwarded-For is the obvious one to reach for and it is attacker-controlled:
// a limiter keyed on it is not a weaker limiter, it is none at all, because a
// new value per request is a new budget per request. internal/lambdahttp sets
// RemoteAddr from the event's own requestContext instead, and this pins that the
// middleware reads that and nothing else.
func TestRateLimiterIgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()

	app := newTestApp(t, baseEnv())
	prefix := config.Defaults().HTTP.APIPrefix

	// Each request claims a different forwarded source and carries no email, so
	// under the default keyBy: email the subject falls back to the address — the
	// one the event reported, which is the same for all of them. One more than
	// the budget must therefore be refused.
	var last int
	for i := 0; i <= rateLimitDefaultMax; i++ {
		h := jsonHeaders("x-forwarded-for", "198.51.100."+strconv.Itoa(i), "forwarded", "for=198.51.100."+strconv.Itoa(i))
		last = invoke(t, app, http.MethodPost, prefix+"/login", h, nil, `{}`).StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("four requests claiming four different forwarded addresses answered %d on the last; "+
			"a client that can choose its own subject has no limit at all", last)
	}
}

// TestAcceptInvitationIsLimitedByClientAddress: POST <prefix>/invitations/accept
// is public, and it stays mounted under registration.closed. Each call costs a
// decode, a SHA-256 and a consistent read of the table before any token is
// known to be bad. Its 256-bit token cannot be guessed, so the threat is a
// flood, not a guess. The scope name accept-invitation keys it by client
// address, as reset-password is keyed. A flood from one address then spends
// that address's budget and no one else's: an invitee elsewhere still accepts.
func TestAcceptInvitationIsLimitedByClientAddress(t *testing.T) {
	t.Parallel()
	const budget = 3
	app := newTestApp(t, staffRealmEnv(
		"AWESOME_AUTH_RATE_LIMIT_ENABLED", "true",
		"AWESOME_AUTH_RATE_LIMIT_SCOPE", "accept-invitation",
		"AWESOME_AUTH_RATE_LIMIT_MAX", strconv.Itoa(budget),
	))
	t.Cleanup(app.Close)

	bogus := `{"token":"` + strings.Repeat("A", 43) + `","password":"` + testPassword + `"}`
	for i := 1; i <= budget; i++ {
		if resp := invokeFrom(t, app, "203.0.113.66", http.MethodPost, "/auth/invitations/accept", bogus); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bogus acceptance %d of a budget of %d answered %d %s, want 401", i, budget, resp.StatusCode, resp.Body)
		}
	}
	if resp := invokeFrom(t, app, "203.0.113.66", http.MethodPost, "/auth/invitations/accept", bogus); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("acceptance %d of a budget of %d answered %d %s, want 429", budget+1, budget, resp.StatusCode, resp.Body)
	}

	// Another address is a budget of its own: a real invitee accepts.
	invite := invokeIAM(t, app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, `{"email":"limited@example.test"}`)
	token, _ := decodeBody(t, invite)["token"].(string)
	if invite.StatusCode != http.StatusCreated || token == "" {
		t.Fatalf("invite answered %d %s", invite.StatusCode, invite.Body)
	}
	accept := invokeFrom(t, app, "198.51.100.23", http.MethodPost, "/auth/invitations/accept",
		`{"token":"`+token+`","password":"`+testPassword+`"}`)
	if accept.StatusCode != http.StatusForbidden || decodeBody(t, accept)["code"] != "2FA_SETUP_REQUIRED" {
		t.Fatalf("an invitee at another address answered %d %s, want the realm's 403 2FA_SETUP_REQUIRED", accept.StatusCode, accept.Body)
	}
}

// TestRateLimiterHandsTheBodyToTheHandlerIntact: keying by email means reading
// the request body in the outermost middleware, and the handler below has to see
// exactly what the client sent.
//
// The check is behavioural rather than structural: a register with a password
// that the login route then accepts proves both halves of the body survived the
// peek, which inspecting r.Body in a stub could not.
func TestRateLimiterHandsTheBodyToTheHandlerIntact(t *testing.T) {
	t.Parallel()

	app := newTestApp(t, baseEnv())
	prefix := config.Defaults().HTTP.APIPrefix
	const email = "intact@example.test"

	if resp := invoke(t, app, http.MethodPost, prefix+"/register", jsonHeaders(), nil, registerBody(email)); resp.StatusCode/100 != 2 {
		t.Fatalf("register through the limiter answered %d %s; the body did not survive the peek", resp.StatusCode, resp.Body)
	}
	resp := invoke(t, app, http.MethodPost, prefix+"/login", jsonHeaders(), nil, registerBody(email))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login through the limiter answered %d %s; the body did not survive the peek", resp.StatusCode, resp.Body)
	}
}

// TestRateLimiterFallsBackToTheAddressWhenTheBodyNamesNoSubject covers the case
// the schema does not answer: keyBy: email on a route whose body carries no
// email.
//
// The behaviour has to be a real limit and not a hole, and it has to not be one
// shared bucket. Both halves are checked: the budget is enforced, and it is
// enforced per address rather than globally — a single sentinel subject would
// make every such request in the deployment share one budget, which is a
// self-inflicted outage an attacker triggers by sending an empty body.
func TestRateLimiterFallsBackToTheAddressWhenTheBodyNamesNoSubject(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		body string
	}{
		{"an empty object", `{}`},
		{"no body at all", ``},
		{"a body that is not JSON", `not json at all`},
		{"an email that is not a string", `{"email":{"nested":true}}`},
		{"an email that is empty", `{"email":"   "}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := newTestApp(t, baseEnv())
			prefix := config.Defaults().HTTP.APIPrefix
			var last int
			for i := 0; i <= rateLimitDefaultMax; i++ {
				last = invoke(t, app, http.MethodPost, prefix+"/login", jsonHeaders(), nil, tc.body).StatusCode
			}
			if last != http.StatusTooManyRequests {
				t.Errorf("a body naming no subject was never limited (last answer %d); "+
					"an unkeyable body must fall back to the client address, not switch the limiter off", last)
			}
		})
	}
}

// TestRateLimiterIsOffWhenTheBlockIsOff and its sibling below pin the two ways
// the limiter must be absent: the operator turned it off, and the operator
// enabled it over nothing.
//
// Both matter because nil is what the core reads as "no limiter" and composes a
// pass-through for. Returning a middleware that matches nothing would be
// indistinguishable in behaviour and would cost a map lookup on every request of
// every route for the life of the deployment.
func TestRateLimiterIsOffWhenTheBlockIsOff(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.RateLimit.Enabled = false
	if newRateLimiter(cfg, nil, discardLogger()) != nil {
		t.Errorf("a disabled block still produced a limiter; nil is how the core is told there is none")
	}
}

func TestRateLimiterIsOffWhenTheScopeIsEmpty(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Scope = nil
	if newRateLimiter(cfg, nil, discardLogger()) != nil {
		t.Errorf("an empty scope still produced a limiter; it would match nothing and cost a lookup per request")
	}
}

// TestRateLimiterFailsOpenWhenTheCounterIsUnavailable is the decision this block
// is most likely to be second-guessed on, so it is pinned with the argument in
// the failure message.
//
// The counter is in the same table as the user store, so on this product "the
// limiter cannot count" and "the route cannot serve" are one event. Failing
// closed would turn a partial DynamoDB degradation into a total outage on
// exactly the routes people need during one, and would replace a 500 naming the
// store with a 429 blaming the caller.
func TestRateLimiterFailsOpenWhenTheCounterIsUnavailable(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Max = 3
	cfg.RateLimit.WindowSeconds = 60
	cfg.RateLimit.KeyBy = config.RateLimitKeyByIP
	cfg.RateLimit.Scope = []string{"login"}

	broken := counterFunc(func(context.Context, string, string, int, time.Duration) (bool, time.Duration, error) {
		return false, 0, errors.New("dynamodb: ProvisionedThroughputExceededException")
	})
	h := newRateLimiter(cfg, broken, discardLogger())(okHandler())

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loginRequest())
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d answered %d with an unreachable counter, want 200: the limiter fails open", i, rec.Code)
		}
	}

	// The floor is the local tier, and it is a real one: within a single
	// execution environment the budget still applies during the outage, so a
	// store failure is max per environment rather than no limit at all.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginRequest())
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("the fourth request during an outage answered %d, want 429: the in-process tier is the floor under a fail-open window", rec.Code)
	}
}

// TestLocalTierNeverRefusesWhatTheSharedCounterWouldAllow is the soundness
// property of the pre-filter, and the reason a local refusal is legitimate at
// all.
//
// The local tier increments only when it allows, and every locally-allowed
// request reaches the shared counter, so by the time the local count reaches max
// the shared counter is at max too. The test states it the way a bug would break
// it: with a counter that allows everything, the local tier must still not
// refuse before max.
func TestLocalTierNeverRefusesWhatTheSharedCounterWouldAllow(t *testing.T) {
	t.Parallel()

	local := newLocalRateLimiter(5, time.Minute, func() time.Time { return time.Unix(1_800_000_060, 0) })
	for i := 1; i <= 5; i++ {
		if !local.allow("login", "a@example.test") {
			t.Fatalf("request %d of a budget of 5 was refused locally; the pre-filter has a false positive", i)
		}
	}
	if local.allow("login", "a@example.test") {
		t.Errorf("request 6 of a budget of 5 passed the pre-filter; it would cost a write to learn what it already knew")
	}
	// A second subject and a second scope are separate budgets, exactly as they
	// are in the shared counter.
	if !local.allow("login", "b@example.test") {
		t.Errorf("a second subject was refused; the local key is not per subject")
	}
	if !local.allow("forgot-password", "a@example.test") {
		t.Errorf("a second scope was refused; the local key is not per scope")
	}
}

// TestLocalTierNamesTheSameWindowAsTheSharedCounter pins the duplicated
// arithmetic the pre-filter's soundness rests on.
//
// Both tiers divide seconds-since-epoch by the window length, so they always
// name the same window. If the local tier aligned to a subject's first request
// instead, it could refuse inside a window the shared counter considered fresh,
// which is a false positive on the login path. The shared half of this is
// TestRateLimitWindowIsEpochAligned in internal/store/dynamodb.
func TestLocalTierNamesTheSameWindowAsTheSharedCounter(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_119, 0)
	local := newLocalRateLimiter(1, time.Minute, func() time.Time { return now })

	if !local.allow("login", "a@example.test") {
		t.Fatalf("the first request was refused")
	}
	if local.allow("login", "a@example.test") {
		t.Fatalf("the budget of 1 was not enforced")
	}

	// One second later is the next epoch-aligned minute, and therefore a fresh
	// budget — not sixty seconds after this subject first appeared.
	now = now.Add(time.Second)
	if !local.allow("login", "a@example.test") {
		t.Errorf("the budget did not reset at the epoch-aligned boundary; the two tiers name different windows")
	}

	// rateLimitRemaining, which the locally-refused path uses for Retry-After,
	// has to agree with the same boundary or a client would be told to come back
	// before or after the budget actually resets.
	if got := rateLimitRemaining(time.Unix(1_800_000_119, 0), time.Minute); got != time.Second {
		t.Errorf("rateLimitRemaining = %s one second before the boundary, want 1s", got)
	}
}

// TestLocalTierDoesNotRefuseWhenItsTableIsFull: the bound on the local map is an
// allocation bound, never a decision. Over the cap an untracked subject is
// allowed through to the shared counter, which is the real limit; refusing
// instead would be a false positive, and a limiter whose own table filling up
// starts refusing legitimate traffic is the classic way a limiter becomes the
// outage.
func TestLocalTierDoesNotRefuseWhenItsTableIsFull(t *testing.T) {
	t.Parallel()

	local := newLocalRateLimiter(1, time.Minute, func() time.Time { return time.Unix(1_800_000_060, 0) })
	local.maxSubjects = 4

	for i := 0; i < 4; i++ {
		if !local.allow("login", "filler"+strconv.Itoa(i)) {
			t.Fatalf("filler %d was refused", i)
		}
	}
	for i := 0; i < 10; i++ {
		if !local.allow("login", "overflow@example.test") {
			t.Fatalf("an untracked subject was refused locally on attempt %d; a full table is not a decision", i)
		}
	}
}

// TestLocalTierIsSafeUnderConcurrency. One execution environment serves one
// request at a time, so this is not the runtime's shape — but the same code runs
// under `go test -race` in this package's other tests and in any host that is
// not Lambda, and a limiter with a data race is a limiter whose count is
// undefined.
func TestLocalTierIsSafeUnderConcurrency(t *testing.T) {
	t.Parallel()

	local := newLocalRateLimiter(50, time.Minute, func() time.Time { return time.Unix(1_800_000_060, 0) })
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			local.allow("login", "shared@example.test")
			local.allow("login", "own"+strconv.Itoa(i))
		}(i)
	}
	wg.Wait()
}

// TestRateLimitingAddsNoCoreOption records that this block fills none of the
// option slots D3 reserved, and that this is a decision rather than an omission
// — the same position `docs` is in.
//
// The whole surface is auth.HTTPConfig.RateLimiter, which the adapter reads at
// mount time. Inventing an auth.Option to occupy a slot would be filling the
// slot rather than wiring the block, and it would move every later block's
// landing site.
func TestRateLimitingAddsNoCoreOption(t *testing.T) {
	t.Parallel()

	if got := rateLimitOptions(); len(got) != 0 {
		t.Errorf("rateLimitOptions returned %d options; the block reaches the core entirely through HTTPConfig.RateLimiter", len(got))
	}

	// And the limiter really does reach the adapter, which is the half that
	// would otherwise be an untested claim: a limiter built and never attached
	// is a deployment that logs "rate limiting is on" and limits nothing.
	cfg := config.Defaults()
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Max = 1
	cfg.RateLimit.KeyBy = config.RateLimitKeyByIP
	cfg.RateLimit.Scope = []string{"login"}
	if newRateLimiter(cfg, nil, discardLogger()) == nil {
		t.Fatalf("a configured block produced no limiter")
	}
}

// TestResolveRateLimitFollowsTheAPIPrefix: the match table is built from the
// resolved prefix, so a deployment that moved its mount keeps its limiter over
// the routes rather than over paths nothing serves.
func TestResolveRateLimitFollowsTheAPIPrefix(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.HTTP.APIPrefix = "/identity"
	cfg.RateLimit.Scope = []string{"login", "magic-link"}

	rl := resolveRateLimit(cfg)
	for _, want := range []string{
		"POST /identity/login",
		"POST /identity/magic-link/send",
		"POST /identity/magic-link/verify",
	} {
		if _, ok := rl.routes[want]; !ok {
			t.Errorf("the resolved table has no entry for %q; the limiter did not follow http.apiPrefix", want)
		}
	}
	if len(rl.routes) != 3 {
		t.Errorf("the resolved table holds %d entries for two scopes covering three routes: %v", len(rl.routes), rl.routes)
	}
}

// ── small fixtures ───────────────────────────────────────────────────────────

// counterFunc adapts a function to rateLimitCounter, so a test can supply a
// counter that fails, or one that always allows, without a type of its own.
type counterFunc func(ctx context.Context, scope, subject string, max int, window time.Duration) (bool, time.Duration, error)

func (f counterFunc) AllowRequest(ctx context.Context, scope, subject string, max int, window time.Duration) (bool, time.Duration, error) {
	return f(ctx, scope, subject, max, window)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func loginRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, config.Defaults().HTTP.APIPrefix+"/login", strings.NewReader(`{}`))
	r.RemoteAddr = "203.0.113.7:0"
	return r
}
