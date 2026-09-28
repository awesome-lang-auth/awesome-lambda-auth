package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The built-in rate limiter: the `rateLimit` block of the schema (§1.16), which
// internal/config/phases.go no longer refuses.
//
// ── this is net-new, and nothing upstream decides any of it ──────────────────
//
// The reference has no rate limiting at all. RouterOptions.rateLimiter
// (auth.router.ts:46) is an empty slot for a host-supplied Express handler;
// absent, the router collapses it to an empty middleware list (rl = [], :468)
// and ships no algorithm, no default and no response shape. So there is no
// behaviour to reproduce here and no upstream to appeal to: every value below is
// a product decision, the spec left every one of them TBD, and the argument for
// each has to be written down because nothing else can be pointed at.
//
// The wire consequence is one refusal the reference never makes, and it is
// registered as the product deviation `rate-limited-routes-answer-429`
// (deviations.go), which quotes the body and the headers verbatim.
//
// ── where it goes, and why the shape of the core's field matters ─────────────
//
// auth.HTTPConfig.RateLimiter is a **constructor**, not a handler. Each adapter
// calls it once per route at mount time — some thirty calls for one mount
// (adapter/nethttp guard) — so the counters have to be created *outside* the
// function this file returns and captured by it. newRateLimiter therefore builds
// the local tier and resolves the route table once and returns a closure over
// them; allocating either inside the returned function would give every route a
// private budget instead of the single shared one the whole design rests on.
//
// The adapter composes it outermost: RateLimiter, then CSRFMiddleware, then the
// auth middleware (adapter/nethttp guard, `auth.RateLimitMiddleware(a.cfg)(auth.CSRFMiddleware(a.cfg)(h))`),
// reproducing the reference's own ordering, where rl is prepended ahead of the
// auth middleware on every route (:541 onwards, GET /me at :656). That order is
// the point of a limiter: a refusal costs nothing downstream — no token
// verified, no store read, no CSRF comparison — and it has one visible
// consequence worth naming, since the CSRF auto-init cookie is distributed by a
// middleware *inside* the chain: a client whose very first request is refused
// receives no csrf-token cookie with the 429. That is correct. A refused request
// is a request the deployment did no work for, and handing out a CSRF token is
// work.
//
// It is applied to every auth route and not to the JWKS document, which the
// adapter registers ahead of the chain. One pair of routes falls *inside* the
// slot here that falls outside it in the reference — the OAuth stubs for an
// unconfigured provider, which the reference registers as bare 404s with no rl
// (:1361-1362, :1407-1408) and which this port mounts as one always-guarded
// handler per route. Behind a limiter at its limit those answer 429 here and 404
// there. That difference belongs to the core, whose HTTPConfig.RateLimiter
// comment names it and whose register carries it; this file does not restate it
// as a product deviation, and the product entry says so rather than leaving the
// reader to wonder. It is also unreachable on a default deployment, because no
// OAuth route is in the default scope.
//
// ── nothing here adds a route ────────────────────────────────────────────────
//
// This is a middleware and registers no pattern, exactly like docsSecurityHeaders:
// the adapter still owns every path under the api prefix, and the rule that
// nothing in this binary may add one is untouched. What the middleware does
// instead is *match* on the resolved prefix and a table of path suffixes, which
// is the one coupling this file has to the adapter's route table and is pinned
// by TestRateLimitedRoutesAreMountedByTheAdapter.
//
// ── two tiers, and which one is the limit ────────────────────────────────────
//
// **An in-process limiter is not a limiter on this runtime, and that has to be
// said plainly.** A Lambda execution environment serves one request at a time
// and AWS runs as many of them as the arrival rate demands; an in-process
// counter therefore limits each environment separately, so the effective ceiling
// is max × a concurrency nobody chose and nothing reports. An attacker who can
// raise concurrency raises their own budget with it, which is the opposite of a
// limit.
//
// So there are two tiers and only one of them is the limit:
//
//   - **The shared counter** (internal/store/dynamodb rate_limit.go) is the
//     limit. One conditional UpdateItem per request against an item every
//     execution environment shares.
//   - **The local tier** (localRateLimiter below) is a pre-filter in front of
//     it, and never the limit. It holds the same max over the same
//     epoch-aligned window, so it can only ever refuse a request the shared
//     counter would also have refused — it has no false positives by
//     construction — and what it buys is the write: an environment that has
//     already watched a subject exhaust its budget this window refuses locally
//     and spends nothing.
//
// The soundness argument is worth one more line, because it is the only thing
// that makes a local refusal legitimate. The local tier increments only when it
// allows, and every locally-allowed request reaches the shared counter. So by
// the time the local count reaches max, this environment has sent max requests
// that the shared counter either accepted (leaving it at max) or refused
// (meaning it was already at max). Either way the shared counter is at max, and
// the request the local tier is about to refuse would have been refused there
// too.
//
// ── fail open, and what carries the floor ────────────────────────────────────
//
// When the shared counter cannot be reached, the request is **allowed**.
//
// The argument is topological rather than a preference. The counter lives in the
// same DynamoDB table as the user store, so on this product "the limiter cannot
// count" and "the route cannot serve" are the same event: every route in the
// default scope reads or writes that table immediately after the limiter. A
// limiter that failed closed would therefore refuse requests that were going to
// fail anyway, buy nothing, and do real harm twice over — it would convert a
// partial DynamoDB degradation into a total outage on exactly the routes people
// need during one, and it would hide the cause, replacing a 500 that names the
// store with a 429 that blames the caller.
//
// The alternative reading — "an outage becomes an unmetered window" — is the
// cost, and it is bounded rather than accepted whole. A store failure does not
// remove the local tier: it falls back to it, so the ceiling during an outage is
// max per subject per window *per execution environment* instead of max
// outright. That is the honest description of the floor, and it is the one real
// job the local tier has beyond saving writes. It is written down here, in the
// config reference and in the deviation, because a bound that depends on a
// number AWS chooses is not a bound anyone should discover from a bill.
//
// The failure is logged once per cold start, at WARN, and not once per request:
// a limiter that logged every failed write during a DynamoDB incident would add
// its own load to the incident.
//
// ── the subject, and the route that has no email ─────────────────────────────
//
// `rateLimit.keyBy` is `ip` or `email` and defaults to **email**. See
// rateLimitSubject for how a route's subject is resolved, and
// docs/config-reference.md for why the default is not `ip`.
//
// The interesting case is the one the schema does not answer: `keyBy: email` on
// a route whose body carries no email. Three things could be done and two of
// them are wrong. Keying every such request under one sentinel would put them
// all in one partition under one budget — a self-inflicted denial of service an
// attacker triggers on purpose by sending nothing. Skipping the limiter would
// leave POST /2fa/verify, a six-digit code, unlimited, which is the single route
// a limiter is most obviously for. So each route declares an ordered list of
// subject sources and every list ends, implicitly, at the client address:
// `email` where the body has one, the sha256 of the presented `tempToken` where
// it has a challenge instead, and the address otherwise. Nothing in that chain
// verifies anything or reads a store — a hash is not a check — so the refusal
// still costs nothing downstream.

// The exact 429. It is one literal because the deviation register quotes it
// verbatim and rateLimitResponseIsExactlyThis pins it; anything that reassembled
// it from parts would be free to drift from the text an operator was promised.
//
// **The body is the family envelope**, `{error, code}`, because every other
// error this deployment answers is, and a client that already switches on `code`
// needs no new parser for this one. RATE_LIMITED is net-new — the reference has
// no such code, having no limiter — and it is a code rather than a bare `error`
// because the two clients that would act on it (back off, show a wait) must not
// have to match an English sentence.
const rateLimitBody = `{"error":"Too many requests","code":"RATE_LIMITED"}`

// writeRateLimited sends the refusal.
//
// **Retry-After and nothing else.** The obvious companions are the
// RateLimit-Limit / RateLimit-Remaining / RateLimit-Reset family, and they are
// deliberately not sent. The usual objection — that they hand an attacker the
// limit — is weak on its own, because an attacker willing to spend requests
// discovers the limit by reaching it. The decisive one is what
// RateLimit-Remaining would leak on a *successful* response: with `keyBy: email`
// the counter is per account, so a remaining count is an oracle about somebody
// else's traffic. Anyone able to send one request naming victim@example.com
// could read, from a 200, whether that person has been logging in. The headers
// would introduce a side channel that the 429 alone does not have, in exchange
// for a convenience a client can get from Retry-After.
//
// Retry-After itself is sent because it gives away nothing the refusal has not
// already given away — the caller knows they are limited — and because a client
// that backs off correctly is strictly better for everyone, including the
// deployment. It is the delta-seconds form (RFC 9110 §10.2.3), rounded up and
// never below 1: a `Retry-After: 0` is an invitation to retry immediately, which
// is the behaviour this header exists to prevent.
//
// Cache-Control: no-store is one header's insurance against a shared cache in
// front of the API serving one subject's refusal to another. A 429 is not
// heuristically cacheable, so on a correct cache this changes nothing; it is
// here because "correct cache" is an assumption about somebody else's CDN
// configuration and the cost of not assuming is twelve bytes.
//
// No Set-Cookie, by construction rather than by suppression: the limiter is
// outermost, so nothing that sets one has run.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int64(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	h := w.Header()
	h.Set("Retry-After", strconv.FormatInt(seconds, 10))
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = io.WriteString(w, rateLimitBody)
}

// rateLimitSubjectSource is one place a route's subject may be read from, in the
// order the route prefers them. It is only consulted when `keyBy: email`: with
// `keyBy: ip` the subject is the client address on every route and no body is
// ever read.
type rateLimitSubjectSource struct {
	// field is the JSON body member to read.
	field string

	// address normalises the value the way the core normalises an address
	// (lower-cased and trimmed, service.go:58), so that Alice@Example.com and
	// alice@example.com are one budget rather than two. Without it, case is a
	// free reset.
	address bool

	// hash replaces the value with a truncated sha256 of it. Set for anything
	// that is a credential: a tempToken names the challenge it belongs to, which
	// is exactly the subject wanted, but it is also a bearer credential and must
	// not become a partition key in the clear. The hash is a stable name for the
	// same challenge and reveals nothing about it.
	hash bool
}

// The subject chains. Every one of them ends, implicitly, at the client address;
// see rateLimitSubject.
var (
	// subjectFromEmail: the routes whose body names the account being acted on.
	subjectFromEmail = []rateLimitSubjectSource{{field: "email", address: true}}

	// subjectFromEmailOrChallenge: /magic-link/send and /sms/send take an email
	// in login mode and a tempToken in `mode: "2fa"`, where the address is
	// derived from the token and the body's email is ignored outright
	// (auth.router.ts:1087-1107, :1192-1203). One chain covers both modes
	// without this file having to parse `mode`.
	subjectFromEmailOrChallenge = []rateLimitSubjectSource{
		{field: "email", address: true},
		{field: "tempToken", hash: true},
	}

	// subjectFromChallenge: POST /2fa/verify carries a tempToken and a totpCode
	// and no identity at all (auth.router.ts:859-877). Keying on the challenge
	// is what makes this route's limit exact: an attacker brute-forcing the
	// six-digit code holds one tempToken and presents it with every guess, so
	// the counter is per challenge; one who rotates tokens has to log in again
	// for each, which `login` limits.
	subjectFromChallenge = []rateLimitSubjectSource{{field: "tempToken", hash: true}}

	// subjectFromUserOrChallenge: POST /sms/verify carries `userId` in login
	// mode and `tempToken` in 2FA mode (auth.router.ts:1244-1289). The user id
	// is an identifier and not a credential, so it is keyed on as it stands.
	subjectFromUserOrChallenge = []rateLimitSubjectSource{
		{field: "userId", address: false},
		{field: "tempToken", hash: true},
	}
)

// rateLimitRoute is one path the limiter watches, and how it names a subject on
// it.
type rateLimitRoute struct {
	method string

	// path is the suffix after the resolved api prefix, as the adapter mounts
	// it. These are literals rather than constants imported from the core,
	// because the core exports none for them — and a literal that drifted from
	// the adapter's table would silently stop limiting a route rather than fail
	// to build, which is why TestRateLimitedRoutesAreMountedByTheAdapter drives
	// every one of them through a real mount and fails on a 404.
	path string

	// subjects is the ordered chain tried under `keyBy: email`. Nil means the
	// route has no identity in its body and is keyed by the client address.
	subjects []rateLimitSubjectSource
}

// rateLimitRoutes maps each name `rateLimit.scope` accepts onto the routes it
// covers. The vocabulary is internal/config's rateLimitEndpoints — "the
// unauthenticated, credential-guessable ones; a limiter on anything else would
// be theatre" — and this table is the other half of that definition: the config
// layer says which names exist, this says what each one means on the wire.
// TestEveryScopeNameMapsToRoutes holds the two together, so a name added to one
// and not the other is a build-time failure rather than a scope that validates
// and limits nothing.
//
// Several names cover two routes, and the pairing is always "mint" plus "spend":
// `magic-link` covers /magic-link/send and /magic-link/verify, `sms-code`
// covers /sms/send and /sms/verify. Limiting only the sending half would leave
// the guessable half — a six-digit SMS code — open, and limiting only the
// spending half would leave the mailbox-flooding half open. They are one name
// because an operator who wants one almost never wants only one, and because the
// two halves of a flow sharing a budget is the behaviour that is easy to
// describe.
var rateLimitRoutes = map[string][]rateLimitRoute{
	"login":           {{http.MethodPost, "/login", subjectFromEmail}},
	"register":        {{http.MethodPost, "/register", subjectFromEmail}},
	"forgot-password": {{http.MethodPost, "/forgot-password", subjectFromEmail}},

	"magic-link": {
		{http.MethodPost, "/magic-link/send", subjectFromEmailOrChallenge},
		{http.MethodPost, "/magic-link/verify", subjectFromChallenge},
	},
	"sms-code": {
		{http.MethodPost, "/sms/send", subjectFromEmailOrChallenge},
		{http.MethodPost, "/sms/verify", subjectFromUserOrChallenge},
	},
	"2fa-verify": {{http.MethodPost, "/2fa/verify", subjectFromChallenge}},

	// The four below carry a token and no identity, so under `keyBy: email` they
	// key by the client address like everything else with nothing to key on. The
	// token itself is deliberately not used: the threat on these routes is
	// guessing *a* token, not exhausting a known one, so a per-token budget
	// would give every guess its own and limit nothing.
	"refresh":             {{http.MethodPost, "/refresh", nil}},
	"reset-password":      {{http.MethodPost, "/reset-password", nil}},
	"verify-email":        {{http.MethodGet, "/verify-email", nil}},
	"resend-verification": {{http.MethodPost, "/send-verification-email", nil}},
}

// maxRateLimitBodyPeek bounds what the limiter reads to find a subject.
//
// The bodies on these routes are small JSON objects; 8 KiB is far more than any
// of them and far less than a body an attacker could use to make the limiter
// itself the expensive part of a refused request. What is read is handed back to
// the handler untouched — see rateLimitSubject — so a larger body still arrives
// whole; only the search for a subject gives up, and a body whose first 8 KiB is
// not parseable JSON simply falls through to the client address.
const maxRateLimitBodyPeek = 8 << 10

// rateLimitCounter is the shared counter, discovered structurally on whatever
// the driver returned — the same way settingsStoreProvider finds the settings
// store — so that cmd/auth does not take the store package's vocabulary into its
// own. The DynamoDB store's assertion of this shape is in its own rate_limit.go.
//
// It is one interface and not a provider plus a view, unlike Settings() and
// Templates(), because there is nothing to hand over: the core never sees this
// store. AllowRequest is called by the middleware in this file and by nothing
// else, so the store can satisfy it directly.
type rateLimitCounter interface {
	AllowRequest(ctx context.Context, scope, subject string, max int, window time.Duration) (bool, time.Duration, error)
}

// localRateLimiter is the per-execution-environment pre-filter. It is not the
// limit; see the file header for why, and for the argument that it can never
// refuse a request the shared counter would have allowed.
type localRateLimiter struct {
	mu sync.Mutex

	max    int
	window time.Duration

	// index is the window the counts map describes. When the wall clock moves
	// into a new window the whole map is dropped, which is both the reset and
	// the eviction: a fixed window has nothing to carry forward, so there is no
	// expiry to track per entry and no scan to run.
	index  int64
	counts map[string]int

	// maxSubjects bounds the map, because it is otherwise an
	// attacker-controlled allocation on an unauthenticated route: with `keyBy:
	// email` the key comes out of the request body. Over the cap, a subject that
	// is not already tracked is simply not tracked — it is allowed through to
	// the shared counter, which is the real limit. Refusing instead would be a
	// false positive, and a limiter whose own table being full starts refusing
	// legitimate traffic is the classic way a limiter becomes the outage.
	maxSubjects int

	now func() time.Time
}

// defaultLocalRateLimitSubjects is the cap on the local table.
//
// Ten thousand entries at a few dozen bytes each is noise against a Lambda's
// smallest memory size, and it is far more distinct subjects than one execution
// environment sees in one window of legitimate traffic — which is the number
// that matters, since the cap is only reached by a keyspace flood, and reaching
// it costs nothing but the pre-filter's savings.
const defaultLocalRateLimitSubjects = 10_000

func newLocalRateLimiter(max int, window time.Duration, now func() time.Time) *localRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &localRateLimiter{
		max:         max,
		window:      window,
		counts:      make(map[string]int),
		maxSubjects: defaultLocalRateLimitSubjects,
		now:         now,
	}
}

// allow records one request and reports whether the shared counter still needs
// to be asked. False means this environment has already seen the subject exhaust
// its budget in this window, so the shared counter is at max and the write can
// be skipped.
func (l *localRateLimiter) allow(scope, subject string) bool {
	// The same arithmetic the shared counter uses — seconds since the epoch
	// divided by the window length — deliberately duplicated rather than
	// imported, because this tier must not depend on which store driver is in
	// play and internal/store/dynamodb is one driver. What makes the duplication
	// safe is that both derive the index from the epoch and not from a subject's
	// first request, so the two always name the same window; that is the
	// property the local tier's soundness rests on, and it is pinned on both
	// sides (TestRateLimitWindowIsEpochAligned there,
	// TestLocalTierNamesTheSameWindowAsTheSharedCounter here).
	secs := int64(l.window / time.Second)
	if secs < 1 {
		secs = 1
	}
	index := l.now().UTC().Unix() / secs

	l.mu.Lock()
	defer l.mu.Unlock()

	if index != l.index {
		l.index = index
		l.counts = make(map[string]int, len(l.counts))
	}

	k := scope + "\x00" + subject
	n, tracked := l.counts[k]
	if !tracked && len(l.counts) >= l.maxSubjects {
		// The table is full of other subjects. Do not track this one and do not
		// refuse it: the shared counter is the limit and it is still reachable.
		return true
	}
	if n >= l.max {
		return false
	}
	l.counts[k] = n + 1
	return true
}

// rateLimiterConfig is everything newRateLimiter resolved, kept as a value so
// the cold-start log and the tests can read the same decisions the middleware
// acts on rather than re-deriving them.
type rateLimiterConfig struct {
	window time.Duration
	max    int
	keyBy  string

	// routes is the resolved match table: "METHOD /prefix/path" to the scope
	// name and subject chain. Resolved once, at mount time, because the prefix
	// cannot change afterwards and a per-request join would be work done on
	// every request to answer a question with a constant answer.
	routes map[string]resolvedRateLimitRoute
}

type resolvedRateLimitRoute struct {
	scope    string
	subjects []rateLimitSubjectSource
}

// resolveRateLimit turns the config block into the table the middleware matches
// on. It is separate from newRateLimiter so the cold-start log and the tests can
// see the resolution without building a limiter.
func resolveRateLimit(cfg *config.Config) rateLimiterConfig {
	prefix := httpConfig(cfg).Prefix()
	out := rateLimiterConfig{
		window: time.Duration(cfg.RateLimit.WindowSeconds) * time.Second,
		max:    cfg.RateLimit.Max,
		keyBy:  cfg.RateLimit.KeyBy,
		routes: map[string]resolvedRateLimitRoute{},
	}
	for _, scope := range cfg.RateLimit.Scope {
		for _, rt := range rateLimitRoutes[scope] {
			out.routes[rt.method+" "+prefix+rt.path] = resolvedRateLimitRoute{
				scope:    scope,
				subjects: rt.subjects,
			}
		}
	}
	return out
}

// newRateLimiter returns the value for auth.HTTPConfig.RateLimiter, or nil when
// the block is off — and nil is the right way to say off, because the core reads
// it as "no limiter" and composes a pass-through (auth.RateLimitMiddleware),
// which is the reference's own default.
//
// counter may be nil, which is the development driver having no shared store to
// count in; see logRateLimitSurface for what is said about that and why it is
// not a refusal.
//
// Everything expensive happens here, once, because the returned function is
// called once per route at mount time. See the file header.
func newRateLimiter(cfg *config.Config, counter rateLimitCounter, log *slog.Logger) func(http.Handler) http.Handler {
	if !cfg.RateLimit.Enabled {
		return nil
	}
	rl := resolveRateLimit(cfg)
	if len(rl.routes) == 0 {
		// Enabled with an empty scope. Nothing is limited, and a middleware that
		// matched nothing would still cost a map lookup per request forever.
		return nil
	}

	tier := newRateLimitTier(rl.max, rl.window, counter, log)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route, watched := rl.routes[r.Method+" "+r.URL.Path]
			if !watched {
				next.ServeHTTP(w, r)
				return
			}
			tier.serve(w, r, route.scope, rateLimitSubject(r, rl.keyBy, route.subjects), next)
		})
	}
}

// rateLimitTier is one budget: the in-process pre-filter and the shared counter
// it stands in front of, over one max and one window, with the two
// once-per-cold-start warnings that belong to it.
//
// It is the body newRateLimiter's closure had before the admin console's
// promote route needed the same body under a different match. Two tiers are
// built from one block — one for the auth router, one for that route — and they
// share the counter store, and therefore the table, and nothing else: separate
// local tables, separate scopes, separate warnings. A single tier for both
// would have let a flood on one route spend the pre-filter's table for the
// other, which is small, and would have put the auth router's route table in
// front of a route that is not under the api prefix, which is wrong.
type rateLimitTier struct {
	max     int
	window  time.Duration
	local   *localRateLimiter
	counter rateLimitCounter
	log     *slog.Logger

	degradedOnce  sync.Once
	noAddressOnce sync.Once
}

func newRateLimitTier(max int, window time.Duration, counter rateLimitCounter, log *slog.Logger) *rateLimitTier {
	return &rateLimitTier{
		max:     max,
		window:  window,
		local:   newLocalRateLimiter(max, window, nil),
		counter: counter,
		log:     log,
	}
}

// serve applies the budget for (scope, subject) and either hands the request on
// or writes the refusal. Every branch below is argued in the file header; the
// order is the one the design rests on — local pre-filter, then the shared
// counter, failing open when the counter cannot be reached.
func (t *rateLimitTier) serve(w http.ResponseWriter, r *http.Request, scope, subject string, next http.Handler) {
	if subject == "" {
		// No client address and nothing in the body to key on. This is not
		// something a client can arrange — the address comes from the Lambda
		// event and not from a header (see clientAddress) — so it means an
		// event shape that carries none. There is nothing to count, and
		// refusing every request on a route because the runtime did not report
		// a source is the wrong direction.
		t.noAddressOnce.Do(func() {
			t.log.Warn("rate limiter has no subject to key on and is passing requests through",
				slog.String("path", "rateLimit.keyBy"),
				slog.String("route", r.Method+" "+r.URL.Path),
				slog.String("problem", "the event carries no source address and the request body names no subject, so there is nothing to count per"),
				slog.String("remedy", "this is a property of the event source, not of the document; check that the function is behind API Gateway, an ALB or a Function URL"))
		})
		next.ServeHTTP(w, r)
		return
	}

	if !t.local.allow(scope, subject) {
		// The shared counter is already at max for this subject and window —
		// see the file header for why that follows — so the write is skipped.
		// The window's remaining time is recomputed rather than remembered,
		// which keeps Retry-After honest without storing an instant per
		// subject.
		writeRateLimited(w, rateLimitRemaining(time.Now(), t.window))
		return
	}

	if t.counter == nil {
		// No shared store: the local tier is the whole limiter. It is the
		// development driver, announced at cold start, and never production —
		// RS-12 refuses the memory driver there.
		next.ServeHTTP(w, r)
		return
	}

	allowed, retryAfter, err := t.counter.AllowRequest(r.Context(), scope, subject, t.max, t.window)
	if err != nil {
		// Fail open, deliberately; see the file header. Once per cold start,
		// because a limiter that logged every failed write during a DynamoDB
		// incident would add its own load to the incident.
		t.degradedOnce.Do(func() {
			t.log.Warn("rate limiter cannot reach its shared counter and is failing open",
				slog.String("path", "rateLimit"),
				slog.String("scope", scope),
				slog.String("error", err.Error()),
				slog.String("effect", "requests are allowed through; the remaining bound is the in-process pre-filter, which is per execution environment"),
				slog.String("why", "the counter is in the same table as the user store, so a route refused here would have failed behind the limiter anyway"))
		})
		next.ServeHTTP(w, r)
		return
	}
	if !allowed {
		writeRateLimited(w, retryAfter)
		return
	}
	next.ServeHTTP(w, r)
}

// newAdminPromoteLimiter returns the value for auth.AdminOptions.RateLimiter:
// the console's own limiter slot, which the core applies to exactly one route,
// POST <admin>/users/{id}/promote, ahead of the guard — and to nothing else on
// that surface, the admin login included, on either line (core admin.go,
// AdminOptions.RateLimiter). The login gets a limiter of its own below,
// newAdminLoginLimiter, by a different mechanism.
//
// ── why the slot is filled, and not left nil ─────────────────────────────────
//
// nil is the reference's own default — the private development line, which is
// where the promote route and this slot come from, collapses an absent
// rateLimiter to an empty middleware list (its admin.router.ts:577; the
// published v1.9.0 file has neither the slot nor the route, and that line
// number there is the login's 401 — see the core's
// admin-promote-route-comes-from-the-development-line) and ships no algorithm —
// so leaving it nil would be reproducing the reference. It is filled anyway,
// under the same house rule that fills HTTPConfig.RateLimiter: a product has to
// be safe with an empty configuration, and this is the one route on the console
// that changes *who is an administrator*. It runs before the guard, so a caller
// over budget is refused before a token is verified, a profile is read or a
// policy is evaluated; that is what makes the slot worth anything against an
// unauthenticated flood at the most privileged write in the deployment.
//
// ── why the auth router's limiter cannot serve it ────────────────────────────
//
// newRateLimiter matches "METHOD /prefix/path" against a table resolved under
// http.apiPrefix, and its subjects are read out of the bodies of the flows
// rateLimit.scope names. This route is under the admin mount, not the prefix,
// carries a path parameter the exact-match table cannot express, and has no
// account-shaped subject in its body — `{method}` names how to promote, not
// whom to count. So it gets its own tier over the same block: rateLimit.max and
// rateLimit.windowSeconds are the budget, rateLimit.enabled is the switch, and
// the shared counter is the same store, under a scope name of its own
// (adminPromoteScope) that no document can spell.
//
// ── the subject is the client address, under either keyBy ────────────────────
//
// rateLimit.keyBy chooses between an address and the account the request is
// *about*, and on the credential flows that account is in the body. Here the
// account the request is about is the path parameter — the person being
// promoted — and keying on it would hand an attacker a fresh budget per victim
// id, which is no limit. The caller's own identity is in a token the limiter
// runs before verifying, and a limiter that trusted an unverified token as a
// key would let the caller mint budgets. What remains is the address the event
// reported, which is what every body-less route under keyBy: email already
// falls back to (rateLimitSubject). The consequence is the one keyBy's own
// argument names: an office behind one NAT shares one budget of ten promotions
// a minute, which for this route is not a hardship.
//
// Nil when the block is off, which is the reference's behaviour exactly and
// the core's pass-through.
func newAdminPromoteLimiter(cfg *config.Config, counter rateLimitCounter, log *slog.Logger) func(http.Handler) http.Handler {
	if !cfg.RateLimit.Enabled {
		return nil
	}
	tier := newRateLimitTier(cfg.RateLimit.Max, time.Duration(cfg.RateLimit.WindowSeconds)*time.Second, counter, log)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tier.serve(w, r, adminPromoteScope, clientAddress(r), next)
		})
	}
}

// adminLoginScope is the counter scope of the console login's limiter, a
// sibling of adminPromoteScope for the same reason: a name the shared counter
// keys on that no document can spell.
const adminLoginScope = "admin-login"

// newAdminLoginLimiter puts the rateLimit block in front of POST <admin>/login,
// as a middleware over the mux rather than through any slot: the core has none
// for this route, on either line (core admin.go adminLogin, "No rate limiting
// of its own"), and its comment says what a host that wants one does — wraps
// the handler the adapter mounts. This is that wrap. It registers no pattern
// and matches one method on one path, so the adapter still owns the route.
//
// ── why the login is limited at all ──────────────────────────────────────────
//
// This file used to argue the opposite: that the bound on the route was the
// bcrypt cost of each guess, and that a limiter here would be the product
// wrapping a route it does not own. The first half was false. The route has
// three arms (admin.router.ts:552-573, core adminLogin), and only the first and
// third pay bcrypt: the second compares the presented password against
// admin.bootstrapSecret in constant time for the empty email or the literal
// "admin", and a hit mints an isRoot token that skips the store and the policy.
// The third arm pays bcrypt only for an email the store holds; an unknown one
// is refused at the cost of a lookup, which is also a timing oracle for which
// addresses exist. And the whole route is the one place in the deployment
// where POST <prefix>/login's limit could be side-stepped: the same
// email-and-password pair, guessed at against the same user store, on a route
// the default rateLimit.scope did not reach. The second half of the old
// argument stands and is answered by the shape: a middleware matching one
// route is not a route.
//
// ── what it shares with the auth login ───────────────────────────────────────
//
// The budget (rateLimit.max, rateLimit.windowSeconds), the switch
// (rateLimit.enabled), the counter, the refusal (writeRateLimited) and the
// subject rule: keyBy decides, exactly as it does for POST <prefix>/login —
// the body's normalised email under `email`, the client address under `ip`,
// and the address whenever the body names no subject, which is what the
// bootstrap-secret arm's empty email falls to. The scope is its own, so a
// caller who has spent the auth login's budget on an address has not spent
// this one; the alternative, sharing `login`'s scope, would let the console's
// login exhaust a user's budget on the auth router and the other way round,
// and the two routes are not one surface.
//
// Identity — not nil — when the block is off or the login routes are not
// mounted: assembleHandler always wraps, and a nil there would be a nil
// dereference rather than the reference's behaviour. The login routes exist
// only under a session policy (core AdminGuard.LoginRoutesMounted), which is
// what a non-nil AccessPolicy means here.
func newAdminLoginLimiter(cfg *config.Config, counter rateLimitCounter, log *slog.Logger) func(http.Handler) http.Handler {
	identity := func(next http.Handler) http.Handler { return next }
	hc := httpConfig(cfg)
	if !cfg.RateLimit.Enabled || !hc.AdminMounted() || hc.Admin.AccessPolicy == nil {
		return identity
	}
	tier := newRateLimitTier(cfg.RateLimit.Max, time.Duration(cfg.RateLimit.WindowSeconds)*time.Second, counter, log)
	login := hc.AdminPath() + auth.AdminLoginPath
	keyBy := cfg.RateLimit.KeyBy
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != login {
				next.ServeHTTP(w, r)
				return
			}
			tier.serve(w, r, adminLoginScope, rateLimitSubject(r, keyBy, subjectFromEmail), next)
		})
	}
}

// rateLimitRemaining is the time left in the current fixed window, used for the
// Retry-After of a locally-refused request. It is the same epoch-aligned
// arithmetic the other two tiers use.
func rateLimitRemaining(now time.Time, window time.Duration) time.Duration {
	secs := int64(window / time.Second)
	if secs < 1 {
		secs = 1
	}
	utc := now.UTC()
	end := time.Unix((utc.Unix()/secs+1)*secs, 0).UTC()
	return end.Sub(utc)
}

// rateLimitSubject names the thing being limited.
//
// With `keyBy: ip` it is always the client address and the body is never read,
// which is the cheap case. With `keyBy: email` the route's chain is walked in
// order and the first usable value wins; a route with no chain, a body that does
// not parse, and a chain that finds nothing all fall through to the address. "" is
// returned only when there is no address either, which a client cannot arrange.
//
// The body is read at most once and at most maxRateLimitBodyPeek bytes, and is
// handed back to the handler whole: what was read is put in front of what was
// not, so the route below sees the same bytes it would have seen. That is a real
// cost on a limited request — the limiter buffers up to 8 KiB before it can
// decide — and it is the price of keying on an account rather than an address.
// It is paid by refused requests too, which is unavoidable: the subject has to
// be known before the budget can be checked.
func rateLimitSubject(r *http.Request, keyBy string, sources []rateLimitSubjectSource) string {
	if keyBy != config.RateLimitKeyByEmail || len(sources) == 0 {
		return clientAddress(r)
	}

	body := peekRateLimitBody(r)
	if len(body) > 0 {
		// A map rather than a struct: the members wanted differ per route and
		// the reference's handlers read these bodies loosely too. Decoding
		// failure is not an error here — it is a body that names no subject, and
		// the address is the answer for those.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err == nil {
			for _, src := range sources {
				raw, present := fields[src.field]
				if !present {
					continue
				}
				var v string
				if err := json.Unmarshal(raw, &v); err != nil {
					// The member is present but is not a string. A client
					// sending {"email": {...}} is either broken or probing; in
					// both cases the next source, and finally the address, is
					// the right answer rather than a key built from a number.
					continue
				}
				if v = normalizeRateLimitSubject(v, src); v != "" {
					return v
				}
			}
		}
	}
	return clientAddress(r)
}

// normalizeRateLimitSubject applies the source's rule and bounds the result.
//
// The length cap is the store's own (internal/store/dynamodb
// maxRateLimitSubjectLen, 320 — RFC 5321's longest address). A value over it is
// refused *here*, by returning "" and moving on to the next source, rather than
// being truncated: two addresses sharing a 320-byte prefix would otherwise share
// a budget, which is a way for one account to spend another's.
func normalizeRateLimitSubject(v string, src rateLimitSubjectSource) string {
	if src.address {
		v = strings.ToLower(strings.TrimSpace(v))
	} else {
		v = strings.TrimSpace(v)
	}
	if v == "" {
		return ""
	}
	if src.hash {
		// Truncated to 128 bits, which is far past any collision worth
		// worrying about for a name that lives one window, and keeps the
		// partition key short.
		sum := sha256.Sum256([]byte(v))
		return hex.EncodeToString(sum[:16])
	}
	if len(v) > 320 || strings.ContainsAny(v, "\x00\n\r") {
		return ""
	}
	return v
}

// peekRateLimitBody reads up to maxRateLimitBodyPeek bytes and restores the
// request body so the handler below reads exactly what the client sent.
//
// The original ReadCloser is kept as the Closer: wrapping it in io.NopCloser
// would leak whatever the server closes at the end of the request.
func peekRateLimitBody(r *http.Request) []byte {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	peek, err := io.ReadAll(io.LimitReader(r.Body, maxRateLimitBodyPeek))
	if len(peek) == 0 {
		return nil
	}
	rest := r.Body
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(peek), rest), rest}
	if err != nil {
		// A body that failed mid-read is the handler's problem to report, not
		// the limiter's to pre-empt. What was read is still handed on, and the
		// limiter keys on the address instead of guessing from a fragment.
		return nil
	}
	return peek
}

// clientAddress is the host half of RemoteAddr, and it is deliberately **not**
// X-Forwarded-For.
//
// internal/lambdahttp sets RemoteAddr from the event's own requestContext source
// address — the peer as AWS observed it — and leaves X-Forwarded-For as the
// ordinary request header it is. That header is written by the client. Keying a
// rate limiter on it would let an attacker mint a fresh budget for every single
// request by changing one header value, which is not a weaker limiter but no
// limiter at all. A deployment behind a proxy of its own that needs the
// forwarded address is a change to the event layer, where the trust boundary
// lives and where it can be configured, not a header read here.
func clientAddress(r *http.Request) string {
	addr := strings.TrimSpace(r.RemoteAddr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// rateLimitOptions is the rate-limiting block's contribution to auth.New, and it
// is deliberately empty.
//
// D3 pre-reserved option slots in coreOptionSets for the blocks still to land,
// and this block fills none of them — for the same reason `docs` does not. The
// whole surface is auth.HTTPConfig.RateLimiter, which the adapter reads at mount
// time; there is no auth.Option for a limiter and inventing one to occupy a slot
// would be filling the slot rather than wiring the block. No slot moves and none
// is consumed, so the blocks after this one land exactly where they were
// promised.
//
// The function exists to say so somewhere the compiler can see, and to be the
// landing site if the core ever grows an option. It is referenced by
// TestRateLimitingAddsNoCoreOption.
func rateLimitOptions() []auth.Option { return nil }

// logRateLimitSurface announces what the block resolved to at cold start.
//
// An operator cannot see a limiter from outside without tripping it, which is
// the whole difficulty this block has with being observable, so the log is the
// only place the resolved shape is stated. It names the routes rather than the
// scope names, because a scope name is this product's vocabulary and a path is
// what the operator will see in an access log.
func logRateLimitSurface(cfg *config.Config, counter rateLimitCounter, log *slog.Logger) {
	if !cfg.RateLimit.Enabled {
		log.Info("rate limiting is off",
			slog.String("path", "rateLimit.enabled"),
			slog.String("effect", "every route answers as it would with no limiter, which is the reference's own default (rl = [], auth.router.ts:468)"))
		return
	}

	rl := resolveRateLimit(cfg)
	routes := make([]string, 0, len(rl.routes))
	for pattern := range rl.routes {
		routes = append(routes, pattern)
	}
	sort.Strings(routes)

	if len(routes) == 0 {
		log.Warn("rate limiting is on but its scope is empty",
			slog.String("path", "rateLimit.scope"),
			slog.String("effect", "no route is limited; the block is enabled and does nothing"),
			slog.String("remedy", "name endpoints in rateLimit.scope, or set rateLimit.enabled to false so the document says what the deployment does"))
		return
	}

	log.Info("rate limiting is on",
		slog.String("keyBy", cfg.RateLimit.KeyBy),
		slog.Int("max", cfg.RateLimit.Max),
		slog.Int("windowSeconds", cfg.RateLimit.WindowSeconds),
		slog.String("routes", strings.Join(routes, ", ")),
		slog.String("refusal", "429 with Retry-After and "+rateLimitBody),
		slog.String("window", "fixed: the budget resets on an epoch-aligned boundary, so the worst case over any sliding window of the same length is twice max"))

	if counter == nil {
		log.Warn("rate limiting has no shared counter and is bounded per execution environment",
			slog.String("path", "stores.driver"),
			slog.String("driver", cfg.Stores.Driver),
			slog.String("problem", "this driver provides no shared counter, so each execution environment holds its own budget and the effective ceiling is max multiplied by whatever concurrency AWS runs"),
			slog.String("remedy", "use the dynamodb driver for any deployment where the limit has to mean something; RS-12 already refuses this driver in production"))
	}
}
