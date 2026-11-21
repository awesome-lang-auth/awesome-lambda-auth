package dynamodb

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// The counter behind the built-in rate limiter (rate_limit.go, data-model.md
// §1.5 #61).
//
// These run against DynamoDB Local for the reason the whole package does: the
// only thing AllowRequest is, is a conditional write, and a hand-written fake
// would encode this author's belief about when DynamoDB refuses one. The
// concurrency test in particular is the whole design — a limiter whose
// comparison and increment are not one atomic expression is a limiter two
// Lambdas can both pass.

// TestAllowRequestEnforcesTheBudgetInOneWindow is the primary claim: max
// requests pass, the next does not, and the refusal does not advance the
// counter.
//
// The last assertion is not decoration. A refused request that still
// incremented would make n an attacker-controlled number, and any later feature
// that read it — a progressive delay, a lockout — would inherit that.
func TestAllowRequestEnforcesTheBudgetInOneWindow(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	const max = 3
	for i := 1; i <= max; i++ {
		allowed, retry, err := store.AllowRequest(ctx, "login", "a@example.com", max, time.Minute)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("request %d of a budget of %d was refused; the budget is spent before it is exhausted", i, max)
		}
		if retry <= 0 || retry > time.Minute {
			t.Errorf("request %d: remaining %s is outside (0, 60s]; it is the window's own tail", i, retry)
		}
	}

	allowed, retry, err := store.AllowRequest(ctx, "login", "a@example.com", max, time.Minute)
	if err != nil {
		t.Fatalf("over-budget request: %v", err)
	}
	if allowed {
		t.Fatalf("request %d of a budget of %d was allowed", max+1, max)
	}
	if retry <= 0 || retry > time.Minute {
		t.Errorf("refusal reports %s remaining, outside (0, 60s]; Retry-After is built from this", retry)
	}

	// The refusal is an outcome and not an error, which is the distinction the
	// fail-open decision in cmd/auth turns on. Asserted here so a future change
	// that started returning an error for "over budget" fails in this package
	// rather than by turning every 429 into a 200 up there.
	if err != nil {
		t.Errorf("being over budget produced an error (%v); it is an outcome, and cmd/auth tells it apart from a store fault by exactly this", err)
	}

	index, _ := rateLimitWindow(time.Now().UTC(), time.Minute)
	it := rawItem(t, client, store.table, rateLimitPK("login", "a@example.com", index), skRateLimit)
	if got := getN(it, attrRateLimitCount); got != max {
		t.Errorf("counter is %d after %d allowed and one refused request, want %d: a refused request must not increment", got, max, max)
	}
}

// TestAllowRequestStampsTheItemAndSetsTTL pins the two §7 attributes every item
// in this table carries and the expiry that makes these counters garbage rather
// than an ever-growing table.
//
// The TTL must sit past the end of the window: an item reaped while its window
// is live would hand its subject a fresh budget, which is the one thing a
// counter must not do.
func TestAllowRequestStampsTheItemAndSetsTTL(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	now := time.Date(2026, 3, 1, 12, 30, 30, 0, time.UTC)
	store.now = func() time.Time { return now }

	if _, _, err := store.AllowRequest(ctx, "login", "a@example.com", 5, time.Minute); err != nil {
		t.Fatalf("allow: %v", err)
	}

	index, ends := rateLimitWindow(now, time.Minute)
	it := rawItem(t, client, store.table, rateLimitPK("login", "a@example.com", index), skRateLimit)
	if got := getS(it, attrType); got != typeRateLimit {
		t.Errorf("_t = %q, want %q: a migration sweep finds these by type, not by key prefix", got, typeRateLimit)
	}
	if got := getN(it, attrVer); got != schemaVersion {
		t.Errorf("_v = %d, want %d", got, schemaVersion)
	}
	ttl := getN(it, attrTTL)
	if ttl < ends.Unix() {
		t.Errorf("ttl %d is before the window ends at %d; the counter could be reaped while it is still the live one", ttl, ends.Unix())
	}
	if want := ends.Add(rateLimitTTLGrace).Unix(); ttl != want {
		t.Errorf("ttl = %d, want %d (window end plus the clock-skew grace)", ttl, want)
	}
}

// TestAllowRequestStartsFreshInTheNextWindow is the fixed window itself: the
// window index is inside the partition key, so the next window is a different
// item and needs no reset.
//
// It also pins the boundary burst the design accepts — the budget is available
// again the instant the window rolls, so the worst case over a sliding minute is
// 2×max. That is documented in rate_limit.go and in docs/config-reference.md,
// and a test that pretended otherwise would be the place the documentation and
// the behaviour first disagreed.
func TestAllowRequestStartsFreshInTheNextWindow(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	now := time.Date(2026, 3, 1, 12, 30, 59, 0, time.UTC)
	store.now = func() time.Time { return now }

	const max = 2
	for i := 0; i < max; i++ {
		if allowed, _, err := store.AllowRequest(ctx, "login", "a@example.com", max, time.Minute); err != nil || !allowed {
			t.Fatalf("priming request %d: allowed=%v err=%v", i, allowed, err)
		}
	}
	if allowed, _, err := store.AllowRequest(ctx, "login", "a@example.com", max, time.Minute); err != nil || allowed {
		t.Fatalf("budget not exhausted at the end of the window: allowed=%v err=%v", allowed, err)
	}

	// One second later is the next minute, and therefore the next key.
	now = now.Add(time.Second)
	for i := 0; i < max; i++ {
		allowed, _, err := store.AllowRequest(ctx, "login", "a@example.com", max, time.Minute)
		if err != nil {
			t.Fatalf("next window, request %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("next window, request %d was refused; a fixed window starts at zero because it starts at a key nothing has written", i)
		}
	}
}

// TestResetRateLimitClearsOnlyThatCounter: a reset puts (scope, subject) back
// at zero for the current window — a spent budget is whole again — and touches
// no other subject's counter and no other scope's. Resetting a counter nothing
// has written is not an error. cmd/auth's per-account cap on failed
// second-factor checks is the caller (secondfactor_cap.go).
func TestResetRateLimitClearsOnlyThatCounter(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	const max = 2
	spend := func(scope, subject string) {
		t.Helper()
		for i := 0; i < max; i++ {
			if allowed, _, err := store.AllowRequest(ctx, scope, subject, max, time.Hour); err != nil || !allowed {
				t.Fatalf("priming %s/%s request %d: allowed=%v err=%v", scope, subject, i, allowed, err)
			}
		}
		if allowed, _, err := store.AllowRequest(ctx, scope, subject, max, time.Hour); err != nil || allowed {
			t.Fatalf("%s/%s not exhausted: allowed=%v err=%v", scope, subject, allowed, err)
		}
	}
	spend("2fa-account", "acct-a")
	spend("2fa-account", "acct-b")
	spend("login", "acct-a")

	if err := store.ResetRateLimit(ctx, "2fa-account", "acct-a", time.Hour); err != nil {
		t.Fatalf("reset: %v", err)
	}
	for i := 0; i < max; i++ {
		if allowed, _, err := store.AllowRequest(ctx, "2fa-account", "acct-a", max, time.Hour); err != nil || !allowed {
			t.Fatalf("after the reset, request %d: allowed=%v err=%v; the budget is whole again", i, allowed, err)
		}
	}
	if allowed, _, err := store.AllowRequest(ctx, "2fa-account", "acct-b", max, time.Hour); err != nil || allowed {
		t.Errorf("another subject's counter was cleared: allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := store.AllowRequest(ctx, "login", "acct-a", max, time.Hour); err != nil || allowed {
		t.Errorf("the same subject's counter in another scope was cleared: allowed=%v err=%v", allowed, err)
	}
	if err := store.ResetRateLimit(ctx, "2fa-account", "never-counted", time.Hour); err != nil {
		t.Errorf("resetting a counter nothing wrote: %v", err)
	}
	if err := store.ResetRateLimit(ctx, "2fa-account", "", time.Hour); err == nil {
		t.Error("an empty subject was accepted")
	}
}

// TestAllowRequestKeepsScopesAndSubjectsApart: the budget is per (scope,
// subject, window), so neither a second scope nor a second subject may spend the
// first one's.
//
// The scope half matters more than it looks. Every scope shares one middle
// segment of one key space, so a bug that dropped the scope from the key would
// make all of them one bucket — every configured endpoint sharing one budget per
// subject — and nothing about a single-scope deployment would reveal it.
func TestAllowRequestKeepsScopesAndSubjectsApart(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	if allowed, _, err := store.AllowRequest(ctx, "login", "a@example.com", 1, time.Minute); err != nil || !allowed {
		t.Fatalf("priming: allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := store.AllowRequest(ctx, "login", "a@example.com", 1, time.Minute); err != nil || allowed {
		t.Fatalf("the primed subject is not exhausted: allowed=%v err=%v", allowed, err)
	}

	for _, tc := range []struct{ scope, subject, why string }{
		{"forgot-password", "a@example.com", "a second scope for the same subject"},
		{"login", "b@example.com", "a second subject in the same scope"},
	} {
		allowed, _, err := store.AllowRequest(ctx, tc.scope, tc.subject, 1, time.Minute)
		if err != nil {
			t.Fatalf("%s: %v", tc.why, err)
		}
		if !allowed {
			t.Errorf("%s was refused; it shares a budget it must not share", tc.why)
		}
	}
}

// TestAllowRequestIsAtomicUnderConcurrency is the reason this store exists
// rather than a read-then-write over a counter.
//
// Twenty concurrent callers against a budget of five: exactly five may pass. A
// limiter that read the counter and then wrote it would let every caller that
// observed 4 write 5, and the interesting case — many Lambdas racing on the last
// unit of an attacker's budget — is precisely this one.
func TestAllowRequestIsAtomicUnderConcurrency(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	const (
		callers = 20
		max     = 5
	)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		granted int
	)
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _, err := store.AllowRequest(ctx, "login", "race@example.com", max, time.Minute)
			if err != nil {
				errs <- err
				return
			}
			if allowed {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent AllowRequest: %v", err)
	}
	if granted != max {
		t.Errorf("%d of %d concurrent callers passed a budget of %d; the comparison and the increment are not one atomic expression", granted, callers, max)
	}
}

// TestAllowRequestRefusesAnUnusableSubjectOrScope: the subject is the one key
// segment an attacker chooses, by putting whatever they like in a request body,
// so every bound on it is load-bearing.
//
// All of these are errors and not refusals, which is deliberate: cmd/auth
// answers them by falling back to the client address, a subject it always has
// and never takes from the body, and it can only do that if it can tell them
// from a genuine over-budget answer.
func TestAllowRequestRefusesAnUnusableSubjectOrScope(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		scope   string
		subject string
	}{
		{"empty subject", "login", ""},
		{"subject over the length cap", "login", strings.Repeat("a", maxRateLimitSubjectLen+1)},
		{"subject with a newline", "login", "a@example.com\nb@example.com"},
		{"subject with a NUL", "login", "a@example.com\x00"},
		{"scope with a separator", "log#in", "a@example.com"},
		{"empty scope", "", "a@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowed, _, err := store.AllowRequest(ctx, tc.scope, tc.subject, 5, time.Minute)
			if err == nil {
				t.Fatalf("accepted: a key built from this is either ambiguous or unbounded")
			}
			if allowed {
				t.Errorf("allowed=true alongside an error; a caller that ignored the error would run unlimited")
			}
		})
	}

	// A non-positive budget or window is a caller bug, not a configuration the
	// operator can reach — validate.go refuses both — and it must not silently
	// become "allow everything".
	for _, tc := range []struct {
		name   string
		max    int
		window time.Duration
	}{
		{"zero max", 0, time.Minute},
		{"negative max", -1, time.Minute},
		{"zero window", 5, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if allowed, _, err := store.AllowRequest(ctx, "login", "a@example.com", tc.max, tc.window); err == nil || allowed {
				t.Errorf("allowed=%v err=%v, want a refusal with an error", allowed, err)
			}
		})
	}
}

// TestRateLimitWindowIsEpochAligned needs no deployment: it pins the arithmetic
// the in-process pre-filter in cmd/auth duplicates.
//
// Alignment to the epoch rather than to a subject's first request is what makes
// that duplication sound. Both tiers divide the same wall clock by the same
// length, so they always name the same window, and a local refusal is therefore
// always one the shared counter would also have made. A per-subject alignment
// would make the local tier able to refuse a request the shared counter would
// have allowed, which is a false positive on the login path.
func TestRateLimitWindowIsEpochAligned(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		now       time.Time
		window    time.Duration
		wantIndex int64
		wantEnds  time.Time
	}{
		{
			name:      "the first instant of a minute",
			now:       time.Unix(1_800_000_060, 0).UTC(),
			window:    time.Minute,
			wantIndex: 30_000_001,
			wantEnds:  time.Unix(1_800_000_120, 0).UTC(),
		},
		{
			name:      "the last instant of the same minute",
			now:       time.Unix(1_800_000_119, 999_999_999).UTC(),
			window:    time.Minute,
			wantIndex: 30_000_001,
			wantEnds:  time.Unix(1_800_000_120, 0).UTC(),
		},
		{
			name:      "a sub-second window floors to one second",
			now:       time.Unix(1_800_000_060, 0).UTC(),
			window:    time.Millisecond,
			wantIndex: 1_800_000_060,
			wantEnds:  time.Unix(1_800_000_061, 0).UTC(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index, ends := rateLimitWindow(tc.now, tc.window)
			if index != tc.wantIndex {
				t.Errorf("index = %d, want %d", index, tc.wantIndex)
			}
			if !ends.Equal(tc.wantEnds) {
				t.Errorf("ends = %s, want %s", ends, tc.wantEnds)
			}
		})
	}

	// Two instants either side of one boundary must name different windows, and
	// the same instant must always name the same one however often it is asked.
	a, _ := rateLimitWindow(time.Unix(1_800_000_119, 0).UTC(), time.Minute)
	b, _ := rateLimitWindow(time.Unix(1_800_000_120, 0).UTC(), time.Minute)
	if a == b {
		t.Errorf("the instants either side of a window boundary share window %d; the boundary is where the budget resets", a)
	}
}

// TestRateLimitPKIsUnambiguous pins the property that lets the subject sit in a
// middle segment without being '#'-free: the window index is the trailing
// segment and is always decimal, so no (subject, window) pair can be made to
// build another pair's key.
func TestRateLimitPKIsUnambiguous(t *testing.T) {
	t.Parallel()

	seen := map[string]string{}
	for _, tc := range []struct {
		subject string
		window  int64
	}{
		{"a@example.com", 1},
		{"a@example.com", 12},
		{"a#5", 123},
		{"a", 5},
		{"a#5#123", 1},
		{"", 1},
	} {
		pk := rateLimitPK("login", tc.subject, tc.window)
		if prev, dup := seen[pk]; dup {
			t.Errorf("%q and (%q, %d) build the same key %q; one subject can spend another's budget",
				prev, tc.subject, tc.window, pk)
		}
		seen[pk] = tc.subject
	}
}
