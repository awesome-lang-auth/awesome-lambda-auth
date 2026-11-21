package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The per-account cap on failed second-factor checks: twoFactor.lockout.
//
// ── why the rate limiter is not enough ───────────────────────────────────────
//
// rateLimit counts per subject per scope, and the subject of POST
// <prefix>/2fa/verify is the challenge — sha256 of its tempToken, which is what
// the handler acts on (ratelimit.go, subjectOfTwoFactorVerify). That bounds the
// guesses at one challenge. It does not bound the guesses at an account: every
// login mints a fresh tempToken and with it a fresh budget, so a caller who
// holds the password — or, under twoFactor.required with a mailer, only the
// mailbox, through the password reset — gets about login.max × (tempToken
// lifetime / window) × max codes a window, a sweep of the six-digit code in
// hours. This file is the bound per account: a code checked for an account
// counts against that account whichever challenge, login or address it came
// through.
//
// ── the subject is a verified token's, never a claim ─────────────────────────
//
// The account is read from the token only after its signature, its type and its
// lifetime have been verified, by the core's own verifiers — StepUpSubject for
// a step-up tempToken, TOTPEnrolmentCaller for a forced enrolment — the calls
// the handlers make. A token that does not verify names no account here and is
// passed to the handler uncounted, which refuses it. That is the whole defence
// against using the cap as a lockout weapon: a caller can spend an account's
// budget only with a token the deployment minted for that account, which takes
// its first factor.
//
// ── reserve, then settle ─────────────────────────────────────────────────────
//
// The count is taken BEFORE the check runs, with the shared counter's own
// conditional increment (AllowRequest), and cleared when the check succeeds
// (ResetRateLimit). Counting after a refusal instead would let any number of
// concurrent requests all read "under the cap" before the first of them was
// counted, and on Lambda concurrency is what an attacker buys. So the number
// stored is "checks since the last success in this window", in-flight ones
// included, and at most max of them are ever evaluated per account per window
// however many arrive at once. Every answer that is not a 2xx keeps its count —
// a wrong code, and also a request that never reached the code (a malformed
// body, a CSRF refusal): only a holder of a valid token for the account can send
// one, and counting it costs that account nothing it could not spend anyway.
//
// It does not go through rateLimitTier, and must not: that tier's in-process
// pre-filter is sound only while a window's count never goes down (ratelimit.go
// file header), and a reset in one execution environment would leave another's
// pre-filter refusing an account the shared counter has cleared. On DynamoDB
// the shared counter is asked on every check (one conditional write, and one
// delete on success); on the memory driver an in-process counter with the same
// semantics stands in, which is per execution environment exactly as the
// rate limiter's local tier is there (RS-12 keeps that driver out of
// production).
//
// ── where it sits ────────────────────────────────────────────────────────────
//
// In the adapter's RateLimiter slot, inside the rate limiter: newRateLimiter
// first, so a request the per-challenge or per-address budget refuses never
// reaches this file and spends nothing here; then this; then the CSRF layer and
// the handler. The slot is applied to every auth route, so it is filled even
// when rateLimit is off or its scope is empty (chainLimiters). The limiter's
// 429 is the refusal — the same body, headers and Retry-After — because a
// client must not need a second parser for a second budget.
//
// The routes, each counted only on the branch where it checks a second factor
// for a challenge:
//
//   - POST <prefix>/2fa/verify — always: a tempToken and a TOTP code;
//   - POST <prefix>/magic-link/verify and /sms/verify in mode "2fa" — the
//     emailed link and the texted code as the second step (under
//     twoFactor.required secondFactorGate refuses them before they get here);
//   - POST <prefix>/2fa/verify-setup with an enrolment token, under
//     twoFactor.enrolOnLogin — the forced enrolment, which opens a session.
//     A guess there buys nothing, since the token's holder is handed the
//     secret by /2fa/setup, but it is the same account checking a code and
//     it shares the count. A voluntary enrolment (an access token) is a
//     signed-in user and is not counted.

// secondFactorAccountScope is the counter scope of the cap: a name the shared
// counter keys on that no rateLimit.scope entry can spell, as adminLoginScope is.
const secondFactorAccountScope = "2fa-account"

// secondFactorCounter is the shared counter as the cap uses it: the rate
// limiter's conditional increment, and a reset of the current window. The
// DynamoDB store asserts the same shape in its rate_limit.go; the migrating
// wrapper embeds that store and so has it too.
type secondFactorCounter interface {
	AllowRequest(ctx context.Context, scope, subject string, max int, window time.Duration) (bool, time.Duration, error)
	ResetRateLimit(ctx context.Context, scope, subject string, window time.Duration) error
}

// secondFactorCheck names how a watched route checks a second factor, and
// therefore where its account is read from.
type secondFactorCheck int

const (
	// stepUpCheck: the body's tempToken, always (POST /2fa/verify).
	stepUpCheck secondFactorCheck = iota + 1
	// stepUpInTwoFactorMode: the body's tempToken when mode is "2fa"; the
	// login branch checks no second factor and is not counted.
	stepUpInTwoFactorMode
	// forcedEnrolmentCheck: the enrolment token of a forced enrolment.
	forcedEnrolmentCheck
)

type secondFactorCap struct {
	max     int
	window  time.Duration
	counter secondFactorCounter
	core    *auth.Auth
	routes  map[string]secondFactorCheck
	log     *slog.Logger

	degradedOnce sync.Once
	resetOnce    sync.Once
}

// newSecondFactorCap returns the cap's middleware, or nil when
// twoFactor.lockout.maxFailures is 0. store is the user store the driver
// returned: its shared counter is found structurally, and without one the cap
// counts in process.
func newSecondFactorCap(cfg *config.Config, store any, core *auth.Auth, log *slog.Logger) func(http.Handler) http.Handler {
	lockout := cfg.TwoFactor.Lockout
	if lockout.MaxFailures <= 0 || core == nil {
		return nil
	}
	counter, ok := store.(secondFactorCounter)
	if !ok {
		counter = newLocalAccountCounter(nil)
	}
	prefix := httpConfig(cfg).Prefix()
	c := &secondFactorCap{
		max:     lockout.MaxFailures,
		window:  time.Duration(lockout.WindowSeconds) * time.Second,
		counter: counter,
		core:    core,
		routes: map[string]secondFactorCheck{
			http.MethodPost + " " + prefix + "/2fa/verify":        stepUpCheck,
			http.MethodPost + " " + prefix + "/magic-link/verify": stepUpInTwoFactorMode,
			http.MethodPost + " " + prefix + "/sms/verify":        stepUpInTwoFactorMode,
			http.MethodPost + " " + prefix + "/2fa/verify-setup":  forcedEnrolmentCheck,
		},
		log: log,
	}
	return c.middleware
}

// chainLimiters composes the auth router's two slot occupants, outer first,
// either of which may be nil (off).
func chainLimiters(outer, inner func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	switch {
	case outer == nil:
		return inner
	case inner == nil:
		return outer
	}
	return func(next http.Handler) http.Handler { return outer(inner(next)) }
}

func (c *secondFactorCap) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		check, watched := c.routes[r.Method+" "+r.URL.Path]
		if !watched {
			next.ServeHTTP(w, r)
			return
		}
		subject := c.account(r, check)
		if subject == "" {
			// No verified account: a token that does not verify, a branch that
			// checks no second factor, or a voluntary enrolment. The handler
			// answers it as it always has.
			next.ServeHTTP(w, r)
			return
		}
		allowed, retryAfter, err := c.counter.AllowRequest(r.Context(), secondFactorAccountScope, subject, c.max, c.window)
		if err != nil {
			// Fail open, for the rate limiter's reason (ratelimit.go file
			// header): the counter is in the table the check itself reads, so
			// a check refused here would have failed behind it anyway.
			c.degradedOnce.Do(func() {
				c.log.Warn("the second-factor lockout cannot reach its shared counter and is failing open",
					slog.String("path", "twoFactor.lockout"),
					slog.String("error", err.Error()),
					slog.String("effect", "second-factor checks are not counted per account while this lasts; the rateLimit budgets in front of them still apply"))
			})
			next.ServeHTTP(w, r)
			return
		}
		if !allowed {
			writeRateLimited(w, retryAfter)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status < 200 || sw.status > 299 {
			return
		}
		// A check went through: the count starts again. Detached from the
		// request's cancellation, since the response is already written and
		// the reset must not be lost to a client that hung up.
		if err := c.counter.ResetRateLimit(context.WithoutCancel(r.Context()), secondFactorAccountScope, subject, c.window); err != nil {
			c.resetOnce.Do(func() {
				c.log.Warn("the second-factor lockout could not clear an account's count after a successful check",
					slog.String("path", "twoFactor.lockout"),
					slog.String("error", err.Error()),
					slog.String("effect", "the account keeps the failed checks it made before this success until the window ends"))
			})
		}
	})
}

// account names the account a watched request checks a second factor for, or
// "" when it names none that verifies.
func (c *secondFactorCap) account(r *http.Request, check secondFactorCheck) string {
	switch check {
	case stepUpCheck, stepUpInTwoFactorMode:
		// The handler's own decode, into the handler's own member names
		// (ratelimit.go readRateLimitFields), so the token and the mode read
		// here are the ones the handler reads.
		f := readRateLimitFields(r)
		if check == stepUpInTwoFactorMode && !auth.TwoFactorMode(f.Mode) {
			return ""
		}
		subject, _, ok := c.core.StepUpSubject(f.TempToken, auth.HTTPError{}, auth.HTTPError{})
		if !ok {
			return ""
		}
		return accountSubject(subject.TenantID, subject.UserID)
	case forcedEnrolmentCheck:
		if !c.core.EnrolOnLogin() {
			return ""
		}
		var req auth.TOTPEnrolmentRequest
		peekJSONBody(r, &req)
		// The handler's precedence decides voluntary or forced
		// (auth.Auth.TOTPEnrolmentCaller); asked only when an enrolment token
		// could be present at all — the body's tempToken, or a bearer
		// credential — so a cookie-authenticated voluntary enrolment costs
		// nothing here.
		if req.TempToken == "" && auth.BearerToken(r.Header.Get("Authorization")) == "" {
			return ""
		}
		caller, _, ok := c.core.TOTPEnrolmentCaller(r.Context(), r, req.TempToken)
		if !ok || !caller.Forced {
			return ""
		}
		return accountSubject(caller.User.TenantID, caller.User.ID)
	}
	return ""
}

// accountSubject is the counter subject of one account: a truncated sha256 of
// its tenant and id. Hashed rather than written out because the two are joined
// by a separator neither is barred from containing, and the shared counter
// refuses a NUL; 128 bits keep two accounts apart for any purpose a one-window
// counter has.
func accountSubject(tenantID, userID string) string {
	if strings.TrimSpace(userID) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("awesome-lambda-auth/2fa-account/v1\x00" + tenantID + "\x00" + userID))
	return hex.EncodeToString(sum[:16])
}

// peekJSONBody decodes the body's first JSON value into dst the way the core's
// handlers do (one json.Decoder, one Decode; core DecodeOptionalJSONBody) and
// puts every byte back for the handler, as readRateLimitFields does. The error
// is dropped: a body that does not decode names no account, and the handler
// reports it.
func peekJSONBody(r *http.Request, dst any) {
	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	rest := r.Body
	var seen bytes.Buffer
	_ = json.NewDecoder(io.TeeReader(rest, &seen)).Decode(dst)
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(&seen, rest), rest}
}

// localAccountCounter is the cap's counter on a driver with no shared one: the
// same fixed, epoch-aligned window and the same conditional increment as the
// DynamoDB store's AllowRequest, plus the reset, in one execution environment.
type localAccountCounter struct {
	mu     sync.Mutex
	index  int64
	counts map[string]int
	now    func() time.Time
}

// maxLocalAccounts bounds the table. Its keys are verified accounts, not
// anything a caller can mint, so it is reached only by that many accounts
// failing a check in one window; past it an account is not tracked and is
// allowed, the direction every other tier here fails in.
const maxLocalAccounts = 100_000

func newLocalAccountCounter(now func() time.Time) *localAccountCounter {
	if now == nil {
		now = time.Now
	}
	return &localAccountCounter{counts: map[string]int{}, now: now}
}

func (l *localAccountCounter) roll(window time.Duration) {
	secs := int64(window / time.Second)
	if secs < 1 {
		secs = 1
	}
	if index := l.now().UTC().Unix() / secs; index != l.index {
		l.index = index
		l.counts = map[string]int{}
	}
}

func (l *localAccountCounter) AllowRequest(_ context.Context, scope, subject string, max int, window time.Duration) (bool, time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(window)
	remaining := rateLimitRemaining(l.now(), window)
	k := scope + "\x00" + subject
	n, tracked := l.counts[k]
	if !tracked && len(l.counts) >= maxLocalAccounts {
		return true, remaining, nil
	}
	if n >= max {
		return false, remaining, nil
	}
	l.counts[k] = n + 1
	return true, remaining, nil
}

func (l *localAccountCounter) ResetRateLimit(_ context.Context, scope, subject string, window time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll(window)
	delete(l.counts, scope+"\x00"+subject)
	return nil
}

// logSecondFactorCapSurface announces the cap at cold start.
func logSecondFactorCapSurface(cfg *config.Config, store any, log *slog.Logger) {
	lockout := cfg.TwoFactor.Lockout
	if lockout.MaxFailures <= 0 {
		log.Warn("failed second-factor checks are not capped per account",
			slog.String("path", "twoFactor.lockout.maxFailures"),
			slog.String("effect", "the rateLimit budgets bound the codes checked per challenge and per address only; every login mints a new challenge and a new budget"),
			slog.String("remedy", "set twoFactor.lockout.maxFailures above 0 (default 10)"))
		return
	}
	counter := "shared (the store's rate-limit counter)"
	if _, ok := store.(secondFactorCounter); !ok {
		counter = "in process: per execution environment, as on every driver without a shared counter"
	}
	log.Info("failed second-factor checks are capped per account",
		slog.Int("maxFailures", lockout.MaxFailures),
		slog.Int("windowSeconds", lockout.WindowSeconds),
		slog.String("routes", "POST /2fa/verify; /magic-link/verify and /sms/verify in mode 2fa; /2fa/verify-setup with an enrolment token"),
		slog.String("counter", counter),
		slog.String("refusal", "429 with Retry-After and "+rateLimitBody+" until the window ends; a successful check clears the count"))
}
