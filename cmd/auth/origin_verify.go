package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// Origin verification: only the front door may call the origin
// (http.originVerify, docs/config-reference.md §19).
//
// ── why ──────────────────────────────────────────────────────────────────────
//
// Both functions are reached through hosts nobody can make private from
// inside the stack: the auth function through its execute-api URL, the SSE
// function through a Function URL with AuthType NONE. Whatever a deployment
// puts in front of them — a CloudFront distribution, a WAF rate rule, an edge
// allow-list that routes only the auth routes one realm uses and blocks
// POST <prefix>/register — is advice as long as the origin answers anyone who
// calls it by its own name. The front door therefore adds a header holding a
// shared secret to every request it forwards (a CloudFront origin custom
// header), and with http.originVerify.secretArn set, a request that does not
// carry it never reaches anything in this binary.
//
// ── where the check sits ─────────────────────────────────────────────────────
//
// Outermost, on both functions (app.go, New). Before the event-context
// carrier, the correlation scope and the access log, so a refused request
// costs one invocation and writes no line — the reasoning streamOnly gives for
// the SSE function's path gate, which this check sits outside of, so the
// Function URL is held to it as the execute-api URL is. Before the CORS layer,
// so a preflight is refused like any other request: an OPTIONS a browser sends
// on its own is still a request that did not come through the front door, and
// answering it would put the allow-list's headers on the back one. Before the
// rate limiters, which spend the shared DynamoDB counter. And before every
// route, GET /healthz included unless http.originVerify.exemptHealthz says
// otherwise.
//
// ── what a refusal is ────────────────────────────────────────────────────────
//
// A bare 403: no body, no Content-Type, no Vary, no CORS header, no cookie,
// and the same answer whether the header was missing, repeated or wrong, so
// the response says nothing about which. It is a status the reference never
// sends for a request it would have served, which is the registered deviation
// origin-verify-refusal-is-a-bare-403; a client that comes through the front
// door never sees it.
//
// ── the comparison ───────────────────────────────────────────────────────────
//
// Exactly one value, trimmed of the optional whitespace HTTP allows around
// it. Two values are refused rather than either being tried, because API
// Gateway and a Function URL join repeated headers into one comma-separated
// string and a value that arrived beside another is not one the front door
// set alone. The value is compared as a SHA-256 digest with
// subtle.ConstantTimeCompare against the digest of the secret's AWSCURRENT
// value and of its AWSPREVIOUS value, both comparisons always made: the
// digests are of equal length whatever was sent, so neither the time taken nor
// an early exit tells a caller how much of a guess was right. Plaintext
// secrets are not kept past the read that produced them.
//
// ── rotation ─────────────────────────────────────────────────────────────────
//
// AWSPREVIOUS is accepted beside AWSCURRENT so that a rotation needs no flag
// day: rotate the secret, and the value the front door is still sending is
// the previous one, accepted until the next rotation.
//
// That only holds if every execution environment learns the new value before
// the front door starts sending it, and an environment can stay warm for
// hours. So the two values are read at cold start — where a secret that
// cannot be read refuses the init, like every other cold-start failure here —
// and read again every originSecretRefreshInterval, by the first request that
// finds them stale. That is a deliberate exception to the rule main.go states
// ("everything expensive happens once, in New"): one GetSecretValue pair per
// environment per five minutes, never per request, bought because the
// alternative is a rotation procedure that has to recycle every environment
// before the edge moves. The operator's half is to wait one interval between
// rotating the secret and switching the front door (§19.3).
//
// A failed refresh keeps the values already held and tries again after
// originSecretRetryInterval. It never widens what is accepted: a secret the
// role can no longer read leaves the last values it read in force, and never
// none.
//
// ── after the check ──────────────────────────────────────────────────────────
//
// The header is removed from the request before anything else sees it, so no
// route, guard, script runner or log line downstream can read the front
// door's secret — and its name is on the logging deny-list (logging.go, and
// withRedactedKeys below for a name of the operator's choosing).

// originSecretRefreshInterval is how long a read of the secret is trusted
// before the next request re-reads it. Five minutes is the AWS Parameters and
// Secrets Lambda Extension's default TTL, and it is the wait §19.3 asks for
// between rotating the secret and switching the front door.
const originSecretRefreshInterval = 5 * time.Minute

// originSecretRetryInterval is how soon a failed refresh is tried again. Short
// enough that a throttle or a blip clears inside a minute, long enough that a
// role that lost its permission costs two reads a minute and not two per
// request.
const originSecretRetryInterval = 30 * time.Second

// originSecretMinLength is the floor on the secret's length, the one RS-1 sets
// for the signing secrets. The value is a password presented on every request
// to a public endpoint, and a short one is a guessable one.
const originSecretMinLength = 32

// OriginSecretReader reads the secret http.originVerify.secretArn names, under
// AWSCURRENT and AWSPREVIOUS. awsintegration.SecretStagesReader is the
// production implementation; Options.OriginSecret injects another.
type OriginSecretReader func(ctx context.Context, secretArn string) (awsintegration.SecretStages, error)

// originVerifier is one cold start's origin check: the header it reads, the
// digests it compares against and the refresh that keeps them current.
type originVerifier struct {
	header        string // canonical form
	exemptHealthz bool
	secretArn     string
	read          OriginSecretReader
	now           func() time.Time
	log           *slog.Logger

	// secrets is swapped whole, so the request path is one atomic load; a
	// refresh is serialised by refreshing, and a request that finds another
	// one in progress uses the values already held rather than waiting.
	secrets    atomic.Pointer[originSecrets]
	refreshing sync.Mutex
}

// originSecrets is one read of the secret, as digests.
type originSecrets struct {
	current     [sha256.Size]byte
	previous    [sha256.Size]byte
	hasPrevious bool
	// refreshAt is when the next request re-reads the secret.
	refreshAt time.Time
}

// newOriginVerifier builds the check when http.originVerify.secretArn is set,
// and returns nil — no check, no read, no cost — when it is not.
//
// The secret is read here, at cold start, and a current value that cannot be
// read or is not usable refuses the init: a deployment that would answer 403 to
// every request, the front door's included, is a failed deployment and not an
// outage to be discovered from the edge.
func newOriginVerifier(ctx context.Context, cfg *config.Config, read OriginSecretReader, log *slog.Logger) (*originVerifier, error) {
	return newOriginVerifierAt(ctx, cfg, read, log, time.Now)
}

// newOriginVerifierAt is newOriginVerifier on a clock of the caller's, which is
// how a test walks a rotation through the refresh interval without sleeping.
func newOriginVerifierAt(ctx context.Context, cfg *config.Config, read OriginSecretReader, log *slog.Logger, now func() time.Time) (*originVerifier, error) {
	ov := cfg.HTTP.OriginVerify
	if !ov.Enabled() {
		return nil, nil
	}
	if read == nil {
		read = awsintegration.NewSecretStagesReader(awsintegration.SecretStagesReaderOptions{}).Read
	}
	v := &originVerifier{
		header:        textproto.CanonicalMIMEHeaderKey(ov.Header),
		exemptHealthz: ov.ExemptHealthz,
		secretArn:     ov.SecretARN,
		read:          read,
		// The wall clock, with Go's monotonic reading stripped. The interval
		// is a promise about elapsed time — rotate, wait five minutes, switch
		// the front door — and a monotonic clock is not guaranteed to advance
		// while the platform freezes an idle execution environment between
		// invocations, which would stretch it into five minutes of running
		// time on exactly the environments that serve least.
		now: func() time.Time { return now().Round(0) },
		log: log,
	}
	secrets, previousProblem, err := v.load(ctx)
	if err != nil {
		return nil, fmt.Errorf("http.originVerify.secretArn: refusing to start, because every request would be refused: %w "+
			"-- check the ARN, the value stored under it and the execution role's secretsmanager:GetSecretValue on it", err)
	}
	v.secrets.Store(secrets)
	if previousProblem != "" {
		log.Warn("origin verification: the secret's previous value is not accepted",
			slog.String("path", "http.originVerify.secretArn"),
			slog.String("problem", previousProblem),
			slog.String("effect", "a front door still sending the value the last rotation replaced is refused 403 until it sends the current one"))
	}
	healthz := "refused like every other path without the header"
	if v.exemptHealthz {
		healthz = "answered without the header (http.originVerify.exemptHealthz)"
	}
	log.Info("origin verification on: a request without the front door's header is refused before any route",
		slog.String("path", "http.originVerify"),
		slog.String("header", v.header),
		slog.Bool("previousAccepted", secrets.hasPrevious),
		slog.String("healthz", healthz),
		slog.String("refreshInterval", originSecretRefreshInterval.String()),
		slog.String("refusal", "403 with no body, before CORS, the access log and every route"))
	return v, nil
}

// load reads the secret and turns it into digests. The error and the problem
// describe a value and never contain it.
func (v *originVerifier) load(ctx context.Context) (*originSecrets, string, error) {
	stages, err := v.read(ctx, v.secretArn)
	if err != nil {
		return nil, "", err
	}
	current, problem := originSecretValue(stages.Current)
	if problem != "" {
		return nil, "", fmt.Errorf("the value under %s %s", awsintegration.StageCurrent, problem)
	}
	s := &originSecrets{current: sha256.Sum256([]byte(current)), refreshAt: v.now().Add(originSecretRefreshInterval)}
	previousProblem := stages.PreviousProblem
	if stages.Previous != "" {
		previous, problem := originSecretValue(stages.Previous)
		if problem == "" {
			s.previous, s.hasPrevious = sha256.Sum256([]byte(previous)), true
		} else {
			previousProblem = "the value under " + awsintegration.StagePrevious + " " + problem
		}
	}
	return s, previousProblem, nil
}

// originSecretValue is the value a front door is configured with, out of what
// the secret stores: trimmed of surrounding whitespace — a trailing newline is
// what a secret written from a file usually carries, and no header value can
// hold one — and then held to the length floor and to visible ASCII, the only
// bytes every proxy carries through a header unchanged. It reports a problem
// in words and never echoes the value.
func originSecretValue(raw string) (string, string) {
	v := strings.TrimSpace(raw)
	if len(v) < originSecretMinLength {
		return "", fmt.Sprintf("is %d characters long once trimmed; at least %d are required", len(v), originSecretMinLength)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return "", "holds a character outside visible ASCII (0x21-0x7E), which a header value cannot carry reliably"
		}
	}
	return v, ""
}

// inForce returns the secrets in force, re-reading them first when they are
// due. Only one request re-reads at a time; any other uses what is held.
func (v *originVerifier) inForce(ctx context.Context) *originSecrets {
	held := v.secrets.Load()
	if v.now().Before(held.refreshAt) || !v.refreshing.TryLock() {
		return held
	}
	defer v.refreshing.Unlock()
	if held = v.secrets.Load(); v.now().Before(held.refreshAt) {
		return held
	}

	fresh, previousProblem, err := v.load(ctx)
	if err != nil {
		// The values already held stay in force: a failed read never widens
		// what is accepted and never empties it.
		kept := *held
		kept.refreshAt = v.now().Add(originSecretRetryInterval)
		v.secrets.Store(&kept)
		loggerFrom(ctx, v.log).Warn("origin verification: the secret could not be re-read; the values read before stay in force",
			slog.String("path", "http.originVerify.secretArn"),
			slog.String("error", err.Error()),
			slog.String("retryIn", originSecretRetryInterval.String()))
		return &kept
	}
	if previousProblem != "" {
		loggerFrom(ctx, v.log).Warn("origin verification: the secret's previous value is not accepted",
			slog.String("path", "http.originVerify.secretArn"),
			slog.String("problem", previousProblem))
	}
	v.secrets.Store(fresh)
	return fresh
}

// admits reports whether r carries exactly one value of the header that
// matches the secret's current or previous value.
func (v *originVerifier) admits(r *http.Request) (bool, string) {
	values := r.Header.Values(v.header)
	switch {
	case len(values) == 0:
		return false, "missing"
	case len(values) > 1:
		return false, "repeated"
	}
	presented := strings.Trim(values[0], " \t")
	if presented == "" {
		return false, "empty"
	}
	s := v.inForce(r.Context())
	sum := sha256.Sum256([]byte(presented))
	matchesCurrent := subtle.ConstantTimeCompare(sum[:], s.current[:])
	matchesPrevious := subtle.ConstantTimeCompare(sum[:], s.previous[:])
	if !s.hasPrevious {
		matchesPrevious = 0
	}
	if matchesCurrent|matchesPrevious != 1 {
		return false, "mismatch"
	}
	return true, ""
}

// exempt is the one request the check lets through without the header, and
// only when http.originVerify.exemptHealthz asks for it: the readiness probe,
// by the methods the mux serves it with. Any other method on the path is
// checked, and the mux's 405 stays behind the front door.
func (v *originVerifier) exempt(r *http.Request) bool {
	return v.exemptHealthz && r.URL.Path == "/healthz" &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead)
}

// gate is the middleware: outermost on both functions, identity when the
// check is off.
func (v *originVerifier) gate(next http.Handler) http.Handler {
	if v == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !v.exempt(r) {
			if ok, why := v.admits(r); !ok {
				// Debug only, and never the value: a refusal is the one
				// request this binary otherwise writes nothing about, which is
				// the point on a URL anybody can call, and the line is for an
				// operator wiring a front door with AWESOME_AUTH_LOG_LEVEL=debug.
				loggerFrom(r.Context(), v.log).Debug("origin verification refused a request",
					slog.String("reason", why),
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path))
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, v.strip(r))
	})
}

// strip removes the header from a copy of the request. A copy, because the
// request belongs to the caller — the event adapter builds a fresh one per
// invocation, but a host embedding App.Handler need not.
func (v *originVerifier) strip(r *http.Request) *http.Request {
	if _, present := r.Header[v.header]; !present {
		return r
	}
	clone := r.Clone(r.Context())
	clone.Header.Del(v.header)
	return clone
}

// withRedactedKeys puts names of the operator's choosing on the logging
// deny-list for one logger and everything derived from it. The static list
// (logging.go) carries the default header name; a deployment that renamed it
// gets its own name redacted the same way, by attribute key and
// case-insensitively, whatever handler the logger writes through.
func withRedactedKeys(log *slog.Logger, keys ...string) *slog.Logger {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" && !IsRedactedLogKey(k) {
			set[k] = struct{}{}
		}
	}
	if len(set) == 0 {
		return log
	}
	return slog.New(redactingHandler{next: log.Handler(), keys: set})
}

// redactingHandler replaces the value of every attribute whose key is in keys,
// in a record's own attributes, in those attached with With and inside groups.
type redactingHandler struct {
	next slog.Handler
	keys map[string]struct{}
}

func (h redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.redact(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = h.redact(a)
	}
	return redactingHandler{next: h.next.WithAttrs(redacted), keys: h.keys}
}

func (h redactingHandler) WithGroup(name string) slog.Handler {
	return redactingHandler{next: h.next.WithGroup(name), keys: h.keys}
}

func (h redactingHandler) redact(a slog.Attr) slog.Attr {
	if _, ok := h.keys[strings.ToLower(a.Key)]; ok {
		return slog.String(a.Key, RedactedValue)
	}
	if v := a.Value.Resolve(); v.Kind() == slog.KindGroup {
		group := v.Group()
		redacted := make([]slog.Attr, len(group))
		for i, g := range group {
			redacted[i] = h.redact(g)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(redacted...)}
	}
	return a
}
