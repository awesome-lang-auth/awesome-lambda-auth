package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	auth "github.com/nik2208/awesome-go-auth"
)

// RedactedValue replaces the value of any attribute whose key is on the
// redaction list. It is a constant string rather than "" so that a redacted
// field is visibly redacted in the log, instead of looking like a field the
// caller forgot to set.
const RedactedValue = "[REDACTED]"

// redactedKeys is the explicit deny-list of attribute keys whose values never
// reach stdout. CloudWatch is queryable by anyone with logs:FilterLogEvents,
// which is a far larger set of people than those who may hold a session, so a
// token in a log line is a credential leak with an audit trail attached.
//
// The list is deny-by-key rather than deny-by-value on purpose: a value-shaped
// heuristic ("looks like a JWT") cannot be tested and fails open on the first
// format that was not anticipated, whereas a key that is not on this list is a
// reviewable omission. Every name is matched case-insensitively, and both the
// camelCase wire spelling and the HTTP header spelling are listed where they
// differ, because an attribute may be built from either.
//
// The list grows with the surface. Five credential shapes were added with the
// observability block, and only two of them were missing — which is the point of
// writing down why each is here rather than adding names that look dangerous:
//
//   - `clientSecret` / `client_secret`: the OIDC client's password. The camelCase
//     spelling was already listed; `client_secret` is the snake_case form the
//     token endpoint actually receives, because /token is a form POST in
//     client_secret_post (idp.go, and the discovery document advertises no other
//     method). A key spelled the way the wire spells it is the one an attribute
//     built from the parsed form would carry.
//   - `privateKey`: already listed. idProvider.privateKey is the PEM alternative
//     to the KMS key — the one signing arrangement where this process holds a key
//     it could print (docs/oidc.md §2).
//   - `signature` / `x-webhook-signature`: the HMAC over a webhook body,
//     `X-Webhook-Signature: sha256=<hex>` (awesome-go-auth webhook_sender.go:64,
//     :376). It is not the credential being delivered, it is the proof of
//     authorship: an attacker holding a logged signature plus the body it signed
//     can replay that delivery against the receiver forever, because the receiver
//     verifies exactly those bytes.
//   - `code`: already listed, and it is now carrying more than it was. It is the
//     SMS one-time code AND the OIDC authorization code that /token exchanges for
//     an id_token — single-use, but "single" means "until the first use", and a
//     code in a log is readable before the client gets round to spending it.
//   - `tempToken`: the 2FA step-up handle. wire-contract.md §3 and
//     docs/spec/serverless-gap-analysis.md §1.2 record the reference caveat this
//     product inherited: the tempToken is a *full* access token — same secret,
//     same verifier — so for its five minutes it passes authMiddleware. Logging
//     one is logging a session.
var redactedKeys = []string{
	"accessToken",
	"access_token",
	"apiKey",
	"api_key",
	"authorization",
	"bearer",
	"bootstrapSecret",
	"clientSecret",
	"client_secret",
	"code",
	"cookie",
	"csrf",
	"csrfToken",
	"currentPassword",
	"jwt",
	"newPassword",
	"otp",
	"password",
	"passwordHash",
	"privateKey",
	"proxy-authorization",
	"refreshToken",
	"refresh_token",
	"secret",
	"session",
	"sessionToken",
	"set-cookie",
	"signature",
	"smsCode",
	"tempToken",
	"token",
	"tokenHash",
	"totp",
	"x-api-key",
	"x-csrf-token",
	"x-webhook-signature",
}

var redactedKeySet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(redactedKeys))
	for _, k := range redactedKeys {
		set[strings.ToLower(k)] = struct{}{}
	}
	return set
}()

// RedactedLogKeys returns the redaction list, sorted. Exported so a test can
// assert the list rather than the implementation, and so an operator can print
// what this build promises never to log.
func RedactedLogKeys() []string {
	out := make([]string, 0, len(redactedKeySet))
	for k := range redactedKeySet {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsRedactedLogKey reports whether an attribute key is redacted.
func IsRedactedLogKey(key string) bool {
	_, ok := redactedKeySet[strings.ToLower(key)]
	return ok
}

// newLogger returns the structured JSON logger the whole binary shares.
//
// Everything goes to stdout: CloudWatch captures both streams into the same log
// group, and splitting errors onto stderr only buys interleaving hazards.
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if IsRedactedLogKey(a.Key) {
				return slog.String(a.Key, RedactedValue)
			}
			return a
		},
	}))
}

// LogLevelEnv names the variable that sets the log level. It is an operational
// knob, not a configuration knob: it must keep working when the configuration
// document is the thing that is broken, so it is deliberately outside the
// AWESOME_AUTH_* schema's refuse-to-start machinery.
const LogLevelEnv = "AWESOME_AUTH_LOG_LEVEL"

// logLevel reads LogLevelEnv. An unrecognised value falls back to info rather
// than failing: losing the deployment because a log level was misspelt would be
// a worse outcome than logging one level louder than intended.
func logLevel(getenv func(string) (string, bool)) slog.Level {
	raw, _ := getenv(LogLevelEnv)
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type loggerKey struct{}

// withLogger attaches a request-scoped logger to a context.
func withLogger(ctx context.Context, log *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, log)
}

// loggerFrom returns the request-scoped logger, or fallback when the context
// carries none.
func loggerFrom(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if log, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && log != nil {
		return log
	}
	if fallback != nil {
		return fallback
	}
	return slog.Default()
}

// ── the correlation id ──────────────────────────────────────────────────────
//
// One caller-supplied handle, `X-Correlation-Id`, on every line this deployment
// writes about a request — so that a client's "my login failed at 14:02" can be
// resolved to the invocation that failed rather than to the sixty that did not.
//
// THIS BINARY DOES NOT READ THE HEADER. That is the whole design, and it is a
// change of mind forced by the core: awesome-go-auth v0.9.0 ships the carrier
// (event_context.go), every adapter installs it outermost, and the value it
// reads is published under every Event the core emits. A second parse here would
// produce a second answer to the same question, and the two would be identical
// right up until the day they were not — a host setting HTTPConfig.ClientIP, a
// change in the reference's array-first quirk for a repeated header
// (node-auth auth.router.ts:407-410, ported in EventContextFromRequest), a
// different notion of "absent". So:
//
//	auth.EventContextMiddleware(httpConfig(cfg))   installs it, outermost
//	correlationScope                               copies it onto the logger
//	correlatingTransport                           forwards it outbound
//
// and correlationIDOf below is the only place any of this gets a value from.
// The adapter installs the carrier a second time, further in, for the routes it
// owns; that install recomputes the same function of the same request with the
// same HTTPConfig, so the two cannot disagree by construction rather than by
// agreement. What the outer install adds is coverage: GET /healthz and anything
// else this binary mounts outside the adapter's guard chain.
//
// An absent header stays absent. The core does not mint an id when the caller
// sent none (event_context.go, EventContext.CorrelationID) because an invented
// id joins nothing to anything, and a consumer could not tell it from one the
// caller's gateway assigned — so a request with no header logs no
// correlationId attribute at all, and the absence is the honest answer.
//
// Nothing is echoed back to the caller either. An echo would hand the client a
// value the client just sent, which buys it nothing, and it would put an
// attacker-controlled string into a response header on a credential origin.

// CorrelationIDLogKey is the attribute name every correlated line carries. It is
// not on the redaction list: a correlation id is the one caller-supplied value
// here that is worth nothing to whoever reads the log and everything to whoever
// has to find the line.
const CorrelationIDLogKey = "correlationId"

// maxCorrelationIDBytes bounds what is logged and what is forwarded.
//
// The bound is a cost control, which is why it lives in this block and not in a
// validator. CloudWatch bills ~0.50 USD per GB ingested; API Gateway accepts a
// header of up to ~10 KB, and the access log writes one line per request. A
// caller that sends 10 KB of "correlation id" therefore buys ~5 USD per million
// requests of somebody else's log bill, and 128 bytes is longer than a UUID, an
// X-Ray trace id or a W3C traceparent — the three things a real one ever is.
const maxCorrelationIDBytes = 128

// correlationIDOf returns the correlation id the core's carrier installed, or ""
// when the context has no carrier (a background job, a cold-start line) or the
// request carried no header.
func correlationIDOf(ctx context.Context) string {
	ec, _ := auth.EventContextFromContext(ctx)
	return ec.CorrelationID
}

// loggableCorrelationID is what reaches slog: trimmed, and truncated on a rune
// boundary with an ellipsis so that a truncated id is visibly truncated instead
// of looking like a short one that does not match anything.
//
// Nothing else is stripped. The JSON handler escapes control characters, so a
// hostile value is a noisy log line and not an injected one, and mangling what
// arrived would make the log disagree with the events the core publishes — which
// is the one property this block exists to keep.
func loggableCorrelationID(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= maxCorrelationIDBytes {
		return raw
	}
	cut := maxCorrelationIDBytes
	for cut > 0 && !utf8.RuneStart(raw[cut]) {
		cut--
	}
	return raw[:cut] + "…"
}

// forwardableCorrelationID is the stricter filter for an outbound header, and it
// refuses rather than repairs.
//
// Two reasons it cannot be loggableCorrelationID. A header value outside
// 0x20..0x7E is rejected by net/http's own transport ("invalid header field
// value"), so forwarding one unchecked would turn a poisoned inbound header into
// a webhook this deployment can no longer deliver — a caller-triggered outage on
// a path that carries credentials. And repairing it would forward an id that
// matches nothing at either end, which is worse than forwarding none: the log
// still shows what actually arrived, so the mismatch stays diagnosable.
func forwardableCorrelationID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxCorrelationIDBytes {
		return ""
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] > 0x7e {
			return ""
		}
	}
	return raw
}

// correlationScope copies the carrier's id onto the request-scoped logger.
//
// Onto the logger and not into one log call: every later line — the access log,
// the adapter's OnError, anything a handler writes through loggerFrom — is then
// correlated without any of them knowing this exists. It must sit INSIDE
// auth.EventContextMiddleware (the carrier has to be installed before it is
// read) and OUTSIDE accessLog (whose line is one of the ones that wants it).
func correlationScope(fallback *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := loggableCorrelationID(correlationIDOf(r.Context()))
			if id == "" {
				next.ServeHTTP(w, r)
				return
			}
			log := loggerFrom(r.Context(), fallback).With(slog.String(CorrelationIDLogKey, id))
			next.ServeHTTP(w, r.WithContext(withLogger(r.Context(), log)))
		})
	}
}

// correlatingTransport puts the id on every outbound request this binary makes
// on a route's behalf — the delivery webhook, the claims webhook, the JWKS fetch
// of resource-server mode — so that the receiver's logs and this deployment's
// logs name the same request.
//
// It works because the core builds those with http.NewRequestWithContext from
// the request's own context (awesome-go-auth delivery_webhook.go:207,
// claims_webhook.go:162, resource_server.go:332), so the carrier is still
// reachable at the point the request is issued. A call made from a background
// context simply carries no header.
//
// An id the caller already set on the outbound request wins, because the only
// way one gets there is that something closer to the call site knew better.
type correlatingTransport struct{ next http.RoundTripper }

func (t correlatingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	if r.Header.Get(auth.CorrelationIDHeader) != "" {
		return next.RoundTrip(r)
	}
	id := forwardableCorrelationID(correlationIDOf(r.Context()))
	if id == "" {
		return next.RoundTrip(r)
	}
	// RoundTrip must not modify the request it is given; Clone is the documented
	// way to add a header, and it is shallow enough to be free here.
	clone := r.Clone(r.Context())
	clone.Header.Set(auth.CorrelationIDHeader, id)
	return next.RoundTrip(clone)
}

// correlatingClient wraps the outbound HTTP client in correlatingTransport,
// copying rather than mutating: Options.HTTPClient belongs to the caller, and a
// test that injects an httptest server's client hands over a value it goes on
// using itself.
//
// A nil client is http.DefaultClient wrapped, which is what every consumer of
// Options.HTTPClient already resolves nil to — so wrapping changes which
// transport runs and nothing about timeouts, redirects or TLS.
func correlatingClient(base *http.Client) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	dup := *base
	dup.Transport = correlatingTransport{next: dup.Transport}
	return &dup
}

// statusWriter records what the handler wrote so the access log can report it.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += n
	return n, err
}

// Flush keeps the wrapped writer's http.Flusher behaviour reachable. The event
// adapter's recorder implements it, and a wrapper that swallowed it would make
// a streaming response path silently unavailable to any handler added later.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the writer beneath for what this
// wrapper does not implement — in the SSE function (D9c), the write deadline
// the core's SseManager sets on every frame, which the streaming writer
// honours and which would otherwise stop here as "not supported".
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// accessLog emits one line per request.
//
// What is logged is the whole list: method, path, status, duration and response
// size. The query string is excluded because email-flow routes carry
// single-use tokens in it, headers are excluded because Cookie and
// Authorization live there, and the body is excluded because it carries
// passwords. Adding a field here means adding it to that argument.
//
// The correlation id is the exception that proves it: it is a header, it is on
// this line, and it is not in the argument list below. correlationScope puts it
// on the request-scoped logger instead, so it rides every line of the request
// rather than only this one — and the decision about whether a header may be
// logged at all stays in one place, next to the redaction list, instead of being
// re-taken here.
//
// The carrier holds two more fields, IP and User-Agent, and neither is logged.
// They are personal data with no incident they would settle that the correlation
// id does not: retention is 14 days by default (LogRetentionDays), and a field
// that would have to be justified to a data protection officer is a field worth
// not having. The core still publishes both under its events, where a consumer
// has opted in to them.
func accessLog(fallback *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		status := sw.status
		if status == 0 {
			// A handler that returned without writing produces a 200 with an
			// empty body once the recorder is rendered.
			status = http.StatusOK
		}
		loggerFrom(r.Context(), fallback).Info("http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Int64("durationMs", time.Since(start).Milliseconds()),
			slog.Int("responseBytes", sw.written),
		)
	})
}
