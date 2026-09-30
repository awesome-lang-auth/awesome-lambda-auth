package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	"github.com/nik2208/awesome-lambda-auth/internal/lambdahttp"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The SSE function (D9c): GET <tools>/stream on a Lambda Function URL with
// response streaming, fed by the event log.
//
// ── one composition, two entry points ────────────────────────────────────────
//
// The stream is served by the same composition as every other route: the same
// configuration document, the same secrets, the same stores, the same auth
// core, the same tools facade and the same guard the tools.auth posture
// selects. What differs is the runtime contract — a Function URL in
// RESPONSE_STREAM mode hands the handler an event and takes back a reader,
// where the auth function takes JSON and returns JSON — and that is one line in
// main.go, selected by AWESOME_AUTH_ENTRYPOINT, which the SAM template sets on
// the SSE function and on nothing else.
//
// It is one composition and not two because the alternatives were worse by
// this product's own rules, and both were tried on paper first:
//
//   - A cmd/sse with its own composition. Go cannot import a main package, so
//     it would rebuild the core, the token verification, the session check and
//     the four tools postures from importable pieces — a second copy of
//     coreOptions, httpConfig, adminHTTPOptions and toolsAccess that no test
//     could hold to the first, because no test binary can import two mains. A
//     stream that verified tokens differently from the login that minted them
//     is the drift this codebase exists to rule out.
//   - Moving the composition into an importable package. Every file in this
//     directory would change its package clause, and every sibling block that
//     adds a file here would land a `package main` file beside main.go alone,
//     which does not compile — not a merge anybody could call mechanical.
//
// So the SSE function deploys the auth function's artifact with a different
// entry point, and the price is paid in the open: it cold-starts the whole
// composition (docs/cost-model.md §3.1 measures that at 128 MB), and its IAM
// role is a subset of the auth function's rather than a role of its own shape.
//
// ── what the SSE function serves: the stream, and nothing else ───────────────
//
// The Function URL is a second front door onto the same handler, and an
// AuthType: NONE URL (docs/config-reference.md §17.3 argues the choice) is
// internet-facing with no API Gateway in front of it. So the stream role
// answers GET on exactly <tools>/stream and 404 to every other request —
// HEAD and OPTIONS included — from its outermost handler, before the CORS
// layer, the access log, the console's login limiter or any route (streamOnly)
// — without that gate the URL would be an unmetered path to POST
// <prefix>/login, the admin console and the rest. And the tools router it
// mounts has every other feature switched off (streamToolsOptions), so even
// the tools mount answers the stream alone.
//
// ── the route is the core's, and so is everything in front of it ─────────────
//
// GET <tools>/stream is the core's toolsStreamHandler, reached through the
// core's own chain: ToolsSseTokenMiddleware (?token= → Authorization: Bearer),
// then the guard tools.auth selected, then the handler, which calls
// StreamTopics and SseManager.Serve. Nothing here re-implements any of it.
// What this file adds sits between the guard and the handler — the one place
// the principal is known and the stream has not begun — as a wrapper around
// the guard: sseResumeHook, which resolves the client's cursor, starts
// following the event log for the connection's topics, and writes the two
// lines the resume guarantee needs after the connected frame. See its comment.
//
// ── the auth function is unchanged in what it serves ─────────────────────────
//
// There, DisableStream stays true (tools.go): GET <tools>/stream behind API
// Gateway is still the 404 of tools-stream-is-not-mounted-on-api-gateway, and
// the stream reaches a client through the SSE function — the CloudFront
// behaviour for <tools>/stream when the distribution is on, the Function URL
// itself when it is off (docs/config-reference.md §17.3).

// EntrypointEnv selects the runtime contract main.go starts. It is not a
// configuration knob — it says which function this process is, not how the
// product behaves — so it is read here and not by internal/config.
const EntrypointEnv = "AWESOME_AUTH_ENTRYPOINT"

// The two entry points. The empty value is the auth function, which is what
// every existing deployment and test runs.
const (
	entrypointHTTP   = "http"
	entrypointStream = "stream"
)

// streamEntrypoint reports whether this process is the SSE function. An
// unknown value refuses the cold start: a function that guessed would serve
// the wrong contract and fail every invocation.
func streamEntrypoint(getenv func(string) (string, bool)) (bool, error) {
	v, _ := getenv(EntrypointEnv)
	switch strings.TrimSpace(v) {
	case "", entrypointHTTP:
		return false, nil
	case entrypointStream:
		return true, nil
	default:
		return false, fmt.Errorf("%s is %q; the entry points are %q (the auth function, the default) and %q (the SSE function)",
			EntrypointEnv, v, entrypointHTTP, entrypointStream)
	}
}

// sseLogProvider is what this binary needs from a driver to back the
// dynamodb distributor, found structurally on the user store as every other
// store the tools block consumes is.
type sseLogProvider interface {
	SseLog(ddbstore.SseLogOptions) *ddbstore.SseLog
}

// sseEventLog is the event log as the two functions use it: the core's
// distributor, plus the two calls the stream hook makes.
type sseEventLog interface {
	auth.SseDistributor
	Resume(cursor string) ddbstore.SseResume
	Follow(ctx context.Context, f ddbstore.SseFollow) error
}

var _ sseEventLog = (*ddbstore.SseLog)(nil)

// sseLogOptions maps the two knobs onto the log.
func sseLogOptions(cfg *config.Config) ddbstore.SseLogOptions {
	return ddbstore.SseLogOptions{
		Retention:    time.Duration(cfg.Tools.SSE.EventLogRetentionSeconds) * time.Second,
		PollInterval: time.Duration(cfg.Tools.SSE.PollIntervalMs) * time.Millisecond,
	}
}

// streamToolsOptions turns the tools router the auth function would mount into
// the one the SSE function mounts: the stream on, every other feature off, and
// the resume hook inside the guard.
//
// It refuses the cold start for a document that cannot serve a stream, because
// a Function URL that answered 404 or 503 to every connection would bill an
// invocation per EventSource retry, forever, while looking deployed.
func streamToolsOptions(cfg *config.Config, tw *toolsWiring, opts auth.ToolsOptions, log *slog.Logger) (auth.ToolsOptions, error) {
	switch {
	case tw == nil:
		return opts, fmt.Errorf("config: refusing to start the SSE function: tools.enabled is off, so there is no stream to serve")
	case !cfg.Tools.Stream.Enabled:
		return opts, fmt.Errorf("config: refusing to start the SSE function: tools.stream.enabled is off, so GET %s/stream is not mounted", toolsPath(cfg))
	case !cfg.Tools.SSE.Enabled:
		return opts, fmt.Errorf("config: refusing to start the SSE function: tools.sse.enabled is off, so the stream would answer 503 SSE not enabled to every connection")
	case tw.sseLog == nil:
		return opts, fmt.Errorf("config: refusing to start the SSE function: tools.sse.distributor.type is %q, and without the %s event log the stream would hear no event raised anywhere but in its own execution environment, which is nobody",
			cfg.Tools.SSE.Distributor.Type, config.DistributorDynamoDB)
	}

	opts.DisableStream = false
	opts.DisableTelemetry = true
	opts.DisableNotify = true
	opts.DisableWebhook = true
	opts.Docs = auth.DocsOptions{}
	opts.TelemetryStore = nil
	opts.InboundWebhooks = nil

	hook := sseResumeHook(tw.tools.SSE, tw.sseLog, log)
	var guard func(http.Handler) http.Handler
	if opts.Access != nil {
		guard = opts.Access.Middleware
	}
	// ToolsProtected even for the `none` posture, whose Middleware is nil:
	// the hook has to run somewhere between the token middleware and the
	// handler, and a guard slot holding only the hook admits exactly what
	// the empty slot did.
	opts.Access = auth.ToolsProtected(func(next http.Handler) http.Handler {
		if guard == nil {
			return hook(next)
		}
		return guard(hook(next))
	})

	if hb := cfg.Tools.SSE.HeartbeatIntervalMs; hb <= 0 || hb >= 60_000 {
		log.Warn("the SSE heartbeat will not keep an idle stream open behind CloudFront",
			slog.String("path", "tools.sse.heartbeatIntervalMs"),
			slog.Int("value", hb),
			slog.String("problem", "CloudFront ends an origin response that sends nothing for 60 seconds (the SSE behaviour's OriginReadTimeout), so a quiet stream is cut and the client reconnects"),
			slog.String("remedy", "leave it at 30000, the reference's default"))
	}
	return opts, nil
}

// streamOnly is the SSE function's gate, and the outermost handler it has
// (app.go): GET on <tools>/stream reaches the middleware chain and the mux,
// and every other request is net/http's own 404, which is what the mux answers
// for a path it does not know. See the file header for why the gate exists at
// all.
//
// GET alone. HEAD is refused because the core serves it as a stream (Express
// routes HEAD to a GET handler, tools_stream.go) and the streaming writer has
// no body suppression, so an authenticated HEAD would hold an execution
// environment for a whole segment writing bytes a HEAD response may not carry.
// OPTIONS is refused because EventSource never sends a preflight — it is a
// simple request, withCredentials or not — so the only OPTIONS this URL ever
// sees is one it has no reason to answer, and answering it would put the CORS
// layer's 204, with the allow-list's headers, in front of a public URL for
// every path of the composition. A 404 costs a browser nothing.
func streamOnly(cfg *config.Config, next http.Handler) http.Handler {
	path := toolsPath(cfg) + auth.ToolsStreamPath
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── the resume hook ─────────────────────────────────────────────────────────

// lastEventIDParam is the query spelling of the cursor, for a client that
// cannot set a header on its first connection. EventSource sets Last-Event-ID
// itself on every reconnect, and the header wins over the parameter, because
// the URL is reused unchanged across reconnects and still carries whatever
// cursor it was first built with.
const lastEventIDParam = "lastEventId"

// sseResumeHook is the added guarantee (sse-resume-replays-from-the-event-log),
// between the guard and the core's stream handler.
//
// For each connection it:
//
//  1. resolves the topics exactly as the core's handler will — StreamTopics
//     over the principal the guard put on the context and the ?topics= the
//     client asked for (streamRequestedTopics reproduces the core's parse);
//  2. resolves the cursor — Last-Event-ID, else ?lastEventId= — against the
//     log (SseLog.Resume): a recognised one replays what followed it, one
//     older than the retention is truncated to the horizon, anything else is
//     a start from now, which is the reference's only behaviour;
//  3. starts following the log for those topics from that cursor, delivering
//     through the manager the core's handler is about to register the
//     connection with — gated on the registration, because Serve writes the
//     connected frame before it registers (sse.go) and a delivery in between
//     would reach nobody while the cursor moved past it;
//  4. hands the core's handler a writer that, right after the connected
//     frame, writes a comment when the replay was truncated or the cursor
//     not recognised, and then an id-only frame carrying the connection's
//     starting cursor. An id-only frame dispatches no event — the
//     specification sets the last event ID before it discards a frame with no
//     data — so it is invisible to every EventSource handler and is what
//     makes a quiet segment resumable: without it a client that received
//     nothing but `connected` would reconnect with the connected frame's
//     UUID, which no log can place;
//  5. ends the stream if following fails, so the client reconnects with its
//     last id rather than holding a stream that has stopped hearing anything.
//
// One connection per execution environment is what makes step 3's gate exact
// (a Function URL environment serves one invocation at a time); docs/sse.md
// says what that means for a host that serves the stream role elsewhere.
func sseResumeHook(manager *auth.SseManager, sseLog sseEventLog, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, _ := auth.UserFromContext(r.Context())
			topics := auth.StreamTopics(user.ID, user.TenantID, streamRequestedTopics(r.URL.Query()[auth.ToolsStreamTopicsParam]))
			resume := sseLog.Resume(streamCursor(r))

			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			followed := make(chan struct{})
			go func() {
				defer close(followed)
				err := sseLog.Follow(ctx, ddbstore.SseFollow{
					Topics: topics,
					Floor:  resume.Floor,
					Ready:  func() bool { return manager != nil && manager.ConnectionCount() > 0 },
				})
				if err != nil {
					loggerFrom(ctx, log).Warn("the SSE event log could not be followed; ending the stream so the client resumes",
						slog.String("error", err.Error()))
					cancel()
				}
			}()

			next.ServeHTTP(&resumeWriter{ResponseWriter: w, prelude: resumePrelude(resume)}, r.WithContext(ctx))
			cancel()
			<-followed
		})
	}
}

// streamCursor reads the client's cursor: the Last-Event-ID header, else the
// query parameter present exactly once — the predicate the core applies to
// ?token= (tools_stream.go, toolsSseQueryToken), for the same reason.
func streamCursor(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("Last-Event-ID")); v != "" {
		return v
	}
	if values := r.URL.Query()[lastEventIDParam]; len(values) == 1 {
		return values[0]
	}
	return ""
}

// streamRequestedTopics is the core's toolsStreamRequestedTopics
// (tools_stream.go), which is unexported: exactly one ?topics= value, split on
// commas, each entry trimmed, empties dropped; a repeated parameter is no
// request at all, because Express parses it to an array and the reference's
// typeof test fails. It must agree with the core's, because the hook follows
// the topics this computes and the connection holds the topics the core
// computes — TestTheStreamHookFollowsTheTopicsTheCoreGrants compares the two
// on the wire.
func streamRequestedTopics(values []string) []string {
	if len(values) != 1 {
		return nil
	}
	parts := strings.Split(values[0], ",")
	topics := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			topics = append(topics, trimmed)
		}
	}
	return topics
}

// The two comment lines, byte for byte. An SSE comment is discarded by every
// parser; these are for a human reading the stream and for a client that
// wants to tell a truncated replay from a complete one.
const (
	sseTruncatedComment    = ": replay truncated: events older than the retention are no longer held; resuming from the oldest one kept\n\n"
	sseUnrecognisedComment = ": last event id not recognised; resuming from now\n\n"
)

// resumePrelude is what follows the connected frame.
func resumePrelude(resume ddbstore.SseResume) []byte {
	var b strings.Builder
	switch {
	case resume.Truncated:
		b.WriteString(sseTruncatedComment)
	case resume.Unrecognised:
		b.WriteString(sseUnrecognisedComment)
	}
	b.WriteString("id: ")
	b.WriteString(resume.Floor)
	b.WriteString("\n\n")
	return []byte(b.String())
}

// resumeWriter appends the prelude to the first frame the core writes, when the
// response is an event stream. It is the only way in: Serve owns the writer
// from the first byte and offers no seam for a line of the host's own. The
// first Write of a stream is the connected frame (sse.go, writeConnected);
// anything else — the core's 503 when SSE is off, its 500 when the writer
// cannot flush — is not text/event-stream and passes untouched.
type resumeWriter struct {
	http.ResponseWriter
	prelude []byte
	written bool
}

func (w *resumeWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err != nil || w.written {
		return n, err
	}
	w.written = true
	if strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
		if _, err := w.ResponseWriter.Write(w.prelude); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Flush, FlushError and Unwrap keep the writer beneath reachable to
// http.ResponseController, which is how Serve flushes and sets its write
// deadline; a wrapper that hid them would turn every stream into the core's
// "cannot be flushed" 500.
func (w *resumeWriter) Flush() {
	_ = w.FlushError()
}

func (w *resumeWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *resumeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ── the entry point ─────────────────────────────────────────────────────────

// Streams reports whether this App is the SSE function, which main.go starts
// with StreamHandler instead of Handle.
func (a *App) Streams() bool { return a.stream }

// StreamHandler is the lambda.StartHandlerFunc entrypoint of the SSE function:
// the same per-invocation work Handle does — the request id on the logger —
// and then the streaming adapter over the whole wrapped handler.
func (a *App) StreamHandler() lambdahttp.StreamingHandler {
	stream := lambdahttp.NewStreamingHandler(a.Handler, lambdahttp.Options{
		// No stage prefix: a Function URL serves at the root, and the
		// CloudFront behaviour forwards the viewer path unchanged.
		OnError: func(ctx context.Context, err error) {
			loggerFrom(ctx, a.Logger).Error("event adapter", slog.String("error", err.Error()))
		},
	}, 0)
	return func(ctx context.Context, evt *events.LambdaFunctionURLRequest) (*events.LambdaFunctionURLStreamingResponse, error) {
		log := a.Logger
		if lc, ok := lambdacontext.FromContext(ctx); ok && lc.AwsRequestID != "" {
			log = log.With(slog.String("requestId", lc.AwsRequestID))
		}
		return stream(withLogger(ctx, log), evt)
	}
}

// logStreamSurface says, at cold start, which half of D9c this function is.
func logStreamSurface(cfg *config.Config, tw *toolsWiring, stream bool, log *slog.Logger) {
	if tw == nil || tw.sseLog == nil {
		return
	}
	mount := toolsPath(cfg)
	if stream {
		log.Info("SSE function: serving GET "+mount+"/stream and nothing else",
			slog.String("entrypoint", entrypointStream),
			slog.String("distributor", config.DistributorDynamoDB),
			slog.Int("pollIntervalMs", cfg.Tools.SSE.PollIntervalMs),
			slog.Int("eventLogRetentionSeconds", cfg.Tools.SSE.EventLogRetentionSeconds),
			slog.String("resume", "Last-Event-ID (or ?lastEventId=) replays the event log after it, within the retention (deviation sse-resume-replays-from-the-event-log)"))
		return
	}
	log.Info("the SSE manager publishes to the event log",
		slog.String("path", "tools.sse.distributor.type"),
		slog.String("effect", "every broadcast is written to the event log and delivered by the SSE function to the connections it holds; GET "+mount+"/stream on this function still answers 404, and the stream is the SSE function's (docs/sse.md)"))
}
